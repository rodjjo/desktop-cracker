#!/bin/bash
# Build the desktop-cracker guest image: an initramfs that carries the guest tools, the
# kernel modules the guest needs (9p, virtio_input, virtio_snd, vsock) and an
# init that gives the balloon manager something to read.
#
#   tools/guest-image/build.sh [output.gz]
#
# The image is *small on purpose*: the desktop itself (LightDM, Xfce) lives on
# the guest's root filesystem, which is the root-folder the user configures —
# not inside the initramfs, which is loaded entirely into RAM at boot.
#
# Everything it needs comes from the running host (busybox, /lib/modules of the
# kernel it boots), so no cross-toolchain and no root are required: modules are
# copied with `cp` and their dependencies are written by hand, which is exactly
# what `depmod` would produce for this short list.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root_dir=$(cd "$here/../.." && pwd)
out=${1:-$root_dir/download/initramfs.gz}
kver=${KERNEL_RELEASE:-$(uname -r)}
moddir=${MODULE_DIR:-/lib/modules/$kver}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
root="$tmp/root"

say() { printf 'guest-image: %s\n' "$*"; }

if [ ! -d "$moddir" ]; then
    echo "guest-image: no modules for $kver in $moddir" >&2
    echo "guest-image: set KERNEL_RELEASE/MODULE_DIR, or install the kernel's modules" >&2
    exit 1
fi

mkdir -p "$root"/{bin,sbin,proc,sys,dev,tmp,run,mnt/root,mnt/disk,mnt/share,usr/bin,usr/sbin}

say "compiling the guest tools"
# -lm: the tone the `sound` verb plays is a sine.
gcc -static -O2 -o "$root/bin/guest-tools" "$here/guest-tools.c" -lm

say "installing busybox ($(busybox --help 2>&1 | head -1))"
cp "$(command -v busybox)" "$root/bin/busybox"
chmod +x "$root/bin/busybox"

# ------------------------------------------------------------------- cryptsetup
# The encrypted disk is opened **inside the guest**: the host only hands over
# the container, and the guest runs cryptsetup with the user's passphrase.  The
# binary and its closure come from the host (there is no cross-build here); the
# guest's /lib is an overlay so the closure's own paths are not touched.
if [ "${WITH_CRYPTSETUP:-1}" = "1" ] && [ -x /usr/sbin/cryptsetup ]; then
    say "installing cryptsetup and its dependencies"
    install -D -m 0755 /usr/sbin/cryptsetup "$root/sbin/cryptsetup"
    install -D -m 0755 /usr/sbin/cryptsetup "$root/usr/sbin/cryptsetup"
    # One recursive pass over the whole closure: `ldd` alone misses the
    # libraries that libcryptsetup itself pulls in (libdevmapper, libcrypto,
    # libargon2, ...), and a missing one fails at run time, inside the guest.
    collect_deps() {
        local seen="" so
        for lib in "$@"; do
            for so in $(ldd "$lib" 2>/dev/null | grep -oE '/[^ ]+\.so[^ ]*'); do
                case " $seen " in *" $so "*) continue ;; esac
                seen="$seen $so"
                collect_deps "$so"
            done
        done
        printf '%s\n' $seen
    }
    deps=$(collect_deps /usr/sbin/cryptsetup | sort -u)
    for so in $deps; do
        case "$so" in
        /lib64/*) install -D -m 0755 "$so" "$root$so" ;;
        *) install -D -m 0644 "$so" "$root$so" ;;
        esac
    done
    # LUKS2 is the default of modern cryptsetup; PBKDF is done by libcrypto,
    # which is in the closure above.  Nothing else is needed.
    printf '%s\n' "$deps" | sed 's/^/guest-image:   /'
else
    say "cryptsetup not installed into the image (WITH_CRYPTSETUP=0 or not present): the"
    say "guest will report that it cannot decrypt anything, which is itself a result"
fi

if [ -x "$root/bin/busybox" ]; then
    # `sh` is what the seed copy runs (a pipe of two `tar`s), and `cp`/`rm` are what a
    # person at the console expects; the rest of busybox's applets are a symlink away.
    #
    # `udhcpc` and `ip` are here because the guest's **network** is: the address comes from
    # a userspace helper that answers DHCP on the host, and an initramfs with no
    # client on it is an interface that never comes up — which is what "firefox has no
    # internet" looks like from the other end of the wire.
    for applet in modprobe losetup mount umount sh cp rm mkdir udhcpc ip route wget \
        nslookup; do
        [ -e "$root/sbin/$applet" ] || ln -sf ../bin/busybox "$root/sbin/$applet"
        [ -e "$root/bin/$applet" ] || ln -sf busybox "$root/bin/$applet"
    done
    # `udhcpc` runs a script for every lease; busybox's own `default.script` is not in this
    # image, and without it the lease is not applied and no resolver is written.  This is
    # that script, in the two lines it takes: take the address and the route, and write the
    # resolver passt handed over.
    mkdir -p "$root/usr/share/udhcpc"
    cat > "$root/usr/share/udhcpc/default.script" <<'UDHCPC'
#!/bin/busybox sh
# The lease, applied — and **recorded**, because the system on the disk needs it too: the
# initramfs is the only place that ever talks DHCP (passt answers it), and the disk's own
# systemd has no client of its own.  `/run/net.env` is what `rootboot` copies into the new
# root so the system starts with the same address, route and resolver.
# What the lease carried, so a missing option is visible rather than guessed at.
echo "DESK-NET lease ip=$ip mask=$mask router=$router dns=$dns"
case "$1" in
deconfig) ip addr flush dev "$interface" ;;
bound | renew)
    ip addr add "$ip/$mask" dev "$interface"
    [ -n "$router" ] && ip route add default via "${router%% *}" dev "$interface"
    # The resolver: DHCP's option 6 when the server sent one, and the **gateway** when it
    # did not.  Measured: a server that sends no option 6 leaves `$dns` empty, an empty
    # `/etc/resolv.conf` makes libc default to `127.0.0.1`, and a guest's every lookup goes to
    # the loopback address it does not have — which is exactly "wget: bad address".
    [ -z "$dns" ] && dns="$router"
    # `/etc` **does not exist in an initramfs**, and `: > /etc/resolv.conf` into a missing
    # directory is how a guest ends up with no resolver at all (measured: "can't create
    # /etc/resolv.conf: nonexistent directory", and then libc defaults to `127.0.0.1` — the
    # address a guest does not have, so every lookup fails and the guest says only
    # "bad address").
    mkdir -p /etc
    : >/etc/resolv.conf
    for ns in $dns; do echo "nameserver $ns" >>/etc/resolv.conf; done
    {
        echo "ip=$ip"
        echo "mask=$mask"
        echo "router=${router%% *}"
        echo "dns=$dns"
    } >/run/net.env
    ;;
esac
UDHCPC
    chmod +x "$root/usr/share/udhcpc/default.script"
fi

# ------------------------------------------------------------------ e2fsprogs
# The **disk manager** boot needs the real e2fsprogs: a guest disk is created,
# resized and inspected inside a microvm (no root, no loop device and no package
# on the host), and busybox's `mke2fs` cannot make the filesystems this project
# needs.  The same image serves the desktop boot, so this costs a couple of
# megabytes in both.
if [ "${WITH_E2FSPROGS:-1}" = "1" ]; then
    say "installing e2fsprogs (the disk manager's tools)"
    e2bins=(/bin/tar /sbin/losetup /sbin/partx /sbin/kpartx /sbin/blockdev /sbin/fdisk /sbin/sfdisk /sbin/partprobe /sbin/dmsetup /sbin/debugfs /sbin/mke2fs /sbin/e2fsck /sbin/resize2fs /sbin/tune2fs /sbin/dumpe2fs /sbin/blkid /sbin/e2label)
    e2deps=""
    for b in "${e2bins[@]}"; do
        [ -x "$b" ] || continue
        install -D -m 0755 "$b" "$root$b"
        e2deps="$e2deps $(ldd "$b" | grep -oE '/lib[^ ]+\.so[^ ]*')"
    done
    for so in $(printf '%s\n' $e2deps | sort -u); do
        case "$so" in
        /lib64/*) install -D -m 0755 "$so" "$root$so" ;;
        *) install -D -m 0644 "$so" "$root$so" ;;
        esac
    done
fi

# ------------------------------------------------------------------------ aplay
# The host has a real ALSA client; the guest gets it so that a test can ask the
# guest to *produce* sound and then check what the rule did with it.  (The
# kernel's OSS emulation is off in this kernel, so a tiny `/dev/dsp` writer would
# not work — a real ALSA client is the honest way.)
if [ "${WITH_APLAY:-1}" = "1" ] && [ -x /usr/bin/aplay ]; then
    say "installing aplay (ALSA) so the guest can play sound"
    install -D -m 0755 /usr/bin/aplay "$root/bin/aplay"
    for so in $(ldd /usr/bin/aplay | grep -oE '/lib[^ ]+\.so[^ ]*' | sort -u); do
        case "$so" in
        /lib64/*) install -D -m 0755 "$so" "$root$so" ;;
        *) install -D -m 0644 "$so" "$root$so" ;;
        esac
    done
    # libasound needs its configuration tree to find the card at all: with no
    # /usr/share/alsa it fails with a lookup error even when /dev/snd exists.
    if [ -d /usr/share/alsa ]; then
        mkdir -p "$root/usr/share"
        cp -a /usr/share/alsa "$root/usr/share/"
        say "installed the ALSA configuration tree ($(du -sh "$root/usr/share/alsa" | cut -f1))"
    fi
fi

# ---------------------------------------------------------------- kernel modules
# The list is exactly what the guest's devices need, in load order.  Missing
# modules are not an error: the device simply will not work, and the guest says
# which one in its log.
mods=(
    "kernel/fs/9p/9p.ko"                       # the shares
    "kernel/fs/netfs/netfs.ko"
    "kernel/net/9p/9pnet.ko"
    "kernel/net/9p/9pnet_fd.ko"
    "kernel/net/9p/9pnet_virtio.ko"
    "kernel/drivers/virtio/virtio_input.ko"    # the keyboard in the window
    "kernel/drivers/virtio/virtio_mem.ko"
    # Audio: the sound core plus virtio-sound.  (ALSA PCM is what applications
    # use; `CONFIG_SND_PCM_OSS` is off in this kernel, so `aplay` with a real
    # ALSA client is the way to play — the guest image carries no ALSA userland,
    # so the *host* side's rule is what the audio test proves.)
    "kernel/sound/soundcore.ko"
    "kernel/sound/core/snd.ko"
    "kernel/sound/core/snd-pcm.ko"
    "kernel/sound/core/snd-timer.ko"
    "kernel/sound/core/snd-hwdep.ko"
    "kernel/sound/virtio/virtio_snd.ko"
    # vsock: the remote-X forwarder reaches the host over it.
    "kernel/net/vmw_vsock/vsock.ko"
    "kernel/net/vmw_vsock/vmw_vsock_virtio_transport_common.ko"
    "kernel/net/vmw_vsock/vmw_vsock_virtio_transport.ko"
    "kernel/fs/fuse/virtiofs.ko"
    # overlayfs: the read-only root gets a RAM overlay on top, so a running
    # system has writable paths without the disk ever being written.
    "kernel/fs/overlayfs/overlay.ko"
    "kernel/drivers/md/dm-crypt.ko"            # the encrypted disk, in the guest
    "kernel/crypto/crypto_user.ko"
    "kernel/crypto/essiv.ko"
    # The display: virtio-gpu is what the host's window shows, and the guest
    # needs its DRM stack to have a framebuffer at all (without it there is no
    # /dev/fb0 and no X server can start).
    # drm.ko and drm_kms_helper.ko are built into this kernel (=y), so only the
    # loadable ones are here; virtio_dma_buf is a hard dependency of virtio-gpu.
    "kernel/drivers/virtio/virtio_dma_buf.ko"
    "kernel/drivers/gpu/drm/ttm/ttm.ko"
    "kernel/drivers/gpu/drm/drm_ttm_helper.ko"
    "kernel/drivers/gpu/drm/virtio/virtio-gpu.ko"
    "kernel/drivers/gpu/drm/drm_buddy.ko"
)
installed=0
for rel in "${mods[@]}"; do
    src="$moddir/$rel"
    if [ -f "$src" ]; then
        dst="$root/lib/modules/$kver/$rel"
        mkdir -p "$(dirname "$dst")"
        cp "$src" "$dst"
        installed=$((installed + 1))
        say "module $rel"
    fi
done
if [ "$installed" -eq 0 ]; then
    say "WARNING: no kernel modules found; 9P shares will not mount in the guest"
fi

# depmod writes the metadata insmod() reads via finit_module; without it the
# guest can still `insmod` the file by path, which is what init does below.
if [ "$installed" -gt 0 ] && command -v depmod >/dev/null 2>&1; then
    depmod -b "$root" "$kver" 2>/dev/null && say "module dependencies written with depmod" \
        || say "depmod failed; init will insmod by path"
fi

# --------------------------------------------------------------------- init
cat > "$root/init" <<'INIT'
#!/bin/busybox sh
# The desktop-cracker guest's init.
PATH=/bin:/sbin:/usr/bin:/usr/sbin
export PATH

mkdir -p /proc /sys /dev /tmp /run /mnt/root /mnt/disk /mnt/share /usr/bin /usr/sbin
/bin/busybox --install -s 2>/dev/null

mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sys /sys 2>/dev/null || true
mount -t devtmpfs dev /dev 2>/dev/null || true
[ -c /dev/ttyS0 ] || mknod /dev/ttyS0 c 4 64 2>/dev/null || true
[ -c /dev/console ] || mknod /dev/console c 5 1 2>/dev/null || true

# The guest's devices are virtio-mmio: load the modules the host built for this
# kernel, in the order the device stack needs them.  **Silently**: the console belongs to
# the user (the window shows it), and a line per module is noise a person has to read past.
K=$(uname -r)
load() { [ -f "$1" ] && insmod "$1" 2>/dev/null; }
for m in 9p 9pnet 9pnet_fd 9pnet_virtio; do
    load /lib/modules/$K/kernel/fs/9p/$m.ko
    load /lib/modules/$K/kernel/net/9p/$m.ko
done
load /lib/modules/$K/kernel/fs/netfs/netfs.ko
load /lib/modules/$K/kernel/drivers/virtio/virtio_input.ko
# The DRM stack for the display: the guest gets a framebuffer from virtio-gpu
# only when these are in, in this order (virtio_dma_buf is a hard dependency of
# virtio_gpu; drm.ko and drm_kms_helper.ko are built into this kernel).
load /lib/modules/$K/kernel/fs/overlayfs/overlay.ko
load /lib/modules/$K/kernel/drivers/gpu/drm/drm_buddy.ko
load /lib/modules/$K/kernel/drivers/gpu/drm/ttm/ttm.ko
load /lib/modules/$K/kernel/drivers/gpu/drm/drm_ttm_helper.ko
load /lib/modules/$K/kernel/drivers/virtio/virtio_dma_buf.ko
load /lib/modules/$K/kernel/drivers/gpu/drm/virtio/virtio-gpu.ko
load /lib/modules/$K/kernel/net/vmw_vsock/vsock.ko
load /lib/modules/$K/kernel/net/vmw_vsock/vmw_vsock_virtio_transport_common.ko
load /lib/modules/$K/kernel/net/vmw_vsock/vmw_vsock_virtio_transport.ko
load /lib/modules/$K/kernel/drivers/md/dm-crypt.ko
load /lib/modules/$K/kernel/crypto/crypto_user.ko
load /lib/modules/$K/kernel/crypto/essiv.ko
load /lib/modules/$K/kernel/sound/soundcore.ko
load /lib/modules/$K/kernel/sound/core/snd.ko
# snd-pcm needs snd-timer first: the order here is the dependency order, and a
# wrong one fails silently (insmod's error is swallowed on purpose — a missing
# module must not stop the boot).
load /lib/modules/$K/kernel/sound/core/snd-timer.ko
load /lib/modules/$K/kernel/sound/core/snd-pcm.ko
load /lib/modules/$K/kernel/sound/core/snd-hwdep.ko
load /lib/modules/$K/kernel/sound/virtio/virtio_snd.ko

echo "GUEST init: $(uname -r) / $(uname -m), $(grep -c '^processor' /proc/cpuinfo) cpu(s)"
# Two shapes of boot: the display/desktop guest, and the disk manager (which the
# host starts for a disk job — no userland, no display, just the tools and the
# device it attached).
case "$(cat /proc/cmdline)" in
*desktop-cracker.dmprobe=*)
    exec /bin/guest-tools dmprobe
    ;;
*desk.diskjob=*)
    mkdir -p /run/desktop-cracker
    mount -t 9p -o trans=virtio,version=9p2000.L control /run/desktop-cracker 2>/dev/null || true
    exec /bin/guest-tools diskmgr
    ;;
esac
exec /bin/guest-tools boot
INIT
chmod +x "$root/init"

say "packing $out"
( cd "$root" && find . | cpio -o -H newc --quiet | gzip -9 ) > "$out"
ls -lh "$out" | awk '{print "guest-image: " $5 " " $9}'
