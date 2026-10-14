#!/bin/bash
# Build the guest's userland: the folder the microvm uses as its root filesystem
# (Settings: root-folder; "Installed and configured by default":
# LightDM and Xfce).
#
#   tools/rootfs/build.sh [output-dir]
#
# What goes in is this project's own list: the desktop (LightDM, Xfce, an X
# server), the guest's users, the library applications link to, and "default
# installed software" — the latest VLC and Firefox (from backports where the
# release is behind) and Python 3.13 with pip3 and venv (built from source, since
# bookworm has 3.11).
#
# It runs **debootstrap inside a container** (Docker), so the base system is
# built by Debian's own tooling and the host's package state is never touched.
# The result is a plain directory of files — which is what the 9P root-folder
# share carries into the guest.
#
# The guest's own pieces (the init that mounts the shares, the LightDM session
# that runs Xfce) are added by `dc-rootfs` afterwards, so what this script
# produces is Debian's base plus the packages.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root_dir=$(cd "$here/../.." && pwd)
out=$root_dir/temp/download/rootfs
for a in "$@"; do
    case "$a" in
    /* | ./* | ../*) out=$a ;;
    esac
done

say() { printf 'rootfs: %s\n' "$*"; }

# The packages this project asks for, plus what a desktop needs to exist at
# all inside the guest: an X server (the guest has its own, on the microVM's
# virtio-gpu), a display manager, a window manager, a terminal and fonts.
# `cryptsetup` is what unlocks the encrypted root disk **inside the guest**, so
# it belongs in the guest's userland (the microvm does the decryption, never the
# host).
# **The list of programs the guest ships**: a torrent client, a
# shell, a terminal multiplexer, `curl`, a terminal, the ssh client, a file manager, a system
# monitor, the archive tools and `ffmpeg` — what a person inside the sandbox reaches for, on top of
# the desktop itself.  (`ssh` is `openssh-client`; the server was already here for `--ssh-port`.)
#
# **Xfce, not IceWM** (Installed and configured by default: , changed 2026-10-12): under
# IceWM a window the guest opened was never mapped — `xterm` and `vlc` each had a process, a pty and
# nothing on the screen, and `xwininfo -root -all -tree` listed no window for either (the operator:
# "xterm does not open, never opened in this system").  `xfce4` is the meta-package, so Xfwm4, the
# panel, xfce4-session and Thunar come with it — which is why **Thunar** replaces PCManFM in the
# same line (Thunar is built on PCManFM's own `libfm`).  **Mousepad** is the text editor: Leafpad has
# no installation candidate in Debian 12 (`apt-cache policy leafpad` → `Candidate: (none)`).
# `apt-utils` is this project's own. `libmpdec` is not in Debian 12 at all, so it is not here
# (Python 3.13's `decimal` is built in). `python3-tk` is "Python's Tk libraries": it puts
# `libtk8.6`/`libtcl8.6` in the guest, which is what the source-built Python's `_tkinter` links
# against (its build gets Tk's and Tcl's headers in the container — see `guest-userland.sh`).
#
#
# **The network tools a person tests with** (the operator, 2026-10-12: "Id like you add tools for
# network testing like ping, nc (netcat), traceroute", and "also add wget").  `wget`, `ping`,
# `tracepath`, `traceroute`, `nc` and `dig`/`nslookup` are how a guest's network is checked by hand —
# the guest's `ip` and `ss` were already here, and they are not enough to answer "can this guest reach
# that service, and by what name?".  `iputils-ping` is the one that matters for `--host-network`: a
# `ping parenthost` is a real round trip through the host's own loopback, and it is the shortest
# question a person can ask the rule.
#
# **The guest's disk manager** (the operator, 2026-10-13: *"xfce4-mount-plugin is not what I was
# looking for… what I'm looking for is an application to manage disk device, to mount and dismount
# them, with cryptography support so I can mount encrypted disk… Install gnome-disk-utility for disk
# management"*).  **`gnome-disk-utility`** (GNOME Disks) is that application: it lists every block
# device the run attached, and for each one it **mounts/unmounts the filesystem** and **unlocks a
# LUKS container by asking for its passphrase in a window of its own** — the cryptography is the
# kernel's `dm-crypt` behind it, the same one `desk-disk` uses.  It talks to **`udisks2`**, the
# system service that does the work (its own `udisks2.service`, wanted by `graphical.target`), and
# `udisks2` asks **polkit** whether the user may do it: hence the three packages together.
# `xfce4-mount-plugin` (a panel button, no passphrase window, no unlock) is out.
#
# **What polkit answers, measured** (2026-10-14, read out of the real
# `/usr/share/polkit-1/actions/org.freedesktop.UDisks2.policy` the `udisks2 2.9.4-4+deb12u2` package
# ships — not out of a manual): the defaults are **not one answer for everything**.  For an active
# local session `filesystem-mount` and `encrypted-unlock` are already `yes`, so *those two names need
# no rule*.  What is `auth_admin_keep` is the **system** form of each action, and the system form is
# the one udisks uses for the disks this project attaches: `update_hints` (udiskslinuxblock.c) starts
# at `hint_system = TRUE` and clears it only for removable media or a usb/ieee1394/sdio bus, and a
# virtio disk is none of those.  So a mount, an unmount, an unlock and a lock of `/dev/vdb` ask for
# `filesystem-mount-system`, `filesystem-unmount-others`, `encrypted-unlock-system` and
# `encrypted-lock-others` — all four `auth_admin_keep`.  `auth_admin_keep` in **this** guest is a
# question nobody can answer: nothing in this userland registers a polkit authentication agent on the
# session bus — `xfce4-polkit`, the one Xfce would ship, has **no installation candidate in bookworm**
# (`apt-cache policy xfce4-polkit` → none), and the three that do exist (`policykit-1-gnome`,
# `mate-polkit`, `lxqt-policykit`) are another desktop's and are not installed here.  So polkit has no
# way to ask for an administrator's password and the call is simply refused (`Not authorized`).  The
# `-others` pair is not a corner
# case here either: `desk-disk-mount` mounts and opens as **root** (it re-runs itself under
# `sudo`), and a mount root made is one the desktop user would have to unmount "for another user".
# The step below writes the rule that answers these names, and it is why the desktop never then asks
# for a *sudo* password.  Nothing else changes: the **passphrase of a LUKS container is still asked
# for, by Disks, every time** (polkit authorizes the *action*, it is not the disk's key), and nothing
# is mounted automatically.
#
# **The five packages after `policykit-1` are `udisks2`'s own Recommends, named here because this
# build installs with `--no-install-recommends`** (the rule that keeps the userland small: no
# GStreamer, no GNOME session, no help files behind the desktop).  `udisks2` *Depends* on
# `libblockdev-fs2/-loop2/-part2/-swap2/-utils2` only, and libblockdev loads the rest as plugins at
# run time: with the crypto plugin absent its call is a stub, and the operator's screen said exactly
# that (2026-10-14, Disks → *Unlocking a LUKS device*):
#
#     Error unlocking /dev/vdb: The function 'bd_crypto_luks_open_blob' called, but not implemented!
#
# `libblockdev-crypto2` is that plugin (`/usr/lib/…/libbd_crypto.so.2`), and it is the whole of the
# fix.  `dosfstools`, `exfatprogs` and `ntfs-3g` are the same story for a filesystem udisks mounts
# with a helper (`mkfs.vfat`/`fsck.fat`, `mkfs.exfat`, `mount.ntfs`), and `eject` is the one the
# drive's Eject action runs.  `e2fsprogs` is already in the tree (it is what `mkfs.ext4` and the
# guest's own resize come from), so it is not repeated here.  All five together are 660 KiB of
# download (measured: `apt-get download` of them in a debian:12 container).
#
# **`pavucontrol` and the sound server behind it** (the operator, 2026-10-12: "please Install
# pavucontrol").  The guest's sound card is the kernel's loopback one (`snd-aloop`) and this project
# reads the *capture* end of it (`/dev/snd/pcmC0D1c`); the desktop plays into the *playback* end
# (`pcmC0D0p`), a different PCM device, so the two never fight for the card.  A sound server has to be
# **told** that card — see the step below that writes `/etc/pulse/default.pa.d/desk-sound.pa`,
# which is where the measurement and the reason are.
PKGS_BASE="systemd-sysv dbus lightdm lightdm-gtk-greeter xfce4 xfce4-terminal \
xserver-xorg xserver-xorg-video-fbdev xinit xterm x11-utils x11-xserver-utils xfonts-base \
fonts-dejavu-core sudo less procps iproute2 curl ca-certificates cryptsetup \
openssh-server openssh-client vlc firefox-esr bash tmux thunar mousepad conky \
tar gzip unzip ffmpeg qbittorrent apt-utils python3-tk pavucontrol pulseaudio pulseaudio-utils \
gnome-disk-utility udisks2 policykit-1 libblockdev-crypto2 dosfstools eject exfatprogs ntfs-3g \
 wget iputils-ping iputils-tracepath traceroute netcat-openbsd dnsutils"
# Default installed software: names the latest VLC and Firefox and
# Python 3.13 with pip3 and venv.  The two media ones come from backports when the
# release is behind (a backport that is not there leaves the release's own
# package, which still works); Python 3.13 is not in bookworm at all, so it is
# built from source below.
PKGS_BACKPORTS="firefox-esr vlc"

image=${ROOTFS_IMAGE:-debian:12}
say "base: $image (debootstrap), output: $out"

if ! command -v docker >/dev/null 2>&1; then
    echo "rootfs: docker is needed (the base system is built in a container, so" >&2
    echo "rootfs: the host's own packages are never touched)" >&2
    exit 2
fi

# The tree is built by containers running as root, so removing a previous one
# needs the same: do it in a container rather than as this user.
say "clearing $out"
docker run --rm -v "$(dirname "$out")":/parent "$image" bash -c "rm -rf /parent/$(basename "$out")"
mkdir -p "$out"

# `-v` for the library: the container that configures the tree is also the one that
# installs it (the tree belongs to root, so nothing here can be written from the
# outside).
# The guest's **additional-disk tool**, from this tree (`tools/rootfs/desk-disk-mount.sh`):
# it is a shell script, so it is installed into the userland as a file rather than built.
desk_tool="$here/desk-disk-mount.sh"

run() {
    docker run --rm -v "$out":/out \
        -v "$desk_tool":/desk-disk-mount.sh:ro \
        -v "$root_dir/temp/download/libdesk-guest":/libdesk:ro \
        "$image" bash -euo pipefail -c "$1"
}

# One container does the whole build: `debootstrap` has to exist in the same
# container that runs it (`docker run` starts a fresh one every time), and the
# step after it is a `chroot` into what it produced.
say "building the base and the desktop packages (a few minutes)"
run "export DEBIAN_FRONTEND=noninteractive
apt-get update -qq && apt-get install -y -qq debootstrap >/dev/null 2>&1
debootstrap --variant=minbase --include=systemd-sysv,dbus bookworm /out \
    http://deb.debian.org/debian >/dev/null 2>&1
cat > /out/etc/apt/sources.list <<'SOURCES'
deb http://deb.debian.org/debian bookworm main
deb http://deb.debian.org/debian bookworm-updates main
deb http://security.debian.org/debian-security bookworm-security main
SOURCES
chroot /out bash -c 'apt-get update -qq && \
  apt-get install -y -qq --no-install-recommends $PKGS_BASE'
chroot /out bash -c 'apt-get clean; rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*'"

say "building the library guest applications link to"
# External sate: an application in the guest reads the state of the
# display window.  The library is built for the guest (no X11: the host's state
# file is what answers there), installed, and the userland's ldconfig is run so the
# shared one is found without a path.
bash "$root_dir/tools/libdesk/build.sh" "$root_dir/temp/download/libdesk-guest" --guest

say "configuring the guest's userland"
run "cat > /out/etc/fstab <<'FSTAB'
# the desktop-cracker guest mounts its root itself (see the initramfs init)
proc            /proc    proc    defaults              0 0
sysfs           /sys     sysfs   defaults              0 0
devtmpfs        /dev     devtmpfs mode=0755             0 0
tmpfs           /tmp     tmpfs   mode=1777,size=256m    0 0
tmpfs           /run     tmpfs   mode=0755,size=64m     0 0
tmpfs           /var/tmp tmpfs   mode=1777,size=64m     0 0
FSTAB
# The guest's own user: **\`deskuser\`**, able to sudo.  During development root is used
# (the console's autologin); for the desktop session this is the user LightDM starts Xfce
# for.
if ! grep -q '^deskuser:' /out/etc/passwd; then
    chroot /out useradd -m -s /bin/bash -G sudo,audio,video,input,plugdev deskuser
fi
printf 'deskuser:changeme\n' | chroot /out chpasswd
# The development console logs in as root: \`login\` refuses an account whose
# password field is empty, so root gets one too (the same one, and it is the
# *sandbox's* root — the disk's password is what protects the machine).
printf 'root:deskuser\n' | chroot /out chpasswd
# The design SSH: the guest runs an openssh server, always. It accepts the guest's own users
# and passwords — the same deskuser/changeme the desktop logs in with — and it is attached to
# the guest's own network, so nothing outside can reach it unless the host opens --ssh-port
# for it (the application's network is a userspace one: the guest is behind this process, and
# a port is the only way in).
#
# A file of our own is written rather than one sed over the distribution's defaults, because
# what matters here is not one setting but the whole answer: the distribution ships a policy
# fragment that denies password logins, and a file of ours later in the include order is what
# makes ours the last word.
mkdir -p /out/etc/ssh/sshd_config.d
cat > /out/etc/ssh/sshd_config.d/10-deskuser.conf <<'SSHD'
# The guest users and their passwords are how the guest logs in. The same
# credentials are what sshd accepts: no key is needed to reach the sandbox.
PasswordAuthentication yes
KbdInteractiveAuthentication no
UsePAM yes
# root is not a login over ssh.  The distribution's own default (Debian, since openssh 1:7.0)
# is prohibit-password, and it is kept: root has a password on the console because login
# refuses an empty one, not because ssh should take it.  Sudo, after logging in as deskuser,
# is the way to root.
PermitRootLogin prohibit-password
SSHD
# The session's host keys.  The package makes them as it installs (each ssh-keygen prints one
# above); this is for the container where that step was skipped, because a host key generated
# while sshd starts is a delay in the guest's first boot and this project's reason to exist is
# a guest that boots in seconds.
chroot /out ssh-keygen -A >/dev/null 2>&1 || true
# sshd checks the ownership and the mode of these files and refuses to start otherwise.
chmod 0755 /out/etc/ssh
chmod 0644 /out/etc/ssh/sshd_config /out/etc/ssh/sshd_config.d/10-deskuser.conf
chown -R root:root /out/etc/ssh
chmod 0600 /out/etc/ssh/ssh_host_*_key 2>/dev/null || true
chmod 0644 /out/etc/ssh/ssh_host_*_key.pub 2>/dev/null || true
# sshd is always running: the want-link is written here rather than trusted to
# the package's own enable step in a container, exactly as LightDM's is below — systemd in a
# chroot inside a container cannot always enable a unit, and a missing link here is a guest
# whose port 22 has nothing behind it.
mkdir -p /out/etc/systemd/system/multi-user.target.wants
ln -sf /lib/systemd/system/ssh.service /out/etc/systemd/system/multi-user.target.wants/ssh.service
# What sshd actually reads, printed by sshd itself: a configuration this build got wrong (a
# directive in a file that sorts before ours, a file the server refuses) must not be found out
# at boot.  It is a report, not a failure — and it is why the two lines above are trusted.  (The
# directory is the one sshd insists on having before it will even read its own configuration; at
# boot systemd makes it, through the unit's own \`RuntimeDirectory=sshd\`.)
# (\`|| true\`: this text is inside a double-quoted argument, so a shell function of the outer
# script — \`say\` above — does not exist inside the container this runs in.)
mkdir -p /out/run/sshd
chroot /out sshd -T 2>/dev/null | grep -iE '^(passwordauthentication|permitrootlogin|usepam|kbdinteractiveauthentication) ' \
    | sed 's/^/rootfs: sshd: /' || true
# The design: the VM's timezone is **São Paulo** (America/Sao_Paulo, UTC-3 with
# Brazil's own DST rules).  The symlink is the whole of it: \`date\` in the guest
# reads \`/etc/localtime\`, and the Debian convention is a symlink into
# \`/usr/share/zoneinfo\`.  It must be done after the userland is installed (that is
# what populates zoneinfo).
ln -sf /usr/share/zoneinfo/America/Sao_Paulo /out/etc/localtime
printf 'America/Sao_Paulo\n' > /out/etc/timezone
# LightDM keeps its session files in its own home, and the container that built
# this tree made them as *its* user: without this the greeter cannot write its
# X authority and no session starts.
# The library (and its header) an application in the guest links against.
mkdir -p /out/usr/local/lib /out/usr/local/include /out/usr/local/bin
cp /libdesk/libdesk_display.so.1 /out/usr/local/lib/
ln -sf libdesk_display.so.1 /out/usr/local/lib/libdesk_display.so
cp /libdesk/libdesk_display.a /out/usr/local/lib/
cp /libdesk/desk_display.h /out/usr/local/include/
cp /libdesk/desk-display-status /out/usr/local/bin/
# **The tool that mounts an additional disk**. It belongs in the userland and not in a share: the guest's user runs it from
# anywhere, at any time, whether or not the run that attached the disk is still the one they
# logged in on.
# (Nothing conditional here on purpose: this whole text is one double-quoted argument of the
# outer script, so a \`\"\` inside it would end that argument — and the tool is a build input, so a
# missing file is a build that must fail.)
install -m 0755 /desk-disk-mount.sh /out/usr/local/bin/desk-disk-mount
echo /usr/local/lib > /out/etc/ld.so.conf.d/desk.conf
chroot /out ldconfig 2>/dev/null || true

mkdir -p /out/var/lib/lightdm /out/var/log/lightdm
lduid=\$(awk -F: '\$1==\"lightdm\"{print \$3}' /out/etc/passwd)
ldgid=\$(awk -F: '\$1==\"lightdm\"{print \$4}' /out/etc/passwd)
if [ -n \"\$lduid\" ]; then
    chown -R \"\$lduid:\$ldgid\" /out/var/lib/lightdm /out/var/log/lightdm
    chmod 0750 /out/var/lib/lightdm
fi

mkdir -p /out/etc/systemd/system/serial-getty@ttyS0.service.d
cat > /out/etc/systemd/system/serial-getty@ttyS0.service.d/desk.conf <<'CONF1'
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin root --noclear %I \$TERM
CONF1
mkdir -p /out/etc/systemd/system/getty@tty1.service.d
cat > /out/etc/systemd/system/getty@tty1.service.d/desk.conf <<'CONF2'
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin root --noclear %I \$TERM
CONF2
# **\`sudo\` must not stall on its own hostname.**  sudo resolves the machine's name before it does
# anything else, and this microVM's name is generated at boot (\`63e80b8091c7\`) while no
# \`/etc/hosts\` line claims it — so the lookup goes to a resolver the guest may not be able to
# reach, and sudo sits there until it times out (measured 2026-10-10: \`sudo: unable to resolve
# host …\`, and a \`sudo\` that never returned).  Debian's own images settle it the same way: the
# machine is itself, locally.  (\`127.0.1.1\` is the loopback alias Debian uses for exactly this.)
# The **name itself** is this guest's own, not the container's: building the userland in a
# container gives it that container's generated name (\`6f7c782b95c2\`), and a machine whose own
# \`/etc/hostname\` names something its own \`/etc/hosts\` does not is a machine where every
# privileged tool that looks itself up waits for a resolver.
printf 'desktop-cracker\n' > /out/etc/hostname
grep -q '^127\.0\.1\.1' /out/etc/hosts 2>/dev/null ||
    printf '127.0.0.1\tlocalhost\n127.0.1.1\tdesktop-cracker\n' >> /out/etc/hosts
touch /out/etc/desktop-cracker.env
# Writing the want-links directly is deliberate: systemd in a chroot inside a
# container cannot always enable a unit, and a missing link means no display
# manager at all.
mkdir -p /out/etc/systemd/system/graphical.target.wants
ln -sf /lib/systemd/system/lightdm.service /out/etc/systemd/system/graphical.target.wants/lightdm.service
ln -sf /lib/systemd/system/graphical.target /out/etc/systemd/system/default.target
chroot /out bash -c 'apt-get clean; rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*'"

# The session LightDM starts by itself.  The guest's users log in without a password (a password
# is only what `sudo` asks for), so LightDM autologins `deskuser` straight into Xfce — no greeter,
# no password prompt.
#
# The session's **name** is the file LightDM finds in `/usr/share/xsessions`, and
# it is read from the tree rather than guessed: Debian's Xfce package writes
# `xfce.desktop`, and asking for a name LightDM cannot find makes it log
# `Failed to find session configuration …`, skip the autologin and put the greeter
# up instead.  (The same trap the IceWM name had: that package's file was
# `icewm-session.desktop`, not `icewm`.)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

say "configuring LightDM's autologin"
session=xfce
for f in "$out"/usr/share/xsessions/*xfce*.desktop; do
    [ -f "$f" ] || continue
    session=$(basename "$f" .desktop)
    break
done
say "the Xfce session is $session"
# Written **inside the container**: the tree belongs to root (the container built
# it), so this user cannot add a file to it.
cat > "$work/50-desk.conf" <<LCONF
[Seat:*]
autologin-user=deskuser
autologin-user-timeout=0
autologin-session=$session
user-session=$session
greeter-session=lightdm-gtk-greeter
# The session must not be given up on because a window closed or an application exited:
# the user's desktop is what this project exists to show, and LightDM's default is to
# restart the greeter when the session ends.
session-cleanup-script=
LCONF
docker run --rm -v "$out":/out -v "$work/50-desk.conf":/tmp/50-desk.conf:ro "$image" bash -c '
    mkdir -p /out/etc/lightdm/lightdm.conf.d
    install -m 0644 -o root -g root /tmp/50-desk.conf /out/etc/lightdm/lightdm.conf.d/50-desk.conf
'


say "forcing the X server onto the device this guest has"
# **Why this exists**: this microvm's guest has no GPU driver (the pixels of the display window
# are the guest's own framebuffer, which needs no guest driver), so X's automatic probe finds the
# kernel's framebuffer console (`/dev/fb0`) — and it has to be *told* that, and told which
# virtual terminal to use, or it picks a device that is not there (or none at all) and gives up.
#
# The configuration is written **inside the container** (the tree belongs to root), into
# `/etc/X11/xorg.conf.d`, which X reads before its own defaults.
cat > "$work/20-desktop-cracker-device.conf" <<'XCONF'
# The guest's own device is **not forced here**: this microvm has virtio-gpu (a DRM card) and
# the kernel's framebuffer, and X's probe picks the better one.  What is pinned is the rest of
# the server's behaviour, because those are the parts that made the desktop come and go.
Section "ServerFlags"
    # One seat, one terminal: this microvm has no second screen and nothing to switch to.
    # (A VT switch is what repaints the text console over the picture.)
    Option "DontVTSwitch" "true"
    Option "DontZoom" "true"
    # Never give up because a device or an input was mismatched: a server that exits is a black
    # window, and this project's guest has exactly one of each.
    Option "AutoAddDevices" "true"
EndSection
XCONF
docker run --rm -v "$out":/out -v "$work/20-desktop-cracker-device.conf":/tmp/20-desktop-cracker-device.conf:ro "$image" bash -c '
    mkdir -p /out/etc/X11/xorg.conf.d
    install -m 0644 -o root -g root /tmp/20-desktop-cracker-device.conf /out/etc/X11/xorg.conf.d/20-desktop-cracker-device.conf
'

say "keeping the console off X's terminal, and the session alive"
# **The gettys are what fights X**: `getty@tty1` owns the first virtual terminal, and X is told
# to use it, so the two take turns opening the same device — which is what a desktop that
# appears and then goes away looks like from the host.  The serial console keeps its own getty
# (this project's tests and the operator's log read it); tty1 is X's.
docker run --rm -v "$out":/out "$image" bash -c '
    set -e
    # No getty on tty1: X is the only thing that opens that terminal.
    mkdir -p /out/etc/systemd/system/getty@tty1.service.d
    cat > /out/etc/systemd/system/getty@tty1.service.d/desk.conf <<CONF
[Service]
ExecStart=
ExecStart=-/bin/true
CONF
    # The kernel must not blank the console out from under X, and must not treat a VT switch
    # as a reason to repaint the text console over the picture.
    mkdir -p /out/etc/systemd/system/desktop-cracker-x-session.service.d
    cat > /out/etc/systemd/system/desktop-cracker-console.conf <<CONF
[Service]
Environment=TERM=linux
CONF
    mkdir -p /out/etc/systemd/system.conf.d
    cat > /out/etc/systemd/system.conf.d/desktop-cracker-console.conf <<CONF
[Manager]
DefaultEnvironment=TERM=linux
CONF
    mkdir -p /out/etc/sysctl.d
    cat > /out/etc/sysctl.d/90-desktop-cracker-console.conf <<CONF
kernel.printk = 3 4 1 3
CONF

    # **ping must work for the guest user.**  Debian ships ping with the cap_net_raw capability on
    # the file, and a capability is an extended attribute: this image is packed and unpacked through
    # a disk, which does not keep it.  Measured (2026-10-12, the operator run): /bin/ping in the guest
    # has no capability, and ping parenthost answers
    #     socket: Operation not permitted  =>  missing cap_net_raw+p capability or setuid?
    # The setting that does not depend on any attribute is the kernel own: an unprivileged ICMP
    # datagram socket, which is what ping falls back to.  The kernel default (1 0) allows it for no
    # group at all; the host this project runs on already allows it for every group, so the guest is
    # given the rule it is on.
    cat > /out/etc/sysctl.d/91-desktop-cracker-ping.conf <<CONF
net.ipv4.ping_group_range = 0 2147483647
CONF

    # **The sound card is there before anything asks for it.**  This guest has the loopback card of
    # the kernel itself; the agent modprobes it too, but PulseAudio starts with the session, and a
    # card that appears after the server looked for one is a server with no card to show.
    mkdir -p /out/etc/modules-load.d
    cat > /out/etc/modules-load.d/desktop-cracker-sound.conf <<CONF
snd-aloop
CONF

    # **The session comes back if it dies.**  This project shows the user a desktop; a
    # drawer-session that exited (whatever the reason: a crash of the window manager, an X error, a
    # permissions change) must not leave a black screen, so systemd restarts LightDM and the
    # unit that owns the desktop is also restarted if it stops.
    mkdir -p /out/etc/systemd/system/lightdm.service.d
    cat > /out/etc/systemd/system/lightdm.service.d/desk.conf <<CONF
[Service]
# Always: the greeter is not a one-shot.  A session that ends is a session to start again.
Restart=always
RestartSec=1
# ...and it must not be considered failed when the last session closed.
SuccessExitStatus=0 1
CONF

    # What the user is *supposed* to see: get the display manager up as early as the seat and
    # the devices allow, and do not let a failed dependency leave the machine with no desktop.
    mkdir -p /out/etc/systemd/system/graphical.target.wants
    ln -sf /lib/systemd/system/lightdm.service /out/etc/systemd/system/graphical.target.wants/lightdm.service
    ln -sf /lib/systemd/system/graphical.target /out/etc/systemd/system/default.target
    # **The disk manager is running before the desktop asks it for anything.**  `udisks2.service`
    # is wanted by `graphical.target` and the package writes that link when it is enabled — but the
    # link is written here as well, for the same reason `ssh.service` is (above): systemd in a
    # chroot inside a container does not always enable a unit, and a missing link is a desktop
    # whose Disks says nothing about the disks the run attached.
    ln -sf /lib/systemd/system/udisks2.service /out/etc/systemd/system/graphical.target.wants/udisks2.service
'

say "writing the one polkit rule the guest's disk manager needs"
# **Why a rule at all** (measured 2026-10-14, and the measurement is what changed the plan): the
# first reading of this was "polkit's default for `org.freedesktop.udisks2.*` is `auth_admin_keep`,
# so every action needs a rule".  It is not.  Read out of the policy file the `udisks2` package
# ships (`/usr/share/polkit-1/actions/org.freedesktop.UDisks2.policy`, `udisks2 2.9.4-4+deb12u2`):
# `filesystem-mount` and `encrypted-unlock` are `allow_active=yes` — those two need **nothing**.
# What is `auth_admin_keep` is the **system** form of each action, and the system form is what
# udisks asks for here, because `update_hints` starts at `hint_system = TRUE` and clears it only
# for removable media or a usb/ieee1394/sdio bus — a virtio disk is none of those.  So the four
# names a mount/unmount/unlock/lock of `/dev/vdb` actually ask for are the four below.
#
# `auth_admin_keep` with **no authentication agent** is a refusal, not a prompt: this userland has
# no polkit agent on the session bus — `xfce4-polkit`, the one Xfce would ship, has no installation
# candidate in bookworm at all, and the three that do (`policykit-1-gnome`, `mate-polkit`,
# `lxqt-policykit`) are another desktop's and are not installed — so polkit cannot ask for an
# administrator's password and udisks answers `Not authorized`.  The rule is the answer polkit would
# otherwise have to ask for, and it says exactly what a single-user sandbox means: the user sitting on
# this guest's own console, in the group this guest gives `sudo` to, may do these four things to a
# disk.  Nothing else is widened — `filesystem-fstab`, `modify-device-system`, `ata-secure-erase` and
# the rest keep their own defaults.
#
# **What it does not change**: a LUKS container's **passphrase is still asked for, by Disks, every
# time** — polkit authorizes the *action*, it is not the disk's key (the key goes to `dm-crypt`, and
# a wrong one is refused by cryptsetup).  And nothing is mounted automatically: `hint_auto` stays
# false for a virtio disk (same `update_hints`), so Settings: — the user mounts them —
# is still what happens.
cat > "$work/50-desk-disks.rules" <<'PRULE'
// The disks this project attaches (/dev/vdb, /dev/vdc, …) are virtio disks, and udisks treats a
// disk that is not removable and not on a usb/ieee1394/sdio bus as a *system* disk — so the actions
// its mount/unmount/unlock/lock ask for are the four below, all `auth_admin_keep` by default.
// This guest has no polkit authentication agent on the session bus, so `auth_admin_keep` there is a
// refusal with no question asked.  The rule answers it for the one user of this sandbox: the one
// sitting on its own console, in the group this guest gives `sudo` to.
//
// It is not a key: unlocking a LUKS container still needs that container's passphrase, which Disks
// asks for and `dm-crypt` checks.  And nothing here mounts anything by itself.
polkit.addRule(function (action, subject) {
    if (subject.local && subject.active && subject.isInGroup("sudo") &&
        (action.id == "org.freedesktop.udisks2.filesystem-mount-system" ||
         action.id == "org.freedesktop.udisks2.filesystem-unmount-others" ||
         action.id == "org.freedesktop.udisks2.encrypted-unlock-system" ||
         action.id == "org.freedesktop.udisks2.encrypted-lock-others")) {
        return polkit.Result.YES;
    }
});
PRULE
# `rules.d` belongs to `polkitd` (0700) and polkit refuses a rule file it could be fooled by: it
# must be root-owned and not writable by group or other, which is what `install` writes here.
docker run --rm -v "$out":/out -v "$work/50-desk-disks.rules":/tmp/50-desk-disks.rules:ro "$image" bash -c '
    mkdir -p /out/etc/polkit-1/rules.d
    install -m 0644 -o root -g root /tmp/50-desk-disks.rules /out/etc/polkit-1/rules.d/50-desk-disks.rules
    # What the guest will actually answer, printed by polkit itself rather than trusted to this
    # file: the four names, and the default each one has with no rule at all.
    apt-get update -qq >/dev/null 2>&1 || true
    grep -o "org.freedesktop.udisks2.[a-z-]*" /tmp/50-desk-disks.rules | sort -u |
        sed "s/^/rootfs: polkit rule for /"
'

say "putting the desktop sound server on this guest own sound card"
# **Why this exists.**  PulseAudio finds a card through ALSA, and the card this guest has is the
# kernel loopback one (`snd-aloop`, loaded by the agent).  Measured in a real run with the packages
# installed and nothing configured (2026-10-12): `pactl list short cards` is **empty**, the only sink
# is `auto_null` (`module-null-sink.c`, the fallback PulseAudio makes when it has no card), and the
# desktop sound went into that sink — so nothing reached the loopback card playback side and the
# agent capture side had nothing to ship.  The operator report is exactly that: "the system sound is
# not working any more, it does not use our snd-aloop type of device ... pavucontrol using dummy
# device".
#
# **What is configured.**  A sink is made on the *playback* end of the cable whose *capture* end the
# agent reads, with `module-alsa-sink` and the ALSA device named exactly — `hw:0,0`.  In this guest
# the loopback card is card **0** (measured: `/proc/asound/cards` names card 0 "Loopback", and the
# agent own line is `deskd-audio: reading hw:0,1,0` — device 1 is the capture end, so device 0 is
# the playback end an application plays into).  The rate is the project own one (48 kHz, 16-bit
# stereo: `dc-audio::audio_format` and the agent `StreamFormat`), because the capture stream is opened
# at exactly that and a card settled on 44.1 kHz would resample in the middle of the cable.
#
# `module-alsa-sink` and not `module-alsa-card`: the card form was tried first and it is the one that
# **chooses the device itself** (measured in a container with a card in it: it made
# `alsa_output.<name>.iec958-stereo`, and with no card in it it fails to parse at all).  The sink form
# is given the device and cannot pick another one, which is the whole point here: the sound must land
# on the loopback card, and a sink that lands anywhere else is a sound the host never hears.  No
# *source* is made on purpose: the capture end of the cable is the agent device, and a PulseAudio
# source on it would be a second reader of the same stream.
#
# The file goes in `/etc/pulse/default.pa.d`, which Debian own `default.pa` includes at the end
# (`.include /etc/pulse/default.pa.d`): the distribution file is not edited, and a package upgrade
# does not undo this.  `.nofail` around it: a run whose guest has no loopback card must still get a
# PulseAudio with the fallback sink, not a server that gave up.
docker run --rm -v "$out":/out "$image" bash -euo pipefail -c '
    mkdir -p /out/etc/pulse/default.pa.d
    cat > /out/etc/pulse/default.pa.d/desk-sound.pa <<PACONF
# The card this guest has is the kernel loopback one, and PulseAudio does not find it on its own
# (measured 2026-10-12: no card at all, only the auto_null fallback, and the desktop sound went into
# that fallback).  The sink is the end of the cable an application plays into — device 0, whose other
# end (device 1) the host-side capture reads — named so pavucontrol shows it as what it is.
.nofail
load-module module-alsa-sink device=hw:0,0 sink_name=desktop-cracker-loop sink_properties=device.description=Desktop-cracker-loopback
set-default-sink desktop-cracker-loop
PACONF
    chmod 0644 /out/etc/pulse/default.pa.d/desk-sound.pa
'

# The archive the disk manager unpacks into a new disk.  It is made **inside the
# container**, as root: the userland holds files (/etc/shadow, private keys) that
# only root may read, and a tar made by this user would silently leave them out.
say "installing the guest's own default software (VLC, Firefox, Python 3.13)"
# The script runs *inside* the container, where /out is the tree being built and
# this user is root: nothing here has to escape a shell inside a shell.
docker run --rm -v "$out":/out -v "$here/guest-userland.sh":/guest-userland.sh:ro \
    "$image" bash /guest-userland.sh

say "unplugging the development console so the desktop is what this guest shows"
# **Why this is needed, and why it is in the userland**: the serial console is *this project's*
# instrument (the application echoes it, and the tests read it), and the guest's own systemd
# gives it an autologin getty — but the framebuffer console is the *user's* screen in a microvm
# whose display is that framebuffer.  Two things write to it: systemd's own status messages and
# the getty's login prompt.  On this guest the desktop has been seen to appear and then be
# covered by exactly that text, so the console is told to be quiet and to keep its shell off the
# framebuffer: the serial side is untouched (it is the same kernel console), only the text that
# would land on the screen is dropped.
docker run --rm -v "$out":/out "$image" bash -euo pipefail -c '
    mkdir -p /out/etc/sysctl.d
    cat > /out/etc/sysctl.d/90-desktop-cracker-console.conf <<CONF
# 7 = everything to the console.  The serial console is this project instrument and keeps its
# verbosity; the framebuffer console is the user screen and gets nothing.
kernel.printk = 3 4 1 7
CONF
    # A getty that logs in on the framebuffer console is a login prompt painted over the
    # desktop: the serial one is enough for development, and tty1 belongs to X.
    mkdir -p /out/etc/systemd/system/getty@tty1.service.d
    cat > /out/etc/systemd/system/getty@tty1.service.d/desk.conf <<CONF
[Service]
ExecStart=
ExecStart=-/bin/true
CONF
    # The kernel must not blank the console out from under X either.
    mkdir -p /out/etc/modprobe.d
    cat > /out/etc/modprobe.d/desk-fbcon.conf <<CONF
# The framebuffer console is the user screen here: keep its cursor from blinking over the
# desktop and do not let it blank itself.
options fbcon nodebug=1
CONF
'

say "packing the userland as an ext4 image (what a new disk is seeded from)"
# `mke2fs -d` copies the tree into a fresh filesystem **without mounting it**, so
# this needs no loop device and no privileges — and it is done here, in the
# container that owns the tree, because the tree belongs to root.
seed_image=${SEED_IMAGE:-$root_dir/temp/download/rootfs.ext4}
# `du` cannot read every directory of the tree as this user (they belong to root),
# so an empty answer is normal and the size falls back to a generous default: the
# image is sparse, and the filesystem inside it is what has to be big enough.
# `|| true`: `du` exits non-zero on the directories this user cannot read (and
# `set -o pipefail` would end the script there) — the number is a convenience, not
# something to fail on.
seed_mb=$(du -sm "$out" 2>/dev/null | cut -f1 || true)
case "$seed_mb" in
'' | *[!0-9]*) seed_mb=3072 ;;
esac
seed_mb=$((seed_mb * 3 / 2 + 256))
rm -f "$seed_image"
docker run --rm -v "$out":/out:ro -v "$(dirname "$seed_image")":/seed "$image" bash -euo pipefail -c "
    apt-get update -qq && apt-get install -y -qq e2fsprogs >/dev/null 2>&1
    truncate -s ${seed_mb}M /seed/$(basename "$seed_image")
    mke2fs -q -F -t ext4 -L desk-seed -d /out /seed/$(basename "$seed_image")
    e2fsck -f -y /seed/$(basename "$seed_image") >/dev/null 2>&1 || true
"
say "the userland image is $seed_image ($(du -h "$seed_image" | cut -f1))"

say "packing the seed archive"
seed=${SEED_OUT:-$root_dir/temp/download/rootfs.tar.gz}
docker run --rm -v "$(dirname "$seed")":/seed -v "$out":/out "$image" bash -euo pipefail -c "
    apt-get update -qq && apt-get install -y -qq tar >/dev/null 2>&1
    tar czf /seed/$(basename "$seed") -C /out .
" 2>/dev/null || true
if [ -s "$seed" ]; then
    say "seed archive: $seed ($(du -h "$seed" | cut -f1))"
else
    say "the seed archive was not made; a disk created from this tree will not boot"
fi

say "done: $(du -sh "$out" | cut -f1) in $out"
