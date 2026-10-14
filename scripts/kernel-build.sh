#!/bin/bash
# Build the **guest kernel** for the Firecracker microvm.
#
# Why this exists, in one paragraph: the project's guest boots a kernel, and Firecracker's
# x86_64 platform has **no CMOS RTC** — a distribution kernel spends ~540 ms of its boot
# probing for one (measured). A kernel built from the
# configurations the Firecracker project itself validates has `# CONFIG_RTC_CLASS is not
# set`, and the same guest then reaches its landmark in **~450 ms instead of ~1.0 s**.  The
# same kernel is also where this project's guest-side pieces live: the guest's network
# is a **TUN** (`CONFIG_TUN=y`) created inside the guest and, later, the display's
# framebuffer driver is a module built with this kernel.
#
# So the kernel is built **here**, from Firecracker's own `guest_configs`, with the options
# this project's guest needs — and the build is reproducible: same source version, same
# config, one patch of our own (below), and the kernel's local version says so
# (`6.1.189-desktop-cracker`), so a guest that boots it can be identified from its own console.
#
#   ./build-kernel.sh                  # build (reuses a source tree and a build in temp/)
#   ./build-kernel.sh --clean          # start the build from scratch
#   ./build-kernel.sh --jobs 24
#
# What it needs on the host, and it **never installs anything** (the project's rule: what a
# host needs is reported, and installing is the user's call — `AGENTS.md`):
#
#   gcc make bc flex bison libelf-dev xz cpio
#     Debian/Ubuntu:  sudo apt-get install -y build-essential flex bison libelf-dev bc \
#                         libssl-dev xz-utils cpio
#
# flex, bison and libelf's headers are also looked for in `$HOME/.local` (where a host that
# cannot install packages can put them: flex and bison build from source in a minute, and
# `elfutils`' `libelf.h`/`libelf.so` are enough for `objtool`).
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
# **The guest's C lives under `desktop-cracker/`** (the source); the kernel this script builds goes to
# `temp/download/`, beside the initramfs and the hypervisor a run boots with.
#
# **Where the configuration comes from.**  Firecracker's own `guest_configs` are the base this
# guest's `.config` is built on, and mixing one release's config with another's source is how a
# kernel ends up with options nobody validated.  The copy that travels with this tree is
# `guest-kernel/config-x86_64` — a checkout of Firecracker is **not** needed to build the guest's
# kernel; naming one is only how the base is taken from a newer release:
#
#   FIRECRACKER_DIR=/path/to/firecracker   take the base from that checkout
#   KERNEL_CONFIG=/path/to/file            use that configuration file instead
firecracker=${FIRECRACKER_DIR:-}
config_source=${KERNEL_CONFIG:-}
if [ -z "$config_source" ]; then
    if [ -n "$firecracker" ]; then
        config_source=$firecracker/resources/guest_configs/microvm-kernel-ci-x86_64-6.1.config
    else
        config_source=$root/desktop-cracker/guest-kernel/config-x86_64
    fi
fi

# The source version.  It is the 6.1 series Firecracker's policy supports, and the number is
# pinned rather than "latest" so that two builds of this project produce the same kernel.
version=${KERNEL_VERSION:-6.1.189}
work=${KERNEL_BUILD_DIR:-$root/temp/kernel-build}
# Where the kernel is kept: **`temp/download/`**, where everything a run needs lives (the scratch
# folder, never committed) — the same place `make download` fetches and `make run` reads.
out=$root/temp/download
jobs=${KERNEL_JOBS:-$(nproc)}

say() { printf 'build-kernel: %s\n' "$*"; }
die() { printf 'build-kernel: %s\n' "$*" >&2; exit 1; }

clean=0
while [ $# -gt 0 ]; do
    case "$1" in
        --clean) clean=1 ;;
        --jobs) shift; jobs=${1:?--jobs needs a number} ;;
        -h|--help) sed -n '2,40p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown argument $1" ;;
    esac
    shift
done

# A host that cannot install packages can be told where its tools are.
if [ -d "$HOME/.local/bin" ]; then
    PATH="$HOME/.local/bin:$PATH"
fi
export PATH
export HOSTCFLAGS="-I$HOME/.local/include ${HOSTCFLAGS:-}"
export HOSTLDFLAGS="-L$HOME/.local/lib -Wl,-rpath,$HOME/.local/lib ${HOSTLDFLAGS:-}"

# What the build needs.  Reported, never installed: the line a person would run is printed.
missing=""
for tool in gcc make bc flex bison xz cpio; do
    command -v "$tool" >/dev/null 2>&1 || missing="$missing $tool"
done
[ -f "$HOME/.local/include/libelf.h" ] || [ -f /usr/include/libelf.h ] || missing="$missing libelf-dev"
if [ -n "$missing" ]; then
    say "missing on this host:$missing"
    say "install them with:"
    say "  sudo apt-get install -y build-essential flex bison libelf-dev bc libssl-dev xz-utils cpio"
    say "(or, without root: build flex and bison from source into \$HOME/.local, and put"
    say " elfutils' libelf.h and libelf.so there too — which is what this project did on"
    say " the host this project was measured on)"
    exit 2
fi

[ -r "$config_source" ] || die "Firecracker's guest config is not readable: $config_source
  (set FIRECRACKER_DIR to the Firecracker tree, or KERNEL_CONFIG to a config file)"

mkdir -p "$work" "$out"
cd "$work"

tarball="linux-$version.tar.xz"
if [ ! -f "$tarball" ]; then
    say "downloading $tarball"
    curl -fL --retry 3 -o "$tarball" \
        "https://cdn.kernel.org/pub/linux/kernel/v6.x/$tarball" ||
        die "cannot download $tarball (is this host on the network?)"
fi

if [ "$clean" = 1 ]; then
    say "starting from scratch (--clean)"
    rm -rf "linux-$version"
fi

if [ ! -d "linux-$version" ]; then
    say "extracting $tarball"
    tar xf "$tarball"
fi

cd "linux-$version"

# **This project's own framebuffer**, put into the kernel's tree where the kernel's own build
# system expects it: the module (`guest-kernel/`), the option that selects it (its `Kconfig`,
# sourced from the framebuffer menu) and its `Makefile`.  It is copied rather than built
# out-of-tree because the module that ships has to be built by the same `make modules` as every
# other one — one build, one module tree, nothing to keep in step — and because the kernel's own
# configuration is then the place the choice is made.
guest_kernel="$root/desktop-cracker/guest-kernel"
[ -d "$guest_kernel" ] || die "the framebuffer module is not at $guest_kernel"
mkdir -p drivers/video/desk_fb
cp "$guest_kernel/desk_fb.c" "$guest_kernel/desk_fb.h" "$guest_kernel/Makefile" \
   drivers/video/desk_fb/
cp "$guest_kernel/Kconfig" drivers/video/desk_fb/Kconfig
# The two lines that make the kernel's build find it: the menu entry, and the module.  Both are
# idempotent, so a tree that was prepared once is not prepared into something else.
grep -q "desk_fb/Kconfig" drivers/video/Kconfig ||
    printf '\nsource "drivers/video/desk_fb/Kconfig"\n' >> drivers/video/Kconfig
grep -q "desk_fb/" drivers/video/Makefile ||
    printf '\nobj-$(CONFIG_DESK_FB) += desk_fb/\n' >> drivers/video/Makefile
say "the framebuffer module is in the tree: $(ls drivers/video/desk_fb | tr '\n' ' ')"

# The configuration: Firecracker's own, plus the departures in `kernel-options.sh`.  That
# file is the list and the reason for each one; this is what turns it into a `.config`.
config_stamp="$work/.config-$version"
if [ ! -f "$config_stamp" ] || [ "$config_source" -nt "$config_stamp" ] \
    || [ "$here/kernel-options.sh" -nt "$config_stamp" ] \
    || [ "$guest_kernel/Kconfig" -nt "$config_stamp" ]; then
    say "the configuration: $(basename "$config_source") + kernel-options.sh"
    cp "$config_source" .config
    # shellcheck source=kernel-options.sh
    . "$here/kernel-options.sh"
    for entry in "${DESK_KERNEL_OPTIONS[@]}"; do
        # `--enable` is built-in (`=y`), `--module` is loadable (`=m`) — and the list says
        # which it wants: `CONFIG_FB`, or `m:CONFIG_DRM_VKMS` for a driver the guest loads
        # at run time (the same way this project's own framebuffer driver is one).
        case "$entry" in
            m:*) scripts/config --file .config --module "${entry#m:}" ;;
            \*:*) scripts/config --file .config --enable "${entry#*:}" ;;
            *) scripts/config --file .config --enable "$entry" ;;
        esac
    done
    # The local version, so a guest says which kernel it is on its own console.
    scripts/config --file .config --set-str LOCALVERSION "-desktop-cracker"
    make olddefconfig >/dev/null
    cp .config "$config_stamp"
fi

# Proof, not hope: every option the list asked for really is set.  `olddefconfig` can drop
# one whose dependencies are not met, and a `=y` that silently became "not set" is a guest
# feature that fails in the guest, at run time, far from here.
. "$here/kernel-options.sh"
for entry in "${DESK_KERNEL_OPTIONS[@]}"; do
    case "$entry" in
        m:*)  option=${entry#m:}; want="a module"
              grep -qE "^$option=(y|m)" .config || die "$option was asked for as $want and is not set" ;;
        \*:*) option=${entry#*:}; want="set"
              grep -qE "^$option=(y|m)" .config || die "$option was asked for and is not set" ;;
        *)    option=$entry; want="built in"
              grep -q "^$option=y" .config || die "$option was asked for as $want and is not =y" ;;
    esac
done

# What Firecracker's own configuration already guarantees and this project relies on.
for option in CONFIG_VIRTIO_VSOCKETS CONFIG_VIRTIO_BALLOON CONFIG_FUSE_FS \
              CONFIG_VIRTIO_BLK CONFIG_SERIAL_8250_CONSOLE CONFIG_BLK_DEV_INITRD; do
    grep -q "^$option=y" .config || die "$option is not =y in the resolved config"
done

say "building vmlinux with $jobs job(s)"
make -j"$jobs" vmlinux

[ -x vmlinux ] || die "the build produced no vmlinux"
install -m 0644 vmlinux "$out/kernel"
say "$(du -h "$out/kernel" | cut -f1) $out/kernel ($(make -s kernelrelease 2>/dev/null || echo "$version"))"

# And the **modules** the guest loads at run time (the framebuffer, the sound card, the
# agent's own tools — see `kernel-options.sh`).  They are installed into this tree's own
# module directory, which is what `make guest-image` packs into the initramfs; a kernel
# whose modules are not there is a guest whose devices never appear, and it says so only on
# its own console.
say "building the modules with $jobs job(s)"
make -j"$jobs" modules >/dev/null
moddir="$out/modules/$version-desktop-cracker"
rm -rf "$moddir"
make -s modules_install INSTALL_MOD_PATH="$out/modules" >/dev/null
# `modules_install` names the directory after the kernel's own release.
built=$(ls -1 "$out/modules/lib/modules" 2>/dev/null | head -1)
[ -n "$built" ] || die "the build produced no modules"
rm -rf "$moddir"
mkdir -p "$out/modules"
mv "$out/modules/lib/modules/$built" "$moddir"
rm -rf "$out/modules/lib"
say "$(find "$moddir" -name '*.ko' | wc -l) module(s) in $moddir"
