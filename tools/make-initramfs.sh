#!/bin/bash
# Build **this project's own guest initramfs**: the project's initramfs (`tools/guest-image`)
# with this tree's kernel modules, and with the guest agent wired into its init.
#
# Why this exists: the kernel built by `scripts/build-kernel.sh` is not the host's, so the
# modules the guest's devices need are not in `/lib/modules` either.  The project's own
# builder takes a `MODULE_DIR`/`KERNEL_RELEASE` pair for exactly this, so the initramfs is
# the project's — one builder, one behaviour — and what this script adds is the two things
# this project changed:
#
#   0. **the guest tools**, built from the project's own source (`tools/guest-tools.sh`): the
#      one function that differs is how a shared folder is mounted;
#   1. **the modules of the kernel this tree builds** (`temp/download/modules/<release>`), which
#      is what makes the guest's own framebuffer and sound card exist at all
#      (`scripts/guest-modules.sh` lists them, and why);
#   2. **the guest agent** (`guest-agent-rs/`), which is the guest half of the readiness, network
#      and control channels — and, for the *unchanged* parts (the mounts, `rootboot`, the
#      desktop session), nothing at all: those are the project's own `guest-tools`, exactly
#      as the project's own init does.
#
#   ./tools/make-initramfs.sh                  # -> desktop-cracker/guest-agent-rs/out/initramfs.gz
#   ./tools/make-initramfs.sh --out OTHER.gz
#
# The second point is what keeps this honest: `tools/guest-image/build.sh` is the project's
# file and stays unmodified; the agent is added *after* it, by `guest-agent-rs/make-agent.sh`,
# which patches the init's last lines (idempotently) to bring the channels up and then run
# the project's own `guest-tools boot`.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
# **The guest's agent lives under `desktop-cracker/`**; the tools that build the guest's media are here.
hs="$root/desktop-cracker"

agent="$hs/guest-agent-rs/make-agent.sh"
out="$hs/guest-agent-rs/out/initramfs.gz"
modules="$root/temp/download/modules"
kernel="$root/temp/download/kernel"

say() { printf 'make-initramfs: %s\n' "$*"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --out) out=${2:?--out needs a path}; shift ;;
        -h|--help) sed -n '2,26p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "make-initramfs: unknown argument $1" >&2; exit 2 ;;
    esac
    shift
done

[ -x "$root/tools/guest-image/build.sh" ] || {
    say "the project's own initramfs builder is not at $root/tools/guest-image/build.sh"
    exit 2
}
[ -s "$kernel" ] || { say "no kernel in $root/temp/download: run ./scripts/kernel-build.sh first"; exit 2; }
[ -d "$modules" ] || { say "no modules in $modules: run ./scripts/build-kernel.sh first"; exit 2; }

# The kernel's own release, as the guest will report it — read from the built kernel rather
# than guessed: `temp/download/modules/<release>` is what `build-kernel.sh` named it after.
release=$(ls -1 "$modules" | head -1)
[ -n "$release" ] || { say "no kernel release under $modules"; exit 2; }
say "the kernel this initramfs carries: $release"

# 1. The project's builder, with this kernel's modules.  Its output is a plain initramfs with
#    the guest tools, busybox, cryptsetup and the modules the guest's devices need.
project_out="$root/temp/download/initramfs-base.gz"
MODULE_DIR="$modules/$release" KERNEL_RELEASE="$release" \
    "$root/tools/guest-image/build.sh" "$project_out" >/dev/null
mkdir -p "$(dirname "$out")"
say "the project's initramfs: $(du -h "$project_out" | cut -f1)"

# 2. **This project's own modules**, on top of that list: the virtual display and
#    the loopback sound card — the two things Firecracker does not give the guest
#    (`scripts/guest-modules.sh` says which, and why).  The project's own list already covers
#    the disks, vsock, 9p and the input driver.
. "$root/scripts/guest-modules.sh"
extra=0
for entry in "${DESK_EXTRA_MODULES[@]}"; do
    rel=${entry%%:*}          # the path, up to the first colon
    src="$modules/$release/kernel/$rel"
    dst="$project_out.dir/lib/modules/$release/kernel/$rel"
    [ -f "$src" ] || continue
    extra=$((extra + 1))
done
if [ "$extra" -gt 0 ]; then
    say "unpacking the project's initramfs to add $extra module(s)"
    rm -rf "$project_out.dir"
    mkdir -p "$project_out.dir"
    ( cd "$project_out.dir" && zcat "$project_out" | cpio -idm --quiet )
    for entry in "${DESK_EXTRA_MODULES[@]}"; do
        rel=${entry%%:*}
        src="$modules/$release/kernel/$rel"
        [ -f "$src" ] || continue
        dst="$project_out.dir/lib/modules/$release/kernel/$rel"
        mkdir -p "$(dirname "$dst")"
        install -m 0644 "$src" "$dst"
    done
    # `depmod` writes the metadata `modprobe` reads; the guest's init `insmod`s by path, so
    # this is for the guest's own userland (the desktop's udev, an application's modprobe).
    if command -v depmod >/dev/null 2>&1; then
        depmod -b "$project_out.dir" "$release" 2>/dev/null || true
    fi
    ( cd "$project_out.dir" && find . -print0 | cpio -o -H newc --null --quiet | gzip -9 ) > "$project_out"
    rm -rf "$project_out.dir"
    say "the project's initramfs with the extra modules: $(du -h "$project_out" | cut -f1)"
fi

# 3. The **guest tools**: the project's own source with the one difference this path needs — a
#    shared folder is a FUSE mount here, not a 9P one (`tools/guest-tools.sh`).  Built before
#    the agent so `make-agent.sh` installs it in the same pass.
"$root/tools/guest-tools.sh" --out "$hs/guest-agent-rs/out/guest-tools" >/dev/null

# 4. The agent, and the init lines that bring the channels up.  `make-agent.sh` unpacks the
#    initramfs it is given, installs the agent **and the guest tools**, patches the init and
#    packs it again — so the initramfs it works on is the one that was just built.
GUEST_INITRAMFS="$project_out" AGENT_OUT="$out" "$agent" --initramfs >/dev/null
say "$(du -h "$out" | cut -f1) $out"
