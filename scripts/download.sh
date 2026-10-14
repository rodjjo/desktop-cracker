#!/bin/bash
# make download — put everything the microVM needs to run into temp/download/
#
# download/kernel          the guest's kernel (this project's own build)
# download/initramfs.gz    the guest's initramfs (this project's own build)
# download/base.qcow2      Debian's own cloud image: the base the guest's userland
#                          image (`make rootfs`) is built from
#   download/firecracker                  the hypervisor every run uses (a released binary)
#   download/README                       where each came from
#
# Everything is skipped when it is already there and current, so `make download`
# is cheap to re-run.  Nothing here needs root.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
# **Everything the project fetches lives under `temp/`** (a scratch folder, never committed):
# `temp/download/` is what a run boots from.
dl="$root/temp/download"
mkdir -p "$dl"

DEBIAN_IMG_URL=${DEBIAN_IMG_URL:-https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-nocloud-amd64.qcow2}

say() { printf 'download: %s\n' "$*"; }

# ---------------------------------------------------------------- guest kernel
# **The kernel is this project's own build**, not the host's: Firecracker has no CMOS RTC and a
# distribution kernel spends ~1 s probing for one, where a kernel built for a microVM reaches the
# guest in ~450 ms (measured). `make build` (or `make
# guest-image`) builds it — `scripts/kernel-build.sh`, Firecracker's own guest
# configuration plus the options this guest needs.
kernel="$dl/kernel"
if [ -s "$kernel" ] && [ "$kernel" -nt "$root/scripts/kernel-options.sh" ]; then
    say "kernel already present ($(du -h "$kernel" | cut -f1))"
else
    say "kernel: building it from Firecracker's guest configuration"
    bash "$root/scripts/kernel-build.sh" || {
        echo "download: the kernel build failed; see scripts/kernel-build.sh" >&2
        exit 1
    }
fi

# ------------------------------------------------------------- guest base image
# The Debian **cloud image is the base** the guest's userland is made from: `tools/rootfs/build.sh`
# debootstraps the same release into `download/rootfs`, and `make rootfs` turns that into the image a
# disk is seeded from. A run boots **that** userland, from a raw disk of its own.
base="$dl/base.qcow2"
if [ -s "$base" ]; then
    say "base image already present ($(du -h "$base" | cut -f1))"
else
    say "base image: $DEBIAN_IMG_URL"
    curl -fL --progress-bar -o "$base.part" "$DEBIAN_IMG_URL"
    mv "$base.part" "$base"
    ls -l "$base" | awk '{print "base image: " $5 " bytes"}'
fi

# ------------------------------------------------------------------- firecracker
# **The hypervisor.**  Firecracker is a released binary (this project does not build a VMM), and a
# tree that already has one, or a
# `download/firecracker` from an earlier run — is left alone.
fc="$dl/firecracker"
if [ -x "$fc" ]; then
    say "firecracker already present ($("$fc" --version 2>/dev/null | head -1))"
elif [ -x "$root/temp/fc-study/bin/firecracker" ]; then
    cp "$root/temp/fc-study/bin/firecracker" "$fc"
    chmod +x "$fc"
    say "firecracker: the binary this project was measured with"
    "$fc" --version 2>/dev/null | head -1 || true
else
    say "firecracker: not here, and this tree has none"
    say "firecracker: fetch a release from https://github.com/firecracker-microvm/firecracker/releases"
    say "firecracker: and put the binary at $fc (see README.md)"
fi

# ------------------------------------------------------------------------ README
# Where each file came from, in the folder itself.
cat > "$dl/README" <<EOF
Everything in this folder is what a run needs from outside the source tree.  Nothing here is
committed (see .gitignore): \`make download\` fetches or builds it again.

| what | how it got here |
|---|---|
| \`kernel\` | **this project's own build** (\`scripts/kernel-build.sh\`: Firecracker's guest configuration plus the options this guest needs).  A kernel built for a microVM reaches the guest in ~450 ms; a distribution kernel takes ~1 s probing hardware Firecracker does not have. |
| \`initramfs.gz\` | **this project's own build** (\`make guest-image\`): the project's initramfs plus the framebuffer module, the guest tools and the guest agent. |
| \`firecracker\` | the hypervisor, a released binary: <https://github.com/firecracker-microvm/firecracker/releases> |
| \`base.qcow2\` | Debian 12's own cloud image ($DEBIAN_IMG_URL) — the base the guest's userland is built from by `make rootfs`. |

The guest's userland (\`rootfs\`, \`rootfs.ext4\`) comes from \`make rootfs\`, and the disks in
\`temp/\` from \`desk-disk\` (\`make rootdisk\`).
EOF
say "README written"


