#!/bin/bash
# Turn the guest userland (the folder `tools/rootfs/build.sh` produced) into the
# guest's **root disk**: a raw file holding an ext4 filesystem, optionally
# encrypted with LUKS (the root disk of the settings).
#
# tools/rootfs/mkdisk.sh <rootfs-dir> <out.raw> [size-in-GiB] [passphrase-file]
#
# With a passphrase file the container is LUKS-formatted (the guest unlocks it —
# the microvm does the decryption, never the host). Without one the disk is a
# plain ext4, which is what a test or a throwaway guest uses.
#
# The filesystem is built **without mounting anything**: `mkfs.ext4 -d <dir>`
# copies the directory into the new filesystem itself, so neither the host nor
# the container needs `mount` privileges for it.  The encryption is done by
# `cryptsetup` on the image itself — the same LUKS container the guest opens with
# its own cryptsetup.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root_dir=$(cd "$here/../.." && pwd)
src=${1:?usage: mkdisk.sh <rootfs-dir> <out.raw> [size-GiB] [passphrase-file]}
out=${2:?usage: mkdisk.sh <rootfs-dir> <out.raw> [size-GiB] [passphrase-file]}
size_gib=${3:-8}
pass_file=${4:-}

say() { printf 'mkdisk: %s\n' "$*"; }

[ -d "$src" ] || { echo "mkdisk: $src is not a directory (build the rootfs first)" >&2; exit 2; }
[ -n "$pass_file" ] && [ ! -s "$pass_file" ] && { echo "mkdisk: $pass_file is empty" >&2; exit 2; }

image=${ROOTFS_IMAGE:-debian:12}
# docker wants absolute paths for its bind mounts
src=$(cd "$src" && pwd)
out=$(mkdir -p "$(dirname "$out")" && cd "$(dirname "$out")" && pwd)/$(basename "$out")
[ -n "$pass_file" ] && pass_file=$(cd "$(dirname "$pass_file")" && pwd)/$(basename "$pass_file")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

raw="$work/root.raw"
say "building a ${size_gib} GiB ext4 from $src"
# The image is built on a **loop device** inside the container (privileged, so
# loop devices work there): that is what makes a *real* LUKS container possible —
# the filesystem goes inside the encrypted volume, not the other way round.
mount_opts="-v $work:/work -v $src:/src:ro"
[ -n "$pass_file" ] && mount_opts="$mount_opts -v $pass_file:/pass:ro"
docker run --rm --privileged $mount_opts "$image" bash -euo pipefail -c "
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq e2fsprogs cryptsetup util-linux >/dev/null 2>&1
    truncate -s ${size_gib}G /work/root.raw
    loop=\$(losetup -f --show /work/root.raw)
    echo \"mkdisk: loop device \$loop\"
    if [ -n '${pass_file}' ]; then
        cryptsetup luksFormat --type luks1 --batch-mode --key-file /pass \$loop
        cryptsetup luksOpen --key-file /pass \$loop desk-root
        target=/dev/mapper/desk-root
    else
        target=\$loop
    fi
    # -d copies the tree in without mounting anything
    mkfs.ext4 -q -F -L desk-root -d /src \$target
    if [ -n '${pass_file}' ]; then
        cryptsetup luksClose desk-root
    fi
    losetup -d \$loop
"

mkdir -p "$(dirname "$out")"
# **The disk this project makes is raw**: what a run attaches is the image itself, so that is
# exactly what is produced here — there is no wrapper to convert between.
say "done: $(du -h "$out" | cut -f1) in $out"
