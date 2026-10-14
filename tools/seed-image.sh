#!/bin/bash
# Build the **seed image**: the project's own userland, as a plain ext4 file the job's guest
# mounts read-only and copies into the new disk's root filesystem.
#
# `dc-disk-manager`’s job owns this step (`DiskJob::prepare_seed_image`), and it
# is the same trick here: a few hundred megabytes through a share is minutes, while one block
# device copied to another is what a disk controller is for.  The image is built with
# `mkfs.ext4 -d`, so nothing is mounted anywhere and the host needs no privilege for it.
#
#   ./tools/seed-image.sh ../temp/download/rootfs ../temp/seed.raw 1800
set -euo pipefail
src=${1:?usage: seed-image.sh <userland-dir> <out.raw> [size-MiB]}
out=${2:?usage: seed-image.sh <userland-dir> <out.raw> [size-MiB]}
size_mib=${3:-1800}

say() { printf 'seed-image: %s\n' "$*"; }
[ -d "$src" ] || { say "$src is not a directory"; exit 2; }
mkdir -p "$(dirname "$out")"
src=$(cd "$src" && pwd)
out_dir=$(cd "$(dirname "$out")" && pwd)
out_name=$(basename "$out")
rm -f "$out_dir/$out_name"

say "building a ${size_mib} MiB ext4 from $src"
timeout 900 docker run --rm --privileged \
    -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" -e OUT="$out_name" -e SIZE_MIB="$size_mib" \
    -v "$src:/src:ro" -v "$out_dir:/out" debian:12 bash -c '
    set -e
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq >/dev/null 2>&1
    apt-get install -y -qq e2fsprogs >/dev/null 2>&1
    truncate -s "${SIZE_MIB}M" "/out/$OUT"
    mkfs.ext4 -q -F -L desk-seed -d /src "/out/$OUT"
    chown "$HOST_UID:$HOST_GID" "/out/$OUT"
' >/dev/null
ls -l "$out"
say "$(du -h "$out" | cut -f1) (apparent $(du -h --apparent-size "$out" | cut -f1))"
