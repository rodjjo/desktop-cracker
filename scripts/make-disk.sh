#!/bin/bash
# Build a disk **image** for this project's guest: a raw file, optionally a LUKS
# container, which is what Firecracker can attach.
#
# Why this is a container run: making a real LUKS container means a partition table, a
# filesystem and `cryptsetup` on a block device — and a *file* is not a block device until
# a loop device makes it one, which needs root. The host this project runs on has no
# root and no loop privileges (`tools/rootfs/mkdisk.sh` is the guest userland’s own
# own disks), so the work happens in a **privileged container**, where `losetup` works and
# nothing of the host is touched but the file's own directory.
#
#   ./make-disk.sh out/root.raw 6                  # 6 GiB raw file, LUKS, empty filesystem
#   ./make-disk.sh out/root.raw 6 --tree DIR       # ...with DIR copied into the ext4 inside
#   ./make-disk.sh out/data.raw 2 --plain          # a plain ext4, no container
#   ./make-disk.sh out/root.raw 6 --pass-file FILE # the container's own passphrase
#   ./make-disk.sh out/root.raw 6 --pass-file -   # ...read from standard input instead
#   ./make-disk.sh out/root.raw 6 --uuid           # print the container's UUID and stop
#
# The image is **raw**: Firecracker attaches raw images, so a disk here is a raw file — the
# bytes a disk is, with no wrapper around them.
#
# The image is handed back **owned by the user who asked for it**: a run attaches it
# read-write, and a file owned by root is a run that cannot start (`Permission denied`,
# measured 2026-10-09).
set -euo pipefail

image=${1:?usage: make-disk.sh <image.raw> <size-GiB> [--tree DIR] [--plain] [--pass-file FILE] [--uuid]}
size_gib=${2:?usage: make-disk.sh <image.raw> <size-GiB> [--tree DIR] [--plain] [--pass-file FILE] [--uuid]}
shift 2

tree=""
plain=0
uuid_only=0
pass_file=""
while [ $# -gt 0 ]; do
    case "$1" in
        --tree) tree=${2:?--tree needs a directory}; shift ;;
        --plain) plain=1 ;;
        --uuid) uuid_only=1 ;;
        --pass-file) pass_file=${2:?--pass-file needs a path}; shift ;;
        *) echo "make-disk: unknown argument $1" >&2; exit 2 ;;
    esac
    shift
done

say() { printf 'make-disk: %s\n' "$*"; }
command -v docker >/dev/null 2>&1 || {
    say "docker is not on this host; it is what makes a loop device available without root"
    exit 2
}
if [ -n "$tree" ]; then
    [ -d "$tree" ] || { say "$tree is not a directory" >&2; exit 2; }
    tree=$(cd "$tree" && pwd)
fi
# A passphrase is either a file the caller names or **standard input** (`-`), and the
# second shape is the one to reach for: it goes from the caller's pipe into this run's own
# scratch directory, and the trap takes it away with the rest (`AGENTS.md`: a credential
# lives in memory for as long as it is needed, and this script never leaves one on a disk).
pass_in_stdin=0
if [ "$pass_file" = "-" ]; then
    pass_in_stdin=1
    pass_file=""
elif [ -n "$pass_file" ]; then
    [ -s "$pass_file" ] || { say "$pass_file is empty (a key file with nothing in it is not a passphrase)" >&2; exit 2; }
    pass_file=$(cd "$(dirname "$pass_file")" && pwd)/$(basename "$pass_file")
fi

mkdir -p "$(dirname "$image")"
image=$(cd "$(dirname "$image")" && pwd)/$(basename "$image")
image_dir=$(dirname "$image")
image_name=$(basename "$image")

# The work itself, as a script the container runs: written out rather than inlined, because
# a script that has to be quoted twice is a script nobody can read — and this project already
# got that wrong once (a `chown` that expanded on the wrong side of the quotes).
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
if [ "$pass_in_stdin" = 1 ]; then
    # Read it once, here, and keep it only in this run's own scratch directory (mode 0600),
    # which the trap removes when the build ends.
    IFS= read -r passphrase || true
    printf '%s' "$passphrase" > "$work/pass"
    unset passphrase
    chmod 0600 "$work/pass"
    pass_file="$work/pass"
fi
cat > "$work/build.sh" <<'INNER'
#!/bin/bash
# Runs **inside the container**, as root, with the image directory at /out.
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null 2>&1
apt-get install -y -qq cryptsetup e2fsprogs util-linux >/dev/null 2>&1

image="/out/$IMAGE_NAME"
truncate -s "${SIZE_GIB}G" "$image"
loop=$(losetup -f --show "$image")
trap 'losetup -d "$loop" || true' EXIT

if [ "$PLAIN" = 1 ]; then
    target=$loop
else
    if [ -n "$PASS_FILE" ]; then
        cryptsetup luksFormat --type luks1 --batch-mode --key-file /pass "$loop"
        cryptsetup luksOpen --key-file /pass "$loop" desktop-cracker-root
    else
        # A throwaway passphrase, which is what a probe wants.  A real disk always gets one
        # from the caller — this script never invents a credential a person would rely on.
        head -c 32 /dev/urandom > /work/key
        cryptsetup luksFormat --type luks1 --batch-mode --key-file /work/key "$loop"
        cryptsetup luksOpen --key-file /work/key "$loop" desktop-cracker-root
    fi
    target=/dev/mapper/desktop-cracker-root
fi

if [ -d /src ]; then
    # -d copies a tree in without mounting anything.
    mkfs.ext4 -q -F -L desktop-cracker-root -d /src "$target"
else
    mkfs.ext4 -q -F -L desktop-cracker-root "$target"
fi
[ "$PLAIN" = 1 ] || cryptsetup close desktop-cracker-root
losetup -d "$loop"
trap - EXIT

# The image belongs to the user who asked for it.
chown "$HOST_UID:$HOST_GID" "$image"
ls -l "$image"
INNER
chmod 0755 "$work/build.sh"
mkdir -p "$work/scratch"

mounts=(-v "$image_dir:/out" -v "$work:/work")
[ -n "$tree" ] && mounts+=(-v "$tree:/src:ro")
[ -n "$pass_file" ] && mounts+=(-v "$pass_file:/pass:ro")

if [ "$uuid_only" = 1 ]; then
    say "reading the container's UUID"
    timeout 300 docker run --rm --privileged "${mounts[@]}" \
        -e IMAGE_NAME="$image_name" debian:12 bash -c \
        'apt-get update -qq >/dev/null 2>&1 && apt-get install -y -qq cryptsetup >/dev/null 2>&1 && cryptsetup luksUUID "/out/$IMAGE_NAME"'
    exit 0
fi

say "building $image_name (${size_gib} GiB$([ "$plain" = 1 ] && echo ', plain' || echo ', LUKS'))"
timeout 900 docker run --rm --privileged "${mounts[@]}" \
    -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
    -e IMAGE_NAME="$image_name" -e SIZE_GIB="$size_gib" \
    -e PLAIN="$plain" -e PASS_FILE="$pass_file" \
    debian:12 bash /work/build.sh > "$work/log" 2>&1 || {
    say "the build failed:"
    tail -20 "$work/log" | sed 's/^/  /'
    exit 1
}
ls -l "$image"
say "$(du -h "$image" | cut -f1) $image"
