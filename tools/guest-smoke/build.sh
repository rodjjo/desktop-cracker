#!/bin/bash
# Build the tiny serial guest used by the boot system tests.
#
#   tools/guest-smoke/build.sh [output-initramfs.gz]
#
# The initramfs contains: busybox (dynamically-linked on the host, so the
# toolchains' static loader is not required), the statically-linked guest-probe
# and an init that waits for a line on ttyS0, prints a marker and *halts*.
# Halting matters: a test that waits for the process to exit must not wait for a
# guest that has nothing left to do.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
out=${1:-$here/guest-smoke-initramfs.gz}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

mkdir -p "$(dirname "$out")"
root="$tmp/root"
mkdir -p "$root"/{bin,sbin,proc,sys,dev,tmp}

echo "== compiling guest-probe"
gcc -static -O2 -o "$root/bin/guest-probe" "$here/guest-probe.c"

echo "== installing busybox"
cp "$(command -v busybox)" "$root/bin/busybox"
chmod +x "$root/bin/busybox"

cat > "$root/init" <<'INIT'
#!/bin/busybox sh
mkdir -p /bin /sbin /usr/bin /usr/sbin
/bin/busybox --install -s 2>/dev/null
export PATH=/bin:/sbin
mount -t proc proc /proc 2>/dev/null || true
mount -t sysfs sys /sys 2>/dev/null || true
mount -t devtmpfs dev /dev 2>/dev/null || true
[ -c /dev/ttyS0 ] || mknod /dev/ttyS0 c 4 64 2>/dev/null || true
echo "GUEST init: $(uname -r) on $(uname -m)"
/bin/guest-probe smoke
# Ask the kernel to power off, so a test can wait for the process to exit
# instead of waiting for a timeout (a VMM started with `-no-reboot` exits by itself).
poweroff -f
INIT
chmod +x "$root/init"

echo "== packing $out"
( cd "$root" && find . | cpio -o -H newc --quiet | gzip -9 ) > "$out"
ls -l "$out"
