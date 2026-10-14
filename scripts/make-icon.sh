#!/bin/bash
# Draw the application's icon, in the sizes a desktop wants.
#
#   scripts/make-icon.sh [output-dir]
#
# The application's mark — a dark screen in a frame — and a package needs it as a file: a
# desktop entry
# with no icon is a blank square in the menu.  So the pixels are written here, at
# 16/22/32/48/64/128/256, as PNGs and as one `.ico`, with **no image library**: a PNG is
# a zlib stream of scanlines, and writing one is a header, a CRC and `gzip`'s raw
# deflate.
#
# The mark, in one sentence: a 45° sky-to-teal field, a dark rounded frame, and a
# light screen inside it.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
out=${1:-$root/temp/download/icons}
mkdir -p "$out"

python3 - "$out" <<'PY'
import struct, sys, zlib, pathlib

out = pathlib.Path(sys.argv[1])

def mark(x, y, w, h):
    """The application's mark, in one pixel (RGBA).  The same drawing the window's icon uses,
    scaled: a border, a frame, and a light screen inside it."""
    fx, fy = x / w, y / h
    border = fx < 1 / w or fy < 1 / h or fx > 1 - 1 / w or fy > 1 - 1 / h
    if border:
        return (0x20, 0x20, 0x28, 255)
    margin = 4 / 22
    inner = (margin <= fx <= 1 - margin) and (margin <= fy <= 1 - margin)
    # the frame: a sky-to-teal gradient, as the application's own frame
    t = (fx + fy) / 2
    frame = (
        int(0x2E + (0x18 - 0x2E) * t),
        int(0x7A + (0xB8 - 0x7A) * t),
        int(0xB8 + (0xA0 - 0xB8) * t),
        255,
    )
    if not inner:
        return frame
    screen_margin = 6 / 22
    on_screen = (screen_margin <= fx <= 1 - screen_margin) and (
        screen_margin <= fy <= 1 - screen_margin - 1 / 22
    )
    if on_screen:
        # the guest's own screen: dark, with a hint of the terminal green the guest
        # prints its boot lines in
        return (0x10, 0x18, 0x14, 255)
    return frame

def png(path, size):
    rows = bytearray()
    for y in range(size):
        rows.append(0)  # filter: none
        for x in range(size):
            rows.extend(mark(x, y, size, size))
    def chunk(kind, data):
        return (
            struct.pack(">I", len(data))
            + kind
            + data
            + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
        )
    header = struct.pack(">IIBBBBB", size, size, 8, 6, 0, 0, 0)  # 8-bit RGBA
    body = chunk(b"IHDR", header) + chunk(b"IDAT", zlib.compress(bytes(rows), 9)) + chunk(b"IEND", b"")
    path.write_bytes(b"\x89PNG\r\n\x1a\n" + body)

sizes = [16, 22, 32, 48, 64, 128, 256]
for size in sizes:
    png(out / f"desktop-cracker-{size}.png", size)
# The one a desktop entry names.
png(out / "desktop-cracker.png", 256)

# An `.ico` for the places that want one: a header and the PNGs by offset.
entries = []
blobs = []
offset = 6 + 16 * len(sizes)
for size in sizes:
    data = (out / f"desktop-cracker-{size}.png").read_bytes()
    dim = 0 if size >= 256 else size
    entries.append(struct.pack("<BBBBHHII", dim, dim, 0, 0, 1, 32, len(data), offset))
    blobs.append(data)
    offset += len(data)
ico = struct.pack("<HHH", 0, 1, len(sizes)) + b"".join(entries) + b"".join(blobs)
(out / "desktop-cracker.ico").write_bytes(ico)
print("wrote", ", ".join(sorted(p.name for p in out.iterdir())))
PY

echo "make-icon: $out"
