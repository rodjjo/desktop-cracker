#!/bin/bash
# Build the desktop-cracker library an application **inside** the microvm links to.
#
#   tools/libdesk/build.sh [output-dir]
#
# It produces:
#
#   libdesk_display.so, libdesk_display.a   the library
#   desk_display.h                              its header
# desk-display-status a command that prints the state
#                                                   (what a shell script or a test
#                                                   uses instead of linking)
#
# The library is shipped into the guest's userland by `tools/rootfs` and into the
# dist tarball.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
out=${1:-$root/temp/download/libdesk}

say() { printf 'libdesk: %s\n' "$*"; }

mkdir -p "$out"
cp "$here/desk_display.h" "$out/"

flags=(-O2 -g -fPIC -Wall -Wextra)

say "building the shared library"
gcc "${flags[@]}" -shared -Wl,-soname,libdesk_display.so.1 \
    -o "$out/libdesk_display.so.1" "$here/desk_display.c"
ln -sf libdesk_display.so.1 "$out/libdesk_display.so"

say "building the static library"
gcc "${flags[@]}" -c -o "$out/desk_display.o" "$here/desk_display.c"
ar rcs "$out/libdesk_display.a" "$out/desk_display.o"
rm -f "$out/desk_display.o"

say "building the status command"
cat > "$out/desk-display-status.c" <<'MAIN'
/* Print the display's state, the way an application in the guest would ask for it.
 *
 * desk-display-status the number (-1, 1)
 * desk-display-status --text a word (hidden, normal)
 * desk-display-status --all every value, for a script or a test
 *
 * Exit status: 0 when a state was read, 1 when it could not be (which is itself
 * the answer "outside the microvm").
 */
#include "desk_display.h"
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "";
    bool inside = false, visible = false, numlock = false;
    unsigned long long revision = 0, changed = 0;
    int status = desk_display_status_ex(&inside, &visible, &numlock, &revision, &changed);
    const char *word = status == DISPLAY_HIDDEN ? "hidden" : "normal";
    if (strcmp(mode, "--text") == 0)
        printf("%s\n", word);
    else if (strcmp(mode, "--all") == 0)
        printf("status=%d (%s) inside=%d visible=%d numlock=%d revision=%llu changed_ms=%llu\n",
               status, word, (int)inside, (int)visible, (int)numlock, revision, changed);
    else
        printf("%d\n", status);
    return inside ? 0 : 1;
}
MAIN
gcc -O2 -I"$out" -o "$out/desk-display-status" "$out/desk-display-status.c" \
    "$out/libdesk_display.a"
rm -f "$out/desk-display-status.c"

say "done: $(ls "$out" | tr '\n' ' ')"
