#!/bin/sh
# The launcher: run desktop-cracker from the folder the package was extracted into.
#
# **Why this exists.**  The application finds its own media — the guest kernel, its initramfs, the
# userland image a new disk is made from, and Firecracker — **beside its own binary**, in the
# package's folders (`dc_common::media`: `bin/` beside `kernel/` and `images/`).  So no path has to
# be exported for a run to find what it boots from, and the package works from wherever it was
# extracted and from any working directory.
#
# What this script adds is the loader's path: the shared libraries that travel with the package sit
# in `libraries/`, and `LD_LIBRARY_PATH` is what makes a package's own copy win over the system's.
# Nothing else is set, and nothing here carries a credential.
#
# It is also what `install.sh` links into a folder on the PATH (`~/.local/bin/desk-run`),
# so it resolves its own symlink before it works out where the package is: the link is a name, the
# package is the place.
#
#   desk-run […switches the application takes…]
self=$0
while [ -L "$self" ]; do
    target=$(readlink "$self")
    case "$target" in
    /*) self=$target ;;
    *) self=$(dirname "$self")/$target ;;
    esac
done
here=$(cd "$(dirname "$self")" && pwd)
# The launcher travels under two names, and they sit at two depths: `bin/desk-run` inside
# the package, and `launcher.sh` at the package's own root (which is what `install.sh` links into the
# PATH).  The package is whichever of the two folders has the application beside it.
if [ -x "$here/bin/desktop-cracker" ]; then
    package=$here
else
    package=$(cd "$here/.." && pwd)
fi
if [ ! -x "$package/bin/desktop-cracker" ]; then
    echo "desk-run: no application beside me (looked in $here and $package)" >&2
    exit 1
fi
export LD_LIBRARY_PATH="$package/libraries${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
exec "$package/bin/desktop-cracker" "$@"
