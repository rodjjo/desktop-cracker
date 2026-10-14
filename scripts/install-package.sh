#!/bin/bash
# make install — put the package this tree built where a person can run it.
#
# dist: the user extracts the package anywhere and it works from there. So `make install`
# is **the extraction**, not a copy of a build tree into a prefix: it takes the tarball `make dist`
# built for the version this tree has and extracts it at the target folder (the home, by default),
# which gives `~/desktop-cracker`, and then runs the package's own `install.sh` there — the names on
# the PATH, the desktop entry and the icon.
#
#   scripts/install-package.sh [target-dir]      (default: $HOME)
#   INSTALL_ARGS=…                               passed to the package's install.sh
#
# **The folder has no version in its name**, and that is the point: `~/desktop-cracker` is the
# application, and a new release replaces it.  A name carrying the version leaves
# `desktop-cracker-0.1.0/`, `desktop-cracker-0.2.0/` and `desktop-cracker-0.3.0/` side by side —
# three applications on one machine and no answer to "which one am I running".  The version is inside
# the package, in `VERSION`.
#
# **No tarball for this version, no install.**  `make install` asks for `make dist` rather than
# installing something that was never packaged: a half-built tree becoming "the installed application"
# is the failure this command exists to avoid.
#
# It installs **no development tool** — no compiler, no `-dev` package, no cargo, no test plugin — and
# it never touches `~/.desktop-cracker`, which is the user's disks and settings.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
version=$(grep -m1 '^version' "$root/desktop-cracker/Cargo.toml" | cut -d'"' -f2)
[ -n "$version" ] || { echo "install: no version in desktop-cracker/Cargo.toml" >&2; exit 1; }
tarball=$root/dist/desktop-cracker-$version-x86_64.tar.gz
target=${1:-$HOME}
package=$target/desktop-cracker

say() { printf 'install: %s\n' "$*"; }

if [ ! -f "$tarball" ]; then
    say "there is no package for this version ($version): $tarball is not there."
    echo "       Run 'make dist' first.  It builds the application and the guest's media and" >&2
    echo "       writes the tarball; 'make install' only extracts what 'make dist' made, so what" >&2
    echo "       gets installed is a package and not a half-built tree." >&2
    exit 1
fi

# The folder we are about to replace has to be a package this command made.  A directory of the
# user's that happens to be called `desktop-cracker` is not ours to remove.
if [ -e "$package" ] && [ ! -f "$package/VERSION" ] && [ ! -x "$package/bin/desktop-cracker" ]; then
    say "$package exists and is not a desktop-cracker package; refusing to touch it" >&2
    exit 1
fi

# **The user's data in that folder is copied out and back.**  The package keeps its settings and its
# disks in its own folder (`config.yml`, `disks/`), because that is what makes an installation
# self-contained — and replacing the folder of a newer release must not throw them away.  They are
# moved aside, the package is extracted over the folder, and they are put back; a disk is a
# multi-gigabyte file, so it is moved, never copied.
stash=
if [ -e "$package" ]; then
    for keep in config.yml disks; do
        [ -e "$package/$keep" ] && stash=${stash:-$(mktemp -d -t desktop-cracker-keep.XXXXXX)}
        [ -e "$package/$keep" ] && mv "$package/$keep" "$stash/"
    done
    [ -n "$stash" ] && say "keeping your settings and disks from the installation being replaced"
fi

say "extracting $tarball at $target"
rm -rf "$package"
tar xzf "$tarball" -C "$target"
inside=$(cat "$package/VERSION" 2>/dev/null || echo unknown)
if [ "$inside" != "$version" ]; then
    say "the package inside the tarball says $inside and this tree says $version; refusing to install a package that is not this one" >&2
    rm -rf "$package"
    exit 1
fi
if [ -n "$stash" ]; then
    for keep in config.yml disks; do
        [ -e "$stash/$keep" ] && mv "$stash/$keep" "$package/"
    done
    rmdir "$stash" 2>/dev/null || true
    say "your settings and disks are back in $package"
fi

say "running the package's own install.sh (no system packages: a tree that just built this has them;"
say "  it offers to make the root disk, and says nothing else)"
# `--no-system-deps` is the default here for a reason: `make install` is a developer's command, and a
# developer who just built the package has the libraries already.  `INSTALL_ARGS=--yes` is the answer
# to "install them too"; `INSTALL_ARGS=--no-desktop-entry` skips the menu entry.
# **The disk is offered, not forced**: `--no-disk` here means the application asks for it on its
# first run (its settings window selects the disk, its own dialog asks for the passphrase twice).
# `INSTALL_ARGS=--disk-size 40G` makes a bigger one; `INSTALL_ARGS=--yes` does not ask anything.
args=${INSTALL_ARGS---no-system-deps}
"$package/install.sh" --prefix "${INSTALL_PREFIX:-$HOME/.local}" $args

say "installed at $package (version $inside)"
say "run it: $package/bin/desk-run   (or desk-run, now on the PATH)"
if [ -f "$package/disks/root.raw" ]; then
    say "its root disk: $package/disks/root.raw (yours, kept across installs)"
else
    say "its root disk: $package/disks/root.raw — it does not exist yet, so the application asks"
    say "               for it on its first run (settings window to select it, a dialog for the"
    say "               passphrase).  Or 'make install INSTALL_ARGS="--disk-size 40G"' makes one now"
fi
say "remove it: make uninstall"
