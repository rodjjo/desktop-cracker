#!/bin/bash
# make dist — a tarball with everything needed to run desktop-cracker elsewhere.
#
# dist: build in release mode and create a .tar.gz with **everything needed to run it**,
# including the hypervisor (Firecracker, a released binary this project ships rather than builds),
# extracted to a folder of its own so the system's own copy is never replaced.  A script that
# installs what cannot be shipped (the shared libraries the window needs, the kvm group) comes with
# it, and the user extracts it anywhere and runs it from there.
#
# **What "everything needed to run it" means, measured**: a run reads four things — the guest's
# kernel, its initramfs, the root disk and Firecracker — and `desk-disk rootdisk` reads a fifth,
# the guest's userland image it copies into a new disk.  All five travel.  Nothing in the package is
# a development tool: no compiler, no `-dev` package, no cargo, no test plugin, no source.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
# **The version is the workspace's own** (`desktop-cracker/Cargo.toml`, `[workspace.package] version`), the
# same number `desktop-cracker --version` prints (`dc_common::APP_VERSION` is `CARGO_PKG_VERSION`).
# It used to be read from a `Cargo.toml` at the root of the tree, which stopped existing when the
# project became one workspace: the grep failed, `|| echo 0.1.0` swallowed the failure, and every
# tarball was named `desktop-cracker-0.1.0-x86_64` whatever the release actually was.
version=$(grep -m1 '^version' "$root/desktop-cracker/Cargo.toml" | cut -d'"' -f2)
[ -n "$version" ] || { echo "dist: no version in desktop-cracker/Cargo.toml" >&2; exit 1; }
# **The tarball's name carries the version; the folder inside it does not.**  `desktop-cracker` is
# the package's name, always, so extracting a new release into the same place replaces the old one
# instead of leaving `desktop-cracker-0.1.0/`, `desktop-cracker-0.2.0/`, `desktop-cracker-0.3.0/`
# side by side — several copies of an application on one machine, and no answer to "which one am I
# running".  The version is inside the package, in `VERSION`, and it is what `--version` prints.
name=desktop-cracker-$version-x86_64
package=desktop-cracker
out=$root/dist
stage=$out/$package

say() { printf 'dist: %s\n' "$*"; }

say "building (release)"
# **The build output is the tree's own `target/`**, at the root of this tree and not inside the
# workspace (`CARGO_TARGET_DIR`, the same one the Makefile exports): one folder for the whole
# project, whichever crate a build is of.
export CARGO_TARGET_DIR="$root/target"
(cd "$root/desktop-cracker" && cargo build --release)
(cd "$root/desktop-cracker" && cargo build --release -p desk-disk)

for f in target/release/desktop-cracker \
         target/release/desk-disk; do
    [ -x "$root/$f" ] || { echo "dist: $f is missing; the build failed" >&2; exit 1; }
done
# **The media**, in the folder the Makefile fills (`temp/download/`).  A package without them is a
# package that cannot boot anything, so this is a refusal and not a warning.  (The paths used to be
# `download/…` at the root of the tree, which is where the media has not lived since the media moved
# under `temp/`: `make dist` refused a tree that had everything.)
for f in temp/download/kernel temp/download/initramfs.gz temp/download/firecracker; do
    [ -s "$root/$f" ] || {
        echo "dist: $f is missing; run 'make build' (it builds the kernel, the initramfs and" >&2
        echo "      fetches Firecracker) and 'make rootfs' (the guest's userland) first" >&2
        exit 1
    }
done

rm -rf "$stage"
mkdir -p "$stage"/{bin,libraries,kernel,images,icons,docs,licenses}

# **The package's own version, as a file.**  A folder with no version in its name needs one inside
# it: `VERSION` is what `make install` matches a tarball against, what the README prints, and what a
# person with `~/desktop-cracker` looks at to know what they have.
echo "$version" > "$stage/VERSION"

say "copying the application and its own libraries"
install -m 0755 "$root/target/release/desktop-cracker" "$stage/bin/"
install -m 0755 "$root/target/release/desk-disk" "$stage/bin/"
# **The hypervisor**: a released binary, and the reason a run needs nothing installed on the host.
# It goes in `bin/` because that is where the application looks first, beside its own binary
# (`dc_common::media`), so the package runs from wherever it was extracted with no environment set.
install -m 0755 "$root/temp/download/firecracker" "$stage/bin/firecracker"
# The library a **guest** application links for the display's state:
# it is built for the guest, and it travels so a guest started from this package has it.
if [ -d "$root/temp/download/libdesk-guest" ]; then
    cp -a "$root/temp/download/libdesk-guest/." "$stage/libraries/"
fi

say "copying the guest's media"
# What the microVM boots from, under both names the package layout uses: `kernel/` is the kernel and
# its initramfs, `images/` is the same media plus the guest's userland image a new disk is made from.
install -m 0644 "$root/temp/download/kernel" "$stage/kernel/kernel"
install -m 0644 "$root/temp/download/initramfs.gz" "$stage/kernel/initramfs.gz"
install -m 0644 "$root/temp/download/kernel" "$stage/images/kernel"
install -m 0644 "$root/temp/download/initramfs.gz" "$stage/images/initramfs.gz"
# **The seed image**: the guest's userland as a ready ext4 image, which is what
# `desk-disk rootdisk` (or `create --seed-image PATH`) copies into a new disk.  Without it a
# package runs a disk somebody already made and cannot make one, so it is part of "everything needed
# to run it".  It is built here when the userland is built and the image is not — `make dist` is one
# command.
if [ ! -s "$root/temp/download/rootfs.ext4" ] && [ -d "$root/temp/download/rootfs" ]; then
    say "building the guest's userland image (this runs mkfs.ext4 in a container)"
    "$root/tools/seed-image.sh" "$root/temp/download/rootfs" "$root/temp/download/rootfs.ext4"
fi
if [ -s "$root/temp/download/rootfs.ext4" ]; then
    say "including the guest's userland image ($(du -h "$root/temp/download/rootfs.ext4" | cut -f1))"
    install -m 0644 "$root/temp/download/rootfs.ext4" "$stage/images/rootfs.ext4"
else
    echo "dist: no temp/download/rootfs.ext4 and no userland to build one from; a package without" >&2
    echo "      it cannot create a root disk. Run 'make rootfs' first" >&2
    exit 1
fi

# The launcher, **twice from one file**: as `bin/desk-run`, which runs the package
# straight out of the folder it was extracted to from any working directory, and as `launcher.sh`
# beside `install.sh`, which is what that script installs.  One file, so an installed run and a run
# out of the folder cannot drift apart.
install -m 0755 "$root/scripts/launcher.sh" "$stage/bin/desk-run"
install -m 0755 "$root/scripts/launcher.sh" "$stage/launcher.sh"

say "drawing the package's icons"
bash "$root/scripts/make-icon.sh" "$stage/icons" >/dev/null

say "copying the documentation and the licences"
install -m 0644 "$root/LICENSE" "$stage/licenses/LICENSE"
install -m 0644 "$root/LICENSE" "$stage/LICENSE"
install -m 0644 "$root/README.md" "$stage/docs/README.md"
install -m 0644 "$root/architecture.svg" "$stage/docs/architecture.svg"
install -m 0644 "$root/preview/architecture.png" "$stage/docs/architecture.png"
install -m 0644 "$root/preview/preview.png" "$stage/docs/preview.png"
cat > "$stage/licenses/README.md" <<'LICENSES'
# Licences

This package is **MIT** (see `LICENSE`), and it carries three things that are somebody else's:

* **Firecracker**, in `bin/firecracker` — Apache-2.0, by Amazon Web Services and its contributors
  (<https://github.com/firecracker-microvm/firecracker>).  It is the hypervisor every run uses, and
  it is shipped as a **released binary**, unmodified: its source, its licence and its notice are in
  that repository, and its release page is where the binary comes from.
* the **guest's userland**, in `images/rootfs.ext4` — a Debian 12 system assembled by
  `tools/rootfs/build.sh` from Debian's own packages, each under its own licence (the
  full text of every one of them is inside that image, under
  `/usr/share/doc/*/copyright`).  It also carries VLC, Firefox ESR and a Python built
  from the python.org source — same rule, their own licences, their own text.
* the **guest's framebuffer module** in `kernel/initramfs.gz` — this project's own source
  (`desktop-cracker/guest-kernel/desk_fb.c`), built against the Linux kernel's interfaces and
  carrying the `GPL-2.0` a kernel module declares.  The rest of `kernel/initramfs.gz` — the guest's
  tools and its agent — is this project's own, under the MIT.

The kernel in `kernel/kernel` is **this project's own build** (Firecracker's guest configuration
plus the options this guest needs, `scripts/kernel-build.sh`), and a Linux kernel is under the
GPL-2.0.
LICENSES

# --------------------------------------------------------------------------- the system packages
#
# What cannot be shipped: the shared libraries the **window** links.  The list is not a guess kept by
# hand — it is read from the release binary this very package carries (`ldd`), and each library is
# asked of `dpkg -S` for the package that owns it.  So the list is what this build needs, on this
# distribution, and it is **runtime packages only**: no `-dev`, no compiler, no build tool.  A host
# that is not Debian-family gets the names this project measured on Debian 12 / Ubuntu.
packages=$(
    ldd "$root/target/release/desktop-cracker" 2>/dev/null |
        awk '{print $3}' | grep '^/' |
        while read -r lib; do
            pkg=$(dpkg -S "$lib" 2>/dev/null | cut -d: -f1)
            [ -n "$pkg" ] || pkg=$(dpkg -S "$(readlink -f "$lib")" 2>/dev/null | cut -d: -f1)
            [ -n "$pkg" ] && echo "$pkg"
        done | sort -u | tr '\n' ' '
) || true
if [ -z "${packages// /}" ]; then
    packages="libgtk-3-0 libglib2.0-0 libgdk-pixbuf-2.0-0 libpango-1.0-0 libcairo2 libepoxy0 libpulse0 libxkbcommon0 libwayland-client0 libwayland-cursor0 libwayland-egl1 libx11-6 libx11-xcb1 libxcb1 libxcomposite1 libxcursor1 libxdamage1 libxext6 libxfixes3 libxi6 libxinerama1 libxrandr2 libxrender1"
    say "no dpkg here: the runtime packages named are the ones measured on Debian 12 / Ubuntu"
else
    say "the runtime packages this binary links: $(echo $packages | wc -w) of them"
fi

say "writing install.sh and the README"
cat > "$stage/install.sh" <<'INSTALL'
#!/bin/bash
# Put this package's application where a person can start it, and install what the host is
# missing to run it.
#
#   ./install.sh [--prefix ~/.local] [--no-desktop-entry] [--no-system-deps] [--yes]
#                [--no-disk] [--disk-size 20G]
#
# **The root disk is offered here, and it is optional.**  The settings this package starts with name
# `disks/root.raw` beside this script (dist: — the package is where its state is; the
# application writes `config.yml` there on its first run), so a package with no disk has an
# application that asks for one: it opens the settings window to select the disk and then asks for
# the passphrase it is made with, twice, in a question of its own.  This script is the shortcut —
# `desk-disk rootdisk`, the package's own tool, from the userland image the package carries —
# for a person who would rather type the passphrase once here, on a terminal, than in a dialog.
# **It is `rootdisk` and not `create`: `create` makes a data disk, which copies nothing**, so a root disk made with it boots an empty filesystem and no desktop.
#
# `--no-disk` skips it; `--disk-size 40G` makes a bigger one.
#
# **It does not copy the package anywhere.**  The application runs from the folder it was extracted
# into — that is what "extract it anywhere and run it from there" means — and this script adds the
# three things a folder cannot give itself: a name on the PATH, a desktop entry with an icon, and the
# runtime libraries the host does not have.  Nothing is moved, nothing is duplicated, and nothing in
# `libraries/` is touched: this project's own note on this script is "install system dependencies using
# apt-get, it does not install shared libraries in libraries folder".
#
# **Nothing that builds software is installed**: no compiler, no `-dev` package, no cargo.  A person
# who wants to build this project from source does it in the source tree, where `make dependencies`
# names the build packages.
#
# Run it from anywhere: it works from wherever it was extracted.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
prefix=$HOME/.local
entry=1
system_deps=1
assume_yes=0
disk=1
disk_size=20G
while [ $# -gt 0 ]; do
    case "$1" in
    --prefix) prefix=$2; shift 2 ;;
    --no-desktop-entry) entry=0; shift ;;
    --no-system-deps) system_deps=0; shift ;;
    --yes | -y) assume_yes=1; shift ;;
    --no-disk) disk=0; shift ;;
    --disk-size) disk_size=$2; shift 2 ;;
    -h | --help) sed -n '2,27p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "install.sh: unknown option $1" >&2; exit 2 ;;
    esac
done

version=$(cat "$here/VERSION" 2>/dev/null || echo unknown)
echo "install.sh: desktop-cracker $version, installed at $here"

# **The name on the PATH is a link to this folder's launcher**, not a copy of it.  The launcher
# resolves its own link, so the application it starts is the one beside it — this folder — and a run
# finds its kernel, its initramfs, its userland image and its hypervisor beside that binary
# (`dc_common::media`).  One copy of the application on the machine, and `desk-run` is a
# name for it.
install -d "$prefix/bin"
ln -sf "$here/launcher.sh" "$prefix/bin/desk-run"
ln -sf "$here/bin/desk-disk" "$prefix/bin/desk-disk"
echo "install.sh: $prefix/bin/desk-run -> $here/launcher.sh"

if [ "$entry" = 1 ]; then
    install -d "$prefix/share/applications" "$prefix/share/icons/hicolor/256x256/apps"
    install -m 0644 "$here/icons/desktop-cracker.png" \
        "$prefix/share/icons/hicolor/256x256/apps/desktop-cracker.png" 2>/dev/null || true
    cat > "$prefix/share/applications/desktop-cracker.desktop" <<ENTRY
[Desktop Entry]
Type=Application
Name=Desktop-cracker Desktop
Comment=A sandboxed desktop: a microVM with KVM, shown in a window
Exec=$prefix/bin/desk-run
Icon=desktop-cracker
Terminal=false
Categories=System;Emulator;
Keywords=sandbox;vm;microvm;kvm;
ENTRY
    command -v update-desktop-database >/dev/null 2>&1 &&
        update-desktop-database "$prefix/share/applications" >/dev/null 2>&1 || true
    command -v gtk-update-icon-cache >/dev/null 2>&1 &&
        gtk-update-icon-cache -q "$prefix/share/icons/hicolor" >/dev/null 2>&1 || true
fi

case ":$PATH:" in
*":$prefix/bin:"*) ;;
*) echo "install.sh: add $prefix/bin to your PATH" ;;
esac

if [ "$system_deps" = 1 ]; then
    # The runtime libraries this package's own binary links, read from that binary when the package
    # was built.  **No -dev package and no compiler is in this list**: those are what a person who
    # *builds* this project needs, and they belong to the source tree's `make dependencies`.
    packages="__PACKAGES__"
    echo "install.sh: the packages this needs at runtime:"
    echo "            $packages"
    if ! command -v apt-get >/dev/null 2>&1; then
        echo "install.sh: this host has no apt-get; install the equivalents yourself"
    elif [ "$assume_yes" = 1 ]; then
        sudo apt-get update
        sudo apt-get install -y $packages
    elif [ -t 0 ]; then
        read -r -p "install.sh: install them now with sudo? [y/N] " answer
        case "$answer" in
        y | Y | yes | YES)
            sudo apt-get update
            sudo apt-get install -y $packages
            ;;
        *) echo "install.sh: skipped; run again with --yes to install them" ;;
        esac
    else
        echo "install.sh: run this to install them:"
        echo "            sudo apt-get install -y $packages"
    fi
    if [ -r /dev/kvm ]; then
        echo "install.sh: /dev/kvm is readable: the microVM can use KVM acceleration"
    else
        echo "install.sh: /dev/kvm is not readable by $(id -un):"
        echo "            sudo usermod -aG kvm $(id -un)   # then log in again"
    fi
fi

# **The root disk**: the settings this package uses name `disks/root.raw` beside
# this script, and the application runs only with a disk there.  The tool that makes one is this
# package's own `bin/desk-disk`, and the userland it copies is this package's own
# `images/rootfs.ext4`— both found by the tool itself, which is what makes this work from wherever
# the package was extracted.  The passphrase is asked for **once, on the terminal, by that tool**,
# and it is written into the disk and nowhere else.
if [ "$disk" = 1 ]; then
    root=$here/disks/root.raw
    if [ -f "$root" ]; then
        echo "install.sh: the root disk is already there: $root (left alone)"
    elif [ ! -t 0 ]; then
        echo "install.sh: there is no terminal to ask for the root disk's passphrase; skipped."
        echo "            The application asks for it in a dialog instead, or by hand:"
        echo "              $here/bin/desk-disk rootdisk --path $root --size $disk_size"
    else
        make_it=1
        if [ "$assume_yes" != 1 ]; then
            read -r -p "install.sh: make the guest's root disk now ($disk_size in $here/disks)? [Y/n] " answer
            case "$answer" in
            n | N | no | NO) make_it=0 ;;
            esac
        fi
        if [ "$make_it" = 1 ]; then
            echo "install.sh: making the root disk, $root ($disk_size)."
            echo "            It asks for a passphrase — twice: it is the disk's only key, it is not"
            echo "            written anywhere, and the guest asks for it again when it boots."
            mkdir -p "$here/disks"
            if "$here/bin/desk-disk" rootdisk --path "$root" --size "$disk_size"; then
                echo "install.sh: the root disk is ready: $root"
            else
                echo "install.sh: the root disk was not made; the application asks for it instead" >&2
            fi
        else
            echo "install.sh: skipped; the application asks for the disk when it starts"
        fi
    fi
fi

# **The run's own sockets**: a run puts the Firecracker API
# socket — the channel between the microVM and this application — and every channel of the machine
# under `$XDG_RUNTIME_DIR/desktop-cracker/run-<pid>`, or `~/.desktop-cracker/run`
# where the session has no runtime directory.  Per user, per run, private, and removed when the run
# ends: which is why two people on one machine, or one person in two terminals, do not interfere with
# each other's microVM.  Nothing has to be created here for it.
if [ -z "${XDG_RUNTIME_DIR:-}" ]; then
    echo "install.sh: \$XDG_RUNTIME_DIR is not set in this session; a run will use"
    echo "            ~/.desktop-cracker/run for its sockets instead"
fi

echo "install.sh: done."
if [ -f "$here/disks/root.raw" ]; then
    echo "install.sh: run it:"
    echo "            desk-run"
else
    echo "install.sh: run it — it opens the settings window to select the root disk and asks for"
    echo "            the passphrase that disk is made with:"
    echo "            desk-run"
fi
INSTALL

cat > "$stage/uninstall.sh" <<'UNINSTALL'
#!/bin/bash
# Remove what install.sh put in place: the names on the PATH, the desktop entry and the icon, and
# this package's folder.
#
#   ./uninstall.sh [--prefix ~/.local] [--keep-package] [--keep-data]
#
# **It never touches the user's data.**  `config.yml` and `disks/` in this folder are the user's: the
# settings, the encrypted disk, and everything installed inside the guest.  An uninstall that removed
# them would be a data loss no command should cause by accident, which is why the package folder is
# kept unless `--keep-package` is *not* given **and** there is no data in it — see the end of this
# script.  A run's sockets are not here either: they are in the user's runtime directory and they go
# away with the run.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
prefix=$HOME/.local
keep=0
while [ $# -gt 0 ]; do
    case "$1" in
    --prefix) prefix=$2; shift 2 ;;
    --keep-package) keep=1; shift ;;
    -h | --help) sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "uninstall.sh: unknown option $1" >&2; exit 2 ;;
    esac
done

# **The user's own data in this folder**: the settings and the disks.  Anything there is a reason to
# keep the folder, whatever was asked for.
data=0
[ -f "$here/config.yml" ] && data=1
[ -d "$here/disks" ] && [ -n "$(ls -A "$here/disks" 2>/dev/null)" ] && data=1

echo "uninstall.sh: removing the names install.sh linked into $prefix"
# Only a link that points into this package is removed: a name somebody else put there is theirs.
for name in desk-run desk-disk; do
    path=$prefix/bin/$name
    if [ -L "$path" ]; then
        case "$(readlink -f "$path")" in
        "$here"/*) rm -f "$path"; echo "  removed $path" ;;
        *) echo "  kept $path (it does not point at this package)" ;;
        esac
    fi
done
entry=$prefix/share/applications/desktop-cracker.desktop
if [ -f "$entry" ] && grep -q "desk-run" "$entry" 2>/dev/null; then
    rm -f "$entry"
    echo "  removed $entry"
fi
icon=$prefix/share/icons/hicolor/256x256/apps/desktop-cracker.png
if [ -f "$icon" ]; then
    rm -f "$icon"
    command -v gtk-update-icon-cache >/dev/null 2>&1 &&
        gtk-update-icon-cache -q "$prefix/share/icons/hicolor" >/dev/null 2>&1 || true
fi

if [ "$keep" = 1 ] || [ "$data" = 1 ]; then
    echo "uninstall.sh: the package stays at $here"
    echo "              (its settings and its disks are in that folder: $([ "$data" = 1 ] && echo "this machine has data there" || echo "asked for"))"
else
    echo "uninstall.sh: removing the package at $here"
    rm -rf "$here"
fi

echo "uninstall.sh: your data is untouched.  To remove it as well, delete:"
echo "              $here/config.yml and $here/disks   (the settings and the disks — and with"
echo "                                                 them, everything installed inside the guest)"
UNINSTALL

cat > "$stage/README.md" <<'README'
# desktop-cracker

A **sandboxed desktop**: a microVM with KVM acceleration, displayed and managed from
this host — a window for the guest's screen, the host's folders shared into it, an
encrypted root disk, an audio device, and the host's X server exposed inside it.

**Version __VERSION__** (in `VERSION`).  The number in that file is the number
`desktop-cracker --version` prints.  The folder is `desktop-cracker`, with no version in
its name: a new release replaces the one it is extracted over, instead of leaving several
copies of an application on one machine.

## Install

    tar xzf desktop-cracker-__VERSION__-x86_64.tar.gz -C ~
    cd ~/desktop-cracker
    ./install.sh

`install.sh` does not copy the package anywhere: the application runs from this folder.
It links `desk-run` and `desk-disk` into `~/.local/bin` (or `--prefix`
wherever you like), adds a desktop entry and an icon, and — with `--yes`, or after asking
— installs the runtime libraries that cannot be shipped, using `apt-get`.  Nothing in
`libraries/` is touched: those travelled with the package, **Firecracker included**, so
your system's own copy is never replaced.  **Nothing that builds software is installed**:
no compiler, no `-dev` package, no cargo — those belong to the source tree and its
`make dependencies`.

## What is in here

    bin/          the application, the disk tool and Firecracker (a released binary:
                  https://github.com/firecracker-microvm/firecracker)
    libraries/    the shared libraries that travel with the package (the guest's display library)
    kernel/       the Linux kernel the microVM boots and its initramfs
    images/       the same media, plus rootfs.ext4: the guest's userland a new disk is
                  made from, so the package can **create** a disk as well as run one
    icons/        the application's icon, in the sizes a desktop asks for
    docs/         the README and the architecture picture
    licenses/     what the project's MIT covers, and what is somebody else's (Firecracker)
    disks/        this package's own disks (root.raw is what a run boots, made by install.sh)
    config.yml    this package's own settings (written on the first run, edited by the window)
    VERSION       the version of this package
    install.sh    this script
    launcher.sh   what `bin/desk-run` is, and what `install.sh` links into
                  the PATH

## Run

    bin/desk-run        # straight out of this folder, from any directory

or, after `./install.sh`:

    desk-run

The launcher finds the kernel, the images and the hypervisor **beside its own binary**, so
it works from wherever you extracted this.

## The guest's disk

The guest's root filesystem is an **encrypted raw disk** (Firecracker attaches raw images
and nothing else), and its password is yours — it is never stored anywhere.  `install.sh`
makes it, at `disks/root.raw` beside this file, from the userland image this package carries,
asking you for the passphrase on the terminal.

Or let the application do it: with no disk it opens the settings window to select it and asks for
the passphrase twice in a question of its own (a passphrase is never a setting — the window has no
field for one).

By hand it is the same command:

    bin/desk-disk rootdisk --path disks/root.raw --size 20G

(`rootdisk`, not `create`: `create` makes an **additional** disk for data and copies no userland
into it, so a root disk made with `create` has nothing to boot.)

The userland image is found by the tool itself (the package's `images/rootfs.ext4`), and the
disk is created *inside a microVM of its own*, so this needs no root, no loop device and no
packages of its own.  `desk-disk --help` lists the rest: `change-pass`, `resize`, `info`.

The guest asks for that passphrase on **its own console**, which is the window.

If the disk is not there when the application starts, it opens the **settings window** to
select it and then asks for the passphrase the disk is made with — twice, in a question of
its own, kept in memory only.  `--no-disk` in `install.sh` is how you ask for that instead.

## Where the settings are

`config.yml` in this folder — beside the binaries, not in a hidden directory in your home —
and the disks are in this folder's `disks/`.  A package extracted somewhere else keeps its
own settings and its own disks there: two packages are two installations.

## Where a run's sockets are

`$XDG_RUNTIME_DIR/desktop-cracker/run-<pid>/` — the Firecracker API socket and every
channel of the machine, in a directory of this user and of this run, private and removed
when the run ends.  Where the session has no `$XDG_RUNTIME_DIR`, `~/.desktop-cracker/run/`
instead.  Two runs of two users, or of one user in two terminals, never share one.

The **sockets** are the one thing that lives in the runtime directory rather than in the
package: they are per-run state, not the application's.

## If something is missing

    ./install.sh --no-system-deps     # only report what the host lacks
    ./install.sh --yes                # install it without asking

`/dev/kvm` must be readable by you: `sudo usermod -aG kvm "$USER"` and log in again.
Without it the microVM has no hardware acceleration, and the application says so.
README

# The package's own list and version, substituted into the two files (a here-doc inside a here-doc
# is how this stays one readable file).
python3 - "$stage/install.sh" "$stage/README.md" "$packages" "$version" <<'PY'
import sys
install, readme, packages, version = sys.argv[1:5]
text = open(install).read().replace("__PACKAGES__", " ".join(packages.split()))
open(install, "w").write(text)
text = open(readme).read().replace("__VERSION__", version)
open(readme, "w").write(text)
PY
chmod +x "$stage/install.sh" "$stage/uninstall.sh"

# **The settings and the disks do not travel**, and that is on purpose: `config.yml` names the root
# disk by an absolute path (`disks/root.raw` under this package), which is wrong the moment the
# package is extracted somewhere else, and a new package must not be able to overwrite a disk the
# user already has.  `install.sh` makes `disks/root.raw` where the package is; the application
# writes `config.yml` there on its first run.
rm -f "$stage/config.yml"
rm -rf "$stage/disks"

# The tarball is named after the version; what it contains is `desktop-cracker/`.
say "packing $out/$name.tar.gz (the folder inside it is $package/)"
(cd "$out" && tar czf "$name.tar.gz" "$package")
say "done: $out/$name.tar.gz ($(du -h "$out/$name.tar.gz" | cut -f1))"
say "the user extracts it anywhere and runs $package/install.sh there"
