#!/bin/bash
# The guest userland's "default installed software":
#
#   * the latest VLC media player and Firefox browser — from Debian's backports
#     where the release is behind them (a backport that is not there leaves the
#     release's own package, which still works);
#   * Python 3.13 with `pip3` and `venv`, built from source because bookworm ships
# 3.11 and this project uses the version. It is installed with
#     `--enable-shared` and its own ld.so entry, so `python3 -m venv` works and pip
#     runs from the virtualenv.
#
# It runs **inside the container** whose /out is the tree being built (see
# tools/rootfs/build.sh), so everything below is executed as root there: no
# escaping, and the tree's ownership stays the container's.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
python_version=${PYTHON_VERSION:-3.13.9}

say() { printf 'guest-userland: %s\n' "$*"; }

say "VLC and Firefox (backports when the release is behind)"
if ! grep -q bookworm-backports /etc/apt/sources.list; then
    echo 'deb http://deb.debian.org/debian bookworm-backports main contrib non-free' \
        >> /etc/apt/sources.list
fi
apt-get update -qq
apt-get install -y -qq --no-install-recommends -t bookworm-backports vlc firefox-esr ||
    apt-get install -y -qq --no-install-recommends vlc firefox-esr

say "Python $python_version with pip3, venv and Tk"
# `tk-dev`/`tcl-dev` are **build-time only**, in the container: without Tk's headers CPython does not
# build `_tkinter` at all, and this project asks for Python's Tk libraries in the guest. The runtime
# half (`python3-tk`, `libtk8.6`, `libtcl8.6`) is in the tree from `PKGS_BASE`; these are removed
# with the rest of the build tools below.
apt-get install -y -qq --no-install-recommends \
    build-essential libssl-dev zlib1g-dev libbz2-dev libreadline-dev libsqlite3-dev \
    libffi-dev liblzma-dev libncurses-dev tk-dev tcl-dev libnsl-dev wget ca-certificates >/dev/null

cd /tmp
wget -q "https://www.python.org/ftp/python/$python_version/Python-$python_version.tgz"
tar xf "Python-$python_version.tgz"
cd "Python-$python_version"
./configure --prefix=/usr/local --enable-shared --with-ensurepip=install >/dev/null
make -j"$(nproc)" >/dev/null
# `DESTDIR`: the build happens in this container, but the *tree being built* is
# /out — without it Python would be installed into the container's own filesystem
# and thrown away with it.
make install DESTDIR=/out >/dev/null
cd /
rm -rf "/tmp/Python-$python_version"

# The shared library Python installs is not in the default search path: an entry
# of its own is what makes `python3` and a virtualenv's interpreter work.
mkdir -p /out/etc/ld.so.conf.d
echo /usr/local/lib > /out/etc/ld.so.conf.d/python.conf
chroot /out ldconfig
chroot /out /usr/local/bin/python3 --version
chroot /out /usr/local/bin/python3 -m venv /tmp/venv-check
chroot /out /tmp/venv-check/bin/pip --version
rm -rf /out/tmp/venv-check
# **Tk really is there**: `_tkinter` is built only when Tk's headers were found, and a Python whose
# `tkinter` import fails is a Python that silently cannot draw a window.
chroot /out /usr/local/bin/python3 -c 'import tkinter; print("tkinter", tkinter.TkVersion)'

# The extra build tools were only needed for the build.
apt-get remove -y -qq --auto-remove build-essential libssl-dev zlib1g-dev libbz2-dev \
    libreadline-dev libsqlite3-dev libffi-dev liblzma-dev libncurses-dev \
    tk-dev tcl-dev wget >/dev/null 2>&1 || true
apt-get clean
rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

say "done"
