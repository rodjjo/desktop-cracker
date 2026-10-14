# desktop-cracker — a microVM desktop (Firecracker + KVM) shown in a window.
#
# **What the project is.**  desktop-cracker boots a **microVM** and puts the desktop running inside
# it on this machine's screen: the guest's screen is an OpenGL window, the keyboard and the mouse
# go to the guest, the host's folders are shared into it, its disk is encrypted, and its own
# network is answered by this process.  Nothing of the host's system is given to the guest but the
# files and folders the user asks for.
#
# **Why a microVM.**  Firecracker with KVM starts in a couple of seconds and each machine is a
# process with its own kernel: fast enough to be a desktop, isolated enough to be a sandbox.  A
# boot that takes longer than a few seconds is a bug to investigate, not a fact to live with.
#
#   architecture.svg      the picture of the whole thing: `make architecture` prints its path
#
# **The features.**
#   * the guest's desktop (Debian 12, LightDM + Xfce, VLC, Firefox, Python 3.13) in a window that
#     is the guest's own resolution, centered, or borderless full screen on a big display;
#   * the window's rules: the keys are global — `numlock + F9` hides it (and asks for the unlock
#     password to bring it back), `numlock + F10` opens the settings — and the sound plays only
#     while the window is visible and the numlock key is held;
#   * an **encrypted root disk** (a raw file, opened inside the guest with the passphrase the user
#     types; the host never holds a key), plus as many additional disks as the settings list;
#   * the host's folders shared into the guest, and the guest's `desk-disk-mount` to mount them;
#   * a **userspace network** for the guest: DHCP, NAT, DNS and NTP are answered in this process,
#     with no tap and no root, and `--ssh-port` carries one host port to the guest's sshd;
#   * the host's X server inside the guest (remote X), so a sandboxed application can still open a
#     window on this machine's desktop;
#   * `desk-disk`, the disk tool, which makes, resizes, re-keys and inspects a disk **inside a
#     microVM of its own** — no root, no loop device, no host package;
#   * `--plugin-path`: a test plugin sees the run's milestones, state, screen and questions, which
#     is how `make system-tests` drives a real run without the application growing test-only code.
#
# **The commands.**
#   make dependencies       what this tree needs from outside: the hypervisor, the base image, this
#                           project's guest kernel — and a report of what the host is missing
#   make                    build (release): the application, the disk tool, the test plugin, the
#                           guest's kernel, its initramfs and its agent.  The output is `target/`
#                           at the root of this tree
#   make rootfs             the guest's own userland (Debian + LightDM + Xfce, VLC, Firefox,
#                           Python 3.13), built in a container, and the ext4 image a disk is seeded
#                           from
#   make rootdisk           the guest's root disk from that userland (an existing one is left alone
#                           unless REPLACE=yes; a previous `root.raw.old` is replaced)
#   make run                run it (nothing else): the guest's desktop in a window, network
#                           attached, encrypted disk
#   make disk-tool          say where `desk-disk` is and how to run it
#   make test               the unit tests (no KVM, no guest, no display server, no dialog)
#   make system-tests       the one-pass system test: one boot, many named steps, needs /dev/kvm
#   make check              fmt + clippy + test
#   make architecture       print the path of `architecture.svg`
#   make doc                the workspace's own documentation (cargo doc)
#   make dist               the .tar.gz the package layout names (bin, libraries, kernel, images,
#                           icons, docs, licenses, VERSION and an install.sh that installs the
#                           host's runtime packages).  Its name carries the version; the folder
#                           inside it is always `desktop-cracker/`
#   make install            extract the package of this version at ~/ (giving ~/desktop-cracker)
#                           and run its install.sh; it asks for `make dist` first when there is no
#                           package for this version
#   make uninstall          remove the installed package and the names it linked into the PATH;
#                           never the user's data (~/.desktop-cracker)
#   make clean              remove the build output (keeps the downloaded media)
#   make clear-build        remove every generated artefact — `target/`, the guest initramfs, the
#                           plugin, the icons — so the next `make build` cannot be half a build
#   make distclean          `clean` plus the downloaded media
#
# **The four things a person needs**, each a section of this file:
#
#   1. **the system dependencies** — "dependencies" below.  `make dependencies` downloads what the
#      project ships with (the hypervisor, the base image, this project's own guest kernel) and
#      runs `scripts/install-deps.sh`, which **reports** what this host is missing and installs
#      nothing behind the user's back.  What a run needs on the host: a C compiler and the archive
#      tools (`gcc cpio gzip curl`), GTK3, GL, `libpulse-simple`, glib/gio, and a readable
#      `/dev/kvm` (the `kvm` group).  Building the guest's userland additionally needs `docker`.
#   2. **the build** — "build" below: `make` (or `make build`) builds the workspace, the disk tool,
#      the test plugin, the guest's kernel, the initramfs and the agent into `target/` at the root
#      of this tree; `make rootfs` builds the guest's userland; `make build-kernel` and
#      `make initramfs` are the finer grain.
#   3. **the dist** — "dist" below: `make dist` writes
#      `dist/desktop-cracker-<version>-x86_64.tar.gz`, whose name carries the version and whose
#      inside is always `desktop-cracker/`.
#   4. **the install** — "install" below: `make install` extracts that package at `~/` (giving
#      `~/desktop-cracker`) and runs the package's own `install.sh`, which links `desk-run` and
#      `desk-disk` into the PATH, adds the desktop entry and the icon, and asks `apt-get` for the
#      runtime libraries that cannot be shipped.
#
# The disk tools are **not** a Makefile feature: `desk-disk` is the program that creates, resizes,
# re-keys and inspects a disk, and it is the user who runs it.  `make rootdisk` is only a
# convenience for a developer who wants a disk ready before the first run.

SHELL       := /bin/bash
CARGO       ?= cargo
PREFIX      ?= $(HOME)/.local
BINDIR      ?= $(PREFIX)/bin
# Kept for `uninstall` alone: an installation made by an **older** version of this command put its
# tree here, and removing what one installed is this command's job even when the layout moved.  A
# package installs nothing here — it runs from the folder it was extracted into.
LIBEXECDIR  ?= $(PREFIX)/libexec/desktop-cracker
APPDIR      ?= $(PREFIX)/share/applications
# **Where `make install` extracts the package** (the home, so the application lands at
# `~/desktop-cracker`).  `make install INSTALL_DIR=/opt` puts it at `/opt/desktop-cracker`.
INSTALL_DIR ?= $(HOME)
# **The workspace**: the application, the libraries it is made of, the guest's agent and kernel,
# and the test plugin.
HS          := desktop-cracker
# **The build output is at the root of this tree**, in `target/` — one folder, whatever crate
# inside the workspace a build is of.
TARGET_DIR := $(CURDIR)/target
export CARGO_TARGET_DIR := $(TARGET_DIR)
BIN := $(TARGET_DIR)/release/desktop-cracker
DISK_BIN := $(TARGET_DIR)/release/desk-disk
# **Everything the project fetches or builds for a run lives under `temp/`** (a scratch folder,
# never committed): `temp/download/` is the media and the hypervisor.
DOWNLOAD    := temp/download
FC_BIN      := $(DOWNLOAD)/firecracker
# **Everything the project's own commands work with lives inside the project**, in the git-ignored
# `temp/`: that is this tree's scratch, and `temp/config.yml` names these paths, so the application is
# run with `--config` (the tree's own file, not the one beside the binary — a package keeps its
# settings and its disks in the package's own folder instead "Settings").
#
# The disk a run boots: **raw**, because Firecracker attaches raw images and nothing else.
# `make rootdisk` makes one with this tree's own
# `desk-disk`, in a microVM of its own — no root, no loop device.
ROOT_DISK   ?= $(CURDIR)/temp/root.raw
DISK_FOLDER ?= $(CURDIR)/temp/disks
SEED_IMAGE  ?= $(CURDIR)/temp/seed.raw
RUN_ARGS    ?= --config $(CURDIR)/temp/config.yml
WITH_VLC_FIREFOX ?= 0
DEBUG       ?= 0
DISK_PASS   ?= test

ifeq ($(DEBUG),1)
CARGO_FLAGS :=
BIN := $(TARGET_DIR)/debug/desktop-cracker
DISK_BIN := $(TARGET_DIR)/debug/desk-disk
else
CARGO_FLAGS := --release
endif

# What the host must have for a microVM to run.  `make dependencies` checks them
# and never installs anything behind the user's back.
#
# `gtk+-3.0` is the window's toolkit: the display window is a `gtk::Window` with a
# `gtk::GLArea`, and every dialog the application asks (`dc-dialog`) is a GTK dialog on the
# same thread — so GTK3 is what the application links and what the host has to have,
# development headers to build and the runtime library to run.
# What a run needs on this host: the compiler, the archive tools, and Firecracker (a released
# binary, `make download`).  A disk is a raw image this tree's own `desk-disk` makes in a
# microVM of its own, so nothing else is required.
REQUIRED_TOOLS := gcc cpio gzip curl
REQUIRED_LIBS  := glib-2.0 gio-2.0 gl libpulse-simple gtk+-3.0

.PHONY: all help build build-debug dependencies deps install-deps download \
        guest-image tools rootfs rootdisk run run-config build-kernel initramfs agent postmortem disk disk-tool seed-image run-plain \
        test-plugin \
        settings set-password test system-tests system-test check fmt clippy doc architecture \
        dist install uninstall clean distclean clear-build

all: build

help:
	@sed -n '2,88p' $(MAKEFILE_LIST) | sed 's/^# \{0,1\}//'

# **The picture of the architecture**, at the root of this tree: `architecture.svg` (plain SVG, no
# build step).  This target prints its path, so `make architecture` is how a person or a script
# finds it.
architecture:
	@echo "$(CURDIR)/architecture.svg"

# ---------------------------------------------------------------------- build
# **One command builds the whole project**: the application and the libraries it is made of
# (this workspace), the disk tool, the test plugin, the guest's kernel and its initramfs, and the
# hypervisor if it is not here yet. Everything it builds lands in **`target/` at the root of
# this tree** (`CARGO_TARGET_DIR`), whichever crate inside the workspace it came from.
build: download run-config
	cd $(HS) && $(CARGO) build $(CARGO_FLAGS)
	# **The disk tool too**, with the same flags: `cargo build` at the workspace builds every crate
	# it depends on but only the *default* members' binaries, so `desk-disk` — and the window it
	# opens — is built here as well.
	cd $(HS) && $(CARGO) build $(CARGO_FLAGS) -p desk-disk
	@$(MAKE) --no-print-directory test-plugin
	@$(MAKE) --no-print-directory guest-image
	@$(MAKE) --no-print-directory firecracker

# The hypervisor.  Firecracker is a **released binary** (this project does not build a VMM), and
# `make dependencies` says where it comes from; a tree that already has one is left alone.
firecracker:
	@test -x $(FC_BIN) || { \
		if [ -x temp/fc-study/bin/firecracker ]; then \
			cp temp/fc-study/bin/firecracker $(FC_BIN) && chmod +x $(FC_BIN); \
			echo "make: $(FC_BIN)"; \
		else \
			echo "make: no Firecracker at $(FC_BIN) — run make download (see README.md)"; \
		fi; \
	}

# The **test plugin**: a shared library the application loads only
# when it is started with `--plugin-path`, which is how a test sees and answers the application's
# dialogs.
test-plugin:
	cd $(HS) && $(CARGO) build $(CARGO_FLAGS) -p desk-plugin
	@echo "plugin: $(TARGET_DIR)/$(if $(findstring --release,$(CARGO_FLAGS)),release,debug)/libdesk_plugin.so"

build-debug:
	cd $(HS) && $(CARGO) build

# --------------------------------------------------------------- dependencies
# One word, as this project puts it: the files the microvm needs, plus a
# report of what the host is missing.
dependencies: download install-deps

deps: dependencies

# What the microVM needs from outside this tree: **Firecracker** (the released binary) — the
# guest's userland comes from `make rootfs`, and its kernel and initramfs from `make build`.
download: firecracker
	@bash scripts/download.sh

install-deps:
	@bash scripts/install-deps.sh
	@printf '%-22s' "required tools:"
	@missing=0; for t in $(REQUIRED_TOOLS); do \
		if ! command -v $$t >/dev/null 2>&1; then printf ' %s(missing)' $$t; missing=1; fi; \
	done; \
	for lib in $(REQUIRED_LIBS); do \
		if ! pkg-config --exists $$lib 2>/dev/null; then printf ' %s(missing)' $$lib; missing=1; fi; \
	done; \
	if [ $$missing = 0 ]; then echo " all present"; else echo ""; fi
	@if [ ! -r /dev/kvm ]; then \
		echo "note: /dev/kvm is not readable — add yourself to the 'kvm' group"; fi

# --------------------------------------------------------------------- tools
# **The guest's media**: the kernel this project builds from Firecracker's own guest configuration
# (plus the options the guest needs — `scripts/kernel-options.sh`) and the initramfs that carries
# its modules, the project's guest tools and the guest's agent.
#
# Both are what a run boots: a kernel built for a microVM reaches the guest in ~450 ms where a
# distribution kernel takes ~1 s probing hardware Firecracker does not have (measured).
guest-image:
	$(MAKE) --no-print-directory build-kernel initramfs
	@mkdir -p $(DOWNLOAD)
	@echo "make: $(DOWNLOAD)/kernel and $(DOWNLOAD)/initramfs.gz (this project's own build)"

tools: guest-image
	@mkdir -p tools/guest-smoke/out
	@bash tools/guest-smoke/build.sh tools/guest-smoke/out/guest-smoke-initramfs.gz

# ------------------------------------------------------------ the guest's media, in detail
# The finer grain behind `make build` and `make guest-image`: each of these is one piece of
# the guest's side, for when that is what is wanted.

seed-image:
	./tools/seed-image.sh $(DOWNLOAD)/rootfs $(SEED_IMAGE)

build-kernel:
	./scripts/kernel-build.sh


# The guest's own half: the agent, and the initramfs that starts it.  The initramfs is the
# **project's own** (`../tools/guest-image/build.sh`, with this tree's kernel modules) plus
# the agent's lines (`tools/make-initramfs.sh`) — one builder, one behaviour.
agent:
	./tools/guest-tools.sh --out $(HS)/guest-agent-rs/out/guest-tools
	./$(HS)/guest-agent-rs/make-agent.sh --initramfs
	install -m 0644 $(HS)/guest-agent-rs/out/initramfs.gz $(DOWNLOAD)/initramfs.gz
	@echo "make: $(DOWNLOAD)/initramfs.gz now carries this build's agent"

# **The image a run boots is the one this writes.**  `tools/make-initramfs.sh` builds it under
# `$(HS)/guest-agent-rs/out/`, but a run reads `$(DOWNLOAD)/initramfs.gz` (`media.rs` looks there
# first), so the builder's own path and the run's path are written in the same pass.  That is not
# tidiness: a guest-side edit tested against the image one build behind it looks exactly like the
# bug still being there (measured 2026-10-11 — four runs were spent chasing the guest's sound
# while the initramfs being booted was a build old).
initramfs: build-kernel
	./tools/make-initramfs.sh --out $(CURDIR)/$(DOWNLOAD)/initramfs.gz


# **A postmortem build**: the guest's agent with the sanitizers in, so a crash in the guest says
# where it was instead of freezing a desktop silently.  The agent is the Rust one
# (`desktop-cracker/guest-agent-rs`), so this is that build with Rust's own sanitizers enabled: the
# nightly-only flags a sanitized guest needs are named here, and a build without them says so
# rather than pretending.  It is a *temporary instrument* — the operator's own words — and it is
# removed with the bug it was built for (`AGENTS.md`).
postmortem: build-kernel
	cd $(HS)/guest-agent-rs && \
	  RUSTFLAGS="-Z sanitizer=address" \
	  cargo +nightly build --release --target x86_64-unknown-linux-musl \
	    -Z build-std=std,panic_abort 2>&1 | tail -3 || \
	  { echo "make: a sanitized Rust guest needs a nightly toolchain with rust-src"; exit 1; }
	GUEST_INITRAMFS=$(CURDIR)/$(DOWNLOAD)/initramfs-base.gz \
	  AGENT_OUT=$(CURDIR)/$(DOWNLOAD)/initramfs.gz \
	  $(HS)/guest-agent-rs/make-agent.sh --initramfs
	@echo "make: the initramfs now carries the sanitized agent ($(HS)/guest-agent-rs/out/initramfs.gz)"


# A disk to run with: a raw LUKS image in the project's own scratch folder.  The system on it is
# built by a disk job (`make disk` makes an empty container; `desk-disk rootdisk` fills it) — see
# README.md.
DISK     ?= $(UP)/temp/disk.raw
DISK_GIB ?= 6

disk:
	./scripts/make-disk.sh $(ROOT_DISK) $(DISK_GIB)


# The disk tool, run from this tree: it needs the kernel and the initramfs beside it.
disk-tool: build initramfs
	@echo "desk-disk is at target/release/desk-disk; run it with, e.g.:"
	@echo "  target/release/desk-disk info --path ../temp/d.raw --pass '<passphrase>' \\"
	@echo "      --firecracker $(FC_BIN)"


# The seed image: the project's own userland as a read-only ext4 a disk job copies from.
SEED     ?= $(UP)/temp/seed.raw
USERLAND ?= $(DOWNLOAD)/rootfs


# The same run with the project's own guest image and no guest agent: the console and the
# balloon only (what a step-2 run looks like).
run-plain: build
	cd $(HS) && $(CARGO) run --release --example run -- \
	    --firecracker $(FC_BIN) \
	    --kernel $(DOWNLOAD)/kernel \
	    --initramfs $(DOWNLOAD)/initramfs.gz \
	    --rootfs $(DOWNLOAD)/rootfs.ext4 \
	    --no-readiness $(RUN_ARGS)

# --------------------------------------------------------------------- rootfs
# The guest's userland, built in a container (the host's own packages are never
# touched) and packed as the archive a new disk is seeded from.
# The two directories the build **binds into its containers**.  They are made here, as this
# user, because `docker run -v` creates a missing source itself — as **root** — and a
# root-owned directory that the build then tries to write into fails with "Permission
# denied" (measured: `cp: cannot create regular file '…/libdesk-guest/desk_display.h':
# Permission denied`, which is a build that dies three minutes in for a reason that has
# nothing to do with what it was building).
rootfs:
	@mkdir -p $(DOWNLOAD)/libdesk-guest
	@bash tools/rootfs/build.sh $(DOWNLOAD)/rootfs

# A root disk from that userland.  `desk-disk` does it, in a microVM of its
# own, so this needs no root and no loop device.
#
# `REPLACE` (default `no`): a root disk holds the user's files, so by default an existing one is
# left alone and the command stops.  `make rootdisk DISK_PASS=test REPLACE=yes` is the answer to
# "the userland changed and I want the disk to match it": the disk that was there is moved aside to
# `<disk>.old` — never deleted — and a new one is made from the current userland.  A previous
# `<disk>.old` is overwritten, because it is itself a copy that was already replaced once.
REPLACE     ?= no

rootdisk: build rootfs
	@if [ -f $(ROOT_DISK) ]; then \
		if [ "$(REPLACE)" = yes ]; then \
			mv $(ROOT_DISK) $(ROOT_DISK).old; \
			echo "$(ROOT_DISK) replaced; the disk it replaces is at $(ROOT_DISK).old"; \
		else \
			echo "$(ROOT_DISK) already exists; left alone (REPLACE=yes makes a new one and keeps this one as $(ROOT_DISK).old)"; \
			exit 0; \
		fi; \
	fi
	@# **`rootdisk` is the command that puts a userland in** (the operator, 2026-10-13): `create`
	@# makes an empty data disk, and the root one — the disk the guest boots from — is made by this
	@# one, with the userland this tree built.
	$(DISK_BIN) rootdisk --path $(ROOT_DISK) --size 24G \
		--firecracker $(CURDIR)/$(FC_BIN) \
		--kernel $(DOWNLOAD)/kernel --initramfs $(DOWNLOAD)/initramfs.gz \
		$(if $(DISK_PASS),--pass $(DISK_PASS),)

# ----------------------------------------------------------------------- run
# **`make run` does nothing but run, and it is fast on purpose.**  It is the command a person
# reaches for a dozen times an hour while working on the guest, and a command that re-links a
# workspace, rebuilds a kernel or repacks a userland on every keystroke is a command nobody uses.
# Building is `make build`'s job (and `make rootfs`/`make rootdisk` for the guest's own two
# artefacts); what is left here is the one cheap thing a run needs — `run-config`, which writes
# `temp/config.yml` once and then leaves it alone.
#
# That file is what keeps a run of **this tree** from touching an installed package's settings and
# disks: without it the application would look beside its own binary (or in `~/.desktop-cracker`)
# and use whatever it found there, which is not what a developer means by `make run`.
#
# Nothing here checks that the pieces are there, either: the application is what knows what a run
# needs, and it says so itself when something is missing (the kernel, the initramfs, the
# hypervisor, the disk) — in the same words a user of the installed package gets.
run: run-config
	DESK_FIRECRACKER=$(CURDIR)/$(FC_BIN) $(BIN) $(RUN_ARGS)

# The configuration `make run` passes: it is written once and then left alone (it is the
# user's too — memory, shares, the unlock password live there), and it points at the
# project's temp folder.
#
# The vCPU count is **12**: this host has 24 cores, and giving the guest all of them made
# the boot *slower* and the guest's own watchdog complain (measured: 24 vCPUs took 11 s to
# the first console line and a soft lockup appeared in the log; 8 took 9.2 s, 12 is the
# operator's own choice).  A microvm whose guest spends its time in per-CPU bring-up is not
# faster for having the cores.
.PHONY: run-config
run-config:
	@mkdir -p temp $(DISK_FOLDER)
	@test -f temp/config.yml || { \
		printf 'shared_folders: []\nroot_disk: %s\ndisk_folder: %s\nmemory_mb: 6144\nvcpus: 12\nballoon_automatic: true\nremote_x: false\n' \
			"$(ROOT_DISK)" "$(DISK_FOLDER)" > temp/config.yml; \
		echo "make: wrote temp/config.yml (root disk $(ROOT_DISK))"; \
	}

# Settings helpers (they only touch ~/.desktop-cracker/config.yml).
settings: build
	$(BIN) --show-settings

set-password: build
	@$(BIN) --set-password

# --------------------------------------------------------------------- tests
# The project's own tests: every crate of the workspace (`desktop-cracker/`), including the Firecracker
# machine's channels, the application's libraries and the guest's own tools' Rust half.
test:
	cd $(HS) && $(CARGO) test

# **The one-pass system test**: it boots the application once, drives it through the **plugin**
# (`--plugin-path`) and asserts on events, `/status` and `/frame` — never on a log, never with a
# dialog on screen (`AGENTS.md`, "System testing").  The person running it types the root disk's
# passphrase; nothing about it is written anywhere.
system-tests: build download
	@SYSTEM_TEST_ARGS="$(SYSTEM_TEST_ARGS)" \
		DESK_FIRECRACKER="$(CURDIR)/$(FC_BIN)" \
		DESK_DESKTOP="$(CURDIR)/$(BIN)" \
		bash system-tests/run.sh

# `system-test` was the old name; it still works.
system-test: system-tests

check: fmt clippy test

fmt:
	cd $(HS) && $(CARGO) fmt --all -- --check

clippy:
	cd $(HS) && $(CARGO) clippy --all-targets -- -D warnings

doc:
	cd $(HS) && $(CARGO) doc --workspace --no-deps --document-private-items


# ----------------------------------------------------------------------- dist
# A tarball with everything needed to run the project somewhere else: the application, the
# hypervisor, the guest's kernel and image, and the script that installs what cannot be shipped
# (the system libraries, the kvm group).
# `dist` is **one command**: it builds what it ships.  `guest-image` and `firecracker` are the
# guest's kernel, its initramfs and the hypervisor (both idempotent — the kernel build has its own
# stamp, and a tree that has Firecracker is left alone); the guest's userland image is built by the
# script itself when the userland is here and the image is not.  `dist.sh` refuses, with the command
# to run, when a piece it needs is missing rather than shipping a package that cannot boot.
dist: guest-image firecracker
	@bash scripts/dist.sh

# `install` is **the extraction of the package**, not a copy of a build tree: it takes the tarball
# `make dist` built for the version this tree has and extracts it at the target folder (the home, by
# default), which is `~/desktop-cracker`, and then runs the package's own `install.sh` there.  That
# is what "the user extracts this to any folder he wants and it is suppose to work from
# there" means for a developer too: the installed application *is* the package, one copy, running
# from where it was extracted.
#
# The folder has **no version in its name** on purpose: a new release replaces `~/desktop-cracker`
# instead of leaving `desktop-cracker-0.1.0/`, `desktop-cracker-0.2.0/` and `desktop-cracker-0.3.0/`
# side by side.  The version lives inside the package, in `VERSION`.
#
# **There is no package for this version, there is no install**: the command says "run `make dist`
# first" rather than installing a half-built tree.  `install` deliberately does not depend on `dist`
# — packaging is a decision the developer makes, not a side effect of installing.
#
# It installs **no development tool**: no compiler, no `-dev` package, no cargo, no test plugin, no
# source.  `make dependencies` is where the build packages are named, and they stay there.
install:
	@bash scripts/install-package.sh $(INSTALL_DIR)

# `uninstall` removes the installed package and the names it linked into the PATH.  It runs the
# package's own `uninstall.sh` when the package is there, and falls back to the names this Makefile
# knows about for an installation made by an older version of this command.
#
# It **does not delete the user's data**: `config.yml` and `disks/` in the package's folder are the
# user's, and the package's own script keeps the whole folder when they are there.  An uninstall that
# removed a disk would be a data loss no command should be able to cause by accident.
uninstall:
	@if [ -x $(INSTALL_DIR)/desktop-cracker/uninstall.sh ]; then \
		bash $(INSTALL_DIR)/desktop-cracker/uninstall.sh --prefix $(PREFIX); \
	else \
		echo "uninstall: no package at $(INSTALL_DIR)/desktop-cracker; removing the names it left"; \
		rm -f $(PREFIX)/bin/desk-run $(PREFIX)/bin/desk-disk; \
		rm -f $(APPDIR)/desktop-cracker.desktop; \
		rm -f $(PREFIX)/share/icons/hicolor/256x256/apps/desktop-cracker.png; \
		rm -rf $(LIBEXECDIR); \
		echo "uninstall: your data is untouched.  To remove it as well, delete:"; \
		echo "           $(INSTALL_DIR)/desktop-cracker/config.yml and $(INSTALL_DIR)/desktop-cracker/disks"; \
		echo "                                         (the settings and the disks — and with them,"; \
		echo "                                         everything installed inside the guest)"; \
	fi

# ------------------------------------------------------------------- cleaning
#
# `clear-build` is the one to reach for when something behaves like an older build:
# every artefact this Makefile *generates* is removed, so the next `make build` cannot
# be half a build.  What it keeps is exactly what is not built here — the downloaded
# kernel and the guest userland (minutes to rebuild) and the user's disks in
# `temp/` — and `make dependencies` re-fetches any of those that is missing.
clear-build:
	@echo "clear-build: removing the build output and the generated guest artefacts"
	cd $(HS) && $(CARGO) clean
	rm -rf $(DOWNLOAD)/initramfs.gz $(DOWNLOAD)/icons $(DOWNLOAD)/libdesk $(DOWNLOAD)/libdesk-guest
	rm -rf tools/guest-smoke/out
	@echo "clear-build: kept what is not built here (the kernel, the guest userland,"
	@echo "             the disks in temp/); run 'make build' now"

clean:
	cd $(HS) && $(CARGO) clean

# `distclean` also drops the downloaded artefacts; `clean` keeps them.
distclean: clean
	rm -rf $(DOWNLOAD)/kernel $(DOWNLOAD)/initramfs.gz $(DOWNLOAD)/base.qcow2 \
		$(DOWNLOAD)/rootfs $(DOWNLOAD)/rootfs.tar.gz $(DOWNLOAD)/README
