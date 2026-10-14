#!/bin/bash
# Build the guest agent, and an initramfs that starts it — the guest half of a Firecracker
# run, for this project's own measurements and for the system test that comes with
# step 8.
#
#   ./make-agent.sh                 # build the agent into out/desk-agent
#   ./make-agent.sh --initramfs     # ...and out/initramfs.gz
#
# The initramfs it patches is the **project's own** (`tools/guest-image/build.sh`), with two
# things changed — and both of them are about *how the run talks to the guest*, never about
# what the guest does:
#
#   * the init's last act grows the agent's lines in front of it: the run's files arrive on
#     the control channel, the guest's network is its own TUN, and `DESK-READY` is said on the
#     console **and** as one frame on the readiness channel (which is what the run waits for);
#   * the disk-job branch fetches the job's secrets from the control channel instead of a 9P
#     share, and then hands over to the project's own `guest-tools diskmgr`.
#
# The guest then runs the project's own `guest-tools boot`, unchanged: the mounts, the DHCP,
# `rootboot`, the session on the disk — all of it still the project's.
#
# Two variables let this script work on **this tree's** initramfs instead of the project's:
#
#   GUEST_INITRAMFS=path   the initramfs to unpack (default: the one this tree builds,
#                          `temp/download/initramfs.gz`)
#   AGENT_OUT=path.gz      where to write the patched one (default: out/initramfs.gz)
#
# Nothing here is part of the application: it is the guest side, and the packaging step
# (`make dist`) is what ships this program.
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
out="$here/out"
mkdir -p "$out"

agent="$out/desk-agent"
say() { printf 'guest-agent: %s\n' "$*"; }

# **The guest's agent is this crate** (`guest-agent-rs`): a static musl build, so the guest needs
# none of this host's libraries and the closure below is empty for it.  The C agent that used to be
# beside this script is gone — every verb the guest has (the screen, the shares' FUSE filesystem,
# the sound, the network, the way out, the run's files) is Rust, and a run installs nothing else.
#
# **The build output is the tree's own `target/`** (`CARGO_TARGET_DIR`, which the Makefile exports):
# one folder for the whole project, at the root of the tree, whichever crate a build is of.
target_dir=${CARGO_TARGET_DIR:-$root/target}
rust_agent="$target_dir/x86_64-unknown-linux-musl/release/desk-agent"
say "building the agent (Rust, static: the guest needs nothing of this host's libc)"
( cd "$here" && cargo build --release --target x86_64-unknown-linux-musl 2>&1 | tail -2 )
if [ ! -x "$rust_agent" ]; then
    say "the Rust agent did not build: $rust_agent"
    exit 1
fi
install -m 0755 "$rust_agent" "$out/desk-agent"
ls -lh "$out/desk-agent" | awk '{print "guest-agent: " $5 " " $9 " (static)"}'

# **The agent's library list, as a file the guest's init can read.**  `rootboot` copies the agent
# and its libraries into the system on the disk, and `ldd` is a shell script that does not exist in
# that system's `/bin` yet (measured 2026-10-10: `ldd: not found`, and the agent was then copied
# without the one library it cannot run without).  A static binary has none, and the empty file is
# still written: it is the shape `rootboot` reads.
AGENT_LIBS=""
printf '%s\n' "$AGENT_LIBS" | sed '/^$/d' > "$out/desk-agent.libs"
say "the agent's closure: none (a static binary)"

if [ "${1:-}" != "--initramfs" ]; then
    say "no --initramfs asked for; the agent is built"
    exit 0
fi

work="$out/initramfs"
rm -rf "$work"
mkdir -p "$work"
source_initramfs=${GUEST_INITRAMFS:-$root/temp/download/initramfs.gz}
out_file=${AGENT_OUT:-$out/initramfs.gz}
[ -r "$source_initramfs" ] || { say "no initramfs at $source_initramfs"; exit 2; }
( cd "$work" && zcat "$source_initramfs" | cpio -idm --quiet )

install -m 0755 "$agent" "$work/bin/desk-agent"
# The list of its libraries, in the form the guest's `rootboot` reads when it carries the agent
# into the system on the disk (empty for the Rust one: a static binary needs nothing).
install -m 0644 "$out/desk-agent.libs" "$work/bin/desk-agent.libs"
# Its libraries, at the paths the binary asks for (the same closure `tools/guest-image/build.sh`
# installs for `cryptsetup`).
for so in $AGENT_LIBS; do
    case "$so" in
    /lib64/*) install -D -m 0755 "$so" "$work$so" ;;
    *) install -D -m 0644 "$so" "$work$so" ;;
    esac
done

# The **guest tools**: the project's own, with the differences this path needs (a shared folder is
# a FUSE mount here, not a 9P one, and `rootboot` carries the agent into the system on the disk —
# `tools/guest-tools.sh` builds it).  It is also what **the disk's own session** runs: the agent's
# `session` verb is what `desk-agent.service` starts after the pivot, so the binary has to be
# in the initramfs' `/bin` for `rootboot` to copy it (see `tools/guest-tools.sh`, point 4).
if [ -x "$out/guest-tools" ]; then
    install -m 0755 "$out/guest-tools" "$work/bin/guest-tools"
    say "the guest tools: this tree's own (shares are FUSE mounts)"
fi

# The disk job's branch: at first the control directory was a 9P share the host
# mounted before the guest booted; here it is the control channel (56000), and this is what
# puts the run's files where the guest's own tool reads them.  One substitution, so
# `guest-tools diskmgr` needs no change at all.
python3 - "$work/init" <<'PATCH'
import sys
path = sys.argv[1]
text = open(path).read()
old = """*desk.diskjob=*)
    mkdir -p /run/desktop-cracker
    mount -t 9p -o trans=virtio,version=9p2000.L control /run/desktop-cracker 2>/dev/null || true
    exec /bin/guest-tools diskmgr
    ;;"""
new = """*desk.diskjob=*)
    # The run's files (the secrets, the job's plan) arrive on the **control channel**, and
    # the agent puts them where the guest's own disk tool reads them.
    exec /bin/desk-agent job
    ;;"""
if old in text:
    text = text.replace(old, new)
    open(path, "w").write(text)
PATCH

# One patch, and it is idempotent.  What the guest's own init has to say at the end of its
# boot, and what this project changed about it:
#
#   * the small files the run has for this guest (a disk's passphrase, the mount plan, the
#     addresses of the network) arrive on the **control channel** and are put where the
#     guest's own tools read them (`/run/desktop-cracker`) — that is what a 9P share used to be;
#   * the guest's **network** is its own TUN, configured from what the run told it;
#   * the guest says **`DESK-READY`** on its console *and* on the readiness channel, which is
#     what the run waits for;
#   * and then the project's own `guest-tools boot` does everything it always did — the
#     mounts, the DHCP, and `rootboot` if the run asked for the system on the disk.
python3 - "$work/init" <<'PATCH'
import sys

path = sys.argv[1]
text = open(path).read()

tail = """# **The way out, first**: the guest's own shutdown (`dc-fc-power`).  Firecracker has no ACPI
# power management, so nothing the host does can power this guest off — the *guest* is what ends
# the machine, by resetting itself (the kernel's own `reboot(2)` pulses the i8042 controller
# Firecracker emulates, and Firecracker exits with it).  It is started **before the pivot**
# because that is the only moment the request reaches a kernel this process owns: the handover
# to the system on the disk discards its memory (measured 2026-10-10: after `switch_root` the
# agent is gone, and the guest cannot be asked at all).
mkdir -p /run/desktop-cracker
/bin/desk-agent shutdown --watch /run/desktop-cracker/poweroff &

# **This project's own modules**, which the project's list does not load: the framebuffer the
# guest's screen comes from (Firecracker has no display device) and the loopback sound
# card that stands in for virtio-snd. `modprobe` is asked for them rather than
# `insmod`'s being fed a list: the module tree in this initramfs is this kernel's own
# (`depmod` wrote it), and modprobe is the tool that knows the order and *why* a module refused.
# It is **the only framebuffer** the guest loads, and that is not an accident: `/dev/fb0` has
# to be this project's own (a second fbdev driver — the kernel's `vkms`, say — would take
# `fb0` and Xorg would draw into a screen nobody is watching; measured 2026-10-10).
for m in snd-aloop desk_fb; do
    modprobe "$m" 2>/dev/null || true
done

# The run's own files, over the control channel: a disk's passphrase, the mount plan, the
# addresses of the network.  Names the run chose, and nothing else exists.
mkdir -p /run/desktop-cracker
/bin/desk-agent control diskplan mounts disks root.pass x-display.env network shares display-geometry 2>/dev/null

# The guest is up: the line a person reads, and the same line as an event for the run.
DESK_READY="DESK-READY initramfs MemTotal=$(awk '/^MemTotal:/{print $2}' /proc/meminfo 2>/dev/null)kB control=channel"
/bin/desk-agent ready "$DESK_READY" &

# **One session owns the channels.**  A run that is going to enter the system on the disk
# (`desk.rootboot=1`, which `guest-tools boot` reads a moment from now) must **not** bring the
# screen, the sound, the shares and the network up here as well: that system starts the agent again
# (`desk-agent.service`) and *it* is the session the user sits in.  Two of everything would be
# two connections to a channel that answers one — measured 2026-10-10, `the channel is gone: Broken
# pipe` as the second screen agent dialled 53000 and the first one held it.
#
# So the initramfs keeps what only it can do — the run's files (`root.pass` above all) and the way
# out — and the guest's own session brings the rest up.
if grep -q "desk.rootboot=1" /proc/cmdline; then
    echo "DESK-SESSION booting the system on the disk: it brings the screen, the sound, the shares and the network up"
    exec /bin/guest-tools boot
fi

# **One session owns the channels**, and it is the agent's own: the screen, the sound, the
# shares and the network are one program's business (`desk-agent session --initramfs`),
# not four shell lines that each start something of their own.  What the init keeps is what
# only it can do — the run's files (`root.pass` above all), the modules and the way out.
#
# A run that is going to enter the system on the disk (`desk.rootboot=1`, which
# `guest-tools boot` reads a moment from now) must **not** bring those up here as well: that
# system starts the agent again (`desk-agent.service`) and *it* is the session the user
# sits in.  Two of everything would be two connections to a channel that answers one —
# measured 2026-10-10, `the channel is gone: Broken pipe` as the second screen agent dialled
# 53000 and the first one held it.
if grep -q "desk.rootboot=1" /proc/cmdline; then
    echo "DESK-SESSION booting the system on the disk: it brings the screen, the sound, the shares and the network up"
    exec /bin/guest-tools boot
fi

# The guest's own session: the screen (this project's framebuffer, at the geometry the run
# decided), the sound, the shared folders and the guest's own TUN — and then the project's own
# init, unchanged, which mounts what it is told to mount and, when the run asked for it, opens
# the root disk's container and enters the system on it.
exec /bin/desk-agent session --initramfs -- /bin/guest-tools boot
"""

text = text.replace("exec /bin/guest-tools boot", tail.rstrip("\n"))
open(path, "w").write(text)
PATCH

( cd "$work" && find . -print0 | cpio -o -H newc --null --quiet | gzip -9 ) > "$out_file"
say "$(du -h "$out_file" | cut -f1) $out_file"
# The unpacked tree is scratch (`out/initramfs` is only ever read while patching): a person
# who wants to look at an init can run this script again.
rm -rf "$work"
