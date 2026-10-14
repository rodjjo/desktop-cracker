#!/bin/sh
# desk-disk-mount — the guest's own tool for the **additional disks** an desktop-cracker
# run attached to this microVM (Settings: *additional disk — a list of disks and
# their access mode (RW/RO), the user mounts them himself*).
#
# The application attaches a disk and stops there: it never mounts one, never asks for its
# password and does not care whether it holds a LUKS container or a plain filesystem.  This is
# the other half of that decision, and it is the **only** thing this script does:
#
#     desk-disk-mount                       the disks this run attached
#     desk-disk-mount open  NAME [WHERE]    open it (asking for a password when it is a
#                                               LUKS container) and mount its filesystem
#     desk-disk-mount close NAME [WHERE]    unmount it and close the container
#
# What the host attached is written in the control share (`/run/desktop-cracker/disks`), one line per
# disk: `<device> <name> <ro|rw>`.  A disk is looked up by its **name** (the settings' name for
# it), which is what makes "which of these is my `data`?" a question with an answer.
#
# Two shapes of disk, and both are ordinary Linux:
#
#   * a **LUKS container** — what `desk-disk create` makes — is opened with `cryptsetup` and
#     the password the user types here.  The password is never written anywhere: `cryptsetup`
#     reads it from the terminal (or from this script's standard input, for a script), and the
#     only thing left behind is the mapped device;
#   * a **plain filesystem** (no container) is mounted directly.
#
# A disk that holds a **partition table** (the shape `desk-disk` gives every disk it makes:
# a small state partition and the root one) has its **last** partition mounted: that is where
# the filesystem is, on a disk made by this project.  A disk with no partition table has its
# own device mounted, which is what a plain image written with `dd` is.
#
# Mounting needs root, and the guest's user is a `sudo` user: the script
# asks for that password itself, once, and re-runs under sudo.

set -u

PLAN=${DESK_DISKS_PLAN:-/run/desktop-cracker/disks}
MOUNT_ROOT=${DESK_DISK_MOUNT_ROOT:-/mnt}
MAPPER_PREFIX=desktop-cracker

say() { printf '%s\n' "$*"; }
die() { printf 'desk-disk-mount: %s\n' "$*" >&2; exit 1; }

# Which disks are there.  Read from the control share, which the host writes before the guest
# boots and which stays readable for the whole run.
plan_lines() {
    [ -r "$PLAN" ] || return 0
    grep -v '^#' "$PLAN" 2>/dev/null | grep -v '^[[:space:]]*$'
}

lookup() {
    want=$1
    found=""
    # `read` per line: the plan is `<device> <name> <ro|rw>` and a name has no spaces in it.
    while read -r dev name mode; do
        [ -n "${dev:-}" ] || continue
        if [ "$name" = "$want" ]; then
            DEVICE=$dev
            MODE=${mode:-rw}
            NAME=$name
            found=yes
            return 0
        fi
    done <<EOF
$(plan_lines)
EOF
    [ -n "$found" ]
}

cmd_list() {
    if ! plan_lines | grep -q .; then
        say "no additional disk is attached to this run"
        say "(the host attaches one with --disk PATH, or from the settings window)"
        return 0
    fi
    printf '%-12s %-10s %-6s %s\n' NAME DEVICE MODE "WHAT IS ON IT"
    plan_lines | while read -r dev name mode; do
        [ -n "${dev:-}" ] || continue
        kind=$(blkid -o value -s TYPE "$dev" 2>/dev/null || true)
        [ -n "$kind" ] || kind=$(lsblk -no FSTYPE "$dev" 2>/dev/null | head -1)
        [ -n "$kind" ] || kind="(nothing recognised)"
        case "$kind" in
        crypto_LUKS) kind="LUKS (a container: open asks for its password)" ;;
        esac
        printf '%-12s %-10s %-6s %s\n' "$name" "$(basename "$dev")" "$mode" "$kind"
    done
    say ""
    say "mount one with: desk-disk-mount open NAME [WHERE]"
}

# Where a disk's filesystem is, once any container is open: the **last** partition when the
# device has a partition table, and the device itself when it has none.
filesystem_device() {
    dev=$1
    last=""
    for part in "$dev"[0-9]* "$dev"p[0-9]*; do
        [ -b "$part" ] || continue
        last=$part
    done
    if [ -n "$last" ]; then
        printf '%s\n' "$last"
    else
        printf '%s\n' "$dev"
    fi
}

cmd_open() {
    name=${1:-}
    where=${2:-}
    [ -n "$name" ] || die "open needs a disk name (see: desk-disk-mount)"
    lookup "$name" || die "no attached disk is called '$name' (see: desk-disk-mount)"
    [ -b "$DEVICE" ] || die "$DEVICE is not a block device (was the disk attached?)"
    [ -n "$where" ] || where="$MOUNT_ROOT/$NAME"

    if blkid -o value -s TYPE "$DEVICE" 2>/dev/null | grep -q '^crypto_LUKS$'; then
        if [ -e "/dev/mapper/$MAPPER_PREFIX-$NAME" ]; then
            say "already open: /dev/mapper/$MAPPER_PREFIX-$NAME"
        else
            say "opening the LUKS container on $DEVICE (its password is asked for now)"
            # At a terminal the **person** types it, and `cryptsetup` asks for it itself.  When
            # standard input is not a terminal (a script, a test, an ssh command with its stdin
            # piped) the passphrase is the next line of that input, and it is handed to
            # `cryptsetup` as a **key file in RAM** which is deleted the moment the container is
            # open: `cryptsetup`'s own prompt is read through `/dev/tty`, which a caller like that
            # does not have, and its `--key-file /dev/stdin` reads a stream it also cannot re-read
            # (measured 2026-10-10: `No key available with this passphrase` and `Nothing to read on
            # input`, for a container whose passphrase was right).  Nothing is written to disk: the
            # key lives in `/run`, which is this guest's tmpfs.
            if [ -t 0 ]; then
                if [ "$MODE" = "ro" ]; then
                    cryptsetup luksOpen --readonly "$DEVICE" "$MAPPER_PREFIX-$NAME" ||
                        die "the container could not be opened (wrong password?)"
                else
                    cryptsetup luksOpen "$DEVICE" "$MAPPER_PREFIX-$NAME" ||
                        die "the container could not be opened (wrong password?)"
                fi
            else
                key=/run/desktop-cracker-key.$$
                (umask 077; IFS= read -r passphrase && printf '%s' "$passphrase" > "$key") ||
                    die "open needs the container's passphrase on standard input"
                if [ "$MODE" = "ro" ]; then
                    cryptsetup luksOpen --readonly --key-file "$key" "$DEVICE" \
                        "$MAPPER_PREFIX-$NAME"
                else
                    cryptsetup luksOpen --key-file "$key" "$DEVICE" "$MAPPER_PREFIX-$NAME"
                fi
                opened=$?
                rm -f "$key"
                [ "$opened" = 0 ] || die "the container could not be opened (wrong password?)"
            fi
        fi
        target=$(filesystem_device "/dev/mapper/$MAPPER_PREFIX-$NAME")
    else
        target=$(filesystem_device "$DEVICE")
    fi

    say "mounting $target on $where"
    mkdir -p "$where"
    if [ "$MODE" = "ro" ]; then
        mount -o ro "$target" "$where" || die "$target could not be mounted on $where"
        rest="$(stat -c %a "$where")"
        [ "$rest" = 555 ] || chmod 0555 "$where"
    else
        mount "$target" "$where" || die "$target could not be mounted on $where"
        # **The user who asked for it may write in it.**  The tool has just re-run itself under
        # `sudo` (mounting needs root), so the plain `cryptsetup`/`mount` calls left the mount
        # point root-owned — a disk mounted for the user that the user cannot write in would be
        # the opposite of what "the user mounts them himself" means (measured 2026-10-10:
        # `/mnt/plain/hello: Permission denied`).  The caller's own uid/gid are what the top of
        # the mount point is given; the rest of the filesystem keeps its own permissions.
        owner="${SUDO_UID:-$(id -u)}"
        group="${SUDO_GID:-$(id -g)}"
        rest="$(stat -c %a "$where")"
        [ "$rest" = 755 ] || chmod 0755 "$where"
        chown "$owner:$group" "$where" 2>/dev/null || true
    fi
    say "mounted: $where ($(df -h "$where" | tail -1 | awk '{print $2" of "$3}') used)"
    say "unmount it with: desk-disk-mount close $NAME $where"
}

cmd_close() {
    name=${1:-}
    where=${2:-}
    [ -n "$name" ] || die "close needs a disk name"
    [ -n "$where" ] || where="$MOUNT_ROOT/$name"
    if mountpoint -q "$where" 2>/dev/null; then
        umount "$where" || die "$where could not be unmounted (something is using it)"
        say "unmounted $where"
    fi
    if [ -e "/dev/mapper/$MAPPER_PREFIX-$name" ]; then
        cryptsetup luksClose "$MAPPER_PREFIX-$name" && say "closed the container"
    fi
}

# One word, the same way every time: what the tool is being asked to do, whether it is about to
# be run again under `sudo`, and which of the two the guest ran.
COMMAND=${1:-list}

# **Only the commands that mount need root**, and `list` is not one of them: it reads the run's
# own plan (`/run/desktop-cracker/disks`, which the guest's user may read) and asks each device what is on
# it.  A listing that demanded a password would be a listing a person cannot run to find out what
# they are about to open.
#
# Everything else re-runs itself under `sudo`, and `sudo` reads **one line** of standard input and
# leaves the rest alone — which is why the container's passphrase (the next line) still reaches
# `cryptsetup` inside the privileged run.  At a terminal neither is read from here: `sudo` asks the
# person, and so does `cryptsetup`, exactly as they would for any other command.
case "$COMMAND" in
list | ls | -h | --help | help) ;;
*)
    if [ "$(id -u)" != 0 ]; then
        if [ -t 0 ]; then
            exec sudo -p "desk-disk-mount needs root (password for %u): " "$0" "$@"
        else
            exec sudo -S -p "desk-disk-mount needs root (password for %u): " "$0" "$@"
        fi
    fi
    ;;
esac

case "$COMMAND" in
list | ls) cmd_list ;;
open) shift; cmd_open "$@" ;;
close | umount) shift; cmd_close "$@" ;;
-h | --help | help)
    sed -n '2,36p' "$0" | sed 's/^# \{0,1\}//'
    ;;
*) die "unknown command '$COMMAND' — use list, open or close" ;;
esac
