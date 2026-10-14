#!/bin/bash
# The **guest tools**, built for this guest: `tools/guest-image/guest-tools.c`, with the two
# differences this hypervisor needs.
#
# Why a patched copy instead of an edit to the source: `tools/guest-image/guest-tools.c` is shared
# with the guest image the project's own `tools/guest-image/build.sh` makes, and that builder
# knows nothing of this path's channels.  So the source is one, the build is here, and the patch
# is a patch.
#
# The two differences, and why each is what it is:
#
#   * the guest's pass over its **mount plan**: each line names a **share**, and that share is
#     already mounted by the guest's own agent (`desktop-cracker-fuse` answers on the share's vsock
# channel), whose own `DESK-SHARE ok …` line comes first. So this pass reports what the
#     guest actually has rather than mounting anything itself;
#   * the **agent travels into the system on the disk**: `rootboot` copies it and its libraries
#     into the new root and writes the unit that starts the guest's own session there — a run
#     whose guest is the system on the disk needs its screen, its sound, its shares and its way
#     out to exist *after* the pivot, and the initramfs is gone by then.
#
# Everything else is the project's: the plan file (`/run/desktop-cracker/mounts`), the tag, the mount
# point, the mode, and the `DESK-SHARE …` / `DESK-SHARES n mounted` lines a person reads — and the
# application's own tests assert on.
#
#   ./tools/guest-tools.sh                     # -> desktop-cracker/guest-agent-rs/out/guest-tools
#   ./tools/guest-tools.sh --out PATH
set -euo pipefail

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
# **The guest's agent lives under `desktop-cracker/`** (the application's source); the tools that build
# the guest's media are here.
hs="$root/desktop-cracker"
out="$hs/guest-agent-rs/out/guest-tools"

say() { printf 'guest-tools: %s\n' "$*"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --out) out=${2:?--out needs a path}; shift ;;
        -h|--help) sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "guest-tools: unknown argument $1" >&2; exit 2 ;;
    esac
    shift
done

source_file="$root/tools/guest-image/guest-tools.c"
[ -r "$source_file" ] || { say "the project's guest tools are not at $source_file"; exit 2; }

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
patched="$work/guest-tools.c"

python3 - "$source_file" "$patched" <<'PATCH'
import sys

src, dst = sys.argv[1], sys.argv[2]
text = open(src).read()

# 1. The mount itself: this path's folders are already mounted by the guest's own agent.
old = '''        char opts[256];
        snprintf(opts, sizeof(opts), "trans=virtio,version=9p2000.L%s",
                 strcmp(mode, "ro") == 0 ? ",ro" : "");
        if (mount(tag, where, "9p", 0, opts) != 0) {
            say("DESK-SHARE fail %s on %s (%s)", tag, where, strerror(errno));
            continue;
        }'''
new = '''        /* This path's folders are a **filesystem the guest's own agent serves** over vsock
         * (this project's own), not a 9P mount: the run's plan names the share, the agent
         * mounts it, and the agent's own line has already said so.  What this pass does is
         * report what the guest actually has — the same lines, in the same order, and the same
         * count at the end, as the run's own plan describes. */
        if (share_mounted(where)) {
            n++;
            say("DESK-SHARE ok %s on %s (this path's own filesystem)", tag, where);
        } else {
            say("DESK-SHARE fail %s on %s (not mounted)", tag, where);
        }
        continue;'''
if old not in text:
    raise SystemExit("the project's mount call is not where it was")
text = text.replace(old, new)

# 2. The helper the check needs, beside the project's own helpers.
helper = '''
/* Is this path one of **this path's own** mounts?  The folders are mounted by the guest's own
 * agent (`desktop-cracker-fuse`), so the question a person reading the console wants answered is "is
 * the folder there" — and `/proc/mounts` is where the kernel keeps that answer. */
static int share_mounted(const char *where)
{
    FILE *f = fopen("/proc/mounts", "r");
    if (!f)
        return 0;
    char line[512];
    int found = 0;
    while (fgets(line, sizeof(line), f)) {
        char source[256], target[256], type[64];
        if (sscanf(line, "%255s %255s %63s", source, target, type) != 3)
            continue;
        if (strcmp(target, where) != 0)
            continue;
        if (strncmp(type, "fuse", 4) == 0)
            found = 1;
        break;
    }
    fclose(f);
    return found;
}
'''
anchor = "/* The host writes the mount plan into the control share"
if anchor not in text:
    raise SystemExit("the mount plan reader is not where it was")
text = text.replace(anchor, helper.strip() + "\n\n" + anchor, 1)

# 3. The 9P listing and write probe below the `continue` are now dead: remove them, so what is
#    left reads as what it is.
dead_from = "        /* Prove the guest can actually see inside: list the first entries. */"
dead_to = '        say("DESK-SHARE ok %s on %s writable=%s [%s]", tag, where, writable, listing);\n'
if dead_from in text and dead_to in text:
    start = text.index(dead_from)
    end = text.index(dead_to) + len(dead_to)
    text = text[:start] + text[end:]

# 4. **The session, carried into the system on the disk.**  The initramfs is discarded at the
#    pivot, and with it every one of the project's tools: the system that runs afterwards is
#    Debian's, with no `/bin/desk-agent` and nothing that would start it.  But the *guest's*
#    side of a run — the screen, the sound, the shares, the network, the way out — has to be there
#    in the session the user actually sits in, and the two ways it could happen are "the disk's own
#    systemd starts it" or "it does not happen at all".  So `rootboot` writes a unit for it, and
#    the binary and its libraries are copied where the unit can find them.
#
# This is the one place this project touches the disk's own filesystem, and it writes exactly
#    four things: the binary, its libraries, the unit, and the symlink that enables it.
old_rootboot = """    if (access(NEWROOT "/sbin/init", F_OK) != 0 && access(NEWROOT "/usr/lib/systemd/systemd", F_OK) != 0)"""
new_rootboot = r"""    /* **The session's own agent, into the system we are about to enter.**  A run's guest is the
     * system on the disk, and this is what makes that system bring the guest's side of the run up
     * (the screen, the sound, the shares, the network and the way out).  Copied rather than
     * mounted, for the same reason the kernel modules are: the initramfs goes away at the pivot.
     *
     * Three `cp -a` calls rather than one shell line: a shell here would be quoting inside
     * quoting (this text is a C string, inside a python string, inside a shell heredoc), and the
     * copy needs none of it. */
    {
        const char *copy_agent[] = {"/bin/cp", "-a", "/bin/desk-agent", NEWROOT "/bin/", NULL};
        if (spawn_and_wait(copy_agent) == 0) {
            /* The agent's **own** closure, and nothing else: `ldd` names each library, and
             * `cp -aL` follows the symlinks (`/lib` is a symlink in Debian, and copying the
             * directory itself into a root that already has it fails — measured 2026-10-10:
             * `cp: target /mnt/newroot/lib is not a directory`, and the agent then could not be
             * executed at all).  The interpreter goes with them. */
            /* The libraries come from the **list the host wrote** beside the agent
             * (`desk-agent.libs`): `ldd` is a script this system does not have yet, and the
             * host's own answer is the one that is right for the binary it built. */
            FILE *list = fopen("/bin/desk-agent.libs", "r");
            if (list) {
                char so[512];
                while (fgets(so, sizeof(so), list)) {
                    size_t n = strlen(so);
                    while (n && (so[n - 1] == '\n' || so[n - 1] == '\r'))
                        so[--n] = 0;
                    if (n == 0 || so[0] != '/')
                        continue;
                    char where[640];
                    snprintf(where, sizeof(where), NEWROOT "%s", so);
                    /* **A library the system already has is left alone** — and that is not an
                     * optimisation, it is the difference between a system that boots and one that
                     * does not: overwriting Debian's `libc.so.6` with this host's makes `systemd`
                     * die with `GLIBC_2.36 not found` and the kernel panic with "Attempted to kill
                     * init!" (measured 2026-10-10).  What travels is what is **missing**, which is
                     * exactly the guest's own kernel modules' situation. */
                    if (access(where, F_OK) == 0)
                        continue;
                    char dir[640];
                    snprintf(dir, sizeof(dir), "%.*s", (int)(strrchr(where, '/') - where), where);
                    mkdir_p(dir);
                    const char *cp_one[] = {"/bin/cp", "-aL", so, where, NULL};
                    spawn_and_wait(cp_one);
                }
                fclose(list);
            } else {
                say("DESK-ROOT no desk-agent.libs beside the agent: the session may not start");
            }
            /* The interpreter itself, which the list does not name (it is the loader, not a
             * dependency): without it nothing in that root runs. */
            mkdir_p(NEWROOT "/lib64");
            const char *cp_ld[] = {"/bin/cp", "-aL", "/lib64/ld-linux-x86-64.so.2",
                                   NEWROOT "/lib64/ld-linux-x86-64.so.2", NULL};
            spawn_and_wait(cp_ld);
            const char *unit = NEWROOT "/etc/systemd/system/desk-agent.service";
            mkdir_p(NEWROOT "/etc/systemd/system/multi-user.target.wants");
            mkdir_p(NEWROOT "/usr/lib");
            FILE *f = fopen(unit, "w");
            if (f) {
                fprintf(f,
                        "[Unit]\n"
                        "Description=desktop-cracker's guest agent: the screen, the sound, the "
                        "shares, the network and the way out\n"
                        "After=local-fs.target\n"
                        "Before=display-manager.service\n"
                        "DefaultDependencies=no\n\n"
                        "[Service]\n"
                        "Type=simple\n"
                        "ExecStart=/bin/desk-agent session\n"
                        "Restart=no\n"
                        /* **Its own lines on the console.**  The guest's console is what a person
                         * reads (Console: , and the run echoes it), and a service's
                         * output goes to the journal by default — which is a screen nobody in
                         * this project is looking at.  The session's lines are the guest's own
                         * report of what it brought up, so they go where the rest of them do. */
                        "StandardOutput=tty\n"
                        "StandardError=tty\n"
                        "TTYPath=/dev/ttyS0\n"
                        "TTYReset=no\n"
                        "TTYVHangup=no\n\n"
                        "[Install]\n"
                        "WantedBy=multi-user.target\n");
                fclose(f);
                const char *want = NEWROOT
                    "/etc/systemd/system/multi-user.target.wants/desk-agent.service";
                unlink(want);
                if (symlink("/etc/systemd/system/desk-agent.service", want) == 0)
                    say("DESK-ROOT the guest's agent travels with the system on the disk "
                        "(desk-agent.service)");
            }
        } else {
            say("DESK-ROOT the guest's agent could not be copied into the new root: the session "
                "will have no screen, sound, shares or network");
        }
    }

    if (access(NEWROOT "/sbin/init", F_OK) != 0 && access(NEWROOT "/usr/lib/systemd/systemd", F_OK) != 0)"""
if old_rootboot not in text:
    raise SystemExit("rootboot's own warning line is not where it was")
text = text.replace(old_rootboot, new_rootboot, 1)

open(dst, "w").write(text)
PATCH

say "building the guest tools (the project's source, its mount pass changed)"
gcc -static -O2 -o "$out" "$patched" -lm
ls -lh "$out" | awk '{print "guest-tools: " $5 " " $9}'
