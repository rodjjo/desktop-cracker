/* guest-tools: the small program the desktop-cracker guest image runs.
 *
 * It is deliberately a handful of verbs instead of a shell, because it is what
 * the system tests assert against: it reports a *result* (a line on the console,
 * a file in the control share) rather than a side effect that has to be guessed
 * from a log.
 *
 *   boot        the real guest init: mount the control share, publish the
 *               guest's status, print DESK-READY, then keep sampling /proc/meminfo
 *               into the control share until the guest is powered off.
 *   probe       read one line from the console and echo it back (a boot test).
 *   ro-check D  try to create a file in D; report whether the filesystem
 *               refused (a mount a caller asked for read-only).
 *   rw-check D  the opposite: the run's own mode must allow it.
 * poweroff ask the kernel to power off, which is how a machine ends itself.
 *
 * Static build, glibc only (no busybox needed for these paths).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdarg.h>
#include <math.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <linux/vm_sockets.h>
#include <sys/wait.h>
#include <linux/input.h>
#include <poll.h>
#include <time.h>
#include <sys/sysmacros.h>
#include <termios.h>
#include <linux/fb.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>

#define CONTROL_TAG "control"
#define MOUNT_PLAN CONTROL_DIR "/mounts"
#define CONTROL_DIR "/run/desktop-cracker"
#define READY_FILE CONTROL_DIR "/guest-ready"
#define MEM_FILE CONTROL_DIR "/guest-meminfo"

static double now_seconds(void);
static int spawn_and_wait(const char *const argv[]);
static int wait_status(pid_t pid);
static int do_sound(const char *seconds);
static int xprobe(const char *number, const char *authority);
static int do_dmprobe(void);
static int run_capture(const char *const argv[], char *out, size_t cap);
static int run_capture_into(const char *line, char *out, size_t cap);
static int run_with_input(const char *const argv[], const char *input);




static int do_diskmgr(void);
static int x_forward(int fd, unsigned port);
static int x_forward_listen(unsigned port, const char *number);
static int do_unlock(const char *dev, const char *mapname, const char *passfile, const char *where);
static long long block_device_size_mib(const char *device);
static long long file_size_bytes(const char *path);
static int block_device(char *out, size_t cap);

static void say(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
    fputc('\n', stdout);
    fflush(stdout);
}

static long meminfo_field(const char *key)
{
    FILE *f = fopen("/proc/meminfo", "r");
    if (!f)
        return -1;
    char line[256];
    long value = -1;
    size_t klen = strlen(key);
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, key, klen) == 0 && line[klen] == ':') {
            value = strtol(line + klen + 1, NULL, 10);
            break;
        }
    }
    fclose(f);
    return value;
}

static int mkdir_p(const char *path)
{
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = 0;
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    return mkdir(tmp, 0755);
}

/* Mount one shared folder by the tag its plan names. With trans=virtio the *source* is
 * the tag, so no /sys probing is needed. */
static int mount_tag(const char *tag, const char *where)
{
    mkdir_p(where);
    char opts[128];
    snprintf(opts, sizeof(opts), "trans=virtio,version=9p2000.L");
    if (mount(tag, where, "9p", 0, opts) == 0)
        return 0;
    return -errno;
}

static int read_first_line(const char *path, char *buf, size_t cap)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    size_t n = 0;
    while (n + 1 < cap) {
        char c;
        ssize_t r = read(fd, &c, 1);
        if (r <= 0 || c == '\n')
            break;
        buf[n++] = c;
    }
    buf[n] = 0;
    close(fd);
    return (int)n;
}

static void write_file(const char *path, const char *text)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        say("GUEST cannot write %s: %s", path, strerror(errno));
        return;
    }
    size_t n = strlen(text);
    if (write(fd, text, n) != (ssize_t)n)
        say("GUEST short write to %s", path);
    close(fd);
}

/* The host writes the mount plan into the control share: one line per share,
 * "<tag> <where> <ro|rw>".  The guest is the one that mounts them, so the host
 * stays authoritative about *what* is shared and the guest about *where* it
 * lands.  A line starting with # is a comment. */
static void apply_mount_plan(void)
{
    FILE *f = fopen(MOUNT_PLAN, "r");
    if (!f) {
        say("DESK-SHARES no mount plan (%s)", strerror(errno));
        return;
    }
    char line[512];
    int n = 0;
    while (fgets(line, sizeof(line), f)) {
        char tag[128], where[256], mode[16];
        if (line[0] == '#' || line[0] == '\n')
            continue;
        if (sscanf(line, "%127s %255s %15s", tag, where, mode) != 3)
            continue;
        mkdir_p(where);
        char opts[256];
        snprintf(opts, sizeof(opts), "trans=virtio,version=9p2000.L%s",
                 strcmp(mode, "ro") == 0 ? ",ro" : "");
        if (mount(tag, where, "9p", 0, opts) != 0) {
            say("DESK-SHARE fail %s on %s (%s)", tag, where, strerror(errno));
            continue;
        }
        /* Prove the guest can actually see inside: list the first entries. */
        char listing[256] = "";
        DIR *d = opendir(where);
        if (d) {
            struct dirent *e;
            int shown = 0;
            while ((e = readdir(d)) && shown < 4) {
                if (strcmp(e->d_name, ".") == 0 || strcmp(e->d_name, "..") == 0)
                    continue;
                if (shown)
                    strncat(listing, ",", sizeof(listing) - strlen(listing) - 1);
                strncat(listing, e->d_name, sizeof(listing) - strlen(listing) - 1);
                shown++;
            }
            closedir(d);
        }
        /* Can the guest write there?  A read-only mount must refuse it. */
        char probe[512];
        snprintf(probe, sizeof(probe), "%s/.desk-write-probe", where);
        int fd = open(probe, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        const char *writable = "no";
        if (fd >= 0) {
            close(fd);
            unlink(probe);
            writable = "yes";
        }
        say("DESK-SHARE ok %s on %s writable=%s [%s]", tag, where, writable, listing);
        n++;
    }
    fclose(f);
    say("DESK-SHARES %d mounted", n);
}

/* Report the guest's framebuffer, if the DRM stack came up.  The host's window
 * is showing exactly this, so a test can assert the two agree. */
/* `sound` <seconds>: play a quiet tone through the guest's sound card.
 *
 * The host's audio rule is what is being observed, so this only has to *produce*
 * sound: a 440 Hz sine written as a WAV to /tmp and handed to aplay. */
static int do_sound(const char *seconds)
{
    double secs = seconds ? atof(seconds) : 2.0;
    if (secs <= 0)
        secs = 2.0;
    const int rate = 44100, channels = 2, bits = 16;
    int frames = (int)(rate * secs);
    int data_bytes = frames * channels * bits / 8;
    FILE *f = fopen("/tmp/desk-tone.wav", "wb");
    if (!f) {
        say("DESK-SOUND cannot write the tone: %s", strerror(errno));
        return 1;
    }
    unsigned char hdr[44] = {0};
    memcpy(hdr, "RIFF", 4);
    int riff = 36 + data_bytes;
    memcpy(hdr + 4, &riff, 4);
    memcpy(hdr + 8, "WAVEfmt ", 8);
    int sixteen = 16;
    memcpy(hdr + 16, &sixteen, 4);
    short one = 1, ch = (short)channels, bps = (short)bits;
    memcpy(hdr + 20, &one, 2);
    memcpy(hdr + 22, &ch, 2);
    memcpy(hdr + 24, &rate, 4);
    int byte_rate = rate * channels * bits / 8;
    memcpy(hdr + 28, &byte_rate, 4);
    short align = (short)(channels * bits / 8);
    memcpy(hdr + 32, &align, 2);
    memcpy(hdr + 34, &bps, 2);
    memcpy(hdr + 36, "data", 4);
    memcpy(hdr + 40, &data_bytes, 4);
    fwrite(hdr, 1, sizeof(hdr), f);
    for (int i = 0; i < frames; i++) {
        double t = (double)i / rate;
        short s = (short)(8000.0 * sin(2.0 * 3.14159265358979 * 440.0 * t));
        short frame[2] = {s, s};
        fwrite(frame, sizeof(frame), 1, f);
    }
    fclose(f);

    say("DESK-SOUND playing %.1fs of 440 Hz", secs);
    /* `aplay` is run **directly**, not through a shell: this initramfs's busybox has no `main`
     * applet for shell pipelines, so `system("/bin/aplay … | head …")` answered 127 before
     * aplay even ran.  Two argv forms, because the default device is the one ALSA's
     * configuration names and a bare `aplay` is the fallback.
     *
     * When it cannot even be *started*, the reason is said out loud: `exec` failing and `aplay`
     * refusing are different problems, and a silent 127 is not an answer the host can act
     * on. */
    {
        pid_t probe = fork();
        if (probe == 0) {
            execl("/bin/aplay", "aplay", "--version", (char *)NULL);
            fprintf(stderr, "DESK-SOUND exec /bin/aplay: %s\n", strerror(errno));
            _exit(127);
        }
        int st = 0;
        if (probe > 0 && waitpid(probe, &st, 0) > 0 && WIFEXITED(st) && WEXITSTATUS(st) != 0)
            say("DESK-SOUND /bin/aplay could not run (exit %d)", WEXITSTATUS(st));
    }
    const char *argv_default[] = {"aplay", "-q", "-D", "default",
                                  "/tmp/desk-tone.wav", NULL};
    const char *argv_plain[] = {"aplay", "-q", "/tmp/desk-tone.wav", NULL};
    int status = spawn_and_wait(argv_default);
    if (status != 0)
        status = spawn_and_wait(argv_plain);
    if (status != 0) {
        /* The cards the guest actually sees, and the kernel's own devices: the host wants to
         * know *why* the tone did not come out, and this is that answer. */
        say("DESK-SOUND aplay failed status=%d (is there a sound card?)", status);
        const char *list[] = {"aplay", "-l", NULL};
        if (spawn_and_wait(list) != 0)
            say("DESK-SOUND aplay -l also failed (no ALSA client?)");
        return 1;
    }
    say("DESK-SOUND done");
    return 0;
}

/* A guest with a network device is not a guest with a network.  passt answers
 * DHCP, so asking for a lease is the shortest true test of the network path. */
static void dhcp_if_possible(void)
{
    if (access("/sys/class/net/eth0", F_OK) != 0) {
        say("DESK-NET no eth0: nothing to lease");
        return;
    }
    if (access("/sbin/udhcpc", X_OK) != 0 && access("/bin/udhcpc", X_OK) != 0) {
        say("DESK-NET no dhcp client in this image; interface only");
        return;
    }
    /* The interface has to be **up** first: a device with no carrier comes up administratively
     * down, and a DHCP client on a down interface gets nothing at all — not even a
     * refusal worth reporting.  (Measured: without this the probe said `operstate=down`
     * and nothing else, which is the interface, not the network.) */
    int up = system("busybox ip link set eth0 up 2>&1");
    say("DESK-NET ip link set eth0 up rc=%d", up);
    if (system("busybox ip link show eth0 2>&1 | while read l; do echo \"DESK-NET $l\"; done") != 0)
        say("DESK-NET ip link show could not run");
    /* `-s` is the script that applies the lease: busybox's own is not in this image, so
     * the image carries one (see `tools/guest-image/build.sh`), and without it a lease
     * would be received and thrown away. */
    int rc = system("udhcpc -i eth0 -q -n -t 5 -T 2 -s /usr/share/udhcpc/default.script "
                    "> /run/udhcpc.log 2>&1; cat /run/udhcpc.log > /dev/console 2>/dev/null");
    if (rc != 0) {
        say("DESK-NET dhcp failed (rc=%d)", rc);
        return;
    }
    char buf[128] = "?";
    read_first_line("/sys/class/net/eth0/operstate", buf, sizeof(buf));
    say("DESK-NET dhcp ok operstate=%s", buf);
    /* An address is the proof.  /proc/net/fib_trie is not parseable enough;
     * busybox's `ip` is. */
    FILE *p = popen("ip -4 -o addr show eth0 2>/dev/null", "r");
    if (p) {
        while (fgets(buf, sizeof(buf), p))
            say("DESK-NET addr %s", buf);
        pclose(p);
    }
    p = popen("cat /etc/resolv.conf 2>/dev/null", "r");
    if (p) {
        while (fgets(buf, sizeof(buf), p))
            say("DESK-NET resolver %s", buf);
        pclose(p);
    }
    /* Reaching the **internet** is the question the user actually has ("firefox does not
     * work"), and an address is not an answer to it: the gateway is passt, and passt is
     * what reaches out.  A name is resolved and a byte is fetched, or the reason is
     * printed. */
    /* The route, the resolver and a fetch — in that order, because each answers a
     * different question: is there a way out, can names be looked up, and does a byte
     * come back. */
    if (system("busybox ip route 2>&1 | while read l; do echo \"DESK-NET route $l\"; done") != 0)
        say("DESK-NET ip route could not run");
    /* A page, fetched and thrown away: the question is "does a byte come back?", and the
     * answer that matters is the command's **exit status** — so no pipeline is in the way
     * (a `| while read` returns the reader's status, which is how a failure looked like a
     * success here).  The reason a failure failed is kept. */
    /* `timeout` **around** `wget`, never `wget -T`: this busybox's `wget` dies of a
     * segmentation fault the moment it is given a timeout (measured on the host, with every
     * combination of `-q`, `-O` and `--spider`), and the status that matters is wget's own —
     * 0 when the page came back, 8 when the server refused, 124 when the timeout fired. */
    {
        char why[256] = "";
        rc = run_capture_into("busybox timeout 12 busybox wget -q -O /dev/null "
                              "http://1.1.1.1/ 2>&1",
                              why, sizeof(why));
        say("DESK-NET %s the gateway by address (1.1.1.1) (rc=%d)%s%s",
            rc == 0 ? "reached" : "could not reach", rc, why[0] ? ": " : "", why);
    }
    {
        char why[256] = "";
        rc = run_capture_into("busybox timeout 15 busybox wget -q -O /dev/null "
                              "http://deb.debian.org/debian/ 2>&1",
                              why, sizeof(why));
        say("DESK-NET %s by name (deb.debian.org) (rc=%d)%s%s",
            rc == 0 ? "reached" : "could not reach", rc, why[0] ? ": " : "", why);
    }
}

/* Run a shell line and keep both its output and **its own** exit status.
 *
 * `run_capture` runs a program; this runs a *line* (redirections and all), which is what the
 * network probe needs, and it returns the line's status rather than a reader's — the bug that
 * made "the internet does not work" look like a success. */
static int run_capture_into(const char *line, char *out, size_t cap)
{
    if (cap)
        out[0] = 0;
    int fds[2];
    if (pipe(fds) != 0)
        return -1;
    pid_t pid = fork();
    if (pid == 0) {
        dup2(fds[1], 1);
        dup2(fds[1], 2);
        close(fds[0]);
        close(fds[1]);
        const char *argv[] = {"/bin/sh", "-c", line, NULL};
        execv("/bin/sh", (char *const *)argv);
        _exit(127);
    }
    close(fds[1]);
    size_t used = 0;
    ssize_t n;
    while ((n = read(fds[0], out + used, cap - 1 - used)) > 0) {
        used += (size_t)n;
        if (used + 1 >= cap)
            break;
    }
    out[used] = 0;
    close(fds[0]);
    /* The last line is the interesting one for an error, and one line is all the log wants. */
    size_t len = strlen(out);
    while (len && (out[len - 1] == '\n' || out[len - 1] == '\r'))
        out[--len] = 0;
    for (size_t i = len; i > 1; i--)
        if (out[i - 1] == '\n') {
            memmove(out, out + i, len - i + 1);
            break;
        }
    return wait_status(pid);
}

/* Keep publishing the guest's memory until the machine goes away. */
static void sample_loop(void)
{
    char line[256], old[256];
    read_first_line(MEM_FILE, old, sizeof(old));
    for (int i = 0;; i++) {
        /* The host asks us to stop by creating this file (the microvm has no
         * ACPI, so a `system_powerdown` would have nowhere to land).  This is the
         * guest's own clean shutdown: the same thing `poweroff` does. */
        if (access(CONTROL_DIR "/poweroff", F_OK) == 0) {
            say("DESK-POWEROFF requested by the host");
            sync();
            reboot(RB_POWER_OFF);
            _exit(0);
        }
        long total = meminfo_field("MemTotal");
        long free_ = meminfo_field("MemFree");
        long cached = meminfo_field("Cached");
        snprintf(line, sizeof(line),
                 "GUEST t=%d MemTotal=%ld MemFree=%ld Cached=%ld%s", i, total,
                 free_, cached, (total < 0 || free_ < 0) ? " (no /proc/meminfo)" : "");
        if (i % 2 == 0 || strcmp(line, old) != 0) {
            int fd = open(MEM_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd >= 0) {
                dprintf(fd, "%s\n", line);
                fsync(fd);
                close(fd);
            }
            snprintf(old, sizeof(old), "%s", line);
        }
        if (i % 10 == 0)
            say("%s", line);
        sleep(1);
    }
}

/* ---------------------------------------------------------------- the disk
 *
 * The encrypted disk is decrypted **inside the guest**, by the guest's own
 * cryptsetup: the host only attaches the raw file as a block device and never
 * sees the passphrase or the plaintext. The device carries a LUKS container as
 * its content, so `cryptsetup luksOpen` works on it exactly as it would on a
 * physical disk.
 */

/* The first virtio block device the guest has: /dev/vda, or /sys/block/vda. */
static int block_device(char *out, size_t cap)
{
    DIR *d = opendir("/sys/block");
    if (!d)
        return -1;
    struct dirent *e;
    int found = -1;
    while ((e = readdir(d))) {
        if (strncmp(e->d_name, "vd", 2) != 0 && strncmp(e->d_name, "sd", 2) != 0)
            continue;
        /* Skip partitions (they have a 'partition' attribute). */
        char path[512];
        snprintf(path, sizeof(path), "/sys/block/%s/partition", e->d_name);
        if (access(path, F_OK) == 0)
            continue;
        char dev[288];
        snprintf(dev, sizeof(dev), "/dev/%s", e->d_name);
        if (strlen(dev) >= cap)
            continue;
        snprintf(out, cap, "%s", dev);
        found = 0;
        break;
    }
    closedir(d);
    return found;
}

/* `unlock <device> <mapname> <passfile> [mountpoint]`: the user's own action,
 * run inside the guest.  Everything about the plaintext stays in here. */
static int do_unlock(const char *dev, const char *mapname, const char *passfile,
                     const char *where)
{
    char cmd[1024];
    snprintf(cmd, sizeof(cmd),
             "cryptsetup luksOpen --key-file %s %s %s", passfile, dev, mapname);
    say("DESK-UNLOCK opening %s as %s", dev, mapname);
    int rc = system(cmd);

    /* The passphrase is used once and then gone: it is removed from the control
     * share immediately, whether or not the volume opened, so nothing on the
     * host keeps a copy of the user's secret.  The guest itself only ever holds
     * it in the memory of the cryptsetup process. */
    unlink(passfile);
    say("DESK-UNLOCK passphrase file removed");

    if (rc != 0) {
        say("DESK-UNLOCK fail rc=%d (wrong passphrase, or no dm-crypt in this kernel)", rc);
        return 1;
    }
    char mapper[128];
    snprintf(mapper, sizeof(mapper), "/dev/mapper/%s", mapname);
    say("DESK-UNLOCK ok %s", mapper);

    if (where && where[0]) {
        mkdir_p(where);
        snprintf(cmd, sizeof(cmd), "mount %s %s 2>/dev/null", mapper, where);
        if (system(cmd) == 0) {
            say("DESK-UNLOCK mounted %s on %s", mapper, where);
        } else {
            /* A brand-new container has no filesystem inside it yet: making one
             * is part of the same user action that unlocks it. */
            snprintf(cmd, sizeof(cmd), "mkfs.ext4 -q -F -L desk-crypt %s", mapper);
            if (system(cmd) != 0) {
                /* The host attached the device read-only: the volume can be opened and
                 * read, but not written.  (The host's own read-only flag is what refuses,
                 * not the guest's.) */
                say("DESK-UNLOCK unlocked read-only; not writable here (attached read-only)");
                return 0;
            }
            snprintf(cmd, sizeof(cmd), "mount %s %s", mapper, where);
            if (system(cmd) == 0)
                say("DESK-UNLOCK formatted and mounted %s on %s", mapper, where);
            else
                say("DESK-UNLOCK formatted but the mount failed");
        }
        /* Prove the plaintext is really there: write and read a file back. */
        char probe[512];
        snprintf(probe, sizeof(probe), "%s/desk-note", where);
        FILE *f = fopen(probe, "w");
        if (f) {
            fputs("written inside the encrypted volume\n", f);
            fclose(f);
            char back[128] = "";
            read_first_line(probe, back, sizeof(back));
            say("DESK-UNLOCK volume usable: %s", back);
        }
    }
    return 0;
}

    /* ---------------------------------------------------------------- remote X
 *
 * The **host's** X server, inside the guest: an application there can open a
 * window on the host's desktop, with the cookie the host wrote for it.  This is
 * the whole point of the feature —
 * an application inside the microVM opening a window on the host's desktop — and
 * the handshake is what proves it: the server answers "success" only when the
 * authority is right.
 */
static int xprobe(const char *number, const char *authority);
static int do_dmprobe(void);
static int run_capture(const char *const argv[], char *out, size_t cap);

static int run_with_input(const char *const argv[], const char *input);




static int do_diskmgr(void);
static int x_forward(int fd, unsigned port);
static int x_forward_listen(unsigned port, const char *number);

/* Read one X authority entry for a display number out of `path`, in the format X
 * clients read (see dc-xremote): a family, then address/number/name/data with
 * 16-bit network-order lengths.  An entry with an empty display number applies
 * to every display of that host. */
static int x_read_cookie(const char *path, const char *number, unsigned char *out,
                         size_t out_cap, size_t *out_len)
{
    FILE *f = fopen(path, "rb");
    if (!f)
        return -1;
    unsigned char data[4096];
    size_t n = fread(data, 1, sizeof(data), f);
    fclose(f);
    size_t pos = 0;
    while (pos + 2 <= n) {
        pos += 2; /* family */
        char fields[4][256];
        size_t lens[4];
        int ok = 1;
        for (int i = 0; i < 4; i++) {
            if (pos + 2 > n) { ok = 0; break; }
            size_t len = ((size_t)data[pos] << 8) | data[pos + 1];
            pos += 2;
            if (pos + len > n || len >= sizeof(fields[0])) { ok = 0; break; }
            memcpy(fields[i], data + pos, len);
            fields[i][len] = 0;
            lens[i] = len;
            pos += len;
        }
        if (!ok)
            break;
        if (strcmp(fields[2], "MIT-MAGIC-COOKIE-1") != 0)
            continue;
        if (fields[1][0] != 0 && strcmp(fields[1], number) != 0)
            continue;
        if (lens[3] > out_cap)
            return -1;
        memcpy(out, fields[3], lens[3]);
        *out_len = lens[3];
        return 0;
    }
    return -1;
}


/* The **name** of a mapped device, however the caller spelled it: `desktop-cracker`,
 * `/dev/mapper/desktop-cracker`, or `desk-root`.  The old code did
 * `mapper + strlen("/dev/mapper/")` unconditionally, which is undefined behaviour when
 * the prefix is not there — a guest's own run crashed on it — and it also passed
 * `/dev/mapper/desktop-cracker` to cryptsetup, which is a *path*, not the name it asks for. */
static const char *mapper_name(const char *mapper)
{
    static const char prefix[] = "/dev/mapper/";
    if (strncmp(mapper, prefix, sizeof(prefix) - 1) == 0)
        return mapper + sizeof(prefix) - 1;
    return mapper;
}

/* The X11 connection setup, sent down an already-connected socket. */
static int x_setup(int fd, const unsigned char *cookie, size_t cookie_len)
{
    if (cookie_len == 0) {
        say("DESK-XREMOTE no cookie in the file the host wrote");
        return 1;
    }
    /* The X11 connection setup request.  Its 12-byte header is
     *   byte order | pad | major version | minor version | name length |
     *   data length | pad
     * with the versions and the lengths in the byte order the first byte
     * declares (checked against a real client's request, which is 48 bytes of
     * `l\0 0b 00 00 00 12 00 10 00 00 00` and then the name and the cookie).
     * The name and the data are each padded to a four-byte boundary. */
    static const char auth_name[] = "MIT-MAGIC-COOKIE-1";
    size_t name_len = sizeof(auth_name) - 1; /* without the NUL */
    unsigned char req[256];
    size_t p = 0;
    req[p++] = 'l'; /* little-endian */
    req[p++] = 0;
    req[p++] = 11; /* major version, low byte */
    req[p++] = 0;  /* major version, high byte */
    req[p++] = 0;  /* minor version */
    req[p++] = 0;
    /* The two lengths, in the byte order the first byte declares. */
    req[p++] = (unsigned char)(name_len & 0xff);
    req[p++] = (unsigned char)(name_len >> 8);
    req[p++] = (unsigned char)(cookie_len & 0xff);
    req[p++] = (unsigned char)(cookie_len >> 8);
    req[p++] = 0; /* pad */
    req[p++] = 0; /* pad */
    memcpy(req + p, auth_name, name_len);
    p += name_len;
    while (p % 4)
        req[p++] = 0;
    memcpy(req + p, cookie, cookie_len);
    p += cookie_len;
    while (p % 4)
        req[p++] = 0;
    if (write(fd, req, p) != (ssize_t)p) {
        say("DESK-XREMOTE short write to the X server");
        return 1;
    }

    unsigned char reply[8];
    size_t got = 0;
    while (got < sizeof(reply)) {
        ssize_t r = read(fd, reply + got, sizeof(reply) - got);
        if (r <= 0)
            break;
        got += (size_t)r;
    }
    if (got < 8) {
        say("DESK-XREMOTE the host's X server closed the connection (no reply)");
        return 1;
    }
    int status = reply[0];
    if (status == 1) {
        unsigned len = (unsigned)reply[6] | ((unsigned)reply[7] << 8);
        say("DESK-XREMOTE ok vendor_len=%u (the host accepted this guest's cookie)", len);
        return 0;
    }
    if (status == 2) {
        say("DESK-XREMOTE the host's X server wants a different authorisation");
        return 1;
    }
    say("DESK-XREMOTE the host's X server refused the connection (status %d)", status);
    return 1;
}

/* `xprobe <display-number> <authority-file>`: connect to the host's X server the
 * direct way — through the socket directory the host shares in.  It is the shape
 * a guest application uses when the socket is reachable and no forwarding is
 * needed; the forwarder below is for a guest whose own /tmp cannot be that
 * directory (it has its own X server there). */
static int xprobe(const char *number, const char *authority)
{
    unsigned char cookie[64];
    size_t cookie_len = 0;
    if (x_read_cookie(authority, number, cookie, sizeof(cookie), &cookie_len) != 0) {
        say("DESK-XREMOTE no cookie for display :%s in %s", number, authority);
        return 1;
    }
    char path[128];
    snprintf(path, sizeof(path), "/tmp/.X11-unix/X%.64s", number);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        say("DESK-XREMOTE socket: %s", strerror(errno));
        return 1;
    }
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(sa.sun_path)) {
        say("DESK-XREMOTE the X socket's path is too long: %s", path);
        close(fd);
        return 1;
    }
    snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", path);
    if (connect(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        say("DESK-XREMOTE cannot connect to the host's X server at %s: %s", path,
            strerror(errno));
        close(fd);
        return 1;
    }
    int rc = x_setup(fd, cookie, cookie_len);
    close(fd);
    return rc;
}

/* `xforward <vsock-port> <authority-file>`: reach the host's X server through
 * **virtio-vsock**.
 *
 * A guest that runs its own X server cannot have the host's sockets at
 * /tmp/.X11-unix — that is where *its* sockets live — so the host's X server is
 * reached the other way: the host listens on a vsock port, passes each
 * connection to its own socket, and the guest forwards local connections there.
 * This is that forwarder, and it is what makes a remote X application inside the
 * guest work even when the same directory is busy with the guest's own server.
 */
static int x_forward(int fd, unsigned port)
{
    int vs = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (vs < 0) {
        say("DESK-XREMOTE no vsock in this kernel (%s)", strerror(errno));
        close(fd);
        return 1;
    }
    struct sockaddr_vm sa;
    memset(&sa, 0, sizeof(sa));
    sa.svm_family = AF_VSOCK;
    sa.svm_cid = 2; /* VMADDR_CID_HOST */
    sa.svm_port = port;
    if (connect(vs, (struct sockaddr *)&sa, sizeof(sa)) != 0) {
        say("DESK-XREMOTE cannot reach the host's forwarder on vsock port %u: %s", port,
            strerror(errno));
        close(vs);
        close(fd);
        return 1;
    }
    unsigned char buf[16384];
    int phase = 0;
    for (;;) {
        if (phase == 0) {
            ssize_t n = read(fd, buf, sizeof(buf));
            if (n <= 0)
                break;
            if (write(vs, buf, (size_t)n) != n)
                break;
            phase = 1;
        } else {
            ssize_t n = read(vs, buf, sizeof(buf));
            if (n <= 0)
                break;
            if (write(fd, buf, (size_t)n) != n)
                break;
            phase = 0;
        }
    }
    close(vs);
    close(fd);
    return 0;
}

/* `xforward-listen <vsock-port> <display-number>`: the shape the guest's init
 * runs.  It creates the socket an X client looks for (`/tmp/.X11-unix/X<n>`) and
 * answers each connection by forwarding it to the host over vsock, where the
 * host passes it to its own X server.
 *
 * The display number the guest uses is *not* the host's: the guest has its own
 * server on its own numbers, so the host's is given a spare one (the host writes
 * it in the environment file), and the two never collide.
 */
static int x_forward_listen(unsigned port, const char *number)
{
    char path[128];
    snprintf(path, sizeof(path), "/tmp/.X11-unix/X%.32s", number);
    mkdir_p("/tmp/.X11-unix");
    unlink(path);
    int lfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (lfd < 0) {
        say("DESK-XREMOTE socket: %s", strerror(errno));
        return 1;
    }
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof(sa));
    sa.sun_family = AF_UNIX;
    if (strlen(path) >= sizeof(sa.sun_path)) {
        say("DESK-XREMOTE the X socket's path is too long: %s", path);
        close(lfd);
        return 1;
    }
    snprintf(sa.sun_path, sizeof(sa.sun_path), "%s", path);
    if (bind(lfd, (struct sockaddr *)&sa, sizeof(sa)) != 0 || listen(lfd, 8) != 0) {
        say("DESK-XREMOTE cannot listen on %s: %s", path, strerror(errno));
        close(lfd);
        return 1;
    }
    /* The guest's own X server, when there is one, is on another number, so this
     * socket is the one a client asking for this display gets. */
    chmod(path, 0777);
    say("DESK-XREMOTE forwarding display :%s to the host over vsock port %u", number, port);
    for (;;) {
        int c = accept(lfd, NULL, NULL);
        if (c < 0)
            break;
        pid_t pid = fork();
        if (pid == 0) {
            close(lfd);
            _exit(x_forward(c, port));
        }
        if (pid < 0) {
            /* No children (no fork): serve this connection here and then go back
             * to accepting.  A single client at a time is enough for an X
             * application, and it keeps the failure modes simple. */
            x_forward(c, port);
        }
        close(c);
    }
    close(lfd);
    return 0;
}


/* ------------------------------------------------------- the guest's root disk
 *
 * The microvm boots with an initramfs whose only job is this: ask the user for
 * the root disk's password on the console, unlock the container the guest was
 * given, and `switch_root` into the filesystem on it.  From then on the guest's
 * userland is the one on the disk — the installed applications, home and
 * everything else — while the initramfs's own filesystem is discarded.
 *
 * **There is one mode**: the container is opened and mounted `rw`, with no overlay, so
 * what the user installs or configures persists.  A read-only shape (the container
 * mounted `ro` under a tmpfs overlay) still exists for a caller that asks for it, and
 * nothing in this project's own flow does: the application has one run mode.
 *
 * The shapes are, on the **disk's own mount**:
 *   * writable: the container is opened and mounted `rw`, with no overlay, so what the
 *     user installs or configures persists — the application's one mode, and what
 *     `rootboot` does unless a caller asks for `ro`.
 *
 * The password is never written anywhere: it is read from the console, handed to
 * `cryptsetup` through a pipe, and forgotten.
 */

#define ROOTFS_DIR "/mnt/rootfs"
#define OVERLAY_DIR "/mnt/overlay"
#define NEWROOT "/mnt/newroot"
#define MAPPER "/dev/mapper/desk-root"

static int wait_status(pid_t pid);

static pid_t spawn(char *const argv[])
{
    pid_t pid = fork();
    if (pid == 0) {
        execvp(argv[0], argv);
        _exit(127);
    }
    return pid;
}

static int spawn_and_wait(const char *const argv[])
{
    pid_t pid = fork();
    if (pid == 0) {
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }
    return wait_status(pid);
}

static int wait_status(pid_t pid)
{
    int status = 0;
    if (pid <= 0)
        return -1;
    if (waitpid(pid, &status, 0) < 0)
        return -1;
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* Read one line from the console, with the echo off (a password). */
/* How long a question waits before the caller is told "nobody answered".  Five
 * seconds, which is the pause the operator asked for between one attempt and the next:
 * the question stays on screen, the answer is taken the moment it arrives, and a run
 * whose window has gone does not sit there forever. */
static double console_wait_seconds(void)
{
    return 5.0;
}

/* Ask the user for a line, on the terminals the *window* shows and the serial
 * carries, whichever answers first.
 *
 * **Why not just `/dev/console`:** this kernel's console is the *serial* — the
 * `console=ttyS0` in the command line comes first and the preferred console is what
 * `/dev/console` is — so a read of it waits for the serial port while the user types
 * into the window, and the password is never seen.  That is a measurement, not a
 * guess: the guest's own probe (`DESK-ROOT` lines) shows `/dev/console` reading
 * nothing while the window's terminal is `/dev/tty0`.
 *
 * So the **virtual terminals come first** — `/dev/tty0` (the active one, which is the
 * framebuffer the window displays), then `/dev/tty1`, then `/dev/ttyS0` for a run with
 * no display — and the prompt goes to *all* of them, so it is on the window whether the
 * user reads it there or on a serial console.  Nothing here blocks on a terminal that
 * will never answer: a `poll` with a short wait moves on to the next one.
 */
static int console_readline(const char *prompt, char *buf, size_t cap)
{
    static const char *const candidates[] = {
        "/dev/tty0", "/dev/tty1", "/dev/ttyS0", "/dev/console",
    };
    int fd = -1;
    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
        /* The prompt goes to every candidate: a user watching the window and one
         * watching a serial console both have to see the question. */
        int w = open(candidates[i], O_WRONLY | O_NOCTTY);
        if (w >= 0) {
            dprintf(w, "%s", prompt);
            close(w);
        }
        int r = open(candidates[i], O_RDONLY | O_NOCTTY | O_NONBLOCK);
        if (r < 0)
            continue;
        /* Is this one a terminal somebody can type at?  A `poll` that times out is
         * not an answer, so it is tried and then left behind. */
        struct pollfd p = {.fd = r, .events = POLLIN, .revents = 0};
        int ready = poll(&p, 1, 400);
        if (ready > 0) {
            /* Take it out of non-blocking mode for the read itself: a typed line
             * arrives a character at a time. */
            int flags = fcntl(r, F_GETFL);
            fcntl(r, F_SETFL, flags & ~O_NONBLOCK);
            fd = r;
            say("DESK-ASK the question is on %s (the window's terminal is /dev/tty0)",
                candidates[i]);
            break;
        }
        close(r);
    }
    if (fd < 0) {
        say("DESK-ASK no terminal answered: the question was printed on every one of them");
        return -1;
    }
    struct termios old, raw;
    int have_termios = (tcgetattr(fd, &old) == 0);
    if (have_termios) {
        raw = old;
        raw.c_lflag &= ~(ECHO);
        tcsetattr(fd, TCSANOW, &raw);
    }
    dprintf(fd, "%s", prompt);
    size_t n = 0;
    for (;;) {
        char c;
        ssize_t r = read(fd, &c, 1);
        if (r <= 0)
            break;
        if (c == '\r' || c == '\n')
            break;
        if ((c == 127 || c == 8)) {
            if (n > 0) {
                n--;
                /* Rub the star out, so the user can see the backspace worked. */
                dprintf(fd, "\b \b");
            }
            continue;
        }
        if (n + 1 < cap) {
            buf[n++] = c;
            /* A star per character: the password itself is never echoed, but the user
             * has to see that their typing is arriving — a prompt that shows nothing
             * looks like a prompt that is not listening. */
            dprintf(fd, "*");
        }
    }
    buf[n] = 0;
    if (have_termios)
        tcsetattr(fd, TCSANOW, &old);
    dprintf(fd, "\r\n");
    close(fd);
    return (int)n;
}

static int mkdir_p(const char *path);

/* Mount the guest's root disk and switch to it.  Never returns on success. */
static int rootboot(const char *device, const char *mapper, const char *mode)
{
    /* Three modes: `ro` (mount read-only — a caller asking by hand), `rw` (mount
     * read-write: the one mode the application runs in) and `ro-try` (only ask the
     * container whether the password opens it, then return). */
    int try_only = (strcmp(mode, "ro-try") == 0);
    int writable = (strcmp(mode, "rw") == 0);
    say("DESK-ROOT root disk %s (%s), mapper %s", device, mode, mapper);

    if (access(device, F_OK) != 0) {
        say("DESK-ROOT no %s: this guest has no root disk", device);
        return 1;
    }

    /* **Is this device plain already?**  The host may have decrypted it itself — a root disk
     * guest opened with its own secret and LUKS block node is an ordinary block
     * device by the time the guest sees it (the root disk is decrypted the safest
     * way, and the guest only decrypts the disks that are *not* the root disk).  So the first
     * question is whether the devices carries a LUKS header of its own, and only a device
     * that does gets asked for a passphrase. */

    int fd = open(device, O_RDONLY);
    if (fd < 0) {
        say("DESK-ROOT cannot read %s: %s", device, strerror(errno));
        return 1;
    }
    unsigned char magic[6] = {0};
    int is_luks = (read(fd, magic, sizeof(magic)) == (ssize_t)sizeof(magic) &&
                   memcmp(magic, "LUKS\xba\xbe", 6) == 0);
    close(fd);

    if (is_luks) {
        /* **The host asks for the password; the guest only tries one.**
         *
         * this project asks for the password to be asked "using a gui interface", and the
         * application's window is that interface: a question typed *inside the guest's
         * framebuffer console* is a question the user has to reach through a screen they
         * cannot yet see (the disk is not mounted, so nothing is running), which is
         * exactly the bug this replaces.
         *
         * So the guest never prompts.  It tries the password the host wrote (the
         * `desk-try` verb), says whether it opened the container, and exits; the
         * application asks the user again and starts the guest another time.  The
         * password travels only in the control share, and this copy is unlinked before
         * anything else happens.
         */
        char pass[256] = "";
        const char *keyfile = getenv("DESK_ROOT_PASSWORD_FILE");
        if (!keyfile || !keyfile[0])
            keyfile = "/run/desktop-cracker/root.pass";
        if (access(keyfile, R_OK) != 0)
            keyfile = "/run/root.pass";
        FILE *pf = fopen(keyfile, "r");
        if (pf) {
            if (!fgets(pass, sizeof(pass), pf))
                pass[0] = 0;
            fclose(pf);
            unlink(keyfile);
            size_t n = strlen(pass);
            while (n > 0 && (pass[n - 1] == '\n' || pass[n - 1] == '\r'))
                pass[--n] = 0;
        }
        if (!pass[0]) {
            say("DESK-ROOT no password was provided for the root disk; the host asks the "
                "user and starts this guest again");
            return 1;
        }

        /* Does it open the container?  **Ask the container**, do not guess:
         * `--test-passphrase` is the same question the `luksOpen` below asks, and a
         * wrong answer is reported as such (the host then asks the user again) instead of
         * turning into a confusing failure later. */
        mkdir_p("/run");
        const char *askkey = "/run/askkey";
        int kf = open(askkey, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (kf >= 0) {
            if (write(kf, pass, strlen(pass)) != (ssize_t)strlen(pass))
                say("DESK-ROOT short write of the key file");
            close(kf);
        }
        char probe_name[128];
        snprintf(probe_name, sizeof(probe_name), "%.100s", mapper_name(mapper));
        const char *probe[] = {"/sbin/cryptsetup", "open", "--test-passphrase",
                               "--key-file", askkey, device, probe_name, NULL};
        int opens = (spawn_and_wait(probe) == 0);
        unlink(askkey);
        if (!opens) {
            say("DESK-ROOT wrong-password the password did not open the container");
            memset(pass, 0, sizeof(pass));
            return 1;
        }
        /* The **length** is the most that may be said about a passphrase: it is enough to
         * tell "the question and the answer agree" from "something truncated it", and it
         * gives nothing away.  The bytes themselves are never printed anywhere — not to a
         * log, not to a console, not to a file. */
        say("DESK-ROOT password ok (%zu byte(s), key %s, mapper %s)", strlen(pass), keyfile,
            mapper_name(mapper));
        if (try_only)
            return 0;

        /* The key comes from a **file in RAM**: cryptsetup reads a key file,
         * and a pipe is not one it can re-read if it needs to.  `/dev/shm` may
         * not exist this early, so the file goes in `/run` (the tmpfs the init
         * already made). */
        mkdir_p("/run");
        /* device-mapper's node directory: the guest's initramfs has no udev, so
         * it is created here (libdevmapper then makes the node itself). */
        mkdir_p("/dev/mapper");
        const char *openkey = "/run/rootkey";
        int okf = open(openkey, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (okf >= 0) {
            if (write(okf, pass, strlen(pass)) != (ssize_t)strlen(pass))
                say("DESK-ROOT short write of the key file");
            close(okf);
        }
        memset(pass, 0, sizeof(pass));

        char name[128];
        snprintf(name, sizeof(name), "%.100s", mapper_name(mapper));
        const char *open_argv_ro[] = {"/sbin/cryptsetup", "luksOpen", "--readonly",
                                      "--key-file", openkey, device, name, NULL};
        const char *open_argv_rw[] = {"/sbin/cryptsetup", "luksOpen", "--key-file",
                                      openkey, device, name, NULL};
        int rc = spawn_and_wait(writable ? open_argv_rw : open_argv_ro);
        unlink(openkey);
        if (rc == 0 && access(mapper, F_OK) != 0) {
            /* There is no udev in an initramfs, so the `/dev/mapper/<name>` node
             * udev would have made is missing.  The kernel's own view of the
             * mapped device has the numbers it needs (`/sys/class/block/dm-N`,
             * whose `dm/name` is ours). */
            const char *created = NULL;
            for (int i = 0; i < 16 && !created; i++) {
                char dir[128], path[192], line[64];
                snprintf(dir, sizeof(dir), "/sys/class/block/dm-%d", i);
                if (access(dir, F_OK) != 0)
                    continue;
                snprintf(path, sizeof(path), "%s/dm/name", dir);
                read_first_line(path, line, sizeof(line));
                if (strcmp(line, mapper_name(mapper)) != 0)
                    continue;
                snprintf(path, sizeof(path), "%s/dev", dir);
                unsigned major = 0, minor = 0;
                if (read_first_line(path, line, sizeof(line)) > 0 &&
                    sscanf(line, "%u:%u", &major, &minor) == 2) {
                    if (mknod(mapper, S_IFBLK | 0600, makedev(major, minor)) == 0) {
                        say("DESK-ROOT created %s (maj %u, min %u) for the mapped device %s",
                            mapper, major, minor, dir);
                        created = mapper;
                    }
                }
            }
            if (!created)
                say("DESK-ROOT the mapped device has no node yet (no udev in this initramfs)");
        }
        say("DESK-ROOT cryptsetup exited with %d, mapper present: %s", rc,
            access(mapper, F_OK) == 0 ? "yes" : "no");
        if (rc != 0)
            say("DESK-ROOT the container was refused (wrong password?)");
        if (access(mapper, F_OK) != 0) {
            say("DESK-ROOT the disk could not be unlocked (wrong password, or no dm-crypt)");
            return 1;
        }
        say("DESK-ROOT %s opened as %s", device, mapper);
    } else {
        say("DESK-ROOT the disk is not encrypted: mounting it directly");
    }

    /* A desktop-cracker disk has **partitions inside the container** (the root
     * disk "has partitions that are always read-write used to store temp files
     * and other things that the system does not allow to be read only to work"),
     * so this is where they are published: the container's mapped device is asked
     * for its partitions, the second one is the root filesystem and the first is
     * the state that stays writable.
     *
     * `partx`/`kpartx` is what makes the nodes, because an initramfs has no udev
     * and the device-mapper driver does not scan a mapped device by itself.  A
     * disk without a table is still a disk: then the container itself is the root. */
    char source[192];
    snprintf(source, sizeof(source), "%s", (is_luks) ? mapper : device);
    char state[192] = "";
    if (is_luks) {
        /* `kpartx -a` asks the kernel to publish the partitions of the mapped
         * device and **makes their nodes**; `partx` is a shell script and an
         * initramfs has not the applets it wants.  The kernel names a partition
         * `<parent><n>`, and that is how it is found here — by its name in sysfs,
         * whatever the parent is called. */
        /* `kpartx -a` asks the kernel to publish the partitions of the mapped device and
         * **makes their nodes**.  It is retried, because it is a race: the device-mapper
         * device has just been created by hand (there is no udev in an initramfs) and
         * scanning its table can fail once and succeed a moment later.  Measured: a boot
         * that said "has no partitions (kpartx said 0)" and then refused the mount found
         * the same disk's two partitions when it was tried again.
         *
         * `partx` is a shell script and an initramfs has not the applets it wants, so
         * `kpartx` is the tool; it is `dmsetup`'s own binary under another name. */
        int px = 1;
        for (int attempt = 0; attempt < 8; attempt++) {
            const char *kpartx[] = {"/sbin/kpartx", "-a", source, NULL};
            px = spawn_and_wait(kpartx);
            if (px == 0)
                break;
            struct timespec nap = {0, 200 * 1000 * 1000};
            nanosleep(&nap, NULL);
        }
        const char *parent = mapper_name(source);
        size_t parent_len = strlen(parent);
        char second[192] = "", first[192] = "";
        for (int i = 0; i < 16; i++) {
            char dir[128], name[128] = "", dev[64] = "";
            snprintf(dir, sizeof(dir), "/sys/class/block/dm-%d/dm/name", i);
            if (read_first_line(dir, name, sizeof(name)) <= 0)
                continue;
            if (strncmp(name, parent, parent_len) != 0 || name[parent_len] == 0)
                continue;
            const char *n = name + parent_len;
            if (strlen(n) != 1 || n[0] < '1' || n[0] > '9')
                continue;
            snprintf(dir, sizeof(dir), "/sys/class/block/dm-%d/dev", i);
            if (read_first_line(dir, dev, sizeof(dev)) <= 0)
                continue;
            unsigned major = 0, minor = 0;
            if (sscanf(dev, "%u:%u", &major, &minor) != 2)
                continue;
            char node[192];
            snprintf(node, sizeof(node), "/dev/mapper/%s", name);
            if (access(node, F_OK) != 0 &&
                mknod(node, S_IFBLK | 0600, makedev(major, minor)) != 0) {
                say("DESK-ROOT cannot make a node for partition %s: %s", node,
                    strerror(errno));
                continue;
            }
            say("DESK-ROOT partition %s (dm-%d, maj %u min %u)", node, i, major, minor);
            if (n[0] == '1')
                snprintf(first, sizeof(first), "%s", node);
            else if (n[0] == '2')
                snprintf(second, sizeof(second), "%s", node);
        }
        if (px == 0 && second[0]) {
            snprintf(state, sizeof(state), "%s", first);
            snprintf(source, sizeof(source), "%s", second);
        } else {
            say("DESK-ROOT %s has no partitions (kpartx said %d): the container itself "
                "is the root",
                source, px);
        }
    } else {
        /* **A device the host already decrypted** (or a plain disk): the partitions are the
         * device's own. The root disk is opened **inside the guest** with its own key and an LUKS
         * block node, so what arrives here is /dev/vda with the two partitions inside it —
         * asking `kpartx` about a device that has no device-mapper mapping is what produced
         * "the disk is not encrypted: mounting it directly" followed by "cannot mount
         * /dev/vda: Invalid argument". */
        char second[192] = "", first[192] = "";
        for (int part = 1; part <= 4; part++) {
            char node[64];
            snprintf(node, sizeof(node), "%s%d", device, part);
            if (access(node, F_OK) != 0)
                continue;
            say("DESK-ROOT partition %s", node);
            if (part == 1)
                snprintf(first, sizeof(first), "%s", node);
            else if (part == 2)
                snprintf(second, sizeof(second), "%s", node);
        }
        if (second[0]) {
            snprintf(state, sizeof(state), "%s", first);
            snprintf(source, sizeof(source), "%s", second);
        } else {
            say("DESK-ROOT %s has no partitions: the device itself is the root", device);
        }
    }

    mkdir_p(ROOTFS_DIR);
    if (mount(source, ROOTFS_DIR, "ext4", writable ? 0 : MS_RDONLY, NULL) != 0) {
        say("DESK-ROOT cannot mount %s: %s", source, strerror(errno));
        return 1;
    }
    say("DESK-ROOT %s mounted on %s (%s)", source, ROOTFS_DIR, writable ? "rw" : "ro");

    /* The mode, checked from inside rather than asserted: write a file into the
     * disk's own filesystem and see whether it is refused.  This is what "the
     * filesystem of the vm is readonly, including the root-disk" means. */
    {
        char probe[256];
        snprintf(probe, sizeof(probe), "%s/.desk-write-probe", ROOTFS_DIR);
        int pfd = open(probe, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (pfd >= 0) {
            close(pfd);
            unlink(probe);
            say("DESK-ROOT write-probe on the disk: writable=yes");
        } else {
            say("DESK-ROOT write-probe on the disk: writable=no (%s)", strerror(errno));
        }
    }

    if (writable) {
        /* Admin mode: the disk is the system, and what changes in it stays. */
        mkdir_p(NEWROOT);
        if (mount(ROOTFS_DIR, NEWROOT, NULL, MS_BIND | MS_REC, NULL) != 0) {
            say("DESK-ROOT bind of %s failed: %s", ROOTFS_DIR, strerror(errno));
            return 1;
        }
    } else {
        /* Read-only mode: a writable system on top of a read-only disk.  The
         * upper layer is a tmpfs, so everything a running system writes (its
         * logs, its state, /tmp) lives in RAM and is gone at power-off — and the
         * disk is never written. */
        mkdir_p(OVERLAY_DIR);
        if (mount("tmpfs", OVERLAY_DIR, "tmpfs", 0, "mode=0755,size=1024m") != 0) {
            say("DESK-ROOT cannot make the RAM overlay: %s", strerror(errno));
            return 1;
        }
        char upper[256], work[256];
        snprintf(upper, sizeof(upper), "%s/upper", OVERLAY_DIR);
        snprintf(work, sizeof(work), "%s/work", OVERLAY_DIR);
        mkdir_p(upper);
        mkdir_p(work);
        char opts[512];
        int n = snprintf(opts, sizeof(opts), "lowerdir=%s,upperdir=%s,workdir=%s", ROOTFS_DIR,
                         upper, work);
        if (n < 0 || (size_t)n >= sizeof(opts)) {
            say("DESK-ROOT the overlay's own paths are too long for this kernel");
            return 1;
        }
        mkdir_p(NEWROOT);
        if (mount("overlay", NEWROOT, "overlay", 0, opts) != 0) {
            say("DESK-ROOT overlay mount failed (%s): falling back to the read-only disk itself",
                strerror(errno));
            if (mount(ROOTFS_DIR, NEWROOT, NULL, MS_BIND | MS_REC, NULL) != 0) {
                say("DESK-ROOT bind failed: %s", strerror(errno));
                return 1;
            }
        } else {
            say("DESK-ROOT overlay on %s: writes live in RAM, the disk stays read-only", NEWROOT);
        }
    }

    /* The **state partition** is mounted inside the new root, always read-write —
     * when a caller asked for a read-only mount of the root itself, where a tmpfs
     * overlay carries the rest.  It is where the paths a running system insists on writing
     * live, and it survives a power-off: it is the disk's own scratch area.
     *
     * It is mounted onto the new root's `/var/state`, and the paths that must be
     * writable are pointed at it (see the userland's own fstab, which knows the
     * name).  A disk without one has only the overlay, which is what the tests
     * exercise. */
    /* The paths that leave the container's own filesystem for the state
     * partition: the log, the cache, and the temp directory a system writes to. */
    struct {
        const char *name;
        const char *target;
    } subs[] = {
        {"log", "/var/log"},
        {"cache", "/var/cache"},
        {"tmp", "/var/tmp"},
    };

    if (state[0] && access(state, F_OK) == 0) {
        char where[256];
        snprintf(where, sizeof(where), "%s/var/state", NEWROOT);
        mkdir_p(where);
        if (mount(state, where, "ext4", 0, NULL) == 0) {
            say("DESK-ROOT the state partition %s is mounted on /var/state (rw)", state);
            /* What a running system insists on writing goes **there**, so it
             * survives a power-off (it is the disk's own scratch area) and it is
             * writable even when the rest of the disk was mounted read-only. */
            for (size_t i = 0; i < sizeof(subs) / sizeof(subs[0]); i++) {
                char from[320], to[256];
                snprintf(from, sizeof(from), "%s/var/state/%s", NEWROOT, subs[i].name);
                mkdir_p(from);
                snprintf(to, sizeof(to), "%s%s", NEWROOT, subs[i].target);
                mkdir_p(to);
                if (mount(from, to, NULL, MS_BIND | MS_REC, NULL) == 0)
                    say("DESK-ROOT %s is on the state partition (writable)", subs[i].target);
                else
                    say("DESK-ROOT %s could not be moved onto the state partition: %s",
                        subs[i].target, strerror(errno));
            }
        } else {
            say("DESK-ROOT the state partition could not be mounted: %s", strerror(errno));
        }
    }

    /* The **network** the initramfs leased, given to the system on the disk.
     *
     * The microvm's network is passt: the DHCP answer, the route and the resolver all come
     * from it, and the initramfs (which is what runs before the disk's system) is where the
     * lease is taken — see `dhcp_if_possible`.  A disk whose systemd has no network
     * configuration at all would otherwise come up with an interface that never gets an
     * address, which is what "firefox has no internet" looks like from the other end.
     *
     * Three things, in the new root: the address and the route as a systemd unit that runs
     * once at boot, the resolver written where systemd's own resolver reads it, and the
     * disk's competing network managers switched off (they would flush the address as
     * "unconfigured"). */
    {
        char net_env[256];
        snprintf(net_env, sizeof(net_env), "/run/net.env");
        FILE *env = fopen(net_env, "r");
        if (env) {
            char ip[64] = "", mask[64] = "", router[64] = "", dns[256] = "";
            char line[256];
            while (fgets(line, sizeof(line), env)) {
                sscanf(line, "ip=%63s", ip);
                sscanf(line, "mask=%63s", mask);
                sscanf(line, "router=%63s", router);
                sscanf(line, "dns=%255[^\n]", dns);
            }
            fclose(env);
            if (ip[0]) {
                char path[256];
                snprintf(path, sizeof(path), "%s/etc/systemd/system/desk-network.service",
                         NEWROOT);
                mkdir_p(NEWROOT "/etc/systemd/system");
                FILE *unit = fopen(path, "w");
                if (unit) {
                    /* **The interface is already configured**: this is the same kernel
                     * that the initramfs took the lease in, so `ip addr add` answers
                     * "RTNETLINK answers: File exists" and the unit fails — which is what
                     * "[FAILED] Failed to start desktop-cracker-n…se the initramfs took from passt)"
                     * was, while the network itself was working.  `replace`, not `add`, and
                     * every line prefixed with `-` so that a unit whose whole job is to
                     * describe state is never a failed unit. */
                    fprintf(unit,
                            "[Unit]\nDescription=desktop-cracker network (the lease the "
                            "initramfs took from passt)\n"
                            "After=network-pre.target\nBefore=network.target\n"
                            "DefaultDependencies=no\n\n"
                            "[Service]\nType=oneshot\nRemainAfterExit=yes\n"
                            "ExecStart=-/sbin/ip link set eth0 up\n"
                            "ExecStart=-/sbin/ip addr replace %s/%s dev eth0\n%s"
                            "[Install]\nWantedBy=multi-user.target\n",
                            ip, mask,
                            router[0] ? "" : "");
                    fclose(unit);
                }
                /* The route and the resolver are separate files because they are separate
                 * commands: a route with no gateway is not a route. */
                snprintf(path, sizeof(path),
                         "%s/etc/systemd/system/desk-network.service", NEWROOT);
                FILE *again = fopen(path, "a");
                if (again) {
                    if (router[0])
                        fprintf(again,
                                "[Service]\nExecStart=-/sbin/ip route replace default via %s "
                                "dev eth0\n",
                                router);
                    fclose(again);
                }
                mkdir_p(NEWROOT "/etc");
                snprintf(path, sizeof(path), "%s/etc/resolv.conf", NEWROOT);
                FILE *resolv = fopen(path, "w");
                if (resolv) {
                    if (dns[0]) {
                        char *save = NULL;
                        for (char *ns = strtok_r(dns, " ", &save); ns;
                             ns = strtok_r(NULL, " ", &save))
                            fprintf(resolv, "nameserver %s\n", ns);
                    } else {
                        fprintf(resolv, "nameserver 10.0.2.3\n");
                    }
                    fclose(resolv);
                }
                /* The disk's own network services would flush what we set up: they are
                 * masked by a symlink to /dev/null, which is how systemd disables a unit. */
                const char *off[] = {"systemd-networkd.service", "systemd-networkd.socket",
                                     "networking.service", "NetworkManager.service"};
                mkdir_p(NEWROOT "/etc/systemd/system");
                for (size_t i = 0; i < sizeof(off) / sizeof(off[0]); i++) {
                    char link[256], target[320];
                    snprintf(link, sizeof(link), "%s/etc/systemd/system/%s", NEWROOT, off[i]);
                    snprintf(target, sizeof(target), "/dev/null");
                    unlink(link);
                    if (symlink(target, link) == 0)
                        say("DESK-ROOT %s is off for this boot (the initramfs holds the lease)",
                            off[i]);
                }
                /* And the unit is switched on, so it runs at every boot of this system. */
                mkdir_p(NEWROOT "/etc/systemd/system/multi-user.target.wants");
                char want[320];
                snprintf(want, sizeof(want),
                         "%s/etc/systemd/system/multi-user.target.wants/desk-network.service",
                         NEWROOT);
                unlink(want);
                if (symlink("/etc/systemd/system/desk-network.service", want) != 0)
                    say("DESK-ROOT the network unit could not be enabled (%s)", strerror(errno));
                say("DESK-ROOT the network lease was handed to the system on the disk: %s/%s "
                    "via %s",
                    ip, mask, router[0] ? router : "(no gateway)");
            }
        }
    }

    /* The kernel filesystems, and the two paths every system wants writable even
     * when its root is not.
     *
     * `/dev/pts` is the one that must **not** be a bind of the initramfs's directory: the
     * initramfs' `/dev` is a devtmpfs, and a directory inside it is plain files with no devpts
     * superblock behind them.  Bind that into the new root and `grantpt` answers `ENODEV` —
     * measured 2026-10-12 as the guest's `xterm: Error 32, errno 19: No such device / Reason:
     * get_pty: not enough ptys`, with `/dev/pts` mounted `devtmpfs` and holding no pts at all.
     * A fresh `devpts` mount is what makes the ptmx/pts pair real. */
    struct {
        const char *dir;
        const char *fstype;
        const char *opts;
        int bind_first;
    } mounts[] = {
        {"/proc", "proc", NULL, 1},
        {"/sys", "sysfs", NULL, 1},
        {"/dev", "devtmpfs", "mode=0755", 1},
        {"/dev/pts", "devpts", "mode=0620,ptmxmode=0666", 0},
        {"/run", "tmpfs", "mode=0755,size=64m", 1},
        {"/tmp", "tmpfs", "mode=1777,size=256m", 1},
    };
    for (size_t i = 0; i < sizeof(mounts) / sizeof(mounts[0]); i++) {
        char where[256];
        snprintf(where, sizeof(where), "%s%s", NEWROOT, mounts[i].dir);
        mkdir_p(where);
        if (mounts[i].bind_first &&
            mount(mounts[i].dir, where, mounts[i].fstype, MS_BIND | MS_REC, NULL) == 0)
            continue;
        if (mount(mounts[i].fstype, where, mounts[i].fstype, 0, mounts[i].opts) != 0)
            say("DESK-ROOT could not mount %s in the new root (%s)", mounts[i].dir, strerror(errno));
    }

    /* The **kernel modules** this machine needs, and that only the initramfs
     * carries: they are for the kernel that is running, so they are copied into
     * the system we are about to enter (into the RAM overlay in read-only mode,
     * so the disk is still not written).  Without this the guest's own system
     * has no display, no sound and no input: its kernel has them as modules. */
    {
        char from[256], to[256];
        FILE *f = fopen("/proc/sys/kernel/osrelease", "r");
        char kver[128] = "";
        if (f) {
            if (fgets(kver, sizeof(kver), f)) {
                size_t len = strlen(kver);
                while (len && (kver[len - 1] == '\n' || kver[len - 1] == '\r'))
                    kver[--len] = 0;
            }
            fclose(f);
        }
        if (kver[0]) {
            snprintf(from, sizeof(from), "/lib/modules/%s", kver);
            snprintf(to, sizeof(to), "%s/lib/modules/%s", NEWROOT, kver);
            if (access(to, F_OK) == 0) {
                say("DESK-ROOT the system on the disk already has modules for %s", kver);
            } else {
                mkdir_p(to);
                const char *cp[] = {"/bin/cp", "-a", from, to, NULL};
                /* `cp -a from to` with `to` created copies *into* it, so the
                 * destination's parent is what it needs. */
                char parent[256];
                snprintf(parent, sizeof(parent), "%s/lib/modules", NEWROOT);
                mkdir_p(parent);
                if (spawn_and_wait(cp) == 0)
                    say("DESK-ROOT the kernel modules were copied into the new root (RAM)");
                else
                    say("DESK-ROOT the kernel modules could not be copied: the guest will have "
                        "no display, sound or input");
            }
        }
    }

    if (access(NEWROOT "/sbin/init", F_OK) != 0 && access(NEWROOT "/usr/lib/systemd/systemd", F_OK) != 0)
        say("DESK-ROOT warning: the disk has no /sbin/init; the system may not start");

    /* Hand the console over to the system on the disk and become its init. */
    say("DESK-ROOT starting the system on the disk: switch_root %s /sbin/init", NEWROOT);
    if (chdir(NEWROOT) != 0) {
        say("DESK-ROOT chdir: %s", strerror(errno));
        return 1;
    }
    if (mount(NEWROOT, "/", NULL, MS_MOVE, NULL) != 0) {
        say("DESK-ROOT move mount: %s", strerror(errno));
        return 1;
    }
    if (chroot(".") != 0) {
        say("DESK-ROOT chroot: %s", strerror(errno));
        return 1;
    }
    if (chdir("/") != 0)
        say("guest-tools: cannot move to the new root's own / (%s)", strerror(errno));
    char *const init_argv[] = {"/sbin/init", NULL};
    execv("/sbin/init", init_argv);
    char *const sbin_sh[] = {"/bin/sh", NULL};
    execv("/bin/sh", sbin_sh);
    say("DESK-ROOT exec /sbin/init failed: %s", strerror(errno));
    return 1;
}

/* One value out of the kernel command line (`desktop-cracker.<key>=<value>`). */
static int cmdline_value(const char *key, char *out, size_t cap)
{
    FILE *f = fopen("/proc/cmdline", "r");
    if (!f)
        return -1;
    char line[1024];
    size_t got = fread(line, 1, sizeof(line) - 1, f);
    line[got] = 0;
    fclose(f);
    char want[64];
    snprintf(want, sizeof(want), "%s=", key);
    char *p = strstr(line, want);
    if (!p)
        return -1;
    p += strlen(want);
    size_t n = 0;
    while (p[n] && p[n] != ' ' && p[n] != '\n' && n + 1 < cap) {
        out[n] = p[n];
        n++;
    }
    out[n] = 0;
    return (int)n;
}


/* ------------------------------------------------------------ disk management
 *
 * The disk manager: a microvm whose whole job is to work on a disk image the
 * host attaches.  Everything here runs **inside** the microvm, on the guest's
 * own kernel: creating a filesystem, formatting a LUKS container, opening it,
 * resizing it, changing its passphrase.  The host never needs root, a loop
 * device or a package for any of it — which is the point of doing it this way.
 *
 * The job comes in on the kernel command line:
 *
 *   desk.diskjob=create   desk.disk=ext4|luks   desk.diskfs=ext4
 * desktop-cracker.resize=1 desktop-cracker.rekey=1 desk.mapper=<name>
 *
 * and each line it prints starts with `DESK-DISK` so the host can read the result.
 */

#define KEYFILE "/run/diskkey"

/* Write the secret into a RAM file (cryptsetup reads a key *file*) and keep its
 * path; the file is removed as soon as the operation is done. */
static int write_keyfile(const char *secret)
{
    mkdir_p("/run");
    int fd = open(KEYFILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        say("DESK-DISK cannot write the key file: %s", strerror(errno));
        return -1;
    }
    if (write(fd, secret, strlen(secret)) != (ssize_t)strlen(secret)) {
        say("DESK-DISK short write of the key file");
        close(fd);
        unlink(KEYFILE);
        return -1;
    }
    close(fd);
    return 0;
}

static void forget_keyfile(void)
{
    unlink(KEYFILE);
}

/* Bring up the device-mapper target and make the node for it (no udev here). */
static int mapper_open(const char *device, const char *mapper)
{
    mkdir_p("/dev/mapper");
    const char *open_argv[] = {"/usr/sbin/cryptsetup", "luksOpen", "--key-file",
                               KEYFILE, device, mapper, NULL};
    if (spawn_and_wait(open_argv) != 0) {
        say("DESK-DISK cryptsetup luksOpen failed");
        return -1;
    }
    char path[128];
    snprintf(path, sizeof(path), "/dev/mapper/%s", mapper);
    if (access(path, F_OK) == 0)
        return 0;
    /* No udev in an initramfs: the node the kernel's view describes. */
    for (int i = 0; i < 16; i++) {
        char dir[128], name[192], line[64];
        snprintf(dir, sizeof(dir), "/sys/class/block/dm-%d", i);
        if (access(dir, F_OK) != 0)
            continue;
        snprintf(name, sizeof(name), "%s/dm/name", dir);
        read_first_line(name, line, sizeof(line));
        if (strcmp(line, mapper) != 0)
            continue;
        snprintf(name, sizeof(name), "%s/dev", dir);
        unsigned major = 0, minor = 0;
        if (read_first_line(name, line, sizeof(line)) > 0 &&
            sscanf(line, "%u:%u", &major, &minor) == 2 &&
            mknod(path, S_IFBLK | 0600, makedev(major, minor)) == 0)
            return 0;
    }
    say("DESK-DISK the mapped device has no node");
    return -1;
}

static void mapper_close(const char *mapper)
{
    /* The **name**, never the path: `cryptsetup luksClose /dev/mapper/x` asks the kernel
     * for a device called `/dev/mapper/x`, which is not one.  (The other half of the same
     * mistake the `luksOpen` had — a path where a name is wanted — and it is why a
     * container that a *job* had opened stayed open: `mapper_open` gives cryptsetup the
     * name, this gave it the path, so the close silently did nothing and the container
     * was still mapped when the boot tried to open it again.) */
    const char *name = mapper_name(mapper);
    const char *close_argv[] = {"/usr/sbin/cryptsetup", "luksClose", name, NULL};
    spawn_and_wait(close_argv);
}

/* Put a userland **into** the filesystem the container holds.
 *
 * The host brings the userland as a **second block device** (a read-only ext4
 * image), not as an archive in a share: a few hundred megabytes through 9P, then
 * gunzip, then a thousand small-file writes takes many minutes, while copying from
 * one mounted filesystem to another is what the disk controller is for.  An
 * archive in the control share is still honoured (a one-off experiment hands it
 * over that way), but the block device is the path the tools use.
 */
static int seed_filesystem(const char *mapped, const char *device, const char *seed)
{
    if (device && device[0] && access(device, F_OK) == 0) {
        mkdir_p("/mnt/seed");
        if (mount(device, "/mnt/seed", "ext4", MS_RDONLY, NULL) != 0) {
            say("DESK-DISK the userland device %s could not be mounted: %s", device,
                strerror(errno));
            return 1;
        }
        mkdir_p("/mnt/new");
        if (mount(mapped, "/mnt/new", "ext4", 0, NULL) != 0) {
            say("DESK-DISK cannot mount the new filesystem to seed it: %s", strerror(errno));
            umount("/mnt/seed");
            return 1;
        }
        /* `cp -a` keeps owners, modes, links and timestamps — everything a
         * userland needs to be a system's filesystem. */
        /* `/proc`, `/sys` and `/dev` are the **guest's own**: the new root gets them
         * from its own boot (the disk's fstab, and the init that mounts them), and
         * copying the seed's would copy the character devices — which is a copy that
         * never ends (`/dev/zero` never reaches end of file).  That is not a
         * hypothesis: the copy that hung here was reading a device node forever.
         *
         * The copy is `tar` piping into `tar`: the image has GNU tar, and it keeps
         * owners, modes, links and times — the same as `cp -a` — while its
         * `--exclude` is what leaves the kernel's directories behind. */
        /* `/bin/tar` **by its full path**, because busybox's shell prefers its own
         * applets: a bare `tar` is busybox's, which has no `--exclude` (measured — it
         * answered with its usage line).  The image's `/bin/tar` is GNU tar, and its
         * exclusions are what leave the kernel's directories behind. */
        /* The copy is watched: a seed whose read blocks for good is the one failure this
         * path cannot diagnose from the host (the guest's console goes quiet and the job sits
         * there).  `timeout` on the **reader** side is what turns that into an answer.
         *
         * And the copy's **status is the copy's own**, kept in a variable: a shell whose last
         * command is the `echo` exits 0 whatever the copy did, and a copy that ran out of room on a
         * disk too small for the userland then reported a job that had succeeded (measured on
         * 2026-10-12: `the copy ended with 2` — GNU tar's "cannot write: No space left on device" —
         * followed by `seeded the filesystem`, on a 3 GiB disk against a 1.8 GiB userland).  A disk
         * that is too small is a failure, and it has to end the job. */
        const char *copy[] = {"/bin/sh", "-c",
                              "cd /mnt/seed && echo \"DESK-DISK copying the userland\" && "
                              "timeout 600 /bin/sh -c '/bin/tar --exclude=./proc --exclude=./sys "
                              "--exclude=./dev --exclude=./run --exclude=./tmp "
                              "--exclude=./mnt -cf - . | /bin/tar -C /mnt/new -xf -'; "
                              "status=$?; echo \"DESK-DISK the copy ended with $status\"; exit $status",
                              NULL};
        int rc = spawn_and_wait(copy);
        sync();
        umount("/mnt/new");
        umount("/mnt/seed");
        if (rc != 0) {
            say("DESK-DISK copying the userland from %s failed (the copy's status is %d): is the disk "
                "big enough for it?  (the root partition holds the userland, and a disk smaller "
                "than the image has no room for it)",
                device, rc);
            return 1;
        }
        say("DESK-DISK seeded the filesystem from %s", device);
        return 0;
    }

    if (seed && access(seed, R_OK) == 0) {
        mkdir_p("/mnt/new");
        if (mount(mapped, "/mnt/new", "ext4", 0, NULL) != 0) {
            say("DESK-DISK cannot mount the new filesystem to seed it: %s", strerror(errno));
            return 1;
        }
        const char *argv[] = {"/bin/tar", "xzf", seed, "-C", "/mnt/new", NULL};
        int rc = spawn_and_wait(argv);
        sync();
        umount("/mnt/new");
        if (rc != 0) {
            say("DESK-DISK unpacking the seed archive failed");
            return 1;
        }
        say("DESK-DISK seeded the filesystem from %s", seed);
        return 0;
    }
    say("DESK-DISK no userland to seed with: the disk is a data disk");
    return 0;
}

/* The partition table a desktop-cracker disk has: a small **state** partition first
 * (always read-write: the temp paths and the state a running system insists on
 * writing) and the **root** partition with the rest.  Both inside the container,
 * so the whole disk stays encrypted.
 *
 * Sizes are in MiB, and the state partition is `DESK_STATE_MB` unless the
 * disk is too small for it. */
#define STATE_LABEL "desktop-cracker-state"
#define ROOT_LABEL "desk-root"

static int state_partition_mb(long disk_mb)
{
    const char *env = getenv("DESK_STATE_MB");
    long want = env && env[0] ? strtol(env, NULL, 10) : 2048;
    if (want < 64)
        want = 64;
    if (disk_mb > 0 && want > disk_mb / 2)
        want = disk_mb / 2;
    return (int)want;
}

/* Ask the kernel to publish `mapper`'s partitions and say where the two are.
 *
 * It **writes nothing**: the table is the disk's own, and rewriting it would move
 * the offsets the filesystems live at.  What it does is `kpartx -a`, which makes
 * the kernel publish the partitions *and* their nodes (an initramfs has no udev),
 * and then finds them: the kernel names a partition `<parent><n>`, so the names
 * are read from sysfs rather than assumed.
 *
 * Returns the number of partitions found (0 when the container holds no table,
 * which is a data disk's shape), or -1 when the nodes could not be made. */
static int publish_partitions(const char *mapper, char *root_dev, size_t root_cap,
                              char *state_dev, size_t state_cap)
{
    char map[160];
    snprintf(map, sizeof(map), "/dev/mapper/%s", mapper);
    if (root_dev && root_cap)
        snprintf(root_dev, root_cap, "%s", map);
    if (state_dev && state_cap)
        snprintf(state_dev, state_cap, "%s", map);

    const char *kpartx[] = {"/sbin/kpartx", "-a", map, NULL};
    int px = spawn_and_wait(kpartx);

    size_t parent_len = strlen(mapper);
    int found = 0;
    for (int i = 0; i < 16; i++) {
        char dir[128], name[128] = "", dev[64] = "";
        snprintf(dir, sizeof(dir), "/sys/class/block/dm-%d/dm/name", i);
        if (read_first_line(dir, name, sizeof(name)) <= 0)
            continue;
        if (strncmp(name, mapper, parent_len) != 0)
            continue;
        const char *n = name + parent_len;
        if (strlen(n) != 1 || n[0] < '1' || n[0] > '9')
            continue;
        snprintf(dir, sizeof(dir), "/sys/class/block/dm-%d/dev", i);
        if (read_first_line(dir, dev, sizeof(dev)) <= 0)
            continue;
        unsigned major = 0, minor = 0;
        if (sscanf(dev, "%u:%u", &major, &minor) != 2)
            continue;
        char node[192];
        snprintf(node, sizeof(node), "/dev/mapper/%s", name);
        if (access(node, F_OK) != 0 && mknod(node, S_IFBLK | 0600, makedev(major, minor)) != 0) {
            say("DESK-DISK cannot make a node for partition %s: %s", node, strerror(errno));
            continue;
        }
        found++;
        if (n[0] == '1' && state_dev) {
            snprintf(state_dev, state_cap, "%s", node);
        } else if (n[0] == '2' && root_dev) {
            snprintf(root_dev, root_cap, "%s", node);
        }
    }
    if (px != 0 && found == 0)
        return -1;
    return found;
}

/* Write the two-partition table **inside** the container and publish it: a state
 * partition first (always read-write), the root partition with the rest. */
static int make_partitions(const char *mapper, char *root_dev, size_t root_cap,
                           char *state_dev, size_t state_cap)
{
    char map[160];
    snprintf(map, sizeof(map), "/dev/mapper/%s", mapper);

    char size[32] = "";
    const char *size_argv[] = {"/sbin/blockdev", "--getsize64", map, NULL};
    long mb = 0;
    if (run_capture(size_argv, size, sizeof(size)) == 0 && size[0])
        mb = strtol(size, NULL, 10) / (1024 * 1024);

    int state_mb = state_partition_mb(mb);
    char script[128];
    snprintf(script, sizeof(script), "label: dos\n,%dM,L\n,,L\n", state_mb);
    const char *sfdisk_argv[] = {"/sbin/sfdisk", map, NULL};
    if (run_with_input(sfdisk_argv, script) != 0) {
        say("DESK-DISK sfdisk could not write the table inside %s", map);
        return -1;
    }
    say("DESK-DISK the container has two partitions: %d MiB of state, the rest for the root",
        state_mb);
    return publish_partitions(mapper, root_dev, root_cap, state_dev, state_cap) == 2 ? 0 : -1;
}

/* `dmluks <device> [mapper] [fstype]`: format a LUKS container, open it, write
 * the two-partition table inside it, put a filesystem on each partition, seed the
 * root one with the userland the host brought, and close it again.  This is the
 * shape a guest's root disk has. */
static int do_dmluks(const char *device, const char *mapper, const char *fstype);

static int do_dmluks(const char *device, const char *mapper, const char *fstype)
{
    /* The passphrase itself: read from the job's key file into memory, so the command can
     * be handed it on a pipe. */
    static char key_text[256];
    key_text[0] = 0;
    if (read_first_line(KEYFILE, key_text, sizeof(key_text)) < 0) {
        say("DESK-DISK the job's key file %s could not be read", KEYFILE);
        return 1;
    }
    /* The passphrase comes from the job's own input **as a pipe**:
     * `cryptsetup --key-file -` reads it from standard input, which is the one channel a
     * guest has that never touches a filesystem (the key file may not be readable to
     * cryptsetup at all — it is the *other* end of the container being made). */
    const char *format_argv[] = {"/usr/sbin/cryptsetup", "luksFormat", "--type",
                                 "luks1", "--batch-mode", "--key-file", "-",
                                 device, NULL};
    if (run_with_input(format_argv, key_text) != 0) {
        say("DESK-DISK luksFormat failed on %s", device);
        return 1;
    }
    say("DESK-DISK luksFormat ok device=%s", device);
    if (mapper_open(device, mapper) != 0)
        return 1;

    /* Both partitions live **inside** the container, so the whole disk is
     * encrypted; the first one is the state the system needs writable, the second
     * is the root filesystem itself. */
    char root_dev[192] = "", state_dev[192] = "";
    int partitioned = make_partitions(mapper, root_dev, sizeof(root_dev),
                                      state_dev, sizeof(state_dev)) == 0;
    if (!partitioned) {
        /* A disk with no room for two partitions is still a disk: the container
         * itself takes the filesystem, which is the shape a data disk has. */
        snprintf(root_dev, sizeof(root_dev), "/dev/mapper/%s", mapper);
    }

    const char *mkfs_argv[] = {"/sbin/mke2fs", "-q", "-F", "-t", "ext4", "-L",
                               ROOT_LABEL, root_dev, NULL};
    if (spawn_and_wait(mkfs_argv) != 0) {
        say("DESK-DISK mke2fs failed on %s", root_dev);
        mapper_close(mapper);
        return 1;
    }
    say("DESK-DISK the root filesystem is on %s", root_dev);
    if (partitioned) {
        const char *state_argv[] = {"/sbin/mke2fs", "-q", "-F", "-t", "ext4", "-L",
                                    STATE_LABEL, state_dev, NULL};
        if (spawn_and_wait(state_argv) == 0)
            say("DESK-DISK the always-writable state partition is %s", state_dev);
        else
            say("DESK-DISK the state partition could not be made");
    }

    /* A userland, when the host brought one: what makes the disk bootable.  It
     * goes on the **root** partition, inside the encryption.  The host hands it
     * over as a read-only block device of its own (`desk.seeddev`) or, for a
     * one-off, as an archive in the control share. */
    char seed_dev[64] = "";
    cmdline_value("desk.seeddev", seed_dev, sizeof(seed_dev));
    if (seed_filesystem(root_dev, seed_dev, "/run/desktop-cracker/seed.tar.gz") != 0) {
        mapper_close(mapper);
        return 1;
    }
    mapper_close(mapper);
    say("DESK-DISK luks ok device=%s mapper=%s fstype=%s", device, mapper, fstype);
    return 0;
}

/* `dmpass <device> <mapper>`: change the container's passphrase.
 *
 * Two secrets are involved — the current one, which cryptsetup takes from its
 * key file, and the new one, which it asks for on standard input (twice: it
 * verifies it) — so the new one is written into the child's stdin. */
static int do_dmpass(const char *device, const char *mapper, const char *new_secret)
{
    int fds[2];
    if (pipe(fds) != 0) {
        say("DESK-DISK pipe: %s", strerror(errno));
        return 1;
    }
    pid_t pid = fork();
    if (pid == 0) {
        dup2(fds[0], 0);
        close(fds[0]);
        close(fds[1]);
        const char *argv[] = {"/usr/sbin/cryptsetup", "luksChangeKey",
                              "--key-file", KEYFILE, device, NULL};
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }
    close(fds[0]);
    /* The two new-passphrase reads, and the verification question's answer. */
    char answers[1024];
    int n = snprintf(answers, sizeof(answers), "%s\n%s\n", new_secret, new_secret);
    if (write(fds[1], answers, (size_t)n) != n)
        say("DESK-DISK short write of the new passphrase");
    close(fds[1]);
    memset(answers, 0, sizeof(answers));
    if (wait_status(pid) != 0) {
        say("DESK-DISK luksChangeKey failed on %s", device);
        return 1;
    }
    say("DESK-DISK passphrase changed device=%s mapper=%s", device, mapper);
    return 0;
}

/* **Write the table again, with the last partition filling the container.**
 *
 * This is the part that does not work with `sfdisk -N`: `sfdisk` refuses to rewrite one
 * partition of a disk that is in use, and it refuses by **writing nothing** — measured
 * 2026-10-13, where "New situation" was identical to "Old situation", the table's last
 * partition still ended at 24574 MiB while the container was 32766, and every later step
 * (the map, `resize2fs`) then worked on the partition that was never grown.
 *
 * So the whole table is written: the state partition exactly as it is (its offset and size
 * are read from the table, so nothing about the root filesystem's neighbours moves), the
 * root partition from where it starts to the end of the container, then `kpartx -d`/`-a` to
 * publish the two devices again — an initramfs has no udev, and a device-mapper node keeps
 * the size it was built with.  Nothing is written **into** either partition, so a
 * filesystem keeps its offset and only grows.
 *
 * Returns the number of partitions found afterwards, or -1 when the table cannot be
 * written. */
static int regrow_partitions(const char *mapper, const char *map, char *root_dev,
                             size_t root_cap, long long disk_bytes)
{
    const char *dump[] = {"/sbin/sfdisk", "--dump", map, NULL};
    char out[4096] = "";
    if (run_capture(dump, out, sizeof(out)) < 0) {
        say("DESK-DISK the partition table of %s could not be read", map);
        return -1;
    }
    /* **What the dump said, on one line**: the numbers below are read from it, and a parse is
     * worth nothing without the text it parsed. */
    {
        char one[1024];
        size_t at = 0;
        for (const char *c = out; *c && at + 2 < sizeof(one); c++) {
            if (*c == '\n') {
                one[at++] = ' ';
                one[at++] = '|';
                one[at++] = ' ';
            } else {
                one[at++] = *c;
            }
        }
        one[at] = 0;
        say("DESK-DISK the table dump is: %s", one);
    }
    /* The table's own two entries, in order: the state partition and the root one. */
    long long starts[4] = {0}, sizes[4] = {0};
    char root_type[16] = "83";
    int n = 0;
    char *line = out;
    while (line && *line && n < 4) {
        /* **The line ends where its newline is**: `strstr` searches the whole remaining buffer,
         * so a parse that did not cut the line found the *first* partition's numbers on every
         * turn — measured 2026-10-13, where the table that was written said the root partition
         * started at the state partition's own offset and `sfdisk` refused it. */
        char *nl = strchr(line, '\n');
        if (nl)
            *nl = 0;
        const char *start = strstr(line, "start=");
        const char *size = strstr(line, "size=");
        if (start && size) {
            starts[n] = strtoll(start + 6, NULL, 10);
            sizes[n] = strtoll(size + 5, NULL, 10);
            if (n == 1) {
                const char *t = strstr(line, "type=");
                if (t)
                    snprintf(root_type, sizeof(root_type), "%s", t + 5);
            }
            n++;
        }
        line = nl ? nl + 1 : NULL;
    }
    if (n < 2) {
        say("DESK-DISK %s holds %d partition(s); there is nothing to regrow", map, n);
        return -1;
    }
    long long root_mb = (sizes[1] * 512) / (1024 * 1024);
    long long want_mb = (disk_bytes / (1024 * 1024)) - (starts[1] * 512) / (1024 * 1024) - 1;
    if (want_mb <= root_mb) {
        say("DESK-DISK the root partition already fills the container (%lld MiB)", root_mb);
        return publish_partitions(mapper, root_dev, root_cap, NULL, 0);
    }

    /* The table, whole: sector 0's label, then the two partitions by their own start and
     * **the state one's size left exactly as it is**.  The root partition is given a start
     * and no size — `sfdisk`'s own words are "an empty size means the rest of the disk", and
     * a size written here would be a number this guest computed, which is how a table with
     * "no free sectors left" was written on 2026-10-13 (the size was larger than the space
     * that follows the start, and `sfdisk` refused the whole line). */
    char script[256];
    snprintf(script, sizeof(script),
             "label: dos\nstart=%lld, size=%lld, type=83\nstart=%lld, type=%s\n",
             starts[0], sizes[0], starts[1], root_type);
    say("DESK-DISK writing the table: the root partition takes the rest of the container "
        "(%lld MiB -> %lld MiB)", root_mb, want_mb);
    /* The script itself, in the log, **on one line**: the host shows a caller the lines that
     * carry an `DESK-DISK` marker (a job's own words), so a table printed over several lines
     * would arrive as a single sentence with its numbers missing. */
    {
        char one[256];
        size_t at = 0;
        for (const char *c = script; *c && at + 2 < sizeof(one); c++) {
            if (*c == '\n') {
                one[at++] = ' ';
                one[at++] = '|';
                one[at++] = ' ';
            } else {
                one[at++] = *c;
            }
        }
        one[at] = 0;
        say("DESK-DISK the script is: %s", one);
    }
    /* **`--no-reread`**: the kernel's own reread of a disk in use is refused, and that
     * refusal is what stops `sfdisk` before it writes.  The partitions are published by
     * `kpartx` instead, which is the path this guest has. */
    const char *write[] = {"/sbin/sfdisk", "--force", "--no-reread", map, NULL};
    if (run_with_input(write, script) != 0) {
        say("DESK-DISK the partition table of %s could not be written", map);
        return -1;
    }
    /* Drop the mappings and build them again: they are what carries the new size. */
    const char *drop[] = {"/sbin/kpartx", "-d", map, NULL};
    int dx = spawn_and_wait(drop);
    const char *add[] = {"/sbin/kpartx", "-a", map, NULL};
    int ax = spawn_and_wait(add);
    char state[192] = "";
    int have = publish_partitions(mapper, root_dev, root_cap, state, sizeof(state));
    say("DESK-DISK the table was written and published again (kpartx -d=%d -a=%d, %d "
        "partition(s))", dx, ax, have);
    return have;
}

/* `dmresize <device> <mapper> [fstype]`: grow the filesystem to the disk's current
 * size.
 *
 * A desktop-cracker disk has partitions inside its container, so growing it is:
 *
 *   1. the container is opened (`cryptsetup luksOpen`);
 *   2. its table is **written again with the last partition filling the container**
 *      (`regrow_partitions`: `sfdisk -N` alone refuses on a disk in use and writes nothing,
 *      measured 2026-10-13);
 *   3. the partition mappings are dropped and made again, so the kernel's devices learn the
 *      new size (a device-mapper node keeps the size it was built with, and an initramfs has
 *      no udev);
 *   4. the filesystem is grown into the partition (`resize2fs`).
 *
 * Nothing is ever written **into** a partition: its offset does not move, so the filesystem
 * only grows.  A disk with no partition table (a data disk) is grown as the container
 * itself.
 *
 * Sizes are read where they mean something: the container's and a partition's from
 * `blockdev --getsize64`, the table's from `sfdisk --dump` — and all three are said out loud,
 * because a resize that does not happen is a resize somebody has to be able to explain. */
static int do_dmresize(const char *device, const char *mapper, const char *fstype)
{
    if (!mapper[0]) {
        say("DESK-DISK a container needs its mapper name to be resized");
        return 1;
    }
    if (mapper_open(device, mapper) != 0)
        return 1;

    char map[160];
    snprintf(map, sizeof(map), "/dev/mapper/%s", mapper);

    /* The container's own size, from the kernel. */
    long long map_bytes = block_device_size_mib(map) * 1024 * 1024;
    say("DESK-DISK the container %s is %lld MiB", map, map_bytes / (1024 * 1024));

    char state[192] = "", root[192] = "";
    char target[192];
    snprintf(target, sizeof(target), "%s", map);
    int have = regrow_partitions(mapper, map, root, sizeof(root), map_bytes);
    if (have >= 2) {
        snprintf(target, sizeof(target), "%s", root);
        char now[32] = "";
        const char *size_argv[] = {"/sbin/blockdev", "--getsize64", target, NULL};
        if (run_capture(size_argv, now, sizeof(now)) >= 0 && now[0])
            say("DESK-DISK the partition to grow is %s, %lld MiB",
                target, strtoll(now, NULL, 10) / (1024 * 1024));
        else
            say("DESK-DISK the partition to grow is %s", target);
    }

    /* **The filesystem is never left in a half-grown state**: the last thing the previous boot
     * did with it was write to it, so `e2fsck -f` is what `resize2fs` asks for before it will
     * touch it ("Please run 'e2fsck -f /dev/mapper/desktop-cracker2' first" — measured 2026-10-13).
     * `-y` answers the repair questions; nothing is mounted here (a resize job opens the
     * container and never mounts a filesystem), so this is the offline check the tool wants and
     * it is safe for the filesystem to be repaired. */
    if (access("/sbin/e2fsck", X_OK) == 0) {
        const char *check[] = {"/sbin/e2fsck", "-f", "-y", target, NULL};
        int cx = spawn_and_wait(check);
        say("DESK-DISK e2fsck %s said %d", target, cx);
        if (cx > 1) {
            mapper_close(mapper);
            say("DESK-DISK the filesystem on %s could not be checked (e2fsck %d); nothing was "
                "resized", target, cx);
            return 1;
        }
    }

    const char *argv[] = {"/sbin/resize2fs", target, NULL};
    int rc = spawn_and_wait(argv);
    mapper_close(mapper);
    if (rc != 0) {
        say("DESK-DISK resize2fs failed on %s: the device is smaller than the container, or "
            "the filesystem does not fit where it is",
            target);
        return 1;
    }
    say("DESK-DISK resize ok device=%s mapper=%s fstype=%s", device, mapper, fstype);
    return 0;
}

/* `dminfo <device>`: what is on it, as the host needs to know. */
static int do_dminfo(const char *device)
{
    int fd = open(device, O_RDONLY);
    if (fd < 0) {
        say("DESK-DISK no device %s", device);
        return 1;
    }
    unsigned char magic[6] = {0};
    ssize_t n = read(fd, magic, sizeof(magic));
    close(fd);
    int luks = (n == (ssize_t)sizeof(magic) && memcmp(magic, "LUKS\xba\xbe", 6) == 0);
    say("DESK-DISK info device=%s luks=%s", device, luks ? "yes" : "no");

    /* The filesystem label/size, when there is a filesystem: `dumpe2fs` reads
     * the superblock without mounting anything. */
    char label[128] = "";
    char cmd[256];
    snprintf(cmd, sizeof(cmd), "/sbin/dumpe2fs -h %s 2>/dev/null | sed -n 's/^Filesystem volume name: *//p'", device);
    FILE *p = popen(cmd, "r");
    if (p) {
        if (fgets(label, sizeof(label), p)) {
            size_t len = strlen(label);
            while (len && (label[len - 1] == '\n' || label[len - 1] == '\r'))
                label[--len] = 0;
        }
        pclose(p);
    }
    if (label[0])
        say("DESK-DISK info label=%s", label);

    /* What is on the filesystem, read straight from the superblock with
     * `debugfs` (no mount, no container): a disk with `/etc` and `/usr` holds a
     * userland and can boot a system, an empty one is a data disk. */
    char target[128];
    snprintf(target, sizeof(target), "%s", device);
    if (luks) {
        char mapper[128];
        cmdline_value("desk.mapper", mapper, sizeof(mapper));
        if (mapper[0] && access("/run/desktop-cracker/disk.secret", R_OK) != 0) {
            /* The Info job is asked without a passphrase: the filesystem is named
             * as best it can be without opening the container. */
            snprintf(target, sizeof(target), "%s", device);
        }
    }
    char listing[256];
    snprintf(listing, sizeof(listing),
             "/sbin/debugfs -R 'ls -l /' %s 2>/dev/null", target);
    FILE *ls = popen(listing, "r");
    if (ls) {
        int etc = 0, usr = 0, init = 0, lines = 0;
        char line[512];
        while (fgets(line, sizeof(line), ls)) {
            lines++;
            if (strstr(line, "etc")) etc = 1;
            if (strstr(line, "usr")) usr = 1;
            if (strstr(line, "sbin") || strstr(line, "bin")) init = 1;
        }
        pclose(ls);
        say("DESK-DISK info root_entries=%d userland=%s", lines,
            (etc && usr && init) ? "yes" : (lines > 1 ? "partial" : "no"));
    }
    return 0;
}


static double now_seconds(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* The disk manager's init: read the job from the kernel command line, run it,
 * print the result and power the machine off. */



/* `dmprobe`: how a guest makes an always-writable partition inside its
 * encrypted root disk, with **no udev**.
 *
 * The project's rule: the root disk has partitions that are always read-write, used to store
 * temporary files and the things a system cannot work with on a read-only medium (the disk is
 * entirely encrypted).  The partition table therefore
 * lives *inside* the LUKS container, and the guest has to reach the partitions of
 * a device-mapper device it opened itself — with no udev to make their nodes.
 * This verb is the measurement of how, in the shape the guest actually has:
 *
 *   1. a disk, a LUKS container on it, opened;
 *   2. a partition table written **inside** the open container (`sfdisk` takes a
 *      script, which is what an initramfs without a terminal needs);
 *   3. the kernel asked to publish the partitions (`partx -a`, because the
 *      device-mapper driver does not scan them by itself and there is no udev),
 *      and what `/proc/partitions` and `/dev/mapper` say afterwards;
 *   4. a filesystem made on the first partition and mounted: the always-writable
 *      part of the disk, in one run.
 */
static int do_dmprobe(void)
{
    say("DESK-DM a disk, a LUKS container on it, and partitions inside the container");
    mkdir_p("/run/t");
    mkdir_p("/dev/mapper");
    int fd = open("/run/t/disk.img", O_RDWR | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) {
        say("DESK-DM cannot make the image: %s", strerror(errno));
        return 1;
    }
    if (ftruncate(fd, 64 * 1024 * 1024) != 0)
        say("DESK-DM truncate: %s", strerror(errno));
    close(fd);

    const char *loop_argv[] = {"/sbin/losetup", "-f", "--show", "/run/t/disk.img", NULL};
    char loop[64] = "";
    if (run_capture(loop_argv, loop, sizeof(loop)) != 0 || !loop[0]) {
        say("DESK-DM no loop device (losetup said nothing usable)");
        return 1;
    }
    say("DESK-DM loop device %s", loop);

    const char *keyfile = "/run/t/key";
    int kf = open(keyfile, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (kf >= 0) {
        if (write(kf, "probe", 5) < 0)
            say("DESK-DM short write of the key");
        close(kf);
    }
    const char *format[] = {"/sbin/cryptsetup", "luksFormat", "--type", "luks1",
                            "--batch-mode", "--key-file", keyfile, loop, NULL};
    if (spawn_and_wait(format) != 0) {
        say("DESK-DM luksFormat failed");
        return 1;
    }
    const char *open_map[] = {"/sbin/cryptsetup", "luksOpen", "--key-file", keyfile,
                              loop, "probe", NULL};
    if (spawn_and_wait(open_map) != 0) {
        say("DESK-DM luksOpen failed");
        return 1;
    }
    say("DESK-DM the container is open at /dev/mapper/probe");

    const char *sfdisk_argv[] = {"/sbin/sfdisk", "/dev/mapper/probe", NULL};
    int rc = run_with_input(sfdisk_argv, "label: dos\n,32M,L\n,,L\n");
    say("DESK-DM sfdisk wrote the table inside the container (exit %d)", rc);

    /* The kernel is asked to publish the partitions, and the tools' own words are
     * read: this is the step that decides how a guest gets at them. */
    {
        const char *both[] = {"/bin/sh", "-c",
                              "partx -a /dev/mapper/probe; echo partx=$?; "
                              "kpartx -a /dev/mapper/probe; echo kpartx=$?; "
                              "echo ---; ls /dev/mapper/", NULL};
        char out[512] = "";
        run_capture(both, out, sizeof(out));
        say("DESK-DM partx/kpartx said: %s", out);
    }
    /* What the kernel has for each mapped device of ours: its name, whether it is
     * a partition, and who its parent is. */
    for (int i = 0; i < 8; i++) {
        char dir[128], line[80];
        snprintf(dir, sizeof(dir), "/sys/class/block/dm-%d/dm/name", i);
        if (read_first_line(dir, line, sizeof(line)) <= 0)
            continue;
        char part[16] = "-", slaves[256] = "";
        snprintf(dir, sizeof(dir), "/sys/class/block/dm-%d/partition", i);
        read_first_line(dir, part, sizeof(part));
        snprintf(dir, sizeof(dir), "/bin/ls /sys/class/block/dm-%d/slaves", i);
        (void)slaves;
        say("DESK-DM dm-%d name=%s partition=%s", i, line, part);
    }
    {
        const char *slave[] = {"/bin/sh", "-c",
                               "for d in /sys/class/block/dm-*/slaves/probe; do "
                               "  echo $d: $(cat $d 2>/dev/null) $(readlink -f $d); done", NULL};
        char out[512] = "";
        run_capture(slave, out, sizeof(out));
        say("DESK-DM slave entries: %s", out);
    }
    /* The point of it: a filesystem on the first partition, mounted read-write. */
    {
        const char *first = "/dev/mapper/probe1";
        if (access(first, F_OK) == 0) {
            const char *mkfs2[] = {"/sbin/mke2fs", "-q", "-F", "-t", "ext4", first, NULL};
            if (spawn_and_wait(mkfs2) == 0) {
                mkdir_p("/mnt/probe1");
                if (mount(first, "/mnt/probe1", "ext4", 0, NULL) == 0) {
                    say("DESK-DM the first partition mounts read-write: yes");
                    umount("/mnt/probe1");
                } else {
                    say("DESK-DM the first partition could not be mounted: %s", strerror(errno));
                }
            }
        }
    }

    const char *close_map[] = {"/sbin/cryptsetup", "luksClose", "probe", NULL};
    spawn_and_wait(close_map);
    const char *detach[] = {"/sbin/losetup", "-d", loop, NULL};
    spawn_and_wait(detach);
    unlink(keyfile);
    return 0;
}

/* Run a command and collect its first line of output. */
static int run_capture(const char *const argv[], char *out, size_t cap)
{
    int fds[2];
    if (pipe(fds) != 0)
        return -1;
    pid_t pid = fork();
    if (pid == 0) {
        dup2(fds[1], 1);
        close(fds[0]);
        close(fds[1]);
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }
    close(fds[1]);
    /* **Everything the command wrote**, not one read of it: `sfdisk --dump` prints a line per
     * partition and a pipe hands them over in pieces, so a single `read` here truncated the
     * table to its first line (measured 2026-10-13: a repartition that "succeeded" while the
     * numbers it parsed were the *state* partition's).  The buffer keeps what fits and the rest
     * is read and dropped, so the command never blocks on a full pipe. */
    size_t have = 0;
    for (;;) {
        ssize_t n = read(fds[0], out + have, (cap - 1) - have);
        if (n <= 0)
            break;
        have += (size_t)n;
        if (have >= cap - 1) {
            char drop[512];
            while (read(fds[0], drop, sizeof(drop)) > 0)
                ;
            break;
        }
    }
    out[have] = 0;
    size_t len = strlen(out);
    while (len && (out[len - 1] == '\n' || out[len - 1] == '\r'))
        out[--len] = 0;
    close(fds[0]);
    return wait_status(pid);
}

/* Run a command with a script on its standard input (fdisk's own answers). */
static int run_with_input(const char *const argv[], const char *input)
{
    int fds[2];
    if (pipe(fds) != 0)
        return -1;
    pid_t pid = fork();
    if (pid == 0) {
        dup2(fds[0], 0);
        close(fds[0]);
        close(fds[1]);
        execvp(argv[0], (char *const *)argv);
        _exit(127);
    }
    close(fds[0]);
    if (input[0])
        if (write(fds[1], input, strlen(input)) < 0)
            say("DESK-DM short write to the command's input");
    close(fds[1]);
    return wait_status(pid);
}

/* How big a block device is, in MiB (0 when it cannot be asked). */
static long long block_device_size_mib(const char *device)
{
    int fd = open(device, O_RDONLY);
    if (fd < 0)
        return 0;
    unsigned long long bytes = 0;
    if (ioctl(fd, BLKGETSIZE64, &bytes) != 0)
        bytes = 0;
    close(fd);
    return (long long)(bytes / (1024 * 1024));
}

/* How big a file is, in bytes (0 when it is not there). */
static long long file_size_bytes(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return 0;
    return (long long)st.st_size;
}

static int do_diskmgr(void)
{
    char job[32] = "", kind[32] = "", fstype[32] = "ext4", mapper[128] = "desk";
    char device[64] = "/dev/vda";
    cmdline_value("desk.diskjob", job, sizeof(job));
    cmdline_value("desk.disk", kind, sizeof(kind));
    cmdline_value("desk.diskfs", fstype, sizeof(fstype));
    cmdline_value("desk.mapper", mapper, sizeof(mapper));
    cmdline_value("desk.device", device, sizeof(device));
    say("DESK-DISK job=%s kind=%s fs=%s device=%s mapper=%s", job, kind, fstype,
        device, mapper);
    if (!job[0]) {
        say("DESK-DISK no job given");
        return 2;
    }

    /* The secret, when this job has one, comes from a file the host wrote into
     * the control share; it is copied to RAM and the host's copy is removed. */
    char secret[256] = "";
    if (access("/run/desktop-cracker/disk.secret", R_OK) == 0) {
        read_first_line("/run/desktop-cracker/disk.secret", secret, sizeof(secret));
        unlink("/run/desktop-cracker/disk.secret");
    }
    int has_secret = secret[0] != 0;
    if (has_secret && write_keyfile(secret) != 0) {
        memset(secret, 0, sizeof(secret));
        return 1;
    }
    memset(secret, 0, sizeof(secret));

    if (access(device, F_OK) != 0) {
        say("DESK-DISK no %s attached", device);
        forget_keyfile();
        return 1;
    }

    int rc = 1;
    if (strcmp(job, "validate") == 0) {
        /* The operator's own tool: **prove every layer here**, inside the same guest and on
         * the same kind of device a real run uses, and say what each step did.  It exists
         * because the alternative was testing a disk on the host, with the host's own
         * cryptsetup and a loop device — a different environment, which is how a bug that
         * only the guest has survives being "checked". */
        say("DESK-VALIDATE device=%s mapper=%s", device, mapper);
        say("DESK-VALIDATE ok size=%lldMiB", (long long)block_device_size_mib(device));
        if (!has_secret) {
            say("DESK-VALIDATE failed: no password was given (pass --pass, or pipe it)");
            return 1;
        }
        const char *keyfile = KEYFILE;
        say("DESK-VALIDATE ok keyfile=%s (%lld byte(s))", keyfile, (long long)file_size_bytes(keyfile));
        char probe_name[128];
        snprintf(probe_name, sizeof(probe_name), "%.100s", mapper_name(mapper));
        {
            const char *probe[] = {"/sbin/cryptsetup", "open", "--test-passphrase",
                                   "--key-file", keyfile, device, probe_name, NULL};
            char out[512] = "";
            int probe_rc = run_capture(probe, out, sizeof(out));
            say("DESK-VALIDATE %s cryptsetup --test-passphrase exit=%d %s",
                probe_rc == 0 ? "ok" : "failed", probe_rc, out);
            if (probe_rc != 0) {
                say("DESK-VALIDATE failed: the container refused the password");
                return 1;
            }
        }
        {
            const char *open_argv[] = {"/sbin/cryptsetup", "luksOpen", "--readonly",
                                       "--key-file", keyfile, device, probe_name, NULL};
            char out[512] = "";
            int open_rc = run_capture(open_argv, out, sizeof(out));
            say("DESK-VALIDATE %s luksOpen exit=%d %s", open_rc == 0 ? "ok" : "failed", open_rc,
                out);
            if (open_rc != 0) {
                say("DESK-VALIDATE failed: the container did not open");
                return 1;
            }
        }
        say("DESK-VALIDATE ok mapper=%s", mapper);
        {
            char out[512] = "";
            const char *lsblk[] = {"/bin/busybox", "ls", mapper, NULL};
            int ls_rc = run_capture(lsblk, out, sizeof(out));
            say("DESK-VALIDATE %s the mapped device exists (%d): %s", ls_rc == 0 ? "ok" : "failed",
                ls_rc, out);
        }
        rc = 0;
    } else if (strcmp(job, "desk-try") == 0) {
        /* **One** password — which the sharing above has already copied to a file of its
         * own — one answer, and the machine powers off.  `rootboot` in its `ro-try` mode
         * is what opens the container with that file and reports (`password ok` /
         * `wrong-password`).  The disk manager drives it (`desk-disk`); the
         * application's own root disk never comes this way. */
        if (!has_secret) {
            say("DESK-ROOT wrong-password no password was provided for the disk");
            rc = 0;
        } else {
            /* The password is already in the manager's own key file (`/run/diskkey`,
             * written from the control share and unlinked there): `rootboot` is told
             * where it is with `DESK_ROOT_PASSWORD_FILE`, so nothing is copied
             * twice and the manager's copy is what is tried. */
            setenv("DESK_ROOT_PASSWORD_FILE", KEYFILE, 1);
            const char *try_argv[] = {"/bin/guest-tools", "rootboot", device,
                                      "/dev/mapper/desk-root", "ro-try", NULL};
            rc = spawn_and_wait(try_argv);
            say("DESK-ROOT try exit=%d", rc);
            rc = 0;
        }
    } else if (strcmp(job, "info") == 0)
        rc = do_dminfo(device);
    else if (strcmp(job, "create") == 0)
        rc = has_secret ? do_dmluks(device, mapper, fstype)
                        : (say("DESK-DISK a disk is always encrypted, so it needs a password"), 1);
    else if (strcmp(job, "change-pass") == 0) {
        /* `desktop-cracker.secret2` is the *new* passphrase; `disk.secret` is the
         * current one. */
        char new_secret[256] = "";
        read_first_line("/run/desktop-cracker/disk.secret.new", new_secret, sizeof(new_secret));
        unlink("/run/desktop-cracker/disk.secret.new");
        rc = (has_secret && new_secret[0])
                 ? do_dmpass(device, mapper, new_secret)
                 : (say("DESK-DISK changing a passphrase needs both the current and the new one"),
                    1);
        memset(new_secret, 0, sizeof(new_secret));
    }
    else if (strcmp(job, "resize") == 0)
        rc = do_dmresize(device, kind[0] ? mapper : "", fstype);
    else
        say("DESK-DISK unknown job %s", job);

    forget_keyfile();
    say("DESK-DISK exit=%d", rc);
    sync();
    reboot(RB_POWER_OFF);
    _exit(rc);
}

static int do_boot(void)
{
    char buf[512];
    long total = meminfo_field("MemTotal");


    int rc = mount_tag(CONTROL_TAG, CONTROL_DIR);
    if (rc != 0) {
        say("GUEST control share not mounted (%s): the host will not see the guest status",
            strerror(-rc));
    }

    /* A run with no plan is a **debug** guest: the host's own tooling started it
     * (a smoke test, an experiment) with no shares and no root disk.  It still
     * does everything else an ordinary guest does — it reports its own status,
     * which is what a host waits for — and it also gives a shell on the console,
     * so it can be looked at and asked questions (`keydump`, `xprobe`). */
    char plan[16] = "";
    if (cmdline_value("desktop-cracker.mountplan", plan, sizeof(plan)) <= 0 &&
        cmdline_value("desk.rootboot", plan, sizeof(plan)) <= 0) {
        say("GUEST debug guest: no mount plan and no root disk, so a shell is on the console");
        pid_t shell = fork();
        if (shell == 0) {
            setsid();
            int tty = open("/dev/console", O_RDWR);
            if (tty >= 0) {
                dup2(tty, 0);
                dup2(tty, 1);
                dup2(tty, 2);
                if (tty > 2)
                    close(tty);
            }
            const char *argv[] = {"/bin/sh", NULL};
            execv("/bin/sh", (char *const *)argv);
            _exit(127);
        }
    }

    /* The guest is **up** now: its init ran, its control share is mounted and it
     * has looked at the machine it is on.  This is what the host waits for, and
     * it is reported *before* a system on the disk is entered — after the switch
     * the process's own filesystem is the disk's, and the probes here would be
     * describing another machine. */
    snprintf(buf, sizeof(buf), "DESK-READY initramfs MemTotal=%ldkB control=%s\n", total,
             rc == 0 ? "mounted" : "missing");
    if (rc == 0)
        write_file(READY_FILE, buf);
    say("%s", buf);

    /* The microvm's **network**, leased here and handed to the system on the disk
     * (`rootboot` writes it into the new root).  It is done before the guest is declared
     * up, because in a run with a root disk this process stops existing the moment the
     * disk's system is entered — and a lease taken after that never happens.
     *
     * It is also the **last thing this init prints**: the console belongs to the user (the
     * window shows it), and a guest that announces every device it found floods what a
     * person is trying to read. */
    dhcp_if_possible();

    /* Is this guest meant to start a system from its root disk?  The host says so
     * on the kernel command line, and the password is the only thing missing —
     * the user types it on the console (the window shows this console). */
    char boot_plan[16] = "";
    if (cmdline_value("desk.rootboot", boot_plan, sizeof(boot_plan)) > 0 &&
        strcmp(boot_plan, "1") == 0) {
        /* `rw` is the one mode, and the default: a host that says nothing (an older
         * caller, an `--append` by hand) still gets a usable system. */
        char device[128] = "/dev/vda", mapper[128] = MAPPER, mode[8] = "rw";
        cmdline_value("desktop-cracker.root", device, sizeof(device));
        cmdline_value("desk.mapper", mapper, sizeof(mapper));
        cmdline_value("desktop-cracker.rootmode", mode, sizeof(mode));
        /* The password comes from the control share, and it is **moved, not kept**: read
         * into memory, written to a file in RAM that only `rootboot` reads, and the file in
         * the share is removed — so there is one copy in the guest for as long as it is
         * needed and none afterwards.  It is never put in the environment (any process can
         * read another's, and it outlives the use) and never printed. */
        if (access(CONTROL_DIR "/root.pass", R_OK) == 0) {
            char pass[128] = "";
            if (read_first_line(CONTROL_DIR "/root.pass", pass, sizeof(pass)) > 0) {
                /* The password is read into a file of its own, and `rootboot` reads **that**
                 * file: the same rule the disk manager's jobs follow (the secret is copied to
                 * RAM and the share's copy is removed), and it is what makes this path the one
                 * that was already measured.  It used to be written to `/run/root.pass` and
                 * looked for in the share instead, which is a second guess at the same thing:
                 * one file, one place, and the share's copy goes at once. */
                mkdir_p("/run");
                int f = open(KEYFILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
                if (f >= 0) {
                    if (write(f, pass, strlen(pass)) != (ssize_t)strlen(pass))
                        say("DESK-ROOT the password file could not be written in full");
                    close(f);
                    say("DESK-ROOT a password was provided for this start "
                        "(the share's copy is removed now)");
                } else {
                    say("DESK-ROOT the password file could not be created");
                }
                memset(pass, 0, sizeof(pass));
            }
            unlink(CONTROL_DIR "/root.pass");
        }
        /* The host's environment (its X server, for instance) belongs to the
         * system that is about to start, so it is written where systemd picks
         * environment files up before the system on the disk is entered. */
        if (access(CONTROL_DIR "/x-display.env", R_OK) == 0) {
            mkdir_p(ROOTFS_DIR);
            char target[256];
            snprintf(target, sizeof(target), ROOTFS_DIR "/etc/desktop-cracker.env");
            FILE *in = fopen(CONTROL_DIR "/x-display.env", "r");
            FILE *out = fopen(target, "w");
            if (in && out) {
                char line[256];
                while (fgets(line, sizeof(line), in))
                    if (line[0] != '#')
                        fputs(line, out);
                say("DESK-ROOT the host's environment was written to %s", target);
            }
            if (in)
                fclose(in);
            if (out)
                fclose(out);
        }
        /* The password was moved into KEYFILE above (the share's copy removed): tell
         * `rootboot` where it is, exactly as the `desk-try` job does, so the two paths
         * read the one key file rather than a second guess. */
        setenv("DESK_ROOT_PASSWORD_FILE", KEYFILE, 1);
        rootboot(device, mapper, mode);
        /* rootboot does not return on success; if it did, the system is not
         * reachable and the user is told so on the same console. */
        say("DESK-ROOT the system on the disk did not start; staying in the initramfs");
    }

/* The host's mount plan is authoritative: it names every share, where it
     * goes and whether the guest may write there.  Applying it is also the
     * guest's own read-only assertion (each line reports `writable=`). */
    apply_mount_plan();
    dhcp_if_possible();
    /* Remote X: the host's environment file, if the host wrote one, and the
     * handshake that proves the guest can actually reach the host's X server
     * with the cookie it was given. */
    if (access(CONTROL_DIR "/x-display.env", R_OK) == 0) {
        char display[64] = "", authority[128] = "";
        FILE *f = fopen(CONTROL_DIR "/x-display.env", "r");
        if (f) {
            char line[256];
            while (fgets(line, sizeof(line), f)) {
                char *t = line;
                while (*t == ' ' || *t == '\t')
                    t++;
                sscanf(t, "export DISPLAY=%63s", display);
                sscanf(t, "export XAUTHORITY=%127s", authority);
            }
            fclose(f);
        }
        char vsock_env[64] = "";
        FILE *g = fopen(CONTROL_DIR "/x-display.env", "r");
        if (g) {
            char line[256];
            while (fgets(line, sizeof(line), g)) {
                char *t = line;
                while (*t == ' ' || *t == '\t')
                    t++;
                sscanf(t, "export DESK_X_VSOCK_PORT=%63s", vsock_env);
            }
            fclose(g);
        }
        say("DESK-XREMOTE environment display=%s authority=%s vsock_port=%s", display,
            authority, vsock_env[0] ? vsock_env : "-");
        if (vsock_env[0]) {
            /* The host is forwarding over vsock: start the guest's own forwarder
             * and let it run, so any X client inside sees the host's server at
             * this display number. */
            unsigned port = (unsigned)strtoul(vsock_env, NULL, 10);
            const char *number = strchr(display, ':');
            number = number ? number + 1 : "9";
            char num[16];
            snprintf(num, sizeof(num), "%.15s", number);
            char *dot = strchr(num, '.');
            if (dot)
                *dot = 0;
            pid_t pid = fork();
            if (pid == 0)
                _exit(x_forward_listen(port, num));
            say("DESK-XREMOTE guest forwarder started (pid %d) on display :%s", (int)pid, num);
            /* The forwarder runs in its own child.  Now prove the whole chain:
             * connect to the guest's own socket for that display — which is the
             * forwarder — and complete the X11 setup with the host's cookie.  If
             * this succeeds, an application inside the guest can open a window on
             * the host's desktop. */
            sleep(1);
            if (pid > 0) {
                say("DESK-XREMOTE probing the chain (display :%s)", num);
                xprobe(num, authority[0] ? authority : CONTROL_DIR "/Xauthority");
                say("DESK-XREMOTE probe finished");
            }
        }
        /* Every application the guest starts must find it: export here, and the
         * host's init writes the same file into the session's environment. */
        if (display[0]) {
            setenv("DISPLAY", display, 1);
            const char *number = strchr(display, ':');
            number = number ? number + 1 : "1";
            char probe_n[16];
            snprintf(probe_n, sizeof(probe_n), "%.15s", number);
            char *dot = strchr(probe_n, '.');
            if (dot)
                *dot = 0;
            if (authority[0])
                setenv("XAUTHORITY", authority, 1);
            xprobe(probe_n, authority[0] ? authority : CONTROL_DIR "/Xauthority");
        }
    } else {
        say("DESK-XREMOTE no environment file from the host");
    }


    /* The page cache of everything just read is not worth holding: the guest's
     * RAM is the microVM's, and the balloon can only take back what the guest is
     * not using. */
    {
        int fd = open("/proc/sys/vm/drop_caches", O_WRONLY);
        if (fd >= 0) {
            if (write(fd, "1\n", 2) < 0)
                say("guest-tools: the console's own hand-over did not write (%s)", strerror(errno));
            close(fd);
        }
    }

    /* If the user's passphrase is present in the control share, unlock the
     * encrypted disk with it — the guest does the crypto, never the host. */
    if (access(CONTROL_DIR "/disk.pass", R_OK) == 0) {
        char dev[128];
        if (block_device(dev, sizeof(dev)) == 0)
            do_unlock(dev, "desk-crypt", CONTROL_DIR "/disk.pass", "/mnt/crypt");
        else
            say("DESK-UNLOCK no block device to unlock");
    }

    sample_loop();
    return 0;
}

static int do_ro_check(const char *dir)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/.desktop-cracker-probe", dir);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        close(fd);
        unlink(path);
        say("DESK-CHECK %s WRITABLE", dir);
        return 1; /* writable */
    }
    say("DESK-CHECK %s read-only (%s)", dir, strerror(errno));
    return 0;
}

static int do_probe(void)
{
    char line[256];
    say("GUEST probe ready, waiting for a line");
    if (read_first_line("/dev/ttyS0", line, sizeof(line)) < 0 &&
        read_first_line("/dev/console", line, sizeof(line)) < 0)
        return 2;
    return 0;
}

int main(int argc, char **argv)
{
    const char *mode = argc > 1 ? argv[1] : "boot";
    if (strcmp(mode, "boot") == 0)
        return do_boot();
    if (strcmp(mode, "probe") == 0)
        return do_probe();
    if (strcmp(mode, "ro-check") == 0)
        return do_ro_check(argc > 2 ? argv[2] : "/mnt/root");
    if (strcmp(mode, "rw-check") == 0)
        return do_ro_check(argc > 2 ? argv[2] : "/mnt/root");
    if (strcmp(mode, "dmprobe") == 0)
        return do_dmprobe();
    if (strcmp(mode, "diskmgr") == 0)
        return do_diskmgr();
    if (strcmp(mode, "rootboot") == 0) {
        return rootboot(argc > 2 ? argv[2] : "/dev/vda",
                        argc > 3 ? argv[3] : MAPPER,
                        argc > 4 ? argv[4] : "rw");
    }
    /* `desk-try`: open the container with one password and report the outcome (`DESK-ROOT
     * password ok` / `DESK-ROOT wrong-password …`).  It is the disk manager's tool
     * (`desk-disk`), not the application's: the application's own root disk is opened
     * by the host's own disk tooling, so a run has no dialog to try a password with. The password file is
     * unlinked by `rootboot` before anything else happens.
     */
    if (strcmp(mode, "desk-try") == 0) {
        const char *device = argc > 2 ? argv[2] : "/dev/vda";
        const char *mapper = argc > 3 ? argv[3] : "/dev/mapper/desk-root";
        int rc = rootboot(device, mapper, "ro-try");
        say("DESK-ROOT try exit=%d", rc);
        return 0;
    }
    if (strcmp(mode, "xprobe") == 0) {
        return xprobe(argc > 2 ? argv[2] : "1",
                      argc > 3 ? argv[3] : CONTROL_DIR "/Xauthority");
    }
    if (strcmp(mode, "xforward-listen") == 0) {
        return x_forward_listen(
            argc > 2 ? (unsigned)strtoul(argv[2], NULL, 10) : 0,
            argc > 3 ? argv[3] : "9");
    }
    if (strcmp(mode, "xforward") == 0) {
        return x_forward(0, argc > 2 ? (unsigned)strtoul(argv[2], NULL, 10) : 0);
    }
    if (strcmp(mode, "sound") == 0) {
        return do_sound(argc > 2 ? argv[2] : "2");
    }
    if (strcmp(mode, "unlock") == 0) {
        if (argc < 5) {
            fprintf(stderr, "guest-tools: unlock <device> <mapname> <passfile> [mountpoint]\n");
            return 2;
        }
        return do_unlock(argv[2], argv[3], argv[4], argc > 5 ? argv[5] : NULL);
    }
    if (strcmp(mode, "poweroff") == 0) {
        sync();
        reboot(RB_POWER_OFF);
        return 0;
    }
    fprintf(stderr, "guest-tools: unknown mode %s\n", mode);
    return 2;
}
