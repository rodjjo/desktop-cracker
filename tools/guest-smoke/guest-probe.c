/* guest-probe: read one line from this tty, print a marker, exit (so tests can
 * assert a *result*, not just that the VM is up).
 *
 * Static, no libc surprises: this runs inside the microVM from the initramfs,
 * where there is nothing but the busybox the tools script installs.
 */
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>

static int write_all(const char *s)
{
    size_t n = strlen(s), off = 0;
    while (off < n) {
        ssize_t w = write(1, s + off, n - off);
        if (w <= 0)
            return -1;
        off += (size_t)w;
    }
    return 0;
}

static int read_line(char *buf, size_t cap)
{
    int fd = open("/dev/ttyS0", O_RDONLY);
    if (fd < 0)
        fd = 0;
    size_t n = 0;
    while (n + 1 < cap) {
        char c;
        ssize_t r = read(fd, &c, 1);
        if (r <= 0)
            break;
        if (c == '\n')
            break;
        buf[n++] = c;
    }
    buf[n] = 0;
    if (fd > 2)
        close(fd);
    return (int)n;
}

int main(int argc, char **argv)
{
    const char *tag = argc > 1 ? argv[1] : "probe";
    char line[256];

    char hello[256];
    snprintf(hello, sizeof(hello), "GUEST %s ready, waiting for a line\n", tag);
    if (write_all(hello) != 0)
        return 1;

    if (read_line(line, sizeof(line)) < 0)
        return 2;

    char out[512];
    snprintf(out, sizeof(out), "GUEST %s got: %s\n", tag, line);
    write_all(out);
    return 0;
}
