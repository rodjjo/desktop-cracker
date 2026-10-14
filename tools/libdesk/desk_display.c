/*
 * desk_display.c — the state of the desktop-cracker window.
 *
 * See desk_display.h for what the two states mean. This file is small on
 * purpose: the work it does is (a) decide whether this process is inside a
 * desktop-cracker microvm, (b) read the file the host publishes there, and
 * (c) answer for a plain desktop anywhere else.
 *
 * Nothing here blocks: the host writes the file only when the state changes, so a
 * caller can poll as often as it likes (an application that draws at 60 Hz can ask
 * every frame).
 */
#define _GNU_SOURCE
#include "desk_display.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ------------------------------------------------------------------ inside? */

/*
 * The host writes the display's state into the microvm's control share, which the
 * guest's init mounts at /run/desktop-cracker.  That directory existing *and* holding one
 * of the host's files is what makes this microvm a desktop-cracker one: a
 * different microvm image has no such mount, and a plain desktop has nothing at
 * /run/desktop-cracker at all.
 */
#define DESK_CONTROL_DIR "/run/desktop-cracker"
#define DESK_STATE_FILE DESK_CONTROL_DIR "/display-state"

/* The control share carries these, and at least one is written by the host at
 * every start: the mount plan, the ready marker, the memory numbers. */
static bool control_share_is_the_hosts(void)
{
    static const char *const marks[] = {
        DESK_CONTROL_DIR "/mounts",
        DESK_CONTROL_DIR "/guest-ready",
        DESK_CONTROL_DIR "/guest-meminfo",
        DESK_STATE_FILE,
    };
    struct stat st;
    if (stat(DESK_CONTROL_DIR, &st) != 0 || !S_ISDIR(st.st_mode))
        return false;
    for (size_t i = 0; i < sizeof(marks) / sizeof(marks[0]); i++) {
        if (stat(marks[i], &st) == 0)
            return true;
    }
    /* The directory exists but the host has not written anything yet: it is still
     * our control share (the guest cannot make /run/desktop-cracker itself — its init
     * mounts it there). */
    return true;
}

bool is_inside_desktop_cracker_microvm(void)
{
    return control_share_is_the_hosts();
}

const char *desk_display_state_path(void)
{
    return is_inside_desktop_cracker_microvm() ? DESK_STATE_FILE : NULL;
}

/* --------------------------------------------------------------- the file */

struct host_state {
    int status;
    bool visible;
    bool numlock;
    unsigned long long revision;
    unsigned long long changed_ms;
    bool any;
};

/* One `key=value` line. */
static bool value_of(const char *text, const char *key, char *out, size_t cap)
{
    size_t keylen = strlen(key);
    const char *line = text;
    while (line && *line) {
        const char *end = strchr(line, '\n');
        size_t len = end ? (size_t)(end - line) : strlen(line);
        if (len > keylen && strncmp(line, key, keylen) == 0 && line[keylen] == '=') {
            size_t n = len - keylen - 1;
            if (n >= cap)
                n = cap - 1;
            memcpy(out, line + keylen + 1, n);
            out[n] = 0;
            return true;
        }
        line = end ? end + 1 : NULL;
    }
    return false;
}

static bool read_host_state(struct host_state *out)
{
    memset(out, 0, sizeof(*out));
    out->status = DISPLAY_HIDDEN;
    int fd = open(DESK_STATE_FILE, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return false;
    char buf[1024];
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0)
        return false;
    buf[n] = 0;

    char value[64];
    if (value_of(buf, "status", value, sizeof(value)))
        out->status = atoi(value);
    if (value_of(buf, "visible", value, sizeof(value)))
        out->visible = atoi(value) != 0;
    if (value_of(buf, "numlock", value, sizeof(value)))
        out->numlock = atoi(value) != 0;
    if (value_of(buf, "revision", value, sizeof(value)))
        out->revision = strtoull(value, NULL, 10);
    if (value_of(buf, "changed_ms", value, sizeof(value)))
        out->changed_ms = strtoull(value, NULL, 10);
    out->any = true;
    return true;
}

/* ------------------------------------------------------------- the answer */

int desk_display_status_ex(bool *inside, bool *visible, bool *numlock,
                               unsigned long long *revision,
                               unsigned long long *changed_ms)
{
    struct host_state host;
    if (is_inside_desktop_cracker_microvm() && read_host_state(&host) && host.any) {
        if (inside)
            *inside = true;
        if (visible)
            *visible = host.visible;
        if (numlock)
            *numlock = host.numlock;
        if (revision)
            *revision = host.revision;
        if (changed_ms)
            *changed_ms = host.changed_ms;
        switch (host.status) {
        case DISPLAY_HIDDEN:
        case DISPLAY_NORMAL:
            return host.status;
        default:
            return host.visible ? DISPLAY_NORMAL : DISPLAY_HIDDEN;
        }
    }

 /* Outside the microvm the window is the desktop's own: something the user sees,
 * and nothing of ours hides it. The numlock key is not reported here — it is
 * the guest's rule, and a desktop has its own. */
    if (inside)
        *inside = false;
    if (visible)
        *visible = true;
    if (numlock)
        *numlock = false;
    if (revision)
        *revision = 0;
    if (changed_ms)
        *changed_ms = 0;
return DISPLAY_NORMAL;
}

int desk_display_status(void)
{
    return desk_display_status_ex(NULL, NULL, NULL, NULL, NULL);
}
