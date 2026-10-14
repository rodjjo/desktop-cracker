/* What the library answers, in the two places it can run.
 *
 *   tools/libdesk/tests/test_display_status.c
 *
 * Inside the microvm the answer comes from the file the host publishes; outside it
 * is the desktop's own window, which is always visible. This program is
 * deliberately dependency-free (no framework): it is compiled by the system test
 * that runs it in the guest, and by the host check.
 */
#include "desk_display.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void expect(int got, int want, const char *what)
{
    if (got != want) {
        printf("FAIL %s: got %d, want %d\n", what, got, want);
        failures++;
    } else {
        printf("ok   %s (%d)\n", what, got);
    }
}

int main(int argc, char **argv)
{
    /* `--inside` asserts the microvm branch, `--outside` the other one. */
    const char *mode = argc > 1 ? argv[1] : "";
    bool inside = is_inside_desktop_cracker_microvm();
    printf("is_inside_desktop_cracker_microvm=%d\n", (int)inside);

    if (strcmp(mode, "--inside") == 0) {
        expect((int)inside, 1, "inside the microvm");
        const char *path = desk_display_state_path();
        expect(path != NULL, 1, "the state file has a path");
        int status = desk_display_status();
        expect(status == DISPLAY_HIDDEN || status == DISPLAY_NORMAL, 1,
               "the status is one of the two");
        bool vis = false, num = false;
        unsigned long long rev = 0, changed = 0;
        int again = desk_display_status_ex(&inside, &vis, &num, &rev, &changed);
        expect(again, status, "the two calls agree");
        printf("inside=%d visible=%d numlock=%d revision=%llu changed_ms=%llu\n",
               (int)inside, (int)vis, (int)num, rev, changed);
        /* The rule, as the states are defined: hidden while the window is not on
         * screen, normal when it is. The numlock key does not change the window. */
        if (!vis)
            expect(status, DISPLAY_HIDDEN, "a window that is not visible is hidden");
        else
            expect(status, DISPLAY_NORMAL, "a visible window is normal");
    } else if (strcmp(mode, "--outside") == 0) {
        expect((int)inside, 0, "outside the microvm");
        expect(desk_display_state_path() == NULL, 1, "no state file outside");
        int status = desk_display_status();
        expect(status, DISPLAY_NORMAL,
               "outside, the desktop's window is its own and always visible");
    }

    printf("%s: %d failure(s)\n", argv[0], failures);
    return failures == 0 ? 0 : 1;
}
