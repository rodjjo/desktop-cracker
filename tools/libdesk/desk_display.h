/*
 * desk_display.h — the state of the desktop-cracker window, from inside the
 * microvm.
 *
 * External state: a custom application installed in the guest can read
 * "in real time the current state of the display window":
 *
 * INVISIBLE the window is not visible (it has been hidden with the keys);
 * VISIBLE the window is visible and shown to the user.
 *
 * An application **inside** the microvm asks this library; the same application
 * running on a plain desktop gets the same answer from its own X server: the window
 * is visible there — a desktop hides nothing by itself — so DISPLAY_NORMAL is what
 * it reads. DISPLAY_HIDDEN is never returned outside the microvm.
 *
 * Link with -ldesk_display.
 */
#ifndef DESK_DISPLAY_H
#define DESK_DISPLAY_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/** The window is hidden: the guest keeps running, the window is away. */
#define DISPLAY_HIDDEN -1
/** The window is on screen and showing the guest. */
#define DISPLAY_NORMAL 1

/**
 * Is this process running inside a desktop-cracker microvm?
 *
 * The answer is a fact, not a guess: the guest's own mounting is what says so, and
 * the application that runs the display is the one that writes the state file this
 * library reads. Outside, it is honest and says `false`.
 */
bool is_inside_desktop_cracker_microvm(void);

/**
 * The state of the display window.
 *
 * Returns DISPLAY_HIDDEN or DISPLAY_NORMAL inside the microvm. Outside it, the
 * window is the desktop's own and DISPLAY_NORMAL is the answer.
 */
int desk_display_status(void);

/**
 * The same, with the raw values the answer was decided from (any of them may be
 * NULL). `*inside` says which branch answered, `*visible` is the host's own view
 * (only meaningful inside the microvm), `*numlock` the numlock key as the host reads
 * it, `*revision` the counter the host bumps on every change and `*changed_ms` the
 * wall-clock milliseconds at which it changed — so a caller can tell a fresh value
 * from a stale one without asking twice.
 *
 * Returns desk_display_status's answer.
 */
int desk_display_status_ex(bool *inside, bool *visible, bool *numlock,
                               unsigned long long *revision,
                               unsigned long long *changed_ms);

/**
 * Where the state is read from, for a caller that wants to watch the file itself
 * (inotify, a poll loop of its own):
 *
 *   * inside the microvm, the path of the file the host publishes;
 *   * outside it, NULL — there is nothing to watch.
 */
const char *desk_display_state_path(void);

#ifdef __cplusplus
}
#endif

#endif /* DESK_DISPLAY_H */
