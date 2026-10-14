//! **The keyboard, while the guest has it.**
//!
//! The design ("Display — The window's keys"): the display window pays attention to **three keys
//! and nothing else** — numlock, `numlock + F9`, `numlock + F10` — and those three are read from
//! the host's own keyboard (`dc-display`'s `xinput::KeyReader`, a `QueryKeymap` on every tick of
//! the display loop), never from the window.  Everything else the keyboard produces belongs to the
//! guest: `Alt+F4` closes an application **inside** the microVM, `Super` is the guest's,
//! `Ctrl+Escape` is the guest's.
//!
//! A window that merely *has the focus* does not get that.  A window manager keeps a combination it
//! likes by putting a **passive grab** on its key on the root window — `Alt+F4` is one on GNOME —
//! and a passive grab is answered *before* the focused window is asked, so the combination never
//! reaches us and the session closes our window instead of the guest's application.  Measured on
//! this host (a private X server, a synthesized `Alt+F4`, one client playing the window manager's
//! role and one playing the display window's):
//!
//! * with no grab of ours: the combination is reported to the grabber, and the window is told
//!   **nothing at all**;
//! * with an **active** keyboard grab held (`grab_keyboard`, which is what `gdk_seat_grab` is): the
//!   combination arrives at the window and the grabber is told nothing;
//! * and `QueryKeymap` — the reader the numlock key and the two chords use — answers exactly the
//!   same while the grab is held: the physical state of numlock (77), F9 (75) and F10 (76).
//!
//! **The grab follows the focus, not the screen.**  A grab is the X server giving *this client* the
//! keyboard, and it does not expire when the window manager moves the focus elsewhere: measured on
//! this host (`Xephyr` + `mutter --x11 -d :9`, mutter 42.9, a scratch probe that went with the fix),
//! a click in another window's client area **while our grab is held** moves `XGetInputFocus` to that
//! window — and GTK is told nothing about it: no `focus-out`, no `is-active` notify, and
//! `gtk_window_is_active()` stays `true`.  So a grab held over a window the session has left takes
//! the keyboard from the person's own application and gives the guest nothing, which is the operator's
//! report of 2026-10-12: *"when I minimize it and go using other application of the system, I'm not
//! able of using keyboard at the host anymore."*  The rule's `window_focused` is therefore the focus
//! **read from the server** (`dc-display`'s `xinput::KeyReader::focus_is`), not the window's own
//! focus flag.
//!
//! The same grab is what stops the window from being dragged by its title bar: a title-bar drag is
//! the window manager's own grab op, and it grabs the pointer *and* the keyboard — measured, a second
//! `grab_keyboard` while ours is held is answered `ALREADY_GRABBED` (`temp/xgrab-probe`'s `grabtry`),
//! and the drag moves nothing until our grab is released.  So the rule also lets go of the keyboard
//! while the pointer is dragging **this window's own chrome** (`dragging_our_chrome`): the bar is the
//! window's, not the guest's screen.
//!
//! This module is that grab and the rule for when it is held: one owner (the thread that owns GTK),
//! one grab.  A dialog is the one moment the keyboard is *ours* to type into, so the grab is let go
//! while a question is up and taken back when the question is gone.

use gtk::gdk::{self, prelude::*};
use gtk::prelude::*;

/// **Whose keyboard is it?**  The rule, with nothing GTK in it, so it is a rule a test can pin.
///
/// The window holds the keyboard for the guest while it is **on screen and the focused window**, and
/// while no question of ours is on screen.  Each half is the guest's for a different reason:
///
/// * a **hidden** window is not a window anyone is typing into — the guest keeps running, but the
///   keyboard is the person's own again, and `numlock + F9` (read from the host's keyboard, not from
///   the window) is what brings the window, the focus and the grab back;
/// * an **unfocused** window is the one the operator minimized or alt-tabbed away from.  The X
///   server sends its keys to the focused window whatever our grab says (measured, above), so
///   holding it there is a keyboard the host has lost and the guest has not gained;
/// * **`dragging_our_chrome`** is the pointer dragging this window's own title bar or border.  A
///   drag is the window manager's grab op and it wants the keyboard too, which our grab refuses
///   (`ALREADY_GRABBED`): measured, a title-bar drag moves the window 120 px with no grab of ours
///   held and moves it **nothing** while the grab is held.  The bar is the window's, not the guest's
///   screen, so the keyboard is the window manager's for as long as that drag lasts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyboardRule {
    /// The display window is on screen.
    pub window_visible: bool,
    /// The display window is the window the session is typing into.
    pub window_focused: bool,
    /// A question of ours (a dialog, the settings window) is on screen.
    pub asking: bool,
    /// The pointer is dragging this window's own title bar or border.
    pub dragging_our_chrome: bool,
}

impl KeyboardRule {
    /// Should the display window hold the keyboard for the guest?
    pub fn holds_for_guest(&self) -> bool {
        self.window_visible && self.window_focused && !self.asking && !self.dragging_our_chrome
    }
}

thread_local! {
    /// **The grab this thread's display window holds**, when it holds one.
    ///
    /// It is a thread-local handle rather than a field of some shared state because a `GdkSeat`
    /// belongs to the thread that owns GTK, and because the code that needs to *let go of it* —
    /// every dialog, the settings window — is in crates that sit **below** the display and cannot
    /// reach the display loop's own state.  The display loop publishes it once, on the thread that
    /// made the window; a question borrows the keyboard from it and gives it back.
    static GRAB: std::cell::RefCell<Option<KeyboardGrab>> = const { std::cell::RefCell::new(None) };
    /// **How many of our questions are on screen right now.**  A dialog runs a GTK main loop of its
    /// own (`gtk::Dialog::run`), which runs the display loop's own tick while the question is up;
    /// without this the tick would take the keyboard back from the dialog that is using it.
    static QUESTIONS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
    /// **What the session says about the display window's focus**, as the display loop measured it
    /// on its own tick (`XGetInputFocus` through `dc_display::xinput::KeyReader`).  `None` means
    /// "there was no display to ask", and then the window's own `is_active` is used.
    ///
    /// It is a published *answer* rather than a question because a grab held over a window the
    /// session has left is invisible to GTK (see this module's header): only the server knows, and
    /// the display loop is the place with the connection open.  A dialog that ends reads the last
    /// answer, which is at most one tick old.
    static SESSION_FOCUSED: std::cell::Cell<Option<bool>> = const { std::cell::Cell::new(None) };
}

/// Publish what the **session** says about the display window's focus (the display loop does it on
/// every tick).  `None` when there is no display to ask.
pub fn publish_session_focus(focused: Option<bool>) {
    SESSION_FOCUSED.with(|answer| answer.set(focused));
}

/// What the session says about `is_active`: the published answer when there is one, the window's own
/// flag when the display loop has never had a server to ask.
fn session_focus(is_active: bool) -> bool {
    SESSION_FOCUSED
        .with(|answer| answer.get())
        .unwrap_or(is_active)
}

/// Publish this thread's keyboard grab, so a question can let go of it (`hold_keyboard_for_guest`)
/// and so the loop's own tick knows a question is up (`question_is_up`).
pub fn publish_keyboard_grab(grab: KeyboardGrab) {
    GRAB.with(|slot| *slot.borrow_mut() = Some(grab));
}

/// The grab this thread holds, if any.
pub fn keyboard_grab() -> Option<KeyboardGrab> {
    GRAB.with(|slot| slot.borrow().clone())
}

/// Is one of our questions (a dialog, the settings window) on screen on this thread?
pub fn question_is_up() -> bool {
    QUESTIONS.with(|count| count.get() > 0)
}

/// **Put a question of ours on screen**: let go of the guest's keyboard, run `ask`, take it back.
///
/// A dialog is the one window of ours the person has to type into, and a grab still held over it is
/// a keyboard the dialog cannot use.  The grab comes back whatever the answer was, because the
/// guest's window is still there behind the question — and it comes back **through the rule**, so a
/// window that lost the focus while the question was up does not get one.  With no grab published
/// it is the plain question.
pub fn hold_keyboard_for_guest<T>(ask: impl FnOnce() -> T) -> T {
    QUESTIONS.with(|count| count.set(count.get() + 1));
    let grab = keyboard_grab();
    if let Some(grab) = grab.as_ref() {
        grab.release();
    }
    let answer = ask();
    if let Some(grab) = grab.as_ref() {
        grab.acquire_for_parent();
    }
    QUESTIONS.with(|count| count.set(count.get().saturating_sub(1)));
    answer
}

/// **The keyboard grab**, held by the thread that owns GTK.
///
/// A `Cell` rather than a field of some shared struct, because a `GdkSeat` belongs to one thread
/// and is not `Send`: the display loop decides from the window's state, and the dialog code asks a
/// question that needs the keyboard.  Both are that thread's own.
///
/// It is `Clone` in the shallow sense — the handle is a shared `Cell`, so a copy of it is the *same*
/// grab, which is what the thread-local handle and a dialog's borrow both need.
#[derive(Clone, Default)]
pub struct KeyboardGrab {
    held: std::rc::Rc<std::cell::Cell<bool>>,
}

impl KeyboardGrab {
    /// Ask the seat for the **keyboard** for `window`.
    ///
    /// * `owner_events = true` — events keep going to the window they are over, which is what lets
    ///   the display window's own key signals keep firing while the grab is held;
    /// * `KEYBOARD`, **not** `ALL`: a passive grab is a keyboard thing (it is a key combination the
    ///   window manager keeps for itself), and the pointer needs none — the pointer's events already
    ///   arrive at whatever window they fall on.  Grabbing the pointer too would take it from the
    ///   rest of the session: with `owner_events = true` an event that falls *outside* our windows is
    ///   reported **to us**, so a click on the operator's own terminal would be a click on the
    ///   display window.  That is a worse bug than the one being fixed.
    /// * `ASYNC` — a `SYNC` grab freezes the session until this client answers the grab protocol, and
    ///   a loop that draws thirty frames a second is not a client that answers one.
    ///
    /// It says whether the seat agreed.  A session that refuses (another client holds the keyboard;
    /// a server that will not) keeps the focus-only behaviour this window had before the grab
    /// existed: the guest still gets whatever a focused window is given, and nothing here is worse
    /// for it.
    pub fn acquire(&self, window: &gtk::Window) -> bool {
        if self.held.get() {
            return true;
        }
        let Some(gdk_window) = window.window() else {
            return false;
        };
        let Some(seat) = gdk_window.display().default_seat() else {
            return false;
        };
        let status = seat.grab(
            &gdk_window,
            gdk::SeatCapabilities::KEYBOARD,
            true,
            None,
            None,
            None::<&mut dyn FnMut(&gdk::Seat, &gdk::Window)>,
        );
        let got = status == gdk::GrabStatus::Success;
        self.held.set(got);
        got
    }

    /// Give the keyboard back to the session.
    pub fn release(&self) {
        if !self.held.get() {
            return;
        }
        self.held.set(false);
        let Some(display) = gdk::Display::default() else {
            return;
        };
        if let Some(seat) = display.default_seat() {
            seat.ungrab();
        }
    }

    /// Is it held right now?
    pub fn held(&self) -> bool {
        self.held.get()
    }

    /// Take the keyboard back **for the display window this thread published** (`parent_window`).
    ///
    /// This is what a question does when it is finished: it does not know the window, the thread
    /// does.  With no window published nothing is grabbed, which is a run with no display window.
    ///
    /// The rule is **asked, not assumed**: a question that ends over a window the session is not
    /// typing into leaves the keyboard with the session, because a grab over an unfocused window is
    /// the operator's bug (see this module's header).
    pub fn acquire_for_parent(&self) -> bool {
        match crate::parent_window() {
            // The window, when the rule still holds for it; no window, or one the session has left,
            // is nothing to grab on.
            Some(window) if holds_for(&window) => self.acquire(&window),
            _ => false,
        }
    }

    /// **Carry the rule out**: hold the grab when the rule says so, let it go when it does not.
    ///
    /// The display loop calls it on its own tick.  It costs nothing when nothing changed: the state
    /// lives here, so only a *change* asks the seat for anything (a second grab of a seat we already
    /// grabbed is answered `AlreadyGrabbed`, and an ungrab of a seat we do not hold is a no-op GDK
    /// still charges us a round trip for).
    pub fn apply(&self, rule: KeyboardRule, window: Option<&gtk::Window>) {
        if rule.holds_for_guest() {
            if !self.held.get() {
                if let Some(window) = window {
                    self.acquire(window);
                }
            }
        } else if self.held.get() {
            self.release();
        }
    }
}

/// Is `window` the window the session is typing into, with none of our questions up?
///
/// The focus is the **session's** answer (`session_focus`, the probe the display loop published), and
/// `is_visible` is whether the window is on the screen.  A window that was never shown answers
/// `false` to both, which is the right answer for a hidden window.
fn holds_for(window: &gtk::Window) -> bool {
    !question_is_up() && session_focus(window.is_active()) && window.is_visible()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rule's states, pinned: the keyboard is the guest's **while the window is on screen and
    /// focused**, and it is the person's while the window is hidden, unfocused, a question is up, or
    /// the pointer is dragging the window's own title bar.
    #[test]
    fn the_keyboard_is_the_guests_while_the_window_is_on_screen_and_focused() {
        assert!(
            rule(true, true, false, false).holds_for_guest(),
            "the window is the guest's screen and the session's focus: every key goes in"
        );
        assert!(
            !rule(false, true, false, false).holds_for_guest(),
            "a hidden window takes nothing: the keyboard is the person's own again"
        );
        assert!(
            !rule(true, false, false, false).holds_for_guest(),
            "the operator's report: a minimized window must not keep the host's keyboard"
        );
        assert!(
            !rule(true, true, true, false).holds_for_guest(),
            "a question of ours is a window the person types into"
        );
        assert!(
            !rule(false, false, true, false).holds_for_guest(),
            "a question over a hidden unfocused window is the same answer"
        );
        assert!(
            !rule(true, true, false, true).holds_for_guest(),
            "a drag of the window's own title bar is the window manager's, and it needs the keyboard too"
        );
    }

    /// **A grab is not a rule**: the rule says what should be true, `apply` is what makes it true.
    /// With no display server here there is no seat to ask, and the honest answer is that nothing
    /// is held and nothing panics — a run with no X server keeps the behaviour it had.
    #[test]
    fn a_grab_with_no_seat_to_ask_holds_nothing_and_panics_nothing() {
        let grab = KeyboardGrab::default();
        assert!(!grab.held());
        grab.apply(rule(true, true, false, false), None);
        assert!(!grab.held(), "no window to grab for, nothing held");
        grab.apply(rule(true, false, false, false), None);
        grab.release();
        assert!(
            !grab.held(),
            "releasing what was never held is not an error"
        );
    }

    /// A question asked with no grab published is the plain question: the answer is the answer, and
    /// no grab appears because of it.
    #[test]
    fn a_question_asked_without_a_grab_published_leaves_no_grab_held() {
        let grab = KeyboardGrab::default();
        assert!(!grab.held());
        assert!(
            !grab.acquire_for_parent(),
            "no window published, nothing grabbed"
        );
        assert!(!grab.held());
    }

    fn rule(
        window_visible: bool,
        window_focused: bool,
        asking: bool,
        dragging_our_chrome: bool,
    ) -> KeyboardRule {
        KeyboardRule {
            window_visible,
            window_focused,
            asking,
            dragging_our_chrome,
        }
    }
}
