//! The one UI thread's own vocabulary: **what a window or dialog belongs to, where it goes, and
//! whose keyboard it is**.
//!
//! The application puts up three kinds of things — the display window, the settings window and
//! the dialogs — and there are three rules every one of them follows:
//!
//! 1. **they belong to one thread** (GTK is single-threaded: a widget belongs to the thread that
//!    ran `gtk::init()`, and a dialog destroyed from anywhere else leaves its window on the screen
//!    — measured, the disk's password dialog stayed visible and unresponsive while the guest
//!    booted behind it);
//! 2. **they are centered on the screen before they are shown** (the operator, 2026-10-09: "we
//!    need to center all dialogs and windows on the screen before showing them to the user");
//! 3. **the guest's window holds the keyboard while it is on screen** (`grab`): the window's own
//!    keys are numlock, `numlock + F9` and `numlock + F10`, and those are read from the host's
//!    keyboard rather than from the window, so every other key — `Alt+F4`, `Super`,
//!    `Ctrl+Escape` — is the guest's.
//!
//! This crate is those rules: the **parent** the display loop publishes (the guest's own window,
//! which is what makes a question appear over it), the **placing** every caller asks before it
//! shows anything, and the **keyboard grab** the display window holds for the guest and lets go
//! for a question.  It is a crate of its own rather than a corner of `dc-display` so that every
//! crate that puts a window up depends on the rule instead of each inventing it.

pub mod grab;

pub use grab::{
    hold_keyboard_for_guest, keyboard_grab, publish_keyboard_grab, publish_session_focus,
    question_is_up, KeyboardGrab, KeyboardRule,
};

use gtk::gdk;
use gtk::gdk::prelude::*;
use gtk::prelude::*;

/// The window a dialog belongs to, when the caller knows one.
///
/// It is the display window itself, so a question appears **over the guest's screen** instead of
/// behind it.
pub type Parent = gtk::Window;

thread_local! {
    /// **The display window, on the UI thread.**  A GTK object cannot be sent anywhere (it holds
    /// the X connection's state), so it is not carried in the application's shared state at all:
    /// it lives here, where GTK lives, and the application asks for it *on this thread* — which is
    /// the only thread that may ask GTK anything.
    static PARENT: std::cell::RefCell<Option<gtk::Window>> =
        const { std::cell::RefCell::new(None) };
}

/// The display window, when this thread has one: what a dialog is transient for, so a question
/// lands over the guest's screen instead of behind it.  `None` on any other thread (and before
/// the window exists).
pub fn parent_window() -> Option<gtk::Window> {
    PARENT.with(|slot| slot.borrow().clone())
}

/// Publish the display window for this thread (the display loop does it, once the window exists).
pub fn set_parent_window(window: gtk::Window) {
    PARENT.with(|slot| *slot.borrow_mut() = Some(window));
}

/// **The whole screen, as the one rule below and the display window both need it.**
///
/// The rectangle is the monitor this thread is working on — the one the pointer is over, then the
/// primary one, then the first — and the screen's own geometry when the session reports no monitor
/// at all (a nested X server, a test's own display).  A `None` means "nothing to measure": the
/// caller then keeps whatever the toolkit chose.
pub fn screen_size() -> Option<(i32, i32)> {
    let display = gdk::Display::default()?;
    let pointer = display
        .default_seat()
        .and_then(|seat| seat.pointer())
        .map(|pointer| {
            let (_screen, x, y) = pointer.position();
            (x, y)
        });
    let monitor = pointer
        .and_then(|(x, y)| display.monitor_at_point(x, y))
        .or_else(|| display.primary_monitor())
        .or_else(|| display.monitor(0));
    if let Some(monitor) = monitor {
        // **The work area**, when the session has one: a dialog centered under a panel is not
        // centered for the person looking at it.
        let work = monitor.workarea();
        let (width, height) = if work.width() > 0 && work.height() > 0 {
            (work.width(), work.height())
        } else {
            let geometry = monitor.geometry();
            (geometry.width(), geometry.height())
        };
        if width > 0 && height > 0 {
            return Some((width, height));
        }
    }
    // The root window: every GDK backend has an answer for it, monitors or not.
    let (_, _, width, height) = display.default_screen().root_window()?.geometry();
    (width > 0 && height > 0).then_some((width, height))
}

/// Where to put a window of this size so that it is **in the middle of the screen**:
/// `None` when there is no screen to measure.
///
/// It is the one placement rule the application has, and it is pure arithmetic on purpose: every
/// caller (the display window, the settings window, the dialogs through `dc-dialog`) asks this and
/// moves its window before showing it, and the arithmetic is what the unit tests pin.
pub fn centered_at(size: (i32, i32), screen: (i32, i32)) -> (i32, i32) {
    (
        ((screen.0 - size.0) / 2).max(0),
        ((screen.1 - size.1) / 2).max(0),
    )
}

/// **Put `window` in the middle of the screen, before it is shown.**
///
/// GTK's own `WindowPosition::Center` is set by every caller as well — a window manager that
/// honours it does the job itself — but a session whose window manager is somewhere else (a
/// nested X server, a tiling window manager, no WM at all: measured) ignores it, and the window
/// then lands wherever the toolkit's default puts it.  So the placement is computed here, from the
/// screen and the size the window is about to have, and applied with `move_` **before** the
/// caller's `show_all` — a window moved after it is mapped is a window the user sees jump.
pub fn center(window: &impl IsA<gtk::Window>) {
    let window = window.clone().upcast::<gtk::Window>();
    let Some((screen_w, screen_h)) = screen_size() else {
        return;
    };
    // The size the window is about to have.  A window GTK has just built reports its current
    // size as 1x1, so its **preferred** size is used in that case — which is what GTK is about
    // to give it.
    let (mut width, mut height) = window.size();
    if width <= 1 || height <= 1 {
        let (preferred, _) = window.preferred_size();
        width = preferred.width;
        height = preferred.height;
    }
    if width <= 0 || height <= 0 {
        return;
    }
    let (x, y) = centered_at((width, height), (screen_w, screen_h));
    window.move_(x, y);
}

/// **Put `window` in the middle of the screen, on top of everything, and give it the keyboard.**
///
/// That is what a question needs, and the three parts are not decoration (the operator,
/// 2026-10-09: "when a dialog is shown to the user it should go to the front of every other window
/// in the desktop and gain focus on the password editor"):
///
/// * `center` — the middle of the screen, and **before** the caller's `show_all`, so the user
///   never sees it jump;
/// * `set_keep_above(true)` — over the guest's window, which is a full-screen window of ours and
///   would otherwise be the one on top: a question that a user cannot see is a question that a
///   user answers by clicking on the wrong thing.  GTK asks the window manager for this
///   (`_NET_WM_STATE_ABOVE`), and a session that ignores it still gets the answer below;
/// * `present()` — mapped, raised and given the keyboard: the *first* of these is what makes the
///   answer land in the dialog rather than in the guest behind it.  `grab_focus` on the entry is
///   the caller's (`dc-dialog` does it for a password, where the user came to type).
pub fn bring_to_front(window: &impl IsA<gtk::Window>) {
    let window = window.clone().upcast::<gtk::Window>();
    center(&window);
    window.set_keep_above(true);
    window.present();
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **A thread that has no window has no parent to give a question**: the answer is `None`
    /// rather than a panic, which is what every caller outside the UI thread gets.  (No GTK
    /// window is created here — the rule is about what a thread has *published*.)
    #[test]
    fn the_parent_of_a_thread_that_has_no_window_is_none() {
        assert!(parent_window().is_none());
    }

    /// The placement rule itself: the middle of the screen, for the shapes this application
    /// actually uses.  These are the numbers the operator's own screen gives (2560x1080).
    #[test]
    fn a_window_is_placed_in_the_middle_of_the_screen() {
        // The guest's window at the operator's own resolution.
        assert_eq!(centered_at((1280, 800), (2560, 1080)), (640, 140));
        // A dialog smaller than the screen and odd-sized: the leftover pixel goes to the right.
        assert_eq!(centered_at((329, 226), (2560, 1080)), (1115, 427));
    }

    /// **What each button of the close question means**, pinned where it is decided: *Close* is the
    /// application ending, ***Keep hidden*** is the window staying away with the guest still
    /// running, and anything else (`Esc`, the dialog's own X, the window's close button) is
    /// *Cancel*, which asks for the window back (past the unlock password).
    ///
    /// The labels are the dialog's own (`Choice::LABELS`) and are read back **by name**, which is
    /// what this pins: the button whose meaning changed on 2026-10-13 was renamed with it (it says
    /// *Keep hidden* now, because the window is hidden before the question is up), and a rename that
    /// did not carry the answer with it would be a button that does not do what it says.
    #[test]
    fn the_close_question_s_three_answers_are_the_three_buttons() {
        use dc_dialog::Choice;
        let (close, hide, cancel) = Choice::LABELS;
        assert_eq!((close, hide, cancel), ("Close", "Keep hidden", "Cancel"));
        assert_eq!(Choice::from_response(close), Choice::Close);
        assert_eq!(Choice::from_response(hide), Choice::Hide);
        assert_eq!(Choice::from_response(cancel), Choice::Cancel);
        // The old label is not a button any more, and an answer nothing named is a dismissal.
        assert_eq!(Choice::from_response("Hide"), Choice::Cancel);
        assert_eq!(Choice::from_response(""), Choice::Cancel);
        assert_eq!(Choice::from_response("something else"), Choice::Cancel);
    }

    /// A window larger than the screen is put at the origin: there is no middle to put it in, and
    /// a negative position would push its title bar off the screen.
    #[test]
    fn a_window_bigger_than_the_screen_starts_at_the_origin() {
        assert_eq!(centered_at((3000, 2000), (2560, 1080)), (0, 0));
        assert_eq!(centered_at((2560, 1080), (2560, 1080)), (0, 0));
    }
}
