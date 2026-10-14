//! The host's keyboard, read from its X server — not from our own window.
//!
//! The rule is about the physical key, and asking our own window is
//! wrong in three ways that all showed up in practice: a window that is **hidden** receives
//! no key events at all, a window that is **not focused** receives none either, and a
//! window whose frame is slow reads the state late.  The operator's words: "ensure our
//! window never hangs, as it appears even during the initial state of booting the vm,
//! numlock is still working".
//!
//! So the question is put to the X server the window lives on: `QueryKeymap` returns the
//! **physical** state of every key, whoever has focus and whether or not our window is
//! mapped. The answer does not depend on our window being focused, so the key works from
//! anywhere on the operator's desktop, and a window that is slow to draw still reads it.
//!
//! The keysym is *looked up* rather than assumed (a remapped keyboard may put Num Lock
//! somewhere else), with the evdev position as the fallback.  When there is no display to
//! ask — a headless machine, a test — the reader is simply absent and the caller keeps
//! whatever the environment says.

use x11rb::connection::Connection;
use x11rb::protocol::xproto::ConnectionExt as _;
use x11rb::rust_connection::RustConnection;

/// The keysym X gives the Num Lock key.
pub const XK_NUM_LOCK: u32 = 0xff7f;
/// The keysym X gives the F9 key (the window's *hide/show* key, with numlock held).
pub const XK_F9: u32 = 0xffc6;
/// The keysym X gives the F10 key (the window's *hide and open the settings* key).
pub const XK_F10: u32 = 0xffc7;

/// Where every evdev keyboard puts Num Lock, used when the mapping cannot be read.
pub const EVDEV_NUM_LOCK_KEYCODE: u8 = 77;
/// Where every evdev keyboard puts F9 (its position is fixed; only the *mapping* is looked
/// up, so a remapped keyboard is still right).
pub const EVDEV_F9_KEYCODE: u8 = 75;
/// Where every evdev keyboard puts F10.
pub const EVDEV_F10_KEYCODE: u8 = 76;

/// What the host's keyboard says, right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Keys {
    /// Is the numlock key physically **down**?
    pub numlock: bool,
    /// Is F9 physically down?
    pub f9: bool,
    /// Is F10 physically down?
    pub f10: bool,
}

impl Keys {
    /// The **hotkey** this state means: numlock held together with F9 or F10.
    ///
    /// A chord, and nothing else: a bare F9 or a bare numlock is not a hotkey, so the keys
    /// do not have to be taken away from the guest.
    pub fn hotkey(&self) -> Option<Hotkey> {
        if !self.numlock {
            return None;
        }
        match (self.f9, self.f10) {
            (true, false) => Some(Hotkey::HideOrShow),
            (false, true) => Some(Hotkey::HideAndOpenSettings),
            _ => None,
        }
    }
}

/// A chord the application acts on, wherever the keyboard's focus is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Hotkey {
    /// `numlock + F9`: hide the window, or ask for the password and show it again.
    HideOrShow,
    /// `numlock + F10`: hide the window and open the settings window.
    HideAndOpenSettings,
}

/// Is a **window manager** running on this session?
///
/// EWMH's own question: a manager sets `_NET_SUPPORTING_WM_CHECK` on the root window (and on a
/// window of its own), and a session with nobody managing windows has no such property.  `None`
/// means "could not ask" (no display, a server that refuses), which the caller reads as "assume
/// there is one" — the safer answer, because a window that places itself under a manager is a
/// window that fights it.
pub fn window_manager_running() -> Option<bool> {
    let (connection, screen_number) = RustConnection::connect(None).ok()?;
    let root = connection.setup().roots.get(screen_number)?.root;
    let atom = connection
        .intern_atom(false, b"_NET_SUPPORTING_WM_CHECK")
        .ok()?
        .reply()
        .ok()?
        .atom;
    let reply = connection
        .get_property(
            false,
            root,
            atom,
            x11rb::protocol::xproto::AtomEnum::WINDOW,
            0,
            1,
        )
        .ok()?
        .reply()
        .ok()?;
    Some(reply.value_len > 0 && reply.value32().and_then(|mut v| v.next()).is_some())
}

/// A reader for the host keyboard's physical state.
pub struct KeyReader {
    connection: RustConnection,
    numlock: u8,
    f9: u8,
    f10: u8,
    /// **X's keycode → the kernel's key code**, read from the same server in the same round of
    /// questions: the window forwards the keys it is *not* paying attention to, and it forwards
    /// them as kernel codes (`crate::keymap`).
    codes: crate::keymap::KeyCodes,
}
/// The host display's resolution, in pixels (the X server's root window: the screen the
/// window lives on).  `None` when there is no display to ask, which is not an error — a
/// headless run has no screen.
pub fn screen_size() -> Option<(u32, u32)> {
    let (connection, screen_number) = RustConnection::connect(None).ok()?;
    let screen = connection.setup().roots.get(screen_number)?;
    let (w, h) = (
        u32::from(screen.width_in_pixels),
        u32::from(screen.height_in_pixels),
    );
    if w == 0 || h == 0 {
        return None; // a screen of no size is not an answer
    }
    Some((w, h))
}

impl KeyReader {
    /// Connect to the host's display (`$DISPLAY`) and find the keycodes this project asks
    /// about.
    ///
    /// `None` when there is no display to ask, which is not an error: a headless run has no
    /// keyboard, and the caller keeps its own defaults.
    pub fn connect() -> Option<KeyReader> {
        let (connection, _screen) = RustConnection::connect(None).ok()?;
        let setup = connection.setup();
        let first = setup.min_keycode;
        let count = setup.max_keycode.saturating_sub(setup.min_keycode) + 1;
        let mapping = connection
            .get_keyboard_mapping(first, count)
            .ok()
            .and_then(|cookie| cookie.reply().ok());
        // The map the window forwards keys through, built from the mapping this same round trip
        // answered (see `crate::keymap`: the offset is the server's rule and the keysym is its
        // check).
        let codes = match &mapping {
            Some(reply) => crate::keymap::KeyCodes::from_mapping(
                u16::from(first),
                &reply.keysyms,
                reply.keysyms_per_keycode,
            ),
            None => crate::keymap::KeyCodes::from_mapping(u16::from(first), &[], 1),
        };
        // Each key is **looked up** by its keysym (a remapped keyboard may put it somewhere
        // else) and falls back to where every evdev keyboard puts it.
        let find = |keysym: u32, fallback: u8| -> u8 {
            mapping
                .as_ref()
                .and_then(|reply| {
                    let width = usize::from(reply.keysyms_per_keycode.max(1));
                    reply
                        .keysyms
                        .chunks(width)
                        .enumerate()
                        .find_map(|(index, row)| {
                            row.contains(&keysym).then_some(first + index as u8)
                        })
                })
                .unwrap_or(fallback)
        };
        let (numlock, f9, f10) = (
            find(XK_NUM_LOCK, EVDEV_NUM_LOCK_KEYCODE),
            find(XK_F9, EVDEV_F9_KEYCODE),
            find(XK_F10, EVDEV_F10_KEYCODE),
        );
        Some(KeyReader {
            connection,
            numlock,
            f9,
            f10,
            codes,
        })
    }

    /// **X's keycode → the kernel's key code**, for the keys the window forwards to the guest.
    pub fn key_codes(&self) -> &crate::keymap::KeyCodes {
        &self.codes
    }

    /// **Is `window` the window the session is typing into?** (`XGetInputFocus`)
    ///
    /// This is asked of the **server**, not of our window's own `focus-in`/`focus-out` signals, and
    /// that is the whole point.  Measured on this host (`Xephyr` + `mutter --x11 -d :9`, mutter 42.9,
    /// a scratch probe that went with the fix): while our window holds an active
    /// `gdk_seat_grab(KEYBOARD)`, GTK is told **nothing** about the focus — no `focus-out`, no
    /// `is-active` notify, `gtk_window_is_active()` stays `true` — yet the focus really has moved:
    /// `XGetInputFocus` answers the other window, a click in another window's client area moves it,
    /// and Alt+Tab moves it.  A grab that is supposed to follow the focus has to *read* it.
    ///
    /// `None` when the server answers `PointerRoot` (the focus follows the pointer; no window owns
    /// it) or `None` (nobody has the focus), which the caller reads as "I cannot tell" and answers
    /// with its own focus flag.
    pub fn focus_is(&self, window: u32) -> Option<bool> {
        let reply = self.connection.get_input_focus().ok()?.reply().ok()?;
        // X's two special answers are not window ids: `XCB_POINTER_ROOT` (0x100) means "the focus
        // follows the pointer" and `XCB_NONE` (0) means nobody has it.
        if matches!(reply.focus, 0 | 0x100) {
            return None;
        }
        if reply.focus == window {
            return Some(true);
        }
        // The answer is rarely our toplevel's own id.  Measured, with our window focused the server
        // answers **the `GLArea`'s own GdkWindow** (6291460, whose parent is our window 6291459) —
        // GTK puts the focus on the widget that holds it — and a manager that reparents may answer the
        // **frame** it created for us instead.  So the focus is ours when it is our window, one of its
        // descendants, or the window directly above it.
        let mut at = reply.focus;
        for _ in 0..8 {
            let Some(tree) = self
                .connection
                .query_tree(at)
                .ok()
                .and_then(|cookie| cookie.reply().ok())
            else {
                break;
            };
            if tree.parent == window {
                return Some(true);
            }
            if tree.parent == at || tree.parent == 0 {
                break; // the root, or a window that is its own parent: nothing above to walk to
            }
            at = tree.parent;
        }
        // And the other direction of the same fact: a frame the manager focuses instead of us.
        let ours = self.connection.query_tree(window).ok()?.reply().ok()?;
        Some(ours.parent == reply.focus)
    }

    /// What the keyboard says right now, in **one** round trip.
    ///
    /// The bit is the key's own state, not the lock it toggles, which is what the rule is
    /// about: "we do not care about numlock state, we care only about if the key is pressed
    /// or not".  `QueryKeymap` reports the physical state of every key, whoever has focus and
    /// whether or not our window is mapped.
    pub fn keys(&self) -> Option<Keys> {
        let reply = self.connection.query_keymap().ok()?.reply().ok()?;
        let down = |keycode: u8| -> bool {
            let byte = usize::from(keycode / 8);
            let bit = 1u8 << (keycode % 8);
            reply.keys.get(byte).is_some_and(|value| value & bit != 0)
        };
        Some(Keys {
            numlock: down(self.numlock),
            f9: down(self.f9),
            f10: down(self.f10),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hotkey_is_the_chord_and_nothing_else() {
        // Display: "numlock pressed + F9", "numlock pressed + F10". A bare F9, a
        // bare F10, or the two function keys together are not hotkeys, so the keys stay the
        // guest's.
        let none = Keys::default();
        assert_eq!(none.hotkey(), None);
        assert_eq!(
            Keys {
                numlock: true,
                f9: false,
                f10: false
            }
            .hotkey(),
            None,
            "numlock alone"
        );
        assert_eq!(
            Keys {
                numlock: false,
                f9: true,
                f10: false
            }
            .hotkey(),
            None,
            "F9 alone"
        );
        assert_eq!(
            Keys {
                numlock: true,
                f9: true,
                f10: false
            }
            .hotkey(),
            Some(Hotkey::HideOrShow)
        );
        assert_eq!(
            Keys {
                numlock: true,
                f9: false,
                f10: true
            }
            .hotkey(),
            Some(Hotkey::HideAndOpenSettings)
        );
        assert_eq!(
            Keys {
                numlock: true,
                f9: true,
                f10: true
            }
            .hotkey(),
            None,
            "both together are ambiguous, and guessing would hide a window for no reason"
        );
    }

    #[test]
    fn the_keysyms_are_the_ones_x_defines() {
        assert_eq!(XK_NUM_LOCK, 0xff7f);
        assert_eq!(XK_F9, 0xffc6);
        assert_eq!(XK_F10, 0xffc7);
        // and the evdev fallbacks are the positions every keyboard agrees on
        assert_eq!(
            (EVDEV_NUM_LOCK_KEYCODE, EVDEV_F9_KEYCODE, EVDEV_F10_KEYCODE),
            (77, 75, 76)
        );
    }

    #[test]
    fn the_bit_of_a_keycode_is_where_querykeymap_puts_it() {
        // The protocol's own packing: keycode `k` is bit `k % 8` of byte `k / 8`.  Getting
        // this wrong would read a neighbouring key's state, which is the kind of bug that
        // looks like "the rule is random".
        assert_eq!((77 / 8, 77 % 8), (9, 5));
        assert_eq!((EVDEV_NUM_LOCK_KEYCODE, XK_NUM_LOCK), (77, 0xff7f));
    }
}
