//! **X's keycodes and the kernel's key codes**, which are two different numbers for the same key.
//!
//! The display window is a pipe: every key the user presses goes to the guest, including the
//! combinations a window manager would otherwise keep for itself (`Alt+F4`, `Super`,
//! `Ctrl+Escape`).  For that to be true the window cannot decide what a key *means* — it has to pass
//! the key **as the guest's keyboard understands it**, which is a kernel key code (`KEY_A` is 30,
//! `KEY_F4` is 62), because the guest's agent writes that number straight into its `uinput`
//! keyboard.
//!
//! GDK hands the window a *keyval* (`XK_F4`, `XK_a`) and a *hardware keycode*.  The keyval is the
//! wrong thing to translate: it depends on the shift state and on the layout, so `Shift+2` and `2`
//! are two different keyvals and the guest would be told a different key had been pressed.  The
//! **keycode** is the physical position of the key and it does not move with the layout, which is
//! what a keyboard device wants.
//!
//! ## The offset, which is the server's own rule
//!
//! Xorg's `evdev` driver names its keycodes after the kernel's: the X keycode is the kernel code
//! plus the server's `min_keycode` (8 on this server), so `KEY_A` 30 is keycode 38, `KEY_F4` 62 is
//! keycode 70, and `KEY_NUMLOCK` 69 is keycode 77.  That is the rule this module applies, and it is
//! the rule `temp/xgrab-probe`'s `keymap` binary measured against a real server.
//!
//! ## The keysym, which is the check
//!
//! An offset alone is a rule, and a rule that is wrong is a keyboard that types the wrong letters
//! **silently**: with `min_keycode` read as 0, keycode 38 would be `KEY_L` and nothing downstream
//! would notice.  So every keycode is checked against the server's own keyboard mapping
//! (`GetKeyboardMapping`): the keysym the server says that keycode produces is looked up in the
//! table below, and where the two positively disagree the key is answered `None` — a key the window
//! does not send, which is a keyboard with a missing key, rather than a keyboard with a wrong one.
//! A keysym this project does not know (`dead_acute`, `eurosign`, `adiaeresis`) is not a
//! disagreement: the key is a real physical key at a real position, and the offset is kept.
//!
//! The table is X's `XK_*` numbering (fixed protocol constants, from `X11/keysymdef.h`) against
//! `linux/input-event-codes.h`'s, and both sides of every pair are pinned by test.

use std::collections::HashMap;

use x11rb::connection::Connection;
use x11rb::protocol::xproto::{ConnectionExt as _, Setup};

/// X's keysyms above ASCII: numbers X invented, which carry no relation to a kernel code, so they
/// are the one thing that can say what such a key is.
///
/// The left column is `X11/keysymdef.h`; the right is `linux/input-event-codes.h`.  A keysym with
/// no kernel code of its own (`XK_Execute`, `XK_KP_F1`) is not here: this project does not invent a
/// key it cannot name.
const NAMED_KEYSYM: [(u32, u16); 88] = [
    (0xff08, 14),  // BackSpace            KEY_BACKSPACE
    (0xff09, 15),  // Tab                  KEY_TAB
    (0xff0a, 101), // LineFeed            KEY_LINEFEED
    (0xff0b, 355), // Clear              KEY_CLEAR
    (0xff0d, 28),  // Return               KEY_RETURN
    (0xff13, 119), // Pause               KEY_PAUSE
    (0xff14, 70),  // Scroll_Lock          KEY_SCROLLLOCK
    (0xff15, 99),  // Sys_Req              KEY_SYSRQ
    (0xff1b, 1),   // Escape                KEY_ESC
    (0xff20, 127), // Multi_key           KEY_COMPOSE
    (0xff50, 102), // Home                KEY_HOME
    (0xff51, 105), // Left                KEY_LEFT
    (0xff52, 103), // Up                  KEY_UP
    (0xff53, 106), // Right               KEY_RIGHT
    (0xff54, 108), // Down                KEY_DOWN
    (0xff55, 104), // Prior (Page_Up)     KEY_PAGEUP
    (0xff56, 109), // Next (Page_Down)    KEY_PAGEDOWN
    (0xff57, 107), // End                 KEY_END
    (0xff58, 102), // Begin (BOL)         KEY_HOME
    (0xff60, 353), // Select              KEY_SELECT
    (0xff61, 210), // Print               KEY_PRINT
    (0xff63, 110), // Insert              KEY_INSERT
    (0xff65, 131), // Undo                KEY_UNDO
    (0xff66, 182), // Redo                KEY_REDO
    (0xff67, 139), // Menu                KEY_MENU
    (0xff68, 136), // Find                KEY_FIND
    (0xff6b, 411), // Break               KEY_BREAK
    (0xff7f, 69),  // Num_Lock             KEY_NUMLOCK
    (0xff80, 57),  // KP_Space             KEY_SPACE
    (0xff89, 15),  // KP_Tab               KEY_TAB
    (0xff8d, 96),  // KP_Enter             KEY_KPENTER
    (0xff95, 102), // KP_Home             KEY_HOME
    (0xff96, 105), // KP_Left             KEY_LEFT
    (0xff97, 103), // KP_Up               KEY_UP
    (0xff98, 106), // KP_Right            KEY_RIGHT
    (0xff99, 108), // KP_Down             KEY_DOWN
    (0xff9a, 104), // KP_Prior            KEY_PAGEUP
    (0xff9b, 109), // KP_Next             KEY_PAGEDOWN
    (0xff9c, 107), // KP_End              KEY_END
    (0xff9d, 102), // KP_Begin            KEY_HOME
    (0xff9e, 110), // KP_Insert           KEY_INSERT
    (0xff9f, 111), // KP_Delete           KEY_DELETE
    (0xffaa, 55),  // KP_Multiply          KEY_KPASTERISK
    (0xffab, 78),  // KP_Add               KEY_KPPLUS
    (0xffac, 121), // KP_Separator        KEY_KPCOMMA
    (0xffad, 74),  // KP_Subtract          KEY_KPMINUS
    (0xffae, 83),  // KP_Decimal           KEY_KPDOT
    (0xffaf, 98),  // KP_Divide            KEY_KPSLASH
    (0xffb0, 82),  // KP_0                 KEY_KP0
    (0xffb1, 79),  // KP_1                 KEY_KP1
    (0xffb2, 80),  // KP_2                 KEY_KP2
    (0xffb3, 81),  // KP_3                 KEY_KP3
    (0xffb4, 75),  // KP_4                 KEY_KP4
    (0xffb5, 76),  // KP_5                 KEY_KP5
    (0xffb6, 77),  // KP_6                 KEY_KP6
    (0xffb7, 71),  // KP_7                 KEY_KP7
    (0xffb8, 72),  // KP_8                 KEY_KP8
    (0xffb9, 73),  // KP_9                 KEY_KP9
    (0xffbd, 117), // KP_Equal            KEY_KPEQUAL
    (0xffbe, 59),  // F1                   KEY_F1
    (0xffbf, 60),  // F2                   KEY_F2
    (0xffc0, 61),  // F3                   KEY_F3
    (0xffc1, 62),  // F4                   KEY_F4
    (0xffc2, 63),  // F5                   KEY_F5
    (0xffc3, 64),  // F6                   KEY_F6
    (0xffc4, 65),  // F7                   KEY_F7
    (0xffc5, 66),  // F8                   KEY_F8
    (0xffc6, 67),  // F9                   KEY_F9
    (0xffc7, 68),  // F10                  KEY_F10
    (0xffc8, 87),  // F11                  KEY_F11
    (0xffc9, 88),  // F12                  KEY_F12
    (0xffca, 183), // F13                 KEY_F13
    (0xffd5, 194), // F24                 KEY_F24
    (0xffe1, 42),  // Shift_L              KEY_LEFTSHIFT
    (0xffe2, 54),  // Shift_R              KEY_RIGHTSHIFT
    (0xffe3, 29),  // Control_L            KEY_LEFTCTRL
    (0xffe4, 97),  // Control_R            KEY_RIGHTCTRL
    (0xffe5, 58),  // Caps_Lock            KEY_CAPSLOCK
    (0xffe7, 125), // Meta_L              KEY_LEFTMETA
    (0xffe8, 126), // Meta_R              KEY_RIGHTMETA
    (0xffe9, 56),  // Alt_L                KEY_LEFTALT
    (0xffea, 100), // Alt_R               KEY_RIGHTALT
    (0xffeb, 125), // Super_L              KEY_LEFTMETA
    (0xffec, 126), // Super_R              KEY_RIGHTMETA
    (0xffed, 125), // Hyper_L              KEY_LEFTMETA
    (0xffee, 126), // Hyper_R              KEY_RIGHTMETA
    (0xfe03, 100), // ISO_Level3_Shift     KEY_RIGHTALT
    (0xffff, 111), // Delete               KEY_DELETE
];

/// **X's keysym to the kernel's key code.**
///
/// Two cases: a keysym above ASCII is the table above; a keysym that *is* a code point (`XK_a` is
/// `0x61`, `XK_A` is `0x41`, `XK_asciitilde` is `0x7e`) is the key that produces that character.
/// Anything else — `dead_acute`, `eurosign`, `adiaeresis`, `XF86AudioPlay` — is `None`: this project
/// does not name a key it cannot name.
pub fn kernel_code_of_keysym(keysym: u32) -> Option<u16> {
    if let Some((_, code)) = NAMED_KEYSYM.iter().find(|(symbol, _)| *symbol == keysym) {
        return Some(*code);
    }
    if (0x20..=0x7e).contains(&keysym) {
        return Some(code_of_character(keysym as u8));
    }
    None
}

/// The kernel code for an ASCII character: the key that produces it on the keyboard the kernel's
/// own codes are named after.
///
/// Upper case is the **same key** (`Shift+a` is `KEY_A`, not a different key), and a shifted
/// character is the key it shares with its unshifted one (`!` is `KEY_1`, `~` is `KEY_GRAVE`, `+`
/// is `KEY_EQUAL`).  A letter is the kernel's code in the keyboard's physical order — `KEY_Q` 16
/// through `KEY_M` 50 — which is the order the keys sit on a keyboard, not alphabetical order.
fn code_of_character(byte: u8) -> u16 {
    match byte {
        b' ' => 57,  // KEY_SPACE
        b'!' => 2,   // KEY_1
        b'"' => 40,  // KEY_APOSTROPHE
        b'#' => 4,   // KEY_3
        b'$' => 5,   // KEY_4
        b'%' => 6,   // KEY_5
        b'&' => 8,   // KEY_7
        b'\'' => 40, // KEY_APOSTROPHE
        b'(' => 10,  // KEY_9
        b')' => 11,  // KEY_0
        b'*' => 9,   // KEY_8
        b'+' => 13,  // KEY_EQUAL
        b',' => 51,  // KEY_COMMA
        b'-' => 12,  // KEY_MINUS
        b'.' => 52,  // KEY_DOT
        b'/' => 53,  // KEY_SLASH
        b'0' => 11,  // KEY_0 (the kernel numbers the row 1..9 first: `KEY_1` is 2)
        b'1'..=b'9' => 1 + u16::from(byte - b'0'),
        b':' => 39, // KEY_SEMICOLON
        b';' => 39, // KEY_SEMICOLON
        b'<' => 51, // KEY_COMMA
        b'=' => 13, // KEY_EQUAL
        b'>' => 52, // KEY_DOT
        b'?' => 53, // KEY_SLASH
        b'@' => 3,  // KEY_2
        b'A'..=b'Z' | b'a'..=b'z' => {
            // The three rows, each starting where the kernel starts numbering it: `KEY_Q` 16,
            // `KEY_A` 30, `KEY_Z` 44.  The rows are **not** one run of numbers — the gap after `P`
            // (25 → 30) and after `L` (38 → 44) is the kernel's own, and a letter looked up as if
            // the rows were contiguous lands on the wrong key.
            const ROWS: [(&[u8], u16); 3] =
                [(b"qwertyuiop", 16), (b"asdfghjkl", 30), (b"zxcvbnm", 44)];
            let lower = byte.to_ascii_lowercase();
            ROWS.iter()
                .find_map(|(row, base)| {
                    row.iter()
                        .position(|c| *c == lower)
                        .map(|position| base + position as u16)
                })
                .unwrap_or(0)
        }
        b'[' => 26,  // KEY_LEFTBRACE
        b'\\' => 43, // KEY_BACKSLASH
        b']' => 27,  // KEY_RIGHTBRACE
        b'^' => 7,   // KEY_6
        b'_' => 12,  // KEY_MINUS
        b'`' => 41,  // KEY_GRAVE
        b'{' => 26,  // KEY_LEFTBRACE
        b'|' => 43,  // KEY_BACKSLASH
        b'}' => 27,  // KEY_RIGHTBRACE
        b'~' => 41,  // KEY_GRAVE
        _ => 0,
    }
}

/// **The window's keyboard**: X's keycode → the kernel's key code, for one X server.
///
/// Built once per run from the server's own `Setup` (`min_keycode`, which is the offset) and its
/// `GetKeyboardMapping`.  The offset answers; the mapping vetoes.  See the module's note.
#[derive(Clone, Debug)]
pub struct KeyCodes {
    by_keycode: HashMap<u16, u16>,
    /// The server's `min_keycode`: X's keycode minus this is the kernel's code.
    offset: u16,
    /// The keysym the server gave each keycode, so the check can be read back (and so a test can
    /// see what the mapping said without asking a server).
    keysyms: HashMap<u16, u32>,
    /// Keycodes where the offset and the keysym **disagreed**: keys the window does not send.
    vetoed: Vec<u16>,
}

impl KeyCodes {
    /// Read the server's mapping and check it.  `Err` when the server will not answer.
    pub fn read<C: Connection>(connection: &C) -> Result<Self, String> {
        let setup: &Setup = connection.setup();
        let first = u16::from(setup.min_keycode);
        let last = u16::from(setup.max_keycode);
        if last < first {
            return Err("the server's key range is empty".into());
        }
        let count = u8::try_from(last - first + 1)
            .map_err(|_| "the server's key range is not a byte wide".to_string())?;
        // X's own `KeyCode` is a byte; the map this module builds keeps it as a `u16` because the
        // window's key events carry it that way.
        let first_keycode = u8::try_from(first)
            .map_err(|_| "the server's first keycode is not a byte".to_string())?;
        let reply = connection
            .get_keyboard_mapping(first_keycode, count)
            .map_err(|e| format!("GetKeyboardMapping: {e}"))?
            .reply()
            .map_err(|e| format!("GetKeyboardMapping: {e}"))?;
        Ok(Self::from_mapping(
            first,
            &reply.keysyms,
            reply.keysyms_per_keycode,
        ))
    }

    /// Build and check the map from a mapping that was already read — a test's own mapping, so the
    /// rule and the veto are testable without an X server.
    ///
    /// A row is checked **as a row**.  X puts the key's other names in it, and for the keys this
    /// project cares about the first one is often not the one the kernel numbers: keycode 107 is
    /// `Print` *and* `Sys_Req` (the kernel's `KEY_SYSRQ`, which is what the offset says), and
    /// keycode 79 is `KP_Home` *and* `KP_7` (the kernel's `KEY_KP7`).  A row is accepted when any
    /// name in it is the key the offset names, and vetoed when none is.
    pub fn from_mapping(min_keycode: u16, keysyms: &[u32], keysyms_per_keycode: u8) -> Self {
        let per = usize::from(keysyms_per_keycode.max(1));
        let mut by_keycode = HashMap::new();
        let mut known = HashMap::new();
        let mut vetoed = Vec::new();
        for (keycode, row) in keysyms.chunks(per).enumerate() {
            let keycode = min_keycode + keycode as u16;
            let named: Vec<u32> = row.iter().copied().filter(|symbol| *symbol != 0).collect();
            let Some(&first) = named.first() else {
                continue; // a keycode with no keysym is a key with no name
            };
            known.insert(keycode, first);
            // The offset is the answer; the row only vetoes it, and only when every name in it
            // names a different key.
            let offset_code = keycode - min_keycode;
            let names_this_key = named
                .iter()
                .any(|symbol| kernel_code_of_keysym(*symbol) == Some(offset_code));
            if named
                .iter()
                .all(|symbol| kernel_code_of_keysym(*symbol).is_none())
                || names_this_key
            {
                by_keycode.insert(keycode, offset_code);
            } else {
                vetoed.push(keycode);
            }
        }
        Self {
            by_keycode,
            offset: min_keycode,
            keysyms: known,
            vetoed,
        }
    }

    /// The kernel key code for X's keycode, or `None` for a key this module will not send.
    pub fn code(&self, keycode: u16) -> Option<u16> {
        self.by_keycode.get(&keycode).copied()
    }

    /// X's keycode for a kernel key code (the offset, the other way).
    ///
    /// This is how the window's **own** keys are found: numlock, `numlock + F9` and `numlock + F10`
    /// are read from the keyboard's physical state, and the state is read at the keycode the kernel
    /// code names.  Nothing here is a hard-coded number — on a server whose `min_keycode` is not 8
    /// the reading follows the server.
    pub fn keycode_of(&self, kernel_code: u16) -> Option<u16> {
        self.by_keycode
            .iter()
            .find_map(|(keycode, code)| (*code == kernel_code).then_some(*keycode))
            .or_else(|| Some(self.offset + kernel_code))
    }

    /// The server's `min_keycode`: the offset between the two numberings.
    pub fn offset(&self) -> u16 {
        self.offset
    }

    /// Every keycode the server named, in order — what the `list-keys` example prints.
    pub fn keycodes(&self) -> Vec<u16> {
        let mut codes: Vec<u16> = self.keysyms.keys().copied().collect();
        codes.sort_unstable();
        codes
    }

    /// The keysym the server said this keycode produces (its first, unshifted one).
    pub fn keysym_of(&self, keycode: u16) -> Option<u32> {
        self.keysyms.get(&keycode).copied()
    }

    /// The keycodes where the offset and the keysym disagreed.
    ///
    /// Zero on a server whose mapping is the kernel's (every Xorg driven by `evdev`).  A non-empty
    /// list is a server whose mapping is somebody else's, and the keys on the list are keys the
    /// window does not send — a missing key is a bug a person can see, a wrong key is one they
    /// cannot.
    pub fn vetoed(&self) -> &[u16] {
        &self.vetoed
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The kernel's own numbers, pinned against `linux/input-event-codes.h`: a code that is wrong
    /// here is a key the guest receives as a **different key**, and nothing else would notice.
    #[test]
    fn the_named_keysyms_are_the_kernels_own_codes() {
        for (keysym, expected) in [
            (0xff1bu32, 1u16), // Escape
            (0xff08, 14),      // BackSpace
            (0xff09, 15),      // Tab
            (0xff0d, 28),      // Return
            (0xff13, 119),     // Pause
            (0xff14, 70),      // Scroll_Lock
            (0xff15, 99),      // Sys_Req
            (0xff7f, 69),      // Num_Lock
            (0xff61, 210),     // Print
            (0xff50, 102),     // Home
            (0xff52, 103),     // Up
            (0xff55, 104),     // Prior
            (0xff51, 105),     // Left
            (0xff53, 106),     // Right
            (0xff57, 107),     // End
            (0xff54, 108),     // Down
            (0xff56, 109),     // Next
            (0xff63, 110),     // Insert
            (0xffff, 111),     // Delete
            (0xff67, 139),     // Menu
            (0xff20, 127),     // Multi_key
            (0xffe1, 42),      // Shift_L
            (0xffe2, 54),      // Shift_R
            (0xffe3, 29),      // Control_L
            (0xffe4, 97),      // Control_R
            (0xffe5, 58),      // Caps_Lock
            (0xffe9, 56),      // Alt_L
            (0xffea, 100),     // Alt_R
            (0xffeb, 125),     // Super_L
            (0xffec, 126),     // Super_R
            (0xfe03, 100),     // ISO_Level3_Shift
            (0xffbe, 59),      // F1
            (0xffc1, 62),      // F4
            (0xffc6, 67),      // F9
            (0xffc7, 68),      // F10
            (0xffc8, 87),      // F11
            (0xffc9, 88),      // F12
        ] {
            assert_eq!(
                kernel_code_of_keysym(keysym),
                Some(expected),
                "keysym {keysym:#06x}"
            );
        }
    }

    /// The keypad: its keysyms name a **character**, so they are the one place the offset needs the
    /// table, and the numbers are `linux/input-event-codes.h`'s.
    #[test]
    fn the_keypad_is_the_kernels_own_codes() {
        for (keysym, expected) in [
            (0xffafu32, 98u16), // KP_Divide
            (0xffaa, 55),       // KP_Multiply
            (0xffab, 78),       // KP_Add
            (0xffad, 74),       // KP_Subtract
            (0xff8d, 96),       // KP_Enter
            (0xffae, 83),       // KP_Decimal
            (0xffb0, 82),       // KP_0
            (0xffb1, 79),       // KP_1
            (0xffb2, 80),
            (0xffb3, 81),
            (0xffb4, 75),
            (0xffb5, 76),
            (0xffb6, 77),
            (0xffb7, 71),
            (0xffb8, 72),
            (0xffb9, 73),
        ] {
            assert_eq!(
                kernel_code_of_keysym(keysym),
                Some(expected),
                "keysym {keysym:#06x}"
            );
        }
    }

    /// A character is the **key that produces it**, and upper case is the same key: `Shift+a` is
    /// `KEY_A`, not a different key.  The letters are in the keyboard's physical order, which is the
    /// order the kernel numbers them in.
    #[test]
    fn a_character_is_the_key_that_produces_it() {
        assert_eq!(code_of_character(b'a'), 30);
        assert_eq!(code_of_character(b'A'), 30);
        assert_eq!(code_of_character(b'q'), 16);
        assert_eq!(code_of_character(b'p'), 25);
        assert_eq!(code_of_character(b'z'), 44);
        assert_eq!(code_of_character(b'm'), 50);
        assert_eq!(code_of_character(b'1'), 2);
        assert_eq!(code_of_character(b'0'), 11);
        assert_eq!(code_of_character(b' '), 57);
        assert_eq!(code_of_character(b'-'), 12);
        assert_eq!(code_of_character(b'!'), 2, "Shift+1 is the 1 key");
        assert_eq!(code_of_character(b'*'), 9, "Shift+8 is the 8 key");
        assert_eq!(code_of_character(b':'), 39, "Shift+; is the; key");
        assert_eq!(code_of_character(b'~'), 41, "Shift+` is the ` key");
        assert_eq!(code_of_character(b'+'), 13, "Shift+= is the = key");
        assert_eq!(code_of_character(b'['), 26);
        assert_eq!(code_of_character(b'\''), 40);
        // The letters are 26 distinct codes.
        let mut codes: Vec<u16> = (b'a'..=b'z').map(code_of_character).collect();
        codes.sort_unstable();
        codes.dedup();
        assert_eq!(codes.len(), 26);
    }

    /// **No important key is unnamed.**  A key this module cannot name is a key the guest never
    /// hears, which is how a guest ends up unable to type.
    #[test]
    fn every_key_the_window_forwards_has_a_code() {
        for keysym in [
            0xff1bu32, 0xff08, 0xff09, 0xff0d, 0x20, 0xffff, 0xff63, 0xff50, 0xff57, 0xff55,
            0xff56, 0xff51, 0xff53, 0xff52, 0xff54, 0xff61, 0xff13, 0xff14, 0xff7f, 0xffe5, 0xff67,
            0xff20, 0xffbe, 0xffc1, 0xffc6, 0xffc7, 0xffc8, 0xffc9, 0xffe1, 0xffe2, 0xffe3, 0xffe4,
            0xffe9, 0xffea, 0xffeb, 0xffec, 0xfe03, 0xffab, 0xffad, 0xffae, 0xff8d, 0xffaf, 0xffb0,
            0xffb9,
        ] {
            assert_ne!(
                kernel_code_of_keysym(keysym),
                None,
                "keysym {keysym:#06x} has no kernel code"
            );
        }
        for byte in b'0'..=b'9' {
            assert_ne!(code_of_character(byte), 0, "{}", byte as char);
        }
        for byte in b'a'..=b'z' {
            assert_ne!(code_of_character(byte), 0, "{}", byte as char);
        }
    }

    /// A keysym this module does not know is `None`, not a guess: the window sends nothing for it,
    /// which is what a key with no code means.  `XF86AudioPlay` is exactly such a key.
    #[test]
    fn an_unknown_keysym_is_not_guessed_at() {
        assert_eq!(kernel_code_of_keysym(0x1008_ff00), None);
        assert_eq!(kernel_code_of_keysym(0), None);
        assert_eq!(kernel_code_of_keysym(0x07e1), None, "dead_acute");
        assert_eq!(kernel_code_of_keysym(0x20ac), None, "eurosign");
        assert_eq!(code_of_character(0x01), 0);
    }

    /// **The offset rule, on a mapping that is a real mapping**: `min_keycode` is 8, `KEY_A` 30 is
    /// keycode 38, `KEY_F4` 62 is keycode 70, `KEY_NUMLOCK` 69 is keycode 77, `KEY_LEFTMETA` 125 is
    /// keycode 133, and the keysym the mapping gives each of those keycodes is the keysym the kernel
    /// code stands for.
    ///
    /// The rows below are the ones `temp/xgrab-probe`'s `keymap` binary prints from a real X server
    /// (that one answers **seven** keysyms a keycode; the shape is the same, only the padding
    /// differs), cut to the keys that matter.  Note what the server says about the two keys this
    /// project's own chords use: `F9` is keycode **75** and `F10` is **76** — 76 is `Scroll_Lock`,
    /// and a table that guessed from the kernel's numbering would read the wrong key.
    #[test]
    fn the_offset_is_the_servers_own_rule() {
        let mut keysyms = vec![0u32; 4 * (255 - 8 + 1)];
        let mut row = |keycode: u16, first: u32, second: u32| {
            let index = usize::from(keycode - 8) * 4;
            keysyms[index] = first;
            keysyms[index + 1] = second;
        };
        row(9, 0xff1b, 0x0000); // Escape
        row(23, 0xff09, 0xfe20); // Tab / ISO_Left_Tab
        row(38, 0x61, 0x41); // a / A
        row(49, 0x60, 0x7e); // ` / asciitilde
        row(64, 0xffe9, 0xffe7); // Alt_L / Meta_L
        row(70, 0xffc1, 0xffc1); // F4
        row(75, 0xffc6, 0xffc6); // F9
        row(76, 0xffc7, 0xffc7); // F10
        row(77, 0xff7f, 0x0000); // Num_Lock
        row(78, 0xff14, 0x0000); // Scroll_Lock
        row(107, 0xff61, 0xff15); // Print / Sys_Req
        row(133, 0xffeb, 0x0000); // Super_L
        row(108, 0xffea, 0xfe03); // Alt_R / ISO_Level3_Shift
        row(84, 0xff9d, 0xffb5); // KP_Begin / KP_5 (numlock off, then on)

        let map = KeyCodes::from_mapping(8, &keysyms, 4);
        assert_eq!(map.offset(), 8);
        assert!(
            map.vetoed().is_empty(),
            "a real mapping has no disagreement"
        );
        assert_eq!(map.code(38), Some(30), "keycode 38 is KEY_A");
        assert_eq!(map.code(70), Some(62), "keycode 70 is KEY_F4");
        assert_eq!(map.code(75), Some(67), "keycode 75 is KEY_F9");
        assert_eq!(map.code(76), Some(68), "keycode 76 is KEY_F10");
        assert_eq!(map.code(77), Some(69), "keycode 77 is KEY_NUMLOCK");
        assert_eq!(map.code(78), Some(70), "keycode 78 is KEY_SCROLLLOCK");
        assert_eq!(map.code(107), Some(99), "keycode 107 is KEY_SYSRQ");
        assert_eq!(map.code(133), Some(125), "keycode 133 is KEY_LEFTMETA");
        assert_eq!(map.code(64), Some(56), "keycode 64 is KEY_LEFTALT");
        assert_eq!(map.code(9), Some(1), "keycode 9 is KEY_ESC");
        assert_eq!(map.code(23), Some(15), "keycode 23 is KEY_TAB");
        assert_eq!(map.code(49), Some(41), "keycode 49 is KEY_GRAVE");
        assert_eq!(map.code(84), Some(76), "keycode 84 is KEY_KP5");
        assert_eq!(map.code(255), None, "a keycode with no keysym is no key");
        assert_eq!(map.keysym_of(77), Some(0xff7f));

        // And the other way, which is how the window's own three keys are found.
        assert_eq!(map.keycode_of(69), Some(77), "numlock");
        assert_eq!(map.keycode_of(67), Some(75), "F9");
        assert_eq!(map.keycode_of(68), Some(76), "F10");
        assert_eq!(map.keycode_of(56), Some(64), "Alt_L");
    }

    /// **The veto is what a wrong offset looks like.**  Read `min_keycode` as 0 and every key lands
    /// on a different letter — which is exactly the failure an offset alone would hide.  The check
    /// turns it into keys the window does not send, and a list that says so.
    #[test]
    fn an_offset_that_is_wrong_is_caught_and_sends_nothing() {
        let mut keysyms = vec![0u32; 4 * (255 - 8 + 1)];
        let mut row = |keycode: u16, keysym: u32| {
            let index = usize::from(keycode - 8) * 4;
            keysyms[index] = keysym;
        };
        row(38, 0x61); // a
        row(70, 0xffc1); // F4
        row(77, 0xff7f); // Num_Lock

        // The same mapping, read as if the server's offset were 0.
        let wrong = KeyCodes::from_mapping(0, &keysyms[8 * 4..], 4);
        assert_eq!(
            wrong.code(38),
            None,
            "keycode 38 would be KEY_L; it is not sent"
        );
        assert_eq!(
            wrong.code(70),
            None,
            "keycode 70 would be KEY_F10; it is not sent"
        );
        assert_eq!(
            wrong.vetoed().len(),
            3,
            "every named key disagreed: {wrong:?}"
        );

        // A keysym the module does not know is not a disagreement: the key is a real physical key at
        // a real position, and the offset is kept for it.
        let mut keysyms = vec![0u32; 4 * (255 - 8 + 1)];
        keysyms[(100 - 8) * 4] = 0x07e1; // dead_acute
        let map = KeyCodes::from_mapping(8, &keysyms, 4);
        assert_eq!(map.code(100), Some(92), "an unnamed key keeps the offset");
        assert!(map.vetoed().is_empty());
    }

    /// The table has no keysym answered two different ways: a keysym answered twice is a key whose
    /// meaning depends on which row was found first.
    #[test]
    fn no_keysym_is_answered_twice_with_different_codes() {
        let mut seen: HashMap<u32, u16> = HashMap::new();
        for (keysym, code) in NAMED_KEYSYM {
            if let Some(other) = seen.insert(keysym, code) {
                assert_eq!(other, code, "keysym {keysym:#06x} is answered two ways");
            }
        }
    }

    /// The window's own three keys are **not** hard-coded numbers: they are the kernel codes
    /// `KEY_NUMLOCK`, `KEY_F9`, `KEY_F10`, and the keycode they are read at comes from the server.
    #[test]
    fn the_windows_own_keys_follow_the_server() {
        let keysyms = vec![0u32; 4 * (255 - 8 + 1)];
        let map = KeyCodes::from_mapping(8, &keysyms, 4);
        // A server with no keysyms at all still has an offset, and the three keys are read by it.
        assert_eq!(map.keycode_of(69), Some(77));
        assert_eq!(map.keycode_of(67), Some(75));
        assert_eq!(map.keycode_of(68), Some(76));
        // A server whose offset is 0 puts them elsewhere, and the reading follows.
        let other = KeyCodes::from_mapping(0, &keysyms, 4);
        assert_eq!(other.keycode_of(69), Some(69));
        assert_eq!(other.keycode_of(67), Some(67));
    }
}
