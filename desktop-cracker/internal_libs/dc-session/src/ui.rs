//! The application's side of the **one UI thread**.
//!
//! Every window and every dialog the application puts up belongs to one thread: the thread that
//! runs the GTK main loop (`dc_display::display_loop`).  That thread is the display thread, and
//! the display window — a GTK window whose content is a `gtk::GLArea` — is created on it.
//!
//! This module is the shared state between that thread and the rest of the application:
//!
//! * the rest **asks** for something (a chord's meaning, a close question) by setting a flag;
//! * the UI thread **carries it out** on its own tick, where a GTK dialog is safe to put up;
//! * what the window did (hidden, shown, back after the settings) is written back into the
//!   `WindowControl` the application already reads.
//!
//! Why the split: a dialog asked inside a GTK callback is a dialog inside the frame that was
//! being drawn, and the keyboard read that noticed the chord must never wait for an answer.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};

use dc_display::window::WindowControl;
use dc_display::xinput::Hotkey;

use crate::hotkeys::{self, CloseAnswer, SettingsFile, WindowKeys};

/// Where the root disk's question puts its answer, so the run can read it back.
///
/// The question itself is asked **on the UI thread** (a GTK dialog belongs there) while the run is
/// waiting for it: the answer is a `DiskPassphrase`, which zeroizes itself when it is dropped, and
/// this handle carries no copy of it — the passphrase is moved in and moved out again.
#[derive(Default)]
pub struct DiskAnswer(std::sync::Mutex<Option<crate::diskpass::DiskPassphrase>>);

impl DiskAnswer {
    /// The user's answer, moved in.
    pub fn set(&self, passphrase: crate::diskpass::DiskPassphrase) {
        if let Ok(mut slot) = self.0.lock() {
            *slot = Some(passphrase);
        }
    }

    /// Take it out again: once.  A second read is `None`, so nothing can ask twice.
    pub fn take(&self) -> Option<crate::diskpass::DiskPassphrase> {
        self.0.lock().ok().and_then(|mut slot| slot.take())
    }
}

/// What one tick of the UI thread has to do — decided by [`UiState::plan`] without asking GTK
/// anything, and carried out by [`UiState::work`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tick {
    /// Nothing was asked for.
    Nothing,
    /// The user asked to close the window: ask what that means.
    Close,
    /// `numlock + F10`: open the settings window.
    Settings,
    /// A chord was pressed and not yet acted on.
    Chord(Hotkey),
}

/// What the application asks the UI thread to do, and what the UI thread reports back.
///
/// It is shared with the display loop (which hands it to the window as its [`HotkeySink`]) and
/// read by the application's own loops (which is how a close the user asked for is answered).
///
/// [`HotkeySink`]: dc_display::window::HotkeySink
pub struct UiState {
    /// The display window's control: visibility, the close request, the exit.
    pub window: Arc<WindowControl>,
    /// **The settings file this run holds**: the path, what was read at startup, the settings in
    /// force (which the window replaces when it saves) and the unlock hash this run asks against
    /// (`hotkeys::SettingsFile`).
    pub file: Arc<Mutex<SettingsFile>>,
    /// `numlock + F10` was pressed: open the settings window on the next tick.
    pub settings_wanted: Arc<AtomicBool>,
    /// The run should finish: the settings window's own exit (`numlock + F10`), the `Esc` inside
    /// the window, or the close the user confirmed.
    pub exit_requested: Arc<AtomicBool>,
    /// The chord that was pressed and not yet acted on.  It is the **only** thing the key loop
    /// writes, so reading the keyboard never waits for a question.
    pub pending: Arc<Mutex<Option<Hotkey>>>,
    /// The unlock question is on screen: the application does not ask again while it is.
    pub asking: Arc<AtomicBool>,
    /// The run is **over before it started**: the disk's question was refused, or the disk cannot
    /// be opened with what was typed.  It carries the sentence the run ends with.
    pub failed: Arc<Mutex<Option<String>>>,
    /// A change to `failed`, so the run reacts at once instead of on its next poll.
    pub changed: Arc<(Mutex<u64>, Condvar)>,
}

impl UiState {
    /// A change the run waits for (see `changed`).
    pub fn notify(&self) {
        let (lock, condvar) = &*self.changed;
        if let Ok(mut revision) = lock.lock() {
            *revision += 1;
        }
        condvar.notify_all();
    }

    /// The run failed before it started (the disk's question), with the sentence it ends with.
    pub fn fail(&self, problem: anyhow::Error) {
        if let Ok(mut slot) = self.failed.lock() {
            *slot = Some(format!("{problem}"));
        }
        self.notify();
    }

    /// The failure, when there was one.
    pub fn failure(&self) -> Option<String> {
        self.failed.lock().ok().and_then(|slot| slot.clone())
    }

    /// The key sink the display loop fires chords into: it only **records** them.
    pub fn keys(&self) -> Arc<dyn dc_display::window::HotkeySink> {
        Arc::new(self.keys_value())
    }

    /// The same keys, as the value itself: a caller that has to keep one (a single-shot run, a test)
    /// takes this rather than the trait object.
    pub fn keys_value(&self) -> WindowKeys {
        // A poisoned lock is a panic somewhere else in this process, and the settings are not what
        // that panic was about: the value inside is taken either way.
        let file = match self.file.lock() {
            Ok(file) => file,
            Err(e) => e.into_inner(),
        };
        file.keys(&self.window, &self.settings_wanted, &self.pending)
    }

    /// What **one tick** of the application's work asks for.
    ///
    /// It is decided without touching GTK — the flags are read, nothing is opened and nothing is
    /// cleared — so the decision is testable on its own (see the tests at the end of this file);
    /// [`UiState::work`] is what carries it out, with the dialogs it may need.
    pub fn plan(&self) -> Tick {
        // A close the user asked for (the window's own close button) is the most urgent thing
        // there is: the window is going away, whatever a chord meant.
        if self.window.close_requested() {
            return Tick::Close;
        }
        // The settings window, asked for by `numlock + F10` (or by the first-password flow).
        if self.settings_wanted.load(Ordering::Relaxed) {
            return Tick::Settings;
        }
        match self.pending.lock().ok().and_then(|slot| *slot) {
            Some(hotkey) => Tick::Chord(hotkey),
            None => Tick::Nothing,
        }
    }

    /// One turn of the application's work, **on the UI thread**.
    ///
    /// It is called by the display loop once per tick, before the frame is drawn.  Everything a
    /// GTK dialog needs is here and nothing else: a chord's meaning, the settings window, the
    /// close question and the unlock question.
    ///
    /// **The caller is the UI thread, and so is this**: the display window a question belongs to
    /// is asked of the thread that owns it (`dc_display::display_loop::parent_window`), which is
    /// the same thread, and a GTK object is never carried anywhere.
    ///
    /// **One question per tick**: the tick carries out the first thing [`UiState::plan`] asks
    /// for and returns.  A tick that put two dialogs up would be two dialogs, and the second
    /// would be behind the first; the next tick (33 ms later) has the rest.
    pub fn work(&self) {
        let parent = dc_display::display_loop::parent_window();
        let parent = parent.as_ref();
        match self.plan() {
            // A close the user asked for: the question belongs here, where a dialog is safe.
            //
            // **The window is already hidden when this runs, and nothing here has to hide it**: the
            // click's own callback did that (`dc_display`'s `delete-event`: one call, then the ask is
            // *queued*), so the question is asked over nothing — a question with the window the user
            // just dismissed still in front of it is the window refusing to go, which is what the
            // operator reported on 2026-10-13.  The three answers say what happens to the window the
            // close was asked of: *Close* ends the run, **Keep hidden** leaves it hidden (the state
            // it is already in) and the guest running, and *Cancel* brings it back — past the unlock
            // password, exactly as a hidden window is asked back.  The display loop *stops* GTK's own
            // close rather than letting it destroy the window, so all three are answerable.
            Tick::Close => {
                self.window.clear_close_request();
                match hotkeys::ask_to_close(parent) {
                    CloseAnswer::Close => {
                        dc_common::milestone!(
                            "the user asked to close: the application is finishing"
                        );
                        self.window.request_exit();
                    }
                    CloseAnswer::Hide => {
                        // **Keep hidden** — and there is nothing to do: the click hid it.  Saying so
                        // is the whole of this arm, because "the window is hidden" is exactly what
                        // the user asked for.
                        dc_common::milestone!(
                            "the user asked to keep the window hidden; the guest keeps running \
                             (numlock + F9 brings it back)"
                        );
                    }
                    CloseAnswer::Cancel => {
                        if self.keys_value().ask_for_password(parent) {
                            self.window.set_visible(true);
                            dc_common::milestone!(
                                "the user cancelled the close: the password was right, so the \
                                 window is back"
                            );
                        } else {
                            dc_common::milestone!(
                                "the user cancelled the close, and the password was not given: \
                                 the window stays hidden"
                            );
                        }
                    }
                }
            }
            Tick::Settings => {
                self.settings_wanted.store(false, Ordering::Relaxed);
                self.at_most_one_question(|| self.open_settings(parent));
            }
            // The chord itself: `numlock + F9` hides the window, or asks the unlock password and
            // shows it again.
            Tick::Chord(hotkey) => {
                let keys = self.keys_value();
                match keys.act(hotkey, parent) {
                    Ok(said) => dc_common::milestone!("window: {said}"),
                    Err(e) => dc_common::milestone!("window: {hotkey:?} refused: {e}"),
                }
                keys.clear_pending();
            }
            Tick::Nothing => {}
        }
    }

    /// Put a question up, but never two at once: while one is on screen the tick leaves it alone.
    fn at_most_one_question(&self, ask: impl FnOnce()) {
        if self.asking.swap(true, Ordering::Relaxed) {
            return;
        }
        ask();
        self.asking.store(false, Ordering::Relaxed);
    }

    /// Open the settings window, save what the user edited — **in force at once** — and, when the
    /// window was hidden, ask for the unlock password and show it again as it closes.
    ///
    /// The window is told which password to ask against **before** it opens, and a password it saves
    /// becomes the one this run asks from here on (the operator, 2026-10-13): a person who changes
    /// the password in the window is the person who just typed the old one, so the new one is what
    /// the next question uses — and the question after the window closes is asked with it.
    fn open_settings(&self, parent: Option<&dc_dialog::Parent>) {
        let mut file = match self.file.lock() {
            Ok(file) => file,
            Err(e) => e.into_inner(),
        };
        let shown = file.live.unlock_password.clone();
        // **The window shows what is in force now**, re-read from the path it holds: a setting
        // changed while this run is up (a hand edit, another run) is what the window should show,
        // not the snapshot this run started with.  A file that cannot be read keeps what is in
        // force and says so.
        if let Err(e) = file.reload() {
            dc_common::milestone!(
                "settings: the file could not be read again ({e}); the settings \
 in force are the ones this run has"
            );
        }
        dc_common::milestone!(
            "settings: opening the window (unlock password {})",
            if file.unlock.is_set() {
                "set"
            } else {
                "not set"
            }
        );
        match hotkeys::open_settings(&mut file) {
            Ok(()) => {
                if file.live.unlock_password != shown {
                    dc_common::milestone!(
                        "settings saved to {}; the unlock password is the one just set, for this \
                         run and the next",
                        file.path.display()
                    );
                } else {
                    dc_common::milestone!("settings saved to {}", file.path.display());
                }
            }
            Err(e) => {
                // A window closed without saving is not a failure: nothing was decided.
                dc_common::milestone!("settings not saved: {e}");
                return;
            }
        }
        drop(file);
        // **The question after the window closes** is asked with the password that is in force now:
        // the one this run started with, or the one the window just set.
        if self.keys_value().ask_for_password(parent) {
            self.window.set_visible(true);
            dc_common::milestone!(
                "the settings window closed: the password was right, so the window is back"
            );
        } else {
            dc_common::milestone!("the settings window closed: the window stays hidden");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dc_settings::Settings;

    /// A state for a run with no dialogs to answer: the window control, a settings value and the
    /// flags.  Nothing here opens GTK — which is the point: what one tick *asks for* is decided
    /// without a display, and that is what these tests exercise.
    fn state() -> UiState {
        // **The file is this test's own** (a `tempfile` directory, never the user's settings): the
        // state is built from what it holds, which is the defaults.
        let dir = tempfile::tempdir().unwrap();
        let file = SettingsFile::load(dir.path().join("config.yml"), true).unwrap();
        UiState {
            window: Arc::new(WindowControl::new()),
            file: Arc::new(Mutex::new(file)),
            settings_wanted: Arc::new(AtomicBool::new(false)),
            exit_requested: Arc::new(AtomicBool::new(false)),
            pending: Arc::new(Mutex::new(None)),
            asking: Arc::new(AtomicBool::new(false)),
            failed: Arc::new(Mutex::new(None)),
            changed: Arc::new((Mutex::new(0u64), Condvar::new())),
        }
    }

    /// A tick with nothing asked for does nothing at all.
    #[test]
    fn a_tick_with_nothing_asked_for_asks_for_nothing() {
        assert_eq!(state().plan(), Tick::Nothing);
    }

    /// **A close the user asked for is the most urgent thing there is**, and it asks a question
    /// about a window that is **already off the screen** (Closing the window: ,
    /// 2026-10-13): the click's own callback hides the window and queues the ask
    /// (`dc_display`'s `delete-event`), so the question about what closing means is asked over
    /// nothing — which is what makes the operator's report — the display window still on screen
    /// while the question is up, and numlock unable to hide it — impossible.
    ///
    /// The hiding is `dc-display`'s own — the callback that receives the click does it before it
    /// queues the ask — and what this pins is that the tick **asks** a queued close, over a window
    /// that is already hidden.
    #[test]
    fn a_close_request_is_what_the_tick_carries_out() {
        use dc_display::window::Control;
        let ui = state();
        ui.window.set_visible(true);
        assert!(!ui.window.is_hidden(), "a window that starts shown");
        // The click: the window goes away, the ask is queued.
        ui.window.set_visible(false);
        ui.window.window_closed();
        assert!(ui.window.is_hidden(), "hidden before the question is asked");
        assert_eq!(
            ui.plan(),
            Tick::Close,
            "the close is what the tick carries out"
        );
        // And the window's own rule keeps it that way: `dc_display`'s shape rule answers Hidden for
        // a hidden window **whatever the numlock key is doing** ("hidden stays hidden": when the
        // window is hidden, the numlock events do not change its visibility), so releasing the key
        // while the question is up cannot bring the window back in front of the dialog.
        use dc_display::window::Shape;
        for numlock_held in [true, false] {
            assert_eq!(
                dc_display::window::shape_for(true, true, numlock_held, 2560, 1080),
                Shape::Hidden,
                "a hidden window stays hidden with numlock {numlock_held}"
            );
        }
        assert!(ui.window.is_hidden());
    }

    /// **The settings window is behind the password** (Password: , the operator
    /// 2026-10-13): with a password in force, `numlock + F10` asks for it **before** the window
    /// opens — the settings are where the password is changed, so somebody who cannot open the
    /// display window must not be able to change it either.  The question and the window are the
    /// same path, so the test that pins the guard is the one that pins the tick's order.
    #[test]
    fn the_settings_window_asks_for_the_password_before_it_opens() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.yml");
        let mut settings = Settings::default();
        settings.set_password(Some("the-first-one")).unwrap();
        settings.save_to(&path).unwrap();
        let file = SettingsFile::load(path, false).unwrap();
        assert!(
            file.unlock.is_set(),
            "the run asks against the startup hash"
        );
        assert!(file.unlock.verify("the-first-one"));
        // A password changed in the file while the run lives is **not** the one this run asks
        // against: the window stays shut for somebody who did not type the one in force.
        let mut changed = settings.clone();
        changed.set_password(Some("a-new-one")).unwrap();
        changed.save_to(&file.path).unwrap();
        let mut file = file;
        file.reload().unwrap();
        assert!(
            file.unlock.verify("the-first-one"),
            "the hash in force is the startup one"
        );
        assert!(
            !file.unlock.verify("a-new-one"),
            "and not what the file says now"
        );
        // But a save **the window itself** makes replaces it: that path typed the old password.
        file.adopt(changed);
        assert!(file.unlock.verify("a-new-one"));
        assert!(!file.unlock.verify("the-first-one"));
    }

    /// A chord is **recorded once** and is what the next tick has to carry out; a second press
    /// before the first was acted on does not replace it (one press, one action).
    #[test]
    fn a_chord_is_recorded_once_and_is_what_the_tick_carries_out() {
        let ui = state();
        let keys = ui.keys();
        keys.fire(Hotkey::HideOrShow);
        assert_eq!(ui.plan(), Tick::Chord(Hotkey::HideOrShow));
        // A second, different chord before the first was carried out is not a second decision.
        keys.fire(Hotkey::HideAndOpenSettings);
        assert_eq!(ui.plan(), Tick::Chord(Hotkey::HideOrShow));
        // Acting on it clears the record, so the same key can be pressed again.
        ui.pending.lock().unwrap().take();
        assert_eq!(ui.plan(), Tick::Nothing);
        keys.fire(Hotkey::HideOrShow);
        assert_eq!(ui.plan(), Tick::Chord(Hotkey::HideOrShow));
    }

    /// `numlock + F10` asks for the settings window, and it stays asked for until a tick acts on
    /// it — which is what makes the request survive the moment it was made.
    #[test]
    fn the_settings_window_stays_asked_for_until_the_tick_takes_it() {
        let ui = state();
        ui.settings_wanted.store(true, Ordering::Relaxed);
        assert_eq!(ui.plan(), Tick::Settings);
        assert_eq!(ui.plan(), Tick::Settings);
        ui.settings_wanted.store(false, Ordering::Relaxed);
        assert_eq!(ui.plan(), Tick::Nothing);
    }

    /// A close the user asked for is the most urgent thing there is: it is what the next tick
    /// does, whatever a chord was waiting for.
    #[test]
    fn a_close_the_user_asked_for_comes_before_a_chord() {
        let ui = state();
        ui.keys().fire(Hotkey::HideOrShow);
        ui.window.request_close();
        assert_eq!(ui.plan(), Tick::Close);
        // The request is the window's until the application answers it.
        ui.window.clear_close_request();
        assert_eq!(ui.plan(), Tick::Chord(Hotkey::HideOrShow));
    }

    /// A failure is a sentence the run can read, and it is told about the change so the wait does
    /// not have to poll for it.
    #[test]
    fn a_failure_is_readable_and_announced() {
        let ui = state();
        assert!(ui.failure().is_none());
        let (lock, _) = &*ui.changed;
        let before = *lock.lock().unwrap();
        ui.fail(anyhow::anyhow!("the disk's password was not given"));
        assert_eq!(
            ui.failure().as_deref(),
            Some("the disk's password was not given")
        );
        let (lock, _) = &*ui.changed;
        assert!(
            *lock.lock().unwrap() > before,
            "the change must be visible to a waiter"
        );
    }

    /// The root disk's answer is taken **once**: a second read is `None`, so nothing can ask the
    /// same question twice.
    #[test]
    fn the_disk_answer_is_taken_exactly_once() {
        let answer = DiskAnswer::default();
        assert!(answer.take().is_none());
        answer.set(crate::diskpass::DiskPassphrase::new("hunter2"));
        assert!(answer.take().is_some());
        assert!(answer.take().is_none());
    }
}
