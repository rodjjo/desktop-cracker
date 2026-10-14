//! What the **window's keys** do.
//!
//! Display: — the operator's own words:
//!
//! > Lets detect keys globally even when the window is not in focus: numlock pressed + F9
//! > (hides the display window, or if the display window is already hidden ask password to
//! > show the display window again); numlock pressed + F10 (hide the window and show the
//! > settings window, after settings window disappear ask password to show the display window
//! > again).
//!
//! The chords themselves are read from the host's keyboard by the display loop
//! (`dc_display::display_loop`, 30 times a second, on the thread running the GTK main loop).
//! This module is the other half: **what a chord means**.
//!
//! Two rules shape it, and both come from GTK belonging to one thread:
//!
//! * a chord **only records what it means** (`HotkeySink::fire`): the keyboard is read inside the
//!   loop, and a dialog asked there would be a dialog inside the callback that reads the keyboard;
//! * the work — the password question, the settings window, a hide — happens on the **UI thread**
//!   as well, but on the loop's own tick (`crate::ui::UiState::work`), which is where a question
//!   can be asked and answered without holding anything up.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use dc_display::window::WindowControl;
use dc_display::xinput::Hotkey;
use dc_settings::{Settings, Unlock};

/// **The settings file, as this run holds it**: the path, what was read from it
/// at startup, and the settings **in force** — which change the moment the window saves, so a window
/// opened again in the same run shows what was saved and a run that reads them later reads the new
/// ones.
///
/// The `Unlock` is kept here for one reason, and it is a security rule rather than a convenience
/// (the operator, 2026-10-13): **a password read at startup keeps guarding the window even if the
/// file is changed while the run lives.**  Somebody who could not open the window must not be able
/// to open it by writing a new password into the file and asking again — so the hash this run asks
/// against is the one it started with, and a password the *window itself* saves replaces it, because
/// that path went through the question first.
#[derive(Clone)]
pub struct SettingsFile {
    pub path: std::path::PathBuf,
    /// What the file held when this run started (the fallback for an explicit `None`).
    pub startup: Settings,
    /// What is in force now: the file's values, or the ones the window saved.
    pub live: Settings,
    /// The password this run asks against (see the note above).
    pub unlock: Unlock,
}

impl SettingsFile {
    /// Read the file at startup: what is on disk is what is in force, and the password in it is the
    /// one this run asks against.
    pub fn load(path: std::path::PathBuf, create: bool) -> dc_settings::Result<SettingsFile> {
        let startup = Settings::load_from(&path, create)?;
        Ok(SettingsFile {
            path,
            live: startup.clone(),
            unlock: Unlock::load(&startup),
            startup,
        })
    }

    /// **Read the file again**, keeping the password this run asks against: what a run should see
    /// when the settings changed underneath it.  A file that cannot be read leaves what is in force
    /// alone (and says so in the sentence it returns).
    pub fn reload(&mut self) -> dc_settings::Result<()> {
        self.live = Settings::load_from(&self.path, false)?;
        Ok(())
    }

    /// **Take the settings the window saved**: they are in force at once, the file already holds
    /// them, and a password the window set is the one this run now asks against — that path went
    /// through the question, which is what makes it safe to prefer over the startup hash.
    pub fn adopt(&mut self, saved: Settings) {
        self.live = saved;
        self.unlock = Unlock::load(&self.live);
    }

    /// A copy of the keys for one chord (they share the same `Arc`s, so a change made through one is
    /// a change to all of them).
    pub fn keys(
        &self,
        window: &Arc<WindowControl>,
        settings_wanted: &Arc<AtomicBool>,
        pending: &Arc<Mutex<Option<Hotkey>>>,
    ) -> WindowKeys {
        WindowKeys {
            window: Arc::clone(window),
            file: self.clone(),
            settings_wanted: Arc::clone(settings_wanted),
            pending: Arc::clone(pending),
        }
    }
}

/// The keys, as the application holds them: the window's control and what is needed to ask.
///
/// `fire` records the chord and returns; `act` carries it out, and everything it needs (a dialog a
/// person can type into, the settings in force) is available **exactly because it runs on the UI
/// thread**.
pub struct WindowKeys {
    pub window: Arc<WindowControl>,
    /// The settings file this run holds — the `Arc<Mutex<..>>` shared with the application, so a save
    /// the window makes is a save every reader sees.
    pub file: SettingsFile,
    /// Set by `numlock + F10`: the UI thread opens the settings window on its next tick.
    pub settings_wanted: Arc<AtomicBool>,
    /// The chord that was pressed and not yet acted on: **the only thing `fire` writes**, so the
    /// reader of the keyboard is never held up by a question.
    pub pending: Arc<Mutex<Option<Hotkey>>>,
}

impl dc_display::window::HotkeySink for WindowKeys {
    /// A chord was pressed.  **This returns at once**: the key loop is what draws the window, and
    /// the meaning of the chord (a question, the settings window) is carried out by the UI thread
    /// on its own tick (see `crate::ui::UiState::work`).
    fn fire(&self, hotkey: Hotkey) {
        if let Ok(mut pending) = self.pending.lock() {
            // One chord at a time: a second press before the first was acted on is the same
            // decision, and asking twice for one key is not what a user meant.
            if pending.is_none() {
                *pending = Some(hotkey);
            }
        }
    }
}

impl WindowKeys {
    /// The chord has been acted on (or was dropped): the record is cleared, so the same chord can
    /// be pressed again.
    pub fn clear_pending(&self) {
        if let Ok(mut pending) = self.pending.lock() {
            *pending = None;
        }
    }

    pub fn act(
        &self,
        hotkey: Hotkey,
        parent: Option<&dc_dialog::Parent>,
    ) -> Result<String, String> {
        match hotkey {
            Hotkey::HideOrShow => self.hide_or_show(parent),
            Hotkey::HideAndOpenSettings => self.hide_and_open_settings(parent),
        }
    }

    /// `numlock + F9`: hide the window, or ask for the password and show it again.
    fn hide_or_show(&self, parent: Option<&dc_dialog::Parent>) -> Result<String, String> {
        if !self.window.is_hidden() {
            // The window is on screen: the key **hides** it, and nothing else is asked.
            self.window.set_visible(false);
            return Ok("hidden (numlock + F9)".into());
        }
        let asked = self.ask_for_password(parent);
        if asked {
            self.window.set_visible(true);
            Ok("the password was right: the window is shown".into())
        } else {
            Err("the window stays hidden (no password, or the wrong one)".into())
        }
    }

    /// `numlock + F10`: hide the window, open the settings, and when they close ask for the
    /// password and show the window again.
    ///
    /// **The password comes first when one is in force** (the operator, 2026-10-13): the settings
    /// are where the password itself is changed, so a person who cannot open the window must not be
    /// able to change the password either.  With no password set there is nothing to ask, and the
    /// window opens — and the save on that path sets the first password, which this run then asks
    /// against (the hash a save adopts is the one the saver typed the old password for).
    fn hide_and_open_settings(&self, parent: Option<&dc_dialog::Parent>) -> Result<String, String> {
        if self.file.unlock.is_set() && !self.ask_for_password(parent) {
            return Err(
                "the settings window stays closed: the unlock password was not given".into(),
            );
        }
        self.window.set_visible(false);
        // The settings window is opened by the UI thread on its next tick (it is modal, so
        // opening it here would be opening it inside the callback that read the key): all this
        // does is ask for it.
        self.settings_wanted.store(true, Ordering::Relaxed);
        Ok("hidden, and the settings window was asked for (numlock + F10)".into())
    }

    /// The unlock question: asked **every time** (the password is loaded when the application
    /// starts and is never remembered between shows).
    ///
    /// It is asked on the UI thread, and the dialog is transient for `parent` — the display
    /// window — so it appears over the guest's screen.
    pub fn ask_for_password(&self, parent: Option<&dc_dialog::Parent>) -> bool {
        if !self.file.unlock.is_set() {
            // No password: there is nothing to protect the window with, so it is shown and the
            // user is told how to set one.
            let _ = dc_dialog::message_with_parent(
                parent,
                dc_common::APP_NAME,
                "No unlock password is set, so the window cannot be protected when it is \
                 hidden.\n\nSet one in the settings window: it takes effect at once, because this \
                 run adopts the password the window saves.",
            );
            self.settings_wanted.store(true, Ordering::Relaxed);
            return true;
        }
        self.file.unlock.ask_until_correct(3, |attempt| {
            let prompt = if attempt > 1 {
                format!("Unlock password (attempt {attempt} of 3):")
            } else {
                "Unlock password:".to_string()
            };
            // **The plugin first**, exactly as the disk's password is asked: a client that
            // answers answers it as a person would, and a plugin with no client answers "no
            // answer" — which is what puts the dialog on
            // screen, and gives a person as long as they like to type.  The kind is the protocol's
            // `unlock-password`, so a client knows which secret it is being asked for.
            match dc_dialog::password_question(dc_dialog::Question::new(
                dc_dialog::Kind::UnlockPassword,
                &prompt,
                "The window is hidden; it is shown again when the password is right.",
            )) {
                Some(answer) => Some(answer),
                None => dc_dialog::password_with_parent(parent, dc_common::APP_NAME, &prompt),
            }
        })
    }
}

/// Ask the user what closing the window means, in **one dialog with three buttons**.
///
/// Closing the window: "closing the window, it just ask permission to close the
/// application then it close".  The operator's own words (2026-10-09) name the three answers:
///
/// > We do not need two question when we close the window we need one dialog with three buttons:
/// > Close - Just terminate the application; Hide - Hide the application (that returns by pressing
/// > numlock+f9, like we do currently); Cancel - Does nothing just keep the display window running.
///
/// It used to be two questions in a row, which is what made the answers wrong: somebody who
/// answered "Keep running" was asked a second question they had not asked for, and answering that
/// left the window in a state that did not work.  One dialog, three buttons, one answer.
///
/// **The window is hidden before this is asked** (the operator, 2026-10-13, and this project's own
/// order): the caller hides it first, so this question is the only window in front — and the
/// **Keep hidden** button (the old *Hide*, under the name that says what it does) is the answer
/// that is already true when it is given.  *Cancel* is the one that asks something back: it shows
/// the window again, past the unlock password.
///
/// **A question the plugin answers is answered here too**: the
/// protocol's `confirm` is a yes/no, so a client's "yes" is *Close* and its "no" is *Cancel* —
/// what it cannot say is *Keep hidden*, and a client that wants that answers "no answer" and the
/// dialog is put up for the person.
pub fn ask_to_close(parent: Option<&dc_dialog::Parent>) -> CloseAnswer {
    let question = dc_dialog::Question::new(
        dc_dialog::Kind::Confirm,
        "Close the application?",
        "The window is hidden, and the virtual machine is still running.\n\n\
         Close shuts the virtual machine down and exits.  Keep hidden leaves the window away and \
         the virtual machine running; numlock + F9 brings it back.  Cancel shows the window again, \
         and asks for the unlock password to do it.",
    );
    if let Some(choice) = dc_dialog::choose_question(question) {
        return CloseAnswer::from(choice);
    }
    CloseAnswer::from(dc_dialog::choose_with_parent(
        parent,
        dc_common::APP_NAME,
        &format!("{}\n\n{}", question.prompt, question.detail),
    ))
}

/// What the user answered when the window was closed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseAnswer {
    /// Shut the machine down and exit.
    Close,
    /// **The window stays hidden** (it is hidden already) and the guest keeps running.
    Hide,
    /// Nothing was meant by the click: the window comes back, past the unlock password.
    Cancel,
}

impl From<dc_dialog::Choice> for CloseAnswer {
    fn from(choice: dc_dialog::Choice) -> CloseAnswer {
        match choice {
            dc_dialog::Choice::Close => CloseAnswer::Close,
            dc_dialog::Choice::Hide => CloseAnswer::Hide,
            dc_dialog::Choice::Cancel => CloseAnswer::Cancel,
        }
    }
}

/// Open the settings window and save what the user edited.  **On the UI thread** (see the
/// module's note).
///
/// **What the window shows is what is in force**, not what the file said at startup: a window opened
/// a second time in the same run shows the settings the first one saved (the operator, 2026-10-13:
/// "we can reload the configuration as soon as they are saved, so when we open the dialog again
/// without closing the application, the updated setting is going to be there").
///
/// **The cancel click writes nothing**: `SettingsWindow::draft()` is the values only when Save was
/// pressed, and an untouched window returns exactly what it was given — so a dismissed window cannot
/// change a setting, and a `reload` that found a file somebody edited by hand is not undone by it.
pub fn open_settings(file: &mut SettingsFile) -> Result<(), String> {
    let window = dc_settings_window::SettingsWindow::new(file.live.clone());
    window.open()?;
    let draft = window.draft();
    if !draft.was_saved() {
        return Err("the settings window was closed without saving".into());
    }
    let edited = draft
        .to_settings(&file.live)
        .map_err(|e| format!("the settings are not valid: {e}"))?;
    if edited == file.live {
        return Ok(());
    }
    edited
        .save_to(&file.path)
        .map_err(|e| format!("the settings could not be written: {e}"))?;
    // **In force at once**, and the password the window set is the one this run asks against from
    // here on (that path went through the question).
    file.adopt(edited);
    Ok(())
}
