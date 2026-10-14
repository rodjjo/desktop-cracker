//! The unlock password, as it is used while the application runs.
//!
//! Password: //!
//! > To protect and prevent from unwanted access when the window is hidden it
//! > only can be shown when the user click on show window menu at system tray
//! > icon, this password is loaded when the application is loaded so, if the
//! > user edits the settings directly adding a new password it only will have
//! > effect after opening the window next time.
//!
//! That "loaded when the application is loaded" is the whole behaviour of this
//! type: it takes a **copy** of the hash at startup and never looks at the file
//! again, so an edit made while the application runs changes nothing until the
//! next launch.

use crate::Settings;

/// The password in force for this run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unlock {
    /// The hash loaded at startup, or `None` when the user has no password.
    hash: Option<String>,
}

impl Unlock {
    /// Snapshot the settings as they are now.
    pub fn load(settings: &Settings) -> Unlock {
        Unlock {
            hash: settings
                .unlock_password
                .as_ref()
                .filter(|h| !h.is_empty())
                .cloned(),
        }
    }

    /// Is a password in force?  When not, the window can be shown without
    /// asking anything.
    pub fn is_set(&self) -> bool {
        self.hash.is_some()
    }

    /// Check a password against the hash loaded at startup.
    pub fn verify(&self, plaintext: &str) -> bool {
        match &self.hash {
            Some(h) => crate::verify_password(h, plaintext),
            None => true, // no password: everything opens the window
        }
    }

    /// Ask for the password until it is right, or give up after `tries`.
    ///
    /// `ask` returns `None` when the user cancelled: that is a refusal, not a
    /// retry, because a cancelled password prompt must never open the window.
    pub fn ask_until_correct(
        &self,
        tries: u32,
        mut ask: impl FnMut(u32) -> Option<String>,
    ) -> bool {
        if !self.is_set() {
            return true;
        }
        for attempt in 1..=tries {
            match ask(attempt) {
                Some(p) if self.verify(&p) => return true,
                Some(_) => continue,
                None => return false,
            }
        }
        false
    }

    /// A description for the log: never the hash itself.
    pub fn describe(&self) -> &'static str {
        if self.is_set() {
            "unlock password set (loaded at startup)"
        } else {
            "no unlock password"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Settings;

    #[test]
    fn a_settings_edit_during_the_run_has_no_effect() {
        let mut settings = Settings::default();
        settings.set_password(Some("first")).unwrap();
        let unlock = Unlock::load(&settings);
        assert!(unlock.is_set());
        assert!(unlock.verify("first"));

        // the user edits the file while the application runs...
        settings.set_password(Some("second")).unwrap();
        // ...and the running application still asks for the old one
        assert!(unlock.verify("first"));
        assert!(!unlock.verify("second"));

        // ...until the next start, which loads it again
        let next = Unlock::load(&settings);
        assert!(next.verify("second"));
        assert!(!next.verify("first"));
    }

    #[test]
    fn no_password_means_everything_opens_the_window() {
        let unlock = Unlock::load(&Settings::default());
        assert!(!unlock.is_set());
        assert!(unlock.verify(""));
        assert!(unlock.verify("anything"));
        assert!(unlock.ask_until_correct(3, |_| None));
        assert_eq!(unlock.describe(), "no unlock password");
    }

    #[test]
    fn asking_retries_and_a_cancel_refuses() {
        let mut settings = Settings::default();
        settings.set_password(Some("right")).unwrap();
        let unlock = Unlock::load(&settings);

        let mut answers = vec!["wrong", "also wrong", "right"].into_iter();
        assert!(unlock.ask_until_correct(3, |_| answers.next().map(String::from)));

        let mut answers = vec!["wrong", "still wrong"].into_iter();
        assert!(!unlock.ask_until_correct(2, |_| answers.next().map(String::from)));

        // cancelling on the first prompt refuses immediately
        assert!(!unlock.ask_until_correct(5, |_| None));
    }

    #[test]
    fn an_empty_password_in_the_file_is_the_same_as_none() {
        let settings = Settings {
            unlock_password: Some(String::new()),
            ..Settings::default()
        };
        let unlock = Unlock::load(&settings);
        assert!(!unlock.is_set());
    }
}
