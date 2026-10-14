//! **What the application asks and what its keys mean** — the half of the application that is
//! *not* about which hypervisor runs the guest.
//!
//! Everything here is the application's own: the questions a run asks and the chords the window
//! answers.  It is a crate of its own because more than one program needs them — the application
//! questions, hide and show the same window, mean the same chords and read the same settings.  A
//! second copy of any of it would be a second answer to "what does `numlock + F9` do", which is
//! exactly the kind of drift this project must not introduce.
//!
//! Four modules, and each is the project's own code moved without a change of behaviour:
//!
//! * [`diskpass`] — the root disk's passphrase: asked once, kept only in memory (a
//!   `Zeroizing` buffer), never a file, never an argument, never the environment;
//! * [`hotkeys`] — what a chord means: `numlock + F9` hides or asks the unlock password,
//!   `numlock + F10` hides and opens the settings, and closing the window asks **one** question
//!   with three answers (`Close`/`Hide`/`Cancel`);
//! * [`ui`] — the application's side of the **one UI thread**: what one tick has to do, decided
//!   without touching GTK and carried out where a dialog is safe;
//! * [`prompt`] — the terminal names for the questions `dc-dialog` asks.
//!
//! The seam that makes this legal: an application passes its own **`ask`** closure
//! ([`ui::Asks`]), which is how the machine this project started with hands the disk's question to its `diskpass` and how
//! the Firecracker path hands it to `dc-fc-control`'s channel — the dialog and the decision above
//! it are the same code.

pub mod diskpass;
pub mod hotkeys;
pub mod prompt;
pub mod ui;

/// What the run does with the answer to the disk's question.
///
/// It is a closure rather than a value because the question is asked **on the UI thread** while
/// the run waits for it, and because the two backends put the answer in different places (the machine's
/// `-object secret`, or the run's control share).  What is *not* different is the question, the
/// retries, the plugin's own path through it, and the fact that the answer never becomes a file.
pub type Ask = std::sync::Arc<dyn Fn() -> anyhow::Result<String> + Send + Sync>;
