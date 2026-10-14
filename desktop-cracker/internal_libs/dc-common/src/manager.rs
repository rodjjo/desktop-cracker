//! The application's **controller state**: the guest's phase, the window's visibility, the
//! console's last line and the commands a window sends.
//!
//! It lives in `dc-common` because it is the one thing *everything* shares — the window,
//! the audio rule, the tray, the manager — and a library that needs it (the display, for
//! instance, to report its own visibility) cannot depend on the library that owns the
//! microVM without a cycle.  So this is the vocabulary, and the ownership is stated here:
//!
//! ```text
//! manager <----> window (GL, own thread)
//!                                          |
//!                                          +----------->  microvm (Firecracker, its API, the serial)
//! ```
//!
//! The shape that makes the window never hang: the manager holds the state and the
//! handles, the window **reads** it (atomics and a mutex held for a copy, never for work)
//! and **sends** it commands, and every long operation — starting the machine, waiting for the
//! guest, reading the serial, a password dialog, shutting down — happens on the manager's
//! side or on a thread of its own.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

/// The word a **plugin** (and `/status`) uses for a phase.
///
/// The manager's own `as_str` is for a person ("waiting for you"); the protocol has five words
/// and this is the mapping to them.
pub fn state_word(phase: Phase) -> &'static str {
    match phase {
        Phase::Idle | Phase::Booting => "booting",
        Phase::WaitingForUser => "asking",
        Phase::Running => "running",
        Phase::Stopping | Phase::Stopped => "stopping",
        Phase::Failed => "exited",
    }
}

/// What the guest is doing, as far as the manager knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    /// Nothing started yet.
    Idle,
    /// the machine is up, the guest has not reached its ready marker.
    Booting,
    /// The guest is asking the **user** something (its disk password): the boot clock is
    /// not running while this is the phase, because a person typing is not a failure.
    WaitingForUser,
    /// The guest is up.
    Running,
    /// The guest is shutting down (asked, or by itself).
    Stopping,
    /// The guest is gone.
    Stopped,
    /// The guest could not come up; the events say why.
    Failed,
}

impl Phase {
    /// Is the guest up and usable?
    pub fn is_running(self) -> bool {
        matches!(self, Phase::Running)
    }

    /// Is a person being waited for?
    pub fn is_waiting_for_user(self) -> bool {
        matches!(self, Phase::WaitingForUser)
    }

    /// The word a window puts on its status line.
    pub fn as_str(self) -> &'static str {
        match self {
            Phase::Idle => "idle",
            Phase::Booting => "booting",
            Phase::WaitingForUser => "waiting for you",
            Phase::Running => "running",
            Phase::Stopping => "stopping",
            Phase::Stopped => "stopped",
            Phase::Failed => "failed",
        }
    }
}

/// What a window asks the manager to do.  A command is a **message**, never a call that
/// waits: the window sends it and carries on drawing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Show the window (the tray's `Show`, after the password).
    ShowWindow,
    /// Hide the window (the tray's `Hide`, the window's own close button).
    HideWindow,
    /// Open the settings window.
    Settings,
    /// The window was closed / the user asked to stop.
    Quit,
    /// The user asked the guest to power off (a clean shutdown, not a kill).
    PowerOff,
    /// The user asked the guest to be killed (the last resort).
    Kill,
}

/// What a command means, as the window's answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolution {
    /// The window should be on screen.
    ShowWindow,
    /// The window should be off the screen.
    HideWindow,
    /// Open the settings window (the tray's own thread does it).
    OpenSettings,
    /// Stop the run.
    Quit,
    /// Ask the guest to power off.
    PowerOff,
    /// Kill the guest.
    Kill,
}

/// A sentence for the log (and the window's status line), with the time it happened: the
/// history, so a failure that happened while nobody was looking can still be read.
#[derive(Debug, Clone)]
pub struct Event {
    /// Milliseconds since the manager started.
    pub at_ms: u64,
    /// The phase the guest moved to, when this event is a phase change.
    pub phase: Option<Phase>,
    /// The sentence.
    pub text: String,
}

/// The state a window reads.  Every field is a value it can read **without waiting**:
/// atomics, and a mutex that is never held for more than a copy.
#[derive(Debug)]
pub struct State {
    phase: AtomicU64,
    asking: AtomicBool,
    visible: AtomicBool,
    revision: AtomicU64,
    console_lines: AtomicU64,
    last_line: std::sync::Mutex<String>,
    events: std::sync::Mutex<Vec<Event>>,
    started: std::time::Instant,
}

impl Default for State {
    fn default() -> Self {
        State::new()
    }
}

impl State {
    /// A fresh state: idle, hidden until something shows it.
    pub fn new() -> State {
        State {
            phase: AtomicU64::new(Phase::Idle as u64),
            asking: AtomicBool::new(false),
            visible: AtomicBool::new(false),
            revision: AtomicU64::new(0),
            console_lines: AtomicU64::new(0),
            last_line: std::sync::Mutex::new(String::new()),
            events: std::sync::Mutex::new(Vec::new()),
            started: std::time::Instant::now(),
        }
    }

    /// A shared state (the manager and the window both hold this).
    pub fn shared() -> Arc<State> {
        Arc::new(State::new())
    }

    /// The phase, right now.
    pub fn phase(&self) -> Phase {
        match self.phase.load(Ordering::Relaxed) {
            1 => Phase::Booting,
            2 => Phase::WaitingForUser,
            3 => Phase::Running,
            4 => Phase::Stopping,
            5 => Phase::Stopped,
            6 => Phase::Failed,
            _ => Phase::Idle,
        }
    }

    /// Is the window on screen?
    pub fn visible(&self) -> bool {
        self.visible.load(Ordering::Relaxed)
    }

    /// Is the guest asking the user for its disk password?
    pub fn asking(&self) -> bool {
        self.asking.load(Ordering::Relaxed)
    }

    /// How many lines of the guest's console have been seen.
    pub fn console_lines(&self) -> u64 {
        self.console_lines.load(Ordering::Relaxed)
    }

    /// The last line of the guest's console, for a status line.
    pub fn last_line(&self) -> String {
        self.last_line.lock().map(|s| s.clone()).unwrap_or_default()
    }

    /// How long the manager has been up, in milliseconds.
    pub fn elapsed_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    /// The events, newest last (at most `limit`).
    pub fn events(&self, limit: usize) -> Vec<Event> {
        self.events
            .lock()
            .map(|e| {
                let skip = e.len().saturating_sub(limit);
                e[skip..].to_vec()
            })
            .unwrap_or_default()
    }

    /// One sentence about what is happening, for the window's status line.
    pub fn summary(&self) -> String {
        let asking = if self.asking() { ", asking you" } else { "" };
        let line = self.last_line();
        if line.is_empty() {
            format!("{}{}", self.phase().as_str(), asking)
        } else {
            format!("{}{} — {line}", self.phase().as_str(), asking)
        }
    }
}

/// The manager's side: the state, and what a caller may change.  It is a **handle**: the
/// runner that owns the microvm holds the same `Arc<State>` and moves it along.
#[derive(Clone)]
pub struct Manager {
    state: Arc<State>,
}

impl Default for Manager {
    fn default() -> Self {
        Manager::new()
    }
}

impl Manager {
    /// A manager with a fresh state.
    pub fn new() -> Manager {
        Manager {
            state: State::shared(),
        }
    }

    /// A manager around a state someone else also holds (the application: the window
    /// reads it, the manager writes it).
    pub fn with_state(state: Arc<State>) -> Manager {
        Manager { state }
    }

    /// The state, for a reader that wants to poll it.
    pub fn state(&self) -> Arc<State> {
        Arc::clone(&self.state)
    }

    /// The guest moved to a new phase; the sentence is recorded.
    pub fn set_phase(&self, phase: Phase, note: impl Into<String>) {
        self.state.phase.store(phase as u64, Ordering::Relaxed);
        self.state
            .asking
            .store(phase == Phase::WaitingForUser, Ordering::Relaxed);
        self.record(Some(phase), note);
    }

    /// The guest is asking the user something (its disk password, at its console).
    pub fn set_asking(&self, asking: bool, note: impl Into<String>) {
        self.state.asking.store(asking, Ordering::Relaxed);
        if asking && self.state.phase() != Phase::WaitingForUser {
            self.set_phase(Phase::WaitingForUser, note);
        } else if !asking && self.state.phase() == Phase::WaitingForUser {
            self.set_phase(Phase::Booting, note);
        } else {
            self.record(None, note);
        }
    }

    /// The window was shown or hidden (the tray's `Show`/`Hide`, the window's own close).
    pub fn set_visible(&self, visible: bool) {
        if self.state.visible.swap(visible, Ordering::Relaxed) != visible {
            self.record(
                None,
                if visible {
                    "the window is on screen"
                } else {
                    "the window is hidden"
                },
            );
        }
    }

    /// A line of the guest's console went by (the manager echoes them; the status line
    /// keeps the last one).
    pub fn console_line(&self, line: &str) {
        let first = self.state.console_lines.fetch_add(1, Ordering::Relaxed) == 0;
        if first {
            // The guest's first word is worth keeping ("the console is talking"): the
            // thousands after it are not.
            self.record(None, "the guest's console is talking");
        }
        if let Ok(mut last) = self.state.last_line.lock() {
            *last = line.trim_end().to_string();
        }
    }

    /// The revision of the window's published state (the guest reads the same number
    /// through the control share: one answer to "what is the display doing?").
    pub fn publish(&self, revision: u64) {
        self.state.revision.store(revision, Ordering::Relaxed);
    }

    /// The revision the window last published.
    pub fn revision(&self) -> u64 {
        self.state.revision.load(Ordering::Relaxed)
    }

    /// Record a sentence (and, when it is a phase change, the phase).
    pub fn record(&self, phase: Option<Phase>, note: impl Into<String>) {
        let note = note.into();
        let event = Event {
            at_ms: self.state.elapsed_ms(),
            phase,
            text: note.clone(),
        };
        if let Ok(mut events) = self.state.events.lock() {
            events.push(event);
            if events.len() > 512 {
                events.drain(..256);
            }
        }
        // The phase moving is the run's **state** as far as anything outside is concerned: the
        // window's status line reads it here, and a plugin gets it as a `state` event (with no
        // plugin this is one atomic load and a return).
        if let Some(phase) = phase {
            dc_plugin::state(state_word(phase));
        }
    }

    /// A command from the window: resolve it into what it means.
    ///
    /// It answers immediately — the window is drawing — and the caller acts on the
    /// answer.  Nothing here starts a boot, waits for a machine or talks to the guest: those
    /// are the runner's, on their own threads.
    pub fn handle(&self, command: Command) -> Resolution {
        match command {
            Command::ShowWindow => {
                self.set_visible(true);
                Resolution::ShowWindow
            }
            Command::HideWindow => {
                self.set_visible(false);
                Resolution::HideWindow
            }
            Command::Settings => Resolution::OpenSettings,
            Command::Quit => {
                self.set_phase(Phase::Stopping, "the user asked to quit");
                Resolution::Quit
            }
            Command::PowerOff => {
                self.set_phase(Phase::Stopping, "the guest was asked to power off");
                Resolution::PowerOff
            }
            Command::Kill => {
                self.set_phase(Phase::Stopped, "the guest was killed");
                Resolution::Kill
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fresh_manager_is_idle_and_hidden() {
        let m = Manager::new();
        assert_eq!(m.state().phase(), Phase::Idle);
        assert!(!m.state().visible());
        assert!(!m.state().asking());
        assert_eq!(m.state().console_lines(), 0);
    }

    #[test]
    fn the_guest_asking_for_its_password_is_a_phase_of_its_own() {
        // The distinction the boot clock depends on: a guest waiting for a person is not
        // a boot that is going nowhere.
        let m = Manager::new();
        m.set_phase(Phase::Booting, "the microVM is up");
        assert!(!m.state().phase().is_waiting_for_user());
        m.set_asking(true, "the guest is asking for its disk password");
        assert_eq!(m.state().phase(), Phase::WaitingForUser);
        assert!(m.state().asking());
        m.set_asking(false, "the password was answered");
        assert_eq!(m.state().phase(), Phase::Booting);
        assert!(!m.state().asking());
    }

    #[test]
    fn a_command_is_answered_without_waiting_for_anything() {
        // The window sends a command and carries on drawing: every one of these returns
        // immediately, and the state it changed is readable at once.
        let m = Manager::new();
        assert_eq!(m.handle(Command::ShowWindow), Resolution::ShowWindow);
        assert!(m.state().visible());
        assert_eq!(m.handle(Command::HideWindow), Resolution::HideWindow);
        assert!(!m.state().visible());
        assert_eq!(m.handle(Command::Quit), Resolution::Quit);
        assert_eq!(m.state().phase(), Phase::Stopping);
    }

    #[test]
    fn the_console_and_the_events_are_what_a_window_needs() {
        let m = Manager::new();
        m.console_line("DESK-READY initramfs MemTotal=…");
        m.console_line("DESK-ROOT root disk /dev/vda (ro)");
        assert_eq!(m.state().console_lines(), 2);
        assert!(m.state().last_line().contains("DESK-ROOT"));
        assert!(m.state().summary().contains("DESK-ROOT"));
        let events = m.state().events(8);
        assert!(!events.is_empty());
        assert!(events.last().unwrap().at_ms <= m.state().elapsed_ms());
    }

    #[test]
    fn the_published_revision_is_one_answer_for_two_readers() {
        // The window publishes the state the guest reads (through the control share): the
        // manager keeps the number, so a reader of either side sees the same one.
        let m = Manager::new();
        assert_eq!(m.revision(), 0);
        m.publish(7);
        assert_eq!(m.revision(), 7);
    }
}
