//! **The plugin's state**: the events it has seen, the clients it is feeding, the questions the
//! application is waiting on, and the two things it pulls from the run.
//!
//! Everything is memory and a socket. The design is explicit that the plugin writes
//! **nothing** — no log file, no frame on disk, no passphrase — and that a password lives only
//! for the question that produced it.
//!
//! One place publishes an event: [`Shared::publish`].  It numbers it, keeps it for a client that
//! asks for the backlog (`GET /events?since=SEQ`) and fans it out to the sockets.  Nothing else
//! may send, so the sequence numbers and the two paths can never disagree.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::SyncSender;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use dc_plugin::{FrameInfo, PinningInfo, RunStatus};
use serde_json::{json, Value};

/// The protocol version a **client** speaks. The ABI in
/// `dc-plugin` is the separate thing the two binaries speak to each other.
pub const PROTOCOL: u32 = 1;

/// How long a question waits for the first client **after** the wait-for-client hook returned.
///
/// Nothing: by the time the application asks its first question, the plugin's own
/// [`Shared::wait_for_first_client`] has already waited for a client (or given up because the run
/// is ending), so a question with no client at all is answered "no answer" at once and the
/// application puts up its own dialog.
pub const NO_WAIT: Duration = Duration::from_millis(0);

/// What the application is doing, as `/status` reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum State {
    #[default]
    Booting,
    Asking,
    Running,
    Stopping,
    Exited,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Booting => "booting",
            State::Asking => "asking",
            State::Running => "running",
            State::Stopping => "stopping",
            State::Exited => "exited",
        }
    }

    /// The word the application sent, as a state (unknown words are the caller's default).
    pub fn parse(text: &str) -> Option<State> {
        [
            State::Booting,
            State::Asking,
            State::Running,
            State::Stopping,
            State::Exited,
        ]
        .into_iter()
        .find(|s| s.as_str() == text)
    }
}

/// What a client answered to a question.
///
/// `Debug` is written by hand and **hides the password**: an accidental `{:?}` must not be able
/// to put a credential on a console or in an event.
#[derive(Clone)]
pub enum Answer {
    /// A password: zeroized when it is dropped, and never recorded anywhere.
    Password(zeroize::Zeroizing<String>),
    Confirm(bool),
}

impl std::fmt::Debug for Answer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Answer::Password(_) => f.write_str("Answer::Password(<hidden>)"),
            Answer::Confirm(yes) => write!(f, "Answer::Confirm({yes})"),
        }
    }
}

/// The one question in flight, if any.
///
/// The application asks one at a time (two dialogs on screen at once is something it never
/// does), so one is all there is.
struct Pending {
    id: u64,
    answer: Option<Answer>,
}

#[derive(Default)]
struct Questions {
    pending: Option<Pending>,
    next: u64,
    /// Whether a client has ever connected: with none, a question is answered "no answer" **at
    /// once**, rather than waiting for a client that may never come.
    have_client: bool,
}

/// The plugin's whole state.
pub struct Shared {
    seq: AtomicU64,
    /// Events dropped because a slow client's queue was full (reported in `/status`).
    dropped: AtomicU64,
    /// The sockets to fan out to, one per connected client.
    clients: Mutex<Vec<SyncSender<Value>>>,
    questions: Mutex<Questions>,
    answered: Condvar,
    state: Mutex<State>,
    /// The application's counters, for `/status`.
    status: Mutex<Option<extern "C" fn(*mut RunStatus) -> std::os::raw::c_int>>,
    /// The screen hook: the application copies the frame it is about to draw.
    frame: Mutex<Option<extern "C" fn(*mut u8, usize, *mut FrameInfo) -> usize>>,
    /// Set when the plugin is shutting down: every waiter gives up, nothing new is served.
    stopping: AtomicBool,
    /// Running one of the window's **own** actions, which the application offered as a callback.
    run: Mutex<Option<extern "C" fn(*const std::os::raw::c_char) -> std::os::raw::c_int>>,
    /// Where the application pinned the microVM's vCPUs (see `dc_plugin::PinningInfo`).
    pinning: Mutex<Option<extern "C" fn(*mut PinningInfo) -> std::os::raw::c_int>>,
}

impl Default for Shared {
    fn default() -> Self {
        Shared {
            seq: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
            clients: Mutex::new(Vec::new()),
            questions: Mutex::new(Questions::default()),
            answered: Condvar::new(),
            state: Mutex::new(State::Booting),
            status: Mutex::new(None),
            frame: Mutex::new(None),
            stopping: AtomicBool::new(false),
            run: Mutex::new(None),
            pinning: Mutex::new(None),
        }
    }
}

impl Shared {
    pub fn new() -> Arc<Shared> {
        Arc::new(Shared::default())
    }

    /// **Wait until the first client connects** — the plugin's own patience, spent in the hook the
    /// application calls once right after loading it.
    ///
    /// It waits **for as long as it takes**.  The application asks its first question (the root
    /// disk's passphrase) within milliseconds of loading the plugin, and a client needs the port to
    /// be listening: a run started with `--plugin-path` therefore waits here until whoever is
    /// driving the run connects.  The waiting is the *plugin's*, so the application has no sleep
    /// and no timeout of its own — and a run **without** a plugin never reaches this code.
    ///
    /// It also returns when the plugin is shutting down, so a run that is ending is never held.
    pub fn wait_for_first_client(&self) {
        loop {
            if self.stopping.load(Ordering::Relaxed) {
                return;
            }
            if self
                .questions
                .lock()
                .map(|q| q.have_client)
                .unwrap_or(false)
            {
                return;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Is a client connected?  (A question with none is answered "no answer" at once; the waiting
    /// happened once, in `wait_for_first_client`.)
    pub fn have_client(&self) -> bool {
        self.questions
            .lock()
            .map(|q| q.have_client)
            .unwrap_or(false)
    }

    // ---------------------------------------------------------------- publishing

    /// **The one place an event is sent.**  It gets its sequence number and goes to the client;
    /// nothing is kept.  A client whose queue is full is dropped (and counted): the application is
    /// never delayed by one.
    pub fn publish(&self, mut event: Value) -> u64 {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed) + 1;
        if let Some(object) = event.as_object_mut() {
            object.insert("seq".into(), json!(seq));
        }
        let mut clients = self.clients.lock().unwrap_or_else(|e| e.into_inner());
        let mut alive = Vec::with_capacity(clients.len());
        for client in clients.drain(..) {
            match client.try_send(event.clone()) {
                Ok(()) => alive.push(client),
                Err(std::sync::mpsc::TrySendError::Full(_)) => {
                    self.dropped.fetch_add(1, Ordering::Relaxed);
                }
                Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {}
            }
        }
        *clients = alive;
        seq
    }

    /// A milestone line the application wrote.
    pub fn log(&self, level: &str, message: &str) -> u64 {
        self.publish(json!({"event": "log", "level": level, "message": message}))
    }

    /// The run's state changed.
    pub fn set_state(&self, state: State) -> u64 {
        if let Ok(mut current) = self.state.lock() {
            *current = state;
        }
        self.publish(json!({"event": "state", "state": state.as_str()}))
    }

    /// A new frame is ready.
    pub fn frame_ready(&self) -> u64 {
        self.publish(json!({"event": "frame"}))
    }

    /// The application is **waiting** for this answer.  The prompt and the detail are what the
    /// dialog would have shown; an answer is never part of an event.
    pub fn question(&self, id: u64, kind: &str, prompt: &str, detail: &str) -> u64 {
        self.publish(json!({
            "event": "question",
            "id": id.to_string(),
            "kind": kind,
            "prompt": prompt,
            "detail": detail,
        }))
    }

    /// The welcome line, for a client that has just connected.
    pub fn hello(&self) -> Value {
        json!({
            "event": "hello",
            "seq": self.seq.load(Ordering::Relaxed),
            "protocol": PROTOCOL,
        })
    }

    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    // ---------------------------------------------------------------- clients

    /// **The** client: the plugin serves exactly one — whoever connects first.
    ///
    /// A plugin exists so a *test* can drive the application from the outside
    ///: one client is all there is to serve, and a second one is
    /// refused rather than served beside it, so "who answers the questions" is never a race.
    pub fn has_client(&self) -> bool {
        self.questions
            .lock()
            .map(|q| q.have_client)
            .unwrap_or(false)
    }

    /// Register the client and send it the welcome line.
    pub fn add_client(&self, tx: SyncSender<Value>) {
        let hello = self.hello();
        let _ = tx.try_send(hello);
        let mut clients = self.clients.lock().unwrap_or_else(|e| e.into_inner());
        clients.push(tx);
        drop(clients);
        if let Ok(mut q) = self.questions.lock() {
            q.have_client = true;
        }
    }

    // ---------------------------------------------------------------- questions

    /// **Ask, and wait.**  `None` is "no answer": nobody to ask, the client said so, or the
    /// plugin is shutting down.  The application then does what it always does — the dialog, and
    /// the user's own unbounded time.
    pub fn ask(&self, kind: &str, prompt: &str, detail: &str) -> Option<Answer> {
        if self.stopping.load(Ordering::Relaxed) {
            return None;
        }
        let (id, wait) = {
            let mut q = self.questions.lock().unwrap_or_else(|e| e.into_inner());
            if !q.have_client {
                return None;
            }
            q.next += 1;
            let id = q.next;
            q.pending = Some(Pending { id, answer: None });
            (id, true)
        };
        if wait {
            self.question(id, kind, prompt, detail);
        }

        let mut q = self.questions.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if self.stopping.load(Ordering::Relaxed) {
                q.pending = None;
                return None;
            }
            match &mut q.pending {
                Some(pending) if pending.id == id => {
                    if pending.answer.is_some() {
                        let answer = pending.answer.take();
                        q.pending = None;
                        return answer;
                    }
                }
                // Somebody else's question, or none: this caller's question is over.
                _ => return None,
            }
            q = self
                .answered
                .wait_timeout(q, Duration::from_millis(200))
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
    }

    /// Take an answer from a client.  An answer to something that is not pending (a stale one, or
    /// one from a client that is not the first) is ignored.
    pub fn answer(&self, id: u64, answer: Option<Answer>) {
        let mut q = self.questions.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(pending) = &mut q.pending {
            if pending.id == id {
                pending.answer = Some(answer.unwrap_or(Answer::Confirm(false)));
                self.answered.notify_all();
            }
        }
    }

    /// Is the application waiting for an answer?  (For `/status` — never the answer itself.)
    pub fn waiting(&self) -> bool {
        self.questions
            .lock()
            .map(|q| q.pending.is_some())
            .unwrap_or(false)
    }

    pub fn state(&self) -> State {
        self.state.lock().map(|s| *s).unwrap_or_default()
    }

    // ---------------------------------------------------------------- what it pulls from the run

    /// The application offers these two; with neither, `/status` reports zeros and `/frame`
    /// answers `409`.
    pub fn offer(
        &self,
        status: Option<extern "C" fn(*mut RunStatus) -> std::os::raw::c_int>,
        frame: Option<extern "C" fn(*mut u8, usize, *mut FrameInfo) -> usize>,
        run: Option<extern "C" fn(*const std::os::raw::c_char) -> std::os::raw::c_int>,
    ) {
        if let Ok(mut slot) = self.status.lock() {
            *slot = status;
        }
        if let Ok(mut slot) = self.frame.lock() {
            *slot = frame;
        }
        if let Ok(mut slot) = self.run.lock() {
            *slot = run;
        }
    }

    /// The application offers this one alongside the others (see `offer`).
    pub fn offer_pinning(
        &self,
        pinning: Option<extern "C" fn(*mut PinningInfo) -> std::os::raw::c_int>,
    ) {
        if let Ok(mut slot) = self.pinning.lock() {
            *slot = pinning;
        }
    }

    /// **Where the microVM's vCPUs are pinned**, as the application reports it.  `None` when
    /// there is no hook (a run without a plugin, or an application that does not offer it).
    pub fn pull_pinning(&self) -> Option<PinningInfo> {
        let pull = self.pinning.lock().ok().and_then(|p| *p)?;
        let mut info = PinningInfo::default();
        if pull(&mut info) == 0 {
            Some(info)
        } else {
            None
        }
    }

    /// **Run one of the window's own actions** by name, through the application.  `None` when
    /// there is no application to ask (no hook, or a name the application does not know is a
    /// `Some(1)` — the distinction this project's three answers make).
    pub fn run_action(&self, name: &str) -> Option<std::os::raw::c_int> {
        let run = self.run.lock().ok().and_then(|r| *r)?;
        let name = std::ffi::CString::new(name).ok()?;
        Some(run(name.as_ptr()))
    }

    /// The run's counters, as the application reports them.
    pub fn counters(&self) -> RunStatus {
        let pull = self.status.lock().ok().and_then(|s| *s);
        match pull {
            Some(pull) => {
                let mut status = RunStatus::default();
                if pull(&mut status) == 0 {
                    status
                } else {
                    RunStatus::default()
                }
            }
            None => RunStatus::default(),
        }
    }

    /// Copy the frame the window is about to draw into `out`.  Returns the size it needs (0 when
    /// there is nothing to read yet), so a caller asks once with nothing and then with enough.
    pub fn pull_frame(&self, out: *mut u8, cap: usize, info: *mut FrameInfo) -> usize {
        let pull = self.frame.lock().ok().and_then(|f| *f);
        match pull {
            Some(pull) => pull(out, cap, info),
            None => 0,
        }
    }

    /// The two hooks themselves, for a caller that wants to know whether they are there (the
    /// tests do; `/status` uses `counters`).
    pub fn status_pull(&self) -> Option<extern "C" fn(*mut RunStatus) -> std::os::raw::c_int> {
        self.status.lock().ok().and_then(|s| *s)
    }

    pub fn frame_hook(&self) -> Option<extern "C" fn(*mut u8, usize, *mut FrameInfo) -> usize> {
        self.frame.lock().ok().and_then(|f| *f)
    }

    // ---------------------------------------------------------------- shutting down

    /// The run is ending: every waiter gives up and nothing new is served.
    pub fn stop(&self) {
        self.stopping.store(true, Ordering::Relaxed);
        self.answered.notify_all();
    }

    pub fn stopping(&self) -> bool {
        self.stopping.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_event_gets_its_own_number() {
        // The number is what lets a client notice it missed one; **nothing is kept** for it to
        // ask for later (see the plugin's rules: no history, no file, no log).
        let shared = Shared::new();
        assert_eq!(shared.log("info", "one"), 1);
        assert_eq!(shared.set_state(State::Running), 2);
        assert_eq!(shared.frame_ready(), 3);
        assert_eq!(shared.hello()["seq"], 3);
    }

    #[test]
    fn a_question_is_never_sent_with_an_answer() {
        let shared = Shared::new();
        let (tx, rx) = std::sync::mpsc::sync_channel(8);
        shared.add_client(tx);
        assert_eq!(rx.try_recv().unwrap()["event"], "hello");
        shared.question(7, "disk-password", "Root disk password:", "");
        let event = rx.try_recv().unwrap();
        assert_eq!(event["event"], "question");
        assert_eq!(event["id"], "7");
        assert!(event.get("answer").is_none());
    }

    #[test]
    fn a_question_with_no_client_is_answered_at_once() {
        // The property that keeps a run from hanging: nobody to ask is "no answer", not a wait.
        let shared = Shared::new();
        assert!(shared
            .ask("unlock-password", "Unlock password:", "")
            .is_none());
    }

    #[test]
    fn a_client_takes_a_question_and_answers_it() {
        use std::sync::mpsc::sync_channel;
        let shared = Shared::new();
        let (tx, rx) = sync_channel(8);
        shared.add_client(tx);
        // The welcome line and the backlog came first.
        assert_eq!(rx.try_recv().unwrap()["event"], "hello");

        let asking = {
            let shared = shared.clone();
            std::thread::spawn(move || shared.ask("confirm", "Close?", "the machine will stop"))
        };
        // The question reaches the client, which answers it.
        let question = loop {
            match rx.recv_timeout(Duration::from_secs(2)) {
                Ok(event) if event["event"] == "question" => break event,
                Ok(_) => continue,
                Err(e) => panic!("no question arrived: {e}"),
            }
        };
        assert_eq!(question["kind"], "confirm");
        shared.answer(
            question["id"].as_str().unwrap().parse().unwrap(),
            Some(Answer::Confirm(true)),
        );
        match asking.join().unwrap() {
            Some(Answer::Confirm(yes)) => assert!(yes),
            other => panic!("expected a confirm, got {other:?}"),
        }
    }
}
