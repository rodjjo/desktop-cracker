//! **The control share, as a vsock channel** (port 56000).
//!
//! At first the guest read a small directory the host mounted with 9P: the mount
//! plan (`mounts`), the disks of the run (`disks`), the display's state, and — for a job —
//! the secrets it is to use.  Firecracker has no 9P, so that directory becomes a **channel**
//! with the same contents and the same rules:
//!
//! * the guest **asks for a file by name** and gets its bytes (`READ`), and there is one
//!   file it may **write** — the one exception this project has always had, the
//!   control directory being the writable one (`AGENTS.md`, the project's rules);
//! * a file the run did not put there is **not there**: the guest cannot list the
//!   directory, cannot reach a path outside it, and cannot invent a name to write to.  That
//!   is stricter than a 9P mount of a host directory, and it is what keeps a secret in the
//!   share from being reachable by a name the run never chose;
//! * **a secret is answered once and forgotten**: the run hands it over, the guest removes
//!   its copy, and the host's copy is zeroized when the run is dropped.  Nothing here ever
//!   writes a secret to a file on the host (`AGENTS.md`: the only two ways out of the
//!   process are the guest's control share and `qmp object-add secret`).
//!
//! The protocol is a request and a reply, both framed like every other service
//! (`[u32 len][u16 kind]` + payload), so the guest's agent speaks one wire for all of them:
//!
//! ```text
//! guest → host   kind 1 (READ)   "name\n"                 → kind 2 (DATA)  <bytes>
//!                                                            kind 3 (MISSING) "name\n"
//! guest → host   kind 4 (WRITE)  "name\n<bytes>"          → kind 5 (WROTE)  "name\n"
//!                                                            kind 6 (REFUSED) "name\n"
//! guest → host   kind 7 (LIST)                            → kind 2 (DATA)  "name\nname\n…"
//! ```
//!
//! `LIST` exists because a guest that cannot see what is in the share cannot be told
//! anything new: it is the *names* that are listed, never a path, and a name the run does
//! not know is refused on the way in.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Arc, Mutex};

use dc_vsock::{Frame, Reader, Service};
use zeroize::Zeroize;

/// The guest is asking for a file: the payload is its name.
pub const KIND_READ: u16 = 1;
/// The host's answer: the file's bytes.
pub const KIND_DATA: u16 = 2;
/// The host has no such file.
pub const KIND_MISSING: u16 = 3;
/// The guest is writing one: `name\n` and then the bytes.
pub const KIND_WRITE: u16 = 4;
/// The host took it.
pub const KIND_WROTE: u16 = 5;
/// The host refused it (a name that is not one the run made writable).
pub const KIND_REFUSED: u16 = 6;
/// The guest wants the names of what is here.
pub const KIND_LIST: u16 = 7;

/// The one file the guest may write: the status it publishes for the host
/// (`guest-ready`, `guest-meminfo` — the names the guest's own tools use).
pub const WRITABLE: [&str; 8] = [
    "guest-ready",
    "guest-meminfo",
    "guest-status",
    "poweroff",
    "display-state",
    "unlock-answer",
    "job-result",
    "guest-log",
];

/// What the run put in the share, and what the guest put back.
#[derive(Debug, Default)]
pub struct Control {
    /// The files, by name.  A `BTreeMap` so the listing is in a stable order (a person
    /// reading it twice reads the same thing).
    files: BTreeMap<String, Vec<u8>>,
    /// The secrets the run has handed out, so they can be zeroized when it ends.
    secrets: Vec<String>,
    /// What the guest wrote back.
    written: BTreeMap<String, Vec<u8>>,
    /// Every request the guest made, counted by name — a run whose guest is asking for
    /// something that is not there is a run to look at.
    asked: BTreeMap<String, u64>,
}

impl Control {
    pub fn new() -> Control {
        Control::default()
    }

    /// Put a file in the share: the mount plan, the disks of the run, an environment file.
    pub fn put(&mut self, name: &str, text: impl Into<Vec<u8>>) -> &mut Control {
        self.files.insert(name.to_string(), text.into());
        self
    }

    /// Put a **secret** in the share.  It is held exactly as long as the run needs it and
    /// zeroized when the run ends; it is never written to a file anywhere.
    pub fn put_secret(&mut self, name: &str, secret: impl Into<String>) -> &mut Control {
        let mut secret: String = secret.into();
        let bytes = secret.clone().into_bytes();
        self.files.insert(name.to_string(), bytes);
        secret.zeroize();
        self.secrets.push(name.to_string());
        self
    }

    /// What the guest wrote, by name (the run reads its own status back).
    pub fn written(&self) -> &BTreeMap<String, Vec<u8>> {
        &self.written
    }

    pub fn written_text(&self, name: &str) -> Option<String> {
        self.written
            .get(name)
            .map(|b| String::from_utf8_lossy(b).into_owned())
    }

    /// How many times the guest asked for each name.
    pub fn asked(&self) -> &BTreeMap<String, u64> {
        &self.asked
    }

    /// Answer one request.  The whole policy of the share is here, and it is small on
    /// purpose: a name that is in the map is answered, a name the run made writable is
    /// taken, and everything else is a sentence the guest can act on.
    ///
    /// Public because it **is** the share's contract: the channel calls it for every frame,
    /// and a test (or a tool) that wants to know what the guest would be told asks it the
    /// same question the guest would.
    pub fn answer(&mut self, frame: &Frame) -> Vec<Frame> {
        match frame.kind {
            KIND_READ => {
                let name = text_of(&frame.payload);
                *self.asked.entry(name.clone()).or_insert(0) += 1;
                match self.files.get(&name) {
                    Some(bytes) => vec![Frame::new(KIND_DATA, bytes.clone())],
                    None => vec![Frame::new(KIND_MISSING, name.into_bytes())],
                }
            }
            KIND_WRITE => {
                let (name, body) = split_once_newline(&frame.payload);
                if !is_writable(&name) {
                    return vec![Frame::new(KIND_REFUSED, name.into_bytes())];
                }
                self.written.insert(name.clone(), body.to_vec());
                vec![Frame::new(KIND_WROTE, name.into_bytes())]
            }
            KIND_LIST => {
                let mut listing = String::new();
                for name in self.files.keys() {
                    listing.push_str(name);
                    listing.push('\n');
                }
                for name in self.written.keys() {
                    listing.push_str(name);
                    listing.push('\n');
                }
                vec![Frame::new(KIND_DATA, listing.into_bytes())]
            }
            // A kind this share does not know: nothing to say, and saying nothing is
            // better than a guest acting on an answer that means something else.
            _ => Vec::new(),
        }
    }

    /// Take the secrets out: the run is ending, and what it held it does not hold any
    /// more.  (`AGENTS.md`: a credential lives in memory for as long as it is needed and
    /// is zeroized when it is dropped.)
    pub fn forget_secrets(&mut self) {
        for name in std::mem::take(&mut self.secrets) {
            if let Some(mut bytes) = self.files.remove(&name) {
                bytes.zeroize();
            }
        }
    }
}

impl Drop for Control {
    fn drop(&mut self) {
        self.forget_secrets();
        for bytes in self.files.values_mut() {
            bytes.zeroize();
        }
    }
}

/// Is this a name the guest may write?
pub fn is_writable(name: &str) -> bool {
    WRITABLE.contains(&name)
}

fn text_of(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .trim_end_matches('\n')
        .to_string()
}

fn split_once_newline(bytes: &[u8]) -> (String, &[u8]) {
    match bytes.iter().position(|b| *b == b'\n') {
        Some(at) => (
            String::from_utf8_lossy(&bytes[..at]).to_string(),
            &bytes[at + 1..],
        ),
        None => (String::from_utf8_lossy(bytes).to_string(), &[]),
    }
}

/// The share, serving.
///
/// The accepted connection is kept, because a channel has to be **stoppable**: a guest that
/// has finished its job halts and holds the connection open (a halted guest does not close
/// its sockets — measured 2026-10-09), so a server that only waited for the guest to hang up
/// would wait for a machine that is never going to.  [`ControlChannel::shutdown`] closes the
/// connection from this side, which is what ends the serving thread.
pub struct ControlChannel {
    service: Service,
    control: Arc<Mutex<Control>>,
    /// The connections being served: **every one of them**, because a run has more than one (the
    /// initramfs' guest reads the passphrase, and the session on the disk asks for the same names
    /// again when the system starts).  Each is shut down from this side when the run is over — a
    /// guest that halted does not close its own end (measured).
    accepted: Mutex<Vec<Arc<Mutex<Option<std::os::unix::net::UnixStream>>>>>,
    /// Told to stop accepting: a listener parked in `accept` must not outlive the run.
    stop: std::sync::atomic::AtomicBool,
}

impl ControlChannel {
    /// Listen on `port` at `<uds_path>_<port>`, **now** — before the machine starts, which
    /// is the ordering rule every channel of this run follows.
    pub fn listen(
        uds_path: &Path,
        port: u32,
        control: Arc<Mutex<Control>>,
    ) -> Result<ControlChannel, dc_vsock::VsockError> {
        Ok(ControlChannel {
            service: Service::bind(uds_path, port)?,
            control,
            accepted: Mutex::new(Vec::new()),
            stop: std::sync::atomic::AtomicBool::new(false),
        })
    }

    pub fn port(&self) -> u32 {
        self.service.port()
    }

    pub fn control(&self) -> Arc<Mutex<Control>> {
        self.control.clone()
    }

    /// Stop serving: the connection is shut down from this side, and the serving thread
    /// ends with it.  Called when a job (or a run) is over — the guest may still be holding
    /// its end, and waiting for it to let go is waiting for a machine that has halted.
    pub fn shutdown(&self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        // **Every** connection this channel served is shut down from this side: a guest that
        // halted, or a session that is still running, does not close its own end.
        let connections = {
            let mut accepted = self.accepted.lock().expect("the control channel");
            std::mem::take(&mut *accepted)
        };
        for connection in connections {
            if let Ok(mut stream) = connection.lock() {
                if let Some(stream) = stream.take() {
                    let _ = stream.shutdown(std::net::Shutdown::Both);
                }
            }
        }
    }

    /// Serve the guest until the run ends.
    ///
    /// **The connection is accepted once and then served on its own thread**, and that is not a
    /// detail: the run's first guest (the initramfs, which reads the passphrase and the plan) and
    /// the session on the **disk** (which asks for the same names again when the system starts) are
    /// two connections to one port, one after the other.  A server that served the first and then
    /// stopped is a guest whose second ask goes unanswered — which is what "the system on the disk
    /// has no screen, no shares and no network" looks like (measured 2026-10-10).
    pub fn serve(&self) -> Result<(), dc_vsock::VsockError> {
        // Accepting with a **short wait**, so a run that is over can end this thread: a listener
        // parked in `accept` outlives the run that owns it.
        let _ = self.service.set_nonblocking(true);
        loop {
            if self.stop.load(std::sync::atomic::Ordering::Relaxed) {
                return Ok(());
            }
            let stream = match self.service.accept() {
                Ok(stream) => stream,
                Err(dc_vsock::VsockError::Io { ref source, .. })
                    if source.kind() == std::io::ErrorKind::WouldBlock =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                    continue;
                }
                Err(_) => return Ok(()),
            };
            let _ = stream.set_nonblocking(false);
            let connection = Arc::new(Mutex::new(stream.try_clone().ok()));
            self.accepted
                .lock()
                .expect("the control channel")
                .push(connection.clone());
            let control = self.control.clone();
            let port = self.service.port();
            let mut stream = stream;
            std::thread::spawn(move || {
                let mut reader = Reader::new();
                loop {
                    match reader.read_frame(&mut stream, port) {
                        Ok(Some(frame)) => {
                            let answers = {
                                let mut control = control.lock().expect("the control share");
                                control.answer(&frame)
                            };
                            for answer in answers {
                                if dc_vsock::write_frame(&mut stream, &answer, port).is_err() {
                                    break;
                                }
                            }
                        }
                        Ok(None) => break,
                        Err(_) => break,
                    }
                }
            });
        }
    }

    /// Serve on a thread of its own (what a run does).
    pub fn serve_in_background(self: Arc<Self>) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            let _ = self.serve();
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn a_file_the_run_put_there_is_answered_and_one_it_did_not_is_not() {
        let mut control = Control::new();
        control.put("mounts", "data /mnt/data rw\n");
        let answer = control.answer(&Frame::new(KIND_READ, b"mounts\n".to_vec()));
        assert_eq!(
            answer,
            vec![Frame::new(KIND_DATA, b"data /mnt/data rw\n".to_vec())]
        );
        let answer = control.answer(&Frame::new(KIND_READ, b"/etc/shadow\n".to_vec()));
        assert_eq!(
            answer,
            vec![Frame::new(KIND_MISSING, b"/etc/shadow".to_vec())]
        );
        // A name the run never chose is not a name: no path traversal, no listing of the
        // host's filesystem, nothing but the answer "not here".
        let answer = control.answer(&Frame::new(KIND_READ, b"../../etc/passwd\n".to_vec()));
        assert!(matches!(answer[0].kind, KIND_MISSING));
        assert_eq!(control.asked().get("mounts"), Some(&1));
    }

    #[test]
    fn only_the_names_the_run_made_writable_are_taken() {
        let mut control = Control::new();
        let answers = control.answer(&Frame::new(KIND_WRITE, b"guest-ready\nready\n".to_vec()));
        assert_eq!(
            answers,
            vec![Frame::new(KIND_WROTE, b"guest-ready".to_vec())]
        );
        assert_eq!(
            control.written_text("guest-ready").as_deref(),
            Some("ready\n")
        );

        let answers = control.answer(&Frame::new(KIND_WRITE, b"dc-jobs\nsecret\n".to_vec()));
        assert_eq!(answers, vec![Frame::new(KIND_REFUSED, b"dc-jobs".to_vec())]);
        assert!(control.written_text("dc-jobs").is_none());
    }

    #[test]
    fn the_listing_names_what_is_there_and_nothing_of_the_host() {
        let mut control = Control::new();
        control.put("mounts", "x");
        control.put("disks", "y");
        control.answer(&Frame::new(KIND_WRITE, b"guest-ready\nup\n".to_vec()));
        let answer = control.answer(&Frame::new(KIND_LIST, Vec::new()));
        let listing = String::from_utf8_lossy(&answer[0].payload).to_string();
        assert!(listing.contains("mounts\n"));
        assert!(listing.contains("disks\n"));
        assert!(listing.contains("guest-ready\n"));
        assert!(!listing.contains('/'), "a name, never a path: {listing}");
    }

    #[test]
    fn a_secret_is_answered_once_and_zeroized_when_the_run_ends() {
        let mut control = Control::new();
        control.put_secret("disk.pass", "correct horse battery staple");
        let answer = control.answer(&Frame::new(KIND_READ, b"disk.pass\n".to_vec()));
        assert_eq!(answer[0].kind, KIND_DATA);
        assert_eq!(
            String::from_utf8_lossy(&answer[0].payload),
            "correct horse battery staple"
        );
        control.forget_secrets();
        let answer = control.answer(&Frame::new(KIND_READ, b"disk.pass\n".to_vec()));
        assert_eq!(
            answer[0].kind, KIND_MISSING,
            "the run does not hold it any more"
        );
    }

    #[test]
    fn an_unknown_request_is_answered_with_nothing_at_all() {
        let mut control = Control::new();
        assert!(control.answer(&Frame::new(999, b"?".to_vec())).is_empty());
    }

    #[test]
    fn the_channel_answers_the_guest_over_a_real_socket() {
        let dir = tempfile::tempdir().unwrap();
        let uds = dir.path().join("v.sock");
        let mut control = Control::new();
        control.put("disks", "vdb data rw\n");
        let control = Arc::new(Mutex::new(control));
        let channel =
            Arc::new(ControlChannel::listen(&uds, dc_vsock::ports::CONTROL, control).unwrap());
        let port = channel.port();
        let handle = channel.clone().serve_in_background();

        let mut guest = std::os::unix::net::UnixStream::connect(dc_vsock::listener_path(
            &uds,
            dc_vsock::ports::CONTROL,
        ))
        .unwrap();
        guest
            .write_all(&Frame::new(KIND_READ, b"disks\n".to_vec()).encode())
            .unwrap();
        guest.flush().unwrap();
        let mut reader = Reader::new();
        let answer = reader.read_frame(&mut guest, port).unwrap().unwrap();
        assert_eq!(answer.kind, KIND_DATA);
        assert_eq!(String::from_utf8_lossy(&answer.payload), "vdb data rw\n");

        // And a write, the one exception this project has always had.
        guest
            .write_all(&Frame::new(KIND_WRITE, b"guest-ready\nup\n".to_vec()).encode())
            .unwrap();
        guest.flush().unwrap();
        let answer = reader.read_frame(&mut guest, port).unwrap().unwrap();
        assert_eq!(answer.kind, KIND_WROTE);
        assert_eq!(
            channel
                .control()
                .lock()
                .unwrap()
                .written_text("guest-ready")
                .as_deref(),
            Some("up\n")
        );
        drop(guest);
        // **The run's own way to end the thread**: every channel of a run is stopped from this
        // side when the run is over (`ControlChannel::shutdown`), because a guest may be halted
        // with its end still open.  A test that just dropped the handle would wait for a listener
        // that is waiting for a guest — which is the whole point of having a shutdown.
        channel.shutdown();
        let _ = handle.join();
    }

    #[test]
    fn a_channel_whose_guest_has_halted_is_stopped_from_this_side() {
        // A halted guest does not close its sockets (measured 2026-10-09: a disk job's guest
        // says `reboot: System halted` and the connection stays open), so the server has to
        // be able to end the conversation.  Without this, a job that finished in 7 seconds
        // was waited for until its own timeout — the bug this test is about.
        let dir = tempfile::tempdir().unwrap();
        let uds = dir.path().join("v.sock");
        let channel = Arc::new(
            ControlChannel::listen(
                &uds,
                dc_vsock::ports::CONTROL,
                Arc::new(Mutex::new(Control::new())),
            )
            .unwrap(),
        );
        let handle = {
            let channel = channel.clone();
            std::thread::spawn(move || channel.serve())
        };
        // The guest dials, asks for one thing, and then goes quiet without hanging up.
        let mut guest = std::os::unix::net::UnixStream::connect(dc_vsock::listener_path(
            &uds,
            dc_vsock::ports::CONTROL,
        ))
        .unwrap();
        guest
            .write_all(&Frame::new(KIND_READ, b"mounts\n".to_vec()).encode())
            .unwrap();
        guest.flush().unwrap();
        // Let the server see the request, then stop it as a run does when its job is over.
        std::thread::sleep(std::time::Duration::from_millis(50));
        channel.shutdown();
        handle
            .join()
            .expect("the serving thread ends when the channel is shut down")
            .expect("serving a closed channel is not an error");
    }

    #[test]
    fn a_run_has_more_than_one_guest_on_the_same_port() {
        // A run's guest asks twice: the initramfs' agent reads the passphrase and the plan, and
        // the session on the **disk** asks for the same names again when the system starts (the
        // initramfs is discarded at the pivot, and its agent with it).  Two connections, one
        // port, one after the other — and the second must be answered as well as the first.
        let dir = tempfile::tempdir().unwrap();
        let uds = dir.path().join("v.sock");
        let mut control = Control::new();
        control.put("mounts", "disk /mnt/disk rw\n");
        let channel = Arc::new(
            ControlChannel::listen(
                &uds,
                dc_vsock::ports::CONTROL,
                Arc::new(Mutex::new(control)),
            )
            .unwrap(),
        );
        let port = channel.port();
        let handle = channel.clone().serve_in_background();

        for attempt in 1..=2 {
            let mut guest = std::os::unix::net::UnixStream::connect(dc_vsock::listener_path(
                &uds,
                dc_vsock::ports::CONTROL,
            ))
            .unwrap();
            guest
                .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                .unwrap();
            guest
                .write_all(&Frame::new(KIND_READ, b"mounts\n".to_vec()).encode())
                .unwrap();
            guest.flush().unwrap();
            let mut reader = Reader::new();
            let answer = reader
                .read_frame(&mut guest, port)
                .unwrap_or_else(|e| panic!("connection {attempt}: {e}"))
                .unwrap_or_else(|| panic!("connection {attempt}: the channel said nothing"));
            assert_eq!(answer.kind, KIND_DATA, "connection {attempt}");
            assert_eq!(channel.control().lock().unwrap().asked().len(), 1);
        }
        channel.shutdown();
        let _ = handle.join();
    }

    #[test]
    fn the_channel_listens_before_anything_dials_it() {
        let dir = tempfile::tempdir().unwrap();
        let uds = dir.path().join("v.sock");
        let channel = ControlChannel::listen(
            &uds,
            dc_vsock::ports::CONTROL,
            Arc::new(Mutex::new(Control::new())),
        )
        .unwrap();
        assert!(channel.service.path().exists());
    }
}
