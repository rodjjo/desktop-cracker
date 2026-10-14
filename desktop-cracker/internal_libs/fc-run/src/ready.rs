//! **The readiness channel (port 58000): the guest's own "I am up".**
//!
//! The project waits for a **line on the console** (`DESK-READY`, printed by its
//! initramfs' `guest-tools`), and reads the same line for the numbers a person wants
//! (`MemTotal=…`, `control=mounted`).  A console is a fine place for a person but a
//! poor one for a machine: it is text without a boundary, it arrives interleaved with
//! the guest's own boot log, and the run has to poll a buffer for it.
//!
//! This project keeps **both**: the guest still prints the line (a person reading the
//! application's console sees exactly what they see today), and the guest's agent
//! **also** sends the same line as one frame on the readiness channel, which is what
//! the run waits for.  Waiting on an event rather than on a buffer is what lets the
//! whole boot be timed to the millisecond, and it is what the system test then asserts
//! on (the plugin's own contract's `log`/`state` events).
//!
//! The protocol is deliberately one-way and one-shot, so that a guest which cannot
//! dial it costs nothing:
//!
//! ```text
//! guest → host   [u32 len][u16 kind = 1][the line, as text]
//! host  → guest  [u32 len][u16 kind = 1]["ok\n"]        (then the host closes)
//! ```
//!
//! A later report is the same frame with `kind = 2` — the guest's own words, passed
//! through to the console and to the plugin as a milestone, never parsed.

use std::io::Write;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::{Duration, Instant};

use dc_vsock::{Frame, Reader, Service};
use std::io::Read;

/// The guest is up: the line it would have printed is in the payload.
pub const KIND_READY: u16 = 1;
/// A report from a guest that is already up (its own words; not parsed).
pub const KIND_REPORT: u16 = 2;

/// What arrived on the readiness channel, in the order it arrived.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    /// The guest's own landmark line, exactly as it printed it.
    Ready(String),
    /// A line the guest wanted a person to see.
    Report(String),
    /// The channel ended (the guest closed it, or the machine went away).
    Closed,
}

/// The host's end of the readiness channel: the listener (opened **before** the
/// machine starts, because a guest that dials a port nobody listens on gets a reset),
/// the thread that turns frames into [`Event`]s, and the landmark the run waits for.
pub struct Readiness {
    service: Service,
    events: Receiver<Event>,
    /// Events that arrived while the run was waiting for something else (a report that
    /// came in while the landmark was being waited for is the guest's news, not
    /// something to drop on the floor).
    held: Vec<Event>,
    /// The landmark, when it has arrived: what the run waits for, and what it reports.
    ready: Option<(String, Instant)>,
    started: Instant,
}

impl Readiness {
    /// Listen on `port` at `<uds_path>_<port>` and start turning the guest's frames
    /// into events.
    ///
    /// The listener is created here and the machine is started afterwards: the order is
    /// the point (a guest that connects before the host listens gets a reset, and the
    /// failure looks like a guest that never came up).
    pub fn listen(
        uds_path: &std::path::Path,
        port: u32,
    ) -> std::result::Result<Readiness, dc_vsock::VsockError> {
        let service = Service::bind(uds_path, port)?;
        let (tx, rx) = channel();
        let listener = service
            .listener()
            .try_clone()
            .map_err(|source| dc_vsock::VsockError::Io { port, source })?;
        let started = Instant::now();
        std::thread::spawn(move || serve(listener, port, tx));
        Ok(Readiness {
            service,
            events: rx,
            held: Vec::new(),
            ready: None,
            started,
        })
    }

    /// The port this channel answers on.
    pub fn port(&self) -> u32 {
        self.service.port()
    }

    /// The landmark, when the guest has reported one: the line and the moment it arrived.
    pub fn ready(&self) -> Option<&(String, Instant)> {
        self.ready.as_ref()
    }

    /// Take every event that has arrived, remembering the landmark.
    ///
    /// What an earlier [`Readiness::wait_ready`] did not consume comes out first, in the
    /// order it arrived.
    pub fn poll(&mut self) -> Vec<Event> {
        let mut out = std::mem::take(&mut self.held);
        while let Ok(event) = self.events.try_recv() {
            self.file(&event);
            out.push(event);
        }
        out
    }

    /// Remember the landmark, wherever the event came from.
    fn file(&mut self, event: &Event) {
        if let Event::Ready(line) = event {
            if self.ready.is_none() {
                self.ready = Some((line.clone(), Instant::now()));
            }
        }
    }

    /// Wait until the guest's landmark arrives, or `timeout` passes.
    ///
    /// The wait is the **caller's bound** and nothing else waits: the frames arrive on
    /// their own thread, so this is a receive with a deadline, not a poll of a buffer.
    pub fn wait_ready(&mut self, timeout: Duration) -> Option<Duration> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some((_, at)) = &self.ready {
                return Some(at.duration_since(self.started));
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            match self.events.recv_timeout(left) {
                Ok(Event::Ready(line)) => {
                    if self.ready.is_none() {
                        self.ready = Some((line, Instant::now()));
                    }
                    return self
                        .ready
                        .as_ref()
                        .map(|(_, at)| at.duration_since(self.started));
                }
                // Anything else the guest said on the way is kept for the caller: a
                // report is not something waiting for the landmark may throw away.
                Ok(event) => {
                    self.file(&event);
                    self.held.push(event);
                }
                Err(_) => return None,
            }
        }
    }

    /// How long the channel has been open — the run's own start.
    pub fn elapsed(&self) -> Duration {
        self.started.elapsed()
    }
}

/// Accept one connection after another, and file every frame.
///
/// A guest that reconnects (an agent restarted, a second service on the same port) is
/// served again: the channel is not time-limited, only the landmark is.
fn serve(listener: std::os::unix::net::UnixListener, port: u32, tx: Sender<Event>) {
    // **Every guest that dials answers its own moment.**  A run whose guest is the system on the
    // disk reports its landing **twice**: the initramfs' (`DESK-READY initramfs …`, the machine is
    // alive) and the session's, once the disk's own system has brought the screen, the sound, the
    // shares and the network up.  Each connection is served on its own thread, so the second one
    // is not a guest that has to wait for the first to hang up — the earlier machine's guest could only
    // ever knock once, and this path's knocks again once the system takes over.
    for stream in listener.incoming() {
        let Ok(mut stream) = stream else { break };
        let tx = tx.clone();
        std::thread::spawn(move || {
            let mut reader = Reader::new();
            loop {
                match reader.read_frame(&mut stream, port) {
                    Ok(Some(frame)) => {
                        let text = String::from_utf8_lossy(&frame.payload).to_string();
                        let event = match frame.kind {
                            KIND_READY => Event::Ready(text),
                            KIND_REPORT => Event::Report(text),
                            _ => continue,
                        };
                        let closing = matches!(event, Event::Ready(_));
                        if tx.send(event).is_err() {
                            return;
                        }
                        // One answer, so the agent knows the line landed, and then **this**
                        // connection is done: readiness is a moment, not a conversation — and the
                        // next connection is the next moment.
                        if closing {
                            let _ = stream
                                .write_all(&Frame::new(KIND_READY, b"ok\n".to_vec()).encode());
                            let _ = stream.flush();
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(_) => break,
                }
            }
        });
    }
    let _ = tx.send(Event::Closed);
}

/// The guest's side of the same protocol, for a test that stands in for the agent and
/// for the guest's own tools later on.
///
/// It is **not** used by a run: a run only ever listens.
pub fn report_ready(stream: &mut impl Write, line: &str) -> std::io::Result<()> {
    stream.write_all(&Frame::new(KIND_READY, line.as_bytes().to_vec()).encode())?;
    stream.flush()
}

/// Read the host's answer to a readiness frame — the agent's half, so it does not have to
/// guess whether its line landed.
pub fn read_ack(stream: &mut impl Read) -> std::io::Result<String> {
    let mut reader = Reader::new();
    match reader.read_frame(stream, 0) {
        Ok(Some(frame)) => Ok(String::from_utf8_lossy(&frame.payload).into_owned()),
        Ok(None) => Ok(String::new()),
        // A channel that ended is an acknowledgement nobody read, not an I/O failure the
        // guest's agent should report: the honest answer is "nothing".
        Err(_) => Ok(String::new()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    #[test]
    fn the_host_listens_before_the_guest_dials_and_then_hears_it() {
        let dir = tempfile::tempdir().unwrap();
        let uds = dir.path().join("v.sock");
        let mut readiness = Readiness::listen(&uds, dc_vsock::ports::READY).unwrap();
        // The socket the guest's port hangs off exists before the guest exists: that is
        // the ordering rule of the whole run.
        assert!(readiness.service.path().exists());

        let mut guest =
            UnixStream::connect(dc_vsock::listener_path(&uds, dc_vsock::ports::READY)).unwrap();
        report_ready(
            &mut guest,
            "DESK-READY initramfs MemTotal=609104 control=mounted\n",
        )
        .unwrap();
        assert_eq!(read_ack(&mut guest).unwrap(), "ok\n");

        let waited = readiness.wait_ready(Duration::from_secs(5)).unwrap();
        assert!(waited < Duration::from_secs(5));
        let (line, _) = readiness.ready().unwrap();
        assert_eq!(
            line,
            "DESK-READY initramfs MemTotal=609104 control=mounted\n"
        );
    }

    #[test]
    fn a_landmark_that_never_comes_ends_the_wait_at_the_callers_bound() {
        let dir = tempfile::tempdir().unwrap();
        let mut readiness =
            Readiness::listen(&dir.path().join("v.sock"), dc_vsock::ports::READY).unwrap();
        let started = Instant::now();
        assert!(readiness.wait_ready(Duration::from_millis(60)).is_none());
        assert!(started.elapsed() >= Duration::from_millis(50));
    }

    #[test]
    fn a_report_is_passed_through_as_the_guests_own_words() {
        let dir = tempfile::tempdir().unwrap();
        let uds = dir.path().join("v.sock");
        let mut readiness = Readiness::listen(&uds, dc_vsock::ports::READY).unwrap();
        let mut guest =
            UnixStream::connect(dc_vsock::listener_path(&uds, dc_vsock::ports::READY)).unwrap();
        guest
            .write_all(&Frame::new(KIND_REPORT, b"GUEST t=0 MemTotal=6091040\n".to_vec()).encode())
            .unwrap();
        report_ready(&mut guest, "DESK-READY\n").unwrap();
        readiness.wait_ready(Duration::from_secs(5)).unwrap();
        let events = readiness.poll();
        assert!(
            events.contains(&Event::Report("GUEST t=0 MemTotal=6091040\n".into())),
            "{events:?}"
        );
    }

    #[test]
    fn a_frame_of_an_unknown_kind_is_ignored_rather_than_mistaken_for_a_landmark() {
        let dir = tempfile::tempdir().unwrap();
        let uds = dir.path().join("v.sock");
        let mut readiness = Readiness::listen(&uds, dc_vsock::ports::READY).unwrap();
        let mut guest =
            UnixStream::connect(dc_vsock::listener_path(&uds, dc_vsock::ports::READY)).unwrap();
        guest
            .write_all(&Frame::new(999, b"nonsense".to_vec()).encode())
            .unwrap();
        report_ready(&mut guest, "DESK-READY\n").unwrap();
        assert!(readiness.wait_ready(Duration::from_secs(5)).is_some());
        assert_eq!(readiness.ready().unwrap().0, "DESK-READY\n");
    }

    #[test]
    fn a_guest_that_dials_twice_is_served_twice() {
        let dir = tempfile::tempdir().unwrap();
        let uds = dir.path().join("v.sock");
        let mut readiness = Readiness::listen(&uds, dc_vsock::ports::READY).unwrap();
        let path = dc_vsock::listener_path(&uds, dc_vsock::ports::READY);
        for _ in 0..2 {
            let mut guest = UnixStream::connect(&path).unwrap();
            report_ready(&mut guest, "DESK-READY\n").unwrap();
            assert_eq!(read_ack(&mut guest).unwrap(), "ok\n");
        }
        assert!(readiness.wait_ready(Duration::from_secs(5)).is_some());
    }

    #[test]
    fn a_guest_that_hangs_up_mid_frame_does_not_take_the_channel_with_it() {
        let dir = tempfile::tempdir().unwrap();
        let uds = dir.path().join("v.sock");
        let mut readiness = Readiness::listen(&uds, dc_vsock::ports::READY).unwrap();
        let path = dc_vsock::listener_path(&uds, dc_vsock::ports::READY);
        {
            let mut bad = UnixStream::connect(&path).unwrap();
            // Half a frame, then gone.
            let frame = Frame::new(KIND_READY, b"DESK-READY\n".to_vec()).encode();
            bad.write_all(&frame[..4]).unwrap();
        }
        let mut good = UnixStream::connect(&path).unwrap();
        report_ready(&mut good, "DESK-READY\n").unwrap();
        assert!(readiness.wait_ready(Duration::from_secs(5)).is_some());
    }
}
