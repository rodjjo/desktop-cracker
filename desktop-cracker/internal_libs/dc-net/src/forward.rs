//! **One forwarded port**: a listener on the host, carried into the guest.
//!
//! This project's network is a userspace one (`lib.rs`): the guest sits behind a unix-socket
//! conduit and nothing reaches it from the host's network unless this process opens a door.  This
//! module is that door, and there is exactly one of them — the operator's `--ssh-port` (SPECS.md
//! "SSH"): the host's port `N` becomes a connection to the guest's sshd, which listens on
//! **22 inside the guest** and runs whether the switch is given or not.
//!
//! ```text
//!   ssh on the host  ──▶  127.0.0.1:N (this listener)  ──▶  the relay  ──▶  frames  ──▶  guest:22
//! ```
//!
//! It is deliberately **not** the shared `ports.rs`: that file is a
//! copy of the shared port table, and it carries a whole model this project does not have
//! (an operator's list of mappings, UDP datagrams, published ports on a workspace gateway, a
//! status row per mapping).  What this project needs is the opposite of a model: one listener,
//! one guest port, and no mapping at all when the user asks for none.  What it does borrow is the
//! **mechanism**: the accepted connection is handed to the relay's own `accept_inbound`, so the
//! flow the guest answers is an ordinary inbound flow — the relay opens the guest's side with a
//! SYN and carries the bytes — and none of that is re-implemented here.
//!
//! Three rules, and each one is a decision rather than an accident:
//!
//! * **the host's loopback.**  `127.0.0.1:N`, never `0.0.0.0:N`: a forwarded sshd should be
//!   reachable from the machine the user is sitting at, and from nowhere else.  That is the same
//!   rule the vendored `ports.rs` states for a bare port, kept here because it is the whole point
//!   of the feature being optional;
//! * **nothing listens without a request.**  Without `--ssh-port` no socket is opened at all: the
//!   guest's sshd is not exposed, it is simply there for the guest;
//! * **a taken port is a message, not a failed run.**  A port somebody else holds is a row saying
//!   so (and the application prints it) — the microVM still starts, exactly as it would without
//!   the switch.

use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// How long the serving thread waits between checks of the shutdown flag.
///
/// `std`'s `TcpListener` cannot be interrupted while blocked in `accept`, so the listener is
/// nonblocking and the loop polls: short enough that a run's shutdown returns promptly, long
/// enough that an idle forward costs nothing worth measuring.
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// The port the guest's sshd listens on.  A constant, because the switch names the **host** side:
/// `--ssh-port 2223` forwards the host's 2223 to the guest's 22 (SPECS.md).
pub const SSH_GUEST_PORT: u16 = 22;

/// What became of the forward, for the application to print.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForwardState {
    /// The listener is open and being served.
    Bound,
    /// The listener could not be opened; the string is the OS's own reason.
    Failed(String),
}

/// Where one forward listens, and whether it does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardStatus {
    /// The host address the listener took, or the one it could not take.
    pub host: SocketAddr,
    /// The port inside the guest the connection is carried to.
    pub guest_port: u16,
    /// Whether it is serving, or why it is not.
    pub state: ForwardState,
}

/// What the forward does with one accepted connection: hand it to the relay.
pub type AcceptHandler = Arc<dyn Fn(TcpStream, SocketAddr) + Send + Sync>;

/// One host port, carried into the guest, until it is shut down.
pub struct Forward {
    /// The row the application prints: the address, the guest's port, and what happened.
    status: ForwardStatus,
    /// Set by [`Forward::shutdown`]; the serving thread checks it and returns.
    stopped: Arc<AtomicBool>,
    /// The serving thread, joined by [`Forward::shutdown`].
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl Forward {
    /// Open `host_port` on the host's loopback and carry what arrives to `guest_port`.
    ///
    /// A port that cannot be bound is a `Failed` row and **not** an error: a run whose forward
    /// could not be opened is a run whose guest is up and its sshd unreachable, and saying so is
    /// what the user needs — the switch is a convenience, not a precondition.
    pub fn bind(host_port: u16, guest_port: u16, accept: AcceptHandler) -> Forward {
        let host = SocketAddr::from(([127, 0, 0, 1], host_port));
        let listener = match TcpListener::bind(host) {
            Ok(listener) => listener,
            Err(error) => {
                return Forward {
                    status: ForwardStatus {
                        host,
                        guest_port,
                        state: ForwardState::Failed(format!("cannot bind {host}: {error}")),
                    },
                    stopped: Arc::new(AtomicBool::new(true)),
                    thread: Mutex::new(None),
                }
            }
        };
        // The address the OS actually took (a port `0` would learn its port here, and the status
        // always reports the truth).
        let local = listener.local_addr().unwrap_or(host);
        let stopped = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&stopped);
        let spawned = thread::Builder::new()
            .name(format!("vm-forward-{local}"))
            .spawn(move || serve(listener, accept, stop));
        match spawned {
            Ok(thread) => Forward {
                status: ForwardStatus {
                    host: local,
                    guest_port,
                    state: ForwardState::Bound,
                },
                stopped,
                thread: Mutex::new(Some(thread)),
            },
            Err(error) => Forward {
                status: ForwardStatus {
                    host,
                    guest_port,
                    state: ForwardState::Failed(format!("cannot serve {host}: {error}")),
                },
                stopped: Arc::new(AtomicBool::new(true)),
                thread: Mutex::new(None),
            },
        }
    }

    /// What the forward is: the address it took (or could not), the guest's port, and its state.
    pub fn status(&self) -> &ForwardStatus {
        &self.status
    }

    /// The address the host dials, when the listener is open.
    pub fn address(&self) -> Option<SocketAddr> {
        match self.status.state {
            ForwardState::Bound => Some(self.status.host),
            ForwardState::Failed(_) => None,
        }
    }

    /// Stop listening: the serving thread ends and the listener is closed, so a later connection
    /// to the host's port is refused rather than answered by a guest nobody is watching.
    ///
    /// The thread is joined before this returns, so the refusal is immediate.
    pub fn shutdown(&self) {
        self.stopped.store(true, Ordering::Relaxed);
        let mut thread = self
            .thread
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(handle) = thread.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for Forward {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Serve one forward until `stop` is set: every connection that arrives is handed on.
///
/// The listener is nonblocking because `accept` cannot time out and `shutdown` has to be able to
/// end this thread; the accepted stream is put back into blocking mode before the *relay* sees it,
/// because nonblocking is this loop's implementation detail and not part of the hand-off.
fn serve(listener: TcpListener, accept: AcceptHandler, stop: Arc<AtomicBool>) {
    if listener.set_nonblocking(true).is_err() {
        // Without a nonblocking accept this thread could never notice `stop`: give the forward up
        // rather than wedge a thread (and `shutdown`'s join) forever.
        return;
    }
    loop {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        match listener.accept() {
            Ok((stream, peer)) => {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                let _ = stream.set_nonblocking(false);
                accept(stream, peer);
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => thread::sleep(POLL_INTERVAL),
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            // The listener is broken (not merely empty): the forward is over.
            Err(_) => return,
        }
    }
}

/// The handler for a machine's forward: a connection to the host's port becomes an inbound flow
/// to `guest_port` inside the machine.
///
/// The relay does everything else — it opens the guest's side with a SYN of its own, carries the
/// bytes both ways, and closes the flow when either end does.  This is where this project's own
/// code ends and the vendored relay begins, which is why there is so little of it here.
///
/// A connection the relay refuses (the machine is going away, or it already has as many flows as
/// its ceiling allows) is closed by dropping the stream: the host's client sees the connection
/// end, which is what a refused ssh does anywhere.
pub(crate) fn to_guest(
    relay: Arc<crate::relay::Relay>,
    target: IpAddr,
    guest_port: u16,
) -> AcceptHandler {
    Arc::new(move |stream: TcpStream, peer: SocketAddr| {
        let _ = relay.accept_inbound(stream, guest_port, peer, target);
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpStream as HostStream;
    use std::sync::mpsc;

    /// The forward's own machinery: a connection to the host's port is accepted and handed on,
    /// with the peer's address — and `shutdown` closes the listener (what the run's end does).
    #[test]
    fn a_connection_to_the_hosts_port_is_carried_to_the_guest() {
        // Port 0: the OS picks, and the status reports what it picked — the same shape the tests
        // of the vendored `ports.rs` use.
        let (tx, rx) = mpsc::channel::<(SocketAddr, Vec<u8>)>();
        let handler: AcceptHandler = Arc::new(move |mut stream: TcpStream, peer: SocketAddr| {
            let mut buffer = [0u8; 16];
            let n = stream.read(&mut buffer).unwrap_or(0);
            let _ = stream.write_all(b"carried\n");
            let _ = tx.send((peer, buffer[..n].to_vec()));
        });
        let forward = Forward::bind(0, SSH_GUEST_PORT, handler);
        assert_eq!(forward.status().state, ForwardState::Bound);
        assert_eq!(forward.status().guest_port, 22);
        let address = forward.address().expect("a bound forward has an address");
        assert!(address.ip().is_loopback(), "the forward is on the loopback");

        let client = thread::spawn(move || {
            let mut stream = HostStream::connect(address).expect("the client connects");
            stream.write_all(b"ssh-2.0\n").expect("writes");
            let mut answer = [0u8; 16];
            let n = stream.read(&mut answer).expect("reads");
            answer[..n].to_vec()
        });
        let (peer, said) = rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the connection reached the guest's side");
        assert_eq!(said, b"ssh-2.0\n");
        assert!(peer.ip().is_loopback(), "the peer is the host's own client");
        assert_eq!(client.join().unwrap(), b"carried\n");

        forward.shutdown();
        assert!(
            HostStream::connect(address).is_err(),
            "a forward that was shut down refuses a new connection"
        );
    }

    /// A port somebody else holds is a **row**, not a panic and not a failed run: the microVM
    /// still starts, and the application says what happened.
    #[test]
    fn a_port_that_is_taken_is_reported_and_not_fatal() {
        let held = TcpListener::bind("127.0.0.1:0").expect("a listener of the test's own");
        let taken = held.local_addr().expect("an address").port();
        let forward = Forward::bind(taken, SSH_GUEST_PORT, Arc::new(|_, _| {}));
        match &forward.status().state {
            ForwardState::Failed(reason) => assert!(
                reason.contains("cannot bind"),
                "the row says what could not be bound: {reason}"
            ),
            other => panic!("a taken port was reported as {other:?}"),
        }
        assert_eq!(forward.address(), None);
        forward.shutdown();
    }
}
