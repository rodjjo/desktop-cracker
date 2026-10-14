//! **The guest's own shutdown**, and why it is a channel rather than a keystroke.
//!
//! Firecracker has no ACPI power management.  On x86 it emulates one legacy device that can end
//! the machine — the **i8042 keyboard controller** — and that is what `SendCtrlAltDel` and
//! `reboot=k` both use: the guest's kernel pulses the controller's reset line and Firecracker
//! exits by itself (Firecracker's own documentation says it plainly: the keyboard is what that action
//! *requires*; measured on this host 2026-10-10, `Firecracker v1.17.0`).
//!
//! Two consequences shaped this crate:
//!
//! * **a guest that is still in its initramfs cannot be rebooted that way at all.**  The
//!   initramfs has no `systemd`, so nothing turns a keystroke into a reset — and the module the
//!   kernel's own keyboard-driven reboot needs (`serio`/`atkbd`) is off in Firecracker's guest
//!   configuration.  A real run spends its life in the system on the disk, but a **test** and a
//!   **freshly made disk** do not, so "ask the guest" has to be a channel the guest's agent
//!   serves, and the agent is in both places;
//! * **the guest has to answer with a reboot, not a power-off.**  `poweroff` shuts the guest's
//!   own system down and leaves Firecracker running — nothing to pulse, no ACPI to ask
//!   (Firecracker's own documentation, and measured: a disk job's guest says
//!   `reboot: Power down` and the process stays).  What ends the process is `reboot(2)`, which
//!   the agent runs as its **first act at boot** — before it is chrooted into the disk, while
//!   the initramfs' own kernel is the one that answers — and again after the pivot, where the
//!   guest's own `systemd` sees the reset line and shuts the system down cleanly
//!   (`ctrl-alt-del.target`).
//!
//! So the protocol is one frame in one direction: the host says **go away**, and the guest
//! reboots itself.  The guest's copy of it is the agent's `shutdown` verb (`desk-agent`),
//! which holds the connection open from the moment it starts; the host never *pushes* at a
//! socket the guest has not opened.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use dc_common::milestone;
use dc_vsock::{Frame, Service};

/// The host asks the guest to go away.
pub const KIND_SHUTDOWN: u16 = 1;
/// The guest says it is there (and, once, that it heard the request).
pub const KIND_HELLO: u16 = 2;
/// The guest's answer: it is rebooting (the host's confirmation that the request landed).
pub const KIND_REBOOTING: u16 = 3;

/// The shutdown channel: one listener, one guest connection (the agent's), and one request.
pub struct ShutdownChannel {
    service: Service,
    /// The guest's connection, kept for as long as the run: the request is written on it.
    guest: Arc<Mutex<Option<std::os::unix::net::UnixStream>>>,
    /// Whether the guest has opened its end (the agent is up).
    opened: Arc<AtomicBool>,
    /// Whether the request was written on a channel somebody was reading.
    asked: Arc<AtomicBool>,
    /// How many times the guest said it heard.
    heard: Arc<AtomicU64>,
}

impl ShutdownChannel {
    pub fn listen(uds_path: &std::path::Path) -> Result<ShutdownChannel, dc_vsock::VsockError> {
        Ok(ShutdownChannel {
            service: Service::bind(uds_path, dc_vsock::ports::SHUTDOWN)?,
            guest: Arc::new(Mutex::new(None)),
            opened: Arc::new(AtomicBool::new(false)),
            asked: Arc::new(AtomicBool::new(false)),
            heard: Arc::new(AtomicU64::new(0)),
        })
    }

    pub fn port(&self) -> u32 {
        self.service.port()
    }

    /// Whether the guest's agent has opened the channel: a request written before it has would
    /// go to a socket nobody reads.
    pub fn opened(&self) -> bool {
        self.opened.load(Ordering::Relaxed)
    }

    /// How many times the guest answered.
    pub fn heard(&self) -> u64 {
        self.heard.load(Ordering::Relaxed)
    }

    /// **Ask the guest to go away.**  One frame on the connection the guest opened; `false` is
    /// "the guest's agent has not opened the channel" — which is a sentence, not a silent
    /// no-op (the run's caller says it).
    pub fn ask(&self) -> bool {
        let mut guest = match self.guest.lock() {
            Ok(guest) => guest,
            Err(_) => return false,
        };
        let Some(stream) = guest.as_mut() else {
            return false;
        };
        let sent = dc_vsock::write_frame(
            stream,
            &Frame::new(KIND_SHUTDOWN, Vec::new()),
            self.service.port(),
        )
        .is_ok();
        if sent {
            self.asked.store(true, Ordering::Relaxed);
        }
        sent
    }

    /// Accept one guest connection and keep it: the guest's agent dials **once**, when it
    /// starts, and the request goes on that connection whenever the run is over.
    pub fn serve(&self) -> Result<(), dc_vsock::VsockError> {
        let port = self.service.port();
        let mut stream = self.service.accept()?;
        self.opened.store(true, Ordering::Relaxed);
        if let Ok(mut guest) = self.guest.lock() {
            *guest = stream.try_clone().ok();
        }
        // The conversation is the guest's: it may say it heard (a line for the run's log), and
        // it may say nothing at all — the reboot is what answers, and it ends the machine.
        let mut reader = dc_vsock::Reader::new();
        while let Ok(Some(frame)) = reader.read_frame(&mut stream, port) {
            match frame.kind {
                KIND_HELLO => {}
                KIND_REBOOTING => {
                    self.heard.fetch_add(1, Ordering::Relaxed);
                    milestone!("power: the guest answered — it is rebooting");
                }
                _ => {}
            }
        }
        self.opened.store(false, Ordering::Relaxed);
        Ok(())
    }

    /// Serve on a thread of its own, returning the handle the caller keeps.
    pub fn serve_in_background(self: &Arc<Self>) -> std::thread::JoinHandle<()> {
        let channel = self.clone();
        std::thread::spawn(move || {
            let _ = channel.serve();
        })
    }
}

/// What the guest's agent sends when it opens the channel, and what it says when it heard.
pub mod guest {
    use super::*;

    pub fn hello() -> Frame {
        Frame::new(KIND_HELLO, Vec::new())
    }

    pub fn rebooting() -> Frame {
        Frame::new(KIND_REBOOTING, Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn the_host_asks_and_the_guest_hears_it_over_a_real_socket() {
        let dir = tempfile::tempdir().unwrap();
        let channel = Arc::new(ShutdownChannel::listen(&dir.path().join("v.sock")).unwrap());
        let port = channel.port();
        assert_eq!(port, dc_vsock::ports::SHUTDOWN);
        let thread = channel.serve_in_background();

        // The guest's agent dials, as it does at boot, and says hello.
        let mut guest = std::os::unix::net::UnixStream::connect(dc_vsock::listener_path(
            &dir.path().join("v.sock"),
            port,
        ))
        .unwrap();
        guest
            .set_read_timeout(Some(std::time::Duration::from_millis(2000)))
            .unwrap();
        guest.write_all(&guest::hello().encode()).unwrap();
        guest.flush().unwrap();
        for _ in 0..200 {
            if channel.opened() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert!(channel.opened(), "the guest opened the channel");

        // The run ends, and the host asks.
        assert!(channel.ask(), "the request went out");
        let mut reader = dc_vsock::Reader::new();
        let frame = loop {
            match reader.read_frame(&mut guest, port) {
                Ok(Some(frame)) => break frame,
                Ok(None) => panic!("the channel ended"),
                Err(e) => {
                    if let dc_vsock::VsockError::Io { source, .. } = &e {
                        if source.kind() == std::io::ErrorKind::WouldBlock
                            || source.kind() == std::io::ErrorKind::TimedOut
                        {
                            continue;
                        }
                    }
                    panic!("{e}");
                }
            }
        };
        assert_eq!(frame.kind, KIND_SHUTDOWN);

        // And the guest answers, which is the host's confirmation.
        guest.write_all(&guest::rebooting().encode()).unwrap();
        guest.flush().unwrap();
        for _ in 0..200 {
            if channel.heard() == 1 {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(channel.heard(), 1);
        drop(guest);
        let _ = thread.join();
    }

    #[test]
    fn asking_a_guest_that_never_opened_the_channel_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let channel = ShutdownChannel::listen(&dir.path().join("v.sock")).unwrap();
        // Nothing has dialled: the request has nowhere to go, and it says that rather than
        // pretending it asked (a run whose guest never came up is a run with a sentence).
        assert!(!channel.opened());
        assert!(!channel.ask());
        assert_eq!(channel.heard(), 0);
    }
}
