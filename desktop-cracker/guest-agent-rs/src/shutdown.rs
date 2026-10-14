//! **The guest's own way out**: the shutdown channel, and the reboot that ends the machine.
//!
//! Firecracker has no ACPI power management, so nothing the host does can power this guest off: the
//! *guest* is what ends the machine.  On x86 the kernel's own `reboot(2)` pulses the i8042 keyboard
//! controller's reset line — the one legacy device Firecracker emulates for exactly this — and
//! Firecracker exits by itself.  (`poweroff` would not: the guest's system would shut down and the
//! process would stay, which is Firecracker's own documented behaviour.)
//!
//! So this verb does two things and is deliberately dull about both, exactly as the C agent was:
//!
//! 1. it opens the channel **now** and tells the host it is there, so a request from the host is
//!    never written at a socket nobody is reading;
//! 2. it waits — on that channel, or on a **file the system on the disk watches** when the caller
//!    asks for one (`--watch`, which is how the session that has discarded this process's own
//!    memory still asks for a shutdown) — and then reboots.
//!
//! It runs as the agent's **first act at boot**, before the pivot: the kernel's reboot is its own,
//! and it works the same in the initramfs and in the system on the disk.

use std::io::{Read, Write};
use std::time::Duration;

use crate::channel::{self, ports};

/// The shutdown channel's kinds (`dc-fc-power`).
pub const POWER_SHUTDOWN: u16 = 1;
/// The guest is there and holding the channel.
pub const POWER_HELLO: u16 = 2;
/// The guest is going down (the host's own confirmation that the request landed).
pub const POWER_REBOOTING: u16 = 3;

/// One small frame: a length, a kind and the payload (the project's own framing).
fn send_frame(
    channel: &mut std::os::unix::net::UnixStream,
    kind: u16,
    payload: &[u8],
) -> std::io::Result<()> {
    let len = payload.len() as u32;
    let head: [u8; 6] = [
        (len & 0xff) as u8,
        ((len >> 8) & 0xff) as u8,
        ((len >> 16) & 0xff) as u8,
        ((len >> 24) & 0xff) as u8,
        (kind & 0xff) as u8,
        ((kind >> 8) & 0xff) as u8,
    ];
    channel.write_all(&head)?;
    if !payload.is_empty() {
        channel.write_all(payload)?;
    }
    channel.flush()
}

/// Read one frame, waiting for the pieces of it.
fn read_frame<R: Read>(stream: &mut R) -> std::io::Result<(u16, Vec<u8>)> {
    let mut head = [0u8; 6];
    stream.read_exact(&mut head)?;
    let len = u32::from_le_bytes([head[0], head[1], head[2], head[3]]) as usize;
    let kind = u16::from_le_bytes([head[4], head[5]]);
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload)?;
    Ok((kind, payload))
}

/// `shutdown [--watch FILE]`: hold the shutdown channel, and end the machine when the host (or the
/// watched file) asks.
///
/// Returns the exit code the agent should use — it is only ever reached when the reboot did *not*
/// happen (a host that let go, a channel that failed).
pub fn run(watch: Option<&str>) -> i32 {
    let Some(channel) = channel::dial(ports::SHUTDOWN) else {
        crate::console::note("deskd: the shutdown channel did not answer");
        return 1;
    };
    let mut channel = channel;
    if let Err(e) = send_frame(&mut channel, POWER_HELLO, b"") {
        crate::console::note(&format!("deskd: the shutdown channel: {e}"));
        return 1;
    }

    // The watched file and the channel, **without a busy loop**: the channel is polled with a
    // fifth of a second's patience (a person's blink, and nothing to a shutdown), and the file is
    // checked every time the poll comes back empty.
    let watch = watch.map(std::path::PathBuf::from);
    let mut requested = false;
    loop {
        if let Some(path) = &watch {
            if path.exists() {
                requested = true;
            }
        }
        if !requested {
            match read_one(&mut channel) {
                Ok(Some(POWER_SHUTDOWN)) => requested = true,
                Ok(Some(_)) => continue,
                Ok(None) => return 0, // the host let go: the run is over, and so is this
                Err(_) => return 0,
            }
            continue;
        }
        // The host asked: say so, give the disks their work back, and reset the machine.
        crate::console::say("DESK-POWEROFF the host asked; rebooting to end the machine");
        let _ = send_frame(&mut channel, POWER_REBOOTING, b"");
        unsafe { libc::sync() };
        drop(channel);
        let rc = unsafe { libc::reboot(libc::RB_AUTOBOOT) };
        // Only reachable when the kernel refused the reboot.
        crate::console::note(&format!(
            "deskd: reboot returned ({rc}): {}",
            std::io::Error::last_os_error()
        ));
        return 0;
    }
}

/// Wait up to a fifth of a second for a frame on the channel, and answer its kind.
fn read_one(channel: &mut std::os::unix::net::UnixStream) -> std::io::Result<Option<u16>> {
    let fd = std::os::fd::AsRawFd::as_raw_fd(channel);
    let mut p = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let ready = loop {
        let n = unsafe { libc::poll(&mut p, 1, 200) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        break n;
    };
    if ready == 0 || p.revents & libc::POLLIN == 0 {
        return Ok(None);
    }
    let (kind, _payload) = read_frame(channel)?;
    Ok(Some(kind))
}

/// The pause this loop takes when it has nothing to do: the poll's own patience, named so a test
/// can see it.
pub const POLL_PATIENCE: Duration = Duration::from_millis(200);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_frame_is_a_length_a_kind_and_the_payload() {
        let mut buffer = Vec::new();
        let head: [u8; 6] = [0, 0, 0, 0, POWER_HELLO as u8, 0];
        buffer.extend_from_slice(&head);
        assert_eq!(&buffer[4..6], &POWER_HELLO.to_le_bytes());
    }

    #[test]
    fn a_frame_split_across_reads_is_still_one_frame() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&2u32.to_le_bytes());
        wire.extend_from_slice(&POWER_SHUTDOWN.to_le_bytes());
        wire.extend_from_slice(b"hi");
        let mut reader = std::io::Cursor::new(wire);
        let (kind, payload) = read_frame(&mut reader).unwrap();
        assert_eq!(kind, POWER_SHUTDOWN);
        assert_eq!(payload, b"hi");
    }

    #[test]
    fn the_patience_is_a_fifth_of_a_second() {
        assert_eq!(POLL_PATIENCE.as_millis(), 200);
    }
}
