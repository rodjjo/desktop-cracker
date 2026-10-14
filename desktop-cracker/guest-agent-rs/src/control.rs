//! **The control share**, from the guest's side: the run's own files, fetched by name.
//!
//! The host serves these over the control channel (port 56000, `dc-fc-control`): the guest asks for
//! a name and gets the file's bytes, a name the run did not offer comes back as `MISSING`, and one
//! name — the status the guest publishes — may be written back.
//!
//! ```text
//! guest → host   kind 1 (READ)   "name\n"                 → kind 2 (DATA)  <bytes>
//!                                                            kind 3 (MISSING) "name\n"
//! guest → host   kind 4 (WRITE)  "name\n<bytes>"          → kind 5 (WROTE)  "name\n"
//!                                                            kind 6 (REFUSED) "name\n"
//! ```
//!
//! The protocol is the host's own (`dc-fc-control`'s documentation), and it is written out here
//! rather than shared as a crate because the guest's agent is built for the guest: what is shared
//! is the *wire*, and a wire is numbers.

use std::io::{Read, Write};
use std::time::Duration;

use crate::channel::{self, ports};

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

/// What one request answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// The file's bytes.
    Data(Vec<u8>),
    /// The run did not put a file by that name in the share.
    Missing,
    /// The guest's write was taken.
    Wrote,
    /// The guest's write was refused.
    Refused,
}

/// One frame, as the control channel carries it: a length, a kind and a payload.
fn encode_frame(kind: u16, payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut out = Vec::with_capacity(6 + payload.len());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(payload);
    out
}

/// Read one frame, waiting for the pieces of it (a byte stream hands a message over in as many
/// reads as it likes).
fn read_frame<R: Read>(stream: &mut R) -> std::io::Result<(u16, Vec<u8>)> {
    let mut head = [0u8; 6];
    stream.read_exact(&mut head)?;
    let len = u32::from_le_bytes([head[0], head[1], head[2], head[3]]) as usize;
    let kind = u16::from_le_bytes([head[4], head[5]]);
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload)?;
    Ok((kind, payload))
}

/// **One conversation with the control share**: dial, send one request, read the answers until the
/// host stops talking.
///
/// It is the C agent's own shape — one connection per `control` invocation, one frame per name —
/// and the connection is closed on the way out, which is what tells the host this ask is done.
pub fn request(kinds: &[(u16, Vec<u8>)]) -> std::io::Result<Vec<Answer>> {
    let Some(mut channel) = channel::dial(ports::CONTROL) else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotConnected,
            "the control channel did not answer",
        ));
    };
    // A bounded wait: the host answers a request within its own turn, and a share that has nothing
    // to say must not park the guest's boot.
    let _ = channel.set_read_timeout(Some(Duration::from_secs(5)));
    for (kind, payload) in kinds {
        channel.write_all(&encode_frame(*kind, payload))?;
    }
    channel.flush()?;

    let mut answers = Vec::new();
    // **One answer per request, and no more.**  The host answers a `READ` with one frame (`DATA`
    // or `MISSING`) and a `WRITE` with one (`WROTE` or `REFUSED`), and it keeps the connection open
    // afterwards — waiting for "one more" here would cost the read's whole timeout for every name,
    // which is what a guest that takes half a minute to read its own files looks like (measured:
    // the boot timed out with the session sitting in this loop).
    for _ in kinds {
        match read_frame(&mut channel) {
            Ok((kind, payload)) => answers.push(match kind {
                KIND_DATA => Answer::Data(payload),
                KIND_MISSING => Answer::Missing,
                KIND_WROTE => Answer::Wrote,
                KIND_REFUSED => Answer::Refused,
                _ => Answer::Missing,
            }),
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                break
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        }
    }
    Ok(answers)
}

/// **Read one file by name**, as `control <name>` does.
pub fn read(name: &str) -> std::io::Result<Answer> {
    let mut payload = name.as_bytes().to_vec();
    payload.push(b'\n');
    let answers = request(&[(KIND_READ, payload)])?;
    Ok(answers.into_iter().next().unwrap_or(Answer::Missing))
}

/// **Publish something for the host** — the one direction a guest may write in.
pub fn write(name: &str, bytes: &[u8]) -> std::io::Result<Answer> {
    let mut payload = name.as_bytes().to_vec();
    payload.push(b'\n');
    payload.extend_from_slice(bytes);
    let answers = request(&[(KIND_WRITE, payload)])?;
    Ok(answers.into_iter().next().unwrap_or(Answer::Missing))
}

/// The names the run offers.  A name it did not offer is not an error: a run with no shares has no
/// `shares` file, and one of them (the disk's passphrase) is root's alone.
pub const CONTROL_FILES: [&str; 9] = [
    "diskplan",
    "mounts",
    "disks",
    "root.pass",
    "x-display.env",
    "network",
    "shares",
    "display-geometry",
    "camera",
];

/// Where the run's files live once they are fetched.
pub const CONTROL_DIR: &str = "/run/desktop-cracker";

/// Is this one of the run's **secrets**?  It is the agent's own list, and it is the one place that
/// decides: the passphrase is root's alone.
pub fn is_secret(name: &str) -> bool {
    name == "root.pass"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_frame_is_a_length_a_kind_and_the_payload() {
        assert_eq!(encode_frame(2, b"abc"), vec![3, 0, 0, 0, 2, 0, b'a', b'b', b'c']);
    }

    #[test]
    fn a_frame_split_across_reads_is_still_one_frame() {
        let wire = encode_frame(KIND_DATA, &[7u8; 200]);
        let mut reader = std::io::Cursor::new(wire);
        let (kind, payload) = read_frame(&mut reader).unwrap();
        assert_eq!(kind, KIND_DATA);
        assert_eq!(payload.len(), 200);
    }

    #[test]
    fn only_the_root_disks_passphrase_is_a_secret() {
        assert!(is_secret("root.pass"));
        for name in ["shares", "disks", "display-geometry", "network", "camera"] {
            assert!(!is_secret(name), "{name} is the guest user's to read");
        }
    }

    #[test]
    fn the_names_the_run_offers_are_the_ones_the_control_channel_is_asked_for() {
        assert_eq!(
            CONTROL_FILES,
            [
                "diskplan",
                "mounts",
                "disks",
                "root.pass",
                "x-display.env",
                "network",
                "shares",
                "display-geometry",
                "camera"
            ]
        );
    }
}
