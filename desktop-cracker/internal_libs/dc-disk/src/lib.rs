//! **What a disk is, told from its own bytes.**
//!
//! A disk this project makes is a **raw** file whose content is a LUKS container with a partition
//! table inside it — that is what `desk-disk` writes, in a microVM of its own, and what a run
//! attaches to the guest (Firecracker attaches raw images and nothing else).  Two questions are
//! asked about a disk on the host, and neither one opens it:
//!
//! * **is it a container?**  Its first 512 bytes carry `LUKS\xba\xbe`, which is the header's own
//!   magic (`luks_header`), and it is answered before the user is ever asked for a passphrase:
//!   a run that is pointed at a plain image must not ask for a password nothing will accept;
//! * **is it a shape a run can boot?**  A raw file — the bytes a disk is, not an image another
//!   tool wrapped it in.  Firecracker attaches raw images and nothing else, and saying so with
//!   the conversion the user has to make is the difference between a run that fails with a
//!   sentence and one that fails with a mystery.
//!
//! The **guest** is what decrypts a disk: its own `cryptsetup` opens the container with the
//! passphrase the application handed it through the control share, and
//! the host never holds a key for it.  So there is no secret object here, no block node, no
//! command line to build — only the two answers above, and the error type the disk jobs share.

pub mod luks_header;

use std::path::Path;

/// Why a disk job could not go on.  One type for the whole project's disk handling, so a caller
/// that only writes a plan and a caller that runs a job agree on what a failure is.
#[derive(Debug, thiserror::Error)]
pub enum DiskError {
    #[error("{0}")]
    Io(#[from] dc_common::Error),
    #[error("{program} failed ({status}): {stderr}")]
    Tool {
        program: String,
        status: String,
        stderr: String,
    },
    #[error("{0}")]
    Invalid(String),
}

pub type Result<T> = std::result::Result<T, DiskError>;

/// **Is this file a LUKS container?**  Read from its own first 512 bytes — the magic only, so a
/// password is never needed and the question is answered in one `read`.
///
/// `None` means the question could not be asked at all (the file is not readable): "I could not
/// look" must not be answered as "there is nothing to decrypt", or a locked image would be
/// attached as if it were plain.
pub fn luks_container(path: &Path) -> Option<bool> {
    use std::io::Read;
    const HEADER: usize = 512;
    let mut file = std::fs::File::open(path).ok()?;
    let mut head = [0u8; HEADER];
    let n = file.read(&mut head).ok()?;
    if n < HEADER {
        return Some(false);
    }
    Some(luks_header::magic_present(&head))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A file that is not there is a question that could not be asked, not a "no".
    #[test]
    fn a_file_that_is_not_there_is_not_an_answer() {
        assert_eq!(luks_container(Path::new("/nonexistent/disk.raw")), None);
    }

    /// A file whose first sector is not the header's magic is not a container.
    #[test]
    fn a_plain_image_is_not_a_container() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("plain.raw");
        std::fs::write(&path, vec![0u8; 1024]).unwrap();
        assert_eq!(luks_container(&path), Some(false));
    }

    /// A sector **short of the header** is not a container either: half a header is not a header.
    #[test]
    fn a_truncated_file_is_not_a_container() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("short.raw");
        std::fs::write(&path, b"LUKS\xba\xbe").unwrap();
        assert_eq!(luks_container(&path), Some(false));
    }

    /// The header's own magic is what makes it a container, and it is read from the file.
    #[test]
    fn the_magic_makes_it_a_container() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("locked.raw");
        let mut head = vec![0u8; 512];
        head[..6].copy_from_slice(b"LUKS\xba\xbe");
        std::fs::write(&path, head).unwrap();
        assert_eq!(luks_container(&path), Some(true));
    }

    /// A failure a caller can read: the disk job's own sentence, with the program in it.
    #[test]
    fn a_failed_tool_says_which_one_and_why() {
        let e = DiskError::Tool {
            program: "cryptsetup".into(),
            status: "exit status: 2".into(),
            stderr: "Device is not a LUKS device".into(),
        };
        let said = e.to_string();
        assert!(said.contains("cryptsetup"), "{said}");
        assert!(said.contains("not a LUKS device"), "{said}");
    }
}
