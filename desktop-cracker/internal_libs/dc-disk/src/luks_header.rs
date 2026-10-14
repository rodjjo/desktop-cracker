//! What a LUKS header says, read **without root and without opening the container**.
//!
//! A disk this project makes is a LUKS container, and the host recognises one by its magic
//! — which answers "is this disk encrypted?", and nothing else.  A wrong password and a
//! truncated file look exactly alike from out there, and the difference matters to the
//! person waiting: one says "try again", the other says "this disk is broken, and the
//! answer is not another password".
//!
//! The header carries the rest of the answer, and it is plain bytes in the first sector
//! (the LUKS1 on-disk format, which is what `cryptsetup luksFormat` writes by default):
//!
//! ```text
//!   0   6   magic       "LUKS\xba\xbe"
//!   6   2   version     1
//!   8  32   cipher-name
//!  40  32   cipher-mode
//!  72  32   hash-spec
//! 104   4   payload-offset (in sectors)
//! 108   4   key-bytes
//! 112  20   mk-digest (the master key's salt/digest)
//! 132   4   mk-digest-salt
//! 136   4   mk-digest-iter
//! 208   4   uuid
//! 212   8   key-slot[0..8], 48 bytes each
//! ```
//!
//! So a damaged header is something to *report*, not to guess about: a version that is
//! not 1 or 2, a payload offset of zero, or an unreadable sector are each a sentence the
//! user can act on.  Nothing here needs a password, which is the point: this runs *before*
//! the user is asked for one.

use std::path::Path;

/// What the first sector of a disk says about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LuksHeader {
    /// `1` or `2` (the on-disk version byte).
    pub version: u16,
    /// The container's UUID, in its canonical hex form.
    pub uuid: String,
    /// The cipher, as the header spells it (`aes`, `aes-xts-plain64`, …).
    pub cipher: String,
    /// The hash the key derivation uses.
    pub hash: String,
    /// Where the encrypted payload starts, in MiB — the header's own byte offset divided
    /// by 1 MiB, which is the "the container is smaller than its header" check.
    pub payload_offset_mib: u64,
    /// The key size, in bytes.
    pub key_bytes: u32,
}

/// Why a disk is not a healthy LUKS container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderProblem {
    /// The magic is not there at all: this is not a LUKS container.
    NotLuks,
    /// The magic is there but the version byte is one this format does not have.
    UnknownVersion(u16),
    /// The payload offset is zero: the header says the data starts where the header does,
    /// which no healthy container says — the header is damaged.
    NoPayload,
    /// The first sector could not be read at all.
    Unreadable(String),
}

impl HeaderProblem {
    /// A sentence for the user (the log, and the window's status line).
    pub fn sentence(&self, path: &Path) -> String {
        match self {
            HeaderProblem::NotLuks => format!(
                "{} is not a LUKS container: it cannot be opened with a password",
                path.display()
            ),
            HeaderProblem::UnknownVersion(v) => format!(
                "{} has a LUKS header of version {v}, which this project does not know \
                 (its disks are version 1)",
                path.display()
            ),
            HeaderProblem::NoPayload => format!(
                "{} has a damaged LUKS header (its payload offset is zero): no password \
                 will open it, and the disk needs to be made again",
                path.display()
            ),
            HeaderProblem::Unreadable(why) => format!(
                "{} could not be read to check its LUKS header: {why}",
                path.display()
            ),
        }
    }
}

/// The first 512 bytes of a disk — a **bounded** read, because a disk is a raw file (or a block
/// device): the answer is in the first sector, and reading a header's worth and stopping is what
/// keeps a 20 GiB disk from being read to answer a question about 512 bytes.
fn first_sector(path: &Path) -> Result<Vec<u8>, String> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let mut buf = vec![0u8; 512];
    f.read_exact(&mut buf).map_err(|e| e.to_string())?;
    Ok(buf)
}

fn field(bytes: &[u8], start: usize, len: usize) -> String {
    let end = (start + len).min(bytes.len());
    if start >= end {
        return String::new();
    }
    let raw = &bytes[start..end];
    let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).trim().to_string()
}

fn u32_be(bytes: &[u8], start: usize) -> u32 {
    if bytes.len() < start + 4 {
        return 0;
    }
    u32::from_be_bytes([
        bytes[start],
        bytes[start + 1],
        bytes[start + 2],
        bytes[start + 3],
    ])
}

/// A UUID is 16 raw bytes in the header; it is spelled the way `cryptsetup` spells it.
fn uuid_string(bytes: &[u8], start: usize) -> String {
    if bytes.len() < start + 16 {
        return String::new();
    }
    let b = &bytes[start..start + 16];
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-\
         {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        b[0],
        b[1],
        b[2],
        b[3],
        b[4],
        b[5],
        b[6],
        b[7],
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15]
    )
}

/// Does this disk look like a LUKS container (its magic), and nothing more?
pub fn magic_present(bytes: &[u8]) -> bool {
    bytes.len() >= 6 && &bytes[..6] == b"LUKS\xba\xbe"
}

/// Read and interpret the header of a raw disk (or a block device shown as one).
pub fn read_header(path: &Path) -> Result<LuksHeader, HeaderProblem> {
    let bytes = first_sector(path).map_err(HeaderProblem::Unreadable)?;

    if !magic_present(&bytes) {
        return Err(HeaderProblem::NotLuks);
    }
    let version = if bytes.len() >= 8 {
        u16::from_be_bytes([bytes[6], bytes[7]])
    } else {
        0
    };
    if version != 1 && version != 2 {
        return Err(HeaderProblem::UnknownVersion(version));
    }
    let payload_offset = u32_be(&bytes, 104) as u64;
    if payload_offset == 0 {
        return Err(HeaderProblem::NoPayload);
    }
    Ok(LuksHeader {
        version,
        uuid: uuid_string(&bytes, 208),
        cipher: field(&bytes, 8, 32),
        hash: field(&bytes, 72, 32),
        payload_offset_mib: (payload_offset * 512) / (1024 * 1024),
        key_bytes: u32_be(&bytes, 108),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A header the way `cryptsetup luksFormat` writes one, byte for byte where it counts.
    fn a_header() -> Vec<u8> {
        let mut b = vec![0u8; 512];
        b[..6].copy_from_slice(b"LUKS\xba\xbe");
        b[6..8].copy_from_slice(&1u16.to_be_bytes());
        b[8..11].copy_from_slice(b"aes");
        b[40..51].copy_from_slice(b"xts-plain64");
        b[72..78].copy_from_slice(b"sha256");
        b[104..108].copy_from_slice(&4096u32.to_be_bytes()); // payload at 2 MiB
        b[108..112].copy_from_slice(&32u32.to_be_bytes());
        for (i, byte) in b[208..224].iter_mut().enumerate() {
            *byte = i as u8;
        }
        b
    }

    #[test]
    fn a_healthy_header_reads_what_it_says() {
        let bytes = a_header();
        assert!(magic_present(&bytes));
        // The same interpretation the reader does, without a file.
        assert_eq!(u32_be(&bytes, 104), 4096);
        assert_eq!(field(&bytes, 8, 32), "aes");
        assert_eq!(field(&bytes, 72, 32), "sha256");
        assert_eq!(u32_be(&bytes, 108), 32);
        assert_eq!(
            uuid_string(&bytes, 208),
            "00010203-0405-0607-0809-0a0b0c0d0e0f"
        );
        assert_eq!((u32_be(&bytes, 104) as u64 * 512) / (1024 * 1024), 2);
    }

    #[test]
    fn a_missing_magic_is_not_a_container() {
        let mut bytes = a_header();
        bytes[0] = b'X';
        assert!(!magic_present(&bytes));
    }

    #[test]
    fn a_zero_payload_offset_is_a_damaged_header_and_says_so() {
        // The distinction the loop needs: this is **not** a wrong password, and telling
        // the user to try again would be a lie.
        let problem = HeaderProblem::NoPayload;
        let sentence = problem.sentence(Path::new("/tmp/root.raw"));
        assert!(sentence.contains("damaged LUKS header"), "{sentence}");
        assert!(sentence.contains("no password will open it"), "{sentence}");
    }

    #[test]
    fn every_problem_has_a_sentence_with_the_path_in_it() {
        for problem in [
            HeaderProblem::NotLuks,
            HeaderProblem::UnknownVersion(9),
            HeaderProblem::NoPayload,
            HeaderProblem::Unreadable("boom".into()),
        ] {
            let sentence = problem.sentence(Path::new("/tmp/the-disk.raw"));
            assert!(sentence.contains("/tmp/the-disk.raw"), "{sentence}");
            assert!(!sentence.is_empty());
        }
    }
}
