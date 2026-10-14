//! **A shared folder, mounted in the guest**: the FUSE filesystem this project's agent serves.
//!
//! The host's folders are not a device Firecracker can attach, so the guest gets them the way the
//! project always has: the agent dials the share's own channel (port 54000, 54001, …) and answers
//! the kernel's FUSE requests out of the host's own filesystem.  The host's side is `dc-fc-share`;
//! what is here is the guest's: the kernel's request/reply structures, the opcodes, and the
//! translation between them and the share protocol.
//!
//! ## The two protocols, and why the translation is exact
//!
//! ```text
//!   the kernel ── /dev/fuse ──►  this program  ── vsock ──►  the host's share service
//!      (fuse_in_header + body)      (translate)                 (KIND_* + payload)
//! ```
//!
//! Every request is **one call**: the kernel's own request is turned into one share frame, the
//! share's answer into one FUSE reply.  There is no pipelining, and that is deliberate — the C
//! agent's own postmortem says why (`FUSE_ASYNC_READ` is the flag that must **not** be set: two
//! requests in flight on one socket are two replies the server cannot tell apart, which was a
//! Firefox profile that never came up and a VLC that died on a video it had read a second earlier).
//!
//! ## What the guest's own user can do with it
//!
//! The mount is made **for the guest's user**: `allow_other` and `default_permissions`, so the
//! modes the host reports are the modes that apply, and a shared folder is not a filesystem only
//! the process that mounted it may read (both are the C agent's own corrections: a mount whose
//! `rootmode` had no permission bits, and a folder the guest's own user was refused at).

use std::io::{Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};

use crate::channel;

// ---------------------------------------------------------------- the share service's own kinds

/// The tag the guest names itself with, before anything is mounted.
pub const KIND_HELLO: u16 = 1;
pub const KIND_LOOKUP: u16 = 2;
pub const KIND_GETATTR: u16 = 3;
pub const KIND_OPENDIR: u16 = 4;
pub const KIND_READDIR: u16 = 5;
pub const KIND_RELEASE: u16 = 6;
pub const KIND_OPEN: u16 = 7;
pub const KIND_READ: u16 = 8;
pub const KIND_WRITE: u16 = 9;
pub const KIND_CREATE: u16 = 10;
pub const KIND_MKDIR: u16 = 11;
pub const KIND_UNLINK: u16 = 12;
pub const KIND_RMDIR: u16 = 13;
pub const KIND_RENAME: u16 = 14;
pub const KIND_TRUNCATE: u16 = 15;
pub const KIND_READLINK: u16 = 16;
/// An entry of a listing: the child's handle, its kind and its name.
pub const KIND_ENTRY: u16 = 17;
/// The answer to a request that has nothing to say.
pub const KIND_OK: u16 = 100;
/// A handle and its attributes.
pub const KIND_ATTR: u16 = 101;
/// Bytes (a read, a listing).
pub const KIND_DATA: u16 = 102;
/// A refusal, with the errno as its payload.
pub const KIND_ERROR: u16 = 103;

/// The kind numbers a listing's entry carries (`dc-fc-share`'s own: the `DT_*` values).
pub const KIND_DIR_ENTRY: u8 = 4;
pub const KIND_FILE_ENTRY: u8 = 8;
pub const KIND_LINK_ENTRY: u8 = 10;

/// The size of `dc-fc-share::Attrs::encode`: six 8-byte fields and four 4-byte ones.
pub const ATTRS_ENCODED: usize = 6 * 8 + 4 * 4;

/// The share service's own attributes, as they arrive on the wire.
///
/// **The order is `Attrs::encode`'s**: inode, size, blocks, then the mode as a 64-bit word (it is
/// a `u64` on the wire even where the value is 32 bits), then nlink, uid and gid, then the three
/// times.  Getting it wrong is not a small mistake: a mode read from the wrong offset is a
/// directory whose permissions are a `u64`'s high half, and the kernel then answers a `stat`
/// nobody can explain.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Attrs {
    pub ino: u64,
    pub size: u64,
    pub blocks: u64,
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: i64,
    pub atime: i64,
    pub ctime: i64,
}

impl Attrs {
    /// Decode the share's own encoding.
    pub fn decode(bytes: &[u8]) -> Option<Attrs> {
        if bytes.len() < ATTRS_ENCODED {
            return None;
        }
        let u64_at = |i: usize| u64::from_le_bytes(bytes[i..i + 8].try_into().unwrap());
        let u32_at = |i: usize| u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap());
        Some(Attrs {
            ino: u64_at(0),
            size: u64_at(8),
            blocks: u64_at(16),
            mode: u32_at(24),
            nlink: u32_at(28),
            uid: u32_at(32),
            gid: u32_at(36),
            mtime: u64_at(40) as i64,
            atime: u64_at(48) as i64,
            ctime: u64_at(56) as i64,
        })
    }

    /// **The kernel's own `struct fuse_attr`**, which is what a reply carries: the same numbers, in
    /// the kernel's layout (three times as seconds *and* nanoseconds, then the mode, the link
    /// count, the owner, and the block size this filesystem reports).
    pub fn to_fuse(&self) -> [u8; 88] {
        let mut out = [0u8; 88];
        put_u64(&mut out, 0, self.ino);
        put_u64(&mut out, 8, self.size);
        put_u64(&mut out, 16, self.blocks);
        put_u64(&mut out, 24, self.atime as u64);
        put_u64(&mut out, 32, self.mtime as u64);
        put_u64(&mut out, 40, self.ctime as u64);
        // atimensec, mtimensec, ctimensec (the share carries whole seconds), mode, nlink, uid,
        // gid, rdev, blksize, flags.
        put_u32(&mut out, 48, 0);
        put_u32(&mut out, 52, 0);
        put_u32(&mut out, 56, 0);
        put_u32(&mut out, 60, self.mode);
        put_u32(&mut out, 64, self.nlink);
        put_u32(&mut out, 68, self.uid);
        put_u32(&mut out, 72, self.gid);
        put_u32(&mut out, 76, 0);
        put_u32(&mut out, 80, 4096); // blksize: the block size this filesystem reports
        put_u32(&mut out, 84, 0);
        out
    }
}

// ---------------------------------------------------------------- the kernel's own layout

/// `struct fuse_in_header`: what the kernel writes before every request (40 bytes).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InHeader {
    pub len: u32,
    pub opcode: u32,
    pub unique: u64,
    pub nodeid: u64,
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
}

impl InHeader {
    pub const SIZE: usize = 40;

    pub fn decode(bytes: &[u8]) -> Option<InHeader> {
        if bytes.len() < InHeader::SIZE {
            return None;
        }
        let u32_at = |i: usize| u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap());
        let u64_at = |i: usize| u64::from_le_bytes(bytes[i..i + 8].try_into().unwrap());
        Some(InHeader {
            len: u32_at(0),
            opcode: u32_at(4),
            unique: u64_at(8),
            nodeid: u64_at(16),
            uid: u32_at(24),
            gid: u32_at(28),
            pid: u32_at(32),
        })
    }
}

/// The FUSE opcodes this filesystem answers (`linux/fuse.h`'s own numbers).
pub mod opcode {
    pub const LOOKUP: u32 = 1;
    pub const FORGET: u32 = 2;
    pub const GETATTR: u32 = 3;
    pub const SETATTR: u32 = 4;
    pub const READLINK: u32 = 5;
    pub const SYMLINK: u32 = 6;
    pub const MKNOD: u32 = 8;
    pub const MKDIR: u32 = 9;
    pub const UNLINK: u32 = 10;
    pub const RMDIR: u32 = 11;
    pub const RENAME: u32 = 12;
    pub const LINK: u32 = 13;
    pub const OPEN: u32 = 14;
    pub const READ: u32 = 15;
    pub const WRITE: u32 = 16;
    pub const STATFS: u32 = 17;
    pub const RELEASE: u32 = 18;
    pub const FSYNC: u32 = 20;
    pub const FLUSH: u32 = 25;
    pub const INIT: u32 = 26;
    pub const OPENDIR: u32 = 27;
    pub const READDIR: u32 = 28;
    pub const RELEASEDIR: u32 = 29;
    pub const FSYNCDIR: u32 = 30;
    pub const ACCESS: u32 = 34;
    pub const CREATE: u32 = 35;
    pub const DESTROY: u32 = 38;
    /// The opcodes a *different* filesystem answers, which this one must refuse politely (the
    /// kernel asks for them on any mount, and an answer of "no" is not an error).
    pub const GETXATTR: u32 = 22;
    pub const LISTXATTR: u32 = 23;
}

/// `FUSE_BIG_WRITES`: the one flag this filesystem sets (no `FUSE_ASYNC_READ`, deliberately — see
/// the module's own note).
pub const FUSE_BIG_WRITES: u32 = 1 << 5;
/// The entry's validity in the kernel's cache: zero, because the host's folder is the truth and a
/// cached mode is a mode the guest would have to be told has changed.
pub const ENTRY_VALID: u64 = 0;
/// `FOPEN_KEEP_CACHE`: the kernel may keep what it has read.
pub const FOPEN_KEEP_CACHE: u32 = 1 << 1;

// ---------------------------------------------------------------- the wire to the host

/// One frame: a length, a kind and a payload (the project's own framing).
pub fn encode_frame(kind: u16, payload: &[u8]) -> Vec<u8> {
    let len = payload.len() as u32;
    let mut out = Vec::with_capacity(6 + payload.len());
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&kind.to_le_bytes());
    out.extend_from_slice(payload);
    out
}

/// One whole frame off a byte stream, waiting for its pieces.
pub fn read_frame<R: Read>(stream: &mut R) -> std::io::Result<(u16, Vec<u8>)> {
    let mut head = [0u8; 6];
    stream.read_exact(&mut head)?;
    let len = u32::from_le_bytes([head[0], head[1], head[2], head[3]]) as usize;
    let kind = u16::from_le_bytes([head[4], head[5]]);
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload)?;
    Ok((kind, payload))
}

/// The errno a refusal carries.
pub fn errno_of(payload: &[u8]) -> i32 {
    if payload.len() < 4 {
        return libc::EIO;
    }
    i32::from_le_bytes(payload[..4].try_into().unwrap())
}

// ---------------------------------------------------------------- the mount and its loop

/// The largest request the kernel can hand over (`FUSE_MIN_READ_BUFFER`: a write can be the
/// maximum write size plus the header).
pub const BUFSIZE: usize = 135_168;

/// The most entries one listing may hold (a folder that big is a folder nobody lists by hand).
pub const MAX_ENTRIES: usize = 4096;

/// One entry of the last listing: what the kernel is told, and where it points.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub node: u64,
    pub kind: u8,
    pub name: String,
}

/// **One mount**: the host's connection, `/dev/fuse`, and the entries of the last listing.
pub struct Mount {
    share: std::os::unix::net::UnixStream,
    fuse: OwnedFd,
    entries: Vec<Entry>,
}

impl Mount {
    /// One call to the host: the request, and the answer's kind and payload.
    fn call(&mut self, kind: u16, payload: &[u8]) -> std::io::Result<(u16, Vec<u8>)> {
        self.share.write_all(&encode_frame(kind, payload))?;
        self.share.flush()?;
        read_frame(&mut self.share)
    }

    /// The errno of a refusal, as a FUSE error.
    fn refused(&mut self, unique: u64, payload: &[u8]) {
        self.reply_error(unique, errno_of(payload));
    }

    /// A reply with no body.
    fn reply_ok(&mut self, unique: u64, body: &[u8]) {
        let mut out = Vec::with_capacity(16 + body.len());
        out.extend_from_slice(&((16 + body.len()) as u32).to_le_bytes());
        out.extend_from_slice(&0i32.to_le_bytes());
        out.extend_from_slice(&unique.to_le_bytes());
        out.extend_from_slice(body);
        if let Err(e) = self.fuse_write(&out) {
            crate::console::note(&format!("deskd-fuse: cannot answer: {e}"));
        }
    }

    /// A reply that says no, with the errno the guest's own tools expect.
    fn reply_error(&mut self, unique: u64, error: i32) {
        let mut out = Vec::with_capacity(16);
        out.extend_from_slice(&16u32.to_le_bytes());
        out.extend_from_slice(&(-error).to_le_bytes());
        out.extend_from_slice(&unique.to_le_bytes());
        if let Err(e) = self.fuse_write(&out) {
            crate::console::note(&format!("deskd-fuse: cannot answer an error: {e}"));
        }
    }

    fn fuse_write(&self, bytes: &[u8]) -> std::io::Result<()> {
        let mut written = 0;
        while written < bytes.len() {
            // SAFETY: the fd is `/dev/fuse` and the buffer is this call's own.
            let n = unsafe {
                libc::write(
                    self.fuse.as_raw_fd(),
                    bytes[written..].as_ptr() as *const libc::c_void,
                    bytes.len() - written,
                )
            };
            if n <= 0 {
                return Err(std::io::Error::last_os_error());
            }
            written += n as usize;
        }
        Ok(())
    }

    /// **`FUSE_INIT`**: what this filesystem is and what it can do.
    ///
    /// The one thing to notice is the flag that is **not** set: `FUSE_ASYNC_READ`.  It would let
    /// the kernel put several reads of one file in flight, and this server speaks to the host one
    /// request at a time on one socket, so they would be answered out of order (measured
    /// 2026-10-10: a Firefox profile that never came up, VLC dying on a video it had read a second
    /// earlier, a shared folder answering "Permission denied" for reasons `namei` could not name).
    fn do_init(&mut self, unique: u64, body: &[u8]) {
        let major = if body.len() >= 4 {
            u32::from_le_bytes(body[..4].try_into().unwrap())
        } else {
            7
        };
        let mut out = [0u8; 64];
        let (major, minor) = if major >= 7 { (7u32, 31u32) } else { (major, 0) };
        out[0..4].copy_from_slice(&major.to_le_bytes());
        out[4..8].copy_from_slice(&minor.to_le_bytes());
        out[8..12].copy_from_slice(&0u32.to_le_bytes()); // max_readahead: none
        out[12..16].copy_from_slice(&FUSE_BIG_WRITES.to_le_bytes());
        // **One request in flight** (`max_background = 1`, `congestion_threshold = 0`): this
        // server speaks to the host one request at a time on one socket, so two of them at once
        // are two replies it cannot tell apart.
        out[16..18].copy_from_slice(&1u16.to_le_bytes()); // max_background
        out[18..20].copy_from_slice(&0u16.to_le_bytes()); // congestion_threshold
        out[20..24].copy_from_slice(&65536u32.to_le_bytes()); // max_write
        out[24..28].copy_from_slice(&1u32.to_le_bytes()); // time_gran
        // The reply is the size Linux's own protocol expects for major 7 and a minor below the
        // one that added the fields after `time_gran` — which is what the C agent answered too.
        self.reply_ok(unique, &out[..56]);
    }

    /// **`FUSE_LOOKUP`**: a name inside a directory, answered with the entry the kernel caches.
    fn do_lookup(&mut self, unique: u64, nodeid: u64, body: &[u8]) {
        let name = name_of(body);
        let mut payload = (nodeid - 1).to_le_bytes().to_vec(); // node 1 is the share's root
        payload.extend_from_slice(name.as_bytes());
        match self.call(KIND_LOOKUP, &payload) {
            Ok((KIND_ATTR, reply)) if reply.len() >= 8 + ATTRS_ENCODED => {
                let child = u64::from_le_bytes(reply[..8].try_into().unwrap());
                let Some(attrs) = Attrs::decode(&reply[8..]) else {
                    return self.reply_error(unique, libc::EIO);
                };
                let mut out = [0u8; 128];
                out[0..8].copy_from_slice(&(child + 1).to_le_bytes()); // nodeid
                out[8..16].copy_from_slice(&1u64.to_le_bytes()); // generation
                out[16..24].copy_from_slice(&ENTRY_VALID.to_le_bytes());
                out[24..32].copy_from_slice(&ENTRY_VALID.to_le_bytes());
                out[40..128].copy_from_slice(&attrs.to_fuse());
                self.reply_ok(unique, &out);
            }
            Ok((KIND_ERROR, reply)) => self.refused(unique, &reply),
            _ => self.reply_error(unique, libc::EIO),
        }
    }

    /// **`FUSE_GETATTR`**: what a handle is.
    fn do_getattr(&mut self, unique: u64, nodeid: u64) {
        match self.attrs(nodeid) {
            Ok(attrs) => {
                let mut out = [0u8; 104];
                out[0..8].copy_from_slice(&ENTRY_VALID.to_le_bytes());
                out[8..12].copy_from_slice(&0u32.to_le_bytes());
                out[96..104].copy_from_slice(&0u64.to_le_bytes());
                out[16..104].copy_from_slice(&attrs.to_fuse());
                self.reply_ok(unique, &out);
            }
            Err(error) => self.reply_error(unique, error),
        }
    }

    /// The attributes of a handle, or the errno the host refused it with.
    fn attrs(&mut self, nodeid: u64) -> Result<Attrs, i32> {
        match self.call(KIND_GETATTR, &(nodeid - 1).to_le_bytes()) {
            Ok((KIND_ATTR, reply)) if reply.len() >= 8 + ATTRS_ENCODED => {
                Attrs::decode(&reply[8..]).ok_or(libc::EIO)
            }
            Ok((KIND_ERROR, reply)) => Err(errno_of(&reply)),
            _ => Err(libc::EIO),
        }
    }

    /// **`FUSE_SETATTR`**: a truncation (the only attribute this filesystem changes).
    fn do_setattr(&mut self, unique: u64, nodeid: u64, body: &[u8]) {
        // `struct fuse_setattr_in`: valid (u32), padding (u32), fh (u64), size (u64), …
        const FATTR_SIZE: u32 = 1 << 3;
        if body.len() >= 32 {
            let valid = u32::from_le_bytes(body[0..4].try_into().unwrap());
            if valid & FATTR_SIZE != 0 {
                let size = u64::from_le_bytes(body[16..24].try_into().unwrap());
                let mut payload = (nodeid - 1).to_le_bytes().to_vec();
                payload.extend_from_slice(&size.to_le_bytes());
                if let Ok((KIND_ERROR, reply)) = self.call(KIND_TRUNCATE, &payload) {
                    return self.refused(unique, &reply);
                }
            }
        }
        self.do_getattr(unique, nodeid);
    }

    /// **`FUSE_OPEN`**: the host's file handle, so the guest can read and write what it opened.
    fn do_open(&mut self, unique: u64, nodeid: u64, body: &[u8]) {
        let flags = if body.len() >= 4 {
            i32::from_le_bytes(body[..4].try_into().unwrap())
        } else {
            0
        };
        let mut payload = (nodeid - 1).to_le_bytes().to_vec();
        payload.extend_from_slice(&flags.to_le_bytes());
        match self.call(KIND_OPEN, &payload) {
            Ok((KIND_ERROR, reply)) => self.refused(unique, &reply),
            Ok((_, reply)) if reply.len() >= 8 => {
                let fh = u64::from_le_bytes(reply[..8].try_into().unwrap());
                let mut out = [0u8; 16];
                out[0..8].copy_from_slice(&fh.to_le_bytes());
                out[8..12].copy_from_slice(&FOPEN_KEEP_CACHE.to_le_bytes());
                self.reply_ok(unique, &out);
            }
            _ => self.reply_error(unique, libc::EIO),
        }
    }

    /// **`FUSE_OPENDIR`**: the listing, read **now** from the host, so what the guest sees is the
    /// folder as it was when it opened it.
    fn do_opendir(&mut self, unique: u64, nodeid: u64) {
        let handle = match self.call(KIND_OPENDIR, &(nodeid - 1).to_le_bytes()) {
            Ok((KIND_ERROR, reply)) => return self.refused(unique, &reply),
            Ok((_, reply)) if reply.len() >= 8 => u64::from_le_bytes(reply[..8].try_into().unwrap()),
            _ => return self.reply_error(unique, libc::EIO),
        };
        let (kind, reply) = match self.call(KIND_READDIR, &handle.to_le_bytes()) {
            Ok(answer) => answer,
            Err(_) => return self.reply_error(unique, libc::EIO),
        };
        if kind == KIND_ERROR {
            return self.refused(unique, &reply);
        }
        self.entries = parse_listing(&reply);
        let mut out = [0u8; 16];
        out[0..8].copy_from_slice(&handle.to_le_bytes());
        self.reply_ok(unique, &out);
    }

    /// **`FUSE_READDIR`**: the entries from the offset the kernel names, in its own layout, and as
    /// many as its buffer allows.
    fn do_readdir(&mut self, unique: u64, body: &[u8]) {
        // `struct fuse_read_in`: fh (u64), offset (u64), size (u32), …
        if body.len() < 20 {
            return self.reply_error(unique, libc::EINVAL);
        }
        let offset = u64::from_le_bytes(body[8..16].try_into().unwrap()) as usize;
        let size = u32::from_le_bytes(body[16..20].try_into().unwrap()) as usize;
        let mut out = Vec::with_capacity(size);
        for (index, entry) in self.entries.iter().enumerate().skip(offset) {
            let name = entry.name.as_bytes();
            let raw = 24 + name.len();
            let need = (raw + 7) & !7usize;
            if out.len() + need > size {
                break;
            }
            let mut dirent = vec![0u8; need];
            dirent[0..8].copy_from_slice(&entry.node.to_le_bytes());
            dirent[8..16].copy_from_slice(&((index + 1) as u64).to_le_bytes());
            dirent[16..20].copy_from_slice(&(name.len() as u32).to_le_bytes());
            dirent[20..24].copy_from_slice(&(entry.kind as u32).to_le_bytes());
            dirent[24..24 + name.len()].copy_from_slice(name);
            out.extend_from_slice(&dirent);
        }
        self.reply_ok(unique, &out);
    }

    /// **`FUSE_READ`**: bytes of an open file, which the host reads out of its own filesystem.
    fn do_read(&mut self, unique: u64, body: &[u8]) {
        // `struct fuse_read_in`: fh (u64), offset (u64), size (u32), …
        if body.len() < 20 {
            return self.reply_error(unique, libc::EINVAL);
        }
        let fh = u64::from_le_bytes(body[0..8].try_into().unwrap());
        let offset = u64::from_le_bytes(body[8..16].try_into().unwrap());
        let size = u32::from_le_bytes(body[16..20].try_into().unwrap()).min(65536);
        let mut payload = fh.to_le_bytes().to_vec();
        payload.extend_from_slice(&offset.to_le_bytes());
        payload.extend_from_slice(&size.to_le_bytes());
        match self.call(KIND_READ, &payload) {
            Ok((KIND_ERROR, reply)) => self.refused(unique, &reply),
            Ok((_, reply)) => self.reply_ok(unique, &reply),
            Err(_) => self.reply_error(unique, libc::EIO),
        }
    }

    /// **`FUSE_WRITE`**: the bytes go to the host, and the kernel is told how many landed.
    fn do_write(&mut self, unique: u64, body: &[u8]) {
        // `struct fuse_write_in`: fh (u64), offset (u64), size (u32), write_flags (u32), …
        if body.len() < 40 {
            return self.reply_error(unique, libc::EINVAL);
        }
        let fh = u64::from_le_bytes(body[0..8].try_into().unwrap());
        let offset = u64::from_le_bytes(body[8..16].try_into().unwrap());
        let size = u32::from_le_bytes(body[16..20].try_into().unwrap()) as usize;
        if 40 + size > body.len() {
            return self.reply_error(unique, libc::EINVAL);
        }
        let mut payload = fh.to_le_bytes().to_vec();
        payload.extend_from_slice(&offset.to_le_bytes());
        payload.extend_from_slice(&body[40..40 + size]);
        match self.call(KIND_WRITE, &payload) {
            Ok((KIND_ERROR, reply)) => self.refused(unique, &reply),
            Ok((_, reply)) => {
                let mut out = [0u8; 8];
                let written = if reply.len() >= 4 {
                    u32::from_le_bytes(reply[..4].try_into().unwrap())
                } else {
                    size as u32
                };
                out[0..4].copy_from_slice(&written.to_le_bytes());
                self.reply_ok(unique, &out);
            }
            Err(_) => self.reply_error(unique, libc::EIO),
        }
    }

    /// **`FUSE_CREATE`**: make it and open it, in the two requests the kernel's own answer wants.
    fn do_create(&mut self, unique: u64, nodeid: u64, body: &[u8]) {
        if body.len() < 12 {
            return self.reply_error(unique, libc::EINVAL);
        }
        let flags = u32::from_le_bytes(body[0..4].try_into().unwrap());
        let mode = u32::from_le_bytes(body[4..8].try_into().unwrap()) & 0o777;
        let name = name_of(&body[12..]);
        let mut payload = (nodeid - 1).to_le_bytes().to_vec();
        payload.extend_from_slice(&mode.to_le_bytes());
        payload.extend_from_slice(name.as_bytes());
        let (kind, reply) = match self.call(KIND_CREATE, &payload) {
            Ok(answer) => answer,
            Err(_) => return self.reply_error(unique, libc::EIO),
        };
        if kind == KIND_ERROR {
            return self.refused(unique, &reply);
        }
        if reply.len() < 8 + ATTRS_ENCODED {
            return self.reply_error(unique, libc::EIO);
        }
        let child = u64::from_le_bytes(reply[..8].try_into().unwrap());
        let Some(attrs) = Attrs::decode(&reply[8..]) else {
            return self.reply_error(unique, libc::EIO);
        };
        // The open: the host's handle, so the guest can write what it just made.
        let mut open_payload = child.to_le_bytes().to_vec();
        open_payload.extend_from_slice(&(flags as i32).to_le_bytes());
        let fh = match self.call(KIND_OPEN, &open_payload) {
            Ok((KIND_ERROR, _)) | Err(_) => 0,
            Ok((_, reply)) if reply.len() >= 8 => u64::from_le_bytes(reply[..8].try_into().unwrap()),
            _ => 0,
        };

        let mut out = [0u8; 128 + 16];
        out[0..8].copy_from_slice(&(child + 1).to_le_bytes());
        out[8..16].copy_from_slice(&1u64.to_le_bytes());
        out[16..24].copy_from_slice(&ENTRY_VALID.to_le_bytes());
        out[24..32].copy_from_slice(&ENTRY_VALID.to_le_bytes());
        out[40..128].copy_from_slice(&attrs.to_fuse());
        out[128..136].copy_from_slice(&fh.to_le_bytes());
        out[136..140].copy_from_slice(&FOPEN_KEEP_CACHE.to_le_bytes());
        self.reply_ok(unique, &out);
    }

    /// **`FUSE_MKDIR`**: make a directory, and answer its entry.
    fn do_mkdir(&mut self, unique: u64, nodeid: u64, body: &[u8]) {
        if body.len() < 8 {
            return self.reply_error(unique, libc::EINVAL);
        }
        let mode = u32::from_le_bytes(body[0..4].try_into().unwrap()) & 0o777;
        let name = name_of(&body[8..]);
        let mut payload = (nodeid - 1).to_le_bytes().to_vec();
        payload.extend_from_slice(&mode.to_le_bytes());
        payload.extend_from_slice(name.as_bytes());
        self.entry_reply(unique, nodeid, KIND_MKDIR, &payload);
    }

    /// The request that makes or looks up something and answers with its entry.
    fn entry_reply(&mut self, unique: u64, _nodeid: u64, kind: u16, payload: &[u8]) {
        let (answered, reply) = match self.call(kind, payload) {
            Ok(answer) => answer,
            Err(_) => return self.reply_error(unique, libc::EIO),
        };
        if answered == KIND_ERROR {
            return self.refused(unique, &reply);
        }
        if reply.len() < 8 + ATTRS_ENCODED {
            return self.reply_error(unique, libc::EIO);
        }
        let child = u64::from_le_bytes(reply[..8].try_into().unwrap());
        let Some(attrs) = Attrs::decode(&reply[8..]) else {
            return self.reply_error(unique, libc::EIO);
        };
        let mut out = [0u8; 128];
        out[0..8].copy_from_slice(&(child + 1).to_le_bytes());
        out[8..16].copy_from_slice(&1u64.to_le_bytes());
        out[16..24].copy_from_slice(&ENTRY_VALID.to_le_bytes());
        out[24..32].copy_from_slice(&ENTRY_VALID.to_le_bytes());
        out[40..128].copy_from_slice(&attrs.to_fuse());
        self.reply_ok(unique, &out);
    }

    /// **`FUSE_UNLINK` and `FUSE_RMDIR`**: take a name out of a directory.
    fn do_remove(&mut self, unique: u64, nodeid: u64, body: &[u8], directory: bool) {
        let name = name_of(body);
        let mut payload = (nodeid - 1).to_le_bytes().to_vec();
        payload.extend_from_slice(name.as_bytes());
        let kind = if directory { KIND_RMDIR } else { KIND_UNLINK };
        match self.call(kind, &payload) {
            Ok((KIND_ERROR, reply)) => self.refused(unique, &reply),
            Ok(_) => self.reply_ok(unique, &[]),
            Err(_) => self.reply_error(unique, libc::EIO),
        }
    }

    /// **`FUSE_RENAME`**: a name inside **one** folder.  A rename that crosses into another
    /// directory of the host's tree is not one this service can express, and saying so is the
    /// honest answer (the kernel turns `EXDEV` into its own copy-and-unlink).
    fn do_rename(&mut self, unique: u64, nodeid: u64, body: &[u8]) {
        if body.len() < 8 {
            return self.reply_error(unique, libc::EINVAL);
        }
        let newdir = u64::from_le_bytes(body[0..8].try_into().unwrap());
        if newdir != nodeid {
            return self.reply_error(unique, libc::EXDEV);
        }
        let names = &body[8..];
        let Some(separator) = names.iter().position(|b| *b == 0) else {
            return self.reply_error(unique, libc::EINVAL);
        };
        let from = &names[..separator];
        let to = &names[separator + 1..];
        let mut payload = (nodeid - 1).to_le_bytes().to_vec();
        payload.extend_from_slice(from);
        payload.push(0);
        payload.extend_from_slice(to);
        match self.call(KIND_RENAME, &payload) {
            Ok((KIND_ERROR, reply)) => self.refused(unique, &reply),
            Ok(_) => self.reply_ok(unique, &[]),
            Err(_) => self.reply_error(unique, libc::EIO),
        }
    }

    /// **`FUSE_READLINK`**: where a symlink points, as the host answered.
    fn do_readlink(&mut self, unique: u64, nodeid: u64) {
        match self.call(KIND_READLINK, &(nodeid - 1).to_le_bytes()) {
            Ok((KIND_ERROR, reply)) => self.refused(unique, &reply),
            Ok((_, reply)) => self.reply_ok(unique, &reply),
            Err(_) => self.reply_error(unique, libc::EIO),
        }
    }

    /// **`FUSE_STATFS`**: the numbers a person's `df` reads.  A shared folder is as big as the
    /// host's filesystem, which this filesystem cannot ask about through the share's protocol, so
    /// what it reports is what the C agent reported — the same constants, unchanged.
    fn do_statfs(&mut self, unique: u64) {
        let mut out = [0u8; 80];
        put_u64(&mut out, 0, 1 << 22); // blocks
        put_u64(&mut out, 8, 1 << 21); // bfree
        put_u64(&mut out, 16, 1 << 21); // bavail
        put_u32(&mut out, 40, 4096); // bsize
        put_u32(&mut out, 44, 255); // namelen
        put_u32(&mut out, 48, 4096); // frsize
        self.reply_ok(unique, &out);
    }

    /// **`FUSE_RELEASE` / `FUSE_RELEASEDIR`**: the host's handle goes back.
    fn do_release(&mut self, unique: u64, body: &[u8]) {
        if body.len() >= 8 {
            let fh = u64::from_le_bytes(body[..8].try_into().unwrap());
            let _ = self.call(KIND_RELEASE, &fh.to_le_bytes());
        }
        self.reply_ok(unique, &[]);
    }

    /// **One request**, dispatched exactly as the C agent dispatched it.
    ///
    /// It answers `false` when the mount is gone (the guest unmounted it, the run ended): the loop
    /// then stops, and the process with it.
    fn one(&mut self, request: &[u8]) -> bool {
        let Some(header) = InHeader::decode(request) else {
            return true;
        };
        let body = &request[InHeader::SIZE..];
        let unique = header.unique;
        match header.opcode {
            opcode::INIT => self.do_init(unique, body),
            opcode::LOOKUP => self.do_lookup(unique, header.nodeid, body),
            opcode::GETATTR => self.do_getattr(unique, header.nodeid),
            opcode::SETATTR => self.do_setattr(unique, header.nodeid, body),
            opcode::OPEN => self.do_open(unique, header.nodeid, body),
            opcode::OPENDIR => self.do_opendir(unique, header.nodeid),
            opcode::READDIR => self.do_readdir(unique, body),
            opcode::READ => self.do_read(unique, body),
            opcode::WRITE => self.do_write(unique, body),
            opcode::CREATE => self.do_create(unique, header.nodeid, body),
            opcode::MKDIR => self.do_mkdir(unique, header.nodeid, body),
            opcode::UNLINK => self.do_remove(unique, header.nodeid, body, false),
            opcode::RMDIR => self.do_remove(unique, header.nodeid, body, true),
            opcode::RENAME => self.do_rename(unique, header.nodeid, body),
            opcode::READLINK => self.do_readlink(unique, header.nodeid),
            opcode::STATFS => self.do_statfs(unique),
            opcode::RELEASE => self.do_release(unique, body),
            opcode::RELEASEDIR => self.reply_ok(unique, &[]),
            opcode::MKNOD | opcode::SYMLINK | opcode::LINK => {
                // A device node, a fifo, a symlink or a hard link being made in the host's folder:
                // the service has no operation for any of them, and the honest answer is "this
                // filesystem does not do that".
                self.reply_error(unique, libc::ENOSYS)
            }
            opcode::FLUSH | opcode::ACCESS | opcode::FSYNC | opcode::FSYNCDIR => {
                self.reply_ok(unique, &[])
            }
            opcode::FORGET => {
                // A forget has no reply: the kernel is telling the filesystem it may drop what it
                // knows.  The host's handles go with the connection.
            }
            opcode::DESTROY => return false,
            other => {
                // An opcode this filesystem does not have: `ENOSYS` is the honest answer.  The
                // extended-attribute calls are asked for by any mount and refused in silence; the
                // rest is said out loud, because a wrong answer there is a bug a person has to
                // hear about.
                if other != opcode::GETXATTR && other != opcode::LISTXATTR {
                    crate::console::note(&format!(
                        "deskd-fuse: opcode {other} is not one this filesystem answers"
                    ));
                }
                self.reply_error(unique, libc::ENOSYS);
            }
        }
        true
    }

    /// The loop: one request at a time, answered in full.
    pub fn serve(mut self) {
        let mut buffer = vec![0u8; BUFSIZE];
        loop {
            // SAFETY: the fd is `/dev/fuse` and the buffer is this loop's own.
            let n = unsafe {
                libc::read(
                    self.fuse.as_raw_fd(),
                    buffer.as_mut_ptr() as *mut libc::c_void,
                    buffer.len(),
                )
            };
            if n <= 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                // A mount that cannot be served is said out loud: the kernel ending the
                // connection is the difference between "the folder is empty" and "the folder is
                // gone", and a person needs to know which they are looking at.
                crate::console::note(&format!("deskd-fuse: the mount ended: {err}"));
                break;
            }
            let n = n as usize;
            if n < InHeader::SIZE {
                continue;
            }
            if !self.one(&buffer[..n]) {
                break;
            }
        }
    }
}

/// Write a little-endian number into a buffer at an offset (the kernel's structures are all
/// little-endian on the machine this runs on, and every field here is one of them).
fn put_u64(out: &mut [u8], at: usize, value: u64) {
    out[at..at + 8].copy_from_slice(&value.to_le_bytes());
}

fn put_u32(out: &mut [u8], at: usize, value: u32) {
    out[at..at + 4].copy_from_slice(&value.to_le_bytes());
}

/// A name out of a request body: up to the first NUL (or the whole of it).
fn name_of(body: &[u8]) -> String {
    let end = body.iter().position(|b| *b == 0).unwrap_or(body.len());
    String::from_utf8_lossy(&body[..end]).into_owned()
}

/// **The listing the host answered**: a stream of frames, each an entry (`KIND_ENTRY`), each of
/// them the child's handle, its kind and its name.
pub fn parse_listing(reply: &[u8]) -> Vec<Entry> {
    let mut entries = Vec::new();
    let mut at = 0usize;
    while at + 6 <= reply.len() && entries.len() < MAX_ENTRIES {
        let len = u32::from_le_bytes(reply[at..at + 4].try_into().unwrap()) as usize;
        let kind = u16::from_le_bytes(reply[at + 4..at + 6].try_into().unwrap());
        if at + 6 + len > reply.len() || len < 9 || kind != KIND_ENTRY {
            break;
        }
        let body = &reply[at + 6..at + 6 + len];
        entries.push(Entry {
            node: u64::from_le_bytes(body[..8].try_into().unwrap()),
            kind: body[8],
            name: String::from_utf8_lossy(&body[9..]).into_owned(),
        });
        at += 6 + len;
    }
    entries
}

/// **Mount a shared folder and serve it.**
///
/// The order is the C agent's, and each step is there for a reason:
///
/// 1. dial the share's own channel and say **who we are** (the tag): a wrong tag is a sentence, not
///    a mount that hangs;
/// 2. make the mount point, open `/dev/fuse`, and mount with the options the guest's own user
///    needs to be able to read it (`rootmode=40755` — a root with no permission bits is a folder
///    nobody but root may traverse — and `allow_other`, without which the mount belongs to the
///    process that
///    made it and this one is made by root);
/// 3. **the loop goes on a thread of its own before the probes run**: the probes below are FUSE
///    requests, and the filesystem that answers them is this very process, so probing from the
///    thread that serves would be the filesystem waiting for itself (measured 2026-10-09: the
///    mounts came up and the guest's first `ls` hung forever);
/// 4. the owner is told what came up, with the two probes the project has always run (a listing,
///    and whether it can be written).
pub fn mount_and_serve(tag: &str, port: u32, where_: &str) -> i32 {
    let Some(share) = channel::dial(port) else {
        crate::console::say(&format!("DESK-SHARE fail {tag} on {where_} (no answer on port {port})"));
        return 1;
    };
    let mut share = share;
    if share.write_all(&encode_frame(KIND_HELLO, tag.as_bytes())).is_err() {
        crate::console::say(&format!(
            "DESK-SHARE fail {tag} on {where_} (the share would not answer)"
        ));
        return 1;
    }
    match read_frame(&mut share) {
        Ok((KIND_ERROR, _)) | Err(_) => {
            crate::console::say(&format!(
                "DESK-SHARE fail {tag} on {where_} (port {port} is not this share)"
            ));
            return 1;
        }
        Ok(_) => {}
    }

    let _ = std::fs::create_dir_all(where_);
    let fuse = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/fuse")
    {
        Ok(file) => OwnedFd::from(file),
        Err(e) => {
            crate::console::say(&format!("DESK-SHARE fail {tag} on {where_} (/dev/fuse: {e})"));
            return 1;
        }
    };

    let options = format!(
        "fd={},rootmode=40755,user_id=0,group_id=0,default_permissions,allow_other,subtype=desktop-cracker",
        fuse.as_raw_fd()
    );
    // SAFETY: `where_` is this call's own string, the type is FUSE's, and the options are built
    // from this process's own fd.
    let rc = unsafe {
        libc::mount(
            b"desktop-cracker\0".as_ptr() as *const libc::c_char,
            std::ffi::CString::new(where_).unwrap_or_default().as_ptr(),
            b"fuse\0".as_ptr() as *const libc::c_char,
            libc::MS_NOSUID | libc::MS_NODEV,
            std::ffi::CString::new(options).unwrap_or_default().as_ptr() as *const libc::c_void,
        )
    };
    if rc != 0 {
        let e = std::io::Error::last_os_error();
        crate::console::say(&format!("DESK-SHARE fail {tag} on {where_} (mount: {e})"));
        return 1;
    }

    let mount_point = where_.to_string();
    let serving = std::thread::spawn(move || {
        Mount {
            share,
            fuse,
            entries: Vec::new(),
        }
        .serve();
    });

    // The two probes: can the guest see inside it, and can it write there?
    let mut listing = Vec::new();
    if let Ok(read) = std::fs::read_dir(&mount_point) {
        for entry in read.flatten().take(4) {
            listing.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    let probe = format!("{mount_point}/.desktop-cracker-write-probe");
    let writable = match std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(&probe)
    {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    };
    crate::console::say(&format!(
        "DESK-SHARE ok {tag} on {where_} writable={} [{}]",
        if writable { "yes" } else { "no" },
        listing.join(",")
    ));

    let _ = serving.join();
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_frame_is_a_length_a_kind_and_the_payload() {
        assert_eq!(encode_frame(KIND_OK, b"ab"), vec![2, 0, 0, 0, 100, 0, b'a', b'b']);
    }

    #[test]
    fn the_attributes_are_read_in_the_share_s_own_order() {
        // `Attrs::encode`: ino, size, blocks (u64 each), then mode, nlink, uid, gid (u32 each),
        // then mtime, atime, ctime (u64 each).  A mode read from a `u64`'s high half is the
        // measured bug this pins down.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&7u64.to_le_bytes()); // ino
        bytes.extend_from_slice(&1234u64.to_le_bytes()); // size
        bytes.extend_from_slice(&8u64.to_le_bytes()); // blocks
        bytes.extend_from_slice(&0o100644u32.to_le_bytes()); // mode
        bytes.extend_from_slice(&1u32.to_le_bytes()); // nlink
        bytes.extend_from_slice(&1000u32.to_le_bytes()); // uid
        bytes.extend_from_slice(&1000u32.to_le_bytes()); // gid
        bytes.extend_from_slice(&11u64.to_le_bytes()); // mtime
        bytes.extend_from_slice(&12u64.to_le_bytes()); // atime
        bytes.extend_from_slice(&13u64.to_le_bytes()); // ctime
        let attrs = Attrs::decode(&bytes).expect("the share's own encoding");
        assert_eq!(attrs.ino, 7);
        assert_eq!(attrs.size, 1234);
        assert_eq!(attrs.mode, 0o100644);
        assert_eq!(attrs.uid, 1000);
        assert_eq!(attrs.gid, 1000);
        assert_eq!(attrs.mtime, 11);
        assert_eq!(attrs.atime, 12);
        assert_eq!(attrs.ctime, 13);
        assert_eq!(bytes.len(), ATTRS_ENCODED);
    }

    #[test]
    fn the_kernel_s_attributes_are_the_kernel_s_own_layout() {
        let attrs = Attrs {
            ino: 1,
            size: 2,
            blocks: 3,
            mode: 0o100644,
            nlink: 4,
            uid: 5,
            gid: 6,
            mtime: 7,
            atime: 8,
            ctime: 9,
        };
        let fuse = attrs.to_fuse();
        assert_eq!(fuse.len(), 88, "struct fuse_attr");
        assert_eq!(u64::from_le_bytes(fuse[0..8].try_into().unwrap()), 1);
        assert_eq!(u64::from_le_bytes(fuse[8..16].try_into().unwrap()), 2);
        assert_eq!(u64::from_le_bytes(fuse[16..24].try_into().unwrap()), 3);
        assert_eq!(u64::from_le_bytes(fuse[24..32].try_into().unwrap()), 8, "atime");
        assert_eq!(u64::from_le_bytes(fuse[32..40].try_into().unwrap()), 7, "mtime");
        assert_eq!(u64::from_le_bytes(fuse[40..48].try_into().unwrap()), 9, "ctime");
        assert_eq!(u32::from_le_bytes(fuse[60..64].try_into().unwrap()), 0o100644, "mode");
        assert_eq!(u32::from_le_bytes(fuse[64..68].try_into().unwrap()), 4, "nlink");
        assert_eq!(u32::from_le_bytes(fuse[68..72].try_into().unwrap()), 5, "uid");
        assert_eq!(u32::from_le_bytes(fuse[72..76].try_into().unwrap()), 6, "gid");
        assert_eq!(u32::from_le_bytes(fuse[80..84].try_into().unwrap()), 4096, "blksize");
    }

    #[test]
    fn the_kernels_own_header_is_read_back() {
        let mut bytes = [0u8; InHeader::SIZE];
        bytes[0..4].copy_from_slice(&64u32.to_le_bytes());
        bytes[4..8].copy_from_slice(&opcode::LOOKUP.to_le_bytes());
        bytes[8..16].copy_from_slice(&99u64.to_le_bytes());
        bytes[16..24].copy_from_slice(&3u64.to_le_bytes());
        let header = InHeader::decode(&bytes).unwrap();
        assert_eq!(header.len, 64);
        assert_eq!(header.opcode, opcode::LOOKUP);
        assert_eq!(header.unique, 99);
        assert_eq!(header.nodeid, 3);
    }

    #[test]
    fn a_listing_is_a_stream_of_entry_frames() {
        let mut reply = Vec::new();
        for (handle, kind, name) in [(10u64, KIND_DIR_ENTRY, "src"), (11, KIND_FILE_ENTRY, "a.txt")] {
            let mut body = handle.to_le_bytes().to_vec();
            body.push(kind);
            body.extend_from_slice(name.as_bytes());
            reply.extend_from_slice(&encode_frame(KIND_ENTRY, &body));
        }
        let entries = parse_listing(&reply);
        assert_eq!(
            entries,
            vec![
                Entry {
                    node: 10,
                    kind: KIND_DIR_ENTRY,
                    name: "src".into()
                },
                Entry {
                    node: 11,
                    kind: KIND_FILE_ENTRY,
                    name: "a.txt".into()
                },
            ]
        );
    }

    #[test]
    fn a_listing_that_lost_a_frame_stops_rather_than_reading_rubbish() {
        let mut body = 10u64.to_le_bytes().to_vec();
        body.push(KIND_DIR_ENTRY);
        body.extend_from_slice(b"src");
        let mut reply = encode_frame(KIND_ENTRY, &body);
        reply.extend_from_slice(&[1, 2, 3]); // a truncated frame
        let entries = parse_listing(&reply);
        assert_eq!(entries.len(), 1, "the whole entry, and nothing invented");
    }

    #[test]
    fn a_name_is_read_up_to_its_own_nul() {
        assert_eq!(name_of(b"report.txt\0rubbish"), "report.txt");
        assert_eq!(name_of(b"report.txt"), "report.txt");
    }

    #[test]
    fn a_refusal_carries_the_errno_the_guest_expects() {
        assert_eq!(errno_of(&libc::ENOENT.to_le_bytes()), libc::ENOENT);
        assert_eq!(errno_of(&libc::EACCES.to_le_bytes()), libc::EACCES);
        assert_eq!(errno_of(&[]), libc::EIO);
    }
}
