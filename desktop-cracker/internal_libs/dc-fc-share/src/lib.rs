//! **The host folders, as a filesystem service**.
//!
//! The machine this project started with gives the guest a `virtio-9p` device per shared folder and the guest's kernel
//! mounts it.  Firecracker has no 9P — and its `virtio-fs` is the vhost-user **block** device,
//! which is a different thing entirely — so the guest's folders are put back the way every
//! other missing device is: a **service in this process** and a small piece of the guest that
//! speaks to it.
//!
//! Here is the service.  One **listener per share** (`ports::SHARES + i`), each rooted at one
//! host directory and knowing whether the user asked for it read-only.  The guest's agent
//! mounts the same directory as a **FUSE** filesystem (`/dev/fuse` is in the guest's kernel)
//! whose operations are the requests below — so the guest sees an ordinary directory,
//! `ls`/`open`/`read`/`write` all work on it, and the guest never learns that the bytes travel
//! over vsock.
//!
//! Three rules of the project are visible in this file rather than in a comment:
//!
//! * **the tag is the service's, not the guest's.**  A listener is bound before the machine
//!   starts and it is bound *for one share*: the guest cannot reach a folder the run did not
//!   put in the plan, because the only listener it can dial is the one that folder owns;
//! * **read-only is enforced here.**  A share the user configured `ro` refuses every write,
//!   create, unlink, rename and truncate with `EROFS`: the guest's own mount option is a
//!   courtesy, and this is the authority — RO shares are enforced on the host side;
//! * **no name escapes its share.**  A name is one path component: it may not be empty, may
//!   not be `.` or `..`, and may not contain `/` or a NUL.  A guest cannot reach the host's
//!   `/etc` by asking for `../etc`.
//!
//! The wire is the project's framing (`[u32 len][u16 kind]` + payload), one request and one
//! reply per frame, and a **handle** is the guest's reference to something it has looked up:

use std::collections::HashMap;
use std::io::{Seek, SeekFrom};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileExt, MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use dc_vsock::{Frame, Reader, Service};

/// The guest asks whether this is the share it expects: the payload is the tag.
pub const KIND_HELLO: u16 = 1;
/// Resolve a name inside a directory handle: `[u64 dir][name…]`.
pub const KIND_LOOKUP: u16 = 2;
/// The attributes of a handle: `[u64 handle]`.
pub const KIND_GETATTR: u16 = 3;
/// Open a directory: `[u64 handle]`.
pub const KIND_OPENDIR: u16 = 4;
/// Read the entries of an open directory: `[u64 handle]`.
pub const KIND_READDIR: u16 = 5;
/// Forget a handle: `[u64 handle]`.
pub const KIND_RELEASE: u16 = 6;
/// Open a file: `[u64 handle][u32 flags]`.
pub const KIND_OPEN: u16 = 7;
/// Read: `[u64 handle][u64 offset][u32 size]`.
pub const KIND_READ: u16 = 8;
/// Write: `[u64 handle][u64 offset][payload…]`.
pub const KIND_WRITE: u16 = 9;
/// Make a file: `[u64 dir][u32 mode][name…]`.
pub const KIND_CREATE: u16 = 10;
/// Make a directory: `[u64 dir][u32 mode][name…]`.
pub const KIND_MKDIR: u16 = 11;
/// Remove a file: `[u64 dir][name…]`.
pub const KIND_UNLINK: u16 = 12;
/// Remove a directory: `[u64 dir][name…]`.
pub const KIND_RMDIR: u16 = 13;
/// Move: `[u64 dir][name][0x00][newname…]` — two names, one NUL between them.
pub const KIND_RENAME: u16 = 14;
/// Set a length: `[u64 handle][u64 size]`.
pub const KIND_TRUNCATE: u16 = 15;
/// Read where a symbolic link points: `[u64 handle]`.
pub const KIND_READLINK: u16 = 16;
/// One entry of a listing: `[u64 handle][u8 kind][name…]`.
pub const KIND_ENTRY: u16 = 17;

/// The request worked; the payload is whatever the operation answers (empty for most).
pub const KIND_OK: u16 = 100;
/// Attributes: `[u64 handle][Attrs]` — the handle so the guest can go on using what it looked
/// up without a second request.
pub const KIND_ATTR: u16 = 101;
/// Bytes: a file's content, or a directory's listing.
pub const KIND_DATA: u16 = 102;
/// It did not work: the payload is an `errno`, as `u32`.
pub const KIND_ERROR: u16 = 103;

/// The kinds a listing reports, so the guest does not have to ask for each entry's attributes:
/// 4 is a directory, 8 a file, 10 a symbolic link (the numbers a `readdir`'s `d_type` uses).
pub const KIND_DIR: u8 = 4;
pub const KIND_FILE: u8 = 8;
pub const KIND_LINK: u8 = 10;

/// What the guest is told about a file or a directory: the fields of a `stat` a filesystem
/// needs, in a fixed shape so both ends agree without a struct's padding to argue about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Attrs {
    pub ino: u64,
    pub size: u64,
    pub blocks: u64,
    /// The `st_mode`: the type and the permissions together (as the kernel reports them).
    pub mode: u32,
    pub nlink: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: i64,
    pub atime: i64,
    pub ctime: i64,
}

impl Attrs {
    /// Six `u64` fields (inode, size, blocks, mtime, atime, ctime) and four `u32` ones
    /// (mode, nlink, uid, gid) — and the constant is what both ends check, so a field added
    /// on one side is a decode that fails loudly on the other.
    pub const ENCODED: usize = 6 * 8 + 4 * 4;

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(Self::ENCODED);
        out.extend_from_slice(&self.ino.to_le_bytes());
        out.extend_from_slice(&self.size.to_le_bytes());
        out.extend_from_slice(&self.blocks.to_le_bytes());
        out.extend_from_slice(&self.mode.to_le_bytes());
        out.extend_from_slice(&self.nlink.to_le_bytes());
        out.extend_from_slice(&self.uid.to_le_bytes());
        out.extend_from_slice(&self.gid.to_le_bytes());
        out.extend_from_slice(&self.mtime.to_le_bytes());
        out.extend_from_slice(&self.atime.to_le_bytes());
        out.extend_from_slice(&self.ctime.to_le_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Attrs> {
        if bytes.len() < Self::ENCODED {
            return None;
        }
        let u64_at = |at: usize| u64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
        let u32_at = |at: usize| u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap());
        let i64_at = |at: usize| i64::from_le_bytes(bytes[at..at + 8].try_into().unwrap());
        Some(Attrs {
            ino: u64_at(0),
            size: u64_at(8),
            blocks: u64_at(16),
            mode: u32_at(24),
            nlink: u32_at(28),
            uid: u32_at(32),
            gid: u32_at(36),
            mtime: i64_at(40),
            atime: i64_at(48),
            ctime: i64_at(56),
        })
    }
}

/// **The one name the guest may write**, whatever its share's mode says.
///
/// The project's rule (`dc-shares`' own words, and the display rule's): the control directory is the
/// one writable exception, because it is the channel the guest's *status* comes back on — its memory
/// numbers, its readiness, the display probe, a sound request, the power-off.  On this path the
/// control files travel the control channel (56000), but a run may still offer the guest a
/// **read-only folder in which the control directory lives**, and the guest's own tools write
/// there.  A share that refuses it would be a guest whose status never arrives.
pub const WRITABLE_EXCEPTION: &str = "control";

/// What one share is: the host directory, the tag the guest knows it by, and whether the user
/// allowed writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    pub tag: String,
    /// The host directory.
    pub path: PathBuf,
    /// **Where the guest mounts it.**  It is the project's own path for the tags the project
    /// already has (`/mnt/disk`, `/tmp/.X11-unix`, the shared folders' `/mnt/share/<tag>`), and
    /// it is decided by `dc-shares`' mount plan rather than guessed at here — the guest's own
    /// tools, its session and its X clients look for those paths.
    pub where_: String,
    pub read_only: bool,
    /// Whether this is the project's own **control directory** — the one writable exception
    /// (`WRITABLE_EXCEPTION`).  The machine this project started with's control share is always writable for exactly this
    /// reason, and a run that puts it inside a read-only parent keeps that promise here.
    pub writable_exception: bool,
}

/// What the service is doing, for the milestone line and the tests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counters {
    pub requests: u64,
    pub reads: u64,
    pub writes: u64,
    /// Refused because the share is read-only.
    pub refused_ro: u64,
    /// Refused because the name was not one (an escape, an empty name, a separator).
    pub refused_name: u64,
    pub bytes: u64,
}

/// One open thing: a file (with its descriptor, so a read does not re-open a path that may
/// have moved) or a directory (with what a listing found, so the guest's `ls` is a walk).
enum Handle {
    File {
        file: std::fs::File,
        path: PathBuf,
    },
    Dir {
        path: PathBuf,
        entries: Vec<(String, u8, Attrs)>,
    },
}

/// The filesystem of **one** share.
pub struct ShareService {
    service: Service,
    share: Share,
    /// Every handle this connection has handed out, by number.  Handle **0** is the share's
    /// own root, always.
    handles: Mutex<HashMap<u64, Handle>>,
    next_handle: Mutex<u64>,
    counters: Mutex<Counters>,
}

impl ShareService {
    /// Listen for one share.  The listener exists before the machine starts, like every other
    /// channel of a run.
    pub fn listen(
        uds_path: &Path,
        port: u32,
        share: Share,
    ) -> std::result::Result<ShareService, dc_vsock::VsockError> {
        Ok(ShareService {
            service: Service::bind(uds_path, port)?,
            share,
            handles: Mutex::new(HashMap::new()),
            next_handle: Mutex::new(1),
            counters: Mutex::new(Counters::default()),
        })
    }

    pub fn port(&self) -> u32 {
        self.service.port()
    }

    pub fn tag(&self) -> &str {
        &self.share.tag
    }

    pub fn read_only(&self) -> bool {
        self.share.read_only
    }

    pub fn counters(&self) -> Counters {
        *self.counters.lock().expect("the share's counters")
    }

    /// Serve the guest's connection until it ends.
    pub fn serve(&self) -> std::result::Result<(), dc_vsock::VsockError> {
        let port = self.service.port();
        let mut stream = self.service.accept()?;
        let mut reader = Reader::new();
        loop {
            match reader.read_frame(&mut stream, port) {
                Ok(Some(request)) => {
                    let reply = self.answer(&request);
                    if dc_vsock::write_frame(&mut stream, &reply, port).is_err() {
                        break;
                    }
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }
        Ok(())
    }

    /// One request, one reply.
    pub fn answer(&self, request: &Frame) -> Frame {
        self.counters.lock().expect("the share's counters").requests += 1;
        match request.kind {
            KIND_HELLO => {
                let asked = String::from_utf8_lossy(&request.payload);
                if asked.trim_end_matches('\n') == self.share.tag {
                    Frame::new(KIND_DATA, self.share.tag.as_bytes().to_vec())
                } else {
                    error(libc::ENOENT)
                }
            }
            KIND_LOOKUP => self.lookup(&request.payload),
            KIND_GETATTR => self.getattr(&request.payload),
            KIND_OPENDIR => self.opendir(&request.payload),
            KIND_READDIR => self.readdir(&request.payload),
            KIND_RELEASE => self.release(&request.payload),
            KIND_OPEN => self.open(&request.payload),
            KIND_READ => self.read(&request.payload),
            KIND_WRITE => self.write(&request.payload),
            KIND_CREATE => self.make(&request.payload, false),
            KIND_MKDIR => self.make(&request.payload, true),
            KIND_UNLINK | KIND_RMDIR => self.remove(&request.payload),
            KIND_RENAME => self.rename(&request.payload),
            KIND_TRUNCATE => self.truncate(&request.payload),
            KIND_READLINK => self.readlink(&request.payload),
            _ => error(libc::ENOSYS),
        }
    }

    // ---- the operations -------------------------------------------------------

    /// Does this share refuse writes?  It does when the user made it read-only — **except** for
    /// the control directory, which the project's own rule makes the one writable exception
    /// ([`WRITABLE_EXCEPTION`]): it holds nothing of the user's, and the guest's status is what
    /// travels back through it.
    fn refuses_writes(&self) -> bool {
        self.share.read_only && !self.share.writable_exception
    }

    /// The path a handle names.  Handle **0** is the share's own root: what the guest is given
    /// when it dials, and the only way into the tree.
    fn path_of(&self, handle: u64) -> std::result::Result<PathBuf, i32> {
        if handle == 0 {
            return Ok(self.share.path.clone());
        }
        let handles = self.handles.lock().expect("the share's handles");
        match handles.get(&handle) {
            Some(Handle::File { path, .. }) | Some(Handle::Dir { path, .. }) => Ok(path.clone()),
            None => Err(libc::EBADF),
        }
    }

    /// Join a name to a directory **safely**: a name is one component and nothing about it may
    /// climb out of the share.
    fn join(&self, dir: &Path, name: &[u8]) -> std::result::Result<PathBuf, i32> {
        let name = std::ffi::OsStr::from_bytes(name);
        let text = name.to_string_lossy();
        if text.is_empty()
            || text == "."
            || text == ".."
            || text.contains('/')
            || text.contains('\0')
        {
            self.counters
                .lock()
                .expect("the share's counters")
                .refused_name += 1;
            return Err(libc::EINVAL);
        }
        Ok(dir.join(name))
    }

    /// Look a name up inside a directory: the answer is the child's **handle and attributes**,
    /// so the guest opens what it looked up rather than a path it built itself.
    fn lookup(&self, payload: &[u8]) -> Frame {
        let Some((dir, name)) = split_handle(payload) else {
            return error(libc::EINVAL);
        };
        let base = match self.path_of(dir) {
            Ok(path) => path,
            Err(e) => return error(e),
        };
        let path = match self.join(&base, name) {
            Ok(path) => path,
            Err(e) => return error(e),
        };
        let meta = match std::fs::symlink_metadata(&path) {
            Ok(meta) => meta,
            Err(e) => return error(errno(e)),
        };
        self.remember_path(path, meta)
    }

    /// Note a path as a handle and answer its attributes.
    ///
    /// Every handle points at a **path** until the guest opens it, and that is deliberate: a
    /// guest looks a name up and then decides whether it is opening a file or a directory, so
    /// one shape of handle has to serve both.  `open` turns it into a file handle (a
    /// descriptor), `opendir` into a listing.
    fn remember_path(&self, path: PathBuf, meta: std::fs::Metadata) -> Frame {
        let attrs = attrs_of(&meta);
        let handle = self.remember(Handle::Dir {
            path,
            entries: Vec::new(),
        });
        let mut out = handle.to_le_bytes().to_vec();
        out.extend_from_slice(&attrs.encode());
        Frame::new(KIND_ATTR, out)
    }

    fn getattr(&self, payload: &[u8]) -> Frame {
        let Some(handle) = take_u64(payload) else {
            return error(libc::EINVAL);
        };
        let path = match self.path_of(handle) {
            Ok(path) => path,
            Err(e) => return error(e),
        };
        match std::fs::symlink_metadata(&path) {
            Ok(meta) => {
                let mut out = handle.to_le_bytes().to_vec();
                out.extend_from_slice(&attrs_of(&meta).encode());
                Frame::new(KIND_ATTR, out)
            }
            Err(e) => error(errno(e)),
        }
    }

    fn opendir(&self, payload: &[u8]) -> Frame {
        let Some(handle) = take_u64(payload) else {
            return error(libc::EINVAL);
        };
        let path = match self.path_of(handle) {
            Ok(path) => path,
            Err(e) => return error(e),
        };
        if !path.is_dir() {
            return error(libc::ENOTDIR);
        }
        // The listing is read **now**, so what the guest sees is a directory as it was when it
        // opened it: a folder that changes under a listing is a folder whose earlier entries do
        // not move.
        let mut entries = Vec::new();
        let read = match std::fs::read_dir(&path) {
            Ok(read) => read,
            Err(e) => return error(errno(e)),
        };
        for entry in read.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let (kind, attrs) = match std::fs::symlink_metadata(entry.path()) {
                Ok(meta) => (kind_of(&meta), attrs_of(&meta)),
                Err(_) => (KIND_FILE, Attrs::default()),
            };
            entries.push((name, kind, attrs));
        }
        let handle = self.remember(Handle::Dir { path, entries });
        Frame::new(KIND_OK, handle.to_le_bytes().to_vec())
    }

    fn readdir(&self, payload: &[u8]) -> Frame {
        let Some(handle) = take_u64(payload) else {
            return error(libc::EINVAL);
        };
        let mut handles = self.handles.lock().expect("the share's handles");
        let Some(Handle::Dir { path, entries }) = handles.get_mut(&handle) else {
            return error(libc::EBADF);
        };
        // The listing is answered once per handle: a directory is read, and reading it again
        // is an empty answer rather than the same names twice (`readdir`'s own contract, and
        // the reason a FUSE reader asks until it is given nothing).
        let taken = std::mem::take(entries);
        let path = path.clone();
        drop(handles);
        let mut out = Vec::new();
        for (name, kind, _attrs) in taken.iter() {
            // A **handle for each entry**, made here so the guest's `getattr`/`open` on what it
            // listed is one number and not another lookup.
            let child = self.remember(Handle::Dir {
                path: path.join(name),
                entries: Vec::new(),
            });
            let mut entry = child.to_le_bytes().to_vec();
            entry.push(*kind);
            entry.extend_from_slice(name.as_bytes());
            out.extend_from_slice(&Frame::new(KIND_ENTRY, entry).encode());
        }
        Frame::new(KIND_DATA, out)
    }

    fn release(&self, payload: &[u8]) -> Frame {
        let Some(handle) = take_u64(payload) else {
            return error(libc::EINVAL);
        };
        self.handles
            .lock()
            .expect("the share's handles")
            .remove(&handle);
        Frame::new(KIND_OK, Vec::new())
    }

    fn open(&self, payload: &[u8]) -> Frame {
        let Some((handle, rest)) = split_handle(payload) else {
            return error(libc::EINVAL);
        };
        let flags = rest
            .get(..4)
            .map(|b| i32::from_le_bytes(b.try_into().unwrap()))
            .unwrap_or(libc::O_RDONLY);
        let path = match self.path_of(handle) {
            Ok(path) => path,
            Err(e) => return error(e),
        };
        let writing = flags & (libc::O_WRONLY | libc::O_RDWR) != 0;
        if writing && self.share.read_only {
            self.counters
                .lock()
                .expect("the share's counters")
                .refused_ro += 1;
            return error(libc::EROFS);
        }
        if path.is_dir() {
            // Opening a directory is its own request (`OPENDIR`); a file open on one is not
            // something to guess at.
            return error(libc::EISDIR);
        }
        match std::fs::OpenOptions::new()
            .read(true)
            .write(writing)
            .open(&path)
        {
            Ok(file) => {
                let handle = self.remember(Handle::File { file, path });
                Frame::new(KIND_OK, handle.to_le_bytes().to_vec())
            }
            Err(e) => error(errno(e)),
        }
    }

    fn read(&self, payload: &[u8]) -> Frame {
        let Some((handle, rest)) = split_handle(payload) else {
            return error(libc::EINVAL);
        };
        let Some((offset, rest)) = split_u64(rest) else {
            return error(libc::EINVAL);
        };
        let size = rest
            .get(..4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
            .unwrap_or(4096)
            .min(1 << 20) as usize;
        let handles = self.handles.lock().expect("the share's handles");
        let Some(Handle::File { file, .. }) = handles.get(&handle) else {
            return error(libc::EBADF);
        };
        let mut buffer = vec![0u8; size];
        match file.read_at(&mut buffer, offset) {
            Ok(n) => {
                buffer.truncate(n);
                let mut counters = self.counters.lock().expect("the share's counters");
                counters.reads += 1;
                counters.bytes += n as u64;
                Frame::new(KIND_DATA, buffer)
            }
            Err(e) => error(errno(e)),
        }
    }

    fn write(&self, payload: &[u8]) -> Frame {
        let Some((handle, rest)) = split_handle(payload) else {
            return error(libc::EINVAL);
        };
        let Some((offset, body)) = split_u64(rest) else {
            return error(libc::EINVAL);
        };
        if self.share.read_only {
            self.counters
                .lock()
                .expect("the share's counters")
                .refused_ro += 1;
            return error(libc::EROFS);
        }
        let handles = self.handles.lock().expect("the share's handles");
        let Some(Handle::File { file, .. }) = handles.get(&handle) else {
            return error(libc::EBADF);
        };
        match file.write_at(body, offset) {
            Ok(n) => {
                let mut counters = self.counters.lock().expect("the share's counters");
                counters.writes += 1;
                counters.bytes += n as u64;
                Frame::new(KIND_OK, (n as u32).to_le_bytes().to_vec())
            }
            Err(e) => error(errno(e)),
        }
    }

    /// `create` and `mkdir` are one operation with one flag: both make a name inside a
    /// directory and answer what was made.
    fn make(&self, payload: &[u8], directory: bool) -> Frame {
        let Some((dir, rest)) = split_handle(payload) else {
            return error(libc::EINVAL);
        };
        let mode = rest
            .get(..4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
            .unwrap_or(0o644);
        let name = rest.get(4..).unwrap_or(&[]);
        if self.refuses_writes() {
            self.counters
                .lock()
                .expect("the share's counters")
                .refused_ro += 1;
            return error(libc::EROFS);
        }
        let base = match self.path_of(dir) {
            Ok(path) => path,
            Err(e) => return error(e),
        };
        let path = match self.join(&base, name) {
            Ok(path) => path,
            Err(e) => return error(e),
        };
        let made = if directory {
            std::fs::create_dir(&path)
        } else {
            std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&path)
                .map(|_| ())
        };
        match made {
            Ok(()) => {
                // The permissions the guest asked for, and only the low bits of them: a guest
                // does not get to set a set-uid bit on a file of the host's.
                let _ =
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode & 0o777));
                match std::fs::symlink_metadata(&path) {
                    Ok(meta) => self.remember_path(path, meta),
                    Err(e) => error(errno(e)),
                }
            }
            Err(e) => error(errno(e)),
        }
    }

    fn remove(&self, payload: &[u8]) -> Frame {
        let Some((dir, name)) = split_handle(payload) else {
            return error(libc::EINVAL);
        };
        if self.refuses_writes() {
            self.counters
                .lock()
                .expect("the share's counters")
                .refused_ro += 1;
            return error(libc::EROFS);
        }
        let base = match self.path_of(dir) {
            Ok(path) => path,
            Err(e) => return error(e),
        };
        let path = match self.join(&base, name) {
            Ok(path) => path,
            Err(e) => return error(e),
        };
        let removed = if path.is_dir() {
            std::fs::remove_dir(&path)
        } else {
            std::fs::remove_file(&path)
        };
        match removed {
            Ok(()) => Frame::new(KIND_OK, Vec::new()),
            Err(e) => error(errno(e)),
        }
    }

    /// `[u64 dir][name][0x00][newname…]`: two names with a NUL between them, so a name with
    /// anything printable in it still travels.
    fn rename(&self, payload: &[u8]) -> Frame {
        let Some((dir, rest)) = split_handle(payload) else {
            return error(libc::EINVAL);
        };
        if self.share.read_only {
            self.counters
                .lock()
                .expect("the share's counters")
                .refused_ro += 1;
            return error(libc::EROFS);
        }
        let Some(at) = rest.iter().position(|b| *b == 0) else {
            return error(libc::EINVAL);
        };
        let base = match self.path_of(dir) {
            Ok(path) => path,
            Err(e) => return error(e),
        };
        let from = match self.join(&base, &rest[..at]) {
            Ok(path) => path,
            Err(e) => return error(e),
        };
        let to = match self.join(&base, &rest[at + 1..]) {
            Ok(path) => path,
            Err(e) => return error(e),
        };
        match std::fs::rename(&from, &to) {
            Ok(()) => Frame::new(KIND_OK, Vec::new()),
            Err(e) => error(errno(e)),
        }
    }

    fn truncate(&self, payload: &[u8]) -> Frame {
        let Some((handle, rest)) = split_handle(payload) else {
            return error(libc::EINVAL);
        };
        let Some((size, _)) = split_u64(rest) else {
            return error(libc::EINVAL);
        };
        if self.share.read_only {
            self.counters
                .lock()
                .expect("the share's counters")
                .refused_ro += 1;
            return error(libc::EROFS);
        }
        let path = match self.path_of(handle) {
            Ok(path) => path,
            Err(e) => return error(e),
        };
        let done = std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .and_then(|mut file| {
                file.seek(SeekFrom::Start(size))?;
                file.set_len(size)
            });
        match done {
            Ok(()) => Frame::new(KIND_OK, Vec::new()),
            Err(e) => error(errno(e)),
        }
    }

    fn readlink(&self, payload: &[u8]) -> Frame {
        let Some(handle) = take_u64(payload) else {
            return error(libc::EINVAL);
        };
        let path = match self.path_of(handle) {
            Ok(path) => path,
            Err(e) => return error(e),
        };
        match std::fs::read_link(&path) {
            Ok(target) => {
                // A link is answered as the **name inside the share** when it points inside it:
                // the guest has no path to the host and must not be handed one.
                let text = target.as_os_str().as_bytes();
                let inside = text
                    .split(|b| *b == b'/')
                    .rfind(|part| !part.is_empty())
                    .unwrap_or(text);
                Frame::new(KIND_DATA, inside.to_vec())
            }
            Err(e) => error(errno(e)),
        }
    }

    /// Remember a handle and answer its number.
    fn remember(&self, handle: Handle) -> u64 {
        let mut next = self.next_handle.lock().expect("the share's handles");
        let number = *next;
        *next += 1;
        drop(next);
        self.handles
            .lock()
            .expect("the share's handles")
            .insert(number, handle);
        number
    }
}

fn kind_of(meta: &std::fs::Metadata) -> u8 {
    if meta.file_type().is_symlink() {
        KIND_LINK
    } else if meta.is_dir() {
        KIND_DIR
    } else {
        KIND_FILE
    }
}

fn attrs_of(meta: &std::fs::Metadata) -> Attrs {
    Attrs {
        ino: meta.ino(),
        size: meta.len(),
        blocks: meta.blocks(),
        mode: meta.mode(),
        nlink: meta.nlink() as u32,
        uid: meta.uid(),
        gid: meta.gid(),
        mtime: meta.mtime(),
        atime: meta.atime(),
        ctime: meta.ctime(),
    }
}

fn errno(e: std::io::Error) -> i32 {
    e.raw_os_error().unwrap_or(libc::EIO)
}

fn error(errno: i32) -> Frame {
    Frame::new(KIND_ERROR, (errno as u32).to_le_bytes().to_vec())
}

/// The `errno` an error reply carries.
pub fn errno_of(frame: &Frame) -> i32 {
    let fallback = libc::EIO as u32;
    let value = frame
        .payload
        .get(..4)
        .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
        .unwrap_or(fallback);
    value as i32
}

fn take_u64(bytes: &[u8]) -> Option<u64> {
    Some(u64::from_le_bytes(bytes.get(..8)?.try_into().ok()?))
}

fn split_u64(bytes: &[u8]) -> Option<(u64, &[u8])> {
    Some((take_u64(bytes)?, bytes.get(8..)?))
}

fn split_handle(bytes: &[u8]) -> Option<(u64, &[u8])> {
    split_u64(bytes)
}

/// The requests a **guest** builds: the same bytes the service answers, in one place, so the
/// agent (C) and the tests (Rust) cannot drift from each other.
pub mod request {
    use super::*;

    /// Resolve `name` inside `dir`.
    pub fn lookup(dir: u64, name: &[u8]) -> Frame {
        let mut payload = dir.to_le_bytes().to_vec();
        payload.extend_from_slice(name);
        Frame::new(KIND_LOOKUP, payload)
    }

    /// The attributes of `handle`.
    pub fn getattr(handle: u64) -> Frame {
        Frame::new(KIND_GETATTR, handle.to_le_bytes().to_vec())
    }

    /// Open `handle` as a directory.
    pub fn opendir(handle: u64) -> Frame {
        Frame::new(KIND_OPENDIR, handle.to_le_bytes().to_vec())
    }

    /// Read the entries of an open directory.
    pub fn readdir(handle: u64) -> Frame {
        Frame::new(KIND_READDIR, handle.to_le_bytes().to_vec())
    }

    /// Forget `handle`.
    pub fn release(handle: u64) -> Frame {
        Frame::new(KIND_RELEASE, handle.to_le_bytes().to_vec())
    }

    /// Open `handle` as a file, with the guest's own `open(2)` flags.
    pub fn open(handle: u64, flags: i32) -> Frame {
        let mut payload = handle.to_le_bytes().to_vec();
        payload.extend_from_slice(&flags.to_le_bytes());
        Frame::new(KIND_OPEN, payload)
    }

    /// Read bytes from a file handle.
    pub fn read(handle: u64, offset: u64, size: u32) -> Frame {
        let mut payload = handle.to_le_bytes().to_vec();
        payload.extend_from_slice(&offset.to_le_bytes());
        payload.extend_from_slice(&size.to_le_bytes());
        Frame::new(KIND_READ, payload)
    }

    /// Write bytes to a file handle.
    pub fn write(handle: u64, offset: u64, body: &[u8]) -> Frame {
        let mut payload = handle.to_le_bytes().to_vec();
        payload.extend_from_slice(&offset.to_le_bytes());
        payload.extend_from_slice(body);
        Frame::new(KIND_WRITE, payload)
    }

    /// Make a file (or, with `directory`, a folder) inside `dir`.
    pub fn make(dir: u64, mode: u32, name: &[u8], directory: bool) -> Frame {
        let mut payload = dir.to_le_bytes().to_vec();
        payload.extend_from_slice(&mode.to_le_bytes());
        payload.extend_from_slice(name);
        Frame::new(if directory { KIND_MKDIR } else { KIND_CREATE }, payload)
    }

    /// Remove a name from `dir`.
    pub fn remove(dir: u64, name: &[u8], directory: bool) -> Frame {
        let mut payload = dir.to_le_bytes().to_vec();
        payload.extend_from_slice(name);
        Frame::new(if directory { KIND_RMDIR } else { KIND_UNLINK }, payload)
    }

    /// Rename inside `dir`.
    pub fn rename(dir: u64, from: &[u8], to: &[u8]) -> Frame {
        let mut payload = dir.to_le_bytes().to_vec();
        payload.extend_from_slice(from);
        payload.push(0);
        payload.extend_from_slice(to);
        Frame::new(KIND_RENAME, payload)
    }

    /// Set a file handle's length.
    pub fn truncate(handle: u64, size: u64) -> Frame {
        let mut payload = handle.to_le_bytes().to_vec();
        payload.extend_from_slice(&size.to_le_bytes());
        Frame::new(KIND_TRUNCATE, payload)
    }

    /// Where a symbolic link points.
    pub fn readlink(handle: u64) -> Frame {
        Frame::new(KIND_READLINK, handle.to_le_bytes().to_vec())
    }

    /// What the guest says when it dials: the tag it expects.
    pub fn hello(tag: &str) -> Frame {
        Frame::new(KIND_HELLO, tag.as_bytes().to_vec())
    }
}

/// A reply, as a guest reads it.
pub mod reply {
    use super::*;

    /// The bytes of a data reply, or the `errno` of an error one.
    pub fn bytes(frame: &Frame) -> std::result::Result<&[u8], i32> {
        match frame.kind {
            KIND_DATA => Ok(&frame.payload),
            KIND_ERROR => Err(errno_of(frame)),
            _ => Err(libc::EIO),
        }
    }

    /// The handle and attributes a lookup answers.
    pub fn attrs(frame: &Frame) -> std::result::Result<(u64, Attrs), i32> {
        if frame.kind == KIND_ERROR {
            return Err(errno_of(frame));
        }
        let handle = take_u64(&frame.payload).ok_or(libc::EIO)?;
        let attrs = Attrs::decode(&frame.payload[8..]).ok_or(libc::EIO)?;
        Ok((handle, attrs))
    }

    /// The handle an open answers.
    pub fn handle(frame: &Frame) -> std::result::Result<u64, i32> {
        if frame.kind == KIND_ERROR {
            return Err(errno_of(frame));
        }
        take_u64(&frame.payload).ok_or(libc::EIO)
    }

    /// The entries a listing answers: `(handle, kind, name)`.
    pub fn entries(frame: &Frame) -> std::result::Result<Vec<(u64, u8, String)>, i32> {
        if frame.kind == KIND_ERROR {
            return Err(errno_of(frame));
        }
        let mut reader = Reader::new();
        reader.push(&frame.payload);
        let mut out = Vec::new();
        while let Some(entry) = reader.next_frame().map_err(|_| libc::EIO)? {
            let Some(handle) = take_u64(&entry.payload) else {
                continue;
            };
            let Some(kind) = entry.payload.get(8).copied() else {
                continue;
            };
            out.push((
                handle,
                kind,
                String::from_utf8_lossy(&entry.payload[9..]).to_string(),
            ));
        }
        Ok(out)
    }

    /// The count a write answers, or the error.
    pub fn written(frame: &Frame) -> std::result::Result<u32, i32> {
        if frame.kind == KIND_ERROR {
            return Err(errno_of(frame));
        }
        Ok(frame
            .payload
            .get(..4)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()))
            .unwrap_or(0))
    }
}

/// Every share of one run, in the order the settings list them.
pub struct ShareSet {
    services: Vec<Arc<ShareService>>,
}

impl ShareSet {
    /// Bind one listener per share — **before the machine starts**, like every other channel
    /// The first port is `ports::SHARES`; each share takes the
    /// next one, so the number of listeners a run makes is the number of folders it shares.
    pub fn listen(
        uds_path: &Path,
        shares: &[Share],
    ) -> std::result::Result<ShareSet, dc_vsock::VsockError> {
        let mut services = Vec::with_capacity(shares.len());
        for (index, share) in shares.iter().enumerate() {
            let port = dc_vsock::ports::SHARES + index as u32;
            services.push(Arc::new(ShareService::listen(
                uds_path,
                port,
                share.clone(),
            )?));
        }
        Ok(ShareSet { services })
    }

    pub fn services(&self) -> &[Arc<ShareService>] {
        &self.services
    }

    /// A share by its tag, when this run has it.
    pub fn get(&self, tag: &str) -> Option<&Arc<ShareService>> {
        self.services.iter().find(|service| service.tag() == tag)
    }

    /// The line the guest's agent is given, in the run's **control share**: one line per
    /// folder, `<tag> <port> <ro|rw>`.  It is the same idea as the earlier machine's mount plan —
    /// and the same tags and modes — with the port where the 9P tag used to be.
    pub fn plan(&self) -> String {
        let mut out = String::from("# desktop-cracker shares: <tag> <port> <where> <ro|rw>\n");
        for service in &self.services {
            out.push_str(&format!(
                "{} {} {} {}\n",
                service.tag(),
                service.port(),
                service.share.where_,
                if service.read_only() { "ro" } else { "rw" }
            ));
        }
        out
    }

    /// Every counter, by tag — the numbers a milestone line reads.
    pub fn counters(&self) -> Vec<(String, Counters)> {
        self.services
            .iter()
            .map(|service| (service.tag().to_string(), service.counters()))
            .collect()
    }

    /// Serve every share on a thread of its own, until the run ends (each thread ends when its
    /// socket is closed, or when the guest hangs up).
    pub fn serve_in_background(self: &Arc<Self>) -> Vec<std::thread::JoinHandle<()>> {
        self.services
            .iter()
            .map(|service| {
                let service = service.clone();
                std::thread::spawn(move || {
                    let _ = service.serve();
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::net::UnixStream;

    fn a_directory() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("hello.txt"), b"hello, share\n").unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        std::fs::write(dir.path().join("sub/inner.txt"), b"inner\n").unwrap();
        dir
    }

    fn service_at(dir: &Path, read_only: bool, uds: &Path) -> ShareService {
        ShareService::listen(
            uds,
            dc_vsock::ports::SHARES,
            Share {
                tag: "data".into(),
                path: dir.to_path_buf(),
                where_: "/mnt/share/data".into(),
                read_only,
                writable_exception: false,
            },
        )
        .unwrap()
    }

    fn service(dir: &Path, read_only: bool) -> (ShareService, tempfile::TempDir) {
        let uds = tempfile::tempdir().unwrap();
        let service = service_at(dir, read_only, &uds.path().join("v.sock"));
        (service, uds)
    }

    #[test]
    fn a_share_answers_for_its_own_tag_and_refuses_another() {
        let dir = a_directory();
        let (service, _keep) = service(dir.path(), false);
        let hello = service.answer(&request::hello("data"));
        assert_eq!(hello.kind, KIND_DATA);
        assert_eq!(hello.payload, b"data");
        let other = service.answer(&request::hello("secrets"));
        assert_eq!(errno_of(&other), libc::ENOENT);
    }

    #[test]
    fn a_name_is_looked_up_and_then_read_through_the_handle_it_answered() {
        let dir = a_directory();
        let (service, _keep) = service(dir.path(), false);
        let lookup = service.answer(&request::lookup(0, b"hello.txt"));
        let (handle, attrs) = reply::attrs(&lookup).unwrap();
        assert_eq!(attrs.size, 13);
        assert_eq!(attrs.mode & libc::S_IFMT, libc::S_IFREG);

        let opened = service.answer(&request::open(handle, libc::O_RDONLY));
        let file = reply::handle(&opened).unwrap();
        let read = service.answer(&request::read(file, 0, 4096));
        assert_eq!(reply::bytes(&read).unwrap(), b"hello, share\n");
        // A read beyond the end is an empty answer, not an error.
        let past = service.answer(&request::read(file, 1000, 4096));
        assert_eq!(reply::bytes(&past).unwrap(), b"");
        // And a released handle is gone.
        service.answer(&request::release(file));
        assert_eq!(
            errno_of(&service.answer(&request::read(file, 0, 16))),
            libc::EBADF
        );
    }

    #[test]
    fn a_file_is_made_written_and_read_back_through_the_service() {
        let dir = a_directory();
        let (service, _keep) = service(dir.path(), false);
        let made = service.answer(&request::make(0, 0o644, b"made.txt", false));
        let (handle, attrs) = reply::attrs(&made).unwrap();
        assert_eq!(attrs.mode & 0o777, 0o644);
        assert!(dir.path().join("made.txt").exists());

        let opened = service.answer(&request::open(handle, libc::O_RDWR));
        let file = reply::handle(&opened).unwrap();
        let written = service.answer(&request::write(file, 0, b"written through vsock\n"));
        assert_eq!(reply::written(&written).unwrap(), 22);
        assert_eq!(
            std::fs::read(dir.path().join("made.txt")).unwrap(),
            b"written through vsock\n"
        );
        service.answer(&request::truncate(file, 7));
        assert_eq!(
            std::fs::read(dir.path().join("made.txt")).unwrap(),
            b"written"
        );
        assert_eq!(service.counters().writes, 1);
        assert_eq!(service.counters().bytes, 22);
    }

    #[test]
    fn a_read_only_share_refuses_every_write_and_says_why() {
        let dir = a_directory();
        let (service, _keep) = service(dir.path(), true);
        let lookup = service.answer(&request::lookup(0, b"hello.txt"));
        let (handle, _) = reply::attrs(&lookup).unwrap();
        let opened = service.answer(&request::open(handle, libc::O_RDONLY));
        assert_eq!(
            opened.kind, KIND_OK,
            "a read-only share still lets a file be read"
        );
        assert_eq!(
            errno_of(&service.answer(&request::make(0, 0o644, b"no.txt", false))),
            libc::EROFS
        );
        assert_eq!(
            errno_of(&service.answer(&request::remove(0, b"hello.txt", false))),
            libc::EROFS
        );
        assert_eq!(
            errno_of(&service.answer(&request::rename(0, b"hello.txt", b"other.txt"))),
            libc::EROFS
        );
        assert_eq!(
            errno_of(&service.answer(&request::truncate(handle, 0))),
            libc::EROFS
        );
        assert!(dir.path().join("hello.txt").exists(), "nothing was removed");
        assert!(!dir.path().join("no.txt").exists(), "nothing was made");
        assert_eq!(service.counters().refused_ro, 4);
    }

    #[test]
    fn the_control_directory_is_writable_even_inside_a_read_only_share() {
        // The project's own rule (`dc-shares`' words, and the display rule's): the control directory
        // is the one writable exception, because the guest's *status* is what comes back through it.  A
        // run that offers the guest a read-only folder holding it would otherwise get a guest
        // whose memory numbers, readiness and display state never arrive.
        let dir = a_directory();
        let uds = tempfile::tempdir().unwrap();
        let set = ShareSet::listen(
            &uds.path().join("v.sock"),
            &[Share {
                tag: "control".into(),
                path: dir.path().into(),
                where_: dc_common::GUEST_CONTROL_DIR.into(),
                read_only: true,
                writable_exception: true,
            }],
        )
        .unwrap();
        let service = &set.services()[0];
        // A file the guest writes **is** written, even though the share says `ro`.
        let made = service.answer(&request::make(0, 0o600, b"guest-meminfo", false));
        assert_eq!(made.kind, KIND_ATTR, "the guest's own status file");
        assert!(dir.path().join("guest-meminfo").exists());
        // And the plan says `ro`, because that is what the user's setting is.
        assert!(set.plan().contains("control"), "{}", set.plan());
        assert_eq!(service.counters().refused_ro, 0);
    }

    #[test]
    fn a_name_that_climbs_out_of_the_share_is_refused() {
        let dir = a_directory();
        let (service, _keep) = service(dir.path(), false);
        for name in [
            &b".."[..],
            &b"."[..],
            &b""[..],
            &b"../../etc/passwd"[..],
            &b"sub/../../etc/passwd"[..],
            &b"/etc/passwd"[..],
        ] {
            let reply = service.answer(&request::lookup(0, name));
            assert_eq!(errno_of(&reply), libc::EINVAL, "name {name:?}");
        }
        assert_eq!(service.counters().refused_name, 6);
        // A name that merely looks odd is still a name: it is looked up and it is not there.
        assert_eq!(
            errno_of(&service.answer(&request::lookup(0, b"..hidden"))),
            libc::ENOENT
        );
    }

    #[test]
    fn a_directory_lists_its_children_with_their_kinds() {
        let dir = a_directory();
        let (service, _keep) = service(dir.path(), false);
        let opened = service.answer(&request::opendir(0));
        let listing = reply::handle(&opened).unwrap();
        let entries = reply::entries(&service.answer(&request::readdir(listing))).unwrap();
        let names: Vec<(&str, u8)> = entries
            .iter()
            .map(|(_, kind, name)| (name.as_str(), *kind))
            .collect();
        assert!(names.contains(&("hello.txt", KIND_FILE)), "{names:?}");
        assert!(names.contains(&("sub", KIND_DIR)), "{names:?}");
        // Reading it again is empty: a directory is read once.
        let again = reply::entries(&service.answer(&request::readdir(listing))).unwrap();
        assert!(again.is_empty(), "{again:?}");
        // And an entry's handle opens as what the entry is.
        let file = entries
            .iter()
            .find(|(_, _, name)| name == "hello.txt")
            .unwrap()
            .0;
        let opened = service.answer(&request::open(file, libc::O_RDONLY));
        assert!(
            opened.kind == KIND_OK,
            "the listing's handle is a file handle"
        );
    }

    #[test]
    fn the_plan_names_the_port_and_the_mode_of_every_share() {
        let dir = a_directory();
        let uds = tempfile::tempdir().unwrap();
        let set = ShareSet::listen(
            &uds.path().join("v.sock"),
            &[
                Share {
                    tag: "data".into(),
                    path: dir.path().into(),
                    where_: "/mnt/share/data".into(),
                    read_only: false,
                    writable_exception: false,
                },
                Share {
                    tag: "docs".into(),
                    path: dir.path().into(),
                    where_: "/mnt/share/docs".into(),
                    read_only: true,
                    writable_exception: false,
                },
            ],
        )
        .unwrap();
        let plan = set.plan();
        assert!(plan.starts_with('#'), "{plan}");
        assert!(plan.contains("data 54000 /mnt/share/data rw"), "{plan}");
        assert!(plan.contains("docs 54001 /mnt/share/docs ro"), "{plan}");
        assert_eq!(set.services()[0].port(), dc_vsock::ports::SHARES);
        assert_eq!(set.services()[1].port(), dc_vsock::ports::SHARES + 1);
        assert!(set.get("docs").unwrap().read_only());
        assert!(set.get("nothing").is_none());
    }

    #[test]
    fn a_guest_serves_and_reads_over_a_real_socket() {
        let dir = a_directory();
        let uds = tempfile::tempdir().unwrap();
        let set = Arc::new(
            ShareSet::listen(
                &uds.path().join("v.sock"),
                &[Share {
                    tag: "data".into(),
                    path: dir.path().into(),
                    where_: "/mnt/share/data".into(),
                    read_only: false,
                    writable_exception: false,
                }],
            )
            .unwrap(),
        );
        let port = set.services()[0].port();
        let handles = set.serve_in_background();
        let mut guest =
            UnixStream::connect(dc_vsock::listener_path(&uds.path().join("v.sock"), port)).unwrap();
        let mut reader = Reader::new();
        let call = |guest: &mut UnixStream, reader: &mut Reader, frame: Frame| {
            guest.write_all(&frame.encode()).unwrap();
            guest.flush().unwrap();
            reader.read_frame(guest, port).unwrap().unwrap()
        };
        let hello = call(&mut guest, &mut reader, request::hello("data"));
        assert_eq!(hello.kind, KIND_DATA);
        let lookup = call(&mut guest, &mut reader, request::lookup(0, b"hello.txt"));
        let (handle, _) = reply::attrs(&lookup).unwrap();
        let opened = call(
            &mut guest,
            &mut reader,
            request::open(handle, libc::O_RDONLY),
        );
        let file = reply::handle(&opened).unwrap();
        let read = call(&mut guest, &mut reader, request::read(file, 0, 64));
        assert_eq!(reply::bytes(&read).unwrap(), b"hello, share\n");
        drop(guest);
        for handle in handles {
            let _ = handle.join();
        }
    }

    #[test]
    fn a_read_of_a_whole_file_arrives_in_one_piece_for_the_sizes_a_share_sees() {
        // A 1 MiB file read in one request: the service's own ceiling is 1 MiB, and the
        // framing carries it (the reply is one frame, `MAX_FRAME` is 60 KiB — so a big read is
        // answered in **chunks** the guest asks for, which is what a FUSE reader expects).
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("big.bin"), vec![7u8; 200 * 1024]).unwrap();
        let (service, _keep) = service(dir.path(), false);
        let lookup = service.answer(&request::lookup(0, b"big.bin"));
        let (handle, _) = reply::attrs(&lookup).unwrap();
        let opened = service.answer(&request::open(handle, libc::O_RDONLY));
        let file = reply::handle(&opened).unwrap();
        let read = service.answer(&request::read(file, 0, 32 * 1024));
        assert_eq!(
            reply::bytes(&read).unwrap().len(),
            32 * 1024,
            "a read is what was asked for, up to the ceiling"
        );
    }

    #[test]
    fn a_symlink_inside_the_share_is_answered_as_a_name_and_never_as_a_host_path() {
        let dir = a_directory();
        std::os::unix::fs::symlink("/etc/passwd", dir.path().join("out")).unwrap();
        std::os::unix::fs::symlink("sub/inner.txt", dir.path().join("in")).unwrap();
        let (service, _keep) = service(dir.path(), false);
        let lookup = service.answer(&request::lookup(0, b"out"));
        let (outside, _) = reply::attrs(&lookup).unwrap();
        let target = service.answer(&request::readlink(outside));
        assert_eq!(
            reply::bytes(&target).unwrap(),
            b"passwd",
            "the host's path is not handed over"
        );
        let lookup = service.answer(&request::lookup(0, b"in"));
        let (inside, _) = reply::attrs(&lookup).unwrap();
        let target = service.answer(&request::readlink(inside));
        assert_eq!(reply::bytes(&target).unwrap(), b"inner.txt");
    }

    #[test]
    fn a_guest_that_reads_the_service_more_than_once_is_answered_every_time() {
        // A FUSE reader that asks for less than a frame gets the rest next time; the service
        // holds no cursor beyond the file's own offset, which the guest sends.
        let dir = a_directory();
        let (service, _keep) = service(dir.path(), false);
        let lookup = service.answer(&request::lookup(0, b"hello.txt"));
        let (handle, _) = reply::attrs(&lookup).unwrap();
        let opened = service.answer(&request::open(handle, libc::O_RDONLY));
        let file = reply::handle(&opened).unwrap();
        let a = service.answer(&request::read(file, 0, 5));
        let first = reply::bytes(&a).unwrap().to_vec();
        let b = service.answer(&request::read(file, 5, 5));
        let second = reply::bytes(&b).unwrap().to_vec();
        assert_eq!(first, b"hello");
        assert_eq!(second, b", sha");
    }
}
