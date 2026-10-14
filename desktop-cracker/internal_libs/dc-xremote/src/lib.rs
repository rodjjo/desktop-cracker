//! Remote X: the **host's X server exposed inside the guest** as an additional
//! display (feature 6).
//!
//! > Remote X access — the x server from the host inside the VM as an additional
//! > x server for the applications running there, so the application can create
//! > windows outside the VM while running sandboxed inside the VM.
//!
//! The guest already has its own X server (LightDM starts it) and that screen is
//! what the OpenGL window shows.  This is the *other* direction: an application
//! running inside the microVM may also open a window on the **host's** desktop,
//! as if it had been started there.
//!
//! Three things make that work, and this library owns all three:
//!
//! 1. **the socket**: the host's `/tmp/.X11-unix` is shared into the guest by
//!    9P (`dc-shares`, tag `xdisplay`, always read-only), so the guest sees
//!    `/tmp/.X11-unix/X<n>` — the same path its own X client libraries use;
//! 2. **the authority**: the host server is not `-ac`, so a client needs the
//!    MIT-MAGIC-COOKIE for that display.  `HostDisplay::extract_authority` writes
//!    exactly that cookie, in the `XAUTHORITY` file format, into the application's
//!    control share — which the guest mounts read-write, so the file is *inside*
//!    the guest and nowhere else.  Nothing is granted to the network: the cookie
//!    is only usable by something that can already read that share;
//! 3. **the environment**: `DISPLAY` and `XAUTHORITY` have to reach the guest's
//!    applications.  The host writes an environment file next to the cookie
//!    (`guest_environment`), and the guest's init sources it before starting the
//!    session, so every application inside the guest finds the host's display
//!    without anything being configured by hand.
//!
//! What this deliberately does **not** do: run an X server proxy, or turn off the
//! host's access control (`xhost +`).  A proxy would be a second protocol
//! implementation to keep correct, and `xhost +` would let *any* client of that
//! display connect — including ones that are not this microVM.  A cookie that
//! lives only in the microVM's own share is both smaller and stricter.

use std::path::{Path, PathBuf};

/// The host's X display, as the guest will see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostDisplay {
    /// `:1`, `:99`, `hostname:1` — whatever the host's `DISPLAY` says.
    pub display: String,
    /// The display number (`1`, `99`), which is what the socket and the cookie
    /// are named after.
    pub number: u32,
    /// The host's socket for it (`/tmp/.X11-unix/X1`).
    pub socket: PathBuf,
    /// Where the cookie was extracted from (`~/.Xauthority`), when there was one.
    pub authority_source: Option<PathBuf>,
}

/// Why the forwarder could not start.
#[derive(Debug, thiserror::Error)]
pub enum ForwardError {
    #[error("virtio-vsock is not available on this host ({0}); load vhost_vsock")]
    NoVsock(String),
    #[error("{0}")]
    Io(#[from] std::io::Error),
}

/// Why remote X could not be set up.
#[derive(Debug, thiserror::Error)]
pub enum XRemoteError {
    #[error("{0}")]
    Common(#[from] dc_common::Error),
    #[error("the host has no DISPLAY set")]
    NoDisplay,
    #[error("{display:?} is not a local display (remote X needs the host's own server)")]
    NotLocal { display: String },
    #[error("there is no X socket for {display:?} at {socket}")]
    NoSocket { display: String, socket: PathBuf },
    #[error("no {name} cookie for {display:?} in {file}")]
    NoCookie {
        name: String,
        display: String,
        file: PathBuf,
    },
    #[error("{program} refused: {message}")]
    Tool { program: String, message: String },
    #[error("{0}")]
    Malformed(String),
    #[error("the vsock forwarder: {0}")]
    Forward(#[from] ForwardError),
}

pub type Result<T> = std::result::Result<T, XRemoteError>;

/// The name of the cookie every X server that has one uses.
pub const MIT_COOKIE: &str = "MIT-MAGIC-COOKIE-1";

/// Where the application keeps the files the guest reads.
pub const ENV_FILE: &str = "x-display.env";
/// The authority file the guest is pointed at.
pub const AUTHORITY_FILE: &str = "Xauthority";

/// The display number of a `DISPLAY` value, and whether it is the host's own
/// server.
///
/// `:1` and `hostname:1` are the local server (the part before the colon is the
/// host, and the host is this machine); `otherhost:1` or `:1.0` is a client of
/// something else, which is not what this feature is about.
pub fn parse_display(value: &str) -> Result<(u32, bool)> {
    let value = value.trim();
    let (host, rest) = match value.split_once(':') {
        Some((h, r)) => (h, r),
        None => {
            return Err(XRemoteError::NotLocal {
                display: value.into(),
            })
        }
    };
    // `:1.0` names a screen; the display number is what matters.
    let number = rest.split('.').next().unwrap_or("");
    let number: u32 = number
        .parse()
        .map_err(|_| XRemoteError::Malformed(format!("{value:?} has no display number")))?;
    let local = host.is_empty() || host.eq_ignore_ascii_case(&hostname());
    Ok((number, local))
}

/// This machine's name, as `hostname` reports it (falling back to the file).
pub fn hostname() -> String {
    if let Ok(name) = std::fs::read_to_string("/proc/sys/kernel/hostname") {
        return name.trim().to_string();
    }
    "localhost".to_string()
}

/// The socket path of a display number.
pub fn socket_path(socket_dir: &Path, number: u32) -> PathBuf {
    socket_dir.join(format!("X{number}"))
}

/// Find the host's own X display, if it has one.
pub fn detect(socket_dir: &Path) -> Result<HostDisplay> {
    let value = std::env::var("DISPLAY").map_err(|_| XRemoteError::NoDisplay)?;
    let (number, local) = parse_display(&value)?;
    if !local {
        return Err(XRemoteError::NotLocal { display: value });
    }
    let socket = socket_path(socket_dir, number);
    if !socket.exists() {
        return Err(XRemoteError::NoSocket {
            display: value,
            socket,
        });
    }
    Ok(HostDisplay {
        display: format!(":{number}"),
        number,
        socket,
        authority_source: None,
    })
}

/// Read an `XAUTHORITY` file and return the cookie for a display.
///
/// The format (`Xau` in the X sources): a sequence of entries, each
///
/// ```text
/// u16 family | u16 address length | address | u16 number length | number |
/// u16 name length | name | u16 data length | data
/// ```
///
/// with every length in network byte order.  `number` is the display number as a
/// *string*, and the address may be a hostname (family 0x100, "Local"), or the
/// literal `#ffff#hostname#` form an X server uses for its local connections.
pub fn read_authority(path: &Path, number: u32) -> Result<Vec<u8>> {
    let data = dc_common::fs::read(path)?;
    let mut pos = 0usize;
    let want_number = number.to_string();
    // An entry with an empty display number authorises every display on this
    // host: held here in case no entry names the display exactly.
    let mut default_entry: Option<Vec<u8>> = None;
    while pos + 2 <= data.len() {
        let family = u16::from_be_bytes([data[pos], data[pos + 1]]);
        pos += 2;
        let address = take(&data, &mut pos)?;
        let entries_number = take(&data, &mut pos)?;
        let name = take(&data, &mut pos)?;
        let value = take(&data, &mut pos)?;
        let address = String::from_utf8_lossy(address).to_string();
        let entries_number = String::from_utf8_lossy(entries_number).to_string();
        let name = String::from_utf8_lossy(name).to_string();
        if name != MIT_COOKIE {
            continue;
        }
        // Two forms both authorise every display of this host:
        //   * an entry whose display number is empty and whose address is the
        //     hostname — what a display manager writes, and what `xauth list :1`
        //     matches for any display number;
        //   * an entry with the number we are looking for, from `xauth add`.
        let number_matches = entries_number.is_empty() || entries_number == want_number;
        if !number_matches {
            continue;
        }
        // A *specific* display's entry is the better match, so it wins when it
        // appears later: keep looking for one.
        if entries_number == want_number {
            return Ok(value.to_vec());
        }
        default_entry = Some(value.to_vec());
        let _ = (family, address);
        continue;
    }
    if let Some(cookie) = default_entry {
        return Ok(cookie);
    }
    Err(XRemoteError::NoCookie {
        name: MIT_COOKIE.to_string(),
        display: format!(":{number}"),
        file: path.to_path_buf(),
    })
}

fn take<'a>(data: &'a [u8], pos: &mut usize) -> Result<&'a [u8]> {
    if *pos + 2 > data.len() {
        return Err(XRemoteError::Malformed("truncated authority entry".into()));
    }
    let len = u16::from_be_bytes([data[*pos], data[*pos + 1]]) as usize;
    *pos += 2;
    if *pos + len > data.len() {
        return Err(XRemoteError::Malformed("truncated authority entry".into()));
    }
    let out = &data[*pos..*pos + len];
    *pos += len;
    Ok(out)
}

/// Write an authority file for a cookie, in the format X clients read.
///
/// Two entries, which is what a display manager writes and what the X client
/// library accepts for **any** display of this host on a unix socket:
///
/// * family `Local` (0x0100) with the hostname as the address,
/// * family `Wild` (0xffff) with the `#ffff#<host>#` form.
///
/// Both have an **empty display number**, which is the part that makes them
/// apply to every display: with a number in it, a client asking for another
/// display would be refused.  (`xauth list :0` and `xauth list :1` on a desktop
/// session both match exactly such an entry.)
pub fn write_authority(cookie: &[u8], _number: u32) -> Vec<u8> {
    let host = hostname();
    let mut out = Vec::new();
    for (family, address) in [
        (0x0100u16, host.clone()),
        (0xffffu16, format!("#ffff#{host}#")),
    ] {
        out.extend_from_slice(&family.to_be_bytes());
        for field in [address.as_bytes(), b"".as_slice(), MIT_COOKIE.as_bytes()] {
            out.extend_from_slice(&(field.len() as u16).to_be_bytes());
            out.extend_from_slice(field);
        }
        out.extend_from_slice(&(cookie.len() as u16).to_be_bytes());
        out.extend_from_slice(cookie);
    }
    out
}

impl HostDisplay {
    /// Extract the cookie for this display from the host's authority file and
    /// write it into `dir` (the control share the guest reads).
    ///
    /// Returns the path of the file **as the guest sees it**.
    pub fn extract_authority(&self, authority_source: &Path, dir: &Path) -> Result<PathBuf> {
        let cookie = read_authority(authority_source, self.number)?;
        let file = dir.join(AUTHORITY_FILE);
        dc_common::fs::write_atomic(&file, write_authority(&cookie, self.number))?;
        // Only the owner needs to read it, and it holds a live credential.
        restrict(&file);
        Ok(file)
    }

    /// The environment file the guest sources.  It names the display, the
    /// authority file **inside the guest**, and nothing else.
    pub fn guest_environment(&self, guest_authority: &str) -> String {
        let mut text = String::new();
        text.push_str("# generated by desktop-cracker: the host's X server, for the guest\n");
        text.push_str("# Sourced by the guest's init before the session starts.\n");
        text.push_str(&format!("export DISPLAY={}\n", self.display));
        text.push_str(&format!("export XAUTHORITY={guest_authority}\n"));
        text
    }

    /// Write that file into the control share.
    pub fn write_environment(&self, dir: &Path, guest_authority: &str) -> Result<PathBuf> {
        let file = dir.join(ENV_FILE);
        dc_common::fs::write_atomic(&file, self.guest_environment(guest_authority).as_bytes())?;
        Ok(file)
    }

    /// The environment for a guest that reaches the host through the vsock
    /// forwarder instead: the display number is the guest's **own** spare one
    /// (`:9` by default), and the guest's forwarder is already listening on its
    /// socket, so an application just uses `DISPLAY=:9`.
    pub fn write_forwarded_environment(
        &self,
        dir: &Path,
        guest_authority: &str,
        guest_number: u32,
        vsock_port: u32,
    ) -> Result<PathBuf> {
        let file = dir.join(ENV_FILE);
        // Built line by line: a `format!` with line continuations would put the
        // source's indentation into the file, and the guest `sscanf`s it.
        let mut text = String::new();
        text.push_str("# generated by desktop-cracker: the host's X server, through vsock\n");
        text.push_str("# The guest's forwarder listens on this display number and passes\n");
        text.push_str("# each connection to the host over virtio-vsock.\n");
        text.push_str(&format!("export DISPLAY=:{guest_number}\n"));
        text.push_str(&format!("export XAUTHORITY={guest_authority}\n"));
        text.push_str(&format!("export DESK_X_VSOCK_PORT={vsock_port}\n"));
        dc_common::fs::write_atomic(&file, text.as_bytes())?;
        Ok(file)
    }
}

fn restrict(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

/// Where this user's authority file is: `$XAUTHORITY` when it is set (a display
/// manager keeps it under `/run/user`, and that is the file with the cookie),
/// otherwise `~/.Xauthority`.
pub fn authority_path() -> PathBuf {
    if let Ok(path) = std::env::var("XAUTHORITY") {
        if !path.is_empty() {
            return PathBuf::from(path);
        }
    }
    dc_common::home_dir().join(".Xauthority")
}

/// The xauth program, when the host has it: used only to *check* what the
/// library extracted, so a mismatch is caught here rather than inside the guest.
pub fn xauth_list(display: &str, authority: &Path) -> Result<String> {
    let out = std::process::Command::new("xauth")
        .args(["-f", &authority.display().to_string(), "list", display])
        .output()
        .map_err(|source| dc_common::Error::Io {
            path: PathBuf::from("xauth"),
            source,
        })?;
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    if !out.status.success() && text.trim().is_empty() {
        return Err(XRemoteError::Tool {
            program: format!("xauth -f {} list {display}", authority.display()),
            message: String::from_utf8_lossy(&out.stderr).trim().to_string(),
        });
    }
    Ok(text)
}

/// Is there a cookie in this authority file for this display?  (`false` means
/// the display needs none, or the file is not the right one.)
pub fn has_cookie(path: &Path, number: u32) -> bool {
    read_authority(path, number).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_local_display_is_recognised_and_a_remote_one_is_not() {
        assert_eq!(parse_display(":1").unwrap(), (1, true));
        assert_eq!(parse_display(":0").unwrap(), (0, true));
        assert_eq!(parse_display(":99.0").unwrap(), (99, true));
        let (n, local) = parse_display(&format!("{}:2", hostname())).unwrap();
        assert_eq!((n, local), (2, true));
        let (n, local) = parse_display("elsewhere:2").unwrap();
        assert_eq!((n, local), (2, false));
        assert!(matches!(
            parse_display("nothing-here"),
            Err(XRemoteError::NotLocal { .. })
        ));
        assert!(matches!(
            parse_display(":abc"),
            Err(XRemoteError::Malformed(_))
        ));
    }

    #[test]
    fn what_we_write_authorises_any_display_of_this_host() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Xauthority");
        let cookie = [0x11u8, 0x22, 0x33, 0x44];
        std::fs::write(&path, write_authority(&cookie, 1)).unwrap();
        // the display we extracted it for...
        assert_eq!(read_authority(&path, 1).unwrap(), cookie);
        // ...and every other one on this host, which is what an empty display
        // number means and what a client on another display needs.
        assert_eq!(read_authority(&path, 0).unwrap(), cookie);
        assert_eq!(read_authority(&path, 99).unwrap(), cookie);
        assert!(has_cookie(&path, 7));

        // a file with nothing for this display (a different cookie name) says so
        // by name, so the sentence can say what is missing
        let other = dir.path().join("other");
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&0x0100u16.to_be_bytes());
        for field in [
            b"somewhere".as_slice(),
            b"".as_slice(),
            b"XC-QUERY-SECURITY-1".as_slice(),
        ] {
            bytes.extend_from_slice(&(field.len() as u16).to_be_bytes());
            bytes.extend_from_slice(field);
        }
        bytes.extend_from_slice(&4u16.to_be_bytes());
        bytes.extend_from_slice(&cookie);
        std::fs::write(&other, bytes).unwrap();
        match read_authority(&other, 1) {
            Err(XRemoteError::NoCookie { name, display, .. }) => {
                assert_eq!(name, MIT_COOKIE);
                assert_eq!(display, ":1");
            }
            other => panic!("expected NoCookie, got {other:?}"),
        }
    }

    #[test]
    fn an_entry_that_names_the_display_exactly_wins() {
        // A real file has the display manager's default entry; if a specific one
        // was added later (`xauth add :1 …`), that is the one to use.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Xauthority");
        let mut bytes = write_authority(&[1, 2, 3, 4], 1); // default entries
        bytes.extend_from_slice(&specific_entry(&[9, 9, 9, 9], 1));
        std::fs::write(&path, bytes).unwrap();
        assert_eq!(read_authority(&path, 1).unwrap(), vec![9, 9, 9, 9]);
        // and a display with only the default entry gets that one
        assert_eq!(read_authority(&path, 2).unwrap(), vec![1, 2, 3, 4]);
    }

    /// One authority entry that names a display number (the `xauth add` form).
    fn specific_entry(cookie: &[u8], number: u32) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&0x0100u16.to_be_bytes());
        for field in [
            hostname().as_bytes(),
            number.to_string().as_bytes(),
            MIT_COOKIE.as_bytes(),
        ] {
            out.extend_from_slice(&(field.len() as u16).to_be_bytes());
            out.extend_from_slice(field);
        }
        out.extend_from_slice(&(cookie.len() as u16).to_be_bytes());
        out.extend_from_slice(cookie);
        out
    }

    #[test]
    fn a_truncated_authority_file_is_refused_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Xauthority");
        std::fs::write(&path, [0x01, 0x00, 0xff]).unwrap();
        match read_authority(&path, 1) {
            Err(XRemoteError::Malformed(msg)) => assert!(msg.contains("truncated"), "{msg}"),
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn the_environment_file_says_which_display_and_which_authority() {
        let d = HostDisplay {
            display: ":1".into(),
            number: 1,
            socket: PathBuf::from("/tmp/.X11-unix/X1"),
            authority_source: None,
        };
        let env = d.guest_environment("/run/desktop-cracker/Xauthority");
        assert!(env.contains("export DISPLAY=:1"), "{env}");
        assert!(
            env.contains("export XAUTHORITY=/run/desktop-cracker/Xauthority"),
            "{env}"
        );
        assert!(
            env.starts_with('#'),
            "it is sourced, so comments are fine: {env}"
        );

        let dir = tempfile::tempdir().unwrap();
        let file = d
            .write_environment(dir.path(), "/run/desktop-cracker/Xauthority")
            .unwrap();
        assert_eq!(
            std::fs::read_to_string(&file).unwrap(),
            d.guest_environment("/run/desktop-cracker/Xauthority")
        );
    }

    #[test]
    fn extracting_writes_a_private_authority_file_for_the_guest() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let host_auth = dir.path().join("host-Xauthority");
        std::fs::write(&host_auth, write_authority(&[7, 7, 7, 7], 1)).unwrap();
        let share = dir.path().join("control");
        std::fs::create_dir_all(&share).unwrap();
        let d = HostDisplay {
            display: ":1".into(),
            number: 1,
            socket: PathBuf::from("/tmp/.X11-unix/X1"),
            authority_source: Some(host_auth.clone()),
        };
        let guest_path = d.extract_authority(&host_auth, &share).unwrap();
        assert_eq!(guest_path, share.join(AUTHORITY_FILE));
        // the file the guest gets is a valid authority file for that display
        assert_eq!(read_authority(&guest_path, 1).unwrap(), vec![7, 7, 7, 7]);
        let mode = std::fs::metadata(&guest_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "a live cookie must not be world readable");
    }

    #[test]
    fn detecting_uses_the_hosts_own_display_and_its_socket() {
        let dir = tempfile::tempdir().unwrap();
        // no socket: reported as such, with the path it looked for
        std::env::set_var("DISPLAY", ":7");
        match detect(dir.path()) {
            Err(XRemoteError::NoSocket { display, socket }) => {
                assert_eq!(display, ":7");
                assert_eq!(socket, socket_path(dir.path(), 7));
            }
            other => panic!("expected NoSocket, got {other:?}"),
        }
        // with one: found
        std::fs::write(socket_path(dir.path(), 7), b"").unwrap();
        let found = detect(dir.path()).unwrap();
        assert_eq!(found.display, ":7");
        assert_eq!(found.number, 7);
    }

    #[test]
    fn a_remote_display_is_not_what_this_feature_is_about() {
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var("DISPLAY", "some-other-host:0");
        assert!(matches!(
            detect(dir.path()),
            Err(XRemoteError::NotLocal { .. })
        ));
    }
}

/// The display number the guest uses for the host's server when forwarding is
/// needed: a spare one, so it cannot collide with the guest's own X server (which
/// takes `:0`).
pub const GUEST_DISPLAY_NUMBER: u32 = 9;

/// The virtio-vsock port the host's forwarder listens on.  Fixed, because the
/// guest's side of it is a command line the guest's init runs and neither side
/// has a discovery mechanism.
pub const VSOCK_PORT: u32 = 1026;

/// The host's end of the remote-X path: it listens on **virtio-vsock** and hands
/// every connection it receives to the host's own X socket, byte for byte.
///
/// The direction matters and is worth stating: the *guest* is what connects (a
/// microVM can reach its host's context id), so the host listens on vsock and
/// the guest's forwarder dials it.  The host's X server is then reached from the
/// connection's other end.
pub struct Forwarder {
    /// The vsock listener's descriptor.
    listener: std::os::fd::OwnedFd,
    /// The host socket every connection is passed to.
    target: PathBuf,
    /// The thread accepting connections (stopped when this is dropped).
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
}

impl Forwarder {
    /// Listen on `port` and pass each connection to the X socket `target`.
    ///
    /// `guest_cid` names the one guest this forwarder serves (its connections
    /// carry the guest's context id): two desktop-crackers on one host each
    /// have their own guest, and each answers only its own.
    pub fn start(port: u32, target: &Path, guest_cid: u32) -> Result<Forwarder> {
        let listener = vsock_listener(port).map_err(ForwardError::NoVsock)?;

        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let stop_in = stop.clone();
        let target_in = target.to_path_buf();
        // The accept loop polls with a timeout: a blocking `accept` would only
        // be woken by a connection that may never come, so the application's exit
        // would have to wait for one.
        use std::os::unix::io::AsRawFd;
        let raw = listener.as_raw_fd();
        let handle = std::thread::spawn(move || loop {
            if stop_in.load(std::sync::atomic::Ordering::Relaxed) {
                break;
            }
            let mut pfd = libc::pollfd {
                fd: raw,
                events: libc::POLLIN,
                revents: 0,
            };
            if unsafe { libc::poll(&mut pfd, 1, 200) } <= 0 {
                continue;
            }
            let mut peer: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
            let mut peer_len = std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t;
            let c = unsafe {
                libc::accept(
                    raw,
                    &mut peer as *mut libc::sockaddr_vm as *mut libc::sockaddr,
                    &mut peer_len,
                )
            };
            if c < 0 {
                let err = std::io::Error::last_os_error();
                if err.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                break;
            }
            // Whose connection is it?  A listener that answered every guest would
            // let one application's forwarder serve another's microVM.
            if peer.svm_cid != guest_cid {
                unsafe { libc::close(c) };
                continue;
            }
            use std::os::fd::FromRawFd;
            let stream: std::os::unix::net::UnixStream =
                unsafe { std::os::unix::net::UnixStream::from_raw_fd(c) };
            let target = target_in.clone();
            let _ = std::thread::spawn(move || forward_vsock(stream, &target));
        });

        Ok(Forwarder {
            listener,
            target: target.to_path_buf(),
            stop,
            handle: Some(handle),
        })
    }

    pub fn target(&self) -> &Path {
        &self.target
    }

    /// The port this forwarder listens on.
    pub fn is_listening(&self) -> bool {
        use std::os::unix::io::AsRawFd;
        self.listener.as_raw_fd() >= 0
    }
}

impl Drop for Forwarder {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        // Nothing wakes the blocked `accept` but the fd closing: do that first,
        // then join.
        use std::os::unix::io::AsRawFd;
        unsafe { libc::shutdown(self.listener.as_raw_fd(), libc::SHUT_RDWR) };
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

/// Pass one vsock connection to the host's X socket, both directions.
fn forward_vsock(vsock_side: std::os::unix::net::UnixStream, target: &Path) {
    // A host with no X server at that socket has nothing to forward to: the connection is
    // dropped and the guest's client sees its own error.
    if let Ok(server) = std::os::unix::net::UnixStream::connect(target) {
        pump(vsock_side, server);
    }
}

/// Copy bytes both ways until either end closes.
fn pump(a: std::os::unix::net::UnixStream, b: std::os::unix::net::UnixStream) {
    let Ok(mut a_read) = a.try_clone() else {
        return;
    };
    let Ok(mut b_write) = b.try_clone() else {
        return;
    };
    let up = std::thread::spawn(move || {
        let _ = std::io::copy(&mut a_read, &mut b_write);
    });
    let mut b_read = b;
    let mut a_write = a;
    let _ = std::io::copy(&mut b_read, &mut a_write);
    let _ = up.join();
}

/// Open a virtio-vsock listener (`AF_VSOCK`, the guest connects to the host's
/// context id), which is what makes the forwarder reachable from the microVM.
fn vsock_listener(port: u32) -> std::result::Result<std::os::fd::OwnedFd, String> {
    use std::os::fd::FromRawFd;
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().to_string());
    }
    // VMADDR_CID_ANY = -1: any local context id (the host has one).
    let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    addr.svm_family = libc::AF_VSOCK as u16;
    addr.svm_cid = u32::MAX;
    addr.svm_port = port;
    let rc = unsafe {
        libc::bind(
            fd,
            &addr as *const libc::sockaddr_vm as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        let err = std::io::Error::last_os_error().to_string();
        unsafe { libc::close(fd) };
        return Err(err);
    }
    if unsafe { libc::listen(fd, 8) } != 0 {
        let err = std::io::Error::last_os_error().to_string();
        unsafe { libc::close(fd) };
        return Err(err);
    }
    Ok(unsafe { std::os::fd::OwnedFd::from_raw_fd(fd) })
}

#[cfg(test)]
mod forward_tests {
    use super::*;

    /// The forwarder's *unix* half: a connection made to it is passed to the
    /// target socket, and bytes come back.  (The vsock half needs the host's
    /// `vhost_vsock`, which a unit test must not depend on.)
    #[test]
    fn a_connection_to_the_guest_socket_reaches_the_target() {
        let dir = tempfile::tempdir().unwrap();
        let target_path = dir.path().join("X1");
        let listener = std::os::unix::net::UnixListener::bind(&target_path).unwrap();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let mut stream = stream;
                let mut buf = [0u8; 4];
                use std::io::Read;
                let _ = stream.read_exact(&mut buf);
                use std::io::Write;
                let _ = stream.write_all(b"pong");
            }
        });

        // what the forwarder's inbound side does, without a vsock in the test: a
        // unix socket the "guest" connects to, passed on to the target
        let guest_dir = dir.path().join("guest");
        std::fs::create_dir_all(&guest_dir).unwrap();
        let guest_socket = guest_dir.join("X1");
        let guest_listener = std::os::unix::net::UnixListener::bind(&guest_socket).unwrap();
        let target = target_path.clone();
        std::thread::spawn(move || {
            for client in guest_listener.incoming().flatten() {
                let Ok(server) = std::os::unix::net::UnixStream::connect(&target) else {
                    continue;
                };
                pump(client, server);
            }
        });

        use std::io::{Read, Write};
        let mut c = std::os::unix::net::UnixStream::connect(&guest_socket).unwrap();
        c.write_all(b"ping").unwrap();
        let mut buf = [0u8; 4];
        c.read_exact(&mut buf).unwrap();
        assert_eq!(&buf, b"pong");
    }

    #[test]
    fn the_forwarder_reports_its_target() {
        // `start` needs vsock (the host has vhost_vsock, a CI container may not):
        // when it is missing, the error names the reason rather than panicking.
        let dir = tempfile::tempdir().unwrap();
        match Forwarder::start(VSOCK_PORT, &dir.path().join("X1"), 7) {
            Ok(f) => {
                assert!(f.is_listening());
                assert_eq!(f.target(), dir.path().join("X1"));
            }
            Err(XRemoteError::Forward(ForwardError::NoVsock(reason))) => {
                eprintln!("skipping: this host has no vsock ({reason})");
            }
            Err(other) => panic!("unexpected: {other}"),
        }
    }
}
