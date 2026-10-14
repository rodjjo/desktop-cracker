//! **The guest's channels**: the vsock services the agent dials (`dc-vsock`'s own port numbers).
//!
//! Every one of them is guest-initiated (a service that must push has the
//! guest open the channel and keep it open), so this is one function — `dial` — and the ports.

use std::os::fd::RawFd;

/// The ports, as `dc_vsock::ports` numbers them.  A port belongs to one service and is never
/// reused, and these are the *guest's* own view of the same numbers.
pub mod ports {
    /// Display: pixels, the cursor and the screen's own state.
    pub const DISPLAY: u32 = 53000;
    /// Input: the keyboard and the mouse, flowing the other way (on the display connection).
    pub const INPUT: u32 = 53001;
    /// Shared folders.
    pub const SHARES: u32 = 54000;
    /// Audio.
    pub const AUDIO: u32 = 55000;
    /// Control: the mount plan, the disk plan, the display's state.
    pub const CONTROL: u32 = 56000;
    /// The shutdown channel.
    pub const SHUTDOWN: u32 = 57000;
    /// Readiness: the guest's "I am up" and its reports.
    pub const READY: u32 = 58000;
    /// The network: raw IP frames between the guest's `tun0` and the host's engine.
    pub const NETWORK: u32 = 59000;
    /// Remote X.
    pub const REMOTE_X: u32 = 1026;
}

/// The host's own CID, as `AF_VSOCK` addresses it.
pub const HOST_CID: u32 = 2;

/// Dial the host's service on `port`, answering the connected socket (or `None`, with the reason on
/// stderr — the C agent's own behaviour: a service that cannot be dialled is reported and the
/// caller decides).
pub fn dial(port: u32) -> Option<std::os::unix::net::UnixStream> {
    // SAFETY: a socket is created and immediately owned by the `OwnedFd`-like wrapper below.
    let fd: RawFd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        crate::console::note(&format!("deskd: vsock: {}", std::io::Error::last_os_error()));
        return None;
    }
    let mut addr: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    addr.svm_family = libc::AF_VSOCK as u16;
    addr.svm_cid = HOST_CID;
    addr.svm_port = port;
    // SAFETY: the address is a `sockaddr_vm` of the right family and length, and the fd is open.
    let rc = unsafe {
        libc::connect(
            fd,
            &addr as *const libc::sockaddr_vm as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        let err = std::io::Error::last_os_error();
        crate::console::note(&format!("deskd: connect to port {port}: {err}"));
        unsafe { libc::close(fd) };
        return None;
    }
    // SAFETY: the fd is a connected `AF_VSOCK` stream socket and nothing else owns it.
    Some(unsafe { <std::os::unix::net::UnixStream as std::os::fd::FromRawFd>::from_raw_fd(fd) })
}

/// The guest **says it is up**: kind 1 (`KIND_READY`) with the line, and the host answers with
/// the same kind, which is how the agent knows the line landed rather than hoping it did.
pub const KIND_READY: u16 = 1;
/// A report the guest makes on the same channel (its own progress, for the run's landing).
pub const KIND_REPORT: u16 = 2;

/// **The verbs this program hands to the C agent** (`/bin/desktop-cracker-legacy`), which still owns them:
/// the shares' FUSE filesystem, the sound, the network and the disk job.  The Rust port takes each
/// one over as it lands, and until then a guest keeps every service it had — the legacy program is
/// the *same* code the guest ran before, so nothing about those services changes.
pub const LEGACY_VERBS: [&str; 0] = [];

/// Is this verb one the legacy agent still owns?
pub fn is_legacy(verb: &str) -> bool {
    LEGACY_VERBS.contains(&verb)
}

/// Run the same verb on the legacy agent, with the same arguments, and answer its status.
pub fn run_legacy(args: &[String]) -> i32 {
    let path = std::path::Path::new(super::LEGACY_AGENT);
    if !path.exists() {
        crate::console::note(&format!(
            "deskd: {args:?}: the legacy agent is not at {}",
            super::LEGACY_AGENT
        ));
        return 1;
    }
    match std::process::Command::new(path)
        .args(args)
        .stdin(std::process::Stdio::inherit())
        .status()
    {
        Ok(status) => status.code().unwrap_or(0),
        Err(e) => {
            crate::console::note(&format!("deskd: {}: {e}", super::LEGACY_AGENT));
            1
        }
    }
}

/// `ready`: one line to the console **and** a frame on the readiness channel — which is what the
/// run waits for (`DESK-READY` is the guest's own word for it).
///
/// It is the C agent's own exchange: the line, then the host's answer within a moment.  A run whose
/// answer is not waited for would be a run that starts its guest and hopes.
pub fn ready(line: &str) -> i32 {
    crate::console::say(&format!("{line}"));
    let Some(mut channel) = dial(ports::READY) else {
        crate::console::note(&format!("deskd: the readiness channel did not answer"));
        return 1;
    };
    if let Err(e) = send_frame(&mut channel, KIND_READY, format!("{line}\n").as_bytes()) {
        crate::console::note(&format!("deskd: sending the landmark: {e}"));
        return 1;
    }
    // The host's answer, with the C agent's own patience (5 seconds): a line that never landed is
    // worth saying out loud, and a run that waits forever for it is not.
    let _ = channel.set_read_timeout(Some(std::time::Duration::from_secs(5)));
    let mut answer = [0u8; 64];
    match std::io::Read::read(&mut channel, &mut answer) {
        Ok(0) => {
            crate::console::note(&format!("deskd: the readiness channel closed without answering"));
            1
        }
        Ok(_) => 0,
        Err(e) => {
            crate::console::note(&format!("deskd: the readiness channel: {e}"));
            1
        }
    }
}

/// One small frame: a length, a kind and the payload (the project's own framing, `dc-vsock`).
pub fn send_frame(channel: &mut std::os::unix::net::UnixStream, kind: u16, payload: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_frame_is_a_length_a_kind_and_the_payload() {
        let mut buffer = Vec::new();
        // The framing itself, written into a buffer (there is no socket in a unit test).
        let payload = b"DESK-READY\n";
        let len = payload.len() as u32;
        buffer.extend_from_slice(&len.to_le_bytes());
        buffer.extend_from_slice(&KIND_READY.to_le_bytes());
        buffer.extend_from_slice(payload);
        assert_eq!(&buffer[..4], &(payload.len() as u32).to_le_bytes());
        assert_eq!(&buffer[4..6], &1u16.to_le_bytes());
        assert_eq!(&buffer[6..], payload);
    }

    #[test]
    fn the_verbs_the_rust_agent_does_not_own_go_to_the_legacy_one() {
        for verb in [] as [&str; 0] {
            assert!(is_legacy(verb), "{verb} is the legacy agent's until its port lands");
        }
        for verb in [
            "display",
            "ready",
            "session",
            "control",
            "net",
            "shutdown",
            "job",
            "share",
            "audio",
        ] {
            assert!(!is_legacy(verb), "{verb} is this program's own");
        }
    }

    #[test]
    fn the_ports_are_the_projects_own_numbers() {
        // The same numbers `dc_vsock::ports` holds, so a guest and a host cannot disagree.
        assert_eq!(ports::DISPLAY, dc_fc_display::PORT_DISPLAY);
        assert_eq!(ports::REMOTE_X, 1026);
    }
}
