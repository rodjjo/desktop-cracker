//! **The host's end of every vsock service.**
//!
//! One virtio-vsock device, many ports, and the ports are the services. Two facts
//! of Firecracker's device decide this whole crate, and both were read off its own
//! documentation and measured on this host (2026-10-09):
//!
//! * **a guest-initiated connection is a host listener named after the port.**
//!   The guest connects to `AF_VSOCK` CID 2 and port `P`; Firecracker then
//!   connects to the unix socket `<uds_path>_<P>` on the host.  So the host must
//!   be **listening on that path before the machine starts**: a connection to a
//!   port nobody listens on is a `RST` in the guest, and a service that starts
//!   late loses the call.  That is what [`Service::bind`] is for, and it is why
//!   the host opens every listener before `InstanceStart`.
//! * **it is a byte stream with no message boundaries.**  A 200-byte write can
//!   arrive as 47 + 153, and partial reads are more common under load — so every
//!   service frames what it sends ([`Frame`]) and reads with an accumulator
//!   ([`Reader`]), and nothing here assumes "one read is one message".
//!
//! The direction a service must *push* (the input events of the display) does
//! not use the `CONNECT <port>` host→guest handshake: the guest opens the channel
//! and keeps it open, so there is exactly one direction of initiation and one
//! multiplexer to reason about.  [`connect_to_guest`] implements the other
//! direction anyway, because a guest that cannot dial yet has to be reachable
//! from the host, and because a test wants to stand in for Firecracker.

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

/// The ports, in one place: a port belongs to one service and is never reused.
///
/// The numbers are this project's own namespace, and the one that exists in the
/// project this one started with today keeps its number — a guest's tools already look for
/// it (`dc-xremote`).
pub mod ports {
    /// Remote X (`dc-xremote`): the host's X server, reached from the guest.
    pub const REMOTE_X: u32 = 1026;
    /// Display: pixels, the cursor and the screen's own state.
    pub const DISPLAY: u32 = 53000;
    /// Input: the keyboard and the mouse, flowing the other way.
    pub const INPUT: u32 = 53001;
    /// Shared folders: the filesystem service the guest's FUSE agent talks to.
    pub const SHARES: u32 = 54000;
    /// Audio: PCM in both directions.
    pub const AUDIO: u32 = 55000;
    /// Control: the mount plan, the disk plan, the display's state.
    pub const CONTROL: u32 = 56000;
    /// **The shutdown channel**: the guest's agent opens it when it starts and keeps it open,
    /// and the host sends one frame on it when the guest should go away.  The guest answers by
    /// **rebooting itself**, which is what ends Firecracker on x86: the guest's kernel, booted
    /// with `reboot=k`, pulses the i8042's reset line and Firecracker — which emulates that
    /// controller — exits by itself.  (`poweroff` would not: Firecracker has no ACPI power
    /// management, so the guest's own power-off has nothing to ask.  Measured 2026-10-10,
    /// Firecracker's own device table: the keyboard is what `SendCtrlAltDel` *requires*.)
    ///
    /// The number was the root disk's unlock port in an earlier plan; the unlock is served by
    /// the control share, so the service this port names is the one that exists — a port is
    /// never two services.
    pub const SHUTDOWN: u32 = 57000;
    /// Readiness: the guest's "I am up" and its own reports.
    pub const READY: u32 = 58000;
    /// **The network**: raw IP frames between the guest's own `tun0` and
    /// `dc-net`'s engine in this process.  Firecracker's own net device is a tap
    /// (and a tap is a host-side device with `CAP_NET_ADMIN`), so the run attaches
    /// none and the guest makes its own point-to-point link.
    pub const NETWORK: u32 = 59000;

    /// Every port this project defines, so a test can assert the list is a list
    /// of distinct numbers.
    pub const ALL: [u32; 8] = [
        REMOTE_X, DISPLAY, INPUT, SHARES, AUDIO, CONTROL, SHUTDOWN, NETWORK,
    ];
}

/// The unix socket Firecracker connects to when the guest dials `port`.
///
/// `uds_path` is what `PUT /vsock` was given; the port is appended with an
/// underscore, which is Firecracker's own rule.
pub fn listener_path(uds_path: &Path, port: u32) -> PathBuf {
    let mut name = uds_path.as_os_str().to_os_string();
    name.push(format!("_{port}"));
    PathBuf::from(name)
}

/// What can go wrong on the host's end of the device.
#[derive(Debug, thiserror::Error)]
pub enum VsockError {
    #[error("the vsock listener for port {port}: {source}")]
    Listen { port: u32, source: std::io::Error },
    #[error("the vsock channel for port {port}: {source}")]
    Io { port: u32, source: std::io::Error },
    #[error("the host's vsock socket: {0}")]
    Handshake(String),
    #[error("a frame is {len} bytes, more than the {max} this channel allows")]
    TooLarge { len: u32, max: u32 },
    #[error("a frame arrived in pieces and the channel gave up with {0} bytes of it")]
    Truncated(usize),
    #[error("the bytes after a frame stopped at {got} of the {wanted} it announced")]
    Incomplete { got: usize, wanted: usize },
}

pub type Result<T> = std::result::Result<T, VsockError>;

/// The largest frame this project sends.  The device's own packet buffer is
/// 64 KiB (`MAX_PKT_BUF_SIZE`), so a frame stays under it and travels as one
/// packet rather than a queue of them.
pub const MAX_FRAME: u32 = 60 * 1024;

/// How many bounded stalls [`Reader::read_bytes`] tolerates while the rest of a message is
/// arriving.  It is the socket's own timeout times this count — a slow guest is covered, a run is
/// never hung.  A service that must wait for as long as its peer is open passes `None` to
/// [`Reader::read_bytes_with`] instead.
pub const READ_STALL_LIMIT: u32 = 200;

/// One message on a vsock channel: a length, a kind, and a payload.
///
/// The kind is the service's own vocabulary (a display frame says "damage", the
/// filesystem says "LOOKUP"); this crate only carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub kind: u16,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn new(kind: u16, payload: impl Into<Vec<u8>>) -> Frame {
        Frame {
            kind,
            payload: payload.into(),
        }
    }

    /// The bytes: `[u32 len][u16 kind][payload]`, `len` counting the payload only.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(6 + self.payload.len());
        out.extend_from_slice(&(self.payload.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.kind.to_le_bytes());
        out.extend_from_slice(&self.payload);
        out
    }

    /// How many bytes [`Reader`] needs before this frame is complete.
    pub fn wire_len(payload_len: u32) -> u64 {
        u64::from(payload_len) + 6
    }
}

impl std::fmt::Write for Frame {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        self.payload.extend_from_slice(s.as_bytes());
        Ok(())
    }
}

/// Read frames from a stream that may hand them over in pieces.
///
/// There is no "read a frame" call that can be trusted on a byte stream, so this
/// keeps what it has read and answers a frame only when it has all of it — the
/// measured failure mode of the other way round being a frame that arrives as
/// 47 + 153 bytes and is parsed as two.
#[derive(Debug, Default)]
pub struct Reader {
    buf: Vec<u8>,
}

impl Reader {
    pub fn new() -> Reader {
        Reader { buf: Vec::new() }
    }

    /// Add what arrived.
    pub fn push(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
    }

    /// How much is buffered and not yet a whole frame.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// Take the next whole frame, if there is one.
    pub fn next_frame(&mut self) -> Result<Option<Frame>> {
        if self.buf.len() < 6 {
            return Ok(None);
        }
        let len = u32::from_le_bytes([self.buf[0], self.buf[1], self.buf[2], self.buf[3]]);
        if len > MAX_FRAME {
            return Err(VsockError::TooLarge {
                len,
                max: MAX_FRAME,
            });
        }
        let total = Frame::wire_len(len) as usize;
        if self.buf.len() < total {
            return Ok(None);
        }
        let kind = u16::from_le_bytes([self.buf[4], self.buf[5]]);
        let payload = self.buf[6..total].to_vec();
        self.buf.drain(..total);
        Ok(Some(Frame { kind, payload }))
    }

    /// Read from `stream` until one whole frame is there, and answer it.
    ///
    /// The read is bounded by the caller's socket timeout: a channel that stops
    /// mid-frame is a peer that ended, which is a real answer and not something
    /// to wait for forever.
    pub fn read_frame(&mut self, stream: &mut impl Read, port: u32) -> Result<Option<Frame>> {
        loop {
            if let Some(frame) = self.next_frame()? {
                return Ok(Some(frame));
            }
            let mut chunk = [0u8; 16 * 1024];
            match stream.read(&mut chunk) {
                Ok(0) => {
                    // The end of the stream is the end of the channel once
                    // nothing is left to complete a frame with.
                    return if self.buf.is_empty() {
                        Ok(None)
                    } else {
                        Err(VsockError::Truncated(self.buf.len()))
                    };
                }
                Ok(n) => self.push(&chunk[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(VsockError::Io { port, source: e }),
            }
        }
    }
}

impl Reader {
    /// Read the bytes that **follow** a frame: what a message whose payload announces more
    /// data needs — the display's damage rectangles carry their pixels straight after the
    /// frame (`dc-fc-display`), and that is one message on one stream, not two.
    ///
    /// Bytes that are already buffered are taken first, and that is not an optimisation: a
    /// read that delivered the frame and its pixels in one chunk has the pixels *here*, not on
    /// the socket, so a caller that read the stream instead would wait for bytes that have
    /// already arrived (measured 2026-10-10: the rectangle never appeared, because the pixels
    /// were in the reader's own buffer).
    ///
    /// A peer that stops mid-message is said to have stopped: the caller learns the message was
    /// cut short instead of being handed half of it as if it were whole.  The bounded stall is the
    /// socket's own timeout, retried [`READ_STALL_LIMIT`] times — enough to cover a slow guest,
    /// not enough to hang a run.
    pub fn read_bytes(
        &mut self,
        stream: &mut impl Read,
        count: usize,
        port: u32,
    ) -> Result<Vec<u8>> {
        self.read_bytes_with(stream, count, port, Some(READ_STALL_LIMIT))
    }

    /// The same read with the caller's own patience: `None` waits for the rest of the message for
    /// as long as the stream is open, and only a stream that **ends** (a read of zero bytes)
    /// answers early.
    ///
    /// That is the shape a service whose message is a frame *plus* bytes needs.  The display
    /// channel learned it the hard way (measured 2026-10-10: a late message's pixels were called a
    /// broken stream, the host closed the connection, the guest's next write answered `EPIPE`, and
    /// the screen never drew again); the audio channel is the same shape — a frame and the PCM
    /// straight after it — so it waits too, and a guest that is slow is a guest that is still
    /// talking.
    pub fn read_bytes_with(
        &mut self,
        stream: &mut impl Read,
        count: usize,
        port: u32,
        patience: Option<u32>,
    ) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(count);
        let buffered = count.min(self.buf.len());
        out.extend_from_slice(&self.buf[..buffered]);
        self.buf.drain(..buffered);

        let mut stalls = 0;
        while out.len() < count {
            let mut chunk = [0u8; 16 * 1024];
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    let want = (count - out.len()).min(n);
                    out.extend_from_slice(&chunk[..want]);
                    if want < n {
                        self.push(&chunk[want..n]);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    match patience {
                        Some(limit) => {
                            stalls += 1;
                            if stalls > limit {
                                break;
                            }
                        }
                        None => continue,
                    }
                }
                Err(e) => return Err(VsockError::Io { port, source: e }),
            }
        }
        if out.len() < count {
            return Err(VsockError::Incomplete {
                got: out.len(),
                wanted: count,
            });
        }
        Ok(out)
    }

    /// The same read again, with a word from the caller on every stall: when `live` answers
    /// `false`, the read stops and says the message was not completed.
    ///
    /// This is what a service that may be told to let go of a connection needs — a reader parked on
    /// a guest that has gone quiet would otherwise never look at the fact that its own port has a
    /// newer client.
    pub fn read_bytes_while(
        &mut self,
        stream: &mut impl Read,
        count: usize,
        port: u32,
        live: &dyn Fn() -> bool,
    ) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(count);
        let buffered = count.min(self.buf.len());
        out.extend_from_slice(&self.buf[..buffered]);
        self.buf.drain(..buffered);

        while out.len() < count {
            let mut chunk = [0u8; 16 * 1024];
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    let want = (count - out.len()).min(n);
                    out.extend_from_slice(&chunk[..want]);
                    if want < n {
                        self.push(&chunk[want..n]);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    if !live() {
                        break;
                    }
                }
                Err(e) => return Err(VsockError::Io { port, source: e }),
            }
        }
        if out.len() < count {
            return Err(VsockError::Incomplete {
                got: out.len(),
                wanted: count,
            });
        }
        Ok(out)
    }
}

/// Write one frame, in full.
pub fn write_frame(stream: &mut impl Write, frame: &Frame, port: u32) -> Result<()> {
    if frame.payload.len() as u32 > MAX_FRAME {
        return Err(VsockError::TooLarge {
            len: frame.payload.len() as u32,
            max: MAX_FRAME,
        });
    }
    stream
        .write_all(&frame.encode())
        .and_then(|()| stream.flush())
        .map_err(|source| VsockError::Io { port, source })
}

/// One port's listener on the host: the socket Firecracker connects to when the
/// guest dials `port`.
#[derive(Debug)]
pub struct Service {
    port: u32,
    listener: UnixListener,
    path: PathBuf,
}

impl Service {
    /// Listen on `<uds_path>_<port>`.
    ///
    /// A leftover socket from a run that ended badly is removed first: the path
    /// is a file, and a stale one is a bind that fails for a reason that has
    /// nothing to do with this run.
    pub fn bind(uds_path: &Path, port: u32) -> Result<Service> {
        let path = listener_path(uds_path, port);
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::remove_file(&path);
        let listener =
            UnixListener::bind(&path).map_err(|source| VsockError::Listen { port, source })?;
        Ok(Service {
            port,
            listener,
            path,
        })
    }

    /// A service over a listener the caller made (the tests' seam), with the
    /// port it stands for.
    pub fn over(listener: UnixListener, port: u32, path: impl Into<PathBuf>) -> Service {
        Service {
            port,
            listener,
            path: path.into(),
        }
    }

    pub fn port(&self) -> u32 {
        self.port
    }

    /// The socket the guest's connections to this port arrive on.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The listener itself, so a service can accept in its own thread with its
    /// own timeouts.
    pub fn listener(&self) -> &UnixListener {
        &self.listener
    }

    /// Accept the guest's next connection to this port.
    pub fn accept(&self) -> Result<UnixStream> {
        let (stream, _) = self.listener.accept().map_err(|source| VsockError::Io {
            port: self.port,
            source,
        })?;
        Ok(stream)
    }

    /// Make accepting non-blocking: a listener whose owner may want to end (a shutdown, a
    /// test) asks for this, so a thread waiting for a guest that is never coming can still
    /// notice that the run is over.  The channel's own reads are unaffected — this is the
    /// **listening** socket, not a connection.
    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<()> {
        self.listener
            .set_nonblocking(nonblocking)
            .map_err(|source| VsockError::Io {
                port: self.port,
                source,
            })
    }

    /// Stop listening and remove the socket: a run's own paths are cleaned up by
    /// the run.
    ///
    /// The listener itself is closed when this value is dropped (the `let _ =`
    /// at the end of the function's own scope), and the socket file goes with it.
    pub fn close(self) {
        let path = self.path.clone();
        drop(self);
        let _ = std::fs::remove_file(path);
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// The host's end of a channel the **host** initiates: Firecracker is asked to
/// forward it to the guest's `port`.
///
/// Firecracker answers `OK <hostside_port>\n` (or closes the connection when
/// nobody in the guest listens), and after that the channel is a byte stream.
/// This direction is not what the services use — they are guest-initiated — but
/// it is the device's own interface and a test needs it to stand in for the
/// guest's side.
pub fn connect_to_guest(uds_path: &Path, port: u32) -> Result<(UnixStream, u32)> {
    let mut stream = UnixStream::connect(uds_path)
        .map_err(|e| VsockError::Handshake(format!("{uds_path:?}: {e}")))?;
    stream
        .write_all(format!("CONNECT {port}\n").as_bytes())
        .map_err(|e| VsockError::Handshake(format!("sending CONNECT: {e}")))?;
    stream
        .flush()
        .map_err(|e| VsockError::Handshake(format!("flushing: {e}")))?;
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        match stream.read(&mut byte) {
            Ok(0) => {
                return Err(VsockError::Handshake(
                    "the peer closed the connection".into(),
                ))
            }
            Ok(_) => {
                if byte[0] == b'\n' {
                    break;
                }
                line.push(byte[0]);
                if line.len() > 64 {
                    return Err(VsockError::Handshake("the acknowledgement ran on".into()));
                }
            }
            Err(e) => return Err(VsockError::Handshake(format!("reading the answer: {e}"))),
        }
    }
    let answer = String::from_utf8_lossy(&line);
    Ok((stream, parse_ok_port(&answer)?))
}

/// Read the port out of Firecracker's `OK <port>` answer to `CONNECT`.
pub fn parse_ok_port(answer: &str) -> Result<u32> {
    let mut words = answer.split_whitespace();
    match (words.next(), words.next()) {
        (Some("OK"), Some(port)) => port
            .parse::<u32>()
            .map_err(|_| VsockError::Handshake(format!("{answer:?} is not an acknowledgement"))),
        _ => Err(VsockError::Handshake(format!(
            "{answer:?} is not an acknowledgement"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_listener_of_a_port_is_the_socket_named_after_it() {
        assert_eq!(
            listener_path(Path::new("/run/desktop-cracker/v.sock"), ports::DISPLAY),
            PathBuf::from("/run/desktop-cracker/v.sock_53000")
        );
    }

    #[test]
    fn every_port_is_a_number_of_its_own() {
        let mut all = ports::ALL.to_vec();
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), ports::ALL.len(), "a port is used twice");
        // The one that project already has keeps its number: a guest's
        // own tool looks for it.
        assert_eq!(ports::REMOTE_X, 1026);
        // The network is a service like any other: there is no tap to fall back on.
        assert_eq!(ports::NETWORK, 59000);
        assert_eq!(
            listener_path(Path::new("/r/v.sock"), ports::NETWORK),
            PathBuf::from("/r/v.sock_59000")
        );
    }

    #[test]
    fn a_frame_is_a_length_a_kind_and_the_payload() {
        let frame = Frame::new(7, b"hello".to_vec());
        assert_eq!(
            frame.encode(),
            vec![5, 0, 0, 0, 7, 0, b'h', b'e', b'l', b'l', b'o']
        );
        assert_eq!(Frame::wire_len(5), 11);
    }

    #[test]
    fn a_frame_split_across_reads_is_still_one_frame() {
        // The measured failure mode: 47 + 153 bytes of one message.
        let frame = Frame::new(1, vec![0xab; 200]);
        let wire = frame.encode();
        let mut reader = Reader::new();
        reader.push(&wire[..47]);
        assert_eq!(
            reader.next_frame().unwrap(),
            None,
            "half a frame is not a frame"
        );
        assert_eq!(reader.buffered(), 47);
        reader.push(&wire[47..]);
        assert_eq!(reader.next_frame().unwrap(), Some(frame));
        assert_eq!(reader.buffered(), 0);
    }

    #[test]
    fn two_frames_in_one_read_are_two_frames() {
        let mut reader = Reader::new();
        let mut wire = Frame::new(1, b"one".to_vec()).encode();
        wire.extend(Frame::new(2, b"two".to_vec()).encode());
        reader.push(&wire);
        assert_eq!(
            reader.next_frame().unwrap(),
            Some(Frame::new(1, b"one".to_vec()))
        );
        assert_eq!(
            reader.next_frame().unwrap(),
            Some(Frame::new(2, b"two".to_vec()))
        );
        assert_eq!(reader.next_frame().unwrap(), None);
    }

    #[test]
    fn an_empty_payload_is_a_frame_too() {
        let mut reader = Reader::new();
        reader.push(&Frame::new(9, Vec::new()).encode());
        assert_eq!(
            reader.next_frame().unwrap(),
            Some(Frame::new(9, Vec::new()))
        );
    }

    #[test]
    fn a_frame_that_claims_to_be_too_large_is_refused_rather_than_buffered() {
        let mut reader = Reader::new();
        let mut wire = (MAX_FRAME + 1).to_le_bytes().to_vec();
        wire.extend_from_slice(&0u16.to_le_bytes());
        reader.push(&wire);
        let err = reader.next_frame().unwrap_err();
        assert!(matches!(err, VsockError::TooLarge { .. }), "{err:?}");
        assert!(err.to_string().contains("more than"), "{err}");
    }

    #[test]
    fn a_channel_that_ends_mid_frame_says_so() {
        let mut reader = Reader::new();
        let wire = Frame::new(1, vec![0u8; 100]).encode();
        reader.push(&wire[..30]);
        let mut empty: &[u8] = &[];
        let err = reader.read_frame(&mut empty, ports::SHARES).unwrap_err();
        assert!(matches!(err, VsockError::Truncated(30)), "{err:?}");
    }

    #[test]
    fn a_channel_that_ends_on_a_frame_boundary_is_just_the_end() {
        let mut reader = Reader::new();
        let mut empty: &[u8] = &[];
        assert_eq!(reader.read_frame(&mut empty, ports::AUDIO).unwrap(), None);
    }

    /// A reader that answers a scripted list of results: what a peer that stalls and then finishes
    /// its message does, without a thread, a socket or a clock in the test.
    struct Scripted {
        steps: std::collections::VecDeque<std::io::Result<Vec<u8>>>,
    }

    impl Read for Scripted {
        fn read(&mut self, into: &mut [u8]) -> std::io::Result<usize> {
            match self.steps.pop_front() {
                Some(Ok(bytes)) => {
                    let take = bytes.len().min(into.len());
                    into[..take].copy_from_slice(&bytes[..take]);
                    Ok(take)
                }
                Some(Err(e)) => Err(e),
                None => Ok(0),
            }
        }
    }

    #[test]
    fn the_bytes_after_a_frame_are_waited_for_across_stalls() {
        // The audio and the display both send "a frame, then its bytes".  A peer that hands the
        // frame over and takes a moment over the rest is a peer still talking: the read waits
        // (`None` patience) and the message is answered whole.
        let mut reader = Reader::new();
        let mut scripted = Scripted {
            steps: std::collections::VecDeque::from([
                Ok(b"frame-head".to_vec()),
                Err(std::io::Error::from(std::io::ErrorKind::WouldBlock)),
                Err(std::io::Error::from(std::io::ErrorKind::WouldBlock)),
                Ok(b"and-its".to_vec()),
                Ok(b"-body".to_vec()),
            ]),
        };
        let got = reader
            .read_bytes_with(&mut scripted, 22, ports::AUDIO, None)
            .unwrap();
        assert_eq!(got, b"frame-headand-its-body".to_vec());
        assert_eq!(
            reader.buffered(),
            0,
            "the message is exactly what was announced"
        );
    }

    #[test]
    fn a_peer_that_stops_in_the_middle_of_a_message_is_said_to_have_stopped() {
        // Half a buffer is not a buffer: the caller has to know the count it announced never
        // arrived, rather than play 1 900 bytes of a 3 840-byte one.
        let mut reader = Reader::new();
        let mut scripted = Scripted {
            steps: std::collections::VecDeque::from([Ok(vec![7u8; 1_900])]),
        };
        let err = reader
            .read_bytes(&mut scripted, 3_840, ports::AUDIO)
            .unwrap_err();
        assert!(
            matches!(
                err,
                VsockError::Incomplete {
                    got: 1_900,
                    wanted: 3_840
                }
            ),
            "{err:?}"
        );
        assert!(err.to_string().contains("stopped at 1900"), "{err}");
    }

    #[test]
    fn a_stalled_read_gives_up_after_its_own_patience_and_says_the_same_thing() {
        let mut reader = Reader::new();
        let mut steps = std::collections::VecDeque::new();
        steps.push_back(Ok(vec![9u8; 10]));
        for _ in 0..(READ_STALL_LIMIT + 5) {
            steps.push_back(Err(std::io::Error::from(std::io::ErrorKind::TimedOut)));
        }
        let mut scripted = Scripted { steps };
        let err = reader
            .read_bytes(&mut scripted, 4_000, ports::AUDIO)
            .unwrap_err();
        assert!(
            matches!(
                err,
                VsockError::Incomplete {
                    got: 10,
                    wanted: 4_000
                }
            ),
            "{err:?}"
        );
    }

    #[test]
    fn bytes_the_reader_already_has_are_taken_before_the_socket_is_read() {
        // A read that delivered the frame *and* its pixels in one chunk has them here, not on the
        // socket (measured 2026-10-10: the rectangle never appeared because the caller went back
        // to a stream that had nothing left to give).
        let mut reader = Reader::new();
        reader.push(b"the-whole-body");
        reader.push(b"extra-of-the-next-message");
        let mut scripted = Scripted {
            steps: std::collections::VecDeque::from([Ok(b"never-read".to_vec())]),
        };
        let got = reader
            .read_bytes(&mut scripted, 14, ports::DISPLAY)
            .unwrap();
        assert_eq!(got, b"the-whole-body".to_vec());
        assert!(
            scripted.steps.len() == 1,
            "the socket was not touched: the bytes were already here"
        );
        // What was left over is still the reader's, for the next frame.
        assert_eq!(reader.buffered(), 25);
    }

    #[test]
    fn the_bytes_left_over_from_a_message_stay_the_readers_own() {
        // **The shape of a real channel**: one read off the socket carries the announced bytes *and*
        // the beginning of the next message (the socket's chunk is 16 KiB, a message is 3 858).  The
        // rest of the chunk is not noise and not something to read again — it is the next message,
        // and it has to stay here.  Measured 2026-10-11 on the audio channel: the tail was taken
        // from the *whole* chunk instead of from the part of it nobody had consumed, so the reader
        // kept the announced bytes **twice**, and the next frame it parsed was a piece of PCM read
        // as a length — `a frame is 131072 bytes, more than the 61440 this channel allows`, on a
        // stream whose bytes were correct on the wire.
        let mut reader = Reader::new();
        let mut next_message = Vec::new();
        next_message.extend_from_slice(&12u32.to_le_bytes());
        next_message.extend_from_slice(&2u16.to_le_bytes());
        next_message.extend_from_slice(&1u64.to_le_bytes());
        next_message.extend_from_slice(&3_840u32.to_le_bytes());
        let mut chunk = vec![7u8; 3_840];
        chunk.extend_from_slice(&next_message);
        let mut scripted = Scripted {
            steps: std::collections::VecDeque::from([Ok(chunk.clone())]),
        };
        let got = reader
            .read_bytes(&mut scripted, 3_840, ports::AUDIO)
            .unwrap();
        assert_eq!(got, chunk[..3_840].to_vec());
        assert_eq!(
            reader.buffered(),
            next_message.len(),
            "the rest of the chunk is the next message, and it is still here"
        );
        assert!(
            scripted.steps.is_empty(),
            "the socket was read exactly once: nothing was taken back off it"
        );
        let frame = reader
            .next_frame()
            .unwrap()
            .expect("the next message is here");
        assert_eq!(frame.kind, 2);
        assert_eq!(frame.payload.len(), 12);
        assert_eq!(reader.buffered(), 0, "and the stream is in step again");
    }

    #[test]
    fn the_devices_acknowledgement_is_an_ok_and_a_port() {
        assert_eq!(parse_ok_port("OK 1073741824").unwrap(), 1073741824);
        assert!(parse_ok_port("OK").is_err());
        assert!(parse_ok_port("nope 3").is_err());
        assert!(parse_ok_port("").is_err());
    }

    #[test]
    fn a_service_listens_on_its_own_port_path_and_leaves_nothing_behind() {
        let dir = tempfile::tempdir().unwrap();
        let uds = dir.path().join("v.sock");
        let service = Service::bind(&uds, ports::CONTROL).unwrap();
        assert_eq!(service.port(), ports::CONTROL);
        let path = service.path().to_path_buf();
        assert_eq!(path, listener_path(&uds, ports::CONTROL));
        assert!(
            path.exists(),
            "the socket the guest's port hangs off must exist"
        );
        // Connecting does not need an accept: the backlog holds it, which is how
        // a listener can be tested without starting a thread.
        let client = UnixStream::connect(&path).unwrap();
        drop(client);
        service.close();
        assert!(!path.exists(), "the run cleans its own sockets up");
    }

    #[test]
    fn binding_over_a_stale_socket_from_an_earlier_run_works() {
        let dir = tempfile::tempdir().unwrap();
        let uds = dir.path().join("v.sock");
        let first = Service::bind(&uds, ports::READY).unwrap();
        // A run that died without cleaning up leaves the file behind; the next
        // run must still be able to bind its own port.
        std::mem::forget(first);
        let second = Service::bind(&uds, ports::READY).unwrap();
        assert!(second.path().exists());
    }

    #[test]
    fn a_service_under_a_missing_directory_makes_it() {
        let dir = tempfile::tempdir().unwrap();
        let uds = dir
            .path()
            .join("run")
            .join("desktop-cracker")
            .join("v.sock");
        let service = Service::bind(&uds, ports::SHUTDOWN).unwrap();
        assert!(service.path().exists());
    }
}
