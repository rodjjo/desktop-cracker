//! The wire one machine's conduit speaks.
//!
//! the VMM has three fd-based ways to take this process's conduit, and this module is the small difference
//! between them:
//!
//! | the machine's netdev | the fd is | one frame is |
//! |---|---|---|
//! | `dgram` (7.2+, `-netdev dgram,local.type=fd`) | a `SOCK_DGRAM` socketpair | one datagram |
//! | `stream` (7.2+, `-netdev stream,addr.type=fd`) | a `SOCK_STREAM` socketpair | a 4-byte big-endian length, then the frame |
//! | `socket` (any the VMM, `-netdev socket,id=net0,fd=N`) | a connected `SOCK_STREAM` socket | the same length framing |
//!
//! The last row is the **legacy** spelling, and it is why this module exists: a distribution the VMM such
//! as Ubuntu 22.04's 6.2 has neither `dgram` nor `stream`, but its `-netdev socket,fd=N` is the very
//! same wire as `stream` — the VMM 6.2's `net_socket_receive` prepends `htonl(size)` and its reader
//! consumes the same header (`net/socket.c`). Supporting it costs this one framing implementation and
//! makes the machines' network work on a stock LTS host.
//!
//! Both ends of the conduit are this process's: [`Conduit`] is our end (read on the reader thread,
//! written by the relay), and [`GuestConduit`] is the machine's end — kept only until the process that
//! inherits it has it, and by the tests and live probes that play the guest. Nothing here panics on a
//! hostile or truncated stream: a bad length is an error, which the reader turns into a closed
//! conduit, not a panic.

use std::fs::File;
use std::io::{Error, ErrorKind, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::{UnixDatagram, UnixStream};
use std::sync::Mutex;
use std::time::Duration;

use crate::frame::MAX_FRAME;

/// How many bytes the machine's stream wire puts before each frame.
const LENGTH_PREFIX: usize = 4;

/// Which wire the VMM was given for a machine's conduit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    /// `-netdev dgram`: one datagram is one Ethernet frame, in both directions.
    Datagram,
    /// `-netdev stream` / `-netdev socket,id=…,fd=…`: a connected stream with a 4-byte big-endian
    /// length before each frame, in both directions.
    Stream,
    /// A **tap**: one frame per `read`/`write` on a character device, exactly like a datagram, and the
    /// wire a *command's* namespace uses when it joins the machines' network.
    Tap,
}

impl Framing {
    /// The word for a log line or a status.
    pub fn as_str(self) -> &'static str {
        match self {
            Framing::Datagram => "dgram",
            Framing::Stream => "stream",
            Framing::Tap => "tap",
        }
    }
}

/// This process's end of one machine's conduit.
pub struct Conduit {
    inner: Inner,
}

enum Inner {
    /// A datagram socketpair: the kernel keeps the frame boundaries.
    Datagram(UnixDatagram),
    /// A stream socketpair: the frame boundaries are ours to write and to find again. The writer is
    /// behind a lock because the relay writes from several flow threads, and two interleaved frames
    /// would be a stream neither end could parse.
    Stream {
        reader: UnixStream,
        writer: Mutex<UnixStream>,
    },
    /// A tap device: one frame per read and per write, no framing of its own. The `File` owns the
    /// descriptor, so dropping the conduit closes the tap (which is what ends a command's network).
    Tap(File),
}

impl Conduit {
    /// Our end of a **datagram** conduit (`-netdev dgram`).
    pub fn datagram(socket: UnixDatagram) -> Conduit {
        Conduit {
            inner: Inner::Datagram(socket),
        }
    }

    /// Our end of a **stream** conduit (`-netdev stream`, `-netdev socket,fd=`): the socket is cloned
    /// so the reader thread and the relay's writers hold the same connection independently.
    pub fn stream(socket: UnixStream) -> std::io::Result<Conduit> {
        let writer = socket.try_clone()?;
        Ok(Conduit {
            inner: Inner::Stream {
                reader: socket,
                writer: Mutex::new(writer),
            },
        })
    }

    /// Our end of a **tap** (`/dev/net/tun`, created inside a command's network namespace): one frame
    /// per read and per write, and the descriptor is owned from here — a closed tap is a command that
    /// has stopped.
    pub fn tap(file: File) -> Conduit {
        Conduit {
            inner: Inner::Tap(file),
        }
    }

    /// Which wire this conduit speaks.
    pub fn framing(&self) -> Framing {
        match self.inner {
            Inner::Datagram(_) => Framing::Datagram,
            Inner::Stream { .. } => Framing::Stream,
            Inner::Tap(_) => Framing::Tap,
        }
    }

    /// Write one frame.
    pub fn send(&self, frame: &[u8]) -> std::io::Result<()> {
        match &self.inner {
            Inner::Datagram(socket) => socket.send(frame).map(|_| ()),
            Inner::Stream { writer, .. } => {
                let mut writer = writer
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                writer.write_all(&(frame.len() as u32).to_be_bytes())?;
                writer.write_all(frame)
            }
            // A frame that is too long for the device is refused here rather than truncated: the relay
            // never builds one (the conduit's MTU is what it frames to), and a silent truncation would
            // be a guest reading half a frame.
            Inner::Tap(file) => (&*file).write_all(frame),
        }
    }

    /// Read one whole frame into `buffer`, returning its length. `Ok(0)` means the conduit is closed;
    /// a `WouldBlock`/`TimedOut` error means nothing arrived within the read timeout, and the reader
    /// thread keeps waiting.
    pub fn recv(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
        match &self.inner {
            Inner::Datagram(socket) => socket.recv(buffer),
            Inner::Stream { reader, .. } => {
                let mut reader = reader;
                read_frame(&mut reader, buffer)
            }
            Inner::Tap(file) => (&*file).read(buffer),
        }
    }

    /// Set (or clear) the read timeout, which is only ever done by a test that would otherwise block.
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        match &self.inner {
            Inner::Datagram(socket) => socket.set_read_timeout(timeout),
            Inner::Stream { reader, .. } => reader.set_read_timeout(timeout),
            // A tap has no read timeout: the reader thread blocks in `read` until a frame arrives or
            // the tap goes away (which is the command exiting).
            Inner::Tap(_) => Ok(()),
        }
    }

    /// Close the conduit from our side: the reader thread's `recv` returns `Ok(0)` and the machine's
    /// network ends.
    pub fn shutdown(&self) -> std::io::Result<()> {
        match &self.inner {
            Inner::Datagram(socket) => socket.shutdown(std::net::Shutdown::Both),
            Inner::Stream { reader, .. } => reader.shutdown(std::net::Shutdown::Both),
            // A tap has no shutdown: closing the file it lives in is what ends it, and the reader
            // thread sees that as an error rather than a zero-length frame.
            Inner::Tap(_) => Ok(()),
        }
    }
}

impl AsRawFd for Conduit {
    fn as_raw_fd(&self) -> RawFd {
        match &self.inner {
            Inner::Datagram(socket) => socket.as_raw_fd(),
            Inner::Stream { reader, .. } => reader.as_raw_fd(),
            Inner::Tap(file) => file.as_raw_fd(),
        }
    }
}

/// The **guest's** end of a conduit: the descriptor the VMM inherits, and what a test or a live probe
/// plays the guest with. It is dropped as soon as the VMM has the descriptor, so the machine's network
/// cannot outlive the process that owns it.
pub enum GuestConduit {
    /// The other end of a `-netdev dgram` conduit.
    Datagram(UnixDatagram),
    /// The other end of a `-netdev stream` / `-netdev socket,fd=` conduit.
    Stream(UnixStream),
}

impl GuestConduit {
    /// Write one frame as the guest's NIC would, in whichever wire this end speaks.
    pub fn send(&self, frame: &[u8]) -> std::io::Result<()> {
        match self {
            GuestConduit::Datagram(socket) => socket.send(frame).map(|_| ()),
            GuestConduit::Stream(socket) => {
                let mut socket = socket;
                socket.write_all(&(frame.len() as u32).to_be_bytes())?;
                socket.write_all(frame)
            }
        }
    }

    /// Read one frame, for the tests and the live probe. `Ok(0)` is a closed conduit.
    pub fn recv(&self, buffer: &mut [u8]) -> std::io::Result<usize> {
        match self {
            GuestConduit::Datagram(socket) => socket.recv(buffer),
            GuestConduit::Stream(socket) => {
                let mut socket = socket;
                read_frame(&mut socket, buffer)
            }
        }
    }

    /// Set (or clear) the read timeout, so a test's "hears nothing" is a wait rather than a hang.
    pub fn set_read_timeout(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        match self {
            GuestConduit::Datagram(socket) => socket.set_read_timeout(timeout),
            GuestConduit::Stream(socket) => socket.set_read_timeout(timeout),
        }
    }
}

impl AsRawFd for GuestConduit {
    fn as_raw_fd(&self) -> RawFd {
        match self {
            GuestConduit::Datagram(socket) => socket.as_raw_fd(),
            GuestConduit::Stream(socket) => socket.as_raw_fd(),
        }
    }
}

/// Read the machine's stream framing: a four-byte big-endian length, then that many bytes.
///
/// The first byte is read on its own so a **closed** conduit is `Ok(0)` rather than an error, which is
/// what the reader thread needs to end cleanly; a length that cannot be an Ethernet frame is an error
/// (the conduit is speaking something else), and a stream that ends in the middle of a frame is an
/// error too.
fn read_frame<R: Read>(reader: &mut R, buffer: &mut [u8]) -> std::io::Result<usize> {
    let mut header = [0u8; LENGTH_PREFIX];
    if reader.read(&mut header[..1])? == 0 {
        return Ok(0);
    }
    reader.read_exact(&mut header[1..])?;
    let length = u32::from_be_bytes(header) as usize;
    if length == 0 || length > MAX_FRAME {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!("a stream conduit sent a {length}-byte frame, which is not an Ethernet frame"),
        ));
    }
    if length > buffer.len() {
        return Err(Error::new(
            ErrorKind::InvalidData,
            format!(
                "a stream conduit sent a {length}-byte frame into a {}-byte buffer",
                buffer.len()
            ),
        ));
    }
    reader.read_exact(&mut buffer[..length])?;
    Ok(length)
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn frame(byte: u8, length: usize) -> Vec<u8> {
        vec![byte; length]
    }

    #[test]
    fn a_datagram_conduit_keeps_the_frame_boundaries() {
        let (ours, guest) = UnixDatagram::pair().expect("a socketpair");
        let conduit = Conduit::datagram(ours);
        let guest = GuestConduit::Datagram(guest);
        assert_eq!(conduit.framing(), Framing::Datagram);
        conduit
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("a timeout");
        guest
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("a timeout");

        // Two frames written back to back arrive as two frames, in order.
        guest.send(&frame(1, 60)).expect("the guest writes");
        guest.send(&frame(2, 90)).expect("the guest writes");
        let mut buffer = [0u8; MAX_FRAME];
        assert_eq!(conduit.recv(&mut buffer).expect("a frame"), 60);
        assert_eq!(buffer[0], 1);
        assert_eq!(conduit.recv(&mut buffer).expect("a frame"), 90);
        assert_eq!(buffer[0], 2);

        conduit.send(&frame(3, 40)).expect("we write");
        let read = guest.recv(&mut buffer).expect("the guest reads");
        assert_eq!(read, 40);
        assert_eq!(buffer[0], 3);
    }

    #[test]
    fn a_stream_conduit_prefixes_every_frame_with_its_length() {
        let (ours, guest) = UnixStream::pair().expect("a socketpair");
        let conduit = Conduit::stream(ours).expect("our end");
        let guest = GuestConduit::Stream(guest);
        assert_eq!(conduit.framing(), Framing::Stream);

        guest.send(&frame(7, 100)).expect("the guest writes");
        guest.send(&frame(8, 20)).expect("the guest writes");
        let mut buffer = [0u8; MAX_FRAME];
        assert_eq!(conduit.recv(&mut buffer).expect("a frame"), 100);
        assert_eq!(buffer[..100], frame(7, 100)[..]);
        assert_eq!(conduit.recv(&mut buffer).expect("a frame"), 20);
        assert_eq!(buffer[..20], frame(8, 20)[..]);

        conduit
            .send(&frame(9, 1514))
            .expect("we write the largest frame");
        let read = guest.recv(&mut buffer).expect("the guest reads");
        assert_eq!(read, 1514);
        assert!(buffer[..read].iter().all(|byte| *byte == 9));
    }

    #[test]
    fn a_stream_conduit_reads_a_frame_that_arrives_in_pieces() {
        // the VMM writes a frame with one `writev`, but a stream is allowed to deliver it in pieces: the
        // framing has to put it back together, header and body alike.
        let (ours, guest) = UnixStream::pair().expect("a socketpair");
        let conduit = Conduit::stream(ours).expect("our end");
        let payload = frame(0x5a, 300);
        let written = payload.clone();
        let writer = std::thread::spawn(move || {
            let mut guest = guest;
            for piece in [
                &[0u8, 0, 1][..],
                &[44],
                &written[..100],
                &written[100..257],
                &written[257..],
            ] {
                guest.write_all(piece).expect("a piece of the frame");
                std::thread::sleep(Duration::from_millis(5));
            }
        });
        let mut buffer = [0u8; MAX_FRAME];
        let read = conduit
            .recv(&mut buffer)
            .expect("the frame is put back together");
        assert_eq!(read, 300);
        assert_eq!(buffer[..read], payload[..]);
        writer.join().expect("the writer finishes");
    }

    #[test]
    fn a_stream_conduit_refuses_a_length_that_is_not_a_frame() {
        let (ours, mut guest) = UnixStream::pair().expect("a socketpair");
        let conduit = Conduit::stream(ours).expect("our end");
        let mut buffer = [0u8; MAX_FRAME];

        // A zero length, and a length past any Ethernet frame: both are the peer speaking something
        // that is not this wire, and both are an error rather than a panic or a silent truncation.
        guest.write_all(&0u32.to_be_bytes()).expect("a header");
        assert_eq!(
            conduit
                .recv(&mut buffer)
                .expect_err("a zero length is refused")
                .kind(),
            ErrorKind::InvalidData
        );
        guest
            .write_all(&(MAX_FRAME as u32 + 1).to_be_bytes())
            .expect("a header");
        assert_eq!(
            conduit
                .recv(&mut buffer)
                .expect_err("an oversized frame is refused")
                .kind(),
            ErrorKind::InvalidData
        );
    }

    #[test]
    fn a_closed_conduit_reads_as_zero_and_a_shutdown_wakes_the_reader() {
        let (ours, guest) = UnixStream::pair().expect("a socketpair");
        let conduit = Conduit::stream(ours).expect("our end");
        drop(guest);
        let mut buffer = [0u8; MAX_FRAME];
        assert_eq!(
            conduit.recv(&mut buffer).expect("a closed conduit"),
            0,
            "the guest's end is gone"
        );

        // And our own shutdown is what ends a reader blocked on a live conduit.
        let (ours, _guest) = UnixStream::pair().expect("a socketpair");
        let conduit = Arc::new(Conduit::stream(ours).expect("our end"));
        let reader = Arc::clone(&conduit);
        let thread = std::thread::spawn(move || {
            let mut buffer = [0u8; MAX_FRAME];
            reader.recv(&mut buffer)
        });
        std::thread::sleep(Duration::from_millis(20));
        conduit.shutdown().expect("the shutdown");
        assert_eq!(
            thread
                .join()
                .expect("the reader finishes")
                .expect("a clean end"),
            0
        );
    }
}
