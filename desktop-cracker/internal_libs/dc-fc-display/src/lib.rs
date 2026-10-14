//! **The display, as a service**: the guest's screen, over vsock.
//!
//! Firecracker has no display device.  What the guest has instead is this project's own
//! framebuffer (`guest-kernel/desk_fb.c`): a real `/dev/fb0` of guest memory that Xorg's
//! own `xf86-video-fbdev` draws into, with a control node the guest's agent maps.  The agent
//! therefore **has the pixels in its own address space**, and this service's job is to hear
//! about the ones that changed and to say what should happen to the screen (how big it is, the
//! pointer, whether it is blanked) — plus the way back for the keyboard and the mouse.
//!
//! One connection, both directions: a service that must
//! push has the guest open the channel and keep it open, so the host never needs the
//! `CONNECT <PORT>` handshake and the guest's firewall has nothing to allow.
//!
//! * **pixels** (53000, guest → host): the agent dials, says what the screen is
//!   ([`KIND_SURFACE`]), then reports **damage** — the rectangle that changed, then its bytes,
//!   raw, in the framebuffer's own format.  A frame is only ever the part of the screen that
//!   moved, and a static desktop sends nothing at all;
//! * **input** (host → guest, same connection): keys, the pointer and its shape become frames
//!   on the connection the guest opened.
//!
//! A damage rectangle travels as **two** things on the wire: a frame whose payload is the
//! rectangle, and then the pixels themselves.  That is not a departure from the project's
//! framing — a frame is a length, a kind and a payload, and this message's payload *is*
//! followed by its pixels, which is how a stream carries a rectangle without a second copy.
//!
//! Why the pixels are copied rather than mapped: a `virtio-pmem` region would let both sides
//! map the same memory, and it is worth its cost only if the measured
//! rate of this channel cannot carry a full-screen video.  So the channel is built **to be
//! measured** — [`Counters`] is the answer — and it speaks the same rectangle-and-pixels
//! vocabulary `dc-display`'s frame path uses, so that fallback would change where the bytes
//! come from and nothing above it.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use dc_vsock::{Frame, Service};

pub mod stream;

/// The vsock port the display channel is served on (`dc_vsock::ports::DISPLAY`), kept here so the
/// guest's own crate can name it without depending on the host's transport crate.
pub const PORT_DISPLAY: u32 = 53000;

/// What the guest's screen is: sent once, as soon as the agent has the framebuffer.
pub const KIND_SURFACE: u16 = 1;
/// Damage: `[u32 x][u32 y][u32 width][u32 height]`, then the rectangle's pixels.
pub const KIND_DAMAGE: u16 = 2;
/// A key: `[u32 code][u8 down]` — the guest's own key code, which is what `uinput` takes.
pub const KIND_KEY: u16 = 3;
/// The pointer: `[u32 x][u32 y][u32 buttons]`.
///
/// `buttons` is the **state** the guest's pointer device is being asked to match (bit 0 left, bit 1
/// middle, bit 2 right), not "this event's button": a move during a drag carries the button that is
/// down, and a release carries the buttons that remain down.
pub const KIND_MOUSE: u16 = 4;
/// The pointer's shape: `[u32 x][u32 y][u8 visible]`.
pub const KIND_CURSOR: u16 = 5;
/// The host's display state: `[u8 awake]`.
pub const KIND_POWER: u16 = 6;
/// The wheel: `[i32 steps][i32 hsteps][u32 buttons]` — a **step** on a relative axis (up and right
/// are positive), with the buttons held while it turned.  It is not a button, and it is not a
/// position: the guest's pointer device answers it with `REL_WHEEL`/`REL_HWHEEL`.
pub const KIND_WHEEL: u16 = 8;
/// The host asks for the whole screen: what a window that has just appeared needs.
pub const KIND_REFRESH: u16 = 100;
/// The host says the guest's screen is another size: `[u32 width][u32 height][u32 format]`.
pub const KIND_RESIZE: u16 = 101;
/// The guest reports its own progress: `[u32 len][text]` — what the run's own landing is.
pub const KIND_REPORT: u16 = 7;

/// What the screen is, as the guest reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Surface {
    pub width: u32,
    pub height: u32,
    /// The pixel format, in the `pixman` numbering `dc-display::Geometry` already uses
    /// (`PIXMAN_x8r8g8b8` is `0x2000_0000`), so nothing is translated between the two.
    pub format: u32,
}

impl Surface {
    /// Four bytes per pixel: the framebuffer's own format (`desk_fb.c`'s `XRGB8888`).
    pub fn bytes_per_pixel(&self) -> u32 {
        4
    }

    pub fn stride(&self) -> u32 {
        self.width * self.bytes_per_pixel()
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(12);
        out.extend_from_slice(&self.width.to_le_bytes());
        out.extend_from_slice(&self.height.to_le_bytes());
        out.extend_from_slice(&self.format.to_le_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Surface> {
        if bytes.len() < 12 {
            return None;
        }
        let at = |i: usize| u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap());
        Some(Surface {
            width: at(0),
            height: at(4),
            format: at(8),
        })
    }
}

/// A rectangle of the screen that changed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Rect {
    pub x: u32,
    pub y: u32,
    pub width: u32,
    pub height: u32,
}

impl Rect {
    pub fn is_empty(&self) -> bool {
        self.width == 0 || self.height == 0
    }

    pub fn area(&self) -> u64 {
        self.width as u64 * self.height as u64
    }

    /// The bytes this rectangle's pixels take on the wire.
    pub fn bytes(&self) -> usize {
        self.area() as usize * 4
    }

    pub fn encode(&self) -> [u8; 16] {
        let mut out = [0u8; 16];
        out[0..4].copy_from_slice(&self.x.to_le_bytes());
        out[4..8].copy_from_slice(&self.y.to_le_bytes());
        out[8..12].copy_from_slice(&self.width.to_le_bytes());
        out[12..16].copy_from_slice(&self.height.to_le_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Option<Rect> {
        if bytes.len() < 16 {
            return None;
        }
        let at = |i: usize| u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap());
        Some(Rect {
            x: at(0),
            y: at(4),
            width: at(8),
            height: at(12),
        })
    }

    /// Grown to hold another rectangle: what the agent does with the rows a comparison found,
    /// so a screen that changed in two places costs one message and not two.
    pub fn union(&self, other: Rect) -> Rect {
        if self.is_empty() {
            return other;
        }
        if other.is_empty() {
            return *self;
        }
        let x = self.x.min(other.x);
        let y = self.y.min(other.y);
        let right = (self.x + self.width).max(other.x + other.width);
        let bottom = (self.y + self.height).max(other.y + other.height);
        Rect {
            x,
            y,
            width: right - x,
            height: bottom - y,
        }
    }
}

/// What the service has done: the numbers a milestone line reads — and the numbers the
/// `virtio-pmem` question is answered with: does this channel carry a full screen?
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counters {
    /// Damage messages the guest sent.
    pub rectangles: u64,
    /// Bytes of pixels received.
    pub bytes: u64,
    /// The largest rectangle, in pixels — a full screen is `width × height`.
    pub largest: u64,
    /// Whole frames asked for.
    pub refreshes: u64,
    /// Keys and pointer moves sent to the guest.
    pub inputs: u64,
    /// Pointer shapes sent.
    pub cursors: u64,
    /// **How often the stream had to be re-synchronised**: bytes that could not begin a message
    /// were skipped (a message lost by the transport, or pixel data that looked like a header and
    /// failed its checksum).  One lost message costs one message; the channel keeps working.
    pub resyncs: u64,
    /// Bytes held back because they do not make a whole message yet: a message arriving in pieces
    /// is ordinary on this transport, and this is how a run can see that it is happening.
    pub buffered: u64,
    /// Messages that never arrived, counted from the guest's own numbering (`crate::stream`).
    pub lost: u64,
}

/// A damage rectangle with its pixels, as the window's side wants it: exactly the shape
/// `dc-display`'s frame path takes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Damage {
    pub rect: Rect,
    pub pixels: Vec<u8>,
    /// The guest's own message number for the message this rectangle came in (`crate::stream`).
    /// A **gap** means a whole message was lost on the way — worth counting, and never a reason to
    /// stop reading: the next message is still framed correctly, and the guest's next pass draws
    /// what the lost one would have.  Zero for the older guest, which did not number them.
    pub generation: u32,
}

#[derive(Default)]
struct State {
    surface: Option<Surface>,
    counters: Counters,
}

/// **The display service.**  One listener, one guest connection, and a mailbox the window's
/// side drains — the same shape as `dc-display`'s frame path, so the code above it does not
/// change.
pub struct DisplayService {
    service: Service,
    state: Arc<Mutex<State>>,
    inbox: Arc<Mutex<Vec<Damage>>>,
    connected: Arc<AtomicBool>,
    generation: Arc<AtomicU64>,
    outbox: Arc<Mutex<Vec<Frame>>>,
}

impl DisplayService {
    pub fn listen(
        uds_path: &std::path::Path,
    ) -> std::result::Result<DisplayService, dc_vsock::VsockError> {
        Ok(DisplayService {
            service: Service::bind(uds_path, dc_vsock::ports::DISPLAY)?,
            state: Arc::new(Mutex::new(State::default())),
            inbox: Arc::new(Mutex::new(Vec::new())),
            connected: Arc::new(AtomicBool::new(false)),
            generation: Arc::new(AtomicU64::new(0)),
            outbox: Arc::new(Mutex::new(Vec::new())),
        })
    }

    pub fn port(&self) -> u32 {
        self.service.port()
    }

    /// Accept the guest's connection without serving it.
    ///
    /// A caller that serves in its own way — a tool holding the channel, a test standing in for
    /// the guest — takes the socket here and hands it to [`Self::serve_stream`].
    pub fn accept(
        &self,
    ) -> std::result::Result<std::os::unix::net::UnixStream, dc_vsock::VsockError> {
        self.service.accept()
    }

    /// What the guest said its screen is, once it has said it.
    pub fn surface(&self) -> Option<Surface> {
        self.state.lock().ok()?.surface
    }

    /// The screen's own area in pixels, or `0` before the guest has said what it is.
    fn screen_pixels(&self) -> u64 {
        self.state
            .lock()
            .ok()
            .and_then(|s| s.surface)
            .map(|s| s.width as u64 * s.height as u64)
            .unwrap_or(0)
    }

    pub fn counters(&self) -> Counters {
        self.state
            .lock()
            .map(|state| state.counters)
            .unwrap_or_default()
    }

    /// Whether the guest is on the channel: "no agent yet" and "an agent that went quiet" are
    /// different things, and only this tells them apart.
    pub fn connected(&self) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    /// What the guest drew since this was last called.  Taking it **empties** the mailbox: a
    /// rectangle is delivered once, which is what "damage" means.
    pub fn take_damage(&self) -> Vec<Damage> {
        match self.inbox.lock() {
            Ok(mut inbox) => std::mem::take(&mut *inbox),
            Err(_) => Vec::new(),
        }
    }

    /// Bumped on every rectangle, so a waiter can sleep until there is something.
    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Relaxed)
    }

    /// Ask the guest for the whole screen: a window that has just appeared has seen nothing,
    /// and a screen it has not seen is a screen it has to draw.
    pub fn refresh(&self) {
        self.queue(Frame::new(KIND_REFRESH, Vec::new()));
        self.counted(|counters| counters.refreshes += 1);
    }

    /// A key for the guest, in its own code (the number `uinput` takes).
    pub fn key(&self, code: u32, down: bool) {
        let mut payload = code.to_le_bytes().to_vec();
        payload.push(if down { 1 } else { 0 });
        self.queue(Frame::new(KIND_KEY, payload));
        self.counted(|counters| counters.inputs += 1);
    }

    /// Where the pointer is, and which buttons are held.
    ///
    /// `buttons` is the state the guest's pointer device is asked to match, so a move during a drag
    /// keeps the drag and a release keeps the buttons that are still down.
    pub fn mouse(&self, x: u32, y: u32, buttons: u32) {
        let mut payload = x.to_le_bytes().to_vec();
        payload.extend_from_slice(&y.to_le_bytes());
        payload.extend_from_slice(&buttons.to_le_bytes());
        self.queue(Frame::new(KIND_MOUSE, payload));
        self.counted(|counters| counters.inputs += 1);
    }

    /// The wheel: a **step** on a relative axis (up and right are positive), with the buttons held
    /// while it turned.  A step of zero on both axes is not sent: the guest would have to invent a
    /// meaning for it.
    pub fn wheel(&self, steps: i32, hsteps: i32, buttons: u32) {
        if steps == 0 && hsteps == 0 {
            return;
        }
        let mut payload = steps.to_le_bytes().to_vec();
        payload.extend_from_slice(&hsteps.to_le_bytes());
        payload.extend_from_slice(&buttons.to_le_bytes());
        self.queue(Frame::new(KIND_WHEEL, payload));
        self.counted(|counters| counters.inputs += 1);
    }

    /// The pointer's shape: where it is and whether it is shown (`dc-display`'s `CursorDefine`,
    /// in miniature — the window composites it exactly as it does today).
    pub fn cursor(&self, x: u32, y: u32, visible: bool) {
        let mut payload = x.to_le_bytes().to_vec();
        payload.extend_from_slice(&y.to_le_bytes());
        payload.push(if visible { 1 } else { 0 });
        self.queue(Frame::new(KIND_CURSOR, payload));
        self.counted(|counters| counters.cursors += 1);
    }

    /// The host's own display state (a blanked screen), so the guest can stop drawing.
    pub fn power(&self, awake: bool) {
        self.queue(Frame::new(KIND_POWER, vec![if awake { 1 } else { 0 }]));
    }

    /// Tell the guest its screen is another size.
    pub fn resize(&self, surface: Surface) {
        self.queue(Frame::new(KIND_RESIZE, surface.encode()));
    }

    /// Put a frame in the outbox: the serving thread writes it, so nothing here blocks on a
    /// guest that is not reading.
    fn queue(&self, frame: Frame) {
        if let Ok(mut outbox) = self.outbox.lock() {
            outbox.push(frame);
        }
    }

    fn counted(&self, f: impl FnOnce(&mut Counters)) {
        if let Ok(mut state) = self.state.lock() {
            f(&mut state.counters);
        }
    }

    /// Serve the guest's connection until it ends.
    ///
    /// The read has a **timeout**, and that is the whole trick of one connection carrying both
    /// directions: a guest with a static screen sends nothing, so a blocking read would hold
    /// the keyboard until the guest decided to draw.  A timeout means the outbox is checked
    /// even when the screen is still — the input goes out within one read's worth of time, and a
    /// screen that is drawing is what the read returns.
    ///
    /// **A timeout is not a deadline for a message.**  The bytes of one message may arrive over
    /// several reads (the transport is a third process with its own buffers), so what the read
    /// returns is *added to the parser* and the parser answers only whole messages; a partial one
    /// is held until the rest arrives.  Nothing here ever decides that a message will not finish.
    pub fn serve(&self) -> std::result::Result<(), dc_vsock::VsockError> {
        let stream = self.service.accept()?;
        self.serve_stream(stream)
    }

    /// Serve a connection the caller already accepted, with the same rules as [`Self::serve`].
    ///
    /// It is the same loop with the `accept` taken out, so a caller that owns the socket — a test
    /// standing in for the guest, a tool holding the channel — serves exactly what a run serves.
    pub fn serve_stream(
        &self,
        mut stream: std::os::unix::net::UnixStream,
    ) -> std::result::Result<(), dc_vsock::VsockError> {
        let port = self.service.port();
        // The read timeout is a **pacer**: it is how often the outbox is checked while the guest's
        // screen is still.  50 ms of latency on an idle screen is imperceptible, and a shorter one
        // would wake the loop 200 times a second for nothing.
        let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(50)));
        self.connected.store(true, Ordering::Relaxed);
        let result = self.serve_connected(&mut stream, port);
        self.connected.store(false, Ordering::Relaxed);
        result
    }

    fn serve_connected(
        &self,
        stream: &mut std::os::unix::net::UnixStream,
        port: u32,
    ) -> std::result::Result<(), dc_vsock::VsockError> {
        let mut parser = crate::stream::StreamParser::new();
        let mut chunk = vec![0u8; 64 * 1024];
        loop {
            // 1. Whatever the window asked for goes out first.
            let pending: Vec<Frame> = match self.outbox.lock() {
                Ok(mut outbox) => std::mem::take(&mut *outbox),
                Err(_) => Vec::new(),
            };
            for frame in pending {
                if dc_vsock::write_frame(stream, &frame, port).is_err() {
                    // The guest is gone: its own loop ends and the next run's guest re-connects.
                    return Ok(());
                }
            }

            // 2. Then everything the guest has said, whole messages at a time.  `by_ref`, because
            // the parser is read once more after the loop (its resync/buffered/lost counters).
            for message in parser.by_ref() {
                self.received(message);
            }
            self.counted(|counters| {
                counters.resyncs = parser.resyncs();
                counters.buffered = parser.buffered() as u64;
                counters.lost = parser.lost();
            });

            // 3. And more bytes, waiting for them if the screen is still.
            match std::io::Read::read(stream, &mut chunk) {
                Ok(0) => return Ok(()),
                Ok(n) => parser.push(&chunk[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    continue;
                }
                Err(e) => return Err(dc_vsock::VsockError::Io { port, source: e }),
            }
        }
    }

    /// One whole message off the channel.
    fn received(&self, message: crate::stream::Message) {
        use crate::stream::Message;
        match message {
            Message::Frame { kind, payload } => {
                if kind == KIND_SURFACE {
                    if let Some(surface) = Surface::decode(&payload) {
                        if let Ok(mut state) = self.state.lock() {
                            state.surface = Some(surface);
                        }
                    }
                }
            }
            Message::Damage {
                generation,
                rects,
                pixels,
            } => {
                // One message may carry several rectangles; their pixels are one after another,
                // in the order the message lists them (`crate::stream`).
                let mut at = 0usize;
                for rect in rects {
                    let bytes = rect.bytes();
                    if at + bytes > pixels.len() {
                        break;
                    }
                    let slice = pixels[at..at + bytes].to_vec();
                    at += bytes;
                    self.deliver(rect, slice, generation);
                }
            }
        }
    }

    /// One rectangle with its pixels, into the mailbox the window draws from.
    fn deliver(&self, rect: Rect, pixels: Vec<u8>, generation: u32) {
        let screen = self.screen_pixels();
        let whole = rect.x == 0 && rect.y == 0 && rect.area() >= screen;
        let read = pixels.len();
        if let Ok(mut inbox) = self.inbox.lock() {
            // **A whole screen replaces what is waiting; a rectangle joins it.**  A queue of whole
            // screens is a queue of pictures nobody will ever see, and the newest is the only one
            // worth keeping (the guest is already drawing the next one).
            if whole {
                inbox.retain(|d| d.rect.x != 0 || d.rect.y != 0 || d.rect.area() < screen);
            }
            inbox.push(Damage {
                rect,
                pixels,
                generation,
            });
        }
        self.counted(|counters| {
            counters.rectangles += 1;
            counters.bytes += read as u64;
            counters.largest = counters.largest.max(rect.area());
        });
        self.generation.fetch_add(1, Ordering::Relaxed);
    }
}

/// A **guest** that wants to speak this channel: the messages it sends, built in one place so
/// the agent (C) and the tests (Rust) cannot drift from each other.
pub mod guest {
    use super::*;

    /// What the screen is.
    pub fn surface(surface: Surface) -> Frame {
        Frame::new(KIND_SURFACE, surface.encode())
    }

    /// A rectangle and its pixels, as **one** byte string: the frame, then the pixels.  A
    /// guest that has the mapping writes both in one `writev`, which is what keeps a frame one
    /// round trip.
    pub fn damage(rect: Rect, pixels: &[u8]) -> Vec<u8> {
        let mut out = Frame::new(KIND_DAMAGE, rect.encode().to_vec()).encode();
        out.extend_from_slice(pixels);
        out
    }

    /// The agent's own progress, for the run's landing.
    pub fn report(text: &str) -> Frame {
        Frame::new(KIND_REPORT, text.as_bytes().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dc_vsock::Reader;
    use std::io::Write;
    use std::os::unix::net::UnixStream;

    fn service() -> (Arc<DisplayService>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let service = Arc::new(DisplayService::listen(&dir.path().join("v.sock")).unwrap());
        (service, dir)
    }

    const XRGB: u32 = 0x2000_0000;

    #[test]
    fn a_surface_is_what_the_guest_says_and_its_stride_follows_from_it() {
        let surface = Surface {
            width: 1280,
            height: 800,
            format: XRGB,
        };
        assert_eq!(surface.stride(), 1280 * 4);
        assert_eq!(Surface::decode(&surface.encode()), Some(surface));
        assert_eq!(Surface::decode(&[0u8; 4]), None);
    }

    #[test]
    fn two_rectangles_are_one_when_they_are_grown_together() {
        let a = Rect {
            x: 0,
            y: 0,
            width: 10,
            height: 10,
        };
        let b = Rect {
            x: 5,
            y: 20,
            width: 10,
            height: 4,
        };
        let both = a.union(b);
        assert_eq!(both.x, 0);
        assert_eq!(both.y, 0);
        assert_eq!(both.width, 15);
        assert_eq!(both.height, 24);
        assert_eq!(
            a.union(Rect::default()),
            a,
            "an empty rectangle is not a rectangle"
        );
        assert_eq!(Rect::default().union(a), a);
        assert_eq!(a.area(), 100);
        assert_eq!(a.bytes(), 400);
    }

    #[test]
    fn what_the_host_sends_waits_in_the_outbox_until_the_guest_reads_it() {
        let (service, _dir) = service();
        service.key(30, true); // `a`, in uinput's own numbering
        service.key(30, false);
        service.mouse(100, 200, 1);
        service.cursor(100, 200, true);
        service.refresh();
        assert_eq!(service.counters().inputs, 3);
        assert_eq!(service.counters().cursors, 1);
        assert_eq!(service.counters().refreshes, 1);
        assert_eq!(
            service.outbox.lock().unwrap().len(),
            5,
            "nothing is written yet"
        );
    }

    #[test]
    fn a_guest_that_sends_a_surface_and_a_rectangle_is_understood_over_a_real_socket() {
        let (service, dir) = service();
        let port = service.port();
        let serving = {
            let service = service.clone();
            std::thread::spawn(move || service.serve())
        };
        let mut guest =
            UnixStream::connect(dc_vsock::listener_path(&dir.path().join("v.sock"), port)).unwrap();
        let surface = Surface {
            width: 64,
            height: 32,
            format: XRGB,
        };
        let rect = Rect {
            x: 1,
            y: 2,
            width: 3,
            height: 4,
        };
        guest.write_all(&guest::surface(surface).encode()).unwrap();
        guest.write_all(&guest::damage(rect, &[9u8; 48])).unwrap();
        guest.flush().unwrap();
        let mut taken = Vec::new();
        for _ in 0..200 {
            taken = service.take_damage();
            if !taken.is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(taken.len(), 1, "one rectangle");
        assert_eq!(taken[0].rect, rect);
        assert_eq!(taken[0].pixels, vec![9u8; 48]);
        assert_eq!(service.surface(), Some(surface));
        assert_eq!(service.counters().bytes, 48);
        assert_eq!(service.counters().largest, 12);
        drop(guest);
        let _ = serving.join();
    }

    #[test]
    fn the_hosts_input_reaches_the_guest_on_the_same_connection() {
        let (service, dir) = service();
        let port = service.port();
        let serving = {
            let service = service.clone();
            std::thread::spawn(move || service.serve())
        };
        let mut guest =
            UnixStream::connect(dc_vsock::listener_path(&dir.path().join("v.sock"), port)).unwrap();
        guest
            .set_read_timeout(Some(std::time::Duration::from_millis(2000)))
            .unwrap();
        // The guest is connected (it sent its surface), so the host may send input.
        guest
            .write_all(
                &guest::surface(Surface {
                    width: 8,
                    height: 8,
                    format: XRGB,
                })
                .encode(),
            )
            .unwrap();
        guest.flush().unwrap();
        service.key(30, true);
        let mut reader = Reader::new();
        let frame = loop {
            match reader.read_frame(&mut guest, port) {
                Ok(Some(frame)) => break frame,
                Ok(None) => panic!("the connection ended"),
                Err(e) => {
                    if let dc_vsock::VsockError::Io { source, .. } = &e {
                        if source.kind() == std::io::ErrorKind::WouldBlock
                            || source.kind() == std::io::ErrorKind::TimedOut
                        {
                            continue;
                        }
                    }
                    panic!("{e}");
                }
            }
        };
        assert_eq!(frame.kind, KIND_KEY);
        assert_eq!(
            u32::from_le_bytes(frame.payload[..4].try_into().unwrap()),
            30
        );
        assert_eq!(frame.payload[4], 1);
        drop(guest);
        let _ = serving.join();
    }

    #[test]
    fn a_message_that_is_cut_short_is_waited_for_and_the_next_one_is_still_read() {
        let (service, dir) = service();
        let port = service.port();
        let serving = {
            let service = service.clone();
            std::thread::spawn(move || service.serve())
        };
        let mut guest =
            UnixStream::connect(dc_vsock::listener_path(&dir.path().join("v.sock"), port)).unwrap();
        let rect = Rect {
            x: 0,
            y: 0,
            width: 4,
            height: 4,
        };
        let mut bytes = guest::damage(rect, &vec![1u8; rect.bytes()]);
        let full = bytes.len();
        bytes.truncate(full - 10); // the last ten bytes of pixels never arrive
        guest.write_all(&bytes).unwrap();
        guest.flush().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(150));
        // Nothing is delivered: a message whose pixels have not all arrived is not a message.
        assert!(service.take_damage().is_empty());
        // **And the channel is not dead.**  The rest of those pixels arrives, and the rectangle is
        // delivered exactly as if it had come in one piece — the old code closed the connection
        // here, which is what a frozen screen is.
        guest
            .write_all(&guest::damage(rect, &vec![1u8; rect.bytes()])[full - 10..])
            .unwrap();
        guest.flush().unwrap();
        let mut taken = Vec::new();
        for _ in 0..200 {
            taken = service.take_damage();
            if !taken.is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(taken.len(), 1, "the message finished and was delivered");
        assert_eq!(taken[0].pixels.len(), rect.bytes());
        drop(guest);
        let _ = serving.join();
    }

    #[test]
    fn a_lost_message_costs_one_message_and_the_channel_carries_on() {
        let (service, dir) = service();
        let port = service.port();
        let serving = {
            let service = service.clone();
            std::thread::spawn(move || service.serve())
        };
        let mut guest =
            UnixStream::connect(dc_vsock::listener_path(&dir.path().join("v.sock"), port)).unwrap();
        let rect = Rect {
            x: 0,
            y: 0,
            width: 8,
            height: 8,
        };
        let message = |generation: u32, byte: u8| {
            let m =
                crate::stream::DamageMessage::new(generation, vec![rect], vec![byte; rect.bytes()]);
            let mut out = m.head.to_vec();
            out.extend_from_slice(&m.header);
            out.extend_from_slice(&m.pixels);
            out
        };
        let a = message(1, 7);
        let b = message(2, 8);
        // The first message loses its tail to the transport, and the second follows: the parser
        // must give up on the first and read the second whole.
        guest.write_all(&a[..a.len() / 2]).unwrap();
        guest.write_all(&b).unwrap();
        guest.flush().unwrap();
        let mut taken = Vec::new();
        for _ in 0..200 {
            taken = service.take_damage();
            if !taken.is_empty() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(taken.len(), 1, "the second message is a message: {taken:?}");
        assert_eq!(taken[0].generation, 2, "and it is the one that came second");
        assert_eq!(taken[0].pixels, vec![8u8; rect.bytes()]);
        assert!(
            service.counters().resyncs > 0 || service.counters().lost > 0,
            "the lost message was noticed"
        );
        assert!(service.connected(), "the channel is still open");
        drop(guest);
        let _ = serving.join();
    }
}
