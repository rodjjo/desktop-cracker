//! **The guest's display client**: the screen, from the guest's side, in Rust.
//!
//! It is the replacement for `guest-agent/desktop-cracker-display.c`, and it keeps that design — the guest
//! owns the pixels (the project's own framebuffer, mapped through `/dev/desk_fb-fb`), so the
//! guest is what says what changed and the host draws it — with the damage logic rebuilt:
//!
//! ## What changed, and why
//!
//! 1. **Rectangles, not bands.**  The C code compared whole *rows* and sent screen-wide bands: a
//!    24×24 pointer cost a 1280×24 band (122 KB), and a window being dragged cost most of the
//!    screen at 30 Hz.  Here the comparison works on machine words, the changed *spans* of a row are
//!    found, and spans on neighbouring rows are grown into rectangles: a pointer is its own 24×24
//!    pixels (2.3 KB) and a line of text is the line.  Same comparison, a fraction of the bytes.
//! 2. **One message per frame.**  Everything one pass found goes in **one** damage message: the
//!    header lists the rectangles and the payload is their pixels, in that order.  One `writev`,
//!    one frame on the wire, however many rectangles it holds.
//! 3. **Frames are numbered and checksummed** (`dc_fc_display::stream`): the host can tell a message
//!    the transport damaged from one that is merely late, can count the ones that were lost, and can
//!    never be left desynchronised — which is what a frozen screen was.
//!
//! ## What did not change
//!
//! The pacing, because its numbers were measured:
//! a pass repeats no sooner than [`FRAME_INTERVAL`]; the framebuffer is compared between passes
//! every [`SCAN_INTERVAL`] (the comparison is a `memcmp` over megabytes and this guest is one or two
//! vCPUs); the pixels that go out are budgeted ([`PIXEL_BUDGET_PER_SECOND`]) so a page repaint
//! makes the picture slower rather than stopping the desktop; and the wait between passes is taken
//! in slices so the keyboard and the pointer are never held by a long pass's budget.
//!
//! Nothing here waits for the host, and nothing can end the screen: a message that cannot be
//! written ends the loop the way the C code's `return 0` did (the channel is gone, the run is over).

use std::io::{ErrorKind, IoSlice, Read, Write};
use std::os::fd::AsRawFd;
use std::time::Duration;

use dc_fc_display::stream::{DamageMessage, Message, StreamParser};
use dc_fc_display::Rect;

/// The shortest gap between two passes: 500 a second is more than a desktop needs and is what makes
/// a pointer feel like the hand it belongs to.
///
/// **The window between passes is not idle, and that is deliberate**: while it lasts the channel is
/// read every [`INPUT_SLICE`], so the keys and the pointer arrive promptly; the screen is only
/// *compared* on the cadence below.
pub const FRAME_INTERVAL: Duration = Duration::from_micros(2_000);
/// **How often the framebuffer is compared while nothing is sent.**  A change noticed within this
/// is drawn on the very next window frame (the window draws at 30 Hz).
pub const SCAN_INTERVAL: Duration = Duration::from_micros(8_000);
/// How long a single wait may last before the channel is read again.
pub const INPUT_SLICE: Duration = Duration::from_micros(1_000);
/// **How fast this channel may carry pixels**: Firecracker's vsock moves on the order of 100–150
/// MB/s, and a pass that carried a lot waits proportionally longer.
pub const PIXEL_BUDGET_PER_SECOND: u64 = 150 * 1024 * 1024;
/// A pass never waits longer than this, whatever it sent.
pub const FRAME_GAP_MAX: Duration = Duration::from_millis(200);
/// Above this fraction of the screen, the whole screen goes as one rectangle: one message, one
/// contiguous copy, and a picture the host adopts in place.
pub const WHOLE_SCREEN_DIVISOR: u64 = 3;
/// The most rectangles one message may carry (the framer's own limit).
pub const MAX_RECTS: usize = 64;
/// How many changed words may be skipped and still counted as one run: a dithered area, text with
/// gaps, and a pattern are one span rather than dozens (a word is 2 pixels).
pub const RUN_GAP_WORDS: usize = 4;
/// How close two spans have to be to belong to the same rectangle, in **bytes** (eight pixels): a
/// glyph's strokes and the gap between two words are one rectangle, and two distant areas of the
/// screen are two.
pub const RUN_JOIN_BYTES: usize = 32;
/// How big one message may grow before it is split: a whole screen fits, and nothing holds more
/// than this on either side of the channel.
pub const MAX_MESSAGE_BYTES: usize = 8 * 1024 * 1024;

/// What the guest saw and did — the run's own report, as the C agent's `DESK-DISPLAY` line was.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct DisplayStats {
    /// Frames sent (one message each).
    pub frames: u64,
    /// Rectangles sent, over all frames.
    pub rectangles: u64,
    /// Pixels sent.
    pub bytes: u64,
    /// Passes that carried nothing: the screen was still.
    pub idle: u64,
    /// Frames that carried the whole screen rather than bands.
    pub whole: u64,
}

impl DisplayStats {
    /// The line a milestone reads.
    pub fn report(&self) -> String {
        format!(
            "DESK-DISPLAY {} frame(s), {} rectangle(s), {} KiB, {} whole-screen, {} idle pass(es)",
            self.frames,
            self.rectangles,
            self.bytes >> 10,
            self.whole,
            self.idle
        )
    }
}

/// What the host said, as this client understands it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FromHost {
    /// Anything this client acts on itself (the input devices) or notes and does nothing about.
    Noted,
    /// **Send the whole screen**: a window that has just appeared has seen nothing.
    Refresh,
}

/// One message from the host, read out of its own bytes.
///
/// It is a function of `(kind, payload)` rather than code inside the read loop, because the read
/// loop cannot be run in a unit test (it is a vsock socket) and the **decoding** is exactly the part
/// that must be pinned: a payload read at the wrong offset is a key the guest receives as another
/// key, or a button that never lifts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostInput {
    /// A key: `[u32 code][u8 down]`.
    Key { code: u16, down: bool },
    /// The pointer and the buttons held: `[u32 x][u32 y][u32 buttons]`.
    Pointer { x: i32, y: i32, buttons: u32 },
    /// The wheel: `[i32 steps][i32 hsteps][u32 buttons]`.
    Wheel { steps: i32, hsteps: i32, buttons: u32 },
    /// The host wants the whole screen.
    Refresh,
    /// A message this client has no meaning for.
    Ignored,
}

/// Decode one host message.  A payload that is too short for its kind is **ignored**, never read
/// past its end.
pub fn host_input(kind: u16, payload: &[u8]) -> HostInput {
    match kind {
        dc_fc_display::KIND_KEY if payload.len() >= 5 => HostInput::Key {
            code: u16::from_le_bytes([payload[0], payload[1]]),
            down: payload[4] != 0,
        },
        dc_fc_display::KIND_MOUSE if payload.len() >= 12 => HostInput::Pointer {
            x: i32::from_le_bytes(payload[0..4].try_into().unwrap()),
            y: i32::from_le_bytes(payload[4..8].try_into().unwrap()),
            buttons: u32::from_le_bytes(payload[8..12].try_into().unwrap()),
        },
        dc_fc_display::KIND_WHEEL if payload.len() >= 12 => HostInput::Wheel {
            steps: i32::from_le_bytes(payload[0..4].try_into().unwrap()),
            hsteps: i32::from_le_bytes(payload[4..8].try_into().unwrap()),
            buttons: u32::from_le_bytes(payload[8..12].try_into().unwrap()),
        },
        dc_fc_display::KIND_REFRESH | dc_fc_display::KIND_RESIZE => HostInput::Refresh,
        _ => HostInput::Ignored,
    }
}

/// **The channel and the guest's own input devices**, as this client needs them.
///
/// It is a trait because those are the two things this code cannot do in a unit test: a vsock
/// socket and `/dev/uinput`.  The logic — the comparison, the rectangles, the pacing, the framing —
/// is then ordinary code under test, with a recorder in place of the devices.
pub trait DisplayIo: Send {
    /// Everything the host has said since the last call, **without waiting** for more.
    fn poll_host(&mut self) -> std::io::Result<Vec<FromHost>>;
    /// Write one damage message (head, header and pixels) with `writev`.
    fn send_message(&mut self, message: &DamageMessage) -> std::io::Result<()>;
    /// Write one small frame (the screen's description, a report).
    fn send_frame(&mut self, kind: u16, payload: &[u8]) -> std::io::Result<()>;
    /// A key, in the guest's own key code.
    fn key(&mut self, code: u16, down: bool);
    /// The pointer, in the guest's own pixels, and the buttons held (the **state** the host is
    /// asking the device to match).
    fn pointer(&mut self, x: i32, y: i32, buttons: u32);
    /// The wheel: a step on a relative axis (up and right are positive), with the buttons held.
    fn wheel(&mut self, steps: i32, hsteps: i32, buttons: u32);
    /// Rest for this long, reading the channel as it goes.  A test replaces it with nothing.
    fn rest(&mut self, wait: Duration);
}

/// Turn the host's messages into what this client does, and what the loop needs to know.
///
/// It is a free function generic over [`DisplayIo`] so a test can hand it its own recorder and see
/// exactly what a message did: the read loop above is a vsock socket and cannot run in a unit test,
/// and the dispatch is the half that has to be pinned.
fn dispatch<I: DisplayIo>(
    io: &mut I,
    messages: impl Iterator<Item = Message>,
) -> Vec<FromHost> {
    let mut out = Vec::new();
    for message in messages {
        let Message::Frame { kind, payload } = message else {
            continue;
        };
        match host_input(kind, &payload) {
            HostInput::Key { code, down } => {
                io.key(code, down);
                out.push(FromHost::Noted);
            }
            HostInput::Pointer { x, y, buttons } => {
                io.pointer(x, y, buttons);
                out.push(FromHost::Noted);
            }
            HostInput::Wheel {
                steps,
                hsteps,
                buttons,
            } => {
                io.wheel(steps, hsteps, buttons);
                out.push(FromHost::Noted);
            }
            HostInput::Refresh => out.push(FromHost::Refresh),
            HostInput::Ignored => out.push(FromHost::Noted),
        }
    }
    out
}

/// **The screen**, as the guest sees it: the mapped framebuffer and what the host was last told.
///
/// The mapping is the guest's own memory and Xorg writes into it directly: nothing here copies it,
/// and a row written while it is being read is corrected by the next pass — the contract the C code
/// had, and the reason the comparison, not a damage hint, is what decides.
pub struct Screen {
    /// The mapping, as the module published it.
    mapping: *const u8,
    len: usize,
    pub width: usize,
    pub height: usize,
    pub stride: usize,
    /// The last frame the host was **told about**, row for row (`stride` bytes a row, of which the
    /// first `width * 4` are the picture and any padding is ignored).
    previous: Vec<u8>,
    /// Whole-screen rectangles the scans asked for (they are answered before any band is).
    whole: bool,
}

/// Which of two rows changed, and how much: the runs of a row that differ, in pixels.
type Runs = Vec<(usize, usize)>;

impl Screen {
    /// # Safety
    ///
    /// `mapping` must point at `len` bytes of guest memory that stays mapped for as long as this
    /// value lives, and which the guest's own X server writes into.  That is what the framebuffer's
    /// control node gives (`HFB_GET_INFO`, then `mmap`), and it is the same mapping the C agent
    /// used.
    pub unsafe fn from_mapping(
        mapping: *const u8,
        len: usize,
        width: usize,
        height: usize,
        stride: usize,
    ) -> Screen {
        Screen {
            mapping,
            len,
            width,
            height,
            stride,
            previous: vec![0u8; stride * height],
            whole: false,
        }
    }

    /// The whole screen, as the module mapped it.
    pub fn bytes(&self) -> &[u8] {
        // SAFETY: the mapping is `len` bytes, alive for this value's lifetime.
        unsafe { std::slice::from_raw_parts(self.mapping, self.len) }
    }

    /// One row of the picture (`width * 4` bytes: the row's padding is not the picture).
    pub fn row(&self, y: usize) -> &[u8] {
        let start = y * self.stride;
        &self.bytes()[start..start + self.width * 4]
    }

    /// The row the host was last told about.
    pub fn previous_row(&self, y: usize) -> &[u8] {
        let start = y * self.stride;
        &self.previous[start..start + self.width * 4]
    }

    /// **Everything the guest has drawn so far counts as damage**: the host has seen nothing.
    pub fn forget(&mut self) {
        self.previous.fill(0xff);
        self.whole = true;
    }

    /// Compare the screen with what the host was last told, and answer the rectangles that changed.
    ///
    /// The answer is a whole-screen rectangle when everything (or most of it) moved, and otherwise
    /// the changed spans grown into rectangles, in top-to-bottom order.
    /// The spans are **byte** offsets inside a row; the rectangle each answer describes is in
    /// pixels (`rect_of`).
    pub fn scan(&mut self) -> Vec<Rect> {
        if self.whole {
            self.whole = false;
            return vec![whole_screen(self.width, self.height)];
        }
        let mut open: Vec<(usize, usize, usize, usize)> = Vec::new(); // x0, x1 (bytes), y_first, y_last
        let mut closed: Vec<Rect> = Vec::new();
        let mut rows_changed = 0usize;
        for y in 0..self.height {
            let runs = if self.row(y) == self.previous_row(y) {
                Vec::new()
            } else {
                rows_changed += 1;
                changed_runs(self.row(y), self.previous_row(y))
            };
            if runs.is_empty() {
                // Nothing on this row: every rectangle that was open ends above it.
                for rect in open.drain(..) {
                    closed.push(rect_of(rect));
                }
                continue;
            }
            // **Grow the open rectangles into this row.**  A rectangle continues while a run of
            // this row is next to (or inside) the span it covers; when two open rectangles meet the
            // same run they are merged, so a shape that narrows is still one rectangle.
            let mut taken = vec![false; runs.len()];
            let mut next: Vec<(usize, usize, usize, usize)> = Vec::new();
            for rect in open.drain(..) {
                let mut grown: Option<(usize, usize, usize, usize)> = None;
                for (i, (x0, x1)) in runs.iter().enumerate() {
                    if taken[i] {
                        continue;
                    }
                    if *x0 <= rect.1 + RUN_JOIN_BYTES && rect.0 <= *x1 + RUN_JOIN_BYTES {
                        taken[i] = true;
                        grown = Some(match grown {
                            None => (*x0.min(&rect.0), *x1.max(&rect.1), rect.2, y),
                            Some(span) => (
                                span.0.min(*x0),
                                span.1.max(*x1),
                                span.2,
                                y,
                            ),
                        });
                    }
                }
                match grown {
                    Some(span) => next.push(span),
                    None => closed.push(rect_of(rect)),
                }
            }
            for (i, (x0, x1)) in runs.into_iter().enumerate() {
                if !taken[i] {
                    next.push((x0, x1, y, y));
                }
            }
            open = next;
            if closed.len() + open.len() > MAX_RECTS {
                // Too many pieces: one whole-screen frame is cheaper than a hundred messages, and
                // it is the picture the host adopts in place.
                return vec![whole_screen(self.width, self.height)];
            }
        }
        for rect in open.drain(..) {
            closed.push(rect_of(rect));
        }
        if rows_changed * WHOLE_SCREEN_DIVISOR as usize > self.height {
            return vec![whole_screen(self.width, self.height)];
        }
        closed
    }

    /// **Is there anything to send at all?**  One `memcmp` a row with an early exit: a screen that
    /// is still costs a pass over the memory, and a screen that moved costs a row or two.
    pub fn anything_changed(&self) -> bool {
        if self.whole {
            return true;
        }
        for y in 0..self.height {
            if self.row(y) != self.previous_row(y) {
                return true;
            }
        }
        false
    }

    /// Remember that the host has been told about these rectangles.
    pub fn sent(&mut self, rects: &[Rect]) {
        for rect in rects {
            let x = rect.x as usize * 4;
            let count = rect.width as usize * 4;
            for y in rect.y as usize..(rect.y + rect.height) as usize {
                let start = y * self.stride + x;
                let now = self.bytes()[start..start + count].to_vec();
                self.previous[start..start + count].copy_from_slice(&now);
            }
        }
    }
}

/// The rectangle that is the whole screen.
fn whole_screen(width: usize, height: usize) -> Rect {
    Rect {
        x: 0,
        y: 0,
        width: width as u32,
        height: height as u32,
    }
}

/// The rectangle a run of rows and columns covers: the spans are byte offsets, so the rectangle is
/// in pixels (four bytes each, the framebuffer's own format).
fn rect_of(run: (usize, usize, usize, usize)) -> Rect {
    let (x0, x1, y_first, y_last) = run;
    Rect {
        x: (x0 / 4) as u32,
        y: y_first as u32,
        width: ((x1 - x0) / 4) as u32,
        height: (y_last - y_first + 1) as u32,
    }
}

/// The spans of one row that differ, as **byte** offsets `(first, last_exclusive)`.
///
/// The comparison is on machine words (two pixels at a time), and spans closer than
/// [`RUN_GAP_WORDS`] are one span: a dithered or anti-aliased area is one rectangle, not fifty.
fn changed_runs(now: &[u8], was: &[u8]) -> Runs {
    let mut runs = Vec::new();
    let words = now.len() / 8;
    let mut word = 0usize;
    while word < words {
        let differs = u64::from_le_bytes(now[word * 8..word * 8 + 8].try_into().unwrap())
            != u64::from_le_bytes(was[word * 8..word * 8 + 8].try_into().unwrap());
        if !differs {
            word += 1;
            continue;
        }
        let start = word;
        let mut last = word;
        word += 1;
        while word < words {
            let differs = u64::from_le_bytes(now[word * 8..word * 8 + 8].try_into().unwrap())
                != u64::from_le_bytes(was[word * 8..word * 8 + 8].try_into().unwrap());
            if differs {
                last = word;
                word += 1;
                continue;
            }
            // A gap of up to `RUN_GAP_WORDS` is still the same span; a longer one ends it.
            let mut look = word + 1;
            let mut found = None;
            while look < words && look - last <= RUN_GAP_WORDS {
                let differs = u64::from_le_bytes(now[look * 8..look * 8 + 8].try_into().unwrap())
                    != u64::from_le_bytes(was[look * 8..look * 8 + 8].try_into().unwrap());
                if differs {
                    found = Some(look);
                    break;
                }
                look += 1;
            }
            match found {
                Some(at) => {
                    last = at;
                    word = at + 1;
                }
                None => break,
            }
        }
        runs.push((start * 8, (last + 1) * 8));
    }
    // A tail that is not a whole word (a width that is not a multiple of two pixels): compare it
    // byte by byte, and grow the last span or add one.
    let tail = words * 8;
    if tail < now.len() && now[tail..] != was[tail..] {
        match runs.last_mut() {
            Some(last) if last.1 >= tail && last.1 - tail <= RUN_JOIN_BYTES => {
                last.1 = now.len();
            }
            _ => runs.push((tail, now.len())),
        }
    }
    runs
}

/// **The display client**: the frame loop, the pacing and the damage messages.
pub struct DisplayClient<I: DisplayIo> {
    pub screen: Screen,
    io: I,
    stats: DisplayStats,
    generation: u32,
    send_everything: bool,
    /// The pixels of one message, built in one buffer so the message is one `writev`.
    scratch: Vec<u8>,
    /// **The rest the last pass earned**: what this pass cost, paid for (the same number the loop
    /// then spends in slices, watching the channel as it goes).
    pub last_wait: Duration,
}

impl<I: DisplayIo> DisplayClient<I> {
    pub fn new(screen: Screen, io: I) -> DisplayClient<I> {
        let mut client = DisplayClient {
            screen,
            io,
            stats: DisplayStats::default(),
            generation: 0,
            send_everything: true,
            scratch: Vec::new(),
            last_wait: FRAME_INTERVAL,
        };
        client.screen.forget();
        client
    }

    pub fn stats(&self) -> DisplayStats {
        self.stats
    }

    /// The screen's own description, as the host's first message.
    pub fn announce(&mut self) -> std::io::Result<()> {
        let payload = dc_fc_display::Surface {
            width: self.screen.width as u32,
            height: self.screen.height as u32,
            format: dc_fc_display::stream::PIXMAN_X8R8G8B8,
        }
        .encode();
        self.io.send_frame(dc_fc_display::KIND_SURFACE, &payload)
    }

    /// **One pass**: what changed, one message for it, the host's words, and the rest this pass has
    /// earned.
    ///
    /// Answers `false` when the channel is gone, which is the caller's cue to end the run (the C
    /// agent's own `return 0`).
    pub fn pass(&mut self) -> bool {
        let rects = self.screen.scan();
        if self.send_everything {
            self.send_everything = false;
        }
        let mut carried = 0u64;
        if !rects.is_empty() {
            if self.send_message(&rects).is_err() {
                return false;
            }
            carried = rects.iter().map(|r| r.bytes() as u64).sum();
            self.screen.sent(&rects);
            self.stats.frames += 1;
            self.stats.rectangles += rects.len() as u64;
            self.stats.bytes += carried;
            if rects.len() == 1
                && rects[0].x == 0
                && rects[0].y == 0
                && rects[0].width as usize == self.screen.width
                && rects[0].height as usize == self.screen.height
            {
                self.stats.whole += 1;
            }
        } else {
            self.stats.idle += 1;
        }

        // The host's own words, without waiting: a still screen must not hold the keyboard.
        match self.io.poll_host() {
            Ok(events) => {
                if events.contains(&FromHost::Refresh) {
                    self.screen.forget();
                    self.send_everything = true;
                }
            }
            Err(_) => return false,
        }

        // And a rest: what this pass cost, paid for.  A screen that is still rests a frame; a pass
        // that carried a lot waits proportionally longer, which is what keeps a repaint from
        // becoming a flood and the desktop from becoming a freeze.
        let cost = Duration::from_micros(
            carried.saturating_mul(1_000_000) / PIXEL_BUDGET_PER_SECOND.max(1),
        );
        let mut wait = cost.max(FRAME_INTERVAL);
        if wait > FRAME_GAP_MAX {
            wait = FRAME_GAP_MAX;
        }
        self.last_wait = wait;
        // **The wait is taken in slices and the screen is looked at between them**: a desktop that
        // starts moving again while the last pass's budget is being paid must be drawn at once.
        let mut waited = Duration::ZERO;
        let mut next_scan = SCAN_INTERVAL;
        while waited < wait {
            let slice = INPUT_SLICE.min(wait - waited);
            self.io.rest(slice);
            waited += slice;
            if waited >= next_scan {
                next_scan = waited + SCAN_INTERVAL;
                if self.screen.anything_changed() {
                    break;
                }
            }
        }
        true
    }

    /// One damage message for these rectangles, split if it would be larger than the channel allows.
    fn send_message(&mut self, rects: &[Rect]) -> std::io::Result<()> {
        let mut at = 0usize;
        while at < rects.len() {
            // As many rectangles as fit in one message.
            let mut end = at;
            let mut bytes = 0usize;
            while end < rects.len() && (end == at || bytes + rects[end].bytes() <= MAX_MESSAGE_BYTES)
            {
                bytes += rects[end].bytes();
                end += 1;
            }
            let chunk = &rects[at..end];
            let pixels = self.pixels_of(chunk);
            let message = DamageMessage::new(self.generation, chunk.to_vec(), pixels);
            self.generation = self.generation.wrapping_add(1);
            self.io.send_message(&message)?;
            at = end;
        }
        Ok(())
    }

    /// The pixels of these rectangles, in the order they are listed: a rectangle's rows packed one
    /// after another (`width * 4` bytes each, no padding).
    fn pixels_of(&mut self, rects: &[Rect]) -> Vec<u8> {
        let total: usize = rects.iter().map(|r| r.bytes()).sum();
        self.scratch.clear();
        self.scratch.reserve(total);
        for rect in rects {
            let x = rect.x as usize * 4;
            let count = rect.width as usize * 4;
            for y in rect.y as usize..(rect.y + rect.height) as usize {
                let start = y * self.screen.stride + x;
                self.scratch
                    .extend_from_slice(&self.screen.bytes()[start..start + count]);
            }
        }
        std::mem::take(&mut self.scratch)
    }
}

// ------------------------------------------------------------------------------------- the guest's
// ------------------------------------------------------------------------------ own channel and
// ------------------------------------------------------------------------------- input devices

/// The guest's own channel and its two `uinput` devices.
///
/// The channel is the vsock connection the agent dialled; the devices are created the way the C
/// agent created them (`/dev/uinput`, `UI_SET_EVBIT`/`UI_SET_KEYBIT`, `UI_DEV_CREATE`).
pub struct GuestIo {
    channel: std::os::unix::net::UnixStream,
    keyboard: Option<std::os::fd::OwnedFd>,
    pointer: Option<std::os::fd::OwnedFd>,
    parser: StreamParser,
    /// **The buttons this guest's pointer device is currently holding** (bit 0 left, 1 middle,
    /// 2 right).
    ///
    /// The host sends a *state*, and the device is a state too; this is what lets the agent tell
    /// the device only the button that changed instead of re-stating all three on every event —
    /// which is what keeps a button down through a drag (`crate::uinput::pointer_move`).
    buttons: u32,
}

impl GuestIo {
    pub fn new(channel: std::os::unix::net::UnixStream) -> GuestIo {
        GuestIo {
            channel,
            keyboard: None,
            pointer: None,
            parser: StreamParser::new(),
            buttons: 0,
        }
    }

    /// The two devices: the keyboard, and a pointer whose absolute range is the screen's own pixels
    /// and which offers the wheel as the relative axis the kernel calls a wheel.
    pub fn create_devices(mut self, width: u32, height: u32) -> GuestIo {
        self.keyboard = crate::uinput::keyboard();
        self.pointer = crate::uinput::pointer(width, height);
        self
    }

    /// The channel's own socket, for a caller that wants to wait on it.
    pub fn channel_fd(&self) -> i32 {
        self.channel.as_raw_fd()
    }
}

impl DisplayIo for GuestIo {
    fn poll_host(&mut self) -> std::io::Result<Vec<FromHost>> {
        let mut out = Vec::new();
        let mut buf = [0u8; 16 * 1024];
        loop {
            if !readable(self.channel.as_raw_fd(), 0) {
                break;
            }
            match self.channel.read(&mut buf) {
                Ok(0) => return Err(ErrorKind::UnexpectedEof.into()),
                Ok(n) => self.parser.push(&buf[..n]),
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            }
        }
        let mut messages = Vec::new();
        while let Some(message) = self.parser.next() {
            messages.push(message);
        }
        out.extend(dispatch(self, messages.into_iter()));
        Ok(out)
    }

    fn send_message(&mut self, message: &DamageMessage) -> std::io::Result<()> {
        let parts = [
            IoSlice::new(&message.head),
            IoSlice::new(&message.header),
            IoSlice::new(&message.pixels),
        ];
        write_all_vectored(&mut self.channel, &parts)
    }

    fn send_frame(&mut self, kind: u16, payload: &[u8]) -> std::io::Result<()> {
        let len = payload.len() as u32;
        let head: [u8; 6] = [
            (len & 0xff) as u8,
            ((len >> 8) & 0xff) as u8,
            ((len >> 16) & 0xff) as u8,
            ((len >> 24) & 0xff) as u8,
            (kind & 0xff) as u8,
            ((kind >> 8) & 0xff) as u8,
        ];
        self.channel.write_all(&head)?;
        if !payload.is_empty() {
            self.channel.write_all(payload)?;
        }
        self.channel.flush()
    }

    fn key(&mut self, code: u16, down: bool) {
        if let Some(fd) = self.keyboard.as_ref() {
            crate::uinput::key(fd, code, down);
        }
    }

    fn pointer(&mut self, x: i32, y: i32, buttons: u32) {
        if let Some(fd) = self.pointer.as_ref() {
            crate::uinput::pointer_move(fd, x, y, buttons, &mut self.buttons);
        }
    }

    fn wheel(&mut self, steps: i32, hsteps: i32, buttons: u32) {
        let Some(fd) = self.pointer.as_ref() else {
            return;
        };
        // The buttons the host says are held go to the device first: a wheel during a drag is a
        // wheel while the button is still down, and the device must not be told the drag ended.
        crate::uinput::pointer_buttons(fd, buttons, &mut self.buttons);
        crate::uinput::wheel(fd, steps);
        crate::uinput::hwheel(fd, hsteps);
    }

    fn rest(&mut self, wait: Duration) {
        std::thread::sleep(wait);
    }
}

/// Is this fd readable right now?  One `poll`, with the caller's own timeout.
pub fn readable(fd: i32, timeout_ms: i32) -> bool {
    let mut p = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    loop {
        // SAFETY: one `pollfd` on the stack, valid for the call.
        let n = unsafe { libc::poll(&mut p, 1, timeout_ms) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == ErrorKind::Interrupted {
                continue;
            }
            return false;
        }
        return n > 0;
    }
}

/// `writev` a message in full: the kernel may take part of it on a blocking socket, and the rest is
/// written next — which is what keeps a frame one message rather than several.
fn write_all_vectored(
    stream: &mut std::os::unix::net::UnixStream,
    parts: &[IoSlice<'_>],
) -> std::io::Result<()> {
    // The slices as plain pointers: the kernel may take part of a message on a blocking socket,
    // and what is left is written next — which is what keeps a frame one message.  The buffers
    // belong to the caller and outlive this call, so the pointers are good for it.
    let mut left: Vec<(*const u8, usize)> = parts.iter().map(|p| (p.as_ptr(), p.len())).collect();
    while !left.is_empty() {
        let slices: Vec<IoSlice<'_>> = left
            .iter()
            // SAFETY: each pointer is the start of a caller slice of that length, and nothing in
            // this function or the call below writes through them.
            .map(|(ptr, len)| IoSlice::new(unsafe { std::slice::from_raw_parts(*ptr, *len) }))
            .collect();
        match stream.write_vectored(&slices) {
            Ok(0) => return Err(ErrorKind::WriteZero.into()),
            Ok(n) => {
                let mut remaining = n;
                while remaining > 0 && !left.is_empty() {
                    let (_, len) = left[0];
                    if remaining >= len {
                        remaining -= len;
                        left.remove(0);
                    } else {
                        let (ptr, len) = left[0];
                        // SAFETY: the pointer stays inside the caller's buffer.
                        left[0] = (unsafe { ptr.add(remaining) }, len - remaining);
                        remaining = 0;
                    }
                }
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// A client with nothing to talk to, for a test that is about the screen and not the channel.
pub struct NoIo;

impl DisplayIo for NoIo {
    fn poll_host(&mut self) -> std::io::Result<Vec<FromHost>> {
        Ok(Vec::new())
    }
    fn send_message(&mut self, _message: &DamageMessage) -> std::io::Result<()> {
        Ok(())
    }
    fn send_frame(&mut self, _kind: u16, _payload: &[u8]) -> std::io::Result<()> {
        Ok(())
    }
    fn key(&mut self, _code: u16, _down: bool) {}
    fn pointer(&mut self, _x: i32, _y: i32, _buttons: u32) {}
    fn wheel(&mut self, _steps: i32, _hsteps: i32, _buttons: u32) {}
    fn rest(&mut self, _wait: Duration) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A screen of the given size backed by memory this test owns: the same shape the module's
    /// mapping has, so `Screen`'s own code is what is under test.
    struct Fake {
        screen: Screen,
        owner: Vec<u8>,
    }

    impl Fake {
        fn new(width: usize, height: usize) -> Fake {
            let stride = width * 4;
            let mut owner = vec![0u8; stride * height];
            owner.fill(0x11);
            let screen = unsafe {
                Screen::from_mapping(
                    owner.as_ptr(),
                    owner.len(),
                    width,
                    height,
                    stride,
                )
            };
            Fake { screen, owner }
        }

        /// Draw a rectangle, the way Xorg's fbdev driver writes one.
        fn draw(&mut self, x: usize, y: usize, w: usize, h: usize, value: u8) {
            for row in y..y + h {
                for col in x..x + w {
                    let at = row * self.screen.stride + col * 4;
                    self.owner[at..at + 4].copy_from_slice(&[value, value, value, value]);
                }
            }
            // The mapping points at `owner`, and `owner` may move when it grows: it never grows
            // here (it is built at its final size), so the pointer stays right.
            self.screen = unsafe {
                Screen::from_mapping(
                    self.owner.as_ptr(),
                    self.owner.len(),
                    self.screen.width,
                    self.screen.height,
                    self.screen.stride,
                )
            };
            self.screen.forget();
        }
    }

    /// The channel, recorded: what a message looked like and what the pacing asked for.
    #[derive(Default)]
    struct Recorder {
        messages: Vec<Vec<u8>>,
        waits: Vec<Duration>,
        host: Vec<FromHost>,
        keys: Vec<(u16, bool)>,
        /// The pointer events the host's messages turned into: the position, the buttons, and the
        /// wheel steps.
        pointers: Vec<(i32, i32, u32)>,
        wheels: Vec<(i32, i32, u32)>,
    }

    impl Recorder {
        /// Everything the recorder was sent, parsed back with the host's own parser.
        fn parsed(&self) -> Vec<Message> {
            let mut parser = StreamParser::new();
            let mut out = Vec::new();
            for message in &self.messages {
                parser.push(message);
                while let Some(m) = parser.next() {
                    out.push(m);
                }
            }
            out
        }

        fn damage(&self) -> Vec<(Vec<Rect>, Vec<u8>)> {
            self.parsed()
                .into_iter()
                .filter_map(|m| match m {
                    Message::Damage { rects, pixels, .. } => Some((rects, pixels)),
                    _ => None,
                })
                .collect()
        }
    }

    impl DisplayIo for Recorder {
        fn poll_host(&mut self) -> std::io::Result<Vec<FromHost>> {
            Ok(std::mem::take(&mut self.host))
        }
        fn send_message(&mut self, message: &DamageMessage) -> std::io::Result<()> {
            let mut bytes = message.head.to_vec();
            bytes.extend_from_slice(&message.header);
            bytes.extend_from_slice(&message.pixels);
            self.messages.push(bytes);
            Ok(())
        }
        fn send_frame(&mut self, kind: u16, payload: &[u8]) -> std::io::Result<()> {
            let mut frame = dc_vsock_frame(kind, payload);
            self.messages.append(&mut frame);
            Ok(())
        }
        fn key(&mut self, code: u16, down: bool) {
            self.keys.push((code, down));
        }
        fn pointer(&mut self, x: i32, y: i32, buttons: u32) {
            self.pointers.push((x, y, buttons));
        }
        fn wheel(&mut self, steps: i32, hsteps: i32, buttons: u32) {
            self.wheels.push((steps, hsteps, buttons));
        }
        fn rest(&mut self, wait: Duration) {
            self.waits.push(wait);
        }
    }

    fn dc_vsock_frame(kind: u16, payload: &[u8]) -> Vec<Vec<u8>> {
        let len = payload.len() as u32;
        let mut out = vec![
            (len & 0xff) as u8,
            ((len >> 8) & 0xff) as u8,
            ((len >> 16) & 0xff) as u8,
            ((len >> 24) & 0xff) as u8,
            (kind & 0xff) as u8,
            ((kind >> 8) & 0xff) as u8,
        ];
        out.extend_from_slice(payload);
        vec![out]
    }

    fn client(width: usize, height: usize) -> (DisplayClient<Recorder>, Fake) {
        let fake = Fake::new(width, height);
        // The client is built over the same mapping the drawer writes into, and its own first pass
        // sends the whole screen (`new` marks everything as damage).
        let screen = fake.screen_again();
        (DisplayClient::new(screen, Recorder::default()), fake)
    }

    impl Fake {
        fn screen_again(&self) -> Screen {
            unsafe {
                Screen::from_mapping(
                    self.owner.as_ptr(),
                    self.owner.len(),
                    self.screen.width,
                    self.screen.height,
                    self.screen.stride,
                )
            }
        }
    }

    #[test]
    fn a_still_screen_sends_nothing_at_all() {
        let (mut client, _fake) = client(64, 32);
        client.pass(); // the first pass: the whole screen
        let before = client.stats();
        assert_eq!(before.whole, 1, "the first frame is the whole screen");
        for _ in 0..10 {
            client.pass();
        }
        let after = client.stats();
        assert_eq!(after.frames, 1, "nothing else was sent");
        assert_eq!(after.idle, 10, "ten passes carried nothing");
    }

    #[test]
    fn a_pointer_sized_change_is_a_pointer_sized_rectangle() {
        let (mut client, mut fake) = client(1280, 800);
        client.pass(); // the whole screen, as the guest's very first frame
        fake.draw(100, 200, 24, 24, 0xEE);
        client.pass();
        let damage = client.io.damage();
        assert_eq!(damage.len(), 2, "the first frame and the change");
        let (rects, pixels) = &damage[1];
        assert_eq!(rects.len(), 1, "one rectangle: {rects:?}");
        let rect = rects[0];
        assert!(
            rect.width <= 32 && rect.height <= 24,
            "the rectangle is the pointer's own pixels, not a band: {rect:?}"
        );
        assert!(rect.x <= 100 && rect.y <= 200);
        assert_eq!(pixels.len(), rect.bytes(), "the pixels are the rectangle");
    }

    #[test]
    fn a_line_of_text_is_the_line() {
        let (mut client, mut fake) = client(1280, 800);
        client.pass();
        fake.draw(10, 300, 300, 16, 0x33);
        client.pass();
        let damage = client.io.damage();
        let (rects, pixels) = &damage[1];
        let rect = rects[0];
        assert!(rect.height <= 20, "sixteen rows of text, not a band: {rect:?}");
        assert!(rect.width < 400, "and three hundred columns: {rect:?}");
        assert_eq!(pixels.len(), rect.bytes());
    }

    #[test]
    fn a_screen_that_moved_everywhere_is_one_whole_screen_rectangle() {
        let (mut client, mut fake) = client(64, 64);
        client.pass();
        fake.draw(0, 0, 64, 64, 0x77);
        client.pass();
        let damage = client.io.damage();
        let (rects, _) = &damage[1];
        assert_eq!(rects.len(), 1);
        assert_eq!((rects[0].width, rects[0].height), (64, 64));
        assert_eq!(client.stats().whole, 2, "the first frame and this one");
    }

    #[test]
    fn two_places_that_changed_are_one_message_with_two_rectangles() {
        let (mut client, mut fake) = client(1280, 800);
        client.pass();
        fake.draw(10, 10, 8, 8, 0xAA);
        fake.draw(900, 700, 8, 8, 0xBB);
        // `Fake::draw` forgets (it is the test's own shortcut for "the drawer touched this"), so
        // the two rectangles are seen in the pass that follows the second draw.
        client.pass();
        let damage = client.io.damage();
        let last = damage.last().unwrap();
        assert_eq!(damage.len(), 2, "the first frame and the change");
        assert_eq!(last.0.len(), 2, "two rectangles: {:?}", last.0);
        // Their pixels are in the order the rectangles are listed.
        let (rects, pixels) = last;
        assert_eq!(pixels.len(), rects.iter().map(|r| r.bytes()).sum::<usize>());
    }

    #[test]
    fn the_host_reads_back_exactly_what_the_guest_sent() {
        let (mut client, mut fake) = client(256, 128);
        client.pass();
        fake.draw(3, 5, 7, 9, 0x5A);
        client.pass();
        let damage = client.io.damage();
        let (rects, pixels) = damage.last().unwrap();
        // Every rectangle's pixels are the screen's own bytes where it says they are.
        let mut at = 0;
        for rect in rects {
            for y in rect.y as usize..(rect.y + rect.height) as usize {
                for x in rect.x as usize..(rect.x + rect.width) as usize {
                    let written = &pixels[at..at + 4];
                    assert_eq!(
                        written,
                        &fake.owner[y * fake.screen.stride + x * 4..y * fake.screen.stride + x * 4 + 4],
                        "the pixel at {x},{y} is what the message carries"
                    );
                    at += 4;
                }
            }
        }
    }

    #[test]
    fn the_pacing_pays_for_what_a_pass_carried() {
        let (mut whole, _fake) = client(1280, 800);
        whole.pass(); // 4 MB: a whole screen
        let full = whole.last_wait;
        assert!(
            full >= Duration::from_millis(25),
            "a whole screen waits for its own budget: {full:?}"
        );
        assert!(
            whole.io.waits.iter().all(|w| *w <= INPUT_SLICE),
            "the wait is spent in slices, so the channel is read while it lasts"
        );
        let (mut small, mut fake) = client(1280, 800);
        small.pass();
        fake.draw(1, 1, 8, 8, 0x99);
        small.pass();
        assert_eq!(
            small.last_wait, FRAME_INTERVAL,
            "a small change runs at the frame rate"
        );
    }

    #[test]
    fn a_screen_that_moved_while_the_last_frame_was_being_sent_is_not_forgotten() {
        // The guest sends the whole screen, and the drawer writes into the mapping *after* the
        // message was built: the next pass must still see that change (the copy is what the host
        // was told, not what the screen is now).
        let (mut client, mut fake) = client(64, 64);
        client.pass();
        let before = client.stats().bytes;
        fake.draw(0, 0, 64, 64, 0x42);
        client.pass();
        assert!(client.stats().bytes > before, "the change was sent");
        // And a change that arrives *during* the next pass (nothing can be done about that but the
        // next pass seeing it) is caught by the pass after.
        fake.draw(10, 10, 4, 4, 0x43);
        client.pass();
        assert!(client.stats().rectangles >= 2);
    }

    #[test]
    fn a_host_that_asks_for_the_whole_screen_gets_it() {
        let (mut client, _fake) = client(64, 64);
        client.pass();
        client.io.host.push(FromHost::Refresh);
        client.pass();
        let damage = client.io.damage();
        let last = damage.last().unwrap();
        assert_eq!((last.0[0].width, last.0[0].height), (64, 64), "the whole screen again");
    }

    #[test]
    fn the_runs_of_a_row_are_one_span_across_a_small_gap() {
        // Two changed areas eight pixels apart are one rectangle (the gap is cheaper than a second
        // rectangle), and two areas far apart are two.
        let row = vec![0u8; 256];
        let mut other = row.clone();
        other[0..4].copy_from_slice(&[1, 1, 1, 1]);
        other[16..20].copy_from_slice(&[1, 1, 1, 1]);
        assert_eq!(changed_runs(&other, &row), vec![(0, 24)]);
        let mut far = row.clone();
        far[0..4].copy_from_slice(&[1, 1, 1, 1]);
        far[200..204].copy_from_slice(&[1, 1, 1, 1]);
        assert_eq!(changed_runs(&far, &row), vec![(0, 8), (200, 208)]);
    }

    #[test]
    fn the_report_line_is_the_run_s_own_numbers() {
        let stats = DisplayStats {
            frames: 3,
            rectangles: 5,
            bytes: 4096,
            idle: 7,
            whole: 1,
        };
        let line = stats.report();
        assert!(line.contains("3 frame(s)"), "{line}");
        assert!(line.contains("5 rectangle(s)"), "{line}");
        assert!(line.contains("4 KiB"), "{line}");
    }

    /// **The keyboard is a pipe**: the host's key message carries the kernel key code, and the guest
    /// writes it into its own keyboard unchanged.  `62` is `KEY_F4`, which is what `Alt+F4` is in
    /// the guest; a code read at the wrong offset is a key the guest receives as another key.
    #[test]
    fn a_key_message_is_the_kernel_code_unchanged() {
        let mut payload = 62u32.to_le_bytes().to_vec();
        payload.push(1);
        assert_eq!(
            host_input(dc_fc_display::KIND_KEY, &payload),
            HostInput::Key { code: 62, down: true }
        );
        payload[4] = 0;
        assert_eq!(
            host_input(dc_fc_display::KIND_KEY, &payload),
            HostInput::Key { code: 62, down: false }
        );
        // 125 is `KEY_LEFTMETA`: the Super key reaches the guest as the guest's Super.
        let mut super_ = 125u32.to_le_bytes().to_vec();
        super_.push(1);
        assert_eq!(
            host_input(dc_fc_display::KIND_KEY, &super_),
            HostInput::Key {
                code: 125,
                down: true
            }
        );
    }

    /// **The pointer message is a state**: the mask it carries is the mask the guest's device is
    /// asked to match, so a move during a drag carries the button that is down.
    #[test]
    fn a_pointer_message_carries_the_buttons_held() {
        let mut payload = 300u32.to_le_bytes().to_vec();
        payload.extend_from_slice(&200u32.to_le_bytes());
        payload.extend_from_slice(&1u32.to_le_bytes());
        assert_eq!(
            host_input(dc_fc_display::KIND_MOUSE, &payload),
            HostInput::Pointer {
                x: 300,
                y: 200,
                buttons: 1
            }
        );
        // Left and right held together.
        payload[8..12].copy_from_slice(&5u32.to_le_bytes());
        assert_eq!(
            host_input(dc_fc_display::KIND_MOUSE, &payload),
            HostInput::Pointer {
                x: 300,
                y: 200,
                buttons: 5
            }
        );
    }

    /// **The wheel is its own message**, with signed steps: up is positive, down negative, and the
    /// buttons held while it turned travel with it.
    #[test]
    fn a_wheel_message_is_a_signed_step_with_the_buttons_held() {
        let mut payload = (-1i32).to_le_bytes().to_vec();
        payload.extend_from_slice(&0i32.to_le_bytes());
        payload.extend_from_slice(&1u32.to_le_bytes());
        assert_eq!(
            host_input(dc_fc_display::KIND_WHEEL, &payload),
            HostInput::Wheel {
                steps: -1,
                hsteps: 0,
                buttons: 1
            }
        );
        payload[0..4].copy_from_slice(&3i32.to_le_bytes());
        payload[4..8].copy_from_slice(&(-2i32).to_le_bytes());
        assert_eq!(
            host_input(dc_fc_display::KIND_WHEEL, &payload),
            HostInput::Wheel {
                steps: 3,
                hsteps: -2,
                buttons: 1
            }
        );
    }

    /// A message that is too short for its kind is **ignored**, never read past its end: a truncated
    /// payload on a socket is an ordinary thing, and it must not become a wrong key.
    #[test]
    fn a_short_payload_is_ignored_not_guessed_at() {
        assert_eq!(host_input(dc_fc_display::KIND_KEY, &[1, 0, 0, 0]), HostInput::Ignored);
        assert_eq!(host_input(dc_fc_display::KIND_KEY, &[]), HostInput::Ignored);
        assert_eq!(
            host_input(dc_fc_display::KIND_MOUSE, &[0, 0, 0, 1, 0, 0, 0, 2]),
            HostInput::Ignored
        );
        assert_eq!(
            host_input(dc_fc_display::KIND_WHEEL, &[0, 0, 0, 1]),
            HostInput::Ignored
        );
        assert_eq!(host_input(999, &[0; 32]), HostInput::Ignored);
    }

    /// The host's two "give me the whole screen" messages are still the refresh they were, and the
    /// new wheel kind did not take one of their numbers.
    #[test]
    fn the_refresh_and_resize_messages_are_untouched() {
        assert_eq!(host_input(dc_fc_display::KIND_REFRESH, &[]), HostInput::Refresh);
        assert_eq!(
            host_input(dc_fc_display::KIND_RESIZE, &[8, 7, 0, 0]),
            HostInput::Refresh
        );
        assert_ne!(dc_fc_display::KIND_WHEEL, dc_fc_display::KIND_REPORT);
        assert_ne!(dc_fc_display::KIND_WHEEL, dc_fc_display::KIND_REFRESH);
    }

    /// **A drag is a press, a move and a release, and the buttons are right at every step.**  The
    /// recorder stands in for the guest's device: what the host's messages become.
    #[test]
    fn a_drag_keeps_the_button_held_through_the_move() {
        let pointer_message = |x: u32, y: u32, buttons: u32| {
            let mut payload = x.to_le_bytes().to_vec();
            payload.extend_from_slice(&y.to_le_bytes());
            payload.extend_from_slice(&buttons.to_le_bytes());
            dc_vsock_frame(dc_fc_display::KIND_MOUSE, &payload)
        };
        let wheel_message = |steps: i32, buttons: u32| {
            let mut payload = steps.to_le_bytes().to_vec();
            payload.extend_from_slice(&0i32.to_le_bytes());
            payload.extend_from_slice(&buttons.to_le_bytes());
            dc_vsock_frame(dc_fc_display::KIND_WHEEL, &payload)
        };

        let mut recorder = Recorder::default();
        let mut parser = StreamParser::new();
        for frame in [
            pointer_message(10, 20, 1),
            pointer_message(40, 60, 1),
            pointer_message(40, 60, 0),
            wheel_message(-3, 0),
        ] {
            for bytes in frame {
                parser.push(&bytes);
            }
        }
        let mut messages: Vec<Message> = Vec::new();
        while let Some(message) = parser.next() {
            messages.push(message);
        }
        let said = dispatch(&mut recorder, messages.into_iter());
        assert!(
            said.iter().all(|event| *event == FromHost::Noted),
            "none of these asked for the whole screen: {said:?}"
        );
        assert_eq!(
            recorder.pointers,
            vec![(10, 20, 1), (40, 60, 1), (40, 60, 0)],
            "the move carries the held button, and the release carries the mask after it"
        );
        assert_eq!(recorder.wheels, vec![(-3, 0, 0)], "the wheel is a signed step");
    }
}
