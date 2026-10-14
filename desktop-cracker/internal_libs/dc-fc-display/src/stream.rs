//! **The display channel's own framer**: the bytes on the wire, turned into messages, with a
//! parser that **waits** for what has not arrived and **finds its own way back** when bytes were
//! lost.
//!
//! The channel is a byte stream, and the only thing that says where one message ends is the
//! message itself.  Three facts decide this design:
//!
//! * **a message's length covers everything in it, pixels included.**  A damage message is one
//!   *message*: its header and the pixels of every rectangle it carries, so the parser knows the
//!   whole size before it has the pixels and never infers a size from a rectangle count.
//! * **a message may arrive over several reads, and that is ordinary.**  The transport is a third
//!   process with its own buffers and a non-blocking host socket, so a rectangle can be delivered
//!   in pieces.  A partial message is therefore *held*, never abandoned: the old code answered
//!   "this connection is desynchronised" after a stall and closed it, and a closed connection is
//!   exactly what a frozen screen is (the guest's next write fails, its loop ends, and nothing
//!   draws again — measured out of the VM for that bug).
//! * **the pixels are checksummed too.**  A header's magic and CRC say where a message begins; the
//!   pixels' own CRC is what says whether the message that was read is the message that was sent.
//!   With it, a message whose bytes were damaged (a torn band, a device that dropped some) is
//!   *detected* rather than drawn wrong, and the parser then scans forward for the next message's
//!   magic — which is still there, because nothing was thrown away: **a lost message costs one
//!   message, and the screen keeps drawing.**
//!
//! The cost of the pixels' CRC is why it is the hardware one on any CPU that has it (SSE4.2's
//! `crc32` instruction, ~1 byte a cycle: a 1280x800 frame is 4 MB and about a millisecond).

use crate::{Rect, Surface, KIND_DAMAGE, KIND_RESIZE, KIND_SURFACE};

/// **`PIXMAN_x8r8g8b8`**: the pixel format the guest's window holds, in the numbering
/// `dc-display::Geometry` already uses, so nothing is translated between the two (four bytes a
/// pixel, `XRGB8888`).
pub const PIXMAN_X8R8G8B8: u32 = 0x2000_0000;

/// The four bytes that say "a damage header begins here".  Chosen so that pixel bytes containing it
/// are a 1-in-4-billion event, and the CRCs then reject what is left.
pub const DAMAGE_MAGIC: u32 = 0x4448_4644; // "HDFD", little-endian

/// The most rectangles one message may carry.  A message that claims more is not one of ours.
pub const MAX_RECTS: usize = 256;

/// The largest frame this channel carries when the length does **not** cover the pixels: every
/// other message is `dc_vsock`'s own shape (`MAX_FRAME`).
pub const MAX_SMALL: u32 = 60 * 1024;

/// The largest damage message there can be.  A whole screen is 4 bytes a pixel (8 MB at
/// 1920x1080); a message that claims more than this is not one of ours.
pub const MAX_DAMAGE: u32 = 16 * 1024 * 1024;

/// What one attempt at the parse position gave: a message, "wait for more bytes", or "this offset
/// is not a message".
enum Outcome {
    Message(Message),
    Wait,
    NotHere,
}

/// What a complete message turned into.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// A damage message: the rectangles, their pixels concatenated (in this order, one rectangle
    /// after another), and the guest's own number for the message.
    ///
    /// A **gap** in the number means a whole message was lost on the way: worth counting, never a
    /// reason to stop reading — the next message is framed correctly and the guest's next pass
    /// draws what the lost one would have.
    Damage {
        generation: u32,
        rects: Vec<Rect>,
        pixels: Vec<u8>,
    },
    /// Any other frame: its kind and payload, handed on as they are.
    Frame { kind: u16, payload: Vec<u8> },
}

/// The damage header of one message, as it sits on the wire.
///
/// ```text
///   u32 magic        "HDFD"
///   u32 generation   the guest's number for this message (1, 2, 3, …)
///   u32 rects        how many rectangles follow
///   Rect[rects]      x, y, width, height (little-endian u32 each)
///   u32 header_crc   CRC-32C over everything above
///   u32 pixels_crc   CRC-32C over the pixels that follow the header
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DamageHeader {
    pub generation: u32,
    pub rects: Vec<Rect>,
    pub pixels_crc: u32,
}

impl DamageHeader {
    /// How many bytes this header's rectangles need for their pixels.
    pub fn pixel_bytes(&self) -> usize {
        self.rects.iter().map(|r| r.bytes()).sum()
    }

    /// How many bytes the header itself takes on the wire.
    pub fn len(&self) -> usize {
        12 + self.rects.len() * 16 + 8
    }

    pub fn is_empty(&self) -> bool {
        false
    }

    /// Encode the header (without the frame head), for a guest about to write the message.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.len());
        out.extend_from_slice(&DAMAGE_MAGIC.to_le_bytes());
        out.extend_from_slice(&self.generation.to_le_bytes());
        out.extend_from_slice(&(self.rects.len() as u32).to_le_bytes());
        for rect in &self.rects {
            out.extend_from_slice(&rect.encode());
        }
        let crc = crc32c(&out);
        out.extend_from_slice(&crc.to_le_bytes());
        out.extend_from_slice(&self.pixels_crc.to_le_bytes());
        out
    }

    /// Decode a damage header from the first bytes of a message's payload, answering the header and
    /// how long it is.  `None` when this is not one of ours: a wrong magic, a rectangle count this
    /// channel cannot carry, an empty rectangle, or a header CRC that does not match.
    ///
    /// It needs the header and no more — the pixels come after it (`[`StreamParser`]`).
    pub fn decode(bytes: &[u8]) -> Option<(DamageHeader, usize)> {
        if bytes.len() < 16 {
            return None;
        }
        let at = |i: usize| u32::from_le_bytes(bytes[i..i + 4].try_into().unwrap());
        if at(0) != DAMAGE_MAGIC {
            return None;
        }
        let generation = at(4);
        let count = at(8) as usize;
        if count == 0 || count > MAX_RECTS {
            return None;
        }
        let len = 12 + count * 16 + 8;
        if bytes.len() < len {
            return None;
        }
        let mut rects = Vec::with_capacity(count);
        for i in 0..count {
            let at = 12 + i * 16;
            let rect = Rect {
                x: u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()),
                y: u32::from_le_bytes(bytes[at + 4..at + 8].try_into().unwrap()),
                width: u32::from_le_bytes(bytes[at + 8..at + 12].try_into().unwrap()),
                height: u32::from_le_bytes(bytes[at + 12..at + 16].try_into().unwrap()),
            };
            if rect.is_empty() {
                return None;
            }
            rects.push(rect);
        }
        let header_crc = u32::from_le_bytes(bytes[len - 8..len - 4].try_into().unwrap());
        if header_crc != crc32c(&bytes[..len - 8]) {
            return None;
        }
        let pixels_crc = u32::from_le_bytes(bytes[len - 4..len].try_into().unwrap());
        Some((
            DamageHeader {
                generation,
                rects,
                pixels_crc,
            },
            len,
        ))
    }
}

/// **A damage message, ready to write**: the guest writes it with **one** `writev` (the head, the
/// header and the pixels), which is what keeps a frame one message on the wire.
pub struct DamageMessage {
    pub head: [u8; 6],
    pub header: Vec<u8>,
    pub pixels: Vec<u8>,
}

impl DamageMessage {
    /// Build the message for these rectangles, checksumming the pixels.
    pub fn new(generation: u32, rects: Vec<Rect>, pixels: Vec<u8>) -> DamageMessage {
        let header = DamageHeader {
            generation,
            rects,
            pixels_crc: crc32c(&pixels),
        };
        let body = header.encode();
        let len = (body.len() + pixels.len()) as u32;
        DamageMessage {
            head: [
                (len & 0xff) as u8,
                ((len >> 8) & 0xff) as u8,
                ((len >> 16) & 0xff) as u8,
                ((len >> 24) & 0xff) as u8,
                (KIND_DAMAGE & 0xff) as u8,
                ((KIND_DAMAGE >> 8) & 0xff) as u8,
            ],
            header: body,
            pixels,
        }
    }
}

/// The older damage form: a payload that is exactly four numbers is one rectangle, and its pixels
/// follow the frame with no length of their own.  It is what the C agent sent, and it is understood
/// while it is still the thing running in a guest.
pub fn legacy_rect(payload: &[u8]) -> Option<Rect> {
    if payload.len() != 16 {
        return None;
    }
    Rect::decode(payload)
}

/// **The parser**: bytes in, messages out.
///
/// `next` answers `None` for "not a whole message yet", which on a live channel means **wait**.
/// A message whose header or pixels do not check out is *not* delivered and nothing is thrown
/// away: the parser scans forward for the next message's magic and starts again there, so a lost
/// message costs one message.
#[derive(Default)]
pub struct StreamParser {
    /// The bytes received and not yet dropped, with `pos` the parse position inside them.
    buf: Vec<u8>,
    pos: usize,
    /// How many times the parser had to scan forward for the next boundary.
    resyncs: u64,
    /// How many bytes it skipped doing so.
    skipped: u64,
    /// The largest amount of un-parsed data it ever held.
    high_water: usize,
    /// The last generation delivered, and how many gaps were seen in the numbering.
    last_generation: u32,
    lost_messages: u64,
}

impl StreamParser {
    pub fn new() -> StreamParser {
        StreamParser::default()
    }

    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
        self.high_water = self.high_water.max(self.buf.len() - self.pos);
    }

    pub fn buffered(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// How many times the parser had to find its own way back to a message boundary.
    pub fn resyncs(&self) -> u64 {
        self.resyncs
    }

    /// How many bytes were skipped doing that.
    pub fn skipped(&self) -> u64 {
        self.skipped
    }

    /// How many messages were lost outright (a gap in the guest's own numbering).
    pub fn lost(&self) -> u64 {
        self.lost_messages
    }

    /// The largest amount of un-parsed data this parser ever held.
    pub fn high_water(&self) -> usize {
        self.high_water
    }

    /// **The next whole message**, or `None` when more bytes are needed.
    ///
    /// Named for what it returns rather than for the trait; the trait's [`next`] is the one thing
    /// that calls it, because a stream of messages *is* an iterator and that is how a caller reads it
    /// (`for message in parser.by_ref()`, in `dc-fc-display`'s receive loop).  There is one
    /// implementation and one public way in, so the two cannot drift apart.
    ///
    /// [`next`]: Iterator::next
    fn next_message(&mut self) -> Option<Message> {
        loop {
            match self.try_message() {
                Outcome::Message(message) => return Some(message),
                Outcome::Wait => {
                    self.compact();
                    return None;
                }
                Outcome::NotHere => {
                    self.resync();
                    continue;
                }
            }
        }
    }

    /// One attempt at the current position.
    fn try_message(&mut self) -> Outcome {
        let at = self.pos;
        let have = self.buf.len() - at;
        if have < 6 {
            return Outcome::Wait;
        }
        let len = u32::from_le_bytes(self.buf[at..at + 4].try_into().unwrap());
        let kind = u16::from_le_bytes(self.buf[at + 4..at + 6].try_into().unwrap());

        if kind == KIND_DAMAGE && len != 16 {
            // **The new form**: the length is the header *and* the pixels.
            if len as usize > MAX_DAMAGE as usize {
                return Outcome::NotHere;
            }
            // The header's own size follows from its rectangle count, which is at a fixed offset:
            // so "the header is still arriving" and "this is not a header" are different answers,
            // and only the second one re-synchronises the parse.
            if have < 6 + 12 {
                return Outcome::Wait;
            }
            let count = u32::from_le_bytes(self.buf[at + 14..at + 18].try_into().unwrap()) as usize;
            if count == 0 || count > MAX_RECTS {
                return Outcome::NotHere;
            }
            let header_len = 12 + count * 16 + 8;
            if 6 + header_len > 6 + len as usize {
                return Outcome::NotHere; // the length cannot hold its own header
            }
            if have < 6 + header_len {
                return Outcome::Wait;
            }
            let Some((header, decoded_len)) =
                DamageHeader::decode(&self.buf[at + 6..at + 6 + header_len])
            else {
                return Outcome::NotHere;
            };
            debug_assert_eq!(decoded_len, header_len);
            if header_len + header.pixel_bytes() != len as usize {
                return Outcome::NotHere; // the length and the rectangles disagree
            }
            let total = 6 + len as usize;
            if have < total {
                return Outcome::Wait; // its pixels are still arriving
            }
            let pixels = &self.buf[at + 6 + header_len..at + total];
            if crc32c(pixels) != header.pixels_crc {
                // The message was damaged on the way: nothing is believed, nothing is drawn, and
                // the parser goes looking for the next message — which is why a message lost by
                // the transport costs one message and not the screen.
                return Outcome::NotHere;
            }
            let pixels = pixels.to_vec();
            self.pos += total;
            let generation = header.generation;
            if generation != 0 {
                if self.last_generation != 0 && generation != self.last_generation.wrapping_add(1) {
                    self.lost_messages += 1;
                }
                self.last_generation = generation;
            }
            return Outcome::Message(Message::Damage {
                generation,
                rects: header.rects,
                pixels,
            });
        }

        if kind == KIND_DAMAGE {
            // **The older form**: a 16-byte payload whose pixels follow unannounced.
            if have < 22 {
                return Outcome::Wait;
            }
            let Some(rect) = legacy_rect(&self.buf[at + 6..at + 22]) else {
                return Outcome::NotHere;
            };
            if rect.is_empty() {
                return Outcome::NotHere;
            }
            let total = 22 + rect.bytes();
            if have < total {
                return Outcome::Wait;
            }
            let pixels = self.buf[at + 22..at + total].to_vec();
            self.pos += total;
            return Outcome::Message(Message::Damage {
                generation: 0,
                rects: vec![rect],
                pixels,
            });
        }

        // Every other frame: `dc_vsock`'s own shape, a length that covers its own payload.
        if len > MAX_SMALL || !known_kind(kind) {
            return Outcome::NotHere;
        }
        let total = 6 + len as usize;
        if have < total {
            return Outcome::Wait;
        }
        let payload = self.buf[at + 6..at + total].to_vec();
        self.pos += total;
        Outcome::Message(Message::Frame { kind, payload })
    }

    /// **Find the next message.**  Scan forward for the head of a damage message — the length, the
    /// kind and the magic, in that order — and leave the parse position on it.  A message whose
    /// pixels were damaged is thus *stepped over*: the message after it is still there, whole, and
    /// the bytes that could not be believed are dropped rather than drawn.
    ///
    /// ("The next message's own head" is what has to be looked for, not the header's magic alone: a
    /// magic found in the middle of a message is at the wrong offset, and the length read there is
    /// nonsense — the parse would then be *off*, which is the one thing this must never be.)
    fn resync(&mut self) {
        self.resyncs += 1;
        let magic = DAMAGE_MAGIC.to_le_bytes();
        let at = self.pos;
        let mut scan = at + 1;
        let mut found = None;
        while scan + 10 <= self.buf.len() {
            if self.buf[scan + 4..scan + 6] == KIND_DAMAGE.to_le_bytes()
                && self.buf[scan + 6..scan + 10] == magic
            {
                let len = u32::from_le_bytes(self.buf[scan..scan + 4].try_into().unwrap());
                if len as usize <= MAX_DAMAGE as usize {
                    found = Some(scan);
                    break;
                }
            }
            scan += 1;
        }
        match found {
            Some(scan) => {
                self.skipped += (scan - at) as u64;
                self.pos = scan;
            }
            None => {
                // Nothing here can begin a message: keep only the bytes that could be the start of
                // one (the head of a message is ten bytes before its pixels, so the last nine are
                // kept) and let the rest go.
                let keep = 9.min(self.buf.len() - at);
                self.skipped += (self.buf.len() - at - keep) as u64;
                self.buf.truncate(self.buf.len() - keep);
            }
        }
    }

    /// Drop what has already been parsed, so a long run does not hold every byte it ever saw.
    fn compact(&mut self) {
        if self.pos == 0 {
            return;
        }
        if self.pos == self.buf.len() {
            self.buf.clear();
            self.pos = 0;
            return;
        }
        if self.pos >= 64 * 1024 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
    }
}

impl Iterator for StreamParser {
    type Item = Message;

    /// The next whole message, or `None` when more bytes are needed (see
    /// [`StreamParser::next_message`], which is the implementation).
    fn next(&mut self) -> Option<Message> {
        self.next_message()
    }
}

/// Is this a kind the display channel uses?
///
/// The list is the channel's own (`crate::KIND_*`), and it is what says "this frame is not ours" —
/// a kind that is missing here is a message the guest **never sees**.  `KIND_REFRESH` is the host
/// asking for the whole screen and `KIND_WHEEL` is the wheel: both are host-to-guest, and both were
/// once missing from this list, which is why a window that had just appeared kept its old picture
/// and why the wheel never reached the guest.
fn known_kind(kind: u16) -> bool {
    matches!(
        kind,
        KIND_SURFACE
            | KIND_RESIZE
            | crate::KIND_KEY
            | crate::KIND_MOUSE
            | crate::KIND_CURSOR
            | crate::KIND_POWER
            | crate::KIND_WHEEL
            | crate::KIND_REPORT
            | crate::KIND_REFRESH
    )
}

/// **CRC-32C** (Castagnoli, the polynomial every x86 has in silicon).  The hardware instruction is
/// used when the CPU has it — a whole screen then costs about a millisecond — and the table
/// otherwise, so the number is the same on both ends and in a test.
pub fn crc32c(bytes: &[u8]) -> u32 {
    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("sse4.2") {
            // SAFETY: the feature was just detected.
            return unsafe { crc32c_hw(bytes) };
        }
    }
    crc32c_soft(bytes)
}

/// The table-driven CRC-32C, for a CPU without the instruction (and for the tests' own vectors).
fn crc32c_soft(bytes: &[u8]) -> u32 {
    use std::sync::OnceLock;
    static TABLE: OnceLock<[u32; 256]> = OnceLock::new();
    let table = TABLE.get_or_init(|| {
        let mut table = [0u32; 256];
        for (i, entry) in table.iter_mut().enumerate() {
            let mut crc = i as u32;
            for _ in 0..8 {
                let mask = (crc & 1).wrapping_neg();
                crc = (crc >> 1) ^ (0x82F6_3B78 & mask);
            }
            *entry = crc;
        }
        table
    });
    let mut crc = 0xFFFF_FFFFu32;
    for byte in bytes {
        crc = (crc >> 8) ^ table[((crc ^ *byte as u32) & 0xff) as usize];
    }
    !crc
}

/// The same number, eight bytes at a time, through SSE4.2's `crc32`.
#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "sse4.2")]
unsafe fn crc32c_hw(bytes: &[u8]) -> u32 {
    use std::arch::x86_64::{_mm_crc32_u64, _mm_crc32_u8};
    let mut crc = !0u32 as u64;
    let mut chunks = bytes.chunks_exact(8);
    for chunk in &mut chunks {
        let word = u64::from_le_bytes(chunk.try_into().unwrap());
        crc = _mm_crc32_u64(crc, word);
    }
    let mut tail = crc as u32;
    for byte in chunks.remainder() {
        tail = _mm_crc32_u8(tail, *byte);
    }
    !tail
}

/// The screen's description, for a guest that has just connected: kept beside the parser so both
/// ends of the channel build it the same way.
pub fn surface_message(surface: Surface) -> Vec<u8> {
    dc_vsock::Frame::new(KIND_SURFACE, surface.encode()).encode()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rect(x: u32, y: u32, w: u32, h: u32) -> Rect {
        Rect {
            x,
            y,
            width: w,
            height: h,
        }
    }

    /// A message as the guest writes it: head, header, pixels.
    pub fn wire(generation: u32, rects: Vec<Rect>, pixels: Vec<u8>) -> Vec<u8> {
        let message = DamageMessage::new(generation, rects, pixels);
        let mut out = message.head.to_vec();
        out.extend_from_slice(&message.header);
        out.extend_from_slice(&message.pixels);
        out
    }

    fn pixels_of(rects: &[Rect], byte: u8) -> Vec<u8> {
        vec![byte; rects.iter().map(|r| r.bytes()).sum()]
    }

    #[test]
    fn a_damage_message_with_its_pixels_is_read_back_exactly() {
        let rects = vec![rect(0, 10, 4, 2), rect(2, 40, 3, 1)];
        let pixels: Vec<u8> = (0..pixels_of(&rects, 0).len()).map(|i| i as u8).collect();
        let mut parser = StreamParser::new();
        parser.push(&wire(7, rects.clone(), pixels.clone()));
        match parser.next() {
            Some(Message::Damage {
                generation,
                rects: got,
                pixels: got_pixels,
            }) => {
                assert_eq!(generation, 7);
                assert_eq!(got, rects);
                assert_eq!(got_pixels, pixels);
            }
            other => panic!("one damage message, not {other:?}"),
        }
        assert_eq!(parser.buffered(), 0);
        assert!(parser.next().is_none());
        assert_eq!(parser.resyncs(), 0);
        assert_eq!(parser.lost(), 0);
    }

    #[test]
    fn a_message_that_arrives_in_pieces_is_waited_for_and_never_abandoned() {
        let rects = vec![rect(0, 0, 8, 8)];
        let pixels = pixels_of(&rects, 9);
        let bytes = wire(1, rects, pixels);
        let mut parser = StreamParser::new();
        for (i, byte) in bytes.iter().enumerate() {
            parser.push(&[*byte]);
            let message = parser.next();
            if i + 1 < bytes.len() {
                assert!(message.is_none(), "a partial message is not a message");
            } else {
                assert!(matches!(message, Some(Message::Damage { .. })));
            }
        }
        assert_eq!(parser.resyncs(), 0, "a slow delivery is not a lost frame");
    }

    #[test]
    fn a_message_whose_bytes_were_damaged_is_refused_and_the_next_one_is_read() {
        // The middle of the pixels is lost (a torn band, a device that dropped bytes) while the
        // next message arrives whole: the damaged one must not be drawn, and the next must be read
        // exactly — one lost message, not a lost channel.
        let rects = vec![rect(0, 0, 4, 100)];
        let pixels = pixels_of(&rects, 1);
        let mut a = wire(1, rects.clone(), pixels.clone());
        let b = wire(2, rects.clone(), pixels_of(&rects, 2));
        let cut = a.len() - 1000;
        a.truncate(cut);
        let mut parser = StreamParser::new();
        parser.push(&a);
        parser.push(&b);
        // The parser first believes `a` (its header is intact and `b`'s bytes cover its length),
        // then the pixels' CRC says no, and it finds `b`'s own header inside those bytes.
        let mut found = Vec::new();
        for _ in 0..4 {
            match parser.next() {
                Some(Message::Damage {
                    generation, pixels, ..
                }) => found.push((generation, pixels[0])),
                Some(other) => panic!("{other:?}"),
                None => break,
            }
        }
        assert_eq!(found, vec![(2, 2)], "only the second message is drawn");
        assert!(parser.resyncs() >= 1, "the damaged message was noticed");
    }

    #[test]
    fn a_lost_message_is_counted_from_the_guests_own_numbering() {
        let rects = vec![rect(0, 0, 2, 2)];
        let pixels = pixels_of(&rects, 5);
        let mut parser = StreamParser::new();
        for generation in [1u32, 2] {
            parser.push(&wire(generation, rects.clone(), pixels.clone()));
            assert!(matches!(parser.next(), Some(Message::Damage { .. })));
        }
        assert_eq!(parser.lost(), 0);
        // A message that never arrives (the numbers jump) is counted, and reading carries on.
        parser.push(&wire(4, rects.clone(), pixels.clone()));
        assert!(matches!(
            parser.next(),
            Some(Message::Damage { generation: 4, .. })
        ));
        assert_eq!(parser.lost(), 1);
    }

    #[test]
    fn a_run_of_pixel_bytes_that_looks_like_a_header_is_refused() {
        let mut header = Vec::new();
        header.extend_from_slice(&DAMAGE_MAGIC.to_le_bytes());
        header.extend_from_slice(&3u32.to_le_bytes());
        header.extend_from_slice(&1u32.to_le_bytes());
        header.extend_from_slice(&rect(0, 0, 2, 2).encode());
        header.extend_from_slice(&0xDEAD_BEEFu32.to_le_bytes());
        header.extend_from_slice(&0x1234_5678u32.to_le_bytes());
        assert!(
            DamageHeader::decode(&header).is_none(),
            "a header whose CRC does not check is not a header"
        );
    }

    #[test]
    fn a_header_that_claims_more_pixels_than_it_has_is_refused() {
        let rect = rect(0, 0, 1000, 1000); // 4 MB of pixels
        let header = DamageHeader {
            generation: 1,
            rects: vec![rect],
            pixels_crc: 0,
        }
        .encode();
        let len = (header.len() + 16) as u32; // claims 16 bytes of pixels, not 4 MB
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&len.to_le_bytes());
        bytes.extend_from_slice(&KIND_DAMAGE.to_le_bytes());
        bytes.extend_from_slice(&header);
        bytes.extend_from_slice(&[0u8; 16]);
        let mut parser = StreamParser::new();
        parser.push(&bytes);
        assert!(parser.next().is_none(), "not a message of ours");
        assert!(parser.resyncs() >= 1);
    }

    #[test]
    fn the_older_single_rectangle_is_still_understood() {
        let rect = rect(1, 2, 3, 4);
        let mut bytes = dc_vsock::Frame::new(KIND_DAMAGE, rect.encode().to_vec()).encode();
        bytes.extend_from_slice(&[7u8; 3 * 4 * 4]);
        let mut parser = StreamParser::new();
        parser.push(&bytes);
        match parser.next() {
            Some(Message::Damage { rects, pixels, .. }) => {
                assert_eq!(rects, vec![rect]);
                assert_eq!(pixels.len(), 3 * 4 * 4);
            }
            other => panic!("the older form is a rectangle: {other:?}"),
        }
        assert_eq!(parser.resyncs(), 0);
    }

    #[test]
    fn a_frame_that_is_not_a_damage_is_passed_through() {
        let bytes = surface_message(Surface {
            width: 8,
            height: 4,
            format: 0x2000_0000,
        });
        let mut parser = StreamParser::new();
        parser.push(&bytes);
        match parser.next() {
            Some(Message::Frame { kind, payload }) => {
                assert_eq!(kind, KIND_SURFACE);
                assert_eq!(Surface::decode(&payload).unwrap().width, 8);
            }
            other => panic!("a surface frame: {other:?}"),
        }
    }

    /// **Every kind the host sends is a kind the parser knows.**  A kind missing from the parser's
    /// list is not an error and not a log: the frame is stepped over and the guest never sees it.
    /// That is how a wheel that reaches the host's `wheel` and never the guest looks — from the
    /// window, exactly like a wheel that does not exist.
    #[test]
    fn every_host_to_guest_kind_reaches_the_guest() {
        let small = |kind: u16, payload: &[u8]| {
            let mut bytes = vec![
                (payload.len() & 0xff) as u8,
                ((payload.len() >> 8) & 0xff) as u8,
                ((payload.len() >> 16) & 0xff) as u8,
                ((payload.len() >> 24) & 0xff) as u8,
                (kind & 0xff) as u8,
                ((kind >> 8) & 0xff) as u8,
            ];
            bytes.extend_from_slice(payload);
            bytes
        };
        for kind in [
            KIND_SURFACE,
            KIND_RESIZE,
            crate::KIND_KEY,
            crate::KIND_MOUSE,
            crate::KIND_CURSOR,
            crate::KIND_POWER,
            crate::KIND_WHEEL,
            crate::KIND_REPORT,
            crate::KIND_REFRESH,
        ] {
            let mut parser = StreamParser::new();
            parser.push(&small(kind, &[1, 2, 3, 4]));
            match parser.next() {
                Some(Message::Frame { kind: seen, .. }) => assert_eq!(seen, kind, "kind {kind}"),
                other => panic!("kind {kind} did not reach the guest: {other:?}"),
            }
            assert_eq!(parser.resyncs(), 0, "kind {kind} was treated as noise");
        }
    }

    #[test]
    fn two_messages_in_one_read_are_two_messages() {
        let rects = vec![rect(0, 0, 2, 2)];
        let pixels = pixels_of(&rects, 3);
        let mut bytes = wire(1, rects.clone(), pixels.clone());
        bytes.extend(wire(2, rects, pixels));
        let mut parser = StreamParser::new();
        parser.push(&bytes);
        assert!(matches!(
            parser.next(),
            Some(Message::Damage { generation: 1, .. })
        ));
        assert!(matches!(
            parser.next(),
            Some(Message::Damage { generation: 2, .. })
        ));
        assert!(parser.next().is_none());
        assert_eq!(parser.buffered(), 0);
    }

    #[test]
    fn the_hardware_and_the_software_crc_agree() {
        // The published CRC-32C check value, and the same bytes through both paths.
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
        assert_eq!(crc32c_soft(b"123456789"), 0xE306_9283);
        let mut bytes = Vec::new();
        for i in 0..100_000u32 {
            bytes.extend_from_slice(&i.to_le_bytes());
        }
        assert_eq!(crc32c(&bytes), crc32c_soft(&bytes));
    }

    #[test]
    fn a_long_stream_never_holds_more_than_the_message_it_is_reading() {
        let rects = vec![rect(0, 0, 64, 64)];
        let pixels = pixels_of(&rects, 4);
        let mut parser = StreamParser::new();
        for generation in 1..50u32 {
            parser.push(&wire(generation, rects.clone(), pixels.clone()));
            assert!(parser.next().is_some());
        }
        assert!(
            parser.high_water() < 64 * 1024,
            "the parser does not hoard: {} bytes",
            parser.high_water()
        );
        assert_eq!(parser.lost(), 0);
    }
}
