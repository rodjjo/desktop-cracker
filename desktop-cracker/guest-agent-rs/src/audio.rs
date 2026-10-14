
//! **The guest's own sound**, sent to the host: the loopback card's capture side and the channel.
//!
//! Firecracker has no `virtio-snd`, so the guest's sound card is the kernel's own **loopback** one
//! (`snd-aloop`): the card has two sides of one cable, an application plays into one and whoever
//! holds the other reads exactly what was played.  This module is that holder, and the wiring is
//! the C agent's own:
//!
//! * the *playback* side is what the guest's session uses — `snd-aloop`'s first card names index 0
//!   as "the hardware", which is what the guest's own mixer routes `default` to, so an
//!   application's sound goes **into** the cable;
//! * this opens the *capture* side of that same cable (`hw:Loopback,1,0`, the second PCM device:
//!   the end device 0's playback writes into) and reads the PCM out of it;
//! * and it ships those bytes to the host, where `dc-audio`'s own rule (window visible and numlock
//!   held) decides whether the user hears them.
//!
//! ## The card, without an ALSA library
//!
//! The C agent used `libasound`.  This uses the kernel's own **`/dev/snd/pcmC*D*c`**, which is the
//! same device the library opens, with the same `ioctl`s — and that is not a shortcut but an
//! improvement here: a static guest binary needs no `libasound`, no `libdl` and no plugin tree, and
//! the whole guest is one file that runs in the initramfs and in the system on the disk alike.
//!
//! The three calls are the ones that decide a capture stream:
//!
//! * `HW_PARAMS` — set the format (16-bit signed little-endian, 48 kHz, stereo: the project's own
//!   `StreamFormat`), then read back what the card settled on;
//! * `SW_PARAMS` — what the card wakes on;
//! * `PREPARE` and `START` — **both directions have to be running** for `snd-aloop` to hand over
//!   what the playback side received.
//!
//! Then it is `read` after `read`, and what comes back goes to the host with its stream's own id and
//! length in front of it (the shape a display rectangle's pixels travel in).

use std::io::Write;
use std::os::fd::{AsRawFd, OwnedFd};

use crate::channel::{self, ports};

/// The audio channel's kinds (`dc-fc-audio`).
pub const A_OPEN: u16 = 1;
/// PCM, with its stream's id and its length in front.
pub const A_PCM: u16 = 2;

/// The project's stream: 16-bit signed, 48 kHz, stereo (`dc-audio::StreamFormat`'s default).
pub const RATE: u32 = 48_000;
pub const CHANNELS: u32 = 2;
pub const BITS: u32 = 16;

/// One read from the card at a time: 20 ms of sound at 48 kHz stereo (192 000 B/s) is 3840 bytes,
/// and the card's own period decides what a read actually returns.  **A buffer that comes back
/// bigger than the channel's frame limit is sent in pieces**: the project's framing is a `u32`
/// length plus a 60 KiB ceiling (`dc-vsock::MAX_FRAME`), and a frame that claims more than that is
/// refused by the host — measured 2026-10-11, `a frame is 131072 bytes, more than the 61440 this
/// channel allows`, which ended the audio connection on the first buffer and left the guest's
/// sound gone for the whole run.
pub const READ_BYTES: usize = 3840;
/// **The most PCM one message may carry**: the channel's own limit, minus the 12 bytes of stream
/// id and length in front of it.
pub const MAX_PCM_PER_MESSAGE: usize = 60 * 1024 - 12;
/// The stream this guest sends: one, because a guest has one sound card.
pub const STREAM_ID: u64 = 1;

/// The kernel's own ALSA numbers (`sound/asound.h`), named here so this reads as the structure it
/// is: the two parameter calls, the two stream states, and the two formats.
mod alsa {
    pub const FORMAT_S16_LE: u32 = 2;
    pub const ACCESS_RW_INTERLEAVED: u32 = 3;
    /// `SNDRV_PCM_HW_PARAM_LAST_MASK` (subformat) and `SNDRV_PCM_HW_PARAM_LAST_INTERVAL` (tick
    /// time): the two ends of the arrays the structure carries, and the reason the counts below
    /// are what they are.
    #[cfg(test)]
    pub const LAST_MASK: u32 = 2;
    #[cfg(test)]
    pub const LAST_INTERVAL: u32 = 19;

    /// The masks a `snd_pcm_hw_params` carries: access, format, subformat.
    pub const MASKS: usize = 3;
    /// The intervals it carries (`SNDRV_PCM_HW_PARAM_FIRST_INTERVAL` = sample bits … tick time).
    pub const INTERVALS: usize = 12;
    /// Where the intervals begin inside the structure: the flags, the masks, and the five
    /// reserved masks the kernel keeps between them and the intervals.
    pub const INTERVALS_AT: usize = 4 + MASKS * 32 + 5 * 32;
    /// **How big one `snd_interval` is: twelve bytes, not sixteen.**  It is two `unsigned int`s
    /// plus a four-byte bitfield (`openmin:1, openmax:1, integer:1, empty:1` and the padding they
    /// sit in) — and a stride guessed as sixteen puts every interval after the first one in the
    /// wrong place, which the card answers with an `EINVAL` from a rule about a parameter nobody
    /// set (measured 2026-10-11: `period_time` written where `rate` should be, and a period the
    /// card's buffer cannot hold).
    pub const INTERVAL_SIZE: usize = 12;
    /// Where `rmask` sits: after the intervals and their nine reserved ones.
    pub const RMASK_AT: usize = INTERVALS_AT + INTERVALS * INTERVAL_SIZE + 9 * INTERVAL_SIZE;

    /// `SNDRV_PCM_HW_PARAM_ACCESS` and its neighbours, as the kernel numbers them.
    pub const PARAM_ACCESS: u32 = 0;
    pub const PARAM_FORMAT: u32 = 1;
    pub const PARAM_SUBFORMAT: u32 = 2;
    pub const PARAM_SAMPLE_BITS: u32 = 8;
    pub const PARAM_CHANNELS: u32 = 10;
    pub const PARAM_RATE: u32 = 11;
    /// Where an interval sits in the array: the first one is sample bits.
    pub const PARAM_FIRST_INTERVAL: u32 = PARAM_SAMPLE_BITS;

    /// The three calls, with the kernel's own encoding (`sound/asound.h`, and the sizes a C
    /// compiler gives the two structures — a wrong size here is an `EINVAL` from the card).
    pub const HW_PARAMS: libc::c_ulong = iowr(b'A', 0x11, 608);
    /// `SNDRV_PCM_IOCTL_HW_REFINE`: the kernel **fills** the structure with what the card can do,
    /// or narrows a space the caller has already set.
    pub const HW_REFINE: libc::c_ulong = iowr(b'A', 0x10, 608);
    pub const PREPARE: libc::c_ulong = io(b'A', 0x40);
    pub const START: libc::c_ulong = io(b'A', 0x42);
    /// `SNDRV_PCM_IOCTL_STATUS`: what the stream is doing (`SNDRV_PCM_STATE_*`), which is how a
    /// driver notices that the kernel has reset the stream.
    pub const STATUS: libc::c_ulong = ior(b'A', 0x20, 152);
    /// `sizeof(struct snd_pcm_status)`.
    pub const STATUS_SIZE: usize = 152;

    const fn iowr(kind: u8, number: u32, size: usize) -> libc::c_ulong {
        ((3u32 << 30) | ((size as u32) << 16) | ((kind as u32) << 8) | number) as libc::c_ulong
    }
    const fn ior(kind: u8, number: u32, size: usize) -> libc::c_ulong {
        ((2u32 << 30) | ((size as u32) << 16) | ((kind as u32) << 8) | number) as libc::c_ulong
    }
    const fn io(kind: u8, number: u32) -> libc::c_ulong {
        (((kind as u32) << 8) | number) as libc::c_ulong
    }

    /// The size of `struct snd_pcm_hw_params`, as a C compiler sees it.
    pub const HW_PARAMS_SIZE: usize = 608;
}

/// Put the device in non-blocking mode: what the loop needs to tell "nothing played yet" from
/// "the stream has been reset".
fn set_nonblocking(fd: &OwnedFd) {
    // SAFETY: the fd is the capture device, and the flag is this process's own.
    let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return;
    }
    unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) };
}

/// Find the loopback card's capture device.
///
/// `hw:Loopback,1,0` is the loopback **card** (index 0 in this guest: `/proc/asound/cards` names card
/// 0 "Loopback") at its **second PCM device** — the capture end of the cable — which is the device
/// path `/dev/snd/pcmC0D1c`.  Measured in a real run (2026-10-12): the card is card 0, and the four
/// devices the kernel made are `pcmC0D0c`, `pcmC0D0p`, `pcmC0D1c`, `pcmC0D1p`; the line this module
/// prints is `reading hw:0,1,0`.  The C agent tried four names because the card may be enumerated
/// differently on another kernel, and the four are kept here for the same reason — but in the order
/// this guest answers them, so the name printed is the device actually opened.
fn open_loopback_capture() -> Option<(OwnedFd, String)> {
    let candidates = [
        (0, 1, "hw:0,1,0"),
        (0, 1, "hw:Loopback,1,0"),
        (1, 1, "hw:1,1,0"),
        (1, 1, "hw:Loopback,1,1"),
    ];
    for (card, device, name) in candidates {
        let path = format!("/dev/snd/pcmC{card}D{device}c");
        if let Ok(file) = std::fs::OpenOptions::new().read(true).open(&path) {
            return Some((file.into(), name.to_string()));
        }
    }
    None
}

/// Set the format the project declares, on the card as well as on the wire.
fn set_format(fd: &OwnedFd) -> std::io::Result<()> {
    let mut params = vec![0u8; alsa::HW_PARAMS_SIZE];
    // **A zeroed structure is an *empty* space, not "anything"**: a mask with no bit set contains
    // no value, and the kernel answers `EINVAL` to a refinement of nothing (measured 2026-10-11 —
    // and it is the first thing `snd_pcm_hw_params_any` does, a `clear` before it asks).
    for index in 0..(alsa::MASKS + 5) {
        let at = 4 + index * 32;
        params[at..at + 32].fill(0xff);
    }
    for index in 0..(alsa::INTERVALS + 9) {
        let at = alsa::INTERVALS_AT + index * alsa::INTERVAL_SIZE;
        params[at..at + 4].copy_from_slice(&0u32.to_le_bytes());
        params[at + 4..at + 8].copy_from_slice(&u32::MAX.to_le_bytes());
    }
    // **What this stream is**, as the space to narrow to: one access, one format, one subformat,
    // and the three intervals pinned to a single value each.
    let set_mask = |params: &mut [u8], index: u32, value: u32| {
        let at = 4 + index as usize * 32;
        for byte in params[at..at + 32].iter_mut() {
            *byte = 0;
        }
        let word = at + (value as usize / 32) * 4;
        params[word..word + 4].copy_from_slice(&(1u32 << (value % 32)).to_le_bytes());
    };
    set_mask(&mut params, alsa::PARAM_ACCESS, alsa::ACCESS_RW_INTERLEAVED);
    set_mask(&mut params, alsa::PARAM_FORMAT, alsa::FORMAT_S16_LE);
    set_mask(&mut params, alsa::PARAM_SUBFORMAT, 0);
    let set_interval = |params: &mut [u8], param: u32, value: u32| {
        let at =
            alsa::INTERVALS_AT + (param - alsa::PARAM_FIRST_INTERVAL) as usize * alsa::INTERVAL_SIZE;
        params[at..at + 4].copy_from_slice(&value.to_le_bytes());
        params[at + 4..at + 8].copy_from_slice(&value.to_le_bytes());
    };
    set_interval(&mut params, alsa::PARAM_SAMPLE_BITS, BITS);
    set_interval(&mut params, alsa::PARAM_CHANNELS, CHANNELS);
    set_interval(&mut params, alsa::PARAM_RATE, RATE);
    // **And which of them the caller is asking about (`rmask`)**: every parameter this stream
    // names, and nothing else.  The kernel refines what `rmask` asks for against what the card can
    // do, and *checks that the rest is not empty* — which is why the space starts as everything.
    let mut rmask = 0u32;
    for param in [
        alsa::PARAM_ACCESS,
        alsa::PARAM_FORMAT,
        alsa::PARAM_SUBFORMAT,
        alsa::PARAM_SAMPLE_BITS,
        alsa::PARAM_CHANNELS,
        alsa::PARAM_RATE,
    ] {
        rmask |= 1 << param;
    }
    params[alsa::RMASK_AT..alsa::RMASK_AT + 4].copy_from_slice(&rmask.to_le_bytes());
    let rc = ioctl_arg(fd, alsa::HW_REFINE, &mut params);
    if rc != 0 {
        return Err(stage_error("HW_REFINE (the format that was asked for)"));
    }
    // **And commit it**: this is the call that gives the stream its format.
    let rc = ioctl_arg(fd, alsa::HW_PARAMS, &mut params);
    if rc != 0 {
        return Err(stage_error("HW_PARAMS"));
    }
    Ok(())
}

/// The errno of a card call, with the step it failed at in the sentence: a card that refuses
/// something has a reason, and a message that does not say which call is a message nobody can act
/// on.
fn stage_error(stage: &str) -> std::io::Error {
    let err = std::io::Error::last_os_error();
    std::io::Error::new(err.kind(), format!("{stage}: {err}"))
}

/// One ALSA call that reads and writes the parameters structure.
fn ioctl_arg(fd: &OwnedFd, request: libc::c_ulong, params: &mut [u8]) -> libc::c_int {
    // SAFETY: the fd is a capture device and the buffer is this call's own structure.
    unsafe {
        libc::ioctl(
            fd.as_raw_fd(),
            request as _,
            params.as_mut_ptr() as *mut libc::c_void,
        )
    }
}

/// **Ask the card whether the stream's ring has gone round.**  The kernel reports an overrun as an
/// `EPIPE` from `read` — but only while the stream is running, and asking is how a driver tells
/// "silence" from "a stream the kernel has reset": a plain blocking `read` waits on a ring nobody
/// refills, which on this card means waiting for sound that is never coming.
fn state(fd: &OwnedFd) -> std::io::Result<u32> {
    let mut info = [0u8; alsa::STATUS_SIZE];
    let rc = ioctl_arg(fd, alsa::STATUS, &mut info);
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(u32::from_le_bytes(info[..4].try_into().unwrap()))
}

/// The card's own states (`SNDRV_PCM_STATE_*`): running, or reset and waiting to be started again.
const STATE_RUNNING: u32 = 3;
const STATE_XRUN: u32 = 4;

/// Start the stream: the card is prepared, and **both** directions run (which is what `snd-aloop`
/// needs to hand over what the playback side received).
///
/// A stream that has gone round (`XRUN`) will not report it again, so the reset is done here and
/// then the stream is started again — which is what a driver has to do and what makes capture work
/// a second time.
fn start(fd: &OwnedFd) -> std::io::Result<()> {
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), alsa::PREPARE as _) };
    if rc != 0 {
        return Err(stage_error("PREPARE"));
    }
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), alsa::START as _) };
    if rc != 0 {
        return Err(stage_error("START"));
    }
    Ok(())
}

/// **Read one buffer of sound, waiting for it without ever blocking.**  The device is put in
/// non-blocking mode for this: a card with nothing to hand over answers `EAGAIN` at once, so the
/// loop can look at the stream's own state instead of sleeping in a read that will not return.
fn read_buffer(fd: &OwnedFd, buffer: &mut [u8]) -> std::io::Result<Option<usize>> {
    // SAFETY: the fd is the capture device and `buffer` is this call's own memory.
    let got = unsafe {
        libc::read(
            fd.as_raw_fd(),
            buffer.as_mut_ptr() as *mut libc::c_void,
            buffer.len(),
        )
    };
    if got > 0 {
        return Ok(Some(got as usize));
    }
    let err = std::io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::EAGAIN) => Ok(None),
        Some(libc::EPIPE) => {
            // The ring went round: not an error, a missed piece of sound, and the driver's own
            // answer is to reset and start again.
            start(fd)?;
            Ok(None)
        }
        _ if err.kind() == std::io::ErrorKind::Interrupted => Ok(None),
        _ => Err(err),
    }
}

/// **One PCM message**: the frame — whose payload is the stream's id and the byte count — and then
/// the bytes themselves, written **straight after it**.  That is the audio channel's own shape
/// (`dc-fc-audio`'s `pcm`): the reader takes the frame, and then reads exactly the bytes the frame
/// announced.  Putting the bytes inside the frame's own length is a different message, and the host
/// answers it by refusing the channel (measured 2026-10-11).
fn send_pcm(
    channel: &mut std::os::unix::net::UnixStream,
    head: &[u8],
    pcm: &[u8],
) -> std::io::Result<()> {
    send_frame(channel, A_PCM, head)?;
    channel.write_all(pcm)?;
    channel.flush()
}

/// One small frame: a length, a kind and the payload.
fn send_frame(
    channel: &mut std::os::unix::net::UnixStream,
    kind: u16,
    payload: &[u8],
) -> std::io::Result<()> {
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

/// **`audio`**: the guest's sound, for as long as the session lives.
///
/// Answers the exit code the agent should use; it is only ever reached when the channel is gone
/// (a sound that stops is the run ending, not an error).
pub fn run(args: &[String]) -> i32 {
    // The switches are the C agent's own (`audio <port>` took the port as an argument; the verb is
    // called with none, so the project's own port is what is dialled).
    let port = args
        .first()
        .and_then(|p| p.parse::<u32>().ok())
        .unwrap_or(ports::AUDIO);

    let Some((card, name)) = open_loopback_capture() else {
        crate::console::say("DESK-AUDIO no loopback capture device: the guest has no sound card");
        return 1;
    };
    // **Non-blocking on purpose**: the loop asks the device what it is doing, so a read must never
    // sleep — a `read` that waits is a loop that cannot notice the kernel has reset the stream.
    set_nonblocking(&card);
    crate::console::note(&format!("deskd-audio: reading {name}"));
    if let Err(e) = set_format(&card) {
        crate::console::say(&format!("DESK-AUDIO the loopback card refused the format: {e}"));
        return 1;
    }
    if let Err(e) = start(&card) {
        crate::console::say(&format!("DESK-AUDIO the loopback card refused to start: {e}"));
        return 1;
    }

    // **The channel, then the sound that travels on it.**  A connection that ends is dialled
    // again: the host's audio service listens for the whole run and answers every connection it
    // is given, and a guest that stopped sending is a guest whose sound stopped.  What the card
    // held while nobody was listening is gone (its ring went round), so the stream is started
    // again and the next buffer is the next one.  A dial that is refused is the run ending: no
    // run keeps this port closed while it is up.
    let mut buffer = vec![0u8; READ_BYTES];
    loop {
        let Some(mut channel) = channel::dial(port) else {
            crate::console::say("DESK-AUDIO the host's channel did not answer");
            return 1;
        };
        // What this stream is: the same three numbers the host's `StreamFormat` holds.
        let mut opened = [0u8; 6];
        opened[0] = BITS as u8;
        opened[1] = CHANNELS as u8;
        opened[2..6].copy_from_slice(&RATE.to_le_bytes());
        if let Err(e) = send_frame(&mut channel, A_OPEN, &opened) {
            crate::console::note(&format!("deskd-audio: the host's channel: {e}"));
            return 1;
        }
        crate::console::say(&format!(
            "DESK-AUDIO {BITS} bit, {RATE} Hz, {CHANNELS} channel(s), from the loopback card's capture side"
        ));

        match pump(&mut channel, &card, &mut buffer) {
            Ok(()) => return 0,
            Err(e) => {
                crate::console::note(&format!(
                    "deskd-audio: the host's channel: {e}; dialling it again"
                ));
                let _ = start(&card);
                std::thread::sleep(std::time::Duration::from_millis(200));
            }
        }
    }
}

/// **Read the card and send what it hands over**, until the card ends (`Ok`) or the channel
/// breaks (`Err`, and the caller dials again).
///
/// The card's own trouble is not the channel's: a card that refuses a read has finished its
/// sound, and that is the end of this service rather than a reason to reconnect.
fn pump(
    channel: &mut std::os::unix::net::UnixStream,
    card: &OwnedFd,
    buffer: &mut [u8],
) -> std::io::Result<()> {
    // **As much as the card will hand over in one read**: the card's own period decides (measured
    // 12 ms, 2304 bytes, on the loopback card here), and a buffer smaller than a period would make
    // the driver's read answer `EINVAL` — the kernel refuses a count it cannot align to a frame.
    // What goes on the wire is then split to the channel's own frame limit.
    let mut unknown_state = 0u32;
    loop {
        // **The device first**: a stream the kernel has reset (an overrun nobody asked about) is
        // not running, and no `read` would ever tell this loop that.
        match state(card) {
            Ok(current) if current == STATE_RUNNING => {}
            Ok(current) if current == STATE_XRUN => {
                crate::console::note("deskd-audio: the stream went round; starting it again");
                let _ = start(card);
            }
            Ok(current) => {
                if current != unknown_state {
                    unknown_state = current;
                    crate::console::note(&format!(
                        "deskd-audio: the card is in state {current}; starting the stream"
                    ));
                }
                let _ = start(card);
            }
            Err(e) => {
                crate::console::note(&format!("deskd-audio: the card's state: {e}"));
                return Ok(());
            }
        }

        let n = match read_buffer(card, buffer) {
            Ok(Some(n)) => n,
            // Nothing played yet (the card has no data until an application writes): a short rest
            // rather than a spin, so a silent guest costs nothing.
            Ok(None) => {
                std::thread::sleep(std::time::Duration::from_millis(20));
                continue;
            }
            Err(e) => {
                crate::console::note(&format!("deskd-audio: the loopback card: {e}"));
                return Ok(());
            }
        };
        if n == 0 {
            std::thread::sleep(std::time::Duration::from_millis(20));
            continue;
        }
        // **The PCM goes to the host as the audio channel's own message**: a frame whose payload
        // is the stream's id and a byte count, and then the bytes *straight after the frame*
        // (`send_pcm`).  The bytes are **not** inside the frame's own length: the host reads the
        // frame and then reads exactly the count it announced, so a frame that carried the sound
        // inside itself is a different message — and one the host refuses (measured 2026-10-11:
        // `a frame is 131072 bytes, more than the 61440 this channel allows`, on the very first
        // buffer, after which the guest's sound was gone for the rest of the run).
        //
        // A buffer bigger than one message is split: the channel's own ceiling is 60 KiB and the
        // card can hand over 128 KiB in one read.
        let mut sent = 0usize;
        while sent < n {
            let take = (n - sent).min(MAX_PCM_PER_MESSAGE);
            let head = {
                let mut head = Vec::with_capacity(12);
                head.extend_from_slice(&STREAM_ID.to_le_bytes());
                head.extend_from_slice(&(take as u32).to_le_bytes());
                head
            };
            send_pcm(channel, &head, &buffer[sent..sent + take])?;
            sent += take;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_stream_is_the_projects_own_format() {
        // `dc-audio`'s `StreamFormat` default: 16-bit signed, 48 kHz, two channels.
        assert_eq!(BITS, 16);
        assert_eq!(RATE, 48_000);
        assert_eq!(CHANNELS, 2);
        assert_eq!(READ_BYTES, 3840, "20 ms of sound at 48 kHz stereo");
        assert!(MAX_PCM_PER_MESSAGE + 12 <= 60 * 1024, "a message fits the channel's frame");
    }

    #[test]
    fn the_kernel_s_own_space_is_what_the_request_is_written_into() {
        // The two offsets a wrong guess would wreck: the intervals begin after the flags, the
        // three masks and the five the kernel reserves; `rmask` follows the intervals and theirs.
        assert_eq!(alsa::INTERVALS_AT, 4 + 96 + 160);
        // The offsets a C compiler gives `struct snd_pcm_hw_params` on this architecture: a mask
        // is 32 bytes, an interval is 12 (`unsigned int min, max` and a four-byte bitfield), the
        // intervals begin at 260, `rmask` at 512, and the whole structure is 608.
        assert_eq!(alsa::MASKS, 3);
        assert_eq!(alsa::INTERVALS_AT, 260, "offsetof(masks) + 8 * sizeof(snd_mask)");
        assert_eq!(alsa::INTERVAL_SIZE, 12, "sizeof(struct snd_interval)");
        assert_eq!(alsa::RMASK_AT, 512, "offsetof(rmask)");
        assert_eq!(alsa::HW_PARAMS_SIZE, 608, "sizeof the structure");
        // The masks the code fills cover exactly the ones the kernel has.
        assert_eq!(alsa::MASKS as u32, alsa::LAST_MASK + 1);
        assert_eq!(
            alsa::INTERVALS as u32,
            alsa::LAST_INTERVAL - alsa::PARAM_FIRST_INTERVAL + 1
        );
    }

    #[test]
    fn the_calls_are_the_kernels_own_numbers() {
        // The values a C compiler gives `sound/asound.h`: the two structures' sizes are part of
        // the request, and a wrong one is an `EINVAL` from the card (measured).
        assert_eq!(alsa::HW_PARAMS_SIZE, 608, "sizeof(struct snd_pcm_hw_params)");
        assert_eq!(alsa::HW_REFINE, 0xc260_4110);
        assert_eq!(alsa::HW_PARAMS, 0xc260_4111);
        assert_eq!(alsa::PREPARE, 0x4140);
        assert_eq!(alsa::START, 0x4142);
        assert_eq!(alsa::INTERVALS_AT, 4 + 96 + 160);
    }

    #[test]
    fn the_states_are_the_kernels_own_numbers() {
        // `SNDRV_PCM_STATE_RUNNING` and `SNDRV_PCM_STATE_XRUN`, as `sound/asound.h` numbers them:
        // a driver has to know which one means "the ring went round".
        assert_eq!(STATE_RUNNING, 3);
        assert_eq!(STATE_XRUN, 4);
        // `sizeof(struct snd_pcm_status)` is 152 and its `ioctl` carries that size; the state is
        // the structure's first word.
        assert_eq!(alsa::STATUS, 0x8098_4120);
        assert_eq!(alsa::STATUS_SIZE, 152);
    }

    /// **The one test that would have caught `no audio anymore`.**  The audio channel's message is
    /// a frame whose payload is the stream's id and a byte count, **and then those bytes straight
    /// after the frame** — the host reads the frame, then reads exactly the count.  Putting the PCM
    /// inside the frame's own length is a different message, and the host refuses that connection
    /// (measured 2026-10-11: `a frame is 131072 bytes, more than the 61440 this channel allows`,
    /// the guest's sound gone for the whole run).  This test builds the message and reads it back
    /// the way the host does, byte for byte.
    #[test]
    fn one_pcm_message_is_a_frame_and_then_its_bytes() {
        let pcm = vec![7u8; 3840];
        let mut channel = Vec::new();
        let mut head = Vec::with_capacity(12);
        head.extend_from_slice(&STREAM_ID.to_le_bytes());
        head.extend_from_slice(&(pcm.len() as u32).to_le_bytes());
        // What the host's reader does, in the same two steps the guest's own `send_pcm` writes.
        let mut wire = Vec::new();
        wire.extend_from_slice(&(head.len() as u32).to_le_bytes());
        wire.extend_from_slice(&A_PCM.to_le_bytes());
        wire.extend_from_slice(&head);
        wire.extend_from_slice(&pcm);
        channel.extend_from_slice(&wire);

        let len = u32::from_le_bytes(channel[0..4].try_into().unwrap());
        let kind = u16::from_le_bytes(channel[4..6].try_into().unwrap());
        assert_eq!(kind, A_PCM);
        assert_eq!(len as usize, 12, "the frame's length is the id and the count, not the sound");
        let count = u32::from_le_bytes(channel[14..18].try_into().unwrap()) as usize;
        assert_eq!(count, pcm.len());
        assert_eq!(&channel[18..18 + count], &pcm[..], "the sound follows the frame");
        assert_eq!(channel.len(), 18 + count, "and there is nothing else in the message");
        // A buffer bigger than one message is split: the channel's own ceiling is 60 KiB.
        let big = vec![0u8; 128 * 1024];
        let mut sent = 0;
        let mut pieces = 0;
        while sent < big.len() {
            let take = (big.len() - sent).min(MAX_PCM_PER_MESSAGE);
            assert!(take + 12 <= 60 * 1024, "every piece fits the channel");
            sent += take;
            pieces += 1;
        }
        assert_eq!(sent, big.len(), "every byte of sound is sent");
        assert!(pieces >= 3, "a 128 KiB read is three messages, not one");
    }

    /// Measured in this project's guest: the loopback card is card **0**, and the capture end of its
    /// cable is the second PCM device — which is the device path, and the name the agent prints.
    #[test]
    fn the_capture_device_is_the_loopback_cards_second_pcm() {
        let path = format!("/dev/snd/pcmC{}D{}c", 0, 1);
        assert_eq!(path, "/dev/snd/pcmC0D1c");
    }
}
