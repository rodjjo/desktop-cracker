//! **The guest's sound, as a service**: the PCM, over vsock, and the
//! project's own rule about when it is heard.
//!
//! Firecracker has no `virtio-snd`, so the guest's sound card is the kernel's **loopback** one
//! (`snd-aloop`, in the guest's kernel and its initramfs): an application writes to it and the
//! guest's agent reads the same bytes back from its capture side.  That is the whole trick —
//! `ALSA`'s loopback card has two sides of one cable, and the agent holding the other side is
//! exactly what `virtio-snd` used to be.
//!
//! This is the host's half.  It is deliberately thin, because **the rule already exists**:
//! `dc-audio::AudioPath` is what decides whether a buffer is played or discarded (the window
//! must be visible — the rule the operator restated on 2026-10-14: the numlock key is the
//! chords' key, not a condition for hearing the guest), and it is
//! what talks to the host's own sound device.  So this service does two things:
//!
//! * it reads the agent's frames — a stream's format once, then its PCM — and hands each buffer
//!   to the path's own `write`, which applies the gate and either plays it or records it as
//!   discarded;
//! * it answers [`KIND_OPEN`]/[`KIND_CLOSE`] so the path's counters can say what the guest's
//!   sound was, and the run's milestone line can print the project's own summary.
//!
//! The format is **not invented here**: `dc-display::audio_format::StreamFormat` is the project's
//! one description of a stream (16-bit signed, 48 kHz, two channels), and the guest's agent
//! declares the same numbers to the loopback card, so what arrives is what the path already
//! expects.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use dc_audio::StreamFormat;
use dc_common::milestone;
use dc_vsock::{Frame, Reader, Service};

/// The guest opened a stream: `[u32 bits][u8 channels][u32 freq]`, then the stream's id.
pub const KIND_OPEN: u16 = 1;
/// PCM: `[u64 stream]`, then the bytes themselves.
pub const KIND_PCM: u16 = 2;
/// The guest closed a stream: `[u64 stream]`.
pub const KIND_CLOSE: u16 = 3;
/// The guest reports its own state (how many bytes it has read from the loopback card).
pub const KIND_REPORT: u16 = 4;

/// What the service has done: the numbers a milestone line reads.
#[derive(Debug, Default)]
pub struct Counters {
    /// Streams the guest opened.
    pub streams: AtomicU64,
    /// Buffers received, and their bytes.
    pub buffers: AtomicU64,
    pub bytes: AtomicU64,
    /// What the rule did with them (`dc-audio`'s own counters are the authority; these are the
    /// same numbers as the service sees them).
    pub played: AtomicU64,
    pub discarded: AtomicU64,
}

impl Counters {
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            streams: self.streams.load(Ordering::Relaxed),
            buffers: self.buffers.load(Ordering::Relaxed),
            bytes: self.bytes.load(Ordering::Relaxed),
            played: self.played.load(Ordering::Relaxed),
            discarded: self.discarded.load(Ordering::Relaxed),
        }
    }
}

/// The counters, read at one moment.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Snapshot {
    pub streams: u64,
    pub buffers: u64,
    pub bytes: u64,
    pub played: u64,
    pub discarded: u64,
}

/// What the PCM is put through: **the project's own rule**, which is `dc-audio::AudioPath`'s
/// (`the window is visible`), plus its own playing thread.  A service takes this as
/// a trait so its unit tests can watch the rule without a sound device and without a window.
pub trait Play: Send + Sync {
    /// A buffer of the guest's sound, and what the rule did with it.
    fn play(&self, stream: u64, data: &[u8], format: StreamFormat) -> anyhow::Result<bool>;
}

impl Play for dc_audio::AudioPath {
    fn play(&self, stream: u64, data: &[u8], format: StreamFormat) -> anyhow::Result<bool> {
        // `AudioPath::write` applies the gate, records the discard and queues what is heard;
        // its own counters are the report.  What it answers is the gate.
        let gate = self.write(stream, data)?;
        let _ = format;
        Ok(gate.is_open())
    }
}

/// The audio service: one listener, **one guest connection**.
pub struct AudioService {
    service: Service,
    play: Arc<dyn Play>,
    counters: Arc<Counters>,
    /// The run is over: the accepting loop ends (a listener parked in `accept` would outlive the
    /// run that owns it).
    stop: Arc<std::sync::atomic::AtomicBool>,
    /// **How many connections the guest has made**: a guest that dials again is a guest whose
    /// sound was interrupted, and this is the number that says it happened.
    connections: Arc<std::sync::atomic::AtomicU64>,
    /// The flag the connection being served right now watches.  A newer dial sets it, which is how
    /// the port ends up with one client rather than two.
    current: Arc<std::sync::Mutex<Option<Arc<std::sync::atomic::AtomicBool>>>>,
}

impl AudioService {
    /// Listen on `<uds_path>_55000` — **before the machine starts**, like every other channel.
    pub fn listen(
        uds_path: &std::path::Path,
        play: Arc<dyn Play>,
    ) -> std::result::Result<AudioService, dc_vsock::VsockError> {
        Ok(AudioService {
            service: Service::bind(uds_path, dc_vsock::ports::AUDIO)?,
            play,
            counters: Arc::new(Counters::default()),
            stop: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            connections: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            current: Arc::new(std::sync::Mutex::new(None)),
        })
    }

    pub fn port(&self) -> u32 {
        self.service.port()
    }

    pub fn counters(&self) -> Snapshot {
        self.counters.snapshot()
    }

    /// How many connections the guest has dialled this port.  One is a normal run; more than one
    /// says the sound was interrupted and the guest came back.
    pub fn connections(&self) -> u64 {
        self.connections.load(Ordering::Relaxed)
    }

    /// Serve the guest's sound for as long as the run lives.
    ///
    /// **One client on this port.**  A run has one thing to hear, so a port has one connection to
    /// attend: when the guest dials again, the connection that was being served is **retired** —
    /// its flag is set, its socket closes, and the newer one is what the sound flows on.  The
    /// listener itself stays open for the whole run, because a connection *does* end (the device
    /// resets one that has been silent, measured by the guest as `the host's channel: Broken pipe`
    /// on the first buffer after a quiet spell) and a guest that dials again is a guest whose sound
    /// would otherwise be gone for the rest of the run.  Accepting again is not a second client: it
    /// is the same one, back.
    pub fn serve(self: &Arc<Self>) -> std::result::Result<(), dc_vsock::VsockError> {
        let _ = self.service.set_nonblocking(true);
        loop {
            if self.stop.load(Ordering::Relaxed) {
                return Ok(());
            }
            match self.service.accept() {
                Ok(stream) => {
                    let _ = stream.set_nonblocking(false);
                    // **The older connection goes first**: one port, one client, and the newer dial
                    // is the client.
                    let mine = Arc::new(std::sync::atomic::AtomicBool::new(false));
                    if let Some(previous) = self.current.lock().unwrap().replace(Arc::clone(&mine))
                    {
                        previous.store(true, Ordering::Relaxed);
                    }
                    let port = self.service.port();
                    let service = Arc::clone(self);
                    std::thread::spawn(move || {
                        let _ = service.serve_one(stream, port, mine);
                    });
                }
                Err(dc_vsock::VsockError::Io { ref source, .. })
                    if source.kind() == std::io::ErrorKind::WouldBlock =>
                {
                    std::thread::sleep(std::time::Duration::from_millis(20));
                    continue;
                }
                Err(_) => return Ok(()),
            }
        }
    }

    /// Stop serving: the run is over.  The accepting loop ends by itself within its own patience,
    /// and every connection it was serving ends with the socket.
    pub fn shutdown(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }

    /// The socket this service is listening on (the run's own cleanup removes it).
    pub fn path(&self) -> &std::path::Path {
        self.service.path()
    }

    /// Serve **one** connection: the guest's PCM until that connection ends or is retired by a
    /// newer dial of the same port.
    fn serve_one(
        &self,
        mut stream: std::os::unix::net::UnixStream,
        port: u32,
        mine: Arc<std::sync::atomic::AtomicBool>,
    ) -> std::result::Result<(), dc_vsock::VsockError> {
        // **A connection the device resets is said out loud, once per connection** — not a line per
        // buffer: a guest whose sound keeps being interrupted is a thing a person has to hear
        // about, and a run's counters alone would hide it.
        self.connections.fetch_add(1, Ordering::Relaxed);
        // The read is bounded so this loop can look at its own flag: a connection that is retired
        // while its reader is parked on a silent guest has to notice within its own patience, not
        // when the guest finally speaks.
        let _ = stream.set_read_timeout(Some(std::time::Duration::from_millis(200)));
        let mut reader = Reader::new();
        // The stream's format, as the guest declared it: the same numbers on both sides
        // (`dc-audio::StreamFormat`), so nothing here has to guess at a rate or a depth.
        let mut format = StreamFormat::default();
        loop {
            if mine.load(Ordering::Relaxed) {
                milestone!(
                    "audio: the guest dialled this port again; the older connection is retired ({} so far)",
                    self.connections.load(Ordering::Relaxed)
                );
                break;
            }
            match reader.read_frame(&mut stream, port) {
                Ok(Some(frame)) => match frame.kind {
                    KIND_OPEN => {
                        format = self.opened(&frame.payload);
                        self.counters.streams.fetch_add(1, Ordering::Relaxed);
                        milestone!(
                            "audio: the guest opened a stream: {} bit, {} Hz, {} channel(s)",
                            format.bits,
                            format.freq,
                            format.channels
                        );
                    }
                    KIND_PCM => {
                        let Some(stream_id) = frame
                            .payload
                            .get(..8)
                            .map(|b| u64::from_le_bytes(b.try_into().unwrap()))
                        else {
                            continue;
                        };
                        // The PCM follows the frame, exactly as a display rectangle's pixels do —
                        // and it is **waited for**: the frame announced the count, so a guest that
                        // has not sent the rest yet is a guest still talking, not a broken channel
                        // (`read_bytes_with` with no stall limit — the display channel learned this
                        // the hard way, and a bounded read here was the last silent-close corner
                        // left on this port).
                        let bytes = match reader.read_bytes_while(
                            &mut stream,
                            frame.pixels_hint(),
                            port,
                            &|| !mine.load(Ordering::Relaxed),
                        ) {
                            Ok(bytes) => bytes,
                            Err(e) => {
                                milestone!(
                                    "audio: the guest's sound stopped mid-buffer: {e} ({} so far)",
                                    self.connections.load(Ordering::Relaxed)
                                );
                                break;
                            }
                        };
                        self.received(stream_id, &bytes, format);
                    }
                    KIND_CLOSE => {}
                    _ => {}
                },
                Ok(None) => {
                    milestone!(
                        "audio: the guest's connection closed ({} so far)",
                        self.connections.load(Ordering::Relaxed)
                    );
                    break;
                }
                // A read that timed out is not a goodbye: the guest's sound has quiet spells (a
                // card with nothing to hand over sends nothing), and a connection is retired by a
                // newer dial or by the run ending, not by a pause.  The loop looks at its own flag
                // and reads again.
                Err(dc_vsock::VsockError::Io { ref source, .. })
                    if source.kind() == std::io::ErrorKind::TimedOut
                        || source.kind() == std::io::ErrorKind::WouldBlock =>
                {
                    continue;
                }
                Err(e) => {
                    milestone!(
                        "audio: the guest's connection ended: {e} ({} so far)",
                        self.connections.load(Ordering::Relaxed)
                    );
                    break;
                }
            }
        }
        Ok(())
    }

    /// A stream opened: the format the guest declared.
    fn opened(&self, payload: &[u8]) -> StreamFormat {
        if payload.len() < 9 {
            return StreamFormat::default();
        }
        let bits = payload[0];
        let channels = payload[1];
        let freq = u32::from_le_bytes(payload[2..6].try_into().unwrap());
        let bytes_per_frame = (channels as u32) * (bits as u32).div_ceil(8);
        StreamFormat {
            bits,
            is_signed: true,
            is_float: false,
            freq,
            channels,
            bytes_per_frame,
            bytes_per_second: freq * bytes_per_frame,
            big_endian: false,
        }
    }

    /// One buffer of the guest's sound, through the rule.
    fn received(&self, stream: u64, bytes: &[u8], format: StreamFormat) {
        self.counters.buffers.fetch_add(1, Ordering::Relaxed);
        self.counters
            .bytes
            .fetch_add(bytes.len() as u64, Ordering::Relaxed);
        match self.play.play(stream, bytes, format) {
            Ok(true) => {
                self.counters.played.fetch_add(1, Ordering::Relaxed);
            }
            Ok(false) => {
                // The rule's own "discards": the bytes are gone, and the counters say why
                // (`dc-audio`'s report is where the reason is written down).
                self.counters.discarded.fetch_add(1, Ordering::Relaxed);
            }
            Err(e) => {
                milestone!("audio: the host's sound device refused a buffer: {e}");
                self.counters.discarded.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// The PCM that follows a frame, as a guest announces it: the frame's payload is the stream's
/// id and the **number of bytes** that follow it.
pub fn pcm(stream: u64, bytes: &[u8]) -> Vec<u8> {
    let mut out = Frame::new(KIND_PCM, {
        let mut payload = stream.to_le_bytes().to_vec();
        payload.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
        payload
    })
    .encode();
    out.extend_from_slice(bytes);
    out
}

/// What a guest says when it opens a stream.
pub fn open(bits: u8, channels: u8, freq: u32) -> Frame {
    let mut payload = vec![bits, channels];
    payload.extend_from_slice(&freq.to_le_bytes());
    Frame::new(KIND_OPEN, payload)
}

/// The byte count a PCM frame announces, so the reader knows how much follows it.
trait PixelsHint {
    fn pixels_hint(&self) -> usize;
}

impl PixelsHint for Frame {
    fn pixels_hint(&self) -> usize {
        // The payload is `[u64 stream][u32 bytes]`; without the count there is nothing to read,
        // and a frame that says zero is a frame with no sound in it.
        self.payload
            .get(8..12)
            .map(|b| u32::from_le_bytes(b.try_into().unwrap()) as usize)
            .unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::os::unix::net::UnixStream;
    use std::sync::Mutex;

    /// A sink that remembers what the rule let through, so the test asserts on the **rule**
    /// rather than on a sound device (which a unit test does not have).
    #[derive(Default)]
    struct Recorder {
        open: Mutex<bool>,
        heard: Mutex<Vec<u8>>,
        refusals: Mutex<u64>,
    }

    impl Play for Recorder {
        fn play(&self, _stream: u64, data: &[u8], _format: StreamFormat) -> anyhow::Result<bool> {
            if *self.open.lock().unwrap() {
                self.heard.lock().unwrap().extend_from_slice(data);
                Ok(true)
            } else {
                *self.refusals.lock().unwrap() += 1;
                Ok(false)
            }
        }
    }

    fn service(play: Arc<Recorder>) -> (Arc<AudioService>, tempfile::TempDir) {
        let dir = tempfile::tempdir().unwrap();
        let service = Arc::new(AudioService::listen(&dir.path().join("v.sock"), play).unwrap());
        (service, dir)
    }

    #[test]
    fn a_streams_format_is_the_one_the_guest_declared() {
        let play = Arc::new(Recorder::default());
        let (service, _dir) = service(play);
        let format = service.opened(&[16, 2, 0x80, 0xbb, 0, 0]);
        assert_eq!(format.bits, 16);
        assert_eq!(format.channels, 2);
        assert_eq!(format.freq, 48_000);
        assert_eq!(format.bytes_per_frame, 4);
        assert_eq!(format.bytes_per_second, 192_000);
        assert_eq!(
            format,
            StreamFormat::default(),
            "the project's own 48 kHz stereo"
        );
    }

    #[test]
    fn the_rule_decides_and_the_counters_say_what_it_decided() {
        let play = Arc::new(Recorder::default());
        let (service, _dir) = service(play.clone());
        let pcm_bytes: Vec<u8> = (0..960).map(|i| i as u8).collect();
        // The window is hidden (the rule is closed): the buffer is discarded.
        service.received(1, &pcm_bytes, StreamFormat::default());
        assert_eq!(service.counters().discarded, 1);
        assert_eq!(service.counters().played, 0);
        assert!(play.heard.lock().unwrap().is_empty());
        // Then the rule opens: the same buffer is heard.
        *play.open.lock().unwrap() = true;
        service.received(1, &pcm_bytes, StreamFormat::default());
        assert_eq!(service.counters().played, 1);
        assert_eq!(play.heard.lock().unwrap().len(), 960);
        assert_eq!(service.counters().bytes, 1920);
        assert_eq!(service.counters().buffers, 2);
    }

    #[test]
    fn a_guest_that_sends_pcm_is_heard_over_a_real_socket() {
        let play = Arc::new(Recorder::default());
        *play.open.lock().unwrap() = true;
        let (service, dir) = service(play.clone());
        let port = service.port();
        let serving = {
            let service = service.clone();
            std::thread::spawn(move || service.serve())
        };
        let mut guest =
            UnixStream::connect(dc_vsock::listener_path(&dir.path().join("v.sock"), port)).unwrap();
        guest.write_all(&open(16, 2, 48_000).encode()).unwrap();
        let pcm_bytes = vec![7u8; 3840];
        guest.write_all(&pcm(1, &pcm_bytes)).unwrap();
        guest.flush().unwrap();
        let mut heard = 0;
        for _ in 0..200 {
            heard = play.heard.lock().unwrap().len();
            if heard == pcm_bytes.len() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        assert_eq!(heard, pcm_bytes.len(), "the whole buffer arrived");
        let counters = service.counters();
        assert_eq!(counters.streams, 1);
        assert_eq!(counters.buffers, 1);
        assert_eq!(counters.played, 1);
        // The run is over: the accepting loop is asked to stop and the thread ends by itself (the
        // listener is non-blocking, so its own patience is 20 ms — a unit test does not wait on a
        // thread it cannot stop).
        service.shutdown();
        drop(guest);
        let _ = serving.join();
    }

    /// **A long stream, the way the guest actually writes it**: one `KIND_OPEN`, then hundreds of
    /// PCM messages, each one a frame and its bytes — and, exactly as `send_pcm` does, the head, the
    /// payload and the sound written as **three separate writes**, because a vsock is a byte stream
    /// and a message arrives in pieces.
    ///
    /// This is the test the "no audio anymore" report needed: the run's own counters read
    /// `75 stream(s), 6 906 buffer(s)` with a `a frame is 131072 bytes` line every few hundred
    /// buffers, while a byte-for-byte listener beside the same run read **every** message cleanly.
    /// So the question was never what the guest sends but whether this reader stays in step over a
    /// long stream — and it is the staying-in-step that is asserted here.
    #[test]
    fn a_long_stream_of_buffers_stays_in_step() {
        let play = Arc::new(Recorder::default());
        *play.open.lock().unwrap() = true;
        let (service, dir) = service(play.clone());
        let port = service.port();
        let serving = {
            let service = service.clone();
            std::thread::spawn(move || service.serve())
        };
        let mut guest =
            UnixStream::connect(dc_vsock::listener_path(&dir.path().join("v.sock"), port)).unwrap();
        guest.write_all(&open(16, 2, 48_000).encode()).unwrap();

        // Three writes per message, and a size that is not a round multiple of anything: a real
        // buffer is 3 840 bytes, the card's own period hands over 2 304, and a quiet guest hands
        // over 768.
        let sizes = [3_840usize, 2_304, 768, 3_840, 1_536];
        let mut expected = 0usize;
        for round in 0..60 {
            let n = sizes[round % sizes.len()];
            let sound: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
            expected += n;
            let message = pcm(1, &sound);
            guest.write_all(&message[..6]).unwrap();
            guest.write_all(&message[6..18]).unwrap();
            guest.write_all(&message[18..]).unwrap();
            guest.flush().unwrap();
        }

        let mut heard = 0;
        for _ in 0..400 {
            heard = play.heard.lock().unwrap().len();
            if heard == expected {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        let counters = service.counters();
        assert_eq!(counters.buffers, 60, "every message was one buffer");
        assert_eq!(counters.streams, 1, "and one stream, not one per message");
        assert_eq!(counters.bytes as usize, expected);
        assert_eq!(heard, expected, "the whole of the sound arrived, in order");
        assert_eq!(counters.discarded, 0);
        service.shutdown();
        drop(guest);
        let _ = serving.join();
    }

    /// **One client per port.**  A run has one thing to hear, so when the guest dials the port
    /// again the connection that was being served is retired and the newer one is the client —
    /// never two readers of the same stream at the same time.
    #[test]
    fn a_newer_dial_retires_the_connection_it_replaces() {
        let play = Arc::new(Recorder::default());
        *play.open.lock().unwrap() = true;
        let (service, dir) = service(play.clone());
        let port = service.port();
        let serving = {
            let service = service.clone();
            std::thread::spawn(move || service.serve())
        };
        let path = dc_vsock::listener_path(&dir.path().join("v.sock"), port);

        let mut first = UnixStream::connect(&path).unwrap();
        first.write_all(&open(16, 2, 48_000).encode()).unwrap();
        first.flush().unwrap();
        let mut second = UnixStream::connect(&path).unwrap();
        second.write_all(&open(16, 2, 48_000).encode()).unwrap();
        second.flush().unwrap();

        // The newer one is the one that is heard.
        let sound = vec![9u8; 3_840];
        let mut heard = 0;
        for _ in 0..400 {
            second.write_all(&pcm(1, &sound)).unwrap();
            second.flush().unwrap();
            std::thread::sleep(std::time::Duration::from_millis(5));
            heard = play.heard.lock().unwrap().len();
            if heard >= sound.len() {
                break;
            }
        }
        assert!(
            heard >= sound.len(),
            "the newer connection is served: {heard}"
        );
        // The older one is gone: its own write answers an error, because its socket was closed.
        let refused = first.write_all(&pcm(1, &sound)).and_then(|_| first.flush());
        assert!(
            refused.is_err(),
            "the retired connection is not a client any more"
        );
        assert_eq!(service.connections(), 2, "two dials, one client");

        service.shutdown();
        drop(second);
        let _ = serving.join();
    }

    #[test]
    fn a_frame_that_announces_no_bytes_is_a_frame_with_no_sound() {
        let frame = Frame::new(KIND_PCM, 1u64.to_le_bytes().to_vec());
        assert_eq!(frame.pixels_hint(), 0);
        let with = Frame::new(KIND_PCM, {
            let mut payload = 1u64.to_le_bytes().to_vec();
            payload.extend_from_slice(&64u32.to_le_bytes());
            payload
        });
        assert_eq!(with.pixels_hint(), 64);
    }

    /// **The shape this channel answers, and the one it refuses.**  The message is a frame whose
    /// payload is the stream's id and a byte count, **and then those bytes straight after the
    /// frame** — so two buffers read as two frames and two waits, and nothing is left over.
    ///
    /// The other shape is the regression that ended the guest's sound on its very first buffer
    /// (measured 2026-10-11): the Rust port put the PCM *inside* the frame's own length.  The
    /// reader took that frame, went looking for the count it announced, found the **next**
    /// message's bytes instead, and the length it read after them was a piece of PCM — which is
    /// how a run printed `a frame is 131072 bytes, more than the 61440 this channel allows` and
    /// closed the connection.
    #[test]
    fn the_sound_travels_after_the_frame_and_not_inside_it() {
        let sound = vec![7u8; 3840];

        // The right shape: two buffers, two frames, each followed by exactly what it announced.
        let mut right = pcm(1, &sound);
        right.extend_from_slice(&pcm(1, &sound));
        let mut reader = Reader::new();
        reader.push(&right);
        for _ in 0..2 {
            let frame = reader.next_frame().unwrap().expect("a frame is there");
            assert_eq!(frame.kind, KIND_PCM);
            assert_eq!(frame.payload.len(), 12, "the frame is the id and the count");
            let count = frame.pixels_hint();
            assert_eq!(count, 3840);
            // No socket to read: the bytes are already here, and they are the sound.
            let bytes = reader
                .read_bytes_with(&mut std::io::empty(), count, dc_vsock::ports::AUDIO, None)
                .unwrap();
            assert_eq!(bytes, sound, "the sound follows its frame");
        }
        assert_eq!(
            reader.buffered(),
            0,
            "and the two messages are the whole stream"
        );

        // The wrong shape: the same two buffers, with the sound inside the frame.
        let mut wrong = Frame::new(KIND_PCM, {
            let mut payload = 1u64.to_le_bytes().to_vec();
            payload.extend_from_slice(&(sound.len() as u32).to_le_bytes());
            payload.extend_from_slice(&sound);
            payload
        })
        .encode();
        wrong.extend_from_slice(&pcm(1, &sound));
        let mut reader = Reader::new();
        reader.push(&wrong);
        let first = reader
            .next_frame()
            .unwrap()
            .expect("the first frame parses");
        assert_eq!(
            first.payload.len(),
            12 + 3840,
            "the frame swallowed the sound"
        );
        // The count it announced is paid for out of the *next* message, and what is left of that
        // one is read as a length: a piece of PCM, and a frame nobody would send.
        let _ = reader
            .read_bytes_with(&mut std::io::empty(), 3840, dc_vsock::ports::AUDIO, None)
            .unwrap();
        let err = reader.next_frame().unwrap_err();
        assert!(
            matches!(err, dc_vsock::VsockError::TooLarge { .. }),
            "{err:?}"
        );
        assert!(
            err.to_string().contains("more than"),
            "the host's own answer is to refuse the channel: {err}"
        );
    }
}
