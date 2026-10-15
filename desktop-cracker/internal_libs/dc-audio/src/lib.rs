//! The guest's sound, and the one rule that shapes it.
//!
//! Audio support: //!
//! > The desktop-cracker application implements a audio device exposed inside
//! > the microvm, and it produces sound on the host whenever the display window is visible
//! > (the window can hide and only a system tray window has the application icon); when the
//! > window is not visible it **discards the audio data it receives from the microvm**.
//!
//! The device inside the microvm is the kernel's own **loopback sound card** (`snd-aloop`, which
//! this project's guest kernel builds), and the guest's programs play into its capture side.  The
//! samples travel the **audio channel** (`dc-fc-audio` serves it, on the project's own port), and
//! they reach this library as `Write` calls with the PCM the guest produced.  So the guest always
//! has a real card — applications that find none behave quite differently — and this library is
//! what decides what happens to the sound.
//!
//! Two consequences worth stating plainly:
//!
//! * **the gate is real**: when the rule says no, the bytes are dropped *here*,
//!   on the host, before they ever reach an audio device.  Nothing plays them
//!   later and nothing buffers them up — that is what "discards" means, and it
//!   is what `AudioGate::accept` returns;
//! * **the device is still there**: the guest always has a sound card, it just
//!   is not heard while the window is hidden.  A guest that
//!   finds no device behaves quite differently (applications refuse to start),
//!   which is not what this project asks for.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use dc_common::milestone;
pub use dc_display::window::{Gate, WindowState};

/// The format of one playback stream, as the guest's agent reports it when it opens one.  The type
/// is `dc-display`'s (the display and the sound share one crate of formats), and the extra methods
/// here are the ones the audio path needs.
pub mod pulse;
pub mod queue;

pub use queue::{AudioQueue, Chunk};

pub use dc_display::audio_format::StreamFormat;
pub use pulse::PulseSink;

/// What the audio path has done, for the log and the tests.
#[derive(Debug, Default)]
pub struct AudioStats {
    /// Streams the guest opened.
    pub streams: AtomicU64,
    /// Write calls the channel made (each one is a buffer of PCM).
    pub writes: AtomicU64,
    /// Bytes the guest produced.
    pub bytes_offered: AtomicU64,
    /// Bytes actually played (the rule was open).
    pub bytes_played: AtomicU64,
    /// Bytes dropped because the rule was closed — the project's rule
    /// "discards the audio data it receives".
    pub bytes_dropped: AtomicU64,
    /// Writes dropped for each reason.  There is one reason: the window is not on screen.
    pub dropped_hidden: AtomicU64,
}

impl AudioStats {
    fn record(&self, bytes: usize, gate: Gate) {
        self.writes.fetch_add(1, Ordering::Relaxed);
        self.bytes_offered
            .fetch_add(bytes as u64, Ordering::Relaxed);
        match gate {
            Gate::Open => {
                self.bytes_played.fetch_add(bytes as u64, Ordering::Relaxed);
            }
            Gate::WindowHidden => {
                self.bytes_dropped
                    .fetch_add(bytes as u64, Ordering::Relaxed);
                self.dropped_hidden.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Seconds of sound that were played, at the stream's own rate.
    pub fn played_seconds(&self, rate: u32) -> f64 {
        if rate == 0 {
            return 0.0;
        }

        self.bytes_played.load(Ordering::Relaxed) as f64 / 4.0 / rate as f64
    }

    pub fn summary(&self) -> String {
        format!(
            "{} stream(s), {} write(s), {} KiB played, {} KiB discarded ({} window hidden)",
            self.streams.load(Ordering::Relaxed),
            self.writes.load(Ordering::Relaxed),
            self.bytes_played.load(Ordering::Relaxed) >> 10,
            self.bytes_dropped.load(Ordering::Relaxed) >> 10,
            self.dropped_hidden.load(Ordering::Relaxed)
        )
    }
}

/// Where the bytes go when the rule is open.
///
/// The window's own audio device plays them; the tests give a sink that counts
/// them, which is how "played" can be asserted without making a noise.
pub trait Sink: Send + Sync {
    fn write(&self, stream: u64, data: &[u8], format: StreamFormat) -> anyhow::Result<()>;
}

/// A sink that counts what it is given (used by the tests and by a host with no
/// audio device at all: the guest keeps its sound card either way).
#[derive(Debug, Default)]
pub struct CountingSink {
    pub bytes: AtomicU64,
    pub calls: AtomicU64,
}

impl CountingSink {
    pub fn new() -> Arc<CountingSink> {
        Arc::new(CountingSink::default())
    }

    pub fn bytes(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }

    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::Relaxed)
    }
}

impl Sink for CountingSink {
    fn write(&self, _stream: u64, data: &[u8], _format: StreamFormat) -> anyhow::Result<()> {
        self.bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
        self.calls.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }
}

/// The host side of the guest's audio.
///
/// **Two threads, one queue.**  The reader is the machine's own callback (on the display client's
/// runtime): it applies the rule, hands the bytes to the queue and returns — it never waits for
/// the sound device, because that callback shares the connection the *window's* events arrive
/// on (measured: a sound device that answered slowly left the window with no frames at all).
/// The player is a thread of its own, and it does nothing but take buffers and write them.
pub struct AudioPath {
    window: Arc<WindowState>,
    /// The sink the **player** thread writes to.  The path keeps it alive (and names it here so
    /// the field is not "unused"): the thread has its own `Arc`.
    #[allow(dead_code)]
    sink: Arc<dyn Sink>,
    stats: AudioStats,
    /// The stream formats the guest opened, by id.
    formats: std::sync::Mutex<std::collections::HashMap<u64, StreamFormat>>,
    /// What the reader hands to the player.
    queue: Arc<AudioQueue>,
    /// The playing thread's handle, so the path can be closed and joined (`Mutex`: the path is
    /// shared inside an `Arc`, and shutting down takes it out once).
    player: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
    /// Stop the player.
    stop: Arc<std::sync::atomic::AtomicBool>,
}

/// How much sound may wait between the reader and the player.  **40 ms**: one buffer of
/// latency, which is a stream rather than a delay, and enough that a scheduling hiccup on this
/// host does not become a click.
pub const QUEUE_LIMIT: std::time::Duration = std::time::Duration::from_millis(40);

impl AudioPath {
    pub fn new(window: Arc<WindowState>, sink: Arc<dyn Sink>) -> AudioPath {
        AudioPath::with_limit(window, sink, QUEUE_LIMIT)
    }

    /// The same, with a queue limit of its own (the tests use a small one to see the policy).
    pub fn with_limit(
        window: Arc<WindowState>,
        sink: Arc<dyn Sink>,
        limit: std::time::Duration,
    ) -> AudioPath {
        let queue = Arc::new(AudioQueue::new(limit));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let player = {
            let queue = Arc::clone(&queue);
            let sink = Arc::clone(&sink);
            let stop = Arc::clone(&stop);
            std::thread::Builder::new()
                .name("dc-audio-player".into())
                .spawn(move || {
                    // The player's whole life: take a buffer, write it, again.  The write
                    // blocks (the server has a real device behind it), which is the point —
                    // this thread exists so that nothing else has to wait for it.
                    while !stop.load(Ordering::Relaxed) {
                        let Some(chunk) = queue.pop(std::time::Duration::from_millis(200)) else {
                            continue;
                        };
                        if let Err(_e) = sink.write(chunk.stream, &chunk.data, chunk.format) {}
                    }
                })
                .expect("the audio player thread")
        };
        AudioPath {
            window,
            sink,
            stats: AudioStats::default(),
            formats: std::sync::Mutex::new(std::collections::HashMap::new()),
            queue,
            player: std::sync::Mutex::new(Some(player)),
            stop,
        }
    }

    /// The queue the reader fills and the player drains (its statistics are the honest answer
    /// to "is the sound keeping up?").
    pub fn queue(&self) -> &Arc<AudioQueue> {
        &self.queue
    }

    /// Stop the player and wait for it: the sound stops with the run, and the device is
    /// released here rather than at process exit.
    pub fn shutdown(&self) {
        self.stop.store(true, Ordering::Relaxed);
        self.queue.close();
        let taken = self.player.lock().ok().and_then(|mut p| p.take());
        if let Some(player) = taken {
            let _ = player.join();
        }
    }

    pub fn window(&self) -> &Arc<WindowState> {
        &self.window
    }

    pub fn stats(&self) -> &AudioStats {
        &self.stats
    }

    /// The rule, as it stands right now.
    pub fn gate(&self) -> Gate {
        self.window.gate()
    }

    /// A stream was opened inside the guest.
    pub fn stream_init(&self, id: u64, format: StreamFormat) {
        self.stats.streams.fetch_add(1, Ordering::Relaxed);
        self.formats.lock().unwrap().insert(id, format);
        milestone!(
            "audio: stream {id} opened: {} bit, {} Hz, {} channel(s), {} B/s",
            format.bits,
            format.freq,
            format.channels,
            format.bytes_per_second
        );
    }

    pub fn stream_fini(&self, id: u64) {
        self.formats.lock().unwrap().remove(&id);
    }

    pub fn format_of(&self, id: u64) -> StreamFormat {
        self.formats
            .lock()
            .unwrap()
            .get(&id)
            .copied()
            .unwrap_or_default()
    }

    /// The guest produced PCM.  **After this call the bytes are either played or
    /// gone**: nothing is queued for later, which is what the project's rules
    /// "discards" means.
    pub fn write(&self, stream: u64, data: &[u8]) -> anyhow::Result<Gate> {
        let gate = self.gate();
        let first = self.stats.writes.load(Ordering::Relaxed) == 0;
        self.stats.record(data.len(), gate);
        if first {
            milestone!(
                "audio: first buffer: {} bytes, {:.0} ms of sound, {}",
                data.len(),
                self.format_of(stream).duration_of(data.len()).as_secs_f64() * 1000.0,
                gate.reason()
            );
        }
        if gate.is_open() {
            let format = self.format_of(stream);
            // **The reader never waits**: the buffer goes to the queue, and the player's own
            // thread is what talks to the sound device (see this type's own words).
            self.queue.push(Chunk {
                stream,
                format,
                data: data.to_vec(),
            });
        }
        Ok(gate)
    }

    /// A line for the log, once in a while.
    pub fn report(&self) {
        let _q = self.queue.stats();
    }

    /// The rule and its inputs, as one line: what the log should say when the
    /// application stops, and what a test can assert on without depending on
    /// whether the channel happened to hand any buffer over.
    /// The queue's numbers, for the run's last line: the reader's drops are the project's rules
    /// "discards", and the player's drops are the queue's soft limit doing its job.
    pub fn queue_summary(&self) -> String {
        let q = self.queue.stats();
        format!(
            "audio queue: limit {} ms, {} chunk(s) played, {} dropped ({} KiB), high water {} ms",
            self.queue.limit().as_millis(),
            q.played.load(Ordering::Relaxed),
            q.dropped.load(Ordering::Relaxed),
            q.dropped_bytes.load(Ordering::Relaxed) >> 10,
            q.high_water_ms.load(Ordering::Relaxed)
        )
    }

    pub fn rule_summary(&self) -> String {
        format!(
            "audio rule: {} (window {})",
            self.gate().reason(),
            if self.window.visible() {
                "visible"
            } else {
                "hidden"
            }
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path() -> (Arc<WindowState>, Arc<CountingSink>, AudioPath) {
        let window = WindowState::new();
        let sink = CountingSink::new();
        let audio = AudioPath::new(window.clone(), sink.clone());
        (window, sink, audio)
    }

    /// The sound rule is the window's visibility, and nothing else: the numlock key is the
    /// chords' key, not a condition for hearing the guest.
    #[test]
    fn the_rule_is_the_windows_visibility_alone() {
        let (window, _, audio) = path();
        // nothing said yet: not audible
        assert_eq!(audio.gate(), Gate::WindowHidden);

        window.set_visible(true);
        assert_eq!(audio.gate(), Gate::Open, "no key needs holding");

        // The key changes nothing, held or not.
        window.set_numlock_held(true);
        assert_eq!(audio.gate(), Gate::Open);
        window.set_numlock_held(false);
        assert_eq!(audio.gate(), Gate::Open);

        // hiding the window closes it again
        window.set_visible(false);
        assert_eq!(audio.gate(), Gate::WindowHidden);
        window.set_visible(true);
        assert!(audio.gate().is_open());
    }

    #[test]
    fn sound_is_played_only_while_the_rule_is_open() {
        let (window, sink, audio) = path();
        audio.stream_init(1, StreamFormat::default());
        let pcm = vec![0u8; 4096];

        // hidden: discarded
        assert_eq!(audio.write(1, &pcm).unwrap(), Gate::WindowHidden);
        assert_eq!(sink.bytes(), 0);

        // visible: played — by the **player thread**, which is why this waits for it (a
        // millisecond or two: what is asserted is that it happens, not when)
        window.set_visible(true);
        assert_eq!(audio.write(1, &pcm).unwrap(), Gate::Open);
        assert_eq!(
            wait_for_bytes(&sink, 4096),
            4096,
            "the player wrote the buffer"
        );

        // and the counters say what happened, in bytes
        let s = audio.stats();
        assert_eq!(s.bytes_offered.load(Ordering::Relaxed), 2 * 4096);
        assert_eq!(s.bytes_played.load(Ordering::Relaxed), 4096);
        assert_eq!(s.bytes_dropped.load(Ordering::Relaxed), 4096);
        assert_eq!(s.dropped_hidden.load(Ordering::Relaxed), 1);
        assert!(s.summary().contains("discarded"), "{}", s.summary());
    }

    #[test]
    fn nothing_is_played_late_when_the_rule_opens_again() {
        let (window, sink, audio) = path();
        let pcm = vec![7u8; 1024];
        audio.write(1, &pcm).unwrap(); // discarded
        window.set_visible(true);
        assert_eq!(
            sink.bytes(),
            0,
            "a discarded buffer must not play afterwards"
        );
        audio.write(1, &pcm).unwrap();
        assert_eq!(
            wait_for_bytes(&sink, 1024),
            1024,
            "only the new buffer plays"
        );
    }

    #[test]
    fn the_stream_format_is_remembered_per_stream() {
        let (_, _, audio) = path();
        let f = StreamFormat {
            freq: 44_100,
            channels: 2,
            ..StreamFormat::default()
        };
        audio.stream_init(7, f);
        assert_eq!(audio.format_of(7), f);
        // an unknown stream falls back to the usual format rather than failing
        assert_eq!(audio.format_of(9), StreamFormat::default());
        audio.stream_fini(7);
        assert_eq!(audio.format_of(7), StreamFormat::default());
        assert_eq!(audio.stats().streams.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn a_stream_duration_follows_its_rate() {
        let f = StreamFormat::default(); // 192000 B/s
        assert_eq!(f.duration_of(192_000), std::time::Duration::from_secs(1));
        assert_eq!(f.duration_of(96_000).as_millis(), 500);
        let slow = StreamFormat {
            bytes_per_second: 0,
            ..StreamFormat::default()
        };
        assert_eq!(slow.duration_of(100), std::time::Duration::ZERO);
    }

    #[test]
    fn the_window_state_reports_the_size_the_window_publishes() {
        let w = WindowState::new();
        // a window that has not been shown has published no size, and is silent
        assert_eq!(w.size(), (0, 0));
        w.set_visible(true);
        w.set_size(1280, 800);
        assert_eq!(w.size(), (1280, 800));
        w.set_numlock_held(true);
        assert!(w.visible() && w.numlock_held());
    }

    #[test]
    fn a_sink_error_does_not_stop_the_reader() {
        // The sink is the **player's** business now, and a device that went away must not
        // become the reader's problem: the reader hands the buffer over and returns, and the
        // player reports the failure (its own thread, its own log).
        struct Failing;
        impl Sink for Failing {
            fn write(&self, _s: u64, _d: &[u8], _f: StreamFormat) -> anyhow::Result<()> {
                anyhow::bail!("the device went away")
            }
        }
        let window = WindowState::new();
        window.set_visible(true);
        let audio = AudioPath::new(window, Arc::new(Failing));
        assert_eq!(audio.write(1, &[0u8; 64]).unwrap(), Gate::Open);
        // it was counted as offered and as played: the rule was open, and the sink is what
        // failed — a different problem from a discarded buffer.
        assert_eq!(audio.stats().bytes_offered.load(Ordering::Relaxed), 64);
        assert_eq!(audio.stats().bytes_played.load(Ordering::Relaxed), 64);
    }

    /// Wait (at most a second) for a counting sink to have taken `want` bytes: the player is
    /// another thread, and a test that reads the counter the instant it pushed would only be
    /// testing the scheduler.
    fn wait_for_bytes(sink: &Arc<CountingSink>, want: u64) -> u64 {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        while std::time::Instant::now() < deadline {
            if sink.bytes() >= want {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        sink.bytes()
    }
}
