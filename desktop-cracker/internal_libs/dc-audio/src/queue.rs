//! The queue between the guest's PCM and the host's sound device.
//!
//! Two threads, and they must not be the same one:
//!
//! * **the reader** is the channel's own callback: the channel calls `Write` when
//!   the guest produces sound.  That callback runs on the display client's own runtime, and
//!   anything slow in it stalls *the display* as well — which is exactly what was measured:
//!   the sound device answering slowly (or not at all) left the window with no frames at all,
//!   because the frame loop's event pump waits on the same connection;
//! * **the player** owns the sound device (`pa_simple_write`, which blocks until the server has
//!   taken the buffer) and does nothing else.
//!
//! Between them, one queue with a **soft limit**: the reader never waits (it drops and counts),
//! and the player takes what is there.  The limit is in *time of sound* rather than in buffers,
//! because that is what it means to the listener — a queue that is 40 ms long is a stream, and
//! one that is two seconds long is a delay.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use dc_display::audio_format::StreamFormat;

/// One buffer of PCM, as the guest produced it.
#[derive(Debug, Clone, PartialEq)]
pub struct Chunk {
    pub stream: u64,
    pub format: StreamFormat,
    pub data: Vec<u8>,
}

/// What the queue has done: for the log, and for a test that wants to see the policy work.
#[derive(Debug, Default)]
pub struct QueueStats {
    /// Chunks the reader handed over.
    pub pushed: AtomicU64,
    /// Chunks the player took.
    pub played: AtomicU64,
    /// Chunks **dropped** because the queue was over its limit (the reader never waits).
    pub dropped: AtomicU64,
    /// Bytes dropped that way.
    pub dropped_bytes: AtomicU64,
    /// The longest the queue ever was, in milliseconds of sound: the number that says whether
    /// the queue is a stream or a delay.
    pub high_water_ms: AtomicU64,
}

impl QueueStats {
    fn note_high_water(&self, ms: u64) {
        self.high_water_ms.fetch_max(ms, Ordering::Relaxed);
    }
}

/// A queue with a soft limit, shared by the reader and the player.
pub struct AudioQueue {
    inner: Mutex<Inner>,
    /// Signalled on every push and on shutdown, so the player sleeps instead of spinning.
    ready: Condvar,
    /// The soft limit: sound longer than this is dropped by the **reader**.
    limit: Duration,
    stats: QueueStats,
    closed: Mutex<bool>,
}

#[derive(Default)]
struct Inner {
    chunks: VecDeque<Chunk>,
    /// How much sound is in the queue, in nanoseconds (each chunk knows its own duration).
    queued_ns: u64,
}

impl AudioQueue {
    /// A queue that holds at most `limit` of sound.
    ///
    /// 40 ms is the default: one buffer of latency, which is what a desktop does, and far less
    /// than a person notices.  A guest that produces sound faster than the device takes it
    /// (a stalled server, a busy host) is what the limit is for.
    pub fn new(limit: Duration) -> AudioQueue {
        AudioQueue {
            inner: Mutex::new(Inner::default()),
            ready: Condvar::new(),
            limit,
            stats: QueueStats::default(),
            closed: Mutex::new(false),
        }
    }

    pub fn stats(&self) -> &QueueStats {
        &self.stats
    }

    pub fn limit(&self) -> Duration {
        self.limit
    }

    /// Hand a buffer to the player.  **It never waits**: when the queue is over its limit the
    /// oldest sound is thrown away (it is already late — playing it would be playing the past)
    /// and the reader carries on.  Returns `false` when something was dropped.
    pub fn push(&self, chunk: Chunk) -> bool {
        let mut kept = true;
        {
            let Ok(mut inner) = self.inner.lock() else {
                return false;
            };
            inner.queued_ns += chunk.format.duration_of(chunk.data.len()).as_nanos() as u64;
            inner.chunks.push_back(chunk);
            // The soft limit: the **oldest** goes first, because the newest is the sound the
            // guest is making now.
            while inner.queued_ns > self.limit.as_nanos() as u64 {
                match inner.chunks.pop_front() {
                    Some(old) => {
                        let ns = old.format.duration_of(old.data.len()).as_nanos() as u64;
                        inner.queued_ns = inner.queued_ns.saturating_sub(ns);
                        self.stats.dropped.fetch_add(1, Ordering::Relaxed);
                        self.stats
                            .dropped_bytes
                            .fetch_add(old.data.len() as u64, Ordering::Relaxed);
                        kept = false;
                    }
                    None => break,
                }
            }
            self.stats.note_high_water(inner.queued_ns / 1_000_000);
        }
        self.stats.pushed.fetch_add(1, Ordering::Relaxed);
        self.ready.notify_all();
        kept
    }

    /// Take the next buffer, waiting at most `timeout` for one.  `None` means "nothing arrived
    /// in that time" (or the queue was closed).
    pub fn pop(&self, timeout: Duration) -> Option<Chunk> {
        let deadline = Instant::now() + timeout;
        let mut inner = self.inner.lock().ok()?;
        loop {
            if let Some(chunk) = inner.chunks.pop_front() {
                let ns = chunk.format.duration_of(chunk.data.len()).as_nanos() as u64;
                inner.queued_ns = inner.queued_ns.saturating_sub(ns);
                self.stats.played.fetch_add(1, Ordering::Relaxed);
                return Some(chunk);
            }
            if *self.closed.lock().ok()? {
                return None;
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            let (guard, _) = self.ready.wait_timeout(inner, left).ok()?;
            inner = guard;
        }
    }

    /// How much sound is waiting, in milliseconds (what a test asserts on).
    pub fn queued_ms(&self) -> u64 {
        self.inner
            .lock()
            .map(|i| i.queued_ns / 1_000_000)
            .unwrap_or(0)
    }

    /// Wake the player and tell it there is nothing more coming.
    pub fn close(&self) {
        if let Ok(mut closed) = self.closed.lock() {
            *closed = true;
        }
        self.ready.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn chunk(ms: u64) -> Chunk {
        // 48 kHz, two channels, 16-bit: 192 bytes for every millisecond of sound.
        let format = StreamFormat {
            freq: 48_000,
            channels: 2,
            bits: 16,
            is_signed: true,
            is_float: false,
            bytes_per_frame: 4,
            bytes_per_second: 192_000,
            big_endian: false,
        };
        // 48 kHz * 2 channels * 2 bytes = 192 bytes per ms of sound.
        Chunk {
            stream: 1,
            format,
            data: vec![0u8; (ms * 192) as usize],
        }
    }

    #[test]
    fn the_soft_limit_drops_the_oldest_sound() {
        let q = AudioQueue::new(Duration::from_millis(50));
        assert!(q.push(chunk(20)));
        assert!(q.push(chunk(20)));
        assert_eq!(q.queued_ms(), 40);
        // The third one takes the queue over 50 ms: the **first** is the one to go.
        assert!(!q.push(chunk(20)), "something was dropped");
        assert_eq!(q.queued_ms(), 40, "the queue settled back under the limit");
        assert_eq!(q.stats().dropped.load(Ordering::Relaxed), 1);
        let first = q.pop(Duration::ZERO).expect("a chunk");
        assert_eq!(
            first.data.len(),
            20 * 192,
            "the second push is what is heard"
        );
    }

    #[test]
    fn a_push_never_waits_even_when_nobody_is_playing() {
        // A queue that is never drained is the worst case: the reader must still return at
        // once, and the queue must not grow without bound.
        let q = AudioQueue::new(Duration::from_millis(30));
        let start = Instant::now();
        for _ in 0..1000 {
            q.push(chunk(10));
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_millis(500),
            "1000 pushes took {elapsed:?}"
        );
        assert!(q.queued_ms() <= 30, "the queue stayed inside its limit");
        assert!(q.stats().dropped.load(Ordering::Relaxed) > 0);
    }

    #[test]
    fn the_player_gets_what_was_pushed_in_order() {
        let q = AudioQueue::new(Duration::from_secs(1));
        for _ in 0..3 {
            q.push(chunk(10));
        }
        for _ in 0..3 {
            assert_eq!(q.pop(Duration::ZERO).unwrap().stream, 1);
        }
        assert_eq!(q.stats().played.load(Ordering::Relaxed), 3);
        assert!(q.pop(Duration::from_millis(10)).is_none(), "nothing left");
    }

    #[test]
    fn the_high_water_mark_says_how_long_the_queue_got() {
        let q = AudioQueue::new(Duration::from_millis(200));
        q.push(chunk(60));
        q.push(chunk(60));
        assert_eq!(q.stats().high_water_ms.load(Ordering::Relaxed), 120);
    }
}
