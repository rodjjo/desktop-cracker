//! The host's sound device, through **`libpulse-simple`**.
//!
//! Four calls (`pa_simple_new`, `pa_simple_write`, `pa_simple_drain`, `pa_simple_free`) and
//! one small library — the desktop's own sound server, so what the user hears is what their
//! desktop is configured to play.  It is deliberately *not* a game-audio API: this project's
//! whole shape is "nothing on the display path may be delayed by anything else", and a
//! library that owns a window, an audio device, an event queue and a mixer thread makes that
//! promise impossible to keep.
//!
//! ```text
//!   the gate says "play" ──▶ pa_simple_write ──▶ PulseAudio/PipeWire ──▶ the speakers
//!   the gate says "discard" ─▶ the bytes are counted and never written
//! ```
//!
//! The rule stays where it was (`dc-audio`'s gate): this sink is only *where* the bytes go
//! when the rule is open, and it is deliberately a blocking write on a buffer the server
//! drains — a sink that can block its caller is exactly what the WAV and counting sinks
//! give the tests, and the audio path calls it from its own thread.
//!
//! A host with no sound server (`pa_simple_new` fails) leaves the guest with its sound card
//! and a counting sink: the counters still say what was played and what was dropped, which
//! is what the audio system test asserts.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

use crate::Sink;
pub use dc_display::audio_format::StreamFormat;

/// The PulseAudio simple API, as `libpulse-simple` declares it.
mod ffi {
    use std::os::raw::{c_char, c_int, c_void};

    /// `pa_stream_direction_t`: `PA_STREAM_PLAYBACK` is 1.
    pub const PA_STREAM_PLAYBACK: c_int = 1;
    /// `PA_SAMPLE_S16LE` (from `pa_sample_format_t`).
    pub const PA_SAMPLE_S16LE: c_int = 3;

    /// `pa_sample_spec`.
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    pub struct PaSampleSpec {
        /// `pa_sample_format_t`.
        pub format: c_int,
        /// Samples per second.
        pub rate: u32,
        /// Channels.
        pub channels: u8,
    }

    #[link(name = "pulse-simple")]
    extern "C" {
        /// `pa_simple_new(server, name, dir, dev, stream_name, ss, map, attr, error)`.
        pub fn pa_simple_new(
            server: *const c_char,
            name: *const c_char,
            dir: c_int,
            dev: *const c_char,
            stream_name: *const c_char,
            ss: *const PaSampleSpec,
            map: *const c_void,
            attr: *const c_void,
            error: *mut c_int,
        ) -> *mut c_void;
        /// `pa_simple_write(s, data, bytes, error)`.
        pub fn pa_simple_write(
            s: *mut c_void,
            data: *const c_void,
            bytes: usize,
            error: *mut c_int,
        ) -> c_int;
        /// `pa_simple_drain(s, error)`: wait until the server has played what was written.
        pub fn pa_simple_drain(s: *mut c_void, error: *mut c_int) -> c_int;
        /// `pa_simple_free(s)`.
        pub fn pa_simple_free(s: *mut c_void);
    }

    // `pa_strerror` lives in **libpulse**, not in libpulse-simple (the simple API only
    // *includes* the header): a program that uses it has to link both.  Measured — the simple
    // library exports the four `pa_simple_*` calls and nothing else.
    #[link(name = "pulse")]
    extern "C" {
        /// `pa_strerror(error)`.
        pub fn pa_strerror(error: c_int) -> *const c_char;
    }
}

/// A sink on the host's default output device, through PulseAudio's simple API.
pub struct PulseSink {
    /// The `pa_simple` handle.  `None` after the device went away (a server that stopped):
    /// the bytes are then counted and dropped, which is the same behaviour as a host with
    /// no sound at all.
    handle: Mutex<Option<usize>>,
    /// The format the device was opened with, for the counters and the log.
    format: StreamFormat,
    /// What this sink has written (the audio path counts drops itself).
    bytes: AtomicU64,
}

impl PulseSink {
    /// Open the host's default output device, or `None` when there is no sound server.
    pub fn open(format: StreamFormat) -> Option<PulseSink> {
        let spec = ffi::PaSampleSpec {
            format: ffi::PA_SAMPLE_S16LE,
            rate: format.freq,
            channels: format.channels.max(1),
        };
        let name = c"desktop-cracker".as_ptr();
        let stream = c"the microvm's sound".as_ptr();
        let mut error: std::os::raw::c_int = 0;
        // SAFETY: every pointer is either null (meaning "the default") or a `'static` C
        // string, and `spec` is a `#[repr(C)]` struct that lives for the call.
        let handle = unsafe {
            ffi::pa_simple_new(
                std::ptr::null(),
                name,
                ffi::PA_STREAM_PLAYBACK,
                std::ptr::null(),
                stream,
                &spec,
                std::ptr::null(),
                std::ptr::null(),
                &mut error,
            )
        };
        if handle.is_null() {
            let _why = unsafe {
                let text = ffi::pa_strerror(error);
                if text.is_null() {
                    "the sound server refused the stream".to_string()
                } else {
                    std::ffi::CStr::from_ptr(text).to_string_lossy().to_string()
                }
            };
            return None;
        }
        dc_common::milestone!(
            "audio: playing through the host's output at {} Hz, {} channel(s) (PulseAudio)",
            format.freq,
            format.channels
        );
        Some(PulseSink {
            handle: Mutex::new(Some(handle as usize)),
            format,
            bytes: AtomicU64::new(0),
        })
    }

    /// How many bytes this sink has handed to the sound server.
    pub fn bytes(&self) -> u64 {
        self.bytes.load(Ordering::Relaxed)
    }

    /// The format it was opened with (the guest's stream format).
    pub fn format(&self) -> StreamFormat {
        self.format
    }
}

impl Sink for PulseSink {
    fn write(&self, _stream: u64, data: &[u8], _format: StreamFormat) -> anyhow::Result<()> {
        let guard = self.handle.lock().unwrap_or_else(|p| p.into_inner());
        let Some(handle) = *guard else {
            // The device went away: count it and carry on.  A guest whose sound is
            // "played" into nothing is better than one whose audio thread panics.
            self.bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
            return Ok(());
        };
        let mut error: std::os::raw::c_int = 0;
        // SAFETY: `handle` came from `pa_simple_new` and is freed only in `Drop` (which
        // takes the same lock); `data` is valid for `data.len()` bytes.
        let rc = unsafe {
            ffi::pa_simple_write(
                handle as *mut std::os::raw::c_void,
                data.as_ptr() as *const std::os::raw::c_void,
                data.len(),
                &mut error,
            )
        };
        if rc != 0 {
            let why = unsafe {
                let text = ffi::pa_strerror(error);
                if text.is_null() {
                    "the sound server refused the write".to_string()
                } else {
                    std::ffi::CStr::from_ptr(text).to_string_lossy().to_string()
                }
            };
            anyhow::bail!(
                "pa_simple_write refused {len} bytes: {why}",
                len = data.len()
            );
        }
        self.bytes.fetch_add(data.len() as u64, Ordering::Relaxed);
        Ok(())
    }
}

impl Drop for PulseSink {
    fn drop(&mut self) {
        let handle = self.handle.lock().unwrap_or_else(|p| p.into_inner()).take();
        if let Some(handle) = handle {
            // SAFETY: the handle came from `pa_simple_new`, and this is the only place it is
            // freed (the lock means nobody is writing while it happens).
            unsafe {
                let mut error = 0;
                let _ = ffi::pa_simple_drain(handle as *mut std::os::raw::c_void, &mut error);
                ffi::pa_simple_free(handle as *mut std::os::raw::c_void);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sample_spec_is_the_guest_s_format() {
        // The audio path opens the device with the guest's own format, so nothing resamples
        // between the microvm's sound card and the speakers.
        let format = StreamFormat {
            bits: 16,
            is_signed: true,
            is_float: false,
            freq: 48000,
            channels: 2,
            bytes_per_frame: 4,
            bytes_per_second: 48000 * 2 * 2,
            big_endian: false,
        };
        let spec = ffi::PaSampleSpec {
            format: ffi::PA_SAMPLE_S16LE,
            rate: format.freq,
            channels: format.channels,
        };
        assert_eq!(spec.rate, 48000);
        assert_eq!(spec.channels, 2);
        assert_eq!(spec.format, 3, "PA_SAMPLE_S16LE");
    }

    #[test]
    fn a_sink_with_no_server_counts_instead_of_failing() {
        // The behaviour a headless host gets: no sound server, no panic, and the counters
        // still say what the guest produced.
        let sink = PulseSink {
            handle: Mutex::new(None),
            format: StreamFormat::default(),
            bytes: AtomicU64::new(0),
        };
        sink.write(0, &[0u8; 128], StreamFormat::default()).unwrap();
        assert_eq!(sink.bytes(), 128);
    }
}
