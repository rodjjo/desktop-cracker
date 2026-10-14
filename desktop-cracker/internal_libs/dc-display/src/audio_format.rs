//! The stream format the guest's own agent reports for the sound it opened.
//!
//! It lives in its own module (rather than in `dc-audio`) so the protocol side
//! can name it without depending on the rule: `dc-audio` re-uses this type.

pub use dc_common_audio::*;

/// Re-exported shape of one playback stream.
pub mod dc_common_audio {
    /// What the machine's `Init` says about a stream.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct StreamFormat {
        pub bits: u8,
        pub is_signed: bool,
        pub is_float: bool,
        pub freq: u32,
        pub channels: u8,
        pub bytes_per_frame: u32,
        pub bytes_per_second: u32,
        pub big_endian: bool,
    }

    impl StreamFormat {
        /// How long this many bytes of the stream would play for.
        pub fn duration_of(&self, bytes: usize) -> std::time::Duration {
            if self.bytes_per_second == 0 {
                return std::time::Duration::ZERO;
            }
            std::time::Duration::from_secs_f64(bytes as f64 / self.bytes_per_second as f64)
        }
    }

    impl Default for StreamFormat {
        fn default() -> Self {
            StreamFormat {
                bits: 16,
                is_signed: true,
                is_float: false,
                freq: 48_000,
                channels: 2,
                bytes_per_frame: 4,
                bytes_per_second: 192_000,
                big_endian: false,
            }
        }
    }
}
