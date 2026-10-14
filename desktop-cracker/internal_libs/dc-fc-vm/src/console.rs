//! **The guest's console, as this process sees it.**
//!
//! Firecracker hands the application a pipe it was told to write the serial to; with
//! Firecracker there is no such option, because the guest's serial *is*
//! Firecracker's own **stdout** (`devices/legacy/serial.rs`,
//! `SerialOutInner::Stdout`, and `--serial` does not exist — checked against
//! `src/firecracker/src/main.rs`'s argument list).  Everything the guest prints
//! therefore arrives on the child's stdout, and the application's console echo
//! is a reader on that pipe.
//!
//! **Firecracker's own log is on that same stream** (measured on this host
//! 2026-10-09: with stdout and stderr captured to two files, everything —
//! "Running Firecracker v1.17.0", the API server's lines and the VMM's `vcpu: IO
//! write @ 0x70 failed` — lands on **stdout**, and stderr stays empty).  The two
//! are therefore told apart by their shape, line by line, rather than by the
//! stream: a Firecracker log line begins with an RFC 3339 timestamp and a
//! bracketed instance-and-thread tag (`2026-10-09T18:30:05.17 [anonymous-instance:main] …`),
//! and a guest line is everything else.  A person reading the run should not have
//! the guest's boot log and the VMM's lines mixed, and one of the VMM's lines is
//! normal (that `0x70` write is the guest's kernel looking for a CMOS RTC
//! Firecracker does not have).
//!
//! Two rules of this project hold here unchanged:
//!
//! * **nothing is written to disk** — the console is memory, bounded, and it is
//!   the pipe the child writes to and this process reads;
//! * **nothing is printed per frame or per packet** — what is echoed is what the
//!   *guest* printed, and the guest's own tools print milestones and nothing else.
//!
//! The reader thread is the only thread this module starts, and it ends by
//! itself when the pipe closes (the child is gone), so nothing has to be joined,
//! waited on or killed.

use std::io::Read;
use std::sync::{Arc, Mutex};

/// A bounded text buffer fed by a reader thread.
///
/// The bound is what keeps a guest that prints for hours from growing this
/// without end, and the cut is at a line boundary: a half line in the ring is a
/// line the run would then ask its questions of.
#[derive(Clone, Debug)]
pub struct Text {
    held: Arc<Mutex<String>>,
    limit: usize,
}

impl Default for Text {
    fn default() -> Self {
        // **A MiB is not enough text to ask a question of.**  The console is where the run reads
        // *backwards* for the guest's own sentences — `DESK-SHARE fail …`, `DESK-ROOT wrong-password
        // …`, `did not start` — and a guest that has been up for a while prints far more than a
        // megabyte (a browser alone fills one in minutes).  With the ring at a MiB, a share that
        // failed to mount early in the run is *gone* by the time anything looks, and the run looks
        // healthy while the guest says it is not (measured 2026-10-10: a shared folder that
        // answered "Permission denied", with nothing about it left to read).  Sixteen MiB holds a
        // long session's worth of the guest's own lines and costs nothing but the memory.
        Text::with_limit(16 << 20)
    }
}

impl Text {
    pub fn with_limit(limit: usize) -> Text {
        Text {
            held: Arc::new(Mutex::new(String::new())),
            limit,
        }
    }

    /// Read `out` on a thread of its own until it ends, appending what arrives.
    pub fn follow(&self, mut out: impl Read + Send + 'static) {
        let this = self.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                match out.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => this.push(&String::from_utf8_lossy(&buf[..n])),
                }
            }
        });
    }

    /// Append text, keeping the buffer inside its bound.
    ///
    /// The bound is enforced here rather than only in the reader, so the ring is
    /// never bigger than it says it is whichever way text arrives — and the cut is
    /// at a **line boundary**: a half line in the ring is a line the run would
    /// then ask its questions of.
    pub fn push(&self, text: &str) {
        if let Ok(mut held) = self.held.lock() {
            held.push_str(text);
            if held.len() > self.limit {
                let cut = held.len() - self.limit;
                let at = held[cut..]
                    .find('\n')
                    .map(|i| cut + i + 1)
                    .unwrap_or(held.len());
                held.drain(..at);
            }
        }
    }

    /// Everything kept, as one string.
    pub fn text(&self) -> String {
        self.held.lock().map(|t| t.clone()).unwrap_or_default()
    }

    /// The last `n` lines — the sentence a failed boot prints.
    pub fn tail(&self, n: usize) -> String {
        self.text()
            .lines()
            .rev()
            .take(n)
            .collect::<Vec<_>>()
            .into_iter()
            .rev()
            .collect::<Vec<_>>()
            .join("\n")
    }

    /// The text from byte `from` onwards, and the new offset — the echo's own
    /// cursor.
    pub fn since(&self, from: &mut usize) -> String {
        let held = self.text();
        if held.len() <= *from {
            return String::new();
        }
        let fresh = held[*from..].to_string();
        *from = held.len();
        fresh
    }

    /// Does it contain `marker`?
    pub fn contains(&self, marker: &str) -> bool {
        self.text().contains(marker)
    }

    /// How much is held, in bytes.
    pub fn len(&self) -> usize {
        self.held.lock().map(|t| t.len()).unwrap_or(0)
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Wait until `marker` appears, or `timeout` passes.  The wait is the
    /// *caller's* bound, and the polling interval is small enough that a marker
    /// arriving between two ticks is seen at the next one (the two are 5 ms
    /// apart, which is measured, not guessed: the guest's `DESK-READY` arrives
    /// ~440 ms after the machine starts).
    pub fn wait_for(&self, marker: &str, timeout: std::time::Duration) -> bool {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            if self.contains(marker) {
                return true;
            }
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        false
    }
}

/// The two channels a Firecracker child has: the guest's serial on its stdout,
/// and the VMM's own lines on its stderr.
#[derive(Clone, Debug, Default)]
pub struct Console {
    /// What the **guest** printed (`DESK-READY`, its own milestones, its errors).
    pub guest: Text,
    /// What **Firecracker** logged.  Normally empty at the default warning level;
    /// when it is not, it is the machine's own account of what went wrong.
    pub vmm: Text,
}

impl Console {
    pub fn new() -> Console {
        Console {
            guest: Text::default(),
            vmm: Text::default(),
        }
    }

    /// Hand it the child's pipes.  Called once, by the machine: the pipes belong
    /// to that child, and reading them is what keeps them from filling up and
    /// stalling the machine.
    ///
    /// The stdout reader **splits what it reads into lines** and files each one as
    /// the guest's or the VMM's ([`is_vmm_log_line`]), because both write to that
    /// one stream; stderr is filed as the VMM's whole.
    pub fn follow(&self, stdout: impl Read + Send + 'static, stderr: impl Read + Send + 'static) {
        let this = self.clone();
        std::thread::spawn(move || {
            let mut out = stdout;
            let mut buf = [0u8; 4096];
            let mut pending = String::new();
            loop {
                match out.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        pending.push_str(&String::from_utf8_lossy(&buf[..n]));
                        while let Some(at) = pending.find('\n') {
                            let line: String = pending.drain(..=at).collect();
                            this.file_line(&line);
                        }
                    }
                }
            }
            if !pending.is_empty() {
                this.file_line(&pending);
            }
        });
        let vmm = self.vmm.clone();
        std::thread::spawn(move || {
            let mut err = stderr;
            let mut buf = [0u8; 4096];
            loop {
                match err.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => vmm.push(&String::from_utf8_lossy(&buf[..n])),
                }
            }
        });
    }

    /// Put one line where it belongs.
    fn file_line(&self, line: &str) {
        if is_vmm_log_line(line) {
            self.vmm.push(line);
        } else {
            self.guest.push(line);
        }
    }

    /// Everything the guest said.
    pub fn text(&self) -> String {
        self.guest.text()
    }

    pub fn tail(&self, n: usize) -> String {
        self.guest.tail(n)
    }

    pub fn since(&self, from: &mut usize) -> String {
        self.guest.since(from)
    }

    /// The guest's own ready marker, when this run's guest has one.
    pub fn wait_ready(&self, marker: &str, timeout: std::time::Duration) -> bool {
        self.guest.wait_for(marker, timeout)
    }
}

/// Is this line Firecracker's own log rather than the guest's serial?
///
/// The shape of every line Firecracker writes: an RFC 3339 timestamp, a space, and
/// a bracketed tag naming the instance and the thread that wrote it —
/// `2026-10-09T18:30:05.173900304 [anonymous-instance:fc_api] The API server
/// received a Get request on "/version".`
///
/// The instance's name is the caller's (`--id`), so nothing here matches on
/// "anonymous-instance": what is matched is the *form*, which the guest's own
/// console output does not have.
pub fn is_vmm_log_line(line: &str) -> bool {
    let line = line.trim_end_matches(['\r', '\n']);
    let Some((stamp, rest)) = line.split_once(' ') else {
        return false;
    };
    let rest = rest.trim_start();
    looks_like_timestamp(stamp) && rest.starts_with('[') && rest.contains("] ")
        || (looks_like_timestamp(stamp) && rest.starts_with('[') && rest.ends_with(']'))
}

/// `2026-10-09T18:30:05.173900304` — a date, a `T`, a time, optionally a fraction.
fn looks_like_timestamp(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.len() < 19 {
        return false;
    }
    let digits = |range: std::ops::Range<usize>| bytes[range].iter().all(u8::is_ascii_digit);
    digits(0..4)
        && bytes[4] == b'-'
        && digits(5..7)
        && bytes[7] == b'-'
        && digits(8..10)
        && bytes[10] == b'T'
        && digits(11..13)
        && bytes[13] == b':'
        && digits(14..16)
        && bytes[16] == b':'
        && digits(17..19)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn what_is_pushed_comes_back_as_a_tail_of_lines() {
        let text = Text::with_limit(4096);
        text.push("one\ntwo\nthree\n");
        assert_eq!(text.tail(2), "two\nthree");
        assert_eq!(text.len(), 14);
    }

    #[test]
    fn the_echo_cursor_only_hands_over_what_is_new() {
        let text = Text::with_limit(4096);
        text.push("first\n");
        let mut cursor = 0;
        assert_eq!(text.since(&mut cursor), "first\n");
        assert_eq!(text.since(&mut cursor), "", "nothing new is nothing");
        text.push("second\n");
        assert_eq!(text.since(&mut cursor), "second\n");
    }

    #[test]
    fn a_guest_that_prints_without_end_does_not_grow_the_buffer() {
        let line = "a line of the guest that keeps talking\n";
        let text = Text::with_limit(64);
        for _ in 0..100 {
            text.push(line);
        }
        // The bound is the bound: at most one whole line over it, because the cut
        // is at a line boundary.
        assert!(text.len() <= 64 + line.len(), "held {} bytes", text.len());
        // The cut is at a line boundary, so what is held is whole lines.
        assert!(text.text().starts_with("a line"), "{:?}", text.text());
        assert!(text.text().ends_with('\n'));
    }

    #[test]
    fn a_marker_is_waited_for_and_then_found() {
        let text = Text::default();
        text.push("GUEST init: 6.1.155 / x86_64, 12 cpu(s)\n");
        assert!(text.wait_for("GUEST init:", Duration::from_millis(50)));
        assert!(!text.contains("DESK-READY"));
    }

    #[test]
    fn a_marker_that_never_comes_ends_the_wait_with_false() {
        let text = Text::default();
        let started = std::time::Instant::now();
        assert!(!text.wait_for("DESK-READY", Duration::from_millis(30)));
        assert!(started.elapsed() >= Duration::from_millis(25));
    }

    #[test]
    fn the_pipe_a_child_writes_is_read_into_the_buffer() {
        let text = Text::default();
        text.follow(&b"GUEST init: 6.1.155 / x86_64, 12 cpu(s)\nDESK-READY\n"[..]);
        assert!(
            text.wait_for("DESK-READY", Duration::from_millis(200)),
            "{:?}",
            text.text()
        );
        assert_eq!(text.tail(1), "DESK-READY");
    }

    #[test]
    fn the_guest_and_the_vmm_are_kept_apart() {
        let console = Console::new();
        console.guest.push("DESK-READY\n");
        console.vmm.push("vcpu: IO write @ 0x70 failed\n");
        assert_eq!(console.tail(1), "DESK-READY");
        assert!(console.vmm.contains("0x70"));
        assert!(
            !console.text().contains("0x70"),
            "the VMM's lines are not the guest's"
        );
    }

    #[test]
    fn a_firecracker_line_is_told_from_a_guest_line_by_its_shape() {
        // Measured lines, both from the same stream (Firecracker writes its log to
        // stdout, where the guest's serial also goes).
        for line in [
            "2026-10-09T18:30:05.173900304 [anonymous-instance:main] Running Firecracker v1.17.0",
            "2026-10-09T18:30:05.174065678 [anonymous-instance:main] Listening on API socket (\"/run/api.sock\").",
            "2026-10-09T18:29:51.087394363 [anonymous-instance:fc_vcpu 4] vcpu: IO read @ 0x87:0x1 failed: Failed to find address range.",
            "2026-10-09T18:29:51.116641211 [anonymous-instance:fc_vcpu 4] [Balloon:balloon] notifying queues",
            "2026-10-09T18:30:05.174 [my-instance:main] some other instance",
            "2026-10-09T18:30:05 [i:main]",
        ] {
            assert!(is_vmm_log_line(line), "should be the VMM's: {line}");
        }
        for line in [
            "GUEST init: 6.1.155+ / x86_64, 12 cpu(s)",
            "DESK-READY initramfs MemTotal=609104",
            "[    0.211910] RAX: ffffffffffffffda RBX: 000000002e6a9750",
            "DISK-MOUNT-RW-OK",
            "/bin/sh: can't access tty; job control turned off",
            "",
            "2026-10-09T18:30:05 hello from the guest, which is a day and a time",
            "not a 2026-10-09T18:30:05 [tag] line at all",
        ] {
            assert!(!is_vmm_log_line(line), "should be the guest's: {line}");
        }
    }

    #[test]
    fn one_stream_carrying_both_is_split_line_by_line() {
        // The real thing: Firecracker's own lines and the guest's serial arrive on
        // stdout, interleaved, and a line can be cut in half by a read.
        let console = Console::new();
        let stream: &[u8] = b"2026-10-09T18:29:51.08 [i:fc_vcpu 0] vcpu: IO read @ 0x87:0x1 failed.\nGUEST init: 6.1.155+ / x86_64, 12 cpu(s)\n2026-10-09T18:29:51.11 [i:fc_api] The API server received a Get request.\nDESK-READY initramfs MemTotal=609104\n";
        console.follow(stream, std::io::empty());
        assert!(
            console
                .guest
                .wait_for("DESK-READY", Duration::from_millis(500)),
            "{:?}",
            console.text()
        );
        assert_eq!(
            console.tail(2),
            "GUEST init: 6.1.155+ / x86_64, 12 cpu(s)\nDESK-READY initramfs MemTotal=609104"
        );
        assert!(console.vmm.contains("0x87"), "{:?}", console.vmm.text());
        assert!(console.vmm.contains("fc_api"), "{:?}", console.vmm.text());
        assert!(
            !console.text().contains("anonymous-instance"),
            "the VMM's lines stay out of the guest's"
        );
        assert!(!console.text().contains("fc_api"));
    }

    #[test]
    fn a_guest_line_that_arrives_in_pieces_is_one_line() {
        let console = Console::new();
        console.follow(&b"DESK-REA"[..], std::io::empty());
        std::thread::sleep(Duration::from_millis(20));
        assert!(!console.guest.contains("DESK-READY"));
        // A second stream through the same console: the reader that had half a
        // line is the machine's, and a new run starts clean.
        let console = Console::new();
        console.follow(&b"DESK-READY\n"[..], std::io::empty());
        assert!(console
            .guest
            .wait_for("DESK-READY", Duration::from_millis(500)));
    }
}
