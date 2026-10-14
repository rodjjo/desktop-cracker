//! **What the guest says on its console.**
//!
//! The guest's console is what a person reads (Console: , echoed by the run), and the
//! agent's lines have to arrive **as they happen**: Rust's `println!` is buffered when its output is
//! a pipe — and the guest's console is exactly that — so a milestone that sits in a buffer until the
//! process ends is a guest that looks like it never booted.  The C agent flushed every line
//! (`fflush(stdout)`); this is the same rule, in one place.
//!
//! Nothing here is a log: the lines are the guest's own milestones (what it brought up, what it
//! could not), and there is no per-frame or per-packet line anywhere in this crate.

use std::io::Write;

/// Say a line on the console, **now**.
pub fn say(line: &str) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}

/// Say something on the error stream, now (a problem a person needs to see).
pub fn note(line: &str) {
    let mut out = std::io::stderr().lock();
    let _ = writeln!(out, "{line}");
    let _ = out.flush();
}
