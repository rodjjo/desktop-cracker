//! The terminal half of a dialog: a question on `/dev/tty`, with the password's own
//! echo turned off.
//!
//! Two things matter and both are tested: the password is never echoed, and a
//! cancelled prompt is a **refusal** (it must never open the window), which is what
//! `--set-password` and the tray's `Show window` agree on.  It is this crate's, and
//! not the application's, because the graphical dialog and the terminal prompt have to
//! be **the same question** — the caller asks once and gets the same answer type
//! either way.

use anyhow::{Context, Result};

/// Ask for a line of text on the terminal (what a dialog is not needed for).
pub fn ask_line(prompt: &str) -> Result<Option<String>> {
    use std::io::{BufRead, BufReader, Write};
    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .context("opening /dev/tty")?;
    let mut out = tty.try_clone().context("duplicating the terminal")?;
    write!(out, "{prompt}")?;
    out.flush()?;
    let mut line = String::new();
    match BufReader::new(tty).read_line(&mut line) {
        Ok(0) => Ok(None),
        Ok(_) => Ok(Some(line.trim_end_matches(['\n', '\r']).to_string())),
        Err(e) => Err(e).context("reading the terminal"),
    }
}

/// Ask for a password without echoing it.
pub fn ask_password(prompt: &str) -> Result<Option<String>> {
    use std::io::{BufRead, BufReader, Write};

    let tty = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .context("opening /dev/tty (the unlock password is asked on the terminal)")?;
    let restore = RawMode::disable_echo(&tty)?;
    let mut out = tty.try_clone().context("duplicating the terminal")?;
    write!(out, "{prompt}")?;
    out.flush()?;

    let mut line = String::new();
    let read = BufReader::new(tty).read_line(&mut line);
    drop(restore);
    writeln!(out)?;
    match read {
        Ok(0) => Ok(None), // end of input: the user cancelled
        Ok(_) => {
            let line = line.trim_end_matches(['\n', '\r']).to_string();
            if line.is_empty() {
                Ok(None)
            } else {
                Ok(Some(line))
            }
        }
        Err(e) => Err(e).context("reading the password"),
    }
}

/// Ask twice and require the same answer (what `--set-password` does).  An empty
/// answer clears the password.
pub fn ask_password_twice() -> Result<Option<String>> {
    let first = ask_password("New unlock password (empty to remove): ")?.unwrap_or_default();
    if first.is_empty() {
        return Ok(None);
    }
    let second = ask_password("Repeat it: ")?;
    match second {
        Some(s) if s == first => Ok(Some(first)),
        Some(_) => anyhow::bail!("the two passwords differ; nothing was changed"),
        None => Ok(None),
    }
}

/// Turn the terminal's echo off for as long as this value lives.
struct RawMode {
    fd: i32,
    termios: libc::termios,
}

impl RawMode {
    fn disable_echo(fd: &std::fs::File) -> Result<RawMode> {
        use std::os::unix::io::AsRawFd;
        let raw = fd.as_raw_fd();
        let mut termios: libc::termios = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(raw, &mut termios) } != 0 {
            anyhow::bail!("this is not a terminal; use `desktop-cracker --help` for the switches");
        }
        let saved = termios;
        termios.c_lflag &= !libc::ECHO;
        if unsafe { libc::tcsetattr(raw, libc::TCSANOW, &termios) } != 0 {
            anyhow::bail!("could not turn the terminal's echo off");
        }
        Ok(RawMode {
            fd: raw,
            termios: saved,
        })
    }
}

impl Drop for RawMode {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSANOW, &self.termios);
        }
    }
}
