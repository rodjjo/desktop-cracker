//! **The guest's agent, in Rust**: the guest's own half of the run.
//!
//! The guest is the side that has the pixels, the disk job, the sound, the shares and the network,
//! and this is that side written in Rust: one binary, and the same command line the C agent had, so
//! the initramfs, the disk's own service files and the guest's tools keep working unchanged.
//!
//! Every module is a C file's own subject, and each is built so that it can be unit tested on the
//! host and exercised with no hypervisor in the way:
//!
//! * [`display`] — the screen: the framebuffer's mapping, the damage logic and the channel
//!   (`desktop-cracker-display.c`), with the rectangles, the numbering and the checksums the host's framer
//!   expects (`dc-fc-display::stream`);
//! * [`uinput`] — the guest's own input devices (`desktop-cracker-display.c`'s other half);
//! * [`fb`] — the framebuffer's control node (`desk_fb.h`'s numbers, and the mapping);
//! * [`channel`] — the vsock services the agent dials, and the readiness line;
//! * [`control`] — the control share: the run's own files, and the one direction a guest writes;
//! * [`net`] — the guest's own `tun0` and the network channel (`desk-agent.c`'s `net`);
//! * [`audio`] — the guest's sound, off the loopback card's capture side (`desktop-cracker-audio.c`);
//! * [`share`] — a shared folder, mounted and served out of the host's own filesystem
//!   (`desktop-cracker-fuse.c`);
//! * [`shutdown`] — the way out: the shutdown channel and the reboot that ends the machine;
//! * [`session`] — the guest's boot: the run's files, the modules, the screen, the sound, the
//!   shares, the network and the session's own command line (`desk-agent.c`'s `session`).

pub mod audio;
pub mod channel;

/// **The C agent, beside this one**: the verbs this program hands over until their own Rust port
/// lands (the shares, the sound, the network, the disk job).  It is the same program the guest ran
/// before, so those services behave exactly as they did.
pub const LEGACY_AGENT: &str = "/bin/desktop-cracker-legacy";
pub mod console;
pub mod control;
pub mod display;
pub mod fb;
pub mod net;
pub mod share;
pub mod shutdown;
pub mod session;
pub mod uinput;

/// The message kinds and the framer the guest and the host share (`dc-fc-display`).
pub use dc_fc_display as wire;
