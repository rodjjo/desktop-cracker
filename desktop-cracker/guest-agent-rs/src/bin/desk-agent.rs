//! **deskd** — the guest's agent: the screen, and the verbs the guest's init and its tools use.
//!
//! `desk-agent <verb> …`, the same command line the C agent had, so the initramfs, the disk's
//! service files and the guest's own tools keep working:
//!
//! ```text
//!   desk-agent display <width> <height>   the screen, for as long as the guest lives
//!   desk-agent ready "<line>"             say a line on the console and on the readiness channel
//! ```
//!
//! The `display` verb is the one this first step of the port carries: it is where the freeze was,
//! and it is where the guest's own code can be exercised out of the VM. The
//! other verbs are added to this binary as their own subjects are ported; nothing here changes what
//! the guest does.

use guest_agent_rs::channel;
use guest_agent_rs::display::{DisplayClient, GuestIo, Screen};
use guest_agent_rs::session::{self, SessionPlan};

fn main() {
    // **A broken channel is an error, not a death.**  A screen whose host has gone must end its own
    // loop and say so, not be killed by the write that noticed: `SIGPIPE` is ignored here, once,
    // before any of the services is started (the C agent does not ignore it, which is one of the
    // ways a guest's screen could disappear without a word).
    // SAFETY: the disposition is set before any thread exists, and `SIG_IGN` is a valid handler.
    unsafe { libc::signal(libc::SIGPIPE, libc::SIG_IGN) };

    let args: Vec<String> = std::env::args().skip(1).collect();
    let code = match args.first().map(String::as_str) {
        Some("display") => display(&args[1..]),
        Some("ready") => channel::ready(args.get(1).map(String::as_str).unwrap_or("DESK-READY")),
        Some("session") => session::run(SessionPlan::parse(&args[1..])),
        Some("net") => guest_agent_rs::net::run(&args[1..]),
        Some("job") => session::do_job(),
        Some("audio") => guest_agent_rs::audio::run(&args[1..]),
        Some("share") => {
            // `desk-agent share <tag> <port> <where> <ro|rw>`
            if args.len() < 5 {
                guest_agent_rs::console::note("deskd: share needs <tag> <port> <where> <ro|rw>");
                2
            } else {
                let port = args[2].parse::<u32>().unwrap_or(0);
                guest_agent_rs::share::mount_and_serve(&args[1], port, &args[3])
            }
        }
        Some("shutdown") => {
            let mut watch = None;
            let mut i = 1;
            while i < args.len() {
                if args[i] == "--watch" {
                    i += 1;
                    watch = args.get(i).cloned();
                }
                i += 1;
            }
            guest_agent_rs::shutdown::run(watch.as_deref())
        }
        Some("control") => {
            let names: Vec<&str> = args[1..].iter().map(String::as_str).collect();
            session::do_control(&names)
        }
        // **The verbs this program does not own yet** go to the C agent beside it, unchanged:
        // the guest keeps its shares, its sound, its network and its way out while the port
        // proceeds, and no service is ever missing for the sake of a rewrite.
        Some(verb) if channel::is_legacy(verb) => channel::run_legacy(&args),
        Some(other) => {
            guest_agent_rs::console::note(&format!("deskd: unknown request {other}"));
            2
        }
        None => {
            eprintln!(
                "usage: desk-agent display <width> <height>\n\
                        desk-agent ready \"<line>\"\n\
                        desk-agent session [--watch FILE] [--iface NAME] [--guest IP] \
                [--prefix N] [--gateway IP] [--mtu N] [command…]\n\
                        desk-agent control <name>…"
            );
            2
        }
    };
    std::process::exit(code);
}

/// `desk-agent display <width> <height>`: the screen, for as long as the guest lives.
///
/// The module is the caller's business (the init loads it with the geometry the run decided), so
/// this only maps what the module published and talks to the host — the C agent's own contract.
fn display(args: &[String]) -> i32 {
    let (Some(width), Some(height)) = (
        args.first().and_then(|s| s.parse::<u32>().ok()),
        args.get(1).and_then(|s| s.parse::<u32>().ok()),
    ) else {
        eprintln!("deskd: display needs <width> <height>");
        return 2;
    };

    let (screen, _framebuffer) = match guest_agent_rs::fb::Framebuffer::open().and_then(|fb| {
        let mapping = fb.map()?;
        let stride = fb.info.stride as usize;
        // SAFETY: the mapping is the module's screen, alive for as long as `_framebuffer` is, and
        // the guest's own X server writes into it — which is the contract `Screen` documents.
        let screen = unsafe {
            Screen::from_mapping(
                mapping.as_ptr(),
                mapping.len(),
                fb.info.width as usize,
                fb.info.height as usize,
                stride,
            )
        };
        Ok((screen, fb))
    }) {
        Ok(pair) => pair,
        Err(e) => {
            eprintln!("deskd: the framebuffer's own size: {e}");
            return 1;
        }
    };
    if screen.width != width as usize || screen.height != height as usize {
        println!(
            "DESK-DISPLAY the module says {}x{} (the run asked for {width}x{height})",
            screen.width, screen.height
        );
    }

    let Some(channel) = channel::dial(channel::ports::DISPLAY) else {
        eprintln!("deskd: the display channel did not answer");
        return 1;
    };
    let io = GuestIo::new(channel).create_devices(width, height);
    let mut client = DisplayClient::new(screen, io);
    if let Err(e) = client.announce() {
        eprintln!("deskd: the display channel: {e}");
        return 1;
    }
    println!(
        "DESK-DISPLAY {}x{}, damage by rectangle; keyboard and pointer on /dev/uinput",
        client.screen.width, client.screen.height
    );

    // **The loop**: one pass at a time, and nothing else.  A pass that cannot write is the channel
    // gone, which is the run's own end (the C agent's `return 0`).
    loop {
        if !client.pass() {
            guest_agent_rs::console::say("deskd: the display channel is gone");
            return 0;
        }
        let stats = client.stats();
        if stats.frames > 0 && stats.frames % 1000 == 0 {
            guest_agent_rs::console::say(&stats.report());
        }
    }
}
