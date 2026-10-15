//! **Does the whole run work, with the project's own guest?**
//!
//! An example rather than a test: a unit test must not need KVM or a guest (`AGENTS.md`),
//! and the one running system test belongs to this project's last step.  This is the
//! middle: the run crate against a real Firecracker and a real guest — the same thing the
//! application will do, minus the window.
//!
//! ```text
//! cd desktop-cracker
//! cargo run --release --example run -- \
//!     --firecracker ../temp/fc-study/bin/firecracker \
//!     --kernel      ../temp/fc-study/out/vmlinux-6.1.155 \
//!     --initramfs   guest-agent/out/initramfs-agent.gz \
//!     --rootfs      ../download/rootfs.ext4 --rootfs-ro --vcpus 12 --memory 6144
//! ```
//!
//! What it prints is what a person would see from a run of the application: the milestone
//! lines, the guest's own landmark, the boot's breakdown, the balloon's own numbers, and
//! the shutdown's outcome.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use fc_run::{milestone, RunSpec};

/// The rule the sound is put through is the project's own (`dc-audio::AudioPath`), and its
/// window state is what the window would keep.
use dc_display::window::WindowState;

struct Args {
    firecracker: PathBuf,
    kernel: PathBuf,
    initramfs: Option<PathBuf>,
    rootfs: PathBuf,
    rootfs_ro: bool,
    vcpus: u32,
    memory: u64,
    balloon: Option<u64>,
    run_dir: PathBuf,
    timeout: Duration,
    /// Skip the readiness channel, to see what a run without an agent does.
    no_readiness: bool,
    /// How long to let the guest run after it is up, echoing its console.
    settle_ms: u64,
    /// **The guest's screen**, when the run has one: `WIDTHxHEIGHT` — what the display
    /// service decided before the guest booted.  Absent is a run with no screen (this project
    /// is being measured, or the job is a disk's); a real run always has one.
    display: Option<String>,
    /// **The host port that becomes a connection to the guest's sshd** (`--ssh-port`).  Absent
    /// is the project's own rule: **no socket on the host at all**.
    ssh_port: Option<u16>,
    /// **Whether the guest can be asked to go away**: the run then binds the shutdown channel
    /// (57000) and the guest's agent opens it, so the run's own shutdown reaches a guest that is
    /// still in its initramfs.  A real run always has it.
    can_shutdown: bool,
    /// **Forward remote X**: the guest's X clients dial port 1026 and their connections are
    /// passed to this X socket (the host's own).
    x_socket: Option<PathBuf>,
    /// **The guest's sound**: with it, the run listens on the audio channel and the guest's
    /// own loopback card is read; without it, the guest has no sound card and no channel is
    /// bound.  What is heard is the project's rule, applied by a sink that counts (this example
    /// has no window to be visible and no sound device to play through).
    audio: bool,
    /// Shared folders to offer the guest, `tag:path[:where][:ro]`, repeatable.  The tag is the
    /// guest's own name for the folder, `where` is where it lands in the guest (default
    /// `/mnt/share/<tag>`), and the project's own tags keep their meanings and their places
    /// (`disk` → `/mnt/disk`, `xdisplay` → `/tmp/.X11-unix`).
    shares: Vec<String>,
    /// **Start the system on the disk** rather than staying in the initramfs (a real run),
    /// and the passphrase its container is opened with.  It goes into the run's control
    /// share and on to the guest over the control channel — never a file, never an
    /// argument, never the environment (`AGENTS.md`).
    root_passphrase: Option<String>,
}

const USAGE: &str = "run --firecracker PATH --kernel PATH --rootfs PATH [--initramfs PATH] \
                     [--rootfs-ro] [--vcpus N] [--memory MiB] [--balloon MiB] [--run-dir DIR] \
                     [--timeout SECONDS] [--settle MS] [--root-passphrase P] [--display WxH] [--audio] \
                     [--ssh-port N] \
                     [--x-socket PATH] \
                     [--share TAG:PATH[:WHERE][:ro]] \
                     [--no-readiness]\
\n\n  --root-passphrase starts the system **on the disk**: the guest's own initramfs opens\
 the container with this passphrase (over the control channel) and enters it.";

fn parse() -> Args {
    let mut args = Args {
        firecracker: PathBuf::new(),
        kernel: PathBuf::new(),
        initramfs: None,
        rootfs: PathBuf::new(),
        rootfs_ro: false,
        vcpus: 12,
        memory: 6144,
        balloon: Some(4096),
        run_dir: std::env::temp_dir().join(format!("dc-fc-run-{}", std::process::id())),
        timeout: Duration::from_secs(30),
        no_readiness: false,
        settle_ms: 600,
        display: None,
        ssh_port: None,
        can_shutdown: true,
        x_socket: None,
        audio: false,
        shares: Vec::new(),
        root_passphrase: None,
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut value = |what: &str| {
            it.next().unwrap_or_else(|| {
                eprintln!("{arg} needs {what}\n{USAGE}");
                std::process::exit(2)
            })
        };
        match arg.as_str() {
            "--firecracker" => args.firecracker = value("a path").into(),
            "--kernel" => args.kernel = value("a path").into(),
            "--initramfs" => args.initramfs = Some(value("a path").into()),
            "--rootfs" => args.rootfs = value("a path").into(),
            "--rootfs-ro" => args.rootfs_ro = true,
            "--vcpus" => args.vcpus = value("a count").parse().unwrap_or(12),
            "--memory" => args.memory = value("MiB").parse().unwrap_or(6144),
            "--balloon" => args.balloon = value("MiB").parse().ok(),
            "--run-dir" => args.run_dir = value("a path").into(),
            "--timeout" => {
                args.timeout = Duration::from_secs(value("seconds").parse().unwrap_or(30))
            }
            "--no-readiness" => args.no_readiness = true,
            "--settle" => args.settle_ms = value("milliseconds").parse().unwrap_or(600),
            "--root-passphrase" => args.root_passphrase = Some(value("a passphrase")),
            "--share" => args.shares.push(value("tag:path[:where][:ro]")),
            "--display" => args.display = Some(value("WIDTHxHEIGHT")),
            "--ssh-port" => args.ssh_port = value("a port").parse().ok(),
            "--audio" => args.audio = true,
            "--x-socket" => args.x_socket = Some(PathBuf::from(value("a path"))),
            "-h" | "--help" => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            other => {
                eprintln!("unknown argument {other}\n{USAGE}");
                std::process::exit(2);
            }
        }
    }
    if args.firecracker.as_os_str().is_empty()
        || args.kernel.as_os_str().is_empty()
        || args.rootfs.as_os_str().is_empty()
    {
        eprintln!("{USAGE}");
        std::process::exit(2);
    }
    args
}

fn main() {
    let args = parse();
    let _ = std::fs::remove_dir_all(&args.run_dir);

    // The shares, in the project's own shape: a tag, a folder and whether the user allowed
    // writes.  The guest's own tooling and the run's mount plan are the earlier machine's, so a
    // folder shared here looks exactly like one shared there.
    let mut shares = Vec::new();
    for spec in &args.shares {
        let (tag, rest) = spec.split_once(':').unwrap_or((spec.as_str(), ""));
        let mut parts = rest.split(':');
        let path = parts.next().unwrap_or_default();
        let mut where_ = String::new();
        let mut mode = false;
        for part in parts {
            match part {
                "ro" => mode = true,
                "rw" => mode = false,
                other => where_ = other.to_string(),
            }
        }
        if where_.is_empty() {
            // The project's own place for a folder the user shared.
            where_ = if tag == "disk" {
                dc_common::GUEST_DISK_DIR.to_string()
            } else if tag == "xdisplay" {
                dc_common::GUEST_X_DIR.to_string()
            } else {
                format!("{}/{}", dc_common::GUEST_SHARE_DIR, tag)
            };
        }
        shares.push(dc_fc_share::Share {
            tag: tag.to_string(),
            path: path.into(),
            where_,
            read_only: mode,
            // The writable exception belongs to the **control directory** the run offers its
            // guest (`share_list`); a folder named on the command line is what the user said it
            // is, and nothing else.
            writable_exception: false,
        });
    }
    // The screen, if the run was given one: the two numbers the guest's agent loads the
    // framebuffer with.  The format is the one the framebuffer publishes (`XRGB8888`, which is
    // `dc-display`'s own `PIXMAN_x8r8g8b8`), so nothing is translated on the way to the window.
    let display = args.display.as_ref().and_then(|text| {
        let (width, height) = text.split_once('x')?;
        Some(dc_fc_display::Surface {
            width: width.parse().ok()?,
            height: height.parse().ok()?,
            format: 0x2000_0000,
        })
    });
    let root_passphrase = args.root_passphrase.clone();
    let spec = RunSpec {
        kernel: dc_fc_vm::Kernel {
            image: args.kernel.clone(),
            initramfs: args.initramfs.clone(),
            append: "console=ttyS0 rdinit=/init quiet loglevel=3".into(),
        },
        root: dc_fc_vm::Disk {
            name: "rootfs".into(),
            path: args.rootfs.clone(),
            read_only: args.rootfs_ro,
        },
        vcpus: args.vcpus,
        memory_mib: args.memory,
        program: args.firecracker.clone(),
        run_dir: args.run_dir.clone(),
        balloon_mib: args.balloon,
        guest_timeout: args.timeout,
        // The system on the disk, when a passphrase was given: the guest's own initramfs
        // opens the container (`rootboot`) and enters the system, exactly as it does on the
        // the way a hardware VM's run did.
        boot_from_disk: root_passphrase.is_some(),
        root_passphrase,
        display,
        ssh_port: args.ssh_port,
        shutdown_channel: args.can_shutdown,
        x_socket: args.x_socket.clone(),
        audio: if args.audio {
            // The **rule** is the project's own (`dc-audio::AudioPath`), and this example gives
            // it the project's own window state, opened the way a run with a visible window
            // opens it.  What is heard goes to a sink that counts, because an example host has
            // no sound device to play through — the counters are what says the rule worked.
            let window = WindowState::new();
            window.set_visible(true);
            Some(Arc::new(dc_audio::AudioPath::new(
                window,
                dc_audio::CountingSink::new(),
            )) as Arc<dyn dc_fc_audio::Play>)
        } else {
            None
        },
        shares,
        ..RunSpec::default()
    };

    // The run's own start, which every milestone's number is measured from.
    let started = std::time::Instant::now();
    let mut run = match fc_run::start(spec, !args.no_readiness) {
        Ok(run) => run,
        Err(e) => {
            eprintln!("run: {e}");
            std::process::exit(1);
        }
    };
    milestone(&format!(
        "run: firecracker started in {} ms",
        started.elapsed().as_millis()
    ));

    match run.wait_for_guest() {
        Ok(line) => println!("run: the guest said: {line}"),
        Err(e) => {
            eprintln!("run: {e}");
            let _ = run.shutdown();
            std::process::exit(1);
        }
    }

    // **`--ssh-port`**, opened once the guest is up: the guest's sshd listens on 22 inside it
    // whether the switch is given or not, and the host's port is a door into it.  With no switch,
    // this prints the project's own rule rather than leaving it unsaid.
    if let Some(network) = run.network() {
        match args.ssh_port {
            Some(port) => match network.forward_ssh(port) {
                dc_net::ForwardStatus {
                    state: dc_net::ForwardState::Bound,
                    host,
                    guest_port,
                } => milestone(&format!(
                    "ssh: {host} is forwarded to the guest's sshd (the guest's port {guest_port}); \
                     it is on the host's loopback, so only this machine can reach it"
                )),
                dc_net::ForwardStatus {
                    state: dc_net::ForwardState::Failed(reason),
                    ..
                } => milestone(&format!("ssh: not forwarded ({reason})")),
            },
            None => milestone(&format!(
                "ssh: no --ssh-port, so no socket is open on the host ({} forward(s))",
                network.forwards().len()
            )),
        }
    }

    // The balloon's own numbers, as the machine reports them, and one policy step.
    if let Some(memory) = run.guest_memory() {
        milestone(&format!(
            "memory: the guest has {} MiB, {} MiB free",
            memory.total / (1024 * 1024),
            memory.free / (1024 * 1024)
        ));
    }
    match run.balloon_step() {
        Ok(Some(line)) => milestone(&line),
        Ok(None) => milestone("memory: the balloon is where the policy wants it"),
        Err(e) => milestone(&format!("memory: the balloon could not be moved: {e}")),
    }

    // A short settle: the guest is up, the run is working, and what is asked of it here
    // is that it stays quiet and answers (this project's own rule about a machine that
    // does nothing).  While it settles, the guest's console is echoed the way the
    // application echoes it: what the guest prints is what a person
    // reads, and nothing of it is written to disk.
    let settle_ms = args.settle_ms;
    let console = run.vm.console().clone();
    let mut cursor = 0usize;
    for _ in 0..(settle_ms / 200) {
        std::thread::sleep(Duration::from_millis(200));
        let fresh = console.since(&mut cursor);
        for line in fresh.lines().filter(|l| !l.trim().is_empty()) {
            println!("[guest] {line}");
        }
    }
    for line in run.drain_reports() {
        println!("run: the guest reported: {line}");
    }

    // The network's own counters: the proof that the guest's TUN is on the other end of
    // this channel and the engine answered it (a DHCP lease is four packets at least).
    if args.can_shutdown {
        milestone(&format!(
            "power: the guest's shutdown channel {}{}",
            if run.power().map(|p| p.opened()).unwrap_or(false) {
                "was opened by the guest"
            } else {
                "was never opened by the guest"
            },
            match run.power().map(|p| p.heard()).unwrap_or(0) {
                0 => String::new(),
                n => format!(", and the guest answered {n} time(s)"),
            }
        ));
    }

    // Remote X: what the guest connected to, and how often.
    if let Some(remote) = run.remote() {
        for port in remote.ports() {
            milestone(&format!(
                "remote: port {} answered {} connection(s)",
                port,
                remote.connections(port)
            ));
        }
    }

    // The sound: what the guest played, and what the rule did with it.
    if let Some(audio) = run.audio() {
        let counters = audio.counters();
        milestone(&format!(
            "audio: {} stream(s), {} buffer(s), {} KiB, {} played, {} discarded",
            counters.streams,
            counters.buffers,
            counters.bytes >> 10,
            counters.played,
            counters.discarded
        ));
    }

    // The screen: what the guest said it was, and what it drew.
    if let Some(display) = run.display() {
        let counters = display.counters();
        milestone(&format!(
            "screen: {} ({} rectangle(s), {} B, largest {} px, {} input(s)){}",
            match display.surface() {
                Some(surface) => format!("{}x{} from the guest", surface.width, surface.height),
                None => "the guest never reported it".to_string(),
            },
            counters.rectangles,
            counters.bytes,
            counters.largest,
            counters.inputs,
            if display.connected() {
                ""
            } else {
                " (the guest's agent is not connected)"
            }
        ));
    }

    // The shared folders: what each one did, in the run's own counters.
    if let Some(shares) = run.shares() {
        for (tag, counters) in shares.all() {
            milestone(&format!(
                "share {tag}: {} request(s), {} read(s), {} write(s), {} B, {} refused (ro)",
                counters.requests,
                counters.reads,
                counters.writes,
                counters.bytes,
                counters.refused_ro
            ));
        }
    }

    if let Some(network) = run.network() {
        let counters = network.counters();
        milestone(&format!(
            "network: {} packet(s) in, {} out, {} B, {} dropped",
            counters.in_packets, counters.out_packets, counters.bytes, counters.dropped
        ));
    }

    // **The shutdown, timed**: the number that says whether the guest's own reset landed (a few
    // hundred milliseconds) or the machine had to be taken away (the whole timeout).
    let shutdown_started = std::time::Instant::now();
    match run.shutdown() {
        Ok(how) => milestone(&format!(
            "run: {how} — the shutdown took {:.0} ms (the run, {} ms)",
            shutdown_started.elapsed().as_secs_f64() * 1000.0,
            started.elapsed().as_millis()
        )),
        Err(e) => {
            eprintln!("run: shutting down: {e}");
            std::process::exit(1);
        }
    }
    let _ = std::fs::remove_dir_all(&args.run_dir);
}
