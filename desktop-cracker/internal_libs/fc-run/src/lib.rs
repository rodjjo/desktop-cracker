//! # `fc-run` — one run of the Firecracker microvm
//!
//! The three crates under it are the machine (`dc-fc-vm`), the control plane
//! (`dc-fc-api`) and the guest's channels (`dc-vsock`).  This one is the **run**: the
//! order the pieces are brought up in, what a person is told while it happens, the
//! plugin seam the project tests through, and the shutdown.
//!
//! The order is not a detail — it is a rule of the project:
//!
//! ```text
//! 1  the guest's channels listen        (<uds_path>_<port>, before anything starts)
//! 2  firecracker is spawned             (a child of this process, PDEATHSIG)
//! 3  the API answers                    (a connection, not a file)
//! 4  the machine is defined             (boot source, machine, drives, vsock, balloon,
//!                                        entropy — in that order, and nothing after start)
//! 5  the machine starts                 (PUT /actions InstanceStart)
//! 6  the vCPU threads are pinned        (they exist only now: `fc_vcpu N`)
//! 7  the guest's own landmark arrives   (the readiness channel, not a console)
//! 8  the balloon is driven              (the guest's own numbers, one step at a time)
//! 9  the guest is asked to power off, the child is taken away, the sockets cleaned up
//! ```
//!
//! Two rules of the project are visible in the code rather than in a comment:
//!
//! * **nothing is written to disk** — the console, the milestone lines and the plugin's
//!   events are the run's whole output, and every path a run uses is a file socket or a
//!   disk the *user* asked for;
//! * **the plugin is not linked, it is loaded** — `dc-plugin` is the host half of the
//!   seam the project already has, and the only switch that reaches it is
//!   `--plugin-path`.  With no plugin every call here is a no-op and the run is exactly
//!   the run a person gets.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use dc_fc_api::Api;
use dc_fc_vm::{
    BalloonPolicy, CpuLayout, Disk, Kernel, MemoryManager, Spec, VmProcess, VsockDevice,
};
use dc_vsock::ports;

pub mod ready;

use dc_fc_net::Network;

pub use ready::{Event as ReadyEvent, Readiness};

/// What can go wrong during a run.
#[derive(Debug, thiserror::Error)]
pub enum RunError {
    #[error("{0}")]
    Vm(#[from] dc_fc_vm::VmError),
    #[error("{0}")]
    Api(#[from] dc_fc_api::ApiError),
    #[error("{0}")]
    Vsock(#[from] dc_vsock::VsockError),
    #[error("{0}")]
    Memory(#[from] dc_fc_vm::MemoryError),
    #[error("the run's own directory {0}: {1}")]
    Paths(PathBuf, std::io::Error),
    #[error("the guest did not come up within {0:?}:\n{1}")]
    NoGuest(Duration, String),
}

pub type Result<T> = std::result::Result<T, RunError>;

/// Where a run keeps the sockets it needs.
///
/// One directory per run, named after this process: two machines sharing a vsock
/// `uds_path` collide on the host's sockets, and a run that crashed leaves a socket
/// file behind that the next run must not trip over.  It is a directory of **sockets and
/// nothing else** — the project's own rule (`AGENTS.md`: the application creates no file
/// but the file sockets it needs).
pub fn run_directory(base: &Path, pid: u32) -> PathBuf {
    dc_common::run_directory(base, pid)
}

/// What a run is asked to be: everything the application decides before the machine
/// exists.
/// It is not `Clone`: the control share it carries **holds credentials** (a disk's passphrase),
/// and a value that can be duplicated is one that can be left in two places (`AGENTS.md`: a
/// credential lives in memory for as long as it is needed and is zeroized when it is dropped).
/// It is not `Debug` either: what plays the guest's sound is a trait object (`AudioPath`, and a
/// test's recorder), and a run's spec is not a line anybody logs.
pub struct RunSpec {
    /// The guest kernel: the project's own build.
    pub kernel: Kernel,
    /// The root disk — a raw file, the only one the run needs.
    pub root: Disk,
    /// The other disks, in the order the settings list them.
    pub disks: Vec<Disk>,
    pub vcpus: u32,
    pub memory_mib: u64,
    /// Where the guest's console is echoed from (the application's own stdout).
    pub program: PathBuf,
    /// The directory the run's sockets live in.
    pub run_dir: PathBuf,
    /// The guest's vsock context id.
    pub guest_cid: u64,
    /// The balloon's starting point, in MiB.  `None` is a machine with no balloon.
    pub balloon_mib: Option<u64>,
    /// How long the guest may take to come up.  The bound is generous and it is the
    /// **application's own**, not a test's: a machine that does not come up in it is a
    /// machine to investigate.
    pub guest_timeout: Duration,
    /// How long the guest is given to power off, once it has been asked.  A guest that
    /// does not answer is a guest the process is taken away from; the wait is bounded so
    /// that closing the window is never something a person waits on for long.
    pub shutdown_timeout: Duration,
    /// How the memory policy is written out, when the run is told to.
    pub balloon_policy: BalloonPolicy,
    /// The **control share**: the small files the guest's own tools read (the mount plan,
    /// the disks of the run, a disk's passphrase for the one job that needs one).  Empty is
    /// a run with no share at all, and a guest whose agent asks for a name gets "not here".
    pub control: dc_fc_control::Control,
    /// The **screen**, when this run has one: the geometry the display service decided before
    /// the guest booted (the host's own resolution when the guest is full screen, 1280x800,
    /// otherwise — `dc-display`'s rule).  The guest's agent loads this project's own
    /// framebuffer at this size and dials the display channel with it.
    pub display: Option<dc_fc_display::Surface>,
    /// **The host port that becomes a connection to the guest's sshd** (`--ssh-port`), when the
    /// user asked for one.  `None` is the project's own rule with its own meaning: **no socket is
    /// opened on the host at all** — the machine's network has no listener, not a closed one.
    pub ssh_port: Option<u16>,
    /// **`--host-network`**: this machine may reach the host it
    /// runs on, through the name `parenthost` and the gateway address it answers with.  `false` is
    /// the rule the network has always had, and it is what a run without the switch or the settings
    /// key is.
    pub host_network: bool,
    /// **Whether the guest can be asked to go away**: with this, the run listens on the
    /// shutdown channel and the guest's agent opens it, so [`Started::shutdown`] reaches the
    /// guest **inside** its boot and the guest's own reboot ends Firecracker (`dc-fc-power`'s
    /// own documentation says why a reboot, and not a power-off).
    pub shutdown_channel: bool,
    /// **The host's X socket**, when this run forwards remote X: the guest's X clients dial
    /// port 1026 and their connections are passed to this socket (`dc-xremote`'s own target).
    /// `None` is a run with no X forwarder — and therefore no listener on 1026.
    pub x_socket: Option<std::path::PathBuf>,
    /// **The sound**, when this run has a sound card: the PCM the guest plays is put through
    /// the project's own rule (the window must be visible and the numlock key held —
    /// `dc-audio::AudioPath`, unchanged) by the caller, which is what owns the window and the
    /// host's own sound device.
    pub audio: Option<Arc<dyn dc_fc_audio::Play>>,
    /// The **shared folders**: one listener per folder, each rooted at one host directory and
    /// knowing whether the user allowed writes (`dc-fc-share`). The set is the
    /// project's own (`dc-shares::ShareSet`): the tags, the modes and the mount plan are what
    /// the machine this project started with uses, so the guest's tools and a person's expectations do not change.
    pub shares: Vec<dc_fc_share::Share>,
    /// **The root disk's passphrase**, when this run has one to hand over: it opens the
    /// container **in the guest** — the only shape with no host privilege and no
    /// device-mapper helper on the host. It goes into the
    /// control share under the name the guest's own initramfs reads, and it is zeroized
    /// with the run.
    pub root_passphrase: Option<String>,
    /// Start the system **on the disk** rather than staying in the initramfs: what a real
    /// run does.  The initramfs' own `rootboot` reads the passphrase from the share, opens
    /// the container and switches into the system.
    pub boot_from_disk: bool,
}

impl Default for RunSpec {
    fn default() -> Self {
        RunSpec {
            kernel: Kernel {
                image: PathBuf::new(),
                initramfs: None,
                append: String::new(),
            },
            root: Disk {
                name: "rootfs".into(),
                path: PathBuf::new(),
                read_only: false,
            },
            disks: Vec::new(),
            vcpus: 1,
            memory_mib: 128,
            program: PathBuf::from("firecracker"),
            // The run's own sockets: this user's runtime directory, in a directory of
            // **this run** (`run-<pid>`).  A caller that has a directory of its own (`app/desktop`,
            // a disk job) names it; this default is the rule, not a fixed path the whole machine
            // shares.
            run_dir: dc_common::run_directory(&dc_common::runtime_dir(), std::process::id()),
            guest_cid: 3,
            balloon_mib: None,
            guest_timeout: Duration::from_secs(30),
            shutdown_timeout: Duration::from_secs(10),
            balloon_policy: BalloonPolicy::default(),
            control: dc_fc_control::Control::new(),
            display: None,
            audio: None,
            ssh_port: None,
            host_network: false,
            shutdown_channel: false,
            x_socket: None,
            shares: Vec::new(),
            root_passphrase: None,
            boot_from_disk: false,
        }
    }
}

impl RunSpec {
    /// The machine this run is of: the same answer the API is defined from, in one
    /// place, so the definition and everything that reads it (the plugins, the
    /// milestones) cannot disagree.
    pub fn machine(&self) -> Spec {
        // **The guest's own boot plan**, on the kernel's command line — the same place a
        // hardware VM puts it, plus the two words this platform needs and that one did not:
        //
        // * `reboot=k` (only when this run has a shutdown channel) is what makes the guest's own
        //   `reboot(2)` pulse the **i8042** controller's reset line, which is the one way a guest
        //   ends a Firecracker process on x86 — Firecracker emulates that controller and exits
        // when the guest resets it (Firecracker's own device documentation: the reset command
        //   on `OFS_STATUS`).  It is written here rather than left to the configuration because
        //   the kernel's own default is to *try* several resets, and the deliberate one is the
        //   cheap one (measured 2026-10-10: with it, a shutdown takes single-digit milliseconds);
        // * `8250.nr_uarts=0` is what Firecracker's own guest configuration recommends: this
        //   guest has no 8250 UART, and a kernel that probes for four of them spends boot time
        //   finding nothing.
        let extra = {
            let mut flags = Vec::new();
            if self.shutdown_channel {
                flags.push("reboot=k");
            }
            flags.join(" ")
        };
        let append = if self.boot_from_disk {
            format!(
                "{} {extra} desk.rootboot=1 desktop-cracker.root=/dev/vda desk.mapper=desk \
                 desktop-cracker.rootmode=rw",
                self.kernel.append.trim_end()
            )
        } else if extra.is_empty() {
            self.kernel.append.clone()
        } else {
            format!("{} {extra}", self.kernel.append.trim_end())
        };
        let kernel = Kernel {
            append,
            ..self.kernel.clone()
        };
        Spec {
            kernel,
            root: self.root.clone(),
            disks: self.disks.clone(),
            vcpus: self.vcpus,
            memory_mib: self.memory_mib,
            // There is no network device: the network is a vsock service like every
            // other one, and the guest makes its own TUN.
            tap: None,
            mac: None,
            vsock: Some(VsockDevice {
                guest_cid: self.guest_cid,
                uds_path: self.run_dir.join("v.sock"),
            }),
            balloon_mib: self.balloon_mib,
            api_socket: self.run_dir.join("api.sock"),
            program: self.program.clone(),
            api_timeout: Duration::from_secs(5),
        }
    }

    /// The shares, as the service wants them: the project's own tags and modes, in the order
    /// the settings list them, with the **control directory** of the machine this project started with dropped (on
    /// this path the control files travel the control channel, which is its own service).
    ///
    /// The guest's own expectations are kept exactly: the tag is the folder's name, a folder
    /// the user configured `ro` is read-only, and a tag that the guest's tools know keeps its
    /// meaning (`disk`, `xdisplay`).
    pub fn share_list(
        project: &dc_shares::ShareSet,
        guest_share_dir: &str,
        control_dir: &std::path::Path,
    ) -> Vec<dc_fc_share::Share> {
        // **Where each folder lands is the project's own answer**, taken from its mount plan
        // rather than guessed here: `/mnt/disk` for the disks, `/tmp/.X11-unix` for the host's X
        // sockets, `/mnt/share/<tag>` for a folder the user shared.  The guest's tools, its
        // session and its X clients look for exactly those paths.
        let plan: std::collections::HashMap<String, (String, bool)> = project
            .mount_plan(false, guest_share_dir)
            .lines()
            .filter(|line| !line.starts_with('#') && !line.trim().is_empty())
            .filter_map(|line| {
                let mut parts = line.split_whitespace();
                let tag = parts.next()?.to_string();
                let where_ = parts.next()?.to_string();
                let read_only = parts.next().map(|mode| mode == "ro").unwrap_or(false);
                Some((tag, (where_, read_only)))
            })
            .collect();
        let mut list: Vec<dc_fc_share::Share> = project
            .shares
            .iter()
            .filter(|share| share.tag != dc_common::TAG_CONTROL)
            .map(|share| {
                let (where_, plan_ro) = plan
                    .get(&share.tag)
                    .cloned()
                    .unwrap_or_else(|| (format!("{guest_share_dir}/{}", share.tag), false));
                dc_fc_share::Share {
                    tag: share.tag.clone(),
                    path: share.path.clone(),
                    where_,
                    read_only: plan_ro || share.mode.is_read_only(),
                    writable_exception: false,
                }
            })
            .collect();
        // **The control directory**, when the run has one: the project's own rule is that it is
        // the **one writable exception** (and `dc-shares`' own words) — the guest's
        // status comes back through it, so a guest that cannot write its memory numbers, its
        // readiness or its display state is a guest the rest of the project cannot see.  It is
        // offered even when the folder holding it is read-only, and it keeps its own `ro` in the
        // plan so the user's setting is not silently rewritten.
        if control_dir.is_dir()
            && list
                .iter()
                .any(|share| control_dir.starts_with(&share.path))
        {
            list.push(dc_fc_share::Share {
                tag: dc_common::TAG_CONTROL.into(),
                path: control_dir.to_path_buf(),
                where_: dc_common::GUEST_CONTROL_DIR.into(),
                read_only: true,
                writable_exception: true,
            });
        }
        list
    }

    /// The ports this run listens on before the machine starts.
    ///
    /// Every service the run has is here — a listener created after `InstanceStart` is a
    /// guest that gets a reset for the first thing it dials.
    /// The channels that answer are the run's own services ([`Started::services`]); what
    /// the list is for is the rule that they exist **before** the machine does.
    pub fn services(&self, with_readiness: bool) -> Vec<u32> {
        let mut all = Vec::new();
        if with_readiness {
            all.push(ports::READY);
            all.push(ports::NETWORK);
            all.push(ports::CONTROL);
            if self.display.is_some() {
                all.push(ports::DISPLAY);
            }
            if self.audio.is_some() {
                all.push(ports::AUDIO);
            }
            if self.shutdown_channel {
                all.push(ports::SHUTDOWN);
            }
            if self.x_socket.is_some() {
                all.push(ports::REMOTE_X);
            }
            for index in 0..self.shares.len() {
                all.push(ports::SHARES + index as u32);
            }
        }
        all
    }
}

/// What a run measured, for the plugin, the console and the tests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Timings {
    /// Spawn → the API answering.
    pub api_ms: Option<u128>,
    /// Spawn → the whole machine defined.
    pub defined_ms: Option<u128>,
    /// Spawn → `InstanceStart` accepted.
    pub started_ms: Option<u128>,
    /// Spawn → the guest's own landmark.
    pub guest_ms: Option<u128>,
    /// How many requests the definition took.
    pub api_calls: usize,
}

impl Timings {
    /// The one line a person reads when the guest is up: what the boot cost, where it
    /// went, and how many vCPUs the guest got.
    pub fn summary(&self, vcpus: u32, pinned: Option<&[usize]>) -> String {
        let mut parts = vec![format!("{vcpus} vCPU")];
        if let Some(cpus) = pinned {
            parts.push(format!("pinned {}", dc_fc_vm::cpu::format_cpu_list(cpus)));
        }
        if let Some(api) = self.api_ms {
            parts.push(format!("API {api} ms"));
        }
        if let Some(defined) = self.defined_ms {
            parts.push(format!(
                "defined {defined} ms ({} requests)",
                self.api_calls
            ));
        }
        if let Some(started) = self.started_ms {
            parts.push(format!("started {started} ms"));
        }
        if let Some(guest) = self.guest_ms {
            parts.push(format!("guest up {guest} ms"));
        }
        format!("boot: {}", parts.join(", "))
    }
}

/// **Where a milestone goes**: the console a person reads, and the plugin's event stream
/// when one is loaded.  One function, so a line can never reach one and miss the other.
///
/// The application prints milestones and nothing else (`AGENTS.md`: what the application
/// prints is what a person needs, never a per-frame, per-packet or per-call trail).
pub fn milestone(message: &str) {
    println!("{message}");
    dc_plugin::log("info", message);
}

/// The run's own clock: every number in the milestones and in the plugin is measured
/// from this one instant (the moment the run was asked to start), so two lines can never
/// be counting from two different beginnings.
#[derive(Debug, Clone, Copy)]
pub struct Clock(Instant);

impl Clock {
    fn start() -> Clock {
        Clock(Instant::now())
    }

    /// Spawn → now, in milliseconds.
    fn ms(&self) -> u128 {
        self.0.elapsed().as_millis()
    }
}

/// The run's state, as the plugin's own vocabulary (`/status` answers with the same
/// words): `booting`, `running`, `stopping`, `exited`.
pub fn state(state: &str) {
    dc_plugin::state(state);
}

/// **May this plugin drive this application?**
///
/// The plugin ABI is not versioned on purpose: every plugin is built from the project's
/// own tree, and the thing checked at load time is that the two agree on the ABI number.
/// That is a guard against loading a v1 plugin into a v2 application, and it makes a
/// **visible**: a plugin built against another hypervisor's run
/// drives a run this crate has never heard of — its `/status` reports a
/// `--machine microvm` the run does not have, its `/pin` reads `CPU N/KVM` threads that
/// do not exist, and a test that trusted it would be testing nothing.
///
/// So a plugin says which **VMM** it was built for, and a run refuses any that does not
/// name it.  A plugin that names nothing is accepted: a build from before this switch
/// exists behaves exactly as it did, and that is what "a plugin is optional in every
/// direction" means.
pub fn plugin_accepts(names_this_vmm: Option<&str>, this_vmm: &str) -> bool {
    match names_this_vmm {
        None => true,
        Some(name) => name.eq_ignore_ascii_case(this_vmm),
    }
}

/// A run that has been started: the pieces, in the order they were brought up.
pub struct Started {
    pub vm: VmProcess,
    pub api: Api,
    pub spec: RunSpec,
    pub timings: Timings,
    /// The instant the run was asked to start: what every timing above is measured from.
    pub clock: Clock,
    /// The CPUs the machine's process was confined to, when the host's topology could be
    /// read.
    pub cpus: Option<Vec<usize>>,
    /// How many `fc_vcpu N` threads were put on a core of their own.
    pub vcpus_pinned: usize,
    readiness: Option<Readiness>,
    memory: Option<MemoryManager>,
    network: Option<NetworkService>,
    control: Option<ControlService>,
    shares: Option<ShareService>,
    display: Option<DisplayService>,
    audio: Option<AudioService>,
    remote: Option<RemoteService>,
    power: Option<Arc<dc_fc_power::ShutdownChannel>>,
}

/// The run's **remote X tunnel**: the listener whose service lives in the
/// project's own crate (`dc-xremote`) and whose transport is this run's
/// (`dc-fc-remote` — the seam, and only the seam).
pub struct RemoteService {
    endpoints: Arc<dc_fc_remote::Endpoints>,
    threads: Mutex<Vec<std::thread::JoinHandle<()>>>,
}

impl RemoteService {
    /// The ports bound, in the order the port map lists them.
    pub fn ports(&self) -> Vec<u32> {
        self.endpoints
            .endpoints()
            .iter()
            .map(|e| e.port())
            .collect()
    }

    /// How many connections the guest has made to an endpoint, by port.
    pub fn connections(&self, port: u32) -> u64 {
        self.endpoints
            .endpoints()
            .iter()
            .find(|e| e.port() == port)
            .map(|e| e.connections())
            .unwrap_or(0)
    }
}

/// The run's **sound**: the guest's PCM, and the rule's own decision about it.
pub struct AudioService {
    service: Arc<dc_fc_audio::AudioService>,
    _thread: Option<std::thread::JoinHandle<()>>,
}

impl AudioService {
    pub fn port(&self) -> u32 {
        self.service.port()
    }

    /// What the guest's sound did, as the service saw it (the rule's own counters are
    /// `dc-audio`'s; these are the same numbers from this side).
    pub fn counters(&self) -> dc_fc_audio::Snapshot {
        self.service.counters()
    }
}

/// The run's **screen**: the pixels the guest draws, and the way back for its keyboard.
pub struct DisplayService {
    service: Arc<dc_fc_display::DisplayService>,
    /// The thread serving the channel.  Kept, not joined: it ends when the channel's socket is
    /// closed with the run, and a run that waited for a guest to hang up would wait for a guest
    /// that may never hang up (a halted guest does not close its sockets — measured).
    _thread: Option<std::thread::JoinHandle<()>>,
}

impl DisplayService {
    pub fn port(&self) -> u32 {
        self.service.port()
    }

    /// The channel itself, for a caller that brings its own half of the window
    /// (`dc-fc-window`): the pixels it takes and the input it sends are this service's own
    /// messages, so the window bridge is handed the service rather than a copy of its state.
    pub fn service(&self) -> Arc<dc_fc_display::DisplayService> {
        self.service.clone()
    }

    /// What the guest said its screen is (its own report, once it has the framebuffer).
    pub fn surface(&self) -> Option<dc_fc_display::Surface> {
        self.service.surface()
    }

    /// Whether the guest's agent is on the channel at all.
    pub fn connected(&self) -> bool {
        self.service.connected()
    }

    /// What the guest drew, as the rectangles the window draws: the same shape
    /// `dc-display`'s frame path takes.
    pub fn take_damage(&self) -> Vec<dc_fc_display::Damage> {
        self.service.take_damage()
    }

    pub fn counters(&self) -> dc_fc_display::Counters {
        self.service.counters()
    }

    /// A key for the guest, in its own code (`uinput`'s numbering).
    pub fn key(&self, code: u32, down: bool) {
        self.service.key(code, down);
    }

    /// Where the pointer is and which buttons are held.
    pub fn mouse(&self, x: u32, y: u32, buttons: u32) {
        self.service.mouse(x, y, buttons);
    }

    /// The pointer's shape.
    pub fn cursor(&self, x: u32, y: u32, visible: bool) {
        self.service.cursor(x, y, visible);
    }

    /// A whole screen: a window that has just appeared has seen nothing.
    pub fn refresh(&self) {
        self.service.refresh();
    }
}

/// The run's **shared folders**: the listeners (bound before the machine starts), the threads
/// serving them, and what they are doing.
pub struct ShareService {
    set: Arc<dc_fc_share::ShareSet>,
    _threads: Vec<std::thread::JoinHandle<()>>,
}

impl ShareService {
    /// The line the guest's agent is told: `<tag> <port> <ro|rw>`, one per folder — the
    /// path's mount plan, with the port where the 9P tag used to be.
    pub fn plan(&self) -> String {
        self.set.plan()
    }

    /// One share's counters, by tag.
    pub fn counters(&self, tag: &str) -> Option<dc_fc_share::Counters> {
        self.set.get(tag).map(|service| service.counters())
    }

    /// Every share's counters, and how many folders there are.
    pub fn all(&self) -> Vec<(String, dc_fc_share::Counters)> {
        self.set.counters()
    }
}

/// The run's **control share**: the channel the guest's agent asks for files on, and what
/// the run put there.
pub struct ControlService {
    /// The channel itself.  Held (not dropped) for as long as the run lives: dropping it
    /// would close the guest's share out from under it.
    _channel: Arc<dc_fc_control::ControlChannel>,
    share: Arc<std::sync::Mutex<dc_fc_control::Control>>,
    /// The thread serving it.  Kept, not joined: it ends when the channel's socket is
    /// closed with the run, and a run that waited for a guest to hang up would wait for a
    /// guest that may never hang up.
    _thread: Option<std::thread::JoinHandle<()>>,
}

impl ControlService {
    /// What the guest has written back (its own status, the answer to a question).
    pub fn written(&self, name: &str) -> Option<String> {
        self.share.lock().ok()?.written_text(name)
    }

    /// **Publish a file into the share while the run lives**: what the guest's own library reads
    /// (`display-state`) and what a person's tool may add.  It is the same share the run filled
    /// before the machine started — one place for every file the guest reads, and no second path
    /// into the guest.
    pub fn publish(&self, name: &str, text: impl Into<Vec<u8>>) {
        if let Ok(mut share) = self.share.lock() {
            share.put(name, text);
        }
    }

    /// The names the guest asked for, and how often: a run whose guest is asking for
    /// something that is not there is a run to look at.
    pub fn asked(&self) -> Vec<(String, u64)> {
        self.share
            .lock()
            .map(|share| share.asked().iter().map(|(n, c)| (n.clone(), *c)).collect())
            .unwrap_or_default()
    }

    /// Take the secrets out of the run's memory: the guest cannot need them any more.
    pub fn forget_secrets(&self) {
        if let Ok(mut share) = self.share.lock() {
            share.forget_secrets();
        }
    }
}

/// Bring a run up to the point where the guest has been started and its vCPU threads
/// are pinned.  The guest is not up yet: that is [`Started::wait_for_guest`].
pub fn start(mut spec: RunSpec, with_readiness: bool) -> Result<Started> {
    // The run's own directory, and **private**: a socket this run listens on is a door into it, and
    // the directory it sits in belongs to the user who runs it.
    dc_common::ensure_private(&spec.run_dir)
        .map_err(|e| RunError::Paths(spec.run_dir.clone(), e))?;

    // 1. THE CHANNELS LISTEN FIRST.  A guest that dials a port nobody listens on is a
    //    guest that gets a reset, and the failure looks like a guest that never came up.
    let readiness = if with_readiness {
        let readiness = Readiness::listen(&spec.run_dir.join("v.sock"), ports::READY)?;
        milestone(&format!(
            "channel: the guest's readiness on port {}",
            readiness.port()
        ));
        Some(readiness)
    } else {
        None
    };

    // **The shared folders**: one listener per folder, bound here — before the machine starts,
    // like every other channel — so the guest's agent finds them the moment it dials
    // for this reason.
    let shares = if with_readiness && !spec.shares.is_empty() {
        let set = Arc::new(dc_fc_share::ShareSet::listen(
            &spec.run_dir.join("v.sock"),
            &spec.shares,
        )?);
        let threads = set.serve_in_background();
        milestone(&format!(
            "channel: {} shared folder(s) on ports {}",
            spec.shares.len(),
            set.services()
                .iter()
                .map(|service| service.port().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ));
        Some(ShareService {
            set,
            _threads: threads,
        })
    } else {
        None
    };

    // **The shutdown channel (57000)**: the guest's agent opens it and keeps it open, and the
    // host sends one frame on it when the guest should go away.  It is bound before the machine
    // starts, like every other channel.
    let power = if with_readiness && spec.shutdown_channel {
        let channel = Arc::new(
            dc_fc_power::ShutdownChannel::listen(&spec.run_dir.join("v.sock"))
                .expect("the shutdown channel listens before the machine starts"),
        );
        milestone(&format!(
            "channel: the guest's shutdown on port {}",
            channel.port()
        ));
        // **Served from here**: the guest's agent dials once at boot and holds the connection
        // for the life of the run, so somebody has to be accepting it — a listener nobody
        // serves is a guest whose request has nowhere to land (found by running it: the guest
        // dialled, the host never answered, and the run could not be shut down).
        let _ = channel.serve_in_background();
        Some(channel)
    } else {
        None
    };

    // **Remote X (1026)**: the project's own service, on this run's own
    // transport (a unix socket per port — Firecracker has no `vhost-vsock`).
    let remote = if with_readiness {
        let mut wanted: Vec<(u32, &str, Arc<dyn dc_fc_remote::Accept>)> = Vec::new();
        if let Some(x) = &spec.x_socket {
            wanted.push((
                ports::REMOTE_X,
                "remote X",
                Arc::new(dc_fc_remote::ForwardTo::new(x.clone())),
            ));
        }
        if wanted.is_empty() {
            None
        } else {
            let endpoints = Arc::new(
                dc_fc_remote::Endpoints::listen(&spec.run_dir.join("v.sock"), wanted)
                    .expect("the remote listeners bind before the machine starts"),
            );
            for endpoint in endpoints.endpoints() {
                milestone(&format!(
                    "channel: {} on port {}",
                    endpoint.name(),
                    endpoint.port()
                ));
            }
            let threads = endpoints.serve_in_background();
            Some(RemoteService {
                endpoints,
                threads: Mutex::new(threads),
            })
        }
    } else {
        None
    };

    // **The sound** (55000): the PCM the guest plays into its own loopback card, on its way to
    // the host's own sound device — through the caller's rule.
    let audio = if with_readiness {
        spec.audio.as_ref().map(|play| {
            let service = Arc::new(
                dc_fc_audio::AudioService::listen(&spec.run_dir.join("v.sock"), play.clone())
                    .expect("the audio channel listens before the machine starts"),
            );
            milestone(&format!(
                "channel: the guest's sound on port {}",
                service.port()
            ));
            let thread = {
                let service = service.clone();
                std::thread::spawn(move || {
                    let _ = service.serve();
                })
            };
            AudioService {
                service,
                _thread: Some(thread),
            }
        })
    } else {
        None
    };

    // **The screen** (53000): the guest's pixels, and the way back for its keyboard and mouse.
    // Bound here — before the machine starts — like every other channel of a run, and only when
    // this run has a display: a run with no screen is a run with no channel to hang one on.
    let display = if with_readiness {
        spec.display.map(|surface| {
            let service = Arc::new(
                dc_fc_display::DisplayService::listen(&spec.run_dir.join("v.sock"))
                    .expect("the display channel listens before the machine starts"),
            );
            milestone(&format!(
                "channel: the guest's screen on port {} ({}x{})",
                service.port(),
                surface.width,
                surface.height
            ));
            let thread = {
                let service = service.clone();
                std::thread::spawn(move || {
                    let _ = service.serve();
                })
            };
            DisplayService {
                service,
                _thread: Some(thread),
            }
        })
    } else {
        None
    };

    // **The control share** (56000): the small files the guest's own tools read.  It is a
    // channel like the others, and it is up before the machine starts.
    //
    // `with_readiness` is also "this run brings **our** channels": a caller with its own
    // share (a disk job: its secrets, its plan, and nothing of a run's) asks for a run
    // *without* it and binds its own listener on the same `<uds_path>_56000`.  The two
    // cannot both exist, for the reason this file's documentation gives — a machine has
    // **one** `uds_path`, so one socket per port. A second
    // bind does not fail loudly: it replaces the first socket's file, and the caller's
    // channel then waits for a guest that is talking to ours.  That was a real failure
    // (measured 2026-10-09): a disk job sat out its whole timeout while its guest said
    // `DESK-DISK exit=0` to a channel nobody was reading.
    let control = if with_readiness {
        let mut share = std::mem::take(&mut spec.control);
        // The mount plan the guest's agent reads, beside the other files it fetches: the same
        // name the machine this project started with uses (`mounts`) and, beside it, this path's own line per folder
        // with the port that serves it (`shares`).
        if let Some(shares) = &shares {
            share.put("shares", shares.plan());
        }
        if let Some(surface) = &spec.display {
            // The screen's own line: the module's geometry, in the two numbers the guest's
            // agent passes to it.  It travels with the run's other files because it is decided
            // the same way — by this process, before the guest boots.
            share.put(
                "display-geometry",
                format!("{} {}\n", surface.width, surface.height),
            );
        }
        if let Some(passphrase) = &spec.root_passphrase {
            // The name is the initramfs' own (`/run/desktop-cracker/root.pass`): the guest's tools
            // are told what they always were; what changed is only how the file got there.
            share.put_secret("root.pass", passphrase.clone());
        }
        let share = Arc::new(std::sync::Mutex::new(share));
        let channel = Arc::new(dc_fc_control::ControlChannel::listen(
            &spec.run_dir.join("v.sock"),
            ports::CONTROL,
            share.clone(),
        )?);
        milestone(&format!(
            "channel: the guest's control share on port {}",
            channel.port()
        ));
        Some(ControlService {
            _thread: Some(channel.clone().serve_in_background()),
            _channel: channel,
            share,
        })
    } else {
        None
    };

    // The network is a channel like every other one, and it is **ours**: the guest's
    // agent makes its own TUN on the other end of it, and `dc-net`'s own engine answers
    // in between.  There is no tap and no virtio-net device, which is what the run's
    // machine above says (`spec.machine().tap == None`).
    let network = if with_readiness {
        let network = Arc::new(Network::listen(
            &spec.run_dir.join("v.sock"),
            ports::NETWORK,
        )?);
        let (ours, theirs) = dc_net::conduit_pair()
            .map_err(|source| RunError::Paths(spec.run_dir.clone(), source))?;
        let machine_network = dc_net::MachineNetwork::with_host_network(
            "desktop-cracker",
            ours,
            dc_net::host_resolvers(),
            spec.host_network,
        );
        // The engine's own reader: this is what answers DHCP (its lease table is the
        // machine's) and hands every other frame to the relay.  Without it the channel
        // would carry packets into a thread nobody reads, which is exactly how a guest's
        // network stays silent while everything else looks right.
        machine_network.start();
        network.serve_in_background(machine_network.clone(), theirs)?;
        milestone(&format!(
            "channel: the guest's network on port {}",
            network.port()
        ));
        // The one network fact a person needs to know about this run: whether the guest may reach
        // the machine it is on, and by what name.  It is a milestone, not a trace — a run whose
        // guest cannot reach a service the user expected is a run whose first question is "is the
        // switch on?".
        if spec.host_network {
            milestone(&format!(
                "channel: the guest reaches this computer as {} ({})",
                dc_net::hostnet::HOST_NAME,
                dc_net::hostnet::HOST_ADDRESS
            ));
        }
        Some(NetworkService {
            network,
            machine: machine_network,
            link: dc_fc_net::Link::default(),
        })
    } else {
        None
    };

    let machine = spec.machine();
    let clock = Clock::start();
    let mut timings = Timings::default();

    // 2. AND 3. The child, and the API that answers on a connection (not on a file).
    let mut vm = VmProcess::spawn(&machine)?;
    vm.wait_api(machine.api_timeout)?;
    timings.api_ms = Some(clock.ms());
    milestone(&format!(
        "vmm: firecracker {} (pid {})",
        version_of(&spec.program),
        vm.id()
    ));

    // 4. THE MACHINE, DEFINED BEFORE IT STARTS.  Firecracker freezes the definition at
    //    `InstanceStart`: a drive added afterwards is refused rather than hot-plugged.
    let mut api = Api::connect(vm.api_socket());
    machine.define(&mut api)?;
    timings.defined_ms = Some(clock.ms());
    timings.api_calls = api.calls();
    // 5. AND THE MACHINE RUNS.
    api.start()?;
    timings.started_ms = Some(clock.ms());
    milestone(&format!(
        "machine: {} vCPU, {} MiB, {} drive(s), vsock cid {}",
        spec.vcpus,
        spec.memory_mib,
        1 + spec.disks.len(),
        spec.guest_cid
    ));

    // 6. THE PINNING, NOW THAT THE THREADS EXIST.
    let layout = CpuLayout::detect();
    let cpus = layout.cpus_for(spec.vcpus as usize);
    let mut vcpus_pinned = 0;
    if let Some(cpus) = &cpus {
        if dc_fc_vm::cpu::pin_process(vm.id(), cpus).is_ok() {
            vcpus_pinned = dc_fc_vm::cpu::pin_vcpu_threads(vm.id(), cpus, Path::new("/proc"));
        }
    }

    let memory = spec.balloon_mib.map(|_| {
        let api = std::sync::Arc::new(std::sync::Mutex::new(Api::connect(vm.api_socket())));
        MemoryManager::attach(api, spec.balloon_policy.clone())
    });

    state("booting");
    Ok(Started {
        vm,
        api,
        spec,
        timings,
        clock,
        cpus,
        vcpus_pinned,
        readiness,
        memory,
        network,
        control,
        shares,
        display,
        audio,
        remote,
        power,
    })
}

/// The run's network: the channel, the engine behind it, and the link the guest's agent
/// configures on its own end.
pub struct NetworkService {
    /// The vsock channel this process serves.
    pub network: Arc<Network>,
    /// The engine the channel feeds (the project's own `dc-net`).
    pub machine: Arc<dc_net::MachineNetwork>,
    /// The addresses the guest's TUN is configured with.
    pub link: dc_fc_net::Link,
}

impl NetworkService {
    /// What the guest's agent has to be told, as the facts it needs, in the form the
    /// agent's own switch takes: the interface name, the addresses of the link, and its
    /// MTU.  It is the **guest's** command line, so it is written where the guest reads
    /// it (`/run/desktop-cracker/network`, the initramfs' own file) rather than passed on a
    /// kernel command line the agent would have to parse.
    ///
    /// The `mac` the engine keys its lease on and the `ping_sample` of
    /// [`dc_fc_net::Sample`] are facts of the *protocol* and live in the agent's own code:
    /// they are the same on every run, and a number that cannot change is not a
    /// configuration.
    pub fn handover(&self) -> String {
        format!(
            "--iface tun0 --guest {} --prefix {} --gateway {} --mtu {}",
            self.link.guest_ip, self.link.prefix, self.link.gateway_ip, self.link.mtu,
        )
    }

    /// Open a port forward: one host port on the loopback, carried into the guest.  This
    /// is `--ssh-port` and it is above the channel, so it is the same code as before this machine
    /// path's.
    pub fn forward(&self, host_port: u16, guest_port: u16) -> dc_net::ForwardStatus {
        self.machine.forward(host_port, guest_port)
    }

    /// **The `--ssh-port` forward**: the host's loopback port becomes a
    /// connection to the guest's sshd, which listens on 22 inside the guest and runs whether the
    /// switch was given or not.
    ///
    /// It is opened once the guest is up, and it is the same `dc-net` code the machine this project started with uses,
    /// above the same relay: what changed is where the frames come from. A port that
    /// cannot be bound is a **row to print**, not an error — a run whose forward failed is a run
    /// whose guest is up and whose sshd is unreachable, and saying so is what the user needs.
    pub fn forward_ssh(&self, host_port: u16) -> dc_net::ForwardStatus {
        self.forward(host_port, dc_net::SSH_GUEST_PORT)
    }

    /// Every forward this machine has: the run's own **"no switch, no socket"** answer is
    /// `is_empty()` — with no `--ssh-port` there is no listener at all, not a closed one.
    pub fn forwards(&self) -> Vec<dc_net::ForwardStatus> {
        self.machine.forward_statuses()
    }

    /// The counters, for the `/status` a plugin reads.
    pub fn counters(&self) -> dc_fc_net::Counters {
        self.network.counters()
    }
}

impl Started {
    /// The CPUs the machine is pinned to, as the plugin publishes them.
    pub fn cpus(&self) -> Option<&[usize]> {
        self.cpus.as_deref()
    }

    /// Wait for the guest's own landmark, and say what the boot cost.
    ///
    /// The landmark is the guest's **event**, not a line in a buffer: the agent sends
    /// the same line it prints, and the run stops waiting the moment it arrives.
    /// **The guest's second landing**: the session on the disk, once the system it entered has
    /// brought the screen, the sound, the shares and the network up.  A run whose guest stays in
    /// its initramfs never reports this one, so the wait is a caller's choice and has its own
    /// bound (the application uses it to say, honestly, whether the guest's own session came up).
    pub fn wait_for_session(&mut self, timeout: Duration) -> Option<String> {
        let readiness = self.readiness.as_mut()?;
        let deadline = Instant::now() + timeout;
        loop {
            for event in readiness.poll() {
                if let ReadyEvent::Ready(line) = event {
                    return Some(line);
                }
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    pub fn wait_for_guest(&mut self) -> Result<String> {
        let Some(readiness) = &mut self.readiness else {
            return Err(RunError::NoGuest(
                self.spec.guest_timeout,
                "this run has no readiness channel".into(),
            ));
        };
        let waited = readiness.wait_ready(self.spec.guest_timeout);
        let line = match (waited, readiness.ready()) {
            (Some(_), Some((line, _))) => line.trim_end().to_string(),
            _ => {
                return Err(RunError::NoGuest(
                    self.spec.guest_timeout,
                    self.vm.console().tail(20),
                ))
            }
        };
        self.timings.guest_ms = Some(self.clock.ms());
        // The guest's own words, and the run's one summary line.
        milestone(&line);
        milestone(&self.timings.summary(
            self.spec.vcpus,
            self.cpus.as_deref().filter(|_| self.vcpus_pinned > 0),
        ));
        state("running");
        Ok(line)
    }

    /// Take the events the readiness channel has collected (the guest's own reports), and
    /// pass them on as milestones.
    pub fn drain_reports(&mut self) -> Vec<String> {
        let Some(readiness) = &mut self.readiness else {
            return Vec::new();
        };
        let mut lines = Vec::new();
        for event in readiness.poll() {
            if let ReadyEvent::Report(text) = event {
                let line = text.trim_end().to_string();
                milestone(&line);
                lines.push(line);
            }
        }
        lines
    }

    /// Drive the balloon once: read the guest's own numbers and move the target if the
    /// policy says so.  Returns the line a person would read, when anything moved.
    pub fn balloon_step(&mut self) -> Result<Option<String>> {
        let Some(memory) = &mut self.memory else {
            return Ok(None);
        };
        let Some(adjustment) = memory.step()? else {
            return Ok(None);
        };
        Ok(Some(format!(
            "memory: balloon {} MiB -> {} MiB (guest has {} MiB free of {} MiB)",
            adjustment.previous / (1024 * 1024),
            adjustment.target / (1024 * 1024),
            adjustment.guest_available / (1024 * 1024),
            adjustment.guest_total / (1024 * 1024),
        )))
    }

    /// The memory the guest says it has, in bytes, as the machine reports it.
    pub fn guest_memory(&mut self) -> Option<dc_fc_api::GuestMemory> {
        self.memory.as_mut()?.guest_memory().ok().flatten()
    }

    /// **The clean shutdown**: the guest's own power button, and then the child.
    ///
    /// `SendCtrlAltDel` is Firecracker's ACPI/PL061 power button: the guest's system
    /// shuts down the way it would on a real machine, and the VMM process exits by
    /// itself.  The balloon is deflated first, so the guest's shutdown has all the memory
    /// it expects (that machine's own rule).
    pub fn shutdown(&mut self) -> Result<String> {
        state("stopping");
        if let Some(memory) = &mut self.memory {
            let _ = memory.release_all();
        }
        // **1. The guest's own way out.**  The agent holds the shutdown channel open, and one
        // frame on it makes the guest reboot — which is what ends Firecracker on a machine with
        // no ACPI power management.  This is asked *first* because it is the only ending the
        // guest can do for itself; the button below is what a guest with a real keyboard
        // controller would answer to.
        let power_asked = self
            .power
            .as_ref()
            .map(|power| power.ask())
            .unwrap_or(false);
        // **2. The power button.**  Firecracker's `SendCtrlAltDel` is the keyboard controller's
        // reset: the system on the disk sees it (systemd's `ctrl-alt-del.target`) and shuts
        // itself down cleanly.
        let asked = self.api.send_ctrl_alt_del().is_ok();
        let deadline = Instant::now() + self.spec.shutdown_timeout;
        while Instant::now() < deadline && self.vm.exited().is_none() {
            std::thread::sleep(Duration::from_millis(20));
        }
        let clean = self.vm.exited().is_some();
        // Whether the guest answered or not, the child does not outlive the run.
        let _ = self.vm.kill();
        if let Some(network) = &self.network {
            network.machine.shutdown();
        }
        // The remote listeners are **asked to stop**: a thread waiting for an X client that is
        // never coming must not outlive the run.
        if let Some(remote) = &self.remote {
            if let Ok(mut threads) = remote.threads.lock() {
                remote.endpoints.shutdown(std::mem::take(&mut *threads));
            }
        }
        // **The channel listeners stop too.**  A connection is served on its own thread, so the
        // audio service's accepting loop is the only place that knows every connection; asking it
        // to stop (and closing its socket, which is what `close` does) ends them all.
        if let Some(audio) = &self.audio {
            audio.service.shutdown();
        }
        // The secrets go with the run: the guest had what it needed, and nobody is going to
        // need it again (`AGENTS.md`).
        if let Some(control) = &self.control {
            control.forget_secrets();
        }
        clean_own_sockets(&self.spec.run_dir);
        state("exited");
        Ok(if clean {
            "the guest rebooted to end the machine; firecracker exited".into()
        } else if power_asked {
            "the guest was asked on its own shutdown channel, and did not go; the process was taken away"
                .into()
        } else if asked {
            "the guest has no shutdown channel; it was asked to power off and did not; the process was taken away"
                .into()
        } else {
            "the machine could not be asked to go away; the process was taken away".into()
        })
    }

    /// The machine's own process: whether it is still there, and what it ended with.  A run
    /// whose guest has gone away (a shutdown from inside, a crash) is a run that is over, which
    /// is what the caller's own loop watches for.
    pub fn vm_exited(&mut self) -> bool {
        self.vm.exited().is_some()
    }

    /// The readiness channel's own service, for a caller that wants to read the last
    /// events after the guest is up.
    pub fn readiness(&self) -> Option<&Readiness> {
        self.readiness.as_ref()
    }

    /// The run's network, when it has one.
    pub fn network(&self) -> Option<&NetworkService> {
        self.network.as_ref()
    }

    /// The run's control share, when it has one.
    pub fn control(&self) -> Option<&ControlService> {
        self.control.as_ref()
    }

    /// The run's shared folders, when it has any.
    pub fn shares(&self) -> Option<&ShareService> {
        self.shares.as_ref()
    }

    /// The run's screen, when it has one.
    pub fn display(&self) -> Option<&DisplayService> {
        self.display.as_ref()
    }

    /// The run's sound, when it has one.
    pub fn audio(&self) -> Option<&AudioService> {
        self.audio.as_ref()
    }

    /// The run's remote X listener, when it has one.
    pub fn remote(&self) -> Option<&RemoteService> {
        self.remote.as_ref()
    }

    /// The run's shutdown channel, when it has one.
    pub fn power(&self) -> Option<&Arc<dc_fc_power::ShutdownChannel>> {
        self.power.as_ref()
    }

    /// The line a person reads when the guest's network is up: the channel, the engine
    /// and what the agent was told.
    pub fn network_milestone(&self) -> Option<String> {
        let network = self.network.as_ref()?;
        Some(format!("network: {}", network.handover()))
    }
}

/// The version line of the program a run starts: the one thing a person wants to know
/// about the VMM before a bug report.  Read from the program itself when it answers
/// (`--version`), and never guessed.
fn version_of(program: &Path) -> String {
    let out = std::process::Command::new(program)
        .arg("--version")
        .output();
    match out {
        Ok(out) => {
            let text = String::from_utf8_lossy(&out.stdout);
            text.lines()
                .next()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .unwrap_or("firecracker")
                .to_string()
        }
        Err(_) => program
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "firecracker".into()),
    }
}

/// Take a run's own sockets away.  Deleting the *directory* would delete a file socket a
/// child still holds; deleting the sockets themselves is what the run created and all it
/// created.
pub fn clean_own_sockets(run_dir: &Path) {
    let Ok(entries) = std::fs::read_dir(run_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let is_socket = entry
            .file_type()
            .map(|t| {
                use std::os::unix::fs::FileTypeExt;
                t.is_socket()
            })
            .unwrap_or(false);
        if is_socket {
            let _ = std::fs::remove_file(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The run's own sockets: the directory is **this user's** runtime directory, named
    /// after this process.  A fixed path the whole machine shares is what two runs used to collide
    /// on; a name carrying the pid is what keeps them apart.
    #[test]
    fn a_run_keeps_its_sockets_in_a_directory_of_its_own() {
        let base = Path::new("/run/user/1000/desktop-cracker");
        assert_eq!(
            run_directory(base, 7),
            PathBuf::from("/run/user/1000/desktop-cracker/run-7")
        );
        assert_ne!(run_directory(base, 1), run_directory(base, 2));

        // The default is the rule, not a fixed path: this user's runtime directory, in a directory
        // named after this process.
        let default = RunSpec::default().run_dir;
        assert_eq!(
            default,
            run_directory(&dc_common::runtime_dir(), std::process::id())
        );
        assert!(
            default.ends_with(format!("run-{}", std::process::id())),
            "the run's own directory carries this process's id: {default:?}"
        );
        assert!(
            !default.starts_with("/tmp"),
            "a run's sockets are not in a path every user of the machine shares: {default:?}"
        );
    }

    #[test]
    fn the_machine_of_a_run_has_no_network_device_and_one_root_disk() {
        let spec = RunSpec {
            root: Disk {
                name: "rootfs".into(),
                path: "/d/root.raw".into(),
                read_only: false,
            },
            disks: vec![Disk {
                name: "data".into(),
                path: "/d/data.raw".into(),
                read_only: true,
            }],
            vcpus: 12,
            memory_mib: 6144,
            balloon_mib: Some(4096),
            run_dir: PathBuf::from("/run/user/1000/desktop-cracker/run-9"),
            ..RunSpec::default()
        };
        let machine = spec.machine();
        assert_eq!(
            machine.tap, None,
            "the network is a vsock service: no tap, no device"
        );
        assert_eq!(machine.mac, None);
        assert_eq!(machine.drives().len(), 2);
        assert!(machine.drives()[0].is_root_device);
        assert_eq!(machine.vsock.as_ref().unwrap().guest_cid, 3);
        assert_eq!(
            machine.vsock.as_ref().unwrap().uds_path,
            PathBuf::from("/run/user/1000/desktop-cracker/run-9/v.sock")
        );
        assert_eq!(
            machine.api_socket,
            PathBuf::from("/run/user/1000/desktop-cracker/run-9/api.sock")
        );
        assert_eq!(machine.balloon_mib, Some(4096));
        assert_eq!(machine.machine_configuration().vcpu_count, 12);
    }

    #[test]
    fn a_run_listens_on_its_channels_before_the_machine_starts() {
        let spec = RunSpec::default();
        assert_eq!(
            spec.services(true),
            vec![ports::READY, ports::NETWORK, ports::CONTROL],
            "the guest is up (58000), its network (59000) and its control share (56000)"
        );
        assert!(
            spec.services(false).is_empty(),
            "a run with no agent listens on nothing"
        );
    }

    #[test]
    fn a_run_that_brings_its_own_channels_listens_on_no_port_of_its_own() {
        // The rule the disk job depends on: `with_readiness` false means this crate binds
        // **nothing**, so the caller's own channel owns `<uds_path>_56000`.  A second bind
        // on the same path would replace the caller's socket file (it does not fail: it
        // *succeeds*), and the caller would wait for a guest talking to a channel nobody
        // reads — measured 2026-10-09, on a disk job that sat for its whole timeout.
        let spec = RunSpec::default();
        assert!(spec.services(false).is_empty());
        assert_eq!(
            spec.services(true),
            vec![ports::READY, ports::NETWORK, ports::CONTROL]
        );
    }

    #[test]
    fn the_boot_summary_is_one_line_and_says_where_the_time_went() {
        let timings = Timings {
            api_ms: Some(3),
            defined_ms: Some(1),
            started_ms: Some(6),
            guest_ms: Some(451),
            api_calls: 7,
        };
        let line = timings.summary(12, Some(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]));
        assert_eq!(
            line,
            "boot: 12 vCPU, pinned 0-11, API 3 ms, defined 1 ms (7 requests), started 6 ms, guest up 451 ms"
        );
    }

    #[test]
    fn the_summary_says_the_pinning_only_when_the_machine_was_actually_pinned() {
        let timings = Timings {
            api_ms: Some(3),
            defined_ms: Some(5),
            api_calls: 7,
            ..Timings::default()
        };
        assert!(
            !timings.summary(12, None).contains("pinned"),
            "nothing to report, nothing said"
        );
    }

    #[test]
    fn the_summary_of_a_run_that_never_came_up_says_only_what_it_knows() {
        let timings = Timings {
            api_ms: Some(4),
            api_calls: 6,
            ..Timings::default()
        };
        assert_eq!(
            timings.summary(1, None),
            "boot: 1 vCPU, API 4 ms",
            "a line says only what happened: nothing is invented for what did not"
        );
    }

    #[test]
    fn a_plugin_for_another_hypervisor_is_refused() {
        // The point of the check: a plugin built by that project drives a machine
        // this run has never heard of.
        assert!(!plugin_accepts(Some("another"), "firecracker"));
        assert!(plugin_accepts(Some("firecracker"), "firecracker"));
        assert!(
            plugin_accepts(Some("Firecracker"), "firecracker"),
            "the name is not case"
        );
        // A plugin that names nothing is a build from before the switch: it behaves as it
        // always did.
        assert!(plugin_accepts(None, "firecracker"));
    }

    #[test]
    fn a_run_with_no_plugin_reaches_no_hook_and_prints_its_own_lines() {
        // The seam with nothing loaded: the project's own property, asserted again here
        // because this crate is what calls it during a run.
        assert!(!dc_plugin::is_loaded());
        milestone("boot: 12 vCPU, guest up 451 ms");
        state("running");
    }

    #[test]
    fn the_guest_timeout_is_the_runs_own_bound_and_is_generous() {
        // A machine that does not come up inside it is a machine to investigate, so the
        // bound is not a test's: it is ten times what a boot costs on this host.
        let spec = RunSpec::default();
        assert!(spec.guest_timeout >= Duration::from_secs(20));
        assert!(spec.guest_timeout <= Duration::from_secs(60));
    }

    #[test]
    fn cleaning_a_run_takes_its_sockets_and_leaves_everything_else_alone() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("v.sock_58000");
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let not_ours = dir.path().join("a-disk-the-user-asked-for");
        std::fs::write(&not_ours, b"x").unwrap();
        clean_own_sockets(dir.path());
        assert!(!socket.exists(), "the run's own socket goes");
        assert!(
            not_ours.exists(),
            "a file the run did not create is not the run's to delete"
        );
    }
}
