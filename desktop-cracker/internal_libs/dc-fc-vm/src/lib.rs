//! **The Firecracker machine**: what it is made of, how it is defined on the API,
//! what it costs the host while it runs, and how it ends.
//!
//! The seam this crate sits behind is the same one `dc-vm` has today, one
//! hypervisor further along: the rest of the application keeps its vocabulary (a
//! microVM with a kernel, an initramfs, a root disk, some more disks, a network,
//! a balloon, a serial console and vCPUs pinned to the host's physical cores) and
//! this crate is what knows that the machine under it is Firecracker.
//!
//! Four things here are worth reading before the rest:
//!
//! * [`Spec::define`] is the machine **in the order Firecracker's API requires**:
//!   the boot source, the machine's shape, the drives (the root first, because
//!   that is `/dev/vda`), the network, the vsock device, the balloon, the entropy
//!   device — and `InstanceStart` last, after which nothing may be added.
//! * [`Console`] is the guest's serial, which Firecracker writes to **its own
//!   stdout** (measured: no `-serial` option exists and there is no file), so the
//!   application's console echo comes from the child's pipe — a file on disk was
//!   never the right place for it (`AGENTS.md`).
//! * [`cpu`] pins the machine the way that project measured: the process is
//!   confined to the host's physical cores and each `fc_vcpu N` thread gets a core
//!   of its own.  Firecracker names its vCPU threads, which is what makes the
//!   per-thread half possible without a debugger.
//! * [`balloon`] is the memory policy: the guest's own numbers come from
//!   `GET /balloon/statistics` (which is where the guest's `/proc/meminfo` used to
//!   be read) and `PATCH /balloon` is the only thing that moves.
//!
//! Nothing here starts a thread that a test has to wait for, and nothing here
//! needs `/dev/kvm`: the API is a trait, the topology is a directory, and the
//! policy is arithmetic.  The machine itself is measured in `temp/fc-study/`.

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use dc_fc_api::{BootSource, Drive, MachineConfiguration, NetworkInterface, Vsock};
// The client is part of how a machine is used (`Api::start()`,
// `Api::balloon_stats()`), so it is named as part of this crate's own surface
// rather than only in the signature of `Spec::define`.
pub use dc_fc_api::{Api, ApiError};

pub mod balloon;
pub mod console;
pub mod cpu;

pub use balloon::{BalloonPolicy, MemoryError, MemoryManager};
pub use console::Console;
pub use cpu::CpuLayout;

/// What can go wrong while defining, starting or ending a machine.
#[derive(Debug, thiserror::Error)]
pub enum VmError {
    #[error("{0}")]
    Api(#[from] ApiError),
    #[error("{0}")]
    Invalid(String),
    #[error("the firecracker process: {0}")]
    Process(std::io::Error),
    #[error("firecracker exited with {status} before the guest was up:\n{tail}")]
    EarlyExit { status: String, tail: String },
}

pub type Result<T> = std::result::Result<T, VmError>;

/// The kernel the guest boots, and its own command line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Kernel {
    /// An uncompressed ELF `vmlinux`, or a `bzImage`; both loaders exist.
    pub image: PathBuf,
    /// The initramfs, when the guest has one (this project's guest always does:
    /// its init is what brings the userland up).
    pub initramfs: Option<PathBuf>,
    /// The guest kernel's own command line.
    pub append: String,
}

/// One disk attached to the machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disk {
    /// The id used on the API, and the name in `/run/desktop-cracker/disks`.
    pub name: String,
    /// A **raw** file: the bytes a disk is, not a wrapped image.
    pub path: PathBuf,
    pub read_only: bool,
}

/// The machine's own shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Spec {
    pub kernel: Kernel,
    /// The root disk: the first drive, so the guest sees it as `/dev/vda`.
    pub root: Disk,
    /// The other disks, in the order the settings list them: `/dev/vdb`, `/dev/vdc`…
    pub disks: Vec<Disk>,
    /// vCPUs.  Firecracker takes 1…32.
    pub vcpus: u32,
    /// The guest's RAM, in MiB.
    pub memory_mib: u64,
    /// The tap the guest's interface is on.  Firecracker's only netdev backend.
    pub tap: Option<String>,
    /// The guest's MAC, when the run wants one of its own.
    pub mac: Option<String>,
    /// The guest's vsock CID, and the socket the host's ports hang off.
    pub vsock: Option<VsockDevice>,
    /// The balloon's starting point, in MiB, when the run has one.
    pub balloon_mib: Option<u64>,
    /// The API socket this machine is defined on.
    pub api_socket: PathBuf,
    /// The program: the Firecracker the package ships, or one from `PATH`.
    pub program: PathBuf,
    /// How long to wait for the API socket before giving up on the child.
    pub api_timeout: Duration,
}

/// The vsock device's own two numbers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VsockDevice {
    pub guest_cid: u64,
    pub uds_path: PathBuf,
}

impl Default for Spec {
    fn default() -> Self {
        Spec {
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
            tap: None,
            mac: None,
            vsock: None,
            balloon_mib: None,
            // The run's own sockets: this process's own runtime directory, named after
            // this process.  A caller that runs several machines — `fc-run`, a disk job — replaces
            // it with the path of its own run.
            api_socket: dc_common::run_directory(&dc_common::runtime_dir(), std::process::id())
                .join("api.sock"),
            program: PathBuf::from("firecracker"),
            api_timeout: Duration::from_secs(5),
        }
    }
}

impl Spec {
    /// Everything Firecracker itself would refuse, refused here first, with a
    /// sentence about *this* machine rather than about a JSON field.
    pub fn validate(&self) -> Result<()> {
        if self.kernel.image.as_os_str().is_empty() {
            return Err(VmError::Invalid("the machine has no kernel".into()));
        }
        if !self.kernel.image.exists() {
            return Err(VmError::Invalid(format!(
                "the guest kernel {} is not there",
                self.kernel.image.display()
            )));
        }
        if let Some(initramfs) = &self.kernel.initramfs {
            if !initramfs.exists() {
                return Err(VmError::Invalid(format!(
                    "the guest initramfs {} is not there",
                    initramfs.display()
                )));
            }
        }
        if self.root.path.as_os_str().is_empty() {
            return Err(VmError::Invalid("the machine has no root disk".into()));
        }
        // A read-write root has to be a file this process may write: Firecracker
        // opens it read-write with the run's own rights, and the refusal it gives
        // otherwise ("Error manipulating the backing file: Permission denied") is
        // about a file the user cannot see in the message.
        if !self.root.path.exists() {
            return Err(VmError::Invalid(format!(
                "the root disk {} is not there",
                self.root.path.display()
            )));
        }
        if !self.root.read_only && !writable(&self.root.path) {
            return Err(VmError::Invalid(format!(
                "the root disk {} is not writable by this run",
                self.root.path.display()
            )));
        }
        for disk in &self.disks {
            if !disk.path.exists() {
                return Err(VmError::Invalid(format!(
                    "the disk {} {} is not there",
                    disk.name,
                    disk.path.display()
                )));
            }
        }
        if self.vcpus == 0 || self.vcpus > 32 {
            return Err(VmError::Invalid(format!(
                "Firecracker takes 1 to 32 vCPUs, this machine asks for {}",
                self.vcpus
            )));
        }
        if self.memory_mib < 128 {
            return Err(VmError::Invalid(format!(
                "the guest kernel does not boot below 128 MiB (asked for {})",
                self.memory_mib
            )));
        }
        if self.tap.is_none() && self.mac.is_some() {
            return Err(VmError::Invalid(
                "a MAC address without a network device is not a machine".into(),
            ));
        }
        if let Some(vsock) = &self.vsock {
            if vsock.guest_cid < 3 {
                return Err(VmError::Invalid(format!(
                    "the vsock guest id is {}: 0 and 1 are reserved, and 2 is the host",
                    vsock.guest_cid
                )));
            }
        }
        Ok(())
    }

    /// Every drive, the root first: the guest's `/dev/vda` is the root device and
    /// the others follow in the order they are listed.
    pub fn drives(&self) -> Vec<Drive> {
        let mut all = Vec::with_capacity(1 + self.disks.len());
        all.push(Drive::raw(
            &self.root.name,
            &self.root.path.to_string_lossy(),
            true,
            self.root.read_only,
        ));
        for disk in &self.disks {
            all.push(Drive::raw(
                &disk.name,
                &disk.path.to_string_lossy(),
                false,
                disk.read_only,
            ));
        }
        all
    }

    /// The machine's shape, as the API wants it.
    ///
    /// `track_dirty_pages` is off on purpose: it exists for snapshots, and this
    /// project boots its machines and never restores one.
    pub fn machine_configuration(&self) -> MachineConfiguration {
        MachineConfiguration {
            vcpu_count: self.vcpus,
            mem_size_mib: self.memory_mib,
            smt: Some(false),
            cpu_template: None,
            track_dirty_pages: None,
            huge_pages: None,
        }
    }

    /// **Define the machine on the API, in the one order that works.**
    ///
    /// Every drive, the network, the vsock device and the balloon have to be
    /// there *before* `InstanceStart`: Firecracker's definition is frozen when the
    /// machine starts, and a disk added afterwards is refused rather than
    /// hot-plugged.
    pub fn define(&self, api: &mut Api) -> Result<()> {
        self.validate()?;
        api.put_boot_source(&BootSource {
            kernel_image_path: self.kernel.image.to_string_lossy().into_owned(),
            initrd_path: self
                .kernel
                .initramfs
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned()),
            boot_args: Some(self.kernel.append.clone()),
        })?;
        api.put_machine_config(&self.machine_configuration())?;
        for drive in self.drives() {
            api.put_drive(&drive)?;
        }
        if let Some(tap) = &self.tap {
            api.put_network_interface(&NetworkInterface {
                iface_id: "eth0".into(),
                host_dev_name: tap.clone(),
                guest_mac: self.mac.clone(),
                mtu: None,
                rx_rate_limiter: None,
                tx_rate_limiter: None,
            })?;
        }
        if let Some(vsock) = &self.vsock {
            api.put_vsock(&Vsock {
                guest_cid: vsock.guest_cid,
                uds_path: vsock.uds_path.to_string_lossy().into_owned(),
            })?;
        }
        if let Some(amount_mib) = self.balloon_mib {
            api.put_balloon(&dc_fc_api::Balloon {
                amount_mib,
                deflate_on_oom: true,
                // Statistics on, at the policy's own cadence: with them off, the
                // API refuses to be asked (measured 2026-10-09), and the policy
                // has nothing to decide on.
                stats_polling_interval_s: Some(1),
                free_page_hinting: None,
                free_page_reporting: None,
            })?;
        }
        // The entropy device is free and native, and a guest's `systemd` is
        // measurably happier at boot when it has one.
        api.put_entropy()?;
        Ok(())
    }
}

/// Does the API socket answer?  The API is a unix socket Firecracker accepts on,
/// and a path that exists but does not accept is not an API yet (or any more).
pub fn api_socket_answers(path: &Path) -> bool {
    std::os::unix::net::UnixStream::connect(path).is_ok()
}

/// Is this file writable by *this* process?  `metadata().permissions()` only says
/// what the mode bits say, which is not the same thing when the file belongs to
/// another user and this process has no root.
pub fn writable(path: &Path) -> bool {
    std::fs::OpenOptions::new().write(true).open(path).is_ok()
}

/// The machine as a **child process**: Firecracker runs as this process's child,
/// with the API socket on a path of the run's own.
///
/// `PR_SET_PDEATHSIG` is set in the child before it execs, which is the project's
/// rule (`AGENTS.md`): if desktop-cracker dies, the machine dies with it and
/// is never orphaned.  Firecracker exits by itself when the guest powers off.
#[derive(Debug)]
pub struct VmProcess {
    child: Child,
    console: Console,
    api_socket: PathBuf,
}

impl VmProcess {
    /// Spawn Firecracker on `api_socket`, with its stdout — the guest's serial
    /// console — and its stderr — the VMM's own log — read into `console`.
    pub fn spawn(spec: &Spec) -> Result<VmProcess> {
        let api_socket = spec.api_socket.clone();
        if let Some(parent) = api_socket.parent() {
            std::fs::create_dir_all(parent).map_err(VmError::Process)?;
        }
        let _ = std::fs::remove_file(&api_socket);
        let mut command = command(
            &spec.program,
            &["--api-sock", &api_socket.to_string_lossy()],
        );
        let mut child = spawn_with_pdeathsig(&mut command)?;
        let console = Console::new();
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
        match (stdout, stderr) {
            (Some(out), Some(err)) => console.follow(out, err),
            (Some(out), None) => console.follow(out, std::io::empty()),
            (None, Some(err)) => console.follow(std::io::empty(), err),
            (None, None) => {}
        }
        Ok(VmProcess {
            child,
            console,
            api_socket,
        })
    }

    pub fn id(&self) -> u32 {
        self.child.id()
    }

    pub fn console(&self) -> &Console {
        &self.console
    }

    pub fn api_socket(&self) -> &Path {
        &self.api_socket
    }

    /// Has Firecracker exited on its own — a guest that powered off, or a VMM
    /// that refused what it was given?
    pub fn exited(&mut self) -> Option<std::process::ExitStatus> {
        self.child.try_wait().ok().flatten()
    }

    /// Wait until the API **answers**, or until the machine has died trying.
    ///
    /// The socket file exists a moment before Firecracker is listening on it
    /// (measured on this host: `bind` then `listen` are two steps), and a client
    /// that connects into that window gets `EAGAIN` rather than an answer — which
    /// is what `api_socket_answers` is for, and the reason this waits for a
    /// *connection* rather than for a file.  A machine that has exited has
    /// answered in the only way it is going to.
    pub fn wait_api(&mut self, timeout: Duration) -> Result<()> {
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            if api_socket_answers(&self.api_socket) {
                return Ok(());
            }
            if let Some(status) = self.exited() {
                return Err(VmError::EarlyExit {
                    status: status.to_string(),
                    tail: self.console.tail(20),
                });
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        Err(VmError::EarlyExit {
            status: "the API socket never answered".into(),
            tail: self.console.tail(20),
        })
    }

    /// Take the machine away.  The child is asked to stop and then killed if it
    /// does not: exactly what the machine this project started with does today.
    pub fn kill(&mut self) -> Result<()> {
        if self.exited().is_some() {
            return Ok(());
        }
        let _ = self.child.kill();
        self.child.wait().map_err(VmError::Process)?;
        let _ = std::fs::remove_file(&self.api_socket);
        Ok(())
    }
}

impl Drop for VmProcess {
    fn drop(&mut self) {
        // The child is this process's, and it does not outlive it.
        let _ = self.kill();
    }
}

/// The command that starts Firecracker, before it is spawned: the program, its
/// argument, the API socket on a path of our own, and nothing else.
///
/// Firecracker has three switches of its own (`--api-sock`, `--config-file`,
/// `--no-api`, `--enable-pci`, `--logger`/`--metrics` paths) and **no machine on
/// the command line**: everything about the machine is a request on the socket.
pub fn command(program: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(program);
    command.args(args);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

/// Spawn a command with `PR_SET_PDEATHSIG(SIGKILL)` set in the child.
///
/// The signal is about the *parent thread* that spawned the child, so it is set
/// by the child itself before it execs and checked afterwards — a child whose
/// parent already died in the meantime gets the signal immediately, which is the
/// same answer one step later.
pub fn spawn_with_pdeathsig(command: &mut Command) -> Result<Child> {
    use std::os::unix::process::CommandExt;
    unsafe {
        command.pre_exec(|| {
            // SAFETY: `prctl` with `PR_SET_PDEATHSIG` only sets the calling
            // thread's own parent-death signal; it touches nothing this process
            // holds, and between `fork` and `exec` that is all that may be done.
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command.spawn().map_err(VmError::Process)
}

#[cfg(test)]
mod tests {
    use super::*;
    use dc_fc_api::{Api, Wire};
    use std::sync::{Arc, Mutex};

    /// What a request looked like: method, path, body.
    type Calls = Arc<Mutex<Vec<(String, String, Option<String>)>>>;

    /// A wire that records what the definition asked for, and answers 204 to
    /// everything: defining a machine must not need a Firecracker.
    #[derive(Clone)]
    struct Recorder {
        calls: Calls,
    }

    impl Recorder {
        fn new() -> Recorder {
            Recorder {
                calls: Arc::new(Mutex::new(Vec::new())),
            }
        }

        fn paths(&self) -> Vec<String> {
            self.calls
                .lock()
                .unwrap()
                .iter()
                .map(|c| c.1.clone())
                .collect()
        }

        fn api(&self) -> Api {
            Api::over(Box::new(self.clone()))
        }
    }

    impl Wire for Recorder {
        fn request(
            &mut self,
            method: &str,
            path: &str,
            body: Option<&str>,
        ) -> std::io::Result<(u16, String)> {
            self.calls.lock().unwrap().push((
                method.to_string(),
                path.to_string(),
                body.map(str::to_string),
            ));
            Ok((204, String::new()))
        }
    }

    fn a_kernel(dir: &Path) -> Kernel {
        let image = dir.join("vmlinux");
        std::fs::write(&image, b"\x7fELF not really").unwrap();
        let initramfs = dir.join("initramfs.gz");
        std::fs::write(&initramfs, b"gzip, not really").unwrap();
        Kernel {
            image,
            initramfs: Some(initramfs),
            append: "console=ttyS0 rdinit=/init quiet loglevel=3".into(),
        }
    }

    fn a_spec(dir: &Path) -> Spec {
        let root = dir.join("root.raw");
        std::fs::write(&root, vec![0u8; 4096]).unwrap();
        let data = dir.join("data.raw");
        std::fs::write(&data, vec![0u8; 4096]).unwrap();
        Spec {
            kernel: a_kernel(dir),
            root: Disk {
                name: "rootfs".into(),
                path: root,
                read_only: false,
            },
            disks: vec![Disk {
                name: "data".into(),
                path: data,
                read_only: true,
            }],
            vcpus: 12,
            memory_mib: 6144,
            vsock: Some(VsockDevice {
                guest_cid: 3,
                uds_path: dir.join("v.sock"),
            }),
            balloon_mib: Some(4096),
            ..Spec::default()
        }
    }

    #[test]
    fn a_machine_is_defined_in_the_order_the_api_requires_and_started_last() {
        let dir = tempfile::tempdir().unwrap();
        let spec = a_spec(dir.path());
        let recorder = Recorder::new();
        let mut api = recorder.api();
        spec.define(&mut api).unwrap();
        api.start().unwrap();
        assert_eq!(
            recorder.paths(),
            vec![
                "/boot-source",
                "/machine-config",
                "/drives/rootfs",
                "/drives/data",
                "/vsock",
                "/balloon",
                "/entropy",
                "/actions",
            ]
        );
        let calls = recorder.calls.lock().unwrap().clone();
        assert!(calls[1].2.as_deref().unwrap().contains("\"vcpu_count\":12"));
        assert!(calls[1]
            .2
            .as_deref()
            .unwrap()
            .contains("\"mem_size_mib\":6144"));
        // The root is the root device, the one that becomes `/dev/vda`.
        assert!(calls[2]
            .2
            .as_deref()
            .unwrap()
            .contains("\"is_root_device\":true"));
        assert!(calls[3]
            .2
            .as_deref()
            .unwrap()
            .contains("\"is_root_device\":false"));
        assert!(calls[3]
            .2
            .as_deref()
            .unwrap()
            .contains("\"is_read_only\":true"));
        assert!(calls
            .last()
            .unwrap()
            .2
            .as_deref()
            .unwrap()
            .contains("InstanceStart"));
    }

    #[test]
    fn the_root_disk_is_always_the_first_drive_so_the_guest_boots_the_one_it_should() {
        let dir = tempfile::tempdir().unwrap();
        let mut spec = a_spec(dir.path());
        spec.disks.insert(
            0,
            Disk {
                name: "first".into(),
                path: spec.root.path.clone(),
                read_only: true,
            },
        );
        let drives = spec.drives();
        assert_eq!(drives[0].drive_id, "rootfs");
        assert!(drives[0].is_root_device);
        assert_eq!(
            drives
                .iter()
                .map(|d| d.drive_id.as_str())
                .collect::<Vec<_>>(),
            vec!["rootfs", "first", "data"]
        );
    }

    #[test]
    fn a_machine_without_a_tap_has_no_network_device_and_no_mac() {
        let dir = tempfile::tempdir().unwrap();
        let spec = a_spec(dir.path());
        let recorder = Recorder::new();
        spec.define(&mut recorder.api()).unwrap();
        assert!(!recorder
            .paths()
            .iter()
            .any(|p| p.starts_with("/network-interfaces")));

        let mut with_mac = a_spec(dir.path());
        with_mac.mac = Some("06:00:AC:10:00:01".into());
        let err = with_mac.validate().unwrap_err();
        assert!(
            err.to_string().contains("without a network device"),
            "{err}"
        );
    }

    #[test]
    fn a_tap_names_the_interface_the_guest_gets() {
        let dir = tempfile::tempdir().unwrap();
        let mut spec = a_spec(dir.path());
        spec.tap = Some("desk0".into());
        let recorder = Recorder::new();
        spec.define(&mut recorder.api()).unwrap();
        let calls = recorder.calls.lock().unwrap().clone();
        let iface = calls
            .iter()
            .find(|c| c.1 == "/network-interfaces/eth0")
            .unwrap();
        assert!(iface.2.as_deref().unwrap().contains("desk0"));
        assert!(iface.2.as_deref().unwrap().contains("iface_id"));
    }

    #[test]
    fn the_balloon_is_defined_with_statistics_on_because_the_policy_reads_them() {
        let dir = tempfile::tempdir().unwrap();
        let spec = a_spec(dir.path());
        let recorder = Recorder::new();
        spec.define(&mut recorder.api()).unwrap();
        let calls = recorder.calls.lock().unwrap().clone();
        let balloon = calls.iter().find(|c| c.1 == "/balloon").unwrap();
        let body = balloon.2.as_deref().unwrap();
        assert!(body.contains("\"amount_mib\":4096"), "{body}");
        assert!(body.contains("\"stats_polling_interval_s\":1"), "{body}");
        assert!(body.contains("\"deflate_on_oom\":true"), "{body}");
    }

    #[test]
    fn a_machine_with_no_balloon_says_nothing_about_one() {
        let dir = tempfile::tempdir().unwrap();
        let mut spec = a_spec(dir.path());
        spec.balloon_mib = None;
        let recorder = Recorder::new();
        spec.define(&mut recorder.api()).unwrap();
        assert!(!recorder.paths().iter().any(|p| p == "/balloon"));
    }

    #[test]
    fn the_vsock_device_carries_the_cid_and_the_socket_of_the_ports() {
        let dir = tempfile::tempdir().unwrap();
        let spec = a_spec(dir.path());
        let recorder = Recorder::new();
        spec.define(&mut recorder.api()).unwrap();
        let calls = recorder.calls.lock().unwrap().clone();
        let vsock = calls.iter().find(|c| c.1 == "/vsock").unwrap();
        let body = vsock.2.as_deref().unwrap();
        assert!(body.contains("\"guest_cid\":3"), "{body}");
        assert!(body.contains("v.sock"), "{body}");
    }

    #[test]
    fn a_machine_that_asks_for_more_than_thirty_two_vcpus_is_refused_here() {
        let dir = tempfile::tempdir().unwrap();
        let mut spec = a_spec(dir.path());
        spec.vcpus = 48;
        let err = spec.validate().unwrap_err();
        assert!(err.to_string().contains("1 to 32"), "{err}");
    }

    #[test]
    fn a_guest_id_of_zero_one_or_two_is_refused() {
        for cid in [0, 1, 2] {
            let dir = tempfile::tempdir().unwrap();
            let mut spec = a_spec(dir.path());
            spec.vsock = Some(VsockDevice {
                guest_cid: cid,
                uds_path: dir.path().join("v.sock"),
            });
            let err = spec.validate().unwrap_err();
            assert!(err.to_string().contains("2 is the host"), "{err}");
        }
    }

    #[test]
    fn a_root_disk_this_run_cannot_write_is_refused_before_firecracker_sees_it() {
        let dir = tempfile::tempdir().unwrap();
        let spec = a_spec(dir.path());
        // The file is there and its mode says read-only: Firecracker would answer
        // "Permission denied" about a path the user thought was fine.
        let mut perms = std::fs::metadata(&spec.root.path).unwrap().permissions();
        perms.set_readonly(true);
        std::fs::set_permissions(&spec.root.path, perms).unwrap();
        let err = spec.validate().unwrap_err();
        assert!(
            err.to_string().contains("not writable by this run"),
            "{err}"
        );
    }

    #[test]
    fn a_missing_kernel_or_disk_is_a_sentence_about_the_path() {
        let dir = tempfile::tempdir().unwrap();
        let mut spec = a_spec(dir.path());
        spec.kernel.image = dir.path().join("nope");
        assert!(spec
            .validate()
            .unwrap_err()
            .to_string()
            .contains("not there"));
        let mut spec = a_spec(dir.path());
        spec.disks[0].path = dir.path().join("nope.raw");
        assert!(spec.validate().unwrap_err().to_string().contains("data"));
    }

    #[test]
    fn the_command_that_starts_firecracker_names_the_api_socket_and_nothing_else() {
        let cmd = command(
            Path::new("/usr/bin/firecracker"),
            &["--api-sock", "/run/x.sock"],
        );
        assert_eq!(cmd.get_program(), "/usr/bin/firecracker");
        assert_eq!(
            cmd.get_args()
                .map(|a| a.to_string_lossy().into_owned())
                .collect::<Vec<_>>(),
            vec!["--api-sock", "/run/x.sock"]
        );
    }

    #[test]
    fn the_machine_configuration_leaves_dirty_page_tracking_off() {
        let dir = tempfile::tempdir().unwrap();
        let spec = a_spec(dir.path());
        let config = spec.machine_configuration();
        assert_eq!(config.track_dirty_pages, None);
        assert_eq!(config.smt, Some(false));
    }

    #[test]
    fn an_api_socket_that_answers_is_an_api_and_a_path_that_exists_is_not() {
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("api.sock");
        assert!(!api_socket_answers(&socket), "nothing there yet");

        // The window the example hit: the file is there, nobody is listening.
        {
            let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
            assert!(api_socket_answers(&socket), "a listener answers");
            drop(listener);
        }
        assert!(socket.exists(), "the socket file outlives the listener");
        assert!(
            !api_socket_answers(&socket),
            "and a stale one answers nothing"
        );
    }

    #[test]
    fn the_wait_for_the_api_ends_at_once_when_it_answers() {
        // The wait itself, without a machine: the socket it waits for is this
        // test's own listener, so there is no child to start or to stop.
        let dir = tempfile::tempdir().unwrap();
        let socket = dir.path().join("api.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let started = std::time::Instant::now();
        let mut spins = 0;
        while !api_socket_answers(&socket) {
            spins += 1;
            assert!(spins < 100);
        }
        assert!(started.elapsed() < Duration::from_millis(200));
    }

    #[test]
    fn a_file_this_process_can_write_is_reported_writable() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("f");
        std::fs::write(&f, b"x").unwrap();
        assert!(writable(&f));
        assert!(!writable(&dir.path().join("not-there")));
    }
}
