//! **Does it really work?**  A minimal run of this crate against a real
//! Firecracker: define the machine, start it, wait for the guest's own landmark,
//! read the console, and take the machine away.
//!
//! It is an example rather than a test on purpose.  A unit test must not need
//! KVM, a guest or a Firecracker (`AGENTS.md`), and a system test belongs to the
//! the run as a whole; this is the step between the two, for the person doing
//! this project to run by hand — and it is the shape the application's own run
//! will have.
//!
//! ```text
//! cd desktop-cracker
//! cargo run --release --example boot -- \
//!     --firecracker ../temp/fc-study/bin/firecracker \
//!     --kernel       ../temp/fc-study/out/vmlinux-6.1.155 \
//!     --initramfs    ../download/initramfs.gz \
//!     --rootfs       ../download/rootfs.ext4 \
//!     --rootfs-ro --vcpus 12 --memory 6144
//! ```
//!
//! Every path is required and none has a default inside the project: what the
//! run boots is the caller's business, and a hidden default is a machine nobody
//! asked for.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use dc_fc_vm::{Api, Console, Spec, VmProcess};

struct Args {
    firecracker: PathBuf,
    kernel: PathBuf,
    initramfs: Option<PathBuf>,
    rootfs: PathBuf,
    rootfs_ro: bool,
    vcpus: u32,
    memory: u64,
    marker: String,
    wait: Duration,
}

fn parse() -> Args {
    let mut args = Args {
        firecracker: PathBuf::new(),
        kernel: PathBuf::new(),
        initramfs: None,
        rootfs: PathBuf::new(),
        rootfs_ro: false,
        vcpus: 12,
        memory: 6144,
        marker: "DESK-READY".into(),
        wait: Duration::from_secs(30),
    };
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        let mut value = |what: &str| {
            it.next().unwrap_or_else(|| {
                eprintln!("{arg} needs {what}");
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
            "--marker" => args.marker = value("a string"),
            "--wait" => args.wait = Duration::from_secs(value("seconds").parse().unwrap_or(30)),
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

const USAGE: &str = "boot --firecracker PATH --kernel PATH --rootfs PATH \
                     [--initramfs PATH] [--rootfs-ro] [--vcpus N] [--memory MiB] \
                     [--marker TEXT] [--wait SECONDS]";

fn main() {
    let args = parse();
    let run_dir = std::env::temp_dir().join(format!("dc-fc-example-{}", std::process::id()));
    let _ = std::fs::create_dir_all(&run_dir);

    let spec = Spec {
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
        // The example has no services, so it has no vsock device either: a port
        // whose listener is missing is a guest that gets a reset.
        vsock: None,
        balloon_mib: Some(args.memory / 3 * 2),
        api_socket: run_dir.join("api.sock"),
        program: args.firecracker.clone(),
        ..Spec::default()
    };

    let started = Instant::now();
    let mut vm = VmProcess::spawn(&spec).expect("starting firecracker");
    println!(
        "[example] firecracker pid {} (spawned in {:.1} ms)",
        vm.id(),
        started.elapsed().as_secs_f64() * 1000.0
    );
    vm.wait_api(spec.api_timeout).expect("the API socket");
    println!(
        "[example] API up after {:.1} ms",
        started.elapsed().as_secs_f64() * 1000.0
    );

    let mut api = Api::connect(vm.api_socket());
    let version = api.version().expect("the API answering its own version");
    println!(
        "[example] {} after {:.1} ms",
        version.firecracker_version,
        started.elapsed().as_secs_f64() * 1000.0
    );

    spec.define(&mut api).expect("defining the machine");
    println!(
        "[example] defined ({} requests) after {:.1} ms",
        api.calls(),
        started.elapsed().as_secs_f64() * 1000.0
    );
    api.start().expect("starting the machine");

    // The pinning, as the application does it: the vCPU threads exist once the
    // machine has started, so it is done here and not before.
    let layout = dc_fc_vm::CpuLayout::detect();
    if let Some(cpus) = layout.cpus_for(spec.vcpus as usize) {
        let _ = dc_fc_vm::cpu::pin_process(vm.id(), &cpus);
        let pinned = dc_fc_vm::cpu::pin_vcpu_threads(vm.id(), &cpus, std::path::Path::new("/proc"));
        println!(
            "[example] {pinned} vCPU thread(s) on {}",
            layout.cpus_list()
        );
    }

    let console = vm.console().clone();
    let ready = console.wait_ready(&args.marker, args.wait);
    println!(
        "[example] {} after {:.1} ms",
        if ready {
            "the guest is up"
        } else {
            "NO LANDMARK"
        },
        started.elapsed().as_secs_f64() * 1000.0
    );
    println!("[example] the guest said:\n{}", Console::tail(&console, 8));

    if let Ok(stats) = api.balloon_stats() {
        println!(
            "[example] balloon: target {} MiB, actual {} MiB, guest free {} MiB of {} MiB",
            stats.target_mib,
            stats.actual_mib,
            stats.free_memory.unwrap_or(0) / (1024 * 1024),
            stats.total_memory.unwrap_or(0) / (1024 * 1024)
        );
    }

    // The clean shutdown: the guest's own power button, then the process.
    let _ = api.send_ctrl_alt_del();
    for _ in 0..50 {
        if vm.exited().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    println!(
        "[example] firecracker {} after {:.1} ms",
        if vm.exited().is_some() {
            "exited"
        } else {
            "still running"
        },
        started.elapsed().as_secs_f64() * 1000.0
    );
    let _ = vm.kill();
    let _ = std::fs::remove_dir_all(&run_dir);
}
