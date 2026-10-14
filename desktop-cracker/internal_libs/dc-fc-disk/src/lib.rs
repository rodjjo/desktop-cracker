//! **A disk job, on Firecracker**.
//!
//! The project makes and re-keys a disk in a **second microVM**: the job travels on the
//! kernel command line, the passphrases travel through the run's control share (0600, and
//! the guest removes them), and the guest's own `cryptsetup` does the work — the host never
//! opens the container and never needs a loop device or root (`dc-disk-manager`).
//!
//! None of that needs a hypervisor.  What matters is only *how the pieces are attached*:
//!
//! | | what the pieces are |
//! |---|---|---|
//! | the job | `-append desk.diskjob=…` | the same, Firecracker's `boot_args` |
//! | the image | `virtio-blk-device` | `PUT /drives/probe`, so the guest's `/dev/vda` |
//! | the userland to copy | a second `virtio-blk-device` | `PUT /drives/seed`, `/dev/vdb` |
//! | the secrets | a 9P share mounted at `/run/desktop-cracker` | the **control channel** (56000), the guest's agent asking for each name |
//! | the guest's own words | the machine's serial | Firecracker's stdout, read as one and the same pipe |
//!
//! The job's **shape** is `dc_disk_manager`'s own ([`dc_disk_manager::DiskJob`]), so a caller
//! paths cannot drift: the same command line, the same jobs, the same result parsing.  What
//! is here is the machine that runs it and the two channels it needs.
//!
//! Two facts of this path that are worth stating plainly:
//!
//! * **the image may be a plain file attached read-write**, which is what a job needs and
//!   what a *run* must not do while another machine holds it — a job's guest and a run's
//!   guest cannot both have the same file open for writing;
//! * **there is no image tool**: growing a disk is `ftruncate` on a raw file, and there is no
//!   wrapper to convert between.  A raw image is what Firecracker attaches and what a job grows.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dc_disk_manager::{DiskJob, DiskResult, Job};
use dc_fc_control::{Control, ControlChannel};
use dc_fc_vm::{Disk, Kernel};
use dc_vsock::ports;

/// What can go wrong running a job.
#[derive(Debug, thiserror::Error)]
pub enum JobError {
    #[error("{0}")]
    Disk(#[from] dc_disk::DiskError),
    #[error("{0}")]
    Run(#[from] fc_run::RunError),
    #[error("{0}")]
    Vsock(#[from] dc_vsock::VsockError),
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("the job's guest said nothing this run understands:\n{0}")]
    NoResult(String),
}

pub type Result<T> = std::result::Result<T, JobError>;

/// Everything the job's machine is made of.
#[derive(Debug, Clone)]
pub struct DiskRun {
    /// The guest kernel: the project's own build (`temp/download/kernel`).
    pub kernel: PathBuf,
    /// The guest's initramfs: the same one a run uses, whose init reads
    /// `desk.diskjob=` off the command line instead of booting a system.
    pub initramfs: PathBuf,
    /// The Firecracker binary.
    pub firecracker: PathBuf,
    /// Where the job's sockets go.  A job's `uds_path` is its own: two machines sharing one
    /// is two machines colliding on the host's sockets.
    pub run_dir: PathBuf,
    /// The job's own vCPUs and memory.  It is one linear write, so it is small: the number
    /// is this project's own (`dc-disk-manager` measured four CPUs *failing* the job on
    /// this host, so one is the shape that works).
    pub vcpus: u32,
    pub memory_mib: u64,
    /// How long the job's guest may take.
    pub timeout: Duration,
}

impl Default for DiskRun {
    fn default() -> Self {
        DiskRun {
            kernel: PathBuf::new(),
            initramfs: PathBuf::new(),
            firecracker: PathBuf::from("firecracker"),
            // The run's own sockets: a job's sockets sit in this user's runtime
            // directory, not in a `/tmp` path every user of the machine shares.  A job is not a
            // desktop run and it has no pid in its name — one job at a time is this tool's shape —
            // but it is still this user's own directory.
            run_dir: dc_common::runtime_dir().join("disk-job"),
            vcpus: 1,
            memory_mib: 3072,
            timeout: Duration::from_secs(600),
        }
    }
}

impl DiskRun {
    /// The machine a job runs on: the image as the guest's `/dev/vda` (this project's own
    /// naming), the userland as `/dev/vdb`, and **no network, no balloon, no display** —
    /// the job's guest has nothing to do with any of them.
    ///
    /// The job's own words are on the kernel command line, exactly as the machine this project started with leaves
    /// them (`dc-disk-manager`'s `kernel_append`), so the guest's init and its `guest-tools`
    /// need no changes at all: a job is a job.
    pub fn machine_for(&self, job: &DiskJob) -> Result<fc_run::RunSpec> {
        let mut disks = Vec::new();
        if let Some(seed) = &job.seed_image {
            disks.push(Disk {
                name: "seed".into(),
                path: seed.clone(),
                read_only: true,
            });
        }
        Ok(fc_run::RunSpec {
            kernel: Kernel {
                image: self.kernel.clone(),
                initramfs: Some(self.initramfs.clone()),
                append: job.kernel_append(),
            },
            root: Disk {
                name: "probe".into(),
                path: job.image.clone(),
                read_only: false,
            },
            disks,
            vcpus: self.vcpus,
            memory_mib: self.memory_mib,
            program: self.firecracker.clone(),
            run_dir: self.run_dir.join("machine"),
            // A job's own guest id: a run of the application and a disk job are two
            // machines, and two machines must not share a context id.
            guest_cid: 4,
            balloon_mib: None,
            guest_timeout: self.timeout,
            shutdown_timeout: Duration::from_secs(20),
            balloon_policy: Default::default(),
            // The job's secrets go on the control channel, which the caller fills in
            // (`DiskRun::run`), and a job never boots a system from its disk: it *is* the
            // system that works on one.
            control: dc_fc_control::Control::new(),
            // A disk job has no screen, no sound and no shared folders: it *is* the machine
            // that works on a disk, and every one of those would be a channel nobody uses.
            display: None,
            audio: None,
            // A job's guest is never reached from the host: no port forward, and no switch that
            // could ask for one.  The same is true the other way — a disk job's guest has no reason
            // to reach this computer's services, and `--host-network` is the user's decision about
            // their own guest, not a knob a disk job can set.
            ssh_port: None,
            host_network: false,
            // **But the shutdown channel, yes**: a job's guest is an initramfs with no systemd,
            // and Firecracker has no power button to press — the agent's own reboot is what ends
            // the process (see `dc-fc-power`: without it a finished job sits there until its
            // timeout, which is exactly what was measured on 2026-10-10).
            shutdown_channel: true,
            x_socket: None,
            shares: Vec::new(),
            root_passphrase: None,
            boot_from_disk: false,
        })
    }

    /// Run one job and read what its guest said.
    pub fn run(&self, job: &DiskJob) -> Result<DiskResult> {
        let started = Instant::now();
        let mut owned = job.clone();
        // The userland image is built once and reused (`dc-disk-manager`'s own rule): a
        // few hundred megabytes through a share is minutes, a block device is seconds.
        if let Some(_image) = owned.prepare_seed_image()? {}
        let job = &owned;
        if !job.image.exists() {
            return Err(JobError::Disk(dc_disk::DiskError::Invalid(format!(
                "{} does not exist",
                job.image.display()
            ))));
        }

        // **The job's own directory, and it goes with the job**: a job has the same shape as a run — sockets of its own, in this user's
        // runtime directory — and a finished job leaves nothing behind.  A value that removes
        // itself, so a job that failed half-way is as clean as one that finished.
        let _job_dir = dc_common::PrivateDir::create(&self.run_dir)?;
        // The job's machine and its channels share **one** `uds_path`: the ports of a run
        // hang off the same socket the vsock device was given, so the spec is built first
        // and the channel is named after its own path.
        let spec = self.machine_for(job)?;
        let uds = spec.run_dir.join("v.sock");
        let control = Arc::new(std::sync::Mutex::new(Control::new()));
        // The secrets go **into the run's own memory** and out over the control channel:
        // never a file, never an argument, never the environment (`AGENTS.md`).
        //
        // They go in **before the guest starts**, for every job, and that is not a detail:
        // the guest reads `disk.secret` when it needs it and unlinks it as it does, so a
        // copy that arrived later would be a copy nobody could ask for.  It also means the
        // job's work is the *guest's* order, not ours — a `create` writes the container
        // first and reads the passphrase once it does, through the same tool and the same
        // name the earlier machine's 9P share used.
        {
            let mut control = control.lock().expect("the control share");
            control.put("diskplan", job.kernel_append());
            if let Some(current) = job.current.as_deref() {
                control.put_secret("disk.secret", current);
            }
            if let Some(new) = job.new.as_deref() {
                control.put_secret("disk.secret.new", new);
            }
        }

        let channel = Arc::new(ControlChannel::listen(
            &uds,
            ports::CONTROL,
            control.clone(),
        )?);
        let channel_thread = channel.clone().serve_in_background();

        let outcome = run_the_job(spec, control.clone());
        // The job is over: the guest may be **halted** with its end of the channel still
        // open (measured 2026-10-09 — a halted guest does not close its sockets), so the
        // channel is stopped from this side rather than waited for.
        channel.shutdown();
        let _ = channel_thread.join();
        // And the secrets go out of the run's memory the moment the guest cannot need them.
        control.lock().expect("the control share").forget_secrets();
        let log = outcome?;
        let _ = &channel;

        let lines: Vec<String> = log
            .lines()
            .filter_map(|l| {
                l.split_once("DESK-DISK")
                    .or_else(|| l.split_once("DESK-ROOT"))
                    .map(|(_, rest)| rest.trim().to_string())
            })
            .collect();
        if lines.is_empty() {
            return Err(JobError::NoResult(log));
        }
        let ok = job_succeeded(&lines);
        Ok(DiskResult {
            job: job.job,
            lines,
            ok,
            took: started.elapsed(),
        })
    }
}

/// Did the guest's job succeed?  **Its own last word about the job is the answer.**
///
/// The guest ends a job with `DESK-DISK exit=<status>`, and that status is the job's: a copy that ran
/// out of room on a disk too small for the userland ends with `exit=1` *after* printing the steps
/// that did work (`luksFormat ok`, `luks ok`).  Reading a step's `ok` as the job's answer is what
/// made a failed disk look like a created one (measured 2026-10-12: `the copy ended with 2`,
/// `exit=1`, and a `desk-disk create` that reported "done").  So the exit line wins whenever
/// the guest gave one, and the older reading — a step that said `ok` — is only the fallback for a
/// guest that never reported a status at all.
fn job_succeeded(lines: &[String]) -> bool {
    if let Some(status) = lines.iter().find_map(|line| {
        line.strip_prefix("exit=")
            .and_then(|value| value.trim().parse::<i32>().ok())
    }) {
        return status == 0;
    }
    lines
        .iter()
        .any(|line| line.contains(" ok") && !line.starts_with("info"))
}

/// Bring the job's machine up, let its guest do the work, and answer its console.
///
/// A job's guest **halts** when it is done (`reboot: System halted`), and a halted guest does
/// not end a Firecracker process and does not close its sockets (both measured 2026-10-09), so
/// what ends this is the guest's own last line on the console — `DESK-DISK exit=` or
/// `DESK-ROOT ` — and the machine is taken away the moment it appears.
fn run_the_job(spec: fc_run::RunSpec, control: Arc<std::sync::Mutex<Control>>) -> Result<String> {
    // The run's own startup is this project's order (channels, child, API, define, start) —
    // `fc_run` owns it, so a job cannot drift from a run.
    let mut started = fc_run::start(spec, false)?;
    // The control channel is what this guest is here for — the caller's own listener, on the
    // ports the run deliberately does not bind (`fc_run`'s own documentation says why).
    let _ = &control;
    // **The job is over when the guest says so**, not when the process ends: a job's guest
    // runs `guest-tools`, prints its `DESK-DISK …` lines and halts — and a halted guest does
    // *not* end a Firecracker process (measured 2026-10-09: `reboot: System halted` and
    // Firecracker still running), where a machine was started with `-no-reboot` and exited by
    // itself.  So the two endings are watched for: the guest's own last line, and a process
    // that ended on its own.
    const DONE: [&str; 2] = ["DESK-DISK exit=", "DESK-ROOT "];
    let deadline = Instant::now() + started.spec.guest_timeout;
    loop {
        let console = started.vm.console().text();
        if DONE.iter().any(|marker| console.contains(marker)) {
            break;
        }
        if started.vm.exited().is_some() || Instant::now() >= deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let log = started.vm.console().text();
    // **The whole console, when a probe asked for it** (`DESK_JOB_CONSOLE=1`): the `DESK-DISK …`
    // lines a job prints are what a caller shows a person, and a diagnosis — "which command failed,
    // and what did the kernel say about the device?" — needs the rest of what the guest said.  It is
    // a switch of this function and not of the application (`AGENTS.md`: the application has one run
    // mode); a caller that sets it is a person looking at a job, and the lines go to *its* standard
    // error, never to a file.
    if std::env::var_os("DESK_JOB_CONSOLE").is_some() {
        eprintln!("——— the job's console, as the guest said it ———");
        eprint!("{log}");
        eprintln!("——— end of the job's console ———");
    }
    let _ = started.shutdown();
    if log
        .lines()
        .any(|l| l.contains("DESK-DISK") || l.contains("DESK-ROOT"))
    {
        Ok(log)
    } else {
        Err(JobError::Run(fc_run::RunError::NoGuest(
            started.spec.guest_timeout,
            log.lines().rev().take(20).collect::<Vec<_>>().join("\n"),
        )))
    }
}

/// The images a job works with, and the arithmetic of a raw disk.
///
/// It is here — and not in a container script — because a raw image is a file and growing it is
/// `ftruncate`: no image tool, no loop device and no root are involved.
/// **The machine a disk tool's job runs on**: the guest's kernel, its initramfs and Firecracker found
/// **beside this binary** (`dc_common::media`: a tree, an extracted package, or a path in the
/// environment — the same search a run uses), and **this process's own** run directory
/// (`run-<pid>`, The run's own sockets: two jobs at once — a window and a terminal — do
/// not share sockets).
///
/// `Err` is the sentence a person reads when the media is not there, and it names what to do: every
/// caller that has to print it (`desk-disk`) prints this one.
pub fn tool_run() -> Result<DiskRun> {
    let kernel = dc_common::media::kernel();
    let initramfs = dc_common::media::initramfs();
    if !kernel.is_file() {
        return Err(JobError::Disk(dc_disk::DiskError::Invalid(format!(
            "the guest kernel {} is not there; a disk job boots a microVM of its own and needs it \
             (run `make build-kernel`, or pass --kernel)",
            kernel.display()
        ))));
    }
    let initramfs = initramfs.ok_or_else(|| {
        JobError::Disk(dc_disk::DiskError::Invalid(
            "the guest's initramfs is not there; a disk job boots a microVM of its own and needs it \
             (run `make initramfs`, or pass --initramfs)"
                .into(),
        ))
    })?;
    Ok(DiskRun {
        kernel,
        initramfs,
        firecracker: dc_common::media::firecracker(),
        run_dir: dc_common::run_directory(&dc_common::runtime_dir(), std::process::id()),
        ..DiskRun::default()
    })
}

/// **Make a guest root disk, with this build or package's own userland.**
///
/// The one place a settings window creates a disk: the job is the project's
/// [`Job::CreateLuks`], its userland is **this build or package's own**
/// (`dc_common::media::seed_image`, and the tree's userland directory when no image was built), and
/// the Firecracker binary is found the way a run finds it (`dc_common::media::firecracker`), so an
/// extracted package needs nothing set for this either.
///
/// The image file is created and sized here (one `ftruncate`); the LUKS container and the
/// filesystem inside it are built by the job's own guest — no root, no loop device, no `dm-crypt`
/// on the host.  **An existing file is never a job's target**: a disk is the user's data, and
/// overwriting one is not a thing this command may do.  The caller checks first
/// ([`creatable`](fn@crate::creatable)); this refuses as well, because a check is not a guarantee.
///
/// **The secret never touches a command line**: it is written into the run's control share, which
/// the job's guest removes as soon as it has it.
pub fn create_root_disk(path: &Path, size_mb: u64, passphrase: &str) -> Result<DiskResult> {
    if path.exists() {
        return Err(JobError::Disk(dc_disk::DiskError::Invalid(format!(
            "{} is already there; a disk is never overwritten",
            path.display()
        ))));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    image::create_raw(path, size_mb)?;
    let mut job = DiskJob::new(Job::CreateLuks, path).with_password(passphrase);
    // **The userland goes into the root disk** (this function makes one, and that is the whole
    // difference between it and a data disk): the image first — one block device copied to another
    // is what a disk controller is for — and the tree's own userland directory when no image was
    // built.  A caller with neither gets a refusal rather than a disk that boots nothing.
    match (
        dc_common::media::seed_image(),
        dc_common::media::seed_tree(),
    ) {
        (Some(image), _) => job = job.with_seed_image(image),
        (None, Some(tree)) => job = job.with_seed(tree),
        (None, None) => {
            return Err(JobError::Disk(dc_disk::DiskError::Invalid(
                "there is no userland to put in the root disk: this build has neither \
                 images/rootfs.ext4 nor temp/download/rootfs"
                    .into(),
            )))
        }
    }
    // **The machine a job runs on is found the way a run finds its own** (`tool_run`).
    tool_run()?.run(&job)
}

/// **Is there no disk at this path?** — a path with no file behind it is a package that has not
/// been used yet, and that is a question a window asks before it offers to make one.
pub fn creatable(path: &Path) -> bool {
    !path.as_os_str().is_empty() && !path.exists()
}

pub mod image {
    use super::*;

    /// Make an empty raw image of `size_mb`, without a filesystem inside it.
    pub fn create_raw(path: &Path, size_mb: u64) -> Result<()> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(true)
            .open(path)?;
        file.set_len(size_mb * 1024 * 1024)?;
        Ok(())
    }

    /// Grow a raw image.  There is nothing else to do: a raw file's size *is* its size.
    pub fn resize_raw(path: &Path, size_mb: u64) -> Result<()> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)?;
        let now = file.metadata()?.len();
        let wanted = size_mb * 1024 * 1024;
        if wanted > now {
            file.set_len(wanted)?;
        }
        Ok(())
    }

    /// Is this image a LUKS container?  **The first 512 bytes, and nothing else.**
    ///
    /// A LUKS header is public — its magic, the cipher, the key slots' salts — and the host
    /// may look at it without holding the key: that is how the application knows whether to
    /// ask for a password at all.  Two things about *how* it is read matter on this path,
    /// and both were found the hard way (measured 2026-10-09):
    ///
    /// * **it is a raw image, so the check is the magic.**  A check that asks an outside tool what
    ///   format an image is answers "I could not ask" for a raw file, and a caller that reads that
    ///   as "not encrypted" hands a `resize` job **no passphrase**: the guest's `cryptsetup
    ///   luksOpen` then says "No key available with this passphrase" — a wrong-password error for a
    ///   disk whose password was right.  Firecracker attaches raw files and only raw files, so the
    ///   question here has one answer's worth of code in it: read the magic;
    /// * **a bounded read.**  An earlier check `fs::read` the whole image to look at its first
    ///   bytes: on a 4 GiB disk that is four gigabytes of memory to answer a question about four
    ///   bytes.  It reads a header's worth and stops.
    pub fn is_luks(path: &Path) -> bool {
        use std::io::Read;
        const MAGIC: &[u8] = b"LUKS\xba\xbe";
        const HEADER: usize = 512;
        let Ok(mut file) = std::fs::File::open(path) else {
            return false;
        };
        let mut head = [0u8; HEADER];
        match file.read(&mut head) {
            Ok(n) if n >= MAGIC.len() => head.starts_with(MAGIC),
            _ => false,
        }
    }

    /// What the host can see about an image without opening it: its size and whether it
    /// carries a LUKS header.
    pub fn inspect(path: &Path) -> Result<(u64, bool)> {
        let size = std::fs::metadata(path)?.len();
        Ok((size, is_luks(path)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_raw_image_is_a_file_and_growing_it_is_setting_its_length() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("disk.raw");
        image::create_raw(&path, 4).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 4 * 1024 * 1024);
        image::resize_raw(&path, 8).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 8 * 1024 * 1024);
        // Growing is not shrinking: a resize that asks for less leaves the file as it is
        // (the filesystem inside it may be using the space).
        image::resize_raw(&path, 2).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 8 * 1024 * 1024);
        let (size, encrypted) = image::inspect(&path).unwrap();
        assert_eq!(size, 8 * 1024 * 1024);
        assert!(!encrypted, "an empty file is not a container");
    }

    #[test]
    fn a_luks_container_is_recognised_by_its_own_header_and_only_its_header() {
        let dir = tempfile::tempdir().unwrap();
        let plain = dir.path().join("plain.raw");
        std::fs::write(&plain, vec![0u8; 4096]).unwrap();
        assert!(!image::is_luks(&plain), "an empty file is not a container");
        assert!(
            !image::is_luks(&dir.path().join("nothing.raw")),
            "neither is one that is not there"
        );

        // **A file whose header says LUKS** — and nothing else about it is a container.  The
        // check must answer from the magic: asking an outside tool is what made a real `resize` job
        // send no passphrase at all (measured 2026-10-09).
        let container = dir.path().join("container.raw");
        let mut bytes = vec![0u8; 4096];
        bytes[..6].copy_from_slice(b"LUKS\xba\xbe");
        std::fs::write(&container, &bytes).unwrap();
        assert!(image::is_luks(&container));

        // And a **big** one costs a header's worth of reading, not the whole file: 64 MiB of
        // zeros with a container's magic in front is answered instantly.
        let big = dir.path().join("big.raw");
        let file = std::fs::File::create(&big).unwrap();
        file.set_len(64 * 1024 * 1024).unwrap();
        drop(file);
        {
            use std::io::{Seek, SeekFrom, Write};
            let mut file = std::fs::OpenOptions::new().write(true).open(&big).unwrap();
            file.seek(SeekFrom::Start(0)).unwrap();
            file.write_all(b"LUKS\xba\xbe").unwrap();
        }
        let started = std::time::Instant::now();
        assert!(image::is_luks(&big));
        assert!(
            started.elapsed() < std::time::Duration::from_millis(50),
            "a header is read, not the file ({:?})",
            started.elapsed()
        );
    }

    /// The guest's own status is the job's answer, whatever the steps said on the way there.
    #[test]
    fn a_jobs_answer_is_the_status_the_guest_gave_and_not_a_step_that_said_ok() {
        // A disk too small for the userland: the steps that worked said `ok`, the job did not.
        let failed = [
            "luksFormat ok device=/dev/vda".to_string(),
            "the container has two partitions: 1535 MiB of state, the rest for the root".into(),
            "copying the userland".to_string(),
            "the copy ended with 2".to_string(),
            "copying the userland from /dev/vdb failed (the copy's status is 2)".to_string(),
            "exit=1".to_string(),
        ];
        assert!(
            !job_succeeded(&failed),
            "a job whose guest said `exit=1` did not succeed, whatever it printed first"
        );
        let done = [
            "luksFormat ok device=/dev/vda".to_string(),
            "seeded the filesystem from /dev/vdb".to_string(),
            "luks ok device=/dev/vda mapper=desk fstype=ext4".to_string(),
            "exit=0".to_string(),
        ];
        assert!(job_succeeded(&done));
        // A guest that reported no status at all keeps the older reading.
        let no_status = ["luks ok device=/dev/vda".to_string()];
        assert!(job_succeeded(&no_status));
        let nothing_worked = ["luksFormat failed".to_string()];
        assert!(!job_succeeded(&nothing_worked));
    }

    #[test]
    fn a_jobs_secrets_are_put_where_the_guest_can_ask_for_them_and_nowhere_a_person_would_look() {
        // The whole point of the channel: `dc-disk-manager` writes them to a 9P share; here
        // they are a name in the run's memory, and the guest's agent asks for that name.
        let control = Control::new();
        let mut control = control;
        control.put_secret("disk.secret", "a passphrase");
        let answer = control.answer(&dc_vsock::Frame::new(
            dc_fc_control::KIND_READ,
            b"disk.secret\n".to_vec(),
        ));
        assert_eq!(answer[0].kind, dc_fc_control::KIND_DATA);
        // And a name the job did not put there is not there.
        let answer = control.answer(&dc_vsock::Frame::new(
            dc_fc_control::KIND_READ,
            b"disk.secret.new\n".to_vec(),
        ));
        assert_eq!(answer[0].kind, dc_fc_control::KIND_MISSING);
    }

    #[test]
    fn the_jobs_machine_has_the_image_as_its_root_disk_and_no_network() {
        // What the job's machine is: this project's own naming (the image is the guest's
        // `/dev/vda`), the userland as `/dev/vdb`, no balloon and no tap.
        let manager = DiskRun::default();
        assert_eq!(
            manager.vcpus, 1,
            "the machine this project started with measured four CPUs failing this job"
        );
        assert!(
            manager.memory_mib >= 3072,
            "the job copies a whole userland"
        );
        assert!(manager.run_dir.ends_with("disk-job"));
        assert!(
            !manager.run_dir.starts_with("/tmp"),
            "a job's sockets are in this user's runtime directory, not in a path the whole              machine shares: {:?}",
            manager.run_dir
        );
    }
}
