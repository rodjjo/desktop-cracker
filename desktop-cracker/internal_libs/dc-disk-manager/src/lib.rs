//! The disk-management microVM.
//!
//! Making a guest disk needs a filesystem and a LUKS container built **on** it:
//! `mke2fs`, `cryptsetup`, `resize2fs`.  Doing that on the host means a loop
//! device, `CAP_SYS_ADMIN` and the packages installed there — and this project's
//! host has none of those (no passwordless sudo, and a hypervisor of its own).
//!
//! So the work happens in a **second microVM**, whose entire userland is the
//! tools for it: the guest's own kernel does the block layer, the encryption and
//! the filesystem, and the host only hands it a file it is allowed to write.
//! There is no root, no loop device, no container runtime and no package on the
//! host involved.
//!
//! One run does one job, and the job comes in on the kernel command line (the
//! guest reads `/proc/cmdline`):
//!
//! ```text
//! desk.diskjob=create|info|resize|change-pass
//! desk.disk=luks|ext4       desk.diskfs=ext4
//! desk.mapper=<name>        desk.device=/dev/vda
//! ```
//!
//! The **secrets never touch a command line**: the current passphrase is written
//! into the run's control share (a 9P folder only the microVM can read) and the
//! guest removes it as soon as it has copied it to RAM; a new passphrase for
//! `change-pass` goes the same way, in its own file.

use std::path::{Path, PathBuf};
use std::time::Duration;

use dc_common::fs;

/// What a job's own steps can fail with: the shape `dc-disk` uses, kept here so a caller that
/// only needs the plan and the secrets does not have to know about a driver (the *Firecracker*
/// disk tool, `desktop-cracker/app/disk`, is what runs a job).
pub type Result<T> = std::result::Result<T, dc_disk::DiskError>;

/// What a run is asked to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Job {
    /// Open the container with one password and say whether it worked.
    ///
    /// It is a job of its own because **the application asks for the password, not the
    /// guest**: the guest boots, tries the password the host wrote into the control
    /// share, reports `password ok` or `wrong-password`, and powers off.  The
    /// application asks again when it was wrong — five seconds later, to make guessing
    /// slow — and starts the guest a second time.  Nothing has to be typed at a console
    /// nobody can see yet (the password is asked "using a gui interface").
    TryPassword,
    /// **Prove every layer** of a disk inside the guest a real run uses: the device, the
    /// key file, `cryptsetup --test-passphrase`, `luksOpen`, and the mapped device.
    ///
    /// It is the tool that makes "the disk works" a measurement rather than a guess, in
    /// the environment that will actually run it (`desk-disk validate`).
    Validate,
    /// Make a LUKS container on the device and a filesystem inside it.  There is
    /// no plain-disk job: this project's disk *is* the encrypted one.
    CreateLuks,
    /// Grow the filesystem to the container's current size.
    Resize,
    /// Change the container's passphrase.
    ChangePassword,
    /// Report what is on the device.
    Info,
}

impl Job {
    /// The word the guest's init looks for on the kernel command line.
    pub fn as_str(self) -> &'static str {
        match self {
            Job::TryPassword => "desk-try",
            Job::Validate => "validate",
            Job::CreateLuks => "create",
            Job::Resize => "resize",
            Job::ChangePassword => "change-pass",
            Job::Info => "info",
        }
    }

    /// Every job works through the LUKS container.
    pub fn kind(self) -> &'static str {
        "luks"
    }
}

/// What one run was asked for.
#[derive(Debug, Clone)]
pub struct DiskJob {
    pub job: Job,
    /// The image the host attaches: a raw file.
    pub image: PathBuf,
    /// The passphrase that opens the container, when the job needs one.
    pub current: Option<String>,
    /// The new passphrase, for [`Job::ChangePassword`].
    pub new: Option<String>,
    /// The device-mapper name the guest uses.
    pub mapper: String,
    /// Run the guest with no network at all.
    pub no_network: bool,
    /// The vCPUs the job runs on.  Every job is short and the guest's tools are
    /// CPU-bound (a filesystem, a LUKS keyslot's hashing), so the manager always
    /// boots with several: four is what a disk job uses.
    pub vcpus: u32,
    /// A userland to copy into the new filesystem, which is what makes the disk
    /// *bootable*: without one it is an empty filesystem, which is what a data disk
    /// wants.
    ///
    /// It is handed to the guest as a **read-only ext4 image of its own**, a second
    /// block device (see [`DiskJob::seed_image`]).
    pub seed: Option<PathBuf>,
    /// The image the guest copies the userland **from**: a raw ext4 filesystem the
    /// job builds out of `seed` once (`mke2fs -d`) and reuses.  A few hundred
    /// megabytes through 9P — followed by a thousand small-file writes — takes
    /// minutes, while the guest copying from one block device to another is what a
    /// disk controller is for.
    pub seed_image: Option<PathBuf>,
}

impl DiskJob {
    pub fn new(job: Job, image: impl Into<PathBuf>) -> DiskJob {
        DiskJob {
            job,
            image: image.into(),
            current: None,
            new: None,
            mapper: "desk".into(),
            no_network: true,
            // **One vCPU.**  The disk job is one linear write (a LUKS format, two `mke2fs`, and
            // the copy of a userland into the new filesystem), so more vCPUs buy it nothing —
            // and the operator's measurement is that they cost: giving the job four CPUs made
            // it fail with `luksFormat` on this host, and the guest's own watchdog reports soft
            // lockups ("the machine is slow due CPU doing softlocks from time to time inside
            // the VM", 2026-10-08).  One CPU is the shape that runs.
            vcpus: 1,
            seed: None,
            seed_image: None,
        }
    }

    /// Give the new filesystem a userland (see [`DiskJob::seed`]).
    pub fn with_seed(mut self, seed: impl Into<PathBuf>) -> Self {
        self.seed = Some(seed.into());
        self
    }

    /// The image the guest copies the userland from (see
    /// [`DiskJob::seed_image`]).  Built by the caller — or by
    /// [`DiskJob::prepare_seed_image`], which is what a tree with no image yet
    /// uses.
    pub fn with_seed_image(mut self, image: impl Into<PathBuf>) -> Self {
        self.seed_image = Some(image.into());
        self
    }

    /// How many MiB a directory holds, for the filesystem that will carry it (a `du` of the tree
    /// the userland is; `mke2fs -d` needs a size before it writes).
    fn directory_size_mb(dir: &Path) -> Result<u64> {
        let output = std::process::Command::new("du")
            .args(["-sm", &dir.display().to_string()])
            .output()
            .map_err(|source| dc_disk::DiskError::Invalid(format!("du could not run: {source}")))?;
        let text = String::from_utf8_lossy(&output.stdout);
        let mb = text
            .split_whitespace()
            .next()
            .and_then(|n| n.parse::<u64>().ok())
            .ok_or_else(|| {
                dc_disk::DiskError::Invalid(format!("du said nothing about {}", dir.display()))
            })?;
        Ok(mb)
    }

    /// Build `seed_image` out of `seed` when it is not there yet, and return it.
    ///
    /// `mke2fs -d` writes the tree into a fresh filesystem without mounting
    /// anything, so this needs no privileges and no loop device: the image is a
    /// plain file the guest mounts read-only.
    pub fn prepare_seed_image(&mut self) -> Result<Option<PathBuf>> {
        let Some(seed) = self.seed.clone() else {
            return Ok(None);
        };
        if let Some(image) = &self.seed_image {
            if image.exists() {
                return Ok(Some(image.clone()));
            }
        }
        let image = seed.with_extension("seed.ext4");
        if !seed.is_dir() {
            return Err(dc_disk::DiskError::Invalid(format!(
                "the userland {} is not a directory (a .tar.gz is no longer used: hand \
                 over the tree, or an image made from it)",
                seed.display()
            )));
        }
        // Room for the tree with slack for a filesystem's own bookkeeping.
        let mb = Self::directory_size_mb(&seed)?.max(64) * 3 / 2 + 64;
        let file = std::fs::File::create(&image).map_err(|source| dc_common::Error::Io {
            path: image.clone(),
            source,
        })?;
        file.set_len(mb * 1024 * 1024)
            .map_err(|source| dc_common::Error::Io {
                path: image.clone(),
                source,
            })?;
        drop(file);
        let status = std::process::Command::new("mke2fs")
            .args([
                "-q",
                "-F",
                "-t",
                "ext4",
                "-L",
                "desk-seed",
                "-d",
                &seed.display().to_string(),
                &image.display().to_string(),
            ])
            .status()
            .map_err(|source| {
                dc_disk::DiskError::Invalid(format!("mke2fs could not run: {source}"))
            })?;
        if !status.success() {
            return Err(dc_disk::DiskError::Invalid(format!(
                "mke2fs could not build the userland image {}",
                image.display()
            )));
        }
        self.seed_image = Some(image.clone());
        Ok(Some(image))
    }

    pub fn with_password(mut self, password: impl Into<String>) -> Self {
        self.current = Some(password.into());
        self
    }

    pub fn with_new_password(mut self, password: impl Into<String>) -> Self {
        self.new = Some(password.into());
        self
    }

    /// How many vCPUs the job's microVM gets.
    pub fn with_vcpus(mut self, vcpus: u32) -> Self {
        self.vcpus = vcpus.max(1);
        self
    }

    pub fn with_mapper(mut self, mapper: impl Into<String>) -> Self {
        self.mapper = mapper.into();
        self
    }

    /// The kernel command line for this job: what the guest's init and its
    /// `diskmgr` read.
    pub fn kernel_append(&self) -> String {
        let mut line = format!(
            "console=ttyS0 rdinit=/init quiet loglevel=3 desk.diskjob={} desk.disk={} desk.diskfs=ext4 desk.mapper={} desk.device=/dev/vda",
            self.job.as_str(),
            self.job.kind(),
            self.mapper
        );
        if self.no_network {
            // The guest has nothing to do with a network for this job.
            line.push_str(" desk.nonetwork=1");
        }
        if self.seed_image.is_some() {
            // The second block device is /dev/vdb: the userland to copy from.
            line.push_str(" desk.seeddev=/dev/vdb");
        }
        line
    }

    /// The files the guest reads: the current passphrase and, when it changes,
    /// the new one.  They are written into `control_dir`, which is the run's own
    /// 9P share — the microVM's filesystem, nobody else's.
    pub fn write_secrets(&self, control_dir: &Path) -> Result<Vec<PathBuf>> {
        fs::create_dir_all(control_dir)?;
        let mut written = Vec::new();
        if let Some(current) = &self.current {
            let path = control_dir.join("disk.secret");
            fs::write_atomic(&path, current.as_bytes())?;
            restrict(&path);
            written.push(path);
        }
        if let Some(new) = &self.new {
            let path = control_dir.join("disk.secret.new");
            fs::write_atomic(&path, new.as_bytes())?;
            restrict(&path);
            written.push(path);
        }
        Ok(written)
    }
}

fn restrict(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

/// How long the user is made to wait after a **wrong** password: five seconds, which a
/// person mistyping does not notice and a program guessing does (12 attempts a minute
/// instead of thousands).  It is the pause the application's dialog loop uses.
pub const WRONG_PASSWORD_PAUSE: Duration = Duration::from_secs(5);

/// What the guest said about the **disk's password** (the `desk-try` job).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PasswordVerdict {
    /// The container opened: the password is the disk's.
    Ok,
    /// The container refused it.
    Wrong,
    /// The guest never got as far as trying it (no disk attached, the job failed):
    /// **not** the same as a wrong password, and a caller must not treat it as one.
    Unknown,
}

/// What one run produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskResult {
    pub job: Job,
    /// The lines the guest printed about the job (`DESK-DISK ...`).
    pub lines: Vec<String>,
    /// Did it say the job was done?
    pub ok: bool,
    /// How long the microVM took, wall clock.
    pub took: Duration,
}

impl DiskResult {
    /// How long the user is made to wait after a **wrong** password: five seconds, which a
    /// person mistyping does not notice and a program guessing does (12 attempts a minute
    /// instead of thousands).  It is the pause the application's dialog loop uses.
    pub const WRONG_PASSWORD_PAUSE: Duration = Duration::from_secs(5);

    /// What the guest said about the **disk's password** (the `desk-try` job).
    ///
    /// It reads the guest's own words, and only those: the loop that asks the user must
    /// never mistake "the guest never tried" for "the password is wrong" (one costs a
    /// dialog, the other costs five seconds and another dialog).
    pub fn password_verdict(&self) -> PasswordVerdict {
        if self.lines.iter().any(|l| l.contains("password ok")) {
            PasswordVerdict::Ok
        } else if self.lines.iter().any(|l| l.contains("wrong-password")) {
            PasswordVerdict::Wrong
        } else {
            PasswordVerdict::Unknown
        }
    }

    /// The value of one `key=value` the guest printed (`luks=yes`, `label=…`).
    pub fn field(&self, key: &str) -> Option<&str> {
        let needle = format!("{key}=");
        for line in self.lines.iter().rev() {
            if let Some(rest) = line.split(&needle).nth(1) {
                return rest.split_whitespace().next();
            }
        }
        None
    }

    pub fn summary(&self) -> String {
        let mut out = format!("{:?}: ", self.job);
        if self.lines.is_empty() {
            out.push_str("no output from the disk guest");
        } else {
            out.push_str(&self.lines.join("; "));
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_job_words_are_what_the_guest_reads() {
        assert_eq!(Job::CreateLuks.as_str(), "create");
        assert_eq!(Job::CreateLuks.kind(), "luks");
        assert_eq!(Job::ChangePassword.as_str(), "change-pass");
        assert_eq!(Job::Resize.as_str(), "resize");
        assert_eq!(Job::Info.as_str(), "info");
    }

    #[test]
    fn the_kernel_line_names_the_job_and_the_device() {
        let job = DiskJob::new(Job::CreateLuks, "/tmp/disk.raw");
        let line = job.kernel_append();
        assert!(line.contains("desk.diskjob=create"), "{line}");
        assert!(line.contains("desk.disk=luks"), "{line}");
        assert!(line.contains("desk.mapper=desk"), "{line}");
        assert!(line.contains("desk.device=/dev/vda"), "{line}");
        assert!(
            line.contains("console=ttyS0"),
            "the guest's console is its log: {line}"
        );
    }

    #[test]
    fn the_secrets_go_into_the_control_share_and_are_not_world_readable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let job = DiskJob::new(Job::ChangePassword, "/tmp/disk.raw")
            .with_password("old-one")
            .with_new_password("new-one");
        let written = job.write_secrets(dir.path()).unwrap();
        assert_eq!(written.len(), 2);
        for path in &written {
            let mode = std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "{path:?} must not be readable by anyone else");
        }
        assert_eq!(
            std::fs::read_to_string(dir.path().join("disk.secret")).unwrap(),
            "old-one"
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("disk.secret.new")).unwrap(),
            "new-one"
        );
    }

    #[test]
    fn a_result_reads_the_fields_the_guest_printed() {
        let result = DiskResult {
            job: Job::CreateLuks,
            lines: vec![
                "job=create kind=luks fs=ext4 device=/dev/vda mapper=desk".into(),
                "luksFormat ok device=/dev/vda".into(),
                "luks ok device=/dev/vda mapper=desk fstype=ext4".into(),
                "info label=desk".into(),
                "exit=0".into(),
            ],
            ok: true,
            took: Duration::from_secs(13),
        };
        assert_eq!(result.field("mapper"), Some("desk"));
        assert_eq!(result.field("fstype"), Some("ext4"));
        assert_eq!(result.field("label"), Some("desk"));
        assert_eq!(result.field("nothing"), None);
        assert!(result.ok);
        assert!(result.summary().contains("luks ok"), "{}", result.summary());
    }
}
