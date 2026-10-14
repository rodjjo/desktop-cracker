//! Shared constants, paths and tiny helpers used by every crate of this project.
//!
//! Nothing in here may depend on another internal library: this is the root of
//! the dependency graph.

use std::path::{Path, PathBuf};

/// Name of the project, as it appears on the command line and in the tray.
pub const APP_NAME: &str = "desktop-cracker";

/// The microvm's network: the constants both the network and the machine need (the
/// guest's MAC is the one the guest's own link is given **and** the one the network answers for).
pub mod net {
    /// The MAC of the guest's virtio-net device.  It is shared because two things must agree
    /// on it: the device the guest is given, and the network that answers its
    /// frames (a lease is bound to this MAC, and a frame to a MAC that is not this one is not
    /// this guest's).
    pub const GUEST_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
}

/// The controller state: the guest's phase, the window's visibility, the console's last
/// line and the commands a window sends (see the module's own documentation).
pub mod manager;

/// **The host's CPUs**: the physical cores, their hyper-threads, and the pinning the microVM
/// is given by default (the module carries the measurement it comes from).
pub mod cpu;

/// **The media a run or a job boots from**, and where it is looked for: the guest kernel, its
/// initramfs, the userland image a new disk is made from, and Firecracker.  One search, shared by
/// the application and the disk tool, so a repository, a package and an installed prefix are found
/// the same way.
pub mod media;

/// The version, from `Cargo.toml` — so `--version` and the dist tarball's name
/// are the same number without anyone having to keep two in step.
pub const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

/// The control/display socket the application listens on.
///
/// The project's own acceptance test is literally *"it uses a display
/// socket at /tmp/desktop-cracker-display.sock"*, so this path is not configurable.
pub const DISPLAY_SOCKET: &str = "/tmp/desktop-cracker-display.sock";

/// Where a run's sockets live.
///
/// **`$XDG_RUNTIME_DIR/desktop-cracker`**, which is per user and per login, and writable by that
/// user alone.  The path used to be the fixed `/tmp/desktop-cracker`, which is one place for the
/// whole machine: two runs of two users — or of one user in two terminals, which is what a
/// developer does — bind the same names, and a socket a crashed run left behind is a socket the next
/// run trips over.
///
/// `$XDG_RUNTIME_DIR` is not always set: a session started by `cron`, by `sudo` or by a plain shell
/// has none.  Then the same rule is kept with the user's own directory, `~/.desktop-cracker/run`,
/// which is `0700` like the home directory it sits in.  It is never a shared path under `/tmp`.
pub fn runtime_dir() -> PathBuf {
    runtime_dir_for(
        std::env::var("XDG_RUNTIME_DIR").ok().as_deref(),
        &home_dir(),
    )
}

/// The same rule, with its inputs named: what a test checks without touching the environment or
/// the user's own directory.
pub fn runtime_dir_for(xdg_runtime_dir: Option<&str>, home: &Path) -> PathBuf {
    // An empty value is the same as none: a session that exports the name and nothing else.
    match xdg_runtime_dir.filter(|value| !value.is_empty()) {
        // `$XDG_RUNTIME_DIR` is **shared by every application of this user's session**, so this
        // project's name goes in it.
        Some(value) => {
            let path = PathBuf::from(value);
            let base = if path.is_absolute() {
                path
            } else {
                home.join(value)
            };
            base.join(APP_NAME)
        }
        // The fallback is this project's **own** directory, so it needs no name of its own inside
        // it — and it is kept short on purpose.  A unix socket's whole path has a limit the kernel
        // enforces (`SUN_LEN`, 107 bytes), and a run's longest name is
        // `run-<pid>/v.sock_59000`: the directory above it has to leave room for it.
        None => home.join(".desktop-cracker").join("run"),
    }
}

/// The directory one **run** keeps its sockets in: `<runtime dir>/run-<pid>`.
///
/// The pid is the point: two runs of the same user do not share a vsock path either, and a
/// directory of a run that is gone is named after that run's own pid, so no live run is ever
/// confused with it.
pub fn run_directory(base: &Path, pid: u32) -> PathBuf {
    base.join(format!("run-{pid}"))
}

/// Make the runtime directory, and make it **private**: `0700`, the way `$XDG_RUNTIME_DIR` itself
/// is.  A socket a run listens on is a door into that run, and the directory holding it belongs to
/// the user who runs it.
pub fn ensure_private(path: impl AsRef<Path>) -> std::io::Result<()> {
    let path = path.as_ref();
    // **Every directory this call creates** is private, not only the last one: a run's sockets sit
    // in `…/desktop-cracker/run-<pid>`, and the directory above them is this project's own too.
    // An ancestor that was already there — the session's `$XDG_RUNTIME_DIR`, somebody else made it
    // and knows what mode it wants — is left exactly as it is.
    let mut created = Vec::new();
    let mut at = path;
    while !at.exists() {
        created.push(at.to_path_buf());
        let Some(parent) = at.parent() else { break };
        at = parent;
    }
    std::fs::create_dir_all(path)?;
    for dir in created.iter().rev() {
        set_private(dir)?;
    }
    set_private(path)
}

/// `chmod 0700` on a directory this project made.  A directory that is already there and is not
/// ours (a `$XDG_RUNTIME_DIR` the session made, which is already `0700`) is left exactly as it is.
fn set_private(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mode = std::fs::metadata(path)
        .map(|m| m.permissions().mode() & 0o777)
        .unwrap_or(0o700);
    if mode != 0o700 {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// A directory **this run made**, and the promise that it goes away with the run.
///
/// The run's own sockets: a run leaves nothing behind in the user's runtime directory.
/// A run has more than one way out — the window closed, the guest refused the disk, a signal, an
/// error half-way through the boot — and a cleanup written at the end of one function is a cleanup
/// that only happens on that one path.  This is the cleanup as a value: the directory is created
/// private, and it is removed when the value that owns it is dropped, whichever way the run ended.
///
/// It removes the directory it created, and nothing else.
pub struct PrivateDir {
    path: PathBuf,
}

impl PrivateDir {
    /// Create it (`mkdir -p`, `0700`) and take ownership of it.
    pub fn create(path: impl AsRef<Path>) -> std::io::Result<PrivateDir> {
        let path = path.as_ref();
        ensure_private(path)?;
        Ok(PrivateDir {
            path: path.to_path_buf(),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn join(&self, part: impl AsRef<Path>) -> PathBuf {
        self.path.join(part)
    }
}

impl Drop for PrivateDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Guest-side mount point of the root filesystem folder (9P `rootfs` tag).
pub const GUEST_ROOTFS_DIR: &str = "/mnt/root";

/// Guest-side mount point of the disk/volume folder (9P `disk` tag).
pub const GUEST_DISK_DIR: &str = "/mnt/disk";

/// Guest-side mount point of the shared folders (9P `shareNN` tags).
pub const GUEST_SHARE_DIR: &str = "/mnt/share";

/// Guest-side mount point of the host X11 socket directory (`xdisplay` tag).
pub const GUEST_X_DIR: &str = "/tmp/.X11-unix";

/// 9P mount tag of the root-folder share.
pub const TAG_ROOTFS: &str = "rootfs";

/// 9P mount tag of the disk/volume folder share.
pub const TAG_DISK: &str = "disk";

/// 9P mount tag of the host X11 socket directory share.
pub const TAG_XDISPLAY: &str = "xdisplay";

/// 9P mount tag of the application's own control directory — the one share the
/// guest may always write to, because it carries only the guest's own status
/// files (its memory numbers, its ready flag) and never the user's data.
pub const TAG_CONTROL: &str = "control";

/// Where the guest finds the control directory.  Not `/tmp`: the guest's own
/// `/tmp` is the host's X11 socket directory.
pub const GUEST_CONTROL_DIR: &str = "/run/desktop-cracker";

/// Prefix of the 9P tags generated for the user's shared folders.
pub const TAG_SHARE_PREFIX: &str = "share";

/// The console node this project's window listens on inside the guest.
pub const DISPLAY_CONSOLE: &str = "0";

/// Errors that can happen in any component.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// `std::fs` helpers that keep the failing path in the error message.
pub mod fs {
    use super::{Error, Result};
    use std::fs;
    use std::path::Path;

    pub fn read_to_string(path: impl AsRef<Path>) -> Result<String> {
        let path = path.as_ref();
        fs::read_to_string(path).map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })
    }

    pub fn read(path: impl AsRef<Path>) -> Result<Vec<u8>> {
        let path = path.as_ref();
        fs::read(path).map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })
    }

    pub fn write(path: impl AsRef<Path>, data: impl AsRef<[u8]>) -> Result<()> {
        let path = path.as_ref();
        fs::write(path, data).map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })
    }

    pub fn create_dir_all(path: impl AsRef<Path>) -> Result<()> {
        let path = path.as_ref();
        fs::create_dir_all(path).map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })
    }

    /// Create the parent directory of `path`, if it has one.
    pub fn create_parent(path: impl AsRef<Path>) -> Result<()> {
        if let Some(parent) = path.as_ref().parent() {
            if !parent.as_os_str().is_empty() {
                create_dir_all(parent)?;
            }
        }
        Ok(())
    }

    /// Write `data` to `path` atomically: a temporary file in the same
    /// directory, then `rename(2)`.  Config files are read by a second
    /// instance of the application, so a half-written file must never be
    /// observable.
    pub fn write_atomic(path: impl AsRef<Path>, data: impl AsRef<[u8]>) -> Result<()> {
        let path = path.as_ref();
        create_parent(path)?;
        let tmp = path.with_extension(format!(
            "{}.tmp",
            path.extension().and_then(|e| e.to_str()).unwrap_or("new")
        ));
        fs::write(&tmp, data).map_err(|source| Error::Io {
            path: tmp.clone(),
            source,
        })?;
        fs::rename(&tmp, path).map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })
    }
}

/// The user's home directory (`$HOME`, falling back to the passwd entry).
pub fn home_dir() -> PathBuf {
    if let Ok(h) = std::env::var("HOME") {
        if !h.is_empty() {
            return PathBuf::from(h);
        }
    }
    // getpwuid without pulling in a crate: read /etc/passwd for our uid.
    let uid = unsafe { libc::getuid() };
    if let Ok(passwd) = std::fs::read_to_string("/etc/passwd") {
        for line in passwd.lines() {
            let f: Vec<&str> = line.split(':').collect();
            if f.len() >= 6 && f[2].parse::<u32>() == Ok(uid) {
                return PathBuf::from(f[5]);
            }
        }
    }
    PathBuf::from("/root")
}

/// **Where this package is, and therefore where its state is**.
///
/// The application has **no fallback path**: everything it reads and writes — the settings, the
/// root disk, the folder the disks live in — is in the folder the package was extracted into.  An
/// installed package at `~/desktop-cracker` keeps its `config.yml` there and its disks in its own
/// `disks/`, and a package extracted at `/opt/vm` keeps them in `/opt/vm`.  Two of them are two
/// installations and two folders, never one hidden directory they would share.
///
/// `None` only when the executable's own path cannot be read, which is the one case where nothing
/// can be said about where the package is.
///
/// The rule itself lives in [`crate::media`], where the media a run boots from is looked up: a run
/// and the tool that makes its disk have to answer "where is this package?" the same way.
pub fn package_dir() -> Option<PathBuf> {
    crate::media::package_dir()
}

/// `~/.desktop-cracker` — the folder of an **older** installation, whose settings and disks lived
/// in the user's home instead of in the package.
///
/// Nothing reads it and nothing writes it: it is named here so the code that says "your data is
/// untouched" and the code that explains a moved installation can point at it.
pub fn legacy_config_dir() -> PathBuf {
    home_dir().join(".desktop-cracker")
}

/// The host's physical cores: the CPUs that are not hyper-threads of another.
/// The host's physical cores: the CPUs that are not hyper-threads of another.
///
/// The kernel says so in `/sys/devices/system/cpu/cpuN/topology/thread_siblings_list`,
/// which lists the CPUs sharing one physical core (and includes the CPU's own
/// number).  A host with hyper-threading off answers with just one number each.
/// `None` when the topology is not readable, so the caller can fall back.
///
/// One answer, one reader: this is [`cpu::topology`], counted (the same list is what the
/// microVM is pinned to — see that module).
pub fn physical_cores() -> Option<u32> {
    let topo = cpu::topology();
    if topo.cores() == 0 {
        return None;
    }
    Some(topo.cores() as u32)
}

/// Milliseconds since the Unix epoch.  Used where a value has to say *when* it
/// changed to a reader that cannot be called back (a file a guest polls).
pub fn now_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// The size the guest should believe it has, when the user does not say.
///
/// **6 GiB**, and the number is a measurement rather than a taste.  The guest's own memory
/// pressure is what makes its kernel reclaim, and reclaim is what makes a CPU disappear for
/// 25 seconds inside the guest — the `watchdog: BUG: soft lockup` the operator reported, with
/// `kworker` and `swapper` as the stuck tasks, and the guest's `/proc/stat` showing **zero
/// steal** at the same time (so the vCPUs were `vCPU-time`, not unscheduled).  A guest with a
/// desktop (LightDM, X, Xfce, a browser) that is given 3 GiB reaches for memory the moment it
/// is asked to install or run anything, and it has no swap at all to reach for; 6 GiB is what
/// keeps the guest out of direct reclaim in ordinary use.  `-m 2048` is worse in a different
/// way: this kernel/initramfs pair does not boot at all at exactly that size (measured: every
/// shape stops after `ACPI: Core revision`, though 3072 boots in ~3.6 s).
///
/// The balloon is the other half of the answer: `balloon_automatic` gives this memory back to
/// the host while the guest is not using it, so asking for 6 GiB does not mean holding 6 GiB.
pub const DEFAULT_MEMORY_MB: u32 = 6 * 1024;

/// How many vCPUs a guest gets by default: the host's **physical cores** (not
/// its hyper-threads).  A microvm is meant to use the machine it is on, and a
/// guest that showed every thread would spend its scheduler sharing the physical
/// ones.  Falls back to the online CPUs when the topology is not readable.
pub fn default_vcpus() -> u32 {
    let cores = physical_cores().unwrap_or_else(|| {
        std::thread::available_parallelism()
            .map(|n| n.get() as u32)
            .unwrap_or(2)
            .max(1)
    });
    // **At most twelve.**  The operator's own finding, after a day of "24 cores is causing
    // problems": a microvm given every core of a 24-core host boots *slower* (the guest
    // spends its time bringing CPUs up, and its watchdog reports soft lockups), and the
    // desktop inside it is not faster for having them.  Twelve is a floor that leaves the
    // host room to run the window, the network and the audio path — which are all this same
    // process — and it is what the operator asked for.
    cores.min(MAX_DEFAULT_VCPUS)
}

/// The most vCPUs a machine gets by default (see [`default_vcpus`]).
pub const MAX_DEFAULT_VCPUS: u32 = 12;

/// How big a new root disk is (MiB): enough for a desktop with a browser and a
/// media player in it, and still a small file on the host while it is sparse.
pub const DEFAULT_ROOT_DISK_MB: u64 = 20 * 1024;

/// Report a milestone on the console: one short line, always flushed.
///
/// This is the application's **only** output of its own: there is no logging framework and no
/// log file, and what a person needs to see is written here.  A run that wants a record
/// redirects the process — `make run > run.log`.
pub fn milestone(fmt: std::fmt::Arguments<'_>) {
    use std::io::Write;
    let text = fmt.to_string();
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "[desktop-cracker] {text}");
    let _ = out.flush();
    // A milestone is the application's own line, and a **plugin** — when one is loaded — is the
    // other place it goes (the plugin's own contract, the `log` hook). With no plugin this is
    // one atomic load and a return; with one it is the same line, as an event.
    drop(out);
    dc_plugin::log("info", &text);
}

#[macro_export]
macro_rules! milestone {
    ($($arg:tt)*) => { $crate::milestone(format_args!($($arg)*)) };
}

/// Does this path exist and is it a directory?
pub fn is_dir(path: impl AsRef<Path>) -> bool {
    path.as_ref().is_dir()
}

/// Does this path exist?
pub fn exists(path: impl AsRef<Path>) -> bool {
    path.as_ref().exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_package_is_the_folder_the_binary_is_in() {
        // The test binary is `target/debug/deps/…`, so the folder with a `Cargo.toml` in
        // it is the workspace: the search is the same one the media uses, and it has to land on a
        // directory that really is the tree.
        let dir = package_dir().expect("the test binary is in the project's own tree");
        assert!(dir.ends_with("desktop-cracker"), "{dir:?}");
        assert!(dir.join("Cargo.toml").is_file(), "{dir:?}");
    }

    /// **There is no fallback config path**: the settings file is in the package, so an
    /// installation in two folders is two configurations.
    #[test]
    fn everything_the_application_keeps_is_in_the_package() {
        let package = package_dir().unwrap();
        assert_eq!(
            crate::media::settings_path_for(&package),
            package.join("config.yml")
        );
        assert_eq!(
            crate::media::disk_folder_for(&package),
            package.join("disks"),
            "the disks are the package's own folder, named the way the settings name it"
        );
        assert_eq!(
            crate::media::root_disk_for(&package),
            package.join("disks").join("root.raw"),
            "the root disk is a raw image inside that folder"
        );
    }

    #[test]
    fn tags_are_distinct() {
        assert_ne!(TAG_ROOTFS, TAG_DISK);
        assert_ne!(TAG_DISK, TAG_XDISPLAY);
    }

    /// The run's own sockets: a run's sockets live under the **user's** runtime
    /// directory, so a machine with two users — or one user with two runs — has two places.
    #[test]
    fn a_run_sockets_live_in_the_users_runtime_directory() {
        let home = Path::new("/home/user");
        let base = runtime_dir_for(Some("/run/user/1000"), home);
        assert_eq!(
            base,
            PathBuf::from("/run/user/1000/desktop-cracker"),
            "the name this project uses, under the runtime directory of the user who runs it"
        );
        // The pid names the run, so two runs of the same user have two directories.
        assert_eq!(
            run_directory(&base, 4242),
            PathBuf::from("/run/user/1000/desktop-cracker/run-4242")
        );
        assert_ne!(run_directory(&base, 1), run_directory(&base, 2));
    }

    /// `$XDG_RUNTIME_DIR` is not always set — `cron`, `sudo` and a plain shell have none — and the
    /// rule must not fall back to a path every user of the machine shares.
    #[test]
    fn without_the_runtime_directory_the_fallback_is_the_users_own() {
        let home = Path::new("/home/user");
        let fallback = runtime_dir_for(None, home);
        assert_eq!(
            fallback,
            PathBuf::from("/home/user/.desktop-cracker/run"),
            "this project's own directory, which needs no name of its own inside it"
        );
        assert!(
            !fallback.starts_with("/tmp"),
            "nothing of a run's sockets sits in a directory the whole machine shares: {fallback:?}"
        );
        // An empty value is the same as none: a session that exports nothing.
        assert_eq!(runtime_dir_for(Some(""), home), fallback);
    }

    /// The API socket's name is the one this project uses, and it is a **file** in the run's own
    /// directory — the directory is what the run removes.
    #[test]
    fn the_api_socket_is_in_the_run_s_own_directory() {
        let base = runtime_dir_for(Some("/run/user/1000"), Path::new("/home/user"));
        assert_eq!(
            run_directory(&base, 7).join("api.sock"),
            PathBuf::from("/run/user/1000/desktop-cracker/run-7/api.sock")
        );
    }

    /// The runtime directory is **private**: `0700`, the way `$XDG_RUNTIME_DIR` itself is.  A socket
    /// a run listens on is a door into that run.
    #[test]
    fn the_runtime_directory_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("run/desktop-cracker");
        ensure_private(&target).unwrap();
        ensure_private(&target).unwrap();
        let mode = std::fs::metadata(&target).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o700, "the directory a run's sockets sit in");
    }

    /// **A finished run leaves nothing behind**. The directory
    /// is a value that removes itself, so it is removed on the way out that a run actually took —
    /// including the one that was an error half-way through.
    #[test]
    fn a_runs_own_directory_goes_away_with_the_run() {
        let dir = tempfile::tempdir().unwrap();
        let own = run_directory(dir.path(), 4242);
        {
            let run = PrivateDir::create(&own).unwrap();
            // What a run keeps in it: sockets, and the control directory beside them.
            std::fs::create_dir_all(run.join("control")).unwrap();
            std::fs::write(run.join("api.sock"), b"not a socket, a stand-in").unwrap();
            assert!(own.exists());
        }
        assert!(
            !own.exists(),
            "the run's directory is removed when the run ends, whatever ended it"
        );
    }

    /// The whole chain this call creates is private.  A run's sockets sit in
    /// `…/desktop-cracker/run-<pid>`, and the directory above them is this project's own as well;
    /// a directory somebody else already made is left as they made it.
    #[test]
    fn every_directory_this_project_makes_is_private() {
        use std::os::unix::fs::PermissionsExt;
        let scratch = tempfile::tempdir().unwrap();
        // The session's own runtime directory, made by somebody else, with its own mode.
        let session = scratch.path().join("run-user");
        std::fs::create_dir_all(&session).unwrap();
        std::fs::set_permissions(&session, std::fs::Permissions::from_mode(0o755)).unwrap();

        let own = run_directory(
            &runtime_dir_for(Some(session.to_str().unwrap()), Path::new("/unused-home")),
            4242,
        );
        ensure_private(&own).unwrap();
        let mode = |path: &Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode(&session),
            0o755,
            "a directory somebody else made is left alone"
        );
        assert_eq!(
            mode(&session.join(APP_NAME)),
            0o700,
            "the project's own directory"
        );
        assert_eq!(mode(&own), 0o700, "the run's own directory");
    }

    /// A unix socket's whole path has a limit the kernel enforces (`SUN_LEN`), and the longest name
    /// a run creates is `run-<pid>/v.sock_<port>`.  The fallback is kept short so a run whose
    /// session has no `$XDG_RUNTIME_DIR` still reaches its own sockets.
    #[test]
    fn a_runs_socket_name_fits_what_a_unix_socket_path_may_be() {
        const SUN_LEN: usize = 108;
        let longest = |base: &Path| run_directory(base, 4_294_967_295).join("v.sock_59999");
        let xdg = longest(&runtime_dir_for(
            Some("/run/user/1000"),
            Path::new("/home/user"),
        ));
        let fallback = longest(&runtime_dir_for(None, Path::new("/home/user")));
        for path in [&xdg, &fallback] {
            assert!(
                path.as_os_str().len() < SUN_LEN,
                "a run's socket has to be bindable: {} is {} bytes",
                path.display(),
                path.as_os_str().len()
            );
        }
    }

    /// It removes **its own** directory.  The user's runtime directory, which is not the run's to
    /// take away, stays.
    #[test]
    fn it_removes_the_directory_it_created_and_not_the_one_above_it() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("desktop-cracker");
        std::fs::create_dir_all(&base).unwrap();
        {
            let _run = PrivateDir::create(run_directory(&base, 7)).unwrap();
        }
        assert!(!base.join("run-7").exists());
        assert!(
            base.exists(),
            "the user's own directory is not this run's to remove"
        );
    }

    #[test]
    fn atomic_write_replaces_content() {
        let dir = std::env::temp_dir().join(format!("dc-test-common-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let f = dir.join("a/b.txt");
        fs::write_atomic(&f, b"one").unwrap();
        assert_eq!(fs::read_to_string(&f).unwrap(), "one");
        fs::write_atomic(&f, b"two").unwrap();
        assert_eq!(fs::read_to_string(&f).unwrap(), "two");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
