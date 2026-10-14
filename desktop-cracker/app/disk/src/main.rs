//! `desk-disk` — manage a guest disk, **on the Firecracker path**.
//!
//! ```text
//! desk-disk                                  the disk manager's window (no arguments)
//! desk-disk create      --path disk.raw [--pass <passphrase>] [--size 20G]
//! desk-disk rootdisk    --path disk.raw [--pass <passphrase>] [--size 20G]
//! desk-disk change-pass --path disk.raw [--current-pass <p>] [--new-pass <p2>]
//! desk-disk resize      --path disk.raw [--size 40G] [--pass <passphrase>]
//! desk-disk info        --path disk.raw
//! desk-disk validate    --path disk.raw [--pass <passphrase>]
//! ```
//!
//! **`create` makes a data disk; `rootdisk` makes the disk the guest boots from** (the operator,
//! 2026-10-13): the userland travels into the **root** disk and nowhere else, so `create` copies
//! nothing and an additional disk is an encrypted container with an empty filesystem a person fills.
//! `--seed DIR` / `--seed-image PATH` name a userland explicitly for a caller that really wants a
//! bootable disk, and `rootdisk` is exactly `create` with this build or package's own userland
//!.
//!
//! **The one disk tool this project has**: `create`, `info`, `resize`, `change-pass` and
//! `validate`, each in a microVM of its own — no root, no loop device and no package on the host.
//! Two things are worth saying about it:
//!
//! * **the image is raw.**  Firecracker attaches raw images, so a disk is a raw file and no
//!   image tool is involved anywhere: making an image is `truncate` and growing one is
//!   `ftruncate`, which `dc-fc-disk::image` does;
//! * **the job runs in a Firecracker microVM** (`dc-fc-disk`), with the secrets going to the
//!   guest over the **control channel** instead of a 9P share.  Everything else about a job
//!   — the job name on the kernel command line, the guest's own `cryptsetup`, its
//!   `DESK-DISK …` lines — is the guest's own tool, unchanged.
//!
//! A disk is **always encrypted**: there is
//! no plain-disk option, and the password is the user's own.  When `--pass` is not given (or
//! is empty) the password is **asked for on standard input** — the prompt goes to standard
//! error and the answer is read one line at a time, with the echo off when that input is a
//! terminal.  Nothing is stored: the host holds it in the run's own memory, the guest copies
//! it to RAM and removes it, and the host's copy is zeroized with the run.

use std::path::PathBuf;

use anyhow::{Context, Result};

use dc_disk_manager::{DiskJob, Job};
use dc_fc_disk::{image, DiskRun};

#[cfg(feature = "gui")]
mod window;

/// A milestone line for a person: what the tool is doing, and nothing per-call
/// (`AGENTS.md`: what a program prints is what a person needs, never a per-call trail).
/// The project's own macro prints `[desktop-cracker] …`; this tool is a command a person runs, so
/// its lines are named after the command.
macro_rules! milestone {
    ($($arg:tt)*) => { println!("desk-disk: {}", format_args!($($arg)*)) };
}

/// **What is copied into a new filesystem**: this build's userland image, or the userland as a
/// directory (`mke2fs -d` writes one without mounting anything).  Only a **root** disk gets one.
#[derive(Debug, Clone)]
enum Seed {
    Image(PathBuf),
    Tree(PathBuf),
}

/// The command line, as the user types it.
#[derive(Debug, Default)]
struct Args {
    command: String,
    path: Option<PathBuf>,
    password: Option<String>,
    current_password: Option<String>,
    new_password: Option<String>,
    size: Option<String>,
    seed: Option<PathBuf>,
    seed_image: Option<PathBuf>,
    mapper: String,
    kernel: Option<PathBuf>,
    initramfs: Option<PathBuf>,
    firecracker: Option<PathBuf>,
    run_dir: Option<PathBuf>,
    help: bool,
}

const USAGE: &str = "\
desk-disk — create and manage a desktop-cracker guest disk

USAGE:
    desk-disk                              open the disk manager (a window: make,
                                               resize, change a passphrase, look at what
                                               is on a disk)
    desk-disk <command> [options]

COMMANDS:
    create        make a new **data** disk: a LUKS container with an ext4 filesystem in it and
                  **nothing in it** — an additional disk for the guest to mount and fill
    rootdisk      make the disk the guest **boots from**: the same as create, with this build or
                  package's own userland copied into it (this is what `make rootdisk` runs)
    change-pass   change the disk's passphrase
    resize        grow the filesystem to the disk's current size
    info          report what is on the disk
    validate      **prove** the disk opens, every layer of it, inside a microvm:
                  the device, the key file, cryptsetup's own passphrase test, the
                  open, and the mapped device.  This is the tool to run when the
                  application says a password does not open a disk: it uses the
                  same guest the application uses, and it says which step failed.

OPTIONS:
    --path PATH            the disk image (created if absent, by `create`)
    --pass TEXT            the passphrase; when it is absent or empty it is asked
                           for on standard input (the prompt on standard error)

                           It is a **development convenience**: the shell keeps what
                           was typed here (its history, `ps`'s output, a script), and a
                           password typed at a prompt is not kept anywhere.  Neither is
                           written to a file: it goes into the job's control channel,
                           the guest's own tools read it and remove it, and the run's
                           copy is zeroized when the job ends.
    --current-pass TEXT    the passphrase in force (for change-pass)
    --new-pass TEXT        the new passphrase (for change-pass)
    --size SIZE            the size for a new disk, e.g. 20G (default 20G)
    --seed PATH            a userland **tree** to copy into the new disk, which is
                           what makes it bootable (`make rootfs` builds the tree)
    --seed-image PATH      the userland as a ready ext4 image (`tools/seed-image.sh`
                           makes one from the tree): the same thing, without the tree
                           having to be readable by this user
    --mapper NAME          the device-mapper name inside the guest (default desktop-cracker)
    --kernel PATH          the guest kernel (default temp/download/kernel)
    --initramfs PATH       the guest image (default temp/download/initramfs.gz)
    --firecracker PATH     the Firecracker binary (default: from PATH)
    --run-dir PATH         where the job's own sockets go (default under TMPDIR)
    -h, --help             this text

Every job runs in a microVM, so this needs no root and no loop device: the guest's
own kernel creates the filesystem, the LUKS container and the passphrase change.
A disk is always encrypted, and it is a **raw** file: Firecracker attaches raw
images and nothing else.
";

fn main() {
    if let Err(e) = try_main() {
        eprintln!("desk-disk: {e:#}");
        std::process::exit(1);
    }
}

/// The media a job boots from: the project's **one** search (`dc_common::media`), which is the
/// application's own — the tree's `temp/download/`, the package's `kernel/` and `images/`, and an
/// installed prefix, in that order, beside the executable.  A job and a run are given the same
/// media by the same rule, which is what makes an installed `desk-disk`
/// create the disk an installed `desktop-cracker` boots.
///
/// When nothing is there the tree's own name is named anyway, so the error below says what was
/// looked for.
fn default_kernel() -> PathBuf {
    dc_common::media::kernel()
}

fn default_initramfs() -> PathBuf {
    dc_common::media::initramfs().unwrap_or_else(|| PathBuf::from("temp/download/initramfs.gz"))
}

/// The seed image, when this tree or this package has one: the userland as a ready ext4 image,
/// which is what `create` copies into a new disk.  `None` is the tree's own userland **directory**
/// instead, which the job copies through a share (slower, and it needs no image to be built).
fn default_seed_image() -> Option<PathBuf> {
    dc_common::media::seed_image()
}

fn default_firecracker() -> PathBuf {
    dc_common::media::firecracker()
}

fn try_main() -> Result<()> {
    let args = parse(std::env::args().skip(1))?;
    if args.help {
        print!("{USAGE}");
        return Ok(());
    }
    // **No command is the window** (the objective of 2026-10-13): running `desk-disk` — or
    // `desk-disk`, which is the same program under the name a desktop entry uses — with
    // nothing else opens the disk manager.  A build without the `gui` feature says so and prints the
    // usage rather than opening nothing at all.
    if args.command.is_empty() {
        #[cfg(feature = "gui")]
        {
            std::process::exit(window::DiskWindow::run());
        }
        #[cfg(not(feature = "gui"))]
        {
            eprintln!(
                "desk-disk: this build has no window; run with a command instead: \
                 create, resize, change-pass, info, validate"
            );
            print!("{USAGE}");
            std::process::exit(2);
        }
    }

    let path = args
        .path
        .clone()
        .context("--path is required (the disk image to work on)")?;

    let run = DiskRun {
        kernel: args.kernel.clone().unwrap_or_else(default_kernel),
        initramfs: args.initramfs.clone().unwrap_or_else(default_initramfs),
        firecracker: args.firecracker.clone().unwrap_or_else(default_firecracker),
        // The run's own sockets: this user's runtime directory, named after this
        // process.  A job's sockets are its own, and they go away with the job.
        run_dir: args.run_dir.clone().unwrap_or_else(|| {
            dc_common::run_directory(&dc_common::runtime_dir(), std::process::id())
        }),
        ..DiskRun::default()
    };
    if !run.kernel.exists() {
        anyhow::bail!(
            "the guest kernel {} does not exist (run `make build-kernel`, or pass --kernel)",
            run.kernel.display()
        );
    }
    if !run.initramfs.exists() {
        anyhow::bail!(
            "the guest image {} does not exist (run `make initramfs`, or pass --initramfs)",
            run.initramfs.display()
        );
    }

    let job = match args.command.as_str() {
        "validate" => {
            let password = password(&args.password, "Passphrase: ")?;
            let job = DiskJob::new(Job::Validate, &path).with_password(password);
            let started = std::time::Instant::now();
            let result = run.run(&job)?;
            for line in &result.lines {
                println!("{line}");
            }
            println!(
                "validate: {} in {:.1}s",
                if result.ok { "OK" } else { "FAILED" },
                started.elapsed().as_secs_f64()
            );
            if !result.ok {
                std::process::exit(1);
            }
            return Ok(());
        }
        // **A data disk, or the disk the guest boots from** (the operator, 2026-10-13): the two
        // differ in exactly one thing — whether this build's userland is copied into the new
        // filesystem — and everything else about them is the same job.
        "create" | "rootdisk" => {
            let root = args.command == "rootdisk";
            // The password first, before anything is made: a job that cannot start must not
            // leave a half-made image behind.
            let prompt = if root {
                "Passphrase for the new root disk: "
            } else {
                "Passphrase for the new disk: "
            };
            let password = password(&args.password, prompt)?;
            if !path.exists() {
                let size = parse_size(args.size.as_deref().unwrap_or("20G"))?;
                image::create_raw(&path, size)?;
                milestone!("created {} ({} MiB, raw)", path.display(), size);
            } else {
                milestone!(
                    "using the existing {} (create does not overwrite)",
                    path.display()
                );
            }
            let mut job = DiskJob::new(Job::CreateLuks, &path).with_password(password);
            // **What is copied into it**, in the order the two switches and the command name it:
            // `--seed DIR` and `--seed-image PATH` are a caller naming a userland, `rootdisk` is
            // this build's own, and **`create` copies nothing at all** — an additional disk is the
            // user's own data (dist: the userland travels into the root disk and nowhere
            // else).  The image first when both are here: one block device copied to another is what
            // a disk controller is for.
            let seed = args.seed.clone();
            let seed_image = args.seed_image.clone();
            let picked = match (&seed_image, &seed) {
                (Some(image), _) => Some(Seed::Image(image.clone())),
                (None, Some(tree)) => Some(Seed::Tree(tree.clone())),
                (None, None) if root => match (default_seed_image(), dc_common::media::seed_tree())
                {
                    (Some(image), _) => Some(Seed::Image(image)),
                    (None, Some(tree)) => Some(Seed::Tree(tree)),
                    (None, None) => None,
                },
                (None, None) => None,
            };
            match picked {
                Some(Seed::Image(image)) => job = job.with_seed_image(image),
                Some(Seed::Tree(tree)) => job = job.with_seed(tree),
                None if root => anyhow::bail!(
                    "there is no userland to put in the root disk: this build has neither \
                     images/rootfs.ext4 nor temp/download/rootfs (run `make rootfs` first)"
                ),
                None => milestone!(
                    "nothing is copied into it: a data disk is empty, and the userland belongs to \
                     the root disk (--seed DIR or --seed-image PATH names one if you want it here)"
                ),
            }
            job
        }
        "resize" => {
            // Growing the *image* is this process's work — and on a raw file that is
            // `ftruncate`, nothing else; the guest then grows the filesystem inside the
            // container to fill it.
            let password = if is_luks(&path) {
                Some(password(&args.password, "Passphrase: ")?)
            } else {
                None
            };
            if let Some(size) = &args.size {
                let mb = parse_size(size)?;
                image::resize_raw(&path, mb)?;
                milestone!("{} grown to {} MiB", path.display(), mb);
            }
            let mut job = DiskJob::new(Job::Resize, &path);
            if let Some(password) = password {
                job = job.with_password(password);
            }
            job
        }
        "change-pass" => {
            let current = password(&args.current_password, "Current passphrase: ")?;
            let new = password(&args.new_password, "New passphrase: ")?;
            DiskJob::new(Job::ChangePassword, &path)
                .with_password(current)
                .with_new_password(new)
        }
        "info" => DiskJob::new(Job::Info, &path),
        other => anyhow::bail!("unknown command {other:?}; run --help for the list"),
    };

    let job = job.with_mapper(args.mapper.clone());
    // **One job at a time, for the whole machine** (the tool and the window): a job's directory is
    // `run-<pid>`, so two jobs would not share sockets — but they would write the same disk if they
    // were given it, and the guest's own work is minutes long.  `flock` is what says "somebody else
    // is running a job now", and it is released when this process ends, however it ends.
    let _lock = job_lock(&run.run_dir)?;
    milestone!("running the disk job in a microvm (no root needed)");
    let result = run.run(&job)?;
    for line in &result.lines {
        println!("{line}");
    }
    if !result.ok {
        anyhow::bail!("the job did not succeed (see the lines above)");
    }
    milestone!("done in {:.1}s", result.took.as_secs_f64());
    Ok(())
}

/// **A lock the whole machine honours**: one disk job at a time.  It lives beside the job's own
/// directory (`run-<pid>`'s parent, this user's runtime directory), it is taken with `flock` and it
/// is released when the last holder closes it or ends — which is what makes the window and the tool
/// refuse each other's work rather than run two jobs over one disk.
pub fn job_lock(run_dir: &std::path::Path) -> Result<std::fs::File> {
    let path = run_dir
        .parent()
        .unwrap_or_else(|| std::path::Path::new("."))
        .join("disk-job.lock");
    if let Some(parent) = path.parent() {
        dc_common::fs::create_dir_all(parent)?;
    }
    let file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&path)
        .with_context(|| format!("opening the job lock {}", path.display()))?;
    use std::os::unix::io::AsRawFd;
    let taken = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if taken != 0 {
        anyhow::bail!(
            "another disk job is running (the lock {} is held); wait for it to finish",
            path.display()
        );
    }
    Ok(file)
}

/// A passphrase for a job: the option's value, or **asked for on standard input** when it
/// was not given (or was given empty).
///
/// The prompt goes to standard *error* — so a pipeline's data stays clean — and the answer is
/// read from standard input, one line, with the echo turned off while it is typed when that
/// input is a terminal.
fn password(given: &Option<String>, prompt: &str) -> Result<String> {
    if let Some(text) = given {
        if !text.is_empty() {
            return Ok(text.clone());
        }
    }
    let text = ask_on_stdin(prompt)?;
    if text.is_empty() {
        anyhow::bail!("a disk needs a passphrase (it is not optional); nothing was done");
    }
    Ok(text)
}

/// Ask on standard input, with the echo off when it is a terminal.
fn ask_on_stdin(prompt: &str) -> Result<String> {
    use std::io::{BufRead, Write};

    let mut err = std::io::stderr();
    write!(err, "{prompt}")?;
    err.flush()?;

    let stdin = std::io::stdin();
    let saved = echo_off_stdin();
    let mut line = String::new();
    let read = stdin
        .lock()
        .read_line(&mut line)
        .context("reading the passphrase from standard input");
    restore_echo(saved);
    writeln!(err)?;
    read?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}

/// Turn the echo off, when standard input is a terminal (a pipe has no echo).
fn echo_off_stdin() -> Option<libc::termios> {
    use std::os::unix::io::AsRawFd;
    let stdin = std::io::stdin();
    let fd = stdin.as_raw_fd();
    let mut t: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut t) } != 0 {
        return None;
    }
    let saved = t;
    t.c_lflag &= !libc::ECHO;
    unsafe { libc::tcsetattr(fd, libc::TCSANOW, &t) };
    Some(saved)
}

fn restore_echo(saved: Option<libc::termios>) {
    use std::os::unix::io::AsRawFd;
    let Some(saved) = saved else { return };
    let stdin = std::io::stdin();
    unsafe { libc::tcsetattr(stdin.as_raw_fd(), libc::TCSANOW, &saved) };
}

/// Is the image a LUKS container?  (The magic is readable without a key, and it is **the
/// image's own header** that answers — see `dc_fc_disk::image::is_luks` for why asking an
/// outside tool was wrong on this path.)
fn is_luks(path: &std::path::Path) -> bool {
    image::is_luks(path)
}

/// `20G`, `512M`, `1024` (MiB) — the sizes a person types.
fn parse_size(text: &str) -> Result<u64> {
    let text = text.trim();
    let (digits, unit) = match text.chars().last() {
        Some(c) if c.is_ascii_alphabetic() => (&text[..text.len() - 1], c),
        _ => (text, 'M'),
    };
    let value: u64 = digits
        .trim()
        .parse()
        .with_context(|| format!("{text:?} is not a size (try 20G, 512M)"))?;
    let mb = match unit.to_ascii_uppercase() {
        'M' => value,
        'G' => value * 1024,
        other => anyhow::bail!("{other:?} is not a size unit (use M or G)"),
    };
    if mb < 8 {
        anyhow::bail!("{mb} MiB is too small for a disk");
    }
    Ok(mb)
}

/// The command line parser: one option per thing a person says, in the shapes they say it.
fn parse(args: impl Iterator<Item = String>) -> Result<Args> {
    let mut out = Args {
        mapper: "desk".into(),
        ..Args::default()
    };
    let mut args = args.peekable();
    let mut command_seen = false;
    while let Some(arg) = args.next() {
        let mut value = |what: &str| -> Result<String> {
            args.next().with_context(|| format!("{arg} needs {what}"))
        };
        match arg.as_str() {
            "create" | "rootdisk" | "change-pass" | "resize" | "info" | "validate" => {
                if command_seen {
                    anyhow::bail!("one command at a time (got {arg} after {})", out.command);
                }
                out.command = arg.clone();
                command_seen = true;
            }
            "--path" => out.path = Some(PathBuf::from(value("a path")?)),
            "--pass" => out.password = Some(value("a passphrase")?),
            "--current-pass" => out.current_password = Some(value("a passphrase")?),
            "--new-pass" => out.new_password = Some(value("a passphrase")?),
            "--size" => out.size = Some(value("a size")?),
            "--seed" => out.seed = Some(PathBuf::from(value("a directory")?)),
            "--seed-image" => out.seed_image = Some(PathBuf::from(value("a path")?)),
            "--mapper" => out.mapper = value("a name")?,
            "--kernel" => out.kernel = Some(PathBuf::from(value("a path")?)),
            "--initramfs" => out.initramfs = Some(PathBuf::from(value("a path")?)),
            "--firecracker" => out.firecracker = Some(PathBuf::from(value("a path")?)),
            "--run-dir" => out.run_dir = Some(PathBuf::from(value("a path")?)),
            "-h" | "--help" => out.help = true,
            other if other.starts_with('-') => {
                anyhow::bail!("{other:?} is not an option this tool takes; run --help")
            }
            other => anyhow::bail!("{other:?} is not a command; run --help for the list"),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(args: &[&str]) -> Result<Args> {
        parse(args.iter().map(|s| s.to_string()))
    }

    /// **`rootdisk` is a command, and it is the one that carries a userland** (the operator,
    /// 2026-10-13): `create` makes an empty data disk, and the two are told apart by the word the
    /// caller typed — which is what the job's own choice of what to copy is made from.
    #[test]
    fn the_two_kinds_of_disk_are_two_commands() {
        let data = parsed(&["create", "--path", "data.raw", "--size", "8G"]).unwrap();
        assert_eq!(data.command, "create");
        let root = parsed(&["rootdisk", "--path", "root.raw", "--size", "24G"]).unwrap();
        assert_eq!(root.command, "rootdisk");
        // A command that names a userland itself is still `create`, and it is what the two
        // switches are for.
        let seeded = parsed(&["create", "--path", "d.raw", "--seed", "/tmp/rootfs"]).unwrap();
        assert_eq!(seeded.seed, Some(PathBuf::from("/tmp/rootfs")));
    }

    #[test]
    fn the_command_line_is_the_project_s_own() {
        // The same words, in the same shapes: a person who knows one tool knows the other.
        let a = parsed(&[
            "create",
            "--path",
            "disk.raw",
            "--pass",
            "value",
            "--size",
            "20G",
            "--seed-image",
            "seed.raw",
        ])
        .unwrap();
        assert_eq!(a.command, "create");
        assert_eq!(a.path, Some(PathBuf::from("disk.raw")));
        assert_eq!(a.password.as_deref(), Some("value"));
        assert_eq!(a.size.as_deref(), Some("20G"));
        assert_eq!(a.seed_image, Some(PathBuf::from("seed.raw")));
        assert_eq!(a.mapper, "desk");

        let a = parsed(&[
            "change-pass",
            "--path",
            "d.raw",
            "--current-pass",
            "a",
            "--new-pass",
            "b",
        ])
        .unwrap();
        assert_eq!(a.command, "change-pass");
        assert_eq!(a.current_password.as_deref(), Some("a"));
        assert_eq!(a.new_password.as_deref(), Some("b"));

        assert_eq!(
            parsed(&["info", "--path", "d.raw"]).unwrap().command,
            "info"
        );
    }

    #[test]
    fn a_command_line_this_tool_does_not_know_says_so() {
        let e = parsed(&["shrink", "--path", "d.raw"])
            .unwrap_err()
            .to_string();
        assert!(e.contains("not a command"), "{e}");
        let e = parsed(&["create", "--nonsense"]).unwrap_err().to_string();
        assert!(e.contains("not an option"), "{e}");
        let e = parsed(&["create", "info", "--path", "d.raw"])
            .unwrap_err()
            .to_string();
        assert!(e.contains("one command at a time"), "{e}");
        let e = parsed(&["--path"]).unwrap_err().to_string();
        assert!(e.contains("needs a path"), "{e}");
    }

    #[test]
    fn sizes_are_the_ones_a_person_types() {
        assert_eq!(parse_size("20G").unwrap(), 20 * 1024);
        assert_eq!(parse_size("512M").unwrap(), 512);
        assert_eq!(parse_size("1024").unwrap(), 1024);
        assert_eq!(parse_size(" 2g ").unwrap(), 2048);
        assert!(parse_size("big").is_err());
        assert!(parse_size("2T").is_err());
        assert!(
            parse_size("1M").is_err(),
            "a disk smaller than a filesystem is refused"
        );
    }

    #[test]
    fn a_passphrase_that_was_given_is_used_as_it_was_given() {
        assert_eq!(
            password(&Some("given".into()), "Passphrase: ").unwrap(),
            "given"
        );
        // A passphrase that was **not** given is asked for on standard input, and that path
        // is deliberately not exercised here: a unit test that reads a terminal is a test
        // that waits on a person (`AGENTS.md`: a test does not wait on the system, and a
        // unit test mocks what is outside it).  What the prompt does — the echo off, the
        // prompt on standard error, one line read — is the application's own `dc-dialog` on
        // the real path; here it is the shell conveniences a person runs by hand.
    }

    #[test]
    fn an_image_that_is_not_there_is_not_a_container() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nothing.raw");
        assert!(
            !is_luks(&path),
            "a path that is not there is not a LUKS container"
        );
        std::fs::write(&path, vec![0u8; 4096]).unwrap();
        assert!(!is_luks(&path), "an empty file is not one either");
    }
}
