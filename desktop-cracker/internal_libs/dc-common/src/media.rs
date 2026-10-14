//! **The media a run or a job boots from, and where it is looked for**.
//!
//! Three files and one binary: the guest's kernel, its initramfs, the guest's userland image a new
//! disk is made from, and Firecracker itself.  They are this project's own build (`make build`,
//! `make rootfs`, `make download`), and a package built by `make dist` carries all of them.
//!
//! The search is the shape both a **repository** and an **installed package** need: beside the
//! executable, walking up, and the working directory last.  That is what makes the same binary work
//! from `target/release/`, from the package's `bin/` next to its own `kernel/` and
//! `images/`, and from an installed package at `~/desktop-cracker/bin/` — with no environment
//! variable and no working directory a user has to stand in.  `--kernel` / `--initramfs` override
//! every one of them.
//!
//! **The same search says where the package is, and the package is where the state is.**  A package
//! keeps its `config.yml` in its own folder and its disks in its own `disks/`:
//! extract it at `~/desktop-cracker` and the state is there, extract it at `/opt/vm` and it is
//! there.  There is **no fallback path** — no `~/.desktop-cracker` a run would read a second
//! installation's settings from.

use std::path::{Path, PathBuf};

/// The application's binary: the file whose presence beside a folder is what makes that folder a
/// package (`package_dir_in`).
const APP_BINARY: &str = "desktop-cracker";

/// **The workspace's own folder**, inside the root of this tree: the build output is at the root
/// (`target/`, `CARGO_TARGET_DIR`), so the workspace and the tree are two folders and both are the
/// project.
const WORKSPACE_DIR: &str = "desktop-cracker";

/// The names, in the order they are tried, under each candidate directory.
///
/// The package's own layout first (`make dist` writes `kernel/` and `images/`), then the media the
/// Makefile fills (`temp/download/`), then the bare name beside the binary.
const KERNEL_NAMES: [&str; 6] = [
    "kernel/kernel",
    "images/kernel",
    "temp/download/kernel",
    "download/kernel",
    "desktop-cracker/download/kernel",
    "kernel",
];

const INITRAMFS_NAMES: [&str; 7] = [
    "kernel/initramfs.gz",
    "images/initramfs.gz",
    "temp/download/initramfs.gz",
    "download/initramfs.gz",
    "desktop-cracker/download/initramfs.gz",
    "desktop-cracker/guest-agent-rs/out/initramfs.gz",
    "initramfs.gz",
];

/// The guest's userland as a ready ext4 image: what `desk-disk create --seed-image` copies into
/// a new disk, so a package can **make** a disk as well as run one.
const SEED_NAMES: [&str; 4] = [
    "images/rootfs.ext4",
    "temp/download/rootfs.ext4",
    "download/rootfs.ext4",
    "rootfs.ext4",
];

const SEED_TREE_NAMES: [&str; 3] = ["temp/download/rootfs", "download/rootfs", "rootfs"];

const FIRECRACKER_NAMES: [&str; 4] = [
    "firecracker",
    "bin/firecracker",
    "download/firecracker",
    "temp/download/firecracker",
];

/// The folders a package can be, from the executable upwards — **the same walk the media uses**.
///
/// A run and the tool that makes its disk have to answer "where is this package?" identically, or
/// an installed package would boot one disk and write its settings into another, so there is one
/// walk and both use it.  The working directory is not in it: no fallback, and the folder a person
/// happens to be standing in is not where this application keeps its settings.
pub fn package_candidates() -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(exe) = std::env::current_exe() {
        let mut at = exe.parent().map(Path::to_path_buf);
        for _ in 0..4 {
            let Some(dir) = at else { break };
            if !dirs.contains(&dir) {
                dirs.push(dir.clone());
            }
            at = dir.parent().map(Path::to_path_buf);
        }
    }
    dirs
}

/// **Which of the folders above is the package.**  Two shapes, and nothing else:
///
/// * an **extracted package** — `bin/desktop-cracker` beside its own `kernel/`, `images/`,
///   `libraries/` and `config.yml`;
/// * **this project's own tree** — a `Cargo.toml` with the workspace under it (`app/desktop`),
///   which is the folder a developer runs from.
///
/// A folder is looked at as itself and as the folder the workspace lives in (`desktop-cracker/`):
/// the build output is at the **root** of this tree (`target/`, `CARGO_TARGET_DIR`), so a binary
/// built here sits beside the workspace rather than inside it, and both spellings mean the same
/// project.
///
/// `None` when neither is there, which is the honest answer for a binary that was copied somewhere
/// on its own.
pub fn package_dir_in(dirs: &[PathBuf]) -> Option<PathBuf> {
    for dir in dirs {
        for candidate in [dir.clone(), dir.join(WORKSPACE_DIR)] {
            if candidate.join("bin").join(APP_BINARY).is_file() {
                return Some(candidate);
            }
            if candidate.join("Cargo.toml").is_file()
                && candidate.join("app").join("desktop").is_dir()
            {
                return Some(candidate);
            }
        }
    }
    None
}

/// The package this process belongs to, or `None` when the executable's path cannot be read.
pub fn package_dir() -> Option<PathBuf> {
    package_dir_in(&package_candidates())
}

/// `<package>/config.yml` — **the settings, in the package's own folder**.
pub fn settings_path_for(package: &Path) -> PathBuf {
    package.join("config.yml")
}

/// `<package>/disks` — the folder the settings name as `disk_folder`, the package's own.
pub fn disk_folder_for(package: &Path) -> PathBuf {
    package.join("disks")
}

/// `<package>/disks/root.raw` — the root disk a package boots.
///
/// **ASCII in the name, and `.raw`**: Firecracker attaches raw images, so a disk is a raw file
/// and a name that declares a format it is not is a name that has to be explained.
pub fn root_disk_for(package: &Path) -> PathBuf {
    disk_folder_for(package).join("root.raw")
}

/// The media's names, walking up **five** levels: the package's `bin/`, the package, and the
/// folders above up to the root of a source tree (`target/release/…` → the tree itself). This is
/// `candidate_dirs`, which the media search uses.
fn candidate_dirs_for_walk() -> Vec<PathBuf> {
    let mut dirs = package_candidates();
    dirs.push(PathBuf::from("."));
    dirs
}

/// Where the media lives, in the order an application tries: beside the executable (walking up four
/// levels, which covers `target/release/…` and an installed prefix), then the working
/// directory.
pub fn candidate_dirs() -> Vec<PathBuf> {
    candidate_dirs_for_walk()
}

/// The first `<dir>/<name>` that exists, over each directory in `dirs`.
///
/// `None` when nothing is there: a caller names the absence in its own error, which is what a
/// person needs to fix it (`make build`, `make rootfs`, or the switch that names the path).
pub fn first_in(dirs: &[PathBuf], names: &[&str]) -> Option<PathBuf> {
    for dir in dirs {
        for name in names {
            let candidate = dir.join(name);
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }
    None
}

/// The guest kernel.  When nothing is there the tree's own name is named anyway, so the error a
/// caller prints says what was looked for.
pub fn kernel() -> PathBuf {
    first_in(&candidate_dirs(), &KERNEL_NAMES)
        .unwrap_or_else(|| PathBuf::from("temp/download/kernel"))
}

/// The guest's initramfs: the one this project builds (its tools, its modules and its agent).
pub fn initramfs() -> Option<PathBuf> {
    first_in(&candidate_dirs(), &INITRAMFS_NAMES)
}

/// The guest's userland image, when this build or package has one.
pub fn seed_image() -> Option<PathBuf> {
    first_in(&candidate_dirs(), &SEED_NAMES)
}

/// The guest's userland as a **tree** (the directory `make rootfs` fills), which a disk job copies
/// through a share when no ext4 image was built for it.
pub fn seed_tree() -> Option<PathBuf> {
    first_in(&candidate_dirs(), &SEED_TREE_NAMES)
}

/// Firecracker: `DESK_FIRECRACKER` (the one environment variable this application has, and it
/// carries a **path**, never a credential), then beside the executable, then the PATH's own name.
pub fn firecracker() -> PathBuf {
    if let Some(path) = std::env::var_os("DESK_FIRECRACKER") {
        if !path.is_empty() {
            return PathBuf::from(path);
        }
    }
    first_in(&candidate_dirs(), &FIRECRACKER_NAMES).unwrap_or_else(|| PathBuf::from("firecracker"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A package laid out the way `make dist` lays it out: `bin/` beside `kernel/` and `images/`.
    /// A binary in `bin/` finds its media **one level up**, which is the whole point of the layout.
    #[test]
    fn a_package_finds_its_media_beside_its_bin_folder() {
        let scratch = tempfile::tempdir().unwrap();
        let dir = scratch.path().join("package");
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        std::fs::create_dir_all(dir.join("kernel")).unwrap();
        std::fs::create_dir_all(dir.join("images")).unwrap();
        std::fs::write(dir.join("kernel/kernel"), b"k").unwrap();
        std::fs::write(dir.join("kernel/initramfs.gz"), b"i").unwrap();
        std::fs::write(dir.join("images/rootfs.ext4"), b"s").unwrap();
        std::fs::write(dir.join("bin/firecracker"), b"f").unwrap();

        // The candidate directories of a binary that lives in `bin/`.
        let dirs = [dir.join("bin"), dir.clone()];
        assert_eq!(
            first_in(&dirs, &KERNEL_NAMES).unwrap(),
            dir.join("kernel/kernel")
        );
        assert_eq!(
            first_in(&dirs, &INITRAMFS_NAMES).unwrap(),
            dir.join("kernel/initramfs.gz")
        );
        assert_eq!(
            first_in(&dirs, &SEED_NAMES).unwrap(),
            dir.join("images/rootfs.ext4"),
            "the seed image is what lets an installed package create a disk"
        );
        assert_eq!(
            first_in(&dirs, &FIRECRACKER_NAMES).unwrap(),
            dir.join("bin/firecracker"),
            "the hypervisor the package carries, not the host's own"
        );
    }

    /// A run from the repository finds the media the Makefile fills.
    #[test]
    fn a_run_from_the_tree_finds_the_media_the_makefile_fills() {
        let scratch = tempfile::tempdir().unwrap();
        let dir = scratch.path().join("tree");
        std::fs::create_dir_all(dir.join("temp/download")).unwrap();
        std::fs::write(dir.join("temp/download/kernel"), b"k").unwrap();
        std::fs::write(dir.join("temp/download/initramfs.gz"), b"i").unwrap();
        std::fs::write(dir.join("temp/download/firecracker"), b"f").unwrap();
        let dirs = [dir.clone()];
        assert_eq!(
            first_in(&dirs, &KERNEL_NAMES).unwrap(),
            dir.join("temp/download/kernel")
        );
        assert_eq!(
            first_in(&dirs, &INITRAMFS_NAMES).unwrap(),
            dir.join("temp/download/initramfs.gz")
        );
        assert_eq!(
            first_in(&dirs, &FIRECRACKER_NAMES).unwrap(),
            dir.join("temp/download/firecracker")
        );
    }

    /// Nothing there is a **named** absence, not a panic and not an empty path: a caller's error has
    /// to say what it looked for.
    #[test]
    fn a_media_that_is_not_there_is_named_and_not_invented() {
        let scratch = tempfile::tempdir().unwrap();
        let dir = scratch.path().join("nothing-here");
        std::fs::create_dir_all(&dir).unwrap();
        let dirs = [dir.clone()];
        assert!(first_in(&dirs, &KERNEL_NAMES).is_none());
        assert!(first_in(&dirs, &SEED_NAMES).is_none());
    }

    /// The candidate list is the package's layout **first**: an installed application must not be
    /// reached by a `temp/download` that happens to sit in the directory it was started from.
    #[test]
    fn the_package_layout_is_tried_before_the_trees_own() {
        assert_eq!(KERNEL_NAMES[0], "kernel/kernel");
        assert_eq!(INITRAMFS_NAMES[0], "kernel/initramfs.gz");
        assert_eq!(SEED_NAMES[0], "images/rootfs.ext4");
        assert_eq!(FIRECRACKER_NAMES[0], "firecracker");
    }
}
