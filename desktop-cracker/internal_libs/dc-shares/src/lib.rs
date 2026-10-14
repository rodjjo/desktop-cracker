//! Shared folders, host side and guest side (feature 4 and its
//! "Settings" section).
//!
//! The host side is a **service on the share's own port** (`dc-fc-share`) and a **plan**:
//! `-device virtio-9p-device,fsdev=…,mount_tag=…` pair per shared folder.  The
//! guest side is the plan of what to mount where, which is turned into the
//! mount script the guest init runs: this project wants the folders usable *inside*
//! the VM while it runs, and the tag is how the guest identifies them.
//!
//! Everything here is **serialised into one guest script** instead of being
//! executed by the guest's shell ad hoc, because the microvm's guest has no PCI
//! enumeration surprises worth handling twice: the device path of a
//! virtio-mmio 9P device depends on the order the devices were created in, so
//! the script probes (`/sys/bus/virtio/devices/*` for the one whose `mount_tag`
//! matches) rather than hard-coding `/dev/vda`.

use std::path::{Path, PathBuf};

use dc_common::{fs, TAG_CONTROL, TAG_DISK, TAG_XDISPLAY};
use dc_settings::{ShareMode, SharedFolder};

#[derive(Debug, thiserror::Error)]
pub enum ShareError {
    #[error("{0}")]
    Io(#[from] dc_common::Error),
    #[error("shared folder {path} does not exist")]
    Missing { path: PathBuf },
    #[error("shared folder {path} is not a directory")]
    NotADirectory { path: PathBuf },
    #[error("two devices would use the id {0}")]
    DuplicateId(String),
}

pub type Result<T> = std::result::Result<T, ShareError>;

/// One shared folder, as both ends see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    /// The `fsdev` id (and the device id), unique within one command line.
    pub id: String,
    /// The host directory.
    pub path: PathBuf,
    /// The mount tag the guest uses.
    pub tag: String,
    /// `rw` or `ro`.
    pub mode: ShareMode,
    /// Mount automatically in the guest.
    pub automount: bool,
    /// Whether the guest should mount this **before** the others (the root
    /// filesystem is the one exception: the guest's init switches to it).
    pub is_root: bool,
}

/// The whole set of 9P shares of one run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ShareSet {
    pub shares: Vec<Share>,
}

impl ShareSet {
    /// Build the share set for a run.
    ///
    /// * `root_disk_folder` — the folder that holds the guest's root **disk**
    ///   (`root-disk`). It is shared so the guest can mount other
    ///   volumes from it; the root filesystem itself is a block disk
    ///   (`dc-rootfs`), **not** a folder shared into the guest.
    /// * `disk_folder` — the folder where disks and volumes are kept, tag
    ///   `disk`.
    /// * `x_dir` — the host X11 socket directory, tag `xdisplay`, always
    ///   read-only (the guest attaches to the host's X server; it must never
    ///   be able to replace the host's sockets).
    /// * `control_dir` — the application's own directory for the guest's status
    ///   files: the memory numbers the balloon reads, the ready marker, the
    ///   power-off request, the display probe, the sound request and the test
    ///   pattern.  It holds nothing of the user's, so it cannot be how the guest
    ///   changes the host's state.  (Secrets — the disk's password, the host's X
    ///   cookie — do travel **into** the guest through it, and the guest removes
    ///   each one as soon as it has used it.)
    /// * `user` — the folders from the settings file.
    pub fn build(
        _root_folder: Option<&Path>,
        disk_folder: Option<&Path>,
        x_dir: Option<&Path>,
        control_dir: Option<&Path>,
        user: &[SharedFolder],
        read_write: bool,
    ) -> Result<ShareSet> {
        let mut set = ShareSet::default();

        let root_mode = if read_write {
            ShareMode::Rw
        } else {
            ShareMode::Ro
        };
        if let Some(disk) = disk_folder {
            set.push(Share {
                id: "fsdisk".into(),
                path: disk.to_path_buf(),
                tag: TAG_DISK.into(),
                mode: root_mode,
                automount: true,
                is_root: false,
            })?;
        }

        if let Some(x) = x_dir {
            set.push(Share {
                id: "fsx".into(),
                path: x.to_path_buf(),
                tag: TAG_XDISPLAY.into(),
                // The host's X sockets are never writable from the guest.
                mode: ShareMode::Ro,
                automount: true,
                is_root: false,
            })?;
        }

        if let Some(control) = control_dir {
            set.push(Share {
                id: "fscontrol".into(),
                path: control.to_path_buf(),
                tag: TAG_CONTROL.into(),
                // Always writable, in both modes: see the doc comment above.
                mode: ShareMode::Rw,
                automount: true,
                is_root: false,
            })?;
        }

        for (i, folder) in user.iter().enumerate() {
            set.push(Share {
                id: format!("fsshare{i}"),
                path: folder.path.clone(),
                tag: folder.tag.clone(),
                // The folder's own mode, as the user configured it (`rw` by
                // default): a share the user chose to share writable is writable.
                mode: if read_write {
                    folder.mode
                } else {
                    ShareMode::Ro
                },
                automount: folder.automount,
                is_root: false,
            })?;
        }

        Ok(set)
    }

    fn push(&mut self, share: Share) -> Result<()> {
        if self.shares.iter().any(|s| s.id == share.id) {
            return Err(ShareError::DuplicateId(share.id));
        }
        self.shares.push(share);
        Ok(())
    }

    pub fn get(&self, tag: &str) -> Option<&Share> {
        self.shares.iter().find(|s| s.tag == tag)
    }

    /// Check every host folder exists and is a directory **before** the machine is
    /// started, so the failure is a sentence rather than a hypervisor error later.
    pub fn check_host_paths(&self) -> Result<()> {
        for s in &self.shares {
            if !s.path.exists() {
                return Err(ShareError::Missing {
                    path: s.path.clone(),
                });
            }
            if !s.path.is_dir() {
                return Err(ShareError::NotADirectory {
                    path: s.path.clone(),
                });
            }
        }
        Ok(())
    }

    /// The **mount plan** the guest reads: one line per share,
    /// `<tag> <where> <ro|rw>`.
    ///
    /// The host writes it into the control share before the guest boots, and the
    /// guest applies it — so the host decides *what* is shared and *where* it
    /// lands, and the guest has nothing to guess.  The control share itself is
    /// not in the plan: the guest mounts it to be able to read this file.
    pub fn mount_plan(&self, guest_root: bool, guest_share_dir: &str) -> String {
        let _ = guest_root; // the root is a disk now, not a share
        let mut out = String::from("# desktop-cracker mount plan: <tag> <where> <ro|rw>\n");
        for share in &self.shares {
            if share.tag == TAG_CONTROL || !share.automount {
                continue;
            }
            let where_ = if share.tag == TAG_DISK {
                dc_common::GUEST_DISK_DIR.to_string()
            } else if share.tag == TAG_XDISPLAY {
                dc_common::GUEST_X_DIR.to_string()
            } else {
                format!("{guest_share_dir}/{}", share.tag)
            };
            out.push_str(&format!(
                "{} {} {}\n",
                share.tag,
                where_,
                share.mode.as_str()
            ));
        }
        out
    }

    /// Write the mount plan into the control directory the guest reads.
    pub fn write_mount_plan(
        &self,
        control_dir: &Path,
        guest_root: bool,
        guest_share_dir: &str,
    ) -> Result<PathBuf> {
        let path = control_dir.join("mounts");
        fs::write_atomic(
            &path,
            self.mount_plan(guest_root, guest_share_dir).as_bytes(),
        )?;
        Ok(path)
    }

    /// A description of the shares for the log, one line each.
    pub fn describe(&self) -> String {
        self.shares
            .iter()
            .map(|s| {
                format!(
                    "{} -> {} ({}@{})",
                    s.path.display(),
                    s.tag,
                    s.mode.as_str(),
                    if s.is_root { "root" } else { "guest" }
                )
            })
            .collect::<Vec<_>>()
            .join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scratch directory that **removes itself** when the test ends: the
    /// project's tests must not leave anything behind in /tmp.
    struct Tmp(std::path::PathBuf);

    impl Tmp {
        fn new(name: &str) -> Tmp {
            let d = std::env::temp_dir().join(format!(
                "dc-test-{}-{}-{}",
                std::process::id(),
                name,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            ));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).expect("creating a scratch directory");
            Tmp(d)
        }
    }

    impl Tmp {
        /// The scratch directory as a plain path, for a struct that wants one.
        /// The guard itself stays here, so the directory is still removed.
        fn path(&self) -> std::path::PathBuf {
            self.0.clone()
        }
    }

    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    impl std::ops::Deref for Tmp {
        type Target = std::path::Path;
        fn deref(&self) -> &std::path::Path {
            &self.0
        }
    }

    fn tmpdir(name: &str) -> Tmp {
        Tmp::new(name)
    }

    #[test]
    fn default_mode_makes_everything_read_only() {
        let d = tmpdir("ro");
        let user = vec![SharedFolder {
            path: d.path(),
            mode: ShareMode::Rw,
            tag: "share-proj".into(),
            automount: true,
        }];
        let set = ShareSet::build(None, Some(&d), Some(&d), None, &user, false).unwrap();
        for s in &set.shares {
            // the control share is the one exception (the guest's own status)
            if s.tag != dc_common::TAG_CONTROL {
                assert!(s.mode.is_read_only(), "{} should be read-only", s.tag);
            }
        }
        set.check_host_paths().unwrap();
    }

    #[test]
    fn admin_mode_honours_the_configured_mode() {
        let d = tmpdir("rw");
        let user = vec![SharedFolder {
            path: d.path(),
            mode: ShareMode::Rw,
            tag: "share-proj".into(),
            automount: true,
        }];
        let control = tmpdir("rw-control");
        let set = ShareSet::build(None, Some(&d), None, Some(&control), &user, true).unwrap();
        assert!(!set.get(TAG_DISK).unwrap().mode.is_read_only());
        assert!(!set.get("share-proj").unwrap().mode.is_read_only());
    }

    #[test]
    fn x_display_share_is_never_writable() {
        let d = tmpdir("xro");
        let set = ShareSet::build(None, None, Some(&d), None, &[], true).unwrap();
        assert!(set.get(TAG_XDISPLAY).unwrap().mode.is_read_only());
    }

    #[test]
    fn the_control_share_is_writable_even_when_the_caller_asks_for_read_only() {
        let d = tmpdir("control");
        let control = d.join("control");
        std::fs::create_dir_all(&control).unwrap();
        let set = ShareSet::build(None, None, None, Some(&control), &[], false).unwrap();
        assert!(!set.get(TAG_CONTROL).unwrap().mode.is_read_only());
        // and the guest mounts it where the guest's own tools expect it.  It is **not** in the
        // plan (the guest mounts it in order to read the plan), which is the other half of the
        // rule: the application's own directory is never one of the user's folders.
        let plan = set.mount_plan(false, dc_common::GUEST_SHARE_DIR);
        assert!(!plan.contains("control"), "{plan}");
    }

    #[test]
    fn the_mount_plan_lists_what_the_guest_should_mount() {
        let d = tmpdir("plan");
        let user = vec![
            SharedFolder {
                path: d.path(),
                mode: ShareMode::Ro,
                tag: "share-work".into(),
                automount: true,
            },
            SharedFolder {
                path: d.path(),
                mode: ShareMode::Rw,
                tag: "share-off".into(),
                automount: false,
            },
        ];
        let set = ShareSet::build(None, Some(&d), None, Some(&d), &user, false).unwrap();
        let plan = set.mount_plan(true, dc_common::GUEST_SHARE_DIR);
        assert!(plan.starts_with('#'), "{plan}");
        // the guest's root is a disk now, not a share: the plan lists what it
        // mounts *inside* the guest's filesystem
        assert!(plan.contains("disk /mnt/disk ro"), "{plan}");
        assert!(
            plan.contains("share-work /mnt/share/share-work ro"),
            "{plan}"
        );
        // automount=false is simply absent, and the control share is not listed
        // (the guest mounts it in order to read this file).
        assert!(!plan.contains("share-off"), "{plan}");
        assert!(!plan.contains("control"), "{plan}");

        let path = set
            .write_mount_plan(&d, true, dc_common::GUEST_SHARE_DIR)
            .unwrap();
        assert_eq!(fs::read_to_string(&path).unwrap(), plan);
    }

    #[test]
    fn a_missing_folder_is_refused_before_the_run_starts() {
        let d = tmpdir("missing");
        let gone = d.join("gone");
        let set = ShareSet::build(None, Some(&gone), None, None, &[], false).unwrap();
        match set.check_host_paths() {
            Err(ShareError::Missing { path }) => assert_eq!(path, gone),
            other => panic!("expected Missing, got {other:?}"),
        }
    }

    #[test]
    fn duplicate_ids_are_refused() {
        let d = tmpdir("dup");
        let mut set = ShareSet::default();
        let s = Share {
            id: "same".into(),
            path: d.path(),
            tag: "a".into(),
            mode: ShareMode::Rw,
            automount: true,
            is_root: false,
        };
        set.push(s.clone()).unwrap();
        assert!(matches!(set.push(s), Err(ShareError::DuplicateId(_))));
    }
}
