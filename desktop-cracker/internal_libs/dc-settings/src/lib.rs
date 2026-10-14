//! The settings file: `~/.desktop-cracker/config.yml`.
//!
//! The design ("Settings") says the file stores three things:
//!
//! * **shared folders** — a list of shared folders (9P share), their access
//!   mode (RW/RO) and their tags, so they can be identified inside the VM
//!   during the mounting;
//! * **root-folder** — the folder where the microvm root filesystem is stored;
//! * **Unlock password** — the salted secure hash of the password used to show
//!   the window again.
//!
//! The password is stored as `pbkdf2-sha256$<rounds>$<salt-b64>$<hash-b64>`,
//! which is why `verify` is a constant-time comparison.  The plaintext is never
//! written anywhere.

mod unlock;

pub use unlock::Unlock;

use std::path::{Path, PathBuf};

use dc_common::fs;
use serde::{Deserialize, Serialize};

/// Password hashing parameters.  210 000 rounds of PBKDF2-HMAC-SHA256 is what
/// the OWASP cheat sheet asks for at the time of writing; the hash is only ever
/// verified once per launch, so the cost is paid at most honestly.
pub const PBKDF2_ROUNDS: u32 = 210_000;
pub const SALT_LEN: usize = 16;
pub const KEY_LEN: usize = 32;

/// Access mode of a shared folder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ShareMode {
    /// Read-write: the guest may modify the host folder.
    Rw,
    /// Read-only: the guest sees the folder but cannot change it.
    Ro,
}

impl Default for ShareMode {
    #[allow(clippy::derivable_impls)] // the explicit "Rw is the default" is the point
    fn default() -> Self {
        ShareMode::Rw
    }
}

impl ShareMode {
    /// The `security_model` a network filesystem would need, kept beside the mode: the plan's own
    /// field.
    pub fn is_read_only(self) -> bool {
        matches!(self, ShareMode::Ro)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ShareMode::Rw => "rw",
            ShareMode::Ro => "ro",
        }
    }
}

/// One shared folder, as stored in the settings file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedFolder {
    /// The folder on the host.
    pub path: PathBuf,
    /// `rw` or `ro`.
    #[serde(default)]
    pub mode: ShareMode,
    /// The 9P mount tag the guest uses: `mount -t 9p <tag> /mnt/share/...`.
    pub tag: String,
    /// Mount the share automatically inside the guest (default `true`).
    #[serde(default = "default_true")]
    pub automount: bool,
}

impl SharedFolder {
    /// A share with the tag derived from the folder name, e.g. `/srv/data` ->
    /// `share-data`.  Tags must be unique, which `Settings::validate` checks.
    pub fn new(path: impl Into<PathBuf>, mode: ShareMode) -> Self {
        let path = path.into();
        let base = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "share".into());
        let tag = sanitize_tag(&base);
        SharedFolder {
            path,
            mode,
            tag,
            automount: true,
        }
    }
}

/// 9P tags travel through a `mount` command line, so keep them boring.
pub fn sanitize_tag(name: &str) -> String {
    let mut out = String::with_capacity(name.len() + 6);
    out.push_str("share-");
    for c in name.chars() {
        if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    if out.len() > 60 {
        out.truncate(60);
    }
    out
}

/// **One additional disk** (Settings: *additional disk — a list of disks and
/// their access mode (RW/RO), the user mounts them himself*).
///
/// The application's whole job with one of these is to **attach it**: it becomes a block
/// device of its own inside the guest (`/dev/vdb`, `/dev/vdc`, …) and stops there.  Nothing
/// is mounted for the user, no password is asked for it, and the application does not care
/// whether it is encrypted — the guest's own tooling (`desk-disk-mount`) is what opens a
/// LUKS container with a password the user types inside the guest, or mounts a plain
/// filesystem directly.
///
/// `tag` is the disk's **name on the host**, and it is what makes an attached device
/// identifiable: it is written into the guest's control share as a line of its own
/// (`disk vdb data ro`), so the user — and the guest's tool — know which `/dev/vdX` is which
/// without counting devices.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdditionalDisk {
    /// The image on the host: a raw file or a real block device.
    pub path: PathBuf,
    /// `rw` or `ro` — how it is attached.  A read-only disk is `read-only=on` on both block
    /// nodes, so a guest cannot write to it even as root.
    #[serde(default)]
    pub mode: ShareMode,
    /// The disk's name, e.g. `data`.  Unique among the additional disks, and it is what the
    /// guest is told (the control share's `disks` line) and what the tool takes.
    pub tag: String,
}

fn default_true() -> bool {
    true
}

impl AdditionalDisk {
    /// A disk named after its image's file name (`/srv/vm/data.raw` -> `data`).
    pub fn new(path: impl Into<PathBuf>, mode: ShareMode) -> Self {
        let path = path.into();
        let base = path
            .file_stem()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "disk".into());
        AdditionalDisk {
            path,
            mode,
            tag: sanitize_disk_tag(&base),
        }
    }
}

/// A disk's name travels into the control share's `disks` line and into the guest's tool, so
/// keep it to a word: letters, digits, `-`, `_`, `.`.
pub fn sanitize_disk_tag(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        if c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.' {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        out.push_str("disk");
    }
    if out.len() > 40 {
        out.truncate(40);
    }
    out
}

/// The whole settings file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    /// The list of shared folders (9P shares).
    pub shared_folders: Vec<SharedFolder>,
    /// The **additional disks**: each one is attached to the microVM as
    /// a block device of its own, and the user mounts it inside the guest — the application
    /// never mounts one, never asks for its password and does not care whether it is
    /// encrypted.
    #[serde(default)]
    pub disks: Vec<AdditionalDisk>,
    /// The guest's **root disk**: an encrypted raw image holding the microvm's root filesystem.
    /// This project calls it `root-disk`, and it is the guest's own disk (not a folder shared into
    /// it), so applications installed inside the VM live in it and only the user's password opens
    /// it.
    pub root_disk: PathBuf,
    /// Where disks and volumes are kept.
    pub disk_folder: PathBuf,
    /// `pbkdf2-sha256$rounds$salt$hash`, or `None` when no password is set
    /// (the window then opens without asking).
    pub unlock_password: Option<String>,

    // ---- knobs that are not in the project's rules, but keep it usable ----
    /// Guest RAM in MiB.
    pub memory_mb: u32,
    /// Number of vCPUs.
    pub vcpus: u32,
    /// Initial console geometry.
    pub display_width: u32,
    pub display_height: u32,
    /// Encrypt the root disk with LUKS (a raw image, feature 6).
    /// Set the virtio-balloon target automatically from what the guest uses.
    pub balloon_automatic: bool,
    /// Forward the **host's** X server into the guest (feature 6: "the x server
    /// from the host inside the VM as an additional x server for the applications
    /// running there").
    ///
    /// Off by default: it is a capability for the applications the guest will
    /// run, not something the desktop itself needs, and it means the host's X
    /// cookie travels into the microVM.  Turn it on when a guest application is
    /// meant to open a window on the host's desktop.
    pub remote_x: bool,
    /// **`--host-network`**: the guest may reach the machine
    /// this process runs on, through the name `parenthost` and the gateway address it answers with.
    ///
    /// Off by default, and it stays off unless the file says otherwise: the rule a run has always
    /// had is that the host's own network is not the guest's to reach, and this key is the user's
    /// decision to make the exception permanent instead of typing the switch every run.
    pub host_network: bool,
    /// **`ssh_port`**: the host port carried to the guest's **sshd** (port 22 inside), or `None` for
    /// "nothing is forwarded" — this project's own rule, which `0` and an empty field both mean.
    ///
    /// It is a setting for the same reason `host_network` is: a person who wants `ssh` into the
    /// guest wants it every run, not only on the runs they remembered the switch for.  The switch
    /// wins when it is given, and nothing is opened when neither says so.
    ///
    /// **`None` is the one way this file says "off"** (never a key with `0`): a port this process may
    /// not bind — `22` is the usual one — is refused rather than stored, so the number here is always
    /// one a run can use (see [`SSH_PORT_RANGE`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_port: Option<u16>,
}

/// The ports a **forward** may name: the host's own service ports are below them (`ssh` is 22, and
/// binding one needs a privilege this process does not take), and everything above `1024` is a port
/// a user's own programs use.  `0` is not in the list because `0` is how a *switch* says "off" and
/// the file says "off" by having no port at all.
pub const SSH_PORT_RANGE: std::ops::RangeInclusive<u16> = 1024..=65535;

impl Default for Settings {
    fn default() -> Self {
        // **The package's own folder**: the settings a fresh installation starts
        // with name the root disk and the disk folder of the package this binary is in — never a
        // hidden directory in the user's home, which a second package would share.
        let package = dc_common::package_dir().unwrap_or_default();
        Settings {
            shared_folders: Vec::new(),
            disks: Vec::new(),
            root_disk: dc_common::media::root_disk_for(&package),
            disk_folder: dc_common::media::disk_folder_for(&package),
            unlock_password: None,
            memory_mb: dc_common::DEFAULT_MEMORY_MB,
            // The host's own CPUs (hyper-threads included).  A microvm is meant
            // to use the machine it is on, and this is the number the settings
            // window shows; the value is checked against 1..=64 below.
            vcpus: dc_common::default_vcpus(),
            display_width: 1280,
            display_height: 800,
            balloon_automatic: true,
            remote_x: false,
            host_network: false,
            ssh_port: None,
        }
    }
}

/// Why the settings could not be used.
/// Bring a settings file written by an earlier version up to date, in place.
///
/// The two changes so far: the guest's root is a **disk** (the old
/// `root_folder` named a folder, and the disk was the file inside it), and a disk is always
/// encrypted (so `encrypt_disk` is dropped). Unknown keys are left alone — the strict
/// deserializer then refuses them, which is how a typo in a hand-edited file is
/// still reported instead of being silently ignored.
fn migrate(value: &mut serde_yaml::Value) {
    let Some(map) = value.as_mapping_mut() else {
        return;
    };
    // A file an earlier version wrote, or a hand-edited one, that says `ssh_port: 0`: **`0` is how
    // the switch says "off"**, so the file says "off" by having no port at all.  Dropping the key is
    // the same answer, and it is the only one the file has.
    if map.get("ssh_port").and_then(|v| v.as_u64()) == Some(0) {
        map.remove("ssh_port");
    }
    if !map.contains_key("root_disk") {
        if let Some(folder) = map.get("root_folder").and_then(|v| v.as_str()) {
            let disk = std::path::Path::new(folder).join("root.raw");
            map.insert(
                serde_yaml::Value::from("root_disk"),
                serde_yaml::Value::from(disk.to_string_lossy().to_string()),
            );
        }
    }
    map.remove("root_folder");
    map.remove("encrypt_disk");
}

#[derive(Debug, thiserror::Error)]
pub enum SettingsError {
    #[error("{0}")]
    Io(#[from] dc_common::Error),
    #[error("invalid YAML in {path}: {source}")]
    Yaml {
        path: PathBuf,
        #[source]
        source: serde_yaml::Error,
    },
    #[error("{0}")]
    Invalid(String),
}

pub type Result<T> = std::result::Result<T, SettingsError>;

/// **The settings file of this package**: `<package>/config.yml`, the folder the application was
/// extracted into.
///
/// There is **no fallback path**: a run inside the tree reads the tree's own `config.yml` and an
/// installed package reads the package's, so two packages never share settings and nothing the user
/// has installed elsewhere is read behind their back.  `--config` still names a file of its own,
/// which is what a development tree's `make run` and the system tests use.
pub fn config_path() -> PathBuf {
    dc_common::media::settings_path_for(&dc_common::package_dir().unwrap_or_default())
}

impl Settings {
    /// Load this package's `config.yml`, creating it with defaults the first time the application
    /// runs.
    pub fn load_or_create() -> Result<Settings> {
        Settings::load_from(&config_path(), true)
    }

    /// Load a settings file.  With `create` a missing (or empty) file is
    /// written back with the defaults, so the user has something to edit.
    pub fn load_from(path: &Path, create: bool) -> Result<Settings> {
        let settings = if path.exists() {
            let text = fs::read_to_string(path)?;
            if text.trim().is_empty() {
                Settings::default()
            } else {
                let mut value: serde_yaml::Value =
                    serde_yaml::from_str(&text).map_err(|source| SettingsError::Yaml {
                        path: path.to_path_buf(),
                        source,
                    })?;
                // A file written by an earlier version: the root filesystem
                // became a **disk** (`root-folder` -> `root-disk`) and the disk
                // became always encrypted.  The old names are understood and the
                // file is rewritten on the next save, so an upgrade does not
                // leave the user with an application that will not start.
                migrate(&mut value);
                serde_yaml::from_value(value).map_err(|source| SettingsError::Yaml {
                    path: path.to_path_buf(),
                    source,
                })?
            }
        } else {
            Settings::default()
        };
        let settings = settings.with_host_cpus();
        settings.validate()?;
        if create && !path.exists() {
            settings.save_to(path)?;
        }
        Ok(settings)
    }

    pub fn save(&self) -> Result<()> {
        self.save_to(&config_path())
    }

    pub fn save_to(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let text = serde_yaml::to_string(self).map_err(|source| SettingsError::Yaml {
            path: path.to_path_buf(),
            source,
        })?;
        let header = format!(
            "# {name} settings —\n\
             # Shared folders are 9P shares; the tag is what the guest mounts.\n\
             # disks: each one is attached to the microVM as a block device of its own\n\
             # (the guest's `desk-disk-mount` lists and mounts them; nothing is mounted\n\
             # automatically).\n\
             # unlock_password is a salted hash: set it with `{name} --set-password`.\n",
            name = dc_common::APP_NAME
        );
        fs::write_atomic(path, format!("{header}{text}"))?;
        Ok(())
    }

    /// Reject the things that would make the VM fail to start, with a sentence
    /// the user can act on.
    /// What a file that says nothing about the CPU count means: **the machine this is
    /// running on**, capped (see `dc_common::default_vcpus`: the operator found that giving
    /// a guest every core of a 24-core host makes the boot slower, not faster).
    ///
    /// The operator runs a 24-core/48-thread host and wants the microvm to have those cores
    /// ("I have 24 cpu with 2 thread each, make run should run microvm with 24 cpu cores to
    /// performance").  A settings file has a number in it, written when it was first made, so
    /// the honest reading of a **missing** or **zero** `vcpus` is the host's own default —
    /// `dc_common::default_vcpus()` — rather than a number that was true on the day the file
    /// was written.
    pub fn with_host_cpus(mut self) -> Settings {
        if self.vcpus == 0 {
            self.vcpus = dc_common::default_vcpus();
        }
        self
    }

    pub fn validate(&self) -> Result<()> {
        if self.memory_mb < 128 {
            return Err(SettingsError::Invalid(format!(
                "memory_mb must be at least 128 (the guest kernel does not boot below that), got {}",
                self.memory_mb
            )));
        }
        if self.vcpus < 1 || self.vcpus > 64 {
            return Err(SettingsError::Invalid(format!(
                "vcpus must be between 1 and 64, got {}",
                self.vcpus
            )));
        }
        let mut tags = std::collections::HashSet::new();
        for s in &self.shared_folders {
            if s.tag.is_empty() {
                return Err(SettingsError::Invalid(format!(
                    "shared folder {} has an empty tag",
                    s.path.display()
                )));
            }
            if s.tag == dc_common::TAG_ROOTFS
                || s.tag == dc_common::TAG_DISK
                || s.tag == dc_common::TAG_XDISPLAY
            {
                return Err(SettingsError::Invalid(format!(
                    "shared folder {} uses the reserved tag {:?}",
                    s.path.display(),
                    s.tag
                )));
            }
            if !tags.insert(s.tag.clone()) {
                return Err(SettingsError::Invalid(format!(
                    "two shared folders use the tag {:?}; tags must be unique",
                    s.tag
                )));
            }
            if !s.path.is_absolute() {
                return Err(SettingsError::Invalid(format!(
                    "shared folder {} is not an absolute path",
                    s.path.display()
                )));
            }
        }
        if let Some(hash) = &self.unlock_password {
            if !hash.is_empty() && !hash.starts_with("pbkdf2-sha256$") {
                return Err(SettingsError::Invalid(
                    "unlock_password is not a pbkdf2-sha256 hash".into(),
                ));
            }
        }
        // **The ssh forward's port**: a port this process may
        // bind, or nothing.  A port below 1024 is refused rather than stored — binding one needs a
        // privilege this application does not take, and `22` is a port a host usually has its own
        // service on — and the file has one way to say "off": no key at all.
        if let Some(port) = self.ssh_port {
            if !SSH_PORT_RANGE.contains(&port) {
                return Err(SettingsError::Invalid(format!(
                    "ssh_port is {port}; it must be between {} and {} (or absent, which means \
                     nothing is forwarded)",
                    SSH_PORT_RANGE.start(),
                    SSH_PORT_RANGE.end()
                )));
            }
        }
        // The additional disks: a name the guest can be told, an absolute path, a name that is
        // not one of the shares', and no two of them the same.  What is **not** checked is
        // anything about the image's content: whether it is a container or a plain filesystem
        // is the user's business.
        let mut disk_tags = std::collections::HashSet::new();
        for disk in &self.disks {
            if disk.tag.is_empty() {
                return Err(SettingsError::Invalid(format!(
                    "additional disk {} has an empty name",
                    disk.path.display()
                )));
            }
            if disk.tag != sanitize_disk_tag(&disk.tag) {
                return Err(SettingsError::Invalid(format!(
                    "additional disk {:?} has a name with characters the guest cannot be told \
                     (use letters, digits, '-', '_' or '.')",
                    disk.tag
                )));
            }
            if !disk.path.is_absolute() {
                return Err(SettingsError::Invalid(format!(
                    "additional disk {} is not an absolute path",
                    disk.path.display()
                )));
            }
            if !disk_tags.insert(disk.tag.clone()) {
                return Err(SettingsError::Invalid(format!(
                    "two additional disks are called {:?}; the name is how the guest tells them \
                     apart, so it must be unique",
                    disk.tag
                )));
            }
        }
        Ok(())
    }

    /// The shares the guest is told about, tag order preserved.
    pub fn shares_to_mount(&self) -> impl Iterator<Item = &SharedFolder> {
        self.shared_folders.iter()
    }

    /// The additional disks that should be attached to the microVM, in the order the settings
    /// list them — which is the order the run attaches them, so the first one is the guest's
    /// first disk after its root (`/dev/vdb`).
    pub fn disks_to_attach(&self) -> impl Iterator<Item = &AdditionalDisk> {
        self.disks.iter()
    }

    /// Does this configuration ask for a password before the window is shown?
    pub fn has_password(&self) -> bool {
        self.unlock_password.as_ref().is_some_and(|h| !h.is_empty())
    }

    /// Set (or clear, with `None`) the unlock password from plaintext.
    pub fn set_password(&mut self, plaintext: Option<&str>) -> Result<()> {
        self.unlock_password = match plaintext {
            None => None,
            Some("") => None,
            Some(p) => Some(hash_password(p)?),
        };
        Ok(())
    }

    /// Check a password against the stored hash.  Returns `false` when no
    /// password is configured — callers decide what that means.
    pub fn verify_password(&self, plaintext: &str) -> bool {
        match &self.unlock_password {
            Some(h) if !h.is_empty() => verify_password(h, plaintext),
            _ => false,
        }
    }
}

/// Hash a password: `pbkdf2-sha256$<rounds>$<salt>$<hash>`, both blobs base64.
pub fn hash_password(plaintext: &str) -> Result<String> {
    use rand::RngCore;
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    let mut key = [0u8; KEY_LEN];
    pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(
        plaintext.as_bytes(),
        &salt,
        PBKDF2_ROUNDS,
        &mut key,
    )
    .map_err(|e| SettingsError::Invalid(format!("pbkdf2 failed: {e}")))?;
    Ok(format!(
        "pbkdf2-sha256${}${}${}",
        PBKDF2_ROUNDS,
        base64_encode(&salt),
        base64_encode(&key)
    ))
}

/// Verify a password against a stored hash string.
pub fn verify_password(stored: &str, plaintext: &str) -> bool {
    let parts: Vec<&str> = stored.split('$').collect();
    if parts.len() != 4 || parts[0] != "pbkdf2-sha256" {
        return false;
    }
    let rounds: u32 = match parts[1].parse() {
        Ok(r) if r > 0 => r,
        _ => return false,
    };
    let (salt, want) = match (base64_decode(parts[2]), base64_decode(parts[3])) {
        (Some(s), Some(h)) => (s, h),
        _ => return false,
    };
    let mut got = vec![0u8; want.len()];
    if pbkdf2::pbkdf2::<hmac::Hmac<sha2::Sha256>>(plaintext.as_bytes(), &salt, rounds, &mut got)
        .is_err()
    {
        return false;
    }
    constant_time_eq(&got, &want)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn base64_encode(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | b[2] as u32;
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn base64_decode(text: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let mut acc: u32 = 0;
    let mut bits = 0;
    for c in text.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            b'\n' | b'\r' => continue,
            _ => return None,
        } as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
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

    impl Clone for Tmp {
        fn clone(&self) -> Self {
            Tmp(self.0.clone())
        }
    }

    impl Tmp {
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

    fn tmp(name: &str) -> Tmp {
        Tmp::new(name)
    }

    #[test]
    fn password_roundtrip() {
        let h = hash_password("correct horse battery staple").unwrap();
        assert!(h.starts_with("pbkdf2-sha256$210000$"));
        assert!(verify_password(&h, "correct horse battery staple"));
        assert!(!verify_password(&h, "Correct horse battery staple"));
        assert!(!verify_password(&h, ""));
        // the salt must be random: two hashes of the same password differ
        let h2 = hash_password("correct horse battery staple").unwrap();
        assert_ne!(h, h2);
        assert!(verify_password(&h2, "correct horse battery staple"));
    }

    #[test]
    fn base64_roundtrip() {
        for case in [
            &b""[..],
            &b"a"[..],
            &b"ab"[..],
            &b"abc"[..],
            &b"abcd"[..],
            &[0u8, 255, 128][..],
        ] {
            let e = base64_encode(case);
            assert_eq!(base64_decode(&e).unwrap(), case, "encoded as {e}");
        }
    }

    #[test]
    fn saved_file_roundtrips() {
        let d = tmp("roundtrip");
        let path = d.join("config.yml");
        let mut s = Settings {
            root_disk: d.path().join("root.raw"),
            ..Settings::default()
        };
        s.shared_folders
            .push(SharedFolder::new(d.join("proj"), ShareMode::Ro));
        s.set_password(Some("hunter2")).unwrap();
        s.save_to(&path).unwrap();

        let back = Settings::load_from(&path, false).unwrap();
        assert_eq!(back, s);
        assert!(back.verify_password("hunter2"));
        assert!(back.has_password());
    }

    #[test]
    fn reject_duplicate_tags() {
        let d = tmp("duptags");
        let mut s = Settings::default();
        let mut a = SharedFolder::new(d.join("a"), ShareMode::Rw);
        let mut b = SharedFolder::new(d.join("b"), ShareMode::Rw);
        a.tag = "same".into();
        b.tag = "same".into();
        s.shared_folders = vec![a, b];
        assert!(matches!(s.validate(), Err(SettingsError::Invalid(_))));
    }

    #[test]
    fn a_settings_file_from_an_earlier_version_is_migrated() {
        // Written before the root became a disk: `root_folder` (the folder the
        // old layout kept its disk in) and `encrypt_disk` (a choice that no
        // longer exists, because a disk is always encrypted).
        let dir = tmp("migrate");
        let path = dir.path().join("config.yml");
        std::fs::write(
            &path,
            "shared_folders: []\n\
             root_folder: /srv/desktop-cracker/root\n\
             disk_folder: /srv/desktop-cracker/disks\n\
             unlock_password: null\n\
             memory_mb: 2048\n\
             vcpus: 4\n\
             encrypt_disk: false\n\
             balloon_automatic: true\n\
             remote_x: true\n",
        )
        .unwrap();
        let s = Settings::load_from(&path, false).unwrap();
        assert_eq!(
            s.root_disk,
            PathBuf::from("/srv/desktop-cracker/root/root.raw"),
            "the old folder's disk is where the old layout kept it"
        );
        assert_eq!(s.memory_mb, 2048, "the rest of the file is kept");
        assert_eq!(s.vcpus, 4);
    }

    /// The host's own services: the settings carry the decision, and a file that says
    /// nothing about it says **off** — the rule a run has always had.
    /// **The ssh forward's port is a setting, and it has one way to say "off"**: the key absent.  `0`
    /// and nothing are the same answer (the switch's `0` is migrated away), a port below `1024` is
    /// refused — this process may not bind one and `22` is a host's own — and a port a user's own
    /// programs use is kept and round-trips.
    #[test]
    fn the_ssh_port_is_off_by_absence_and_never_a_privileged_one() {
        let dir = Tmp::new("ssh-port");
        let path = dir.path().join("config.yml");
        assert_eq!(Settings::default().ssh_port, None);

        // Off: the key absent, and `0` (which an older file, or a hand-edited one, may carry) — the
        // two are the same answer, and saving turns the second into the first.
        std::fs::write(&path, "shared_folders: []\nssh_port: 0\n").unwrap();
        let s = Settings::load_from(&path, true).unwrap();
        assert_eq!(s.ssh_port, None, "0 is off");
        s.save_to(&path).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(
            !text.contains("ssh_port"),
            "the file says it one way: {text}"
        );

        // On: a port above the privileged range, which is what the window and the switch store.
        let on = Settings {
            ssh_port: Some(2223),
            ..Settings::default()
        };
        on.save_to(&path).unwrap();
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("ssh_port: 2223"), "{text}");
        assert_eq!(
            Settings::load_from(&path, false).unwrap().ssh_port,
            Some(2223)
        );

        // Refused: a privileged port is not stored, and neither is nonsense.
        for port in [22, 80, 1023] {
            let bad = Settings {
                ssh_port: Some(port),
                ..Settings::default()
            };
            assert!(
                bad.save_to(&path).is_err(),
                "ssh_port {port} is a privileged port and was accepted"
            );
        }
        assert_eq!(
            Settings::load_from(&path, false).unwrap().ssh_port,
            Some(2223),
            "and the refused save left the file alone"
        );
    }

    #[test]
    fn the_host_network_key_is_off_unless_the_file_says_otherwise() {
        assert!(!Settings::default().host_network);
        let dir = tmp("hostnet");
        let path = dir.path().join("config.yml");
        let s = Settings {
            host_network: true,
            ..Settings::default()
        };
        s.save_to(&path).unwrap();
        assert!(Settings::load_from(&path, false).unwrap().host_network);

        // A file written before this key existed is still a file this reads.
        std::fs::write(
            &path,
            "shared_folders: []\n\
             root_disk: /srv/desktop-cracker/root.raw\n\
             disk_folder: /srv/desktop-cracker/disks\n\
             unlock_password: null\n\
             memory_mb: 2048\n\
             vcpus: 4\n\
             balloon_automatic: true\n\
             remote_x: false\n",
        )
        .unwrap();
        assert!(
            !Settings::load_from(&path, false).unwrap().host_network,
            "a settings file from before the switch does not turn it on"
        );
    }

    #[test]
    fn reject_reserved_tag_and_bad_memory() {
        let d = tmp("reserved");
        let mut s = Settings::default();
        let mut a = SharedFolder::new(d.join("a"), ShareMode::Rw);
        a.tag = dc_common::TAG_ROOTFS.into();
        s.shared_folders = vec![a];
        assert!(s.validate().is_err());

        let s = Settings {
            memory_mb: 64,
            ..Settings::default()
        };
        assert!(s.validate().is_err());
    }

    #[test]
    fn missing_file_gets_created_with_defaults() {
        let d = tmp("created");
        let path = d.join("sub/config.yml");
        let s = Settings::load_from(&path, true).unwrap();
        assert_eq!(s, Settings::default());
        assert!(path.exists());
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("shared_folders"), "{text}");
    }

    #[test]
    fn unknown_key_is_an_error_the_user_can_see() {
        let d = tmp("unknown");
        let path = d.join("config.yml");
        std::fs::write(&path, "root_folder: /tmp\nnonexistent_knob: 1\n").unwrap();
        match Settings::load_from(&path, false) {
            Err(SettingsError::Yaml { .. }) => {}
            other => panic!("expected a YAML error, got {other:?}"),
        }
    }

    #[test]
    fn tag_sanitising() {
        assert_eq!(sanitize_tag("my proj"), "share-my_proj");
        assert_eq!(sanitize_tag("a/b"), "share-a_b");
        assert_eq!(sanitize_disk_tag("my data!/v2"), "my_data__v2");
        assert_eq!(sanitize_disk_tag(""), "disk");
    }

    /// **An additional disk**: a path, an access mode and a name, and
    /// nothing about its contents — the application attaches it and the user mounts it.
    #[test]
    fn an_additional_disk_is_a_path_a_mode_and_a_name() {
        let d = tmp("disks");
        let path = d.join("data.raw");
        let disk = AdditionalDisk::new(&path, ShareMode::Rw);
        assert_eq!(disk.tag, "data", "named after the image");
        assert_eq!(disk.path, path);
        assert!(!disk.mode.is_read_only());

        let mut s = Settings {
            disks: vec![disk.clone()],
            ..Settings::default()
        };
        s.validate().unwrap();

        // The **name** is how the guest tells the disks apart, so two of them cannot share it.
        let mut twice = s.clone();
        twice.disks.push(AdditionalDisk {
            path: d.join("other.raw"),
            mode: ShareMode::Ro,
            tag: disk.tag.clone(),
        });
        assert!(matches!(twice.validate(), Err(SettingsError::Invalid(_))));

        // A name with characters the guest cannot be told, and a relative path, are refused
        // with a sentence rather than a device the guest cannot identify.
        let mut bad = disk.clone();
        bad.tag = "not a name".into();
        s.disks = vec![bad];
        assert!(matches!(s.validate(), Err(SettingsError::Invalid(_))));
        let mut relative = disk;
        relative.path = PathBuf::from("data.raw");
        s.disks = vec![relative];
        assert!(matches!(s.validate(), Err(SettingsError::Invalid(_))));
    }

    /// The disks survive the settings file, which is what the window writes and the run reads.
    #[test]
    fn additional_disks_roundtrip_through_the_file() {
        let d = tmp("disks-roundtrip");
        let path = d.join("config.yml");
        let mut s = Settings {
            root_disk: d.path().join("root.raw"),
            ..Settings::default()
        };
        s.disks
            .push(AdditionalDisk::new(d.join("data.raw"), ShareMode::Rw));
        s.disks.push(AdditionalDisk {
            path: d.join("backup.img"),
            mode: ShareMode::Ro,
            tag: "backup".into(),
        });
        s.save_to(&path).unwrap();
        let back = Settings::load_from(&path, false).unwrap();
        assert_eq!(back.disks, s.disks);
        assert_eq!(back.disks_to_attach().count(), 2);
    }
}
