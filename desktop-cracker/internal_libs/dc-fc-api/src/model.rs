//! **The API's shapes**: exactly the fields Firecracker's REST API takes, and no
//! others.
//!
//! The API is `deny_unknown_fields` — a field it does not know is a `400` with a
//! sentence, not something quietly ignored — so a struct here that carries an
//! extra field is a machine that does not start.  The two that cost time when
//! they were guessed wrong are written down where they live: a drive has **no
//! `serial`** (a conventional virtio-blk has one, Firecracker's does not), and the
//! instance's own report is at **`/`**, not at `/instance-info`.
//!
//! Every one of these is read off `src/firecracker/swagger/firecracker.yaml` in
//! the Firecracker tree, and the optional ones are optional in the same places.

use serde::{Deserialize, Serialize};

/// `PUT /boot-source`: what the machine boots.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BootSource {
    /// The guest kernel: an uncompressed ELF `vmlinux`, or a `bzImage` (both
    /// loaders are in Firecracker's `x86_64` boot path).
    pub kernel_image_path: String,
    /// The initramfs, when the guest has one.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub initrd_path: Option<String>,
    /// The guest kernel's own command line (`console=ttyS0 … root=… rw`).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub boot_args: Option<String>,
}

/// `PUT /machine-config`: the shape of the machine.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MachineConfiguration {
    /// 1…32.
    pub vcpu_count: u32,
    /// The guest's RAM, in MiB.
    pub mem_size_mib: u64,
    /// Simultaneous multithreading: two vCPUs per core, only with an even count.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub smt: Option<bool>,
    /// A named CPU template (or a custom one, in a file).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cpu_template: Option<String>,
    /// Track dirty pages, which snapshots need and this project does not.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub track_dirty_pages: Option<bool>,
    /// `2M` huge pages for the guest's memory, when the host has them.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub huge_pages: Option<String>,
}

/// `PUT /drives/{id}`: one block device.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Drive {
    /// The id, which is also the path segment (`/drives/{drive_id}`).
    pub drive_id: String,
    /// The **raw** file on the host. Not a wrapped image, not an encrypted container:
    /// Firecracker maps it as it is.
    pub path_on_host: String,
    /// Is this the root device — the one `/dev/vda`?
    pub is_root_device: bool,
    pub is_read_only: bool,
    /// `Unsafe` (the guest's flushes do not force the host's) or `Writeback`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub cache_type: Option<String>,
    /// `Sync` or `Async` (`Async` needs a host kernel newer than 5.10.51).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub io_engine: Option<String>,
    /// Give the guest this partition's UUID as the root device's.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub partuuid: Option<String>,
    /// A vhost-user **block** backend's socket, instead of `path_on_host`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub socket: Option<String>,
    /// The logical block size advertised to the guest (default 512).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub blk_size: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub rate_limiter: Option<serde_json::Value>,
}

/// **The id a drive is given on the API**: letters, digits and underscores, which is what
/// Firecracker accepts ("API Resource IDs can only contain alphanumeric characters and
/// underscores", measured 2026-10-13 by a disk whose *name* came from its file name and
/// carried a `-`).  Everything else becomes `_`, so a name a person chose is still readable
/// in the id and the API is never given something it will refuse.
pub fn sanitize_drive_id(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        if c.is_ascii_alphanumeric() || c == '_' {
            out.push(c);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        out.push_str("disk");
    }
    out
}

impl Drive {
    /// A raw file as a plain virtio-blk device — the shape every disk in this
    /// project takes.
    pub fn raw(id: &str, path: &str, is_root: bool, read_only: bool) -> Drive {
        Drive {
            drive_id: sanitize_drive_id(id),
            path_on_host: path.to_string(),
            is_root_device: is_root,
            is_read_only: read_only,
            cache_type: Some("Unsafe".into()),
            io_engine: Some("Sync".into()),
            partuuid: None,
            socket: None,
            blk_size: None,
            rate_limiter: None,
        }
    }
}

/// `PUT /network-interfaces/{id}`: the guest's interface, on a tap.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetworkInterface {
    pub iface_id: String,
    /// The tap device's name on the host.  Firecracker's only netdev backend.
    pub host_dev_name: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub guest_mac: Option<String>,
    /// What the guest is told its MTU is.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub mtu: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub rx_rate_limiter: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub tx_rate_limiter: Option<serde_json::Value>,
}

/// `PUT /vsock`: the one channel into the guest, and the sockets the host's end
/// of each port is named after.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Vsock {
    /// The guest's context id.  The host is always 2.
    pub guest_cid: u64,
    /// The host's unix socket.  A guest connecting to port `P` makes Firecracker
    /// connect to `<uds_path>_<P>`, so the host listens **there**, before the
    /// machine starts.
    pub uds_path: String,
}

/// `PUT /balloon`: the balloon device, defined before the machine starts.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Balloon {
    /// Where the balloon starts, in MiB.
    pub amount_mib: u64,
    /// Hand memory back when the guest is out of it.
    pub deflate_on_oom: bool,
    /// Seconds between statistics refreshes; `0` disables them (and asking for
    /// statistics with them disabled is an error, measured 2026-10-09).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub stats_polling_interval_s: Option<u32>,
    /// Let the guest hand free pages back without the balloon's own loop.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub free_page_hinting: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub free_page_reporting: Option<bool>,
}

/// `PATCH /balloon`: where the balloon goes now.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BalloonUpdate {
    pub amount_mib: u64,
}

/// `GET /balloon/statistics`: the guest's own numbers, which is where this
/// project reads the memory it used to read from the guest's `/proc/meminfo`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct BalloonStats {
    pub target_pages: u64,
    pub actual_pages: u64,
    pub target_mib: u64,
    pub actual_mib: u64,
    #[serde(default)]
    pub swap_in: Option<u64>,
    #[serde(default)]
    pub swap_out: Option<u64>,
    #[serde(default)]
    pub major_faults: Option<u64>,
    #[serde(default)]
    pub minor_faults: Option<u64>,
    /// What the guest believes it has free, in **bytes**.
    #[serde(default)]
    pub free_memory: Option<u64>,
    /// What the guest believes it has, in bytes.
    #[serde(default)]
    pub total_memory: Option<u64>,
    #[serde(default)]
    pub available_memory: Option<u64>,
    #[serde(default)]
    pub disk_caches: Option<u64>,
}

/// `PUT /hotplug/memory`: a region the guest may plug and unplug.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct MemoryHotplug {
    /// The whole region's size, in MiB.
    pub total_size_mib: u64,
    /// The granularity the guest can react to.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub slot_size_mib: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub block_size_mib: Option<u64>,
}

/// `PUT /actions`: the three things a running (or about-to-run) machine can be
/// told to do.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Action {
    pub action_type: String,
}

/// `GET /`: the instance's own report.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstanceInfo {
    #[serde(default)]
    pub app_name: String,
    #[serde(default)]
    pub id: String,
    /// `Not started`, `Running` or `Paused`.
    pub state: String,
    #[serde(default)]
    pub vmm_version: String,
}

/// `GET /version`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Version {
    #[serde(default)]
    pub firecracker_version: String,
}

/// The sizes of the machine's memory, in bytes, from the balloon's statistics —
/// the same three numbers `dc-memory::GuestMemory` holds, from the same guest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GuestMemory {
    pub total: u64,
    pub free: u64,
    pub available: u64,
    pub cached: u64,
}

impl From<&BalloonStats> for GuestMemory {
    fn from(stats: &BalloonStats) -> GuestMemory {
        let total = stats.total_memory.unwrap_or(0);
        let free = stats.free_memory.unwrap_or(0);
        GuestMemory {
            total,
            free,
            // `available` when the guest reports it (a guest with a modern
            // kernel does), otherwise free — the rule that machine's own
            // `/proc/meminfo` parser uses.
            available: stats.available_memory.unwrap_or(free),
            cached: stats.disk_caches.unwrap_or(0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **What Firecracker will take as an id**: letters, digits and underscores — and a disk a
    /// person named after its file (`disk-image-001.raw`) is one whose name has to be made into
    /// one of those before the API is given it (measured 2026-10-13: `PUT /drives/disk-image-001`
    /// was refused with "API Resource IDs can only contain alphanumeric characters and
    /// underscores").
    #[test]
    fn a_drives_id_is_what_firecracker_accepts_and_still_says_the_name() {
        assert_eq!(sanitize_drive_id("disk-image-001"), "disk_image_001");
        assert_eq!(sanitize_drive_id("data"), "data");
        assert_eq!(sanitize_drive_id("rootfs"), "rootfs");
        assert_eq!(sanitize_drive_id("my disk.raw"), "my_disk_raw");
        // An empty name is not an id: something is named, and it is a disk.
        assert_eq!(sanitize_drive_id(""), "disk");
        assert_eq!(sanitize_drive_id("---"), "___");
        let drive = Drive::raw("disk-image-001", "/d/disk-image-001.raw", false, false);
        assert_eq!(drive.drive_id, "disk_image_001");
        // And the path is untouched: it is the file the host opens, not an id.
        assert_eq!(drive.path_on_host, "/d/disk-image-001.raw");
    }

    #[test]
    fn a_boot_source_without_an_initramfs_says_nothing_about_one() {
        let boot = BootSource {
            kernel_image_path: "/k/vmlinux".into(),
            initrd_path: None,
            boot_args: Some("console=ttyS0".into()),
        };
        let json = serde_json::to_string(&boot).unwrap();
        assert_eq!(
            json,
            "{\"kernel_image_path\":\"/k/vmlinux\",\"boot_args\":\"console=ttyS0\"}"
        );
    }

    #[test]
    fn a_machine_configuration_is_vcpus_and_memory_and_nothing_surprising() {
        let m = MachineConfiguration {
            vcpu_count: 12,
            mem_size_mib: 6144,
            smt: Some(false),
            cpu_template: None,
            track_dirty_pages: None,
            huge_pages: None,
        };
        let json = serde_json::to_string(&m).unwrap();
        assert_eq!(
            json,
            "{\"vcpu_count\":12,\"mem_size_mib\":6144,\"smt\":false}"
        );
    }

    #[test]
    fn a_balloon_starts_somewhere_and_can_report_itself() {
        let b = Balloon {
            amount_mib: 4096,
            deflate_on_oom: true,
            stats_polling_interval_s: Some(1),
            free_page_hinting: None,
            free_page_reporting: None,
        };
        let json = serde_json::to_string(&b).unwrap();
        assert_eq!(
            json,
            "{\"amount_mib\":4096,\"deflate_on_oom\":true,\"stats_polling_interval_s\":1}"
        );
    }

    #[test]
    fn the_balloons_own_statistics_become_the_memory_the_policy_decides_on() {
        // The numbers a real Firecracker answered on this host, 2026-10-09.
        let raw = r#"{"target_pages":1048576,"actual_pages":82688,"target_mib":4096,
            "actual_mib":323,"swap_in":0,"swap_out":0,"major_faults":0,"minor_faults":0,
            "free_memory":6154436608,"total_memory":6193389568,
            "available_memory":6023303168,"disk_caches":2809856}"#;
        let stats: BalloonStats = serde_json::from_str(raw).unwrap();
        let mem = GuestMemory::from(&stats);
        assert_eq!(mem.total, 6193389568);
        assert_eq!(mem.free, 6154436608);
        assert_eq!(mem.available, 6023303168);
        assert_eq!(mem.cached, 2809856);
    }

    #[test]
    fn a_statistics_answer_without_available_memory_falls_back_to_free() {
        let stats = BalloonStats {
            target_pages: 0,
            actual_pages: 0,
            target_mib: 0,
            actual_mib: 0,
            free_memory: Some(100),
            total_memory: Some(200),
            ..Default::default()
        };
        let mem = GuestMemory::from(&stats);
        assert_eq!(mem.available, 100);
    }

    #[test]
    fn the_instance_states_are_the_three_the_api_names() {
        for state in ["Not started", "Running", "Paused"] {
            let info: InstanceInfo =
                serde_json::from_str(&format!("{{\"state\":\"{state}\"}}")).unwrap();
            assert_eq!(info.state, state);
        }
    }

    #[test]
    fn a_drive_made_by_the_helper_carries_both_engines_and_nothing_else() {
        let d = Drive::raw("data", "/d/data.raw", false, true);
        let json = serde_json::to_string(&d).unwrap();
        assert_eq!(
            json,
            "{\"drive_id\":\"data\",\"path_on_host\":\"/d/data.raw\",\"is_root_device\":false,\
             \"is_read_only\":true,\"cache_type\":\"Unsafe\",\"io_engine\":\"Sync\"}"
                .replace(' ', "")
        );
    }

    #[test]
    fn a_field_the_api_does_not_know_is_refused_rather_than_ignored() {
        // The point of `deny_unknown_fields`: a `serial` (a conventional virtio-blk has
        // one) must not silently disappear on the way to the API.
        let raw = r#"{"drive_id":"d","path_on_host":"/p","is_root_device":false,
                      "is_read_only":true,"serial":"desk-data"}"#;
        let err = serde_json::from_str::<Drive>(raw).unwrap_err();
        assert!(err.to_string().contains("serial"), "{err}");
    }
}
