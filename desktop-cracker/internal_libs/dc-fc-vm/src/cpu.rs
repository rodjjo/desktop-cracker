//! **The host's CPUs, and how the machine is pinned to them.**
//!
//! The project measured what happens without this (`dc-common::cpu`): with the host
//! saturated, an
//! unpinned guest booted in 7.6–7.9 s against 3.36–3.40 s pinned, and its worst
//! wake-up went from ~3.0 ms to 0.13–1.35 ms.  The rule that came out of it is
//! what this file implements for Firecracker, unchanged in its intent and
//! different only in what it has to hold on to:
//!
//! * the machine's **process** is confined to the host's **physical cores** — a
//!   CPU per core, never a hyper-thread that shares a core with another;
//! * each of its **vCPU threads** is put on a core of its own;
//! * the application's own threads (the window, the network, the audio path) are
//!   **not** pinned, so the cores the guest is not using are theirs.
//!
//! The one thing Firecracker changes: it names its vCPU threads `fc_vcpu <n>` where
//! and Firecracker names its own **`fc_vcpu <n>`** (`vstate/vcpu.rs`,
//! `thread::Builder::new().name(format!("fc_vcpu {}", self.kvm_vcpu.index))`).
//! That is what makes the per-thread half possible without a debugger, a tracing
//! build or a patch.
//!
//! Everything here reads a directory and writes an affinity mask; the directory is
//! a parameter, so the unit tests use a `/sys` and a `/proc` of their own and
//! never touch the host's real CPUs.

use std::path::{Path, PathBuf};

/// The name Firecracker gives a vCPU thread, and the index inside it.
///
/// A single place, because both the pinning and the `/status` the plugin reads
/// count these threads.
pub const VCPU_THREAD_PREFIX: &str = "fc_vcpu ";

/// The host's topology: one entry per **physical core**, in the kernel's own
/// numbering, with the hyper-threads that share each of them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpuLayout {
    /// One CPU per physical core: what the machine's process is confined to.
    pub cpus: Vec<usize>,
    /// The CPUs sharing each of `cpus`, the core first.  A CPU whose group could
    /// not be read is a group of one — the honest answer when the topology is not
    /// readable is "this CPU, and no thread beside it".
    pub siblings: Vec<Vec<usize>>,
    /// Was this read from the kernel's topology, or is it the online CPU list?
    /// A host whose topology could not be read is left unpinned, and the run says
    /// so in one line.
    pub from_topology: bool,
}

impl CpuLayout {
    /// Read the host's topology.
    pub fn detect() -> CpuLayout {
        CpuLayout::from_sys(Path::new("/sys/devices/system/cpu"))
    }

    /// Read a `/sys/devices/system/cpu` tree — this one, or a test's.
    pub fn from_sys(dir: &Path) -> CpuLayout {
        let mut online: Vec<usize> = Vec::new();
        let Ok(entries) = std::fs::read_dir(dir) else {
            return CpuLayout {
                cpus: Vec::new(),
                siblings: Vec::new(),
                from_topology: false,
            };
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            // `cpu0` … and not `cpufreq`, `cpuidle` or `cpu0/cache`.
            let Some(n) = name
                .strip_prefix("cpu")
                .and_then(|rest| rest.parse::<usize>().ok())
            else {
                continue;
            };
            if !entry.path().join("topology").is_dir() && !entry.path().join("online").exists() {
                continue;
            }
            online.push(n);
        }
        online.sort_unstable();
        if online.is_empty() {
            return CpuLayout {
                cpus: Vec::new(),
                siblings: Vec::new(),
                from_topology: false,
            };
        }

        let mut cpus = Vec::new();
        let mut siblings = Vec::new();
        let mut from_topology = false;
        for &cpu in &online {
            let group = std::fs::read_to_string(
                dir.join(format!("cpu{cpu}/topology/thread_siblings_list")),
            )
            .ok()
            .map(|text| parse_cpu_list(&text))
            .unwrap_or_default();
            if group.is_empty() {
                cpus.push(cpu);
                siblings.push(vec![cpu]);
                continue;
            }
            from_topology = true;
            // Only the **first** CPU of the group is the core; the rest are its
            // threads and are recorded once, with the core they belong to.
            if group[0] == cpu {
                cpus.push(cpu);
                siblings.push(group);
            }
        }
        if cpus.is_empty() {
            return CpuLayout {
                siblings: online.iter().map(|&c| vec![c]).collect(),
                cpus: online,
                from_topology: false,
            };
        }
        CpuLayout {
            cpus,
            siblings,
            from_topology,
        }
    }

    /// How many physical cores the host has.
    pub fn cores(&self) -> usize {
        self.cpus.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cpus.is_empty()
    }

    /// The list as a person reads it (`0-23`, `0,2,4`).
    pub fn cpus_list(&self) -> String {
        format_cpu_list(&self.cpus)
    }

    pub fn siblings_of(&self, i: usize) -> &[usize] {
        self.siblings.get(i).map(Vec::as_slice).unwrap_or(&[])
    }

    /// The CPUs a guest with `vcpus` vCPUs is pinned to: one CPU per physical
    /// core, in the kernel's order — and when the guest has **more** vCPUs than
    /// the host has cores, the cores' hyper-threads follow (a 12-core/24-thread
    /// host with a 24-vCPU guest).
    ///
    /// `None` when there is nothing to pin to, which the caller reads as "leave
    /// it to the scheduler".  Note what is *not* here: `vcpus` CPUs taken blindly
    /// from the online list — on a hyper-threaded host that is the shape the
    /// pinning exists to avoid.
    pub fn cpus_for(&self, vcpus: usize) -> Option<Vec<usize>> {
        if self.cpus.is_empty() || vcpus == 0 {
            return None;
        }
        if vcpus <= self.cpus.len() {
            return Some(self.cpus[..vcpus].to_vec());
        }
        let mut out = self.cpus.clone();
        for (i, core) in self.cpus.iter().enumerate() {
            if out.len() >= vcpus {
                break;
            }
            for &thread in self.siblings_of(i).iter().filter(|&&t| t != *core) {
                if out.len() >= vcpus {
                    break;
                }
                out.push(thread);
            }
        }
        Some(out)
    }

    /// A `cpu_set_t` for a list of CPUs, as `sched_setaffinity` wants it.
    ///
    /// `None` when the list is empty or names a CPU the kernel's set cannot hold:
    /// an affinity call with a set that means "nothing" makes the process
    /// unschedulable, which is the one mistake worth refusing here.
    pub fn set_of(cpus: &[usize]) -> Option<libc::cpu_set_t> {
        if cpus.is_empty() {
            return None;
        }
        // SAFETY: `cpu_set_t` is a fixed-size bit array, and all-zero is a valid
        // one; `CPU_SET` only writes inside it.
        let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        for &cpu in cpus {
            if cpu >= libc::CPU_SETSIZE as usize {
                return None;
            }
            // SAFETY: the index was just checked against `CPU_SETSIZE`.
            unsafe { libc::CPU_SET(cpu, &mut set) };
        }
        Some(set)
    }
}

/// Parse a kernel CPU list: `0-3,8,10-11`.
pub fn parse_cpu_list(text: &str) -> Vec<usize> {
    let mut out = Vec::new();
    for part in text.trim().split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        match part.split_once('-') {
            Some((from, to)) => {
                if let (Ok(from), Ok(to)) =
                    (from.trim().parse::<usize>(), to.trim().parse::<usize>())
                {
                    for cpu in from..=to {
                        out.push(cpu);
                    }
                }
            }
            None => {
                if let Ok(cpu) = part.parse::<usize>() {
                    out.push(cpu);
                }
            }
        }
    }
    out
}

/// Format a CPU list the way the kernel does: `0-3,8`.
pub fn format_cpu_list(cpus: &[usize]) -> String {
    let mut sorted = cpus.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    let mut parts: Vec<String> = Vec::new();
    let mut i = 0;
    while i < sorted.len() {
        let start = sorted[i];
        let mut end = start;
        while i + 1 < sorted.len() && sorted[i + 1] == end + 1 {
            end = sorted[i + 1];
            i += 1;
        }
        if start == end {
            parts.push(start.to_string());
        } else {
            parts.push(format!("{start}-{end}"));
        }
        i += 1;
    }
    parts.join(",")
}

/// Confine a process to a list of CPUs.
///
/// The count of CPUs it actually got, for the milestone line.
pub fn pin_process(pid: u32, cpus: &[usize]) -> std::io::Result<usize> {
    let Some(set) = CpuLayout::set_of(cpus) else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "no CPUs to pin to",
        ));
    };
    // SAFETY: `set` is a cpu_set_t of the size `sched_setaffinity` takes, and
    // `pid` is a process this run started (its own child).
    let rc = unsafe {
        libc::sched_setaffinity(
            pid as libc::pid_t,
            std::mem::size_of::<libc::cpu_set_t>(),
            &set,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(cpus.len())
}

/// Put each of the machine's vCPU threads on a CPU of its own.
///
/// The threads do not exist until the machine has started, so this is called
/// again as the vCPUs come up (`fc_vcpu N` appears one by one); an index already
/// pinned is left alone.  `proc_root` is `/proc`, or a test's own.
///
/// A thread whose index has no CPU left is left where it is: an unpinned vCPU by
/// the host's own choice is better than a guest with a vCPU on a core that does
/// not exist.
pub fn pin_vcpu_threads(pid: u32, cpus: &[usize], proc_root: &Path) -> usize {
    pin_vcpu_threads_with(pid, cpus, proc_root, pin_thread)
}

/// [`pin_vcpu_threads`] with the affinity call supplied — the seam the unit tests
/// use, so a test never touches the host's real scheduler to learn which
/// `(thread, cpu)` pairs the rule produces.
pub fn pin_vcpu_threads_with(
    pid: u32,
    cpus: &[usize],
    proc_root: &Path,
    pin: impl Fn(u32, &[usize]) -> std::io::Result<()>,
) -> usize {
    let mut pinned = 0;
    let tasks = proc_root.join(pid.to_string()).join("task");
    let Ok(entries) = std::fs::read_dir(&tasks) else {
        return 0;
    };
    for entry in entries.flatten() {
        let tid: u32 = match entry.file_name().to_str().and_then(|n| n.parse().ok()) {
            Some(tid) => tid,
            None => continue,
        };
        let Ok(name) = std::fs::read_to_string(entry.path().join("comm")) else {
            continue;
        };
        let Some(index) = vcpu_index(name.trim()) else {
            continue;
        };
        let Some(&cpu) = cpus.get(index) else {
            continue;
        };
        if pin(tid, &[cpu]).is_ok() {
            pinned += 1;
        }
    }
    pinned
}

/// The index inside an `fc_vcpu N` thread name, when it is one.
pub fn vcpu_index(thread_name: &str) -> Option<usize> {
    thread_name
        .strip_prefix(VCPU_THREAD_PREFIX)?
        .trim()
        .parse()
        .ok()
}

/// Pin one thread (a `tid` in `/proc/<pid>/task`).
pub fn pin_thread(tid: u32, cpus: &[usize]) -> std::io::Result<()> {
    let Some(set) = CpuLayout::set_of(cpus) else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "no CPUs",
        ));
    };
    // SAFETY: same call as `pin_process`, on a thread id this run owns.
    let rc = unsafe {
        libc::sched_setaffinity(
            tid as libc::pid_t,
            std::mem::size_of::<libc::cpu_set_t>(),
            &set,
        )
    };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Which CPUs the machine's vCPU threads are on right now: `(vcpu index, cpus)`.
///
/// This is what a run publishes for the plugin's `/status` (`pinning`), so a test
/// can assert the machine is pinned instead of trusting it.
pub fn vcpu_affinity(pid: u32, proc_root: &Path) -> Vec<(usize, Vec<usize>)> {
    let mut out = Vec::new();
    let tasks = proc_root.join(pid.to_string()).join("task");
    let Ok(entries) = std::fs::read_dir(&tasks) else {
        return out;
    };
    for entry in entries.flatten() {
        let Ok(name) = std::fs::read_to_string(entry.path().join("comm")) else {
            continue;
        };
        let Some(index) = vcpu_index(name.trim()) else {
            continue;
        };
        if let Ok(list) = std::fs::read_to_string(entry.path().join("status")) {
            if let Some(line) = list.lines().find(|l| l.starts_with("Cpus_allowed_list:")) {
                let cpus = parse_cpu_list(line.trim_start_matches("Cpus_allowed_list:").trim());
                out.push((index, cpus));
            }
        }
    }
    out.sort_by_key(|(index, _)| *index);
    out
}

/// A `PathBuf` for the machine's own API socket and vsock socket, under one
/// run directory.
///
/// One directory per run, and one run's paths are not another's: two machines
/// sharing a vsock `uds_path` collide on the host's sockets, so the directory
/// carries the process id.
pub fn run_dir(base: &Path, pid: u32) -> PathBuf {
    dc_common::run_directory(base, pid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// A `/sys/devices/system/cpu` tree: four cores, two threads each.
    fn a_sys_tree() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path();
        for cpu in 0..8 {
            let core = cpu % 4; // 0-3 and 4-7 are hyper-thread pairs
            let first = core;
            let second = core + 4;
            let topo = base.join(format!("cpu{cpu}/topology"));
            fs::create_dir_all(&topo).unwrap();
            fs::write(
                topo.join("thread_siblings_list"),
                format!("{first},{second}\n"),
            )
            .unwrap();
        }
        fs::create_dir_all(base.join("cpufreq")).unwrap();
        dir
    }

    /// A `/proc` tree with a process's `fc_vcpu N` threads.
    fn a_proc_tree(pid: u32, vcpus: usize, allowed: &[usize]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let tasks = dir.path().join(pid.to_string()).join("task");
        fs::create_dir_all(&tasks).unwrap();
        for n in 0..vcpus {
            let tid = 1000 + n;
            let task = tasks.join(tid.to_string());
            fs::create_dir_all(&task).unwrap();
            fs::write(task.join("comm"), format!("fc_vcpu {n}\n")).unwrap();
            fs::write(
                task.join("status"),
                format!(
                    "Name:\tfc_vcpu {n}\nCpus_allowed_list:\t{}\n",
                    format_cpu_list(allowed)
                ),
            )
            .unwrap();
        }
        // The threads that are not vCPUs: the API server and the vmm.
        for name in ["fc_api", "firecracker"] {
            let task = tasks.join(format!("{}", 2000 + name.len()));
            fs::create_dir_all(&task).unwrap();
            fs::write(task.join("comm"), name).unwrap();
        }
        dir
    }

    #[test]
    fn the_topology_is_one_entry_per_physical_core_and_its_threads() {
        let sys = a_sys_tree();
        let layout = CpuLayout::from_sys(sys.path());
        assert_eq!(
            layout.cpus,
            vec![0, 1, 2, 3],
            "one entry per core, not per CPU"
        );
        assert_eq!(layout.siblings_of(0), &[0, 4]);
        assert_eq!(layout.siblings_of(3), &[3, 7]);
        assert_eq!(layout.cores(), 4);
        assert!(layout.from_topology);
        assert_eq!(layout.cpus_list(), "0-3");
    }

    #[test]
    fn a_host_whose_topology_cannot_be_read_is_left_alone_rather_than_guessed_at() {
        let dir = tempfile::tempdir().unwrap();
        let layout = CpuLayout::from_sys(dir.path());
        assert!(layout.is_empty());
        assert!(!layout.from_topology);
        assert_eq!(
            layout.cpus_for(12),
            None,
            "nothing to pin to is a 'leave it to the scheduler'"
        );
    }

    #[test]
    fn a_guest_with_fewer_vcpus_than_cores_gets_one_core_each() {
        let sys = a_sys_tree();
        let layout = CpuLayout::from_sys(sys.path());
        assert_eq!(layout.cpus_for(1), Some(vec![0]));
        assert_eq!(layout.cpus_for(3), Some(vec![0, 1, 2]));
        assert_eq!(layout.cpus_for(4), Some(vec![0, 1, 2, 3]));
    }

    #[test]
    fn a_guest_bigger_than_the_host_gets_the_hyper_threads_too_and_not_random_cpus() {
        let sys = a_sys_tree();
        let layout = CpuLayout::from_sys(sys.path());
        assert_eq!(layout.cpus_for(6), Some(vec![0, 1, 2, 3, 4, 5]));
        assert_eq!(
            layout.cpus_for(99).unwrap().len(),
            8,
            "the host runs out of CPUs, not of sense"
        );
    }

    #[test]
    fn cpu_lists_are_parsed_and_formatted_the_way_the_kernel_writes_them() {
        assert_eq!(parse_cpu_list("0-3,8,10-11\n"), vec![0, 1, 2, 3, 8, 10, 11]);
        assert_eq!(parse_cpu_list(""), Vec::<usize>::new());
        assert_eq!(parse_cpu_list("  7 "), vec![7]);
        assert_eq!(format_cpu_list(&[0, 1, 2, 3, 8, 10, 11]), "0-3,8,10-11");
        assert_eq!(format_cpu_list(&[5]), "5");
        assert_eq!(format_cpu_list(&[]), "");
        assert_eq!(format_cpu_list(&[3, 1, 2, 2]), "1-3");
    }

    #[test]
    fn a_thread_name_says_which_vcpu_it_is() {
        assert_eq!(vcpu_index("fc_vcpu 0"), Some(0));
        assert_eq!(vcpu_index("fc_vcpu 11"), Some(11));
        assert_eq!(vcpu_index("fc_api"), None);
        assert_eq!(vcpu_index("firecracker"), None);
        assert_eq!(
            vcpu_index("CPU 3/KVM"),
            None,
            "the thread's own name is not this one"
        );
        assert_eq!(vcpu_index("fc_vcpu"), None);
        assert_eq!(vcpu_index("fc_vcpu x"), None);
    }

    #[test]
    fn pinning_the_vcpus_touches_the_vcpu_threads_and_only_those() {
        // A `/proc` of our own and the affinity call recorded rather than made:
        // the real one would need a Firecracker to have run, and a unit test does
        // not touch the host's scheduler.
        let proc = a_proc_tree(4242, 4, &[0, 1, 2, 3, 4, 5, 6, 7]);
        let seen = std::cell::RefCell::new(Vec::new());
        let pinned = pin_vcpu_threads_with(4242, &[0, 1, 2, 3], proc.path(), |tid, cpus| {
            seen.borrow_mut().push((tid, cpus.to_vec()));
            Ok(())
        });
        assert_eq!(pinned, 4, "four vCPU threads, and not the API server");
        // One CPU each, and the vCPU's own index is what chose it.  The threads
        // are walked in `/proc`'s own (unordered) order, so the pairs are sorted
        // before they are asserted on.
        let mut seen = seen.into_inner();
        seen.sort_unstable();
        assert_eq!(seen.len(), 4);
        for (n, (tid, cpus)) in seen.iter().enumerate() {
            assert_eq!(*tid, 1000 + n as u32, "the thread of vCPU {n}");
            assert_eq!(cpus, &[n], "vCPU {n} gets a core of its own");
        }
        let found = vcpu_affinity(4242, proc.path());
        assert_eq!(
            found.iter().map(|(i, _)| *i).collect::<Vec<_>>(),
            vec![0, 1, 2, 3]
        );
    }

    #[test]
    fn a_vcpu_with_no_cpu_left_for_it_is_left_where_it_is() {
        let proc = a_proc_tree(7, 4, &[0, 1]);
        // Only two CPUs for four vCPUs: the two that can be pinned are, and the
        // others are not an error (an unpinned vCPU by the host's choice is better
        // than a guest with a vCPU on a core that does not exist).
        let seen = std::cell::RefCell::new(Vec::new());
        let pinned = pin_vcpu_threads_with(7, &[0, 1], proc.path(), |tid, cpus| {
            seen.borrow_mut().push((tid, cpus.to_vec()));
            Ok(())
        });
        assert_eq!(pinned, 2);
        let mut seen = seen.into_inner();
        seen.sort_unstable();
        assert_eq!(seen, vec![(1000, vec![0]), (1001, vec![1])]);
    }

    #[test]
    fn a_thread_that_refuses_to_be_pinned_is_counted_as_not_pinned() {
        let proc = a_proc_tree(9, 3, &[0, 1, 2]);
        let pinned = pin_vcpu_threads_with(9, &[0, 1, 2], proc.path(), |_, _| {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "no",
            ))
        });
        assert_eq!(pinned, 0);
    }

    #[test]
    fn a_process_that_is_gone_is_no_pinning_at_all() {
        let proc = a_proc_tree(1, 2, &[0]);
        assert_eq!(pin_vcpu_threads(999_999, &[0, 1], proc.path()), 0);
        assert!(vcpu_affinity(999_999, proc.path()).is_empty());
    }

    #[test]
    fn an_affinity_set_with_no_cpu_in_it_is_refused_rather_than_made_unschedulable() {
        assert!(CpuLayout::set_of(&[]).is_none());
        assert!(CpuLayout::set_of(&[0, 1]).is_some());
        // A CPU the kernel's own set cannot name is refused too.
        assert!(CpuLayout::set_of(&[libc::CPU_SETSIZE as usize + 1]).is_none());
    }

    #[test]
    fn pinning_this_process_to_one_of_its_own_cpus_works_and_leaves_it_running() {
        // The one test that touches the real scheduler, with the CPU this test is
        // already on: it is a smoke test of the `sched_setaffinity` call itself,
        // and it never takes the process off every CPU.
        let proc = Path::new("/proc");
        let layout = CpuLayout::detect();
        if layout.is_empty() {
            return; // a host with no topology is a host this test cannot say anything about
        }
        let before = read_own_affinity(proc);
        assert!(!before.is_empty());
        assert!(pin_process(std::process::id(), &[before[0]]).is_ok());
        assert_eq!(read_own_affinity(proc), vec![before[0]]);
        assert!(
            pin_process(std::process::id(), &before).is_ok(),
            "and back, so the test host is left as it was"
        );
    }

    fn read_own_affinity(proc_root: &Path) -> Vec<usize> {
        let status = fs::read_to_string(proc_root.join("self/status")).unwrap_or_default();
        status
            .lines()
            .find(|l| l.starts_with("Cpus_allowed_list:"))
            .map(|l| parse_cpu_list(l.trim_start_matches("Cpus_allowed_list:").trim()))
            .unwrap_or_default()
    }

    #[test]
    fn a_runs_own_directory_carries_its_process_id() {
        let base = Path::new("/run/user/1000/desktop-cracker");
        assert_eq!(
            run_dir(base, 4242),
            PathBuf::from("/run/user/1000/desktop-cracker/run-4242")
        );
        assert_ne!(
            run_dir(base, 1),
            run_dir(base, 2),
            "two runs must not share a vsock path"
        );
    }
}
