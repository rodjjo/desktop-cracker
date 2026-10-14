//! **The host's CPUs, and how the microVM is pinned to them.**
//!
//! A microVM is a process with one thread per vCPU, and the host's scheduler is free to
//! move those threads anywhere — including onto the same physical core as a compile, or onto
//! the second hyper-thread of a core another thread is already using.  Measured with the
//! measured on this host (2026-10-09: a
//! 24-core / 48-thread Threadripper with another tenant holding ~48 threads):
//!
//! | shape | boot | guest's own worst wake-up lateness |
//! |---|---|---|
//! | nothing pinned, host saturated | 7.6–7.9 s | ~3.0 ms (0.2–1 % of 10 000 wakes >1 ms) |
//! | pinned to 12 CPUs the load leaves alone | 3.36–3.40 s | 0.13–1.35 ms |
//!
//! and the disk path follows the same shape (1049 → 2064 MiB/s write, 4414 → 9143 MiB/s
//! read).  On a *quiet* host pinning changes nothing measurable — it is insurance for the
//! machine this project actually runs on, where the host is in constant use.
//!
//! So the microVM is pinned **by default**: the machine's **process** is confined to the host's
//! physical cores (its hyper-threads are left to the host), and each of its **vCPU threads**
//! is put on a physical core of its own — a guest with 12 vCPUs is spread across 12 real
//! cores instead of being packed onto 12 threads that may share 6.  the machine's other threads
//! (the main loop, the display, the I/O) then have the cores the guest is not using, which
//! is what keeps the window drawing while the guest is busy.
//!
//! **The application itself is not pinned**: it is the process that draws the window, answers
//! the network and runs the audio path, and confining it would take the host's cores away
//! from the work the user is watching.  It is the microVM that is the guest on this machine.
//!
//! Nothing here is a new run mode, a switch or a setting: it is what the machine *is*, the
//! same way `-cpu host` and `accel=kvm` are.  A host whose topology cannot be read falls back
//! to its online CPUs, and a caller that cannot pin at all says so in one line and keeps
//! going — a microVM on a busy host without pinning is what this project used to be, not a
//! failure.

use std::sync::OnceLock;

/// One microVM's worth of host CPUs: the physical cores, and their hyper-threads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CpuTopology {
    /// One CPU per **physical core**, in the kernel's own numbering — what the microVM
    /// process is allowed to use.
    pub cpus: Vec<usize>,
    /// The CPUs sharing each of `cpus`, in the same order (`cpus[i]` first).  A CPU whose
    /// group could not be read is a **group of one** — the honest answer for a host whose
    /// topology is not readable is "this CPU, and no thread beside it", and it keeps
    /// `siblings_of(i)` answerable for every CPU in `cpus`.
    pub siblings: Vec<Vec<usize>>,
    /// Was this read from the kernel's topology, or is it the online CPU list?
    pub from_topology: bool,
}

impl CpuTopology {
    /// Read the host's topology: one physical core per entry, taken in order.
    ///
    /// `/sys/devices/system/cpu/cpuN/topology/thread_siblings_list` names every CPU that
    /// shares the physical core `N` sits on (including `N`), so the first CPU of each group
    /// is a physical core and the group is its hyper-threads.  A CPU that reports no
    /// topology is taken as a core of its own rather than dropped: a guest with too few
    /// CPUs is a worse answer than a guest whose "cores" are hyper-threads.
    pub fn detect() -> CpuTopology {
        Self::from_dir(std::path::Path::new("/sys/devices/system/cpu"))
    }

    /// [`CpuTopology::detect`] against another `/sys` tree (the tests' own).
    pub fn from_dir(dir: &std::path::Path) -> CpuTopology {
        let mut online: Vec<usize> = Vec::new();
        let Ok(entries) = std::fs::read_dir(dir) else {
            return CpuTopology {
                cpus: Vec::new(),
                siblings: Vec::new(),
                from_topology: false,
            };
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            let Some(n) = name
                .strip_prefix("cpu")
                .and_then(|r| r.parse::<usize>().ok())
            else {
                continue;
            };
            // `cpu0` … but not `cpufreq`, `cpuidle`, `cpufreq/…`.
            if !entry.path().join("topology").is_dir() && !entry.path().join("online").exists() {
                continue;
            }
            online.push(n);
        }
        online.sort_unstable();
        if online.is_empty() {
            return CpuTopology {
                cpus: Vec::new(),
                siblings: Vec::new(),
                from_topology: false,
            };
        }

        let mut cpus: Vec<usize> = Vec::new();
        let mut siblings: Vec<Vec<usize>> = Vec::new();
        let mut from_topology = false;
        for &cpu in &online {
            let list = match std::fs::read_to_string(
                dir.join(format!("cpu{cpu}/topology/thread_siblings_list")),
            ) {
                Ok(text) => text,
                Err(_) => {
                    cpus.push(cpu);
                    siblings.push(vec![cpu]);
                    continue;
                }
            };
            let group = parse_cpu_list(&list);
            if group.is_empty() {
                cpus.push(cpu);
                siblings.push(vec![cpu]);
                continue;
            }
            from_topology = true;
            // Only the **first** CPU of the group is the core; the others are its threads,
            // and they are recorded once, with the core they belong to.
            if group[0] == cpu {
                cpus.push(cpu);
                siblings.push(group);
            }
        }
        if cpus.is_empty() {
            // Every CPU reported a group that does not begin with itself (a topology this
            // parser did not expect): the online CPUs are the best answer there is, each its
            // own core.
            return CpuTopology {
                siblings: online.iter().map(|&c| vec![c]).collect(),
                cpus: online,
                from_topology: false,
            };
        }
        CpuTopology {
            cpus,
            siblings,
            from_topology,
        }
    }

    /// How many physical cores the host has (the microVM's CPU budget).
    pub fn cores(&self) -> usize {
        self.cpus.len()
    }

    /// The CPU list as it is printed (`0-23`, `0,2,4`), for a milestone a person reads.
    pub fn cpus_list(&self) -> String {
        format_cpu_list(&self.cpus)
    }

    /// The hyper-threads of the core the microVM's `i`-th CPU is on.
    pub fn siblings_of(&self, i: usize) -> &[usize] {
        self.siblings.get(i).map(Vec::as_slice).unwrap_or(&[])
    }

    /// A `cpu_set_t` for a list of CPUs, as `sched_setaffinity` wants it.
    ///
    /// `None` when the list is empty or names a CPU the kernel's set cannot hold: an
    /// affinity call with a set that means "nothing" would make the process unschedulable,
    /// which is the one mistake worth refusing here.
    pub fn set_of(cpus: &[usize]) -> Option<libc::cpu_set_t> {
        if cpus.is_empty() {
            return None;
        }
        // `cpu_set_t` is a fixed-size bit array; `CPU_SETSIZE` is the highest CPU it can name.
        let mut set: libc::cpu_set_t = unsafe { std::mem::zeroed() };
        for &cpu in cpus {
            if cpu >= libc::CPU_SETSIZE as usize {
                return None;
            }
            unsafe { libc::CPU_SET(cpu, &mut set) };
        }
        Some(set)
    }
}

/// The host's topology, read once for the process.
pub fn topology() -> &'static CpuTopology {
    static TOPOLOGY: OnceLock<CpuTopology> = OnceLock::new();
    TOPOLOGY.get_or_init(CpuTopology::detect)
}

/// **The CPUs one microVM is allowed to use.**
///
/// It is a list and never a single CPU, because a microVM is a process with a thread per vCPU
/// plus the threads that draw it, feed it and answer its network — pinning it to one CPU would
/// be pinning a desktop to one CPU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pinning {
    /// The host's physical cores, in order.
    pub cpus: Vec<usize>,
    /// The hyper-threads of each of them, in the same order.
    pub siblings: Vec<Vec<usize>>,
    /// Was the list read from the kernel's topology?  `false` means it is the online CPUs —
    /// still a usable list, and a milestone says so.
    pub from_topology: bool,
}

impl Pinning {
    /// Read the host and build the list the microVM runs on.
    pub fn detect() -> Pinning {
        Pinning::of(topology())
    }

    /// The list from an already-read topology (the tests use this).
    pub fn of(topo: &CpuTopology) -> Pinning {
        Pinning {
            cpus: topo.cpus.clone(),
            siblings: topo.siblings.clone(),
            from_topology: topo.from_topology,
        }
    }

    /// No pinning at all: the microVM is left to the host's scheduler.
    pub fn none() -> Pinning {
        Pinning {
            cpus: Vec::new(),
            siblings: Vec::new(),
            from_topology: false,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.cpus.is_empty()
    }

    /// The CPUs a guest with `vcpus` vCPUs is pinned to.
    ///
    /// One CPU per physical core, in the order the kernel lists them — and when the guest has
    /// **more** vCPUs than the host has cores, the cores' hyper-threads are used as well (a
    /// 12-core/24-thread host with a 24-vCPU guest).  `None` when there is nothing to pin to,
    /// which the caller reads as "leave it to the scheduler".
    ///
    /// Note what is *not* here: `vcpus` CPUs taken blindly from the online list.  On a
    /// hyper-threaded host that would put a 12-vCPU guest on CPUs that may be six physical
    /// cores — the shape the pinning exists to avoid.
    pub fn cpus_for(&self, vcpus: usize) -> Option<Vec<usize>> {
        if self.cpus.is_empty() || vcpus == 0 {
            return None;
        }
        if vcpus <= self.cpus.len() {
            return Some(self.cpus[..vcpus].to_vec());
        }
        // More vCPUs than cores: the guest is the host, so it gets the cores and then their
        // hyper-threads, core by core.
        let mut out = self.cpus.clone();
        for (i, core) in self.cpus.clone().iter().enumerate() {
            if out.len() >= vcpus {
                break;
            }
            if let Some(threads) = self.siblings.get(i) {
                for &t in threads.iter().filter(|&&t| t != *core) {
                    if out.len() >= vcpus {
                        break;
                    }
                    out.push(t);
                }
            }
        }
        Some(out)
    }

    /// The CPUs as a list a person reads (`0-23`).
    pub fn list(&self) -> String {
        format_cpu_list(&self.cpus)
    }
}

/// The thread ids of a process, as Linux lists them (`/proc/<pid>/task`).
///
/// The vCPU threads are named by their hypervisor (`CPU 0/KVM`, `fc_vcpu 0`), and a thread id is the only
/// `sched_setaffinity` takes for one thread of another process.
pub fn thread_ids(pid: libc::pid_t) -> Vec<libc::pid_t> {
    let mut out = Vec::new();
    if let Ok(entries) = std::fs::read_dir(format!("/proc/{pid}/task")) {
        for entry in entries.flatten() {
            if let Ok(tid) = entry.file_name().to_string_lossy().parse::<libc::pid_t>() {
                out.push(tid);
            }
        }
    }
    out.sort_unstable();
    out
}

/// Parse the kernel's CPU lists: `0,24`, `0-3`, `0-3,8,10-11`.
pub fn parse_cpu_list(text: &str) -> Vec<usize> {
    let mut out = Vec::new();
    for part in text.trim().split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        match part.split_once('-') {
            Some((a, b)) => {
                if let (Ok(a), Ok(b)) = (a.trim().parse::<usize>(), b.trim().parse::<usize>()) {
                    for n in a..=b {
                        out.push(n);
                    }
                }
            }
            None => {
                if let Ok(n) = part.parse::<usize>() {
                    out.push(n);
                }
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// Print a CPU list the way the kernel does, collapsing runs (`0-23`).
pub fn format_cpu_list(cpus: &[usize]) -> String {
    let mut nums = cpus.to_vec();
    nums.sort_unstable();
    nums.dedup();
    let mut out = String::new();
    let mut i = 0;
    while i < nums.len() {
        let start = nums[i];
        let mut end = start;
        while i + 1 < nums.len() && nums[i + 1] == end + 1 {
            i += 1;
            end = nums[i];
        }
        if !out.is_empty() {
            out.push(',');
        }
        if start == end {
            out.push_str(&start.to_string());
        } else {
            out.push_str(&format!("{start}-{end}"));
        }
        i += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    /// A scratch `/sys/devices/system/cpu` tree the test writes itself.
    struct FakeSys(PathBuf);

    impl FakeSys {
        fn new(name: &str) -> FakeSys {
            let dir = std::env::temp_dir().join(format!(
                "dc-cpu-{}-{}-{}",
                std::process::id(),
                name,
                crate::now_millis()
            ));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            FakeSys(dir)
        }

        /// Add a CPU with the given `thread_siblings_list` (no topology when `None`).
        fn cpu(&self, n: usize, siblings: Option<&str>) {
            let dir = self.0.join(format!("cpu{n}"));
            std::fs::create_dir_all(&dir).unwrap();
            match siblings {
                Some(list) => {
                    let topo = dir.join("topology");
                    std::fs::create_dir_all(&topo).unwrap();
                    std::fs::write(topo.join("thread_siblings_list"), list).unwrap();
                }
                None => std::fs::write(dir.join("online"), "1\n").unwrap(),
            }
        }

        fn topo(&self) -> CpuTopology {
            CpuTopology::from_dir(&self.0)
        }
    }

    impl Drop for FakeSys {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn the_cpu_list_parses_what_the_kernel_writes() {
        assert_eq!(parse_cpu_list("0,24\n"), vec![0, 24]);
        assert_eq!(parse_cpu_list("0-3"), vec![0, 1, 2, 3]);
        assert_eq!(parse_cpu_list("0-3,8,10-11"), vec![0, 1, 2, 3, 8, 10, 11]);
        assert_eq!(parse_cpu_list(""), Vec::<usize>::new());
        assert_eq!(format_cpu_list(&[0, 1, 2, 3, 8]), "0-3,8");
    }

    #[test]
    fn a_hyperthreaded_host_gives_one_cpu_per_physical_core() {
        // The host this project was measured on: 24 cores, threads paired (n, n+24).
        let sys = FakeSys::new("ht");
        for n in 0..48 {
            sys.cpu(n, Some(&format!("{},{}\n", n % 24, n % 24 + 24)));
        }
        let topo = sys.topo();
        assert!(topo.from_topology);
        assert_eq!(topo.cores(), 24, "{:?}", topo.cpus);
        assert_eq!(topo.cpus[0], 0);
        assert_eq!(topo.siblings_of(0), &[0, 24]);
        assert_eq!(topo.cpus_list(), "0-23");
    }

    #[test]
    fn a_host_without_hyperthreading_gives_every_cpu() {
        let sys = FakeSys::new("noht");
        for n in 0..4 {
            sys.cpu(n, Some(&format!("{n}\n")));
        }
        let topo = sys.topo();
        assert_eq!(topo.cpus, vec![0, 1, 2, 3]);
        assert_eq!(topo.siblings_of(2), &[2]);
    }

    #[test]
    fn a_missing_topology_falls_back_to_the_online_cpus() {
        let sys = FakeSys::new("bare");
        for n in 0..3 {
            sys.cpu(n, None);
        }
        let topo = sys.topo();
        assert!(!topo.from_topology);
        assert_eq!(topo.cpus, vec![0, 1, 2]);
        // Every CPU is its own group: `siblings_of` must still answer for each of them.
        assert_eq!(topo.siblings, vec![vec![0], vec![1], vec![2]]);
        assert_eq!(topo.siblings_of(2), &[2]);
    }

    #[test]
    fn a_guest_with_fewer_vcpus_than_cores_gets_cpus_of_its_own() {
        let sys = FakeSys::new("pin-few");
        for n in 0..48 {
            sys.cpu(n, Some(&format!("{},{}\n", n % 24, n % 24 + 24)));
        }
        let pin = Pinning::of(&sys.topo());
        assert_eq!(pin.cpus_for(12), Some((0..12).collect()));
        assert_eq!(pin.cpus_for(24), Some((0..24).collect()));
        assert_eq!(pin.list(), "0-23");
        // Nothing to pin to is "leave it to the scheduler", not an empty affinity.
        assert_eq!(Pinning::none().cpus_for(12), None);
        assert_eq!(pin.cpus_for(0), None);
    }

    #[test]
    fn a_guest_with_more_vcpus_than_cores_gets_the_hyperthreads_too() {
        let sys = FakeSys::new("pin-many");
        for n in 0..48 {
            sys.cpu(n, Some(&format!("{},{}\n", n % 24, n % 24 + 24)));
        }
        let pin = Pinning::of(&sys.topo());
        let cpus = pin.cpus_for(48).unwrap();
        assert_eq!(cpus.len(), 48);
        // Every physical core first, then every thread beside it: no core is left without
        // its sibling being used only after the cores.
        assert_eq!(cpus[..24], (0..24).collect::<Vec<_>>()[..]);
        assert!(cpus[24..].contains(&24) && cpus[24..].contains(&47));
    }

    #[test]
    fn a_cpu_set_is_refused_when_it_would_hold_nothing() {
        assert!(CpuTopology::set_of(&[]).is_none());
        assert!(CpuTopology::set_of(&[0]).is_some());
        assert!(CpuTopology::set_of(&[0, 3]).is_some());
        // A CPU the kernel's own set cannot hold is refused, not silently dropped.
        assert!(CpuTopology::set_of(&[libc::CPU_SETSIZE as usize]).is_none());
    }
}
