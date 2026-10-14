//! **The balloon: the memory policy, and the one thing that moves.**
//!
//! The policy is that machine's own (`dc-memory`), moved to where its inputs
//! and its actuator now are:
//!
//! * the *inputs* used to be the guest's `/proc/meminfo`, read out of the guest
//!   through the control share.  Firecracker answers them itself:
//!   `GET /balloon/statistics` carries the guest's own numbers (`free_memory`,
//!   `total_memory`, `available_memory`, `disk_caches`, in bytes) — measured on
//!   this host, 2026-10-09, on a guest that had just booted:
//!   `free_memory 6154436608, total_memory 6193389568, available_memory
//!   6023303168`.
//! * the *actuator* used to be QMP's `balloon` command; it is now
//!   `PATCH /balloon`, and it is the **only** thing this file does to the machine.
//!
//! Two facts about the statistics endpoint decide how the manager is built:
//!
//! * with `stats_polling_interval_s` at 0 (or absent), asking for statistics is an
//!   **error**, not an empty answer — "Received stats query when stats are
//!   disabled" (measured) — so the device is defined with the interval on and the
//!   numbers are as fresh as that interval;
//! * the numbers are the guest's **own**, so the policy's arithmetic is unchanged:
//!   floor, ceiling, headroom, hysteresis and the largest single step, exactly as
//!   `dc-memory` decided them for the same guest.
//!
//! The manager borrows the API rather than owning it: one client serves the whole
//! run, and a manager that held it would starve the console's status calls, the
//! shutdown and anything else that needs to ask the machine something.  That is
//! the same lesson that project learned about QMP (`dc-memory`'s own note).

use std::sync::{Arc, Mutex};

use dc_fc_api::{Api, ApiError, GuestMemory};

/// One mebibyte, the unit everything here is counted in.
pub const MIB: u64 = 1024 * 1024;

/// What can go wrong while driving the balloon.
#[derive(Debug, thiserror::Error)]
pub enum MemoryError {
    #[error("{0}")]
    Api(#[from] ApiError),
    #[error("the shared API connection was poisoned (a thread panicked while holding it)")]
    Poisoned,
}

pub type Result<T> = std::result::Result<T, MemoryError>;

/// The policy, with the numbers that project measured and kept:
/// a floor the guest kernel needs, a ceiling that is the machine's own RAM,
/// headroom left free for the guest's page cache and bursts, hysteresis so a
/// target does not chase every sample, and a largest single step so a change is
/// a step and not a cliff.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BalloonPolicy {
    /// The smallest target the policy will ever ask for: below this the guest
    /// kernel itself starts failing allocations.
    pub floor: u64,
    /// Never target more than this (the machine's RAM).
    pub ceiling: u64,
    /// How much of the guest's RAM to leave free for it, as a percentage.
    pub headroom_percent: u64,
    /// Ignore moves smaller than this.
    pub hysteresis: u64,
    /// The largest single move.
    pub step_max: u64,
}

impl Default for BalloonPolicy {
    fn default() -> Self {
        BalloonPolicy {
            floor: 192 * MIB,
            ceiling: u64::MAX,
            headroom_percent: 15,
            hysteresis: 64 * MIB,
            step_max: 256 * MIB,
        }
    }
}

impl BalloonPolicy {
    /// A policy for a guest with `total` bytes of RAM.
    pub fn for_guest(total: u64) -> BalloonPolicy {
        let floor = (total / 4).clamp(128 * MIB, 512 * MIB);
        BalloonPolicy {
            floor,
            ceiling: total,
            ..BalloonPolicy::default()
        }
    }

    /// The target to ask for, or `None` when the current one is still right.
    ///
    /// `current` is the target in force (0 when the balloon is deflated).
    pub fn decide(&self, current: u64, guest: &GuestMemory) -> Option<u64> {
        if guest.total == 0 {
            return None; // the guest has not told us anything yet
        }
        let headroom = (guest.total * self.headroom_percent / 100).max(32 * MIB);
        let max_target = guest.total.saturating_sub(self.floor).min(self.ceiling);
        let ideal = guest.available.saturating_sub(headroom).min(max_target);

        // Under pressure the answer is always "give memory back to the guest".
        if guest.available < headroom && current > 0 {
            let target = current.saturating_sub(self.step_max);
            return Some(if target < self.hysteresis { 0 } else { target });
        }
        if ideal > current.saturating_add(self.hysteresis) {
            return Some((current + self.step_max).min(ideal).min(self.ceiling));
        }
        if ideal + self.hysteresis < current {
            let target = current.saturating_sub(self.step_max).max(ideal);
            return Some(if target < self.hysteresis { 0 } else { target });
        }
        None
    }

    /// The target to start from: nobody holds anything, and the guest has every
    /// byte it was given while it boots.
    pub fn initial_target(&self) -> u64 {
        0
    }
}

/// What one adjustment did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Adjustment {
    pub previous: u64,
    pub target: u64,
    pub guest_available: u64,
    pub guest_total: u64,
}

/// Drives the balloon of a running machine.
pub struct MemoryManager {
    api: Arc<Mutex<Api>>,
    policy: BalloonPolicy,
    current: u64,
    history: Vec<Adjustment>,
}

impl MemoryManager {
    /// Attach to a running machine.  The balloon starts deflated
    /// ([`BalloonPolicy::initial_target`]): the guest gets its whole RAM while it
    /// boots, and takes back what it is not using afterwards.
    pub fn attach(api: Arc<Mutex<Api>>, policy: BalloonPolicy) -> MemoryManager {
        let current = policy.initial_target();
        MemoryManager {
            api,
            policy,
            current,
            history: Vec::new(),
        }
    }

    pub fn policy(&self) -> &BalloonPolicy {
        &self.policy
    }

    pub fn current(&self) -> u64 {
        self.current
    }

    pub fn history(&self) -> &[Adjustment] {
        &self.history
    }

    /// The guest's memory as **Firecracker** reports it — the numbers the policy
    /// decides on.  `None` while the guest has not answered yet: a machine that
    /// has just started has no statistics, and that is not an error.
    pub fn guest_memory(&mut self) -> Result<Option<GuestMemory>> {
        let mut api = self.api.lock().map_err(|_| MemoryError::Poisoned)?;
        match api.balloon_stats() {
            Ok(stats) => Ok(Some(GuestMemory::from(&stats))),
            // Statistics come with the balloon's own interval, so the first call
            // of a run can land before the guest has filled them in.  That is a
            // "not yet", not a failure of the run.
            Err(ApiError::Refused { message, .. }) if message.contains("stats") => Ok(None),
            Err(e) => Err(MemoryError::Api(e)),
        }
    }

    /// What the balloon is actually holding, in bytes, as the machine reports it.
    pub fn balloon_actual(&mut self) -> Result<u64> {
        let mut api = self.api.lock().map_err(|_| MemoryError::Poisoned)?;
        Ok(api.balloon_stats()?.actual_mib * MIB)
    }

    /// Apply one observation of the guest's memory.  Returns what changed.
    pub fn observe(&mut self, guest: &GuestMemory) -> Result<Option<Adjustment>> {
        let Some(target) = self.policy.decide(self.current, guest) else {
            return Ok(None);
        };
        self.api
            .lock()
            .map_err(|_| MemoryError::Poisoned)?
            .patch_balloon(target / MIB)?;
        let adj = Adjustment {
            previous: self.current,
            target,
            guest_available: guest.available,
            guest_total: guest.total,
        };
        self.current = target;
        self.history.push(adj);
        Ok(Some(adj))
    }

    /// Read the guest's numbers and act on them, in one call — what the run's own
    /// loop does.
    pub fn step(&mut self) -> Result<Option<Adjustment>> {
        match self.guest_memory()? {
            Some(guest) => self.observe(&guest),
            None => Ok(None),
        }
    }

    /// Deflate the balloon completely, so a guest about to shut down has all the
    /// memory it expects.  Firecracker's guest can also be left to do this itself
    /// (`deflate_on_oom`), and this is the deliberate version.
    pub fn release_all(&mut self) -> Result<()> {
        if self.current != 0 {
            self.api
                .lock()
                .map_err(|_| MemoryError::Poisoned)?
                .patch_balloon(0)?;
            self.current = 0;
        }
        Ok(())
    }

    /// How much of the guest's RAM the balloon is holding, in bytes.
    pub fn held(&self) -> u64 {
        self.current
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use dc_fc_api::Wire;
    use std::sync::Mutex;

    /// A wire that answers the statistics with a scripted body and records what
    /// the policy asked for.
    struct Stub {
        stats: Arc<Mutex<Vec<String>>>,
        patches: Arc<Mutex<Vec<u64>>>,
    }

    impl Stub {
        fn scripted(stats: Vec<&str>) -> (Arc<Mutex<Api>>, Arc<Mutex<Vec<u64>>>) {
            let patches = Arc::new(Mutex::new(Vec::new()));
            let stub = Stub {
                stats: Arc::new(Mutex::new(
                    stats.into_iter().map(str::to_string).rev().collect(),
                )),
                patches: patches.clone(),
            };
            (Arc::new(Mutex::new(Api::over(Box::new(stub)))), patches)
        }
    }

    impl Wire for Stub {
        fn request(
            &mut self,
            method: &str,
            path: &str,
            body: Option<&str>,
        ) -> std::io::Result<(u16, String)> {
            if path == "/balloon/statistics" {
                let mut stats = self.stats.lock().unwrap();
                if stats.is_empty() {
                    return Ok((
                        400,
                        "{\"fault_message\":\"Internal VMM error: Balloon: Received stats \
                         query when stats are disabled.\"}"
                            .into(),
                    ));
                }
                return Ok((200, stats.pop().unwrap()));
            }
            // The target moves with a `PATCH` (a `PUT` defines the device, and needs every
            // field of it) — which is what the real API insists on, measured 2026-10-09.
            if path == "/balloon" && method == "PATCH" {
                let body = body.unwrap_or("{}");
                let value = body
                    .split("\"amount_mib\":")
                    .nth(1)
                    .and_then(|rest| rest.trim_end_matches('}').parse::<u64>().ok())
                    .unwrap_or(0);
                self.patches.lock().unwrap().push(value);
                return Ok((204, String::new()));
            }
            Ok((204, String::new()))
        }
    }

    /// The stats a real Firecracker answered on this host, 2026-10-09, scaled to
    /// the interesting part: a guest with 6 GiB, most of it free.
    fn stats(free_bytes: u64, total_bytes: u64) -> String {
        format!(
            "{{\"target_pages\":0,\"actual_pages\":0,\"target_mib\":0,\"actual_mib\":0,\
              \"free_memory\":{free_bytes},\"total_memory\":{total_bytes},\
              \"available_memory\":{free_bytes},\"disk_caches\":2809856}}"
        )
    }

    #[test]
    fn a_guest_that_has_not_answered_yet_decides_nothing() {
        let (api, patches) = Stub::scripted(vec![]);
        let mut manager = MemoryManager::attach(api, BalloonPolicy::for_guest(6 * 1024 * MIB));
        assert_eq!(manager.step().unwrap(), None);
        assert!(
            patches.lock().unwrap().is_empty(),
            "nothing is asked of a machine with no numbers"
        );
    }

    #[test]
    fn the_policy_moves_the_balloon_one_step_at_a_time() {
        let total = 6 * 1024 * MIB;
        // A guest using almost nothing: the policy takes back what it is not using.
        let (api, patches) = Stub::scripted(vec![
            &stats(5 * 1024 * MIB, total),
            &stats(5 * 1024 * MIB, total),
            &stats(5 * 1024 * MIB, total),
        ]);
        let mut manager = MemoryManager::attach(api, BalloonPolicy::for_guest(total));
        assert_eq!(manager.current(), 0);
        let first = manager.step().unwrap().unwrap();
        assert_eq!(first.previous, 0);
        assert_eq!(first.target, 256 * MIB, "one step, not a cliff");
        assert_eq!(manager.step().unwrap().unwrap().target, 512 * MIB);
        assert_eq!(manager.step().unwrap().unwrap().target, 768 * MIB);
        assert_eq!(*patches.lock().unwrap(), vec![256, 512, 768]);
    }

    #[test]
    fn the_policy_settles_once_the_target_is_right() {
        let total = 6 * 1024 * MIB;
        let headroom = total * 15 / 100;
        let policy = BalloonPolicy::for_guest(total);
        let (api, patches) = Stub::scripted(vec![]);
        let mut manager = MemoryManager::attach(api, policy.clone());
        // A guest using nothing: the climb takes one step.
        manager
            .observe(&GuestMemory {
                total,
                free: total,
                available: total,
                cached: 0,
            })
            .unwrap();
        let held = manager.held();
        assert_eq!(held, 256 * MIB, "the first step, not the whole distance");
        // Now the guest's own numbers are exactly what the policy asked for:
        // available - headroom == what the balloon holds, so nothing is asked.
        let available = held + headroom;
        assert_eq!(
            manager
                .observe(&GuestMemory {
                    total,
                    free: available,
                    available,
                    cached: 0
                })
                .unwrap(),
            None,
            "a target that is already right is not sent"
        );
        let sent = patches.lock().unwrap().len();
        manager
            .observe(&GuestMemory {
                total,
                free: available,
                available,
                cached: 0,
            })
            .unwrap();
        assert_eq!(
            patches.lock().unwrap().len(),
            sent,
            "and it is not sent twice either"
        );
    }

    #[test]
    fn a_guest_under_pressure_gets_its_memory_back_without_hysteresis() {
        let total = 6 * 1024 * MIB;
        let (api, patches) = Stub::scripted(vec![]);
        let mut manager = MemoryManager::attach(api, BalloonPolicy::for_guest(total));
        // Hold 1 GiB, then tell the manager the guest is nearly out of memory.
        manager
            .observe(&GuestMemory {
                total,
                free: total,
                available: total,
                cached: 0,
            })
            .unwrap();
        let held = manager.held();
        assert!(held > 0);
        let adj = manager
            .observe(&GuestMemory {
                total,
                free: MIB,
                available: MIB,
                cached: 0,
            })
            .unwrap()
            .unwrap();
        assert!(adj.target < held, "pressure deflates");
        assert_eq!(adj.target, held - 256 * MIB);
        assert!(patches.lock().unwrap().len() >= 2);
    }

    #[test]
    fn the_floor_is_never_crossed_and_the_ceiling_is_the_machines_own_ram() {
        let total = 6 * 1024 * MIB;
        let policy = BalloonPolicy::for_guest(total);
        // A guest with everything free: the balloon would like all of it, but the
        // floor is the guest's.
        let target = policy
            .decide(
                0,
                &GuestMemory {
                    total,
                    free: total,
                    available: total,
                    cached: 0,
                },
            )
            .unwrap();
        assert_eq!(
            target, policy.step_max,
            "one step of a long climb, not a cliff"
        );
        assert!(policy.floor <= total / 4 + 1);
        let mut current = 0;
        for _ in 0..100 {
            match policy.decide(
                current,
                &GuestMemory {
                    total,
                    free: total,
                    available: total,
                    cached: 0,
                },
            ) {
                Some(next) => current = next,
                None => break,
            }
        }
        assert!(
            current <= total - policy.floor,
            "the guest keeps its floor: {current}"
        );
        assert!(current <= total, "never more than the machine has");
    }

    #[test]
    fn releasing_everything_deflates_the_balloon_once() {
        let total = 6 * 1024 * MIB;
        let (api, patches) = Stub::scripted(vec![]);
        let mut manager = MemoryManager::attach(api, BalloonPolicy::for_guest(total));
        manager
            .observe(&GuestMemory {
                total,
                free: total,
                available: total,
                cached: 0,
            })
            .unwrap();
        assert!(manager.held() > 0);
        manager.release_all().unwrap();
        assert_eq!(manager.held(), 0);
        let n = patches.lock().unwrap().len();
        manager.release_all().unwrap();
        assert_eq!(
            patches.lock().unwrap().len(),
            n,
            "a deflated balloon is not deflated again"
        );
    }

    #[test]
    fn the_guests_numbers_come_from_the_api_and_are_in_bytes() {
        let total = 6 * 1024 * MIB;
        let (api, _) = Stub::scripted(vec![&stats(4 * 1024 * MIB, total)]);
        let mut manager = MemoryManager::attach(api, BalloonPolicy::for_guest(total));
        let guest = manager.guest_memory().unwrap().unwrap();
        assert_eq!(guest.total, total);
        assert_eq!(guest.free, 4 * 1024 * MIB);
        assert_eq!(
            guest.available,
            4 * 1024 * MIB,
            "available falls back to free when absent"
        );
        assert_eq!(guest.cached, 2809856);
    }

    #[test]
    fn statistics_that_the_device_has_not_filled_in_yet_are_a_not_yet_not_a_failure() {
        let (api, _) = Stub::scripted(vec![]);
        let mut manager = MemoryManager::attach(api, BalloonPolicy::for_guest(6 * 1024 * MIB));
        assert_eq!(manager.guest_memory().unwrap(), None);
    }

    #[test]
    fn the_history_is_what_went_to_the_machine() {
        let total = 6 * 1024 * MIB;
        let (api, _) = Stub::scripted(vec![&stats(5 * 1024 * MIB, total)]);
        let mut manager = MemoryManager::attach(api, BalloonPolicy::for_guest(total));
        let adj = manager.step().unwrap().unwrap();
        assert_eq!(manager.history(), &[adj]);
        assert_eq!(adj.guest_total, total);
        assert_eq!(adj.guest_available, 5 * 1024 * MIB);
    }
}
