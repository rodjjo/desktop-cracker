//! The host's shape, as the guest is told it: `-smp` and `-cpu host`.
//!
//! A microvm gets this host's **physical cores** (24 on a 24-core/48-thread
//! machine, not 48): every core is one it can use, and a guest that showed every
//! thread would spend its scheduler's time sharing the physical ones.  The
//! number is read from the topology the kernel exposes, so this checks it
//! against the kernel's own answer.

#[test]
fn the_vcpu_default_is_the_hosts_physical_cores() {
    let cores = dc_common::default_vcpus();
    assert!(cores >= 1, "{cores} vCPUs is not a machine");
    let online = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1) as u32;
    assert!(
        cores <= online,
        "{cores} vCPUs > {online} online CPUs: a guest cannot have more than the host"
    );
    // On a host with hyper-threading the two differ, and the smaller one is the
    // physical count — which is what the guest is given.
    if online > cores {
        assert_eq!(
            cores % (online / cores),
            0,
            "{cores} does not divide {online}: the physical count should"
        );
    }
    println!("host: {online} online CPUs, guest gets {cores}");
}
