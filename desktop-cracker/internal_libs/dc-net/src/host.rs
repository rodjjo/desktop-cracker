//! What a machine may **not** reach: the host's own network.
//!
//! A machine's traffic leaves the relay as ordinary host sockets, so without a policy the guest could
//! dial anything this process can — the host's loopback services (this process's own API among
//! them), the operator's LAN, a neighbour's printer. The machines are meant to have the **internet**
//! and their own peers, and nothing else on this host: this is the refusal, kept in one place so it can
//! be read in one sitting.
//!
//! The list is discovered, not guessed: `getifaddrs` at startup gives the host's own addresses *and*
//! the subnets they are attached to (the LAN is refused as a LAN, not address by address), and the
//! ranges that are local by definition — loopback, link-local, multicast, broadcast — are always
//! refused. A deployment behind a router still reaches the internet, because a public destination is
//! not in any of those.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// The host's own addresses and subnets, in a form the hot path can ask once per flow.
#[derive(Debug, Default)]
pub struct HostGuard {
    /// `(address, prefix length)` for every IPv4 address of this host, and every subnet it sits on.
    v4: Vec<(Ipv4Addr, u8)>,
    /// The same for IPv6.
    v6: Vec<(Ipv6Addr, u8)>,
    /// Addresses that are local by definition, whatever the interfaces say.
    fixed4: HashSet<Ipv4Addr>,
    fixed6: HashSet<Ipv6Addr>,
}

impl HostGuard {
    /// The host's network as it is right now.
    ///
    /// Called once per process: interfaces do not change under a running deployment in any way this
    /// policy needs to notice, and a guest connection is not the place to enumerate them.
    pub fn discover() -> HostGuard {
        let mut guard = HostGuard::default();
        // Local by definition, and refused whether or not an interface currently carries them.
        for address in [
            Ipv4Addr::new(0, 0, 0, 0),
            Ipv4Addr::new(127, 0, 0, 1),
            Ipv4Addr::BROADCAST,
        ] {
            guard.fixed4.insert(address);
        }
        guard.fixed6.insert(Ipv6Addr::LOCALHOST);
        guard.fixed6.insert(Ipv6Addr::UNSPECIFIED);
        guard.discover_interfaces();
        guard
    }

    /// A guard with nothing in it: what a test that is about the byte path uses.
    pub fn none() -> HostGuard {
        HostGuard::default()
    }

    /// Whether `ip` is this host (or a network this host is on) and must not be dialed by a guest.
    pub fn refuses(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(address) => self.refuses4(address),
            IpAddr::V6(address) => self.refuses6(address),
        }
    }

    fn refuses4(&self, address: Ipv4Addr) -> bool {
        if address.is_loopback()
            || address.is_link_local()
            || address.is_multicast()
            || address.is_broadcast()
        {
            return true;
        }
        if self.fixed4.contains(&address) || address.octets()[0] == 0 {
            return true;
        }
        self.v4
            .iter()
            .any(|(network, prefix)| in_prefix4(address, *network, *prefix))
    }

    fn refuses6(&self, address: Ipv6Addr) -> bool {
        if address.is_loopback() || address.is_unspecified() || address.is_multicast() {
            return true;
        }
        // `fe80::/10`: link-local, which on this host means this process's own conduit peers.
        let segments = address.segments();
        if segments[0] & 0xffc0 == 0xfe80 {
            return true;
        }
        self.fixed6.contains(&address)
            || self
                .v6
                .iter()
                .any(|(network, prefix)| in_prefix6(address, *network, *prefix))
    }

    /// Every address of this host and the subnet it is attached to, read from the kernel.
    #[cfg(target_os = "linux")]
    fn discover_interfaces(&mut self) {
        // SAFETY: `getifaddrs` fills a list we own and that we hand back to `freeifaddrs`; each entry is
        // read only while the list is alive, and the sockaddr is checked for its family before it is cast.
        unsafe {
            let mut head: *mut libc::ifaddrs = std::ptr::null_mut();
            if libc::getifaddrs(&mut head) != 0 || head.is_null() {
                return;
            }
            let mut entry = head;
            while !entry.is_null() {
                let address = (*entry).ifa_addr;
                let netmask = (*entry).ifa_netmask;
                if !address.is_null() {
                    match i32::from((*address).sa_family) {
                        libc::AF_INET => {
                            let address = sockaddr_v4(address);
                            self.v4.push((address, prefix4(netmask)));
                            self.fixed4.insert(address);
                        }
                        libc::AF_INET6 => {
                            let address = sockaddr_v6(address);
                            self.v6.push((address, prefix6(netmask)));
                            self.fixed6.insert(address);
                        }
                        _ => {}
                    }
                }
                entry = (*entry).ifa_next;
            }
            libc::freeifaddrs(head);
        }
    }

    /// Off Linux there is nothing to enumerate; the fixed ranges above are all that is refused.
    #[cfg(not(target_os = "linux"))]
    fn discover_interfaces(&mut self) {}
}

/// Read an `AF_INET` `sockaddr` as an address.
///
/// SAFETY: the caller guarantees `address` points at an `AF_INET` `sockaddr` from a live `getifaddrs`
/// list, which is the only thing this is ever called with.
#[cfg(target_os = "linux")]
fn sockaddr_v4(address: *const libc::sockaddr) -> Ipv4Addr {
    let address = unsafe { &*(address as *const libc::sockaddr_in) };
    Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr))
}

/// Read an `AF_INET6` `sockaddr` as an address.
///
/// SAFETY: as [`sockaddr_v4`], for an `AF_INET6` entry of the same list.
#[cfg(target_os = "linux")]
fn sockaddr_v6(address: *const libc::sockaddr) -> Ipv6Addr {
    let address = unsafe { &*(address as *const libc::sockaddr_in6) };
    Ipv6Addr::from(address.sin6_addr.s6_addr)
}

/// The prefix length a netmask means (`255.255.0.0` → `/16`).
#[cfg(target_os = "linux")]
fn prefix4(netmask: *const libc::sockaddr) -> u8 {
    if netmask.is_null() {
        return 32;
    }
    // SAFETY: an `AF_INET` netmask from the same live list.
    let mask = u32::from_be(unsafe { (*(netmask as *const libc::sockaddr_in)).sin_addr.s_addr });
    mask.leading_ones() as u8
}

/// The prefix length an IPv6 netmask means.
#[cfg(target_os = "linux")]
fn prefix6(netmask: *const libc::sockaddr) -> u8 {
    if netmask.is_null() {
        return 128;
    }
    // SAFETY: an `AF_INET6` netmask from the same live list.
    let mask =
        u128::from_be_bytes(unsafe { (*(netmask as *const libc::sockaddr_in6)).sin6_addr.s6_addr });
    mask.leading_ones() as u8
}

/// Whether an IPv4 address is inside a network.
fn in_prefix4(address: Ipv4Addr, network: Ipv4Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    let mask = if prefix >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix as u32)
    };
    (u32::from(address) & mask) == (u32::from(network) & mask)
}

/// The same for IPv6.
fn in_prefix6(address: Ipv6Addr, network: Ipv6Addr, prefix: u8) -> bool {
    if prefix == 0 {
        return true;
    }
    let mask = if prefix >= 128 {
        u128::MAX
    } else {
        u128::MAX << (128 - prefix as u32)
    };
    (u128::from(address) & mask) == (u128::from(network) & mask)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hosts_own_ranges_are_refused_and_the_internet_is_not() {
        let guard = HostGuard::discover();
        for local in [
            "127.0.0.1",
            "127.9.9.9",
            "169.254.1.1",
            "0.0.0.0",
            "224.0.0.251",
            "255.255.255.255",
        ] {
            assert!(
                guard.refuses(local.parse().unwrap()),
                "{local} is this host's own network"
            );
        }
        // ::1 and fe80::/10 are the host's own; a public v6 address is not.
        assert!(guard.refuses("::1".parse().unwrap()));
        assert!(guard.refuses("fe80::1".parse().unwrap()));
        assert!(!guard.refuses("2606:4700:4700::1111".parse().unwrap()));
        // The subnets this host is on are refused as subnets, not address by address.
        for (network, prefix) in &guard.v4 {
            assert!(
                guard.refuses(IpAddr::V4(Ipv4Addr::from(u32::from(*network) | 1))),
                "{network}/{prefix}"
            );
        }
        // A public address is reachable: the machines keep the internet.
        for public in ["1.1.1.1", "8.8.8.8", "93.184.216.34"] {
            assert!(
                !guard.refuses(public.parse().unwrap()),
                "{public} is not on this host"
            );
        }
    }

    #[test]
    fn a_prefix_membership_is_exact() {
        let network: Ipv4Addr = "192.168.50.0".parse().unwrap();
        assert!(in_prefix4("192.168.50.160".parse().unwrap(), network, 24));
        assert!(!in_prefix4("192.168.51.1".parse().unwrap(), network, 24));
        assert!(
            in_prefix4("10.0.0.1".parse().unwrap(), network, 0),
            "a /0 is everything"
        );
    }
}
