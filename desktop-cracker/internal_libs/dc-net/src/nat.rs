//! The built-in NAT table: every association that crosses between the guest subnet and the host.
//!
//! This process is the router between two worlds: the machines live in a private subnet that
//! exists on **no interface**, and this process reaches the real network by opening ordinary host
//! sockets.  Every one of those crossings is an entry here, whichever direction it started:
//!
//! | who started it | the entry | what it carries |
//! |---|---|---|
//! | a guest (`connect()`/`sendto`) | `Outbound`, with the socket we opened for it | replies back to the guest, from the address it asked for |
//! | the operator's port mapping (`ports`) | `Inbound`, with the **listening socket** and its host port | so the guest's reply leaves through the same host port the sender wrote to — a datagram to a UDP mapping and a connection to a TCP one both need this |
//! | one machine to another | no entry: the frame is forwarded to the peer's conduit (guest↔guest never leaves this process) |
//!
//! Two things make the table more than bookkeeping:
//!
//! * **It is the reply path.** A guest replying to a datagram that arrived on a mapped port must not
//!   open a fresh host socket: the remote is watching the mapped port, and a reply from an ephemeral
//!   one is dropped (or, worse, looks like a different flow). The table remembers which socket a
//!   `(guest port, remote)` pair belongs to.
//! * **It is the answer to "what is this machine talking to?"** — the status carries its summary, and a
//!   table that is full refuses new flows with a counter rather than growing without bound.
//!
//! Entries expire: UDP associations after an idle timeout (a DNS lookup's socket must not live
//! forever), TCP ones when their flow ends or after a longer idle period (a half-open connection that
//! nobody closed is the classic leak).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// The transport of a NAT entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NatProto {
    /// A stream association (one host connection).
    Tcp,
    /// A datagram association (many datagrams, one socket).
    Udp,
}

/// Who started the association.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NatDirection {
    /// A guest connected out: this process opened the host socket.
    Outbound,
    /// The operator's port mapping accepted a connection or datagram: the host side came to us.
    Inbound,
}

/// What an entry is keyed by: which guest port, talking to which address.
///
/// The guest's **own address** is deliberately not part of the key: a machine has one conduit and one
/// lease, so its port plus the remote address identifies the association, and including the address
/// would only make a re-lease look like a different flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NatKey {
    /// The transport.
    pub proto: NatProto,
    /// The guest's port (the source of an outbound flow, the destination of an inbound one).
    pub guest_port: u16,
    /// The address on the host's side of the crossing.
    pub remote: SocketAddr,
}

impl NatKey {
    /// An outbound key.
    pub fn outbound(proto: NatProto, guest_port: u16, remote: SocketAddr) -> NatKey {
        NatKey {
            proto,
            guest_port,
            remote,
        }
    }

    /// An inbound key: the guest port the mapping forwards to, and the sender that arrived.
    pub fn inbound(proto: NatProto, guest_port: u16, remote: SocketAddr) -> NatKey {
        NatKey {
            proto,
            guest_port,
            remote,
        }
    }
}

/// One association.
pub struct NatEntry {
    /// What it is keyed by.
    pub key: NatKey,
    /// Who started it.
    pub direction: NatDirection,
    /// The host port the operator mapped, for an inbound entry (the port the sender wrote to).
    pub host_port: Option<u16>,
    /// The datagram socket that carries this association, when it is UDP: ours for an outbound flow,
    /// the **mapping's** for an inbound one (which is the whole point — the reply must leave from the
    /// mapped port).
    pub socket: Option<Arc<std::net::UdpSocket>>,
    /// When it was opened.
    pub created: Instant,
    /// When it last carried anything.
    pub last_seen: Instant,
    /// How many packets have crossed.
    pub packets: u64,
    /// How many bytes have crossed.
    pub bytes: u64,
}

impl NatEntry {
    /// How long it has been idle.
    pub fn idle(&self, now: Instant) -> Duration {
        now.saturating_duration_since(self.last_seen)
    }
}

/// A summary of the table, for a status.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize)]
pub struct NatSnapshot {
    /// Every live association.
    pub total: usize,
    /// The stream ones.
    pub tcp: usize,
    /// The datagram ones.
    pub udp: usize,
    /// The ones a guest started.
    pub outbound: usize,
    /// The ones a port mapping started.
    pub inbound: usize,
    /// Packets carried by the live associations.
    pub packets: u64,
    /// Bytes carried by them.
    pub bytes: u64,
    /// Associations expired for being idle, over the table's lifetime.
    pub expired: u64,
    /// Associations refused because the table was full, over its lifetime.
    pub refused: u64,
}

/// The table itself: a bounded map with idle expiry and a running tally.
pub struct NatTable {
    entries: HashMap<NatKey, NatEntry>,
    limit: usize,
    udp_timeout: Duration,
    tcp_timeout: Duration,
    expired: u64,
    refused: u64,
}

impl NatTable {
    /// A table that holds at most `limit` associations; a UDP one expires after `udp_timeout` idle and
    /// a TCP one after `tcp_timeout`.
    pub fn new(limit: usize, udp_timeout: Duration, tcp_timeout: Duration) -> Self {
        NatTable {
            entries: HashMap::new(),
            limit: limit.max(1),
            udp_timeout,
            tcp_timeout,
            expired: 0,
            refused: 0,
        }
    }

    /// How many associations are live.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the table is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Record a new association, or refresh one that already exists.
    ///
    /// An existing entry is **kept**, not replaced: the socket it holds is the reply path, and a second
    /// datagram from the same remote must not move the association to a new socket. `Err` means the
    /// table is full.
    pub fn open(
        &mut self,
        key: NatKey,
        direction: NatDirection,
        host_port: Option<u16>,
        socket: Option<Arc<std::net::UdpSocket>>,
    ) -> Result<(), String> {
        if let Some(entry) = self.entries.get_mut(&key) {
            entry.last_seen = Instant::now();
            entry.packets += 1;
            if socket.is_some() && entry.socket.is_none() {
                entry.socket = socket;
            }
            return Ok(());
        }
        if self.entries.len() >= self.limit {
            self.refused += 1;
            return Err(format!(
                "the NAT table is full ({} associations): close a machine or raise --vm-max-flows",
                self.limit
            ));
        }
        let now = Instant::now();
        self.entries.insert(
            key,
            NatEntry {
                key,
                direction,
                host_port,
                socket,
                created: now,
                last_seen: now,
                packets: 1,
                bytes: 0,
            },
        );
        Ok(())
    }

    /// One association.
    pub fn entry(&self, key: &NatKey) -> Option<&NatEntry> {
        self.entries.get(key)
    }

    /// Count one packet of `bytes` against an association; `false` when it is not there.
    pub fn touch(&mut self, key: &NatKey, bytes: u64) -> bool {
        match self.entries.get_mut(key) {
            Some(entry) => {
                entry.last_seen = Instant::now();
                entry.packets += 1;
                entry.bytes += bytes;
                true
            }
            None => false,
        }
    }

    /// Take an association away (a flow that ended, a mapping that closed).
    pub fn close(&mut self, key: &NatKey) -> Option<NatEntry> {
        self.entries.remove(key)
    }

    /// Drop the associations that have been idle past their timeout, and answer which they were (so
    /// the caller can let their sockets go).
    pub fn expire(&mut self, now: Instant) -> Vec<NatKey> {
        let limit = self.udp_timeout.max(self.tcp_timeout);
        let _ = limit;
        let mut gone = Vec::new();
        self.entries.retain(|key, entry| {
            let timeout = match key.proto {
                NatProto::Udp => self.udp_timeout,
                NatProto::Tcp => self.tcp_timeout,
            };
            if entry.idle(now) >= timeout {
                gone.push(*key);
                false
            } else {
                true
            }
        });
        self.expired += gone.len() as u64;
        gone
    }

    /// Every live association (a status, and a test's assertion).
    pub fn entries(&self) -> Vec<&NatEntry> {
        self.entries.values().collect()
    }

    /// The summary a status carries.
    pub fn snapshot(&self) -> NatSnapshot {
        let mut snapshot = NatSnapshot {
            total: self.entries.len(),
            expired: self.expired,
            refused: self.refused,
            ..NatSnapshot::default()
        };
        for entry in self.entries.values() {
            match entry.key.proto {
                NatProto::Tcp => snapshot.tcp += 1,
                NatProto::Udp => snapshot.udp += 1,
            }
            match entry.direction {
                NatDirection::Outbound => snapshot.outbound += 1,
                NatDirection::Inbound => snapshot.inbound += 1,
            }
            snapshot.packets += entry.packets;
            snapshot.bytes += entry.bytes;
        }
        snapshot
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from((Ipv4Addr::new(93, 184, 216, 34), port))
    }

    fn key(guest_port: u16, remote_port: u16) -> NatKey {
        NatKey::outbound(NatProto::Udp, guest_port, addr(remote_port))
    }

    #[test]
    fn an_association_is_recorded_and_counted() {
        let mut table = NatTable::new(8, Duration::from_secs(120), Duration::from_secs(600));
        assert!(table.is_empty());
        table
            .open(key(40000, 53), NatDirection::Outbound, None, None)
            .expect("open");
        assert!(table.touch(&key(40000, 53), 64));
        let entry = table.entry(&key(40000, 53)).expect("the entry");
        assert_eq!(entry.direction, NatDirection::Outbound);
        assert_eq!(entry.packets, 2, "the open counts as the first packet");
        assert_eq!(entry.bytes, 64);
        assert_eq!(entry.key.remote, addr(53));
        let snapshot = table.snapshot();
        assert_eq!(snapshot.total, 1);
        assert_eq!(snapshot.udp, 1);
        assert_eq!(snapshot.outbound, 1);
        assert_eq!(snapshot.inbound, 0);
        assert_eq!(snapshot.bytes, 64);
    }

    #[test]
    fn a_second_packet_keeps_the_socket_the_association_started_with() {
        // The reply path must not move: a datagram socket that a mapping owns stays the one the
        // association uses.
        let mut table = NatTable::new(4, Duration::from_secs(120), Duration::from_secs(600));
        let first = Arc::new(std::net::UdpSocket::bind(("127.0.0.1", 0)).expect("a socket"));
        let second = Arc::new(std::net::UdpSocket::bind(("127.0.0.1", 0)).expect("a socket"));
        table
            .open(
                key(53, 4444),
                NatDirection::Inbound,
                Some(5300),
                Some(Arc::clone(&first)),
            )
            .expect("open");
        table
            .open(
                key(53, 4444),
                NatDirection::Inbound,
                Some(5300),
                Some(Arc::clone(&second)),
            )
            .expect("refresh");
        let entry = table.entry(&key(53, 4444)).expect("the entry");
        assert!(
            Arc::ptr_eq(entry.socket.as_ref().expect("a socket"), &first),
            "the first socket stays"
        );
        assert_eq!(entry.host_port, Some(5300), "the mapped port is remembered");
        assert_eq!(entry.packets, 2, "and the second packet was counted");
    }

    #[test]
    fn an_inbound_and_an_outbound_association_to_the_same_place_are_different_entries() {
        let mut table = NatTable::new(8, Duration::from_secs(120), Duration::from_secs(600));
        table
            .open(key(53, 4444), NatDirection::Inbound, Some(5300), None)
            .expect("inbound");
        table
            .open(key(5353, 4444), NatDirection::Outbound, None, None)
            .expect("outbound");
        assert_eq!(table.len(), 2);
        let snapshot = table.snapshot();
        assert_eq!(snapshot.inbound, 1);
        assert_eq!(snapshot.outbound, 1);
    }

    #[test]
    fn a_full_table_refuses_and_says_so() {
        let mut table = NatTable::new(2, Duration::from_secs(120), Duration::from_secs(600));
        table
            .open(key(1, 1), NatDirection::Outbound, None, None)
            .expect("first");
        table
            .open(key(2, 2), NatDirection::Outbound, None, None)
            .expect("second");
        let refused = table
            .open(key(3, 3), NatDirection::Outbound, None, None)
            .unwrap_err();
        assert!(refused.contains("NAT table is full"), "{refused}");
        assert_eq!(table.len(), 2, "nothing was evicted for it");
        assert_eq!(table.snapshot().refused, 1, "and the refusal is counted");
        // Refreshing an existing association is not a new one, so a full table still works for them.
        table
            .open(key(1, 1), NatDirection::Outbound, None, None)
            .expect("a refresh fits");
    }

    #[test]
    fn an_idle_association_expires_and_a_busy_one_does_not() {
        let mut table = NatTable::new(8, Duration::from_secs(30), Duration::from_secs(600));
        table
            .open(key(40000, 53), NatDirection::Outbound, None, None)
            .expect("udp");
        table
            .open(
                NatKey::outbound(NatProto::Tcp, 40001, addr(80)),
                NatDirection::Outbound,
                None,
                None,
            )
            .expect("tcp");

        // Nothing is idle yet.
        assert!(table.expire(Instant::now()).is_empty());

        // An hour later the UDP association is gone and the TCP one is too (600 s is shorter).
        let later = Instant::now() + Duration::from_secs(3600);
        let gone = table.expire(later);
        assert_eq!(
            gone.len(),
            2,
            "both were idle past their timeouts: {gone:?}"
        );
        assert!(table.is_empty());
        assert_eq!(table.snapshot().expired, 2);
    }

    #[test]
    fn closing_an_association_takes_it_away_without_counting_it_as_expired() {
        let mut table = NatTable::new(8, Duration::from_secs(30), Duration::from_secs(600));
        table
            .open(key(40000, 53), NatDirection::Outbound, None, None)
            .expect("open");
        let closed = table.close(&key(40000, 53)).expect("the entry came back");
        assert_eq!(closed.key, key(40000, 53));
        assert!(table.is_empty());
        assert_eq!(
            table.snapshot().expired,
            0,
            "a closed flow is not an expired one"
        );
    }
}
