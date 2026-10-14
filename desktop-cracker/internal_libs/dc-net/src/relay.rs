//! The userspace relay: a guest's flow becomes a host socket, and the bytes are carried both ways.
//!
//! There is no kernel network stack behind a socket conduit, so this
//! module *is* the guest's network:
//!
//! | the guest does | the relay does |
//! |---|---|
//! | `ARP` for the gateway, or for a peer it may reach | answers with our MAC (proxy ARP for a peer) |
//! | `ICMP` echo to the gateway | answers, with the identifier and sequence intact |
//! | `UDP` to an external address | opens a host `UdpSocket`, forwards, and carries the replies back |
//! | `UDP` to the gateway's port 53 | answers `vm-<name>` from the directory, and proxies the rest to the host's resolver |
//! | `UDP` to the gateway's port 123 | answers the time from the **host's clock**, so a guest's clock is right |
//! | `TCP` to an external address | terminates the handshake, opens a host `TcpStream`, and speaks enough TCP to carry the bytes |
//! | anything to another machine's address | forwards the **frame** to that machine's conduit (MAC rewritten), so guest↔guest is a real L2 path |
//! | a host connection through a port mapping | opens the guest side with a SYN of its own, and relays the bytes |
//! | IPv6, or an ethertype we do not implement | dropped, with a counter the status can show |
//!
//! Two design choices are worth stating, because they decide what the code looks like:
//!
//! * **A flow is a thread, not a state machine in an event loop.** One guest TCP flow is one thread
//!   that owns the host `TcpStream` plus one shared sequence record; guest payloads arrive over a
//!   channel. That is a fraction of the code a poll-based reactor needs, it cannot deadlock on a slow
//!   `connect`, and the flows are bounded ([`RelayConfig::max_flows`]). The cost is a thread per flow,
//!   which for a workspace's machines is the right trade.
//! * **Sequence handling is deliberately in-order and ACK-and-wait.** We accept the segment whose
//!   sequence is the next one, always ACK what we have, and let the guest's own stack retransmit into a
//!   gap. That is enough for a shell, a package manager or a download; it is not a TCP implementation
//!   for a hostile network, and this module says so rather than pretending.

use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::gateway::GatewayPorts;
use crate::nat::{NatDirection, NatKey, NatProto, NatSnapshot, NatTable};

/// The lifetimes we advertise for the machines' IPv6 prefix: a day, the same as the DHCPv6 lease, so
/// the two never disagree about when the prefix is stale.
const DEFAULT_V6_LIFETIME: u32 = 86_400;

/// The conduit's MTU: 1500-byte Ethernet, the only size the socketpair's frames carry.
const CONDUIT_MTU: u32 = 1500;

/// How long a flow may carry nothing at all before the relay gives up on it, in either direction.
///
/// The same ten minutes the NAT table's TCP associations expire after: a peer that vanished without a
/// FIN — a machine that was killed, a host that froze with the socket open — must not hold a flow's
/// place in the table (and its thread) for the life of the process.
const FLOW_IDLE: Duration = Duration::from_secs(600);

/// How much of an offending packet an ICMPv6 error carries back (RFC 8200 caps it so the error
/// itself stays under the minimum IPv6 MTU of 1280).
const ICMPV6_ERROR_QUOTE: usize = 1232;
use crate::frame::{
    build_arp_reply, build_ethernet, build_icmp_echo_reply, build_icmpv6, build_icmpv6_echo_reply,
    build_ipv4, build_ipv6, build_tcp, build_udp, build_udp_v6, multicast_mac, parse_arp,
    parse_ethernet, parse_icmp, parse_icmpv6, parse_ipv4, parse_ipv6, parse_tcp, parse_udp, Arp,
    Icmp, ALL_NODES_MULTICAST, ETHERTYPE_ARP, ETHERTYPE_IPV4, ETHERTYPE_IPV6, IPPROTO_ICMP,
    IPPROTO_ICMPV6, IPPROTO_TCP, IPPROTO_UDP, TCP_ACK, TCP_FIN, TCP_PSH, TCP_RST, TCP_SYN,
};
use crate::ndp;

/// How the relay writes one frame back on a conduit (the guest's, or a peer's).
pub type FrameSender = Arc<dyn Fn(Vec<u8>) + Send + Sync>;

/// Where the other machines are, and whether this one may reach them.
///
/// The engine implements this over this machine registry; the relay never knows which
/// workspace a peer belongs to, only what the directory will tell it.
pub trait PeerDirectory: Send + Sync {
    /// The MAC and the conduit of the machine that holds `ip` (IPv4 or IPv6), when `from` is allowed
    /// to reach it. `None` means "not a reachable peer" — an external address, or one the isolation
    /// rules refuse.
    fn peer_for(&self, from: &str, ip: IpAddr) -> Option<Peer>;
}

/// One reachable peer: its MAC, and how to write a frame to its conduit.
#[derive(Clone)]
pub struct Peer {
    /// The peer's MAC (the frame's destination once we forward it).
    pub mac: [u8; 6],
    /// The peer's conduit.
    pub send: FrameSender,
}

/// A directory that refuses everything: a machine with no peers.
pub struct NoPeers;

impl PeerDirectory for NoPeers {
    fn peer_for(&self, _from: &str, _ip: IpAddr) -> Option<Peer> {
        None
    }
}

/// A directory over a fixed set of peers (the engine's simple case, and the tests').
pub struct FixedPeers {
    peers: HashMap<IpAddr, Peer>,
}

impl FixedPeers {
    /// A directory from `(address, mac, sender)` triples, either family.
    pub fn new(peers: Vec<(IpAddr, [u8; 6], FrameSender)>) -> Self {
        FixedPeers {
            peers: peers
                .into_iter()
                .map(|(ip, mac, send)| (ip, Peer { mac, send }))
                .collect(),
        }
    }
}

impl PeerDirectory for FixedPeers {
    fn peer_for(&self, _from: &str, ip: IpAddr) -> Option<Peer> {
        self.peers.get(&ip).cloned()
    }
}

/// A lookup by name, for the two families: what the caller's own directory is asked.
pub type NameLookup<T> = Arc<dyn Fn(&str) -> Option<T> + Send + Sync>;

/// The names a relay answers **itself** (`vm-<name>`), one lookup per family.
///
/// The relay is not what knows a machine's address; whoever runs it is.  A query for `vm-debian`
/// is answered from here, and because a machine's IPv6 address is learned from its DHCPv6 lease,
/// the two lookups can disagree for a moment after a machine appears — which is exactly what a
/// real network does.
#[derive(Clone)]
pub struct NameDirectory {
    /// The IPv4 address of the machine whose display name slugs to the name.
    pub addr4: NameLookup<Ipv4Addr>,
    /// Its IPv6 address: the DHCPv6 lease once it has one, otherwise the link-local it forms.
    pub addr6: NameLookup<Ipv6Addr>,
}

/// The machine the relay serves, as the guest sees itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GuestIdentity {
    /// The guest's MAC.
    pub mac: [u8; 6],
    /// The guest's IPv4 address (its DHCP lease).
    pub ip: Ipv4Addr,
    /// The guest's IPv6 address: its **link-local** (the modified EUI-64 of its MAC), which every
    /// guest forms for itself and which is what an answer addressed to "the guest" starts from. A
    /// flow's real address is the one the guest used, read from its own frames.
    pub ip6: Ipv6Addr,
}

/// The relay's fixed settings.
#[derive(Debug, Clone)]
pub struct RelayConfig {
    /// Our MAC: the other end of the conduit, and the address every answer is sent from.
    pub our_mac: [u8; 6],
    /// Our address: the guest's gateway.
    pub our_ip: Ipv4Addr,
    /// The address the guest is told to use as a resolver (our own, so `vm-<name>` works).
    pub dns_ip: Ipv4Addr,
    /// Our IPv6 address on this conduit: the gateway's **link-local**, the EUI-64 of our end's MAC
    /// (`fe80::5054:ff:fe00:1`), and the address every NDP answer comes from.
    pub our_ip6: Ipv6Addr,
    /// Our **ULA** on this conduit (`fd10:177::1`, the first host of the machines' prefix): a second
    /// address we answer for, so a guest can also reach its gateway by a routable name.
    pub our_ula6: Ipv6Addr,
    /// The address the guest is told to use as a resolver over IPv6 (our link-local, so `vm-<name>`
    /// works there too).
    pub dns_ip6: Ipv6Addr,
    /// The machines' internal IPv6 prefix (`fd10:177::`), which exists on no interface either.
    pub subnet6: Ipv6Addr,
    /// Its prefix length (`64`).
    pub prefix6: u8,
    /// The subnet the peers live in (`10.177.0.0/16`).
    pub subnet: Ipv4Addr,
    /// The subnet's prefix length.
    pub prefix: u8,
    /// How long to wait for a host connection before the guest is told it failed.
    pub connect_timeout: Duration,
    /// How many flows one machine may have open at once.
    pub max_flows: usize,
    /// The host's resolvers, for the queries we do not answer ourselves (from `/etc/resolv.conf`).
    pub resolvers: Vec<SocketAddr>,
    /// The workspace's **published ports**: what a flow to our own address on one of them is
    /// carried to, and what the holder's traffic looks like coming from. Shared with every relay of the
    /// workspace, because the peer that dials and the peer that answers are different relays.
    pub gateway_ports: Arc<GatewayPorts>,
    /// The workspace this relay serves — what the ports table is keyed by.
    pub workspace: String,
    /// What a machine may **not** reach: the host's own addresses and subnets (`crate::host`, ``).
    ///
    /// `None` is "no policy" and exists for the tests that drive a guest straight at a `127.0.0.1`
    /// server to exercise the byte path; the engine always builds one with the host's real network.
    pub host_guard: Option<Arc<crate::host::HostGuard>>,
}

impl RelayConfig {
    /// Whether an IPv6 address belongs to the machines' internal subnet (another machine, not the
    /// internet).
    pub fn is_internal6(&self, ip: Ipv6Addr) -> bool {
        if self.prefix6 == 0 || self.prefix6 > 128 {
            return false;
        }
        let mask = if self.prefix6 == 128 {
            u128::MAX
        } else {
            u128::MAX << (128 - self.prefix6 as u32)
        };
        (u128::from(ip) & mask) == (u128::from(self.subnet6) & mask)
    }

    /// Whether an address belongs to our internal subnet (another machine, not the internet).
    pub fn is_internal(&self, ip: Ipv4Addr) -> bool {
        if self.prefix == 0 || self.prefix > 32 {
            return false;
        }
        let mask = u32::MAX << (32 - self.prefix as u32);
        (u32::from(ip) & mask) == (u32::from(self.subnet) & mask)
    }
}

/// What the relay has done, for the status (``: a dropped-frame counter is what makes a silent
/// guest diagnosable).
#[derive(Debug, Default)]
pub struct RelayStats {
    /// Frames that arrived from the guest.
    pub frames_in: AtomicU64,
    /// Frames written back to the guest.
    pub frames_out: AtomicU64,
    /// Frames forwarded to another machine's conduit.
    pub peers_forwarded: AtomicU64,
    /// Frames refused because the isolation rules forbid that peer.
    pub dropped_isolation: AtomicU64,
    /// IPv6 frames the relay refused: malformed or truncated, a fragment or jumbogram (there is no
    /// reassembly), an NDP message it must not answer, or a ULA no machine holds.
    pub dropped_ipv6: AtomicU64,
    /// Frames of an ethertype or protocol we do not implement.
    pub dropped_other: AtomicU64,
    /// IPv4 packets for an address in our subnet that is not a reachable machine, and echo requests
    /// to hosts we cannot reach.
    pub dropped_unreachable: AtomicU64,
    /// TCP flows opened (either direction).
    pub tcp_flows: AtomicU64,
    /// UDP flows opened.
    pub udp_flows: AtomicU64,
    /// Echo requests we answered.
    pub icmp_replies: AtomicU64,
    /// Flows refused because the machine is at `max_flows`.
    pub dropped_busy: AtomicU64,
    /// Packets of a **published port** that could not be rewritten — a fragment whose ports
    /// cannot be named — and were dropped rather than delivered with the wrong port.
    pub dropped_mapped: AtomicU64,
    /// Datagrams a port mapping carried **into** the guest.
    pub inbound_udp: AtomicU64,
    /// Flows and datagrams refused because their destination is the **host's own network** .
    pub dropped_host: AtomicU64,
    /// Echo requests dropped because this host grants no unprivileged ping socket.
    pub icmp_unavailable: AtomicU64,
    /// Associations the NAT table refused because it is full.
    pub nat_refused: AtomicU64,
    /// Associations the NAT table expired for being idle.
    pub nat_expired: AtomicU64,
    /// IPv6 frames the relay **spoke** (as opposed to the ones it refuses, `dropped_ipv6`).
    pub v6_frames: AtomicU64,
    /// Echo replies to a guest or a peer over ICMPv6.
    pub icmp6_replies: AtomicU64,
    /// Router Advertisements sent (on a solicitation, and periodically).
    pub ra_sent: AtomicU64,
    /// Neighbor Solicitations answered (for our own addresses and, as a proxy, for a peer's).
    pub ns_answered: AtomicU64,
    /// Neighbor Advertisements sent.
    pub na_sent: AtomicU64,
    /// ICMPv6 Packet-Too-Big messages sent, so a guest's own PMTUD can shrink its segments.
    pub ptb_sent: AtomicU64,
}

/// A snapshot of [`RelayStats`], for a status body.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct RelaySnapshot {
    /// See [`RelayStats::frames_in`].
    pub frames_in: u64,
    /// See [`RelayStats::frames_out`].
    pub frames_out: u64,
    /// See [`RelayStats::peers_forwarded`].
    pub peers_forwarded: u64,
    /// See [`RelayStats::dropped_isolation`].
    pub dropped_isolation: u64,
    /// See [`RelayStats::dropped_ipv6`].
    pub dropped_ipv6: u64,
    /// See [`RelayStats::dropped_other`].
    pub dropped_other: u64,
    /// See [`RelayStats::dropped_unreachable`].
    pub dropped_unreachable: u64,
    /// See [`RelayStats::tcp_flows`].
    pub tcp_flows: u64,
    /// See [`RelayStats::udp_flows`].
    pub udp_flows: u64,
    /// See [`RelayStats::icmp_replies`].
    pub icmp_replies: u64,
    /// See [`RelayStats::dropped_busy`].
    pub dropped_busy: u64,
    /// See [`RelayStats::dropped_mapped`].
    pub dropped_mapped: u64,
    /// See [`RelayStats::dropped_host`].
    pub dropped_host: u64,
    /// See [`RelayStats::inbound_udp`].
    pub inbound_udp: u64,
    /// See [`RelayStats::icmp_unavailable`].
    pub icmp_unavailable: u64,
    /// See [`RelayStats::nat_refused`].
    pub nat_refused: u64,
    /// See [`RelayStats::nat_expired`].
    pub nat_expired: u64,
    /// See [`RelayStats::v6_frames`].
    pub v6_frames: u64,
    /// See [`RelayStats::icmp6_replies`].
    pub icmp6_replies: u64,
    /// See [`RelayStats::ra_sent`].
    pub ra_sent: u64,
    /// See [`RelayStats::ns_answered`].
    pub ns_answered: u64,
    /// See [`RelayStats::na_sent`].
    pub na_sent: u64,
    /// See [`RelayStats::ptb_sent`].
    pub ptb_sent: u64,
    /// The built-in NAT table's summary: every association crossing to the host (`nat`).
    pub nat: NatSnapshot,
}

/// Where a TCP flow is in its short life.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlowState {
    /// We sent (or are about to send) our SYN.
    SynSent,
    /// The handshake is done and bytes can move.
    Open,
    /// The guest sent FIN; we are still reading the host socket.
    GuestClosed,
}

/// The sequence numbers one flow tracks. Shared with the flow's thread, because both the frame
/// handler (which ACKs) and the host reader (which sends data) move them.
#[derive(Debug)]
struct FlowSeq {
    /// The next sequence number **we** will send.
    our_next: u32,
    /// The next sequence number we expect **from the guest**.
    their_next: u32,
    /// The highest sequence number the guest has **acknowledged** for our data.
    ///
    /// With `our_next` this is how many bytes of ours are in flight, and it is what keeps us inside
    /// the guest's window (see [`FlowSeq::room`]). It starts at the SYN's own sequence number, so the
    /// handshake itself counts.
    their_ack: u32,
    /// How many more bytes the guest's last segment said it can take (`Tcp::window`).
    their_window: u32,
}

impl FlowSeq {
    /// How many more bytes the guest's window lets us put on the wire.
    ///
    /// The relay used to ignore this entirely, which was survivable only because the flow thread was
    /// slow enough never to fill a 64 KiB window. At speed it is not: the guest discards what does not
    /// fit, and **nothing on this side retransmits**, so a transfer would stop dead.
    fn room(&self) -> usize {
        self.their_window
            .saturating_sub(self.our_next.wrapping_sub(self.their_ack)) as usize
    }
}

/// Take the guest's acknowledgement and window into the flow's send accounting.
///
/// Only an ack that is level with or ahead of what we know counts (RFC 793's serial comparison), so a
/// delayed or duplicated old segment cannot rewind the window.
fn accept_ack(numbers: &mut FlowSeq, segment: &crate::frame::Tcp<'_>) {
    if segment.has(TCP_ACK) {
        if segment.ack.wrapping_sub(numbers.their_ack) < 1 << 31 {
            numbers.their_ack = segment.ack;
        }
        numbers.their_window = u32::from(segment.window);
    }
}

/// Which table a flow's entry lives in, so ending its thread can take the entry out.
#[derive(Debug, Clone, Copy)]
enum FlowLeaf {
    /// A flow the guest opened.
    Outbound(OutboundKey),
    /// A flow an operator's port mapping accepted.
    Inbound(InboundKey),
}

/// Owns one flow's entry, and gives it back when the flow's thread ends.
///
/// The **outbound** spawn had no cleanup at all: a connection the host closed normally left its entry
/// in `state.outbound` forever (those maps have no expiry of their own — only the NAT table sweeps),
/// so after `max_flows` finished connections the machine's ceiling was reached and every new one was
/// answered with a RST. The guest sees exactly this: "it worked nicely, then after a few hundred
/// megabytes **every** host is connection refused" — an installer fetching packages is thousands of
/// connections, and 256 of them are one install. A guard rather than a call after `run`, so a panic
/// on the way out does not leak it either.
struct FlowCleanup {
    state: Arc<Mutex<State>>,
    leaf: FlowLeaf,
    /// The built-in NAT table's association for this flow: the two go together, because an
    /// association exists for the flow's lifetime.
    nat_key: NatKey,
}

impl FlowCleanup {
    fn new(state: Arc<Mutex<State>>, leaf: FlowLeaf, nat_key: NatKey) -> FlowCleanup {
        FlowCleanup {
            state,
            leaf,
            nat_key,
        }
    }
}

impl Drop for FlowCleanup {
    fn drop(&mut self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match self.leaf {
            FlowLeaf::Outbound(key) => {
                state.outbound.remove(&key);
            }
            FlowLeaf::Inbound(key) => {
                state.inbound.remove(&key);
            }
        }
        state.nat.close(&self.nat_key);
    }
}

/// The key of an outbound flow: what the guest asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct OutboundKey {
    guest_port: u16,
    /// Where the guest asked to go: either family, so one flow type serves both.
    dst: SocketAddr,
}

/// The key of an inbound flow (a port mapping): the guest's port, on a port of ours.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct InboundKey {
    guest_port: u16,
    our_port: u16,
}

/// One TCP flow, as the frame handler sees it.
struct TcpFlow {
    /// The guest's port (the flow's identity from the guest's side).
    guest_port: u16,
    /// The guest's own address for this flow (the source of its segments), either family.
    guest_ip: IpAddr,
    /// The address the guest believes it is talking to: the real destination outbound, us inbound.
    from_ip: IpAddr,
    /// The port our segments are sent **from** (the destination port outbound, an ephemeral one
    /// inbound).
    our_port: u16,
    /// The sequence numbers, shared with the flow's thread.
    seq: Arc<Mutex<FlowSeq>>,
    /// Guest payloads waiting for the host socket.
    to_socket: Option<Sender<Vec<u8>>>,
    state: FlowState,
    /// The host peer, for an **inbound** flow (a port mapping): it is half of the flow's NAT key, so
    /// the payload the guest sends can be counted against the association the operator can see.
    peer: Option<SocketAddr>,
}

/// What the relay owns, behind one lock.
struct State {
    outbound: HashMap<OutboundKey, TcpFlow>,
    inbound: HashMap<InboundKey, TcpFlow>,
    /// The **built-in NAT table**: every association that crosses to the host, whichever direction it
    /// started in. It is the reply path for a mapped port and the answer to "what is this machine
    /// talking to?" (`crate::nat`).
    nat: NatTable,
    /// The next ephemeral port for an inbound flow (``'s port mapping).
    next_our_port: u16,
}

impl Default for State {
    fn default() -> Self {
        // The ceiling is the relay's own (`max_flows`), so it is set by `Relay::new`; a default state
        // exists only for the struct literal's `..Default::default()` convenience in tests.
        State {
            outbound: HashMap::new(),
            inbound: HashMap::new(),
            nat: NatTable::new(256, Duration::from_secs(120), Duration::from_secs(600)),
            next_our_port: 49152,
        }
    }
}

/// The relay for one machine.
pub struct Relay {
    config: RelayConfig,
    guest: GuestIdentity,
    /// The machine's id, as the peer directory knows it.
    vm: String,
    send: FrameSender,
    peers: Arc<dyn PeerDirectory>,
    /// The names this relay can answer itself (`vm-<name>` → the peer's lease, ``).
    names: Option<NameDirectory>,
    /// The built-in time server: the host's clock, answered on the gateway's port 123.
    ntp: crate::ntp::Server,
    state: Arc<Mutex<State>>,
    stats: Arc<RelayStats>,
    down: AtomicBool,
    /// The identifier the next external ping uses (the kernel overwrites it with the socket's port, so
    /// we pick one per request and put the guest's own back in the answer).
    next_icmp_id: AtomicU64,
    /// Lookups carried to the host's resolver right now (see [`MAX_DNS_IN_FLIGHT`]).
    dns_in_flight: AtomicUsize,
}

/// How many of one peer's lookups may be with the host's resolver at once.
///
/// A lookup needs its own thread — the alternative is the peer's only reader waiting on the host — and
/// a guest can ask for any number of them. Beyond this the guest is answered SERVFAIL, which is a
/// signal a resolver is overloaded, rather than the deployment growing threads without bound.
const MAX_DNS_IN_FLIGHT: usize = 32;

impl Relay {
    /// A relay for one machine.
    pub fn new(
        vm: impl Into<String>,
        config: RelayConfig,
        guest: GuestIdentity,
        send: FrameSender,
        peers: Arc<dyn PeerDirectory>,
        names: Option<NameDirectory>,
    ) -> Arc<Relay> {
        // The NAT table is bounded by the same flow ceiling the relay uses: one association is one
        // socket (or one flow thread), so the two numbers are the same decision.
        let nat = NatTable::new(
            config.max_flows,
            Duration::from_secs(120),
            Duration::from_secs(600),
        );
        Arc::new(Relay {
            config,
            guest,
            vm: vm.into(),
            send,
            peers,
            names,
            ntp: crate::ntp::Server::new(),
            state: Arc::new(Mutex::new(State {
                outbound: HashMap::new(),
                inbound: HashMap::new(),
                nat,
                next_our_port: 49152,
            })),
            stats: Arc::new(RelayStats::default()),
            down: AtomicBool::new(false),
            next_icmp_id: AtomicU64::new(0x4000),
            dns_in_flight: AtomicUsize::new(0),
        })
    }

    /// The guest's identity.
    pub fn guest(&self) -> GuestIdentity {
        self.guest
    }

    /// What the relay has done so far.
    pub fn snapshot(&self) -> RelaySnapshot {
        let load = |value: &AtomicU64| value.load(Ordering::Relaxed);
        RelaySnapshot {
            frames_in: load(&self.stats.frames_in),
            frames_out: load(&self.stats.frames_out),
            peers_forwarded: load(&self.stats.peers_forwarded),
            dropped_isolation: load(&self.stats.dropped_isolation),
            dropped_ipv6: load(&self.stats.dropped_ipv6),
            dropped_other: load(&self.stats.dropped_other),
            dropped_unreachable: load(&self.stats.dropped_unreachable),
            tcp_flows: load(&self.stats.tcp_flows),
            udp_flows: load(&self.stats.udp_flows),
            icmp_replies: load(&self.stats.icmp_replies),
            dropped_busy: load(&self.stats.dropped_busy),
            dropped_mapped: load(&self.stats.dropped_mapped),
            dropped_host: load(&self.stats.dropped_host),
            inbound_udp: load(&self.stats.inbound_udp),
            icmp_unavailable: load(&self.stats.icmp_unavailable),
            nat_refused: load(&self.stats.nat_refused),
            nat_expired: load(&self.stats.nat_expired),
            v6_frames: load(&self.stats.v6_frames),
            icmp6_replies: load(&self.stats.icmp6_replies),
            ra_sent: load(&self.stats.ra_sent),
            ns_answered: load(&self.stats.ns_answered),
            na_sent: load(&self.stats.na_sent),
            ptb_sent: load(&self.stats.ptb_sent),
            nat: self.state.lock().expect("the relay state").nat.snapshot(),
        }
    }

    /// Stop taking new flows (the machine is going away). Flows already running end when their socket
    /// closes: the conduit is dropped with the machine, so their next write fails and their thread
    /// returns.
    pub fn shutdown(&self) {
        self.down.store(true, Ordering::Relaxed);
        let mut state = self.state.lock().expect("the relay state");
        state.outbound.clear();
        state.inbound.clear();
        state.nat = NatTable::new(1, Duration::from_secs(1), Duration::from_secs(1));
    }

    /// Handle one frame from the guest.
    pub fn handle(self: &Arc<Self>, frame: &[u8]) {
        if self.down.load(Ordering::Relaxed) {
            return;
        }
        let seen = self.stats.frames_in.fetch_add(1, Ordering::Relaxed);
        // Every so often, let the NAT table drop what has gone idle: a flow nobody uses must not hold a
        // socket (or a port) forever. The sweep is amortized over the frames that keep arriving, so it
        // costs one pass per few hundred frames rather than one per frame.
        if seen % 256 == 0 {
            let now = std::time::Instant::now();
            let expired = self
                .state
                .lock()
                .expect("the relay state")
                .nat
                .expire(now)
                .len();
            if expired > 0 {
                self.stats
                    .nat_expired
                    .fetch_add(expired as u64, Ordering::Relaxed);
            }
        }
        let Some(ethernet) = parse_ethernet(frame) else {
            self.stats.dropped_other.fetch_add(1, Ordering::Relaxed);
            return;
        };
        match ethernet.ethertype {
            ETHERTYPE_ARP => self.handle_arp(ethernet.payload),
            ETHERTYPE_IPV4 => self.handle_ipv4(ethernet.payload),
            ETHERTYPE_IPV6 => self.handle_ipv6(ethernet.payload),
            _ => {
                self.stats.dropped_other.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Answer ARP for ourselves, and proxy it for a peer the isolation rules allow.
    fn handle_arp(&self, payload: &[u8]) {
        let Some(request) = parse_arp(payload) else {
            self.stats.dropped_other.fetch_add(1, Ordering::Relaxed);
            return;
        };
        if request.op != crate::frame::ARP_REQUEST {
            return;
        }
        if request.target_ip == self.config.our_ip {
            self.answer_arp(&request, self.config.our_mac, self.config.our_ip);
            return;
        }
        if !self.config.is_internal(request.target_ip) {
            // An address outside our subnet is never ours to speak for: the guest must route it to us
            // as the gateway, and the IP path answers for it.
            return;
        }
        match self.peers.peer_for(&self.vm, IpAddr::V4(request.target_ip)) {
            Some(peer) => self.answer_arp(&request, peer.mac, request.target_ip),
            None => {
                // A machine address that is not a reachable peer: silence is the honest answer, and
                // the guest's own stack reports "host unreachable" instead of a black hole.
                self.stats
                    .dropped_unreachable
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Send one ARP reply to the asker.
    fn answer_arp(&self, request: &Arp, mac: [u8; 6], ip: Ipv4Addr) {
        let payload = build_arp_reply(request, mac, ip);
        self.emit(build_ethernet(
            request.sender_mac,
            mac,
            ETHERTYPE_ARP,
            &payload,
        ));
    }

    /// Handle one IPv4 packet: a peer's, or ours (the gateway's, or the internet's).
    fn handle_ipv4(self: &Arc<Self>, payload: &[u8]) {
        let Some(packet) = parse_ipv4(payload) else {
            self.stats.dropped_other.fetch_add(1, Ordering::Relaxed);
            return;
        };
        // A flow **to our own address** on a port the workspace published is the gateway carrying it to
        // the peer that holds it. The rewrite is stateless — the table decides both directions —
        // so nothing has to track the connection.
        if packet.dst == self.config.our_ip {
            if let Some((src_port, dst_port)) = ports_of(&packet) {
                if let Some((peer, peer_port)) = self
                    .config
                    .gateway_ports
                    .target(&self.config.workspace, dst_port)
                {
                    match crate::frame::translate_ipv4(
                        payload,
                        packet.src,
                        peer,
                        Some(src_port),
                        Some(peer_port),
                    ) {
                        Some(rewritten) => {
                            self.forward_to_peer(peer, &rewritten);
                            return;
                        }
                        None => {
                            // A fragment whose ports cannot be named: dropped rather than delivered with
                            // the wrong port, and counted so it is not a silent hole.
                            self.stats.dropped_mapped.fetch_add(1, Ordering::Relaxed);
                            return;
                        }
                    }
                }
            }
        }
        if self.config.is_internal(packet.dst) && packet.dst != self.config.our_ip {
            // A packet **from** a published port looks like it comes from the gateway, so the peer that
            // dialled it keeps the address it dialled.
            let mut rewritten = None;
            if let Some((src_port, _)) = ports_of(&packet) {
                if let Some(gateway_port) = self.config.gateway_ports.published_from(
                    &self.config.workspace,
                    self.guest.ip,
                    src_port,
                ) {
                    rewritten = crate::frame::translate_ipv4(
                        payload,
                        self.config.our_ip,
                        packet.dst,
                        Some(gateway_port),
                        None,
                    );
                    if rewritten.is_none() {
                        self.stats.dropped_mapped.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                }
            }
            match rewritten {
                Some(rewritten) => self.forward_to_peer(packet.dst, &rewritten),
                None => self.forward_to_peer(packet.dst, payload),
            }
            return;
        }
        match packet.protocol {
            IPPROTO_TCP => self.handle_tcp(&packet),
            IPPROTO_UDP => self.handle_udp(&packet),
            IPPROTO_ICMP => self.handle_icmp(&packet),
            _ => {
                self.stats.dropped_other.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Forward one IPv4 packet to a peer's conduit, rewriting the MACs so the peer sees a frame from
    /// its gateway.
    fn forward_to_peer(&self, dst: Ipv4Addr, packet: &[u8]) {
        let Some(peer) = self.peers.peer_for(&self.vm, IpAddr::V4(dst)) else {
            self.stats.dropped_isolation.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let frame = build_ethernet(peer.mac, self.config.our_mac, ETHERTYPE_IPV4, packet);
        (peer.send)(frame);
        self.stats.peers_forwarded.fetch_add(1, Ordering::Relaxed);
    }

    /// Handle one IPv6 packet: a peer's, ours, or an external host's.
    ///
    /// The shape is the same as IPv4's, with one difference that matters: a machine has **two** kinds
    /// of address a peer can hold — the DHCPv6 ULA inside the machines' prefix, and the link-local it
    /// forms for itself — so "is this a peer?" is the directory's answer for either, rather than a
    /// prefix test. The prefix test is still what separates "a machine address nobody holds" (silence,
    /// so the guest's stack reports the failure) from "the internet" (a flow through the NAT table).
    fn handle_ipv6(self: &Arc<Self>, payload: &[u8]) {
        let Some(packet) = parse_ipv6(payload) else {
            // An IPv6 frame we will not speak: truncated, a fragment or a jumbogram (there is no
            // reassembly here), or an extension chain that never ends.
            self.stats.dropped_ipv6.fetch_add(1, Ordering::Relaxed);
            return;
        };
        // A packet larger than the conduit's MTU cannot be carried, and its fragments are refused:
        // tell the guest with a Packet Too Big, which is what makes its own PMTUD shrink the next one.
        if 40 + packet.payload.len() > CONDUIT_MTU as usize {
            self.send_packet_too_big(payload, packet.src);
            return;
        }
        if !self.is_ours6(packet.dst) {
            if let Some(peer) = self.peers.peer_for(&self.vm, IpAddr::V6(packet.dst)) {
                let frame = build_ethernet(peer.mac, self.config.our_mac, ETHERTYPE_IPV6, payload);
                (peer.send)(frame);
                self.stats.peers_forwarded.fetch_add(1, Ordering::Relaxed);
                return;
            }
            if self.config.is_internal6(packet.dst) {
                // A ULA in the machines' prefix that no machine holds: the honest answer is silence
                // (the guest's own stack turns that into "no route"/a timeout, which a status can
                // then explain).
                self.stats.dropped_ipv6.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        match packet.next_header {
            IPPROTO_TCP => self.handle_tcp6(&packet),
            IPPROTO_UDP => self.handle_udp6(&packet),
            IPPROTO_ICMPV6 => self.handle_icmp6(&packet),
            _ => {
                self.stats.dropped_other.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Whether an IPv6 address is one of ours: the gateway's link-local, or its ULA.
    fn is_ours6(&self, address: Ipv6Addr) -> bool {
        address == self.config.our_ip6 || address == self.config.our_ula6
    }

    /// Send an ICMPv6 **Packet Too Big** , quoting the offending packet so the guest's PMTUD
    /// can match it to the flow that produced it.
    fn send_packet_too_big(&self, invoking: &[u8], guest: Ipv6Addr) {
        let quoted = &invoking[..invoking.len().min(ICMPV6_ERROR_QUOTE)];
        let mut body = Vec::with_capacity(4 + quoted.len());
        body.extend_from_slice(&CONDUIT_MTU.to_be_bytes());
        body.extend_from_slice(quoted);
        let message = build_icmpv6(self.config.our_ip6, guest, 2, 0, &body);
        let answer = build_ipv6(self.config.our_ip6, guest, IPPROTO_ICMPV6, 64, &message);
        let ethernet = build_ethernet(self.guest.mac, self.config.our_mac, ETHERTYPE_IPV6, &answer);
        self.emit(ethernet);
        self.stats.ptb_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Handle one ICMPv6 message: the NDP messages that let a guest use the conduit at all,
    /// and echo.
    ///
    /// The Neighbor Discovery answers are the difference between an IPv6-capable guest and a guest
    /// that cannot resolve its gateway: `ndp.rs` builds the messages, this decides when to send one.
    fn handle_icmp6(&self, packet: &crate::frame::Ipv6<'_>) {
        let Some(message) = parse_icmpv6(packet.payload) else {
            self.stats.dropped_other.fetch_add(1, Ordering::Relaxed);
            return;
        };
        match message.kind {
            ndp::ROUTER_SOLICITATION => self.answer_router_solicitation(packet),
            ndp::NEIGHBOR_SOLICITATION => self.answer_neighbor_solicitation(packet, &message),
            // A neighbour's advertisement, or a guest's own advertisement/redirect: a host on this
            // conduit (which is all our stack is) has no neighbour cache to feed from them.
            ndp::NEIGHBOR_ADVERTISEMENT | ndp::ROUTER_ADVERTISEMENT => {
                self.stats.dropped_other.fetch_add(1, Ordering::Relaxed);
            }
            128 => self.answer_echo6(packet),
            // A reply to an echo we sent, and a Packet-Too-Big a peer sent the guest: both are
            // information for the guest's stack, which will send its own if it needs to. Nothing here
            // is ours to act on, and neither is an error.
            129 | 2 => {}
            _ => {
                self.stats.dropped_other.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Answer a Router Solicitation with our Router Advertisement.
    ///
    /// We are the only router on the conduit, so the advertisement is **our** configuration, not a
    /// copy of anything on the host: the machines' ULA prefix (on-link, so peers talk directly via
    /// us), an MTU of 1500 (the conduit's frame size), and M+O set, because addresses and DNS come
    /// from DHCPv6 (`dhcp6.rs`). We never send unsolicited advertisements: a guest that wants the
    /// prefix asks for it, which is the first thing a Linux guest does when its interface comes up.
    fn answer_router_solicitation(&self, packet: &crate::frame::Ipv6<'_>) {
        let config = ndp::RouterAdConfig {
            our_mac: self.config.our_mac,
            prefix: self.config.subnet6,
            prefix_len: self.config.prefix6,
            managed: true,
            other_config: true,
            on_link: true,
            // The addresses come from DHCPv6, so the prefix is **not** used for stateless
            // autoconfiguration (the A flag); a guest that autoconfigured would pick an address the
            // relay has no lease for.
            autonomous: false,
            // The lease's own lifetimes, so a guest that also runs stateless autoconfiguration against
            // the prefix (some do, even with M set) deprecates it exactly when DHCPv6 says to.
            valid_lifetime: DEFAULT_V6_LIFETIME,
            preferred_lifetime: DEFAULT_V6_LIFETIME,
            // We *are* the default router: the guest's only way off the conduit.
            router_lifetime: 1800,
            // The conduit carries 1500-byte Ethernet frames, and a guest's PMTU must not exceed what
            // the conduit's datagrams can hold.
            mtu: 1500,
            current_hop_limit: 64,
        };
        let body = ndp::router_advertisement_body(&config);
        // A solicitation whose source is still `::` (the guest has not finished DAD) cannot be
        // answered to a unicast address: the reply goes to all-nodes.
        let dst = if packet.src.is_unspecified() {
            ALL_NODES_MULTICAST
        } else {
            packet.src
        };
        let message = build_icmpv6(
            self.config.our_ip6,
            dst,
            ndp::ROUTER_ADVERTISEMENT,
            0,
            &body,
        );
        let answer = build_ipv6(self.config.our_ip6, dst, IPPROTO_ICMPV6, 255, &message);
        let ethernet = build_ethernet(
            self.destination_mac(dst),
            self.config.our_mac,
            ETHERTYPE_IPV6,
            &answer,
        );
        self.emit(ethernet);
        self.stats.ra_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Answer a Neighbor Solicitation: for ourselves, and — as a proxy — for a reachable peer.
    ///
    /// A **Duplicate Address Detection** probe is deliberately left unanswered (RFC 4862 ): the
    /// guest is asking whether anyone holds the address it wants, and for an address inside the
    /// machines' prefix the answer would otherwise be a false "taken". A peer's address is spoken for
    /// only when the isolation rules allow this machine to reach it, which is the same test the
    /// forwarding path uses.
    fn answer_neighbor_solicitation(&self, packet: &crate::frame::Ipv6<'_>, message: &Icmp<'_>) {
        let Some(target) = message
            .payload
            .get(..16)
            .and_then(|octets| <[u8; 16]>::try_from(octets).ok())
            .map(Ipv6Addr::from)
        else {
            self.stats.dropped_other.fetch_add(1, Ordering::Relaxed);
            return;
        };
        if packet.src.is_unspecified() {
            // A DAD probe: nobody answers, and nothing is counted as lost (this is the expected path
            // for every address the guest configures).
            return;
        }
        let (mac, flags) = if self.is_ours6(target) {
            // Ours: we are a router, so the advertisement says so. The Override flag is left clear:
            // nothing here overrides a cache entry, and it is what marks a **proxy** advertisement
            // (`ndp::NeighborMessage::is_proxy`), which ours is not.
            (self.config.our_mac, ndp::NA_SOLICITED | ndp::NA_ROUTER)
        } else if let Some(peer) = self.peers.peer_for(&self.vm, IpAddr::V6(target)) {
            // A peer's address: a proxy advertisement, which names the peer's MAC, must not claim to
            // be a router, and does override whatever the guest had cached for the target.
            (peer.mac, ndp::NA_SOLICITED | ndp::NA_OVERRIDE)
        } else {
            if self.config.is_internal6(target) {
                self.stats.dropped_ipv6.fetch_add(1, Ordering::Relaxed);
            }
            return;
        };
        let body = ndp::neighbor_advertisement_body(flags, target, Some(mac));
        // The advertisement's source is the **target** address, so the guest's neighbour cache maps
        // that address to the MAC we name — which is the whole point of a proxy advertisement.
        let message = build_icmpv6(target, packet.src, ndp::NEIGHBOR_ADVERTISEMENT, 0, &body);
        let answer = build_ipv6(target, packet.src, IPPROTO_ICMPV6, 255, &message);
        let ethernet = build_ethernet(self.guest.mac, self.config.our_mac, ETHERTYPE_IPV6, &answer);
        self.emit(ethernet);
        self.stats.ns_answered.fetch_add(1, Ordering::Relaxed);
        self.stats.na_sent.fetch_add(1, Ordering::Relaxed);
    }

    /// Answer an echo request addressed to us, or to a group we belong to; for anywhere else, try the
    /// host's own ping socket.
    fn answer_echo6(&self, packet: &crate::frame::Ipv6<'_>) {
        if self.is_ours6(packet.dst) || packet.dst.is_multicast() {
            // The reply comes from the address the guest echoed: its link-local for the common case, and
            // the ULA when that is what it asked (a reply from a different address is legal, but a
            // guest's own tools report it, and there is no reason to be confusing).
            let from = if packet.dst == self.config.our_ula6 {
                self.config.our_ula6
            } else {
                self.config.our_ip6
            };
            let Some(reply) = build_icmpv6_echo_reply(from, packet.src, packet.payload) else {
                self.stats.dropped_other.fetch_add(1, Ordering::Relaxed);
                return;
            };
            let answer = build_ipv6(from, packet.src, IPPROTO_ICMPV6, 64, &reply);
            let ethernet =
                build_ethernet(self.guest.mac, self.config.our_mac, ETHERTYPE_IPV6, &answer);
            self.emit(ethernet);
            self.stats.icmp6_replies.fetch_add(1, Ordering::Relaxed);
            return;
        }
        // An external address: answer it with a real echo through the host's ping socket, exactly as
        // the IPv4 path does (`ping_external`), or drop it with the counter that says why.
        match self.ping_external6(packet.dst, packet.src, packet.payload) {
            Some(reply) => {
                let answer =
                    build_ipv6(self.config.our_ip6, packet.src, IPPROTO_ICMPV6, 64, &reply);
                let ethernet =
                    build_ethernet(self.guest.mac, self.config.our_mac, ETHERTYPE_IPV6, &answer);
                self.emit(ethernet);
                self.stats.icmp6_replies.fetch_add(1, Ordering::Relaxed);
            }
            None => {
                self.stats
                    .dropped_unreachable
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Echo an external IPv6 host on the guest's behalf, through the host's unprivileged ICMPv6 ping
    /// socket (the same mechanism as [`Relay::ping_external`], and refusing the same way when the host
    /// does not grant one).
    fn ping_external6(
        &self,
        dst: Ipv6Addr,
        guest_src: Ipv6Addr,
        request: &[u8],
    ) -> Option<Vec<u8>> {
        #[cfg(unix)]
        {
            let id = (self.next_icmp_id.fetch_add(1, Ordering::Relaxed) & 0x7fff) as u16;
            // SAFETY: `socket(2)` with constants; the descriptor is closed on every path below.
            let fd =
                unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, libc::IPPROTO_ICMPV6) };
            if fd < 0 {
                self.stats.icmp_unavailable.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            let mut address: libc::sockaddr_in6 = unsafe { std::mem::zeroed() };
            address.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            address.sin6_port = id.to_be();
            address.sin6_addr.s6_addr = dst.octets();
            let length = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
            // SAFETY: the address is a valid `sockaddr_in6` of the length we pass.
            if unsafe { libc::bind(fd, &address as *const _ as *const libc::sockaddr, length) } < 0
            {
                unsafe { libc::close(fd) };
                self.stats.icmp_unavailable.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            let timeout = libc::timeval {
                tv_sec: 1,
                tv_usec: 0,
            };
            // SAFETY: a `timeval` of the size we pass, for `SO_RCVTIMEO`.
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_RCVTIMEO,
                    &timeout as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::timeval>() as libc::socklen_t,
                );
            }
            // The guest's header has the identifier and sequence it used; ours is the socket's, and it
            // is the one the kernel's reply will carry back, so we send the rest of the message only
            // and remember what to put back.
            let parsed = parse_icmpv6(request)?;
            let probe = crate::frame::build_icmpv6_echo_request(
                self.config.our_ip6,
                dst,
                id,
                u16::from_be_bytes([parsed.rest[2], parsed.rest[3]]),
                parsed.payload,
            );
            // SAFETY: the buffer is ours for its whole length, and the address is the one we bound.
            let sent = unsafe {
                libc::sendto(
                    fd,
                    probe.as_ptr() as *const libc::c_void,
                    probe.len(),
                    0,
                    &address as *const _ as *const libc::sockaddr,
                    length,
                )
            };
            if sent < 0 {
                unsafe { libc::close(fd) };
                return None;
            }
            let mut buffer = [0u8; 1500];
            // SAFETY: a stack buffer of the length we pass, and a descriptor we own.
            let read = unsafe {
                libc::recv(
                    fd,
                    buffer.as_mut_ptr() as *mut libc::c_void,
                    buffer.len(),
                    0,
                )
            };
            unsafe { libc::close(fd) };
            if read <= 0 {
                return None;
            }
            let reply = parse_icmpv6(&buffer[..read as usize])?;
            let mut body = Vec::with_capacity(4 + reply.payload.len());
            body.extend_from_slice(&parsed.rest);
            body.extend_from_slice(reply.payload);
            Some(build_icmpv6(self.config.our_ip6, guest_src, 129, 0, &body))
        }
        #[cfg(not(unix))]
        {
            let _ = (dst, guest_src, request);
            None
        }
    }

    /// The Ethernet destination for an IPv6 address: the guest itself for a unicast address, and the
    /// multicast MAC for a group.
    fn destination_mac(&self, address: Ipv6Addr) -> [u8; 6] {
        if address.is_multicast() {
            multicast_mac(address)
        } else {
            self.guest.mac
        }
    }

    /// Answer an echo request aimed at us.
    ///
    /// Only our own address is answered (a peer's is forwarded above): an echo to an external host
    /// would need a raw or ping socket this process may not have, and a fabricated reply would be a
    /// lie. The counter says so.
    fn handle_icmp(&self, packet: &crate::frame::Ipv4<'_>) {
        let Some(message) = parse_icmp(packet.payload) else {
            self.stats.dropped_other.fetch_add(1, Ordering::Relaxed);
            return;
        };
        if message.kind != 8 {
            self.stats.dropped_other.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if packet.dst != self.config.our_ip {
            if self.refuses_host(IpAddr::V4(packet.dst)) {
                // A ping of the operator's own machine or LAN: the guest has the internet and its
                // peers, and nothing else on this host.
                self.stats.dropped_host.fetch_add(1, Ordering::Relaxed);
                return;
            }
            // An echo to a host outside the machines' subnet: we answer it by actually pinging, when
            // this host grants an unprivileged ping socket. A fabricated reply would be a lie, and
            // silence is only right when the host forbids the socket — which the counter records.
            if let Some(reply) = self.ping_external(packet.dst, message.rest, message.payload) {
                let answer =
                    build_ipv4(self.config.our_ip, self.guest.ip, IPPROTO_ICMP, 64, &reply);
                self.emit(build_ethernet(
                    self.guest.mac,
                    self.config.our_mac,
                    ETHERTYPE_IPV4,
                    &answer,
                ));
                self.stats.icmp_replies.fetch_add(1, Ordering::Relaxed);
                return;
            }
            self.stats
                .dropped_unreachable
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
        let Some(reply) = build_icmp_echo_reply(packet.payload) else {
            self.stats.dropped_other.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let segment = build_ipv4(self.config.our_ip, self.guest.ip, IPPROTO_ICMP, 64, &reply);
        self.emit(build_ethernet(
            self.guest.mac,
            self.config.our_mac,
            ETHERTYPE_IPV4,
            &segment,
        ));
        self.stats.icmp_replies.fetch_add(1, Ordering::Relaxed);
    }

    /// Whether a destination is the host's own network, which a machine may not reach.
    fn refuses_host(&self, ip: IpAddr) -> bool {
        self.config
            .host_guard
            .as_ref()
            .map(|guard| guard.refuses(ip))
            .unwrap_or(false)
    }

    /// Ping a host outside our subnet on the guest's behalf, with the answer the guest expects.
    ///
    /// Linux can grant unprivileged ICMP echo through an ordinary datagram socket
    /// (`socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP)`), which is exactly what a guest's `ping` needs and
    /// what a TAP could never have given us without a capability. When the host does not allow it the
    /// request is dropped, with a counter and a log line rather than a silent hole.
    fn ping_external(
        &self,
        dst: Ipv4Addr,
        request_id: [u8; 4],
        request_payload: &[u8],
    ) -> Option<Vec<u8>> {
        #[cfg(unix)]
        {
            let id = (self.next_icmp_id.fetch_add(1, Ordering::Relaxed) & 0x7fff) as u16;
            // SAFETY: `socket(2)` with constants; the descriptor is closed on every path below.
            let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, libc::IPPROTO_ICMP) };
            if fd < 0 {
                self.stats.icmp_unavailable.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            let mut address: libc::sockaddr_in = unsafe { std::mem::zeroed() };
            address.sin_family = libc::AF_INET as libc::sa_family_t;
            address.sin_port = id.to_be();
            address.sin_addr.s_addr = u32::from_ne_bytes(dst.octets());
            let length = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            // SAFETY: the address is a valid `sockaddr_in` of the length we pass.
            if unsafe { libc::bind(fd, &address as *const _ as *const libc::sockaddr, length) } < 0
            {
                unsafe { libc::close(fd) };
                self.stats.icmp_unavailable.fetch_add(1, Ordering::Relaxed);
                return None;
            }
            let timeout = libc::timeval {
                tv_sec: 1,
                tv_usec: 0,
            };
            // SAFETY: a `timeval` of the size we pass, for `SO_RCVTIMEO`.
            unsafe {
                libc::setsockopt(
                    fd,
                    libc::SOL_SOCKET,
                    libc::SO_RCVTIMEO,
                    &timeout as *const _ as *const libc::c_void,
                    std::mem::size_of::<libc::timeval>() as libc::socklen_t,
                );
            }
            let sequence = u16::from_be_bytes([request_id[2], request_id[3]]);
            let request = crate::frame::build_icmp_echo_request(id, sequence, request_payload);
            // SAFETY: the buffer is ours for its whole length, and the address is the one we bound.
            let sent = unsafe {
                libc::sendto(
                    fd,
                    request.as_ptr() as *const libc::c_void,
                    request.len(),
                    0,
                    &address as *const _ as *const libc::sockaddr,
                    length,
                )
            };
            if sent < 0 {
                unsafe { libc::close(fd) };
                return None;
            }
            let mut buffer = [0u8; 1500];
            // SAFETY: a stack buffer of the length we pass, and a descriptor we own.
            let read = unsafe {
                libc::recv(
                    fd,
                    buffer.as_mut_ptr() as *mut libc::c_void,
                    buffer.len(),
                    0,
                )
            };
            unsafe { libc::close(fd) };
            if read <= 0 {
                return None;
            }
            let reply = parse_icmp(&buffer[..read as usize])?;
            // The guest gets **its own** identifier and sequence back (ours were the socket's), and the
            // data the host actually sent.
            let mut answer = vec![0u8, 0u8, 0, 0];
            answer.extend_from_slice(&request_id);
            answer.extend_from_slice(reply.payload);
            let sum = crate::frame::checksum(&answer);
            answer[2..4].copy_from_slice(&sum.to_be_bytes());
            Some(answer)
        }
        #[cfg(not(unix))]
        {
            let _ = (dst, request_id, request_payload);
            None
        }
    }

    /// Handle one IPv4 TCP segment.
    fn handle_tcp(&self, packet: &crate::frame::Ipv4<'_>) {
        self.handle_tcp_at(
            IpAddr::V4(packet.src),
            IpAddr::V4(packet.dst),
            packet.payload,
        );
    }

    /// Handle one IPv6 TCP segment.
    fn handle_tcp6(&self, packet: &crate::frame::Ipv6<'_>) {
        self.handle_tcp_at(
            IpAddr::V6(packet.src),
            IpAddr::V6(packet.dst),
            packet.payload,
        );
    }

    /// Handle one TCP segment, either family: a new flow, or an existing one.
    fn handle_tcp_at(&self, src: IpAddr, dst: IpAddr, payload: &[u8]) {
        let Some(segment) = parse_tcp(payload) else {
            self.stats.dropped_other.fetch_add(1, Ordering::Relaxed);
            return;
        };
        // An inbound flow (a port mapping) is one the guest answers on a port *we* opened: it is
        // addressed to us, not to an external host.
        // An inbound flow (a port mapping) answers on a port *we* opened: it is addressed to us, not
        // to an external host — in either family.
        let to_us = match dst {
            IpAddr::V4(address) => address == self.config.our_ip,
            IpAddr::V6(address) => address == self.config.our_ip6,
        };
        if to_us {
            let key = InboundKey {
                guest_port: segment.src_port,
                our_port: segment.dst_port,
            };
            let known = self
                .state
                .lock()
                .expect("the relay state")
                .inbound
                .contains_key(&key);
            if known {
                self.inbound_segment(key, &segment);
                return;
            }
        }
        let key = OutboundKey {
            guest_port: segment.src_port,
            dst: SocketAddr::new(dst, segment.dst_port),
        };
        let known = self
            .state
            .lock()
            .expect("the relay state")
            .outbound
            .contains_key(&key);
        if known {
            self.outbound_segment(key, &segment);
            return;
        }
        if segment.has(TCP_SYN) && !segment.has(TCP_ACK) {
            self.open_outbound(key, src, &segment);
            return;
        }
        // A segment for a flow we do not have: tell the guest, so it does not wait.
        self.send_tcp(
            dst,
            src,
            segment.src_port,
            segment.dst_port,
            0,
            segment.seq.wrapping_add(1),
            TCP_RST | TCP_ACK,
            &[],
        );
    }

    /// The guest opened a flow: complete the handshake with it, then open the host socket.
    fn open_outbound(&self, key: OutboundKey, guest_ip: IpAddr, segment: &crate::frame::Tcp<'_>) {
        // The host's own network is not the guest's to reach: the answer is the same RST a
        // refused connection gets, so the guest's `connect()` fails now and says so.
        if self.refuses_host(key.dst.ip()) {
            self.stats.dropped_host.fetch_add(1, Ordering::Relaxed);
            self.send_tcp(
                key.dst.ip(),
                guest_ip,
                key.guest_port,
                key.dst.port(),
                0,
                segment.seq.wrapping_add(1),
                TCP_RST | TCP_ACK,
                &[],
            );
            return;
        }
        {
            let state = self.state.lock().expect("the relay state");
            if state.outbound.len() + state.inbound.len() >= self.config.max_flows
                || state.nat.len() >= self.config.max_flows
            {
                drop(state);
                self.stats.dropped_busy.fetch_add(1, Ordering::Relaxed);
                self.send_tcp(
                    key.dst.ip(),
                    guest_ip,
                    key.guest_port,
                    key.dst.port(),
                    0,
                    segment.seq.wrapping_add(1),
                    TCP_RST | TCP_ACK,
                    &[],
                );
                return;
            }
        }
        let our_isn = pseudo_isn(&self.vm, key.guest_port, key.dst.port());
        let seq = Arc::new(Mutex::new(FlowSeq {
            our_next: our_isn.wrapping_add(1),
            their_next: segment.seq.wrapping_add(1),
            // The SYN is one sequence number of ours that the guest has yet to acknowledge, and its
            // own window is where the send window starts.
            their_ack: our_isn,
            their_window: u32::from(segment.window),
        }));
        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        let flow = TcpFlow {
            guest_port: key.guest_port,
            guest_ip,
            from_ip: key.dst.ip(),
            our_port: key.dst.port(),
            seq: Arc::clone(&seq),
            to_socket: Some(tx),
            state: FlowState::SynSent,
            peer: None,
        };
        {
            let mut state = self.state.lock().expect("the relay state");
            // The association the operator can see: this machine talking to that address:port.
            let nat_key = NatKey::outbound(NatProto::Tcp, key.guest_port, key.dst);
            if state
                .nat
                .open(nat_key, NatDirection::Outbound, None, None)
                .is_err()
            {
                self.stats.nat_refused.fetch_add(1, Ordering::Relaxed);
            }
            state.outbound.insert(key, flow);
        }
        self.stats.tcp_flows.fetch_add(1, Ordering::Relaxed);
        // The handshake with the guest is ours to complete immediately: a guest's `connect()` should
        // not wait on the host's, and a host that refuses is a RST after the fact.
        self.send_tcp(
            key.dst.ip(),
            guest_ip,
            key.guest_port,
            key.dst.port(),
            our_isn,
            segment.seq.wrapping_add(1),
            TCP_SYN | TCP_ACK,
            &[],
        );
        self.spawn_outbound(key, guest_ip, rx, seq, our_isn);
    }

    /// Connect the host socket for an outbound flow and run it.
    fn spawn_outbound(
        &self,
        key: OutboundKey,
        guest_ip: IpAddr,
        rx: Receiver<Vec<u8>>,
        seq: Arc<Mutex<FlowSeq>>,
        _our_isn: u32,
    ) {
        let dst = key.dst;
        let context = FlowContext {
            guest: self.guest,
            config: self.config.clone(),
            send: Arc::clone(&self.send),
            seq: Arc::clone(&seq),
            stats: Arc::clone(&self.stats),
            guest_port: key.guest_port,
            guest_ip,
            our_port: key.dst.port(),
            from_ip: key.dst.ip(),
            handshake: false,
            nat: Arc::clone(&self.state),
            nat_key: NatKey::outbound(NatProto::Tcp, key.guest_port, key.dst),
        };
        let state = Arc::clone(&self.state);
        std::thread::Builder::new()
            .name(format!("vmnet-tcp-{}", key.dst.port()))
            .spawn(move || {
                // The flow's entry lives exactly as long as this thread, whatever ends it.
                let _cleanup = FlowCleanup::new(
                    Arc::clone(&state),
                    FlowLeaf::Outbound(key),
                    NatKey::outbound(NatProto::Tcp, key.guest_port, dst),
                );
                match TcpStream::connect_timeout(&dst, context.config.connect_timeout) {
                    Ok(stream) => {
                        let _ = stream.set_nodelay(true);
                        context.run(stream, rx);
                    }
                    Err(_) => {
                        // The host refused (or is unreachable): reset the guest's half so its
                        // `connect()` fails now instead of hanging. The guard removes the entry.
                        context
                            .stats
                            .dropped_unreachable
                            .fetch_add(1, Ordering::Relaxed);
                        let (our_next, their_next) = {
                            let seq = context.seq.lock().expect("the flow sequence");
                            (seq.our_next, seq.their_next)
                        };
                        context.emit_segment(our_next, their_next, TCP_RST | TCP_ACK, &[]);
                    }
                }
            })
            .expect("a flow thread");
    }

    /// A segment for an outbound flow: ACK what we got, hand the payload to the socket.
    fn outbound_segment(&self, key: OutboundKey, segment: &crate::frame::Tcp<'_>) {
        let accepted = {
            let mut state = self.state.lock().expect("the relay state");
            let Some(flow) = state.outbound.get_mut(&key) else {
                return;
            };
            if segment.has(TCP_RST) {
                state.outbound.remove(&key);
                state
                    .nat
                    .close(&NatKey::outbound(NatProto::Tcp, key.guest_port, key.dst));
                return;
            }
            let mut numbers = flow.seq.lock().expect("the flow sequence");
            accept_ack(&mut numbers, segment);
            let accepted = accept_segment(&mut numbers, segment);
            if segment.has(TCP_FIN) {
                flow.state = FlowState::GuestClosed;
                if let Some(tx) = &flow.to_socket {
                    let _ = tx.send(Vec::new()); // a zero-length write is our "guest is done"
                }
            }
            accepted
        };
        let payload = if accepted { segment.payload } else { &[] };
        if !payload.is_empty() {
            // The built-in NAT table is the answer to "what is this machine talking to?", and a TCP
            // flow that carried bytes must say so: the segments it accepted are its traffic.
            let mut state = self.state.lock().expect("the relay state");
            state.nat.touch(
                &NatKey::outbound(NatProto::Tcp, key.guest_port, key.dst),
                payload.len() as u64,
            );
        }
        // Data (or a FIN) is acknowledged; a bare ACK from the guest needs no answer, or the two
        // stacks would trade acknowledgements forever.
        if !payload.is_empty() || segment.has(TCP_FIN) {
            let (our_next, their_next, from_ip, guest_ip, guest_port, our_port) = {
                let state = self.state.lock().expect("the relay state");
                match state.outbound.get(&key) {
                    Some(flow) => {
                        let numbers = flow.seq.lock().expect("the flow sequence");
                        (
                            numbers.our_next,
                            numbers.their_next,
                            flow.from_ip,
                            flow.guest_ip,
                            flow.guest_port,
                            flow.our_port,
                        )
                    }
                    None => return,
                }
            };
            self.send_tcp(
                from_ip,
                guest_ip,
                guest_port,
                our_port,
                our_next,
                their_next,
                TCP_ACK,
                &[],
            );
        }
        if !payload.is_empty() {
            let state = self.state.lock().expect("the relay state");
            if let Some(flow) = state.outbound.get(&key) {
                if let Some(tx) = &flow.to_socket {
                    let _ = tx.send(payload.to_vec());
                }
            }
        }
    }

    /// A segment for an inbound flow (a connection a port mapping accepted).
    fn inbound_segment(&self, key: InboundKey, segment: &crate::frame::Tcp<'_>) {
        let (payload, syn_sent, peer) = {
            let mut state = self.state.lock().expect("the relay state");
            // A reset takes the flow away before anything else looks at it (and without holding a
            // borrow of the flow while the map is mutated).
            if segment.has(TCP_RST) {
                state.inbound.remove(&key);
                return;
            }
            let Some(flow) = state.inbound.get_mut(&key) else {
                return;
            };
            let mut numbers = flow.seq.lock().expect("the flow sequence");
            accept_ack(&mut numbers, segment);
            let syn_sent = flow.state == FlowState::SynSent;
            let mut payload = Vec::new();
            if syn_sent && segment.has(TCP_SYN) && segment.has(TCP_ACK) {
                // The guest accepted our SYN: its next byte is the one after its sequence number.
                numbers.their_next = segment.seq.wrapping_add(1);
                flow.state = FlowState::Open;
            } else if !syn_sent && accept_segment(&mut numbers, segment) {
                payload = segment.payload.to_vec();
            }
            if segment.has(TCP_FIN) {
                flow.state = FlowState::GuestClosed;
                if let Some(tx) = &flow.to_socket {
                    let _ = tx.send(Vec::new());
                }
            }
            (payload, syn_sent, flow.peer)
        };
        if !payload.is_empty() {
            // The mapping's association is in the NAT table; the bytes the guest sent are its traffic
            // , and `peer` is the other half of that association's key.
            if let Some(peer) = peer {
                let mut state = self.state.lock().expect("the relay state");
                state.nat.touch(
                    &NatKey::inbound(NatProto::Tcp, key.guest_port, peer),
                    payload.len() as u64,
                );
            }
        }
        if syn_sent || !payload.is_empty() || segment.has(TCP_FIN) {
            let (our_next, their_next, from_ip, guest_ip, guest_port, our_port) = {
                let state = self.state.lock().expect("the relay state");
                match state.inbound.get(&key) {
                    Some(flow) => {
                        let numbers = flow.seq.lock().expect("the flow sequence");
                        (
                            numbers.our_next,
                            numbers.their_next,
                            flow.from_ip,
                            flow.guest_ip,
                            flow.guest_port,
                            flow.our_port,
                        )
                    }
                    None => return,
                }
            };
            self.send_tcp(
                from_ip,
                guest_ip,
                guest_port,
                our_port,
                our_next,
                their_next,
                TCP_ACK,
                &[],
            );
        }
        if !payload.is_empty() {
            let state = self.state.lock().expect("the relay state");
            if let Some(flow) = state.inbound.get(&key) {
                if let Some(tx) = &flow.to_socket {
                    let _ = tx.send(payload);
                }
            }
        }
    }

    /// The host opened a connection through a port mapping: open the guest's side with a SYN.
    ///
    /// Called by the engine when [`crate::ports`] hands it an accepted connection. The flow is keyed
    /// by a port **we** choose, so the guest's answer is unambiguous.
    pub fn accept_inbound(
        &self,
        stream: TcpStream,
        guest_port: u16,
        peer: SocketAddr,
        target: IpAddr,
    ) -> Result<(), String> {
        // The family of the mapping's listener decides which of the machine's addresses the
        // connection is carried to: a v4 listener reaches the guest's v4 address, a v6 one its ULA
        // or link-local address.
        let (guest_ip, our_addr) = match target {
            IpAddr::V4(_) => (IpAddr::V4(self.guest.ip), IpAddr::V4(self.config.our_ip)),
            IpAddr::V6(address) => (IpAddr::V6(address), IpAddr::V6(self.config.our_ip6)),
        };
        if self.down.load(Ordering::Relaxed) {
            return Err("the machine's network is not running".to_string());
        }
        let our_port = {
            let mut state = self.state.lock().expect("the relay state");
            if state.outbound.len() + state.inbound.len() >= self.config.max_flows
                || state.nat.len() >= self.config.max_flows
            {
                drop(state);
                self.stats.dropped_busy.fetch_add(1, Ordering::Relaxed);
                return Err("the machine has too many flows open".to_string());
            }
            let start = if state.next_our_port < 49152 {
                49152
            } else {
                state.next_our_port
            };
            let mut port = start;
            loop {
                if !state.inbound.keys().any(|key| key.our_port == port) {
                    break;
                }
                port = if port == 65535 { 49152 } else { port + 1 };
                if port == start {
                    return Err("no free port for an inbound connection".to_string());
                }
            }
            state.next_our_port = if port == 65535 { 49152 } else { port + 1 };
            port
        };
        let our_isn = pseudo_isn(&self.vm, guest_port, our_port);
        let seq = Arc::new(Mutex::new(FlowSeq {
            our_next: our_isn.wrapping_add(1),
            their_next: 0,
            their_ack: our_isn,
            // Until the guest's SYN|ACK says otherwise, its window is the one a stack without window
            // scaling can advertise at most.
            their_window: 65535,
        }));
        let (tx, rx) = mpsc::channel::<Vec<u8>>();
        let key = InboundKey {
            guest_port,
            our_port,
        };
        let flow = TcpFlow {
            guest_port,
            guest_ip,
            from_ip: our_addr,
            our_port,
            seq: Arc::clone(&seq),
            to_socket: Some(tx),
            state: FlowState::SynSent,
            peer: Some(peer),
        };
        {
            let mut state = self.state.lock().expect("the relay state");
            // The inbound association: the host peer is the remote, and the port the mapping listens on
            // is recorded so a status can say which host port carried it.
            let nat_key = NatKey::inbound(NatProto::Tcp, guest_port, peer);
            if state
                .nat
                .open(nat_key, NatDirection::Inbound, Some(our_port), None)
                .is_err()
            {
                self.stats.nat_refused.fetch_add(1, Ordering::Relaxed);
            }
            state.inbound.insert(key, flow);
        }
        self.stats.tcp_flows.fetch_add(1, Ordering::Relaxed);
        // Our SYN goes to the guest; the guest's SYN|ACK is handled by `inbound_segment`.
        self.send_tcp(
            our_addr,
            guest_ip,
            guest_port,
            our_port,
            our_isn,
            0,
            TCP_SYN,
            &[],
        );
        let context = FlowContext {
            guest: self.guest,
            config: self.config.clone(),
            send: Arc::clone(&self.send),
            seq,
            stats: Arc::clone(&self.stats),
            guest_port,
            our_port,
            guest_ip,
            from_ip: our_addr,
            handshake: true,
            nat: Arc::clone(&self.state),
            nat_key: NatKey::inbound(NatProto::Tcp, guest_port, peer),
        };
        let state = Arc::clone(&self.state);
        std::thread::Builder::new()
            .name(format!("vmnet-in-{guest_port}"))
            .spawn(move || {
                let _cleanup = FlowCleanup::new(
                    Arc::clone(&state),
                    FlowLeaf::Inbound(key),
                    NatKey::inbound(NatProto::Tcp, guest_port, peer),
                );
                context.run(stream, rx);
            })
            .map_err(|err| format!("cannot start the inbound flow: {err}"))?;
        Ok(())
    }

    /// Handle one IPv4 UDP datagram: a resolver query we answer, or a flow to a host socket.
    fn handle_udp(self: &Arc<Self>, packet: &crate::frame::Ipv4<'_>) {
        let Some(datagram) = parse_udp(packet.payload) else {
            self.stats.dropped_other.fetch_add(1, Ordering::Relaxed);
            return;
        };
        self.handle_udp_at(
            IpAddr::V4(packet.src),
            datagram.src_port,
            IpAddr::V4(packet.dst),
            datagram.dst_port,
            datagram.payload,
        );
    }

    /// Handle one IPv6 UDP datagram, the same way.
    fn handle_udp6(self: &Arc<Self>, packet: &crate::frame::Ipv6<'_>) {
        let Some(datagram) = parse_udp(packet.payload) else {
            self.stats.dropped_other.fetch_add(1, Ordering::Relaxed);
            return;
        };
        self.handle_udp_at(
            IpAddr::V6(packet.src),
            datagram.src_port,
            IpAddr::V6(packet.dst),
            datagram.dst_port,
            datagram.payload,
        );
    }

    /// Carry one UDP datagram, either family: a resolver query we answer, or a flow to a host socket.
    ///
    /// `src` is the address the guest sent from (which the reply is addressed to), and `dst` where it
    /// wanted it to go. The flow's host socket is bound in the destination's family, so an external
    /// IPv6 destination leaves through the host's own IPv6 stack — no NAT64, dual-stack.
    fn handle_udp_at(
        self: &Arc<Self>,
        src: IpAddr,
        src_port: u16,
        dst: IpAddr,
        dst_port: u16,
        payload: &[u8],
    ) {
        if dst_port == 53
            && (dst == IpAddr::V4(self.config.dns_ip) || dst == IpAddr::V6(self.config.dns_ip6))
        {
            self.handle_dns(dst, src, src_port, payload);
            return;
        }
        // The time, beside the resolver: a query to the gateway's own port 123 is answered here from
        // the host's clock, so a guest's clock is right without it reaching the internet.
        if dst_port == crate::ntp::NTP_PORT && self.answers_at(dst) {
            self.handle_ntp(dst, src, src_port, payload);
            return;
        }
        if dst.is_multicast() {
            // A guest's multicast (mDNS, SSDP, …) is its own link's business and is never carried to
            // the host, which has no membership in it.
            self.stats.dropped_other.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let remote = SocketAddr::new(dst, dst_port);
        // The host's own network, refused before a socket is opened. An association that is already in
        // the table is a mapping's reply path and is left alone: that traffic was the operator's.
        if self.refuses_host(dst)
            && !self
                .state
                .lock()
                .expect("the relay state")
                .nat
                .entry(&NatKey::outbound(NatProto::Udp, src_port, remote))
                .is_some()
        {
            self.stats.dropped_host.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let key = NatKey::outbound(NatProto::Udp, src_port, remote);
        // An association already in the table is the **reply path**: a datagram that arrived through one
        // of the operator's mappings must leave through that mapping's socket (so the sender sees the
        // mapped port again), and an outbound flow's replies keep their own socket.
        let existing = {
            let state = self.state.lock().expect("the relay state");
            match state.nat.entry(&key) {
                // An association with a socket is the reply path. One without (a TCP entry, or a UDP
                // entry whose socket is gone) is not, and the datagram opens a fresh flow below.
                Some(entry) => entry
                    .socket
                    .as_ref()
                    .map(|socket| (Arc::clone(socket), entry.direction)),
                None => None,
            }
        };
        let socket = match existing {
            Some((socket, direction)) => {
                self.state
                    .lock()
                    .expect("the relay state")
                    .nat
                    .touch(&key, payload.len() as u64);
                // A **mapping's** socket is bound but not connected (it answers whoever writes to it), so
                // the guest's answer must name the destination; ours are connected and use `send`.
                let sent = match direction {
                    NatDirection::Inbound => socket.send_to(payload, remote),
                    NatDirection::Outbound => socket.send(payload),
                };
                if sent.is_err() {
                    self.stats
                        .dropped_unreachable
                        .fetch_add(1, Ordering::Relaxed);
                }
                return;
            }
            None => {
                if self.flow_budget_exhausted() {
                    self.stats.dropped_busy.fetch_add(1, Ordering::Relaxed);
                    return;
                }
                let any = if dst.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
                let socket = match UdpSocket::bind(any) {
                    Ok(socket) => Arc::new(socket),
                    Err(_) => {
                        self.stats
                            .dropped_unreachable
                            .fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                };
                let _ = socket.connect(remote);
                {
                    let mut state = self.state.lock().expect("the relay state");
                    if state
                        .nat
                        .open(key, NatDirection::Outbound, None, Some(Arc::clone(&socket)))
                        .is_err()
                    {
                        drop(state);
                        self.stats.nat_refused.fetch_add(1, Ordering::Relaxed);
                        return;
                    }
                    state.nat.touch(&key, payload.len() as u64);
                }
                self.stats.udp_flows.fetch_add(1, Ordering::Relaxed);
                self.spawn_udp_reader(key, Arc::clone(&socket), src);
                socket
            }
        };
        let _ = socket.send(payload);
    }

    /// Whether the machine is at its flow ceiling (the TCP flows and the NAT associations together).
    fn flow_budget_exhausted(&self) -> bool {
        let state = self.state.lock().expect("the relay state");
        state.outbound.len() + state.inbound.len() >= self.config.max_flows
            || state.nat.len() >= self.config.max_flows
    }

    /// Carry one datagram from a **port mapping** into the guest and remember the association.
    ///
    /// The guest sees the datagram as coming from the real sender, at the real port; when it answers to
    /// that address, the NAT table sends the answer out through the **mapping's** socket, so the sender
    /// sees a reply from the port it wrote to — the whole reason the table exists.
    pub fn accept_inbound_udp(
        &self,
        guest_port: u16,
        socket: Arc<UdpSocket>,
        host_port: u16,
        from: SocketAddr,
        payload: &[u8],
        target: IpAddr,
    ) {
        if self.down.load(Ordering::Relaxed) {
            return;
        }
        let key = NatKey::inbound(NatProto::Udp, guest_port, from);
        {
            let mut state = self.state.lock().expect("the relay state");
            if state
                .nat
                .open(
                    key,
                    NatDirection::Inbound,
                    Some(host_port),
                    Some(Arc::clone(&socket)),
                )
                .is_err()
            {
                drop(state);
                self.stats.nat_refused.fetch_add(1, Ordering::Relaxed);
                return;
            }
            state.nat.touch(&key, payload.len() as u64);
        }
        // The datagram reaches the guest from the sender it actually came from, in the mapping's own
        // family (a v4 mapping to a machine's link-local would be a frame that lies about itself).
        let frame = match (from.ip(), target) {
            (IpAddr::V4(remote), IpAddr::V4(guest)) => {
                let datagram = build_udp(remote, guest, from.port(), guest_port, payload);
                let packet = build_ipv4(remote, guest, IPPROTO_UDP, 64, &datagram);
                build_ethernet(self.guest.mac, self.config.our_mac, ETHERTYPE_IPV4, &packet)
            }
            (IpAddr::V6(remote), IpAddr::V6(guest)) => {
                let datagram = build_udp_v6(remote, guest, from.port(), guest_port, payload);
                let packet = build_ipv6(remote, guest, IPPROTO_UDP, 64, &datagram);
                build_ethernet(self.guest.mac, self.config.our_mac, ETHERTYPE_IPV6, &packet)
            }
            _ => return,
        };
        self.emit(frame);
        self.stats.inbound_udp.fetch_add(1, Ordering::Relaxed);
    }

    /// Read replies for one UDP association and carry them back to the guest.
    ///
    /// `guest_ip` is the address the guest sent its first datagram from: replies are addressed there,
    /// in that address's family.
    fn spawn_udp_reader(&self, key: NatKey, socket: Arc<UdpSocket>, guest_ip: IpAddr) {
        let guest = self.guest;
        let our_mac = self.config.our_mac;
        let send = Arc::clone(&self.send);
        let state = Arc::clone(&self.state);
        let stats = Arc::clone(&self.stats);
        // An idle flow ends by itself: a DNS lookup's socket must not live forever.
        let idle = self.config.connect_timeout.max(Duration::from_secs(30));
        let _ = socket.set_read_timeout(Some(idle));
        std::thread::Builder::new()
            .name(format!("vmnet-udp-{}", key.remote.port()))
            .spawn(move || {
                let mut buffer = vec![0u8; 65535];
                while let Ok(read) = socket.recv(&mut buffer) {
                    // The reply comes from the address the flow was opened to, in the same
                    // family as the guest's own.
                    let frame = match (key.remote.ip(), guest_ip) {
                        (IpAddr::V4(source), IpAddr::V4(to)) => {
                            let payload = build_udp(
                                source,
                                to,
                                key.remote.port(),
                                key.guest_port,
                                &buffer[..read],
                            );
                            let packet = build_ipv4(source, to, IPPROTO_UDP, 64, &payload);
                            build_ethernet(guest.mac, our_mac, ETHERTYPE_IPV4, &packet)
                        }
                        (IpAddr::V6(source), IpAddr::V6(to)) => {
                            let payload = build_udp_v6(
                                source,
                                to,
                                key.remote.port(),
                                key.guest_port,
                                &buffer[..read],
                            );
                            let packet = build_ipv6(source, to, IPPROTO_UDP, 64, &payload);
                            build_ethernet(guest.mac, our_mac, ETHERTYPE_IPV6, &packet)
                        }
                        _ => break,
                    };
                    send(frame);
                    stats.frames_out.fetch_add(1, Ordering::Relaxed);
                }
                let mut state = state.lock().expect("the relay state");
                state.nat.close(&key);
            })
            .expect("a UDP flow thread");
    }

    /// Answer a DNS query: our own names locally, everything else through the host's resolver.
    ///
    /// The answer goes back over the **same family** the query arrived on (`from` is the address the
    /// guest asked from, `dns` the DNS address it asked), so a guest resolving a name over IPv6 gets an
    /// AAAA or a proxied answer over IPv6. A query we forward is carried to the host's resolver over
    /// IPv4 whatever the guest's family: DNS is transport-independent, and a host's configured
    /// resolvers are where this process's own lookups go.
    fn handle_dns(self: &Arc<Self>, dns: IpAddr, from: IpAddr, from_port: u16, query: &[u8]) {
        if let (Some(names), Some((question, qtype))) = (&self.names, dns_question(query)) {
            let record = match qtype {
                1 => (names.addr4)(&question).map(DnsRecord::A),
                // A **link-local** is not an address a name can answer with: it is reachable only with
                // the receiving interface's scope id, which no resolver can put in the answer — and a
                // client that sees one *beside* the A record throws the whole reply away
                // (`getaddrinfo`: "Name or service not known"), which is what every client did here.
                // Measured: `nslookup ctr-web` printed 10.177.0.16 *and* `fe80::…`, and then `curl`,
                // `wget` and `ping` all failed **by name** while the address worked. So a peer's name
                // is answered with its routable address (a machine's ULA), and "no AAAA" is answered
                // as **NODATA** below instead of being invented.
                //
                // `fe80::/10` is the link-local range, read here by hand because the standard
                // library's own `is_unicast_link_local` is newer than the version this project
                // builds against.
                28 => (names.addr6)(&question)
                    .filter(|address| (address.segments()[0] & 0xffc0) != 0xfe80)
                    .map(DnsRecord::Aaaa),
                _ => None,
            };
            if let Some(record) = record {
                let answer = dns_answer(query, record);
                self.emit_udp(dns, from, from_port, &answer);
                return;
            }
            // The name is **ours** and has no record of this family: answer NODATA (rcode 0, no
            // answers) rather than forwarding it. A forwarded `ctr-web` comes back NXDOMAIN from the
            // internet, and the client is told the name does not exist while its A record was in this
            // very directory. A name that is not ours falls through to the resolver below, untouched.
            if (names.addr4)(&question).is_some() || (names.addr6)(&question).is_some() {
                let answer = dns_nodata(query);
                self.emit_udp(dns, from, from_port, &answer);
                return;
            }
        }
        let Some(resolver) = self.config.resolvers.first().copied() else {
            // No resolver on this host: an empty (SERVFAIL) answer is honest, and a silent drop would
            // look like a broken network in the guest.
            let answer = dns_servfail(query);
            self.emit_udp(dns, from, from_port, &answer);
            return;
        };
        // **Off the frame path.** The lookup is the host's to answer and can take seconds, while this
        // thread is the peer's only reader: waiting here stalls every other frame the peer sends
        // (measured: a 700ms resolver held an unrelated echo for 651ms, and an unresponsive one holds it
        // for the full five-second timeout, once per query). A thread per forwarded query, capped, keeps
        // the peer's own traffic moving; past the cap the guest is told the lookup failed rather than
        // the deployment growing threads without bound.
        let servfail = dns_servfail(query);
        if self.dns_in_flight.fetch_add(1, Ordering::Relaxed) >= MAX_DNS_IN_FLIGHT {
            self.dns_in_flight.fetch_sub(1, Ordering::Relaxed);
            self.stats.dropped_busy.fetch_add(1, Ordering::Relaxed);
            self.emit_udp(dns, from, from_port, &servfail);
            return;
        }
        let relay = Arc::clone(self);
        let query = query.to_vec();
        if std::thread::Builder::new()
            .name("dns-forward".to_string())
            .spawn(move || {
                relay.forward_dns(dns, from, from_port, resolver, &query);
                relay.dns_in_flight.fetch_sub(1, Ordering::Relaxed);
            })
            .is_err()
        {
            // No thread to spare: the lookup is refused, the peer's frames keep flowing.
            self.dns_in_flight.fetch_sub(1, Ordering::Relaxed);
            self.emit_udp(dns, from, from_port, &servfail);
        }
    }

    /// Carry one query to the host's resolver and its answer back to the guest. Runs on its own
    /// thread: see [`Relay::handle_dns`].
    ///
    /// The socket is **connected** to the resolver, so the kernel drops any datagram from anyone else,
    /// and the answer's transaction id must match the query's — an off-path packet that reached the
    /// port is not an answer. Both are cheap, and without them the first datagram to arrive would be
    /// handed to the guest as the truth.
    fn forward_dns(
        &self,
        dns: IpAddr,
        guest: IpAddr,
        guest_port: u16,
        resolver: SocketAddr,
        query: &[u8],
    ) {
        if query.len() < 12 {
            return;
        }
        let Ok(socket) = UdpSocket::bind(("0.0.0.0", 0)) else {
            return;
        };
        if socket.connect(resolver).is_err() {
            return;
        }
        if socket.send(query).is_err() {
            return;
        }
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut buffer = vec![0u8; 65535];
        loop {
            let remaining = deadline.saturating_duration_since(std::time::Instant::now());
            if remaining.is_zero() {
                return;
            }
            let _ = socket.set_read_timeout(Some(remaining.min(Duration::from_millis(500))));
            match socket.recv(&mut buffer) {
                // The id has to be the one we sent; anything else is somebody else's packet and is
                // ignored, not answered.
                Ok(read) if read >= 12 && buffer[..2] == query[..2] => {
                    self.emit_udp(dns, guest, guest_port, &buffer[..read]);
                    return;
                }
                Ok(_) => continue,
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) => {}
                Err(_) => return,
            }
        }
    }

    /// Write one resolver answer to the guest, from the DNS address it queried.
    fn emit_udp(&self, dns: IpAddr, guest_ip: IpAddr, guest_port: u16, payload: &[u8]) {
        self.emit_udp_from(dns, 53, guest_ip, guest_port, payload);
    }

    /// Whether `ip` is one of the addresses this relay **answers itself** — the gateway's own (its IPv4
    /// address, its link-local and its ULA) — rather than an address to carry somewhere.
    ///
    /// The resolver and the time server both live here, and a guest may reach this
    /// relay by any name the DHCP servers gave it.
    fn answers_at(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(address) => address == self.config.our_ip || address == self.config.dns_ip,
            IpAddr::V6(address) => {
                address == self.config.our_ip6
                    || address == self.config.our_ula6
                    || address == self.config.dns_ip6
            }
        }
    }

    /// Answer a time query: no host socket, no flow — one frame back from the gateway.
    ///
    /// The request is answered only if it is a client request this server speaks; anything else (a
    /// truncated datagram, a reply, a control mode) is a drop like any other unhandled frame, so a
    /// port scanner or a stray broadcast costs the relay nothing.
    fn handle_ntp(&self, server: IpAddr, from: IpAddr, from_port: u16, query: &[u8]) {
        match self.ntp.reply(query, std::time::SystemTime::now()) {
            Some(answer) => {
                self.emit_udp_from(server, crate::ntp::NTP_PORT, from, from_port, &answer)
            }
            None => {
                self.stats.dropped_other.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Write one datagram to the guest, from `server_ip`/`server_port` — the address and port the guest
    /// believes it is talking to. Used by the two services the relay answers itself: the resolver on 53
    /// and the time server on 123.
    fn emit_udp_from(
        &self,
        server_ip: IpAddr,
        server_port: u16,
        guest_ip: IpAddr,
        guest_port: u16,
        payload: &[u8],
    ) {
        let frame = match (server_ip, guest_ip) {
            (IpAddr::V4(from), IpAddr::V4(to)) => {
                let datagram = build_udp(from, to, server_port, guest_port, payload);
                let packet = build_ipv4(from, to, IPPROTO_UDP, 64, &datagram);
                build_ethernet(self.guest.mac, self.config.our_mac, ETHERTYPE_IPV4, &packet)
            }
            (IpAddr::V6(from), IpAddr::V6(to)) => {
                let datagram = build_udp_v6(from, to, server_port, guest_port, payload);
                let packet = build_ipv6(from, to, IPPROTO_UDP, 64, &datagram);
                build_ethernet(self.guest.mac, self.config.our_mac, ETHERTYPE_IPV6, &packet)
            }
            _ => return,
        };
        self.emit(frame);
    }

    /// One TCP segment to the guest. `from_ip` is the address the **guest** believes it is talking
    /// to: the real destination for an outbound flow, and us for an inbound one.
    #[allow(clippy::too_many_arguments)]
    fn send_tcp(
        &self,
        from_ip: IpAddr,
        guest_ip: IpAddr,
        guest_port: u16,
        our_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: &[u8],
    ) {
        let frame = tcp_frame(
            self.guest.mac,
            self.config.our_mac,
            from_ip,
            guest_ip,
            our_port,
            guest_port,
            seq,
            ack,
            flags,
            payload,
        );
        self.emit(frame);
    }

    /// Write one frame and count it.
    fn emit(&self, frame: Vec<u8>) {
        // A frame we speak over IPv6 is counted here rather than at every call site: it is the
        // counterpart of `dropped_ipv6`, and the status reads "what we refused" and "what we said".
        if frame.len() >= 14 && u16::from_be_bytes([frame[12], frame[13]]) == ETHERTYPE_IPV6 {
            self.stats.v6_frames.fetch_add(1, Ordering::Relaxed);
        }
        (self.send)(frame);
        self.stats.frames_out.fetch_add(1, Ordering::Relaxed);
    }
}

/// One flow's thread: the host socket on one side, the conduit on the other.
struct FlowContext {
    guest: GuestIdentity,
    config: RelayConfig,
    send: FrameSender,
    seq: Arc<Mutex<FlowSeq>>,
    stats: Arc<RelayStats>,
    guest_port: u16,
    our_port: u16,
    /// The guest's own address for this flow, and the address it believes it is talking to.
    guest_ip: IpAddr,
    from_ip: IpAddr,
    /// Whether this flow must wait for the guest's SYN|ACK before touching the host socket. An
    /// **inbound** flow (a port mapping) does: the host's client may have written its request before
    /// the guest even saw our SYN, and sending it with an unset acknowledgement would be a bug the
    /// guest's stack could not recover from.
    handshake: bool,
    /// The flow's association in the built-in NAT table, so the bytes read **from the host** are
    /// counted against it too (``: the table's counters are the whole conversation, not one side).
    nat: Arc<Mutex<State>>,
    nat_key: NatKey,
}

impl FlowContext {
    /// Run the host socket to completion: read what it sent, carry it to the guest, and write what the
    /// guest sent to it.
    fn run(&self, mut stream: TcpStream, rx: Receiver<Vec<u8>>) {
        if self.handshake && !self.wait_for_handshake() {
            // The guest never accepted the connection: drop the host's client rather than carry bytes
            // into a flow that does not exist.
            return;
        }
        // **Neither direction may wait on the other.** This loop used to read the host socket with a
        // 200 ms timeout and then wait up to 20 ms on the guest's channel: a download moved one
        // 1400-byte segment per 20 ms (~70 kB/s) and an upload one payload per 200 ms (~58 kbps),
        // whatever the link underneath could do. Both directions are drained every pass now, the host
        // read waits a millisecond rather than two hundred, and the guest's **window** is what stops us
        // sending more (`FlowSeq::room`) — the one thing that must not be ignored: the guest drops what
        // does not fit and nothing on this side retransmits.
        let _ = stream.set_read_timeout(Some(Duration::from_millis(1)));
        let mut buffer = vec![0u8; 64 * 1024];
        let mut guest_finished = false;
        let mut last_activity = std::time::Instant::now();
        // How long to wait for the guest when neither direction moved. A pass that moved something
        // waits a millisecond or two — a window that just filled reopens when the guest's ack lands,
        // and that ack does not ring a bell of its own — while a flow that has been quiet for a while
        // backs off so it is not a busy loop.
        let mut idle = Duration::from_millis(2);
        loop {
            // The guest first: its payloads are what the host is waiting for, and its acks are what
            // reopen the window for the host's data.
            let mut moved = false;
            loop {
                match rx.try_recv() {
                    Ok(payload) if payload.is_empty() => {
                        // The guest is done sending: half-close the host socket, and end when it
                        // answers with its own end of stream.
                        guest_finished = true;
                        let _ = stream.shutdown(Shutdown::Write);
                    }
                    Ok(payload) => {
                        moved = true;
                        last_activity = std::time::Instant::now();
                        if stream.write_all(&payload).is_err() {
                            let (our_next, their_next) = self.numbers();
                            self.emit_segment(our_next, their_next, TCP_RST | TCP_ACK, &[]);
                            return;
                        }
                    }
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => return,
                }
            }
            // Then the host, as far as the guest's window allows: a full window leaves the rest in the
            // kernel's socket buffer, which is TCP's own backpressure on the server.
            loop {
                let room = self.room();
                if room == 0 {
                    break;
                }
                let take = room.min(buffer.len());
                match stream.read(&mut buffer[..take]) {
                    Ok(0) => {
                        // The host closed: FIN to the guest (one sequence number for the FIN itself).
                        let (our_next, their_next) = self.advance(1);
                        self.emit_segment(our_next, their_next, TCP_FIN | TCP_ACK, &[]);
                        return;
                    }
                    Ok(read) => {
                        moved = true;
                        last_activity = std::time::Instant::now();
                        self.nat
                            .lock()
                            .expect("the relay state")
                            .nat
                            .touch(&self.nat_key, read as u64);
                        let mut offset = 0;
                        while offset < read {
                            let end = (offset + 1400).min(read);
                            let (our_next, their_next) = self.advance((end - offset) as u32);
                            self.emit_segment(
                                our_next,
                                their_next,
                                TCP_ACK | TCP_PSH,
                                &buffer[offset..end],
                            );
                            offset = end;
                        }
                    }
                    Err(err)
                        if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) =>
                    {
                        break
                    }
                    Err(err) if err.kind() == ErrorKind::Interrupted => continue,
                    Err(_) => {
                        let (our_next, their_next) = self.numbers();
                        self.emit_segment(our_next, their_next, TCP_RST | TCP_ACK, &[]);
                        return;
                    }
                }
            }
            if !moved {
                if last_activity.elapsed() >= FLOW_IDLE {
                    // A peer that went away without saying so: the guest is told (it may still have a
                    // socket open on its side) and the flow gives its place back through the guard.
                    let (our_next, their_next) = self.numbers();
                    self.emit_segment(our_next, their_next, TCP_RST | TCP_ACK, &[]);
                    return;
                }
                // Both sides are quiet: wait for the guest rather than spinning. The host's side is
                // picked up by the read above, which waits a millisecond.
                match rx.recv_timeout(idle) {
                    Ok(payload) if payload.is_empty() => {
                        guest_finished = true;
                        let _ = stream.shutdown(Shutdown::Write);
                    }
                    Ok(payload) => {
                        if stream.write_all(&payload).is_err() {
                            let (our_next, their_next) = self.numbers();
                            self.emit_segment(our_next, their_next, TCP_RST | TCP_ACK, &[]);
                            return;
                        }
                    }
                    Err(mpsc::RecvTimeoutError::Timeout) => {
                        idle = (idle * 2).min(Duration::from_millis(50));
                    }
                    Err(mpsc::RecvTimeoutError::Disconnected) => return,
                }
            } else {
                idle = Duration::from_millis(2);
            }
            if guest_finished {
                // Nothing more can arrive from the guest; the read above will report the host's end.
                let _ = guest_finished;
            }
        }
    }

    /// Wait for the guest's SYN|ACK on an inbound flow, up to the connect timeout.
    fn wait_for_handshake(&self) -> bool {
        let deadline = std::time::Instant::now() + self.config.connect_timeout;
        loop {
            if self.seq.lock().expect("the flow sequence").their_next != 0 {
                return true;
            }
            if std::time::Instant::now() >= deadline {
                let (our_next, their_next) = {
                    let numbers = self.seq.lock().expect("the flow sequence");
                    (numbers.our_next, numbers.their_next)
                };
                self.emit_segment(our_next, their_next, TCP_RST | TCP_ACK, &[]);
                return false;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// Advance our sequence number by `count` and return what we sent and what we expect.
    /// The flow's current numbers, for a segment that does not consume sequence space (a RST).
    fn numbers(&self) -> (u32, u32) {
        let numbers = self.seq.lock().expect("the flow sequence");
        (numbers.our_next, numbers.their_next)
    }

    /// How many more bytes the guest's window lets us send right now.
    fn room(&self) -> usize {
        self.seq.lock().expect("the flow sequence").room()
    }

    fn advance(&self, count: u32) -> (u32, u32) {
        let mut numbers = self.seq.lock().expect("the flow sequence");
        let next = numbers.our_next;
        numbers.our_next = numbers.our_next.wrapping_add(count);
        (next, numbers.their_next)
    }

    /// One segment to the guest, from this flow.
    fn emit_segment(&self, seq: u32, ack: u32, flags: u8, payload: &[u8]) {
        let frame = tcp_frame(
            self.guest.mac,
            self.config.our_mac,
            self.from_ip,
            self.guest_ip,
            self.our_port,
            self.guest_port,
            seq,
            ack,
            flags,
            payload,
        );
        (self.send)(frame);
        self.stats.frames_out.fetch_add(1, Ordering::Relaxed);
    }
}

/// One TCP segment as a whole Ethernet frame, in whichever family the two addresses are.
///
/// The families must match: a v4 flow's frames are IPv4 and a v6 flow's are IPv6, and a flow's family
/// comes from the frame that started it, so a mismatch is not something a caller can produce. If one
/// ever appeared, the guest gets nothing rather than a frame that lies about its family.
#[allow(clippy::too_many_arguments)]
fn tcp_frame(
    guest_mac: [u8; 6],
    our_mac: [u8; 6],
    from_ip: IpAddr,
    guest_ip: IpAddr,
    from_port: u16,
    guest_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    payload: &[u8],
) -> Vec<u8> {
    match (from_ip, guest_ip) {
        (IpAddr::V4(from), IpAddr::V4(guest)) => {
            let segment = build_tcp(
                from, guest, from_port, guest_port, seq, ack, flags, 64240, payload,
            );
            let packet = build_ipv4(from, guest, IPPROTO_TCP, 64, &segment);
            build_ethernet(guest_mac, our_mac, ETHERTYPE_IPV4, &packet)
        }
        (IpAddr::V6(from), IpAddr::V6(guest)) => {
            let segment = crate::frame::build_tcp_v6(
                from, guest, from_port, guest_port, seq, ack, flags, 64240, payload,
            );
            let packet = build_ipv6(from, guest, IPPROTO_TCP, 64, &segment);
            build_ethernet(guest_mac, our_mac, ETHERTYPE_IPV6, &packet)
        }
        _ => Vec::new(),
    }
}

/// Accept a guest segment if it is the next one, and advance what we expect.
///
/// Returns whether the payload is new (and should be forwarded). A retransmission is ACKed but not
/// forwarded again; a gap is ACKed with what we have, so the guest retransmits from the hole.
fn accept_segment(numbers: &mut FlowSeq, segment: &crate::frame::Tcp<'_>) -> bool {
    let length = segment.payload.len() as u32;
    if segment.seq == numbers.their_next {
        let fin = if segment.has(TCP_FIN) { 1 } else { 0 };
        numbers.their_next = numbers.their_next.wrapping_add(length + fin);
        return true;
    }
    // A duplicate (or an old retransmission) is not forwarded again; anything else is a gap, and the
    // ACK we send tells the guest where we are.
    false
}

/// A stable, per-flow initial sequence number: not random (this is not a security boundary — the only
/// peer is the guest's own stack) but different per flow, which is all a stack needs.
fn pseudo_isn(vm: &str, guest_port: u16, other_port: u16) -> u32 {
    let mut hash: u32 = 2166136261;
    for byte in vm
        .bytes()
        .chain(guest_port.to_be_bytes())
        .chain(other_port.to_be_bytes())
    {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(16777619);
    }
    hash
}

/// The first question of a DNS query: its name (lower-case, no trailing dot) **and its type**, when
/// it is a type we can answer ourselves.
///
/// The type matters over IPv6: a guest resolving `vm-debian` asks for `AAAA`, and answering it with an
/// A record would be a reply to a different question.
fn dns_question(query: &[u8]) -> Option<(String, u16)> {
    if query.len() < 12 {
        return None;
    }
    if u16::from_be_bytes([query[4], query[5]]) != 1 {
        return None;
    }
    let mut labels = Vec::new();
    let mut offset = 12;
    loop {
        let length = *query.get(offset)? as usize;
        if length == 0 {
            offset += 1;
            break;
        }
        if length > 63 || offset + 1 + length > query.len() {
            return None;
        }
        let label = std::str::from_utf8(&query[offset + 1..offset + 1 + length]).ok()?;
        labels.push(label.to_ascii_lowercase());
        offset += 1 + length;
    }
    let qtype = u16::from_be_bytes([*query.get(offset)?, *query.get(offset + 1)?]);
    if !matches!(qtype, 1 | 28) || labels.is_empty() {
        return None;
    }
    Some((labels.join("."), qtype))
}

/// The offset just past the first question: the end of its name, its type and its class.
///
/// An answer echoes the **question section and nothing else** — see [`dns_answer`], where the rest of
/// the client's query (an EDNS0 OPT record, which glibc sends because a guest's `/etc/resolv.conf`
/// carries `options edns0 trust-ad`) must not come back with `ARCOUNT` zeroed: that is a packet whose
/// sections do not add up, and glibc's `getaddrinfo` discards the whole answer with *"Name or service
/// not known"* — measured: `nslookup ctr-web` (a resolver that does not ask with EDNS0) answered
/// 10.177.0.16 while `getent hosts`, `getent ahostsv4`, `wget` and `ping` all failed by name.
fn dns_question_end(query: &[u8]) -> Option<usize> {
    if query.len() < 12 || u16::from_be_bytes([query[4], query[5]]) != 1 {
        return None;
    }
    let mut offset = 12;
    loop {
        let length = *query.get(offset)? as usize;
        if length == 0 {
            offset += 1;
            break;
        }
        if length > 63 || offset + 1 + length > query.len() {
            return None;
        }
        offset += 1 + length;
    }
    // The type and the class.
    let end = offset + 4;
    (end <= query.len()).then_some(end)
}

/// The record a name resolves to, in the family the guest asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DnsRecord {
    /// An A record: the machine's IPv4 lease.
    A(Ipv4Addr),
    /// An AAAA record: the machine's IPv6 address (its DHCPv6 lease, or its link-local).
    Aaaa(Ipv6Addr),
}

impl DnsRecord {
    /// The record's type code, and its data.
    fn wire(self) -> (u16, Vec<u8>) {
        match self {
            DnsRecord::A(address) => (1, address.octets().to_vec()),
            DnsRecord::Aaaa(address) => (28, address.octets().to_vec()),
        }
    }
}

/// Build an answer for `query` pointing at `record`: the same question, one record, authoritative.
fn dns_answer(query: &[u8], record: DnsRecord) -> Vec<u8> {
    // The question section, and only it: whatever else the client sent (an EDNS0 OPT record) is not
    // echoed — the counts below say there are no other sections, and a copy that kept the bytes would
    // not add up. See `dns_question_end`.
    let Some(end) = dns_question_end(query) else {
        return query.to_vec();
    };
    let mut answer = query[..end].to_vec();
    answer[2] = 0x84; // QR = 1, AA = 1
    answer[3] = 0x00; // no error
    answer[6..8].copy_from_slice(&1u16.to_be_bytes()); // ANCOUNT = 1
    answer[8..12].copy_from_slice(&[0, 0, 0, 0]);
    let (kind, data) = record.wire();
    // A pointer to the question's name (offset 12), then type/class/TTL/rdlength/rdata.
    answer.extend_from_slice(&[0xc0, 0x0c]);
    answer.extend_from_slice(&kind.to_be_bytes());
    answer.extend_from_slice(&1u16.to_be_bytes());
    answer.extend_from_slice(&30u32.to_be_bytes());
    answer.extend_from_slice(&(data.len() as u16).to_be_bytes());
    answer.extend_from_slice(&data);
    answer
}

/// A SERVFAIL for a query we cannot even proxy (no resolver on the host).
fn dns_servfail(query: &[u8]) -> Vec<u8> {
    let Some(end) = dns_question_end(query) else {
        return query.to_vec();
    };
    let mut answer = query[..end].to_vec();
    answer[2] = 0x80;
    answer[3] = 0x02; // SERVFAIL
    answer[6..8].copy_from_slice(&0u16.to_be_bytes());
    answer[8..12].copy_from_slice(&[0, 0, 0, 0]);
    answer
}

/// The **NODATA** answer: the name exists (ours), and this family has no record — `rcode` 0 with no
/// answers, which a resolver reads as "no AAAA here" and which leaves the A it already has usable.
///
/// This is the alternative to inventing an address for a family a peer has nothing routable in: a
/// link-local is a real address but not one a name can carry (see `handle_dns`), and NXDOMAIN would be
/// a lie about a name we know.
fn dns_nodata(query: &[u8]) -> Vec<u8> {
    let Some(end) = dns_question_end(query) else {
        return query.to_vec();
    };
    let mut answer = query[..end].to_vec();
    answer[2] = 0x84; // QR = 1, AA = 1
    answer[3] = 0x00; // no error, and no answers of this type
    answer[6..8].copy_from_slice(&0u16.to_be_bytes());
    answer[8..12].copy_from_slice(&[0, 0, 0, 0]);
    answer
}

/// The source and destination ports of an IPv4 packet, when it has a transport header to read them from.
///
/// A fragment other than the first carries neither (its payload is the middle of a segment), which is why
/// this is `None` there and the callers drop the packet with a counter.
fn ports_of(packet: &crate::frame::Ipv4<'_>) -> Option<(u16, u16)> {
    match packet.protocol {
        IPPROTO_TCP => {
            parse_tcp(packet.payload).map(|segment| (segment.src_port, segment.dst_port))
        }
        IPPROTO_UDP => {
            parse_udp(packet.payload).map(|datagram| (datagram.src_port, datagram.dst_port))
        }
        _ => None,
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::frame::{build_arp_request, build_icmp_echo_request, ARP_REPLY};
    use std::os::unix::net::UnixDatagram;
    use std::sync::atomic::AtomicU32;

    const GUEST_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0xaa, 0xbb, 0xcc];
    const OUR_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x00, 0x00, 0x01];
    const PEER_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x00, 0x00, 0x10];

    fn ip(text: &str) -> Ipv4Addr {
        text.parse().expect("an address")
    }

    fn ip6(text: &str) -> Ipv6Addr {
        text.parse().expect("an address")
    }

    fn guest_ip() -> Ipv4Addr {
        ip("10.177.0.16")
    }

    /// The guest's own link-local, which is the source of every v6 frame it writes.
    fn guest6() -> Ipv6Addr {
        crate::frame::link_local_of(GUEST_MAC)
    }

    /// Our own link-local on the conduit: the address every NDP answer comes from.
    fn our6() -> Ipv6Addr {
        crate::frame::link_local_of(OUR_MAC)
    }

    /// A peer's DHCPv6 ULA inside the machines' prefix.
    fn peer6() -> Ipv6Addr {
        ip6("fd10:177::17")
    }

    /// One TCP segment, owned (the parser borrows the frame; the tests keep the fields).
    #[derive(Debug)]
    struct Seg {
        src: Ipv4Addr,
        dst: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        payload: Vec<u8>,
    }

    impl Seg {
        fn has(&self, flag: u8) -> bool {
            self.flags & flag != 0
        }
    }

    /// A relay wired to a unix socketpair: the test plays the guest, exactly as the machine's `dgram` backend
    /// would. What the relay writes is captured in order.
    type PeerRecordings = Arc<Mutex<Vec<(IpAddr, Vec<u8>)>>>;

    struct Rig {
        relay: Arc<Relay>,
        guest: UnixDatagram,
        from_relay: Arc<Mutex<Vec<Vec<u8>>>>,
        /// What the relay sent to each peer it was configured with, in order.
        peers: PeerRecordings,
    }

    impl Rig {
        fn new() -> Rig {
            Rig::with_peers(Vec::new(), None)
        }

        fn with_peers(peers: Vec<Ipv4Addr>, names: Option<NameDirectory>) -> Rig {
            Rig::with_addresses(peers.into_iter().map(IpAddr::V4).collect(), names)
        }

        /// The same setup with the **host's own policy** in force, which is what production always
        /// has: a datagram to a host-network address (loopback, link-local, multicast, broadcast) is
        /// refused before a socket exists.
        fn with_host_guard(peers: Vec<Ipv4Addr>) -> Rig {
            Rig::with_addresses_and_guard(
                peers.into_iter().map(IpAddr::V4).collect(),
                None,
                Some(Arc::new(crate::host::HostGuard::discover())),
            )
        }

        /// The same setup with peers of either family.
        fn with_addresses(peers: Vec<IpAddr>, names: Option<NameDirectory>) -> Rig {
            Rig::with_addresses_and_guard(peers, names, None)
        }

        fn with_addresses_and_guard(
            peers: Vec<IpAddr>,
            names: Option<NameDirectory>,
            host_guard: Option<Arc<crate::host::HostGuard>>,
        ) -> Rig {
            let (relay_side, guest_side) = UnixDatagram::pair().expect("a socketpair");
            // The conduit, in both directions: the relay writes frames to its end, the test reads the
            // other one; the test writes frames the relay reads and `handle`s. Nothing here is a
            // stub — it is the same datagram interface the VMM uses with `local.type=fd`.
            let relay_out = relay_side.try_clone().expect("a clone of the relay's end");
            let _ = relay_side.set_write_timeout(Some(Duration::from_millis(500)));
            let send: FrameSender = Arc::new(move |frame: Vec<u8>| {
                let _ = relay_out.send(&frame);
            });
            let captured = Arc::new(Mutex::new(Vec::new()));
            let peer_frames = Arc::new(Mutex::new(Vec::new()));
            let directory = if peers.is_empty() {
                Arc::new(NoPeers) as Arc<dyn PeerDirectory>
            } else {
                let captured = Arc::clone(&peer_frames);
                let list: Vec<(IpAddr, [u8; 6], FrameSender)> = peers
                    .iter()
                    .map(|address| {
                        let captured = Arc::clone(&captured);
                        let address = *address;
                        let sender: FrameSender = Arc::new(move |frame: Vec<u8>| {
                            captured
                                .lock()
                                .expect("the peer capture")
                                .push((address, frame));
                        });
                        (address, PEER_MAC, sender)
                    })
                    .collect();
                Arc::new(FixedPeers::new(list)) as Arc<dyn PeerDirectory>
            };
            let config = RelayConfig {
                our_mac: OUR_MAC,
                our_ip: ip("10.177.0.1"),
                dns_ip: ip("10.177.0.1"),
                our_ip6: crate::frame::link_local_of(OUR_MAC),
                our_ula6: ip6("fd10:177::1"),
                dns_ip6: crate::frame::link_local_of(OUR_MAC),
                subnet: ip("10.177.0.0"),
                prefix: 16,
                subnet6: ip6("fd10:177::"),
                prefix6: 64,
                connect_timeout: Duration::from_secs(2),
                max_flows: 32,
                resolvers: Vec::new(),
                // No host policy unless the test asked for one: most of these drive a guest straight at
                // a `127.0.0.1` server to exercise the byte path. The engine, which is what production
                // uses, always has one.
                host_guard,
                gateway_ports: Arc::new(GatewayPorts::new()),
                workspace: "ws-1".to_string(),
            };
            let relay = Relay::new(
                "vm-1",
                config,
                GuestIdentity {
                    mac: GUEST_MAC,
                    ip: guest_ip(),
                    ip6: crate::frame::link_local_of(GUEST_MAC),
                },
                send,
                directory,
                names,
            );
            // The guest's frames arrive on the relay's end and go straight into `handle`, as the
            // engine does with what it reads from the conduit.
            let relay_in = relay_side.try_clone().expect("a clone of the relay's end");
            let handler = Arc::clone(&relay);
            std::thread::spawn(move || {
                let mut buffer = vec![0u8; 65536];
                while let Ok(read) = relay_in.recv(&mut buffer) {
                    handler.handle(&buffer[..read]);
                }
            });
            // And what the relay writes is collected, in order.
            let guest_out = guest_side.try_clone().expect("a clone of the guest's end");
            let collected = Arc::clone(&captured);
            std::thread::spawn(move || {
                let mut buffer = vec![0u8; 65536];
                while let Ok(read) = guest_out.recv(&mut buffer) {
                    collected
                        .lock()
                        .expect("the capture")
                        .push(buffer[..read].to_vec());
                }
            });
            let _ = guest_side.set_write_timeout(Some(Duration::from_millis(500)));
            Rig {
                relay,
                guest: guest_side,
                from_relay: captured,
                peers: peer_frames,
            }
        }

        fn send(&self, frame: Vec<u8>) {
            self.guest.send(&frame).expect("the guest writes");
        }

        /// Wait for a frame the relay wrote that satisfies `predicate`.
        fn frame_where(&self, predicate: impl Fn(&[u8]) -> bool) -> Vec<u8> {
            for _ in 0..600 {
                let mut frames = self.from_relay.lock().expect("the capture");
                if let Some(index) = frames.iter().position(|frame| predicate(frame)) {
                    return frames.remove(index);
                }
                drop(frames);
                std::thread::sleep(Duration::from_millis(5));
            }
            panic!("no matching frame arrived");
        }

        fn answered_nothing(&self) -> bool {
            self.from_relay.lock().expect("the capture").is_empty()
        }

        /// Take every frame the relay has written so far, so a bulk test can drain in batches instead
        /// of scanning the capture once per segment.
        fn take_frames(&self) -> Vec<Vec<u8>> {
            std::mem::take(&mut *self.from_relay.lock().expect("the capture"))
        }

        fn guest_udp(
            &self,
            dst: Ipv4Addr,
            dst_port: u16,
            src_port: u16,
            payload: &[u8],
        ) -> Vec<u8> {
            let datagram = build_udp(guest_ip(), dst, src_port, dst_port, payload);
            let packet = build_ipv4(guest_ip(), dst, IPPROTO_UDP, 64, &datagram);
            build_ethernet(OUR_MAC, GUEST_MAC, ETHERTYPE_IPV4, &packet)
        }

        /// A TCP segment from the guest, in one frame: the header's own fields in the order they
        /// go on the wire, which is how the tests read them.
        #[allow(clippy::too_many_arguments)]
        fn guest_tcp(
            &self,
            dst: Ipv4Addr,
            dst_port: u16,
            src_port: u16,
            seq: u32,
            ack: u32,
            flags: u8,
            payload: &[u8],
        ) -> Vec<u8> {
            let segment = build_tcp(
                guest_ip(),
                dst,
                src_port,
                dst_port,
                seq,
                ack,
                flags,
                64240,
                payload,
            );
            let packet = build_ipv4(guest_ip(), dst, IPPROTO_TCP, 64, &segment);
            build_ethernet(OUR_MAC, GUEST_MAC, ETHERTYPE_IPV4, &packet)
        }

        /// A UDP datagram from the guest's link-local to `dst`, in one frame.
        fn guest_udp6(
            &self,
            dst: Ipv6Addr,
            dst_port: u16,
            src_port: u16,
            payload: &[u8],
        ) -> Vec<u8> {
            let datagram = build_udp_v6(guest6(), dst, src_port, dst_port, payload);
            let packet = build_ipv6(guest6(), dst, IPPROTO_UDP, 64, &datagram);
            build_ethernet(OUR_MAC, GUEST_MAC, ETHERTYPE_IPV6, &packet)
        }

        /// A TCP segment from the guest's link-local, in one frame.
        /// The same segment over IPv6.
        #[allow(clippy::too_many_arguments)]
        fn guest_tcp6(
            &self,
            dst: Ipv6Addr,
            dst_port: u16,
            src_port: u16,
            seq: u32,
            ack: u32,
            flags: u8,
            payload: &[u8],
        ) -> Vec<u8> {
            let segment = crate::frame::build_tcp_v6(
                guest6(),
                dst,
                src_port,
                dst_port,
                seq,
                ack,
                flags,
                64240,
                payload,
            );
            let packet = build_ipv6(guest6(), dst, IPPROTO_TCP, 64, &segment);
            build_ethernet(OUR_MAC, GUEST_MAC, ETHERTYPE_IPV6, &packet)
        }

        /// An ICMPv6 message from the guest (`src` is `::` for a DAD probe).
        fn guest_icmp6(&self, src: Ipv6Addr, dst: Ipv6Addr, kind: u8, body: &[u8]) -> Vec<u8> {
            let message = build_icmpv6(src, dst, kind, 0, body);
            let packet = build_ipv6(src, dst, IPPROTO_ICMPV6, 255, &message);
            let mac = if dst.is_multicast() {
                multicast_mac(dst)
            } else {
                OUR_MAC
            };
            build_ethernet(mac, GUEST_MAC, ETHERTYPE_IPV6, &packet)
        }

        /// The ICMPv6 body (the four bytes after the checksum, then the rest), which is what the
        /// NDP parsers take.
        fn icmp6_body(message: &Icmp<'_>) -> Vec<u8> {
            let mut body = message.rest.to_vec();
            body.extend_from_slice(message.payload);
            body
        }

        /// The IPv6 packet inside a captured frame, with its next header and payload.
        fn inner6(frame: &[u8]) -> (u8, Ipv6Addr, Ipv6Addr, Vec<u8>) {
            let ethernet = parse_ethernet(frame).expect("a frame");
            let packet = parse_ipv6(ethernet.payload).expect("a packet");
            (
                packet.next_header,
                packet.src,
                packet.dst,
                packet.payload.to_vec(),
            )
        }

        /// The IPv4 packet inside a captured frame, with its payload.
        fn inner(frame: &[u8]) -> (u8, Vec<u8>) {
            let ethernet = parse_ethernet(frame).expect("a frame");
            let packet = parse_ipv4(ethernet.payload).expect("a packet");
            (packet.protocol, packet.payload.to_vec())
        }

        /// A TCP segment from a captured frame, owned so the assertions can keep it.
        fn tcp_segment(frame: &[u8]) -> Seg {
            let ethernet = parse_ethernet(frame).expect("a frame");
            let packet = parse_ipv4(ethernet.payload).expect("a packet");
            let segment = parse_tcp(packet.payload).expect("a segment");
            Seg {
                src: packet.src,
                dst: packet.dst,
                src_port: segment.src_port,
                dst_port: segment.dst_port,
                seq: segment.seq,
                ack: segment.ack,
                flags: segment.flags,
                payload: segment.payload.to_vec(),
            }
        }
    }

    #[test]
    fn the_gateway_answers_arp_for_itself() {
        let rig = Rig::new();
        let request = build_arp_request(GUEST_MAC, guest_ip(), ip("10.177.0.1"));
        rig.send(build_ethernet(OUR_MAC, GUEST_MAC, ETHERTYPE_ARP, &request));
        let frame = rig
            .frame_where(|frame| parse_ethernet(frame).map(|e| e.ethertype) == Some(ETHERTYPE_ARP));
        let ethernet = parse_ethernet(&frame).expect("a frame");
        assert_eq!(
            ethernet.dst, GUEST_MAC,
            "the answer is addressed to the asker"
        );
        assert_eq!(ethernet.src, OUR_MAC);
        let reply = parse_arp(ethernet.payload).expect("an ARP message");
        assert_eq!(reply.op, ARP_REPLY);
        assert_eq!(reply.sender_ip, ip("10.177.0.1"));
        assert_eq!(reply.sender_mac, OUR_MAC);
        assert_eq!(reply.target_ip, guest_ip());
    }

    #[test]
    fn a_peer_is_answered_by_proxy_arp_and_an_unknown_machine_is_not() {
        let peer_ip = ip("10.177.0.17");
        let rig = Rig::with_peers(vec![peer_ip], None);
        let request = build_arp_request(GUEST_MAC, guest_ip(), peer_ip);
        rig.send(build_ethernet(OUR_MAC, GUEST_MAC, ETHERTYPE_ARP, &request));
        let frame = rig
            .frame_where(|frame| parse_ethernet(frame).map(|e| e.ethertype) == Some(ETHERTYPE_ARP));
        let reply = parse_arp(parse_ethernet(&frame).expect("a frame").payload).expect("ARP");
        assert_eq!(reply.sender_ip, peer_ip, "the peer's address is spoken for");
        assert_eq!(reply.sender_mac, PEER_MAC, "with the peer's MAC");

        // An address in our subnet that is not a reachable peer gets no answer at all.
        let rig = Rig::with_peers(vec![peer_ip], None);
        let request = build_arp_request(GUEST_MAC, guest_ip(), ip("10.177.0.99"));
        rig.send(build_ethernet(OUR_MAC, GUEST_MAC, ETHERTYPE_ARP, &request));
        std::thread::sleep(Duration::from_millis(80));
        assert!(rig.answered_nothing(), "no reply for nobody");
        assert_eq!(rig.relay.snapshot().dropped_unreachable, 1);
    }

    #[test]
    fn an_echo_to_the_gateway_is_answered_and_an_echo_elsewhere_is_dropped() {
        let rig = Rig::new();
        let echo = build_icmp_echo_request(0x2222, 3, b"hello");
        let packet = build_ipv4(guest_ip(), ip("10.177.0.1"), IPPROTO_ICMP, 64, &echo);
        rig.send(build_ethernet(OUR_MAC, GUEST_MAC, ETHERTYPE_IPV4, &packet));
        let frame = rig.frame_where(|frame| Rig::inner(frame).0 == IPPROTO_ICMP);
        let (protocol, payload) = Rig::inner(&frame);
        assert_eq!(protocol, IPPROTO_ICMP);
        let reply = parse_icmp(&payload).expect("ICMP");
        assert_eq!(reply.kind, 0, "an echo reply");
        assert_eq!(reply.rest, [0x22, 0x22, 0x00, 0x03]);
        assert_eq!(reply.payload, b"hello");
        assert_eq!(rig.relay.snapshot().icmp_replies, 1);

        // An echo to an external host is not fabricated.
        let echo = build_icmp_echo_request(1, 1, b"x");
        let packet = build_ipv4(guest_ip(), ip("93.184.216.34"), IPPROTO_ICMP, 64, &echo);
        rig.send(build_ethernet(OUR_MAC, GUEST_MAC, ETHERTYPE_IPV4, &packet));
        std::thread::sleep(Duration::from_millis(80));
        assert!(rig.relay.snapshot().dropped_unreachable >= 1);
    }

    #[test]
    fn an_echo_to_a_host_outside_the_subnet_is_answered_when_the_host_allows_it() {
        // The relay pings for the guest when this host grants an unprivileged ICMP socket (a datagram
        // socket with `IPPROTO_ICMP`), which is what makes a guest's `ping` work without a capability.
        // When the host forbids it, the request is dropped **with a counter** instead — and this test
        // asserts whichever answer this host gives, because both are correct.
        let rig = Rig::new();
        let echo = crate::frame::build_icmp_echo_request(0x1234, 9, b"ping");
        let packet = build_ipv4(guest_ip(), ip("127.0.0.1"), IPPROTO_ICMP, 64, &echo);
        rig.send(build_ethernet(OUR_MAC, GUEST_MAC, ETHERTYPE_IPV4, &packet));
        std::thread::sleep(Duration::from_millis(500));
        let snapshot = rig.relay.snapshot();
        if snapshot.icmp_unavailable > 0 {
            assert_eq!(
                snapshot.icmp_replies, 0,
                "no ping socket, no reply: {snapshot:?}"
            );
            return;
        }
        let frame = rig.frame_where(|frame| Rig::inner(frame).0 == IPPROTO_ICMP);
        let (_, payload) = Rig::inner(&frame);
        let reply = parse_icmp(&payload).expect("ICMP");
        assert_eq!(reply.kind, 0, "an echo reply");
        assert_eq!(
            reply.rest,
            [0x12, 0x34, 0x00, 0x09],
            "the guest's own identifier and sequence come back"
        );
        assert_eq!(reply.payload, b"ping", "with the data the host echoed");
        assert_eq!(rig.relay.snapshot().icmp_replies, 1);
    }

    #[test]
    fn a_udp_flow_reaches_a_host_socket_and_its_reply_comes_back() {
        let server = UdpSocket::bind("127.0.0.1:0").expect("a host server");
        let server_port = server.local_addr().expect("an address").port();
        std::thread::spawn(move || {
            let mut buffer = [0u8; 1024];
            if let Ok((read, from)) = server.recv_from(&mut buffer) {
                let mut reply = b"pong:".to_vec();
                reply.extend_from_slice(&buffer[..read]);
                let _ = server.send_to(&reply, from);
            }
        });

        let rig = Rig::new();
        rig.send(rig.guest_udp(ip("127.0.0.1"), server_port, 40000, b"ping"));
        let frame = rig.frame_where(|frame| match Rig::inner(frame) {
            (protocol, payload) if protocol == IPPROTO_UDP => parse_udp(&payload)
                .map(|datagram| datagram.payload.starts_with(b"pong:"))
                .unwrap_or(false),
            _ => false,
        });
        let ethernet = parse_ethernet(&frame).expect("a frame");
        let packet = parse_ipv4(ethernet.payload).expect("a packet");
        assert_eq!(packet.dst, guest_ip(), "the answer is for the guest");
        assert_eq!(
            packet.src,
            ip("127.0.0.1"),
            "and comes from the address it asked"
        );
        let datagram = parse_udp(packet.payload).expect("a datagram");
        assert_eq!(datagram.dst_port, 40000, "the guest's port");
        assert_eq!(datagram.src_port, server_port);
        assert_eq!(datagram.payload, b"pong:ping");
        assert_eq!(rig.relay.snapshot().udp_flows, 1);
    }

    #[test]
    fn a_tcp_flow_handshakes_carries_bytes_and_closes() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a host server");
        let server_port = listener.local_addr().expect("an address").port();
        // The host holds the connection open until the test has looked at the tables, so the
        // assertions below are about a **live** flow — and the end of the test is about what happens
        // when it closes (`a_finished_flow_gives_its_place_back`).
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("a connection");
            let mut buffer = [0u8; 1024];
            let read = stream.read(&mut buffer).expect("a request");
            assert_eq!(&buffer[..read], b"ping\n");
            stream.write_all(b"pong\n").expect("a reply");
            let _ = release_rx.recv_timeout(Duration::from_secs(5));
            stream.shutdown(Shutdown::Write).expect("the server closes");
            std::thread::sleep(Duration::from_millis(200));
        });

        let rig = Rig::new();
        let our_isn = 1000u32;
        rig.send(rig.guest_tcp(
            ip("127.0.0.1"),
            server_port,
            50000,
            our_isn,
            0,
            TCP_SYN,
            &[],
        ));
        let syn_ack = rig.frame_where(|frame| match Rig::inner(frame) {
            (protocol, payload) if protocol == IPPROTO_TCP => parse_tcp(&payload)
                .map(|segment| segment.has(TCP_SYN) && segment.has(TCP_ACK))
                .unwrap_or(false),
            _ => false,
        });
        let segment = Rig::tcp_segment(&syn_ack);
        assert!(
            segment.has(TCP_ACK) && segment.has(TCP_SYN),
            "a SYN|ACK: {segment:?}"
        );
        assert_eq!(segment.ack, our_isn + 1, "the guest's SYN is acknowledged");
        assert_eq!(segment.dst, guest_ip(), "and it is addressed to the guest");
        assert_eq!(
            segment.src_port, server_port,
            "the answer looks like it came from the server"
        );
        let relay_isn = segment.seq;

        rig.send(rig.guest_tcp(
            ip("127.0.0.1"),
            server_port,
            50000,
            our_isn + 1,
            relay_isn + 1,
            TCP_ACK | TCP_PSH,
            b"ping\n",
        ));
        let data = rig.frame_where(|frame| match Rig::inner(frame) {
            (protocol, payload) if protocol == IPPROTO_TCP => parse_tcp(&payload)
                .map(|segment| segment.payload == b"pong\n")
                .unwrap_or(false),
            _ => false,
        });
        let ethernet = parse_ethernet(&data).expect("a frame");
        let packet = parse_ipv4(ethernet.payload).expect("a packet");
        let segment = parse_tcp(packet.payload).expect("a segment");
        assert_eq!(
            segment.seq,
            relay_isn + 1,
            "the reply continues our sequence"
        );
        assert_eq!(
            segment.ack,
            our_isn + 6,
            "and acknowledges the five bytes plus the SYN"
        );
        assert_eq!(
            packet.src,
            ip("127.0.0.1"),
            "from the address the guest asked"
        );
        let snapshot = rig.relay.snapshot();
        assert_eq!(snapshot.tcp_flows, 1);
        // The built-in NAT table is what "what is this machine talking to?" reads, so a flow that
        // carried bytes must say so — not just that it was opened.
        assert_eq!(snapshot.nat.tcp, 1, "{snapshot:?}");
        assert!(
            snapshot.nat.packets >= 2,
            "the request and the reply are counted: {snapshot:?}"
        );
        assert!(
            snapshot.nat.bytes >= 10,
            "and so are their bytes: {snapshot:?}"
        );

        // Let the host close: the flow's entry and its association go with the flow. Leaving them
        // behind is what filled the table with dead connections until every new one was a RST.
        release_tx.send(()).expect("the release");
        server.join().expect("the host server finishes");
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        loop {
            let after = rig.relay.snapshot();
            if after.nat.total == 0 || std::time::Instant::now() > deadline {
                assert_eq!(
                    after.nat.total, 0,
                    "a finished flow left its association behind: {after:?}"
                );
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// A bulk transfer runs at the speed of the link, not at the speed of the loop.
    ///
    /// Reported live as *"the VM network feels like a 58 kbps modem"*: the flow thread read the host
    /// socket with a 200 ms timeout and then waited up to 20 ms on the guest's channel, so a download
    /// moved one 1400-byte segment per 20 ms (~70 kB/s) and an upload one payload per 200 ms — whatever
    /// the link could do. The host did 40 MB/s on the same file while the guest did 69 kB/s. This moves
    /// 8 MB in under five seconds (about 1.6 MB/s, which the serialized loop could not do in a minute)
    /// and it also pins the flow control that speed made necessary: the loop must not put more on the
    /// wire than the guest's window says it can take.
    #[test]
    fn a_bulk_download_is_not_throttled_by_the_flow_loop() {
        const TOTAL: usize = 8 * 1024 * 1024;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a host server");
        let server_port = listener.local_addr().expect("an address").port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("a connection");
            // The guest asks for nothing: it just acknowledges what arrives, which is what a download
            // looks like from this side.
            let chunk = vec![0xA5u8; 64 * 1024];
            let mut sent = 0;
            while sent < TOTAL {
                let take = chunk.len().min(TOTAL - sent);
                if stream.write_all(&chunk[..take]).is_err() {
                    break;
                }
                sent += take;
            }
            // Hold the connection open: an immediate close would be a FIN, not a bulk transfer.
            std::thread::sleep(Duration::from_millis(300));
        });

        let rig = Rig::new();
        let our_isn = 7000u32;
        rig.send(rig.guest_tcp(
            ip("127.0.0.1"),
            server_port,
            50000,
            our_isn,
            0,
            TCP_SYN,
            &[],
        ));
        let syn_ack = rig.frame_where(|frame| match Rig::inner(frame) {
            (protocol, payload) if protocol == IPPROTO_TCP => parse_tcp(&payload)
                .map(|segment| segment.has(TCP_SYN) && segment.has(TCP_ACK))
                .unwrap_or(false),
            _ => false,
        });
        let relay_isn = Rig::tcp_segment(&syn_ack).seq;
        rig.send(rig.guest_tcp(
            ip("127.0.0.1"),
            server_port,
            50000,
            our_isn + 1,
            relay_isn + 1,
            TCP_ACK,
            &[],
        ));

        // Drain the download as the guest does: acknowledge what arrived, in order, and count it — and
        // the acknowledgement is also what reopens the relay's send window.
        let started = std::time::Instant::now();
        let mut received = 0usize;
        let mut expected_seq = relay_isn + 1;
        while received < TOTAL {
            let frames = rig.take_frames();
            if frames.is_empty() {
                std::thread::sleep(Duration::from_millis(1));
                continue;
            }
            for frame in frames {
                let (protocol, payload) = Rig::inner(&frame);
                if protocol != IPPROTO_TCP {
                    continue;
                }
                let Some(segment) = parse_tcp(&payload) else {
                    continue;
                };
                if segment.payload.is_empty() {
                    continue;
                }
                assert_eq!(segment.seq, expected_seq, "the download arrives in order");
                expected_seq = expected_seq.wrapping_add(segment.payload.len() as u32);
                received += segment.payload.len();
                rig.send(rig.guest_tcp(
                    ip("127.0.0.1"),
                    server_port,
                    50000,
                    our_isn + 1,
                    expected_seq,
                    TCP_ACK,
                    &[],
                ));
            }
        }
        let elapsed = started.elapsed();
        assert_eq!(received, TOTAL, "every byte of the 8 MB arrived");
        assert!(
            elapsed < Duration::from_secs(5),
            "8 MB took {elapsed:?}: the flow loop is serializing the two directions again (it must not \
             wait on the guest's channel while the host has data, nor block 200 ms on the host's read)"
        );
        server.join().expect("the host server finishes");
    }

    /// The other direction of the same bug: an upload must not wait 200 ms per payload.
    ///
    /// The loop used to read the host socket (200 ms timeout) *before* looking at the guest's channel,
    /// and then took **one** queued payload per pass — so an upload moved a segment every 200 ms, which
    /// is the "58 kbps" the operator measured. Here the host has nothing to say while the guest sends,
    /// which is exactly that case.
    #[test]
    fn a_bulk_upload_is_not_throttled_by_the_flow_loop() {
        const TOTAL: usize = 8 * 1024 * 1024;
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a host server");
        let server_port = listener.local_addr().expect("an address").port();
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("a connection");
            let mut total = 0usize;
            let mut buffer = vec![0u8; 64 * 1024];
            while total < TOTAL {
                match stream.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(read) => total += read,
                    Err(_) => break,
                }
            }
            let _ = done_tx.send(total);
            std::thread::sleep(Duration::from_millis(200));
        });

        let rig = Rig::new();
        let our_isn = 9000u32;
        rig.send(rig.guest_tcp(
            ip("127.0.0.1"),
            server_port,
            51000,
            our_isn,
            0,
            TCP_SYN,
            &[],
        ));
        let syn_ack = rig.frame_where(|frame| match Rig::inner(frame) {
            (protocol, payload) if protocol == IPPROTO_TCP => parse_tcp(&payload)
                .map(|segment| segment.has(TCP_SYN) && segment.has(TCP_ACK))
                .unwrap_or(false),
            _ => false,
        });
        let relay_isn = Rig::tcp_segment(&syn_ack).seq;
        rig.send(rig.guest_tcp(
            ip("127.0.0.1"),
            server_port,
            51000,
            our_isn + 1,
            relay_isn + 1,
            TCP_ACK,
            &[],
        ));

        let started = std::time::Instant::now();
        let payload = vec![0x5Au8; 1400];
        let mut seq = our_isn + 1;
        let mut sent = 0usize;
        while sent < TOTAL {
            let take = payload.len().min(TOTAL - sent);
            rig.send(rig.guest_tcp(
                ip("127.0.0.1"),
                server_port,
                51000,
                seq,
                relay_isn + 1,
                TCP_ACK | TCP_PSH,
                &payload[..take],
            ));
            seq = seq.wrapping_add(take as u32);
            sent += take;
            // Keep the relay's acknowledgements drained: its conduit is a datagram socket, and an
            // unread one would block it rather than test the data path.
            if sent % (payload.len() * 32) == 0 {
                let _ = rig.take_frames();
            }
        }
        let total = done_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("the whole upload arrives within five seconds");
        let elapsed = started.elapsed();
        assert_eq!(total, TOTAL, "the host sink counted every byte");
        assert!(
            elapsed < Duration::from_secs(5),
            "8 MB uploaded in {elapsed:?}"
        );
        server.join().expect("the host server finishes");
    }

    /// A finished connection gives its place back, or the machine's table fills with dead flows.
    ///
    /// Reported live: an Ubuntu install moved a few hundred megabytes at full speed and then **every**
    /// host became "connection refused" — `wget` to anything failed while the same address was fine from
    /// the host. The outbound spawn never removed a flow whose host had closed normally (the *inbound*
    /// one did), and the flow maps have no expiry of their own, so after `max_flows` connections the
    /// ceiling was reached and `open_outbound` answered each new one with a RST. This opens more
    /// connections than the ceiling, one after another, and each must be accepted.
    #[test]
    fn a_finished_flow_gives_its_place_back() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a host server");
        let server_port = listener.local_addr().expect("an address").port();
        // More connections than `Rig`'s ceiling of 32: with the leak the 33rd is refused.
        let connections = 40u16;
        let server = std::thread::spawn(move || {
            for _ in 0..connections {
                let Ok((mut stream, _)) = listener.accept() else {
                    break;
                };
                // One byte, then the host's FIN: a short connection, like a package fetch.
                let _ = stream.write_all(b"x");
                let _ = stream.shutdown(Shutdown::Write);
            }
            // Give the last flow a moment to notice before the listener goes away.
            std::thread::sleep(Duration::from_millis(200));
        });

        let rig = Rig::new();
        for index in 0..connections {
            let guest_port = 50000 + index;
            let our_isn = 10_000 + u32::from(index) * 1000;
            rig.send(rig.guest_tcp(
                ip("127.0.0.1"),
                server_port,
                guest_port,
                our_isn,
                0,
                TCP_SYN,
                &[],
            ));
            let answer = rig.frame_where(|frame| match Rig::inner(frame) {
                (protocol, payload) if protocol == IPPROTO_TCP => parse_tcp(&payload)
                    .map(|segment| {
                        segment.dst_port == guest_port
                            && (segment.has(TCP_SYN) || segment.has(TCP_RST))
                    })
                    .unwrap_or(false),
                _ => false,
            });
            let segment = Rig::tcp_segment(&answer);
            assert!(
                segment.has(TCP_SYN) && !segment.has(TCP_RST),
                "connection {index} was refused: the table is full of flows that already finished ({segment:?})"
            );
            // Complete the handshake, and let the host's one byte and FIN come back.
            rig.send(rig.guest_tcp(
                ip("127.0.0.1"),
                server_port,
                guest_port,
                our_isn + 1,
                segment.seq.wrapping_add(1),
                TCP_ACK,
                &[],
            ));
            rig.frame_where(|frame| match Rig::inner(frame) {
                (protocol, payload) if protocol == IPPROTO_TCP => parse_tcp(&payload)
                    .map(|segment| segment.dst_port == guest_port && segment.has(TCP_FIN))
                    .unwrap_or(false),
                _ => false,
            });
            // The flow's thread has to see the close and let go of its entry.
            std::thread::sleep(Duration::from_millis(20));
        }
        server.join().expect("the host server finishes");

        // And the tables are empty again: the flows' entries went with their threads, and so did the
        // NAT associations they were opened with.
        let deadline = std::time::Instant::now() + Duration::from_secs(3);
        loop {
            let snapshot = rig.relay.snapshot();
            if snapshot.nat.total == 0 || std::time::Instant::now() > deadline {
                assert_eq!(
                    snapshot.nat.total, 0,
                    "the NAT table still holds finished flows: {snapshot:?}"
                );
                break;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn a_duplicate_segment_is_acknowledged_but_not_forwarded_twice() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a host server");
        let server_port = listener.local_addr().expect("an address").port();
        let received = Arc::new(AtomicU32::new(0));
        let counter = Arc::clone(&received);
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("a connection");
            let mut buffer = [0u8; 1024];
            if let Ok(read) = stream.read(&mut buffer) {
                counter.fetch_add(read as u32, Ordering::Relaxed);
            }
            std::thread::sleep(Duration::from_millis(400));
        });

        let rig = Rig::new();
        rig.send(rig.guest_tcp(ip("127.0.0.1"), server_port, 50001, 10, 0, TCP_SYN, &[]));
        let syn_ack = rig.frame_where(|frame| match Rig::inner(frame) {
            (protocol, payload) if protocol == IPPROTO_TCP => parse_tcp(&payload)
                .map(|segment| segment.has(TCP_SYN))
                .unwrap_or(false),
            _ => false,
        });
        let syn = Rig::tcp_segment(&syn_ack);
        rig.send(rig.guest_tcp(
            ip("127.0.0.1"),
            server_port,
            50001,
            11,
            syn.seq + 1,
            TCP_ACK | TCP_PSH,
            b"once",
        ));
        rig.send(rig.guest_tcp(
            ip("127.0.0.1"),
            server_port,
            50001,
            11,
            syn.seq + 1,
            TCP_ACK | TCP_PSH,
            b"once",
        ));
        std::thread::sleep(Duration::from_millis(400));
        assert_eq!(
            received.load(Ordering::Relaxed),
            4,
            "the duplicate did not reach the host twice"
        );
    }

    #[test]
    fn a_frame_to_a_peer_is_forwarded_with_the_peers_mac() {
        let peer_ip = ip("10.177.0.17");
        let rig = Rig::with_peers(vec![peer_ip], None);
        let payload = build_udp(guest_ip(), peer_ip, 40000, 40001, b"to the peer");
        let packet = build_ipv4(guest_ip(), peer_ip, IPPROTO_UDP, 64, &payload);
        rig.send(build_ethernet(OUR_MAC, GUEST_MAC, ETHERTYPE_IPV4, &packet));
        for _ in 0..200 {
            if !rig.peers.lock().expect("the peer capture").is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let peers = rig.peers.lock().expect("the peer capture");
        assert_eq!(peers.len(), 1, "the frame went to exactly one peer");
        let (address, frame) = &peers[0];
        assert_eq!(*address, IpAddr::V4(peer_ip));
        let ethernet = parse_ethernet(frame).expect("a frame");
        assert_eq!(ethernet.dst, PEER_MAC, "addressed to the peer");
        assert_eq!(ethernet.src, OUR_MAC, "from the gateway");
        assert_eq!(
            parse_ipv4(ethernet.payload).expect("a packet").dst,
            peer_ip,
            "the packet is untouched"
        );
        assert_eq!(rig.relay.snapshot().peers_forwarded, 1);
    }

    #[test]
    fn a_broadcast_is_not_a_way_to_reach_the_peers() {
        // **Discovery by broadcast is the one thing this network cannot do.** A machine's "link" is a
        // point-to-point conduit to the relay, so there is no shared segment for a broadcast, an mDNS
        // query or an SSDP search to cross: the relay forwards to a peer's **exact** leased address and
        // to nothing else. A guest that tries is answered by a counter, not by a peer — and a
        // unicast to the peer's own address is the way that works.
        let peer_ip = ip("10.177.0.17");
        let rig = Rig::with_host_guard(vec![peer_ip]);
        let before = rig.relay.snapshot();
        // The all-ones broadcast: a host-network address, refused by the guard like any other.
        rig.send(rig.guest_udp(ip("255.255.255.255"), 5353, 50000, b"anyone?"));
        // The subnet's own broadcast: inside our range, and an address no machine holds.
        rig.send(rig.guest_udp(ip("10.177.255.255"), 5353, 50001, b"anyone?"));
        // The mDNS group a real stack would ask on.
        rig.send(rig.guest_udp(ip("224.0.0.251"), 5353, 50002, b"anyone?"));
        // The unicast that does reach it, last, so seeing it proves the three before it were handled.
        rig.send(rig.guest_udp(peer_ip, 5353, 50003, b"you?"));
        for _ in 0..200 {
            if !rig.peers.lock().expect("the peer capture").is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let peers = rig.peers.lock().expect("the peer capture");
        assert_eq!(peers.len(), 1, "only the unicast was forwarded");
        assert_eq!(peers[0].0, IpAddr::V4(peer_ip));

        let after = rig.relay.snapshot();
        assert_eq!(
            after.dropped_host,
            before.dropped_host + 1,
            "255.255.255.255 is a host address"
        );
        assert_eq!(
            after.dropped_isolation,
            before.dropped_isolation + 1,
            "the subnet broadcast names no machine"
        );
        assert_eq!(
            after.dropped_other,
            before.dropped_other + 1,
            "multicast is nobody's business here"
        );
        assert_eq!(
            after.peers_forwarded,
            before.peers_forwarded + 1,
            "and the unicast went through"
        );
    }

    #[test]
    fn a_frame_to_an_isolated_machine_is_dropped_with_a_counter() {
        let rig = Rig::new();
        let payload = build_udp(guest_ip(), ip("10.177.0.17"), 40000, 40001, b"nope");
        let packet = build_ipv4(guest_ip(), ip("10.177.0.17"), IPPROTO_UDP, 64, &payload);
        rig.send(build_ethernet(OUR_MAC, GUEST_MAC, ETHERTYPE_IPV4, &packet));
        std::thread::sleep(Duration::from_millis(60));
        assert!(rig.peers.lock().expect("the peer capture").is_empty());
        assert_eq!(rig.relay.snapshot().dropped_isolation, 1);
    }

    #[test]
    fn our_own_names_are_answered_from_the_directory() {
        let peer_ip = ip("10.177.0.17");
        let names = NameDirectory {
            addr4: Arc::new(move |name: &str| (name == "vm-debian").then_some(peer_ip)),
            addr6: Arc::new(|_| None),
        };
        let rig = Rig::with_peers(vec![peer_ip], Some(names));
        let mut query = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        query.push(9);
        query.extend_from_slice(b"vm-debian");
        query.push(0);
        query.extend_from_slice(&1u16.to_be_bytes());
        query.extend_from_slice(&1u16.to_be_bytes());
        rig.send(rig.guest_udp(ip("10.177.0.1"), 53, 33333, &query));
        let frame = rig.frame_where(|frame| match Rig::inner(frame) {
            (protocol, payload) if protocol == IPPROTO_UDP => parse_udp(&payload)
                .map(|datagram| datagram.src_port == 53 && datagram.payload.len() > query.len())
                .unwrap_or(false),
            _ => false,
        });
        let ethernet = parse_ethernet(&frame).expect("a frame");
        let packet = parse_ipv4(ethernet.payload).expect("a packet");
        let datagram = parse_udp(packet.payload).expect("a datagram");
        assert_eq!(datagram.dst_port, 33333);
        assert_eq!(
            datagram.payload[0..2],
            [0x12, 0x34],
            "the transaction id comes back"
        );
        assert_eq!(
            &datagram.payload[datagram.payload.len() - 4..],
            &peer_ip.octets(),
            "the A record"
        );
    }

    #[test]
    fn a_link_local_aaaa_is_answered_as_nodata_and_the_a_record_still_answers() {
        // A container's name in the directory exactly as the engine builds it: an IPv4 lease and the
        // **link-local** the tap forms for itself. Answering that link-local as the name's AAAA is what
        // broke every client — `getaddrinfo` refuses the whole reply — so the name's family it cannot
        // carry is answered NODATA, and the A record answers as it always did.
        let peer_ip = ip("10.177.0.16");
        let link_local = crate::frame::link_local_of(GUEST_MAC);
        let names = NameDirectory {
            addr4: Arc::new(move |name: &str| (name == "ctr-web").then_some(peer_ip)),
            addr6: Arc::new(move |name: &str| (name == "ctr-web").then_some(link_local)),
        };
        let rig = Rig::with_peers(vec![peer_ip], Some(names));
        let query = |qtype: u16| {
            let mut query = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
            query.push(7); // the label's length: "ctr-web" is seven bytes
            query.extend_from_slice(b"ctr-web");
            query.push(0);
            query.extend_from_slice(&qtype.to_be_bytes());
            query.extend_from_slice(&1u16.to_be_bytes());
            query
        };
        let answer = |query: &[u8]| {
            rig.send(rig.guest_udp(ip("10.177.0.1"), 53, 33333, query));
            let frame = rig.frame_where(|frame| match Rig::inner(frame) {
                (protocol, payload) if protocol == IPPROTO_UDP => parse_udp(&payload)
                    .map(|datagram| datagram.src_port == 53)
                    .unwrap_or(false),
                _ => false,
            });
            let ethernet = parse_ethernet(&frame).expect("a frame");
            let packet = parse_ipv4(ethernet.payload).expect("a packet");
            parse_udp(packet.payload)
                .expect("a datagram")
                .payload
                .to_vec()
        };

        // The AAAA query: NODATA — rcode 0, no answers, the question echoed, nothing invented.
        let nodata = answer(&query(28));
        assert_eq!(nodata[0..2], [0x12, 0x34], "the transaction id comes back");
        assert_eq!(
            nodata[3] & 0x0f,
            0,
            "no error: the name exists, this family does not"
        );
        assert_eq!(
            u16::from_be_bytes([nodata[6], nodata[7]]),
            0,
            "and no answers"
        );
        assert_eq!(
            nodata.len(),
            query(28).len(),
            "the question is echoed and nothing is appended"
        );
        assert!(
            !nodata
                .windows(16)
                .any(|window| window == link_local.octets()),
            "the link-local is not published as a name"
        );

        // The A query is unchanged: the address the workspace resolves.
        let a = answer(&query(1));
        assert_eq!(u16::from_be_bytes([a[6], a[7]]), 1, "one answer");
        assert_eq!(&a[a.len() - 4..], &peer_ip.octets(), "the A record");
    }

    #[test]
    fn a_name_that_is_not_ours_is_still_forwarded_not_answered_nodata() {
        // NODATA means "ours, no such family". A name the directory does not know must fall through to
        // the host's resolver — an empty SERVFAIL here, because this test host has none — or this process
        // would be telling its guests that `example.com` does not exist.
        let names = NameDirectory {
            addr4: Arc::new(|name: &str| (name == "ctr-web").then_some(ip("10.177.0.16"))),
            addr6: Arc::new(|_| None),
        };
        let rig = Rig::with_peers(vec![ip("10.177.0.16")], Some(names));
        let mut query = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        query.push(11);
        query.extend_from_slice(b"example.com");
        query.push(0);
        query.extend_from_slice(&28u16.to_be_bytes());
        query.extend_from_slice(&1u16.to_be_bytes());
        rig.send(rig.guest_udp(ip("10.177.0.1"), 53, 33333, &query));
        let frame = rig.frame_where(|frame| match Rig::inner(frame) {
            (protocol, payload) if protocol == IPPROTO_UDP => parse_udp(&payload)
                .map(|datagram| datagram.src_port == 53)
                .unwrap_or(false),
            _ => false,
        });
        let ethernet = parse_ethernet(&frame).expect("a frame");
        let packet = parse_ipv4(ethernet.payload).expect("a packet");
        let answer = parse_udp(packet.payload).expect("a datagram").payload;
        assert_eq!(
            answer[3] & 0x0f,
            2,
            "SERVFAIL: there is no resolver to forward it to here"
        );
        assert_ne!(
            answer[3] & 0x0f,
            0,
            "and certainly not a NODATA for a name we do not own"
        );
    }

    #[test]
    fn an_edns0_query_is_answered_without_echoing_its_opt_record() {
        // A guest's `/etc/resolv.conf` carries `options edns0 trust-ad`, so glibc asks **with** an OPT
        // record. An answer that echoed the client's packet and only patched the counts was a packet
        // whose sections did not add up, and `getaddrinfo` threw it away — while `nslookup`, which asks
        // without EDNS0, worked. The answer is the question section plus the record, and nothing else.
        let peer_ip = ip("10.177.0.16");
        let names = NameDirectory {
            addr4: Arc::new(move |name: &str| (name == "ctr-web").then_some(peer_ip)),
            addr6: Arc::new(|_| None),
        };
        let rig = Rig::with_peers(vec![peer_ip], Some(names));
        let mut query = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1]; // ARCOUNT = 1: the OPT
        query.push(7);
        query.extend_from_slice(b"ctr-web");
        query.push(0);
        query.extend_from_slice(&1u16.to_be_bytes()); // A
        query.extend_from_slice(&1u16.to_be_bytes()); // IN
                                                      // The OPT RR: root name, type 41, UDP payload size 4096, extended rcode/version 0, no options.
        query.push(0);
        query.extend_from_slice(&41u16.to_be_bytes());
        query.extend_from_slice(&4096u16.to_be_bytes());
        query.extend_from_slice(&[0, 0, 0, 0]);
        query.extend_from_slice(&0u16.to_be_bytes());

        rig.send(rig.guest_udp(ip("10.177.0.1"), 53, 33333, &query));
        let frame = rig.frame_where(|frame| match Rig::inner(frame) {
            (protocol, payload) if protocol == IPPROTO_UDP => parse_udp(&payload)
                .map(|datagram| datagram.src_port == 53)
                .unwrap_or(false),
            _ => false,
        });
        let ethernet = parse_ethernet(&frame).expect("a frame");
        let packet = parse_ipv4(ethernet.payload).expect("a packet");
        let answer = parse_udp(packet.payload).expect("a datagram").payload;
        let question_end = 12 + 1 + 7 + 1 + 4;
        assert_eq!(u16::from_be_bytes([answer[6], answer[7]]), 1, "one answer");
        assert_eq!(
            u16::from_be_bytes([answer[10], answer[11]]),
            0,
            "and no additional records"
        );
        assert_eq!(
            answer.len(),
            question_end + 16,
            "the question, then the one answer RR — the client's OPT record is not echoed"
        );
        assert_eq!(
            &answer[answer.len() - 4..],
            &peer_ip.octets(),
            "the A record"
        );
    }

    #[test]
    fn hostile_or_unimplemented_frames_are_counted_not_fatal() {
        let rig = Rig::new();
        rig.send(vec![0u8; 8]);
        // A v6 packet whose next header is one we do not speak (47 = GRE), and a v6 packet cut short.
        rig.send(build_ethernet(
            OUR_MAC,
            GUEST_MAC,
            ETHERTYPE_IPV6,
            &build_ipv6(guest6(), our6(), 47, 64, b"gre"),
        ));
        rig.send(build_ethernet(
            OUR_MAC,
            GUEST_MAC,
            ETHERTYPE_IPV6,
            &[0u8; 20],
        ));
        rig.send(build_ethernet(OUR_MAC, GUEST_MAC, 0x1337, b"whatever"));
        rig.send(rig.guest_tcp(ip("93.184.216.34"), 80, 40000, 1, 0, TCP_ACK, b"stray"));
        std::thread::sleep(Duration::from_millis(80));
        let snapshot = rig.relay.snapshot();
        assert_eq!(snapshot.frames_in, 5);
        assert_eq!(
            snapshot.dropped_ipv6, 1,
            "the truncated v6 frame is refused: {snapshot:?}"
        );
        assert!(
            snapshot.dropped_other >= 2,
            "the GRE packet and the odd ethertype: {snapshot:?}"
        );
        assert!(
            snapshot.frames_out >= 1,
            "the stray segment is answered with a reset"
        );
    }

    #[test]
    fn a_port_mapping_opens_the_guest_side_and_carries_the_bytes() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a listener");
        let port = listener.local_addr().expect("an address").port();
        let client = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(("127.0.0.1", port)).expect("the client connects");
            stream.write_all(b"from the host\n").expect("writes");
            let mut buffer = [0u8; 64];
            let read = stream.read(&mut buffer).expect("reads");
            buffer[..read].to_vec()
        });
        let (server, _) = listener.accept().expect("an accepted connection");
        let rig = Rig::new();
        let peer = server.peer_addr().expect("the accepted connection's peer");
        rig.relay
            .accept_inbound(server, 22, peer, IpAddr::V4(ip("10.177.0.1")))
            .expect("the flow starts");

        // The relay sends a SYN to the guest (from us, to the guest's port).
        let syn = rig.frame_where(|frame| match Rig::inner(frame) {
            (protocol, payload) if protocol == IPPROTO_TCP => parse_tcp(&payload)
                .map(|segment| {
                    segment.has(TCP_SYN) && !segment.has(TCP_ACK) && segment.dst_port == 22
                })
                .unwrap_or(false),
            _ => false,
        });
        let syn_segment = Rig::tcp_segment(&syn);
        let our_port = syn_segment.src_port;
        let our_isn = syn_segment.seq;

        // The guest accepts; then the host's line arrives as a data segment.
        rig.send(rig.guest_tcp(
            ip("10.177.0.1"),
            our_port,
            22,
            5000,
            our_isn + 1,
            TCP_SYN | TCP_ACK,
            &[],
        ));
        let data = rig.frame_where(|frame| match Rig::inner(frame) {
            (protocol, payload) if protocol == IPPROTO_TCP => parse_tcp(&payload)
                .map(|segment| segment.payload == b"from the host\n")
                .unwrap_or(false),
            _ => false,
        });
        let segment = Rig::tcp_segment(&data);
        assert_eq!(segment.src, ip("10.177.0.1"), "from the machine's gateway");
        assert_eq!(segment.dst_port, 22, "the guest's port");
        assert_eq!(segment.ack, 5001, "the guest's SYN is acknowledged");

        // And the guest's answer reaches the host's client.
        rig.send(rig.guest_tcp(
            ip("10.177.0.1"),
            our_port,
            22,
            5001,
            segment.seq + segment.payload.len() as u32,
            TCP_ACK | TCP_PSH,
            b"from the guest\n",
        ));
        let received = client.join().expect("the client finishes");
        assert_eq!(received, b"from the guest\n");
    }

    #[test]
    fn a_relay_that_is_shut_down_answers_nothing() {
        let rig = Rig::new();
        rig.relay.shutdown();
        let request = build_arp_request(GUEST_MAC, guest_ip(), ip("10.177.0.1"));
        rig.send(build_ethernet(OUR_MAC, GUEST_MAC, ETHERTYPE_ARP, &request));
        std::thread::sleep(Duration::from_millis(60));
        assert!(rig.answered_nothing());
    }

    #[test]
    fn a_config_knows_which_addresses_are_machines_and_which_are_the_internet() {
        let config = RelayConfig {
            our_mac: OUR_MAC,
            our_ip: ip("10.177.0.1"),
            dns_ip: ip("10.177.0.1"),
            our_ip6: crate::frame::link_local_of(OUR_MAC),
            our_ula6: ip6("fd10:177::1"),
            dns_ip6: crate::frame::link_local_of(OUR_MAC),
            subnet: ip("10.177.0.0"),
            prefix: 16,
            subnet6: ip6("fd10:177::"),
            prefix6: 64,
            connect_timeout: Duration::from_secs(1),
            max_flows: 8,
            resolvers: Vec::new(),
            host_guard: None,
            gateway_ports: Arc::new(GatewayPorts::new()),
            workspace: "ws-1".to_string(),
        };
        assert!(config.is_internal(ip("10.177.0.17")), "another machine");
        assert!(
            config.is_internal(ip("10.177.255.254")),
            "the whole /16 is ours"
        );
        assert!(!config.is_internal(ip("10.178.0.1")), "the next /16 is not");
        assert!(
            !config.is_internal(ip("93.184.216.34")),
            "the internet is not"
        );
        assert!(
            !config.is_internal(ip("10.0.2.15")),
            "slirp's own range is not ours"
        );
    }

    #[test]
    fn a_router_solicitation_is_answered_with_our_advertisement() {
        // A guest brings its interface up and asks for a router: the answer is what tells it the
        // machines' prefix, the conduit's MTU, and that addresses and DNS come from DHCPv6.
        let rig = Rig::new();
        rig.send(rig.guest_icmp6(
            guest6(),
            crate::frame::ALL_ROUTERS_MULTICAST,
            ndp::ROUTER_SOLICITATION,
            &ndp::router_solicitation_body(),
        ));
        let frame = rig.frame_where(|frame| Rig::inner6(frame).0 == IPPROTO_ICMPV6);
        let (_, src, dst, payload) = Rig::inner6(&frame);
        assert_eq!(src, our6(), "the advertisement comes from the gateway");
        assert_eq!(dst, guest6());
        let message = parse_icmpv6(&payload).expect("ICMPv6");
        assert_eq!(message.kind, ndp::ROUTER_ADVERTISEMENT);
        let advertisement = ndp::parse_router_advertisement(&Rig::icmp6_body(&message))
            .expect("the advertisement parses");
        assert!(
            advertisement.managed() && advertisement.other_config(),
            "addresses and DNS come from DHCPv6"
        );
        assert_eq!(advertisement.link_layer, Some(OUR_MAC));
        assert_eq!(advertisement.mtu, Some(1500));
        let prefix = advertisement.prefix.expect("a prefix");
        assert_eq!(prefix.prefix, ip6("fd10:177::"));
        assert_eq!(prefix.prefix_len, 64);
        assert!(
            prefix.on_link() && !prefix.autonomous(),
            "on-link, but not for autoconfiguration"
        );
        let snapshot = rig.relay.snapshot();
        assert_eq!(snapshot.ra_sent, 1);
        assert_eq!(
            snapshot.v6_frames, 1,
            "the frame we spoke was counted: {snapshot:?}"
        );
    }

    #[test]
    fn neighbor_solicitations_are_answered_for_us_and_for_a_peer_but_not_for_a_dad_probe() {
        // Ours: a router advertisement naming our MAC.
        let rig = Rig::new();
        let body = ndp::neighbor_solicitation_body(our6(), Some(GUEST_MAC));
        rig.send(rig.guest_icmp6(
            guest6(),
            crate::frame::solicited_node_multicast(our6()),
            ndp::NEIGHBOR_SOLICITATION,
            &body,
        ));
        let frame = rig.frame_where(|frame| {
            let (header, _, _, payload) = Rig::inner6(frame);
            header == IPPROTO_ICMPV6
                && parse_icmpv6(&payload)
                    .map(|message| message.kind == ndp::NEIGHBOR_ADVERTISEMENT)
                    .unwrap_or(false)
        });
        let (_, src, _, payload) = Rig::inner6(&frame);
        assert_eq!(src, our6(), "the source is the address we speak for");
        let message = parse_icmpv6(&payload).expect("ICMPv6");
        let advertisement =
            ndp::parse_neighbor(&Rig::icmp6_body(&message)).expect("an advertisement");
        assert_eq!(advertisement.target, our6());
        assert_eq!(advertisement.link_layer, Some(OUR_MAC));
        assert!(
            advertisement.is_advertisement() && !advertisement.is_proxy(),
            "ours is a router's"
        );
        assert_eq!(rig.relay.snapshot().na_sent, 1);

        // A peer's ULA: a proxy advertisement naming the peer's MAC, and not claiming to be a router.
        let rig = Rig::with_addresses(vec![IpAddr::V6(peer6())], None);
        let body = ndp::neighbor_solicitation_body(peer6(), Some(GUEST_MAC));
        rig.send(rig.guest_icmp6(
            guest6(),
            crate::frame::solicited_node_multicast(peer6()),
            ndp::NEIGHBOR_SOLICITATION,
            &body,
        ));
        let frame = rig.frame_where(|frame| {
            let (header, _, _, payload) = Rig::inner6(frame);
            header == IPPROTO_ICMPV6
                && parse_icmpv6(&payload)
                    .map(|message| message.kind == ndp::NEIGHBOR_ADVERTISEMENT)
                    .unwrap_or(false)
        });
        let (_, src, _, payload) = Rig::inner6(&frame);
        assert_eq!(src, peer6(), "the proxy speaks with the peer's own address");
        let message = parse_icmpv6(&payload).expect("ICMPv6");
        let advertisement =
            ndp::parse_neighbor(&Rig::icmp6_body(&message)).expect("an advertisement");
        assert_eq!(advertisement.target, peer6());
        assert_eq!(
            advertisement.link_layer,
            Some(PEER_MAC),
            "with the peer's MAC"
        );
        assert!(advertisement.is_proxy(), "a host is not a router");
        assert_eq!(rig.relay.snapshot().ns_answered, 1);

        // A DAD probe for an address inside our prefix is left unanswered, so a guest can claim it.
        let rig = Rig::new();
        let address = ip6("fd10:177::1000");
        let body = ndp::neighbor_solicitation_body(address, None);
        rig.send(rig.guest_icmp6(
            Ipv6Addr::UNSPECIFIED,
            crate::frame::solicited_node_multicast(address),
            ndp::NEIGHBOR_SOLICITATION,
            &body,
        ));
        std::thread::sleep(Duration::from_millis(80));
        assert!(rig.answered_nothing(), "a DAD probe is not answered");
    }

    #[test]
    fn a_v6_udp_flow_reaches_a_host_socket_and_its_reply_comes_back() {
        // The whole v6 UDP path over a real host socket: the guest's link-local is its source, and the
        // answer comes back to the address it actually used.
        let server = std::net::UdpSocket::bind("[::1]:0").expect("a v6 loopback server");
        let server_port = server.local_addr().expect("an address").port();
        let echo = std::thread::spawn(move || {
            let mut buffer = [0u8; 256];
            let (read, from) = server.recv_from(&mut buffer).expect("a datagram");
            server
                .send_to(&[b"pong:".as_slice(), &buffer[..read]].concat(), from)
                .expect("a reply");
            std::thread::sleep(Duration::from_millis(100));
        });
        let rig = Rig::new();
        rig.send(rig.guest_udp6(ip6("::1"), server_port, 40000, b"v6 ping"));
        let frame = rig.frame_where(|frame| {
            let (header, _, _, payload) = Rig::inner6(frame);
            header == IPPROTO_UDP
                && parse_udp(&payload)
                    .map(|d| d.payload.starts_with(b"pong:"))
                    .unwrap_or(false)
        });
        let (_, src, dst, payload) = Rig::inner6(&frame);
        assert_eq!(
            src,
            ip6("::1"),
            "the answer comes from the address the guest asked"
        );
        assert_eq!(dst, guest6());
        let datagram = parse_udp(&payload).expect("a datagram");
        assert_eq!(datagram.dst_port, 40000);
        assert_eq!(datagram.src_port, server_port);
        assert_eq!(datagram.payload, b"pong:v6 ping");
        assert_eq!(rig.relay.snapshot().udp_flows, 1);
        echo.join().expect("the server finishes");
    }

    #[test]
    fn a_v6_tcp_flow_handshakes_and_carries_bytes() {
        let listener = std::net::TcpListener::bind("[::1]:0").expect("a v6 host server");
        let server_port = listener.local_addr().expect("an address").port();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("a connection");
            let mut buffer = [0u8; 256];
            let read = stream.read(&mut buffer).expect("a request");
            assert_eq!(&buffer[..read], b"v6 ping\n");
            stream.write_all(b"v6 pong\n").expect("a reply");
            stream.shutdown(Shutdown::Write).expect("the server closes");
            std::thread::sleep(Duration::from_millis(200));
        });
        let rig = Rig::new();
        rig.send(rig.guest_tcp6(ip6("::1"), server_port, 50000, 1000, 0, TCP_SYN, &[]));
        let syn_ack = rig.frame_where(|frame| {
            Rig::inner6(frame).0 == IPPROTO_TCP
                && parse_tcp(&Rig::inner6(frame).3)
                    .map(|segment| segment.has(TCP_SYN))
                    .unwrap_or(false)
        });
        let (_, src, _, payload) = Rig::inner6(&syn_ack);
        assert_eq!(
            src,
            ip6("::1"),
            "the handshake comes from the address the guest asked"
        );
        let segment = parse_tcp(&payload).expect("a segment");
        rig.send(rig.guest_tcp6(
            ip6("::1"),
            server_port,
            50000,
            1001,
            segment.seq + 1,
            TCP_ACK | TCP_PSH,
            b"v6 ping\n",
        ));
        let data = rig.frame_where(|frame| {
            let (header, _, _, payload) = Rig::inner6(frame);
            header == IPPROTO_TCP
                && parse_tcp(&payload)
                    .map(|s| s.payload == b"v6 pong\n")
                    .unwrap_or(false)
        });
        assert_eq!(
            parse_tcp(&Rig::inner6(&data).3).expect("a segment").payload,
            b"v6 pong\n"
        );
        server.join().expect("the server finishes");
    }

    #[test]
    fn a_v6_frame_to_a_peer_is_forwarded_and_an_unknown_machine_is_dropped() {
        let rig = Rig::with_addresses(vec![IpAddr::V6(peer6())], None);
        let datagram = build_udp_v6(guest6(), peer6(), 40000, 40001, b"to the peer");
        let packet = build_ipv6(guest6(), peer6(), IPPROTO_UDP, 64, &datagram);
        rig.send(build_ethernet(
            multicast_mac(peer6()),
            GUEST_MAC,
            ETHERTYPE_IPV6,
            &packet,
        ));
        for _ in 0..200 {
            if !rig.peers.lock().expect("the peer capture").is_empty() {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        let peers = rig.peers.lock().expect("the peer capture");
        assert_eq!(peers.len(), 1, "the frame went to exactly one peer");
        let (address, frame) = &peers[0];
        assert_eq!(*address, IpAddr::V6(peer6()));
        let ethernet = parse_ethernet(frame).expect("a frame");
        assert_eq!(ethernet.dst, PEER_MAC, "addressed to the peer");
        assert_eq!(ethernet.src, OUR_MAC, "from the gateway");
        drop(peers);
        assert_eq!(rig.relay.snapshot().peers_forwarded, 1);

        // A ULA nobody holds: silence, counted as a v6 drop rather than a NAT flow.
        let rig = Rig::new();
        let datagram = build_udp_v6(guest6(), ip6("fd10:177::99"), 40000, 40001, b"nobody");
        let packet = build_ipv6(guest6(), ip6("fd10:177::99"), IPPROTO_UDP, 64, &datagram);
        rig.send(build_ethernet(
            multicast_mac(ip6("fd10:177::99")),
            GUEST_MAC,
            ETHERTYPE_IPV6,
            &packet,
        ));
        std::thread::sleep(Duration::from_millis(60));
        let snapshot = rig.relay.snapshot();
        assert!(
            rig.answered_nothing(),
            "an address nobody holds is not a flow"
        );
        assert_eq!(snapshot.dropped_ipv6, 1, "{snapshot:?}");
        assert_eq!(snapshot.udp_flows, 0);
    }

    #[test]
    fn a_v6_echo_to_the_gateway_is_answered_and_an_external_one_is_not_fabricated() {
        let rig = Rig::new();
        rig.send(rig.guest_icmp6(guest6(), our6(), 128, &[0x22, 0x22, 0, 3, b'h', b'i']));
        let frame = rig.frame_where(|frame| {
            Rig::inner6(frame).0 == IPPROTO_ICMPV6
                && parse_icmpv6(&Rig::inner6(frame).3)
                    .map(|message| message.kind == 129)
                    .unwrap_or(false)
        });
        let (_, src, dst, payload) = Rig::inner6(&frame);
        assert_eq!(src, our6());
        assert_eq!(dst, guest6());
        let reply = parse_icmpv6(&payload).expect("ICMPv6");
        assert_eq!(reply.rest, [0x22, 0x22, 0, 3]);
        assert_eq!(reply.payload, b"hi");
        assert_eq!(rig.relay.snapshot().icmp6_replies, 1);

        // An external v6 address is never fabricated: this host has no global IPv6, so the request is
        // dropped with a counter (or answered by a real echo, on a host that has a route).
        let rig = Rig::new();
        rig.send(rig.guest_icmp6(
            guest6(),
            ip6("2606:4700:4700::1111"),
            128,
            &[0x11, 0x11, 0, 1],
        ));
        std::thread::sleep(Duration::from_millis(1200));
        let snapshot = rig.relay.snapshot();
        assert_eq!(
            snapshot.icmp6_replies + snapshot.dropped_unreachable,
            1,
            "{snapshot:?}"
        );
    }

    #[test]
    fn a_v6_name_is_answered_with_an_aaaa_record() {
        let names = NameDirectory {
            addr4: Arc::new(|_| None),
            addr6: Arc::new(move |name: &str| (name == "vm-debian").then_some(peer6())),
        };
        let rig = Rig::with_addresses(vec![IpAddr::V6(peer6())], Some(names));
        let mut query = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        query.push(9);
        query.extend_from_slice(b"vm-debian");
        query.push(0);
        query.extend_from_slice(&28u16.to_be_bytes()); // AAAA
        query.extend_from_slice(&1u16.to_be_bytes());
        rig.send(rig.guest_udp6(our6(), 53, 33333, &query));
        let frame = rig.frame_where(|frame| {
            let (header, _, _, payload) = Rig::inner6(frame);
            header == IPPROTO_UDP
                && parse_udp(&payload)
                    .map(|d| d.src_port == 53 && d.payload.len() > query.len())
                    .unwrap_or(false)
        });
        let (_, src, dst, payload) = Rig::inner6(&frame);
        assert_eq!(
            src,
            our6(),
            "the answer comes from the resolver the guest asked"
        );
        assert_eq!(dst, guest6());
        let datagram = parse_udp(&payload).expect("a datagram");
        assert_eq!(datagram.dst_port, 33333);
        assert_eq!(
            datagram.payload[0..2],
            [0x12, 0x34],
            "the transaction id comes back"
        );
        assert_eq!(
            &datagram.payload[datagram.payload.len() - 16..],
            &peer6().octets(),
            "the AAAA record"
        );
    }

    /// The seconds-since-1970 an NTP timestamp names (the client's own arithmetic, in the tests).
    fn decode_ntp(stamp: &[u8]) -> f64 {
        let seconds = u32::from_be_bytes(stamp[..4].try_into().expect("four bytes")) as f64;
        let fraction =
            u32::from_be_bytes(stamp[4..].try_into().expect("four bytes")) as f64 / 2f64.powi(32);
        seconds + fraction - 2_208_988_800f64
    }

    /// A client's NTP request: version 4, mode 3, the poll it would send, and the transmit stamp it
    /// claims (which the answer must hand straight back).
    fn ntp_request(poll: u8) -> Vec<u8> {
        let mut query = vec![0u8; crate::ntp::PACKET_LEN];
        query[0] = (4 << 3) | 3;
        query[2] = poll;
        query[40..48].copy_from_slice(&crate::ntp::timestamp(std::time::SystemTime::now()));
        query
    }

    #[test]
    fn a_time_query_to_the_gateway_is_answered_from_the_hosts_clock() {
        // The clock is a service the relay answers **itself**, beside the resolver — no host
        // socket, no flow, one frame back. This is a real NTPv4 client packet.
        use std::time::{SystemTime, UNIX_EPOCH};
        let rig = Rig::new();
        let query = ntp_request(6);
        let client_sent = query[40..48].to_vec();
        let sent_at = SystemTime::now();
        rig.send(rig.guest_udp(ip("10.177.0.1"), crate::ntp::NTP_PORT, 40000, &query));
        let frame = rig.frame_where(|frame| match Rig::inner(frame) {
            (protocol, payload) if protocol == IPPROTO_UDP => parse_udp(&payload)
                .map(|datagram| {
                    datagram.src_port == crate::ntp::NTP_PORT && datagram.dst_port == 40000
                })
                .unwrap_or(false),
            _ => false,
        });
        let ethernet = parse_ethernet(&frame).expect("a frame");
        let packet = parse_ipv4(ethernet.payload).expect("a packet");
        let datagram = parse_udp(packet.payload).expect("a datagram");
        assert_eq!(
            datagram.payload.len(),
            crate::ntp::PACKET_LEN,
            "the header, and nothing else"
        );
        assert_eq!(datagram.payload[0] & 0x07, 4, "a server reply");
        assert_eq!(
            (datagram.payload[0] >> 3) & 0x07,
            4,
            "the client's version comes back"
        );
        assert_eq!(datagram.payload[0] >> 6, 0, "no leap warning invented");
        assert_eq!(datagram.payload[1], 2, "a secondary reference");
        assert_eq!(datagram.payload[2], 6, "the client's poll is echoed");
        assert_eq!(
            &datagram.payload[12..16],
            b"LOCL",
            "the reference is the host's own clock"
        );
        assert_eq!(
            &datagram.payload[24..32],
            &client_sent[..],
            "the client's own transmit comes back"
        );

        // The transmit stamp is **now**: within a second of this test's clock, which is the same clock
        // the guest is being told about (the test stands exactly where the guest does).
        let answered = decode_ntp(&datagram.payload[40..48]);
        let now = sent_at
            .duration_since(UNIX_EPOCH)
            .expect("after the epoch")
            .as_secs_f64();
        assert!(
            (answered - now).abs() < 1.0,
            "{answered} is not within a second of {now}"
        );
        assert_eq!(
            &datagram.payload[32..40],
            &datagram.payload[40..48],
            "receive and transmit are one instant"
        );

        // A datagram that is not a client request is dropped with a counter, not answered: a truncated
        // packet, and a *reply* sent at us (a port scanner, or a loop).
        let before = rig.relay.snapshot().dropped_other;
        rig.send(rig.guest_udp(ip("10.177.0.1"), crate::ntp::NTP_PORT, 40001, &[0u8; 12]));
        let mut foreign = ntp_request(6);
        foreign[0] = (4 << 3) | 4;
        rig.send(rig.guest_udp(ip("10.177.0.1"), crate::ntp::NTP_PORT, 40002, &foreign));
        // The valid request that follows is answered, so everything before it has been handled.
        rig.send(rig.guest_udp(
            ip("10.177.0.1"),
            crate::ntp::NTP_PORT,
            40003,
            &ntp_request(6),
        ));
        rig.frame_where(|frame| match Rig::inner(frame) {
            (protocol, payload) if protocol == IPPROTO_UDP => parse_udp(&payload)
                .map(|datagram| {
                    datagram.src_port == crate::ntp::NTP_PORT && datagram.dst_port == 40003
                })
                .unwrap_or(false),
            _ => false,
        });
        assert!(
            rig.relay.snapshot().dropped_other >= before + 2,
            "the truncated and the foreign packet were counted, not answered"
        );
    }

    #[test]
    fn a_time_query_over_ipv6_is_answered_over_ipv6_from_either_gateway_address() {
        // The same service on the second stack, and at **both** addresses the gateway has: the
        // link-local the DHCPv6 answer and the RA name, and the ULA the RA advertises as on-link.
        let rig = Rig::new();
        for (index, gateway) in [our6(), ip6("fd10:177::1")].into_iter().enumerate() {
            let query = ntp_request(4);
            let client_sent = query[40..48].to_vec();
            let port = 41000 + index as u16;
            rig.send(rig.guest_udp6(gateway, crate::ntp::NTP_PORT, port, &query));
            let frame = rig.frame_where(|frame| {
                let (header, _, _, payload) = Rig::inner6(frame);
                header == IPPROTO_UDP
                    && parse_udp(&payload)
                        .map(|datagram| {
                            datagram.src_port == crate::ntp::NTP_PORT && datagram.dst_port == port
                        })
                        .unwrap_or(false)
            });
            let (_, src, dst, payload) = Rig::inner6(&frame);
            assert_eq!(
                src, gateway,
                "the answer comes from the address the guest asked"
            );
            assert_eq!(dst, guest6());
            let datagram = parse_udp(&payload).expect("a datagram");
            assert_eq!(datagram.payload.len(), crate::ntp::PACKET_LEN);
            assert_eq!(
                datagram.payload[0] & 0x07,
                4,
                "a server reply over IPv6 too"
            );
            assert_eq!(&datagram.payload[24..32], &client_sent[..]);
        }
    }

    #[test]
    fn the_gateway_answers_for_its_ula_too() {
        // A guest can reach its router by the ULA the RA advertises as on-link (`fd10:177::1`), not
        // only by the link-local: an NS for it gets an advertisement from it, and an echo is answered.
        let rig = Rig::new();
        let ula = ip6("fd10:177::1");
        let body = ndp::neighbor_solicitation_body(ula, Some(GUEST_MAC));
        rig.send(rig.guest_icmp6(
            guest6(),
            crate::frame::solicited_node_multicast(ula),
            ndp::NEIGHBOR_SOLICITATION,
            &body,
        ));
        let frame = rig.frame_where(|frame| {
            let (header, _, _, payload) = Rig::inner6(frame);
            header == IPPROTO_ICMPV6
                && parse_icmpv6(&payload)
                    .map(|message| message.kind == ndp::NEIGHBOR_ADVERTISEMENT)
                    .unwrap_or(false)
        });
        let (_, src, dst, payload) = Rig::inner6(&frame);
        assert_eq!(
            src, ula,
            "the advertisement comes from the address asked about"
        );
        assert_eq!(dst, guest6());
        let message = parse_icmpv6(&payload).expect("ICMPv6");
        let advertisement =
            ndp::parse_neighbor(&Rig::icmp6_body(&message)).expect("an advertisement");
        assert_eq!(advertisement.target, ula);
        assert_eq!(advertisement.link_layer, Some(OUR_MAC));
        assert!(
            !advertisement.is_proxy(),
            "it is our own address, so it is a router's"
        );

        rig.send(rig.guest_icmp6(guest6(), ula, 128, &[0x33, 0x33, 0, 1, b'y', b'o']));
        let frame = rig.frame_where(|frame| {
            Rig::inner6(frame).0 == IPPROTO_ICMPV6
                && parse_icmpv6(&Rig::inner6(frame).3)
                    .map(|message| message.kind == 129)
                    .unwrap_or(false)
        });
        let (_, src, _, payload) = Rig::inner6(&frame);
        assert_eq!(src, ula);
        assert_eq!(parse_icmpv6(&payload).expect("ICMPv6").payload, b"yo");
    }

    #[test]
    fn an_oversized_v6_packet_is_answered_with_a_packet_too_big() {
        // A datagram bigger than the conduit's MTU cannot be carried, and IPv6 has no router
        // fragmentation: the guest is told the real MTU, quoting the packet, so its own PMTUD works.
        let rig = Rig::new();
        let payload = vec![b'x'; 1500];
        rig.send(rig.guest_udp6(ip6("::1"), 9, 40000, &payload));
        let frame = rig.frame_where(|frame| {
            Rig::inner6(frame).0 == IPPROTO_ICMPV6
                && parse_icmpv6(&Rig::inner6(frame).3)
                    .map(|message| message.kind == 2)
                    .unwrap_or(false)
        });
        let (_, src, dst, payload) = Rig::inner6(&frame);
        assert_eq!(src, our6());
        assert_eq!(dst, guest6());
        let message = parse_icmpv6(&payload).expect("ICMPv6");
        assert_eq!(
            u32::from_be_bytes(message.rest),
            1500,
            "the conduit's real MTU"
        );
        assert_eq!(
            message.payload[0] >> 4,
            6,
            "the offending packet is quoted back: {message:?}"
        );
        let snapshot = rig.relay.snapshot();
        assert_eq!(snapshot.ptb_sent, 1);
        assert_eq!(snapshot.udp_flows, 0, "nothing was carried to the host");
    }

    #[test]
    fn a_v6_guest_multicast_datagram_is_not_carried_to_the_host() {
        // mDNS and the rest of a guest's multicast is its own link's business: it is never forwarded,
        // and never becomes a host socket.
        let rig = Rig::new();
        rig.send(rig.guest_udp6(ip6("ff02::fb"), 5353, 5353, b"anyone?"));
        std::thread::sleep(Duration::from_millis(80));
        let snapshot = rig.relay.snapshot();
        assert!(rig.answered_nothing());
        assert_eq!(snapshot.udp_flows, 0);
        assert_eq!(snapshot.dropped_other, 1, "{snapshot:?}");
    }
}
