//! The microVM's **network, in this process** — no `passt`, no tap, no root.
//!
//! The guest's frames are ours to answer, because there is no kernel stack behind a unix socket
//! conduit.
//!
//! ```text
//!   guest  ── frame ──▶  the network channel  ── dgram socketpair ──▶  dc-net
//!     ▲                                                   │
//!     └───────────────── frames we build ◀────────────────┘
//! ```
//!
//! What answers a guest's frame:
//!
//! | the guest asks | who answers |
//! |---|---|
//! | `DHCP DISCOVER`/`REQUEST` | our own allocator (`dhcp.rs`): one address per machine |
//! | `ARP` for the gateway | us, with the conduit's MAC |
//! | `ICMP` echo | us |
//! | `UDP`/`TCP` to the internet | our userspace NAT: a guest flow becomes a host socket |
//! | a name | our DNS answer for this machine, the host's resolver for the rest |
//! | time (`NTP`) | the host's clock |
//! | another machine | forwarded frame to frame, if the rules allow it |
//!
//! Two things this buys over `passt`, and they are the reasons for it: the guest's traffic
//! never leaves this process as a *host* process with its own identity (so "the microvm may
//! not reach the host's own services" is a rule we can actually enforce), and the network's
//! lifecycle is the application's — a machine's network cannot outlive it.

use std::sync::Arc;

pub use conduit::{Conduit, Framing, GuestConduit};
pub use dhcp::{DhcpConfig, DhcpServer};
pub use forward::{AcceptHandler, Forward, ForwardState, ForwardStatus, SSH_GUEST_PORT};
pub use gateway::GatewayPorts;
pub use relay::{FixedPeers, NoPeers, Peer, PeerDirectory, Relay, RelayConfig, RelaySnapshot};

/// The module that owns the host-side port forward: **one** listener, the guest's sshd.
///
/// It exists because a userspace network has no other way in: a
/// connection to the host's port is handed to the relay, which carries it to the guest as an
/// ordinary inbound flow.
pub mod forward;

/// The `--host-network` rule: the name `parenthost`, and the
/// one address that stands for the machine this process runs on.
///
/// This is the other half of the rule, beside `forward`: a userspace network is what decides what
/// a guest may reach. A name answered here, a frame rewritten before it
/// reaches the relay and again on its way back — that is the whole of it.
pub mod hostnet;

// The network's own modules, one per subject: the wire, the frame codec, the address servers, the
// relay, the NAT table, the port tables and the host guard.
pub mod conduit;
pub mod dhcp;
pub mod dhcp6;
pub mod frame;
pub mod gateway;
pub mod host;
pub mod nat;
pub mod ndp;
pub mod ntp;
pub mod ports;
pub mod relay;

/// The MAC the conduit's own end answers from: the address every frame the guest receives
/// from its gateway carries.
pub const GATEWAY_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x01];

/// The subnet every desktop-cracker machine's network is: `10.0.177.0/24`, the shape this
/// project has always used, so the guest's addresses are recognisable in a log.
pub const SUBNET: [u8; 4] = [10, 0, 177, 0];
pub const SUBNET_PREFIX: u8 = 24;

/// The guest's own address on the conduit, and the gateway's.
pub const GATEWAY_IP: [u8; 4] = [10, 0, 177, 1];
/// The address the relay **believes** the guest has.  The guest's own lease decides what it
/// really has (DHCP hands out `10.0.177.16`, the first slot of the allocator's range), and this
/// is only what the frames *this process builds* are addressed to: an echo's reply, a lookup's
/// answer, the segments of a forwarded connection.  It must be the address the guest listens on,
/// or the guest drops every one of them — see the system test's `ssh` step, which is where that
/// was found.
pub const GUEST_IP: [u8; 4] = [10, 0, 177, 16];

/// A machine's network: the conduit the channel writes to, the relay that answers it, and the
/// thread that carries frames between them.
pub struct MachineNetwork {
    conduit: Arc<Conduit>,
    relay: Arc<Relay>,
    /// The DHCP server, ours: the guest's lease comes from this process and nowhere else.
    dhcp: Arc<DhcpServer>,
    /// The leases it has handed out (one machine, one address).
    leases: std::sync::Mutex<dhcp::LeaseTable>,
    /// The host's resolvers, in the order that works (a lookup is asked of them directly).
    resolvers: Vec<std::net::SocketAddr>,
    /// The port forwards this machine has, if any: a listener on the host's loopback whose
    /// connections go into the guest (`--ssh-port`).  Empty means **no socket is open on the
    /// host**, which is what a run without the switch is.
    ///
    /// Behind a lock because the network is shared (a `Arc<MachineNetwork>`) and a forward is
    /// opened once the machine is running — the guest has to be there to answer it.
    forwards: std::sync::Mutex<Vec<Forward>>,
    /// **`--host-network`** (the host's own services): the guest may reach the machine
    /// this process runs on, through the gateway's own address.  `false` is the rule the network
    /// has always had — the host's own network is not the guest's to reach — and it is the default.
    host_network: bool,
    /// The machine's forwards, in the shape the `--host-network` rule reads: an `Arc` swapped when
    /// a forward is opened, so the reader thread copies a pointer per frame rather than building a
    /// list, and a frame is never held up by a port lookup.
    forwarded: std::sync::Mutex<std::sync::Arc<hostnet::Forwarded>>,
    thread: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
}

impl MachineNetwork {
    /// Build the machine's network around one end of a conduit: the host's own services are
    /// **not** reachable, which is what a run without `--host-network` is.
    pub fn new(
        device: &str,
        conduit: Conduit,
        resolvers: Vec<std::net::SocketAddr>,
    ) -> Arc<MachineNetwork> {
        Self::with_host_network(device, conduit, resolvers, false)
    }

    /// Build the machine's network, saying whether the host's own services are reachable from it.
    pub fn with_host_network(
        device: &str,
        conduit: Conduit,
        resolvers: Vec<std::net::SocketAddr>,
        host_network: bool,
    ) -> Arc<MachineNetwork> {
        let config = RelayConfig {
            our_mac: GATEWAY_MAC,
            our_ip: GATEWAY_IP.into(),
            dns_ip: GATEWAY_IP.into(),
            our_ip6: frame::link_local_of(GATEWAY_MAC),
            our_ula6: "fd10:177::1".parse().expect("a constant address"),
            dns_ip6: frame::link_local_of(GATEWAY_MAC),
            subnet6: "fd10:177::".parse().expect("a constant address"),
            prefix6: 64,
            subnet: SUBNET.into(),
            prefix: SUBNET_PREFIX,
            connect_timeout: std::time::Duration::from_secs(10),
            max_flows: 256,
            resolvers: resolvers.clone(),
            gateway_ports: Arc::new(GatewayPorts::default()),
            workspace: device.to_string(),
            host_guard: None,
        };
        let conduit = Arc::new(conduit);
        let sender: relay::FrameSender = {
            let conduit = conduit.clone();
            // `--host-network`: a frame a host socket answered **from the host's loopback** is put
            // back at the address the guest dialled, so the flow looks to the guest like one it
            // opened to its own gateway (the host's own services). It is done only for
            // a machine that was given the switch, and it is the mirror of `hostnet::to_host`: a
            // real guest's stack sends no frame to `127.0.0.1` at all — that address is the guest's
            // own loopback and never leaves its `lo` — so a flow whose answer comes from the host's
            // loopback is one this rule created.  Every other frame, the machine's own answers
            // included, goes out exactly as it was built.
            let carried = host_network;
            Arc::new(move |frame: Vec<u8>| {
                let frame = match carried {
                    true => hostnet::from_host(&frame).unwrap_or(frame),
                    false => frame,
                };
                if let Err(_e) = conduit.send(&frame) {}
            })
        };
        let relay = Relay::new(
            device.to_string(),
            config,
            relay::GuestIdentity {
                mac: dc_common::net::GUEST_MAC,
                ip: GUEST_IP.into(),
                ip6: frame::link_local_of(dc_common::net::GUEST_MAC),
            },
            sender,
            Arc::new(NoPeers),
            None,
        );
        let dhcp = Arc::new(DhcpServer::new(DhcpConfig::for_subnet(
            SUBNET.into(),
            SUBNET_PREFIX,
        )));
        Arc::new(MachineNetwork {
            conduit,
            relay,
            dhcp,
            leases: std::sync::Mutex::new(dhcp::LeaseTable::new()),
            resolvers: resolvers.clone(),
            forwards: std::sync::Mutex::new(Vec::new()),
            host_network,
            forwarded: std::sync::Mutex::new(std::sync::Arc::new(hostnet::Forwarded::default())),
            thread: std::sync::Mutex::new(None),
            stop: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        })
    }

    /// Whether this machine may reach the host it is on (`--host-network`).
    pub fn host_network(&self) -> bool {
        self.host_network
    }

    /// Answer a DHCP request: our lease table, our MAC, and the guest's own MAC as the key
    /// (one machine, and the only MAC the conduit carries).
    fn answer_dhcp(&self, frame: &[u8]) {
        let mut leases = self.leases.lock().expect("the lease table");
        let answers = self.dhcp.handle(
            frame,
            &mut leases,
            "desk",
            dc_common::net::GUEST_MAC,
            GATEWAY_MAC,
            Some("desk"),
        );
        drop(leases);
        for answer in answers {
            if let Err(_e) = self.conduit.send(&answer) {}
        }
    }

    /// The host's resolvers, as this machine will ask them.
    pub fn resolvers(&self) -> &[std::net::SocketAddr] {
        &self.resolvers
    }

    /// **`--host-network`**: the answer for a lookup of `parenthost`, when the query is one.
    ///
    /// `None` means the name is not this rule's, and the host's resolver answers it as it always
    /// did.  With the switch off it is `None` for every name, which is the whole of what "off by
    /// default" means for a name.
    fn answer_host_query(&self, query: &GuestQuery) -> Option<Vec<u8>> {
        if !self.host_network {
            return None;
        }
        let (name, qtype) = hostnet::question(&query.query)?;
        let record = hostnet::owns_query(&name, qtype)?;
        Some(hostnet::answer_for(&query.query, record))
    }

    /// Send one lookup's answer back to the guest that asked it.
    ///
    /// From the gateway's address, because that is the nameserver the guest was told to use: a
    /// reply from anywhere else is a reply glibc throws away (that exact failure is what the
    /// image's old `resolv.conf` caused ).
    fn answer_query(&self, query: &GuestQuery, answer: &[u8]) {
        let udp = frame::build_udp(GATEWAY_IP.into(), query.from, 53, query.from_port, answer);
        let ip = frame::build_ipv4(GATEWAY_IP.into(), query.from, frame::IPPROTO_UDP, 64, &udp);
        let ethernet = frame::build_ethernet(
            dc_common::net::GUEST_MAC,
            GATEWAY_MAC,
            frame::ETHERTYPE_IPV4,
            &ip,
        );
        if let Err(_e) = self.conduit.send(&ethernet) {}
    }

    /// The relay, for a caller that wants its counters.
    pub fn relay(&self) -> &Arc<Relay> {
        &self.relay
    }

    /// Open a **port forward** on the host: `host_port` on the host's loopback becomes a
    /// connection to `guest_port` inside this machine (`--ssh-port`).
    ///
    /// It is called once the machine is running, because it is a door into a guest that has to be
    /// there to answer it, and it returns what the forward is — the address it took, or the reason
    /// it could not take it — for the application to report.  Without a call like this the machine
    /// has **no** listener on the host at all.
    pub fn forward(&self, host_port: u16, guest_port: u16) -> ForwardStatus {
        let handler = forward::to_guest(self.relay.clone(), GUEST_IP.into(), guest_port);
        let forward = Forward::bind(host_port, guest_port, handler);
        let status = forward.status().clone();
        self.forwards
            .lock()
            .expect("the machine's forwards")
            .push(forward);
        // The rule's snapshot, rebuilt once per forward (a forward is opened a handful of times in
        // a run, and read once per frame).
        let held = self.forwards.lock().expect("the machine's forwards");
        let all: Vec<_> = held.iter().map(|one| one.status().clone()).collect();
        drop(held);
        let snapshot = hostnet::Forwarded {
            host_ports: all.iter().map(|one| one.host.port()).collect(),
            guest_ports: all.iter().map(|one| one.guest_port).collect(),
        };
        *self.forwarded.lock().expect("the forwarded ports") = std::sync::Arc::new(snapshot);
        status
    }

    /// The port forwards this machine has, as they are (one row each).
    pub fn forward_statuses(&self) -> Vec<ForwardStatus> {
        self.forwards
            .lock()
            .expect("the machine's forwards")
            .iter()
            .map(|forward| forward.status().clone())
            .collect()
    }

    /// The machine's forwards, as the `--host-network` rule reads them.
    fn forward_ports(&self) -> std::sync::Arc<hostnet::Forwarded> {
        std::sync::Arc::clone(&self.forwarded.lock().expect("the forwarded ports"))
    }

    /// Start the reader thread: every frame that arrives is answered.
    pub fn start(self: &Arc<Self>) {
        let this = self.clone();
        let handle = std::thread::spawn(move || {
            let mut buffer = vec![0u8; frame::MAX_FRAME];
            while !this.stop.load(std::sync::atomic::Ordering::Relaxed) {
                match this.conduit.recv(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => {
                        // A DHCP request is answered **here**, before the relay's port-mapping
                        // path can mistake it for a mapped port's reply (see `dhcp_is_ours`).
                        if dhcp_is_ours(&buffer[..n]) {
                            this.answer_dhcp(&buffer[..n]);
                        } else if let Some(query) = guest_query(&buffer[..n]) {
                            // `--host-network`: the name `parenthost` is **ours** to answer, with
                            // the gateway's own address (the host's own services). It is
                            // answered here rather than in the relay's DNS path because this is the
                            // path that works on a host whose resolver is a stub (see
                            // `resolve_and_answer`), and because the name must be answered whether
                            // or not the host has a resolver at all.
                            if let Some(answer) = this.answer_host_query(&query) {
                                this.answer_query(&query, &answer);
                            } else {
                                // A lookup is asked of the host's resolver by **this process**,
                                // on a thread of its own (see `resolve_and_answer`).
                                resolve_and_answer(this.clone(), query);
                            }
                        } else if this.host_network {
                            // A flow to the gateway's address is the guest dialling the machine it
                            // is on: the destination becomes the host's loopback and the relay
                            // carries it like any other flow of this machine.  The machine's own
                            // forwarded ports are the exception, and they are answered rather than
                            // left alone — a door that goes *into* the guest, dialled from the
                            // inside, is a loop, and a loop is a refusal said now (see
                            // `hostnet::refusal`).
                            let forwarded = this.forward_ports();
                            if let Some(no) = hostnet::refusal(&buffer[..n], &forwarded) {
                                if let Err(_e) = this.conduit.send(&no) {}
                            } else if let Some(carried) = hostnet::to_host(&buffer[..n], &forwarded)
                            {
                                this.relay.handle(&carried);
                            } else {
                                this.relay.handle(&buffer[..n]);
                            }
                        } else {
                            this.relay.handle(&buffer[..n]);
                        }
                    }
                    Err(_e) => {
                        break;
                    }
                }
            }
        });
        *self.thread.lock().expect("the network's thread") = Some(handle);
    }

    /// Stop the machine's network.
    pub fn shutdown(&self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = self.conduit.shutdown();
        if let Some(handle) = self.thread.lock().expect("the network's thread").take() {
            let _ = handle.join();
        }
        // The doors into the guest close **before** the relay stops: a connection that arrived
        // while the machine was going away has nothing left to be carried by.
        for forward in self
            .forwards
            .lock()
            .expect("the machine's forwards")
            .drain(..)
        {
            forward.shutdown();
        }
        self.relay.shutdown();
    }
}

impl Drop for MachineNetwork {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = self.conduit.shutdown();
    }
}

/// The conduit for a machine: a `SOCK_DGRAM` socketpair, our end and the machine's end.
///
/// A datagram pair, not a stream: the kernel keeps the frame boundaries, so neither end has
/// to frame anything (the machine's `-netdev dgram,local.type=fd` expects exactly this).
pub fn conduit_pair() -> std::io::Result<(Conduit, GuestConduit)> {
    let (ours, theirs) = std::os::unix::net::UnixDatagram::pair()?;
    Ok((Conduit::datagram(ours), GuestConduit::Datagram(theirs)))
}

/// Where the guest's DNS query goes, and why it does not go through the relay.
///
/// The vendored `relay.rs` treats a datagram **to the gateway's own address** as a reply
/// through one of the *deployment's published ports* (`handle_ipv4`), and it opens a socket
/// bound to `127.0.0.1:53` to answer it — measured here: `cannot answer 127.0.0.1:53 through
/// the mapping: Connection refused`, and the guest's lookups were lost while the relay kept
/// creating sockets.  In this project there are no published ports and no peers: the
/// gateway's port 53 is **ours to answer**, and the answer comes from this process asking the
/// host's resolver (see `resolve_and_answer`).  So the reader thread recognises a DNS query
/// first, exactly as it recognises DHCP.
///
/// A **DNS query to us**: the guest's source address and port, and the query itself.
struct GuestQuery {
    from: std::net::Ipv4Addr,
    from_port: u16,
    query: Vec<u8>,
}

/// Is this frame a DNS query addressed to the gateway?
///
/// The check the reader thread makes, beside `dhcp_is_ours`, and the reason it is here: the
/// relay's own DNS path answers a name the *deployment* owns and forwards the rest — and it
/// forwards them through a socket bound to the guest's own address on the host, which the
/// kernel will not use to reach a resolver on `127.0.0.1` (measured on this host, whose only
/// resolver is `systemd-resolved`'s `127.0.0.53`).  So this project asks the host's resolver
/// itself, on a thread, and frames the answer back.
fn guest_query(payload: &[u8]) -> Option<GuestQuery> {
    let ethernet = frame::parse_ethernet(payload)?;
    if ethernet.ethertype != frame::ETHERTYPE_IPV4 {
        return None;
    }
    let ip = frame::parse_ipv4(ethernet.payload)?;
    if ip.protocol != frame::IPPROTO_UDP {
        return None;
    }
    let udp = frame::parse_udp(ip.payload)?;
    if udp.dst_port != 53 || udp.payload.len() < 12 {
        return None;
    }
    // **Any** destination on port 53 from the guest is a lookup for us: it is what the guest
    // was told to use (the gateway, in DHCP's option 6) and what `resolv.conf` now says, but a
    // guest that read `127.0.0.53` from somewhere else must not be left shouting into a void
    // either.  Port 53 is the question; who answers it is this process.
    let _ = ip.dst;
    Some(GuestQuery {
        from: ip.src,
        from_port: udp.src_port,
        query: udp.payload.to_vec(),
    })
}

/// Ask the host's resolver, on a thread of its own, and frame its answer back to the guest.
///
/// A thread, because a lookup is the host's to answer and can take seconds: the reader
/// thread is the guest's **only** reader, and waiting in it would stall every other frame the
/// guest sends (the vendored relay says the same thing about its own forwarded queries, and
/// it is the same reasoning).
fn resolve_and_answer(network: Arc<MachineNetwork>, query: GuestQuery) {
    let resolvers = network.resolvers.clone();
    let conduit = network.conduit.clone();
    std::thread::spawn(move || {
        let socket = match std::net::UdpSocket::bind("127.0.0.1:0") {
            Ok(socket) => socket,
            Err(_e) => {
                return;
            }
        };
        let _ = socket.set_read_timeout(Some(std::time::Duration::from_secs(5)));
        for resolver in &resolvers {
            if socket.send_to(&query.query, resolver).is_err() {
                continue;
            }
            let mut answer = vec![0u8; 1500];
            match socket.recv_from(&mut answer) {
                Ok((n, _)) => {
                    let answer = &answer[..n];
                    // The transaction id must be the guest's (it is the query's first two
                    // bytes): a client discards an answer that is not its own.
                    let udp = frame::build_udp(
                        GATEWAY_IP.into(),
                        query.from,
                        53,
                        query.from_port,
                        answer,
                    );
                    let ip = frame::build_ipv4(
                        GATEWAY_IP.into(),
                        query.from,
                        frame::IPPROTO_UDP,
                        64,
                        &udp,
                    );
                    let ethernet = frame::build_ethernet(
                        dc_common::net::GUEST_MAC,
                        GATEWAY_MAC,
                        frame::ETHERTYPE_IPV4,
                        &ip,
                    );
                    if let Err(_e) = conduit.send(&ethernet) {}
                    return;
                }
                Err(_e) => {}
            }
        }
        // Nothing answered: say so **to the guest**, rather than leaving its resolver to
        // time out on its own (a SERVFAIL is an answer; silence is not).
        let servfail = servfail_for(&query.query);
        let udp = frame::build_udp(
            GATEWAY_IP.into(),
            query.from,
            53,
            query.from_port,
            &servfail,
        );
        let ip = frame::build_ipv4(GATEWAY_IP.into(), query.from, frame::IPPROTO_UDP, 64, &udp);
        let ethernet = frame::build_ethernet(
            dc_common::net::GUEST_MAC,
            GATEWAY_MAC,
            frame::ETHERTYPE_IPV4,
            &ip,
        );
        let _ = conduit.send(&ethernet);
    });
}

/// A SERVFAIL for a query: the query's header and question, with the error code set.
fn servfail_for(query: &[u8]) -> Vec<u8> {
    let mut answer = query.to_vec();
    if answer.len() >= 12 {
        answer[2] = 0x81; // response, recursion desired
        answer[3] = 0x82; // recursion available + SERVFAIL (rcode 2)
        for byte in answer[6..12].iter_mut() {
            *byte = 0; // no records of any kind
        }
    }
    answer
}

/// Why a datagram to the gateway's own address must not go through the port-mapping path.
///
/// `relay.rs`'s UDP path treats a datagram **to our own address** as a reply through one of
/// the *operator's published ports* — a socket that is bound but *not connected*, so
/// `send` cannot work and the code needs `send_to` with a known destination.  A guest that
/// asks for a DHCP lease has no address yet: it broadcasts its DISCOVER, and our answer
/// goes to `255.255.255.255:68`, which is not a destination that path can use (measured:
/// `cannot answer 255.255.255.255:67 through the mapping: Destination address required`).
///
/// In a machine network with no mappings there is nothing to be a reply to, so a datagram to
/// the gateway belongs to **us** — DHCP above all.  This is the one place this project's
/// front differs from the vendored code in *behaviour* rather than in wiring, and it is
/// stated here so the day the two projects are one, this is what merges.
fn dhcp_is_ours(payload: &[u8]) -> bool {
    // An Ethernet/IPv4/UDP datagram whose destination port is 67 (the DHCP server) is ours.
    let Some(ethernet) = frame::parse_ethernet(payload) else {
        return false;
    };
    if ethernet.ethertype != frame::ETHERTYPE_IPV4 {
        return false;
    }
    let Some(ip) = frame::parse_ipv4(ethernet.payload) else {
        return false;
    };
    if ip.protocol != frame::IPPROTO_UDP {
        return false;
    }
    matches!(frame::parse_udp(ip.payload), Some(udp) if udp.dst_port == 67)
}

/// The descriptor a child must inherit, and the network it belongs to.
///
/// The guest's end of the socketpair, **cleared of `FD_CLOEXEC`** so the `exec` into the child
/// carries it — which is the whole trick: there is no path, no device and no privilege, just
/// a descriptor this process owns and a child is handed.
pub struct Attachment {
    /// The descriptor to pass as `-netdev dgram,id=net0,local.type=fd,local.str=<fd>`.
    pub fd: std::os::fd::RawFd,
    /// The same socket, kept until the child has it: this process must not hold a second copy of
    /// the guest's end, or the conduit would outlive the machine.  Dropped right after the
    /// spawn.
    pub keepalive: GuestConduit,
    /// The machine's network (ours to answer with, and ours to stop).
    pub network: Arc<MachineNetwork>,
}

/// Give a machine its network: a datagram conduit, our end answering it, and the machine's end in
/// `fd`.  The host's own services are **not** reachable from it, which is the rule without
/// `--host-network`.
pub fn attach(device: &str, resolvers: Vec<std::net::SocketAddr>) -> std::io::Result<Attachment> {
    attach_with_host_network(device, resolvers, false)
}

/// The same, saying whether the machine may reach the host it is on (`--host-network`).
pub fn attach_with_host_network(
    device: &str,
    resolvers: Vec<std::net::SocketAddr>,
    host_network: bool,
) -> std::io::Result<Attachment> {
    let (ours, theirs) = conduit_pair()?;
    clear_cloexec(&theirs)?;
    let network = MachineNetwork::with_host_network(device, ours, resolvers, host_network);
    Ok(Attachment {
        fd: {
            use std::os::fd::AsRawFd as _;
            theirs.as_raw_fd()
        },
        keepalive: theirs,
        network,
    })
}

/// Clear `FD_CLOEXEC`, so the descriptor survives the `exec` into the child.
fn clear_cloexec(socket: &impl std::os::fd::AsRawFd) -> std::io::Result<()> {
    let fd = socket.as_raw_fd();
    // SAFETY: `fd` is open (the socketpair was just made), and `fcntl` with these two commands
    // takes an int and returns one.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error());
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// The host's resolvers, from `/etc/resolv.conf` — with the ones a **guest cannot use**
/// moved to the end.
///
/// The relay answers a name it does not own by asking the host's resolver, so the resolver
/// has to be reachable from *this* process.  It is not always: on a desktop with
/// `systemd-resolved` the name is `127.0.0.53`, which answers only a process running in
/// **this** network namespace — and a relay that looks a name up through a socket it opened
/// succeeds, while its *reply* to the guest cannot be delivered, because the relay's UDP
/// path sends through a socket bound to the guest's address on the host (`10.0.177.1`) and
/// the kernel refuses to route `127.0.0.1`-sourced traffic out of it (measured: the guest's
/// every lookup timed out while the answer arrived at the socket).
///
/// So the usable resolvers come first and the loopback ones last, and a host with only a
/// stub resolver is *saying so* rather than failing silently.  (The day the relay's answer
/// path is fixed upstream — this project's own copy records the correction — the ordering
/// still holds: a reachable resolver is the one to use.)
pub fn host_resolvers() -> Vec<std::net::SocketAddr> {
    let mut local = Vec::new();
    let mut remote = Vec::new();
    if let Ok(text) = std::fs::read_to_string("/etc/resolv.conf") {
        for line in text.lines() {
            let mut words = line.split_whitespace();
            if words.next() != Some("nameserver") {
                continue;
            }
            let Some(addr) = words
                .next()
                .and_then(|a| a.parse::<std::net::IpAddr>().ok())
            else {
                continue;
            };
            if addr.is_loopback() {
                local.push(std::net::SocketAddr::new(addr, 53));
            } else {
                remote.push(std::net::SocketAddr::new(addr, 53));
            }
        }
    }
    // A host with no resolver of its own: its loopback ones are all there is, and they are
    // what the guest's queries are sent to.
    remote.extend(local);
    remote
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_conduit_pair_carries_a_frame_both_ways() {
        // The wire the child is given: one datagram is one Ethernet frame.
        let (ours, theirs) = conduit_pair().unwrap();
        let frame = frame::build_ethernet([0xff; 6], GATEWAY_MAC, frame::ETHERTYPE_ARP, &[0u8; 28]);
        theirs.send(&frame).unwrap();
        let mut buffer = vec![0u8; frame::MAX_FRAME];
        let n = ours.recv(&mut buffer).unwrap();
        assert_eq!(n, frame.len());
        assert_eq!(&buffer[..n], &frame[..]);
        assert_eq!(ours.framing(), Framing::Datagram);
    }
}

#[cfg(test)]
mod forward_tests {
    use super::*;
    use std::time::Duration;

    /// A connection to the host's forwarded port becomes an **inbound flow into the guest**: the
    /// relay opens the guest's side with a SYN for the guest's own port (22, its sshd), which is
    /// the same thing the vendored relay does for the port mappings of the project it came from.
    ///
    /// Nothing about the guest's side is faked: the "guest" is the conduit's frame end, so what
    /// this asserts is what a child would carry into the machine.
    #[test]
    fn a_connection_to_the_forwarded_port_reaches_the_guest() {
        let attachment = attach("forward-test", vec![]).expect("a conduit");
        attachment.network.start();
        let status = attachment.network.forward(0, SSH_GUEST_PORT);
        assert_eq!(status.state, ForwardState::Bound);
        assert_eq!(status.guest_port, SSH_GUEST_PORT);
        let address = status.host;
        assert!(
            address.ip().is_loopback(),
            "a forward is on the host's loopback, not on the network: {address}"
        );

        let client = std::thread::spawn(move || std::net::TcpStream::connect(address).is_ok());

        // The guest's end of the conduit sees the relay's SYN, for the guest's own port.
        let mut buffer = vec![0u8; frame::MAX_FRAME];
        attachment
            .keepalive
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut syn_for = None;
        for _ in 0..8 {
            let Ok(n) = attachment.keepalive.recv(&mut buffer) else {
                break;
            };
            let Some(ethernet) = frame::parse_ethernet(&buffer[..n]) else {
                continue;
            };
            let Some(ip) = frame::parse_ipv4(ethernet.payload) else {
                continue;
            };
            let Some(tcp) = frame::parse_tcp(ip.payload) else {
                continue;
            };
            if tcp.has(frame::TCP_SYN) {
                syn_for = Some(tcp.dst_port);
                break;
            }
        }
        attachment.network.shutdown();
        assert!(
            client.join().unwrap(),
            "the client connected to the forwarded port"
        );
        assert_eq!(
            syn_for,
            Some(SSH_GUEST_PORT),
            "the connection was carried to the guest's sshd"
        );
    }

    /// **Without the switch there is no door.**  A machine that was asked for no forward holds no
    /// listener on the host, so the guest's sshd is not exposed; one that was asked for one holds
    /// exactly that port, and gives it back when the run ends.
    #[test]
    fn a_machine_opens_a_door_only_when_it_is_asked_for_one() {
        let attachment = attach("no-forward", vec![]).expect("a conduit");
        assert!(
            attachment.network.forward_statuses().is_empty(),
            "a machine with no --ssh-port listens on nothing"
        );

        let status = attachment.network.forward(0, SSH_GUEST_PORT);
        assert_eq!(status.state, ForwardState::Bound);
        let taken = status.host;
        assert_eq!(attachment.network.forward_statuses().len(), 1);
        // The address is really held while the forward lives...
        assert!(
            std::net::TcpListener::bind(taken).is_err(),
            "the forward holds {taken}"
        );
        attachment.network.shutdown();
        // ...and the run's end gives it back, so the next run can take it again.
        assert!(
            std::net::TcpListener::bind(taken).is_ok(),
            "the port is free once the network is stopped"
        );
    }
}

#[cfg(test)]
mod dhcp_tests {
    use super::*;

    /// A DHCP DISCOVER the way a guest sends it: broadcast Ethernet, IPv4 from 0.0.0.0 to
    /// 255.255.255.255, UDP 68 → 67, one `Message Type: DISCOVER` option.
    fn a_discover() -> Vec<u8> {
        let mut bootp = vec![0u8; 236];
        bootp[0] = 1; // op: request
        bootp[1] = 1; // htype: ethernet
        bootp[2] = 6; // hlen
        bootp[3] = 0; // hops
        bootp[4..8].copy_from_slice(&0x1234_5678u32.to_be_bytes()); // xid
        bootp[28..34].copy_from_slice(&dc_common::net::GUEST_MAC); // chaddr
        bootp.extend_from_slice(&[99, 130, 83, 99]); // magic cookie
        bootp.extend_from_slice(&[53, 1, 1]); // option 53 (message type), length 1, DISCOVER
        bootp.push(255); // end
        let udp = frame::build_udp(
            "0.0.0.0".parse().unwrap(),
            "255.255.255.255".parse().unwrap(),
            68,
            67,
            &bootp,
        );
        let ip = frame::build_ipv4(
            "0.0.0.0".parse().unwrap(),
            "255.255.255.255".parse().unwrap(),
            frame::IPPROTO_UDP,
            64,
            &udp,
        );
        frame::build_ethernet(
            [0xff; 6],
            dc_common::net::GUEST_MAC,
            frame::ETHERTYPE_IPV4,
            &ip,
        )
    }

    #[test]
    fn a_dhcp_request_is_ours_and_an_ordinary_datagram_is_not() {
        // The recognition the reader thread uses: DHCP goes to our own server, everything
        // else to the relay.
        assert!(dhcp_is_ours(&a_discover()));
        let dns = frame::build_udp(GUEST_IP.into(), GATEWAY_IP.into(), 40000, 53, &[0u8; 12]);
        let ip = frame::build_ipv4(
            GUEST_IP.into(),
            GATEWAY_IP.into(),
            frame::IPPROTO_UDP,
            64,
            &dns,
        );
        let ethernet = frame::build_ethernet(
            GATEWAY_MAC,
            dc_common::net::GUEST_MAC,
            frame::ETHERTYPE_IPV4,
            &ip,
        );
        assert!(
            !dhcp_is_ours(&ethernet),
            "a DNS query to the gateway is the relay's"
        );
    }

    #[test]
    fn our_dhcp_server_answers_a_discover_with_an_offer_for_this_machine() {
        // The server is ours and the answer carries the guest's own MAC + the address the
        // pool gave it: no passt, no host DHCP, nothing shared with the host's network.
        let dhcp =
            dhcp::DhcpServer::new(dhcp::DhcpConfig::for_subnet(SUBNET.into(), SUBNET_PREFIX));
        let mut leases = dhcp::LeaseTable::new();
        let answers = dhcp.handle(
            &a_discover(),
            &mut leases,
            "desk",
            dc_common::net::GUEST_MAC,
            GATEWAY_MAC,
            Some("desk"),
        );
        assert_eq!(answers.len(), 1, "a DISCOVER is answered");
        let offer = &answers[0];
        // The offer is an Ethernet frame to the guest, and inside it a BOOTREPLY that names
        // an address in **our** subnet (the bytes: 14 of Ethernet, then BOOTP's op, …, yiaddr
        // at BOOTP offset 16).
        assert_eq!(
            &offer[..6],
            &dc_common::net::GUEST_MAC,
            "addressed to the guest"
        );
        // The answer is an Ethernet frame (14 bytes) + IPv4 (20) + UDP (8) + the BOOTP
        // message; the BOOTP part is read from there.
        let bootp = &offer[42..];
        assert_eq!(bootp[0], 2, "op = BOOTREPLY");
        assert_eq!(
            &bootp[28..34],
            &dc_common::net::GUEST_MAC,
            "for this machine's MAC"
        );
        let ip = std::net::Ipv4Addr::new(bootp[16], bootp[17], bootp[18], bootp[19]);
        assert_eq!(
            ip.octets()[..3],
            SUBNET[..3],
            "the offer is inside our subnet: {ip}"
        );
    }
}

#[cfg(test)]
mod conduit_tests {
    use super::*;

    /// The whole point of this module: a **guest's TCP to a host address** is answered by
    /// this process with a real connection, with no `passt` and no tap.
    ///
    /// It runs against a host listener of its own, so the test needs no internet: the guest
    /// inside the test is a plain `TcpStream` opened *from the conduit's frame side*.
    #[test]
    fn a_guest_tcp_connection_is_relayed_to_a_host_socket() {
        use std::io::Write as _;
        use std::net::TcpListener;

        // A host service to reach: it says one word and closes.
        let listener = TcpListener::bind("127.0.0.1:0").expect("a listener");
        let port = listener.local_addr().unwrap().port();
        let service = std::thread::spawn(move || {
            if let Ok((mut socket, _)) = listener.accept() {
                let _ = socket.write_all(b"hello from the host");
                let _ = socket.flush();
            }
        });

        // The machine's network, and the guest's end of its conduit.
        let attachment = attach("test", vec![]).expect("a conduit");
        attachment.network.start();
        let guest = &attachment.keepalive;

        // The guest's SYN: Ethernet + IPv4 + TCP 40000 → the host service's port.
        let syn = {
            let tcp = frame::build_tcp(
                GUEST_IP.into(),
                "127.0.0.1".parse().unwrap(),
                40000,
                port,
                1000,
                0,
                frame::TCP_SYN,
                65535,
                &[],
            );
            let ip = frame::build_ipv4(
                GUEST_IP.into(),
                "127.0.0.1".parse().unwrap(),
                frame::IPPROTO_TCP,
                64,
                &tcp,
            );
            frame::build_ethernet(
                GATEWAY_MAC,
                dc_common::net::GUEST_MAC,
                frame::ETHERTYPE_IPV4,
                &ip,
            )
        };
        guest
            .send(&syn)
            .expect("the frame is written to the conduit");

        // The relay answers the handshake, and then the service's bytes arrive as frames.
        let mut buffer = vec![0u8; frame::MAX_FRAME];
        let mut saw_syn_ack = false;
        let mut carried = Vec::new();
        guest
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        for _ in 0..16 {
            let Ok(n) = guest.recv(&mut buffer) else {
                break;
            };
            let Some(ethernet) = frame::parse_ethernet(&buffer[..n]) else {
                continue;
            };
            let Some(ip) = frame::parse_ipv4(ethernet.payload) else {
                continue;
            };
            let Some(tcp) = frame::parse_tcp(ip.payload) else {
                continue;
            };
            if tcp.has(frame::TCP_SYN) && tcp.has(frame::TCP_ACK) {
                saw_syn_ack = true;
            }
            // The guest ACKs what it is given (the relay's flow wants an in-order ACK).
            carried.extend_from_slice(tcp.payload);
            if !tcp.payload.is_empty() {
                let ack = frame::build_tcp(
                    GUEST_IP.into(),
                    "127.0.0.1".parse().unwrap(),
                    40000,
                    port,
                    tcp.seq.wrapping_add(tcp.payload.len() as u32),
                    tcp.ack,
                    frame::TCP_ACK,
                    65535,
                    &[],
                );
                let ip = frame::build_ipv4(
                    GUEST_IP.into(),
                    "127.0.0.1".parse().unwrap(),
                    frame::IPPROTO_TCP,
                    64,
                    &ack,
                );
                let frame = frame::build_ethernet(
                    GATEWAY_MAC,
                    dc_common::net::GUEST_MAC,
                    frame::ETHERTYPE_IPV4,
                    &ip,
                );
                let _ = guest.send(&frame);
            }
            if carried.windows(5).any(|w| w == b"hello") {
                break;
            }
        }
        attachment.network.shutdown();
        let _ = service.join();
        assert!(
            saw_syn_ack,
            "the relay answered the guest's SYN with a SYN-ACK"
        );
        assert!(
            carried.windows(5).any(|w| w == b"hello"),
            "the host service's bytes arrived as frames for the guest: {carried:?}"
        );
    }
}

#[cfg(test)]
mod udp_tests {
    use super::*;

    /// A guest's UDP to the internet is answered by a **host socket this process opens**,
    /// with the reply carried back as frames — the other half of the relay, and the one a
    /// DNS lookup (and therefore "firefox has no internet") depends on.
    #[test]
    fn a_guest_udp_datagram_is_relayed_to_a_host_socket() {
        use std::net::UdpSocket;

        let service = UdpSocket::bind("127.0.0.1:0").expect("a host socket");
        let port = service.local_addr().unwrap().port();
        let echo = std::thread::spawn(move || {
            let mut buffer = [0u8; 64];
            if let Ok((n, from)) = service.recv_from(&mut buffer) {
                let _ = service.send_to(b"pong", from);
                return buffer[..n].to_vec();
            }
            Vec::new()
        });

        let attachment = attach("udp-test", vec![]).expect("a conduit");
        attachment.network.start();
        let guest = &attachment.keepalive;

        let datagram = frame::build_udp(
            GUEST_IP.into(),
            "127.0.0.1".parse().unwrap(),
            41000,
            port,
            b"ping",
        );
        let ip = frame::build_ipv4(
            GUEST_IP.into(),
            "127.0.0.1".parse().unwrap(),
            frame::IPPROTO_UDP,
            64,
            &datagram,
        );
        let frame = frame::build_ethernet(
            GATEWAY_MAC,
            dc_common::net::GUEST_MAC,
            frame::ETHERTYPE_IPV4,
            &ip,
        );
        guest
            .send(&frame)
            .expect("the datagram reaches the conduit");

        guest
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut buffer = vec![0u8; frame::MAX_FRAME];
        let mut answer = Vec::new();
        for _ in 0..16 {
            let Ok(n) = guest.recv(&mut buffer) else {
                break;
            };
            let Some(ethernet) = frame::parse_ethernet(&buffer[..n]) else {
                continue;
            };
            let Some(ip) = frame::parse_ipv4(ethernet.payload) else {
                continue;
            };
            let Some(udp) = frame::parse_udp(ip.payload) else {
                continue;
            };
            if udp.src_port == port {
                answer.extend_from_slice(udp.payload);
                break;
            }
        }
        attachment.network.shutdown();
        let what_the_host_saw = echo.join().unwrap_or_default();
        assert_eq!(
            what_the_host_saw, b"ping",
            "the host socket received the guest's bytes"
        );
        assert_eq!(
            &answer[..],
            b"pong",
            "the host's answer came back as a frame"
        );
    }
}

#[cfg(test)]
mod dns_tests {
    use super::*;

    /// A guest's lookup of a name **we do not own** goes to the host's resolver, and its
    /// answer comes back — the piece "firefox cannot resolve anything" is about.
    ///
    /// The test plays the host's resolver on `127.0.0.1`, so it needs no internet: an
    /// `A` query for `example.com` is answered with a fixed address, and the frames must
    /// carry it back to the guest.
    #[test]
    fn a_guest_lookup_is_forwarded_to_the_hosts_resolver() {
        use std::net::UdpSocket;

        let resolver = UdpSocket::bind("127.0.0.1:0").expect("a resolver");
        let resolver_port = resolver.local_addr().unwrap().port();
        let server = std::thread::spawn(move || {
            let mut buffer = [0u8; 512];
            if let Ok((n, from)) = resolver.recv_from(&mut buffer) {
                let mut answer = buffer[..n].to_vec();
                // A minimal answer: the standard reply header, the question echoed, and one
                // A record (name pointer, type 1, class 1, ttl, length 4, 93.184.216.34).
                answer[2] = 0x81; // QR + RD
                answer[3] = 0x80; // RA
                answer[6] = 0;
                answer[7] = 1; // one answer
                answer.extend_from_slice(&[
                    0xc0, 0x0c, // name: a pointer to the question's name
                    0x00, 0x01, // type A
                    0x00, 0x01, // class IN
                    0x00, 0x00, 0x00, 0x3c, // ttl 60
                    0x00, 0x04, // length 4
                    93, 184, 216, 34,
                ]);
                let _ = resolver.send_to(&answer, from);
            }
        });

        let attachment = attach(
            "dns-test",
            vec![std::net::SocketAddr::from(([127, 0, 0, 1], resolver_port))],
        )
        .expect("a conduit");
        attachment.network.start();
        let guest = &attachment.keepalive;

        // The guest's query: `example.com` A, transaction id 0x1234.
        let mut query = vec![0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        query.extend_from_slice(&[7, b'e', b'x', b'a', b'm', b'p', b'l', b'e']);
        query.extend_from_slice(&[3, b'c', b'o', b'm', 0]);
        query.extend_from_slice(&[0, 1, 0, 1]);
        let datagram = frame::build_udp(GUEST_IP.into(), GATEWAY_IP.into(), 44000, 53, &query);
        let ip = frame::build_ipv4(
            GUEST_IP.into(),
            GATEWAY_IP.into(),
            frame::IPPROTO_UDP,
            64,
            &datagram,
        );
        let frame = frame::build_ethernet(
            dc_common::net::GUEST_MAC,
            GATEWAY_MAC,
            frame::ETHERTYPE_IPV4,
            &ip,
        );
        guest.send(&frame).expect("the query reaches the conduit");

        guest
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut buffer = vec![0u8; frame::MAX_FRAME];
        let mut answer = Vec::new();
        for _ in 0..40 {
            let Ok(n) = guest.recv(&mut buffer) else {
                break;
            };
            let Some(ethernet) = frame::parse_ethernet(&buffer[..n]) else {
                continue;
            };
            let Some(ip) = frame::parse_ipv4(ethernet.payload) else {
                continue;
            };
            let Some(udp) = frame::parse_udp(ip.payload) else {
                continue;
            };
            // The answer comes back from our own address, on port 53.
            if udp.src_port == 53 && udp.dst_port == 44000 {
                answer.extend_from_slice(udp.payload);
                break;
            }
        }
        attachment.network.shutdown();
        let _ = server.join();
        assert!(
            answer.len() > 12,
            "the resolver's answer came back to the guest: {answer:?}"
        );
        assert!(
            answer.windows(4).any(|w| w == [93, 184, 216, 34]),
            "and it carries the address the host's resolver gave: {answer:?}"
        );
    }
}

#[cfg(test)]
mod guest_lookup_tests {
    use super::*;

    /// A guest's lookup is recognised **by the frames**, whatever address it aims at: the
    /// guest was told to use the gateway, and a guest that read `127.0.0.53` somewhere else
    /// must still be answered (the reader thread decides with this function).
    #[test]
    fn a_lookup_is_recognised_from_the_frame() {
        for destination in ["10.0.177.1", "10.0.177.2", "127.0.0.53", "1.1.1.1"] {
            let query = [0x12u8, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
            let datagram = frame::build_udp(
                GUEST_IP.into(),
                destination.parse().unwrap(),
                40000,
                53,
                &query,
            );
            let ip = frame::build_ipv4(
                GUEST_IP.into(),
                destination.parse().unwrap(),
                frame::IPPROTO_UDP,
                64,
                &datagram,
            );
            let ethernet = frame::build_ethernet(
                GATEWAY_MAC,
                dc_common::net::GUEST_MAC,
                frame::ETHERTYPE_IPV4,
                &ip,
            );
            let found = guest_query(&ethernet);
            assert!(found.is_some(), "a lookup to {destination} is ours");
            let query = found.unwrap();
            assert_eq!(query.from_port, 40000);
            assert_eq!(query.from, std::net::Ipv4Addr::from(GUEST_IP));
        }
    }

    /// Anything that is not a lookup is left to the relay: a DNS *answer*, a query on
    /// another port, and a web request all pass through.
    #[test]
    fn what_is_not_a_lookup_is_the_relays() {
        let not_a_lookup =
            frame::build_udp(GUEST_IP.into(), GATEWAY_IP.into(), 40000, 80, &[0u8; 12]);
        let ip = frame::build_ipv4(
            GUEST_IP.into(),
            GATEWAY_IP.into(),
            frame::IPPROTO_UDP,
            64,
            &not_a_lookup,
        );
        let ethernet = frame::build_ethernet(
            GATEWAY_MAC,
            dc_common::net::GUEST_MAC,
            frame::ETHERTYPE_IPV4,
            &ip,
        );
        assert!(guest_query(&ethernet).is_none());
    }
}

#[cfg(test)]
mod host_network_tests {
    use super::*;

    /// A guest's `A` query for `name`, on the conduit.
    fn lookup(name: &str, from_port: u16) -> Vec<u8> {
        let mut query = vec![0x12u8, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0);
        query.extend_from_slice(&1u16.to_be_bytes()); // type A
        query.extend_from_slice(&1u16.to_be_bytes()); // class IN
        let datagram = frame::build_udp(GUEST_IP.into(), GATEWAY_IP.into(), from_port, 53, &query);
        let ip = frame::build_ipv4(
            GUEST_IP.into(),
            GATEWAY_IP.into(),
            frame::IPPROTO_UDP,
            64,
            &datagram,
        );
        frame::build_ethernet(
            GATEWAY_MAC,
            dc_common::net::GUEST_MAC,
            frame::ETHERTYPE_IPV4,
            &ip,
        )
    }

    /// One answer the conduit carries back, as the DNS payload.
    fn one_answer(guest: &GuestConduit, from_port: u16) -> Vec<u8> {
        guest
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut buffer = vec![0u8; frame::MAX_FRAME];
        for _ in 0..16 {
            let Ok(n) = guest.recv(&mut buffer) else {
                break;
            };
            let Some(ethernet) = frame::parse_ethernet(&buffer[..n]) else {
                continue;
            };
            let Some(ip) = frame::parse_ipv4(ethernet.payload) else {
                continue;
            };
            let Some(udp) = frame::parse_udp(ip.payload) else {
                continue;
            };
            if udp.src_port == 53 && udp.dst_port == from_port {
                return udp.payload.to_vec();
            }
        }
        Vec::new()
    }

    /// `--host-network`: the name is answered **here**, with the gateway's own address, and no
    /// resolver is asked (the machine was built with none, which is the point of the assertion).
    #[test]
    fn the_name_parenthost_is_answered_with_the_gateways_address() {
        let attachment = attach_with_host_network("hostnet-on", vec![], true).expect("a conduit");
        attachment.network.start();
        let guest = &attachment.keepalive;
        guest.send(&lookup("parenthost", 44001)).unwrap();
        let answer = one_answer(guest, 44001);
        attachment.network.shutdown();
        assert!(answer.len() > 12, "the name was answered: {answer:?}");
        assert_eq!(
            &answer[..2],
            &[0x12, 0x34],
            "the guest's own transaction id"
        );
        assert_eq!(answer[3] & 0x0f, 0, "no error");
        assert_eq!(u16::from_be_bytes([answer[6], answer[7]]), 1, "one record");
        assert!(
            answer.windows(4).any(|w| w == GATEWAY_IP),
            "the record is the gateway's address, which is what the guest dials: {answer:?}"
        );
    }

    /// **Off by default**: without the switch the name is not ours, and nothing answers it with
    /// the gateway's address.  With no resolver on this machine the honest answer is a failure —
    /// which is the same answer any other name gets from a machine with no resolver.
    #[test]
    fn without_the_switch_the_name_is_not_answered_with_the_gateways_address() {
        let attachment = attach("hostnet-off", vec![]).expect("a conduit");
        attachment.network.start();
        let guest = &attachment.keepalive;
        guest.send(&lookup("parenthost", 44002)).unwrap();
        let answer = one_answer(guest, 44002);
        attachment.network.shutdown();
        assert!(
            !answer.windows(4).any(|w| w == GATEWAY_IP),
            "the gateway's address was handed out for a name the rule does not own: {answer:?}"
        );
        assert_eq!(
            u16::from_be_bytes([answer[6], answer[7]]),
            0,
            "no record of any kind"
        );
    }

    /// The other half, end to end: the guest dials the gateway's address, a **service on the
    /// host's loopback** answers, and the answer reaches the guest as a frame from the address it
    /// dialled.  Nothing in the middle knows the service is on the host.
    #[test]
    fn a_flow_to_the_gateways_address_reaches_a_service_on_the_host() {
        use std::io::Write as _;
        use std::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").expect("a host service");
        let port = listener.local_addr().unwrap().port();
        let service = std::thread::spawn(move || {
            let Ok((mut socket, _)) = listener.accept() else {
                return String::new();
            };
            let _ = socket.write_all(b"from the host");
            let _ = socket.flush();
            let mut seen = [0u8; 8];
            let _ = std::io::Read::read(&mut socket, &mut seen);
            socket
                .peer_addr()
                .map(|p| p.ip().to_string())
                .unwrap_or_default()
        });

        let attachment = attach_with_host_network("hostnet-flow", vec![], true).expect("a conduit");
        attachment.network.start();
        let guest = &attachment.keepalive;

        let dial = |payload: &[u8], seq: u32| {
            let tcp = frame::build_tcp(
                GUEST_IP.into(),
                hostnet::HOST_ADDRESS,
                40001,
                port,
                seq,
                1,
                frame::TCP_ACK,
                65535,
                payload,
            );
            let ip = frame::build_ipv4(
                GUEST_IP.into(),
                hostnet::HOST_ADDRESS,
                frame::IPPROTO_TCP,
                64,
                &tcp,
            );
            frame::build_ethernet(
                GATEWAY_MAC,
                dc_common::net::GUEST_MAC,
                frame::ETHERTYPE_IPV4,
                &ip,
            )
        };
        // The guest's SYN, to its gateway's address on the service's port.
        let syn = {
            let tcp = frame::build_tcp(
                GUEST_IP.into(),
                hostnet::HOST_ADDRESS,
                40001,
                port,
                1000,
                0,
                frame::TCP_SYN,
                65535,
                &[],
            );
            let ip = frame::build_ipv4(
                GUEST_IP.into(),
                hostnet::HOST_ADDRESS,
                frame::IPPROTO_TCP,
                64,
                &tcp,
            );
            frame::build_ethernet(
                GATEWAY_MAC,
                dc_common::net::GUEST_MAC,
                frame::ETHERTYPE_IPV4,
                &ip,
            )
        };
        guest.send(&syn).expect("the dial reaches the conduit");

        guest
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut buffer = vec![0u8; frame::MAX_FRAME];
        let mut from = None;
        let mut carried = Vec::new();
        for _ in 0..16 {
            let Ok(n) = guest.recv(&mut buffer) else {
                break;
            };
            let Some(ethernet) = frame::parse_ethernet(&buffer[..n]) else {
                continue;
            };
            let Some(ip) = frame::parse_ipv4(ethernet.payload) else {
                continue;
            };
            let Some(tcp) = frame::parse_tcp(ip.payload) else {
                continue;
            };
            from = Some(ip.src);
            carried.extend_from_slice(tcp.payload);
            if !tcp.payload.is_empty() {
                let _ = guest.send(&dial(&[], tcp.seq.wrapping_add(tcp.payload.len() as u32)));
                break;
            }
        }
        attachment.network.shutdown();
        let peer_the_host_saw = service.join().unwrap_or_default();

        assert_eq!(
            &carried[..],
            b"from the host",
            "the host service's bytes arrived as frames for the guest"
        );
        assert_eq!(
            from,
            Some(hostnet::HOST_ADDRESS),
            "and from the address the guest dialled, not from the host's loopback"
        );
        assert_eq!(
            peer_the_host_saw, "127.0.0.1",
            "the service saw a connection from the host's loopback, which is what a carried flow is"
        );
    }

    /// **The loop the operator hit is not there.**  With the switch on *and* a forward open, a guest
    /// that dials the forwarded port is refused **now**, by the gateway, instead of being carried to
    /// the host and handed back to the same listener.  That loop is what produced
    /// `kex_exchange_identification: read: Connection reset by peer`: the guest was completing a
    /// handshake with this process while this process was opening a second flow into the guest, and
    /// the two halves of one ssh conversation ended up on two different flows.
    #[test]
    fn a_guest_that_dials_the_forwarded_port_is_refused_rather_than_looped() {
        let attachment = attach_with_host_network("hostnet-ssh", vec![], true).expect("a conduit");
        attachment.network.start();
        let status = attachment.network.forward(0, SSH_GUEST_PORT);
        assert_eq!(status.state, ForwardState::Bound);
        let guest = &attachment.keepalive;

        // The guest dials `parenthost:<the host's own forwarded port>`.
        let syn = {
            let tcp = frame::build_tcp(
                GUEST_IP.into(),
                hostnet::HOST_ADDRESS,
                40002,
                status.host.port(),
                1000,
                0,
                frame::TCP_SYN,
                65535,
                &[],
            );
            let ip = frame::build_ipv4(
                GUEST_IP.into(),
                hostnet::HOST_ADDRESS,
                frame::IPPROTO_TCP,
                64,
                &tcp,
            );
            frame::build_ethernet(
                GATEWAY_MAC,
                dc_common::net::GUEST_MAC,
                frame::ETHERTYPE_IPV4,
                &ip,
            )
        };
        guest.send(&syn).expect("the dial reaches the conduit");

        guest
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut buffer = vec![0u8; frame::MAX_FRAME];
        let mut answer = None;
        for _ in 0..16 {
            let Ok(n) = guest.recv(&mut buffer) else {
                break;
            };
            let Some(ethernet) = frame::parse_ethernet(&buffer[..n]) else {
                continue;
            };
            let Some(ip) = frame::parse_ipv4(ethernet.payload) else {
                continue;
            };
            let Some(tcp) = frame::parse_tcp(ip.payload) else {
                continue;
            };
            answer = Some((ip.src, tcp.src_port, tcp.dst_port, tcp.flags));
            break;
        }
        attachment.network.shutdown();
        let (from, from_port, to_port, flags) = answer.expect("the machine answered the dial");
        assert_eq!(
            from,
            std::net::IpAddr::V4(hostnet::HOST_ADDRESS),
            "the refusal comes from the address the guest dialled"
        );
        assert_eq!(from_port, status.host.port());
        assert_eq!(to_port, 40002, "and to the guest's own flow");
        assert_eq!(
            flags & (frame::TCP_RST | frame::TCP_ACK),
            frame::TCP_RST | frame::TCP_ACK,
            "a refusal, not a handshake this process starts and then takes back ({flags:#04x})"
        );
    }
}
