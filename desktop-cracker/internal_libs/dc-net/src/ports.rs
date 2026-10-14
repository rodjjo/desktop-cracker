//! The host-side port mappings: the only sockets this process ever listens on
//! .
//!
//! A machine's network is a unix-socket conduit to the VMM — no TAP, no bridge, no host
//! interface — so nothing a guest runs is reachable from the network unless an operator writes a
//! `ports:` entry for it. This module is that entry and nothing more: it opens one host listener per
//! mapping, hands what arrives to the engine, and lets the engine carry it into the guest over the
//! conduit. Two rules from are the point of the module and are worth restating:
//!
//! - **Loopback unless the operator says otherwise.** A bare `2222` means `127.0.0.1:2222`; exposing
//!   a guest to the LAN is a deliberate `0.0.0.0:2222` or a literal address.
//! - **A taken port is a row, not a failed start.** One mapping that cannot bind is recorded as
//!   [`MappingState::Failed`] with the OS's own reason and the address it could not take; every
//!   other mapping still binds, so a collision can never stop a machine.
//!
//! Nothing here panics on operator input: [`PortMapping::parse`] returns a sentence for a host spec or
//! protocol it cannot read, and [`PortTable::bind`] turns every bind failure into a status row. A
//! binding thread never panics on its own either — a socket error ends that one mapping, not the
//! process.
//!
//! ## Shutdown
//!
//! `std`'s `TcpListener` has no `shutdown` and its `accept` cannot time out, so a serving thread
//! cannot be interrupted while it is blocked. Each thread therefore polls: the TCP listener is put in
//! nonblocking mode and the loop checks a shared flag between short [`POLL_INTERVAL`] sleeps; the UDP
//! socket keeps a matching read timeout and re-checks the flag on every timeout. [`PortTable::shutdown`]
//! sets the flag **and joins the threads**, so when it returns the listeners have been dropped and a
//! later connect to a mapped host port is refused. The UDP read timeout (rather than a nonblocking
//! socket) leaves the socket handed to the engine a blocking send, which is what answering from the
//! mapped port needs.

use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// How long a serving thread waits between checks of the shutdown flag.
///
/// Short enough that `shutdown` (which joins the threads) returns within a few milliseconds, long
/// enough that an idle mapping costs nothing worth measuring.
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// The largest UDP payload a mapping can carry: a datagram cannot be bigger than 65535 bytes in
/// total, and reading past that would truncate anyway.
const MAX_DATAGRAM: usize = 65_535;

/// The transport a mapping forwards.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Proto {
    /// A stream mapping: one host connection becomes one guest connection.
    Tcp,
    /// A datagram mapping: every host datagram is carried separately.
    Udp,
}

impl Proto {
    /// The protocol's name, as the operator writes it and the status prints it.
    pub fn as_str(self) -> &'static str {
        match self {
            Proto::Tcp => "tcp",
            Proto::Udp => "udp",
        }
    }

    /// Parse `tcp` or `udp`, case-insensitively. Anything else is a sentence, not a panic.
    pub fn parse(text: &str) -> Result<Proto, String> {
        match text.trim().to_ascii_lowercase().as_str() {
            "tcp" => Ok(Proto::Tcp),
            "udp" => Ok(Proto::Udp),
            other => Err(format!("'{other}' is not a protocol; use tcp or udp")),
        }
    }
}

/// One host-side listener for one guest port. `host` is the address the operator asked for
/// (loopback unless they wrote another), `guest_port` the port inside the guest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortMapping {
    /// The host address and port to listen on.
    pub host: SocketAddr,
    /// The port inside the guest that arriving traffic is carried to.
    pub guest_port: u16,
    /// The transport the mapping forwards.
    pub proto: Proto,
}

impl PortMapping {
    /// Parse `"[addr:]port"` the way the VM definition does: a bare port means `127.0.0.1`,
    /// and a port that is not a number is a sentence, not a panic.
    ///
    /// An IPv6 literal may be written bare (`::1:2222`) or bracketed (`[::1]:2222`). The protocol is
    /// read here too, so a mapping that would never serve anything is refused at parse time rather
    /// than as a bind failure later.
    pub fn parse(host: &str, guest_port: u16, proto: &str) -> Result<PortMapping, String> {
        let proto = Proto::parse(proto)?;
        let text = host.trim();
        if text.is_empty() {
            return Err(
                "a port mapping needs a host port, like 2222 or 127.0.0.1:2222".to_string(),
            );
        }
        let (address, port) = match text.rsplit_once(':') {
            Some((address, port)) => {
                let address = address
                    .strip_prefix('[')
                    .and_then(|a| a.strip_suffix(']'))
                    .unwrap_or(address);
                if address.is_empty() {
                    return Err(format!("'{text}' names a port but no host address"));
                }
                let address = address
                    .parse::<IpAddr>()
                    .map_err(|_| format!("'{address}' is not a host address"))?;
                let port = port
                    .parse::<u16>()
                    .map_err(|_| format!("'{text}' is not a port"))?;
                (address, port)
            }
            None => {
                // No address at all: the operator asked for loopback, the safe default.
                let port = text
                    .parse::<u16>()
                    .map_err(|_| format!("'{text}' is not a port"))?;
                (IpAddr::V4(Ipv4Addr::LOCALHOST), port)
            }
        };
        Ok(PortMapping {
            host: SocketAddr::new(address, port),
            guest_port,
            proto,
        })
    }

    /// Parse one mapping **as an operator writes it in a list**: `[addr:]port:guestport[/proto]` —
    /// `2222:22`, `0.0.0.0:8080:80`, `127.0.0.1:5353:53/udp`, `[::1]:2222:22`.
    ///
    /// The **last** colon is the guest's port and everything before it is the host side, so an address
    /// with colons of its own still reads as it was written; `/proto` is optional and `tcp` when it is
    /// absent. The host side is returned **as it was written** (a machine's definition stores what the
    /// operator asked for) after [`PortMapping::parse`] has validated it, so both spellings refuse the
    /// same mistakes with the same sentence.
    ///
    /// It is the grammar the dialog's Ports field takes and the one the API's `ports` list has always
    /// *claimed* to take (`ports must be ["2222:22"] or [{host, to, proto}]`) without accepting it.
    pub fn parse_spec(text: &str) -> Result<(String, u16, String), String> {
        let text = text.trim();
        if text.is_empty() {
            return Err(
                "a port mapping needs a host port and a guest port, like 2222:22".to_string(),
            );
        }
        let (head, proto) = match text.rsplit_once('/') {
            Some((head, proto)) => (head, proto.trim().to_ascii_lowercase()),
            None => (text, "tcp".to_string()),
        };
        // Refused here rather than at bind time: a mapping that could never serve anything is a
        // sentence about the list, not a row that failed once the machine was up.
        Proto::parse(&proto)?;
        let Some((host, guest)) = head.rsplit_once(':') else {
            return Err(format!(
                "'{text}' has no guest port; write it as host:guest, like 2222:22"
            ));
        };
        let guest_port = guest
            .trim()
            .parse::<u16>()
            .map_err(|_| format!("'{guest}' is not a guest port in '{text}'"))?;
        let host = host.trim();
        if host.is_empty() {
            return Err(format!("'{text}' names a guest port but no host port"));
        }
        // The host half goes through the object form's own parser: an address that is not an address
        // and a port that is not a port are refused by the same code, with the same words.
        PortMapping::parse(host, guest_port, &proto)?;
        Ok((host.to_string(), guest_port, proto))
    }
}

/// A connection that arrived from the host and must be carried into the guest.
pub struct InboundTcp {
    /// The accepted host-side stream; the engine owns it from here.
    pub stream: TcpStream,
    /// The guest port the mapping names.
    pub guest_port: u16,
    /// The host peer that connected.
    pub peer: SocketAddr,
}

/// A datagram that arrived from the host and must be carried into the guest (and the socket to
/// answer it with).
pub struct InboundUdp {
    /// The bound socket, so the engine can answer from the mapped host port.
    pub socket: Arc<UdpSocket>,
    /// The guest port the mapping names.
    pub guest_port: u16,
    /// The host peer that sent the datagram.
    pub from: SocketAddr,
    /// The datagram body.
    pub payload: Vec<u8>,
}

/// What the engine gives the table: how to carry an accepted connection into the guest.
pub type TcpHandler = Arc<dyn Fn(InboundTcp) + Send + Sync>;
/// What the engine gives the table: how to carry an accepted datagram into the guest.
pub type UdpHandler = Arc<dyn Fn(InboundUdp) + Send + Sync>;

/// What happened to one mapping, for the status.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum MappingState {
    /// The listener is open and being served.
    Bound,
    /// The listener could not be opened (or served); the string is the OS's own reason.
    Failed(String),
}

/// One row of a table's status: which mapping, and what became of it.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct MappingStatus {
    /// The host address the listener took (or the one it could not take).
    pub host: SocketAddr,
    /// The guest port inside the mapping.
    pub guest_port: u16,
    /// The transport the mapping forwards.
    pub proto: Proto,
    /// Whether it is serving, or why it is not.
    pub state: MappingState,
}

/// Every bound mapping, and the threads serving them.
pub struct PortTable {
    /// One row per mapping, in the order the mappings were given.
    statuses: Vec<MappingStatus>,
    /// Set by [`PortTable::shutdown`]; every serving thread checks it and returns when it is set.
    stopped: Arc<AtomicBool>,
    /// The serving threads, joined by [`PortTable::shutdown`].
    threads: Mutex<Vec<JoinHandle<()>>>,
}

impl PortTable {
    /// Bind every mapping and start serving it.
    ///
    /// A mapping whose host address/port cannot be bound is recorded as `Failed(<the reason>)` and
    /// **the rest still bind** — one taken port must not stop a machine.
    ///
    /// A `Bound` row's `host` is the address the listener actually took (read back from the OS), so
    /// a mapping that asked for port `0` reports the ephemeral port; a `Failed` row's `host` is the
    /// address that could not be taken.
    pub fn bind(mappings: Vec<PortMapping>, tcp: TcpHandler, udp: UdpHandler) -> PortTable {
        let stopped = Arc::new(AtomicBool::new(false));
        let mut statuses = Vec::with_capacity(mappings.len());
        let mut threads = Vec::new();

        for mapping in mappings {
            match mapping.proto {
                Proto::Tcp => match TcpListener::bind(mapping.host) {
                    Ok(listener) => {
                        // The address the OS actually gave us, which is how a port `0` mapping
                        // learns its port.
                        let local = listener.local_addr().unwrap_or(mapping.host);
                        let guest_port = mapping.guest_port;
                        let handler = Arc::clone(&tcp);
                        let stop = Arc::clone(&stopped);
                        let spawned = thread::Builder::new()
                            .name(format!("vm-port-tcp-{local}"))
                            .spawn(move || serve_tcp(listener, guest_port, handler, stop));
                        match spawned {
                            Ok(handle) => {
                                threads.push(handle);
                                statuses.push(row(&mapping, local, MappingState::Bound));
                            }
                            Err(error) => statuses.push(row(
                                &mapping,
                                mapping.host,
                                MappingState::Failed(format!(
                                    "cannot serve {}: {error}",
                                    mapping.host
                                )),
                            )),
                        }
                    }
                    Err(error) => statuses.push(row(
                        &mapping,
                        mapping.host,
                        MappingState::Failed(format!("cannot bind {}: {error}", mapping.host)),
                    )),
                },
                Proto::Udp => match UdpSocket::bind(mapping.host) {
                    Ok(socket) => {
                        let local = socket.local_addr().unwrap_or(mapping.host);
                        let guest_port = mapping.guest_port;
                        let handler = Arc::clone(&udp);
                        let stop = Arc::clone(&stopped);
                        let spawned = thread::Builder::new()
                            .name(format!("vm-port-udp-{local}"))
                            .spawn(move || serve_udp(Arc::new(socket), guest_port, handler, stop));
                        match spawned {
                            Ok(handle) => {
                                threads.push(handle);
                                statuses.push(row(&mapping, local, MappingState::Bound));
                            }
                            Err(error) => statuses.push(row(
                                &mapping,
                                mapping.host,
                                MappingState::Failed(format!(
                                    "cannot serve {}: {error}",
                                    mapping.host
                                )),
                            )),
                        }
                    }
                    Err(error) => statuses.push(row(
                        &mapping,
                        mapping.host,
                        MappingState::Failed(format!("cannot bind {}: {error}", mapping.host)),
                    )),
                },
            }
        }

        PortTable {
            statuses,
            stopped,
            threads: Mutex::new(threads),
        }
    }

    /// One row per mapping, in the order they were given.
    pub fn statuses(&self) -> Vec<MappingStatus> {
        self.statuses.clone()
    }

    /// Whether the table holds no mappings at all (not whether any of them bound).
    pub fn is_empty(&self) -> bool {
        self.statuses.is_empty()
    }

    /// Stop listening: the accept/read threads end and their listeners are closed, so a later connect
    /// to a host port is refused.
    ///
    /// The threads are joined before this returns, so the refusal is immediate rather than eventual.
    pub fn shutdown(&self) {
        self.stopped.store(true, Ordering::Relaxed);
        // A poisoned lock only means some thread panicked while holding it; the handles are still
        // ours to join, so recover rather than panic here.
        let mut threads = self
            .threads
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for handle in threads.drain(..) {
            let _ = handle.join();
        }
    }
}

impl Drop for PortTable {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// Build the status row for `mapping`, reported at `host`.
fn row(mapping: &PortMapping, host: SocketAddr, state: MappingState) -> MappingStatus {
    MappingStatus {
        host,
        guest_port: mapping.guest_port,
        proto: mapping.proto,
        state,
    }
}

/// Serve one TCP mapping until `stop` is set.
///
/// The listener is nonblocking because `std`'s `TcpListener` cannot be interrupted while blocked in
/// `accept`; the loop polls the flag between short sleeps. The accepted stream is put back into
/// blocking mode before the engine sees it, since nonblocking is our implementation detail, not part
/// of the hand-off.
fn serve_tcp(listener: TcpListener, guest_port: u16, handler: TcpHandler, stop: Arc<AtomicBool>) {
    if listener.set_nonblocking(true).is_err() {
        // Without nonblocking accept this thread could never notice `stop`; give the mapping up
        // rather than wedge a thread (and `shutdown`'s join) forever.
        return;
    }
    loop {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        match listener.accept() {
            Ok((stream, peer)) => {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                let _ = stream.set_nonblocking(false);
                handler(InboundTcp {
                    stream,
                    guest_port,
                    peer,
                });
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => thread::sleep(POLL_INTERVAL),
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            // The listener is broken (not merely empty); end this one mapping.
            Err(_) => return,
        }
    }
}

/// Serve one UDP mapping until `stop` is set.
///
/// A read timeout, rather than a nonblocking socket, is what lets the loop notice `stop`: the socket
/// is handed to the engine to answer on, and that send should stay blocking.
fn serve_udp(socket: Arc<UdpSocket>, guest_port: u16, handler: UdpHandler, stop: Arc<AtomicBool>) {
    if socket.set_read_timeout(Some(POLL_INTERVAL)).is_err() {
        return;
    }
    let mut buffer = vec![0u8; MAX_DATAGRAM];
    loop {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        match socket.recv_from(&mut buffer) {
            Ok((len, from)) => {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                let payload = buffer[..len].to_vec();
                handler(InboundUdp {
                    socket: Arc::clone(&socket),
                    guest_port,
                    from,
                    payload,
                });
            }
            // A timeout is the poll tick, not an error.
            Err(error) if matches!(error.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                continue
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;
    use std::time::Instant;

    /// A handler that does nothing, for mappings whose traffic is not the subject of the test.
    fn ignore_tcp() -> TcpHandler {
        Arc::new(|_| {})
    }

    /// A handler that does nothing, for mappings whose traffic is not the subject of the test.
    fn ignore_udp() -> UdpHandler {
        Arc::new(|_| {})
    }

    #[test]
    fn a_host_spec_parses_loopback_for_a_bare_port_and_refuses_nonsense() {
        let bare = PortMapping::parse("2222", 22, "tcp").expect("a bare port");
        assert_eq!(
            bare.host,
            SocketAddr::from(([127, 0, 0, 1], 2222)),
            "a bare port is loopback"
        );
        assert_eq!(bare.guest_port, 22);
        assert_eq!(bare.proto, Proto::Tcp);
        assert_eq!(bare.proto.as_str(), "tcp");

        let explicit = PortMapping::parse("0.0.0.0:8080", 80, "udp").expect("an explicit address");
        assert_eq!(explicit.host, SocketAddr::from(([0, 0, 0, 0], 8080)));
        assert_eq!(explicit.guest_port, 80);
        assert_eq!(explicit.proto, Proto::Udp);

        // A protocol is read case-insensitively, and a bracketed IPv6 literal is understood.
        assert_eq!(Proto::parse("TCP"), Ok(Proto::Tcp));
        assert_eq!(
            PortMapping::parse("[::1]:2222", 22, "tcp")
                .expect("an IPv6 literal")
                .host,
            SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 1], 2222))
        );

        // Everything unreadable is a sentence, not a panic.
        assert!(
            PortMapping::parse("nonsense", 22, "tcp").is_err(),
            "not a port"
        );
        assert!(
            PortMapping::parse("127.0.0.1:notaport", 22, "tcp").is_err(),
            "not a numeric port"
        );
        assert!(
            PortMapping::parse("2222", 22, "sctp").is_err(),
            "not a protocol"
        );
        assert!(
            PortMapping::parse("", 22, "tcp").is_err(),
            "no host spec at all"
        );
        assert!(
            PortMapping::parse(":2222", 22, "tcp").is_err(),
            "a port with no address"
        );
    }

    #[test]
    fn the_list_spelling_reads_a_host_side_and_a_guest_port() {
        // What the dialog's Ports field and the API's `ports: ["2222:22"]` take: the last colon is the
        // guest's port, so `0.0.0.0:8080:80` means the host's 8080 too, and `/udp` is the transport.
        assert_eq!(
            PortMapping::parse_spec("2222:22").expect("a bare port"),
            ("2222".to_string(), 22, "tcp".to_string())
        );
        assert_eq!(
            PortMapping::parse_spec("0.0.0.0:8080:80").expect("an address"),
            ("0.0.0.0:8080".to_string(), 80, "tcp".to_string())
        );
        assert_eq!(
            PortMapping::parse_spec(" 127.0.0.1:5353:53/UDP ").expect("a transport"),
            ("127.0.0.1:5353".to_string(), 53, "udp".to_string()),
            "the transport is read case-insensitively"
        );
        assert_eq!(
            PortMapping::parse_spec("[::1]:2222:22").expect("an IPv6 literal"),
            ("[::1]:2222".to_string(), 22, "tcp".to_string())
        );
        // The host half is validated by the object form's parser, so a bare port still means loopback
        // and an address with colons is not mistaken for a host port.
        assert_eq!(
            PortMapping::parse_spec("2222:22").map(|(host, to, proto)| PortMapping::parse(
                &host, to, &proto
            )
            .expect("valid")
            .host),
            Ok(SocketAddr::from(([127, 0, 0, 1], 2222)))
        );

        // Every way it can be wrong is a sentence naming the piece that is wrong, never a panic.
        for (spec, fragment) in [
            ("", "needs a host port and a guest port"),
            ("22", "has no guest port"),
            ("2222:not-a-port", "is not a guest port"),
            (":22", "names a guest port but no host port"),
            ("2222:22/sctp", "is not a protocol"),
            ("not-an-address:8080:80", "is not a host address"),
        ] {
            let reason = PortMapping::parse_spec(spec).expect_err(spec);
            assert!(reason.contains(fragment), "{spec}: {reason}");
        }
    }

    #[test]
    fn a_bound_tcp_mapping_accepts_and_reports_the_guest_port_and_peer() {
        let (tx, rx) = mpsc::channel();
        let tcp: TcpHandler = Arc::new(move |inbound: InboundTcp| {
            let _ = tx.send((inbound.guest_port, inbound.peer));
            // The stream is dropped here, which is a fine answer for this test.
        });
        // Port 0 lets the OS choose, so the test needs no probe port and cannot race for one.
        let mapping = PortMapping::parse("127.0.0.1:0", 2222, "tcp").expect("a mapping");
        let table = PortTable::bind(vec![mapping], tcp, ignore_udp());

        let statuses = table.statuses();
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].state, MappingState::Bound);
        assert_ne!(
            statuses[0].host.port(),
            0,
            "a bound row reports the port the OS gave us"
        );
        let host = statuses[0].host;

        let client = TcpStream::connect(host).expect("the mapping is listening");
        let client_addr = client.local_addr().expect("the client's own address");
        let (guest_port, peer) = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("the handler was called");
        assert_eq!(guest_port, 2222, "the guest port comes from the mapping");
        assert_eq!(peer, client_addr, "the peer is the client that connected");

        table.shutdown();
    }

    #[test]
    fn a_taken_port_is_one_failed_row_and_the_other_mapping_still_binds() {
        // Keep a listener alive on an OS-chosen address; the mapping that asks for it must fail.
        let taken = TcpListener::bind(("127.0.0.1", 0)).expect("a probe listener");
        let taken_addr = taken.local_addr().expect("the probe address");

        let mappings = vec![
            PortMapping {
                host: taken_addr,
                guest_port: 22,
                proto: Proto::Tcp,
            },
            PortMapping::parse("127.0.0.1:0", 80, "tcp").expect("a free mapping"),
        ];
        let table = PortTable::bind(mappings, ignore_tcp(), ignore_udp());

        let statuses = table.statuses();
        assert_eq!(statuses.len(), 2);
        assert_eq!(statuses[0].host, taken_addr);
        match &statuses[0].state {
            MappingState::Failed(reason) => {
                assert!(
                    reason.contains(&taken_addr.to_string()),
                    "the reason names the address it could not take: {reason}"
                );
            }
            other => panic!("expected a failure for the taken port, got {other:?}"),
        }
        assert_eq!(
            statuses[1].state,
            MappingState::Bound,
            "the other mapping binds anyway"
        );
        assert_eq!(statuses[1].guest_port, 80);

        table.shutdown();
    }

    #[test]
    fn a_duplicate_host_address_binds_once_and_fails_once() {
        // An explicit port, chosen by the OS and then released, so both mappings name the same one.
        let probe = TcpListener::bind(("127.0.0.1", 0)).expect("a probe listener");
        let addr = probe.local_addr().expect("the probe address");
        drop(probe);

        let mappings = vec![
            PortMapping {
                host: addr,
                guest_port: 22,
                proto: Proto::Tcp,
            },
            PortMapping {
                host: addr,
                guest_port: 80,
                proto: Proto::Tcp,
            },
        ];
        let table = PortTable::bind(mappings, ignore_tcp(), ignore_udp());

        let statuses = table.statuses();
        let bound = statuses
            .iter()
            .filter(|s| s.state == MappingState::Bound)
            .count();
        let failed = statuses
            .iter()
            .filter(|s| matches!(s.state, MappingState::Failed(_)))
            .count();
        assert_eq!(
            bound, 1,
            "the OS refuses the second bind, so exactly one mapping is bound: {statuses:?}"
        );
        assert_eq!(
            failed, 1,
            "and exactly one is the failure row: {statuses:?}"
        );
        assert_eq!(
            statuses[0].state,
            MappingState::Bound,
            "the first one asked, the first one wins"
        );
        assert_eq!(statuses[0].host, addr);

        table.shutdown();
    }

    #[test]
    fn a_bound_udp_mapping_receives_a_datagram_and_can_answer_on_its_own_socket() {
        let (tx, rx) = mpsc::channel();
        let udp: UdpHandler = Arc::new(move |inbound: InboundUdp| {
            // The engine's answer path: reply to the sender from the mapped host port.
            let _ = inbound.socket.send_to(b"pong", inbound.from);
            let _ = tx.send((inbound.guest_port, inbound.from, inbound.payload));
        });
        let mapping = PortMapping::parse("127.0.0.1:0", 53, "udp").expect("a mapping");
        let table = PortTable::bind(vec![mapping], ignore_tcp(), udp);

        let statuses = table.statuses();
        assert_eq!(statuses[0].state, MappingState::Bound);
        let host = statuses[0].host;

        let client = UdpSocket::bind(("127.0.0.1", 0)).expect("a client socket");
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("a read timeout");
        client
            .send_to(b"ping", host)
            .expect("send to the mapped port");

        let (guest_port, from, payload) = rx
            .recv_timeout(Duration::from_secs(2))
            .expect("the handler was called");
        assert_eq!(guest_port, 53, "the guest port comes from the mapping");
        assert_eq!(from, client.local_addr().expect("the client's own address"));
        assert_eq!(payload, b"ping");

        let mut reply = [0u8; 16];
        let (len, reply_from) = client
            .recv_from(&mut reply)
            .expect("the mapped socket answers");
        assert_eq!(&reply[..len], b"pong");
        assert_eq!(
            reply_from, host,
            "the answer comes from the mapped host port"
        );

        table.shutdown();
    }

    #[test]
    fn statuses_keep_the_input_order_and_is_empty_follows_the_mappings() {
        let empty = PortTable::bind(vec![], ignore_tcp(), ignore_udp());
        assert!(empty.is_empty(), "no mappings, no rows");
        assert!(empty.statuses().is_empty());
        empty.shutdown();

        // Port 0 everywhere: three mappings, three distinct OS-chosen ports, all bound.
        let mappings = vec![
            PortMapping::parse("127.0.0.1:0", 22, "tcp").expect("a mapping"),
            PortMapping::parse("127.0.0.1:0", 53, "udp").expect("a mapping"),
            PortMapping::parse("127.0.0.1:0", 80, "tcp").expect("a mapping"),
        ];
        let table = PortTable::bind(mappings, ignore_tcp(), ignore_udp());
        assert!(!table.is_empty());

        let statuses = table.statuses();
        assert_eq!(
            statuses.iter().map(|s| s.guest_port).collect::<Vec<_>>(),
            vec![22, 53, 80]
        );
        assert_eq!(
            statuses.iter().map(|s| s.proto).collect::<Vec<_>>(),
            vec![Proto::Tcp, Proto::Udp, Proto::Tcp]
        );
        assert!(statuses.iter().all(|s| s.state == MappingState::Bound));

        table.shutdown();
    }

    #[test]
    fn shutdown_stops_the_listener_and_a_later_connect_is_refused() {
        let table = PortTable::bind(
            vec![PortMapping::parse("127.0.0.1:0", 22, "tcp").expect("a mapping")],
            ignore_tcp(),
            ignore_udp(),
        );
        let host = table.statuses()[0].host;

        // It is listening to begin with.
        TcpStream::connect(host).expect("connect while the mapping is bound");

        table.shutdown();

        // The listener is gone; allow a short window in case a thread was mid-poll when it was asked
        // to stop. A few hundred milliseconds is plenty for a 10 ms poll, and this never sleeps long.
        let deadline = Instant::now() + Duration::from_millis(500);
        loop {
            match TcpStream::connect(host) {
                Err(_) => break,
                Ok(_) if Instant::now() < deadline => thread::sleep(Duration::from_millis(10)),
                Ok(_) => panic!("the listener still accepts after shutdown"),
            }
        }
    }
}
