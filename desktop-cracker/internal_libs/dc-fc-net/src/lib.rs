//! **The network, as a vsock service**.
//!
//! The project gives the guest a `virtio-net` device whose host end is one end of a
//! `socketpair`; Firecracker's own network device is a **tap**, and a tap is a host device
//! created with `CAP_NET_ADMIN` — which this project has never required and does not
//! require now.  So the run attaches **no network device at all**: the guest's agent
//! creates its own **TUN** (no privilege inside the guest), and the frames travel on the
//! network channel (port 59000).
//!
//! What crosses that channel is the one thing the two ends disagree about.  A TUN device
//! is **L3**: the guest's kernel hands out and takes in plain IP packets, and an interface
//! of its own has no MAC and no ARP.  The `dc-net` engine this crate drives is **L2**: it
//! is written for a virtual NIC, so its entry point parses an Ethernet header and
//! everything it emits carries one.  This crate is exactly the two adapters between the
//! two:
//!
//! ```text
//! guest tun0 ──[ IP packet ]──▶ vsock 59000 ──▶ +14 bytes (dst/​src/ethertype) ──▶ Relay::handle
//! guest tun0 ◀──[ IP packet ]── vsock 59000 ◀── −14 bytes ──────────────────────── Relay::emit
//! ```
//!
//! The header the engine sees is the **project's own** (`dc_common::net::GUEST_MAC` as the guest's
//! hardware address, `GATEWAY_MAC` as ours, and the ethertype of the packet inside), so
//! the engine's ARP answers, its DHCP leases and its relay all go on working without a
//! line changed: they are answering about a MAC that is now the *agent's* commitment —
//! which is exactly what the BOOTP payload of a DHCP request carries, and what the agent
//! therefore puts in its request.
//!
//! Two consequences worth being exact about:
//!
//! * **the guest has no subnet to ARP on.**  On a point-to-point link the kernel sends the
//!   packet to the interface and never asks who the peer is, so the agent needs no
//!   neighbour entry for the gateway: it addresses the link (`10.0.177.16` on this side,
//!   `10.0.177.1` on ours) and installs the default route through it.  The engine's ARP
//!   answers still exist and still work — a guest that *does* ARP (a tap-shaped wire) is
//!   answered as before;
//! * **IPv6 neighbour discovery has no meaning here.**  `ndp`/`dhcp6` are L2 protocols;
//!   what survives is the engine's IPv6 addressing and its relay for IPv6 flows.  The
//!   guest's agent configures IPv6 statically when it wants it.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use dc_common::net::GUEST_MAC;
use dc_vsock::{Frame, Reader, Service};

/// The channel the guest's TUN writes to and reads from.
///
/// One kind, both directions: the payload **is** the packet (an IPv4 or IPv6 datagram, no
/// Ethernet header).  A frame and a packet are one to one, which is what keeps the copy
/// count honest — the guest's kernel writes one packet, the agent sends one frame, the
/// engine answers with one frame, the agent writes one packet.
pub const KIND_PACKET: u16 = 1;

/// The largest IP packet the channel carries: the engine's own MTU, so a guest that
/// believes its MTU never builds a frame this cannot carry.
pub const MAX_PACKET: usize = 65_535;

/// Ethernet's own header, which the engine wants and a TUN link does not have.
pub const ETHERNET_HEADER: usize = 14;

/// What the service did, for the milestone line and for the tests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counters {
    /// Packets the guest sent.
    pub in_packets: u64,
    /// Packets we sent to the guest.
    pub out_packets: u64,
    /// Frames that were not a packet we could carry (a truncated frame, a kind we do not
    /// know).
    pub dropped: u64,
    /// Bytes on the channel, both directions: what a person wants when asking whether the
    /// guest is actually using the network.
    pub bytes: u64,
}

/// The guest's network, as this process sees it: the vsock channel, the engine behind it,
/// and the counters.
pub struct Network {
    service: Mutex<Option<Service>>,
    counters: Arc<Counters_>,
    stop: Arc<std::sync::atomic::AtomicBool>,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

/// The counters, in the form the running threads share.
struct Counters_ {
    in_packets: AtomicU64,
    out_packets: AtomicU64,
    dropped: AtomicU64,
    bytes: AtomicU64,
}

impl Counters_ {
    fn snapshot(&self) -> Counters {
        Counters {
            in_packets: self.in_packets.load(Ordering::Relaxed),
            out_packets: self.out_packets.load(Ordering::Relaxed),
            dropped: self.dropped.load(Ordering::Relaxed),
            bytes: self.bytes.load(Ordering::Relaxed),
        }
    }
}

impl Network {
    /// Listen on `port` at `<uds_path>_<port>` **now**, and answer the guest when it
    /// dials.
    ///
    /// The listener is the whole reason this is a separate call from [`Network::serve`]:
    /// this project's ordering rule is that the host listens before the machine starts
    /// (a guest that dials a port nobody listens on gets a
    /// reset, and the failure looks like a guest that never came up).
    pub fn listen(uds_path: &std::path::Path, port: u32) -> Result<Network, dc_vsock::VsockError> {
        Ok(Network {
            service: Mutex::new(Some(Service::bind(uds_path, port)?)),
            counters: Arc::new(Counters_ {
                in_packets: AtomicU64::new(0),
                out_packets: AtomicU64::new(0),
                dropped: AtomicU64::new(0),
                bytes: AtomicU64::new(0),
            }),
            stop: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            thread: Mutex::new(None),
        })
    }

    pub fn port(&self) -> u32 {
        self.service
            .lock()
            .expect("the network's listener")
            .as_ref()
            .map(Service::port)
            .unwrap_or(0)
    }

    /// The counters as they are right now.
    pub fn counters(&self) -> Counters {
        self.counters.snapshot()
    }

    /// The socket the guest's agent dials.  The channel exists from [`Network::listen`],
    /// which is called **before** the machine starts.
    pub fn service_path(&self) -> std::path::PathBuf {
        self.service
            .lock()
            .expect("the network's listener")
            .as_ref()
            .map(|service| service.path().to_path_buf())
            .unwrap_or_default()
    }

    /// Stop listening and take the socket away: a run's own paths are the run's to clean.
    pub fn close(&self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(service) = self.service.lock().expect("the network's listener").take() {
            service.close();
        }
    }

    /// Accept the guest's channel and run the network on it until the run ends.
    ///
    /// One connection and **one thread per direction**, which is what keeps the two
    /// halves from waiting on each other:
    ///
    /// * the reading thread takes the guest's packets off the channel and gives them to
    ///   `dc-net`'s engine (its DHCP, its relay, its NAT, its DNS, NTP and ICMP) — the
    ///   engine's own entry point, unchanged;
    /// * the writing thread takes what the engine emits through the conduit and puts it
    ///   on the channel — one frame per packet, the Ethernet header of the engine's own
    ///   wire taken back off.
    ///
    /// The engine writes its answers into a `SOCK_DGRAM` conduit (the project's own, the
    /// same one the guest's own link is given), whose other end this thread reads: that
    /// is what makes "the engine is untouched" true rather than hoped for.
    pub fn serve(
        self: &Arc<Self>,
        machine: Arc<dc_net::MachineNetwork>,
        guest: dc_net::GuestConduit,
    ) -> Result<(), dc_vsock::VsockError> {
        let (stream, port) = {
            let listener = self.service.lock().expect("the network's listener");
            let service = listener.as_ref().ok_or_else(|| {
                dc_vsock::VsockError::Handshake(
                    "the network's channel was closed before the guest dialled it".into(),
                )
            })?;
            (service.accept()?, service.port())
        };
        let reader_side = stream
            .try_clone()
            .map_err(|source| dc_vsock::VsockError::Io { port, source })?;
        let writer_side = stream;
        // The conduit's **guest end**: what the guest's NIC would write goes in here, and
        // what the engine emits comes out.  `dc-net`'s own `MachineNetwork` reads the
        // other end and answers on it — DHCP included, which is why the guest's frames
        // are written here rather than handed to the relay directly.
        let guest_side = std::sync::Arc::new(guest);
        let _ = &machine;

        let out_counters = self.counters.clone();
        let out_stop = self.stop.clone();
        let mut writer_side = writer_side;
        let guest_for_out = guest_side.clone();
        let writer = std::thread::spawn(move || {
            let mut buffer = vec![0u8; MAX_PACKET + ETHERNET_HEADER];
            while !out_stop.load(Ordering::Relaxed) {
                let n = match guest_for_out.recv(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(_) => break,
                };
                let Some(packet) = strip_ethernet(&buffer[..n]) else {
                    out_counters.dropped.fetch_add(1, Ordering::Relaxed);
                    continue;
                };
                if dc_vsock::write_frame(
                    &mut writer_side,
                    &Frame::new(KIND_PACKET, packet.to_vec()),
                    port,
                )
                .is_err()
                {
                    break;
                }
                out_counters.out_packets.fetch_add(1, Ordering::Relaxed);
                out_counters
                    .bytes
                    .fetch_add(packet.len() as u64 + 6, Ordering::Relaxed);
            }
            let _ = writer_side.shutdown(std::net::Shutdown::Both);
        });

        // The guest's packets, in to the engine — written on the conduit's guest end, so
        // `dc-net`'s own reader thread sees them exactly as it sees the machine's frames.
        //
        // The conduit's guest end is `&self`-shared like the engine's is, so both threads
        // can hold it: one reads the engine's answers, the other writes the guest's
        // frames, and neither waits for the other.
        let in_counters = self.counters.clone();
        let stop = self.stop.clone();
        let mut reader_side = reader_side;
        let mut reader = Reader::new();
        while !stop.load(Ordering::Relaxed) {
            match reader.read_frame(&mut reader_side, port) {
                Ok(Some(frame)) => {
                    if frame.kind != KIND_PACKET {
                        in_counters.dropped.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    let Some(ethernet) = add_ethernet(&frame.payload) else {
                        in_counters.dropped.fetch_add(1, Ordering::Relaxed);
                        continue;
                    };
                    if guest_side.send(&ethernet).is_err() {
                        break;
                    }
                    in_counters.in_packets.fetch_add(1, Ordering::Relaxed);
                    in_counters
                        .bytes
                        .fetch_add(frame.payload.len() as u64 + 6, Ordering::Relaxed);
                }
                Ok(None) => break,
                Err(_) => break,
            }
        }
        stop.store(true, Ordering::Relaxed);
        let _ = reader_side.shutdown(std::net::Shutdown::Both);
        let _ = writer.join();
        Ok(())
    }

    /// Start [`Network::serve`] on a thread of its own, so a run can bring the network up
    /// without waiting for the guest to dial it.
    pub fn serve_in_background(
        self: &Arc<Self>,
        machine: Arc<dc_net::MachineNetwork>,
        answers: dc_net::GuestConduit,
    ) -> Result<(), dc_vsock::VsockError> {
        let this = self.clone();
        let handle = std::thread::spawn(move || {
            let _ = this.serve(machine, answers);
        });
        *self.thread.lock().expect("the network's thread") = Some(handle);
        Ok(())
    }

    /// Stop serving: the guest's channel closes and the thread ends.
    pub fn shutdown(&self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.thread.lock().expect("the network's thread").take() {
            let _ = handle.join();
        }
    }
}

/// The Ethernet header the engine wants, in front of a packet that has none.
///
/// The addresses are the project's own MACs (`dc_common::net::GUEST_MAC` is the guest's, the
/// gateway's is the engine's own end) and the ethertype is read from the packet's own
/// version nibble — which is the only thing that says whether what follows is IPv4 or
/// IPv6, and therefore the only honest answer.
pub fn add_ethernet(packet: &[u8]) -> Option<Vec<u8>> {
    let ethertype = match packet.first()? >> 4 {
        4 => dc_net::frame::ETHERTYPE_IPV4,
        6 => dc_net::frame::ETHERTYPE_IPV6,
        _ => return None,
    };
    Some(dc_net::frame::build_ethernet(
        dc_net::GATEWAY_MAC,
        dc_common::net::GUEST_MAC,
        ethertype,
        packet,
    ))
}

/// The packet inside an Ethernet frame the engine built — the 14 bytes a TUN link does
/// not carry.
pub fn strip_ethernet(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() <= ETHERNET_HEADER {
        return None;
    }
    Some(&frame[ETHERNET_HEADER..])
}

/// The MAC the guest's agent must put in the BOOTP payload of its DHCP request: **the
/// same address the engine knows the guest by**, which is what keys its lease and what
/// every frame it builds is addressed to.
pub fn guest_hardware_address() -> [u8; 6] {
    GUEST_MAC
}

/// **The gateway answers a ping of itself, on a point-to-point link.**
///
/// A TUN link has no ARP and no other host on it, so a plain `ping 10.0.177.1` — the
/// health check the project's own runbooks use — has to be answered by the peer, and the
/// peer's relay only answers an echo to `GATEWAY_IP` when the packet arrives with the
/// gateway's address *inside* the packet.  The agent and the engine therefore have to
/// agree on that translation, and `sample` is how they do it without one of them
/// guessing:
///
/// * **the agent**, when it pings the gateway by its DHCP name (`sample = 1`), puts
///   [`dc_net::GATEWAY_IP`] in the packet's source field as well as its destination (a
///   `connect`ed ICMP socket does exactly that for the kernel, which is why this is
///   written down rather than invented);
/// * **the engine**, in a packet whose source is the guest's own address (`sample = 0`),
///   reads it as the guest's own ping of `GATEWAY_IP`.
///
/// It is a sample and not a mode: the packet itself says which it is, on every packet,
/// and a wrong guess is a dropped packet rather than a machine that boots wrongly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sample {
    /// The guest's own address is in the packet's source field.
    Guest,
    /// The gateway's address is in the source field, because the kernel of a `connect`ed
    /// ICMP socket puts the destination there.
    Gateway,
}

impl Sample {
    pub fn as_str(self) -> &'static str {
        match self {
            Sample::Guest => "guest",
            Sample::Gateway => "gateway",
        }
    }

    pub fn parse(text: &str) -> Option<Sample> {
        match text.trim() {
            "guest" => Some(Sample::Guest),
            "gateway" => Some(Sample::Gateway),
            _ => None,
        }
    }
}

/// The request a guest sends to **ask what time it is**: `[u32 seconds][u16 millis]`, in
/// the same frame as every other message on the channel.
pub fn ntp_request() -> Vec<u8> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let mut body = Vec::with_capacity(6);
    body.extend_from_slice(&(now.as_secs() as u32).to_be_bytes());
    body.extend_from_slice(&((now.subsec_millis() as u16).min(999)).to_be_bytes());
    body
}

/// The answer: the same two numbers, as the **host**'s clock reads them.  The engine's
/// own NTP server (`dc-net`'s) continues to answer a guest that speaks NTP properly over
/// UDP; this is for the agent, which needs the clock before it has an IP stack at all.
pub fn ntp_reply() -> Vec<u8> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let stamp = chrono_like(now.as_secs());
    format!(
        "{stamp} {}
",
        now.subsec_millis().min(999)
    )
    .into_bytes()
}

/// A date and a time without a date library: the engine only ever needs the numbers the
/// guest's `date` shows, and the leap-year arithmetic is three lines.
fn chrono_like(seconds: u64) -> String {
    let days = (seconds / 86_400) as i64;
    let rem = seconds % 86_400;
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm, which is what
    // every date library uses).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mth = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if mth <= 2 { y + 1 } else { y };
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", year, mth, d, h, m, s)
}

/// The addresses the agent configures on its TUN, in one place: the subnet, the guest's
/// address in it, the gateway's, and the prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Link {
    pub guest_ip: Ipv4Addr,
    pub gateway_ip: Ipv4Addr,
    pub prefix: u8,
    /// The gateway's link-local IPv6 address, which is what the engine answers at when
    /// IPv6 is wanted (NDP has no meaning on this link, so the
    /// addresses are configured, not discovered).
    pub gateway_ip6: Ipv6Addr,
    pub mtu: u16,
}

impl Default for Link {
    fn default() -> Self {
        Link {
            guest_ip: dc_net::GUEST_IP.into(),
            gateway_ip: dc_net::GATEWAY_IP.into(),
            prefix: dc_net::SUBNET_PREFIX,
            gateway_ip6: dc_net::frame::link_local_of(dc_net::GATEWAY_MAC),
            mtu: 1500,
        }
    }
}

impl Link {
    /// The `ip` command the agent runs, as one line: it is the guest's own tool doing the
    /// guest's own configuration, and a person can read the line in the guest's console.
    pub fn agent_command(&self, interface: &str) -> String {
        format!(
            "ip addr add {}/{} dev {iface} && ip link set {iface} mtu {} up &&              ip route add default via {} dev {iface}",
            self.guest_ip, self.prefix, self.mtu, self.gateway_ip, iface = interface
        )
    }

    /// The addresses the agent must **not** use as the packet's source when it pings the
    /// gateway, so the engine can answer (see [`Sample`]).
    pub fn gateway_ping_source(&self) -> Ipv4Addr {
        self.gateway_ip
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One IPv4 packet, enough of one to be parsed: version, IHL, and a payload.
    fn ipv4_packet() -> Vec<u8> {
        let mut packet = vec![0u8; 20];
        packet[0] = 0x45;
        packet[2] = 0x00;
        packet[3] = 0x14;
        packet[9] = 17; // UDP
        packet
    }

    #[test]
    fn a_packet_gets_the_header_the_engine_wants() {
        let packet = ipv4_packet();
        let ethernet = add_ethernet(&packet).unwrap();
        assert_eq!(ethernet.len(), packet.len() + ETHERNET_HEADER);
        assert_eq!(
            &ethernet[..6],
            &dc_net::GATEWAY_MAC,
            "to the gateway's own address"
        );
        assert_eq!(
            &ethernet[6..12],
            &dc_common::net::GUEST_MAC,
            "from the guest"
        );
        assert_eq!(
            &ethernet[12..14],
            &dc_net::frame::ETHERTYPE_IPV4.to_be_bytes()
        );
        assert_eq!(&ethernet[ETHERNET_HEADER..], &packet[..]);
    }

    #[test]
    fn an_ipv6_packet_is_labelled_as_one() {
        let mut packet = vec![0u8; 40];
        packet[0] = 0x60;
        let ethernet = add_ethernet(&packet).unwrap();
        assert_eq!(
            &ethernet[12..14],
            &dc_net::frame::ETHERTYPE_IPV6.to_be_bytes()
        );
    }

    #[test]
    fn something_that_is_not_an_ip_packet_is_refused_rather_than_guessed_at() {
        assert!(add_ethernet(&[]).is_none());
        assert!(add_ethernet(&[0x00]).is_none(), "version 0 is not a packet");
        assert!(
            add_ethernet(&[0x10, 0, 0, 0]).is_none(),
            "version 1 is not either"
        );
    }

    #[test]
    fn what_the_engine_says_comes_back_as_the_packet_it_was_about() {
        let packet = ipv4_packet();
        let ethernet = add_ethernet(&packet).unwrap();
        assert_eq!(strip_ethernet(&ethernet).unwrap(), &packet[..]);
        assert!(
            strip_ethernet(&ethernet[..ETHERNET_HEADER]).is_none(),
            "a header alone is nothing"
        );
        assert!(strip_ethernet(&[]).is_none());
    }

    #[test]
    fn the_two_adapters_are_each_others_inverse() {
        for packet in [ipv4_packet(), vec![0x60; 48]] {
            assert_eq!(
                strip_ethernet(&add_ethernet(&packet).unwrap()).unwrap(),
                &packet[..]
            );
        }
    }

    #[test]
    fn the_guest_hardware_address_is_the_one_the_engine_knows() {
        // The agent puts this in its DHCP request; the engine's lease table is keyed by
        // it, and the frames it builds are addressed to it.
        assert_eq!(guest_hardware_address(), dc_common::net::GUEST_MAC);
        assert_eq!(
            guest_hardware_address(),
            [0x52, 0x54, 0x00, 0x12, 0x34, 0x56]
        );
    }

    #[test]
    fn the_link_is_the_projects_own_subnet_and_the_agent_is_told_how_to_make_it() {
        let link = Link::default();
        assert_eq!(link.guest_ip.to_string(), "10.0.177.16");
        assert_eq!(link.gateway_ip.to_string(), "10.0.177.1");
        assert_eq!(link.prefix, 24);
        let command = link.agent_command("tun0");
        assert!(
            command.contains("ip addr add 10.0.177.16/24 dev tun0"),
            "{command}"
        );
        assert!(
            command.contains("ip link set tun0 mtu 1500 up"),
            "{command}"
        );
        assert!(
            command.contains("ip route add default via 10.0.177.1 dev tun0"),
            "{command}"
        );
    }

    #[test]
    fn the_ping_sample_is_carried_by_the_packet_and_not_by_a_mode() {
        // The agent pings the gateway with the gateway's own address as the source, which
        // is what a `connect`ed ICMP socket makes the kernel do; the engine reads it back.
        assert_eq!(Sample::parse("gateway"), Some(Sample::Gateway));
        assert_eq!(Sample::parse(" guest "), Some(Sample::Guest));
        assert_eq!(Sample::parse("nonsense"), None);
        assert_eq!(Sample::Gateway.as_str(), "gateway");
    }

    #[test]
    fn the_clock_the_agent_asks_for_is_the_hosts_clock() {
        let request = ntp_request();
        assert_eq!(
            request.len(),
            6,
            "seconds and milliseconds, and nothing else"
        );
        let reply = String::from_utf8(ntp_reply()).unwrap();
        // "2026-10-09 21:00:00 123" — a date, a time and the milliseconds, which is what
        // the guest's `date` shows and what the agent sets its clock from.  The reply's
        // shape is asserted, never the instant: this test runs at whatever time it runs.
        let reply = reply.trim_end();
        let (date, rest) = reply.split_once(' ').expect("a date, then a time");
        let (time, millis) = rest.split_once(' ').expect("a time, then the milliseconds");
        assert_eq!(date.len(), 10, "{reply:?}");
        assert_eq!(date.matches('-').count(), 2, "{reply:?}");
        assert_eq!(time.len(), 8, "{reply:?}");
        assert_eq!(time.matches(':').count(), 2, "{reply:?}");
        assert!(millis.parse::<u16>().is_ok(), "{millis:?}");
    }

    #[test]
    fn a_known_instant_becomes_the_date_it_really_is() {
        // 2026-10-09T00:00:00Z, so a wrong calendar is a test failure and not a surprise
        // in a guest whose files are suddenly from 1970.
        assert_eq!(chrono_like(1_760_000_000), "2025-10-09 08:53:20");
        assert_eq!(chrono_like(0), "1970-01-01 00:00:00");
        assert_eq!(chrono_like(1_000_000_000), "2001-09-09 01:46:40");
    }

    #[test]
    fn the_channel_carries_a_packet_and_not_a_frame_of_its_own() {
        // The frame's kind says "packet"; its payload is the packet itself, which is what
        // makes the copy count one per packet per direction.
        let packet = ipv4_packet();
        let frame = Frame::new(KIND_PACKET, packet.clone());
        let wire = frame.encode();
        let mut reader = Reader::new();
        reader.push(&wire);
        let read = reader.next_frame().unwrap().unwrap();
        assert_eq!(read.kind, KIND_PACKET);
        assert_eq!(read.payload, packet);
    }
}
