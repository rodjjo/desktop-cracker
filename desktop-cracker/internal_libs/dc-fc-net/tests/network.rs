//! **The network channel, end to end, with the project's own engine.**
//!
//! The guest half is played by this test (it is what the guest's agent does), the host half
//! is the real thing: a listener on a port, `dc-fc-net`'s adapters, and `dc-net`'s own
//! DHCP server answering through its own relay.
//!
//! What it proves, in one pass:
//!
//! * the listener exists **before** anything connects (this project's ordering rule);
//! * a packet that arrives on the channel goes in as an L3 packet and comes out at the
//!   engine's door as the Ethernet frame it expects — the two adapters are each other's
//!   inverse, with a real engine behind one of them;
//! * the engine's answer comes back on the same channel as a **packet**, not as a frame:
//!   the 14 bytes the engine's wire carries are gone;
//! * the answer is a real DHCP offer for the address the project's own subnet uses, with
//!   the guest's own hardware address in it.
//!
//! No KVM, no guest, no host socket beyond this test's own: the DHCP path is pure.

use std::io::Write;
use std::time::{Duration, Instant};

use dc_fc_net::{Network, KIND_PACKET};
use dc_vsock::{ports, Frame, Reader, Service};

/// A DHCPDISCOVER, built as a client puts it on the wire: Ethernet broadcast, IPv4
/// `0.0.0.0` → `255.255.255.255`, UDP 68 → 67, the magic cookie, and option 53.
///
/// It is written here rather than taken from the engine's own test helper because a client
/// is what the guest's agent will be: the test states what the agent has
/// to send.
fn dhcp_discover(mac: [u8; 6], xid: u32) -> Vec<u8> {
    const BOOTREQUEST: u8 = 1;
    const MAGIC: [u8; 4] = [99, 130, 83, 99];
    let mut bootp = Vec::with_capacity(300);
    bootp.push(BOOTREQUEST);
    bootp.push(1); // htype: ethernet
    bootp.push(6); // hlen
    bootp.push(0); // hops
    bootp.extend_from_slice(&xid.to_be_bytes());
    bootp.extend_from_slice(&0u16.to_be_bytes()); // secs
    bootp.extend_from_slice(&0x8000u16.to_be_bytes()); // broadcast flag
    bootp.extend_from_slice(&[0u8; 4]); // ciaddr
    bootp.extend_from_slice(&[0u8; 12]); // yiaddr, siaddr, giaddr
    bootp.extend_from_slice(&mac);
    bootp.extend_from_slice(&[0u8; 10]); // the rest of chaddr
    bootp.extend_from_slice(&[0u8; 64]); // sname
    bootp.extend_from_slice(&[0u8; 128]); // file
    bootp.extend_from_slice(&MAGIC);
    bootp.extend_from_slice(&[53, 1, 1]); // DHCPDISCOVER
    bootp.push(255); // end
    while bootp.len() < 300 {
        bootp.push(0);
    }

    let mut udp = Vec::with_capacity(8 + bootp.len());
    udp.extend_from_slice(&68u16.to_be_bytes());
    udp.extend_from_slice(&67u16.to_be_bytes());
    udp.extend_from_slice(&((8 + bootp.len()) as u16).to_be_bytes());
    udp.extend_from_slice(&[0, 0]); // checksum, filled by the engine's parser's rules
    udp.extend_from_slice(&bootp);

    // The kernel's own UDP length and checksum are not what the engine checks: it reads
    // the ports.  The IPv4 header it does parse.
    let mut packet = vec![0u8; 20];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&((20 + udp.len()) as u16).to_be_bytes());
    packet[8] = 64; // ttl
    packet[9] = 17; // UDP
    packet.extend_from_slice(&udp);
    packet
}

/// The `yiaddr` and the client's hardware address out of a BOOTP reply, and the message
/// type in option 53.
fn read_offer(packet: &[u8]) -> Option<(std::net::Ipv4Addr, [u8; 6], u8)> {
    // IPv4 → UDP → BOOTP, from a bare packet (no Ethernet header: this is what came off
    // the channel).
    let ihl = (packet[0] & 0x0f) as usize * 4;
    let udp = &packet[ihl..];
    let bootp = &udp[8..];
    let yiaddr = std::net::Ipv4Addr::new(bootp[16], bootp[17], bootp[18], bootp[19]);
    let mut mac = [0u8; 6];
    mac.copy_from_slice(&bootp[28..34]);
    let options = &bootp[240..];
    let mut i = 0;
    let mut message_type = 0;
    while i + 1 < options.len() {
        let code = options[i];
        if code == 255 {
            break;
        }
        if code == 0 {
            i += 1;
            continue;
        }
        let len = options[i + 1] as usize;
        if code == 53 && len == 1 {
            message_type = options[i + 2];
        }
        i += 2 + len;
    }
    Some((yiaddr, mac, message_type))
}

#[test]
fn a_packet_goes_in_and_the_engines_own_dhcp_offer_comes_back_on_the_channel() {
    let dir = tempfile::tempdir().unwrap();
    let uds = dir.path().join("v.sock");

    // The host's side: the channel listens first (before anything connects), and the
    // engine behind it is the project's own.
    let network = std::sync::Arc::new(Network::listen(&uds, ports::NETWORK).unwrap());
    let (ours, theirs) = dc_net::conduit_pair().unwrap();
    let machine = dc_net::MachineNetwork::new(
        "desktop-cracker",
        ours,
        Vec::new(), // no resolvers: this test never leaves the machine
    );
    machine.start();
    network
        .serve_in_background(machine.clone(), theirs)
        .unwrap();

    // The guest's side: the agent's own dial.
    let mut guest =
        std::os::unix::net::UnixStream::connect(dc_vsock::listener_path(&uds, ports::NETWORK))
            .unwrap();
    let mac = dc_fc_net::guest_hardware_address();
    let discover = dhcp_discover(mac, 0x1234_5678);
    guest
        .write_all(&Frame::new(KIND_PACKET, discover).encode())
        .unwrap();
    guest.flush().unwrap();

    // The answer, on the same channel, as a packet.
    guest
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut reader = Reader::new();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut offer = None;
    while Instant::now() < deadline && offer.is_none() {
        match reader.read_frame(&mut guest, ports::NETWORK) {
            Ok(Some(frame)) => {
                assert_eq!(frame.kind, KIND_PACKET, "the channel carries packets");
                // The engine's own wire has an Ethernet header; this does not.
                assert_eq!(frame.payload[0] >> 4, 4, "an IPv4 packet, and not a frame");
                if let Some((ip, mac_in, kind)) = read_offer(&frame.payload) {
                    if kind == 2 {
                        offer = Some((ip, mac_in));
                    }
                }
            }
            Ok(None) => break,
            Err(e) => panic!("the channel ended: {e}"),
        }
    }

    let (ip, mac_in) = offer.expect("the engine's DHCP server answers a discover");
    assert_eq!(
        mac_in, mac,
        "the offer is for the address the agent asked as"
    );
    assert!(
        ip.octets()[..3] == dc_net::SUBNET[..3],
        "the offer is on the project's own subnet, and it is {ip}"
    );
    assert_eq!(
        ip.to_string(),
        "10.0.177.16",
        "the address the machine this project started with hands out is the address this path hands out"
    );

    let counters = network.counters();
    assert_eq!(counters.in_packets, 1, "one packet in");
    assert!(counters.out_packets >= 1, "and the answer came back out");
    assert!(counters.bytes > 0);
    assert_eq!(counters.dropped, 0, "nothing was thrown away");
}

#[test]
fn a_frame_that_is_not_a_packet_is_counted_and_not_given_to_the_engine() {
    let dir = tempfile::tempdir().unwrap();
    let uds = dir.path().join("v.sock");
    let network = std::sync::Arc::new(Network::listen(&uds, ports::NETWORK).unwrap());
    let (ours, theirs) = dc_net::conduit_pair().unwrap();
    let machine = dc_net::MachineNetwork::new("desktop-cracker", ours, Vec::new());
    network.serve_in_background(machine, theirs).unwrap();
    let mut guest =
        std::os::unix::net::UnixStream::connect(dc_vsock::listener_path(&uds, ports::NETWORK))
            .unwrap();

    // A frame of a kind this service does not know, and one whose payload is not an IP
    // packet: both are dropped, and the run is not disturbed.
    guest
        .write_all(&Frame::new(7, b"nonsense".to_vec()).encode())
        .unwrap();
    guest
        .write_all(&Frame::new(KIND_PACKET, vec![0x10, 0, 0, 0]).encode())
        .unwrap();
    guest.flush().unwrap();
    let deadline = Instant::now() + Duration::from_millis(300);
    while Instant::now() < deadline && network.counters().dropped < 2 {
        std::thread::sleep(Duration::from_millis(5));
    }
    let counters = network.counters();
    assert_eq!(counters.dropped, 2, "{counters:?}");
    assert_eq!(counters.in_packets, 0);
}

#[test]
fn a_run_that_ends_leaves_no_socket_behind() {
    let dir = tempfile::tempdir().unwrap();
    let uds = dir.path().join("v.sock");
    let network = std::sync::Arc::new(Network::listen(&uds, ports::NETWORK).unwrap());
    let path = network.service_path();
    assert!(path.exists());
    network.close();
    assert!(!path.exists(), "a run cleans up its own sockets");
    // And the listener Service is gone with it.
    let _ = Service::bind(&uds, ports::NETWORK).unwrap();
}
