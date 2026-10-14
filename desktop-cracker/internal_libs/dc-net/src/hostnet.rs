//! The `--host-network` rule: SPECS.md "The host's own services".
//!
//! The guest's gateway is `10.0.177.1`, and the rule a run has always had is that the host's own
//! network is **not the guest's to reach**.  `--host-network` is the operator's exception to it
//! (2026-10-12): the builtin DNS answers the name `parenthost` with the gateway address, and a
//! connection the guest makes to that address is carried to the **host's `127.0.0.1`**.
//!
//! ```text
//!   guest                    this process                    the host
//!   curl http://parenthost ──▶ DNS: parenthost = 10.0.177.1
//!   connect 10.0.177.1:8080 ──▶ rewrite 10.0.177.1 → 127.0.0.1 ──▶ 127.0.0.1:8080
//!   ◀──────────── the answer, rewritten back to 10.0.177.1 ──────────┘
//! ```
//!
//! Three things are worth stating because they are the parts that could be gotten wrong:
//!
//! * **the rewrite is in the addresses only**, never the ports.  The guest dials
//!   `10.0.177.1:8080` and the answer arrives *from* `10.0.177.1:8080`, so nothing inside the
//!   guest has to know the service is not in the microVM.  A proxy that rewrites the port would
//!   break every `Host:` header and every redirect that follows it.
//! * **it is a rewrite, not a route.**  The frame is handed to the same userspace relay the
//!   guest's other flows go through, so the flow is a flow of this machine: counted, bounded by
//!   the machine's flow ceiling, and closed when the machine goes away.
//! * **`10.0.177.1` is the only address carried.**  A guest that dials `127.0.0.1` — its own
//!   loopback, which is where its sshd sits — or the host's LAN address is answered exactly as
//!   it was before the switch existed.  The name is the door, and the gateway address is the
//!   only way through it.

use std::net::Ipv4Addr;

use crate::frame;

/// SPECS.md's name for the machine this process runs on.
pub const HOST_NAME: &str = "parenthost";

/// The address that name answers with, and the only address the rule carries: the guest's gateway.
pub const HOST_ADDRESS: Ipv4Addr = Ipv4Addr::new(10, 0, 177, 1);

/// The address a carried flow leaves through on the host.
pub const HOST_LOOPBACK: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);

/// The DNS query type this rule answers with a record, and the one it answers with NODATA.
const QTYPE_A: u16 = 1;
const QTYPE_AAAA: u16 = 28;

/// Is this the name the rule answers?  `parenthost`, `parenthost.`, in any case: a resolver sends
/// the name as it was written, and a trailing dot is how a search list can hand it over.
pub fn is_host_name(name: &str) -> bool {
    name.strip_suffix('.')
        .unwrap_or(name)
        .eq_ignore_ascii_case(HOST_NAME)
}

/// The question a query asks: the name, lowercased, and its type.
///
/// The 12-byte header, then the labels — a length byte and that many bytes, until a zero length —
/// then the two-byte type.  A name that runs off the end of the datagram is not a question, and
/// `None` means "this is not something to answer".
pub fn question(query: &[u8]) -> Option<(String, u16)> {
    let end = question_end(query)?;
    let name = name_of(query, 12)?;
    let qtype = u16::from_be_bytes([query[end - 4], query[end - 3]]);
    Some((name, qtype))
}

/// The name of a query, lowercased, with the dots the labels had.
fn name_of(query: &[u8], at: usize) -> Option<String> {
    let mut at = at;
    let mut name = String::new();
    loop {
        let length = *query.get(at)? as usize;
        at += 1;
        if length == 0 {
            return Some(name);
        }
        // A label is at most 63 bytes (RFC 1035), and a compressed name (a `0xc0` pointer) is not
        // something this answers: the queries a Linux resolver sends are written out in full.
        if length > 63 || at + length > query.len() {
            return None;
        }
        let label = std::str::from_utf8(&query[at..at + length]).ok()?;
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(label);
        at += length;
    }
}

/// One past the question section: the name, its type and its class.
///
/// The answer echoes **the question and nothing else** — an EDNS0 `OPT` record the client appended
/// is not echoed, because the counts below say there is nothing after the question.
fn question_end(query: &[u8]) -> Option<usize> {
    // The labels, from the start of the question section: a length byte and that many bytes.
    let mut at = 12;
    loop {
        let length = *query.get(at)? as usize;
        at += 1;
        if length == 0 {
            break;
        }
        at += length;
    }
    // QTYPE and QCLASS.
    (at + 4 <= query.len()).then_some(at + 4)
}

/// Does this query belong to the rule?
///
/// `Some(true)`: answer it with an A record for [`HOST_ADDRESS`].  `Some(false)`: the name is ours
/// and this family has nothing to answer with — NODATA, which is what leaves a client that already
/// has the A record alone (the vendored relay's own reasoning about a peer's name).  `None`: the
/// name is not ours, and the host's resolver answers it as it always did.
pub fn owns_query(name: &str, qtype: u16) -> Option<bool> {
    if !is_host_name(name) {
        return None;
    }
    match qtype {
        QTYPE_A => Some(true),
        QTYPE_AAAA => Some(false),
        _ => Some(false),
    }
}

/// The answer for a query the rule owns: the question echoed, the guest's own transaction id, and
/// one A record for [`HOST_ADDRESS`] — or no record at all when this family has nothing.
///
/// The shape is the vendored relay's own `dns_answer`, so a lookup answered here and one answered
/// there are the same bytes on the wire: a pointer to the question's name at offset 12, a TTL of
/// 30 seconds, and the counts that match.
pub fn answer_for(query: &[u8], record: bool) -> Vec<u8> {
    let Some(end) = question_end(query) else {
        return query.to_vec();
    };
    let mut answer = query[..end].to_vec();
    answer[2] = 0x84; // QR = 1, authoritative, recursion not asked for
    answer[3] = 0x00; // no error
    if !record {
        answer[6..12].copy_from_slice(&[0, 0, 0, 0, 0, 0]);
        return answer;
    }
    answer[6..8].copy_from_slice(&1u16.to_be_bytes()); // ANCOUNT = 1
    answer[8..12].copy_from_slice(&[0, 0, 0, 0]); // no authority, no additional
    answer.extend_from_slice(&[0xc0, 0x0c]); // the name, by pointer to the question
    answer.extend_from_slice(&QTYPE_A.to_be_bytes());
    answer.extend_from_slice(&1u16.to_be_bytes()); // class IN
    answer.extend_from_slice(&30u32.to_be_bytes());
    answer.extend_from_slice(&4u16.to_be_bytes());
    answer.extend_from_slice(&HOST_ADDRESS.octets());
    answer
}

/// The ports this machine already carries **into** the guest (`--ssh-port`), which the rule must
/// not turn into a loop.
///
/// A forward is a door with two sides: the host's port and the guest's port.  A guest that dials
/// the host port is dialling the door from the inside, and a frame the guest sends **from** the
/// guest port is an answer on a flow the forward already owns.  Both are left to the relay exactly
/// as they were, because rewriting either one takes the frame out of the flow it belongs to — which
/// is what a reset looks like from the outside.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Forwarded {
    /// The host's side: `127.0.0.1:2223` in the operator's own command line.
    pub host_ports: Vec<u16>,
    /// The guest's side those ports lead to: 22, the guest's sshd.
    pub guest_ports: Vec<u16>,
}

impl Forwarded {
    /// Is this port one of the machine's doors, on either side of it?
    fn holds(&self, port: u16) -> bool {
        self.host_ports.contains(&port) || self.guest_ports.contains(&port)
    }
}

/// The frame the guest sent **to its gateway**, rewritten for the host's loopback.
///
/// Only the addresses, and only when the destination is the gateway: the ports, the sequence
/// numbers and the payload are the flow's own and are left exactly as the guest wrote them.  The
/// IP and transport checksums are recomputed for the new pair (`frame::translate_ipv4` does both,
/// and leaves an ICMP payload alone because an ICMP checksum covers no IP header).
///
/// **TCP, UDP and ICMP echo.**  A `ping` is how a person checks the rule with their own eyes, and
/// the host answers one on an ordinary datagram socket (this host grants it to every group:
/// `net.ipv4.ping_group_range = 0 2147483647`), so a carried echo is a real round trip and not a
/// reply this process made up.
///
/// **What stays with the gateway.**  Port **53** and port **123** are this project's own answers —
/// the lookup and the time SPECS.md gives the guest so its names resolve and its clock is right
/// without reaching anything — and carrying them to the host's loopback would be the switch turning
/// off the network it is built on.  So do the ports of a `--ssh-port` forward: that door goes *into*
/// the guest, and a guest dialling it from the inside is a connection handed straight back to the
/// same forward — a loop whose answer is a reset (measured 2026-10-12: `ssh -p 2223
/// deskuser@127.0.0.1` **from inside the guest**, with `--host-network`, is
/// `kex_exchange_identification: read: Connection reset by peer`).
pub fn to_host(frame: &[u8], forwarded: &Forwarded) -> Option<Vec<u8>> {
    let ethernet = frame::parse_ethernet(frame)?;
    if ethernet.ethertype != frame::ETHERTYPE_IPV4 {
        return None;
    }
    let packet = frame::parse_ipv4(ethernet.payload)?;
    if packet.dst != HOST_ADDRESS {
        return None;
    }
    match packet.protocol {
        frame::IPPROTO_TCP => {
            let segment = frame::parse_tcp(packet.payload)?;
            if forwarded.holds(segment.dst_port) || forwarded.holds(segment.src_port) {
                return None;
            }
        }
        frame::IPPROTO_UDP => {
            let datagram = frame::parse_udp(packet.payload)?;
            if matches!(datagram.dst_port, 53 | 123)
                || forwarded.holds(datagram.dst_port)
                || forwarded.holds(datagram.src_port)
            {
                return None;
            }
        }
        frame::IPPROTO_ICMP => {
            // An echo **request** only: a reply, an unreachable or a timestamp is not something to
            // send back out, and the machine's own answers to the guest must not be echoed at it.
            if !matches!(frame::parse_icmp(packet.payload), Some(message) if message.kind == 8) {
                return None;
            }
        }
        _ => return None,
    }
    let payload = frame::translate_ipv4(ethernet.payload, packet.src, HOST_LOOPBACK, None, None)?;
    Some(frame::build_ethernet(
        ethernet.dst,
        ethernet.src,
        frame::ETHERTYPE_IPV4,
        &payload,
    ))
}

/// The frame that says **no** to a guest dialling one of the machine's own doors, and the reason
/// it has to be said here.
///
/// A `--ssh-port 2223` forward is a listener on the host's loopback that leads *into* the guest.  A
/// guest that dials `parenthost:2223` is dialling that door from the inside, and there is nothing on
/// the host behind it to answer: carrying the flow to `127.0.0.1:2223` hands the connection back to
/// the same forward, which opens a second flow into the guest, and the two halves of one ssh
/// handshake end up on two different flows — which is what a reset in the middle of
/// `kex_exchange_identification` is.  Left to the relay it is a handshake this process completes for
/// the guest and then takes back, seconds later, when the host side gives up.
///
/// So the answer is the one a refused connection gets everywhere else: a reset, now, from the
/// address the guest dialled.  The guest's `connect()` fails and says so, and the forward keeps the
/// meaning it was given.
pub fn refusal(frame: &[u8], forwarded: &Forwarded) -> Option<Vec<u8>> {
    let ethernet = frame::parse_ethernet(frame)?;
    if ethernet.ethertype != frame::ETHERTYPE_IPV4 {
        return None;
    }
    let packet = frame::parse_ipv4(ethernet.payload)?;
    if packet.dst != HOST_ADDRESS || packet.protocol != frame::IPPROTO_TCP {
        return None;
    }
    let segment = frame::parse_tcp(packet.payload)?;
    // A **new** flow only — the same test the relay uses before it opens one.  Everything the guest
    // sends after the refusal is a flow this process does not have, and the relay already answers
    // that with a reset of its own.
    if !segment.has(frame::TCP_SYN) || segment.has(frame::TCP_ACK) {
        return None;
    }
    if !forwarded.holds(segment.dst_port) || forwarded.holds(segment.src_port) {
        return None;
    }
    let tcp = frame::build_tcp(
        HOST_ADDRESS,
        packet.src,
        segment.dst_port,
        segment.src_port,
        0,
        segment.seq.wrapping_add(1),
        frame::TCP_RST | frame::TCP_ACK,
        0,
        &[],
    );
    let ip = frame::build_ipv4(HOST_ADDRESS, packet.src, frame::IPPROTO_TCP, 64, &tcp);
    Some(frame::build_ethernet(
        ethernet.src,
        ethernet.dst,
        frame::ETHERTYPE_IPV4,
        &ip,
    ))
}

/// The frame a host socket answered with, rewritten back to the address the guest dialled.
///
/// This is the other half, and it is the half that makes the rule invisible inside the guest: a
/// flow opened to `127.0.0.1` is answered to the guest as if it had been opened to
/// `10.0.177.1`.  The frame's **destination is left alone** — it is the guest's own address, which
/// the relay took from the flow — so this rewrites one address and nothing else.  A frame from
/// anywhere **but** the loopback is not this rule's business and is `None`, so the machine's own
/// answers — from its gateway, its ULA, its link-local — reach the guest exactly as they were built.
pub fn from_host(frame: &[u8]) -> Option<Vec<u8>> {
    let ethernet = frame::parse_ethernet(frame)?;
    if ethernet.ethertype != frame::ETHERTYPE_IPV4 {
        return None;
    }
    let packet = frame::parse_ipv4(ethernet.payload)?;
    if packet.src != HOST_LOOPBACK {
        return None;
    }
    let payload = frame::translate_ipv4(ethernet.payload, HOST_ADDRESS, packet.dst, None, None)?;
    Some(frame::build_ethernet(
        ethernet.dst,
        ethernet.src,
        frame::ETHERTYPE_IPV4,
        &payload,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr as Addr;

    /// A query for `name`, type 1 (A), from a client that used transaction id `0x1234`.
    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut out = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            out.push(label.len() as u8);
            out.extend_from_slice(label.as_bytes());
        }
        out.push(0);
        out.extend_from_slice(&qtype.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes());
        out
    }

    /// The guest's own frame: from its address, to the gateway, carrying `payload`.
    fn guest_frame(protocol: u8, payload: &[u8]) -> Vec<u8> {
        let ip = frame::build_ipv4(crate::GUEST_IP.into(), HOST_ADDRESS, protocol, 64, payload);
        frame::build_ethernet(
            crate::GATEWAY_MAC,
            dc_common::net::GUEST_MAC,
            frame::ETHERTYPE_IPV4,
            &ip,
        )
    }

    #[test]
    fn the_name_is_parenthost_and_only_parenthost() {
        assert!(is_host_name("parenthost"));
        assert!(is_host_name("parenthost."));
        assert!(is_host_name("Parenthost"));
        assert!(!is_host_name("parenthost.local"));
        assert!(!is_host_name("notparenthost"));
        assert!(!is_host_name("deb.debian.org"));
        assert!(!is_host_name(""));
    }

    #[test]
    fn a_query_for_the_name_is_ours_and_an_a_query_gets_a_record() {
        let (name, qtype) = question(&query("parenthost", 1)).expect("a question");
        assert_eq!(name, "parenthost");
        assert_eq!(qtype, QTYPE_A);
        assert_eq!(owns_query(&name, qtype), Some(true));
    }

    #[test]
    fn a_query_for_any_other_name_is_the_resolvers() {
        let (name, qtype) = question(&query("deb.debian.org", 1)).expect("a question");
        assert_eq!(name, "deb.debian.org");
        assert_eq!(owns_query(&name, qtype), None);
    }

    #[test]
    fn the_name_has_no_ipv6_record_and_says_so() {
        let (name, qtype) = question(&query("parenthost", QTYPE_AAAA)).expect("a question");
        assert_eq!(owns_query(&name, qtype), Some(false));
    }

    #[test]
    fn the_answer_is_one_a_record_of_the_gateway_address() {
        let asked = query("parenthost", 1);
        let answer = answer_for(&asked, true);
        // The transaction id is the guest's, and it is a response with one answer.
        assert_eq!(&answer[..2], &asked[..2]);
        assert_eq!(answer[2] & 0x80, 0x80, "QR");
        assert_eq!(answer[3] & 0x0f, 0, "no error");
        assert_eq!(u16::from_be_bytes([answer[6], answer[7]]), 1);
        // The record: a pointer to the question's name, type A, class IN, four bytes of address.
        let record = &answer[asked.len()..];
        assert_eq!(&record[..2], &[0xc0, 0x0c]);
        assert_eq!(u16::from_be_bytes([record[2], record[3]]), QTYPE_A);
        assert_eq!(u16::from_be_bytes([record[4], record[5]]), 1);
        assert_eq!(u16::from_be_bytes([record[10], record[11]]), 4);
        assert_eq!(&record[12..16], &HOST_ADDRESS.octets());
    }

    #[test]
    fn the_answer_with_no_record_is_nodata_and_not_a_failure() {
        let asked = query("parenthost", QTYPE_AAAA);
        let answer = answer_for(&asked, false);
        assert_eq!(answer.len(), asked.len());
        assert_eq!(answer[3] & 0x0f, 0, "rcode 0: the name exists");
        assert_eq!(&answer[6..12], &[0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn a_frame_to_the_gateway_leaves_through_the_hosts_loopback() {
        let segment = frame::build_tcp(
            Addr::new(10, 0, 177, 16),
            HOST_ADDRESS,
            44000,
            8080,
            7,
            0,
            frame::TCP_SYN,
            65535,
            b"",
        );
        let carried = to_host(
            &guest_frame(frame::IPPROTO_TCP, &segment),
            &Forwarded::default(),
        )
        .expect("carried");
        let ethernet = frame::parse_ethernet(&carried).expect("a frame");
        let packet = frame::parse_ipv4(ethernet.payload).expect("a packet");
        assert_eq!(packet.dst, HOST_LOOPBACK);
        assert_eq!(
            packet.src,
            Addr::new(10, 0, 177, 16),
            "the guest's own address"
        );
        let tcp = frame::parse_tcp(packet.payload).expect("a segment");
        assert_eq!(tcp.src_port, 44000);
        assert_eq!(
            tcp.dst_port, 8080,
            "the port the guest dialled is the port the host hears"
        );
        assert_eq!(tcp.flags & frame::TCP_SYN, frame::TCP_SYN);
    }

    #[test]
    fn the_answer_comes_back_from_the_address_the_guest_dialled() {
        let segment = frame::build_tcp(
            HOST_LOOPBACK,
            Addr::new(10, 0, 177, 16),
            8080,
            44000,
            1,
            8,
            frame::TCP_SYN | frame::TCP_ACK,
            65535,
            b"",
        );
        let ip = frame::build_ipv4(
            HOST_LOOPBACK,
            Addr::new(10, 0, 177, 16),
            frame::IPPROTO_TCP,
            64,
            &segment,
        );
        let from_host_frame = frame::build_ethernet(
            dc_common::net::GUEST_MAC,
            crate::GATEWAY_MAC,
            frame::ETHERTYPE_IPV4,
            &ip,
        );
        let back = from_host(&from_host_frame).expect("rewritten");
        let ethernet = frame::parse_ethernet(&back).expect("a frame");
        let packet = frame::parse_ipv4(ethernet.payload).expect("a packet");
        assert_eq!(
            packet.src, HOST_ADDRESS,
            "the guest is told it talked to its gateway"
        );
        assert_eq!(packet.dst, Addr::new(10, 0, 177, 16));
        let tcp = frame::parse_tcp(packet.payload).expect("a segment");
        assert_eq!((tcp.src_port, tcp.dst_port), (8080, 44000));
    }

    #[test]
    fn a_frame_from_anywhere_else_is_not_rewritten() {
        // The machine's own answers come from the gateway, and they are already what the guest
        // expects: rewriting them would be the bug.
        let ip = frame::build_ipv4(
            HOST_ADDRESS,
            Addr::new(10, 0, 177, 16),
            frame::IPPROTO_TCP,
            64,
            &frame::build_tcp(
                HOST_ADDRESS,
                Addr::new(10, 0, 177, 16),
                22,
                44000,
                1,
                8,
                frame::TCP_SYN | frame::TCP_ACK,
                65535,
                b"",
            ),
        );
        let ours = frame::build_ethernet(
            dc_common::net::GUEST_MAC,
            crate::GATEWAY_MAC,
            frame::ETHERTYPE_IPV4,
            &ip,
        );
        assert!(from_host(&ours).is_none());
    }

    #[test]
    fn a_frame_to_any_other_address_is_not_carried() {
        // The host's LAN, the guest's own loopback, another machine: none of them are the rule.
        for dst in [
            Addr::new(127, 0, 0, 1),
            Addr::new(10, 0, 177, 16),
            Addr::new(10, 177, 0, 9),
            Addr::new(192, 168, 1, 1),
        ] {
            let ip = frame::build_ipv4(
                Addr::new(10, 0, 177, 16),
                dst,
                frame::IPPROTO_TCP,
                64,
                &frame::build_tcp(
                    Addr::new(10, 0, 177, 16),
                    dst,
                    44000,
                    8080,
                    7,
                    0,
                    frame::TCP_SYN,
                    65535,
                    b"",
                ),
            );
            let frame = frame::build_ethernet(
                crate::GATEWAY_MAC,
                dc_common::net::GUEST_MAC,
                frame::ETHERTYPE_IPV4,
                &ip,
            );
            assert!(
                to_host(&frame, &Forwarded::default()).is_none(),
                "{dst} was carried to the host"
            );
        }
    }

    #[test]
    fn a_carried_flow_keeps_the_checksums_a_stack_accepts() {
        // The rewrite changes the pair of addresses the checksums are built from, so a flow whose
        // checksums were left alone is a flow the guest's stack throws away.  A header or a segment
        // whose checksum is the right one for the bytes it now holds verifies to zero (RFC 1071),
        // which is what a receiver computes.
        let payload = b"hello";
        let datagram = frame::build_udp(Addr::new(10, 0, 177, 16), HOST_ADDRESS, 51000, 9, payload);
        let carried = to_host(
            &guest_frame(frame::IPPROTO_UDP, &datagram),
            &Forwarded::default(),
        )
        .expect("carried");
        let ethernet = frame::parse_ethernet(&carried).expect("a frame");
        let packet = frame::parse_ipv4(ethernet.payload).expect("a packet");
        assert_eq!(packet.dst, HOST_LOOPBACK);
        assert_eq!(
            frame::checksum(&ethernet.payload[..20]),
            0,
            "the IP header's checksum is the one for the addresses now in it"
        );
        let udp = frame::parse_udp(packet.payload).expect("a datagram");
        assert_eq!(udp.payload, payload, "the datagram is the guest's own");
        assert_eq!(
            frame::transport_checksum(packet.src, packet.dst, frame::IPPROTO_UDP, packet.payload),
            0,
            "the pseudo-header the checksum was made from is the one the packet now has"
        );
    }

    #[test]
    fn a_frame_that_is_not_ipv4_is_left_to_the_relay() {
        let arp = frame::build_ethernet(
            [0xff; 6],
            crate::GATEWAY_MAC,
            frame::ETHERTYPE_ARP,
            &[0u8; 28],
        );
        assert!(to_host(&arp, &Forwarded::default()).is_none());
    }

    /// A `ping` of the gateway address is carried to the host, which is what makes `ping
    /// parenthost` a real round trip instead of a reply this process invented.  An echo **reply**
    /// is not: the machine's own answers must not be echoed back at the guest.
    #[test]
    fn a_ping_of_the_gateway_is_carried_and_a_ping_reply_is_not() {
        let request = frame::build_icmp_echo_request(7, 1, b"probe");
        let carried = to_host(
            &guest_frame(frame::IPPROTO_ICMP, &request),
            &Forwarded::default(),
        )
        .expect("carried");
        let ethernet = frame::parse_ethernet(&carried).expect("a frame");
        let packet = frame::parse_ipv4(ethernet.payload).expect("a packet");
        assert_eq!(packet.dst, HOST_LOOPBACK);
        assert_eq!(packet.protocol, frame::IPPROTO_ICMP);
        let echo = frame::parse_icmp(packet.payload).expect("an ICMP message");
        assert_eq!(echo.kind, 8, "still an echo request");
        assert_eq!(
            echo.rest,
            request[4..8],
            "the guest's identifier and sequence"
        );
        assert_eq!(echo.payload, b"probe");

        let reply = frame::build_icmp_echo_reply(&request).expect("a reply");
        assert!(
            to_host(
                &guest_frame(frame::IPPROTO_ICMP, &reply),
                &Forwarded::default()
            )
            .is_none(),
            "an echo reply is not something to send back out"
        );
    }

    /// **The `--ssh-port` loop, which is what the operator hit.**  With the switch on, a guest that
    /// dials the host's forwarded port is dialling the door that leads *into* it: carrying that to
    /// the host hands the connection back to the same forward, and the answer is a reset in the
    /// middle of the ssh handshake.  Those ports keep the meaning the forward gave them.
    #[test]
    fn a_forwarded_port_is_not_carried_back_into_its_own_forward() {
        let forwarded = Forwarded {
            host_ports: vec![2223],
            guest_ports: vec![crate::SSH_GUEST_PORT],
        };
        let dial = frame::build_tcp(
            Addr::new(10, 0, 177, 16),
            HOST_ADDRESS,
            44000,
            2223,
            7,
            0,
            frame::TCP_SYN,
            65535,
            b"",
        );
        assert!(
            to_host(&guest_frame(frame::IPPROTO_TCP, &dial), &forwarded).is_none(),
            "parenthost:2223 is the host's door into the guest, not a service on the host"
        );

        // The guest's own side of the same door: a frame **from** port 22 is the sshd answering a
        // flow the forward owns, and rewriting it takes it out of that flow.
        let answer = frame::build_tcp(
            Addr::new(10, 0, 177, 16),
            HOST_ADDRESS,
            crate::SSH_GUEST_PORT,
            44000,
            7,
            0,
            frame::TCP_ACK,
            65535,
            b"",
        );
        assert!(
            to_host(&guest_frame(frame::IPPROTO_TCP, &answer), &forwarded).is_none(),
            "a frame from the guest's sshd belongs to the forward's own flow"
        );

        // A port nobody forwarded is still carried, in the same machine.
        let other = frame::build_tcp(
            Addr::new(10, 0, 177, 16),
            HOST_ADDRESS,
            44001,
            1919,
            7,
            0,
            frame::TCP_SYN,
            65535,
            b"",
        );
        assert!(
            to_host(&guest_frame(frame::IPPROTO_TCP, &other), &forwarded).is_some(),
            "the service the operator was reaching is still reached"
        );
    }

    /// A lookup and a time query at the gateway address stay this project's own answers, with the
    /// switch on: `--host-network` lets the guest reach the host's services, it does not hand the
    /// guest the host's resolver or take the builtin time away.
    #[test]
    fn a_lookup_and_a_time_query_stay_with_the_gateway() {
        for port in [53, 123] {
            let datagram = frame::build_udp(
                Addr::new(10, 0, 177, 16),
                HOST_ADDRESS,
                40000,
                port,
                b"query",
            );
            assert!(
                to_host(
                    &guest_frame(frame::IPPROTO_UDP, &datagram),
                    &Forwarded::default()
                )
                .is_none(),
                "port {port} is answered by this process, not carried to the host"
            );
        }
        // Any other UDP port — a service, a game, an mDNS probe — is carried.
        let other = frame::build_udp(
            Addr::new(10, 0, 177, 16),
            HOST_ADDRESS,
            40000,
            5353,
            b"mdns",
        );
        assert!(to_host(
            &guest_frame(frame::IPPROTO_UDP, &other),
            &Forwarded::default()
        )
        .is_some());
    }

    /// The refusal itself: a reset **from the address the guest dialled**, for a new flow only.
    /// A guest that dials a door that leads into it gets the answer a refused connection gets
    /// anywhere else, and a frame that is not a dial gets nothing from this function.
    #[test]
    fn the_refusal_is_a_reset_from_the_address_the_guest_dialled() {
        let forwarded = Forwarded {
            host_ports: vec![2223],
            guest_ports: vec![crate::SSH_GUEST_PORT],
        };
        let dial = frame::build_tcp(
            Addr::new(10, 0, 177, 16),
            HOST_ADDRESS,
            44002,
            2223,
            1000,
            0,
            frame::TCP_SYN,
            65535,
            b"",
        );
        let no = refusal(&guest_frame(frame::IPPROTO_TCP, &dial), &forwarded).expect("a refusal");
        let ethernet = frame::parse_ethernet(&no).expect("a frame");
        let packet = frame::parse_ipv4(ethernet.payload).expect("a packet");
        assert_eq!(
            packet.src, HOST_ADDRESS,
            "from the address the guest dialled"
        );
        assert_eq!(
            packet.dst,
            Addr::new(10, 0, 177, 16),
            "to the guest's own flow"
        );
        let tcp = frame::parse_tcp(packet.payload).expect("a segment");
        assert_eq!(tcp.src_port, 2223);
        assert_eq!(tcp.dst_port, 44002);
        assert_eq!(
            tcp.flags & (frame::TCP_RST | frame::TCP_ACK),
            frame::TCP_RST | frame::TCP_ACK
        );

        // Not a dial: an ACK on a flow nobody has, and a dial of a port nobody forwarded.
        let ack = frame::build_tcp(
            Addr::new(10, 0, 177, 16),
            HOST_ADDRESS,
            44002,
            2223,
            1001,
            0,
            frame::TCP_ACK,
            65535,
            b"",
        );
        assert!(refusal(&guest_frame(frame::IPPROTO_TCP, &ack), &forwarded).is_none());
        let open = frame::build_tcp(
            Addr::new(10, 0, 177, 16),
            HOST_ADDRESS,
            44003,
            1919,
            1000,
            0,
            frame::TCP_SYN,
            65535,
            b"",
        );
        assert!(refusal(&guest_frame(frame::IPPROTO_TCP, &open), &forwarded).is_none());
        assert!(refusal(
            &guest_frame(frame::IPPROTO_TCP, &open),
            &Forwarded::default()
        )
        .is_none());
    }
}
