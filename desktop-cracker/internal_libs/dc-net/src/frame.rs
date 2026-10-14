//! The Ethernet/IPv4/TCP/UDP/ICMP/ARP codec the relay is built on.
//!
//! The machine's frames arrive on a unix socket, one datagram (or one length-prefixed stream packet)
//! at a time, and every one of them is ours to answer: there is no kernel network stack behind a
//! socket conduit. So this module is deliberately small, total and
//! boring — a parser that returns `Option` and never panics on a truncated or hostile frame, and
//! builders that compute the checksums the guest's stack will verify.
//!
//! Everything here is **one frame in, one frame out**: no state, no allocation beyond the bytes of the
//! answer, and no assumption that a frame is well formed. A guest is an untrusted operating system
//! , and a malformed frame must be a dropped counter, not a panic in this process.

use std::net::{Ipv4Addr, Ipv6Addr};

/// The ethertype of an IPv4 payload.
pub const ETHERTYPE_IPV4: u16 = 0x0800;
/// The ethertype of an ARP payload.
pub const ETHERTYPE_ARP: u16 = 0x0806;
/// The ethertype of an IPv6 payload (recognized only so it can be counted and dropped, ).
pub const ETHERTYPE_IPV6: u16 = 0x86dd;

/// The broadcast MAC address.
pub const BROADCAST_MAC: [u8; 6] = [0xff; 6];

/// ICMP (RFC 792).
pub const IPPROTO_ICMP: u8 = 1;
/// TCP (RFC 793).
pub const IPPROTO_TCP: u8 = 6;
/// UDP (RFC 768).
pub const IPPROTO_UDP: u8 = 17;
/// ICMPv6 (RFC 4443): NDP, echo and the v6 error messages all travel here.
pub const IPPROTO_ICMPV6: u8 = 58;

/// The IPv6 header's next-header values that are *extension* headers rather than transports: they
/// chain to the next header, and the relay walks them to find the transport it speaks.
const IPV6_EXTENSION_HEADERS: &[u8] = &[
    0,  // hop-by-hop options
    43, // routing
    44, // fragment
    51, // authentication header
    60, // destination options
];
/// The IPv6 header's next-header value for "no next header".
const IPPROTO_NONE: u8 = 59;

/// The link-layer prefix every IPv6 multicast address maps to (`33:33:` + the low 32 bits).
pub const IPV6_MULTICAST_MAC_PREFIX: [u8; 2] = [0x33, 0x33];

/// The all-nodes multicast address (`ff02::1`): every machine on the conduit.
pub const ALL_NODES_MULTICAST: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
/// The all-routers multicast address (`ff02::2`): the gateway.
pub const ALL_ROUTERS_MULTICAST: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 2);
/// The all-DHCP-servers multicast address (`ff02::1:2`): where a DHCPv6 client sends its requests.
pub const ALL_DHCP_SERVERS_MULTICAST: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 1, 2);

/// TCP flag: the connection is closing.
pub const TCP_FIN: u8 = 0x01;
/// TCP flag: synchronize sequence numbers.
pub const TCP_SYN: u8 = 0x02;
/// TCP flag: reset the connection.
pub const TCP_RST: u8 = 0x04;
/// TCP flag: push buffered data.
pub const TCP_PSH: u8 = 0x08;
/// TCP flag: the acknowledgement field is meaningful.
pub const TCP_ACK: u8 = 0x10;

/// The largest frame we will ever answer: a 1500-byte Ethernet payload plus the header.
pub const MAX_FRAME: usize = 1514;

/// An Ethernet II frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ethernet<'a> {
    /// The destination MAC.
    pub dst: [u8; 6],
    /// The source MAC.
    pub src: [u8; 6],
    /// The ethertype (what the payload is).
    pub ethertype: u16,
    /// The payload, borrowed from the frame.
    pub payload: &'a [u8],
}

/// Parse an Ethernet II frame; `None` for anything shorter than a header.
pub fn parse_ethernet(buf: &[u8]) -> Option<Ethernet<'_>> {
    if buf.len() < 14 {
        return None;
    }
    let mut dst = [0u8; 6];
    let mut src = [0u8; 6];
    dst.copy_from_slice(&buf[0..6]);
    src.copy_from_slice(&buf[6..12]);
    let ethertype = u16::from_be_bytes([buf[12], buf[13]]);
    Some(Ethernet {
        dst,
        src,
        ethertype,
        payload: &buf[14..],
    })
}

/// Build an Ethernet II frame around `payload`.
pub fn build_ethernet(dst: [u8; 6], src: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(14 + payload.len());
    frame.extend_from_slice(&dst);
    frame.extend_from_slice(&src);
    frame.extend_from_slice(&ethertype.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// An IPv4 packet (RFC 791), without options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4<'a> {
    /// The source address.
    pub src: Ipv4Addr,
    /// The destination address.
    pub dst: Ipv4Addr,
    /// The protocol of the payload.
    pub protocol: u8,
    /// The time to live.
    pub ttl: u8,
    /// The identification field.
    pub id: u16,
    /// The payload, borrowed from the packet.
    pub payload: &'a [u8],
}

/// Parse an IPv4 packet. IPv4 options are parsed over (the header length is honoured) and a
/// non-IPv4 or truncated packet is `None`.
pub fn parse_ipv4(buf: &[u8]) -> Option<Ipv4<'_>> {
    if buf.len() < 20 {
        return None;
    }
    if buf[0] >> 4 != 4 {
        return None;
    }
    let header_len = ((buf[0] & 0x0f) as usize) * 4;
    if header_len < 20 || buf.len() < header_len {
        return None;
    }
    let total_len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    // A packet whose total length claims more than we hold is truncated: drop it rather than hand a
    // short buffer to a protocol parser.
    if total_len < header_len || total_len > buf.len() {
        return None;
    }
    let id = u16::from_be_bytes([buf[4], buf[5]]);
    let ttl = buf[8];
    let protocol = buf[9];
    let src = Ipv4Addr::new(buf[12], buf[13], buf[14], buf[15]);
    let dst = Ipv4Addr::new(buf[16], buf[17], buf[18], buf[19]);
    Some(Ipv4 {
        src,
        dst,
        protocol,
        ttl,
        id,
        payload: &buf[header_len..total_len],
    })
}

/// Build an IPv4 packet (20-byte header, no options, checksum filled in).
pub fn build_ipv4(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, ttl: u8, payload: &[u8]) -> Vec<u8> {
    let total = 20 + payload.len();
    let mut packet = Vec::with_capacity(total);
    packet.push(0x45);
    packet.push(0);
    packet.extend_from_slice(&(total as u16).to_be_bytes());
    // The identification is a counter the caller does not need: a zero id is legal for a packet this
    // process fragments never (we never build a datagram bigger than the guest's MTU).
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.extend_from_slice(&0u16.to_be_bytes());
    packet.push(ttl);
    packet.push(protocol);
    packet.extend_from_slice(&[0, 0]);
    packet.extend_from_slice(&src.octets());
    packet.extend_from_slice(&dst.octets());
    packet.extend_from_slice(payload);
    let sum = checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&sum.to_be_bytes());
    packet
}

/// A TCP segment (RFC 793), without options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tcp<'a> {
    /// The source port.
    pub src_port: u16,
    /// The destination port.
    pub dst_port: u16,
    /// The sequence number.
    pub seq: u32,
    /// The acknowledgement number.
    pub ack: u32,
    /// The flags (see [`TCP_SYN`] and friends).
    pub flags: u8,
    /// The advertised window.
    pub window: u16,
    /// The payload, borrowed from the segment.
    pub payload: &'a [u8],
}

impl Tcp<'_> {
    /// Whether a flag is set.
    pub fn has(&self, flag: u8) -> bool {
        self.flags & flag != 0
    }
}

/// Parse a TCP segment. Options are parsed over (the data offset is honoured).
pub fn parse_tcp(buf: &[u8]) -> Option<Tcp<'_>> {
    if buf.len() < 20 {
        return None;
    }
    let header_len = ((buf[12] >> 4) as usize) * 4;
    if header_len < 20 || buf.len() < header_len {
        return None;
    }
    Some(Tcp {
        src_port: u16::from_be_bytes([buf[0], buf[1]]),
        dst_port: u16::from_be_bytes([buf[2], buf[3]]),
        seq: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
        ack: u32::from_be_bytes([buf[8], buf[9], buf[10], buf[11]]),
        flags: buf[13],
        window: u16::from_be_bytes([buf[14], buf[15]]),
        payload: &buf[header_len..],
    })
}

/// Build a TCP segment (20-byte header plus `options`), with the checksum filled in.
///
/// The argument list is the header's own fields in the order they go on the wire, which is what a
/// caller building a segment by hand wants to read: one parameter per field, no structure to
/// unpack.
#[allow(clippy::too_many_arguments)]
pub fn build_tcp(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut segment = Vec::with_capacity(20 + payload.len());
    segment.extend_from_slice(&src_port.to_be_bytes());
    segment.extend_from_slice(&dst_port.to_be_bytes());
    segment.extend_from_slice(&seq.to_be_bytes());
    segment.extend_from_slice(&ack.to_be_bytes());
    segment.push(0x50); // 5 words of header, no options
    segment.push(flags);
    segment.extend_from_slice(&window.to_be_bytes());
    segment.extend_from_slice(&[0, 0]); // checksum, filled below
    segment.extend_from_slice(&[0, 0]); // urgent pointer
    segment.extend_from_slice(payload);
    let sum = transport_checksum(src, dst, IPPROTO_TCP, &segment);
    segment[16..18].copy_from_slice(&sum.to_be_bytes());
    segment
}

/// A UDP datagram (RFC 768).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Udp<'a> {
    /// The source port.
    pub src_port: u16,
    /// The destination port.
    pub dst_port: u16,
    /// The payload, borrowed from the datagram.
    pub payload: &'a [u8],
}

/// Parse a UDP datagram.
pub fn parse_udp(buf: &[u8]) -> Option<Udp<'_>> {
    if buf.len() < 8 {
        return None;
    }
    let length = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    if length < 8 || length > buf.len() {
        return None;
    }
    Some(Udp {
        src_port: u16::from_be_bytes([buf[0], buf[1]]),
        dst_port: u16::from_be_bytes([buf[2], buf[3]]),
        payload: &buf[8..length],
    })
}

/// Build a UDP datagram with its checksum filled in.
pub fn build_udp(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let length = 8 + payload.len();
    let mut datagram = Vec::with_capacity(length);
    datagram.extend_from_slice(&src_port.to_be_bytes());
    datagram.extend_from_slice(&dst_port.to_be_bytes());
    datagram.extend_from_slice(&(length as u16).to_be_bytes());
    datagram.extend_from_slice(&[0, 0]); // checksum, filled below
    datagram.extend_from_slice(payload);
    let sum = transport_checksum(src, dst, IPPROTO_UDP, &datagram);
    // A UDP checksum of zero means "no checksum": send the all-ones form instead.
    let sum = if sum == 0 { 0xffff } else { sum };
    datagram[6..8].copy_from_slice(&sum.to_be_bytes());
    datagram
}

/// An ICMP message (RFC 792), the first four bytes of its body kept as a unit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Icmp<'a> {
    /// The message type (8 = echo request, 0 = echo reply, 3 = unreachable).
    pub kind: u8,
    /// The code, meaningful per type.
    pub code: u8,
    /// The four bytes after the checksum: identifier and sequence for an echo.
    pub rest: [u8; 4],
    /// The data after those four bytes.
    pub payload: &'a [u8],
}

/// Parse an ICMP message.
pub fn parse_icmp(buf: &[u8]) -> Option<Icmp<'_>> {
    if buf.len() < 8 {
        return None;
    }
    Some(Icmp {
        kind: buf[0],
        code: buf[1],
        rest: [buf[4], buf[5], buf[6], buf[7]],
        payload: &buf[8..],
    })
}

/// Build an echo **reply** to an echo request: type 0, the same identifier, sequence and data.
pub fn build_icmp_echo_reply(request: &[u8]) -> Option<Vec<u8>> {
    let parsed = parse_icmp(request)?;
    if parsed.kind != 8 {
        return None;
    }
    let mut reply = Vec::with_capacity(request.len());
    reply.push(0);
    reply.push(0);
    reply.extend_from_slice(&[0, 0]); // checksum, filled below
    reply.extend_from_slice(&parsed.rest);
    reply.extend_from_slice(parsed.payload);
    let sum = checksum(&reply);
    reply[2..4].copy_from_slice(&sum.to_be_bytes());
    Some(reply)
}

/// Build an echo request (used by our own reachability checks, and by tests).
pub fn build_icmp_echo_request(id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut request = Vec::with_capacity(8 + payload.len());
    request.push(8);
    request.push(0);
    request.extend_from_slice(&[0, 0]);
    request.extend_from_slice(&id.to_be_bytes());
    request.extend_from_slice(&seq.to_be_bytes());
    request.extend_from_slice(payload);
    let sum = checksum(&request);
    request[2..4].copy_from_slice(&sum.to_be_bytes());
    request
}

/// An IPv6 packet (RFC 8200), with its extension-header chain already walked.
///
/// `next_header` is the **transport** (TCP, UDP or ICMPv6) and `payload` is that transport's bytes,
/// whatever extension headers sat between the fixed header and it. IPv6 has no header checksum, so a
/// packet is "valid" only once its transport checksum (which covers the pseudo-header) is verified —
/// which is why the builders here and [`transport_checksum_v6`] take the addresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6<'a> {
    /// The source address.
    pub src: Ipv6Addr,
    /// The destination address.
    pub dst: Ipv6Addr,
    /// The transport protocol, after the extension headers.
    pub next_header: u8,
    /// The hop limit.
    pub hop_limit: u8,
    /// The transport bytes.
    pub payload: &'a [u8],
}

/// Parse an IPv6 packet, walking the extension headers to the transport.
///
/// `None` for anything this relay will not speak: not IPv6, truncated, a chain that never ends, or a
/// **fragment** (reassembly is not implemented — a guest's fragments are counted and dropped, ``).
pub fn parse_ipv6(buf: &[u8]) -> Option<Ipv6<'_>> {
    if buf.len() < 40 || buf[0] >> 4 != 6 {
        return None;
    }
    let payload_len = u16::from_be_bytes([buf[4], buf[5]]) as usize;
    // A payload length of zero means either an empty packet or a jumbogram (via a hop-by-hop option):
    // jumbograms are refused, and an empty payload is nothing to parse.
    if payload_len == 0 {
        return None;
    }
    let end = 40usize.checked_add(payload_len)?;
    if end > buf.len() {
        return None;
    }
    let src = Ipv6Addr::from(<[u8; 16]>::try_from(&buf[8..24]).ok()?);
    let dst = Ipv6Addr::from(<[u8; 16]>::try_from(&buf[24..40]).ok()?);
    let hop_limit = buf[7];
    let mut next_header = buf[6];
    let mut offset = 40usize;
    // At most a handful of extension headers: a chain longer than this is not something a guest sends,
    // and refusing it keeps a hostile frame from walking us through the whole packet.
    for _ in 0..8 {
        if next_header == IPPROTO_NONE {
            return None;
        }
        if !IPV6_EXTENSION_HEADERS.contains(&next_header) {
            return Some(Ipv6 {
                src,
                dst,
                next_header,
                hop_limit,
                payload: &buf[offset..end],
            });
        }
        if offset + 2 > end {
            return None;
        }
        match next_header {
            // The fragment header is fixed at eight bytes; a non-zero offset is not the first
            // fragment, and a first fragment is still not a transport we can parse safely.
            44 => return None,
            // The authentication header counts in four-byte units, plus two.
            51 => {
                let length = (buf[offset + 1] as usize + 2) * 4;
                if length < 8 || offset + length > end {
                    return None;
                }
                next_header = buf[offset];
                offset += length;
            }
            // Hop-by-hop, routing and destination options count in eight-byte units, plus one.
            _ => {
                let length = (buf[offset + 1] as usize + 1) * 8;
                if length < 8 || offset + length > end {
                    return None;
                }
                next_header = buf[offset];
                offset += length;
            }
        }
    }
    None
}

/// Build an IPv6 packet (fixed header, no extension headers).
pub fn build_ipv6(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    next_header: u8,
    hop_limit: u8,
    payload: &[u8],
) -> Vec<u8> {
    let mut packet = Vec::with_capacity(40 + payload.len());
    packet.push(0x60);
    // The traffic class and flow label are zero: this relay does not classify or shape traffic.
    packet.extend_from_slice(&[0, 0, 0]);
    packet.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    packet.push(next_header);
    packet.push(hop_limit);
    packet.extend_from_slice(&src.octets());
    packet.extend_from_slice(&dst.octets());
    packet.extend_from_slice(payload);
    packet
}

/// The checksum of a transport segment over the IPv6 pseudo-header (RFC 8200 ).
///
/// Unlike IPv4 there is no "checksum optional": UDP and ICMPv6 both **must** carry one, and a receiver
/// that computes a different value drops the packet without a word.
pub fn transport_checksum_v6(src: Ipv6Addr, dst: Ipv6Addr, next_header: u8, segment: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + segment.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&(segment.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, next_header]);
    pseudo.extend_from_slice(segment);
    checksum(&pseudo)
}

/// Build a TCP segment for IPv6, with the pseudo-header checksum filled in.
/// The same segment over IPv6 (the checksum covers an IPv6 pseudo-header; the fields are the
/// same, in the same order).
#[allow(clippy::too_many_arguments)]
pub fn build_tcp_v6(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    window: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut segment = Vec::with_capacity(20 + payload.len());
    segment.extend_from_slice(&src_port.to_be_bytes());
    segment.extend_from_slice(&dst_port.to_be_bytes());
    segment.extend_from_slice(&seq.to_be_bytes());
    segment.extend_from_slice(&ack.to_be_bytes());
    segment.push(0x50);
    segment.push(flags);
    segment.extend_from_slice(&window.to_be_bytes());
    segment.extend_from_slice(&[0, 0]);
    segment.extend_from_slice(&[0, 0]);
    segment.extend_from_slice(payload);
    let sum = transport_checksum_v6(src, dst, IPPROTO_TCP, &segment);
    segment[16..18].copy_from_slice(&sum.to_be_bytes());
    segment
}

/// Build a UDP datagram for IPv6, with its mandatory checksum filled in.
pub fn build_udp_v6(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let length = 8 + payload.len();
    let mut datagram = Vec::with_capacity(length);
    datagram.extend_from_slice(&src_port.to_be_bytes());
    datagram.extend_from_slice(&dst_port.to_be_bytes());
    datagram.extend_from_slice(&(length as u16).to_be_bytes());
    datagram.extend_from_slice(&[0, 0]);
    datagram.extend_from_slice(payload);
    // Zero is not "no checksum" in IPv6: the all-ones form is the one that means a computed zero.
    let sum = transport_checksum_v6(src, dst, IPPROTO_UDP, &datagram);
    datagram[6..8].copy_from_slice(&(if sum == 0 { 0xffff } else { sum }).to_be_bytes());
    datagram
}

/// Build an ICMPv6 message with the checksum the pseudo-header demands.
///
/// `body` is everything after the four-byte type/code/checksum header (for NDP: the flags, addresses
/// and options; for echo: the identifier, sequence and data).
pub fn build_icmpv6(src: Ipv6Addr, dst: Ipv6Addr, kind: u8, code: u8, body: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(4 + body.len());
    message.push(kind);
    message.push(code);
    message.extend_from_slice(&[0, 0]);
    message.extend_from_slice(body);
    let sum = transport_checksum_v6(src, dst, IPPROTO_ICMPV6, &message);
    message[2..4].copy_from_slice(&sum.to_be_bytes());
    message
}

/// An ICMPv6 message: the same four-byte header ICMP has, over IPv6.
///
/// `rest` is the four bytes after the checksum — for an echo, the identifier and sequence; for a
/// Neighbor Solicitation or Advertisement, the flags and the first half of the target address. The
/// callers that need more read it from `payload`.
pub fn parse_icmpv6(buf: &[u8]) -> Option<Icmp<'_>> {
    parse_icmp(buf)
}

/// Build an ICMPv6 echo **reply** to an echo request, with the identifier, sequence and data intact.
pub fn build_icmpv6_echo_reply(src: Ipv6Addr, dst: Ipv6Addr, request: &[u8]) -> Option<Vec<u8>> {
    let parsed = parse_icmpv6(request)?;
    if parsed.kind != 128 {
        return None;
    }
    let mut body = Vec::with_capacity(4 + parsed.payload.len());
    body.extend_from_slice(&parsed.rest);
    body.extend_from_slice(parsed.payload);
    Some(build_icmpv6(src, dst, 129, 0, &body))
}

/// Build an ICMPv6 echo request (our own reachability checks, and the tests).
pub fn build_icmpv6_echo_request(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    id: u16,
    seq: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut body = Vec::with_capacity(4 + payload.len());
    body.extend_from_slice(&id.to_be_bytes());
    body.extend_from_slice(&seq.to_be_bytes());
    body.extend_from_slice(payload);
    build_icmpv6(src, dst, 128, 0, &body)
}

/// The Ethernet MAC an IPv6 multicast address maps to (`33:33:` + the low 32 bits, RFC 2464).
pub fn multicast_mac(address: Ipv6Addr) -> [u8; 6] {
    let octets = address.octets();
    [
        IPV6_MULTICAST_MAC_PREFIX[0],
        IPV6_MULTICAST_MAC_PREFIX[1],
        octets[12],
        octets[13],
        octets[14],
        octets[15],
    ]
}

/// The solicited-node multicast address of `address` (`ff02::1:ffXX:XXXX`): where a Neighbor
/// Solicitation goes, and therefore which MAC a guest's NS frame is sent to.
pub fn solicited_node_multicast(address: Ipv6Addr) -> Ipv6Addr {
    let octets = address.octets();
    Ipv6Addr::new(
        0xff02,
        0,
        0,
        0,
        0,
        1,
        0xff00 | octets[13] as u16,
        ((octets[14] as u16) << 8) | octets[15] as u16,
    )
}

/// The modified EUI-64 interface identifier of a MAC address (RFC 4291): the link-local address a
/// guest forms for itself is `fe80::` plus this.
pub fn eui64_interface_id(mac: [u8; 6]) -> [u8; 8] {
    [
        mac[0] ^ 0x02,
        mac[1],
        mac[2],
        0xff,
        0xfe,
        mac[3],
        mac[4],
        mac[5],
    ]
}

/// The link-local address a machine with `mac` forms (`fe80::` + the modified EUI-64).
pub fn link_local_of(mac: [u8; 6]) -> Ipv6Addr {
    let iid = eui64_interface_id(mac);
    let mut octets = [0u8; 16];
    octets[0] = 0xfe;
    octets[1] = 0x80;
    octets[8..16].copy_from_slice(&iid);
    Ipv6Addr::from(octets)
}

/// A whole IPv6 answer to the guest: Ethernet + IPv6 + the transport payload already built.
pub fn ipv6_to_guest(
    guest_mac: [u8; 6],
    our_mac: [u8; 6],
    our_ip: Ipv6Addr,
    guest_ip: Ipv6Addr,
    next_header: u8,
    payload: &[u8],
) -> Vec<u8> {
    let packet = build_ipv6(our_ip, guest_ip, next_header, 64, payload);
    frame_to_guest(guest_mac, our_mac, ETHERTYPE_IPV6, &packet)
}

/// An ARP message (RFC 826) for Ethernet/IPv4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Arp {
    /// 1 = request, 2 = reply.
    pub op: u16,
    /// The sender's hardware address.
    pub sender_mac: [u8; 6],
    /// The sender's protocol address.
    pub sender_ip: Ipv4Addr,
    /// The target's hardware address (zero in a request).
    pub target_mac: [u8; 6],
    /// The target's protocol address.
    pub target_ip: Ipv4Addr,
}

/// An ARP request.
pub const ARP_REQUEST: u16 = 1;
/// An ARP reply.
pub const ARP_REPLY: u16 = 2;

/// Parse an ARP message. Anything that is not Ethernet/IPv4 ARP is `None`.
pub fn parse_arp(buf: &[u8]) -> Option<Arp> {
    if buf.len() < 28 {
        return None;
    }
    let htype = u16::from_be_bytes([buf[0], buf[1]]);
    let ptype = u16::from_be_bytes([buf[2], buf[3]]);
    if htype != 1 || ptype != ETHERTYPE_IPV4 {
        return None;
    }
    if buf[4] != 6 || buf[5] != 4 {
        return None;
    }
    let mut sender_mac = [0u8; 6];
    let mut target_mac = [0u8; 6];
    sender_mac.copy_from_slice(&buf[8..14]);
    target_mac.copy_from_slice(&buf[18..24]);
    Some(Arp {
        op: u16::from_be_bytes([buf[6], buf[7]]),
        sender_mac,
        sender_ip: Ipv4Addr::new(buf[14], buf[15], buf[16], buf[17]),
        target_mac,
        target_ip: Ipv4Addr::new(buf[24], buf[25], buf[26], buf[27]),
    })
}

/// Build the ARP payload (not the frame) for an answer to `request`, from `our_mac` and `our_ip`.
pub fn build_arp_reply(request: &Arp, our_mac: [u8; 6], our_ip: Ipv4Addr) -> Vec<u8> {
    let mut arp = Vec::with_capacity(28);
    arp.extend_from_slice(&1u16.to_be_bytes());
    arp.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    arp.push(6);
    arp.push(4);
    arp.extend_from_slice(&ARP_REPLY.to_be_bytes());
    arp.extend_from_slice(&our_mac);
    arp.extend_from_slice(&our_ip.octets());
    arp.extend_from_slice(&request.sender_mac);
    arp.extend_from_slice(&request.sender_ip.octets());
    arp
}

/// Build the ARP payload for a request asking who holds `target_ip`.
pub fn build_arp_request(our_mac: [u8; 6], our_ip: Ipv4Addr, target_ip: Ipv4Addr) -> Vec<u8> {
    let mut arp = Vec::with_capacity(28);
    arp.extend_from_slice(&1u16.to_be_bytes());
    arp.extend_from_slice(&ETHERTYPE_IPV4.to_be_bytes());
    arp.push(6);
    arp.push(4);
    arp.extend_from_slice(&ARP_REQUEST.to_be_bytes());
    arp.extend_from_slice(&our_mac);
    arp.extend_from_slice(&our_ip.octets());
    arp.extend_from_slice(&[0u8; 6]);
    arp.extend_from_slice(&target_ip.octets());
    arp
}

/// Rewrite an IPv4 packet's addresses and (for TCP/UDP) its ports, recomputing every checksum that
/// covers them.
///
/// What a published port needs: a flow to the gateway becomes a flow to the peer that holds the
/// port, and a flow from that peer becomes a flow from the gateway. Nothing else about the packet moves —
/// not the sequence numbers, not the flags, not the length — so the two ends each see an ordinary
/// connection.
///
/// `None` when the packet cannot be rewritten honestly: a **fragment** other than the first carries no
/// transport header (so its ports cannot be named), and a transport segment too short to hold one is not
/// something to guess at. The caller drops those and says so in its counters rather than forwarding a
/// packet that would arrive with the wrong port.
pub fn translate_ipv4(
    payload: &[u8],
    src: Ipv4Addr,
    dst: Ipv4Addr,
    src_port: Option<u16>,
    dst_port: Option<u16>,
) -> Option<Vec<u8>> {
    let packet = parse_ipv4(payload)?;
    // The fragment field: offset in the low 13 bits, `MF` above it. Only the first fragment of an
    // unfragmented packet carries the ports, and only that one can be rewritten.
    let fragment = u16::from_be_bytes([*payload.get(6)?, *payload.get(7)?]);
    if fragment & 0x1fff != 0 || fragment & 0x2000 != 0 {
        return None;
    }
    let header_len = ((payload[0] & 0x0f) as usize) * 4;
    if header_len < 20 || payload.len() < header_len {
        return None;
    }
    let mut out = payload.to_vec();
    out[12..16].copy_from_slice(&src.octets());
    out[16..20].copy_from_slice(&dst.octets());
    out[10] = 0;
    out[11] = 0;
    let header = checksum(&out[..header_len]);
    out[10..12].copy_from_slice(&header.to_be_bytes());

    let segment = &mut out[header_len..];
    match packet.protocol {
        IPPROTO_TCP if segment.len() >= 20 => {
            if let Some(port) = src_port {
                segment[0..2].copy_from_slice(&port.to_be_bytes());
            }
            if let Some(port) = dst_port {
                segment[2..4].copy_from_slice(&port.to_be_bytes());
            }
            segment[16] = 0;
            segment[17] = 0;
            let sum = transport_checksum(src, dst, IPPROTO_TCP, segment);
            // A computed zero is written as `0xffff`: zero means "no checksum" to a receiver of UDP, and
            // TCP's checksum of zero is a value it computes to `0xffff` anyway.
            let sum = if sum == 0 { 0xffff } else { sum };
            segment[16..18].copy_from_slice(&sum.to_be_bytes());
        }
        IPPROTO_UDP if segment.len() >= 8 => {
            if let Some(port) = src_port {
                segment[0..2].copy_from_slice(&port.to_be_bytes());
            }
            if let Some(port) = dst_port {
                segment[2..4].copy_from_slice(&port.to_be_bytes());
            }
            // An IPv4 UDP checksum of zero means "not computed" and stays that way: there is nothing to
            // recompute and a receiver will not check it.
            if segment[6] != 0 || segment[7] != 0 {
                segment[6] = 0;
                segment[7] = 0;
                let sum = transport_checksum(src, dst, IPPROTO_UDP, segment);
                let sum = if sum == 0 { 0xffff } else { sum };
                segment[6..8].copy_from_slice(&sum.to_be_bytes());
            }
        }
        _ => {}
    }
    Some(out)
}

/// The internet checksum (RFC 1071) over `data`.
pub fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut chunks = data.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        sum += u16::from_be_bytes([*last, 0]) as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// The checksum of a transport segment, over the IPv4 pseudo-header (RFC 793).
pub fn transport_checksum(src: Ipv4Addr, dst: Ipv4Addr, protocol: u8, segment: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + segment.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(protocol);
    pseudo.extend_from_slice(&(segment.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(segment);
    checksum(&pseudo)
}

/// A whole answer, ready to write on the conduit: the Ethernet frame for `payload` from us to the
/// guest.
pub fn frame_to_guest(
    guest_mac: [u8; 6],
    our_mac: [u8; 6],
    ethertype: u16,
    payload: &[u8],
) -> Vec<u8> {
    build_ethernet(guest_mac, our_mac, ethertype, payload)
}

/// A whole IPv4 answer to the guest: Ethernet + IPv4 (+ the transport payload already built).
pub fn ipv4_to_guest(
    guest_mac: [u8; 6],
    our_mac: [u8; 6],
    our_ip: Ipv4Addr,
    guest_ip: Ipv4Addr,
    protocol: u8,
    payload: &[u8],
) -> Vec<u8> {
    let packet = build_ipv4(our_ip, guest_ip, protocol, 64, payload);
    frame_to_guest(guest_mac, our_mac, ETHERTYPE_IPV4, &packet)
}

/// Whether a MAC is the broadcast address (or a multicast address, which we never join).
pub fn is_broadcast_or_multicast(mac: &[u8; 6]) -> bool {
    mac[0] & 1 == 1
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(text: &str) -> Ipv4Addr {
        text.parse().expect("a valid address")
    }

    #[test]
    fn an_ethernet_frame_round_trips() {
        let frame = build_ethernet(
            [1, 2, 3, 4, 5, 6],
            [7, 8, 9, 10, 11, 12],
            ETHERTYPE_IPV4,
            b"payload",
        );
        let parsed = parse_ethernet(&frame).expect("parses");
        assert_eq!(parsed.dst, [1, 2, 3, 4, 5, 6]);
        assert_eq!(parsed.src, [7, 8, 9, 10, 11, 12]);
        assert_eq!(parsed.ethertype, ETHERTYPE_IPV4);
        assert_eq!(parsed.payload, b"payload");

        // A truncated frame is refused, and the shortest legal one is not.
        assert!(
            parse_ethernet(&frame[..13]).is_none(),
            "a frame shorter than the header is refused"
        );
        assert!(parse_ethernet(&[0u8; 14]).is_some());
    }

    #[test]
    fn an_ipv4_packet_round_trips_with_a_valid_checksum() {
        // The builder must produce a header a real stack accepts: the kernel's check is that the
        // checksum over the header (with the checksum field in place) is zero.
        let payload = b"hello";
        let packet = build_ipv4(ip("10.177.0.1"), ip("10.177.0.2"), IPPROTO_UDP, 64, payload);
        assert_eq!(checksum(&packet[..20]), 0, "the header checksum verifies");
        let parsed = parse_ipv4(&packet).expect("parses");
        assert_eq!(parsed.src, ip("10.177.0.1"));
        assert_eq!(parsed.dst, ip("10.177.0.2"));
        assert_eq!(parsed.protocol, IPPROTO_UDP);
        assert_eq!(parsed.ttl, 64);
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn a_truncated_or_hostile_packet_is_dropped_rather_than_panicking() {
        // A guest is an untrusted operating system: every one of these must be a quiet `None`.
        assert!(parse_ipv4(&[]).is_none());
        assert!(parse_ipv4(&[0u8; 19]).is_none(), "shorter than a header");
        assert!(parse_ipv4(&[0x60; 20]).is_none(), "not IPv4");
        let mut short_header = build_ipv4(ip("10.0.0.1"), ip("10.0.0.2"), IPPROTO_TCP, 64, b"x");
        short_header[0] = 0x40; // an IHL of zero
        assert!(parse_ipv4(&short_header).is_none());
        let mut liar = build_ipv4(ip("10.0.0.1"), ip("10.0.0.2"), IPPROTO_TCP, 64, b"x");
        // The total-length field claims 900 bytes while the buffer holds 21.
        liar[2..4].copy_from_slice(&900u16.to_be_bytes());
        assert!(
            parse_ipv4(&liar).is_none(),
            "a length beyond the buffer is refused"
        );

        assert!(parse_tcp(&[0u8; 19]).is_none());
        let mut bad_offset = build_tcp(
            ip("10.0.0.1"),
            ip("10.0.0.2"),
            1,
            2,
            0,
            0,
            TCP_SYN,
            1024,
            b"",
        );
        bad_offset[12] = 0x10; // a data offset of one word
        assert!(parse_tcp(&bad_offset).is_none());
        assert!(parse_udp(&[0u8; 7]).is_none());
        assert!(parse_icmp(&[0u8; 7]).is_none());
        assert!(parse_arp(&[0u8; 27]).is_none());
    }

    #[test]
    fn a_tcp_segment_round_trips_with_a_valid_checksum() {
        let payload = b"GET / HTTP/1.0\r\n\r\n";
        let segment = build_tcp(
            ip("10.177.0.2"),
            ip("93.184.216.34"),
            40000,
            80,
            1000,
            2000,
            TCP_ACK | TCP_PSH,
            64240,
            payload,
        );
        // A stack checks the checksum by verifying that the pseudo-header sum is zero.
        assert_eq!(
            transport_checksum(ip("10.177.0.2"), ip("93.184.216.34"), IPPROTO_TCP, &segment),
            0,
            "the segment checksum verifies",
        );
        let parsed = parse_tcp(&segment).expect("parses");
        assert_eq!(parsed.src_port, 40000);
        assert_eq!(parsed.dst_port, 80);
        assert_eq!(parsed.seq, 1000);
        assert_eq!(parsed.ack, 2000);
        assert!(parsed.has(TCP_ACK) && parsed.has(TCP_PSH) && !parsed.has(TCP_SYN));
        assert_eq!(parsed.payload, payload);
    }

    #[test]
    fn a_udp_datagram_round_trips_and_never_sends_a_zero_checksum() {
        let payload = b"\x12\x34\x01\x00";
        let datagram = build_udp(ip("10.177.0.2"), ip("10.177.0.1"), 68, 67, payload);
        assert_eq!(
            transport_checksum(ip("10.177.0.2"), ip("10.177.0.1"), IPPROTO_UDP, &datagram),
            0,
            "the datagram checksum verifies",
        );
        let parsed = parse_udp(&datagram).expect("parses");
        assert_eq!(parsed.src_port, 68);
        assert_eq!(parsed.dst_port, 67);
        assert_eq!(parsed.payload, payload);
        // A checksum computed as zero must be sent as all ones, or the receiver reads it as "absent".
        assert_ne!(&datagram[6..8], &[0, 0]);
    }

    #[test]
    fn an_icmp_echo_request_gets_a_matching_reply() {
        let request = build_icmp_echo_request(0x1234, 7, b"abcdef");
        assert_eq!(checksum(&request), 0, "a request we build verifies too");
        let reply = build_icmp_echo_reply(&request).expect("an echo request is answered");
        let parsed = parse_icmp(&reply).expect("parses");
        assert_eq!(parsed.kind, 0, "an echo reply");
        assert_eq!(
            parsed.rest,
            [0x12, 0x34, 0x00, 0x07],
            "the identifier and sequence come back"
        );
        assert_eq!(parsed.payload, b"abcdef");
        assert_eq!(checksum(&reply), 0, "and the reply's checksum verifies");

        // Something that is not an echo request is not answered by this builder.
        assert!(build_icmp_echo_reply(&[3, 0, 0, 0, 0, 0, 0, 0]).is_none());
    }

    #[test]
    fn an_arp_request_is_answered_with_the_askers_details_reversed() {
        let request_payload = build_arp_request([0xaa; 6], ip("10.177.0.2"), ip("10.177.0.1"));
        let request = parse_arp(&request_payload).expect("parses");
        assert_eq!(request.op, ARP_REQUEST);
        assert_eq!(request.sender_ip, ip("10.177.0.2"));
        assert_eq!(request.target_ip, ip("10.177.0.1"));
        assert_eq!(
            request.target_mac, [0; 6],
            "a request asks, it does not tell"
        );

        let reply =
            parse_arp(&build_arp_reply(&request, [0xbb; 6], ip("10.177.0.1"))).expect("parses");
        assert_eq!(reply.op, ARP_REPLY);
        assert_eq!(reply.sender_mac, [0xbb; 6]);
        assert_eq!(reply.sender_ip, ip("10.177.0.1"));
        assert_eq!(
            reply.target_mac, [0xaa; 6],
            "the reply is addressed to the asker"
        );
        assert_eq!(reply.target_ip, ip("10.177.0.2"));
    }

    #[test]
    fn a_whole_answer_to_the_guest_is_one_frame_away() {
        // The shape every DHCP/ARP/ICMP answer takes: Ethernet + IPv4 + the payload, addressed to the
        // guest's MAC from ours.
        let udp = build_udp(ip("10.177.0.1"), ip("10.177.0.2"), 67, 68, b"dhcp");
        let frame = ipv4_to_guest(
            [1, 1, 1, 1, 1, 1],
            [2, 2, 2, 2, 2, 2],
            ip("10.177.0.1"),
            ip("10.177.0.2"),
            IPPROTO_UDP,
            &udp,
        );
        let ethernet = parse_ethernet(&frame).expect("a frame");
        assert_eq!(ethernet.dst, [1, 1, 1, 1, 1, 1]);
        assert_eq!(ethernet.src, [2, 2, 2, 2, 2, 2]);
        assert_eq!(ethernet.ethertype, ETHERTYPE_IPV4);
        let packet = parse_ipv4(ethernet.payload).expect("a packet");
        assert_eq!(packet.dst, ip("10.177.0.2"));
        assert_eq!(
            parse_udp(packet.payload).expect("a datagram").payload,
            b"dhcp"
        );
    }

    #[test]
    fn an_ipv6_packet_round_trips_and_its_checksums_are_mandatory() {
        let src = "fd10:177::1".parse::<Ipv6Addr>().expect("an address");
        let dst = "fd10:177::16".parse::<Ipv6Addr>().expect("an address");
        let datagram = build_udp_v6(src, dst, 547, 546, b"dhcpv6");
        // A v6 receiver verifies the checksum by summing the pseudo-header and the segment to zero.
        assert_eq!(
            transport_checksum_v6(src, dst, IPPROTO_UDP, &datagram),
            0,
            "the datagram checksum verifies"
        );
        assert_ne!(
            &datagram[6..8],
            &[0, 0],
            "and IPv6 never sends the 'no checksum' form"
        );
        let packet = build_ipv6(src, dst, IPPROTO_UDP, 64, &datagram);
        let parsed = parse_ipv6(&packet).expect("parses");
        assert_eq!(parsed.src, src);
        assert_eq!(parsed.dst, dst);
        assert_eq!(parsed.next_header, IPPROTO_UDP);
        assert_eq!(parsed.hop_limit, 64);
        assert_eq!(
            parse_udp(parsed.payload).expect("a datagram").payload,
            b"dhcpv6"
        );
    }

    #[test]
    fn an_icmpv6_message_carries_the_pseudo_header_checksum() {
        let our = "fe80::5054:ff:fe00:1"
            .parse::<Ipv6Addr>()
            .expect("an address");
        let guest = "fe80::5054:ff:feaa:bbcc"
            .parse::<Ipv6Addr>()
            .expect("an address");
        let request = build_icmpv6_echo_request(guest, our, 0x1234, 7, b"hello");
        assert_eq!(
            transport_checksum_v6(guest, our, IPPROTO_ICMPV6, &request),
            0,
            "the ICMPv6 checksum covers the pseudo-header, and it verifies",
        );
        let reply =
            build_icmpv6_echo_reply(our, guest, &request).expect("an echo request is answered");
        let parsed = parse_icmpv6(&reply).expect("parses");
        assert_eq!(parsed.kind, 129, "an echo reply");
        assert_eq!(parsed.rest, [0x12, 0x34, 0x00, 0x07]);
        assert_eq!(parsed.payload, b"hello");
        assert_eq!(transport_checksum_v6(our, guest, IPPROTO_ICMPV6, &reply), 0);
        assert!(
            build_icmpv6_echo_reply(our, guest, &build_icmpv6(our, guest, 133, 0, &[])).is_none(),
            "not an echo"
        );
    }

    #[test]
    fn the_extension_header_chain_is_walked_to_the_transport() {
        // Hop-by-hop options, then TCP: the parser must find TCP and hand back the segment.
        let src = "fd10:177::16".parse::<Ipv6Addr>().unwrap();
        let dst = "2606:2800:220:1:248:1893:25c8:1946"
            .parse::<Ipv6Addr>()
            .unwrap();
        let segment = build_tcp_v6(src, dst, 40000, 443, 1, 0, TCP_SYN, 1024, b"");
        let hop_by_hop = [IPPROTO_TCP, 0, 0, 0, 0, 0, 0, 0];
        let mut payload = hop_by_hop.to_vec();
        payload.extend_from_slice(&segment);
        let packet = build_ipv6(src, dst, 0, 64, &payload);
        let parsed = parse_ipv6(&packet).expect("the chain is walked");
        assert_eq!(
            parsed.next_header, IPPROTO_TCP,
            "past the hop-by-hop header"
        );
        assert_eq!(parse_tcp(parsed.payload).expect("a segment").dst_port, 443);
        // The same for a destination-options header after a routing header.
        let routing = [60u8, 0, 0, 0, 0, 0, 0, 0];
        let destination = [IPPROTO_UDP, 0, 0, 0, 0, 0, 0, 0];
        let mut payload = routing.to_vec();
        payload.extend_from_slice(&destination);
        payload.extend_from_slice(&build_udp_v6(src, dst, 5353, 53, b"q"));
        let packet = build_ipv6(src, dst, 43, 64, &payload);
        let parsed = parse_ipv6(&packet).expect("two extension headers are walked");
        assert_eq!(parsed.next_header, IPPROTO_UDP);
    }

    #[test]
    fn an_ipv6_frame_we_will_not_speak_is_refused_rather_than_mis_read() {
        let src = "fd10:177::1".parse::<Ipv6Addr>().unwrap();
        let dst = "fd10:177::16".parse::<Ipv6Addr>().unwrap();
        let segment = build_tcp_v6(src, dst, 1, 2, 0, 0, 0, 1024, b"x");
        // A fragment: reassembly is not implemented, so neither the first fragment nor a later one is
        // handed to a transport parser.
        let fragment = [IPPROTO_TCP, 0, 0, 1, 0, 0, 0, 0];
        let mut payload = fragment.to_vec();
        payload.extend_from_slice(&segment);
        assert!(
            parse_ipv6(&build_ipv6(src, dst, 44, 64, &payload)).is_none(),
            "fragments are dropped"
        );
        // A chain that never ends, a truncated packet and a lying length are all quiet `None`s.
        assert!(
            parse_ipv6(&build_ipv6(src, dst, 0, 64, &[0, 0, 0, 0, 0, 0, 0, 0])).is_none(),
            "no transport after it"
        );
        assert!(parse_ipv6(&[0x60; 39]).is_none(), "shorter than a header");
        assert!(parse_ipv6(&[0x40; 40]).is_none(), "not IPv6");
        let mut liar = build_ipv6(src, dst, IPPROTO_UDP, 64, b"x");
        liar[4..6].copy_from_slice(&900u16.to_be_bytes());
        assert!(
            parse_ipv6(&liar).is_none(),
            "a length beyond the buffer is refused"
        );
        // A jumbogram's zero payload length is refused too (we do not reassemble).
        let mut jumbo = build_ipv6(src, dst, IPPROTO_UDP, 64, b"");
        jumbo[4..6].copy_from_slice(&0u16.to_be_bytes());
        assert!(parse_ipv6(&jumbo).is_none());
    }

    #[test]
    fn the_multicast_helpers_say_where_a_guest_sends_its_probes() {
        // A Neighbor Solicitation goes to the solicited-node multicast of the address being asked
        // about, and that address maps to 33:33:ff:xx:xx:xx — the MAC the relay must accept.
        let target = "fd10:177::16".parse::<Ipv6Addr>().unwrap();
        let solicited = solicited_node_multicast(target);
        assert_eq!(solicited, "ff02::1:ff00:16".parse::<Ipv6Addr>().unwrap());
        assert_eq!(
            multicast_mac(solicited),
            [0x33, 0x33, 0xff, 0x00, 0x00, 0x16]
        );
        assert_eq!(
            multicast_mac(ALL_ROUTERS_MULTICAST),
            [0x33, 0x33, 0x00, 0x00, 0x00, 0x02]
        );
        // The gateway's link-local is the modified EUI-64 of this process's MAC (OUR_MAC).
        let link_local = link_local_of([0x52, 0x54, 0x00, 0x00, 0x00, 0x01]);
        assert_eq!(
            link_local,
            "fe80::5054:ff:fe00:1".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(
            eui64_interface_id([0x52, 0x54, 0x00, 0x00, 0x00, 0x01]),
            [0x50, 0x54, 0x00, 0xff, 0xfe, 0x00, 0x00, 0x01]
        );
    }

    #[test]
    fn a_whole_ipv6_answer_to_the_guest_is_one_frame_away() {
        let our = "fd10:177::1".parse::<Ipv6Addr>().unwrap();
        let guest = "fd10:177::16".parse::<Ipv6Addr>().unwrap();
        // A realistic Neighbor Advertisement body: the flags, then the 16-byte target address (every
        // real ICMPv6 message carries at least the four bytes after the checksum, plus something).
        let mut body = vec![0x60, 0, 0, 0];
        body.extend_from_slice(&guest.octets());
        let message = build_icmpv6(our, guest, 136, 0, &body);
        let frame = ipv6_to_guest(
            [1, 1, 1, 1, 1, 1],
            [2, 2, 2, 2, 2, 2],
            our,
            guest,
            IPPROTO_ICMPV6,
            &message,
        );
        let ethernet = parse_ethernet(&frame).expect("a frame");
        assert_eq!(ethernet.ethertype, ETHERTYPE_IPV6);
        assert_eq!(ethernet.dst, [1, 1, 1, 1, 1, 1]);
        let packet = parse_ipv6(ethernet.payload).expect("a packet");
        assert_eq!(packet.dst, guest);
        assert_eq!(parse_icmpv6(packet.payload).expect("ICMPv6").kind, 136);
    }

    #[test]
    fn a_multicast_or_broadcast_mac_is_recognized() {
        assert!(is_broadcast_or_multicast(&BROADCAST_MAC));
        assert!(
            is_broadcast_or_multicast(&[0x01, 0x00, 0x5e, 0, 0, 1]),
            "IPv4 multicast"
        );
        assert!(
            !is_broadcast_or_multicast(&[0x52, 0x54, 0x00, 0x11, 0x22, 0x33]),
            "a unicast MAC"
        );
    }
}
