//! Neighbour Discovery for the machines' IPv6 network (RFC 4861), and the ICMPv6 messages it uses.
//!
//! The machines live in a private subnet that exists on no interface ( ,
//! ): each one is a unix `socketpair` conduit, and this process sits at the other end as the
//! **router**. IPv6 is stage V5, and this module is to IPv6 what the relay's ARP handling is to IPv4 —
//! a guest asks "who holds this address?" and we answer for ourselves and for the peers the isolation
//! rules allow, and we announce the prefix the guest configures itself from. Nothing here touches a
//! host interface, and nothing here allocates state: these are the builders and parsers the relay
//! calls, one message at a time.
//!
//! Five decisions shape the module:
//!
//! * **A Duplicate Address Detection probe is left alone.** Before a guest configures an address it
//!   multicasts a Neighbor Solicitation for it from the unspecified address (`::`), with no Source
//!   Link-Layer Address option. That is the one solicitation the relay must **not** answer: replying
//!   would tell the guest its own tentative address is taken by somebody else, so it would pick
//!   another address — or report a conflict — on a conduit where it is the only claimant.
//!   [`NeighborMessage::is_dad_probe`] recognizes the shape (a solicitation, flags zero, no
//!   link-layer option), and the relay checks the source address itself where it can, because the
//!   source lives in the IPv6 header and not in the body parsed here.
//! * **The kind is inferred, because the body does not carry it.**  The ICMPv6 type (133…136) sits
//!   in the four-byte header *in front of* the body this module parses.  A solicitation's first
//!   four bytes are reserved and must be zero (RFC 4861), while an advertisement's first byte is
//!   the R/S/O flags, so [`parse_neighbor`] reads a zero first byte as a solicitation — except
//!   that a
//!   Target Link-Layer Address option (code 2, which only an advertisement carries) settles it as an
//!   advertisement even with every flag clear. A Neighbor Advertisement with no flags *and* no target
//!   option is byte-for-byte a solicitation at this layer; a caller that has already read the ICMPv6
//!   type should prefer that type where the difference matters.
//! * **The Router Advertisement is our own configuration, not a copy of the host's.**  This
//!   process is the only router a guest can see, so there is no upstream advertisement to mirror:
//!   [`RouterAdConfig`] is the router's own statement of the internal ULA prefix, its lifetimes
//!   and its hop limit.
//! * **The RA carries an MTU, and that is not decoration.**  The conduit moves 1500-byte Ethernet
//!   frames.  A guest that assumed a 65535-byte IPv6 MTU could hand the VMM a packet larger than
//!   the conduit can hold, and it would have to be dropped or fragmented before it ever reached us.
//!   Telling the guest 1500 keeps every packet it builds inside one conduit frame, which is the only
//!   MTU that actually exists here.
//! * **The option walk is eight-byte units, total, and finite.** Every NDP option is a type, a length
//!   in units of eight bytes, and a value. A zero length is malformed and ends the walk; so does a
//!   length that runs past the body.  Neither is a panic and neither can loop forever, because a
//!   guest is an untrusted operating system and a hostile option must be a quiet end, not a hang.

use std::net::Ipv6Addr;

/// ICMPv6 Router Solicitation (RFC 4861 ): a guest asks for an advertisement.
pub const ROUTER_SOLICITATION: u8 = 133;
/// ICMPv6 Router Advertisement (RFC 4861 ): the router states the prefix, its lifetimes and the
/// hop limit a guest should use.
pub const ROUTER_ADVERTISEMENT: u8 = 134;
/// ICMPv6 Neighbor Solicitation (RFC 4861 ): "who holds this address?".
pub const NEIGHBOR_SOLICITATION: u8 = 135;
/// ICMPv6 Neighbor Advertisement (RFC 4861 ): "I hold this address".
pub const NEIGHBOR_ADVERTISEMENT: u8 = 136;

/// Neighbor Advertisement flag: the sender is a router (RFC 4861 ).
pub const NA_ROUTER: u8 = 0x80;
/// Neighbor Advertisement flag: this is a reply to a solicitation.
pub const NA_SOLICITED: u8 = 0x40;
/// Neighbor Advertisement flag: the receiver should replace its cached link-layer address. A **proxy**
/// advertisement — one given on another node's behalf — sets it.
pub const NA_OVERRIDE: u8 = 0x20;

/// NDP option: the sender's link-layer address (in a solicitation).
pub const OPTION_SOURCE_LINK_LAYER: u8 = 1;
/// NDP option: the target's link-layer address (in an advertisement).
pub const OPTION_TARGET_LINK_LAYER: u8 = 2;
/// NDP option: a prefix the guest may configure addresses from.
pub const OPTION_PREFIX_INFORMATION: u8 = 3;
/// NDP option: the link MTU the guest should assume.
pub const OPTION_MTU: u8 = 5;

/// The fixed part of a Neighbor Solicitation or Advertisement: the four-byte flags/reserved field and
/// the sixteen-byte target address.
const NEIGHBOR_FIXED: usize = 20;
/// The fixed part of a Router Advertisement: hop limit, flags, router lifetime, reachable time and
/// retransmission timer (RFC 4861: twelve bytes, before the options).
const ROUTER_ADVERTISEMENT_FIXED: usize = 12;
/// The M (managed) flag of a Router Advertisement: addresses come from DHCPv6.
const RA_MANAGED: u8 = 0x80;
/// The O (other configuration) flag of a Router Advertisement: DNS and friends come from DHCPv6.
const RA_OTHER_CONFIG: u8 = 0x40;
/// The on-link flag of a Prefix Information option: peers in the prefix are reachable directly.
const PREFIX_ON_LINK: u8 = 0x80;
/// The autonomous flag of a Prefix Information option: the prefix may feed stateless autoconfiguration.
const PREFIX_AUTONOMOUS: u8 = 0x40;

/// A Neighbor Solicitation or Advertisement, parsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NeighborMessage {
    /// `NEIGHBOR_SOLICITATION` or `NEIGHBOR_ADVERTISEMENT`.
    ///
    /// The ICMPv6 type is not part of the body, so this is inferred (see the module docs): a zero
    /// first byte is a solicitation unless a target link-layer option proves otherwise. A caller that
    /// read the type from the ICMPv6 header should prefer that reading for an advertisement whose
    /// flags are all clear and which carries no target option.
    pub kind: u8,
    /// The flags byte (only meaningful for an advertisement; zero for a solicitation).
    pub flags: u8,
    /// The address being asked about or announced.
    pub target: Ipv6Addr,
    /// The sender's link-layer address, when the message carries one.
    pub link_layer: Option<[u8; 6]>,
}

impl NeighborMessage {
    /// Whether the message is an advertisement.
    pub fn is_advertisement(&self) -> bool {
        self.kind == NEIGHBOR_ADVERTISEMENT
    }

    /// Whether the advertisement is a **proxy** advertisement (the Override flag).
    ///
    /// The relay answers for a peer the isolation rules allow exactly as a proxy ARP reply would, and
    /// this is the v6 spelling of that: an advertisement carrying [`NA_OVERRIDE`], which tells the
    /// guest to replace whatever it had cached for the target.
    pub fn is_proxy(&self) -> bool {
        self.is_advertisement() && self.flags & NA_OVERRIDE != 0
    }

    /// Whether this is a Duplicate Address Detection probe: a solicitation from the unspecified
    /// address (`::`) for its own tentative address. The relay must **not** answer one.
    ///
    /// A DAD solicitation is the one shape with no Source Link-Layer Address option — the sender has
    /// no address yet, so it cannot name a source — and with the reserved field, and therefore the
    /// flags byte, at zero. This module cannot see the source address (it is in the IPv6 header, not
    /// the ICMPv6 body), so the test is the shape it *can* see: a solicitation, flags zero, and no
    /// link-layer option. The relay, which does hold the packet, checks `src == ::` itself as well;
    /// this method is the cheap second line for the same decision.
    pub fn is_dad_probe(&self) -> bool {
        self.kind == NEIGHBOR_SOLICITATION && self.flags == 0 && self.link_layer.is_none()
    }
}

/// Parse a Neighbor Solicitation/Advertisement's ICMPv6 body (everything after the four-byte
/// type/code/checksum header). `None` for anything shorter than flags + target.
///
/// The option walk covers whatever follows the twenty-byte fixed part, and a malformed option simply
/// ends it; the target and flags are still returned.
pub fn parse_neighbor(body: &[u8]) -> Option<NeighborMessage> {
    let flags = *body.first()?;
    let raw = body.get(4..NEIGHBOR_FIXED)?;
    let target = Ipv6Addr::from(<[u8; 16]>::try_from(raw).ok()?);
    let parsed = options(body, NEIGHBOR_FIXED);
    // A Target Link-Layer Address option is only ever sent by an advertisement, so it settles the
    // kind even when every flag is clear; otherwise the reserved field (zero in a solicitation) does.
    let advertisement = flags != 0
        || parsed
            .iter()
            .any(|(code, value)| *code == OPTION_TARGET_LINK_LAYER && value.len() >= 6);
    Some(NeighborMessage {
        kind: if advertisement {
            NEIGHBOR_ADVERTISEMENT
        } else {
            NEIGHBOR_SOLICITATION
        },
        flags,
        target,
        link_layer: link_layer_option(&parsed),
    })
}

/// A Router Advertisement, parsed (the relay sends them; tests and a mirroring relay read them).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterAdvertisement {
    /// The current hop limit to advertise.
    pub current_hop_limit: u8,
    /// The M (managed) and O (other config) flags, plus the reserved bits.
    pub flags: u8,
    /// The router lifetime (seconds).
    pub router_lifetime: u16,
    /// The reachable time.
    pub reachable_time: u32,
    /// The retransmission timer.
    pub retrans_timer: u32,
    /// The Prefix Information option, when one is present: the prefix, its length, its flags, and the
    /// valid and preferred lifetimes.
    pub prefix: Option<PrefixInformation>,
    /// The MTU option, when one is present.
    pub mtu: Option<u32>,
    /// The Source Link-Layer Address option, when one is present.
    pub link_layer: Option<[u8; 6]>,
}

impl RouterAdvertisement {
    /// Whether the M (managed) flag is set: addresses come from DHCPv6.
    pub fn managed(&self) -> bool {
        self.flags & RA_MANAGED != 0
    }

    /// Whether the O (other config) flag is set: DNS and friends come from DHCPv6.
    pub fn other_config(&self) -> bool {
        self.flags & RA_OTHER_CONFIG != 0
    }
}

/// One Prefix Information option.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrefixInformation {
    /// The prefix.
    pub prefix: Ipv6Addr,
    /// Its length in bits (usually 64).
    pub prefix_len: u8,
    /// The option's flags byte: on-link (0x80) and autonomous (0x40).
    pub flags: u8,
    /// The valid lifetime.
    pub valid_lifetime: u32,
    /// The preferred lifetime.
    pub preferred_lifetime: u32,
}

impl PrefixInformation {
    /// Whether the prefix may be used for stateless autoconfiguration.
    pub fn autonomous(&self) -> bool {
        self.flags & PREFIX_AUTONOMOUS != 0
    }

    /// Whether the prefix is on-link (a guest may talk to peers in it directly).
    pub fn on_link(&self) -> bool {
        self.flags & PREFIX_ON_LINK != 0
    }
}

/// Parse the body of a Router Advertisement (everything after the four-byte type/code/checksum
/// header). `None` for anything shorter than the twelve-byte fixed part.
///
/// This is the reader side of [`router_advertisement_body`], and what a mirroring relay or a test
/// uses to check what we sent. Options other than the three we build are ignored; the first of each
/// kind wins, so a hostile duplicate cannot overwrite what a guest was told first.
pub fn parse_router_advertisement(body: &[u8]) -> Option<RouterAdvertisement> {
    let fixed = body.get(..ROUTER_ADVERTISEMENT_FIXED)?;
    let mut prefix = None;
    let mut mtu = None;
    let mut link_layer = None;
    for (code, value) in options(body, ROUTER_ADVERTISEMENT_FIXED) {
        match code {
            OPTION_SOURCE_LINK_LAYER | OPTION_TARGET_LINK_LAYER if link_layer.is_none() => {
                if let Some(octets) = value.get(..6) {
                    let mut mac = [0u8; 6];
                    mac.copy_from_slice(octets);
                    link_layer = Some(mac);
                }
            }
            OPTION_MTU if mtu.is_none() => {
                // Type, length, two reserved bytes, then the four-byte MTU.
                if let Some(mtu_value) = value.get(2..6) {
                    mtu = Some(u32::from_be_bytes([
                        mtu_value[0],
                        mtu_value[1],
                        mtu_value[2],
                        mtu_value[3],
                    ]));
                }
            }
            OPTION_PREFIX_INFORMATION if prefix.is_none() => {
                // Prefix length, flags, valid lifetime, preferred lifetime, four reserved bytes, prefix.
                if let Some(octets) = value.get(14..30) {
                    if let Ok(address) = <[u8; 16]>::try_from(octets) {
                        prefix = Some(PrefixInformation {
                            prefix: Ipv6Addr::from(address),
                            prefix_len: value[0],
                            flags: value[1],
                            valid_lifetime: u32::from_be_bytes([
                                value[2], value[3], value[4], value[5],
                            ]),
                            preferred_lifetime: u32::from_be_bytes([
                                value[6], value[7], value[8], value[9],
                            ]),
                        });
                    }
                }
            }
            _ => {}
        }
    }
    Some(RouterAdvertisement {
        current_hop_limit: fixed[0],
        flags: fixed[1],
        router_lifetime: u16::from_be_bytes([fixed[2], fixed[3]]),
        reachable_time: u32::from_be_bytes([fixed[4], fixed[5], fixed[6], fixed[7]]),
        retrans_timer: u32::from_be_bytes([fixed[8], fixed[9], fixed[10], fixed[11]]),
        prefix,
        mtu,
        link_layer,
    })
}

/// What the relay advertises. It is the router for every machine's conduit, so the RA is its own
/// configuration, not a copy of anything on the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouterAdConfig {
    /// Our MAC (the Source Link-Layer Address option).
    pub our_mac: [u8; 6],
    /// The internal ULA prefix (`fd10:177::`).
    pub prefix: Ipv6Addr,
    /// The prefix's length in bits.
    pub prefix_len: u8,
    /// Whether addresses come from DHCPv6 (the M flag).
    pub managed: bool,
    /// Whether DNS and other configuration come from DHCPv6 (the O flag).
    pub other_config: bool,
    /// Whether the prefix is on-link.
    pub on_link: bool,
    /// Whether the prefix may feed stateless autoconfiguration.
    pub autonomous: bool,
    /// The valid lifetime advertised for the prefix (seconds).
    pub valid_lifetime: u32,
    /// The preferred lifetime advertised for the prefix (seconds).
    pub preferred_lifetime: u32,
    /// The router lifetime (seconds); zero means "not a default router".
    pub router_lifetime: u16,
    /// The MTU option: the frames on this conduit are 1500-byte Ethernet, so that is what a guest is
    /// told, and it is what keeps a guest's packet inside the conduit's buffer.
    pub mtu: u32,
    /// The hop limit a guest is told to use.
    pub current_hop_limit: u8,
}

/// Build the ICMPv6 body of a Router Advertisement (everything after the four-byte header), with the
/// Source Link-Layer Address, MTU and Prefix Information options in that order.
///
/// The order is the one RFC 4861 recommends, and it is what a guest's kernel accepts without
/// argument: the link-layer address lets it record the router immediately, the MTU caps what it will
/// build, and the prefix is what it configures an address from. The reachable time and the
/// retransmission timer are zero, which RFC 4861 defines as "unspecified" — we do not run NUD timers
/// on the guest's behalf, so we do not pretend to have numbers for them.
///
/// The ICMPv6 checksum is not computed here: it needs the IPv6 pseudo-header, so it is
/// [`crate::frame::build_icmpv6`]'s job.
pub fn router_advertisement_body(config: &RouterAdConfig) -> Vec<u8> {
    let mut body = Vec::with_capacity(64);
    body.push(config.current_hop_limit);
    let mut flags = 0u8;
    if config.managed {
        flags |= RA_MANAGED;
    }
    if config.other_config {
        flags |= RA_OTHER_CONFIG;
    }
    body.push(flags);
    body.extend_from_slice(&config.router_lifetime.to_be_bytes());
    body.extend_from_slice(&0u32.to_be_bytes()); // reachable time: unspecified
    body.extend_from_slice(&0u32.to_be_bytes()); // retransmission timer: unspecified

    // Option 1: our link-layer address, so the guest can use us as the next hop at once.
    body.push(OPTION_SOURCE_LINK_LAYER);
    body.push(1);
    body.extend_from_slice(&config.our_mac);

    // Option 2: the conduit's MTU. This is the one that must be true, not generous.
    body.push(OPTION_MTU);
    body.push(1);
    body.extend_from_slice(&[0, 0]);
    body.extend_from_slice(&config.mtu.to_be_bytes());

    // Option 3: the prefix, its lifetimes and its on-link/autonomous flags.
    body.push(OPTION_PREFIX_INFORMATION);
    body.push(4);
    body.push(config.prefix_len);
    let mut prefix_flags = 0u8;
    if config.on_link {
        prefix_flags |= PREFIX_ON_LINK;
    }
    if config.autonomous {
        prefix_flags |= PREFIX_AUTONOMOUS;
    }
    body.push(prefix_flags);
    body.extend_from_slice(&config.valid_lifetime.to_be_bytes());
    body.extend_from_slice(&config.preferred_lifetime.to_be_bytes());
    body.extend_from_slice(&[0, 0, 0, 0]);
    body.extend_from_slice(&config.prefix.octets());
    body
}

/// Build the ICMPv6 body of a Neighbor Advertisement: the flags, the target address, and the Target
/// Link-Layer Address option when `link_layer` is given.
pub fn neighbor_advertisement_body(
    flags: u8,
    target: Ipv6Addr,
    link_layer: Option<[u8; 6]>,
) -> Vec<u8> {
    let mut body = Vec::with_capacity(if link_layer.is_some() { 28 } else { 20 });
    body.push(flags);
    body.extend_from_slice(&[0, 0, 0]); // the remaining reserved bits
    body.extend_from_slice(&target.octets());
    if let Some(mac) = link_layer {
        body.push(OPTION_TARGET_LINK_LAYER);
        body.push(1);
        body.extend_from_slice(&mac);
    }
    body
}

/// Build the ICMPv6 body of a Neighbor Solicitation.
///
/// The four reserved bytes are zero (a solicitation has no flags), and the source link-layer option
/// is included only when the caller has one: a DAD probe deliberately does not.
pub fn neighbor_solicitation_body(target: Ipv6Addr, link_layer: Option<[u8; 6]>) -> Vec<u8> {
    let mut body = Vec::with_capacity(if link_layer.is_some() { 28 } else { 20 });
    body.extend_from_slice(&[0, 0, 0, 0]); // reserved
    body.extend_from_slice(&target.octets());
    if let Some(mac) = link_layer {
        body.push(OPTION_SOURCE_LINK_LAYER);
        body.push(1);
        body.extend_from_slice(&mac);
    }
    body
}

/// Build the ICMPv6 body of a Router Solicitation: the four reserved bytes RFC 4861 puts after
/// the checksum, and no options.
///
/// The reserved bytes are written rather than omitted because they are what makes the message the
/// eight bytes every ICMPv6 message is: a receiver that parses the fixed header (`frame::parse_icmp`)
/// refuses anything shorter, and a real guest's solicitation carries them.
pub fn router_solicitation_body() -> Vec<u8> {
    vec![0, 0, 0, 0]
}

/// Walk the NDP options in an ICMPv6 body that starts after the fixed part (`offset` bytes in).
/// Yields `(option code, option value)` and never panics on a malformed option: a zero length stops
/// the walk.
///
/// The value is the bytes after the option's two-byte type/length header, so a link-layer option's
/// value is its six-byte MAC and an MTU option's is its two reserved bytes plus the four-byte MTU.
/// A length that would run past the body also stops the walk, and no partial option is reported for
/// it; an `offset` past the end is simply an empty list.
pub fn options(body: &[u8], offset: usize) -> Vec<(u8, Vec<u8>)> {
    let mut found = Vec::new();
    let mut cursor = offset;
    loop {
        // Two bytes hold the type and the length; a body that cannot hold both ends the walk. The
        // subtraction is ordered so a hostile `offset` (even `usize::MAX`) cannot underflow.
        if cursor >= body.len() || body.len() - cursor < 2 {
            break;
        }
        let code = body[cursor];
        let words = body[cursor + 1] as usize;
        // A zero length advances nothing and describes no option: it would loop forever.
        if words == 0 {
            break;
        }
        // Every option covers `words` eight-byte units; `words` is a byte, so the product cannot
        // overflow, and the addition is checked anyway.
        let end = match cursor.checked_add(words * 8) {
            Some(end) if end <= body.len() => end,
            _ => break,
        };
        found.push((code, body[cursor + 2..end].to_vec()));
        cursor = end;
    }
    found
}

/// The link-layer address in an options list, whatever code the sender used (1 for a solicitation's
/// source, 2 for an advertisement's target).
///
/// A value too short to hold a MAC is not one, and the walk keeps looking rather than reporting an
/// address that is not there.
pub fn link_layer_option(options: &[(u8, Vec<u8>)]) -> Option<[u8; 6]> {
    options.iter().find_map(|(code, value)| {
        if *code != OPTION_SOURCE_LINK_LAYER && *code != OPTION_TARGET_LINK_LAYER {
            return None;
        }
        let octets = value.get(..6)?;
        let mut mac = [0u8; 6];
        mac.copy_from_slice(octets);
        Some(mac)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame;

    fn ip(text: &str) -> Ipv6Addr {
        text.parse().expect("a valid address")
    }

    /// The relay's own advertisement: the internal ULA prefix, our MAC, and the conduit's MTU.
    fn sample_config() -> RouterAdConfig {
        RouterAdConfig {
            our_mac: [0x52, 0x54, 0x00, 0x00, 0x00, 0x01],
            prefix: ip("fd10:177::"),
            prefix_len: 64,
            managed: true,
            other_config: true,
            on_link: true,
            autonomous: true,
            valid_lifetime: 2_592_000,
            preferred_lifetime: 604_800,
            router_lifetime: 1_800,
            mtu: 1500,
            current_hop_limit: 64,
        }
    }

    /// The NDP body of a built ICMPv6 message: `parse_icmpv6` splits the fixed NDP part as its `rest`
    /// and the remainder as its `payload`, and this module's parsers want them joined again.
    fn icmpv6_body(message: &[u8]) -> Vec<u8> {
        let parsed = frame::parse_icmpv6(message).expect("an ICMPv6 message");
        let mut body = parsed.rest.to_vec();
        body.extend_from_slice(parsed.payload);
        body
    }

    #[test]
    fn a_router_advertisement_round_trips_with_a_verifiable_checksum() {
        let config = sample_config();
        let body = router_advertisement_body(&config);
        assert_eq!(
            body.len(),
            60,
            "12 fixed bytes, then two 8-byte options and one 32-byte option"
        );

        // Sent the way the relay sends it: one ICMPv6 message to the all-nodes multicast, from our
        // own link-local address.
        let our = frame::link_local_of(config.our_mac);
        let message = frame::build_icmpv6(
            our,
            frame::ALL_NODES_MULTICAST,
            ROUTER_ADVERTISEMENT,
            0,
            &body,
        );
        assert_eq!(
            frame::transport_checksum_v6(
                our,
                frame::ALL_NODES_MULTICAST,
                frame::IPPROTO_ICMPV6,
                &message
            ),
            0,
            "the ICMPv6 checksum covers the pseudo-header, and it verifies",
        );
        assert_eq!(
            frame::parse_icmpv6(&message).expect("ICMPv6").kind,
            ROUTER_ADVERTISEMENT
        );

        let parsed =
            parse_router_advertisement(&icmpv6_body(&message)).expect("a Router Advertisement");
        assert_eq!(parsed.current_hop_limit, config.current_hop_limit);
        assert_eq!(parsed.flags, RA_MANAGED | RA_OTHER_CONFIG);
        assert_eq!(parsed.router_lifetime, config.router_lifetime);
        assert_eq!(
            parsed.mtu,
            Some(config.mtu),
            "the MTU a guest is told is the conduit's own"
        );
        assert_eq!(parsed.link_layer, Some(config.our_mac));
        let prefix = parsed.prefix.expect("a Prefix Information option");
        assert_eq!(prefix.prefix, config.prefix);
        assert_eq!(prefix.prefix_len, config.prefix_len);
        assert_eq!(prefix.valid_lifetime, config.valid_lifetime);
        assert_eq!(prefix.preferred_lifetime, config.preferred_lifetime);
    }

    #[test]
    fn the_router_advertisement_flags_are_readable_through_helpers() {
        let advertised = parse_router_advertisement(&router_advertisement_body(&sample_config()))
            .expect("an advertisement");
        assert!(advertised.managed(), "the M flag is set by the config");
        assert!(advertised.other_config(), "the O flag is set by the config");
        let prefix = advertised.prefix.expect("a prefix");
        assert!(prefix.on_link() && prefix.autonomous());

        let mut quiet = sample_config();
        quiet.managed = false;
        quiet.other_config = false;
        quiet.on_link = false;
        quiet.autonomous = false;
        let advertised = parse_router_advertisement(&router_advertisement_body(&quiet))
            .expect("an advertisement");
        assert!(!advertised.managed() && !advertised.other_config());
        let prefix = advertised.prefix.expect("a prefix");
        assert!(!prefix.on_link() && !prefix.autonomous());
    }

    #[test]
    fn a_neighbor_solicitation_round_trips() {
        let target = ip("fd10:177::16");
        let mac = [0x52, 0x54, 0x00, 0x11, 0x22, 0x33];
        let body = neighbor_solicitation_body(target, Some(mac));
        assert_eq!(
            body.len(),
            28,
            "reserved + target, then the source link-layer option"
        );

        let our = ip("fe80::5054:ff:fe11:2233");
        let message = frame::build_icmpv6(
            our,
            frame::solicited_node_multicast(target),
            NEIGHBOR_SOLICITATION,
            0,
            &body,
        );
        assert_eq!(
            frame::transport_checksum_v6(
                our,
                frame::solicited_node_multicast(target),
                frame::IPPROTO_ICMPV6,
                &message
            ),
            0,
        );

        let parsed = parse_neighbor(&icmpv6_body(&message)).expect("a Neighbor Solicitation");
        assert_eq!(parsed.kind, NEIGHBOR_SOLICITATION);
        assert_eq!(parsed.flags, 0);
        assert_eq!(parsed.target, target);
        assert_eq!(parsed.link_layer, Some(mac));
        assert!(!parsed.is_advertisement());
    }

    #[test]
    fn a_neighbor_advertisement_round_trips_and_the_override_flag_marks_a_proxy() {
        let target = ip("fd10:177::16");
        let mac = [0x52, 0x54, 0x00, 0x11, 0x22, 0x33];

        let body = neighbor_advertisement_body(NA_SOLICITED | NA_OVERRIDE, target, Some(mac));
        let parsed = parse_neighbor(&body).expect("a Neighbor Advertisement");
        assert_eq!(parsed.kind, NEIGHBOR_ADVERTISEMENT);
        assert!(parsed.is_advertisement());
        assert_eq!(parsed.flags, NA_SOLICITED | NA_OVERRIDE);
        assert_eq!(parsed.target, target);
        assert_eq!(parsed.link_layer, Some(mac));
        assert!(
            parsed.is_proxy(),
            "the Override flag is what a proxy advertisement sets"
        );

        let solicited = parse_neighbor(&neighbor_advertisement_body(NA_SOLICITED, target, None))
            .expect("an advertisement");
        assert!(
            !solicited.is_proxy(),
            "a solicited reply with no Override is not a proxy"
        );
        let override_only = parse_neighbor(&neighbor_advertisement_body(NA_OVERRIDE, target, None))
            .expect("an advertisement");
        assert!(override_only.is_proxy());
        let router = parse_neighbor(&neighbor_advertisement_body(NA_ROUTER, target, Some(mac)))
            .expect("an advertisement");
        assert!(
            router.is_advertisement() && !router.is_proxy(),
            "the Router flag alone is not Override"
        );
    }

    #[test]
    fn a_solicitation_without_a_link_layer_option_is_a_dad_probe() {
        let target = ip("fd10:177::16");
        let probe =
            parse_neighbor(&neighbor_solicitation_body(target, None)).expect("a solicitation");
        assert!(
            probe.is_dad_probe(),
            ":: for its own tentative address, with no source link-layer option"
        );
        assert!(!probe.is_advertisement());

        let ordinary = parse_neighbor(&neighbor_solicitation_body(
            target,
            Some([0x52, 0x54, 0x00, 0x11, 0x22, 0x33]),
        ))
        .expect("a solicitation");
        assert!(
            !ordinary.is_dad_probe(),
            "a solicitation that says who the sender is is not a probe"
        );

        let advertisement =
            parse_neighbor(&neighbor_advertisement_body(NA_SOLICITED, target, None))
                .expect("an advertisement");
        assert!(
            !advertisement.is_dad_probe(),
            "an advertisement is never a probe"
        );
    }

    #[test]
    fn the_option_walk_stops_at_a_zero_length_option() {
        let mut body = vec![0u8; NEIGHBOR_FIXED];
        body.extend_from_slice(&[OPTION_SOURCE_LINK_LAYER, 1, 1, 2, 3, 4, 5, 6]);
        body.extend_from_slice(&[OPTION_MTU, 0, 9, 9, 9, 9, 9, 9]);
        body.extend_from_slice(&[OPTION_PREFIX_INFORMATION, 4, 0, 0, 0, 0, 0, 0, 0]);
        let found = options(&body, NEIGHBOR_FIXED);
        assert_eq!(
            found.len(),
            1,
            "the zero-length option ends the walk, and nothing after it is read"
        );
        assert_eq!(found[0].0, OPTION_SOURCE_LINK_LAYER);
        assert_eq!(found[0].1, vec![1, 2, 3, 4, 5, 6]);

        // An offset beyond the body, and an empty body, are quiet empties too.
        assert!(options(&body, 10_000).is_empty());
        assert!(options(&body, usize::MAX).is_empty());
        assert!(options(&[], 0).is_empty());
    }

    #[test]
    fn a_truncated_or_hostile_neighbor_message_is_refused_rather_than_panicking() {
        assert!(parse_neighbor(&[]).is_none());
        assert!(
            parse_neighbor(&[0u8; 19]).is_none(),
            "shorter than the flags and the target"
        );
        assert!(
            parse_neighbor(&[0u8; NEIGHBOR_FIXED]).is_some(),
            "the shortest legal body parses"
        );

        // An option whose length runs past the body is malformed: no value is reported, no panic.
        let mut oversized = vec![0u8; NEIGHBOR_FIXED];
        oversized.extend_from_slice(&[OPTION_PREFIX_INFORMATION, 255, 1, 2, 3]);
        assert!(options(&oversized, NEIGHBOR_FIXED).is_empty());
        assert!(
            parse_neighbor(&oversized).is_some(),
            "the fixed part is still readable"
        );

        // A trailing byte that cannot hold a type and a length is ignored.
        let mut trailing = vec![0u8; NEIGHBOR_FIXED];
        trailing.push(OPTION_MTU);
        assert!(options(&trailing, NEIGHBOR_FIXED).is_empty());

        // A Router Advertisement shorter than its fixed part is refused too.
        assert!(parse_router_advertisement(&[0u8; 11]).is_none());
        assert!(parse_router_advertisement(&[0u8; ROUTER_ADVERTISEMENT_FIXED]).is_some());
    }

    #[test]
    fn the_link_layer_option_is_found_under_either_code() {
        let mac = [0x52, 0x54, 0x00, 0x11, 0x22, 0x33];
        assert_eq!(
            link_layer_option(&[(OPTION_SOURCE_LINK_LAYER, mac.to_vec())]),
            Some(mac)
        );
        assert_eq!(
            link_layer_option(&[(OPTION_TARGET_LINK_LAYER, mac.to_vec())]),
            Some(mac)
        );
        assert_eq!(
            link_layer_option(&[(OPTION_MTU, vec![0; 6])]),
            None,
            "another option is not a link-layer address"
        );
        assert_eq!(link_layer_option(&[]), None);
        assert_eq!(
            link_layer_option(&[(OPTION_SOURCE_LINK_LAYER, vec![1, 2, 3])]),
            None,
            "a truncated value is not a MAC"
        );
        assert_eq!(
            link_layer_option(&[
                (OPTION_SOURCE_LINK_LAYER, vec![1; 6]),
                (OPTION_TARGET_LINK_LAYER, vec![2; 6])
            ]),
            Some([1; 6]),
            "the first usable option wins",
        );
    }

    #[test]
    fn a_router_advertisement_carries_its_options_in_order() {
        let config = sample_config();
        let body = router_advertisement_body(&config);
        let our = frame::link_local_of(config.our_mac);
        let message = frame::build_icmpv6(
            our,
            frame::ALL_NODES_MULTICAST,
            ROUTER_ADVERTISEMENT,
            0,
            &body,
        );
        assert_eq!(
            frame::transport_checksum_v6(
                our,
                frame::ALL_NODES_MULTICAST,
                frame::IPPROTO_ICMPV6,
                &message
            ),
            0,
            "a full ICMPv6 message verifies its checksum",
        );

        let codes: Vec<u8> = options(&icmpv6_body(&message), ROUTER_ADVERTISEMENT_FIXED)
            .into_iter()
            .map(|(code, _)| code)
            .collect();
        assert_eq!(
            codes,
            vec![
                OPTION_SOURCE_LINK_LAYER,
                OPTION_MTU,
                OPTION_PREFIX_INFORMATION
            ],
            "the source link-layer address, then the MTU, then the prefix",
        );
    }

    #[test]
    fn a_router_solicitation_body_is_four_reserved_bytes_and_no_options() {
        assert_eq!(
            router_solicitation_body(),
            vec![0, 0, 0, 0],
            "the reserved field, and no options"
        );
    }
}
