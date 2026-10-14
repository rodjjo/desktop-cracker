//! The DHCPv6 server and lease table.
//!
//! A machine's IPv6 address is ours to give for the same reason its IPv4 address is: the
//! conduit is a unix `socketpair` with **no kernel network stack** on the far side, so no DHCPv6 server
//! and no resolver exists unless this process is them. This module is the server half of the IPv6
//! story — the address, the DNS servers and the domain search list a machine is handed — while the
//! Router Advertisement side lives beside it in the relay.
//!
//! The design mirrors [`crate::dhcp`] deliberately, so the two read as one family:
//!
//! - **One lease per machine, keyed by the machine id (with the client DUID as the fallback).**
//!   The key is what survives a restart; the DUID is what a real server keys on, and letting it
//!   re-key a lease means a machine renamed between runs keeps its address.  Allocation always
//!   takes the **lowest free** address in `[range_start, range_end]`, which makes a restart
//!   reproducible.
//! - **The server is a stateless function over the table.** [`Dhcp6Server`] holds only [`Dhcp6Config`]
//!   — the answers — and every call receives the [`Lease6Table`] it should mutate. Persisting the
//!   table is the caller's business.
//! - **Replies are unicast** to the guest's MAC from the relay's MAC, because the conduit has exactly
//!   one peer: a multicast frame would reach nobody else. The IPv6 source is our link-local; the IPv6
//!   destination is the address the request came from, except that a client which has not configured
//!   an address yet sends from `::`, and then we answer to the link-local its MAC forms (the same
//!   modified EUI-64 rule [`crate::frame`] uses for us). The choice is stated on
//!   [`Dhcp6Server::reply_destination`] and pinned down by the tests.
//! - **Frames are built with [`crate::frame`]**, so every length and the mandatory UDP-over-IPv6
//!   checksum are the codec's problem, and a malformed or hostile frame is a dropped packet — never a
//!   panic.
//!
//! Only the small part of RFC 8415 a guest actually needs is implemented: SOLICIT → ADVERTISE,
//! REQUEST → REPLY, RENEW/REBIND → REPLY, RELEASE → REPLY and INFORMATION-REQUEST → REPLY, carrying
//! the Client Identifier (1), Server Identifier (2), IA_NA (3) with IAADDR (5), Preference (7),
//! Status Code (13), DNS Recursive Name Server (23) and Domain Search List (24) options. Nothing runs
//! on a timer: the lifetimes are answers we hand out, not a clock we keep.

use std::net::Ipv6Addr;

use crate::frame::{
    build_udp_v6, ipv6_to_guest, link_local_of, parse_ethernet, parse_ipv6, parse_udp,
    ETHERTYPE_IPV6, IPPROTO_UDP,
};

/// The UDP port a DHCPv6 server listens on (RFC 8415).
const SERVER_PORT: u16 = 547;
/// The UDP port a DHCPv6 client listens on.
const CLIENT_PORT: u16 = 546;

/// Message type 1: the client is looking for a server.
const MSG_SOLICIT: u8 = 1;
/// Message type 2: a server's offer.
const MSG_ADVERTISE: u8 = 2;
/// Message type 3: the client is asking for (or confirming) an address.
const MSG_REQUEST: u8 = 3;
/// Message type 5: the client is renewing with the server it got its lease from.
const MSG_RENEW: u8 = 5;
/// Message type 6: the client is rebinding with any server.
const MSG_REBIND: u8 = 6;
/// Message type 7: the server's answer.
const MSG_REPLY: u8 = 7;
/// Message type 8: the client gives an address back.
const MSG_RELEASE: u8 = 8;
/// Message type 11: the client wants configuration (DNS, domain) but no address.
const MSG_INFORMATION_REQUEST: u8 = 11;

/// Option 1: the client's DUID.
const OPTION_CLIENTID: u16 = 1;
/// Option 2: the server's DUID.
const OPTION_SERVERID: u16 = 2;
/// Option 3: an identity association for a non-temporary address.
const OPTION_IA_NA: u16 = 3;
/// Option 5: one address inside an IA_NA.
const OPTION_IAADDR: u16 = 5;
/// Option 7: how strongly the server wants to be chosen.
const OPTION_PREFERENCE: u16 = 7;
/// Option 13: a status code and (optionally) a message.
const OPTION_STATUS_CODE: u16 = 13;
/// Option 23: the recursive DNS servers.
const OPTION_DNS_SERVERS: u16 = 23;
/// Option 24: the domain search list, in DNS wire encoding.
const OPTION_DOMAIN_LIST: u16 = 24;
/// Option 56: the NTP server (RFC 5908), which is this relay.
const OPTION_NTP_SERVER: u16 = 56;
/// Suboption 1 of option 56: one NTP server's IPv6 address.
const NTP_SUBOPTION_SERVER_ADDRESS: u16 = 1;

/// Status code 0: the request succeeded.
const STATUS_SUCCESS: u16 = 0;
/// Status code 2: no addresses are available to the client.
const STATUS_NO_ADDRS_AVAIL: u16 = 2;

/// The Preference option value for an Advertise: we are the only server on the conduit.
const PREFERENCE_MAX: u8 = 255;
/// How long a default lease is: a day. The lease is effectively permanent for a machine (the table
/// makes it sticky), so the value only bounds how often a guest renews.
const DEFAULT_LIFETIME_SECS: u32 = 86_400;
/// The DUID type of a link-layer DUID (DUID-LL, RFC 8415 ).
const DUID_LL_TYPE: [u8; 2] = [0x00, 0x03];
/// The hardware type of Ethernet (RFC 826), as DUID-LL spells it.
const HARDWARE_TYPE_ETHERNET: [u8; 2] = [0x00, 0x01];
/// The longest label a DNS name may carry (RFC 1035).
const DNS_LABEL_MAX: usize = 63;

/// The layout of the machines' internal IPv6 subnet and the answers a client is given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Dhcp6Config {
    /// Our server DUID (option 2), stable per deployment: `00:03:00:01:<our mac>` (DUID-LL).
    pub server_duid: Vec<u8>,
    /// The address our replies come **from** (the gateway's link-local, `link_local_of(our_mac)`),
    /// and the address we put in the DHCPv6 "server unicast"/source.
    pub server_link_local: Ipv6Addr,
    /// The MAC of this process's end of the conduit (the Ethernet source of every answer).
    pub our_mac: [u8; 6],
    /// The internal ULA prefix (`fd10:177::`) and its length (`64`).
    pub prefix: Ipv6Addr,
    /// The length of [`Dhcp6Config::prefix`] in bits.
    pub prefix_len: u8,
    /// The first and last address that may be leased (inside the prefix).
    pub range_start: Ipv6Addr,
    /// The last address that may be leased.
    pub range_end: Ipv6Addr,
    /// The DNS servers the guest is told to use (ours, so `vm-<name>` works).
    pub dns: Vec<Ipv6Addr>,
    /// The NTP servers the guest is told to use (ours: the relay answers the time itself, ``).
    pub ntp: Vec<Ipv6Addr>,
    /// The domain search list, when one is configured.
    pub domain: Option<String>,
    /// The preferred lifetime handed out, in seconds.
    pub preferred_lifetime: u32,
    /// The valid lifetime handed out, in seconds.
    pub valid_lifetime: u32,
}

impl Dhcp6Config {
    /// The default layout for `prefix` / `prefix_len`, with `our_mac` as the gateway:
    /// `server_link_local = link_local_of(our_mac)`, leases from the prefix's `::1000` to `::ffff`,
    /// DNS = `[server_link_local]`, and day-long lifetimes.
    ///
    /// The **`::1000` start** leaves the low host addresses (including the prefix's own `::1`) free
    /// for anything this process places by hand and keeps allocation deterministic across restarts; the
    /// **`::ffff` end** is the last host of a `/64`'s low 16 bits, so a default range never spills past
    /// its prefix. The gateway, DNS server and DHCP server are the same link-local, because the relay
    /// is the only way out of the conduit and the only resolver the machines need for `vm-<name>`.
    ///
    /// Both lifetimes are a day. The lease is sticky for the life of the deployment, so the value is a
    /// renewal cadence rather than an expiry: a guest that has not been configured yet is still
    /// answered tomorrow.
    ///
    /// A prefix longer than a `/112` (fewer than 16 host bits) would put `::ffff` beyond them; that is
    /// out of scope for the internal `/64` (the range is left as computed rather than silently changed).
    pub fn for_prefix(prefix: Ipv6Addr, prefix_len: u8, our_mac: [u8; 6]) -> Self {
        let prefix_len = prefix_len.min(128);
        let prefix = mask_prefix(prefix, prefix_len);
        let server_link_local = link_local_of(our_mac);
        Self {
            server_duid: duid_ll(our_mac),
            server_link_local,
            our_mac,
            prefix,
            prefix_len,
            range_start: address_from_bits(address_bits(prefix).saturating_add(0x1000)),
            range_end: address_from_bits(address_bits(prefix).saturating_add(0xffff)),
            dns: vec![server_link_local],
            ntp: vec![server_link_local],
            domain: None,
            preferred_lifetime: DEFAULT_LIFETIME_SECS,
            valid_lifetime: DEFAULT_LIFETIME_SECS,
        }
    }
}

/// One address handed to one machine. `key` is the machine id (sticky across restarts) and `duid` is
/// the client's DUID (what a real server would key on).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease6 {
    /// The machine id the address belongs to.
    pub key: String,
    /// The client's DUID, as last seen.
    pub duid: Vec<u8>,
    /// The address handed out.
    pub address: Ipv6Addr,
    /// The hostname the machine was told to use, when one was known at allocation time.
    pub hostname: Option<String>,
}

/// The allocator: one address per key/DUID, never two.
///
/// The table is small (a handful of machines) and read rarely, so a `Vec` in allocation order is both
/// the cheapest and the most predictable structure: finding the lowest free address is a scan, and
/// [`Lease6Table::all`] hands a stable order back to the caller that persists it.
#[derive(Default, Clone)]
pub struct Lease6Table {
    /// Every live lease, in the order it was allocated.
    leases: Vec<Lease6>,
    /// Whether a lease's holder is still on the network (see [`Lease6Table::set_liveness`]).
    live: Option<LiveCheck>,
}

impl std::fmt::Debug for Lease6Table {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Lease6Table")
            .field("leases", &self.leases)
            .field("liveness", &self.live.is_some())
            .finish()
    }
}

/// Whether the peer holding a lease is **still on the network** (see the IPv4 table's
/// [`crate::dhcp::LiveCheck`], which this mirrors).
pub type LiveCheck = std::sync::Arc<dyn Fn(&str) -> bool + Send + Sync>;

impl Lease6Table {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Install the directory this table asks before it moves an address from one key to another (the
    /// IPv4 table's [`crate::dhcp::LeaseTable::set_liveness`]).
    pub fn set_liveness(&mut self, live: LiveCheck) {
        self.live = Some(live);
    }

    /// Whether this key is on the network right now.
    fn is_live(&self, key: &str) -> bool {
        self.live.as_ref().map(|live| live(key)).unwrap_or(false)
    }

    /// The address for `key` (or for a client with this DUID), allocating the lowest free one in
    /// `[range_start, range_end]` when it has none. Sticky: the same key always gets the same address.
    ///
    /// A machine that reaches the table under a new key but the same DUID keeps its address (the DUID
    /// outlives a rename), and the DUID is refreshed when the key matches, so the table always
    /// describes the machine as we last saw it. Returns `None` only when the range is exhausted (or
    /// inverted).
    pub fn allocate(
        &mut self,
        key: &str,
        duid: &[u8],
        range_start: Ipv6Addr,
        range_end: Ipv6Addr,
    ) -> Option<Ipv6Addr> {
        if let Some(lease) = self.leases.iter_mut().find(|lease| lease.key == key) {
            if !duid.is_empty() && lease.duid.as_slice() != duid {
                lease.duid = duid.to_vec();
            }
            return Some(lease.address);
        }
        if !duid.is_empty() {
            // The DUID is bytes the guest chooses, so a **live** peer's lease is never adopted through
            // it: a guest that presents another peer's DUID would otherwise take its address (and with
            // it, its identity). A DUID whose holder is gone is the rename case, which keeps it.
            let holder_live = self
                .leases
                .iter()
                .find(|lease| lease.duid.as_slice() == duid)
                .map(|lease| lease.key.clone())
                .filter(|holder| self.is_live(holder));
            if holder_live.is_some() {
                return None;
            }
            if let Some(lease) = self
                .leases
                .iter_mut()
                .find(|lease| lease.duid.as_slice() == duid)
            {
                lease.key = key.to_string();
                return Some(lease.address);
            }
        }
        let start = address_bits(range_start);
        let end = address_bits(range_end);
        if start > end {
            return None;
        }
        let mut candidate = start;
        loop {
            let address = address_from_bits(candidate);
            if !self.leases.iter().any(|lease| lease.address == address) {
                self.leases.push(Lease6 {
                    key: key.to_string(),
                    duid: duid.to_vec(),
                    address,
                    hostname: None,
                });
                return Some(address);
            }
            if candidate == end {
                return None;
            }
            candidate += 1;
        }
    }

    /// Give an address back. Returns the lease that was freed.
    pub fn release(&mut self, address: Ipv6Addr) -> Option<Lease6> {
        let index = self
            .leases
            .iter()
            .position(|lease| lease.address == address)?;
        Some(self.leases.remove(index))
    }

    /// The lease holding `address`, if any.
    pub fn by_address(&self, address: Ipv6Addr) -> Option<&Lease6> {
        self.leases.iter().find(|lease| lease.address == address)
    }

    /// The lease held by the machine with this id.
    pub fn by_key(&self, key: &str) -> Option<&Lease6> {
        self.leases.iter().find(|lease| lease.key == key)
    }

    /// The lease held by the client with this DUID.
    pub fn by_duid(&self, duid: &[u8]) -> Option<&Lease6> {
        self.leases
            .iter()
            .find(|lease| lease.duid.as_slice() == duid)
    }

    /// Every live lease, in allocation order.
    pub fn all(&self) -> Vec<&Lease6> {
        self.leases.iter().collect()
    }

    /// Whether no address is allocated.
    pub fn is_empty(&self) -> bool {
        self.leases.is_empty()
    }

    /// How many addresses are allocated.
    pub fn len(&self) -> usize {
        self.leases.len()
    }

    /// The address this machine already holds, keyed by id first and DUID second. The DUID lookup is
    /// what lets a renamed machine keep its address.
    fn held_address(&self, key: &str, duid: &[u8]) -> Option<Ipv6Addr> {
        if let Some(lease) = self.by_key(key) {
            return Some(lease.address);
        }
        if !duid.is_empty() {
            // Only a DUID whose holder has left: a live peer's address is not confirmed to another.
            if let Some(lease) = self.by_duid(duid).filter(|lease| !self.is_live(&lease.key)) {
                return Some(lease.address);
            }
        }
        None
    }

    /// Reserve one specific address for `key` when it is free and this client holds nothing else. This
    /// is the INIT-REBOOT case: a machine that already knows the address it wants and we have no lease
    /// for it yet. It never gives a client a second address.
    fn reserve(&mut self, key: &str, duid: &[u8], address: Ipv6Addr) -> Option<Ipv6Addr> {
        if self.leases.iter().any(|lease| lease.address == address) {
            return None;
        }
        if self
            .leases
            .iter()
            .any(|lease| lease.key == key || (!duid.is_empty() && lease.duid.as_slice() == duid))
        {
            return None;
        }
        self.leases.push(Lease6 {
            key: key.to_string(),
            duid: duid.to_vec(),
            address,
            hostname: None,
        });
        Some(address)
    }

    /// Record the name the machine was told to use, so the table describes it as we last saw it.
    fn note_hostname(&mut self, address: Ipv6Addr, hostname: Option<&str>) {
        if let Some(lease) = self
            .leases
            .iter_mut()
            .find(|lease| lease.address == address)
        {
            lease.hostname = hostname.filter(|name| !name.is_empty()).map(str::to_string);
        }
    }
}

/// The DHCPv6 server: a stateless function over the table (it holds only the answers to hand out).
#[derive(Debug, Clone)]
pub struct Dhcp6Server {
    /// The subnet layout and the options every answer carries.
    config: Dhcp6Config,
}

impl Dhcp6Server {
    /// A server that answers with `config`.
    pub fn new(config: Dhcp6Config) -> Self {
        Self { config }
    }

    /// The layout this server answers with.
    pub fn config(&self) -> &Dhcp6Config {
        &self.config
    }

    /// Answer one guest frame. Returns the whole Ethernet frames to write back on the conduit, in
    /// order (empty when the frame is not a DHCPv6 message for us, or when nothing is to be said).
    ///
    /// `key` is the machine id (its lease key) and `hostname` what the machine should be told its name
    /// is. The server is a function of its config: the only mutation is in `leases`.
    pub fn handle(
        &self,
        frame: &[u8],
        leases: &mut Lease6Table,
        key: &str,
        hostname: Option<&str>,
    ) -> Vec<Vec<u8>> {
        let Some(request) = parse_incoming(frame) else {
            return Vec::new();
        };
        if !matches!(
            request.message_type,
            MSG_SOLICIT
                | MSG_REQUEST
                | MSG_RENEW
                | MSG_REBIND
                | MSG_RELEASE
                | MSG_INFORMATION_REQUEST
        ) {
            return Vec::new();
        }
        // RFC 8415: a server discards a client message that names no client. We need the DUID both
        // to key the lease and to echo option 1, so a message without one is not answered.
        let Some(client_id) = option(request.options, OPTION_CLIENTID) else {
            return Vec::new();
        };
        let ia_na = option(request.options, OPTION_IA_NA).and_then(parse_ia_na);
        let iaid = ia_na.as_ref().map(|ia| ia.iaid).unwrap_or([0; 4]);
        let requested = ia_na.as_ref().and_then(|ia| ia.address);
        let destination = self.reply_destination(request.source, request.guest_mac);
        let (start, end) = (self.config.range_start, self.config.range_end);

        match request.message_type {
            MSG_SOLICIT => match leases.allocate(key, client_id, start, end) {
                Some(address) => {
                    leases.note_hostname(address, hostname);
                    vec![self.answer(
                        Answer::new(
                            MSG_ADVERTISE,
                            request.transaction_id,
                            client_id,
                            destination,
                            request.guest_mac,
                        )
                        .with_preference()
                        .with_address(iaid, address),
                    )]
                }
                // RFC 8415: with nothing to offer, advertise that fact rather than stay silent.
                None => vec![self.answer(
                    Answer::new(
                        MSG_ADVERTISE,
                        request.transaction_id,
                        client_id,
                        destination,
                        request.guest_mac,
                    )
                    .with_preference()
                    .with_status(STATUS_NO_ADDRS_AVAIL),
                )],
            },
            MSG_REQUEST => {
                let held = leases.held_address(key, client_id);
                let confirmed = match requested {
                    // The address we already hold for this machine: confirm it.
                    Some(address) if held == Some(address) => Some(address),
                    // A free address inside the range that the client names and no other machine holds:
                    // adopt exactly it (an INIT-REBOOT after a restart).
                    Some(address)
                        if held.is_none()
                            && in_range(address, start, end)
                            && leases.by_address(address).is_none() =>
                    {
                        leases.reserve(key, client_id, address)
                    }
                    // Anything else is refused: we will not move a machine that holds an address, and we
                    // will not grant an address another machine holds or one outside the range.
                    Some(_) => None,
                    // No address named (a renew or a request that lost its IAADDR): our held lease, or
                    // the next free one.
                    None => held.or_else(|| leases.allocate(key, client_id, start, end)),
                };
                match confirmed {
                    Some(address) => {
                        leases.note_hostname(address, hostname);
                        vec![self.answer(
                            Answer::new(
                                MSG_REPLY,
                                request.transaction_id,
                                client_id,
                                destination,
                                request.guest_mac,
                            )
                            .with_address(iaid, address),
                        )]
                    }
                    None => vec![self.answer(
                        Answer::new(
                            MSG_REPLY,
                            request.transaction_id,
                            client_id,
                            destination,
                            request.guest_mac,
                        )
                        .with_status(STATUS_NO_ADDRS_AVAIL),
                    )],
                }
            }
            // A RENEW/REBIND keeps the address the table already holds for this machine; a client with
            // no lease is treated as asking for one.
            MSG_RENEW | MSG_REBIND => match leases.allocate(key, client_id, start, end) {
                Some(address) => {
                    leases.note_hostname(address, hostname);
                    vec![self.answer(
                        Answer::new(
                            MSG_REPLY,
                            request.transaction_id,
                            client_id,
                            destination,
                            request.guest_mac,
                        )
                        .with_address(iaid, address),
                    )]
                }
                None => vec![self.answer(
                    Answer::new(
                        MSG_REPLY,
                        request.transaction_id,
                        client_id,
                        destination,
                        request.guest_mac,
                    )
                    .with_status(STATUS_NO_ADDRS_AVAIL),
                )],
            },
            MSG_RELEASE => {
                // Only the machine that holds a lease may give it back: a frame on one conduit must not
                // free an address that belongs to another.
                let owned = leases
                    .by_key(key)
                    .map(|lease| lease.address)
                    .or_else(|| leases.by_duid(client_id).map(|lease| lease.address));
                if let Some(address) = owned {
                    leases.release(address);
                }
                vec![self.answer(
                    Answer::new(
                        MSG_REPLY,
                        request.transaction_id,
                        client_id,
                        destination,
                        request.guest_mac,
                    )
                    .with_status(STATUS_SUCCESS),
                )]
            }
            // Configuration only: DNS and the domain list, and no address at all.
            MSG_INFORMATION_REQUEST => vec![self.answer(Answer::new(
                MSG_REPLY,
                request.transaction_id,
                client_id,
                destination,
                request.guest_mac,
            ))],
            _ => Vec::new(),
        }
    }

    /// Where a reply goes on the wire, given the address the request came from and the guest's MAC.
    ///
    /// A client that has configured an address sends from it, and the reply is unicast straight back.
    /// A client that has **not** configured one yet sends from `::`; the conduit's Ethernet header
    /// still carries its MAC, so we answer to the link-local that MAC forms (`link_local_of` — the same
    /// modified EUI-64 rule the codec uses for us). This is the "use the guest's link-local if you can
    /// learn it" branch: the MAC is always learnable here, so the alternative of answering to
    /// `ff02::1:2` and its mapped MAC is never needed, and the tests assert the link-local choice.
    fn reply_destination(&self, source: Ipv6Addr, guest_mac: [u8; 6]) -> Ipv6Addr {
        if !source.is_unspecified() && !source.is_multicast() {
            source
        } else {
            link_local_of(guest_mac)
        }
    }

    /// Build one whole answer frame: the DHCPv6 message in UDP 547 → 546, over IPv6 from our
    /// link-local to `destination`, in an Ethernet frame from our MAC to the guest's.
    fn answer(&self, answer: Answer<'_>) -> Vec<u8> {
        let message = self.message(&answer);
        let datagram = build_udp_v6(
            self.config.server_link_local,
            answer.destination,
            SERVER_PORT,
            CLIENT_PORT,
            &message,
        );
        ipv6_to_guest(
            answer.guest_mac,
            self.config.our_mac,
            self.config.server_link_local,
            answer.destination,
            IPPROTO_UDP,
            &datagram,
        )
    }

    /// The DHCPv6 message of an answer: message type, transaction id, then the options in the layout
    /// the tests pin down (1, 2, 3, 7, 23, 24, 13) and no padding.
    fn message(&self, answer: &Answer<'_>) -> Vec<u8> {
        let mut message = Vec::with_capacity(128);
        message.push(answer.message_type);
        message.extend_from_slice(&answer.transaction_id);
        push_option(&mut message, OPTION_CLIENTID, answer.client_id);
        push_option(&mut message, OPTION_SERVERID, &self.config.server_duid);
        if let Some((iaid, address)) = answer.ia {
            push_option(&mut message, OPTION_IA_NA, &self.ia_na(iaid, address));
        }
        if answer.preference {
            push_option(&mut message, OPTION_PREFERENCE, &[PREFERENCE_MAX]);
        }
        if !self.config.dns.is_empty() {
            let mut servers = Vec::with_capacity(self.config.dns.len() * 16);
            for server in &self.config.dns {
                servers.extend_from_slice(&server.octets());
            }
            push_option(&mut message, OPTION_DNS_SERVERS, &servers);
        }
        // The time server (option 56, RFC 5908): one suboption-1 per address, which is the shape a
        // client expects. Without it a guest would have to be told the address by hand.
        if !self.config.ntp.is_empty() {
            let mut servers = Vec::with_capacity(self.config.ntp.len() * 20);
            for server in &self.config.ntp {
                servers.extend_from_slice(&NTP_SUBOPTION_SERVER_ADDRESS.to_be_bytes());
                servers.extend_from_slice(&16u16.to_be_bytes());
                servers.extend_from_slice(&server.octets());
            }
            push_option(&mut message, OPTION_NTP_SERVER, &servers);
        }
        if let Some(domain) = self.config.domain.as_deref() {
            if let Some(wire) = domain_wire(domain) {
                push_option(&mut message, OPTION_DOMAIN_LIST, &wire);
            }
        }
        if let Some(status) = answer.status {
            push_option(&mut message, OPTION_STATUS_CODE, &status.to_be_bytes());
        }
        message
    }

    /// The value of an IA_NA option: IAID, T1, T2, then one IAADDR (address, preferred, valid).
    ///
    /// T1 is half the preferred lifetime and T2 four fifths of it, the conventional renewal points, so
    /// a guest renews with us (T1) and rebinds to us alone (T2) on a sane schedule. Both are derived
    /// from the configured preferred lifetime rather than fixed, so a deployment that shortens the
    /// lease shortens the timers with it.
    fn ia_na(&self, iaid: [u8; 4], address: Ipv6Addr) -> Vec<u8> {
        let mut value = Vec::with_capacity(40);
        value.extend_from_slice(&iaid);
        value.extend_from_slice(&self.t1().to_be_bytes());
        value.extend_from_slice(&self.t2().to_be_bytes());
        let mut iaaddr = Vec::with_capacity(24);
        iaaddr.extend_from_slice(&address.octets());
        iaaddr.extend_from_slice(&self.config.preferred_lifetime.to_be_bytes());
        iaaddr.extend_from_slice(&self.config.valid_lifetime.to_be_bytes());
        push_option(&mut value, OPTION_IAADDR, &iaaddr);
        value
    }

    /// The T1 (renew) timer handed to the client.
    fn t1(&self) -> u32 {
        self.config.preferred_lifetime / 2
    }

    /// The T2 (rebind) timer handed to the client.
    fn t2(&self) -> u32 {
        self.config.preferred_lifetime.saturating_mul(4) / 5
    }
}

/// One reply under construction: the fields every answer carries, plus the optional IA_NA and Status
/// Code options a particular message adds.
struct Answer<'a> {
    /// The message type (ADVERTISE or REPLY).
    message_type: u8,
    /// The transaction id, echoed from the request.
    transaction_id: [u8; 3],
    /// The client's DUID, echoed verbatim.
    client_id: &'a [u8],
    /// The IAID and address of the IA_NA/IAADDR, when the answer grants one.
    ia: Option<([u8; 4], Ipv6Addr)>,
    /// The Status Code, when the answer has something to say beyond the address.
    status: Option<u16>,
    /// Whether to include the Preference option (Advertise only).
    preference: bool,
    /// Where the IPv6 packet is addressed.
    destination: Ipv6Addr,
    /// The Ethernet destination.
    guest_mac: [u8; 6],
}

impl<'a> Answer<'a> {
    /// A bare answer, before the options a particular message adds.
    fn new(
        message_type: u8,
        transaction_id: [u8; 3],
        client_id: &'a [u8],
        destination: Ipv6Addr,
        guest_mac: [u8; 6],
    ) -> Self {
        Self {
            message_type,
            transaction_id,
            client_id,
            ia: None,
            status: None,
            preference: false,
            destination,
            guest_mac,
        }
    }

    /// Grant `address` under `iaid`.
    fn with_address(mut self, iaid: [u8; 4], address: Ipv6Addr) -> Self {
        self.ia = Some((iaid, address));
        self
    }

    /// Carry a Status Code option.
    fn with_status(mut self, status: u16) -> Self {
        self.status = Some(status);
        self
    }

    /// Ask to be chosen: an Advertise carries a full Preference.
    fn with_preference(mut self) -> Self {
        self.preference = true;
        self
    }
}

/// A parsed client frame: the fields an answer echoes plus the options field.
struct Incoming<'a> {
    /// The guest's MAC, learned from the Ethernet source.
    guest_mac: [u8; 6],
    /// The address the request came from (the reply's destination).
    source: Ipv6Addr,
    /// The DHCPv6 message type.
    message_type: u8,
    /// The transaction id, echoed into the answer.
    transaction_id: [u8; 3],
    /// The options field, from just after the transaction id to the end of the datagram.
    options: &'a [u8],
}

/// Parse a guest frame as a DHCPv6 message. Anything shorter, non-IPv6, non-UDP, not addressed to port
/// 547 or too short to hold a message header is `None`.
fn parse_incoming(frame: &[u8]) -> Option<Incoming<'_>> {
    let ethernet = parse_ethernet(frame)?;
    if ethernet.ethertype != ETHERTYPE_IPV6 {
        return None;
    }
    let packet = parse_ipv6(ethernet.payload)?;
    if packet.next_header != IPPROTO_UDP {
        return None;
    }
    let datagram = parse_udp(packet.payload)?;
    if datagram.dst_port != SERVER_PORT {
        return None;
    }
    let payload = datagram.payload;
    if payload.len() < 4 {
        return None;
    }
    Some(Incoming {
        guest_mac: ethernet.src,
        source: packet.src,
        message_type: payload[0],
        transaction_id: [payload[1], payload[2], payload[3]],
        options: &payload[4..],
    })
}

/// An IA_NA option: the identity association id and, when the client named one, the address it asked
/// for.
struct IaNa {
    /// The IAID, echoed into the answer.
    iaid: [u8; 4],
    /// The address inside the IA_NA's IAADDR, when there is one.
    address: Option<Ipv6Addr>,
}

/// Parse an IA_NA option value: IAID (4), T1 (4), T2 (4), then options. Values that do not carry at
/// least the 12-byte header are `None`.
fn parse_ia_na(value: &[u8]) -> Option<IaNa> {
    if value.len() < 12 {
        return None;
    }
    let iaid = [value[0], value[1], value[2], value[3]];
    let address = option(&value[12..], OPTION_IAADDR).and_then(parse_iaaddr);
    Some(IaNa { iaid, address })
}

/// The 16-byte address at the head of an IAADDR option value.
fn parse_iaaddr(value: &[u8]) -> Option<Ipv6Addr> {
    let octets: [u8; 16] = value.get(..16)?.try_into().ok()?;
    Some(Ipv6Addr::from(octets))
}

/// Walk a DHCPv6 options field, yielding `(code, value)` pairs. A truncated option ends the walk
/// quietly instead of panicking, so hostile input never reaches a slice index unchecked.
struct Options<'a> {
    /// The bytes not yet walked.
    remaining: &'a [u8],
}

impl<'a> Options<'a> {
    /// Walk an options field.
    fn new(data: &'a [u8]) -> Self {
        Self { remaining: data }
    }
}

impl<'a> Iterator for Options<'a> {
    type Item = (u16, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining.len() < 4 {
            self.remaining = &[];
            return None;
        }
        let code = u16::from_be_bytes([self.remaining[0], self.remaining[1]]);
        let length = u16::from_be_bytes([self.remaining[2], self.remaining[3]]) as usize;
        let end = 4 + length;
        if end > self.remaining.len() {
            self.remaining = &[];
            return None;
        }
        let value = &self.remaining[4..end];
        self.remaining = &self.remaining[end..];
        Some((code, value))
    }
}

/// The first option with `code`, if any.
fn option(data: &[u8], code: u16) -> Option<&[u8]> {
    Options::new(data)
        .find(|(current, _)| *current == code)
        .map(|(_, value)| value)
}

/// Append one `(u16 code, u16 length, value)` option. A value that cannot be expressed in one length
/// field is dropped rather than truncated: a malformed answer is worse than an omitted optional option.
fn push_option(out: &mut Vec<u8>, code: u16, value: &[u8]) {
    if value.len() > u16::MAX as usize {
        return;
    }
    out.extend_from_slice(&code.to_be_bytes());
    out.extend_from_slice(&(value.len() as u16).to_be_bytes());
    out.extend_from_slice(value);
}

/// Encode a domain as the DNS wire name option 24 carries: each label length-prefixed, then a zero
/// length. An empty name, or one with a label longer than 63 bytes, is `None`.
fn domain_wire(domain: &str) -> Option<Vec<u8>> {
    let mut wire = Vec::new();
    for label in domain.split('.') {
        if label.is_empty() {
            continue;
        }
        let bytes = label.as_bytes();
        if bytes.len() > DNS_LABEL_MAX {
            return None;
        }
        wire.push(bytes.len() as u8);
        wire.extend_from_slice(bytes);
    }
    if wire.is_empty() {
        return None;
    }
    wire.push(0);
    Some(wire)
}

/// The DUID-LL of a MAC: `00:03` (link-layer), `00:01` (Ethernet), then the address.
fn duid_ll(mac: [u8; 6]) -> Vec<u8> {
    let mut duid = Vec::with_capacity(10);
    duid.extend_from_slice(&DUID_LL_TYPE);
    duid.extend_from_slice(&HARDWARE_TYPE_ETHERNET);
    duid.extend_from_slice(&mac);
    duid
}

/// The 128-bit value of an address, the form ranges are compared in.
fn address_bits(address: Ipv6Addr) -> u128 {
    u128::from_be_bytes(address.octets())
}

/// The address with this 128-bit value.
fn address_from_bits(bits: u128) -> Ipv6Addr {
    Ipv6Addr::from(bits.to_be_bytes())
}

/// `address` masked to its first `prefix_len` bits.
fn mask_prefix(address: Ipv6Addr, prefix_len: u8) -> Ipv6Addr {
    if prefix_len == 0 {
        return Ipv6Addr::UNSPECIFIED;
    }
    let shift = 128 - prefix_len.min(128) as u32;
    let mask = if shift == 128 { 0 } else { u128::MAX << shift };
    address_from_bits(address_bits(address) & mask)
}

/// Whether `address` lies within the inclusive range `[start, end]`. An inverted range contains nothing.
fn in_range(address: Ipv6Addr, start: Ipv6Addr, end: Ipv6Addr) -> bool {
    let address = address_bits(address);
    let start = address_bits(start);
    let end = address_bits(end);
    start <= address && address <= end
}

/// Whether a frame is a DHCPv6 message for the server (Ethernet + IPv6 + UDP to port 547).
///
/// This is the transport-level gate an engine can route on; whether the datagram is a well-formed
/// client message is settled by [`Dhcp6Server::handle`], which quietly ignores anything else.
pub fn is_dhcp6(frame: &[u8]) -> bool {
    let Some(ethernet) = parse_ethernet(frame) else {
        return false;
    };
    if ethernet.ethertype != ETHERTYPE_IPV6 {
        return false;
    }
    let Some(packet) = parse_ipv6(ethernet.payload) else {
        return false;
    };
    if packet.next_header != IPPROTO_UDP {
        return false;
    }
    let Some(datagram) = parse_udp(packet.payload) else {
        return false;
    };
    datagram.dst_port == SERVER_PORT
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{
        build_ethernet, build_icmpv6_echo_request, build_ipv4, build_ipv6, build_udp,
        multicast_mac, transport_checksum_v6, ALL_DHCP_SERVERS_MULTICAST, BROADCAST_MAC,
        ETHERTYPE_IPV4, IPPROTO_ICMPV6,
    };
    use std::net::Ipv4Addr;

    /// The relay's MAC, the source of every answer.
    const OUR_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];
    /// The first guest.
    const GUEST_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x11, 0x22, 0x33];
    /// The second guest.
    const GUEST_MAC_B: [u8; 6] = [0x52, 0x54, 0x00, 0x11, 0x22, 0x44];
    /// The third guest.
    const GUEST_MAC_C: [u8; 6] = [0x52, 0x54, 0x00, 0x11, 0x22, 0x55];

    fn prefix() -> Ipv6Addr {
        "fd10:177::".parse().expect("a valid address")
    }

    fn address(text: &str) -> Ipv6Addr {
        text.parse().expect("a valid address")
    }

    fn config() -> Dhcp6Config {
        Dhcp6Config::for_prefix(prefix(), 64, OUR_MAC)
    }

    /// A client DUID, distinct per byte so two clients never share one.
    fn duid(byte: u8) -> Vec<u8> {
        vec![0x00, 0x03, 0x00, 0x01, 0x52, 0x54, 0x00, 0x00, 0x00, byte]
    }

    fn iaid(value: u32) -> [u8; 4] {
        value.to_be_bytes()
    }

    /// An IA_NA option, as a guest builds it, optionally naming an address.
    fn ia_na_option(id: [u8; 4], address: Option<Ipv6Addr>) -> (u16, Vec<u8>) {
        let mut value = Vec::new();
        value.extend_from_slice(&id);
        value.extend_from_slice(&0u32.to_be_bytes()); // T1
        value.extend_from_slice(&0u32.to_be_bytes()); // T2
        if let Some(address) = address {
            let mut iaaddr = Vec::new();
            iaaddr.extend_from_slice(&address.octets());
            iaaddr.extend_from_slice(&3_600u32.to_be_bytes()); // preferred
            iaaddr.extend_from_slice(&7_200u32.to_be_bytes()); // valid
            push_option(&mut value, OPTION_IAADDR, &iaaddr);
        }
        (OPTION_IA_NA, value)
    }

    /// Build a whole guest frame: an Ethernet frame from `mac`, IPv6 from `source` to the all-DHCP
    /// servers multicast, UDP 546 → 547, around a DHCPv6 message.
    fn guest_frame(
        message_type: u8,
        xid: [u8; 3],
        mac: [u8; 6],
        source: Ipv6Addr,
        options: &[(u16, Vec<u8>)],
    ) -> Vec<u8> {
        let mut message = vec![message_type];
        message.extend_from_slice(&xid);
        for (code, value) in options {
            push_option(&mut message, *code, value);
        }
        let datagram = build_udp_v6(
            source,
            ALL_DHCP_SERVERS_MULTICAST,
            CLIENT_PORT,
            SERVER_PORT,
            &message,
        );
        let packet = build_ipv6(
            source,
            ALL_DHCP_SERVERS_MULTICAST,
            IPPROTO_UDP,
            64,
            &datagram,
        );
        build_ethernet(
            multicast_mac(ALL_DHCP_SERVERS_MULTICAST),
            mac,
            ETHERTYPE_IPV6,
            &packet,
        )
    }

    /// A guest client message with the options every type shares. An INFORMATION-REQUEST carries no
    /// IA_NA; every other type does.
    #[allow(clippy::too_many_arguments)]
    fn guest_message(
        message_type: u8,
        xid: [u8; 3],
        mac: [u8; 6],
        source: Ipv6Addr,
        client_id: &[u8],
        id: [u8; 4],
        address: Option<Ipv6Addr>,
        server_id: Option<&[u8]>,
    ) -> Vec<u8> {
        let mut options: Vec<(u16, Vec<u8>)> = vec![(OPTION_CLIENTID, client_id.to_vec())];
        if let Some(server_id) = server_id {
            options.push((OPTION_SERVERID, server_id.to_vec()));
        }
        if message_type != MSG_INFORMATION_REQUEST {
            options.push(ia_na_option(id, address));
        }
        guest_frame(message_type, xid, mac, source, &options)
    }

    /// A DHCPv4 frame (UDP 68 → 67), to prove it is not mistaken for DHCPv6.
    fn dhcpv4_frame(mac: [u8; 6]) -> Vec<u8> {
        let datagram = build_udp(
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
            68,
            67,
            b"not dhcpv6",
        );
        let packet = build_ipv4(
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
            IPPROTO_UDP,
            64,
            &datagram,
        );
        build_ethernet(BROADCAST_MAC, mac, ETHERTYPE_IPV4, &packet)
    }

    /// An ICMPv6 frame (an echo request), to prove the module speaks only DHCPv6.
    fn icmpv6_frame(mac: [u8; 6], source: Ipv6Addr) -> Vec<u8> {
        let message = build_icmpv6_echo_request(source, ALL_DHCP_SERVERS_MULTICAST, 1, 1, b"ping");
        let packet = build_ipv6(
            source,
            ALL_DHCP_SERVERS_MULTICAST,
            IPPROTO_ICMPV6,
            64,
            &message,
        );
        build_ethernet(
            multicast_mac(ALL_DHCP_SERVERS_MULTICAST),
            mac,
            ETHERTYPE_IPV6,
            &packet,
        )
    }

    /// A parsed answer frame, with the fields the tests assert on.
    struct Reply {
        ethernet_dst: [u8; 6],
        ethernet_src: [u8; 6],
        ethertype: u16,
        src: Ipv6Addr,
        dst: Ipv6Addr,
        src_port: u16,
        dst_port: u16,
        checksum: u16,
        message: Vec<u8>,
    }

    impl Reply {
        fn parse(frame: &[u8]) -> Self {
            let ethernet = parse_ethernet(frame).expect("an Ethernet frame");
            assert_eq!(ethernet.ethertype, ETHERTYPE_IPV6);
            let packet = parse_ipv6(ethernet.payload).expect("an IPv6 packet");
            assert_eq!(packet.next_header, IPPROTO_UDP);
            let datagram = parse_udp(packet.payload).expect("a UDP datagram");
            Self {
                ethernet_dst: ethernet.dst,
                ethernet_src: ethernet.src,
                ethertype: ethernet.ethertype,
                src: packet.src,
                dst: packet.dst,
                src_port: datagram.src_port,
                dst_port: datagram.dst_port,
                checksum: transport_checksum_v6(
                    packet.src,
                    packet.dst,
                    IPPROTO_UDP,
                    packet.payload,
                ),
                message: datagram.payload.to_vec(),
            }
        }

        fn message_type(&self) -> u8 {
            self.message[0]
        }

        fn transaction_id(&self) -> [u8; 3] {
            [self.message[1], self.message[2], self.message[3]]
        }

        fn option(&self, code: u16) -> Option<&[u8]> {
            option(&self.message[4..], code)
        }

        fn ia(&self) -> Option<IaNa> {
            self.option(OPTION_IA_NA).and_then(parse_ia_na)
        }

        fn ia_address(&self) -> Option<Ipv6Addr> {
            self.ia().and_then(|ia| ia.address)
        }

        fn status(&self) -> Option<u16> {
            let value = self.option(OPTION_STATUS_CODE)?;
            if value.len() < 2 {
                return None;
            }
            Some(u16::from_be_bytes([value[0], value[1]]))
        }
    }

    /// Run a SOLICIT and return the address the ADVERTISE hands out.
    fn solicit(
        server: &Dhcp6Server,
        leases: &mut Lease6Table,
        key: &str,
        mac: [u8; 6],
        client_id: &[u8],
        id: [u8; 4],
        source: Ipv6Addr,
    ) -> Ipv6Addr {
        let request = guest_message(
            MSG_SOLICIT,
            [1, 2, 3],
            mac,
            source,
            client_id,
            id,
            None,
            None,
        );
        assert!(
            is_dhcp6(&request),
            "the helper builds a frame is_dhcp6 accepts"
        );
        let replies = server.handle(&request, leases, key, None);
        assert_eq!(
            replies.len(),
            1,
            "a SOLICIT is answered with exactly one ADVERTISE"
        );
        let reply = Reply::parse(&replies[0]);
        assert_eq!(reply.message_type(), MSG_ADVERTISE);
        reply
            .ia_address()
            .expect("the ADVERTISE carries an address")
    }

    /// Decode a DNS wire name (the Domain Search List's encoding) back into text.
    fn decode_domain(wire: &[u8]) -> Option<String> {
        let mut labels = Vec::new();
        let mut index = 0;
        while index < wire.len() {
            let length = wire[index] as usize;
            if length == 0 {
                return Some(labels.join("."));
            }
            let start = index + 1;
            let end = start + length;
            if end > wire.len() {
                return None;
            }
            labels.push(String::from_utf8(wire[start..end].to_vec()).ok()?);
            index = end;
        }
        None
    }

    #[test]
    fn for_prefix_lays_out_the_subnet_around_our_mac() {
        let config = Dhcp6Config::for_prefix(prefix(), 64, OUR_MAC);
        assert_eq!(
            config.server_link_local,
            link_local_of(OUR_MAC),
            "the gateway is our EUI-64 link-local"
        );
        assert_eq!(config.prefix, prefix());
        assert_eq!(config.prefix_len, 64);
        assert_eq!(
            config.server_duid,
            vec![0x00, 0x03, 0x00, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            "DUID-LL is 00:03:00:01 plus our MAC",
        );
        assert_eq!(
            config.range_start,
            address("fd10:177::1000"),
            "leases start at ::1000"
        );
        assert_eq!(
            config.range_end,
            address("fd10:177::ffff"),
            "and end at ::ffff"
        );
        assert!(
            in_range(config.range_start, config.range_start, config.range_end),
            "the range is not inverted"
        );
        assert_eq!(
            address_bits(config.range_start) >> 64,
            address_bits(config.prefix) >> 64,
            "the range starts inside the prefix",
        );
        assert_eq!(
            address_bits(config.range_end) >> 64,
            address_bits(config.prefix) >> 64,
            "the range ends inside the prefix",
        );
        assert_eq!(
            config.dns,
            vec![config.server_link_local],
            "DNS is us, so vm-<name> resolves"
        );
        assert_eq!(config.preferred_lifetime, DEFAULT_LIFETIME_SECS);
        assert_eq!(config.valid_lifetime, DEFAULT_LIFETIME_SECS);
        assert!(
            config.domain.is_none(),
            "no domain is configured by default"
        );

        // An unaligned address is masked to its prefix before the layout is chosen.
        let unaligned = Dhcp6Config::for_prefix(address("fd10:177::dead:beef"), 64, OUR_MAC);
        assert_eq!(unaligned.prefix, prefix());
        assert_eq!(unaligned.range_start, config.range_start);
    }

    #[test]
    fn a_solicit_is_advertised_with_a_lease_and_a_verifiable_frame() {
        let config = config();
        let server = Dhcp6Server::new(config.clone());
        let mut leases = Lease6Table::new();
        let client_id = duid(0x0a);
        let source = link_local_of(GUEST_MAC);

        let request = guest_message(
            MSG_SOLICIT,
            [0xde, 0xad, 0xbe],
            GUEST_MAC,
            source,
            &client_id,
            iaid(7),
            None,
            None,
        );
        assert!(is_dhcp6(&request));
        let replies = server.handle(&request, &mut leases, "vm-a", Some("vm-a"));
        assert_eq!(replies.len(), 1, "a SOLICIT is answered with an ADVERTISE");

        let reply = Reply::parse(&replies[0]);
        assert_eq!(
            reply.ethernet_dst, GUEST_MAC,
            "the answer is addressed to the guest"
        );
        assert_eq!(reply.ethernet_src, OUR_MAC, "and comes from the relay");
        assert_eq!(reply.ethertype, ETHERTYPE_IPV6);
        assert_eq!(
            reply.src, config.server_link_local,
            "the IPv6 source is our link-local"
        );
        assert_eq!(
            reply.dst, source,
            "the IPv6 destination is where the request came from"
        );
        assert_eq!(
            reply.src_port, SERVER_PORT,
            "the server answers from port 547"
        );
        assert_eq!(reply.dst_port, CLIENT_PORT, "to the client's port 546");
        assert_eq!(
            reply.checksum, 0,
            "the mandatory UDP-over-IPv6 checksum verifies"
        );

        assert_eq!(reply.message_type(), MSG_ADVERTISE);
        assert_eq!(
            reply.transaction_id(),
            [0xde, 0xad, 0xbe],
            "the transaction id is echoed"
        );
        assert_eq!(
            reply.option(OPTION_CLIENTID),
            Some(&client_id[..]),
            "option 1 echoes the client DUID"
        );
        assert_eq!(
            reply.option(OPTION_SERVERID),
            Some(&config.server_duid[..]),
            "option 2 is ours"
        );
        assert_eq!(
            reply.option(OPTION_PREFERENCE),
            Some(&[PREFERENCE_MAX][..]),
            "option 7 asks to be chosen"
        );

        let ia = reply.ia().expect("option 3 is an IA_NA");
        assert_eq!(ia.iaid, iaid(7), "the IAID is echoed");
        let address = ia.address.expect("the IA_NA contains an IAADDR");
        assert!(
            in_range(address, config.range_start, config.range_end),
            "the address is inside the range"
        );
        assert_eq!(
            address, config.range_start,
            "the first machine takes the lowest slot"
        );

        // The IA_NA's T1/T2 and the IAADDR's lifetimes are the configured ones.
        let value = reply.option(OPTION_IA_NA).expect("the IA_NA value");
        assert_eq!(
            u32::from_be_bytes([value[4], value[5], value[6], value[7]]),
            config.preferred_lifetime / 2,
            "T1 is half the preferred lifetime",
        );
        assert_eq!(
            u32::from_be_bytes([value[8], value[9], value[10], value[11]]),
            config.preferred_lifetime * 4 / 5,
            "T2 is four fifths of the preferred lifetime",
        );
        let iaaddr = option(&value[12..], OPTION_IAADDR).expect("the IAADDR");
        assert_eq!(
            &iaaddr[..16],
            &address.octets()[..],
            "the IAADDR holds the address"
        );
        assert_eq!(
            u32::from_be_bytes([iaaddr[16], iaaddr[17], iaaddr[18], iaaddr[19]]),
            config.preferred_lifetime,
            "the preferred lifetime is the configured one",
        );
        assert_eq!(
            u32::from_be_bytes([iaaddr[20], iaaddr[21], iaaddr[22], iaaddr[23]]),
            config.valid_lifetime,
            "the valid lifetime is the configured one",
        );

        assert_eq!(leases.len(), 1, "the SOLICIT commits the lease");
        assert_eq!(
            leases.by_key("vm-a").map(|lease| lease.address),
            Some(address)
        );
        assert_eq!(
            leases
                .by_key("vm-a")
                .and_then(|lease| lease.hostname.as_deref()),
            Some("vm-a")
        );
    }

    #[test]
    fn a_request_for_the_advertised_address_is_replied_with_it() {
        let config = config();
        let server = Dhcp6Server::new(config.clone());
        let mut leases = Lease6Table::new();
        let client_id = duid(0x0a);
        let source = link_local_of(GUEST_MAC);
        let advertised = solicit(
            &server,
            &mut leases,
            "vm-a",
            GUEST_MAC,
            &client_id,
            iaid(7),
            source,
        );

        let request = guest_message(
            MSG_REQUEST,
            [0x01, 0x02, 0x03],
            GUEST_MAC,
            source,
            &client_id,
            iaid(7),
            Some(advertised),
            Some(&config.server_duid),
        );
        let replies = server.handle(&request, &mut leases, "vm-a", Some("vm-a"));
        assert_eq!(replies.len(), 1, "a REQUEST is answered with a REPLY");
        let reply = Reply::parse(&replies[0]);
        assert_eq!(reply.message_type(), MSG_REPLY);
        assert_eq!(reply.transaction_id(), [0x01, 0x02, 0x03]);
        assert_eq!(reply.checksum, 0, "the reply checksum verifies");
        assert_eq!(reply.option(OPTION_CLIENTID), Some(&client_id[..]));
        assert_eq!(reply.option(OPTION_SERVERID), Some(&config.server_duid[..]));
        assert!(
            reply.option(OPTION_PREFERENCE).is_none(),
            "a REPLY carries no Preference"
        );
        assert!(
            reply.status().is_none(),
            "a granted request needs no status"
        );
        let ia = reply.ia().expect("option 3 is an IA_NA");
        assert_eq!(ia.iaid, iaid(7), "the IAID comes from the request");
        assert_eq!(
            ia.address,
            Some(advertised),
            "the advertised address is confirmed"
        );
        assert_eq!(
            leases.by_key("vm-a").map(|lease| lease.address),
            Some(advertised)
        );
    }

    #[test]
    fn two_clients_get_different_addresses_and_each_keeps_its_own() {
        let config = config();
        let server = Dhcp6Server::new(config.clone());
        let mut leases = Lease6Table::new();
        let source = link_local_of(GUEST_MAC);

        let a = solicit(
            &server,
            &mut leases,
            "vm-a",
            GUEST_MAC,
            &duid(0x0a),
            iaid(1),
            source,
        );
        let b = solicit(
            &server,
            &mut leases,
            "vm-b",
            GUEST_MAC_B,
            &duid(0x0b),
            iaid(2),
            source,
        );
        assert_ne!(a, b, "two machines never share an address");
        assert_eq!(
            a, config.range_start,
            "the first machine takes the first slot"
        );
        assert_ne!(b, config.range_start, "the second takes the next");

        let a_again = solicit(
            &server,
            &mut leases,
            "vm-a",
            GUEST_MAC,
            &duid(0x0a),
            iaid(1),
            source,
        );
        let b_again = solicit(
            &server,
            &mut leases,
            "vm-b",
            GUEST_MAC_B,
            &duid(0x0b),
            iaid(2),
            source,
        );
        assert_eq!(a_again, a, "a second SOLICIT keeps the lease");
        assert_eq!(b_again, b, "for both machines");
        assert_eq!(leases.len(), 2, "and does not leak leases");
    }

    #[test]
    fn a_renew_keeps_the_address_and_a_release_frees_it_for_the_next_client() {
        let server = Dhcp6Server::new(config());
        let mut leases = Lease6Table::new();
        let client_id = duid(0x0a);
        let source = link_local_of(GUEST_MAC);
        let a = solicit(
            &server,
            &mut leases,
            "vm-a",
            GUEST_MAC,
            &client_id,
            iaid(1),
            source,
        );

        // A RENEW names the address it is keeping.
        let renew = guest_message(
            MSG_RENEW,
            [2, 2, 2],
            GUEST_MAC,
            source,
            &client_id,
            iaid(1),
            Some(a),
            None,
        );
        let reply = Reply::parse(&server.handle(&renew, &mut leases, "vm-a", None)[0]);
        assert_eq!(reply.message_type(), MSG_REPLY);
        assert_eq!(reply.ia_address(), Some(a), "a RENEW keeps the address");
        assert_eq!(leases.by_key("vm-a").map(|lease| lease.address), Some(a));

        // A REBIND behaves the same.
        let rebind = guest_message(
            MSG_REBIND,
            [3, 3, 3],
            GUEST_MAC,
            source,
            &client_id,
            iaid(1),
            Some(a),
            None,
        );
        let reply = Reply::parse(&server.handle(&rebind, &mut leases, "vm-a", None)[0]);
        assert_eq!(reply.message_type(), MSG_REPLY);
        assert_eq!(reply.ia_address(), Some(a), "a REBIND keeps the address");

        // A RELEASE frees it and is acknowledged.
        let release = guest_message(
            MSG_RELEASE,
            [4, 4, 4],
            GUEST_MAC,
            source,
            &client_id,
            iaid(1),
            Some(a),
            None,
        );
        let reply = Reply::parse(&server.handle(&release, &mut leases, "vm-a", None)[0]);
        assert_eq!(reply.message_type(), MSG_REPLY);
        assert_eq!(
            reply.status(),
            Some(STATUS_SUCCESS),
            "a RELEASE is acknowledged"
        );
        assert!(reply.ia().is_none(), "and grants nothing");
        assert!(leases.is_empty(), "the address is given back");

        // The freed lowest slot goes to the next machine.
        let c = solicit(
            &server,
            &mut leases,
            "vm-c",
            GUEST_MAC_C,
            &duid(0x0c),
            iaid(5),
            source,
        );
        assert_eq!(c, a, "a freed address is allocated again");
    }

    #[test]
    fn an_exhausted_range_is_refused_with_no_addrs_avail() {
        let mut config = config();
        config.range_end = config.range_start; // a single address
        let server = Dhcp6Server::new(config.clone());
        let mut leases = Lease6Table::new();
        let source = link_local_of(GUEST_MAC);

        let a = solicit(
            &server,
            &mut leases,
            "vm-a",
            GUEST_MAC,
            &duid(0x0a),
            iaid(1),
            source,
        );
        assert_eq!(a, config.range_start);

        // The allocator itself reports exhaustion.
        assert_eq!(
            leases.allocate("vm-b", &duid(0x0b), config.range_start, config.range_end),
            None
        );
        assert_eq!(leases.len(), 1, "a failed allocation creates no lease");

        // A REQUEST for the only address, held by another machine, is a Reply with NoAddrsAvail.
        let request = guest_message(
            MSG_REQUEST,
            [5, 5, 5],
            GUEST_MAC_B,
            source,
            &duid(0x0b),
            iaid(2),
            Some(a),
            None,
        );
        let replies = server.handle(&request, &mut leases, "vm-b", None);
        assert_eq!(replies.len(), 1, "a REQUEST is still answered");
        let reply = Reply::parse(&replies[0]);
        assert_eq!(reply.message_type(), MSG_REPLY);
        assert_eq!(reply.status(), Some(STATUS_NO_ADDRS_AVAIL));
        assert!(reply.ia().is_none(), "a refused reply carries no address");
        assert!(leases.by_key("vm-b").is_none(), "and creates no lease");

        // A REQUEST that names nothing is refused the same way when the range is full.
        let request = guest_message(
            MSG_REQUEST,
            [6, 6, 6],
            GUEST_MAC_B,
            source,
            &duid(0x0b),
            iaid(2),
            None,
            None,
        );
        let reply = Reply::parse(&server.handle(&request, &mut leases, "vm-b", None)[0]);
        assert_eq!(reply.status(), Some(STATUS_NO_ADDRS_AVAIL));
    }

    #[test]
    fn an_advertise_with_no_room_carries_no_addrs_avail() {
        let mut config = config();
        config.range_end = config.range_start;
        let server = Dhcp6Server::new(config.clone());
        let mut leases = Lease6Table::new();
        let source = link_local_of(GUEST_MAC);
        let taken = solicit(
            &server,
            &mut leases,
            "vm-a",
            GUEST_MAC,
            &duid(0x0a),
            iaid(1),
            source,
        );
        assert_eq!(taken, config.range_start);

        let request = guest_message(
            MSG_SOLICIT,
            [7, 7, 7],
            GUEST_MAC_B,
            source,
            &duid(0x0b),
            iaid(2),
            None,
            None,
        );
        let reply = Reply::parse(&server.handle(&request, &mut leases, "vm-b", None)[0]);
        assert_eq!(reply.message_type(), MSG_ADVERTISE);
        assert_eq!(
            reply.status(),
            Some(STATUS_NO_ADDRS_AVAIL),
            "an Advertise can say there is no room"
        );
        assert!(reply.ia().is_none());
        assert!(leases.by_key("vm-b").is_none());
    }

    #[test]
    fn an_information_request_gets_dns_and_domain_and_no_address() {
        let mut config = config();
        config.domain = Some("vms.local".to_string());
        let server = Dhcp6Server::new(config.clone());
        let mut leases = Lease6Table::new();
        let client_id = duid(0x0a);
        let source = link_local_of(GUEST_MAC);

        let request = guest_message(
            MSG_INFORMATION_REQUEST,
            [8, 8, 8],
            GUEST_MAC,
            source,
            &client_id,
            iaid(1),
            None,
            None,
        );
        let replies = server.handle(&request, &mut leases, "vm-a", None);
        assert_eq!(replies.len(), 1);
        let reply = Reply::parse(&replies[0]);
        assert_eq!(reply.message_type(), MSG_REPLY);
        assert_eq!(reply.option(OPTION_CLIENTID), Some(&client_id[..]));
        assert_eq!(reply.option(OPTION_SERVERID), Some(&config.server_duid[..]));
        assert!(
            reply.option(OPTION_IA_NA).is_none(),
            "an INFORMATION-REQUEST is answered without an address"
        );
        assert!(reply.ia_address().is_none());
        assert_eq!(
            reply.option(OPTION_DNS_SERVERS),
            Some(&config.server_link_local.octets()[..]),
            "option 23 carries our link-local as the resolver",
        );
        assert!(
            reply.option(OPTION_DOMAIN_LIST).is_some(),
            "option 24 carries the domain"
        );
        // Option 56 (RFC 5908) is the time server, as suboption 1 with our own link-local: it is what
        // makes a guest sync without being configured.
        let ntp = reply
            .option(OPTION_NTP_SERVER)
            .expect("option 56 carries the NTP server");
        assert_eq!(&ntp[..2], &NTP_SUBOPTION_SERVER_ADDRESS.to_be_bytes());
        assert_eq!(&ntp[2..4], &16u16.to_be_bytes(), "one 16-byte address");
        assert_eq!(&ntp[4..], &config.server_link_local.octets()[..]);
        assert!(leases.is_empty(), "configuration alone creates no lease");
    }

    #[test]
    fn garbage_truncated_and_foreign_frames_answer_nothing() {
        let server = Dhcp6Server::new(config());
        let mut leases = Lease6Table::new();
        let source = link_local_of(GUEST_MAC);
        let client_id = duid(0x0a);

        // Noise of every length, including a full-size frame.
        let noise: Vec<u8> = (0..1500u32)
            .map(|i| (i.wrapping_mul(37) % 251) as u8)
            .collect();
        assert!(server.handle(&noise, &mut leases, "vm-a", None).is_empty());
        assert!(server.handle(&[], &mut leases, "vm-a", None).is_empty());
        assert!(server
            .handle(&[0xff; 14], &mut leases, "vm-a", None)
            .is_empty());

        // A real frame cut at every interesting boundary: Ethernet, IPv6, UDP, the DHCPv6 header and
        // each option. A prefix of a frame is never a frame.
        let valid = guest_message(
            MSG_SOLICIT,
            [1, 1, 1],
            GUEST_MAC,
            source,
            &client_id,
            iaid(1),
            None,
            None,
        );
        for cut in [
            0usize,
            1,
            13,
            14,
            20,
            39,
            40,
            47,
            48,
            53,
            54,
            58,
            59,
            60,
            62,
            63,
            70,
            valid.len() - 1,
        ] {
            assert!(
                server
                    .handle(&valid[..cut], &mut leases, "vm-a", None)
                    .is_empty(),
                "a frame cut at {cut} is ignored",
            );
        }

        // A datagram to port 547 whose payload is not a DHCPv6 message at all.
        let datagram = build_udp_v6(
            source,
            ALL_DHCP_SERVERS_MULTICAST,
            CLIENT_PORT,
            SERVER_PORT,
            b"not dhcpv6",
        );
        let packet = build_ipv6(
            source,
            ALL_DHCP_SERVERS_MULTICAST,
            IPPROTO_UDP,
            64,
            &datagram,
        );
        let frame = build_ethernet(
            multicast_mac(ALL_DHCP_SERVERS_MULTICAST),
            GUEST_MAC,
            ETHERTYPE_IPV6,
            &packet,
        );
        assert!(is_dhcp6(&frame), "it is routed to DHCPv6 by transport");
        assert!(
            server.handle(&frame, &mut leases, "vm-a", None).is_empty(),
            "but it is not answered"
        );

        // Frames from other protocols.
        assert!(server
            .handle(&dhcpv4_frame(GUEST_MAC), &mut leases, "vm-a", None)
            .is_empty());
        assert!(server
            .handle(&icmpv6_frame(GUEST_MAC, source), &mut leases, "vm-a", None)
            .is_empty());

        assert!(leases.is_empty(), "no malformed frame creates a lease");
    }

    #[test]
    fn is_dhcp6_recognizes_dhcpv6_and_rejects_other_protocols() {
        let source = link_local_of(GUEST_MAC);
        assert!(is_dhcp6(&guest_message(
            MSG_SOLICIT,
            [0; 3],
            GUEST_MAC,
            source,
            &duid(1),
            iaid(1),
            None,
            None
        )));
        assert!(is_dhcp6(&guest_message(
            MSG_REQUEST,
            [0; 3],
            GUEST_MAC,
            source,
            &duid(1),
            iaid(1),
            None,
            None
        )));

        assert!(
            !is_dhcp6(&dhcpv4_frame(GUEST_MAC)),
            "a DHCPv4 frame is not DHCPv6"
        );
        assert!(
            !is_dhcp6(&icmpv6_frame(GUEST_MAC, source)),
            "an ICMPv6 frame is not DHCPv6"
        );

        // UDP to a port other than 547.
        let datagram = build_udp_v6(source, ALL_DHCP_SERVERS_MULTICAST, 546, 53, b"dns");
        let packet = build_ipv6(
            source,
            ALL_DHCP_SERVERS_MULTICAST,
            IPPROTO_UDP,
            64,
            &datagram,
        );
        let frame = build_ethernet(
            multicast_mac(ALL_DHCP_SERVERS_MULTICAST),
            GUEST_MAC,
            ETHERTYPE_IPV6,
            &packet,
        );
        assert!(!is_dhcp6(&frame));

        assert!(!is_dhcp6(&[]), "an empty frame is not DHCPv6");
        assert!(!is_dhcp6(&[0u8; 14]), "nor is a header with no payload");
    }

    #[test]
    fn the_domain_search_list_is_dns_encoded_and_round_trips() {
        let mut config = config();
        config.domain = Some("vms.local".to_string());
        let server = Dhcp6Server::new(config);
        let mut leases = Lease6Table::new();
        let source = link_local_of(GUEST_MAC);
        let client_id = duid(0x0a);

        let request = guest_message(
            MSG_INFORMATION_REQUEST,
            [9, 9, 9],
            GUEST_MAC,
            source,
            &client_id,
            iaid(1),
            None,
            None,
        );
        let reply = Reply::parse(&server.handle(&request, &mut leases, "vm-a", None)[0]);
        let wire = reply
            .option(OPTION_DOMAIN_LIST)
            .expect("option 24 is present");
        assert_eq!(
            wire,
            &[3, b'v', b'm', b's', 5, b'l', b'o', b'c', b'a', b'l', 0],
            "labels are length-prefixed and the name is zero-terminated",
        );
        assert_eq!(
            decode_domain(wire).as_deref(),
            Some("vms.local"),
            "the encoding round-trips"
        );
    }

    #[test]
    fn a_solicit_from_the_unspecified_source_is_answered_to_the_macs_link_local() {
        let server = Dhcp6Server::new(config());
        let mut leases = Lease6Table::new();
        let client_id = duid(0x0a);

        // A client that has not configured an address sends from `::`.
        let request = guest_message(
            MSG_SOLICIT,
            [1, 2, 3],
            GUEST_MAC,
            Ipv6Addr::UNSPECIFIED,
            &client_id,
            iaid(1),
            None,
            None,
        );
        let replies = server.handle(&request, &mut leases, "vm-a", None);
        assert_eq!(replies.len(), 1);
        let reply = Reply::parse(&replies[0]);
        assert_eq!(
            reply.ethernet_dst, GUEST_MAC,
            "the Ethernet destination is still the guest's MAC"
        );
        assert_eq!(
            reply.dst,
            link_local_of(GUEST_MAC),
            "an unanswered `::` source is replaced by the link-local the guest's MAC forms",
        );
        assert_eq!(reply.src, server.config().server_link_local);
        assert_eq!(reply.checksum, 0, "and the packet is still a valid one");
    }

    #[test]
    fn a_release_only_frees_the_releasing_machines_lease() {
        let server = Dhcp6Server::new(config());
        let mut leases = Lease6Table::new();
        let source = link_local_of(GUEST_MAC);
        let a = solicit(
            &server,
            &mut leases,
            "vm-a",
            GUEST_MAC,
            &duid(0x0a),
            iaid(1),
            source,
        );
        let b = solicit(
            &server,
            &mut leases,
            "vm-b",
            GUEST_MAC_B,
            &duid(0x0b),
            iaid(2),
            source,
        );
        assert_eq!(leases.len(), 2);

        // vm-b names vm-a's address in its RELEASE.
        let release = guest_message(
            MSG_RELEASE,
            [3, 3, 3],
            GUEST_MAC_B,
            source,
            &duid(0x0b),
            iaid(2),
            Some(a),
            None,
        );
        let reply = Reply::parse(&server.handle(&release, &mut leases, "vm-b", None)[0]);
        assert_eq!(reply.status(), Some(STATUS_SUCCESS));
        assert_eq!(
            leases.by_address(a).map(|lease| lease.key.as_str()),
            Some("vm-a"),
            "vm-a keeps its address"
        );
        assert!(
            leases.by_address(b).is_none(),
            "vm-b gave its own address back"
        );
        assert_eq!(leases.len(), 1);
    }

    #[test]
    fn a_request_for_a_free_address_reserves_exactly_it_and_a_foreign_one_is_refused() {
        let config = config();
        let server = Dhcp6Server::new(config.clone());
        let mut leases = Lease6Table::new();
        let source = link_local_of(GUEST_MAC);
        let a = solicit(
            &server,
            &mut leases,
            "vm-a",
            GUEST_MAC,
            &duid(0x0a),
            iaid(1),
            source,
        );
        assert_eq!(a, config.range_start);

        // vm-b asks for a specific free address that is not the lowest: it is granted exactly that.
        let wanted = address_from_bits(address_bits(config.range_start) + 5);
        let request = guest_message(
            MSG_REQUEST,
            [9, 9, 9],
            GUEST_MAC_B,
            source,
            &duid(0x0b),
            iaid(2),
            Some(wanted),
            None,
        );
        let reply = Reply::parse(&server.handle(&request, &mut leases, "vm-b", None)[0]);
        assert_eq!(reply.message_type(), MSG_REPLY);
        assert_eq!(
            reply.ia_address(),
            Some(wanted),
            "the requested free address, not the lowest"
        );
        assert_eq!(
            leases.by_key("vm-b").map(|lease| lease.address),
            Some(wanted)
        );

        // vm-c asks for the address vm-a holds: no second machine gets it.
        let request = guest_message(
            MSG_REQUEST,
            [10, 10, 10],
            GUEST_MAC_C,
            source,
            &duid(0x0c),
            iaid(3),
            Some(a),
            None,
        );
        let reply = Reply::parse(&server.handle(&request, &mut leases, "vm-c", None)[0]);
        assert_eq!(reply.status(), Some(STATUS_NO_ADDRS_AVAIL));
        assert!(leases.by_key("vm-c").is_none());

        // An address outside the range is refused too.
        let outside = address_from_bits(address_bits(config.range_end) + 1);
        let request = guest_message(
            MSG_REQUEST,
            [11, 11, 11],
            GUEST_MAC_C,
            source,
            &duid(0x0c),
            iaid(3),
            Some(outside),
            None,
        );
        let reply = Reply::parse(&server.handle(&request, &mut leases, "vm-c", None)[0]);
        assert_eq!(
            reply.status(),
            Some(STATUS_NO_ADDRS_AVAIL),
            "an address outside the range is refused"
        );

        // A machine that already holds an address cannot move itself to a free one.
        let request = guest_message(
            MSG_REQUEST,
            [12, 12, 12],
            GUEST_MAC,
            source,
            &duid(0x0a),
            iaid(1),
            Some(wanted),
            None,
        );
        let reply = Reply::parse(&server.handle(&request, &mut leases, "vm-a", None)[0]);
        assert_eq!(
            reply.status(),
            Some(STATUS_NO_ADDRS_AVAIL),
            "one machine, one address"
        );
        assert_eq!(leases.by_key("vm-a").map(|lease| lease.address), Some(a));
    }

    #[test]
    fn a_message_without_a_client_identifier_is_not_answered() {
        let server = Dhcp6Server::new(config());
        let mut leases = Lease6Table::new();
        let source = link_local_of(GUEST_MAC);

        // A SOLICIT with only an IA_NA: RFC 8415 has the server discard it, and so do we.
        let options = vec![ia_na_option(iaid(1), None)];
        let frame = guest_frame(MSG_SOLICIT, [1, 1, 1], GUEST_MAC, source, &options);
        assert!(is_dhcp6(&frame), "it is still a DHCPv6 frame by transport");
        assert!(server.handle(&frame, &mut leases, "vm-a", None).is_empty());
        assert!(leases.is_empty());

        // A server message type from a guest is not answered either.
        let request = guest_message(
            MSG_ADVERTISE,
            [2, 2, 2],
            GUEST_MAC,
            source,
            &duid(0x0a),
            iaid(1),
            None,
            None,
        );
        assert!(server
            .handle(&request, &mut leases, "vm-a", None)
            .is_empty());
    }

    #[test]
    fn allocation_is_sticky_by_key_and_by_duid() {
        let (start, end) = (config().range_start, config().range_end);
        let mut leases = Lease6Table::new();
        let client = duid(0x0a);

        let first = leases
            .allocate("vm-a", &client, start, end)
            .expect("room for one");
        assert_eq!(
            leases.allocate("vm-a", &client, start, end),
            Some(first),
            "the key keeps the address"
        );

        // A machine renamed between runs keeps its address through its DUID.
        assert_eq!(leases.allocate("renamed", &client, start, end), Some(first));
        assert!(
            leases.by_key("vm-a").is_none(),
            "the old key no longer holds it"
        );
        assert_eq!(
            leases.by_key("renamed").map(|lease| lease.address),
            Some(first)
        );
        assert_eq!(
            leases.by_duid(&client).map(|lease| lease.address),
            Some(first)
        );
        assert_eq!(leases.len(), 1);

        // A different DUID gets a different address.
        let second = leases
            .allocate("vm-b", &duid(0x0b), start, end)
            .expect("room for two");
        assert_ne!(first, second);

        // An inverted range is empty, not a panic.
        assert_eq!(leases.allocate("vm-c", &duid(0x0c), end, start), None);

        // A release returns the lease and frees the slot for the next client.
        assert_eq!(
            leases.release(first).map(|lease| lease.key),
            Some("renamed".to_string())
        );
        assert!(leases.by_address(first).is_none());
        assert_eq!(
            leases.allocate("vm-c", &duid(0x0c), start, end),
            Some(first),
            "the lowest freed slot is reused"
        );
    }

    #[test]
    fn lease_table_lookups_and_iteration_are_consistent() {
        let empty = Lease6Table::new();
        assert!(empty.is_empty());
        assert_eq!(empty.len(), 0);
        assert!(empty.all().is_empty());
        assert!(empty.by_address(config().range_start).is_none());
        assert!(empty.by_key("nobody").is_none());
        assert!(empty.by_duid(&duid(1)).is_none());

        let mut leases = Lease6Table::new();
        let (start, end) = (config().range_start, config().range_end);
        let address = leases
            .allocate("vm-a", &duid(0x0a), start, end)
            .expect("room");
        assert!(!leases.is_empty());
        assert_eq!(leases.len(), 1);
        assert_eq!(leases.all().len(), 1);
        assert_eq!(
            leases.by_address(address).map(|lease| lease.key.as_str()),
            Some("vm-a")
        );
        assert_eq!(
            leases.by_key("vm-a").map(|lease| lease.address),
            Some(address)
        );
        assert_eq!(
            leases.by_duid(&duid(0x0a)).map(|lease| lease.address),
            Some(address)
        );
    }
}
