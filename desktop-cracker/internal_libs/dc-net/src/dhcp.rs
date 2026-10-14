//! The lease allocator and the DHCP server.
//!
//! A machine's network is a unix-socket conduit, so there is **no kernel network stack** on the far
//! side: nothing answers the guest's `DHCPDISCOVER` unless we do. That makes this module load-bearing
//! rather than convenient — it is the single address allocator for the whole network, and the reason
//! two machines can never be handed the same address. It is also where the guest is told what
//! its gateway and DNS are: the relay's own address and, when a workspace names one, its resolver.
//!
//! The design is deliberately small:
//!
//! - **One lease per machine, keyed by the machine id** (with the MAC as a fallback), so a restart
//!   replays the same address.  Addresses are allocated from the lowest free slot in the configured
//!   range, which makes a restart of the process reproducible.
//! - **The server is a stateless function over the table.** It holds only [`DhcpConfig`] — the answers
//!   — and every call receives the [`LeaseTable`] it should mutate. Persisting the table is the
//!   caller's business.
//! - **Answers are unicast** to the guest's MAC from the relay's MAC: the conduit has exactly one
//!   peer, so a broadcast frame would reach nobody else and only cost clarity. The *IPv4* destination
//!   is the broadcast address, though, because a client that has not been configured yet has no
//!   address to receive on.
//! - **Frames are built with [`crate::frame`]**, so every length and checksum is the codec's problem,
//!   and a malformed or hostile frame is a dropped packet — never a panic.
//!
//! Only the small part of RFC 2131/2132 a guest actually needs is implemented: DISCOVER → OFFER,
//! REQUEST → ACK/NAK, RELEASE and DECLINE free a lease. Nothing here renews on a timer; the lease
//! time is an answer we hand out, not a clock we keep.

use std::net::Ipv4Addr;

use crate::frame::{
    build_udp, ipv4_to_guest, parse_ethernet, parse_ipv4, parse_udp, ETHERTYPE_IPV4, IPPROTO_UDP,
};

/// The UDP port a DHCP server listens on.
const SERVER_PORT: u16 = 67;
/// The UDP port a DHCP client listens on.
const CLIENT_PORT: u16 = 68;
/// The RFC 1048 / RFC 2132 magic cookie that begins the options field.
const MAGIC_COOKIE: [u8; 4] = [99, 130, 83, 99];
/// `BOOTREQUEST`: a client message.
const BOOTREQUEST: u8 = 1;
/// `BOOTREPLY`: a server message.
const BOOTREPLY: u8 = 2;
/// Hardware type 1: Ethernet.
const HTYPE_ETHERNET: u8 = 1;
/// The hardware address length of an Ethernet MAC.
const HARDWARE_LEN: u8 = 6;
/// The fixed BOOTP header, up to (not including) the options field.
const BOOTP_FIXED_LEN: usize = 236;
/// The RFC 2131 minimum DHCP message length, in octets. Real clients (and `dhclient`) expect it, so
/// the answer is padded with the pad option rather than sent short.
const MIN_BOOTP_LEN: usize = 300;

/// How long a default lease is: a day. The address is effectively permanent for a machine (the table
/// makes it sticky), so the value only bounds how often a guest renews.
const DEFAULT_LEASE_SECS: u32 = 86_400;

/// DHCP message type: the client is looking for a server.
const DHCP_DISCOVER: u8 = 1;
/// DHCP message type: a server's offer of an address.
const DHCP_OFFER: u8 = 2;
/// DHCP message type: the client is asking for (or renewing) an address.
const DHCP_REQUEST: u8 = 3;
/// DHCP message type: the client refuses an address it was offered.
const DHCP_DECLINE: u8 = 4;
/// DHCP message type: the server confirms an address.
const DHCP_ACK: u8 = 5;
/// DHCP message type: the server refuses the client's notion of its address.
const DHCP_NAK: u8 = 6;
/// DHCP message type: the client gives an address back.
const DHCP_RELEASE: u8 = 7;

/// Option 0: padding.
const OPTION_PAD: u8 = 0;
/// Option 1: the subnet mask.
const OPTION_SUBNET_MASK: u8 = 1;
/// Option 3: the default gateway.
const OPTION_ROUTER: u8 = 3;
/// Option 6: the DNS resolver.
const OPTION_DNS: u8 = 6;
/// Option 12: the client's hostname.
const OPTION_HOSTNAME: u8 = 12;
/// Option 15: the DNS domain name.
const OPTION_DOMAIN: u8 = 15;
/// Option 26: the interface MTU.
const OPTION_MTU: u8 = 26;
/// Option 42: the NTP servers (RFC 2132), which is this relay.
const OPTION_NTP: u8 = 42;
/// Option 50: the address the client is asking for.
const OPTION_REQUESTED_IP: u8 = 50;
/// Option 51: the lease time in seconds.
const OPTION_LEASE_TIME: u8 = 51;
/// Option 53: the DHCP message type.
const OPTION_MESSAGE_TYPE: u8 = 53;
/// Option 54: the selected server's identifier.
const OPTION_SERVER_ID: u8 = 54;
/// Option 255: the end of the options field.
const OPTION_END: u8 = 255;

/// The layout of our internal subnet and the answers the guest is given.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DhcpConfig {
    /// The DHCP server's address. The relay answers from this address, and it is also the identifier a
    /// client must name in option 54 for its REQUEST to be confirmed.
    pub server_ip: Ipv4Addr,
    /// The gateway the guest is handed (option 3). Same address as the server: the relay is the only
    /// way out of the conduit.
    pub gateway_ip: Ipv4Addr,
    /// The DNS resolver the guest is handed (option 6).
    pub dns_ip: Ipv4Addr,
    /// The NTP server the guest is handed (option 42). Same address as the resolver: the relay answers
    /// the time itself, so a guest needs nothing configured to have a right clock.
    pub ntp_ip: Ipv4Addr,
    /// The subnet mask the guest is handed (option 1).
    pub netmask: Ipv4Addr,
    /// The first address in the allocatable range, inclusive.
    pub range_start: Ipv4Addr,
    /// The last address in the allocatable range, inclusive.
    pub range_end: Ipv4Addr,
    /// The lease time handed out in option 51, in seconds.
    pub lease_secs: u32,
    /// The DNS domain pushed in option 15, when one is configured.
    pub domain: Option<String>,
    /// The interface MTU pushed in option 26, when one is configured.
    pub mtu: Option<u16>,
}

impl DhcpConfig {
    /// The default layout for `subnet` with `prefix` bits (e.g. `10.177.0.0` / 16).
    ///
    /// The server, gateway and DNS all live at the **first host address of the subnet** — for the
    /// default `10.177.0.0/16` that is `10.177.0.1`, the `.1` of the first `/24`-aligned block, so the
    /// address is the same memorable `.1` whatever the prefix. Leases start at `.16` of that first
    /// block and run to the last usable address of the subnet: the low addresses (including `.2`–`.15`)
    /// stay free for anything this process itself may need to place by hand, and starting at a fixed
    /// slot rather than at `.2` keeps allocation deterministic across restarts.
    ///
    /// The subnet is masked to its network first, so an unaligned input such as `10.177.5.9/16` lays
    /// out exactly as `10.177.0.0/16` does. A prefix narrower than a `/24` (so small the `.16` start
    /// falls outside the subnet) yields an empty range rather than a wrong one.
    pub fn for_subnet(subnet: Ipv4Addr, prefix: u8) -> Self {
        let prefix = prefix.min(32);
        let mask = mask_for_prefix(prefix);
        let network = u32::from_be_bytes(subnet.octets()) & mask;
        let broadcast = network | !mask;
        let server = Ipv4Addr::from(network.saturating_add(1).to_be_bytes());
        let range_start = Ipv4Addr::from(network.saturating_add(16).to_be_bytes());
        let range_end = Ipv4Addr::from(broadcast.saturating_sub(1).to_be_bytes());
        Self {
            server_ip: server,
            gateway_ip: server,
            dns_ip: server,
            ntp_ip: server,
            netmask: Ipv4Addr::from(mask.to_be_bytes()),
            range_start,
            range_end,
            lease_secs: DEFAULT_LEASE_SECS,
            domain: None,
            mtu: None,
        }
    }
}

/// The network mask for `prefix` bits, as a 32-bit value.
fn mask_for_prefix(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else if prefix >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix)
    }
}

/// Whether `ip` lies within the inclusive range `[start, end]`. An inverted range contains nothing.
fn in_range(ip: Ipv4Addr, start: Ipv4Addr, end: Ipv4Addr) -> bool {
    let ip = u32::from_be_bytes(ip.octets());
    let start = u32::from_be_bytes(start.octets());
    let end = u32::from_be_bytes(end.octets());
    start <= ip && ip <= end
}

/// One address handed to one machine. `key` is the machine id (sticky across restarts).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Lease {
    /// The machine id the address belongs to.
    pub key: String,
    /// The machine's MAC, as last seen.
    pub mac: [u8; 6],
    /// The address handed out.
    pub ip: Ipv4Addr,
    /// The hostname the machine was told to use, when one was known at allocation time.
    pub hostname: Option<String>,
}

/// The allocator: one address per key/mac, never two.
///
/// The table is small (a handful of machines) and read rarely, so a `Vec` in allocation order is both
/// the cheapest and the most predictable structure: scanning for the lowest free address is a scan,
/// and [`LeaseTable::all`] hands a stable order back to the caller that persists it.
#[derive(Default, Clone)]
pub struct LeaseTable {
    /// Every live lease, in the order it was allocated.
    leases: Vec<Lease>,
    /// Addresses a machine has refused (an option-4 DECLINE), remembered so the same address is not
    /// offered to the same machine again. It is per-machine on purpose: the address itself is fine,
    /// the machine just should not be given it back.
    declined: Vec<(String, Ipv4Addr)>,
    /// Whether a lease's holder is still on the network (see [`LeaseTable::set_liveness`]).
    live: Option<LiveCheck>,
    /// The addresses the leases above hold, so "is this candidate free?" is a lookup rather than a scan
    /// of every lease. Without it, placing the N-th peer of a busy deployment is N comparisons per
    /// candidate and N candidates — the whole table under one lock, measured at 2.7s for 1600 live
    /// peers before this index existed.
    used: std::collections::HashSet<u32>,
}

impl std::fmt::Debug for LeaseTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LeaseTable")
            .field("leases", &self.leases)
            .field("declined", &self.declined)
            .field("liveness", &self.live.is_some())
            .field("used", &self.used.len())
            .finish()
    }
}

/// Whether the peer holding a lease is **still on the network**. Installed by the engine, which owns
/// the directory of live peers; the lease table itself knows only keys.
///
/// It is what keeps the one dangerous promise honest: a machine may keep its address across a rename
/// **because its old entry is gone**, never because a *live* peer's identity (a MAC, a DUID) was
/// presented to the table. Without it an address in use could be handed to a second live peer, and two
/// peers sharing an address is a shared identity across workspaces.
pub type LiveCheck = std::sync::Arc<dyn Fn(&str) -> bool + Send + Sync>;

impl LeaseTable {
    /// An empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Install the directory the table asks before it moves an address from one key to another.
    ///
    /// With none installed nothing is known to be live and the historical behaviour stands (a MAC match
    /// re-keys a lease); the engine always installs one, and its tests pin both sides.
    pub fn set_liveness(&mut self, live: LiveCheck) {
        self.live = Some(live);
    }

    /// Whether this key is on the network right now.
    fn is_live(&self, key: &str) -> bool {
        self.live.as_ref().map(|live| live(key)).unwrap_or(false)
    }

    /// The address for `key` (or for a machine with this MAC), allocating the lowest free one in
    /// `[range_start, range_end]` when it has none. Sticky: the same key always gets the same address.
    ///
    /// A machine that reaches the table under a new key but the same MAC keeps its address (the MAC is
    /// derived from the VM, so this is what makes a lease survive a rename). Returns `None` only when
    /// the range is exhausted — or when every remaining candidate is one this machine has declined.
    pub fn allocate(
        &mut self,
        key: &str,
        mac: [u8; 6],
        range_start: Ipv4Addr,
        range_end: Ipv4Addr,
    ) -> Option<Ipv4Addr> {
        if let Some(existing) = self.lease_for(key, mac) {
            return Some(existing);
        }
        let start = u32::from_be_bytes(range_start.octets());
        let end = u32::from_be_bytes(range_end.octets());
        if start > end {
            return None;
        }
        for candidate in start..=end {
            if self.used.contains(&candidate) {
                continue;
            }
            let ip = Ipv4Addr::from(candidate.to_be_bytes());
            if self.is_declined(key, ip) {
                continue;
            }
            self.leases.push(Lease {
                key: key.to_string(),
                mac,
                ip,
                hostname: None,
            });
            self.used.insert(candidate);
            return Some(ip);
        }
        None
    }

    /// Give an address back. Returns the lease that was freed.
    pub fn release(&mut self, ip: Ipv4Addr) -> Option<Lease> {
        let index = self.leases.iter().position(|lease| lease.ip == ip)?;
        self.used.remove(&u32::from_be_bytes(ip.octets()));
        Some(self.leases.remove(index))
    }

    /// The lease holding `ip`, if any.
    pub fn by_ip(&self, ip: Ipv4Addr) -> Option<&Lease> {
        self.leases.iter().find(|lease| lease.ip == ip)
    }

    /// The lease held by the machine with this id.
    pub fn by_key(&self, key: &str) -> Option<&Lease> {
        self.leases.iter().find(|lease| lease.key == key)
    }

    /// Every live lease, in allocation order.
    pub fn all(&self) -> Vec<&Lease> {
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

    /// The address this machine already holds, keyed by id first and MAC second. Finding it by MAC
    /// re-keys the lease, so a renamed machine keeps its address under its new id. The MAC is also
    /// refreshed when the key matches, so the table always describes the machine as we last saw it.
    fn lease_for(&mut self, key: &str, mac: [u8; 6]) -> Option<Ipv4Addr> {
        if let Some(lease) = self.leases.iter_mut().find(|lease| lease.key == key) {
            if lease.mac != mac {
                lease.mac = mac;
            }
            return Some(lease.ip);
        }
        // A **live** peer's address is not moved: a MAC collision (two peers can present one — this
        // deployment's MACs carry 24 bits of identity) must cost the newcomer a fresh address, never
        // the incumbent its lease. A MAC whose holder is gone is the reinstall/rename case, and that
        // one keeps the address.
        let holder_live = self
            .leases
            .iter()
            .find(|lease| lease.mac == mac)
            .map(|lease| lease.key.clone())
            .filter(|holder| self.is_live(holder));
        if holder_live.is_some() {
            return None;
        }
        if let Some(lease) = self.leases.iter_mut().find(|lease| lease.mac == mac) {
            lease.key = key.to_string();
            return Some(lease.ip);
        }
        None
    }

    /// Whether `key` has refused `ip`.
    fn is_declined(&self, key: &str, ip: Ipv4Addr) -> bool {
        self.declined
            .iter()
            .any(|(declined_by, declined_ip)| declined_by == key && *declined_ip == ip)
    }

    /// Remember that `key` refused `ip`, and free it if this machine was the holder. The address stays
    /// available to every other machine: only this one must not be given it again this session.
    fn decline(&mut self, key: &str, ip: Ipv4Addr) -> Option<Lease> {
        if !self.is_declined(key, ip) {
            self.declined.push((key.to_string(), ip));
        }
        if self
            .leases
            .iter()
            .any(|lease| lease.ip == ip && lease.key == key)
        {
            self.release(ip)
        } else {
            None
        }
    }

    /// Reserve one specific address for `key` when it is free and inside the range. This is the
    /// INIT-REBOOT case: a machine that already knows the address it wants and we have no lease for
    /// it yet. It never moves a machine that already holds a different address.
    fn reserve(
        &mut self,
        key: &str,
        mac: [u8; 6],
        ip: Ipv4Addr,
        range_start: Ipv4Addr,
        range_end: Ipv4Addr,
    ) -> Option<Ipv4Addr> {
        if !in_range(ip, range_start, range_end) || self.is_declined(key, ip) {
            return None;
        }
        if self
            .leases
            .iter()
            .any(|lease| lease.ip == ip && lease.key != key)
        {
            return None;
        }
        if let Some(existing) = self.lease_for(key, mac) {
            return (existing == ip).then_some(existing);
        }
        self.leases.push(Lease {
            key: key.to_string(),
            mac,
            ip,
            hostname: None,
        });
        self.used.insert(u32::from_be_bytes(ip.octets()));
        Some(ip)
    }
}

/// The DHCP server: a stateless function over the table (it holds only the answers to hand out).
#[derive(Debug, Clone)]
pub struct DhcpServer {
    /// The subnet layout and the options every answer carries.
    config: DhcpConfig,
}

impl DhcpServer {
    /// A server that answers with `config`.
    pub fn new(config: DhcpConfig) -> Self {
        Self { config }
    }

    /// The layout this server answers with.
    pub fn config(&self) -> &DhcpConfig {
        &self.config
    }

    /// Answer one guest frame. Returns the frames to write back on the conduit, in order (empty when
    /// the frame is not a DHCP message for us, or when nothing is to be said).
    ///
    /// `key` is the machine id, `guest_mac` its MAC, `our_mac` the relay's MAC (the source of every
    /// answer), `hostname` is what this machine should be told its name is (from the VM's name).
    pub fn handle(
        &self,
        frame: &[u8],
        leases: &mut LeaseTable,
        key: &str,
        guest_mac: [u8; 6],
        our_mac: [u8; 6],
        hostname: Option<&str>,
    ) -> Vec<Vec<u8>> {
        let Some(request) = parse_bootp_request(frame) else {
            return Vec::new();
        };
        let Some(message_type) = option_value(request.options, OPTION_MESSAGE_TYPE)
            .and_then(|data| data.first().copied())
        else {
            return Vec::new();
        };
        match message_type {
            DHCP_DISCOVER => {
                match leases.allocate(
                    key,
                    guest_mac,
                    self.config.range_start,
                    self.config.range_end,
                ) {
                    Some(ip) => {
                        vec![self.answer(DHCP_OFFER, request.xid, ip, guest_mac, our_mac, hostname)]
                    }
                    None => Vec::new(),
                }
            }
            DHCP_REQUEST => {
                self.answer_request(&request, leases, key, guest_mac, our_mac, hostname)
            }
            DHCP_DECLINE => {
                // The client refused what it was offered. Free it and make sure this machine is not
                // handed the same address again; the address itself stays in the pool for others.
                if let Some(ip) = requested_or_ciaddr(&request)
                    .or_else(|| leases.by_key(key).map(|lease| lease.ip))
                {
                    leases.decline(key, ip);
                }
                Vec::new()
            }
            DHCP_RELEASE => {
                if let Some(ip) = requested_or_ciaddr(&request)
                    .or_else(|| leases.by_key(key).map(|lease| lease.ip))
                {
                    // Only the machine that holds a lease may give it back: a frame on one conduit
                    // must not free an address that belongs to another.
                    let owned = leases
                        .by_ip(ip)
                        .is_some_and(|lease| lease.key == key || lease.mac == guest_mac);
                    if owned {
                        leases.release(ip);
                    }
                }
                Vec::new()
            }
            // OFFER, ACK and NAK are server messages: a guest sending them is not answered.
            _ => Vec::new(),
        }
    }

    /// Answer a REQUEST with an ACK or a NAK.
    fn answer_request(
        &self,
        request: &Bootp<'_>,
        leases: &mut LeaseTable,
        key: &str,
        guest_mac: [u8; 6],
        our_mac: [u8; 6],
        hostname: Option<&str>,
    ) -> Vec<Vec<u8>> {
        let server_id = option_ip(request.options, OPTION_SERVER_ID);
        let requested = option_ip(request.options, OPTION_REQUESTED_IP);
        // A client that names a server identifier is answering an OFFER. If it named somebody else,
        // that server owns the decision and we say no rather than confirm a lease we did not grant.
        if server_id.is_some_and(|id| id != self.config.server_ip) {
            return vec![self.answer(
                DHCP_NAK,
                request.xid,
                Ipv4Addr::UNSPECIFIED,
                guest_mac,
                our_mac,
                hostname,
            )];
        }
        let held = leases.lease_for(key, guest_mac);
        let confirmed = match requested {
            // The address we already hold for this machine: confirm it.
            Some(ip) if Some(ip) == held => Some(ip),
            // An address we do not hold: adopt it only if it is free and in range (an INIT-REBOOT
            // after a restart), otherwise refuse — we cannot give this machine that address.
            Some(ip) => leases.reserve(
                key,
                guest_mac,
                ip,
                self.config.range_start,
                self.config.range_end,
            ),
            // No address named (a renew or a malformed request): our held lease, or the next free one.
            None => held.or_else(|| {
                leases.allocate(
                    key,
                    guest_mac,
                    self.config.range_start,
                    self.config.range_end,
                )
            }),
        };
        match confirmed {
            Some(ip) => vec![self.answer(DHCP_ACK, request.xid, ip, guest_mac, our_mac, hostname)],
            None => vec![self.answer(
                DHCP_NAK,
                request.xid,
                Ipv4Addr::UNSPECIFIED,
                guest_mac,
                our_mac,
                hostname,
            )],
        }
    }

    /// Build one whole answer frame: BOOTP reply, UDP 67 → 68, IPv4 to the guest's MAC.
    fn answer(
        &self,
        message_type: u8,
        xid: u32,
        yiaddr: Ipv4Addr,
        guest_mac: [u8; 6],
        our_mac: [u8; 6],
        hostname: Option<&str>,
    ) -> Vec<u8> {
        let bootp = self.bootp(message_type, xid, yiaddr, guest_mac, hostname);
        // The client may have no address yet, so the datagram is addressed to the broadcast address;
        // the Ethernet frame is unicast to the one peer the conduit has.
        let datagram = build_udp(
            self.config.server_ip,
            Ipv4Addr::BROADCAST,
            SERVER_PORT,
            CLIENT_PORT,
            &bootp,
        );
        ipv4_to_guest(
            guest_mac,
            our_mac,
            self.config.server_ip,
            Ipv4Addr::BROADCAST,
            IPPROTO_UDP,
            &datagram,
        )
    }

    /// The BOOTP payload of an answer, options and padding included.
    fn bootp(
        &self,
        message_type: u8,
        xid: u32,
        yiaddr: Ipv4Addr,
        guest_mac: [u8; 6],
        hostname: Option<&str>,
    ) -> Vec<u8> {
        let mut bootp = Vec::with_capacity(MIN_BOOTP_LEN);
        bootp.push(BOOTREPLY);
        bootp.push(HTYPE_ETHERNET);
        bootp.push(HARDWARE_LEN);
        bootp.push(0); // hops
        bootp.extend_from_slice(&xid.to_be_bytes());
        bootp.extend_from_slice(&0u16.to_be_bytes()); // secs
        bootp.extend_from_slice(&0u16.to_be_bytes()); // flags: we unicast, so never the broadcast bit
        bootp.extend_from_slice(&[0u8; 4]); // ciaddr
        bootp.extend_from_slice(&yiaddr.octets());
        bootp.extend_from_slice(&[0u8; 4]); // siaddr: no next-server
        bootp.extend_from_slice(&[0u8; 4]); // giaddr: we are not a relay
        bootp.extend_from_slice(&guest_mac);
        bootp.extend_from_slice(&[0u8; 10]); // chaddr is 16 bytes
        bootp.extend_from_slice(&[0u8; 64]); // sname
        bootp.extend_from_slice(&[0u8; 128]); // file
        bootp.extend_from_slice(&MAGIC_COOKIE);

        push_option(&mut bootp, OPTION_MESSAGE_TYPE, &[message_type]);
        push_option(
            &mut bootp,
            OPTION_SERVER_ID,
            &self.config.server_ip.octets(),
        );
        // A NAK carries no lease and no parameters: it says only "that address is not yours".
        if message_type != DHCP_NAK {
            push_option(
                &mut bootp,
                OPTION_LEASE_TIME,
                &self.config.lease_secs.to_be_bytes(),
            );
            push_option(
                &mut bootp,
                OPTION_SUBNET_MASK,
                &self.config.netmask.octets(),
            );
            push_option(&mut bootp, OPTION_ROUTER, &self.config.gateway_ip.octets());
            push_option(&mut bootp, OPTION_DNS, &self.config.dns_ip.octets());
            // The time server (option 42, RFC 2132), which is this relay too: a stock
            // systemd-networkd guest hands it to systemd-timesyncd, and chrony's `sourcedir
            // /run/chrony-dhcp` reads it, so the clock is right with no configuration in the guest.
            push_option(&mut bootp, OPTION_NTP, &self.config.ntp_ip.octets());
            if let Some(domain) = &self.config.domain {
                push_option(&mut bootp, OPTION_DOMAIN, domain.as_bytes());
            }
            if let Some(mtu) = self.config.mtu {
                push_option(&mut bootp, OPTION_MTU, &mtu.to_be_bytes());
            }
            if let Some(hostname) = hostname.filter(|name| !name.is_empty()) {
                push_option(&mut bootp, OPTION_HOSTNAME, hostname.as_bytes());
            }
        }
        bootp.push(OPTION_END);
        bootp.resize(bootp.len().max(MIN_BOOTP_LEN), OPTION_PAD);
        bootp
    }
}

/// Whether a frame is a DHCP message for the server (Ethernet + IPv4 + UDP to port 67).
///
/// This is the transport-level gate an engine can route on; whether the datagram is a well-formed
/// BOOTP request (a BOOTREQUEST carrying the magic cookie) is settled by [`DhcpServer::handle`], which
/// quietly ignores anything else.
pub fn is_dhcp(frame: &[u8]) -> bool {
    let Some(ethernet) = parse_ethernet(frame) else {
        return false;
    };
    if ethernet.ethertype != ETHERTYPE_IPV4 {
        return false;
    }
    let Some(packet) = parse_ipv4(ethernet.payload) else {
        return false;
    };
    if packet.protocol != IPPROTO_UDP {
        return false;
    }
    let Some(datagram) = parse_udp(packet.payload) else {
        return false;
    };
    datagram.dst_port == SERVER_PORT
}

/// A parsed BOOTP request: the fields an answer echoes, plus the options field.
struct Bootp<'a> {
    /// The transaction id, echoed into the answer.
    xid: u32,
    /// The client's current address, meaningful on RENEW/RELEASE.
    ciaddr: Ipv4Addr,
    /// The options field, from just after the magic cookie to the end of the datagram.
    options: &'a [u8],
}

/// Parse a guest frame as a well-formed BOOTP/DHCP request. Anything shorter, non-IPv4, non-UDP, not
/// addressed to port 67, not a BOOTREQUEST or missing the magic cookie is `None`.
fn parse_bootp_request(frame: &[u8]) -> Option<Bootp<'_>> {
    let ethernet = parse_ethernet(frame)?;
    if ethernet.ethertype != ETHERTYPE_IPV4 {
        return None;
    }
    let packet = parse_ipv4(ethernet.payload)?;
    if packet.protocol != IPPROTO_UDP {
        return None;
    }
    let datagram = parse_udp(packet.payload)?;
    if datagram.dst_port != SERVER_PORT {
        return None;
    }
    let payload = datagram.payload;
    if payload.len() < BOOTP_FIXED_LEN + MAGIC_COOKIE.len() {
        return None;
    }
    if payload[0] != BOOTREQUEST || payload[1] != HTYPE_ETHERNET || payload[2] != HARDWARE_LEN {
        return None;
    }
    if payload[BOOTP_FIXED_LEN..BOOTP_FIXED_LEN + MAGIC_COOKIE.len()] != MAGIC_COOKIE {
        return None;
    }
    let xid = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);
    let ciaddr = Ipv4Addr::new(payload[12], payload[13], payload[14], payload[15]);
    Some(Bootp {
        xid,
        ciaddr,
        options: &payload[BOOTP_FIXED_LEN + MAGIC_COOKIE.len()..],
    })
}

/// Walk the options field and return the first option with `code`, bounds-checking every step so a
/// truncated or hostile field is `None` rather than a panic.
fn option_value(options: &[u8], code: u8) -> Option<&[u8]> {
    let mut index = 0;
    while index < options.len() {
        let current = options[index];
        if current == OPTION_PAD {
            index += 1;
            continue;
        }
        if current == OPTION_END {
            return None;
        }
        let length = *options.get(index + 1)? as usize;
        let start = index + 2;
        let end = start.checked_add(length)?;
        if end > options.len() {
            return None;
        }
        if current == code {
            return Some(&options[start..end]);
        }
        index = end;
    }
    None
}

/// The four-byte address an option carries (options 50 and 54), if it is well formed.
fn option_ip(options: &[u8], code: u8) -> Option<Ipv4Addr> {
    let data = option_value(options, code)?;
    if data.len() != 4 {
        return None;
    }
    Some(Ipv4Addr::new(data[0], data[1], data[2], data[3]))
}

/// The address a RELEASE/DECLINE is about: option 50 when the client names one, otherwise its
/// `ciaddr` (a bare RELEASE carries the address there).
fn requested_or_ciaddr(request: &Bootp<'_>) -> Option<Ipv4Addr> {
    option_ip(request.options, OPTION_REQUESTED_IP)
        .or_else(|| (!request.ciaddr.is_unspecified()).then_some(request.ciaddr))
}

/// Append one TLV option. An option whose value cannot be expressed in one length byte is dropped
/// rather than truncated: a malformed answer is worse than an omitted optional option.
fn push_option(out: &mut Vec<u8>, code: u8, data: &[u8]) {
    if data.len() > u8::MAX as usize {
        return;
    }
    out.push(code);
    out.push(data.len() as u8);
    out.extend_from_slice(data);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::{
        build_ethernet, build_icmp_echo_request, build_ipv4, checksum, transport_checksum,
        BROADCAST_MAC,
    };

    /// The relay's MAC, the source of every answer.
    const OUR_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

    fn ip(text: &str) -> Ipv4Addr {
        text.parse().expect("a valid address")
    }

    /// Build a guest frame around a BOOTP request, exactly as a client would put it on the wire:
    /// Ethernet broadcast from `mac`, IPv4 0.0.0.0 → 255.255.255.255, UDP 68 → 67.
    fn guest_frame(
        message_type: u8,
        xid: u32,
        mac: [u8; 6],
        ciaddr: Ipv4Addr,
        options: &[(u8, Vec<u8>)],
    ) -> Vec<u8> {
        let mut bootp = Vec::with_capacity(MIN_BOOTP_LEN);
        bootp.push(BOOTREQUEST);
        bootp.push(HTYPE_ETHERNET);
        bootp.push(HARDWARE_LEN);
        bootp.push(0); // hops
        bootp.extend_from_slice(&xid.to_be_bytes());
        bootp.extend_from_slice(&0u16.to_be_bytes()); // secs
        bootp.extend_from_slice(&0x8000u16.to_be_bytes()); // the client sets the broadcast flag
        bootp.extend_from_slice(&ciaddr.octets());
        bootp.extend_from_slice(&[0u8; 12]); // yiaddr, siaddr, giaddr
        bootp.extend_from_slice(&mac);
        bootp.extend_from_slice(&[0u8; 10]); // chaddr is 16 bytes
        bootp.extend_from_slice(&[0u8; 64]); // sname
        bootp.extend_from_slice(&[0u8; 128]); // file
        bootp.extend_from_slice(&MAGIC_COOKIE);
        bootp.push(OPTION_MESSAGE_TYPE);
        bootp.push(1);
        bootp.push(message_type);
        for (code, data) in options {
            bootp.push(*code);
            bootp.push(data.len() as u8);
            bootp.extend_from_slice(data);
        }
        bootp.push(OPTION_END);
        bootp.resize(bootp.len().max(MIN_BOOTP_LEN), OPTION_PAD);

        let datagram = build_udp(
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
            CLIENT_PORT,
            SERVER_PORT,
            &bootp,
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

    /// Parse an answer frame into its options, `yiaddr` and `xid`.
    fn parse_answer(frame: &[u8]) -> (Vec<u8>, Ipv4Addr, u32) {
        let ethernet = parse_ethernet(frame).expect("an Ethernet frame");
        let packet = parse_ipv4(ethernet.payload).expect("an IPv4 packet");
        let datagram = parse_udp(packet.payload).expect("a UDP datagram");
        let bootp = datagram.payload;
        assert!(
            bootp.len() >= MIN_BOOTP_LEN,
            "an answer is padded to the DHCP minimum"
        );
        let yiaddr = Ipv4Addr::new(bootp[16], bootp[17], bootp[18], bootp[19]);
        let xid = u32::from_be_bytes([bootp[4], bootp[5], bootp[6], bootp[7]]);
        (bootp[240..].to_vec(), yiaddr, xid)
    }

    fn option(options: &[u8], code: u8) -> Option<Vec<u8>> {
        option_value(options, code).map(<[u8]>::to_vec)
    }

    /// Whether the options field is explicitly terminated by option 255.
    fn has_end(options: &[u8]) -> bool {
        let mut index = 0;
        while index < options.len() {
            match options[index] {
                OPTION_PAD => index += 1,
                OPTION_END => return true,
                _ => {
                    let Some(length) = options.get(index + 1).copied().map(usize::from) else {
                        return false;
                    };
                    index += 2 + length;
                }
            }
        }
        false
    }

    fn message_type(options: &[u8]) -> Option<u8> {
        option(options, OPTION_MESSAGE_TYPE).and_then(|data| data.first().copied())
    }

    /// Run a DISCOVER and return the OFFER's options and `yiaddr`.
    fn offer(
        server: &DhcpServer,
        leases: &mut LeaseTable,
        key: &str,
        mac: [u8; 6],
        xid: u32,
        hostname: Option<&str>,
    ) -> (Vec<u8>, Ipv4Addr) {
        assert!(is_dhcp(&guest_frame(
            DHCP_DISCOVER,
            xid,
            mac,
            Ipv4Addr::UNSPECIFIED,
            &[]
        )));
        let request = guest_frame(DHCP_DISCOVER, xid, mac, Ipv4Addr::UNSPECIFIED, &[]);
        let replies = server.handle(&request, leases, key, mac, OUR_MAC, hostname);
        assert_eq!(
            replies.len(),
            1,
            "a DISCOVER is answered with exactly one OFFER"
        );
        let (options, yiaddr, _) = parse_answer(&replies[0]);
        assert_eq!(message_type(&options), Some(DHCP_OFFER));
        (options, yiaddr)
    }

    fn range() -> (Ipv4Addr, Ipv4Addr) {
        (ip("10.177.0.16"), ip("10.177.255.254"))
    }

    #[test]
    fn a_discover_is_offered_an_address_from_the_range_with_a_verifiable_frame() {
        let config = DhcpConfig::for_subnet(ip("10.177.0.0"), 16);
        let server = DhcpServer::new(config.clone());
        let mut leases = LeaseTable::new();
        let mac = [0x52, 0x54, 0x00, 0x11, 0x22, 0x33];

        let request = guest_frame(DHCP_DISCOVER, 0xdead_beef, mac, Ipv4Addr::UNSPECIFIED, &[]);
        let replies = server.handle(&request, &mut leases, "vm-a", mac, OUR_MAC, Some("vm-a"));
        assert_eq!(replies.len(), 1, "a DISCOVER is answered with an OFFER");

        let ethernet = parse_ethernet(&replies[0]).expect("a frame");
        assert_eq!(ethernet.dst, mac, "the answer is addressed to the guest");
        assert_eq!(ethernet.src, OUR_MAC, "and comes from the relay");
        assert_eq!(ethernet.ethertype, ETHERTYPE_IPV4);

        let packet_bytes = ethernet.payload;
        assert_eq!(
            checksum(&packet_bytes[..20]),
            0,
            "the IPv4 header checksum verifies"
        );
        let packet = parse_ipv4(packet_bytes).expect("a packet");
        assert_eq!(packet.protocol, IPPROTO_UDP);
        assert_eq!(packet.src, config.server_ip);
        assert_eq!(
            transport_checksum(packet.src, packet.dst, IPPROTO_UDP, packet.payload),
            0,
            "the UDP checksum verifies",
        );
        let datagram = parse_udp(packet.payload).expect("a datagram");
        assert_eq!(
            datagram.src_port, SERVER_PORT,
            "the server answers from port 67"
        );
        assert_eq!(datagram.dst_port, CLIENT_PORT, "to the client's port 68");

        let bootp = datagram.payload;
        assert!(
            bootp.len() >= MIN_BOOTP_LEN,
            "the answer is padded to the BOOTP minimum"
        );
        assert_eq!(bootp[0], BOOTREPLY, "op is BOOTREPLY");
        assert_eq!(
            u32::from_be_bytes([bootp[4], bootp[5], bootp[6], bootp[7]]),
            0xdead_beef,
            "the xid is echoed"
        );
        let yiaddr = Ipv4Addr::new(bootp[16], bootp[17], bootp[18], bootp[19]);
        assert!(
            in_range(yiaddr, config.range_start, config.range_end),
            "the offer is inside the range"
        );
        assert_eq!(&bootp[20..24], &[0u8; 4], "siaddr stays zero");
        assert_eq!(&bootp[24..28], &[0u8; 4], "giaddr stays zero");
        assert_eq!(
            &bootp[236..240],
            &MAGIC_COOKIE,
            "the magic cookie is present"
        );

        let options = &bootp[240..];
        assert_eq!(message_type(options), Some(DHCP_OFFER));
        assert_eq!(
            option(options, OPTION_SERVER_ID).as_deref(),
            Some(&config.server_ip.octets()[..])
        );
        assert_eq!(
            option(options, OPTION_LEASE_TIME).map(|value| value.len()),
            Some(4),
            "option 51 has a time"
        );
        assert_eq!(
            option(options, OPTION_SUBNET_MASK).as_deref(),
            Some(&config.netmask.octets()[..])
        );
        assert_eq!(
            option(options, OPTION_ROUTER).as_deref(),
            Some(&config.gateway_ip.octets()[..])
        );
        assert_eq!(
            option(options, OPTION_DNS).as_deref(),
            Some(&config.dns_ip.octets()[..])
        );
        // Option 42 is the time server, and it is this relay: a guest that trusts its lease has a right
        // clock without a single line of configuration.
        assert_eq!(
            option(options, OPTION_NTP).as_deref(),
            Some(&config.ntp_ip.octets()[..])
        );
        assert_eq!(
            config.ntp_ip, config.gateway_ip,
            "the relay answers the time itself"
        );
        assert_eq!(
            option(options, OPTION_HOSTNAME).as_deref(),
            Some(&b"vm-a"[..])
        );
        assert!(has_end(options), "the options field is terminated");
    }

    #[test]
    fn a_request_is_acknowledged_with_the_same_address_and_xid() {
        let config = DhcpConfig::for_subnet(ip("10.177.0.0"), 16);
        let server = DhcpServer::new(config.clone());
        let mut leases = LeaseTable::new();
        let mac = [0x52, 0x54, 0x00, 0x11, 0x22, 0x33];
        let (_, offered) = offer(&server, &mut leases, "vm-a", mac, 1, Some("vm-a"));

        let request = guest_frame(
            DHCP_REQUEST,
            0x0102_0304,
            mac,
            Ipv4Addr::UNSPECIFIED,
            &[
                (OPTION_REQUESTED_IP, offered.octets().to_vec()),
                (OPTION_SERVER_ID, config.server_ip.octets().to_vec()),
            ],
        );
        let replies = server.handle(&request, &mut leases, "vm-a", mac, OUR_MAC, Some("vm-a"));
        assert_eq!(replies.len(), 1, "a REQUEST is answered");
        let (options, yiaddr, xid) = parse_answer(&replies[0]);
        assert_eq!(message_type(&options), Some(DHCP_ACK));
        assert_eq!(yiaddr, offered, "the ACK confirms the offered address");
        assert_eq!(xid, 0x0102_0304, "with the client's transaction id");
        assert_eq!(
            option(&options, OPTION_SERVER_ID).as_deref(),
            Some(&config.server_ip.octets()[..])
        );
    }

    #[test]
    fn a_request_without_a_server_id_renews_the_held_address() {
        let config = DhcpConfig::for_subnet(ip("10.177.0.0"), 16);
        let server = DhcpServer::new(config);
        let mut leases = LeaseTable::new();
        let mac = [0x52, 0x54, 0x00, 0x11, 0x22, 0x33];
        let (_, offered) = offer(&server, &mut leases, "vm-a", mac, 1, None);

        // A renewing client sets ciaddr and names neither a server nor a requested address.
        let request = guest_frame(DHCP_REQUEST, 2, mac, offered, &[]);
        let replies = server.handle(&request, &mut leases, "vm-a", mac, OUR_MAC, None);
        assert_eq!(replies.len(), 1);
        let (options, yiaddr, _) = parse_answer(&replies[0]);
        assert_eq!(message_type(&options), Some(DHCP_ACK));
        assert_eq!(yiaddr, offered);
    }

    #[test]
    fn a_request_for_a_foreign_server_or_address_is_refused() {
        let config = DhcpConfig::for_subnet(ip("10.177.0.0"), 16);
        let server = DhcpServer::new(config.clone());
        let mut leases = LeaseTable::new();
        let mac = [0x52, 0x54, 0x00, 0x11, 0x22, 0x34];
        let (_, offered) = offer(&server, &mut leases, "vm-a", mac, 1, None);

        // The client accepted another server's offer.
        let foreign = guest_frame(
            DHCP_REQUEST,
            2,
            mac,
            Ipv4Addr::UNSPECIFIED,
            &[
                (OPTION_REQUESTED_IP, offered.octets().to_vec()),
                (OPTION_SERVER_ID, ip("10.177.9.9").octets().to_vec()),
            ],
        );
        let replies = server.handle(&foreign, &mut leases, "vm-a", mac, OUR_MAC, None);
        assert_eq!(replies.len(), 1);
        let (options, yiaddr, _) = parse_answer(&replies[0]);
        assert_eq!(
            message_type(&options),
            Some(DHCP_NAK),
            "another server's grant is not ours to confirm"
        );
        assert!(yiaddr.is_unspecified(), "a NAK carries no address");

        // The client asks for an address outside the range.
        let outside = guest_frame(
            DHCP_REQUEST,
            3,
            mac,
            Ipv4Addr::UNSPECIFIED,
            &[(OPTION_REQUESTED_IP, ip("10.178.0.5").octets().to_vec())],
        );
        let replies = server.handle(&outside, &mut leases, "vm-a", mac, OUR_MAC, None);
        assert_eq!(replies.len(), 1);
        let (options, _, _) = parse_answer(&replies[0]);
        assert_eq!(
            message_type(&options),
            Some(DHCP_NAK),
            "an address outside the range is refused"
        );

        // The client asks for a different address inside the range that this machine does not hold.
        let other = guest_frame(
            DHCP_REQUEST,
            4,
            mac,
            Ipv4Addr::UNSPECIFIED,
            &[(OPTION_REQUESTED_IP, ip("10.177.0.99").octets().to_vec())],
        );
        let replies = server.handle(&other, &mut leases, "vm-a", mac, OUR_MAC, None);
        assert_eq!(
            message_type(&parse_answer(&replies[0]).0),
            Some(DHCP_NAK),
            "a machine may not move itself"
        );
    }

    #[test]
    fn two_machines_get_different_addresses_and_each_keeps_its_own() {
        let config = DhcpConfig::for_subnet(ip("10.177.0.0"), 16);
        let server = DhcpServer::new(config.clone());
        let mut leases = LeaseTable::new();
        let mac_a = [0x52, 0x54, 0x00, 0x00, 0x00, 0x0a];
        let mac_b = [0x52, 0x54, 0x00, 0x00, 0x00, 0x0b];

        let (_, a) = offer(&server, &mut leases, "vm-a", mac_a, 1, None);
        let (_, b) = offer(&server, &mut leases, "vm-b", mac_b, 2, None);
        assert_ne!(a, b, "two machines never share an address");
        assert_eq!(
            a, config.range_start,
            "the first machine takes the first slot"
        );

        let (_, a_again) = offer(&server, &mut leases, "vm-a", mac_a, 3, None);
        let (_, b_again) = offer(&server, &mut leases, "vm-b", mac_b, 4, None);
        assert_eq!(a_again, a, "a second DISCOVER keeps the lease");
        assert_eq!(b_again, b, "for both machines");
        assert_eq!(leases.len(), 2, "offers do not leak leases");
    }

    #[test]
    fn a_release_returns_the_address_to_the_pool() {
        let config = DhcpConfig::for_subnet(ip("10.177.0.0"), 16);
        let server = DhcpServer::new(config.clone());
        let mut leases = LeaseTable::new();
        let mac_a = [0x52, 0x54, 0x00, 0x00, 0x00, 0x0a];
        let mac_b = [0x52, 0x54, 0x00, 0x00, 0x00, 0x0b];
        let mac_c = [0x52, 0x54, 0x00, 0x00, 0x00, 0x0c];

        let (_, a) = offer(&server, &mut leases, "vm-a", mac_a, 1, None);
        let (_, _b) = offer(&server, &mut leases, "vm-b", mac_b, 2, None);
        assert_eq!(a, config.range_start);

        // A bare RELEASE carries the address in ciaddr.
        let release = guest_frame(DHCP_RELEASE, 3, mac_a, a, &[]);
        let replies = server.handle(&release, &mut leases, "vm-a", mac_a, OUR_MAC, None);
        assert!(replies.is_empty(), "a RELEASE is not answered");
        assert!(leases.by_ip(a).is_none(), "the address is given back");

        // The lowest freed slot goes to the next machine.
        let (_, c) = offer(&server, &mut leases, "vm-c", mac_c, 4, None);
        assert_eq!(c, a, "a freed address is allocated again");
    }

    #[test]
    fn a_machine_cannot_release_another_machines_lease() {
        let config = DhcpConfig::for_subnet(ip("10.177.0.0"), 16);
        let server = DhcpServer::new(config);
        let mut leases = LeaseTable::new();
        let mac_a = [0x52, 0x54, 0x00, 0x00, 0x00, 0x0a];
        let mac_b = [0x52, 0x54, 0x00, 0x00, 0x00, 0x0b];

        let (_, a) = offer(&server, &mut leases, "vm-a", mac_a, 1, None);
        let (_, _b) = offer(&server, &mut leases, "vm-b", mac_b, 2, None);

        // vm-b names vm-a's address in a RELEASE.
        let release = guest_frame(DHCP_RELEASE, 3, mac_b, a, &[]);
        server.handle(&release, &mut leases, "vm-b", mac_b, OUR_MAC, None);
        assert_eq!(
            leases.by_ip(a).map(|lease| lease.key.as_str()),
            Some("vm-a"),
            "the lease survives"
        );
    }

    #[test]
    fn a_declined_address_is_not_offered_to_the_same_machine_again() {
        let config = DhcpConfig::for_subnet(ip("10.177.0.0"), 16);
        let server = DhcpServer::new(config.clone());
        let mut leases = LeaseTable::new();
        let mac = [0x52, 0x54, 0x00, 0x00, 0x00, 0x0a];

        let (_, first) = offer(&server, &mut leases, "vm-a", mac, 1, None);
        assert_eq!(first, config.range_start);

        let decline = guest_frame(
            DHCP_DECLINE,
            2,
            mac,
            Ipv4Addr::UNSPECIFIED,
            &[(OPTION_REQUESTED_IP, first.octets().to_vec())],
        );
        let replies = server.handle(&decline, &mut leases, "vm-a", mac, OUR_MAC, None);
        assert!(replies.is_empty(), "a DECLINE is not answered");
        assert!(
            leases.by_ip(first).is_none(),
            "the declined address is freed"
        );

        let (_, second) = offer(&server, &mut leases, "vm-a", mac, 3, None);
        assert_ne!(second, first, "the machine is given a fresh address");
        assert_eq!(
            second,
            ip("10.177.0.17"),
            "the next free slot, not the declined one"
        );
    }

    #[test]
    fn garbage_and_truncated_frames_answer_nothing_and_do_not_panic() {
        let config = DhcpConfig::for_subnet(ip("10.177.0.0"), 16);
        let server = DhcpServer::new(config);
        let mut leases = LeaseTable::new();
        let mac = [0x52, 0x54, 0x00, 0x00, 0x00, 0x0a];

        // Noise of every length, including a full-size frame.
        let noise: Vec<u8> = (0..1500u32)
            .map(|i| (i.wrapping_mul(37) % 251) as u8)
            .collect();
        assert!(server
            .handle(&noise, &mut leases, "vm-a", mac, OUR_MAC, None)
            .is_empty());
        assert!(server
            .handle(&[], &mut leases, "vm-a", mac, OUR_MAC, None)
            .is_empty());
        assert!(server
            .handle(&[0xff; 14], &mut leases, "vm-a", mac, OUR_MAC, None)
            .is_empty());

        // A real frame cut at every interesting boundary: header, IPv4, UDP, BOOTP and options.
        let valid = guest_frame(DHCP_DISCOVER, 1, mac, Ipv4Addr::UNSPECIFIED, &[]);
        for cut in [0usize, 1, 13, 14, 33, 34, 41, 42, 239, 245, 260, 341] {
            assert!(
                server
                    .handle(&valid[..cut], &mut leases, "vm-a", mac, OUR_MAC, None)
                    .is_empty(),
                "a frame cut at {cut} is ignored",
            );
        }

        // A UDP datagram to port 67 that is not a BOOTP request at all.
        let datagram = build_udp(
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
            CLIENT_PORT,
            SERVER_PORT,
            b"not dhcp",
        );
        let packet = build_ipv4(
            Ipv4Addr::UNSPECIFIED,
            Ipv4Addr::BROADCAST,
            IPPROTO_UDP,
            64,
            &datagram,
        );
        let frame = build_ethernet(BROADCAST_MAC, mac, ETHERTYPE_IPV4, &packet);
        assert!(is_dhcp(&frame), "it is routed to DHCP by transport");
        assert!(
            server
                .handle(&frame, &mut leases, "vm-a", mac, OUR_MAC, None)
                .is_empty(),
            "but it is not answered"
        );

        assert!(leases.is_empty(), "no malformed frame creates a lease");
    }

    #[test]
    fn is_dhcp_recognizes_dhcp_and_rejects_other_protocols() {
        let mac = [0x52, 0x54, 0x00, 0x00, 0x00, 0x0a];
        assert!(is_dhcp(&guest_frame(
            DHCP_DISCOVER,
            1,
            mac,
            Ipv4Addr::UNSPECIFIED,
            &[]
        )));
        assert!(is_dhcp(&guest_frame(
            DHCP_REQUEST,
            2,
            mac,
            Ipv4Addr::UNSPECIFIED,
            &[]
        )));

        // An ICMP echo request is not DHCP.
        let icmp = build_icmp_echo_request(1, 1, b"ping");
        let packet = build_ipv4(
            ip("10.177.0.2"),
            ip("10.177.0.1"),
            crate::frame::IPPROTO_ICMP,
            64,
            &icmp,
        );
        let frame = build_ethernet(BROADCAST_MAC, mac, ETHERTYPE_IPV4, &packet);
        assert!(!is_dhcp(&frame));

        // Neither is UDP to some other port.
        let datagram = build_udp(ip("10.177.0.2"), ip("10.177.0.1"), 40000, 53, b"dns");
        let packet = build_ipv4(
            ip("10.177.0.2"),
            ip("10.177.0.1"),
            IPPROTO_UDP,
            64,
            &datagram,
        );
        let frame = build_ethernet(BROADCAST_MAC, mac, ETHERTYPE_IPV4, &packet);
        assert!(!is_dhcp(&frame));

        assert!(!is_dhcp(&[]), "an empty frame is not DHCP");
        assert!(!is_dhcp(&[0u8; 14]), "nor is a header with no payload");
    }

    #[test]
    fn the_default_subnet_layout_is_stable() {
        let config = DhcpConfig::for_subnet(ip("10.177.0.0"), 16);
        assert_eq!(
            config.server_ip,
            ip("10.177.0.1"),
            "server at the subnet's first host"
        );
        assert_eq!(
            config.gateway_ip,
            ip("10.177.0.1"),
            "the gateway is the relay too"
        );
        assert_eq!(config.dns_ip, ip("10.177.0.1"));
        assert_eq!(config.netmask, ip("255.255.0.0"));
        assert_eq!(config.range_start, ip("10.177.0.16"), "leases start at .16");
        assert_eq!(
            config.range_end,
            ip("10.177.255.254"),
            "and end at the last host"
        );
        assert_eq!(config.lease_secs, DEFAULT_LEASE_SECS);

        let network = ip("10.177.0.0");
        let broadcast = ip("10.177.255.255");
        assert!(
            in_range(config.range_start, network, broadcast),
            "the range starts inside the /16"
        );
        assert!(
            in_range(config.range_end, network, broadcast),
            "and stays inside it"
        );

        // An unaligned address is masked to its network before the layout is chosen.
        let unaligned = DhcpConfig::for_subnet(ip("10.177.5.9"), 16);
        assert_eq!(
            unaligned, config,
            "an unaligned input lays out as its network does"
        );
    }

    #[test]
    fn allocation_returns_none_when_the_range_is_exhausted() {
        let mut leases = LeaseTable::new();
        let start = ip("10.0.0.7");
        let end = ip("10.0.0.8");
        assert_eq!(leases.allocate("a", [1; 6], start, end), Some(start));
        assert_eq!(leases.allocate("b", [2; 6], start, end), Some(end));
        assert_eq!(
            leases.allocate("c", [3; 6], start, end),
            None,
            "a full range allocates nothing"
        );
        assert_eq!(leases.len(), 2);

        // Freeing a slot makes it allocatable again.
        assert_eq!(
            leases.release(start).map(|lease| lease.key),
            Some("a".to_string())
        );
        assert_eq!(leases.allocate("d", [4; 6], start, end), Some(start));

        // An inverted range is empty, not a panic.
        assert_eq!(leases.allocate("e", [5; 6], end, start), None);
    }

    #[test]
    fn a_machine_keeps_its_address_when_it_is_rekeyed_by_mac() {
        let mut leases = LeaseTable::new();
        let mac = [0x52, 0x54, 0x00, 0x00, 0x00, 0x0a];
        let (start, end) = range();
        let first = leases
            .allocate("before-restart", mac, start, end)
            .expect("room for one");
        let second = leases
            .allocate("after-restart", mac, start, end)
            .expect("the same machine");
        assert_eq!(
            first, second,
            "the MAC keeps the address across a key change"
        );
        assert_eq!(leases.len(), 1, "and there is still one lease");
        assert_eq!(
            leases.by_key("after-restart").map(|lease| lease.ip),
            Some(first)
        );
        assert!(
            leases.by_key("before-restart").is_none(),
            "the old key no longer holds it"
        );
    }

    #[test]
    fn the_answer_carries_the_configured_domain_and_mtu() {
        let mut config = DhcpConfig::for_subnet(ip("10.177.0.0"), 16);
        config.domain = Some("vms.local".to_string());
        config.mtu = Some(1400);
        let server = DhcpServer::new(config);
        let mut leases = LeaseTable::new();
        let mac = [0x52, 0x54, 0x00, 0x00, 0x00, 0x0a];

        let (options, _) = offer(&server, &mut leases, "vm-a", mac, 1, Some("agent-vm"));
        assert_eq!(
            option(&options, OPTION_DOMAIN).as_deref(),
            Some(&b"vms.local"[..])
        );
        assert_eq!(
            option(&options, OPTION_MTU).as_deref(),
            Some(&1400u16.to_be_bytes()[..])
        );
        assert_eq!(
            option(&options, OPTION_HOSTNAME).as_deref(),
            Some(&b"agent-vm"[..])
        );
    }

    #[test]
    fn lease_table_lookups_and_iteration_are_consistent() {
        let table = LeaseTable::new();
        assert!(table.is_empty());
        assert_eq!(table.len(), 0);
        assert!(table.all().is_empty());
        assert!(table.by_ip(ip("10.177.0.16")).is_none());
        assert!(table.by_key("nobody").is_none());

        let mut table = LeaseTable::new();
        let (start, end) = range();
        let mac = [0x52, 0x54, 0x00, 0x00, 0x00, 0x0a];
        let ip_a = table.allocate("vm-a", mac, start, end).expect("room");
        assert!(!table.is_empty());
        assert_eq!(table.len(), 1);
        assert_eq!(
            table.by_ip(ip_a).map(|lease| lease.key.as_str()),
            Some("vm-a")
        );
        assert_eq!(table.by_key("vm-a").map(|lease| lease.ip), Some(ip_a));
        assert_eq!(table.all().len(), 1);
    }
}
