//! The built-in **NTP server**: the gateway answers the time.
//!
//! A machine's clock is otherwise whatever its virtual RTC said at boot — the VMM seeds it from the host
//! once, and every guest drifts from there. The relay already *is* the machines' network (DHCP, DNS,
//! ICMP, NAT), so the clock joins the list: a unicast client request to the gateway's port
//! [`NTP_PORT`] is answered from **the host's own clock**, and both DHCP servers advertise that
//! address (`dhcp::OPTION_NTP`, `dhcp6::OPTION_NTP_SERVER`) so a stock guest uses it with no
//! configuration at all — the same reason the resolver is ours.
//!
//! This is the **server half of NTPv4** (RFC 5905 ), which is also SNTP: the 48-byte header, no
//! extension fields, no MAC, and none of the control or private modes (mode 6/7 are where NTP's
//! amplification reputation comes from, and nothing here needs them). A guest may run `ntpsec`,
//! `chrony`, `ntpd`, systemd-timesyncd or busybox `ntpd` against it.
//!
//! What it promises, and what it cannot:
//!
//! * **A secondary reference** at stratum [`STRATUM`], reporting [`REFERENCE_ID`] (`LOCL`) — the
//!   process has no atomic clock and no upstream of its own, so the honest claim is "this is the
//!   host's clock".  A guest syncing to it is as right as the host is.
//! * **Receive and transmit are the same instant.** The reply is built in the relay's own thread and
//!   the "network" is a unix socketpair, so a client's offset is accurate to the symmetry of that
//!   path rather than to microseconds. For a virtual machine's clock that is the problem solved; it
//!   is not a time chain for a lab.
//! * **Unicast, and only from this conduit.** Every peer is a machine of the workspace (or its
//!   shell); a request that is short, or is not a client request, is ignored rather than answered.

use std::time::{SystemTime, UNIX_EPOCH};

/// The port an NTP client sends to (and the one our answer leaves from).
pub const NTP_PORT: u16 = 123;

/// The bytes of the header every NTP packet starts with — and, here, the whole packet: this server
/// speaks neither extension fields nor authentication, so a request's tail is ignored and an answer is
/// exactly this long.
pub const PACKET_LEN: usize = 48;

/// The mode a **client** sends (`3`); the mode we answer with (`4`, server).
const MODE_CLIENT: u8 = 3;
const MODE_SERVER: u8 = 4;

/// A **secondary** reference (`2`): we are not the clock, we are a server synced to one.
const STRATUM: u8 = 2;

/// The clock's precision as NTP's signed `i8` (2⁻²⁰ s ≈ 1 µs), which is the honest order for a
/// timestamp taken in userspace.
const PRECISION: i8 = -20;

/// Root dispersion in NTP's 2⁻¹⁶ s units (~15 ms): what we claim about our own distance from the
/// reference. Zero would claim a perfect clock, which we do not have.
const ROOT_DISPERSION: u32 = 0x0000_1000;

/// The reference identifier of a stratum-2 server is its upstream's address; ours is the conventional
/// **`LOCL`** — *an uncalibrated local clock* — because that is exactly what the host's clock is to us.
const REFERENCE_ID: [u8; 4] = *b"LOCL";

/// The leap indicator we always send: `0`, "no warning". We have no leap-second source to ask, and
/// guessing is worse than saying nothing.
const LEAP_NONE: u8 = 0;

/// The seconds between the NTP epoch (1900-01-01) and the Unix epoch (1970-01-01).
const NTP_EPOCH_OFFSET: u64 = 2_208_988_800;

/// A relay's time server. It keeps one fact: since when this clock has been the reference.
#[derive(Debug, Clone)]
pub struct Server {
    reference: SystemTime,
}

impl Default for Server {
    fn default() -> Server {
        Server::new()
    }
}

impl Server {
    /// A server whose reference time is now — the moment the machine's network came up.
    pub fn new() -> Server {
        Server {
            reference: SystemTime::now(),
        }
    }

    /// The reply to `request` as of `now`, or `None` when it is not a client request we answer.
    ///
    /// `now` is a parameter rather than a `SystemTime::now()` here so the packet's arithmetic is
    /// testable at a fixed instant (the relay passes the real clock).
    pub fn reply(&self, request: &[u8], now: SystemTime) -> Option<[u8; PACKET_LEN]> {
        let header = request.get(..PACKET_LEN)?;
        let mode = header[0] & 0x07;
        let version = (header[0] >> 3) & 0x07;
        if mode != MODE_CLIENT || !(1..=4).contains(&version) {
            return None;
        }
        let mut answer = [0u8; PACKET_LEN];
        answer[0] = (LEAP_NONE << 6) | (version << 3) | MODE_SERVER;
        answer[1] = STRATUM;
        // The client's poll interval is echoed: it is the client's own scheduling fact, and a server
        // that invented a different one would be correcting a decision that is not its business.
        answer[2] = header[2];
        answer[3] = PRECISION as u8;
        // Root delay `0`: we are not a stratum 1 with a measured path to a reference.
        answer[4..8].copy_from_slice(&0u32.to_be_bytes());
        answer[8..12].copy_from_slice(&ROOT_DISPERSION.to_be_bytes());
        answer[12..16].copy_from_slice(&REFERENCE_ID);
        answer[16..24].copy_from_slice(&timestamp(self.reference));
        // **Originate** is the client's transmit timestamp handed straight back: it is the `T1` the
        // client's own offset formula needs, and copying it is also what proves the reply is an answer
        // to *this* request.
        answer[24..32].copy_from_slice(&header[40..48]);
        // Receive and transmit are the same instant: the answer is built here, in one thread.
        let sent = timestamp(now);
        answer[32..40].copy_from_slice(&sent);
        answer[40..48].copy_from_slice(&sent);
        Some(answer)
    }
}

/// `at` as an NTP timestamp (RFC 5905 ): 32 bits of seconds since 1900 and 32 bits of fraction.
///
/// A time before the Unix epoch — which a host clock should never be — reads as `0` rather than
/// wrapping into a timestamp in 2036.
pub fn timestamp(at: SystemTime) -> [u8; 8] {
    let Ok(since_epoch) = at.duration_since(UNIX_EPOCH) else {
        return [0; 8];
    };
    let seconds = since_epoch.as_secs().wrapping_add(NTP_EPOCH_OFFSET);
    // `<< 32` on a value below 10⁹ cannot overflow a `u64` (10⁹ · 2³² ≈ 4.3 · 10¹⁸), and `/ 10⁹` is the
    // fraction in 2⁻³² s units — the rounding NTP's own conversion uses.
    let fraction = ((since_epoch.subsec_nanos() as u64) << 32) / 1_000_000_000;
    let mut out = [0u8; 8];
    out[..4].copy_from_slice(&(seconds as u32).to_be_bytes());
    out[4..].copy_from_slice(&(fraction as u32).to_be_bytes());
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// A client packet: version, poll, and the transmit timestamp it claims.
    fn request(version: u8, poll: u8, transmit: [u8; 8]) -> Vec<u8> {
        let mut packet = vec![0u8; PACKET_LEN];
        packet[0] = (version << 3) | MODE_CLIENT;
        packet[2] = poll;
        packet[40..48].copy_from_slice(&transmit);
        packet
    }

    /// The seconds-since-1970 an NTP timestamp names, as a float (the client's own arithmetic).
    fn decode(stamp: &[u8]) -> f64 {
        let seconds = u32::from_be_bytes(stamp[..4].try_into().expect("four bytes")) as f64;
        let fraction =
            u32::from_be_bytes(stamp[4..].try_into().expect("four bytes")) as f64 / 2f64.powi(32);
        seconds + fraction - NTP_EPOCH_OFFSET as f64
    }

    #[test]
    fn a_client_request_gets_a_reply_whose_timestamps_close_the_offset_formula() {
        let reference = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        let server = Server { reference };
        let client_sent = UNIX_EPOCH + Duration::from_secs(1_700_000_100);
        let now = client_sent + Duration::from_millis(250);
        let answer = server
            .reply(&request(4, 6, timestamp(client_sent)), now)
            .expect("a reply");

        assert_eq!(answer[0] & 0x07, MODE_SERVER, "a server reply");
        assert_eq!(
            (answer[0] >> 3) & 0x07,
            4,
            "the client's version comes back"
        );
        assert_eq!(answer[0] >> 6, LEAP_NONE, "no leap warning");
        assert_eq!(answer[1], STRATUM, "a secondary reference");
        assert_eq!(answer[2], 6, "the client's poll is echoed");
        assert_eq!(answer[3] as i8, PRECISION);
        assert_eq!(&answer[12..16], &REFERENCE_ID);
        assert_eq!(
            &answer[16..24],
            &timestamp(reference),
            "the reference is when this clock became ours"
        );
        assert_eq!(
            &answer[24..32],
            &timestamp(client_sent),
            "originate is the client's own transmit"
        );
        assert_eq!(&answer[32..40], &timestamp(now), "receive is now");
        assert_eq!(
            &answer[40..48],
            &timestamp(now),
            "and transmit is the same instant"
        );

        // What a client computes from an answer: with `T1` its own send, `T2`/`T3` our receive/transmit
        // and `T4` its read, the offset is ((T2−T1) + (T3−T4))/2. Our two stamps being one instant is
        // what makes the whole error the path's asymmetry, so the answer must name `now`, not a guess.
        assert!((decode(&answer[32..40]) - decode(&timestamp(now))).abs() < 1e-9);
        assert!((decode(&answer[40..48]) - decode(&timestamp(now))).abs() < 1e-9);
        assert!((decode(&answer[24..32]) - decode(&timestamp(client_sent))).abs() < 1e-9);
    }

    #[test]
    fn the_clients_version_is_echoed_and_the_ones_we_do_not_speak_are_ignored() {
        let server = Server::new();
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
        for version in 1..=4u8 {
            let answer = server
                .reply(&request(version, 4, [0; 8]), now)
                .expect("a reply");
            assert_eq!(
                (answer[0] >> 3) & 0x07,
                version,
                "version {version} is echoed"
            );
        }
        assert!(
            server.reply(&request(0, 4, [0; 8]), now).is_none(),
            "version 0 is not a version"
        );
        assert!(
            server.reply(&request(5, 4, [0; 8]), now).is_none(),
            "nor is 5"
        );
    }

    #[test]
    fn a_packet_that_is_not_a_client_request_is_ignored() {
        let server = Server::new();
        let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);

        // Too short to hold a header: the request arrived truncated.
        for cut in [0usize, 1, 23, 47] {
            assert!(
                server.reply(&vec![0u8; cut], now).is_none(),
                "{cut} bytes is not a packet"
            );
        }
        // A server reply, a broadcast, a control message and a private message are not questions.
        for mode in [0u8, 1, 2, 4, 5, 6, 7] {
            let mut packet = request(4, 4, [0; 8]);
            packet[0] = (4 << 3) | mode;
            assert!(
                server.reply(&packet, now).is_none(),
                "mode {mode} is not a client request"
            );
        }
        // An authenticated or extended request is longer than the header: its tail is ignored, and the
        // answer is still exactly one header.
        let mut long = request(4, 4, [1; 8]);
        long.extend_from_slice(&[0u8; 20]);
        let answer = server.reply(&long, now).expect("a reply");
        assert_eq!(answer.len(), PACKET_LEN);
        assert_eq!(
            &answer[24..32],
            &[1; 8],
            "the originate stamp is still read from the header"
        );
    }

    #[test]
    fn timestamps_use_the_ntp_epoch_and_its_fraction() {
        // 1970-01-01 is 2 208 988 800 seconds after the NTP epoch: 0x83AA7E80.
        assert_eq!(timestamp(UNIX_EPOCH), [0x83, 0xAA, 0x7E, 0x80, 0, 0, 0, 0]);
        assert_eq!(
            timestamp(UNIX_EPOCH + Duration::from_secs(1)),
            [0x83, 0xAA, 0x7E, 0x81, 0, 0, 0, 0]
        );
        // Half a second is 0x8000_0000 of the 2⁻³² fraction.
        assert_eq!(
            timestamp(UNIX_EPOCH + Duration::from_millis(500)),
            [0x83, 0xAA, 0x7E, 0x80, 0x80, 0, 0, 0]
        );
        // A quarter of a second, to show the fraction is a real conversion and not a shift.
        let quarter = timestamp(UNIX_EPOCH + Duration::from_millis(250));
        assert_eq!(&quarter[4..], &0x4000_0000u32.to_be_bytes());
        // A clock before 1970 reads as the zero timestamp rather than wrapping into 2036.
        assert_eq!(timestamp(UNIX_EPOCH - Duration::from_secs(1)), [0; 8]);
    }
}
