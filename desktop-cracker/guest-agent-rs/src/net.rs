//! **The guest's own network**: its `tun0`, and the network channel that carries its IP frames.
//!
//! Firecracker's own net device is a tap (and a tap is a host-side device the application would need
//! `CAP_NET_ADMIN` for), so a run attaches none and the guest makes its own point-to-point link
//! — this program opens a **TUN** interface — an L3 device, one IP
//! packet per read and per write, no Ethernet header — and ships those packets to the host's engine
//! over the network channel.  The channel's framing is the project's own, and its kinds are
//! `dc-fc-net`'s.
//!
//! The interface is configured **only once the host is answering**: a kernel that started using it
//! before the engine was there would take a DHCP-less address, and nothing here should pretend the
//! network works before it does.

use std::io::{Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

use crate::channel::{self, ports};

/// The network channel's kind: one IP packet (`dc-fc-net::KIND_PACKET`).
pub const KIND_PACKET: u16 = 1;

/// The largest IP packet this channel carries (`dc-fc-net::MAX_PACKET`).
pub const MAX_PACKET: usize = 65_535;

/// What the run told the guest its network is.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkPlan {
    pub iface: String,
    pub guest: String,
    pub gateway: String,
    pub prefix: u32,
    pub mtu: u32,
}

impl Default for NetworkPlan {
    fn default() -> Self {
        NetworkPlan {
            iface: "tun0".into(),
            guest: "10.0.177.16".into(),
            gateway: "10.0.177.1".into(),
            prefix: 24,
            mtu: 1500,
        }
    }
}

impl NetworkPlan {
    /// The plan from a `net` command line (`--iface`, `--guest`, `--gateway`, `--prefix`, `--mtu`).
    pub fn parse(args: &[String]) -> NetworkPlan {
        let mut plan = NetworkPlan::default();
        let mut i = 0;
        while i < args.len() {
            let value = |i: &mut usize| -> Option<String> {
                *i += 1;
                args.get(*i).cloned()
            };
            match args[i].as_str() {
                "--iface" => plan.iface = value(&mut i).unwrap_or(plan.iface),
                "--guest" => plan.guest = value(&mut i).unwrap_or(plan.guest),
                "--gateway" => plan.gateway = value(&mut i).unwrap_or(plan.gateway),
                "--prefix" => {
                    plan.prefix = value(&mut i).and_then(|v| v.parse().ok()).unwrap_or(plan.prefix)
                }
                "--mtu" => plan.mtu = value(&mut i).and_then(|v| v.parse().ok()).unwrap_or(plan.mtu),
                _ => {}
            }
            i += 1;
        }
        plan
    }

    /// The command the guest's own `ip` runs, which is what the C agent ran too: nothing here
    /// guesses an address, the run's own numbers are handed over.
    pub fn configure_command(&self) -> String {
        format!(
            "ip addr add {}/{} dev {} 2>/dev/null; ip link set {} mtu {} up; \
             ip route add default via {} dev {} 2>/dev/null; true",
            self.guest, self.prefix, self.iface, self.iface, self.mtu, self.gateway, self.iface
        )
    }

    /// **The guest's resolver**: the gateway the run named, which is the address this project's
    /// engine answers a lookup at.
    ///
    /// The guest has no DHCP client and no lease (there is no `eth0`: the network is this TUN), and
    /// the system on the disk carries the resolver its image was built with — measured 2026-10-12:
    /// `/etc/resolv.conf` says `nameserver 192.168.50.1`, the address of the machine that built the
    /// image.  A query to it *is* answered (the engine takes any lookup on port 53 and asks the
    /// host's resolver, framing the answer back from the gateway), but glibc keeps the answer only if
    /// it comes from the address it asked, so the reply is discarded and the lookup fails: `getent
    /// hosts deb.debian.org` says nothing while `curl http://1.1.1.1/` answers in 12 ms.  This is the
    /// same rule the project's own `udhcpc` script had — "the **gateway** when the server sent no
    /// option 6" — now applied where the numbers actually are.
    pub fn resolver_contents(&self) -> String {
        format!(
            "# desktop-cracker: this guest's lookups are answered by the run's gateway.\nnameserver {}\n",
            self.gateway
        )
    }
}

/// The kernel's own `/dev/net/tun`, opened as a TUN interface with no packet information prefix.
fn open_tun(name: &str) -> std::io::Result<OwnedFd> {
    if !std::path::Path::new("/dev/net/tun").exists() {
        // `devtmpfs` usually makes it; when it does not, the node is the kernel's own, and making
        // it is what `ip tuntap add` would have done.
        let _ = std::fs::create_dir_all("/dev/net");
        let dev = libc::makedev(10, 200);
        // SAFETY: the path is created above and the device number is the kernel's own for tun.
        let rc = unsafe {
            libc::mknod(
                b"/dev/net/tun\0".as_ptr() as *const libc::c_char,
                libc::S_IFCHR | 0o666,
                dev,
            )
        };
        if rc != 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::EEXIST) {
                return Err(err);
            }
        }
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/net/tun")?;
    let fd: OwnedFd = file.into();

    // `struct ifreq`, with the flags and the name in it.  `IFF_TUN` is an L3 interface and
    // `IFF_NO_PI` says no four-byte prefix travels in front of each packet.
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct IfReq {
        name: [u8; 16],
        flags: i16,
        _pad: [u8; 22],
    }
    let mut request = IfReq {
        name: [0; 16],
        flags: (libc::IFF_TUN | libc::IFF_NO_PI) as i16,
        _pad: [0; 22],
    };
    let bytes = name.as_bytes();
    let len = bytes.len().min(15);
    request.name[..len].copy_from_slice(&bytes[..len]);

    // SAFETY: the fd is a tun device and `request` is the structure `TUNSETIFF` reads and fills.
    let rc = unsafe { libc::ioctl(fd.as_raw_fd(), libc::TUNSETIFF as _, &mut request) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(fd)
}

/// One small frame: a length, a kind and the payload.
fn send_frame(channel: &mut std::os::unix::net::UnixStream, kind: u16, payload: &[u8]) -> std::io::Result<()> {
    let len = payload.len() as u32;
    let head: [u8; 6] = [
        (len & 0xff) as u8,
        ((len >> 8) & 0xff) as u8,
        ((len >> 16) & 0xff) as u8,
        ((len >> 24) & 0xff) as u8,
        (kind & 0xff) as u8,
        ((kind >> 8) & 0xff) as u8,
    ];
    channel.write_all(&head)?;
    channel.write_all(payload)?;
    channel.flush()
}

/// Read one whole frame, waiting for its pieces.
fn read_frame<R: Read>(stream: &mut R) -> std::io::Result<(u16, Vec<u8>)> {
    let mut head = [0u8; 6];
    stream.read_exact(&mut head)?;
    let len = u32::from_le_bytes([head[0], head[1], head[2], head[3]]) as usize;
    let kind = u16::from_le_bytes([head[4], head[5]]);
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload)?;
    Ok((kind, payload))
}

/// `net [--iface NAME] [--guest IP] [--gateway IP] [--prefix N] [--mtu N]`: the guest's own link.
///
/// It never returns while the network lives: the two directions are threads of this process, and
/// the interface is the process's reason to exist.
pub fn run(args: &[String]) -> i32 {
    let plan = NetworkPlan::parse(args);
    let tun = match open_tun(&plan.iface) {
        Ok(tun) => tun,
        Err(e) => {
            crate::console::note(&format!("deskd: {}: {e}", plan.iface));
            return 1;
        }
    };
    let Some(channel) = channel::dial(ports::NETWORK) else {
        crate::console::note("deskd: the network channel did not answer");
        return 2;
    };

    // **Only now is the interface configured**: the host's engine is answering.
    let command = plan.configure_command();
    let status = std::process::Command::new("sh").arg("-c").arg(&command).status();
    crate::console::note(&format!(
        "deskd: {} {}/{} via {}, on the host's channel",
        plan.iface, plan.guest, plan.prefix, plan.gateway
    ));
    let _ = status;

    // **And the resolver**, beside it: the gateway the run just named is the address this project's
    // engine answers a lookup at, and the guest has no other way to be told that (`NetworkPlan`'s
    // `resolver_contents` says why the address the image carries is not an answer).
    if let Err(e) = std::fs::write("/etc/resolv.conf", plan.resolver_contents()) {
        crate::console::note(&format!("deskd: the guest's resolver: {e}"));
    }

    // The two directions, each on its own thread: the TUN writes frames, the channel writes
    // packets, and neither waits for the other.  Each thread takes **its own clone** of the two
    // descriptors (a TUN and a socket are one thing with two ends), and the first thread to end
    // takes the link down: a network that half works is worse than one that says so.
    let Ok(mut down) = channel.try_clone() else {
        crate::console::note("deskd: the network channel: cannot share the socket");
        return 1;
    };
    let mut up = channel;
    let up_fd = match dup_fd(&tun) {
        Ok(fd) => fd,
        Err(e) => {
            crate::console::note(&format!("deskd: {e}"));
            return 1;
        }
    };
    let down_fd = match dup_fd(&tun) {
        Ok(fd) => fd,
        Err(e) => {
            crate::console::note(&format!("deskd: {e}"));
            return 1;
        }
    };
    let up_thread = std::thread::spawn(move || {
        let mut tun_file = up_fd;
        let mut buffer = vec![0u8; MAX_PACKET];
        loop {
            match tun_file.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    if send_frame(&mut up, KIND_PACKET, &buffer[..n]).is_err() {
                        break;
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
    });
    let down_thread = std::thread::spawn(move || {
        let mut tun_file = down_fd;
        loop {
            match read_frame(&mut down) {
                Ok((KIND_PACKET, packet)) => {
                    if tun_file.write_all(&packet).is_err() {
                        break;
                    }
                }
                Ok(_) => continue,
                Err(_) => break,
            }
        }
    });
    let _ = up_thread.join();
    let _ = down_thread.join();
    // The interface goes with the process that served it (the channel's end is this process's).
    unsafe { libc::close(tun.as_raw_fd()) };
    0
}

/// One more descriptor for the same TUN: each direction owns its own, so neither closes the other's.
fn dup_fd(fd: &OwnedFd) -> std::io::Result<std::fs::File> {
    // SAFETY: the fd is open, and `dup` answers a new one for the same open file description.
    let copy = unsafe { libc::dup(fd.as_raw_fd()) };
    if copy < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `copy` is a fresh descriptor this process owns.
    Ok(unsafe { std::fs::File::from_raw_fd(copy) })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(words: &[&str]) -> Vec<String> {
        words.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn the_plan_is_read_from_the_switches_the_run_sends() {
        let plan = NetworkPlan::parse(&args(&[
            "--guest", "10.0.177.16", "--prefix", "24", "--gateway", "10.0.177.1",
            "--iface", "tun0", "--mtu", "1500",
        ]));
        assert_eq!(plan.iface, "tun0");
        assert_eq!(plan.guest, "10.0.177.16");
        assert_eq!(plan.gateway, "10.0.177.1");
        assert_eq!(plan.prefix, 24);
        assert_eq!(plan.mtu, 1500);
    }

    #[test]
    fn the_defaults_are_the_projects_own_addresses() {
        let plan = NetworkPlan::default();
        assert_eq!(plan.guest, "10.0.177.16");
        assert_eq!(plan.gateway, "10.0.177.1");
        assert_eq!(plan.prefix, 24);
    }

    #[test]
    fn the_configuration_is_what_the_guest_s_own_ip_is_told() {
        let command = NetworkPlan::default().configure_command();
        assert!(command.contains("ip addr add 10.0.177.16/24 dev tun0"), "{command}");
        assert!(command.contains("ip link set tun0 mtu 1500 up"), "{command}");
        assert!(command.contains("ip route add default via 10.0.177.1 dev tun0"), "{command}");
    }

    /// The lookup the guest makes is answered by the gateway, so the gateway is the resolver the
    /// guest is told about — not the address the image happens to carry.
    #[test]
    fn the_guest_s_resolver_is_the_gateway_the_run_named() {
        let plan = NetworkPlan::parse(&args(&["--gateway", "10.0.177.1"]));
        let text = plan.resolver_contents();
        assert_eq!(text.lines().last(), Some("nameserver 10.0.177.1"), "{text}");
        assert_eq!(
            NetworkPlan::parse(&args(&["--gateway", "192.168.9.1"])).resolver_contents(),
            "# desktop-cracker: this guest's lookups are answered by the run's gateway.\nnameserver 192.168.9.1\n"
        );
    }

    #[test]
    fn a_packet_frame_is_a_length_a_kind_and_the_packet() {
        let mut wire = Vec::new();
        wire.extend_from_slice(&4u32.to_le_bytes());
        wire.extend_from_slice(&KIND_PACKET.to_le_bytes());
        wire.extend_from_slice(b"ping");
        let mut reader = std::io::Cursor::new(wire);
        let (kind, packet) = read_frame(&mut reader).unwrap();
        assert_eq!(kind, KIND_PACKET);
        assert_eq!(packet, b"ping");
    }
}
