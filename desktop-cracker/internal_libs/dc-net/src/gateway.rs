//! Ports published on a workspace's **gateway** .
//!
//! A container's `-p` mapping is **not** a host port. It is a reservation in the workspace's own table,
//! and the relay carries a flow to `<gateway>:<published>` to the peer that holds it, at the port that
//! peer listens on. One port number per workspace, so a second container asking for the same one is
//! refused **naming the holder**, while the same number in another workspace is a different binding
//! because the networks are isolated.
//!
//! The rewrite is **stateless**, which is what makes it cheap: both directions are decided from the table
//! alone. A packet from a peer to the gateway's published port becomes a packet to the holder; a packet
//! from the holder on its published port becomes a packet from the gateway. Nothing has to remember a
//! connection, because a published port has exactly one holder and a holder has exactly one published
//! port per container port.
//!
//! Only **TCP** is served. A UDP datagram can be fragmented, and a fragment carries no ports to
//! translate, so a UDP mapping is refused by name where it is asked for rather than working for small
//! datagrams and failing silently for large ones.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::Mutex;

/// One port published on a workspace's gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedPort {
    /// The port on the gateway that peers in the workspace dial.
    pub gateway_port: u16,
    /// The peer that answers it.
    pub peer: Ipv4Addr,
    /// The port that peer's own process listens on.
    pub peer_port: u16,
    /// Who holds the port — the container's name, so a refusal can name the container to remove.
    pub holder: String,
}

/// Every workspace's published ports, as one shared table.
///
/// Shared rather than per-relay because a relay serves **one peer**: the peer that dials the gateway
/// consults the target half, and the peer that holds the port consults the source half, and they are
/// different relays of the same workspace.
#[derive(Debug, Default)]
pub struct GatewayPorts {
    published: Mutex<HashMap<String, Vec<PublishedPort>>>,
}

impl GatewayPorts {
    /// An empty table.
    pub fn new() -> GatewayPorts {
        GatewayPorts::default()
    }

    /// Reserve a port in a workspace's table, or refuse **naming the holder** of the one already there.
    pub fn publish(&self, workspace: &str, port: PublishedPort) -> Result<(), String> {
        let mut all = self.published.lock().expect("the gateway ports");
        let ports = all.entry(workspace.to_string()).or_default();
        if let Some(index) = ports
            .iter()
            .position(|held| held.gateway_port == port.gateway_port)
        {
            // The **same** holder publishing again is a restart, not a duplicate: the container keeps its
            // port across a stop and a start. Another holder is the refusal the operator asked for.
            if ports[index].holder == port.holder {
                ports[index] = port;
                return Ok(());
            }
            return Err(format!(
                "port {} is already published in this workspace by '{}': a workspace's gateway has one port \
                 number each, so publish this container on another port or remove that one",
                port.gateway_port, ports[index].holder
            ));
        }
        ports.push(port);
        Ok(())
    }

    /// Take every port a holder has off the gateway. Safe for a holder that has none.
    pub fn unpublish(&self, workspace: &str, holder: &str) {
        if let Some(ports) = self
            .published
            .lock()
            .expect("the gateway ports")
            .get_mut(workspace)
        {
            ports.retain(|port| port.holder != holder);
        }
    }

    /// What a flow to the gateway's `gateway_port` is carried to: the peer and the port it listens on.
    pub fn target(&self, workspace: &str, gateway_port: u16) -> Option<(Ipv4Addr, u16)> {
        let all = self.published.lock().expect("the gateway ports");
        let ports = all.get(workspace)?;
        ports
            .iter()
            .find(|port| port.gateway_port == gateway_port)
            .map(|port| (port.peer, port.peer_port))
    }

    /// The gateway port a packet from `peer` on `peer_port` should appear to come from — the other half
    /// of the same mapping, so a client's reply is addressed back to the gateway it dialled.
    pub fn published_from(&self, workspace: &str, peer: Ipv4Addr, peer_port: u16) -> Option<u16> {
        let all = self.published.lock().expect("the gateway ports");
        let ports = all.get(workspace)?;
        ports
            .iter()
            .find(|port| port.peer == peer && port.peer_port == peer_port)
            .map(|port| port.gateway_port)
    }

    /// A workspace's published ports, for a status line or a test.
    pub fn of(&self, workspace: &str) -> Vec<PublishedPort> {
        let all = self.published.lock().expect("the gateway ports");
        all.get(workspace).cloned().unwrap_or_default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a_port(gateway_port: u16, peer: &str, peer_port: u16, holder: &str) -> PublishedPort {
        PublishedPort {
            gateway_port,
            peer: peer.parse().expect("an address"),
            peer_port,
            holder: holder.to_string(),
        }
    }

    /// One port number per workspace, the holder named in the refusal, and another workspace free.
    #[test]
    fn a_workspace_gateway_has_one_port_number_each_and_names_the_holder() {
        let ports = GatewayPorts::new();
        ports
            .publish("ws-1", a_port(8080, "10.177.0.7", 80, "web"))
            .expect("the first");

        let refused = ports
            .publish("ws-1", a_port(8080, "10.177.0.9", 80, "api"))
            .expect_err("the duplicate");
        assert!(refused.contains("8080"), "{refused}");
        assert!(
            refused.contains("'web'"),
            "the refusal names the container that holds it: {refused}"
        );

        // A different workspace is a different network, so the same number is its own binding.
        ports
            .publish("ws-2", a_port(8080, "10.177.0.9", 80, "api"))
            .expect("another workspace");

        // The two directions of the mapping read back the same thing.
        assert_eq!(
            ports.target("ws-1", 8080),
            Some(("10.177.0.7".parse().expect("an address"), 80))
        );
        assert_eq!(
            ports.published_from("ws-1", "10.177.0.7".parse().expect("an address"), 80),
            Some(8080)
        );
        assert_eq!(ports.target("ws-1", 8081), None, "a port nobody published");
        assert_eq!(
            ports.published_from("ws-2", "10.177.0.7".parse().expect("an address"), 80),
            None
        );

        // The same holder publishing again is a restart: it keeps its number.
        ports
            .publish("ws-1", a_port(8080, "10.177.0.7", 80, "web"))
            .expect("a restart republishes the same container's port");

        // Removing a holder takes its ports and nothing else.
        ports.unpublish("ws-1", "web");
        assert_eq!(ports.of("ws-1"), Vec::new());
        assert_eq!(ports.target("ws-1", 8080), None);
        assert_eq!(
            ports.of("ws-2").len(),
            1,
            "another workspace's port is untouched"
        );
        ports.unpublish("ws-1", "web");
    }
}
