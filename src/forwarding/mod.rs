//! IP forwarding engine: validates packets and moves them between tunnel
//! sessions and the network (TUN device).
//!
//! Data plane paths:
//! - client → network: validate → TTL decrement → route lookup → TUN write
//! - client → client (hairpin): same validation, delivered to the peer
//!   session's sink — this is what makes site-to-site and rootless testing
//!   work with no TUN device at all
//! - network → client: parse → route lookup → TTL decrement → session sink

pub mod icmp;
pub mod packet;
pub mod router;
pub mod tun;

use bytes::Bytes;
use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::mpsc;

use crate::capsule::{AssignedAddress, IpAddressRange};
use crate::error::ForwardingError;
use crate::session::SessionId;

use self::icmp::{IcmpErrorKind, IcmpSource, build_icmp_error};
use self::router::RouteTable;

/// Where a client packet ended up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Forwarded {
    /// Delivered to another tunnel session (or looped back to the sender).
    Hairpin(SessionId),
    /// Written toward the network via the TUN device.
    Tun,
}

/// What a session is allowed to send to: exactly the ranges the proxy
/// advertised in its ROUTE_ADVERTISEMENT (RFC 9484 §4.7.3 — clients MUST
/// NOT send packets outside them, so the proxy enforces it).
#[derive(Debug, Clone)]
pub struct EgressPolicy {
    ranges: Arc<Vec<IpAddressRange>>,
}

impl EgressPolicy {
    pub fn new(ranges: Arc<Vec<IpAddressRange>>) -> Self {
        Self { ranges }
    }

    pub fn allows(&self, dst: &std::net::IpAddr, proto: u8) -> bool {
        self.ranges.iter().any(|r| r.contains(dst, proto))
    }
}

/// The forwarding engine shared by all sessions.
#[derive(Debug)]
pub struct ForwardingEngine {
    route_table: Arc<RouteTable>,
    /// Per-session sinks delivering packets toward that session's client.
    session_sinks: DashMap<SessionId, mpsc::Sender<Bytes>>,
    /// Per-session egress policies (the advertised routes).
    policies: DashMap<SessionId, EgressPolicy>,
    /// Packets bound for the network; `None` when running without a TUN.
    tun_tx: Option<mpsc::Sender<Bytes>>,
    /// Tunnel MTU enforced on both directions.
    mtu: usize,
    /// Source addresses for generated ICMP errors (the pool gateways).
    icmp_source: IcmpSource,
}

impl ForwardingEngine {
    pub fn new(
        route_table: Arc<RouteTable>,
        tun_tx: Option<mpsc::Sender<Bytes>>,
        mtu: u16,
        icmp_source: IcmpSource,
    ) -> Self {
        Self {
            route_table,
            session_sinks: DashMap::new(),
            policies: DashMap::new(),
            tun_tx,
            mtu: mtu as usize,
            icmp_source,
        }
    }

    pub fn route_table(&self) -> &Arc<RouteTable> {
        &self.route_table
    }

    /// Register the sink that delivers packets toward a session's client,
    /// and the egress policy matching what was advertised to it.
    pub fn register_session(&self, id: SessionId, sink: mpsc::Sender<Bytes>, policy: EgressPolicy) {
        self.session_sinks.insert(id, sink);
        self.policies.insert(id, policy);
    }

    /// Remove a session's sink and policy (teardown).
    pub fn unregister_session(&self, id: SessionId) {
        self.session_sinks.remove(&id);
        self.policies.remove(&id);
    }

    /// Process a packet received from a client tunnel.
    ///
    /// Validates (BCP 38 source check, MTU, destination sanity, egress
    /// policy), acts as one IP hop (TTL decrement), then either hairpins to
    /// another session or hands the packet to the TUN device. Drops that a
    /// router would report earn an ICMP error back to the sender (§7.2).
    pub fn forward_from_client(
        &self,
        from: SessionId,
        assigned: &[AssignedAddress],
        mut packet: Vec<u8>,
    ) -> Result<Forwarded, ForwardingError> {
        // Malformed and spoofed packets are dropped silently: no ICMP for
        // senders we cannot trust (BCP 38).
        let info = packet::parse_packet(&packet)?;
        packet::validate_source(&info, assigned)?;

        if packet.len() > self.mtu {
            self.send_icmp_error(
                from,
                IcmpErrorKind::PacketTooBig {
                    mtu: self.mtu as u16,
                },
                &packet,
            );
            return Err(ForwardingError::MtuExceeded);
        }
        packet::validate_destination(&info.dst)?;

        // Split-tunnel enforcement: only advertised destinations.
        let allowed = self
            .policies
            .get(&from)
            .map(|p| p.allows(&info.dst, info.protocol))
            .unwrap_or(false);
        if !allowed {
            self.send_icmp_error(from, IcmpErrorKind::AdminProhibited, &packet);
            return Err(ForwardingError::NotAllowed(info.dst));
        }

        // One IP hop. On expiry the packet is unmodified, so the ICMP quote
        // carries the TTL as received.
        if let Err(e) = packet::decrement_ttl(&mut packet) {
            if matches!(e, ForwardingError::TtlExpired) {
                self.send_icmp_error(from, IcmpErrorKind::TimeExceeded, &packet);
            }
            return Err(e);
        }

        // Hairpin: destination is another tunnel client (or the sender
        // itself), so the packet never touches the TUN device.
        if let Some(target) = self.route_table.lookup(info.dst, info.protocol) {
            self.deliver_to_session(target, Bytes::from(packet))?;
            return Ok(Forwarded::Hairpin(target));
        }

        match &self.tun_tx {
            Some(tx) => {
                // Datagram semantics: drop rather than block when congested.
                tx.try_send(Bytes::from(packet))
                    .map_err(|_| ForwardingError::Congested)?;
                Ok(Forwarded::Tun)
            }
            None => {
                tracing::trace!(session = %from, dst = %info.dst, "no route (running without TUN)");
                self.send_icmp_error(from, IcmpErrorKind::NoRoute, &packet);
                Err(ForwardingError::NoRoute)
            }
        }
    }

    /// Build an ICMP error about `original` and queue it back to the
    /// sending session. Best-effort: failures only trace.
    fn send_icmp_error(&self, to: SessionId, kind: IcmpErrorKind, original: &[u8]) {
        let Some(icmp_packet) = build_icmp_error(kind, self.icmp_source, original) else {
            return;
        };
        if let Err(e) = self.deliver_to_session(to, Bytes::from(icmp_packet)) {
            tracing::trace!(session = %to, "ICMP error not delivered: {e}");
        } else {
            tracing::trace!(session = %to, ?kind, "ICMP error sent");
        }
    }

    /// Process a packet arriving from the network (TUN device) and dispatch
    /// it to the owning session.
    pub fn dispatch_from_network(&self, mut packet: Vec<u8>) -> Result<SessionId, ForwardingError> {
        if packet.len() > self.mtu {
            return Err(ForwardingError::MtuExceeded);
        }
        let info = packet::parse_packet(&packet)?;
        let target = self
            .route_table
            .lookup(info.dst, info.protocol)
            .ok_or(ForwardingError::NoRoute)?;
        packet::decrement_ttl(&mut packet)?;
        self.deliver_to_session(target, Bytes::from(packet))?;
        Ok(target)
    }

    fn deliver_to_session(&self, id: SessionId, packet: Bytes) -> Result<(), ForwardingError> {
        let sink = self
            .session_sinks
            .get(&id)
            .ok_or(ForwardingError::NoRoute)?;
        // Datagram semantics: drop on backpressure instead of blocking the
        // whole data plane.
        sink.try_send(packet)
            .map_err(|_| ForwardingError::Congested)
    }

    /// Drive TUN → sessions: read packets from the TUN ingress channel and
    /// dispatch until the channel closes.
    pub async fn run_network_ingress(self: Arc<Self>, mut rx: mpsc::Receiver<Vec<u8>>) {
        while let Some(packet) = rx.recv().await {
            match self.dispatch_from_network(packet) {
                Ok(session) => tracing::trace!(%session, "network packet dispatched"),
                Err(e) => tracing::trace!("network packet dropped: {e}"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::packet::build_ipv4_icmp_echo;
    use super::*;

    fn assigned(addr: Ipv4Addr) -> Vec<AssignedAddress> {
        vec![AssignedAddress {
            request_id: 0,
            ip_version: 4,
            ip_address: addr.into(),
            prefix_length: 32,
        }]
    }

    fn allow_all_policy() -> EgressPolicy {
        EgressPolicy::new(Arc::new(vec![
            IpAddressRange::from_net("0.0.0.0/0".parse().unwrap(), 0),
            IpAddressRange::from_net("::/0".parse().unwrap(), 0),
        ]))
    }

    fn test_icmp_source() -> IcmpSource {
        IcmpSource {
            v4: "10.100.0.1".parse().unwrap(),
            v6: Some("fd00::1".parse().unwrap()),
        }
    }

    fn engine_no_tun(mtu: u16) -> (Arc<ForwardingEngine>, Arc<RouteTable>) {
        let table = Arc::new(RouteTable::new());
        let engine = Arc::new(ForwardingEngine::new(
            table.clone(),
            None,
            mtu,
            test_icmp_source(),
        ));
        (engine, table)
    }

    #[tokio::test]
    async fn hairpin_between_sessions() {
        let (engine, table) = engine_no_tun(1400);
        let a = SessionId(0);
        let b = SessionId(4);
        let addr_a: Ipv4Addr = "10.100.0.2".parse().unwrap();
        let addr_b: Ipv4Addr = "10.100.0.3".parse().unwrap();

        let (tx_a, _rx_a) = mpsc::channel(8);
        let (tx_b, mut rx_b) = mpsc::channel(8);
        engine.register_session(a, tx_a, allow_all_policy());
        engine.register_session(b, tx_b, allow_all_policy());
        table.insert_client_addr(addr_a.into(), a);
        table.insert_client_addr(addr_b.into(), b);

        let ping = build_ipv4_icmp_echo(addr_a, addr_b, false, 1, 1, b"hi", 64);
        let result = engine
            .forward_from_client(a, &assigned(addr_a), ping)
            .unwrap();
        assert_eq!(result, Forwarded::Hairpin(b));

        let delivered = rx_b.recv().await.unwrap();
        assert_eq!(delivered[8], 63, "TTL decremented by the proxy hop");
        let info = packet::parse_packet(&delivered).unwrap();
        assert_eq!(info.dst, std::net::IpAddr::from(addr_b));
    }

    #[tokio::test]
    async fn source_spoofing_rejected_silently() {
        let (engine, table) = engine_no_tun(1400);
        let a = SessionId(0);
        let addr_a: Ipv4Addr = "10.100.0.2".parse().unwrap();
        let (tx_a, mut rx_a) = mpsc::channel(8);
        engine.register_session(a, tx_a, allow_all_policy());
        table.insert_client_addr(addr_a.into(), a);

        // Session A claims a source address it was never assigned.
        let spoofed = build_ipv4_icmp_echo(
            "10.100.0.99".parse().unwrap(),
            "192.0.2.1".parse().unwrap(),
            false,
            1,
            1,
            b"",
            64,
        );
        let err = engine
            .forward_from_client(a, &assigned(addr_a), spoofed)
            .unwrap_err();
        assert!(matches!(err, ForwardingError::SourceAddressViolation(_)));
        // No ICMP for spoofers (BCP 38): nothing lands in A's queue.
        assert!(rx_a.try_recv().is_err());
    }

    #[tokio::test]
    async fn no_route_generates_destination_unreachable() {
        let (engine, _table) = engine_no_tun(1400);
        let a = SessionId(0);
        let addr_a: Ipv4Addr = "10.100.0.2".parse().unwrap();
        let (tx_a, mut rx_a) = mpsc::channel(8);
        engine.register_session(a, tx_a, allow_all_policy());

        let pkt = build_ipv4_icmp_echo(addr_a, "192.0.2.1".parse().unwrap(), false, 1, 1, b"", 64);
        let err = engine
            .forward_from_client(a, &assigned(addr_a), pkt)
            .unwrap_err();
        assert!(matches!(err, ForwardingError::NoRoute));

        let icmp_reply = rx_a.recv().await.unwrap();
        assert_eq!(icmp_reply[9], 1, "ICMP");
        assert_eq!(icmp_reply[20], 3, "Destination Unreachable");
        assert_eq!(icmp_reply[21], 0, "net unreachable");
        let info = packet::parse_packet(&icmp_reply).unwrap();
        assert_eq!(info.src, "10.100.0.1".parse::<std::net::IpAddr>().unwrap());
        assert_eq!(info.dst, std::net::IpAddr::from(addr_a));
    }

    #[tokio::test]
    async fn policy_violation_generates_admin_prohibited() {
        let (engine, _table) = engine_no_tun(1400);
        let a = SessionId(0);
        let addr_a: Ipv4Addr = "10.100.0.2".parse().unwrap();
        let (tx_a, mut rx_a) = mpsc::channel(8);
        // Split tunnel: only 192.0.2.0/24 is advertised.
        let policy = EgressPolicy::new(Arc::new(vec![IpAddressRange::from_net(
            "192.0.2.0/24".parse().unwrap(),
            0,
        )]));
        engine.register_session(a, tx_a, policy);

        let pkt = build_ipv4_icmp_echo(
            addr_a,
            "198.51.100.9".parse().unwrap(),
            false,
            1,
            1,
            b"",
            64,
        );
        let err = engine
            .forward_from_client(a, &assigned(addr_a), pkt)
            .unwrap_err();
        assert!(matches!(err, ForwardingError::NotAllowed(_)));

        let icmp_reply = rx_a.recv().await.unwrap();
        assert_eq!(icmp_reply[20], 3, "Destination Unreachable");
        assert_eq!(icmp_reply[21], 13, "administratively prohibited");
    }

    #[tokio::test]
    async fn ttl_expiry_generates_time_exceeded() {
        let (engine, table) = engine_no_tun(1400);
        let a = SessionId(0);
        let addr_a: Ipv4Addr = "10.100.0.2".parse().unwrap();
        let (tx_a, mut rx_a) = mpsc::channel(8);
        engine.register_session(a, tx_a, allow_all_policy());
        table.insert_client_addr(addr_a.into(), a);

        let pkt = build_ipv4_icmp_echo(addr_a, addr_a, false, 1, 1, b"", 1);
        let err = engine
            .forward_from_client(a, &assigned(addr_a), pkt)
            .unwrap_err();
        assert!(matches!(err, ForwardingError::TtlExpired));

        let icmp_reply = rx_a.recv().await.unwrap();
        assert_eq!(icmp_reply[20], 11, "Time Exceeded");
        // The quoted original still carries TTL 1 (pre-decrement).
        assert_eq!(icmp_reply[28 + 8], 1);
    }

    #[tokio::test]
    async fn network_ingress_dispatches_to_session() {
        let (engine, table) = engine_no_tun(1400);
        let a = SessionId(0);
        let addr_a: Ipv4Addr = "10.100.0.2".parse().unwrap();
        let (tx_a, mut rx_a) = mpsc::channel(8);
        engine.register_session(a, tx_a, allow_all_policy());
        table.insert_client_addr(addr_a.into(), a);

        let inbound =
            build_ipv4_icmp_echo("192.0.2.1".parse().unwrap(), addr_a, true, 1, 1, b"", 64);
        let session = engine.dispatch_from_network(inbound).unwrap();
        assert_eq!(session, a);
        assert!(rx_a.recv().await.is_some());
    }

    #[tokio::test]
    async fn mtu_enforced_with_packet_too_big() {
        let (engine, _table) = engine_no_tun(1280);
        let a = SessionId(0);
        let addr_a: Ipv4Addr = "10.100.0.2".parse().unwrap();
        let (tx_a, mut rx_a) = mpsc::channel(8);
        engine.register_session(a, tx_a, allow_all_policy());

        let big = build_ipv4_icmp_echo(
            addr_a,
            "192.0.2.1".parse().unwrap(),
            false,
            1,
            1,
            &[0u8; 1400],
            64,
        );
        let err = engine
            .forward_from_client(a, &assigned(addr_a), big)
            .unwrap_err();
        assert!(matches!(err, ForwardingError::MtuExceeded));

        let icmp_reply = rx_a.recv().await.unwrap();
        assert_eq!(icmp_reply[20], 3);
        assert_eq!(icmp_reply[21], 4, "fragmentation needed");
        assert_eq!(
            u16::from_be_bytes([icmp_reply[26], icmp_reply[27]]),
            1280,
            "next-hop MTU"
        );
    }
}
