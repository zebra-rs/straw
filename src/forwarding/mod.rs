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
pub mod limiter;
pub mod nat;
pub mod packet;
pub mod router;
pub mod tun;
pub mod vnet;

use bytes::Bytes;
use dashmap::DashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::sync::mpsc;

use crate::capsule::{AssignedAddress, IpAddressRange};
use crate::datagram::{IpProxyingDatagram, encode_quic_datagram};
use crate::error::ForwardingError;
use crate::metrics::Metrics;
use crate::session::SessionId;

use self::icmp::{IcmpErrorKind, IcmpSource, build_icmp_error};
use self::limiter::{RateLimits, SessionLimiter};
use self::router::RouteTable;

/// Where packets bound for a session's client are delivered.
///
/// The hot path writes straight into the QUIC connection: `send_datagram`
/// is synchronous and lock-cheap, so hairpin and TUN-ingress packets skip
/// the per-session queue and the handler-task wakeup they used to cost
/// (Step 32). The channel variant remains for tests, which want to inspect
/// delivered packets.
#[derive(Debug, Clone)]
pub enum SessionSink {
    /// Deliver into a channel (tests, inspection).
    Channel(mpsc::Sender<Bytes>),
    /// Encode as an HTTP Datagram and send on the session's connection
    /// (quinn for the proxy, noq for a strawcat peer — via [`DatagramConn`]).
    Datagram {
        conn: Arc<dyn crate::datagram::DatagramConn>,
        qsid: u64,
    },
}

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
    session_sinks: DashMap<SessionId, SessionSink>,
    /// Per-session teardown signals: `unregister_session` fires them so the
    /// session handler (idle reaper path) wakes and runs its teardown, a job
    /// the dropped per-session channel used to do.
    session_notify: DashMap<SessionId, Arc<tokio::sync::Notify>>,
    /// Per-session egress policies (the advertised routes).
    policies: DashMap<SessionId, EgressPolicy>,
    /// Per-session token buckets; absent when limits are unlimited.
    limiters: DashMap<SessionId, SessionLimiter>,
    /// Per-session tunnel MTU: the largest IP packet one QUIC DATAGRAM can
    /// carry toward that client, capped by the configured MTU (RFC 9484
    /// §7.2). Live rather than sampled — quinn's path MTU starts low and
    /// rises as discovery probes, so a value frozen at setup would pin the
    /// tunnel to the initial estimate and reject full-size packets forever.
    session_mtus: DashMap<SessionId, Arc<AtomicUsize>>,
    /// Packets bound for the network; `None` when running without a TUN.
    tun_tx: Option<mpsc::Sender<Bytes>>,
    /// Tunnel MTU enforced on both directions.
    mtu: usize,
    /// Source addresses for generated ICMP errors (the pool gateways).
    icmp_source: IcmpSource,
    /// Per-session rate limits applied to client traffic.
    limits: RateLimits,
    metrics: Arc<Metrics>,
}

impl ForwardingEngine {
    pub fn new(
        route_table: Arc<RouteTable>,
        tun_tx: Option<mpsc::Sender<Bytes>>,
        mtu: u16,
        icmp_source: IcmpSource,
        limits: RateLimits,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self {
            route_table,
            session_sinks: DashMap::new(),
            session_notify: DashMap::new(),
            policies: DashMap::new(),
            limiters: DashMap::new(),
            session_mtus: DashMap::new(),
            tun_tx,
            mtu: mtu as usize,
            icmp_source,
            limits,
            metrics,
        }
    }

    pub fn route_table(&self) -> &Arc<RouteTable> {
        &self.route_table
    }

    /// Register the sink that delivers packets toward a session's client,
    /// and the egress policy matching what was advertised to it.
    pub fn register_session(
        &self,
        id: SessionId,
        sink: SessionSink,
        policy: EgressPolicy,
        mtu: Arc<AtomicUsize>,
    ) -> Arc<tokio::sync::Notify> {
        self.session_sinks.insert(id, sink);
        self.policies.insert(id, policy);
        self.session_mtus.insert(id, mtu);
        if !self.limits.is_unlimited() {
            self.limiters.insert(id, SessionLimiter::new(self.limits));
        }
        let notify = Arc::new(tokio::sync::Notify::new());
        self.session_notify.insert(id, notify.clone());
        notify
    }

    /// Remove a session's sink, policy and limiter (teardown).
    pub fn unregister_session(&self, id: SessionId) {
        self.session_sinks.remove(&id);
        self.policies.remove(&id);
        self.session_mtus.remove(&id);
        self.limiters.remove(&id);
        if let Some((_, notify)) = self.session_notify.remove(&id) {
            notify.notify_waiters();
        }
    }

    /// The current tunnel MTU toward `id`, or the configured MTU for a
    /// session that registered none.
    fn session_mtu(&self, id: SessionId) -> usize {
        self.session_mtus
            .get(&id)
            .map(|m| m.load(Ordering::Relaxed))
            .unwrap_or(self.mtu)
    }

    /// Process a packet received from a client tunnel.
    ///
    /// Rate-limits, validates (BCP 38 source check, MTU, destination
    /// sanity, egress policy), acts as one IP hop (TTL decrement), then
    /// either hairpins to another session or hands the packet to the TUN
    /// device. Drops that a router would report earn an ICMP error back to
    /// the sender (§7.2).
    ///
    /// Takes `Bytes` so the common case (a uniquely owned datagram payload)
    /// mutates TTL in place without copying (Step 32).
    pub fn forward_from_client(
        &self,
        from: SessionId,
        assigned: &[AssignedAddress],
        packet: Bytes,
    ) -> Result<Forwarded, ForwardingError> {
        Metrics::add(&self.metrics.bytes_from_client_total, packet.len() as u64);

        // Rate limiting first: over-limit traffic must not cost validation
        // work, and is dropped silently (Step 25).
        if let Some(limiter) = self.limiters.get(&from)
            && !limiter.try_consume(packet.len() as u64)
        {
            Metrics::incr(&self.metrics.packets_rate_limited_total);
            return Err(ForwardingError::RateLimited);
        }

        let result = self.forward_validated(from, assigned, packet);
        match &result {
            Ok(Forwarded::Hairpin(_)) => Metrics::incr(&self.metrics.packets_hairpin_total),
            Ok(Forwarded::Tun) => Metrics::incr(&self.metrics.packets_tun_out_total),
            Err(_) => Metrics::incr(&self.metrics.packets_dropped_total),
        }
        result
    }

    fn forward_validated(
        &self,
        from: SessionId,
        assigned: &[AssignedAddress],
        packet: Bytes,
    ) -> Result<Forwarded, ForwardingError> {
        // Zero-copy when we hold the sole reference to the buffer; only a
        // shared buffer (e.g. quinn batching) costs a copy.
        let mut packet = packet
            .try_into_mut()
            .unwrap_or_else(|shared| bytes::BytesMut::from(&shared[..]));

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
        // itself), so the packet never touches the TUN device. The
        // receiver's scope applies on ingress too: a flow-scoped session
        // (RFC 9484 §8.3) only accepts packets from within its scope.
        if let Some(target) = self.route_table.lookup(info.dst, info.protocol) {
            if !self.session_accepts(target, &info) {
                self.send_icmp_error(from, IcmpErrorKind::AdminProhibited, &packet);
                return Err(ForwardingError::NotAllowed(info.dst));
            }
            let peer_mtu = self.session_mtu(target);
            if packet.len() > peer_mtu {
                Metrics::incr(&self.metrics.packets_mtu_dropped_total);
                self.send_icmp_error(
                    from,
                    IcmpErrorKind::PacketTooBig {
                        mtu: peer_mtu as u16,
                    },
                    &packet,
                );
                return Err(ForwardingError::MtuExceeded);
            }
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
            Metrics::incr(&self.metrics.icmp_errors_sent_total);
            tracing::trace!(session = %to, ?kind, "ICMP error sent");
        }
    }

    /// Whether packets from `info.src` fall inside the receiving session's
    /// advertised scope (ICMP is exempt on the protocol dimension).
    fn session_accepts(&self, target: SessionId, info: &packet::PacketInfo) -> bool {
        self.policies
            .get(&target)
            .map(|p| p.allows(&info.src, info.protocol))
            .unwrap_or(false)
    }

    /// Process a packet arriving from the network (TUN device) and dispatch
    /// it to the owning session.
    pub fn dispatch_from_network(&self, packet: Bytes) -> Result<SessionId, ForwardingError> {
        // Zero-copy when the buffer is uniquely owned, mirroring the
        // client→network path (Step 32).
        let mut packet = packet
            .try_into_mut()
            .unwrap_or_else(|shared| bytes::BytesMut::from(&shared[..]));
        let info = packet::parse_packet(&packet)?;
        let target = self
            .route_table
            .lookup(info.dst, info.protocol)
            .ok_or(ForwardingError::NoRoute)?;
        // Ingress scope: flow-scoped sessions only accept traffic from
        // their target (dropped silently for network-originated packets).
        if !self.session_accepts(target, &info) {
            return Err(ForwardingError::NotAllowed(info.src));
        }
        // The tunnel toward this client can briefly be narrower than the TUN
        // device before path-MTU discovery ramps. Drop and count rather than
        // inject a martian-sourced ICMP into the network; PMTUD toward the
        // network is the kernel's job via the device MTU.
        let mtu = self.session_mtu(target);
        if packet.len() > mtu {
            Metrics::incr(&self.metrics.packets_mtu_dropped_total);
            return Err(ForwardingError::MtuExceeded);
        }
        packet::decrement_ttl(&mut packet)?;
        self.deliver_to_session(target, Bytes::from(packet))?;
        Ok(target)
    }

    fn deliver_to_session(&self, id: SessionId, packet: Bytes) -> Result<(), ForwardingError> {
        let sink = self
            .session_sinks
            .get(&id)
            .ok_or(ForwardingError::NoRoute)?;
        let len = packet.len() as u64;
        match sink.value() {
            // Datagram semantics: drop on backpressure instead of blocking
            // the whole data plane.
            SessionSink::Channel(tx) => {
                tx.try_send(packet)
                    .map_err(|_| ForwardingError::Congested)?;
            }
            // Direct egress: encode and hand to QUIC right here. The engine
            // checked the packet against the session MTU, so an oversize
            // datagram means the path narrowed under us — count it.
            SessionSink::Datagram { conn, qsid } => {
                let wire = encode_quic_datagram(*qsid, &IpProxyingDatagram::ip_packet(packet));
                if let Some(max) = conn.max_datagram_size()
                    && wire.len() > max
                {
                    Metrics::incr(&self.metrics.packets_mtu_dropped_total);
                    tracing::debug!(
                        session = %id, len = wire.len(), max,
                        "datagram exceeds the connection's datagram size"
                    );
                    return Err(ForwardingError::MtuExceeded);
                }
                conn.send_datagram(wire).map_err(|e| {
                    tracing::debug!(session = %id, "send_datagram failed: {e}");
                    ForwardingError::Congested
                })?;
            }
        }
        Metrics::incr(&self.metrics.packets_to_client_total);
        Metrics::add(&self.metrics.bytes_to_client_total, len);
        Ok(())
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

    fn unlimited_mtu() -> Arc<AtomicUsize> {
        Arc::new(AtomicUsize::new(usize::MAX))
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
        engine_with_limits(mtu, RateLimits::default())
    }

    fn engine_with_limits(
        mtu: u16,
        limits: RateLimits,
    ) -> (Arc<ForwardingEngine>, Arc<RouteTable>) {
        let table = Arc::new(RouteTable::new());
        let engine = Arc::new(ForwardingEngine::new(
            table.clone(),
            None,
            mtu,
            test_icmp_source(),
            limits,
            Arc::new(Metrics::default()),
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
        engine.register_session(
            a,
            SessionSink::Channel(tx_a),
            allow_all_policy(),
            unlimited_mtu(),
        );
        engine.register_session(
            b,
            SessionSink::Channel(tx_b),
            allow_all_policy(),
            unlimited_mtu(),
        );
        table.insert_client_addr(addr_a.into(), a);
        table.insert_client_addr(addr_b.into(), b);

        let ping = build_ipv4_icmp_echo(addr_a, addr_b, false, 1, 1, b"hi", 64);
        let result = engine
            .forward_from_client(a, &assigned(addr_a), ping.into())
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
        engine.register_session(
            a,
            SessionSink::Channel(tx_a),
            allow_all_policy(),
            unlimited_mtu(),
        );
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
            .forward_from_client(a, &assigned(addr_a), spoofed.into())
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
        engine.register_session(
            a,
            SessionSink::Channel(tx_a),
            allow_all_policy(),
            unlimited_mtu(),
        );

        let pkt = build_ipv4_icmp_echo(addr_a, "192.0.2.1".parse().unwrap(), false, 1, 1, b"", 64);
        let err = engine
            .forward_from_client(a, &assigned(addr_a), pkt.into())
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
        engine.register_session(a, SessionSink::Channel(tx_a), policy, unlimited_mtu());

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
            .forward_from_client(a, &assigned(addr_a), pkt.into())
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
        engine.register_session(
            a,
            SessionSink::Channel(tx_a),
            allow_all_policy(),
            unlimited_mtu(),
        );
        table.insert_client_addr(addr_a.into(), a);

        let pkt = build_ipv4_icmp_echo(addr_a, addr_a, false, 1, 1, b"", 1);
        let err = engine
            .forward_from_client(a, &assigned(addr_a), pkt.into())
            .unwrap_err();
        assert!(matches!(err, ForwardingError::TtlExpired));

        let icmp_reply = rx_a.recv().await.unwrap();
        assert_eq!(icmp_reply[20], 11, "Time Exceeded");
        // The quoted original still carries TTL 1 (pre-decrement).
        assert_eq!(icmp_reply[28 + 8], 1);
    }

    #[tokio::test]
    async fn rate_limit_drops_excess_packets() {
        let (engine, table) = engine_with_limits(
            1400,
            RateLimits {
                packets_per_sec: 2,
                bytes_per_sec: 0,
            },
        );
        let a = SessionId(0);
        let addr_a: Ipv4Addr = "10.100.0.2".parse().unwrap();
        let (tx_a, mut rx_a) = mpsc::channel(8);
        engine.register_session(
            a,
            SessionSink::Channel(tx_a),
            allow_all_policy(),
            unlimited_mtu(),
        );
        table.insert_client_addr(addr_a.into(), a);

        let ping = || build_ipv4_icmp_echo(addr_a, addr_a, false, 1, 1, b"x", 64);
        assert!(
            engine
                .forward_from_client(a, &assigned(addr_a), ping().into())
                .is_ok()
        );
        assert!(
            engine
                .forward_from_client(a, &assigned(addr_a), ping().into())
                .is_ok()
        );
        let err = engine
            .forward_from_client(a, &assigned(addr_a), ping().into())
            .unwrap_err();
        assert!(matches!(err, ForwardingError::RateLimited));
        // Two delivered, nothing else (silent drop: no ICMP either).
        assert!(rx_a.recv().await.is_some());
        assert!(rx_a.recv().await.is_some());
        assert!(rx_a.try_recv().is_err());
    }

    /// Rewrite an ICMP echo into the given IP protocol (fixing the header
    /// checksum) to fake other transports in tests.
    fn with_proto(mut pkt: Vec<u8>, proto: u8) -> Vec<u8> {
        pkt[9] = proto;
        pkt[10] = 0;
        pkt[11] = 0;
        let cs = packet::ipv4_checksum(&pkt[..20]);
        pkt[10..12].copy_from_slice(&cs.to_be_bytes());
        pkt
    }

    #[tokio::test]
    async fn flow_scoped_session_filters_ingress() {
        let (engine, table) = engine_no_tun(1400);
        let a = SessionId(0); // full tunnel
        let b = SessionId(4); // flow tunnel scoped to {A's address, UDP}
        let c = SessionId(8); // full tunnel
        let addr_a: Ipv4Addr = "10.100.0.2".parse().unwrap();
        let addr_b: Ipv4Addr = "10.100.0.3".parse().unwrap();
        let addr_c: Ipv4Addr = "10.100.0.4".parse().unwrap();

        let (tx_a, _rx_a) = mpsc::channel(8);
        let (tx_b, mut rx_b) = mpsc::channel(8);
        let (tx_c, mut rx_c) = mpsc::channel(8);
        engine.register_session(
            a,
            SessionSink::Channel(tx_a),
            allow_all_policy(),
            unlimited_mtu(),
        );
        engine.register_session(
            b,
            SessionSink::Channel(tx_b),
            EgressPolicy::new(Arc::new(vec![IpAddressRange {
                ip_version: 4,
                start_ip: addr_a.into(),
                end_ip: addr_a.into(),
                ip_protocol: 17, // UDP only
            }])),
            unlimited_mtu(),
        );
        engine.register_session(
            c,
            SessionSink::Channel(tx_c),
            allow_all_policy(),
            unlimited_mtu(),
        );
        table.insert_client_addr(addr_a.into(), a);
        table.insert_client_addr(addr_b.into(), b);
        table.insert_client_addr(addr_c.into(), c);

        // In-scope sender + protocol: delivered.
        let udp_from_a = with_proto(
            build_ipv4_icmp_echo(addr_a, addr_b, false, 1, 1, b"udpish", 64),
            17,
        );
        assert_eq!(
            engine
                .forward_from_client(a, &assigned(addr_a), udp_from_a.into())
                .unwrap(),
            Forwarded::Hairpin(b)
        );
        assert!(rx_b.recv().await.is_some());

        // Out-of-scope sender: dropped, sender told it is prohibited.
        let udp_from_c = with_proto(
            build_ipv4_icmp_echo(addr_c, addr_b, false, 1, 1, b"udpish", 64),
            17,
        );
        let err = engine
            .forward_from_client(c, &assigned(addr_c), udp_from_c.into())
            .unwrap_err();
        assert!(matches!(err, ForwardingError::NotAllowed(_)));
        let icmp_reply = rx_c.recv().await.unwrap();
        assert_eq!(icmp_reply[20], 3);
        assert_eq!(icmp_reply[21], 13, "administratively prohibited");
        assert!(rx_b.try_recv().is_err(), "nothing leaked to B");

        // ICMP from the in-scope peer passes despite the UDP-only scope
        // (RFC 9484: ICMP always allowed on the protocol dimension).
        let icmp_from_a = build_ipv4_icmp_echo(addr_a, addr_b, false, 1, 2, b"ping", 64);
        assert_eq!(
            engine
                .forward_from_client(a, &assigned(addr_a), icmp_from_a.into())
                .unwrap(),
            Forwarded::Hairpin(b)
        );
        assert!(rx_b.recv().await.is_some());
    }

    #[tokio::test]
    async fn network_ingress_dispatches_to_session() {
        let (engine, table) = engine_no_tun(1400);
        let a = SessionId(0);
        let addr_a: Ipv4Addr = "10.100.0.2".parse().unwrap();
        let (tx_a, mut rx_a) = mpsc::channel(8);
        engine.register_session(
            a,
            SessionSink::Channel(tx_a),
            allow_all_policy(),
            unlimited_mtu(),
        );
        table.insert_client_addr(addr_a.into(), a);

        let inbound =
            build_ipv4_icmp_echo("192.0.2.1".parse().unwrap(), addr_a, true, 1, 1, b"", 64);
        let session = engine.dispatch_from_network(inbound.into()).unwrap();
        assert_eq!(session, a);
        assert!(rx_a.recv().await.is_some());
    }

    #[tokio::test]
    async fn mtu_enforced_with_packet_too_big() {
        let (engine, _table) = engine_no_tun(1280);
        let a = SessionId(0);
        let addr_a: Ipv4Addr = "10.100.0.2".parse().unwrap();
        let (tx_a, mut rx_a) = mpsc::channel(8);
        engine.register_session(
            a,
            SessionSink::Channel(tx_a),
            allow_all_policy(),
            unlimited_mtu(),
        );

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
            .forward_from_client(a, &assigned(addr_a), big.into())
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
