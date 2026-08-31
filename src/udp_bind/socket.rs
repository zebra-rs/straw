//! Per-session bound UDP socket and its encap/decap rewrite loop (design
//! §7.2). This is the relay's data plane for a bind session: raw UDP to the
//! Internet on one side, context-framed HTTP Datagrams to the peer on the
//! other.
//!
//! Two directions:
//! - **network → peer**: a UDP packet from some `remote` is wrapped as an
//!   HTTP Datagram — an existing compressed context for that exact remote,
//!   else the uncompressed context (which spells the address out). With the
//!   uncompressed context closed and no compressed match, the packet is
//!   dropped: the relay is then a firewall for registered remotes only
//!   (design §7.3, §10.4).
//! - **peer → network**: an HTTP Datagram from the peer is decoded to
//!   `(remote, payload)` and sent as UDP — after the egress checks that keep
//!   this from being an open reflector (design §7.4, §10.1): a destination
//!   denylist (RFC 1918, loopback, multicast, unspecified) and the session's
//!   pps/bandwidth cap.
//!
//! The socket is bound to the public tuple [`crate::udp_bind::alloc`] handed
//! out; abuse controls above and mandatory auth at the handler make bind
//! mode safe to expose.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::forwarding::limiter::SessionLimiter;
use crate::udp_bind::context::ContextTable;

/// Largest UDP payload the relay will move in either direction.
const MAX_UDP_PAYLOAD: usize = 65_535;

/// Which destinations a bind session may send to (design §10.1). Denying
/// private and local ranges is the amplification/SSRF guard; an operator
/// can widen it, never silently narrow past these.
#[derive(Debug, Clone, Default)]
pub struct DestinationPolicy {
    /// Extra CIDRs to deny beyond the always-denied local ranges.
    denied: Arc<Vec<ipnet::IpNet>>,
    /// Prefixes explicitly permitted by the operator, overriding the
    /// built-in local-range denial (design §10.1, "unless explicitly
    /// configured"). Needed to relay within a private network or on one host.
    allowed: Arc<Vec<ipnet::IpNet>>,
    /// Test-only escape hatch to reach a loopback echo server; never set in
    /// production.
    allow_all: bool,
}

impl DestinationPolicy {
    /// Deny these extra prefixes on top of the built-in local ranges.
    pub fn with_denied(denied: Vec<ipnet::IpNet>) -> Self {
        Self {
            denied: Arc::new(denied),
            ..Default::default()
        }
    }

    /// Operator config: permit `allowed` prefixes (overriding local-range
    /// denial) and additionally deny `denied`.
    pub fn new(allowed: Vec<ipnet::IpNet>, denied: Vec<ipnet::IpNet>) -> Self {
        Self {
            denied: Arc::new(denied),
            allowed: Arc::new(allowed),
            allow_all: false,
        }
    }

    /// Whether the relay may forward to `addr`.
    pub fn allows(&self, addr: &SocketAddr) -> bool {
        if addr.port() == 0 {
            return false;
        }
        if self.allow_all {
            return true;
        }
        let ip = addr.ip();
        // An explicit allow beats the local-range denial, but a configured
        // deny still wins over an allow (deny is the safer default).
        if self.denied.iter().any(|net| net.contains(&ip)) {
            return false;
        }
        if self.allowed.iter().any(|net| net.contains(&ip)) {
            return true;
        }
        !is_local(&ip)
    }

    /// Allow any (nonzero-port) destination, loopback included — only to
    /// reach a loopback echo server in tests (unit and integration).
    #[doc(hidden)]
    pub fn allow_all_for_test() -> Self {
        Self {
            allow_all: true,
            ..Default::default()
        }
    }
}

/// Ranges the relay must never reflect to: its own host, private networks,
/// link-local, multicast, and the unspecified address. Blocks the obvious
/// SSRF/amplification targets regardless of operator config.
fn is_local(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || v4.octets()[0] == 0
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xffc0) == 0xfe80 // link-local
                || (v6.segments()[0] & 0xfe00) == 0xfc00 // unique local
        }
    }
}

/// A bound UDP socket serving one bind session.
pub struct BindSocket {
    socket: Arc<UdpSocket>,
    public_addr: SocketAddr,
    contexts: Arc<Mutex<ContextTable>>,
    policy: DestinationPolicy,
    limiter: Arc<SessionLimiter>,
}

impl BindSocket {
    /// Bind a UDP socket to `public_addr` (the allocated tuple) for a
    /// session sharing `contexts` with its capsule handler.
    pub async fn bind(
        public_addr: SocketAddr,
        contexts: Arc<Mutex<ContextTable>>,
        policy: DestinationPolicy,
        limiter: Arc<SessionLimiter>,
    ) -> std::io::Result<Self> {
        let socket = Arc::new(UdpSocket::bind(public_addr).await?);
        let public_addr = socket.local_addr()?;
        Ok(Self {
            socket,
            public_addr,
            contexts,
            policy,
            limiter,
        })
    }

    /// The bound public tuple (its ephemeral port resolved if 0 was passed).
    pub fn public_addr(&self) -> SocketAddr {
        self.public_addr
    }

    /// Run the rewrite loop until either channel closes.
    ///
    /// `from_peer` yields HTTP Datagram bodies the peer sent (context id +
    /// optional address + UDP payload); `to_peer` receives the datagram
    /// bodies to hand back over QUIC. Egress is dropped, not errored, when a
    /// destination is denied or the rate cap is hit — datagram semantics.
    pub async fn run(self, mut from_peer: mpsc::Receiver<Bytes>, to_peer: mpsc::Sender<Bytes>) {
        let socket = self.socket.clone();
        let contexts = self.contexts.clone();

        // network → peer
        let inbound = tokio::spawn(async move {
            let mut buf = vec![0u8; MAX_UDP_PAYLOAD];
            loop {
                let (n, remote) = match socket.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::debug!("bind socket recv failed: {e}");
                        return;
                    }
                };
                let wire = {
                    let table = contexts.lock().unwrap();
                    encapsulate(&table, remote, &buf[..n])
                };
                match wire {
                    Some(wire) => {
                        if to_peer.try_send(wire).is_err() {
                            // peer gone or congested: datagram semantics
                        }
                    }
                    // Firewall: unregistered remote with no uncompressed
                    // context — dropped (design §7.3).
                    None => tracing::trace!(%remote, "inbound from unregistered remote dropped"),
                }
            }
        });

        // peer → network
        let socket = self.socket;
        let contexts = self.contexts;
        let policy = self.policy;
        let limiter = self.limiter;
        while let Some(body) = from_peer.recv().await {
            let decoded = {
                let table = contexts.lock().unwrap();
                table.decode_datagram(body)
            };
            let dg = match decoded {
                Ok(dg) => dg,
                Err(e) => {
                    tracing::trace!("peer datagram dropped: {e}");
                    continue;
                }
            };
            if !policy.allows(&dg.remote) {
                tracing::debug!(remote = %dg.remote, "egress to denied destination dropped");
                continue;
            }
            if !limiter.try_consume(dg.payload.len() as u64) {
                tracing::trace!("egress rate cap hit; datagram dropped");
                continue;
            }
            if let Err(e) = socket.send_to(&dg.payload, dg.remote).await {
                tracing::trace!(remote = %dg.remote, "egress send failed: {e}");
            }
        }
        inbound.abort();
    }
}

/// Wrap a UDP payload from `remote` as an HTTP Datagram body, choosing the
/// context: a compressed context bound to this exact remote if one exists,
/// otherwise the uncompressed context. `None` means drop (no context can
/// carry it — the firewall case).
fn encapsulate(table: &ContextTable, remote: SocketAddr, payload: &[u8]) -> Option<Bytes> {
    // Prefer a compressed context for this remote (smaller on the wire and
    // the only path once the uncompressed context is closed).
    if let Some(id) = table.compressed_context_for(remote) {
        return table.encode_datagram(id, remote, payload).ok();
    }
    let id = table.uncompressed_context()?;
    table.encode_datagram(id, remote, payload).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::forwarding::limiter::RateLimits;
    use crate::udp_bind::context::{Binding, CompressionAssign, FIRST_UNCOMPRESSED_CONTEXT};

    fn unlimited() -> Arc<SessionLimiter> {
        Arc::new(SessionLimiter::new(RateLimits::default()))
    }

    #[test]
    fn policy_denies_local_and_private_targets() {
        let p = DestinationPolicy::default();
        assert!(p.allows(&"198.51.100.7:443".parse().unwrap()));
        assert!(p.allows(&"[2001:db8::1]:443".parse().unwrap()));
        for denied in [
            "127.0.0.1:443",
            "10.0.0.1:443",
            "192.168.1.1:443",
            "169.254.0.1:443",
            "224.0.0.1:443",
            "0.0.0.0:443",
            "198.51.100.7:0", // port 0
            "[::1]:443",
            "[fe80::1]:443",
            "[fc00::1]:443",
            "[ff02::1]:443",
        ] {
            assert!(
                !p.allows(&denied.parse().unwrap()),
                "{denied} should be denied"
            );
        }
    }

    #[test]
    fn policy_allowlist_overrides_local_denial() {
        // Permit loopback explicitly (single-host relay), still deny the rest.
        let p = DestinationPolicy::new(vec!["127.0.0.0/8".parse().unwrap()], vec![]);
        assert!(p.allows(&"127.0.0.1:9000".parse().unwrap()));
        assert!(
            !p.allows(&"10.0.0.1:9000".parse().unwrap()),
            "other locals stay denied"
        );
        assert!(p.allows(&"198.51.100.1:9000".parse().unwrap()));
        // A deny beats an allow.
        let d = DestinationPolicy::new(
            vec!["10.0.0.0/8".parse().unwrap()],
            vec!["10.6.6.0/24".parse().unwrap()],
        );
        assert!(d.allows(&"10.1.2.3:80".parse().unwrap()));
        assert!(!d.allows(&"10.6.6.6:80".parse().unwrap()));
    }

    #[test]
    fn policy_honours_extra_denied_prefixes() {
        let p = DestinationPolicy::with_denied(vec!["203.0.113.0/24".parse().unwrap()]);
        assert!(!p.allows(&"203.0.113.5:443".parse().unwrap()));
        assert!(p.allows(&"198.51.100.5:443".parse().unwrap()));
    }

    fn table_with_uncompressed() -> Arc<Mutex<ContextTable>> {
        let mut t = ContextTable::new();
        t.register(CompressionAssign {
            context_id: FIRST_UNCOMPRESSED_CONTEXT,
            binding: Binding::Uncompressed,
        })
        .unwrap();
        t.ack(FIRST_UNCOMPRESSED_CONTEXT).unwrap();
        Arc::new(Mutex::new(t))
    }

    #[tokio::test]
    async fn inbound_udp_is_encapsulated_to_the_peer() {
        // A raw sender on loopback stands in for an Internet remote; the
        // inbound path has no destination policy (that guards egress only).
        let contexts = table_with_uncompressed();
        let bind = BindSocket::bind(
            "127.0.0.1:0".parse().unwrap(),
            contexts.clone(),
            DestinationPolicy::default(),
            unlimited(),
        )
        .await
        .unwrap();
        let relay_addr = bind.public_addr();

        let (_to_net_tx, to_net_rx) = mpsc::channel(8);
        let (from_net_tx, mut from_net_rx) = mpsc::channel(8);
        tokio::spawn(bind.run(to_net_rx, from_net_tx));

        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender_addr = sender.local_addr().unwrap();
        sender.send_to(b"hello", relay_addr).await.unwrap();

        let wire = tokio::time::timeout(std::time::Duration::from_secs(2), from_net_rx.recv())
            .await
            .expect("encapsulated within 2s")
            .expect("a datagram");
        let dg = contexts.lock().unwrap().decode_datagram(wire).unwrap();
        assert_eq!(dg.remote, sender_addr, "carries the sender's address");
        assert_eq!(&dg.payload[..], b"hello");
    }

    #[tokio::test]
    async fn full_round_trip_through_the_bound_socket() {
        // peer datagram -> relay UDP -> echo -> relay -> peer datagram.
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            while let Ok((n, from)) = echo.recv_from(&mut buf).await {
                let _ = echo.send_to(&buf[..n], from).await;
            }
        });

        let contexts = table_with_uncompressed();
        let bind = BindSocket::bind(
            "127.0.0.1:0".parse().unwrap(),
            contexts.clone(),
            DestinationPolicy::allow_all_for_test(),
            unlimited(),
        )
        .await
        .unwrap();

        let (to_net_tx, to_net_rx) = mpsc::channel(8);
        let (from_net_tx, mut from_net_rx) = mpsc::channel(8);
        tokio::spawn(bind.run(to_net_rx, from_net_tx));

        let body = contexts
            .lock()
            .unwrap()
            .encode_datagram(FIRST_UNCOMPRESSED_CONTEXT, echo_addr, b"ping")
            .unwrap();
        to_net_tx.send(body).await.unwrap();

        let reply = tokio::time::timeout(std::time::Duration::from_secs(2), from_net_rx.recv())
            .await
            .expect("reply within 2s")
            .expect("a datagram");
        let dg = contexts.lock().unwrap().decode_datagram(reply).unwrap();
        assert_eq!(dg.remote, echo_addr);
        assert_eq!(&dg.payload[..], b"ping");
    }

    /// The §10.4 lockdown's actual security property, at the only place it can
    /// be observed: with the uncompressed context closed, the relay forwards
    /// inbound only for the *bound* peer and drops everything else at its edge,
    /// before it ever becomes an inner-QUIC packet for the peer to parse.
    #[tokio::test]
    async fn after_lockdown_only_the_bound_peer_reaches_the_session() {
        let peer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let peer_addr = peer.local_addr().unwrap();
        let stranger = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        // A locked-down table: one compressed context, no uncompressed one.
        let contexts = Arc::new(Mutex::new(ContextTable::new()));
        {
            let mut t = contexts.lock().unwrap();
            t.register(CompressionAssign {
                context_id: 4,
                binding: Binding::Compressed(peer_addr),
            })
            .unwrap();
            t.ack(4).unwrap();
        }

        let bind = BindSocket::bind(
            "127.0.0.1:0".parse().unwrap(),
            contexts.clone(),
            DestinationPolicy::default(),
            unlimited(),
        )
        .await
        .unwrap();
        let relay_addr = bind.public_addr();
        let (_to_net_tx, to_net_rx) = mpsc::channel(8);
        let (from_net_tx, mut from_net_rx) = mpsc::channel(8);
        tokio::spawn(bind.run(to_net_rx, from_net_tx));

        // The stranger is dropped at the edge...
        stranger.send_to(b"unsolicited", relay_addr).await.unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(400), from_net_rx.recv())
                .await
                .is_err(),
            "an unregistered remote must not be forwarded once the uncompressed \
             context is closed"
        );

        // ...while the bound peer still gets through, on its compressed
        // context. Dropping everything would be a broken relay, not a firewall.
        peer.send_to(b"from-the-peer", relay_addr).await.unwrap();
        let wire = tokio::time::timeout(std::time::Duration::from_secs(2), from_net_rx.recv())
            .await
            .expect("the bound peer is still forwarded")
            .expect("a datagram");
        let dg = contexts.lock().unwrap().decode_datagram(wire).unwrap();
        assert_eq!(dg.context_id, 4, "carried on the compressed context");
        assert_eq!(dg.remote, peer_addr);
        assert_eq!(&dg.payload[..], b"from-the-peer");
    }

    #[tokio::test]
    async fn egress_to_a_denied_destination_is_dropped() {
        // Default policy denies loopback, so nothing reaches the echo.
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        let got = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let seen = got.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 64];
            if echo.recv_from(&mut buf).await.is_ok() {
                seen.store(true, std::sync::atomic::Ordering::SeqCst);
            }
        });

        let contexts = table_with_uncompressed();
        let bind = BindSocket::bind(
            "127.0.0.1:0".parse().unwrap(),
            contexts.clone(),
            DestinationPolicy::default(),
            unlimited(),
        )
        .await
        .unwrap();
        let (to_net_tx, to_net_rx) = mpsc::channel(8);
        let (from_net_tx, _from_net_rx) = mpsc::channel(8);
        tokio::spawn(bind.run(to_net_rx, from_net_tx));

        let body = contexts
            .lock()
            .unwrap()
            .encode_datagram(FIRST_UNCOMPRESSED_CONTEXT, echo_addr, b"ping")
            .unwrap();
        to_net_tx.send(body).await.unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        assert!(
            !got.load(std::sync::atomic::Ordering::SeqCst),
            "denied loopback destination must not be reached"
        );
    }
}
