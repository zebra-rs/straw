//! Relay-side CONNECT-UDP bind support (design §7): the untrusted UDP
//! forwarder half of the P2P direct path.
//!
//! A peer opens an Extended CONNECT with `:protocol = connect-udp` and
//! `connect-udp-bind: ?1`; the relay allocates a public (IP, port), binds a
//! UDP socket to it, and forwards packets both ways — inner-QUIC ciphertext
//! it cannot read (design §4). This is the TURN-equivalent from
//! draft-ietf-masque-connect-udp-listen.
//!
//! This increment lands the two pure, self-contained pieces the rest builds
//! on:
//! - [`context`] — the COMPRESSION_ASSIGN/ACK/CLOSE capsule codec and the
//!   per-session context table (§3.1); also the uncompressed/compressed
//!   HTTP Datagram payload codec that carries remote addresses.
//! - [`alloc`] — public (IP, port) allocation from a configured pool (§7.1).
//!
//! The per-session bound socket and its encap/decap rewrite loop
//! (`socket.rs`), the connect-udp request handler, and the abuse caps (§7.4,
//! §10) build on these next.
//!
//! Provisional codepoints (design §9) are pinned here and in [`context`] so
//! the eventual swap to the finalized listen-draft numbers is one place.

pub mod alloc;
pub mod context;
pub mod handler;
pub mod socket;

use std::sync::Arc;

use bytes::Bytes;
use dashmap::DashMap;
use tokio::sync::mpsc;

use crate::forwarding::limiter::RateLimits;
use crate::session::SessionId;
use crate::udp_bind::alloc::PortAllocator;
use crate::udp_bind::socket::DestinationPolicy;

/// Relay-wide CONNECT-UDP bind state, shared through [`crate::server::ProxyContext`].
///
/// Present (with a live allocator) only when bind mode is enabled; otherwise
/// a connect-udp request is refused. The `sessions` registry lets the
/// connection's datagram demux route a bind session's datagrams to its
/// [`socket::BindSocket`](crate::udp_bind::socket) without decoding them as
/// CONNECT-IP.
#[derive(Debug)]
pub struct UdpBindState {
    allocator: Option<Arc<PortAllocator>>,
    policy: DestinationPolicy,
    egress_limits: RateLimits,
    /// qsid-keyed (via `SessionId`) sinks delivering peer datagrams to each
    /// bind session's bound socket.
    sessions: DashMap<SessionId, mpsc::Sender<Bytes>>,
}

impl UdpBindState {
    /// Bind mode disabled: connect-udp requests are refused.
    pub fn disabled() -> Self {
        Self {
            allocator: None,
            policy: DestinationPolicy::default(),
            egress_limits: RateLimits::default(),
            sessions: DashMap::new(),
        }
    }

    /// Bind mode enabled with the given allocator, egress policy and caps.
    pub fn enabled(
        allocator: PortAllocator,
        policy: DestinationPolicy,
        egress_limits: RateLimits,
    ) -> Self {
        Self {
            allocator: Some(Arc::new(allocator)),
            policy,
            egress_limits,
            sessions: DashMap::new(),
        }
    }

    /// Whether bind mode is enabled on this relay.
    pub fn is_enabled(&self) -> bool {
        self.allocator.is_some()
    }

    pub fn allocator(&self) -> Option<&Arc<PortAllocator>> {
        self.allocator.as_ref()
    }

    pub fn policy(&self) -> &DestinationPolicy {
        &self.policy
    }

    pub fn egress_limits(&self) -> RateLimits {
        self.egress_limits
    }

    /// Register a bind session's peer→socket sink (demux routing).
    pub fn register(&self, id: SessionId, sink: mpsc::Sender<Bytes>) {
        self.sessions.insert(id, sink);
    }

    /// Remove a bind session's sink on teardown.
    pub fn unregister(&self, id: SessionId) {
        self.sessions.remove(&id);
    }

    /// The peer→socket sink for a bind session, if this is one.
    pub fn sink(&self, id: SessionId) -> Option<mpsc::Sender<Bytes>> {
        self.sessions.get(&id).map(|s| s.clone())
    }
}
