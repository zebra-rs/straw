//! Peer orchestration for the direct path (design §2–4): open a bind session
//! at the relay, then form the inner, SPKI-pinned QUIC connection to the
//! other peer over it.
//!
//! Two roles for the relay path (§2.1): the token *issuer* listens (inner
//! QUIC server), the token *holder* connects (inner QUIC client). The
//! symmetric role tie-break by SPKI is only needed for hole punching (§5,
//! P2); here listen/connect is unambiguous.

use std::net::SocketAddr;
use std::sync::Arc;

use noq::crypto::rustls::{QuicClientConfig, QuicServerConfig};

use crate::client::{BindClient, ClientAuth, TlsMode};
use crate::error::ProxyError;
use crate::p2p::identity::{Identity, SpkiPin};
use crate::p2p::inner_tls;
use crate::p2p::relay_socket::{PathMuxHandle, mux_endpoint};
use crate::p2p::token::TokenV2;

/// How to reach and authenticate to the relay (the outer connection).
#[derive(Clone)]
pub struct RelayAccess {
    pub addr: SocketAddr,
    pub server_name: String,
    pub tls: TlsMode,
    pub auth: ClientAuth,
}

/// A listening peer: its relay-public address (`paddr`) to advertise in a
/// token, and an inner endpoint that accepts one SPKI-pinned connection.
pub struct Listener {
    pub paddr: SocketAddr,
    /// The relay's view of this peer's outer source. Only its *IP* is this
    /// peer's public address; the port belongs to the outer bind socket, so the
    /// punch pairs the IP with the direct socket's port instead.
    pub reflexive: Option<SocketAddr>,
    /// The outer bind socket. The v1 app-level punch dialled from it; the
    /// native punch uses the mux's direct socket instead, so this is exposed
    /// only for callers that want the underlying endpoint.
    pub punch_endpoint: quinn::Endpoint,
    /// The combined-transport socket's handle: the direct socket's local
    /// address, which is half of this peer's candidate (Stage 3).
    pub mux: PathMuxHandle,
    endpoint: noq::Endpoint,
}

impl Listener {
    /// Accept the next inner connection (already mutually pin-verified).
    pub async fn accept(&self) -> Result<noq::Connection, ProxyError> {
        let incoming = self
            .endpoint
            .accept()
            .await
            .ok_or_else(|| ProxyError::Quic("inner endpoint closed".into()))?;
        incoming
            .await
            .map_err(|e| ProxyError::Quic(format!("inner accept failed: {e}")))
    }
}

/// An established inner connection to a peer; holds its endpoint alive.
pub struct PeerConnection {
    pub conn: noq::Connection,
    /// The relay's view of this peer's outer source; the punch reuses its IP
    /// (see [`Listener::reflexive`]).
    pub reflexive: Option<SocketAddr>,
    /// This peer's own relay-allocated public address (its relay candidate).
    pub relay_paddr: SocketAddr,
    /// The outer bind socket (see [`Listener::punch_endpoint`]).
    pub punch_endpoint: quinn::Endpoint,
    /// The combined-transport socket's handle (Stage 3).
    pub mux: PathMuxHandle,
    _endpoint: noq::Endpoint,
}

/// Transport config for inner QUIC that runs *inside* the relay's bind
/// datagrams. Each inner packet is re-encapsulated as one outer QUIC DATAGRAM,
/// so the inner MTU must never exceed what a single outer datagram carries.
/// noq's own path-MTU discovery would probe upward (e.g. to ~1420) and those
/// oversize packets fail `send_datagram`, stalling the connection after the
/// handshake. Pin the inner MTU at the 1200-byte floor and disable discovery so
/// inner packets always fit; a keepalive holds the idle pipe open.
///
/// **Multipath and NAT traversal are enabled** (Stage 3): the connection starts
/// on the relay path and adds a *direct* path that noq validates and migrates
/// to natively — driven by the QUIC-layer NAT-traversal extension
/// (ADD_ADDRESS / REACH_OUT probes), replacing the app-level second-connection
/// race. Candidate exchange at the QUIC layer is invisible to the application,
/// so it works identically for raw-stream and h3/VPN inner protocols.
///
/// The MTU pin applies to every path here, not just the relay one: MTU
/// discovery is a connection-wide setting in noq, and the relay path cannot
/// survive discovery (each inner packet must fit one outer datagram). A direct
/// path therefore also runs at 1200 — correct, if conservative.
fn relay_transport() -> std::sync::Arc<noq::TransportConfig> {
    let mut t = noq::TransportConfig::default();
    t.mtu_discovery_config(None);
    t.initial_mtu(INNER_MTU);
    t.min_mtu(INNER_MTU);
    t.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
    // Allow a relay path + a direct path on one connection (Stage 3).
    t.max_concurrent_multipath_paths(8);
    // Enable n0's NAT-traversal extension (draft-seemann-quic-nat-traversal):
    // the peer may advertise this many candidate addresses to probe.
    t.max_remote_nat_traversal_addresses(MAX_NAT_ADDRESSES);
    // Keep an idle direct path alive so it stays the preferred path and its
    // NAT binding does not lapse while the pipe is quiet (design G3).
    t.default_path_keep_alive_interval(Some(std::time::Duration::from_secs(10)));
    std::sync::Arc::new(t)
}

/// How many candidate addresses each side may advertise to the other.
///
/// The ordinary case needs two or three (reflexive, host, port-mapped), but
/// `--punch-strategy predict` offers a *window* of predicted ports — a couple
/// of dozen — so the cap has to clear that. It is only a ceiling on what the
/// peer may claim; unused slots cost nothing.
pub const MAX_NAT_ADDRESSES: u8 = 32;

/// The pinned inner MTU. Every relay-path packet is re-wrapped as one outer
/// QUIC DATAGRAM, so this must fit inside one — and it is the QUIC floor, the
/// only size guaranteed to fit whatever the outer path turns out to carry.
///
/// It applies to the **direct** path too, which is the cost: a real socket
/// would carry ~1400. Lifting it needs a per-path MTU, and noq 1.2.0 has none
/// — `mtu_discovery_config` is per *connection* and `allow_mtud` is fixed per
/// *endpoint* at construction (from `AsyncUdpSocket::may_fragment`). Raising
/// the shared pin instead is the trap this pin exists for: an inner packet
/// larger than one outer datagram fails `send_datagram`, and the connection
/// stalls *after* a handshake that fit. See `log_mtu_headroom` for what the
/// cost actually is on a given path.
const INNER_MTU: u16 = 1200;

/// Report how much room the pinned inner MTU leaves unused on this session, so
/// the cost of the connection-wide pin is visible rather than theoretical.
/// Purely observational.
fn log_mtu_headroom(outer: &quinn::Connection) {
    let Some(outer_datagram) = outer.max_datagram_size() else {
        tracing::debug!("outer connection carries no datagrams; relay path will not work");
        return;
    };
    // The bind framing (quarter-stream id + context id + address) rides inside
    // the outer datagram with the inner packet.
    let usable = outer_datagram.saturating_sub(BIND_FRAMING_MAX);
    tracing::debug!(
        outer_datagram,
        usable,
        inner_mtu = INNER_MTU,
        "inner MTU is pinned at the QUIC floor; a per-path MTU would let the \
         direct path run larger (noq 1.2.0 has no such API)"
    );
    if usable < INNER_MTU as usize {
        tracing::warn!(
            usable,
            inner_mtu = INNER_MTU,
            "the outer datagram cannot carry a floor-sized inner packet; the \
             relay path may stall once packets reach full size"
        );
    }
}

/// Worst-case bind framing per datagram: quarter-stream id, context id, and an
/// IPv6 address with port, each varint-or-fixed encoded.
const BIND_FRAMING_MAX: usize = 8 + 8 + 1 + 16 + 2;

/// Bind the socket that carries direct paths, in the **same address family as
/// the relay path**.
///
/// This is not a free choice. noq derives a connection's family from the
/// remotes of the paths it already has (`is_ipv6`), and refuses a path whose
/// remote is in the other family — so on a connection whose relay path is
/// IPv4, an IPv6 direct path is rejected before it ever reaches the socket,
/// and vice versa. Matching the relay path is therefore the only binding that
/// can ever carry traffic. (On Linux a `[::]` bind is dual-stack by default,
/// so the IPv6 socket also reaches IPv4-mapped destinations.)
async fn direct_socket(relay_paddr: SocketAddr) -> Result<tokio::net::UdpSocket, ProxyError> {
    let bind: SocketAddr = if relay_paddr.is_ipv6() {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    };
    tokio::net::UdpSocket::bind(bind)
        .await
        .map_err(ProxyError::Io)
}

/// Open a bind session and stand up the inner *server* endpoint over it.
/// `expected_peer` pins the connecting holder's key when known out of band,
/// else `None` accepts it on first use (design §3.2).
pub async fn listen(
    relay: RelayAccess,
    identity: &Identity,
    expected_peer: Option<SpkiPin>,
    // Where to deliver PEER_REFLEXIVE capsules if the relay runs the on-path
    // observer (`--udp-bind-observe`). No punch strategy consumes them since
    // the move to native traversal — the probes no longer pass through the
    // relay for it to observe — so callers pass `None`; the receiving end is
    // kept because the relay-side feature still exists.
    peer_reflexive_sink: Option<std::sync::Arc<std::sync::Mutex<Vec<SocketAddr>>>>,
) -> Result<Listener, ProxyError> {
    let bind = BindClient::connect(relay.addr, &relay.server_name, relay.tls, relay.auth).await?;
    log_mtu_headroom(bind.connection());
    let paddr = bind.public_addr;
    let reflexive = bind.observed_addr;
    let punch_endpoint = bind.endpoint();
    let (server_tls, _verifier) = inner_tls::server_config(identity, expected_peer)?;
    let mut quic = noq::ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(server_tls).map_err(|e| ProxyError::Tls(e.to_string()))?,
    ));
    quic.transport_config(relay_transport());
    let direct = direct_socket(paddr).await?;
    // No relay peer to preset: the dialer's paddr is learned from the packet
    // this endpoint answers.
    let (endpoint, mux) = mux_endpoint(
        bind.into_relay_parts(peer_reflexive_sink),
        direct,
        Some(quic),
        None,
    )
    .map_err(|e| ProxyError::Quic(e.to_string()))?;
    Ok(Listener {
        paddr,
        reflexive,
        punch_endpoint,
        mux,
        endpoint,
    })
}

/// Open a bind session and dial the token's issuer at its `paddr`, pinning
/// the issuer's key to the token's `ppin` (design §4).
pub async fn connect(
    relay: RelayAccess,
    identity: &Identity,
    token: &TokenV2,
    // Where to deliver PEER_REFLEXIVE capsules if the relay runs the on-path
    // observer (`--udp-bind-observe`). No punch strategy consumes them since
    // the move to native traversal — the probes no longer pass through the
    // relay for it to observe — so callers pass `None`; the receiving end is
    // kept because the relay-side feature still exists.
    peer_reflexive_sink: Option<std::sync::Arc<std::sync::Mutex<Vec<SocketAddr>>>>,
) -> Result<PeerConnection, ProxyError> {
    let issuer: SocketAddr = token
        .paddr
        .first()
        .ok_or_else(|| ProxyError::InvalidRequest("token carries no paddr".into()))?
        .parse()
        .map_err(|e| ProxyError::InvalidRequest(format!("token paddr invalid: {e}")))?;

    let bind = BindClient::connect(relay.addr, &relay.server_name, relay.tls, relay.auth).await?;
    log_mtu_headroom(bind.connection());
    let reflexive = bind.observed_addr;
    let relay_paddr = bind.public_addr;
    let punch_endpoint = bind.endpoint();
    let (client_tls, _verifier) = inner_tls::client_config(identity, Some(token.peer_pin()))?;
    let mut quic = noq::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(client_tls).map_err(|e| ProxyError::Tls(e.to_string()))?,
    ));
    quic.transport_config(relay_transport());
    let direct = direct_socket(relay_paddr).await?;
    // The issuer's paddr must be tunnelled from the very first packet.
    let (endpoint, mux) = mux_endpoint(
        bind.into_relay_parts(peer_reflexive_sink),
        direct,
        None,
        Some(issuer),
    )
    .map_err(|e| ProxyError::Quic(e.to_string()))?;
    let conn = endpoint
        .connect_with(quic, issuer, "peer")
        .map_err(|e| ProxyError::Quic(e.to_string()))?
        .await
        .map_err(|e| ProxyError::Quic(format!("inner connect failed: {e}")))?;
    Ok(PeerConnection {
        conn,
        reflexive,
        relay_paddr,
        punch_endpoint,
        mux,
        _endpoint: endpoint,
    })
}
