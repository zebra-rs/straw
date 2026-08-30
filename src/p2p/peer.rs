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

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};

use crate::client::{BindClient, ClientAuth, TlsMode};
use crate::error::ProxyError;
use crate::p2p::identity::{Identity, SpkiPin};
use crate::p2p::inner_tls;
use crate::p2p::relay_socket::inner_endpoint;
use crate::p2p::token::TokenV2;

/// How to reach and authenticate to the relay (the outer connection).
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
    /// The relay's view of this peer's outer source (its reflexive candidate).
    pub reflexive: Option<SocketAddr>,
    /// The outer bind socket, reused for the hole punch (design §5.3, §12).
    pub punch_endpoint: quinn::Endpoint,
    endpoint: quinn::Endpoint,
}

impl Listener {
    /// Accept the next inner connection (already mutually pin-verified).
    pub async fn accept(&self) -> Result<quinn::Connection, ProxyError> {
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
    pub conn: quinn::Connection,
    /// This peer's reflexive candidate (the relay's view of its outer source).
    pub reflexive: Option<SocketAddr>,
    /// This peer's own relay-allocated public address (its relay candidate).
    pub relay_paddr: SocketAddr,
    /// The outer bind socket, reused for the hole punch (design §5.3, §12).
    pub punch_endpoint: quinn::Endpoint,
    _endpoint: quinn::Endpoint,
}

/// Transport config for inner QUIC that runs *inside* the relay's bind
/// datagrams. Each inner packet is re-encapsulated as one outer QUIC DATAGRAM,
/// so the inner MTU must never exceed what a single outer datagram carries.
/// quinn's own path-MTU discovery would probe upward (e.g. to ~1420) and those
/// oversize packets fail `send_datagram`, stalling the connection after the
/// handshake. Pin the inner MTU at quinn's 1200-byte floor and disable
/// discovery so inner packets always fit; a keepalive holds the idle pipe open.
fn relay_transport() -> std::sync::Arc<quinn::TransportConfig> {
    let mut t = quinn::TransportConfig::default();
    t.mtu_discovery_config(None);
    t.initial_mtu(1200);
    t.min_mtu(1200);
    t.keep_alive_interval(Some(std::time::Duration::from_secs(10)));
    std::sync::Arc::new(t)
}

/// Open a bind session and stand up the inner *server* endpoint over it.
/// `expected_peer` pins the connecting holder's key when known out of band,
/// else `None` accepts it on first use (design §3.2).
pub async fn listen(
    relay: RelayAccess,
    identity: &Identity,
    expected_peer: Option<SpkiPin>,
) -> Result<Listener, ProxyError> {
    let bind = BindClient::connect(relay.addr, &relay.server_name, relay.tls, relay.auth).await?;
    let paddr = bind.public_addr;
    let reflexive = bind.observed_addr;
    let punch_endpoint = bind.endpoint();
    let (server_tls, _verifier) = inner_tls::server_config(identity, expected_peer)?;
    let mut quic = quinn::ServerConfig::with_crypto(Arc::new(
        QuicServerConfig::try_from(server_tls).map_err(|e| ProxyError::Tls(e.to_string()))?,
    ));
    quic.transport_config(relay_transport());
    let endpoint = inner_endpoint(bind.into_relay_socket(), Some(quic))
        .map_err(|e| ProxyError::Quic(e.to_string()))?;
    Ok(Listener {
        paddr,
        reflexive,
        punch_endpoint,
        endpoint,
    })
}

/// Open a bind session and dial the token's issuer at its `paddr`, pinning
/// the issuer's key to the token's `ppin` (design §4).
pub async fn connect(
    relay: RelayAccess,
    identity: &Identity,
    token: &TokenV2,
) -> Result<PeerConnection, ProxyError> {
    let issuer: SocketAddr = token
        .paddr
        .first()
        .ok_or_else(|| ProxyError::InvalidRequest("token carries no paddr".into()))?
        .parse()
        .map_err(|e| ProxyError::InvalidRequest(format!("token paddr invalid: {e}")))?;

    let bind = BindClient::connect(relay.addr, &relay.server_name, relay.tls, relay.auth).await?;
    let reflexive = bind.observed_addr;
    let relay_paddr = bind.public_addr;
    let punch_endpoint = bind.endpoint();
    let (client_tls, _verifier) = inner_tls::client_config(identity, Some(token.peer_pin()))?;
    let mut quic = quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(client_tls).map_err(|e| ProxyError::Tls(e.to_string()))?,
    ));
    quic.transport_config(relay_transport());
    let endpoint = inner_endpoint(bind.into_relay_socket(), None)
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
        _endpoint: endpoint,
    })
}
