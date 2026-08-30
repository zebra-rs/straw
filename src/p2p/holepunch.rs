//! Hole-punch coordination over the inner relay connection (design §5.2–5.3).
//!
//! With an inner QUIC connection already up through the relay (Phase B), the
//! two peers exchange candidates on a control stream, then perform the
//! coordinated simultaneous open ([`crate::p2p::punch`]) toward each other's
//! candidates. A success is an authenticated *direct* connection that
//! bypasses the relay; a failure leaves the relay path in place (design §6
//! fallback).
//!
//! v1 uses candidate-exchange completion as the "punch now" sync point rather
//! than an explicit PUNCH round message: the exchange is symmetric, so both
//! peers finish it within a few milliseconds and start punching together.
//! The draft's round/PUNCH_ME_NOW coordination (`Control::Punch`) and the
//! backoff schedule (§6) are refinements for tuning real-NAT timing.

use std::net::SocketAddr;
use std::time::Duration;

use crate::error::ProxyError;
use crate::p2p::candidates::{Sources, gather};
use crate::p2p::identity::{Identity, SpkiPin};
use crate::p2p::punch::Puncher;
use crate::p2p::wire::{Candidate, Control};

/// Total time to spend punching before falling back to the relay.
const PUNCH_TIMEOUT: Duration = Duration::from_secs(5);

/// A direct connection won by punching; holds its endpoint alive.
pub struct Direct {
    pub conn: quinn::Connection,
    _endpoint: quinn::Endpoint,
}

/// Exchange candidates with the peer over a fresh control stream on the
/// inner connection. The `initiator` opens the stream, the other accepts it.
pub async fn exchange_candidates(
    inner: &quinn::Connection,
    local: &[Candidate],
    initiator: bool,
) -> Result<Vec<Candidate>, ProxyError> {
    let (mut send, mut recv) = if initiator {
        inner
            .open_bi()
            .await
            .map_err(|e| ProxyError::Quic(e.to_string()))?
    } else {
        inner
            .accept_bi()
            .await
            .map_err(|e| ProxyError::Quic(e.to_string()))?
    };

    for c in local {
        send.write_all(&Control::Candidate(*c).encode())
            .await
            .map_err(|e| ProxyError::Quic(e.to_string()))?;
    }
    send.finish().map_err(|e| ProxyError::Quic(e.to_string()))?;

    let buf = recv
        .read_to_end(64 * 1024)
        .await
        .map_err(|e| ProxyError::Quic(e.to_string()))?;
    let mut off = 0;
    let mut remote = Vec::new();
    while let Some((msg, n)) = Control::decode(&buf[off..])
        .map_err(|_| ProxyError::InvalidRequest("malformed candidate".into()))?
    {
        if let Control::Candidate(c) = msg {
            remote.push(c);
        }
        off += n;
    }
    Ok(remote)
}

/// Run the whole punch: gather candidates (host from a fresh punch socket,
/// plus the reflexive and relay addresses in `sources`), exchange them over
/// `inner`, then simultaneously open toward the peer's candidates. Returns a
/// direct connection, or an error to fall back to the relay path.
///
/// `initiator` must differ between the two peers (the inner client is the
/// initiator; the inner server is not) so exactly one opens the control
/// stream.
pub async fn coordinate(
    inner: &quinn::Connection,
    initiator: bool,
    identity: &Identity,
    peer_pin: Option<SpkiPin>,
    bind_addr: SocketAddr,
    reflexive: Option<SocketAddr>,
    relay: SocketAddr,
) -> Result<Direct, ProxyError> {
    // Bind the punch socket to a concrete address, not the wildcard, so its
    // local address is a usable host candidate. Production callers pass an
    // interface IP (loopback in tests); the reflexive candidate covers the
    // NAT case.
    let puncher = Puncher::new(bind_addr, identity, peer_pin)?;
    let host = puncher.local_addr()?;

    // A wildcard bind (0.0.0.0) yields no usable host candidate. Offer a host
    // candidate only when bound to a concrete interface (LAN-adjacent peers).
    let host_cands = if host.ip().is_unspecified() {
        vec![]
    } else {
        vec![host]
    };
    // Predict the punch socket's *own* server-reflexive address. The relay's
    // OBSERVED_ADDRESS reports the outer connection's mapping; a fresh punch
    // socket gets a different one, but under a port-preserving NAT (Linux
    // default) the public port equals the socket's local port, so the punch
    // reflexive is (observed public IP, punch local port). This is what makes
    // the simultaneous open reach the peer through the NAT.
    let punch_reflexive = reflexive.map(|obs| SocketAddr::new(obs.ip(), host.port()));

    let local = gather(&Sources {
        host: host_cands,
        reflexive: punch_reflexive,
        relay,
    });
    tracing::debug!(?local, "punch: local candidates");
    let remote = exchange_candidates(inner, &local, initiator).await?;
    tracing::debug!(?remote, "punch: remote candidates");

    // Punch every distinct host/reflexive candidate. The relay candidate is
    // the fallback path (its address is the relay's forwarding socket, not a
    // direct inner-QUIC endpoint), so it is never a punch target (§5.3).
    let mut targets: Vec<SocketAddr> = Vec::new();
    for c in &remote {
        if c.kind != crate::p2p::wire::CandidateKind::Relay && !targets.contains(&c.addr) {
            targets.push(c.addr);
        }
    }
    tracing::debug!(?targets, "punch: dialing");
    if targets.is_empty() {
        return Err(ProxyError::Quic(
            "peer offered no punchable candidates".into(),
        ));
    }

    let conn = puncher
        .punch(identity.pin(), peer_pin, &targets, PUNCH_TIMEOUT)
        .await?;
    tracing::info!(remote = %conn.remote_address(), "direct path established");
    Ok(Direct {
        conn,
        _endpoint: puncher.endpoint().clone(),
    })
}
