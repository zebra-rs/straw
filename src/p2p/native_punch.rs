//! The native-multipath punch (design §0 Stage 3): upgrade the single inner
//! noq connection from the relay path to a **direct** path, in-protocol, via
//! `Connection::open_path` over the combined-transport socket
//! ([`PathMuxSocket`](crate::p2p::relay_socket::PathMuxSocket)) — replacing the
//! app-level second-connection race of the v1 design (§5.3).
//!
//! Flow: gather this peer's direct-socket candidate, exchange candidates with
//! the peer over the inner connection, register the peer's candidates on the
//! mux (so sends there go out the real socket), then:
//!
//! - the inner-QUIC **client** opens a path to each peer candidate (only the
//!   client may `open_path`; the server gets `ServerSideNotAllowed`);
//! - the **server** just registers and waits — QUIC answers the client's
//!   PATH_CHALLENGE out the real socket automatically.
//!
//! Both sides watch `path_events()` for an `Established` event on a non-zero
//! path id — noq has validated the direct path and migrates to it.
//!
//! **Status / caveat.** This app-level candidate exchange (a dedicated bidi
//! stream) works for raw-stream apps (pipe mode) but would collide with h3 in
//! VPN mode — h3 would see the exchange stream as a request. The correct, mode-
//! agnostic mechanism is noq's own NAT-traversal *frames*
//! (`Connection::add_nat_traversal_address` on the server +
//! `initiate_nat_traversal_round` on the client, enabled by
//! `TransportConfig::max_remote_nat_traversal_addresses`): control traffic at
//! the QUIC layer, invisible to the app. The proven building block —
//! `open_path` validating over the combined socket — is shared by both; the
//! session wiring will move to the frame-based exchange.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use futures::StreamExt;
use noq::{FourTuple, PathEvent, PathId, PathStatus};
use crate::error::ProxyError;
use crate::p2p::relay_socket::PathMuxHandle;
use crate::p2p::wire::{Candidate, CandidateKind, Control};

/// noq needs a spare remote connection ID per path, issued shortly after the
/// handshake; opening a path before then fails `RemoteCidsExhausted`.
const CID_SETTLE: Duration = Duration::from_millis(300);

/// Run the punch on an established inner connection. `client` is true for the
/// inner-QUIC client (the token holder / connector). `reflexive_ip` is this
/// peer's public IP as the relay observed it (from the bind session's
/// OBSERVED_ADDRESS); the direct socket's reflexive candidate is that IP with
/// the direct socket's port — exact for a port-preserving (NETMAP / full-cone)
/// NAT and for same-host tests. Returns the established direct [`PathId`].
pub async fn punch(
    conn: &noq::Connection,
    mux: &PathMuxHandle,
    client: bool,
    reflexive_ip: Option<IpAddr>,
    timeout: Duration,
) -> Result<PathId, ProxyError> {
    // 1. This peer's direct-socket candidate. On a port-preserving NAT the
    //    reflexive is (observed public IP, direct port); on loopback the
    //    observed IP is the loopback address, so this degenerates to the host
    //    candidate. (A PAT cone NAT would need STUN on the direct socket to
    //    learn the translated port — a follow-on.)
    let direct_port = mux.direct_local().port();
    let mut local = Vec::new();
    if let Some(ip) = reflexive_ip {
        local.push(Candidate {
            seq: 0,
            addr: SocketAddr::new(ip, direct_port),
            kind: CandidateKind::Reflexive,
        });
    }

    // 2. Exchange candidates over the inner connection (a dedicated control
    //    stream, opened before the application opens its streams).
    let remote = exchange(conn, &local, client).await?;
    if remote.is_empty() {
        return Err(ProxyError::Quic("peer sent no punch candidates".into()));
    }

    // 3. Route sends to the peer's candidates out the real socket.
    for c in &remote {
        mux.register_direct_remote(c.addr);
    }

    // 4. Watch for an established direct path (both roles).
    let mut events = conn.path_events();

    // 5. The client drives path opening; the server only responds.
    if client {
        tokio::time::sleep(CID_SETTLE).await;
        for c in &remote {
            let conn = conn.clone();
            let addr = c.addr;
            tokio::spawn(async move {
                if let Err(e) = conn
                    .open_path_ensure(FourTuple::from_remote(addr), PathStatus::Available)
                    .await
                {
                    tracing::debug!(%addr, "open_path failed: {e:?}");
                }
            });
        }
    }

    // 6. First non-relay path to establish wins.
    let wait = async {
        while let Some(ev) = events.next().await {
            if let Ok(PathEvent::Established { id, .. }) = ev
                && id != PathId::ZERO
            {
                return Some(id);
            }
        }
        None
    };
    match tokio::time::timeout(timeout, wait).await {
        Ok(Some(id)) => {
            tracing::info!(?id, "direct path established (native multipath)");
            Ok(id)
        }
        Ok(None) => Err(ProxyError::Quic("path event stream ended".into())),
        Err(_) => Err(ProxyError::Quic("hole punch timed out".into())),
    }
}

/// Exchange candidate lists on a dedicated bidirectional stream: the client
/// opens it, the server accepts it; each side writes its length-delimited
/// `Control::Candidate` messages, finishes, and reads the peer's.
async fn exchange(
    conn: &noq::Connection,
    local: &[Candidate],
    client: bool,
) -> Result<Vec<Candidate>, ProxyError> {
    let (mut send, mut recv) = if client {
        conn.open_bi().await.map_err(|e| ProxyError::Quic(e.to_string()))?
    } else {
        conn.accept_bi().await.map_err(|e| ProxyError::Quic(e.to_string()))?
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
