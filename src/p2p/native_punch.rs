//! The native-multipath punch (design §0 Stage 3): upgrade the single inner
//! noq connection from the relay path to a **direct** path, in-protocol —
//! replacing the app-level second-connection race of the v1 design (§5.3).
//!
//! Candidates are exchanged by noq's own NAT-traversal frames
//! (draft-seemann-quic-nat-traversal, enabled by
//! `TransportConfig::max_remote_nat_traversal_addresses`), not by an
//! application message. That matters beyond tidiness: an app-level exchange
//! needs a stream, and in VPN mode the inner protocol is h3, which would read
//! that stream as a request. At the QUIC layer the exchange is invisible to
//! the application, so one punch driver serves both inner protocols.
//!
//! Roles follow the draft's asymmetry:
//!
//! - the inner **server** advertises its candidates in ADD_ADDRESS frames
//!   ([`advertise`]), and answers probes;
//! - the inner **client** learns them, advertises its own in REACH_OUT frames
//!   and probes the server's ([`Connection::initiate_nat_traversal_round`]).
//!   On a probe response noq opens the validated path itself.
//!
//! Both sides then see `PathEvent::Established` for a non-zero path id — noq
//! has validated a direct path. Promotion to the *preferred* path is the
//! caller's job ([`crate::p2p::session`]): a traversal-opened path arrives with
//! `PathStatus::Backup`, so until it is marked available the relay path (0,
//! `Available` by default) keeps carrying the data.
//!
//! Both roles' probes leave over the real UDP socket without any registration
//! step, because [`PathMuxSocket`] sends direct by default and tunnels only
//! addresses known to be relay-side.
//!
//! [`PathMuxSocket`]: crate::p2p::relay_socket::PathMuxSocket

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use futures::StreamExt;
use noq::{PathEvent, PathId};

use crate::error::ProxyError;
use crate::p2p::relay_socket::PathMuxHandle;

/// How long to wait for the peer's ADD_ADDRESS before initiating a round. The
/// server advertises as soon as it has the connection, so this only covers the
/// flight; giving up early would waste the whole punch window.
const ADDRESS_WAIT: Duration = Duration::from_secs(3);

/// A round's probes are retried with backoff for ~4s (noq's
/// `MAX_NAT_PROBE_ATTEMPTS`); re-initiate at a slightly longer interval so a
/// new round never cancels probes that are still live.
const ROUND_INTERVAL: Duration = Duration::from_secs(5);

/// This peer's direct-path candidates, in the order they are advertised.
///
/// `reflexive_ip` is the peer's public IP as the relay observed it on the outer
/// bind session; paired with the *direct* socket's port it is the address a
/// port-preserving (full-cone / NETMAP / explicitly forwarded) NAT presents to
/// the other peer. `mapped` is an address a PCP/NAT-PMP forward made reachable
/// (`--port-map`), which holds even on a symmetric NAT.
pub fn candidates(
    mux: &PathMuxHandle,
    reflexive_ip: Option<IpAddr>,
    mapped: Option<SocketAddr>,
) -> Vec<SocketAddr> {
    let port = mux.direct_local().port();
    let mut out = Vec::new();
    // The explicit forward first: it is the one that survives a symmetric NAT.
    if let Some(m) = mapped {
        out.push(m);
    }
    if let Some(ip) = reflexive_ip {
        let reflexive = SocketAddr::new(ip, port);
        if !out.contains(&reflexive) {
            out.push(reflexive);
        }
    }
    out
}

/// Offer `addrs` to the peer as addresses this endpoint may be reached at.
///
/// On the inner server these go out as ADD_ADDRESS frames immediately; on the
/// inner client they are held until a round is initiated, then sent as
/// REACH_OUT. Both sides call this — the draft's exchange is symmetric in
/// content, asymmetric only in framing.
pub fn advertise(conn: &noq::Connection, addrs: &[SocketAddr]) -> Result<(), ProxyError> {
    for &addr in addrs {
        conn.add_nat_traversal_address(addr)
            .map_err(|e| ProxyError::Quic(format!("advertising {addr}: {e}")))?;
    }
    Ok(())
}

/// Run the punch to completion on an established inner connection, returning
/// the direct [`PathId`] noq validated.
///
/// `client` is true for the inner-QUIC client (the token holder / connector),
/// which is the side that initiates traversal rounds; the server only answers.
/// The caller must have called [`advertise`] with this peer's candidates first.
pub async fn punch(
    conn: &noq::Connection,
    client: bool,
    timeout: Duration,
) -> Result<PathId, ProxyError> {
    // Subscribe before anything can fire: path events are a broadcast stream,
    // and an Established we are not yet listening for is simply lost.
    let mut events = conn.path_events();

    let established = async {
        while let Some(ev) = events.next().await {
            match ev {
                Ok(PathEvent::Established { id, .. }) if id != PathId::ZERO => return Ok(id),
                // A lagged broadcast may have dropped an Established. The path
                // is still there, so keep watching rather than failing: a later
                // event, or the timeout, decides.
                Err(lag) => tracing::debug!(%lag, "path events lagged during the punch"),
                _ => {}
            }
        }
        Err(ProxyError::Quic("path event stream ended".into()))
    };

    // The round driver runs *inside* this future rather than as a spawned
    // task, so it stops probing the moment the punch ends — whether it
    // succeeded or timed out. It never resolves, so only the event watch or
    // the timeout can end the punch.
    let driver = async {
        if client {
            tokio::select! {
                outcome = established => outcome,
                _ = drive_rounds(conn.clone()) => unreachable!("the round driver never resolves"),
            }
        } else {
            established.await
        }
    };

    match tokio::time::timeout(timeout, driver).await {
        Ok(Ok(id)) => {
            tracing::info!(?id, "direct path established (native NAT traversal)");
            Ok(id)
        }
        Ok(Err(e)) => Err(e),
        Err(_) => Err(ProxyError::Quic("hole punch timed out".into())),
    }
}

/// Client side: initiate a traversal round as soon as the server has advertised
/// an address, then keep re-initiating until the punch ends and drops this
/// future. Retrying matters on a NAT whose binding only opens once *both* sides
/// have sent outward.
///
/// Never resolves. When there is nothing left to drive it goes pending rather
/// than returning, because it is raced against the path-event watch: finishing
/// would cancel the watch and lose an `Established` that an earlier round had
/// already set in motion.
async fn drive_rounds(conn: noq::Connection) {
    if wait_for_peer_address(&conn).await {
        loop {
            match conn.initiate_nat_traversal_round() {
                Ok(probed) => tracing::debug!(?probed, "NAT traversal round initiated"),
                // NotEnoughAddresses (no candidate of our own) or a closed
                // connection: another round will not help.
                Err(e) => {
                    tracing::debug!("NAT traversal round refused: {e}");
                    break;
                }
            }
            tokio::time::sleep(ROUND_INTERVAL).await;
        }
    } else {
        tracing::debug!("peer advertised no NAT-traversal candidates; staying on the relay");
    }
    std::future::pending::<()>().await
}

/// Wait until the server's ADD_ADDRESS has landed. Returns whether there is at
/// least one remote candidate to probe.
///
/// The update stream carries an ADD_ADDRESS / REMOVE_ADDRESS enum that noq does
/// not re-export from its root, so each update is a signal to re-read the
/// authoritative set rather than something to match on. That also absorbs a
/// removal following an addition.
async fn wait_for_peer_address(conn: &noq::Connection) -> bool {
    let mut updates = conn.nat_traversal_updates();
    let known = |conn: &noq::Connection| {
        conn.get_remote_nat_traversal_addresses()
            .is_ok_and(|a| !a.is_empty())
    };
    // Subscribing races the frame: check what is already known first.
    if known(conn) {
        return true;
    }
    let first = async {
        while updates.next().await.is_some() {
            if known(conn) {
                tracing::debug!("peer advertised a NAT-traversal candidate");
                return true;
            }
        }
        false
    };
    tokio::time::timeout(ADDRESS_WAIT, first)
        .await
        .unwrap_or(false)
}
