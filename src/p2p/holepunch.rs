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

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc as StdArc, Mutex};
use std::time::Duration;

use crate::error::ProxyError;
use crate::p2p::candidates::{Sources, gather};
use crate::p2p::identity::{Identity, SpkiPin};
use crate::p2p::peer::RelayAccess;
use crate::p2p::punch::{self, Puncher};
use crate::p2p::strategy::PunchStrategy;
use crate::p2p::wire::{Candidate, CandidateKind, Control};

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
pub async fn coordinate(inputs: PunchInputs<'_>) -> Result<Direct, ProxyError> {
    match inputs.strategy {
        PunchStrategy::Basic => strategy_basic(inputs).await,
        PunchStrategy::Predict => strategy_predict(inputs).await,
        PunchStrategy::Birthday => strategy_birthday(inputs).await,
        PunchStrategy::RelayAssisted => strategy_relay_assisted(inputs).await,
    }
}

/// Everything a punch attempt needs; strategy-specific fields are optional and
/// only read by the strategy that needs them. Built fresh per attempt by the
/// session manager, so re-punches re-read the live inputs.
pub struct PunchInputs<'a> {
    pub inner: &'a quinn::Connection,
    pub initiator: bool,
    pub identity: &'a Identity,
    pub peer_pin: Option<SpkiPin>,
    /// The outer bind socket, reused for the punch (design §5.3, §12).
    pub punch_endpoint: quinn::Endpoint,
    /// The relay-observed reflexive of `punch_endpoint`.
    pub reflexive: Option<SocketAddr>,
    /// The relay's forwarding address (the fallback candidate).
    pub relay: SocketAddr,
    pub strategy: PunchStrategy,
    /// How to reach the relay to open auxiliary bind sessions
    /// (predict/birthday sample the NAT's port allocation with these).
    pub relay_access: Option<StdArc<RelayAccess>>,
    /// Peer-facing sources the on-path relay observed and signalled
    /// (relay-assisted); a growing shared list read each attempt.
    pub peer_reflexive: Option<StdArc<Mutex<Vec<SocketAddr>>>>,
}

/// Reuse the outer bind socket and advertise the relay-observed reflexive —
/// the endpoint-independent (cone) NAT case (design §5.3, §12).
async fn strategy_basic(inputs: PunchInputs<'_>) -> Result<Direct, ProxyError> {
    let PunchInputs {
        inner,
        initiator,
        identity,
        peer_pin,
        punch_endpoint,
        reflexive,
        relay,
        ..
    } = inputs;

    // Punch on the outer socket so its source matches the advertised reflexive;
    // pin the now-known peer key on the accept side.
    punch_endpoint.set_server_config(Some(punch::build_server_config(identity, peer_pin)?));
    let puncher = Puncher::on_endpoint(punch_endpoint.clone(), identity, peer_pin)?;
    let host = host_candidate(&puncher)?;

    let local = gather(&Sources {
        host,
        reflexive,
        relay,
    });
    tracing::debug!(?local, "punch: local candidates");
    let remote = exchange_candidates(inner, &local, initiator).await?;
    tracing::debug!(?remote, "punch: remote candidates");

    let targets = punch_targets(&remote);
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

/// A wildcard-bound socket has no usable host candidate; offer one only when
/// bound to a concrete interface (LAN-adjacent peers).
fn host_candidate(puncher: &Puncher) -> Result<Vec<SocketAddr>, ProxyError> {
    let host = puncher.local_addr()?;
    Ok(if host.ip().is_unspecified() {
        vec![]
    } else {
        vec![host]
    })
}

/// The peer's punchable candidates: every distinct non-relay address. The relay
/// candidate is the fallback path, never a punch target (§5.3).
fn punch_targets(remote: &[Candidate]) -> Vec<SocketAddr> {
    let mut targets: Vec<SocketAddr> = Vec::new();
    for c in remote {
        if c.kind != crate::p2p::wire::CandidateKind::Relay && !targets.contains(&c.addr) {
            targets.push(c.addr);
        }
    }
    targets
}

/// How many back-to-back aux sockets to sample the NAT's allocation with.
const SAMPLE_COUNT: usize = 3;
/// A stride larger than this reads as random, not sequential.
const MAX_STRIDE: i64 = 8;
/// Scan ±this many ports around the predicted peer-facing port.
const PREDICT_SPAN: u16 = 6;

/// A NAT's port-mapping behaviour, inferred from reflexive samples of
/// back-to-back sockets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mapping {
    /// Consecutive allocations move by a constant stride, so the next port is
    /// predictable (stride 0 is a port-overloading NAT that reuses one port).
    Sequential { stride: i64 },
    /// Unpredictable — only the relay can bridge such a NAT.
    Random,
}

/// Classify from the external ports of sockets opened back-to-back: a constant,
/// small inter-sample stride is a sequential allocator; anything else is random.
fn classify(ports: &[u16]) -> Mapping {
    if ports.len() < 2 {
        return Mapping::Random;
    }
    let diffs: Vec<i64> = ports.windows(2).map(|w| w[1] as i64 - w[0] as i64).collect();
    let first = diffs[0];
    if diffs.iter().all(|&d| d == first) && first.abs() <= MAX_STRIDE {
        Mapping::Sequential { stride: first }
    } else {
        Mapping::Random
    }
}

/// The peer-facing ports to advertise: the sequential allocator's next port
/// after `last_port`, plus a small ± scan window for slack (other allocations
/// may nudge the counter between the sample and the punch).
fn predict_range(ip: IpAddr, last_port: u16, stride: i64, span: u16) -> Vec<SocketAddr> {
    let base = last_port as i64 + stride;
    let lo = (base - span as i64).max(1);
    let hi = (base + span as i64).min(u16::MAX as i64);
    (lo..=hi)
        .map(|p| SocketAddr::new(ip, p as u16))
        .collect()
}

/// Sample the NAT by opening `n` bind sessions back-to-back and reading each
/// socket's relay-observed external port.
async fn sample_ports(ra: &RelayAccess, n: usize) -> Result<Vec<u16>, ProxyError> {
    let mut ports = Vec::with_capacity(n);
    for _ in 0..n {
        let bc = crate::client::BindClient::connect(
            ra.addr,
            &ra.server_name,
            ra.tls.clone(),
            ra.auth.clone(),
        )
        .await?;
        if let Some(obs) = bc.observed_addr {
            ports.push(obs.port());
        }
        bc.close().await;
    }
    Ok(ports)
}

/// Classify the NAT via aux-socket sampling and, when it allocates
/// sequentially, advertise a predicted peer-facing port range alongside the
/// reflexive — so a symmetric-but-sequential NAT can still be punched. A
/// random allocator (this netns MASQUERADE) offers no prediction and falls
/// through to the reflexive, i.e. the relay (design §12).
async fn strategy_predict(inputs: PunchInputs<'_>) -> Result<Direct, ProxyError> {
    let PunchInputs {
        inner,
        initiator,
        identity,
        peer_pin,
        punch_endpoint,
        reflexive,
        relay,
        relay_access,
        ..
    } = inputs;

    punch_endpoint.set_server_config(Some(punch::build_server_config(identity, peer_pin)?));
    let puncher = Puncher::on_endpoint(punch_endpoint.clone(), identity, peer_pin)?;
    let host = host_candidate(&puncher)?;

    // Sample the NAT's allocation pattern and predict the peer-facing port.
    let mut predicted: Vec<SocketAddr> = Vec::new();
    if let (Some(ra), Some(refl)) = (relay_access.as_ref(), reflexive) {
        match sample_ports(ra, SAMPLE_COUNT).await {
            Ok(ports) if ports.len() >= 2 => {
                let mapping = classify(&ports);
                tracing::debug!(?mapping, ?ports, "predict: NAT mapping");
                if let Mapping::Sequential { stride } = mapping {
                    let last = *ports.last().unwrap();
                    predicted = predict_range(refl.ip(), last, stride, PREDICT_SPAN);
                }
            }
            Ok(_) => tracing::debug!("predict: too few samples; using reflexive only"),
            Err(e) => tracing::debug!("predict: sampling failed: {e}"),
        }
    }

    let mut local = gather(&Sources {
        host,
        reflexive,
        relay,
    });
    for addr in &predicted {
        local.push(Candidate {
            seq: local.len() as u32,
            addr: *addr,
            kind: CandidateKind::Reflexive,
        });
    }
    tracing::debug!(predicted = predicted.len(), "predict: local candidates");
    let remote = exchange_candidates(inner, &local, initiator).await?;

    let targets = punch_targets(&remote);
    if targets.is_empty() {
        return Err(ProxyError::Quic(
            "peer offered no punchable candidates".into(),
        ));
    }
    let conn = puncher
        .punch(identity.pin(), peer_pin, &targets, PUNCH_TIMEOUT)
        .await?;
    tracing::info!(remote = %conn.remote_address(), "direct path established (predict)");
    Ok(Direct {
        conn,
        _endpoint: puncher.endpoint().clone(),
    })
}

async fn strategy_birthday(inputs: PunchInputs<'_>) -> Result<Direct, ProxyError> {
    tracing::warn!("birthday strategy not yet implemented; using basic");
    strategy_basic(inputs).await
}

async fn strategy_relay_assisted(inputs: PunchInputs<'_>) -> Result<Direct, ProxyError> {
    tracing::warn!("relay-assisted strategy not yet implemented; using basic");
    strategy_basic(inputs).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_reads_sequential_and_random() {
        assert_eq!(classify(&[40000, 40001, 40002]), Mapping::Sequential { stride: 1 });
        assert_eq!(classify(&[40000, 40002, 40004]), Mapping::Sequential { stride: 2 });
        assert_eq!(classify(&[500, 500, 500]), Mapping::Sequential { stride: 0 });
        assert_eq!(classify(&[40000, 51000, 33000]), Mapping::Random);
        // A single sample cannot establish a pattern.
        assert_eq!(classify(&[40000]), Mapping::Random);
        // A large but constant stride is not a useful prediction.
        assert_eq!(classify(&[100, 200, 300]), Mapping::Random);
    }

    #[test]
    fn predict_range_extrapolates_and_clamps() {
        let ip: IpAddr = "192.0.2.6".parse().unwrap();
        let r = predict_range(ip, 40000, 1, 2);
        // next port is 40001, scanned ±2.
        assert_eq!(
            r.iter().map(|a| a.port()).collect::<Vec<_>>(),
            vec![39999, 40000, 40001, 40002, 40003]
        );
        assert!(r.iter().all(|a| a.ip() == ip));
        // Clamps at the u16 ceiling without wrapping.
        let top = predict_range(ip, 65534, 1, 4);
        assert_eq!(top.iter().map(|a| a.port()).max().unwrap(), 65535);
    }
}
