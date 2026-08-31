//! Predicting a symmetric NAT's peer-facing port (design §12, `--punch-strategy
//! predict`).
//!
//! A symmetric NAT gives a socket a *different* external port per destination,
//! so the reflexive address the relay observed is not the address the peer's
//! packets will arrive from, and the ordinary punch fails. But some symmetric
//! NATs allocate those ports *sequentially*. For those, the peer-facing port is
//! predictable: sample a few allocations, measure the stride, and offer the
//! next port — plus a small window, since other traffic may nudge the counter
//! between the sample and the punch.
//!
//! This survived the move to QUIC-native NAT traversal because a prediction is
//! a claim about **this peer's own address**, which is exactly what the
//! ADD_ADDRESS / REACH_OUT frames carry. (The other two symmetric strategies
//! did not: `birthday` needs several sockets, and `relay-assisted` needs the
//! relay to see the probes, which now go direct.)
//!
//! It remains best-effort. A random allocator — including the netns
//! MASQUERADE the harness uses — offers nothing to predict, and the session
//! falls back to the relay.

use std::net::{IpAddr, SocketAddr};

use crate::client::BindClient;
use crate::error::ProxyError;
use crate::p2p::peer::RelayAccess;

/// How many back-to-back aux sockets to sample the NAT's allocation with.
pub const SAMPLE_COUNT: usize = 3;
/// A stride larger than this reads as random, not sequential.
const MAX_STRIDE: i64 = 8;
/// Offer ±this many ports around the predicted one.
pub const PREDICT_SPAN: u16 = 6;

/// A NAT's port-mapping behaviour, inferred from reflexive samples of
/// back-to-back sockets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mapping {
    /// Consecutive allocations move by a constant stride, so the next port is
    /// predictable (stride 0 is a port-overloading NAT that reuses one port).
    Sequential { stride: i64 },
    /// Unpredictable — only the relay can bridge such a NAT.
    Random,
}

/// Classify from the external ports of sockets opened back-to-back: a constant,
/// small inter-sample stride is a sequential allocator; anything else is random.
pub fn classify(ports: &[u16]) -> Mapping {
    if ports.len() < 2 {
        return Mapping::Random;
    }
    let diffs: Vec<i64> = ports
        .windows(2)
        .map(|w| w[1] as i64 - w[0] as i64)
        .collect();
    let first = diffs[0];
    if diffs.iter().all(|&d| d == first) && first.abs() <= MAX_STRIDE {
        Mapping::Sequential { stride: first }
    } else {
        Mapping::Random
    }
}

/// The peer-facing addresses to advertise: the sequential allocator's next port
/// after `last_port`, plus a ± window for slack.
pub fn predict_range(ip: IpAddr, last_port: u16, stride: i64, span: u16) -> Vec<SocketAddr> {
    let base = last_port as i64 + stride;
    let lo = (base - span as i64).max(1);
    let hi = (base + span as i64).min(u16::MAX as i64);
    (lo..=hi).map(|p| SocketAddr::new(ip, p as u16)).collect()
}

/// Sample the NAT by opening `n` bind sessions back-to-back and reading each
/// socket's relay-observed external address. The addresses carry the peer's
/// public IP as well as the ports, so no extra lookup is needed afterwards.
pub async fn sample(relay: &RelayAccess, n: usize) -> Result<Vec<SocketAddr>, ProxyError> {
    let mut seen = Vec::with_capacity(n);
    for _ in 0..n {
        let bind = BindClient::connect(
            relay.addr,
            &relay.server_name,
            relay.tls.clone(),
            relay.auth.clone(),
        )
        .await?;
        if let Some(observed) = bind.observed_addr {
            seen.push(observed);
        }
        bind.close().await;
    }
    Ok(seen)
}

/// Sample this peer's NAT and, if it allocates sequentially, return the
/// predicted peer-facing addresses to advertise alongside the ordinary
/// candidates. A random allocator returns nothing — that is the case the relay
/// carries, and saying so plainly is more useful than a futile scan.
pub async fn predicted_candidates(relay: &RelayAccess) -> Vec<SocketAddr> {
    let samples = match sample(relay, SAMPLE_COUNT).await {
        Ok(samples) => samples,
        Err(e) => {
            tracing::warn!("could not sample the NAT for prediction: {e}");
            return Vec::new();
        }
    };
    let ports: Vec<u16> = samples.iter().map(|a| a.port()).collect();
    let Some(last) = samples.last().copied() else {
        return Vec::new();
    };
    let Mapping::Sequential { stride } = classify(&ports) else {
        tracing::info!(
            ?ports,
            "NAT allocates unpredictably; no port prediction (the relay carries this case)"
        );
        return Vec::new();
    };
    let predicted = predict_range(last.ip(), last.port(), stride, PREDICT_SPAN);
    tracing::info!(
        stride,
        last = %last,
        count = predicted.len(),
        "NAT allocates sequentially; advertising a predicted peer-facing range"
    );
    predicted
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip() -> IpAddr {
        "203.0.113.7".parse().unwrap()
    }

    #[test]
    fn a_constant_small_stride_reads_as_sequential() {
        assert_eq!(
            classify(&[100, 101, 102]),
            Mapping::Sequential { stride: 1 }
        );
        assert_eq!(
            classify(&[500, 502, 504]),
            Mapping::Sequential { stride: 2 }
        );
        // A port-overloading NAT reuses one port: stride 0, still predictable.
        assert_eq!(
            classify(&[700, 700, 700]),
            Mapping::Sequential { stride: 0 }
        );
        // Descending allocators exist too.
        assert_eq!(
            classify(&[900, 899, 898]),
            Mapping::Sequential { stride: -1 }
        );
    }

    #[test]
    fn anything_irregular_or_far_apart_reads_as_random() {
        // Irregular gaps.
        assert_eq!(classify(&[100, 101, 105]), Mapping::Random);
        // Constant but too large a stride to be a counter we can follow.
        assert_eq!(classify(&[100, 200, 300]), Mapping::Random);
        // Not enough samples to say anything.
        assert_eq!(classify(&[100]), Mapping::Random);
        assert_eq!(classify(&[]), Mapping::Random);
    }

    #[test]
    fn the_predicted_window_is_centred_on_the_next_port() {
        let out = predict_range(ip(), 1000, 2, 2);
        let ports: Vec<u16> = out.iter().map(|a| a.port()).collect();
        // Next port is 1002; the window is ±2 around it.
        assert_eq!(ports, vec![1000, 1001, 1002, 1003, 1004]);
        assert!(out.iter().all(|a| a.ip() == ip()));
    }

    #[test]
    fn the_window_stays_inside_the_port_range() {
        // Near zero: never predicts port 0, which is not a real destination.
        let low = predict_range(ip(), 2, -1, 6);
        assert_eq!(low.first().unwrap().port(), 1);
        // Near the top: never wraps past 65535.
        let high = predict_range(ip(), u16::MAX - 1, 1, 6);
        assert_eq!(high.last().unwrap().port(), u16::MAX);
    }
}
