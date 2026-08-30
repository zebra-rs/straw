//! Provisional wire formats for hole punching (design §5.2, §9).
//!
//! Candidates and punch coordination travel on the inner connection's
//! control stream 0 as CBOR, private to the two peers — the relay never sees
//! them. This is the v1 stand-in for the draft-seemann-quic-nat-traversal
//! frames, kept 1:1 with the draft's semantics (inner *server* offers
//! addresses, inner *client* pairs them and drives rounds, a higher round
//! cancels outstanding probes) so the v2 swap to real QUIC frames is
//! mechanical once quinn exposes an extension-frame API.
//!
//! Everything provisional lives here behind one module, per §9.

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

/// The kind of a candidate, in ICE-style priority order (host > reflexive >
/// relay): a lower discriminant is preferred (design §5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CandidateKind {
    /// A local interface address (LAN-adjacent peers). Leaks LAN topology,
    /// so gated behind `--direct=full` (design §10.3).
    Host,
    /// The peer's outer source as seen by the relay (from OBSERVED_ADDRESS).
    Reflexive,
    /// The relay-allocated `paddr` — always present, already validated.
    Relay,
}

impl CandidateKind {
    /// ICE-style priority; higher is more preferred.
    pub fn priority(self) -> u32 {
        match self {
            Self::Host => 126,
            Self::Reflexive => 100,
            Self::Relay => 0,
        }
    }
}

/// One transport-address candidate a peer offers (design §5.1). `seq` is the
/// offering peer's own numbering, referenced by [`Punch`] pairs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Candidate {
    #[serde(rename = "s")]
    pub seq: u32,
    #[serde(rename = "a")]
    pub addr: SocketAddr,
    #[serde(rename = "k")]
    pub kind: CandidateKind,
}

/// A control message on inner stream 0 (design §5.2). A tagged CBOR enum so
/// the three message types share one framed stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Control {
    /// Offer a candidate (mirrors the draft's ADD_ADDRESS).
    #[serde(rename = "cand")]
    Candidate(Candidate),
    /// Ask to punch these `(local_seq, remote_seq)` pairs this `round`
    /// (mirrors PUNCH_ME_NOW). A higher round cancels lower ones.
    #[serde(rename = "punch")]
    Punch { round: u32, pairs: Vec<(u32, u32)> },
    /// Retire a previously offered candidate (mirrors REMOVE_ADDRESS).
    #[serde(rename = "retire")]
    Retire { seq: u32 },
}

impl Control {
    /// CBOR-encode, length-delimited (a 2-byte big-endian length prefix), so
    /// messages frame cleanly on the control stream.
    pub fn encode(&self) -> Vec<u8> {
        let mut body = Vec::new();
        ciborium::into_writer(self, &mut body).expect("Control serializes");
        let mut out = Vec::with_capacity(2 + body.len());
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(&body);
        out
    }

    /// Decode one length-delimited message from the front of `buf`, returning
    /// it and the number of bytes consumed, or `None` if `buf` does not yet
    /// hold a whole message.
    pub fn decode(buf: &[u8]) -> Result<Option<(Control, usize)>, WireError> {
        if buf.len() < 2 {
            return Ok(None);
        }
        let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
        if buf.len() < 2 + len {
            return Ok(None);
        }
        let msg = ciborium::from_reader(&buf[2..2 + len]).map_err(|_| WireError::BadCbor)?;
        Ok(Some((msg, 2 + len)))
    }
}

/// Errors decoding a control message.
#[derive(Debug, PartialEq, Eq)]
pub enum WireError {
    BadCbor,
}

/// Concurrency cap on candidate pairs probed per round (design §5.2/§10.2).
pub const MAX_PAIRS_PER_ROUND: usize = 4;

/// Pair the client's own candidates with the server's offered ones, most
/// promising first (higher summed priority), capped at
/// [`MAX_PAIRS_PER_ROUND`] — the inner *client*'s job (design §5.2). Returns
/// `(local_seq, remote_seq)` pairs and the addresses to probe.
pub fn pair_candidates(local: &[Candidate], remote: &[Candidate]) -> Vec<(u32, u32, SocketAddr)> {
    let mut pairs: Vec<(u32, u32, SocketAddr, u32)> = Vec::new();
    for l in local {
        for r in remote {
            // Only pair same-family candidates: a v4 socket cannot reach a
            // v6 remote.
            if l.addr.is_ipv4() != r.addr.is_ipv4() {
                continue;
            }
            let score = l.kind.priority() + r.kind.priority();
            pairs.push((l.seq, r.seq, r.addr, score));
        }
    }
    pairs.sort_by(|a, b| b.3.cmp(&a.3));
    pairs.truncate(MAX_PAIRS_PER_ROUND);
    pairs.into_iter().map(|(l, r, a, _)| (l, r, a)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cand(seq: u32, addr: &str, kind: CandidateKind) -> Candidate {
        Candidate {
            seq,
            addr: addr.parse().unwrap(),
            kind,
        }
    }

    #[test]
    fn control_messages_round_trip_length_delimited() {
        let msgs = [
            Control::Candidate(cand(1, "203.0.113.7:41000", CandidateKind::Reflexive)),
            Control::Punch {
                round: 2,
                pairs: vec![(1, 3), (2, 4)],
            },
            Control::Retire { seq: 5 },
        ];
        // Concatenate on a stream, decode back in order.
        let mut stream = Vec::new();
        for m in &msgs {
            stream.extend_from_slice(&m.encode());
        }
        let mut off = 0;
        let mut got = Vec::new();
        while let Some((m, n)) = Control::decode(&stream[off..]).unwrap() {
            got.push(m);
            off += n;
        }
        assert_eq!(got, msgs);
        assert_eq!(off, stream.len());
    }

    #[test]
    fn decode_waits_for_a_whole_message() {
        let wire = Control::Retire { seq: 9 }.encode();
        // A partial buffer yields None, not an error.
        assert_eq!(Control::decode(&wire[..1]).unwrap(), None);
        assert_eq!(Control::decode(&wire[..wire.len() - 1]).unwrap(), None);
        assert!(Control::decode(&wire).unwrap().is_some());
    }

    #[test]
    fn garbage_body_is_an_error_not_a_panic() {
        let mut wire = vec![0x00, 0x03];
        wire.extend_from_slice(&[0xff, 0xff, 0xff]);
        assert_eq!(Control::decode(&wire), Err(WireError::BadCbor));
    }

    #[test]
    fn priority_orders_host_over_reflexive_over_relay() {
        assert!(CandidateKind::Host.priority() > CandidateKind::Reflexive.priority());
        assert!(CandidateKind::Reflexive.priority() > CandidateKind::Relay.priority());
    }

    #[test]
    fn pairing_prefers_high_priority_and_caps_per_round() {
        let local = vec![
            cand(1, "192.168.1.2:5000", CandidateKind::Host),
            cand(2, "203.0.113.2:5000", CandidateKind::Reflexive),
        ];
        let remote = vec![
            cand(10, "192.168.9.9:6000", CandidateKind::Host),
            cand(11, "203.0.113.9:6000", CandidateKind::Reflexive),
            cand(12, "198.51.100.9:6000", CandidateKind::Relay),
        ];
        let pairs = pair_candidates(&local, &remote);
        assert!(pairs.len() <= MAX_PAIRS_PER_ROUND);
        // Best pair is host×host (126+126).
        assert_eq!(pairs[0], (1, 10, "192.168.9.9:6000".parse().unwrap()));
    }

    #[test]
    fn pairing_never_crosses_address_families() {
        let local = vec![cand(1, "192.168.1.2:5000", CandidateKind::Host)];
        let remote = vec![cand(10, "[2001:db8::9]:6000", CandidateKind::Host)];
        assert!(pair_candidates(&local, &remote).is_empty());
    }
}
