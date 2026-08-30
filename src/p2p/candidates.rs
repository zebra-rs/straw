//! Candidate gathering for hole punching (design §5.1).
//!
//! A peer offers its transport-address candidates to the other over the
//! inner control stream; the set is, in ICE-style priority order: host
//! addresses (local interfaces, opt-in), the server-reflexive address (from
//! the relay's OBSERVED_ADDRESS), and the relay address (`paddr`, always
//! present). This module assembles and numbers that set; the actual probing
//! lives in the punch layer.

use std::net::SocketAddr;

use crate::p2p::wire::{Candidate, CandidateKind};

/// The inputs a peer has for gathering (design §5.1).
#[derive(Debug, Clone)]
pub struct Sources {
    /// Local interface addresses (host candidates). Empty unless the
    /// operator opted into `--direct=full` (design §10.3).
    pub host: Vec<SocketAddr>,
    /// The relay's observed outer source (reflexive), if reported.
    pub reflexive: Option<SocketAddr>,
    /// The relay-allocated public address — always present.
    pub relay: SocketAddr,
}

/// Assemble the candidate set: host, then reflexive, then relay, numbered by
/// `seq` in that order, de-duplicated by address (the reflexive address can
/// equal a host or the relay address behind a full-cone NAT), and sorted by
/// descending priority.
pub fn gather(sources: &Sources) -> Vec<Candidate> {
    let mut out: Vec<Candidate> = Vec::new();
    let mut seen: Vec<SocketAddr> = Vec::new();
    let push = |addr: SocketAddr,
                kind: CandidateKind,
                out: &mut Vec<Candidate>,
                seen: &mut Vec<SocketAddr>| {
        if seen.contains(&addr) {
            return;
        }
        seen.push(addr);
        out.push(Candidate {
            seq: out.len() as u32,
            addr,
            kind,
        });
    };
    for &h in &sources.host {
        push(h, CandidateKind::Host, &mut out, &mut seen);
    }
    if let Some(r) = sources.reflexive {
        push(r, CandidateKind::Reflexive, &mut out, &mut seen);
    }
    push(sources.relay, CandidateKind::Relay, &mut out, &mut seen);

    out.sort_by(|a, b| b.kind.priority().cmp(&a.kind.priority()));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn a(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn gathers_in_priority_order_with_the_relay_always_present() {
        let set = gather(&Sources {
            host: vec![a("192.168.1.2:5000")],
            reflexive: Some(a("203.0.113.2:41000")),
            relay: a("198.51.100.5:32768"),
        });
        assert_eq!(set.len(), 3);
        assert_eq!(set[0].kind, CandidateKind::Host);
        assert_eq!(set[1].kind, CandidateKind::Reflexive);
        assert_eq!(set[2].kind, CandidateKind::Relay);
    }

    #[test]
    fn reflexive_only_is_the_common_nat_case() {
        // No host candidates (default --direct=reflexive).
        let set = gather(&Sources {
            host: vec![],
            reflexive: Some(a("203.0.113.2:41000")),
            relay: a("198.51.100.5:32768"),
        });
        assert_eq!(set.len(), 2);
        assert_eq!(set[0].kind, CandidateKind::Reflexive);
        assert_eq!(set[1].kind, CandidateKind::Relay);
    }

    #[test]
    fn duplicate_addresses_are_collapsed() {
        // Full-cone NAT: the reflexive address equals the relay-seen public
        // address, and a host equals the reflexive (no NAT). Only distinct
        // addresses survive; the relay is always represented.
        let addr = a("203.0.113.2:41000");
        let set = gather(&Sources {
            host: vec![addr],
            reflexive: Some(addr),
            relay: a("198.51.100.5:32768"),
        });
        let addrs: Vec<_> = set.iter().map(|c| c.addr).collect();
        assert_eq!(addrs.len(), 2);
        assert!(addrs.contains(&addr));
        assert!(addrs.contains(&a("198.51.100.5:32768")));
    }

    #[test]
    fn no_reflexive_still_yields_the_relay_candidate() {
        let set = gather(&Sources {
            host: vec![],
            reflexive: None,
            relay: a("198.51.100.5:32768"),
        });
        assert_eq!(set.len(), 1);
        assert_eq!(set[0].kind, CandidateKind::Relay);
    }
}
