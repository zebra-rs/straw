//! Public (IP, port) allocation for bind sessions (design §7.1).
//!
//! Each `connect-udp-bind` session gets one stable (IP, port) from a
//! configured pool for its lifetime — the address a peer publishes as its
//! `paddr` in a token (§3.2) and the source the relay forwards from. Ports
//! are handed out round-robin across the configured IPs so a small pool of
//! addresses multiplexes many sessions, and released on teardown for reuse.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;

/// Allocator over a set of public IPs and an inclusive port range.
#[derive(Debug)]
pub struct PortAllocator {
    ips: Vec<IpAddr>,
    port_lo: u16,
    port_hi: u16,
    state: Mutex<State>,
}

#[derive(Debug)]
struct State {
    in_use: HashSet<SocketAddr>,
    /// Round-robin cursor into `ips`, so consecutive allocations spread
    /// across addresses rather than exhausting one.
    next_ip: usize,
    /// Next port to try; wraps within `[port_lo, port_hi]`.
    next_port: u16,
}

impl PortAllocator {
    /// Build an allocator. Errors on an empty IP list or an inverted range.
    pub fn new(ips: Vec<IpAddr>, port_lo: u16, port_hi: u16) -> Result<Self, String> {
        if ips.is_empty() {
            return Err("udp_bind allocator needs at least one public IP".into());
        }
        if port_lo > port_hi {
            return Err(format!("inverted port range {port_lo}..={port_hi}"));
        }
        Ok(Self {
            ips,
            port_lo,
            port_hi,
            state: Mutex::new(State {
                in_use: HashSet::new(),
                next_ip: 0,
                next_port: port_lo,
            }),
        })
    }

    /// Total addressable tuples (IPs × ports).
    pub fn capacity(&self) -> usize {
        self.ips.len() * (self.port_hi as usize - self.port_lo as usize + 1)
    }

    /// Allocate the next free (IP, port), or `None` when the pool is full.
    ///
    /// Scans ports from the round-robin cursor, trying every IP at each port
    /// before advancing — so one busy IP doesn't strand the others.
    pub fn allocate(&self) -> Option<SocketAddr> {
        let mut st = self.state.lock().unwrap();
        let span = self.port_hi as u32 - self.port_lo as u32 + 1;
        // At most `span` ports × `ips.len()` tuples to examine.
        for _ in 0..span {
            let port = st.next_port;
            // Try each IP at this port, starting from the cursor.
            for k in 0..self.ips.len() {
                let idx = (st.next_ip + k) % self.ips.len();
                let candidate = SocketAddr::new(self.ips[idx], port);
                if !st.in_use.contains(&candidate) {
                    st.in_use.insert(candidate);
                    st.next_ip = (idx + 1) % self.ips.len();
                    if st.next_ip == 0 {
                        st.next_port = next_port(port, self.port_lo, self.port_hi);
                    }
                    return Some(candidate);
                }
            }
            st.next_port = next_port(port, self.port_lo, self.port_hi);
        }
        None
    }

    /// Return an address to the pool.
    pub fn release(&self, addr: SocketAddr) {
        self.state.lock().unwrap().in_use.remove(&addr);
    }

    /// Currently allocated tuples.
    pub fn in_use(&self) -> usize {
        self.state.lock().unwrap().in_use.len()
    }
}

fn next_port(port: u16, lo: u16, hi: u16) -> u16 {
    if port >= hi { lo } else { port + 1 }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn allocations_are_unique_and_within_range() {
        let a = PortAllocator::new(vec![ip("192.0.2.45")], 32768, 32770).unwrap();
        assert_eq!(a.capacity(), 3);
        let mut seen = HashSet::new();
        for _ in 0..3 {
            let s = a.allocate().unwrap();
            assert_eq!(s.ip(), ip("192.0.2.45"));
            assert!((32768..=32770).contains(&s.port()));
            assert!(seen.insert(s), "no address handed out twice");
        }
        assert!(a.allocate().is_none(), "pool exhausted");
        assert_eq!(a.in_use(), 3);
    }

    #[test]
    fn release_makes_an_address_available_again() {
        let a = PortAllocator::new(vec![ip("192.0.2.45")], 1000, 1000).unwrap();
        let s = a.allocate().unwrap();
        assert!(a.allocate().is_none());
        a.release(s);
        assert_eq!(a.in_use(), 0);
        assert_eq!(a.allocate(), Some(s));
    }

    #[test]
    fn spreads_across_ips_round_robin() {
        let a = PortAllocator::new(vec![ip("192.0.2.1"), ip("192.0.2.2")], 5000, 5001).unwrap();
        assert_eq!(a.capacity(), 4);
        // First two allocations should land on different IPs (same port).
        let s1 = a.allocate().unwrap();
        let s2 = a.allocate().unwrap();
        assert_ne!(s1.ip(), s2.ip(), "round-robin across IPs first");
        assert_eq!(s1.port(), s2.port());
        // Exhaust the rest.
        let s3 = a.allocate().unwrap();
        let s4 = a.allocate().unwrap();
        assert!(a.allocate().is_none());
        let all: HashSet<_> = [s1, s2, s3, s4].into_iter().collect();
        assert_eq!(all.len(), 4);
    }

    #[test]
    fn rejects_bad_configuration() {
        assert!(PortAllocator::new(vec![], 1, 2).is_err());
        assert!(PortAllocator::new(vec![ip("192.0.2.1")], 2, 1).is_err());
        // A single-port single-ip pool is valid (capacity 1).
        assert_eq!(
            PortAllocator::new(vec![ip("192.0.2.1")], 7, 7)
                .unwrap()
                .capacity(),
            1
        );
    }
}
