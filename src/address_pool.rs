//! IPv4/IPv6 address allocation for tunnel sessions.
//!
//! Addresses are handed out lazily (cursor + free list) so huge ranges —
//! an IPv6 /64 has 2^64 hosts — never get materialized.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Mutex;

use dashmap::DashMap;
use ipnet::{Ipv4Net, Ipv6Net};

use crate::capsule::{AssignedAddress, RequestedAddress};
use crate::session::SessionId;

#[derive(Debug)]
struct V4Pool {
    net: Ipv4Net,
    /// Offset of the next never-used host (0 = network address).
    cursor: u32,
    /// Released addresses available for reuse.
    free: BTreeSet<Ipv4Addr>,
}

impl V4Pool {
    fn next(&mut self) -> Option<Ipv4Addr> {
        if let Some(addr) = self.free.pop_first() {
            return Some(addr);
        }
        let base = u32::from(self.net.network());
        let broadcast = u32::from(self.net.broadcast());
        loop {
            let candidate = base.checked_add(self.cursor)?;
            if candidate >= broadcast {
                return None; // exhausted (broadcast excluded)
            }
            self.cursor += 1;
            // Skip offset 0 (network address) and offset 1 (the gateway,
            // which the proxy reserves for itself on the TUN interface).
            if self.cursor <= 2 {
                continue;
            }
            return Some(Ipv4Addr::from(candidate));
        }
    }
}

#[derive(Debug)]
struct V6Pool {
    net: Ipv6Net,
    cursor: u128,
    free: BTreeSet<Ipv6Addr>,
}

impl V6Pool {
    fn next(&mut self) -> Option<Ipv6Addr> {
        if let Some(addr) = self.free.pop_first() {
            return Some(addr);
        }
        let base = u128::from(self.net.network());
        let max_hosts = if self.net.prefix_len() >= 128 {
            1
        } else {
            1u128 << (128 - self.net.prefix_len() as u32).min(64)
        };
        loop {
            if self.cursor >= max_hosts {
                return None;
            }
            let candidate = base.checked_add(self.cursor)?;
            self.cursor += 1;
            // Skip the anycast/subnet-router address (::0) and reserve ::1
            // for the proxy itself.
            if self.cursor <= 2 {
                continue;
            }
            return Some(Ipv6Addr::from(candidate));
        }
    }
}

/// Manages the pools of assignable client addresses.
#[derive(Debug)]
pub struct AddressPool {
    v4: Mutex<V4Pool>,
    v6: Option<Mutex<V6Pool>>,
    /// Session → allocated addresses, for release on teardown.
    allocations: DashMap<SessionId, Vec<IpAddr>>,
    /// Reverse index guarding against double allocation of specific requests.
    allocated: DashMap<IpAddr, SessionId>,
}

impl AddressPool {
    pub fn new(ipv4: Ipv4Net, ipv6: Option<Ipv6Net>) -> Self {
        Self {
            v4: Mutex::new(V4Pool {
                net: ipv4,
                cursor: 0,
                free: BTreeSet::new(),
            }),
            v6: ipv6.map(|net| {
                Mutex::new(V6Pool {
                    net,
                    cursor: 0,
                    free: BTreeSet::new(),
                })
            }),
            allocations: DashMap::new(),
            allocated: DashMap::new(),
        }
    }

    /// The proxy-side gateway address (first host of the IPv4 pool).
    pub fn ipv4_gateway(&self) -> (Ipv4Addr, u8) {
        let pool = self.v4.lock().unwrap();
        let base = u32::from(pool.net.network());
        (Ipv4Addr::from(base + 1), pool.net.prefix_len())
    }

    /// The proxy-side IPv6 gateway (first host of the IPv6 pool), if any.
    pub fn ipv6_gateway(&self) -> Option<(Ipv6Addr, u8)> {
        let pool = self.v6.as_ref()?.lock().unwrap();
        let base = u128::from(pool.net.network());
        Some((Ipv6Addr::from(base + 1), pool.net.prefix_len()))
    }

    /// The configured pool subnets (used to guard client route installs).
    pub fn pool_nets(&self) -> Vec<ipnet::IpNet> {
        let mut nets = vec![ipnet::IpNet::V4(self.v4.lock().unwrap().net)];
        if let Some(pool) = &self.v6 {
            nets.push(ipnet::IpNet::V6(pool.lock().unwrap().net));
        }
        nets
    }

    /// Allocate the next available IPv4 address for a session (unprompted
    /// assignment, request_id = 0).
    pub fn allocate_v4(&self, session: SessionId) -> Option<AssignedAddress> {
        let addr = {
            let mut pool = self.v4.lock().unwrap();
            loop {
                let candidate = pool.next()?;
                if !self.allocated.contains_key(&IpAddr::V4(candidate)) {
                    break candidate;
                }
            }
        };
        self.record(session, IpAddr::V4(addr));
        Some(AssignedAddress {
            request_id: 0,
            ip_version: 4,
            ip_address: IpAddr::V4(addr),
            prefix_length: 32,
        })
    }

    /// Allocate the next available IPv6 address, if a pool is configured.
    pub fn allocate_v6(&self, session: SessionId) -> Option<AssignedAddress> {
        let pool = self.v6.as_ref()?;
        let addr = {
            let mut pool = pool.lock().unwrap();
            loop {
                let candidate = pool.next()?;
                if !self.allocated.contains_key(&IpAddr::V6(candidate)) {
                    break candidate;
                }
            }
        };
        self.record(session, IpAddr::V6(addr));
        Some(AssignedAddress {
            request_id: 0,
            ip_version: 6,
            ip_address: IpAddr::V6(addr),
            prefix_length: 128,
        })
    }

    /// Serve an ADDRESS_REQUEST entry (RFC 9484 §4.7.2): honor a specific
    /// free address when possible, otherwise fall back to pool order.
    /// Returns `None` when nothing can be allocated for the request.
    pub fn allocate_for_request(
        &self,
        session: SessionId,
        request: &RequestedAddress,
    ) -> Option<AssignedAddress> {
        // "Any address" markers (0.0.0.0 / ::) or full-prefix requests fall
        // back to pool allocation.
        let specific = match request.ip_address {
            IpAddr::V4(a) if !a.is_unspecified() && request.prefix_length == 32 => {
                Some(IpAddr::V4(a))
            }
            IpAddr::V6(a) if !a.is_unspecified() && request.prefix_length == 128 => {
                Some(IpAddr::V6(a))
            }
            _ => None,
        };

        if let Some(addr) = specific
            && self.try_allocate_specific(session, addr)
        {
            return Some(AssignedAddress {
                request_id: request.request_id,
                ip_version: request.ip_version,
                ip_address: addr,
                prefix_length: request.prefix_length,
            });
        }

        let assigned = match request.ip_version {
            4 => self.allocate_v4(session),
            6 => self.allocate_v6(session),
            _ => None,
        }?;
        Some(AssignedAddress {
            request_id: request.request_id,
            ..assigned
        })
    }

    fn try_allocate_specific(&self, session: SessionId, addr: IpAddr) -> bool {
        let in_pool = match addr {
            IpAddr::V4(a) => {
                let pool = self.v4.lock().unwrap();
                pool.net.contains(&a) && a != pool.net.network() && a != pool.net.broadcast()
            }
            IpAddr::V6(a) => match &self.v6 {
                Some(pool) => pool.lock().unwrap().net.contains(&a),
                None => false,
            },
        };
        if !in_pool {
            return false;
        }
        // Reject the gateway and anything already handed out.
        if addr == IpAddr::V4(self.ipv4_gateway().0) {
            return false;
        }
        if self.allocated.contains_key(&addr) {
            return false;
        }
        self.record(session, addr);
        true
    }

    fn record(&self, session: SessionId, addr: IpAddr) {
        self.allocated.insert(addr, session);
        self.allocations.entry(session).or_default().push(addr);
    }

    /// Release all addresses held by a session.
    pub fn release(&self, session: SessionId) {
        let Some((_, addrs)) = self.allocations.remove(&session) else {
            return;
        };
        for addr in addrs {
            self.allocated.remove(&addr);
            match addr {
                IpAddr::V4(a) => {
                    self.v4.lock().unwrap().free.insert(a);
                }
                IpAddr::V6(a) => {
                    if let Some(pool) = &self.v6 {
                        pool.lock().unwrap().free.insert(a);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool() -> AddressPool {
        AddressPool::new("10.100.0.0/29".parse().unwrap(), None)
    }

    #[test]
    fn sequential_allocation_skips_network_gateway_broadcast() {
        let p = pool();
        // /29 = .0 network, .1 gateway, .2-.6 usable, .7 broadcast.
        let a = p.allocate_v4(SessionId(0)).unwrap();
        assert_eq!(a.ip_address, "10.100.0.2".parse::<IpAddr>().unwrap());
        let b = p.allocate_v4(SessionId(4)).unwrap();
        assert_eq!(b.ip_address, "10.100.0.3".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn exhaustion_and_release() {
        let p = pool();
        let mut allocated = Vec::new();
        for i in 0..5 {
            allocated.push(p.allocate_v4(SessionId(i)).unwrap());
        }
        assert!(p.allocate_v4(SessionId(99)).is_none(), "pool exhausted");

        p.release(SessionId(0));
        let again = p.allocate_v4(SessionId(100)).unwrap();
        assert_eq!(again.ip_address, allocated[0].ip_address);
    }

    #[test]
    fn specific_request_honored_once() {
        let p = pool();
        let req = RequestedAddress {
            request_id: 9,
            ip_version: 4,
            ip_address: "10.100.0.5".parse().unwrap(),
            prefix_length: 32,
        };
        let a = p.allocate_for_request(SessionId(0), &req).unwrap();
        assert_eq!(a.request_id, 9);
        assert_eq!(a.ip_address, "10.100.0.5".parse::<IpAddr>().unwrap());

        // Second identical request cannot get the same address.
        let b = p.allocate_for_request(SessionId(4), &req).unwrap();
        assert_eq!(b.request_id, 9);
        assert_ne!(b.ip_address, a.ip_address);
    }

    #[test]
    fn any_address_request_uses_pool_order() {
        let p = pool();
        let req = RequestedAddress {
            request_id: 3,
            ip_version: 4,
            ip_address: "0.0.0.0".parse().unwrap(),
            prefix_length: 32,
        };
        let a = p.allocate_for_request(SessionId(0), &req).unwrap();
        assert_eq!(a.request_id, 3);
        assert_eq!(a.ip_address, "10.100.0.2".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn gateway_is_first_host() {
        let p = pool();
        assert_eq!(p.ipv4_gateway(), ("10.100.0.1".parse().unwrap(), 29));
    }

    #[test]
    fn v6_allocation_when_configured() {
        let p = AddressPool::new(
            "10.100.0.0/24".parse().unwrap(),
            Some("fd00:6d61:7371::/64".parse().unwrap()),
        );
        let a = p.allocate_v6(SessionId(0)).unwrap();
        assert_eq!(a.ip_version, 6);
        assert_eq!(a.prefix_length, 128);
        let b = p.allocate_v6(SessionId(0)).unwrap();
        assert_ne!(a.ip_address, b.ip_address);
    }

    #[test]
    fn out_of_pool_specific_request_falls_back() {
        let p = pool();
        let req = RequestedAddress {
            request_id: 1,
            ip_version: 4,
            ip_address: "192.168.1.1".parse().unwrap(),
            prefix_length: 32,
        };
        let a = p.allocate_for_request(SessionId(0), &req).unwrap();
        // Falls back to the pool rather than assigning a foreign address.
        assert_eq!(a.ip_address, "10.100.0.2".parse::<IpAddr>().unwrap());
    }
}
