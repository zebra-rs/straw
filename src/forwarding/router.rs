//! Route table: destination address → session, for reverse-path (network →
//! client) forwarding and client↔client hairpin routing.

use std::net::IpAddr;
use std::sync::RwLock;

use dashmap::DashMap;
use ipnet::{IpNet, Ipv4Subnets, Ipv6Subnets};

use crate::capsule::IpAddressRange;
use crate::session::SessionId;

/// A prefix route toward a session.
#[derive(Debug, Clone)]
pub struct RouteEntry {
    pub prefix: IpNet,
    /// IP protocol scope; 0 = all protocols.
    pub ip_protocol: u8,
    pub session_id: SessionId,
}

/// Maps destination IPs to the session that should receive them.
///
/// Assigned client addresses sit in a hash map fast path; prefix routes
/// (site-to-site, Phase 3) use longest-prefix match.
#[derive(Debug, Default)]
pub struct RouteTable {
    routes: RwLock<Vec<RouteEntry>>,
    client_addrs: DashMap<IpAddr, SessionId>,
}

impl RouteTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Register an assigned client address (fast path).
    pub fn insert_client_addr(&self, addr: IpAddr, session: SessionId) {
        self.client_addrs.insert(addr, session);
    }

    /// Install a prefix route toward a session.
    pub fn insert_route(&self, entry: RouteEntry) {
        self.routes.write().unwrap().push(entry);
    }

    /// Replace all prefix routes for a session (full-state semantics of
    /// ROUTE_ADVERTISEMENT, RFC 9484 §4.7.3). Assigned client addresses are
    /// untouched.
    pub fn replace_session_routes(&self, session: SessionId, entries: Vec<RouteEntry>) {
        let mut routes = self.routes.write().unwrap();
        routes.retain(|r| r.session_id != session);
        routes.extend(entries);
    }

    /// Remove all state for a session.
    pub fn remove_session(&self, session: SessionId) {
        self.client_addrs.retain(|_, s| *s != session);
        self.routes
            .write()
            .unwrap()
            .retain(|r| r.session_id != session);
    }

    /// Find the session that should receive a packet for `dst` / `proto`.
    pub fn lookup(&self, dst: IpAddr, proto: u8) -> Option<SessionId> {
        if let Some(session) = self.client_addrs.get(&dst) {
            return Some(*session);
        }
        let routes = self.routes.read().unwrap();
        routes
            .iter()
            .filter(|r| r.prefix.contains(&dst))
            .filter(|r| r.ip_protocol == 0 || r.ip_protocol == proto)
            .max_by_key(|r| r.prefix.prefix_len())
            .map(|r| r.session_id)
    }
}

/// Maximum prefixes installed from one client's ROUTE_ADVERTISEMENT.
pub const MAX_CLIENT_ROUTE_PREFIXES: usize = 128;

/// Convert client-advertised ranges into route entries toward `session`
/// (site-to-site, RFC 9484 §4.7.3 / design Step 22).
///
/// Safety rules: ranges overlapping any `deny` prefix (the proxy's address
/// pools — accepting those would hijack other clients) are skipped with a
/// warning, and the total prefix count is capped.
pub fn entries_from_client_ranges(
    session: SessionId,
    ranges: &[IpAddressRange],
    deny: &[IpNet],
) -> Vec<RouteEntry> {
    let mut entries = Vec::new();
    'ranges: for range in ranges {
        let prefixes: Vec<IpNet> = match (range.start_ip, range.end_ip) {
            (IpAddr::V4(start), IpAddr::V4(end)) if start <= end => {
                Ipv4Subnets::new(start, end, 0).map(IpNet::V4).collect()
            }
            (IpAddr::V6(start), IpAddr::V6(end)) if start <= end => {
                Ipv6Subnets::new(start, end, 0).map(IpNet::V6).collect()
            }
            _ => {
                tracing::warn!(?range, "ignoring malformed client route range");
                continue;
            }
        };

        for prefix in &prefixes {
            if deny.iter().any(|d| overlaps(d, prefix)) {
                tracing::warn!(
                    %prefix, %session,
                    "refusing client route overlapping the proxy address pool"
                );
                continue 'ranges;
            }
        }

        for prefix in prefixes {
            if entries.len() >= MAX_CLIENT_ROUTE_PREFIXES {
                tracing::warn!(%session, "client route prefix cap reached; ignoring the rest");
                return entries;
            }
            entries.push(RouteEntry {
                prefix,
                ip_protocol: range.ip_protocol,
                session_id: session,
            });
        }
    }
    entries
}

fn overlaps(a: &IpNet, b: &IpNet) -> bool {
    a.contains(&b.network()) || b.contains(&a.network())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn client_addr_fast_path() {
        let table = RouteTable::new();
        table.insert_client_addr(ip("10.100.0.2"), SessionId(0));
        table.insert_client_addr(ip("10.100.0.3"), SessionId(4));

        assert_eq!(table.lookup(ip("10.100.0.2"), 6), Some(SessionId(0)));
        assert_eq!(table.lookup(ip("10.100.0.3"), 17), Some(SessionId(4)));
        assert_eq!(table.lookup(ip("10.100.0.4"), 6), None);
    }

    #[test]
    fn longest_prefix_match() {
        let table = RouteTable::new();
        table.insert_route(RouteEntry {
            prefix: "192.168.0.0/16".parse().unwrap(),
            ip_protocol: 0,
            session_id: SessionId(0),
        });
        table.insert_route(RouteEntry {
            prefix: "192.168.1.0/24".parse().unwrap(),
            ip_protocol: 0,
            session_id: SessionId(4),
        });

        assert_eq!(table.lookup(ip("192.168.1.7"), 6), Some(SessionId(4)));
        assert_eq!(table.lookup(ip("192.168.2.7"), 6), Some(SessionId(0)));
    }

    #[test]
    fn protocol_scoped_route() {
        let table = RouteTable::new();
        table.insert_route(RouteEntry {
            prefix: "203.0.113.0/24".parse().unwrap(),
            ip_protocol: 17, // UDP only
            session_id: SessionId(8),
        });

        assert_eq!(table.lookup(ip("203.0.113.9"), 17), Some(SessionId(8)));
        assert_eq!(table.lookup(ip("203.0.113.9"), 6), None);
    }

    #[test]
    fn client_ranges_become_prefix_routes() {
        let range = IpAddressRange::from_net("192.168.50.0/24".parse().unwrap(), 0);
        let entries = entries_from_client_ranges(SessionId(4), &[range], &[]);
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].prefix,
            "192.168.50.0/24".parse::<IpNet>().unwrap()
        );
        assert_eq!(entries[0].session_id, SessionId(4));
    }

    #[test]
    fn client_range_decomposes_to_minimal_prefixes() {
        // .0.10 - .0.13 needs two prefixes: .10/31 and .12/31.
        let range = IpAddressRange {
            ip_version: 4,
            start_ip: ip("192.168.50.10"),
            end_ip: ip("192.168.50.13"),
            ip_protocol: 0,
        };
        let entries = entries_from_client_ranges(SessionId(0), &[range], &[]);
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn client_range_overlapping_pool_is_refused() {
        let pool: IpNet = "10.100.0.0/24".parse().unwrap();
        // A hostile "route everything to me" advertisement.
        let hijack = IpAddressRange::from_net("0.0.0.0/0".parse().unwrap(), 0);
        assert!(entries_from_client_ranges(SessionId(0), &[hijack], &[pool]).is_empty());

        // Direct overlap with the pool subnet.
        let overlap = IpAddressRange::from_net("10.100.0.0/16".parse().unwrap(), 0);
        assert!(entries_from_client_ranges(SessionId(0), &[overlap], &[pool]).is_empty());

        // Disjoint range passes.
        let fine = IpAddressRange::from_net("172.16.0.0/16".parse().unwrap(), 0);
        assert_eq!(
            entries_from_client_ranges(SessionId(0), &[fine], &[pool]).len(),
            1
        );
    }

    #[test]
    fn client_route_prefix_cap() {
        // One giant scattered range: .0.0.1 - .255.255.254 explodes into many
        // prefixes; the cap must hold.
        let range = IpAddressRange {
            ip_version: 4,
            start_ip: ip("11.0.0.1"),
            end_ip: ip("11.255.255.254"),
            ip_protocol: 0,
        };
        let entries = entries_from_client_ranges(SessionId(0), &[range], &[]);
        assert!(entries.len() <= MAX_CLIENT_ROUTE_PREFIXES);
    }

    #[test]
    fn replace_session_routes_is_full_state() {
        let table = RouteTable::new();
        table.insert_client_addr(ip("10.100.0.2"), SessionId(0));
        table.insert_route(RouteEntry {
            prefix: "192.168.0.0/16".parse().unwrap(),
            ip_protocol: 0,
            session_id: SessionId(0),
        });

        table.replace_session_routes(
            SessionId(0),
            vec![RouteEntry {
                prefix: "172.16.0.0/16".parse().unwrap(),
                ip_protocol: 0,
                session_id: SessionId(0),
            }],
        );

        assert_eq!(table.lookup(ip("192.168.1.1"), 6), None, "old route gone");
        assert_eq!(table.lookup(ip("172.16.1.1"), 6), Some(SessionId(0)));
        assert_eq!(
            table.lookup(ip("10.100.0.2"), 6),
            Some(SessionId(0)),
            "client address untouched"
        );
    }

    #[test]
    fn remove_session_clears_both_paths() {
        let table = RouteTable::new();
        table.insert_client_addr(ip("10.100.0.2"), SessionId(0));
        table.insert_route(RouteEntry {
            prefix: "192.168.0.0/16".parse().unwrap(),
            ip_protocol: 0,
            session_id: SessionId(0),
        });

        table.remove_session(SessionId(0));
        assert_eq!(table.lookup(ip("10.100.0.2"), 6), None);
        assert_eq!(table.lookup(ip("192.168.1.1"), 6), None);
    }
}
