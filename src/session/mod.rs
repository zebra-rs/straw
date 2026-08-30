//! Per-tunnel session state and the concurrent session table.

pub mod handler;

use std::sync::Arc;
use std::time::Instant;

use dashmap::DashMap;

use crate::capsule::{AssignedAddress, IpAddressRange};
use crate::error::ProxyError;
use crate::uri_template::RequestScope;

/// Unique identifier for a CONNECT-IP tunnel session.
///
/// The value is the HTTP/3 request stream ID that carries the tunnel, which
/// is unique per connection; combined with a connection counter it is made
/// globally unique (see [`SessionId::compose`]).
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct SessionId(pub u64);

impl SessionId {
    /// Compose a globally unique session ID from a per-endpoint connection
    /// counter and the request stream ID.
    ///
    /// Stream IDs are 62-bit values but request streams are client-initiated
    /// bidirectional (id % 4 == 0) and in practice small; 40 bits of stream
    /// ID space (~275 billion streams per connection) is retained.
    pub fn compose(conn_seq: u64, stream_id: u64) -> Self {
        SessionId((conn_seq << 40) | (stream_id & ((1 << 40) - 1)))
    }

    /// The request stream ID on its connection.
    pub fn stream_id(&self) -> u64 {
        self.0 & ((1 << 40) - 1)
    }

    /// The connection sequence number this session belongs to.
    pub fn conn_seq(&self) -> u64 {
        self.0 >> 40
    }
}

impl std::fmt::Display for SessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.conn_seq(), self.stream_id())
    }
}

/// Per-session tunnel state (design §4.1).
#[derive(Debug)]
pub struct TunnelSession {
    pub id: SessionId,
    pub scope: RequestScope,
    /// IP addresses assigned to the client.
    pub assigned_addresses: Vec<AssignedAddress>,
    /// Routes advertised to the client.
    pub advertised_routes: Vec<IpAddressRange>,
    /// Routes received from the client (site-to-site, Phase 3).
    pub client_routes: Vec<IpAddressRange>,
    /// Addresses the client assigned to the proxy end (site-to-site).
    pub proxy_addresses: Vec<AssignedAddress>,
    /// Timestamp of last activity for idle timeout (Phase 4).
    pub last_activity: Instant,
}

impl TunnelSession {
    pub fn new(id: SessionId, scope: RequestScope) -> Self {
        Self {
            id,
            scope,
            assigned_addresses: Vec::new(),
            advertised_routes: Vec::new(),
            client_routes: Vec::new(),
            proxy_addresses: Vec::new(),
            last_activity: Instant::now(),
        }
    }
}

/// Concurrent session table.
#[derive(Debug, Default)]
pub struct SessionManager {
    sessions: DashMap<SessionId, TunnelSession>,
    /// Hot-path snapshot of assigned addresses, read per received datagram.
    assigned: DashMap<SessionId, Arc<Vec<AssignedAddress>>>,
    max_sessions: usize,
}

impl SessionManager {
    pub fn new(max_sessions: usize) -> Self {
        Self {
            sessions: DashMap::new(),
            assigned: DashMap::new(),
            max_sessions,
        }
    }

    /// Register a new session, enforcing the session limit.
    pub fn insert(&self, session: TunnelSession) -> Result<(), ProxyError> {
        if self.max_sessions > 0 && self.sessions.len() >= self.max_sessions {
            return Err(ProxyError::InvalidRequest(format!(
                "session limit reached ({})",
                self.max_sessions
            )));
        }
        self.assigned
            .insert(session.id, Arc::new(session.assigned_addresses.clone()));
        self.sessions.insert(session.id, session);
        Ok(())
    }

    /// Replace the session's assigned addresses (and its hot-path snapshot).
    pub fn set_assigned(&self, id: SessionId, addrs: Vec<AssignedAddress>) {
        if let Some(mut s) = self.sessions.get_mut(&id) {
            s.assigned_addresses = addrs.clone();
        }
        self.assigned.insert(id, Arc::new(addrs));
    }

    /// Record client-advertised routes (site-to-site, Phase 3).
    pub fn set_client_routes(&self, id: SessionId, routes: Vec<IpAddressRange>) {
        if let Some(mut s) = self.sessions.get_mut(&id) {
            s.client_routes = routes;
        }
    }

    /// Record addresses the client assigned to the proxy (site-to-site).
    pub fn set_proxy_addresses(&self, id: SessionId, addrs: Vec<AssignedAddress>) {
        if let Some(mut s) = self.sessions.get_mut(&id) {
            s.proxy_addresses = addrs;
        }
    }

    /// Snapshot of assigned addresses for datagram-path validation.
    pub fn assigned_snapshot(&self, id: SessionId) -> Option<Arc<Vec<AssignedAddress>>> {
        self.assigned.get(&id).map(|a| a.clone())
    }

    pub fn touch(&self, id: SessionId) {
        if let Some(mut s) = self.sessions.get_mut(&id) {
            s.last_activity = Instant::now();
        }
    }

    pub fn remove(&self, id: SessionId) {
        self.sessions.remove(&id);
        self.assigned.remove(&id);
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> RequestScope {
        RequestScope {
            target: None,
            ip_proto: None,
        }
    }

    #[test]
    fn session_id_compose_roundtrip() {
        let id = SessionId::compose(7, 44);
        assert_eq!(id.conn_seq(), 7);
        assert_eq!(id.stream_id(), 44);
    }

    #[test]
    fn session_limit_enforced() {
        let mgr = SessionManager::new(1);
        mgr.insert(TunnelSession::new(SessionId(1), scope()))
            .unwrap();
        assert!(
            mgr.insert(TunnelSession::new(SessionId(2), scope()))
                .is_err()
        );
        mgr.remove(SessionId(1));
        assert!(
            mgr.insert(TunnelSession::new(SessionId(2), scope()))
                .is_ok()
        );
    }

    #[test]
    fn assigned_snapshot_tracks_updates() {
        let mgr = SessionManager::new(10);
        let id = SessionId(4);
        mgr.insert(TunnelSession::new(id, scope())).unwrap();
        assert!(mgr.assigned_snapshot(id).unwrap().is_empty());

        mgr.set_assigned(
            id,
            vec![AssignedAddress {
                request_id: 0,
                ip_version: 4,
                ip_address: "10.100.0.5".parse().unwrap(),
                prefix_length: 32,
            }],
        );
        assert_eq!(mgr.assigned_snapshot(id).unwrap().len(), 1);
    }
}
