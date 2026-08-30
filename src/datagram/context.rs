//! Context ID management (RFC 9484 §4.7 / RFC 9297 §4).
//!
//! Phase 2 uses only Context ID 0 (full IP packet). The registry exists so
//! future extensions (e.g. compression contexts) slot in without changing
//! the datagram path: unknown context IDs are dropped, not errors.

use std::collections::HashMap;

/// Meaning of a registered context ID on one CONNECT-IP stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextKind {
    /// Context ID 0: full IP packet.
    IpPacket,
}

/// Per-session registry of negotiated datagram context IDs.
///
/// Context IDs are allocated like stream IDs: the client owns even values,
/// the server odd values (RFC 9297 §4).
#[derive(Debug)]
pub struct ContextRegistry {
    contexts: HashMap<u64, ContextKind>,
}

impl ContextRegistry {
    /// A fresh registry with context 0 registered as "IP packet" per RFC 9484.
    pub fn new() -> Self {
        let mut contexts = HashMap::new();
        contexts.insert(super::CONTEXT_ID_IP_PACKET, ContextKind::IpPacket);
        Self { contexts }
    }

    /// Look up a context ID. `None` means unknown: the datagram MUST be
    /// silently dropped (RFC 9297 §4).
    pub fn lookup(&self, context_id: u64) -> Option<ContextKind> {
        self.contexts.get(&context_id).copied()
    }

    /// Register a context ID (future extension capsules).
    pub fn register(&mut self, context_id: u64, kind: ContextKind) {
        self.contexts.insert(context_id, kind);
    }
}

impl Default for ContextRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_zero_is_ip_packet() {
        let reg = ContextRegistry::new();
        assert_eq!(reg.lookup(0), Some(ContextKind::IpPacket));
    }

    #[test]
    fn unknown_context_is_none() {
        let reg = ContextRegistry::new();
        assert_eq!(reg.lookup(2), None);
    }
}
