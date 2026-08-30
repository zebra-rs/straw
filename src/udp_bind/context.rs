//! Compression contexts for CONNECT-UDP bind (design §3.1).
//!
//! A *context* maps a small integer id, carried at the front of each HTTP
//! Datagram, to how the datagram's remote address is conveyed:
//!
//! - the **uncompressed** context (registered first, id 2) prefixes every
//!   payload with an explicit `(IP version, address, port)` — used while a
//!   peer talks to many remotes (candidate probing), and
//! - a **compressed** context binds one fixed remote, so its datagrams
//!   carry only the id and the UDP payload — the steady-state direct peer.
//!
//! Registration rides the capsule stream: `COMPRESSION_ASSIGN` (0x11)
//! proposes a context, `COMPRESSION_ACK` (0x12) confirms it, and
//! `COMPRESSION_CLOSE` (0x13) retires it. Closing the uncompressed context
//! turns the relay into a firewall that forwards only for registered
//! remotes (design §10.4). Context ids follow the RFC 9297 parity rule:
//! client-allocated ids are even, relay-allocated odd.
//!
//! The type numbers are provisional (design §9); they live here so the swap
//! to the finalized listen-draft codepoints is a one-line change.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use bytes::{Buf, BufMut, Bytes, BytesMut};

use crate::capsule::codec::{read_varint, varint_len, write_varint};
use crate::error::DecodeError;

/// Provisional capsule type: register a compression context.
pub const CAPSULE_COMPRESSION_ASSIGN: u64 = 0x11;
/// Provisional capsule type: acknowledge a registered context.
pub const CAPSULE_COMPRESSION_ACK: u64 = 0x12;
/// Provisional capsule type: retire a context.
pub const CAPSULE_COMPRESSION_CLOSE: u64 = 0x13;

/// The first client-allocated (even) context id (design §3.1).
pub const FIRST_UNCOMPRESSED_CONTEXT: u64 = 2;

/// How a context conveys its datagrams' remote address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Binding {
    /// Every datagram carries an explicit `(version, address, port)`.
    Uncompressed,
    /// All datagrams are to/from this fixed remote; the wire carries only
    /// the context id and the UDP payload.
    Compressed(SocketAddr),
}

/// A `COMPRESSION_ASSIGN` capsule body: register `context_id` with `binding`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressionAssign {
    pub context_id: u64,
    pub binding: Binding,
}

impl CompressionAssign {
    /// Encode the capsule (type + length + body).
    pub fn encode(&self, buf: &mut BytesMut) {
        let mut body = BytesMut::new();
        write_varint(&mut body, self.context_id).expect("context id fits varint");
        match self.binding {
            // IP version 0 marks an uncompressed context (design §3.1).
            Binding::Uncompressed => body.put_u8(0),
            Binding::Compressed(addr) => put_addr(&mut body, addr),
        }
        write_varint(buf, CAPSULE_COMPRESSION_ASSIGN).unwrap();
        write_varint(buf, body.len() as u64).unwrap();
        buf.extend_from_slice(&body);
    }

    /// Decode from a capsule body (after type + length).
    pub fn decode(mut body: Bytes) -> Result<Self, DecodeError> {
        let context_id = read_varint(&mut body)?;
        let binding = match get_u8(&mut body)? {
            0 => Binding::Uncompressed,
            v => Binding::Compressed(get_addr(&mut body, v)?),
        };
        if body.has_remaining() {
            return Err(DecodeError::TrailingBytes(body.remaining()));
        }
        Ok(Self {
            context_id,
            binding,
        })
    }
}

/// Encode a bare-`context_id` capsule (`ACK` or `CLOSE`).
pub fn encode_context_capsule(capsule_type: u64, context_id: u64, buf: &mut BytesMut) {
    write_varint(buf, capsule_type).unwrap();
    write_varint(buf, varint_len(context_id).unwrap() as u64).unwrap();
    write_varint(buf, context_id).unwrap();
}

/// Decode a bare-`context_id` capsule body.
pub fn decode_context_capsule(mut body: Bytes) -> Result<u64, DecodeError> {
    let context_id = read_varint(&mut body)?;
    if body.has_remaining() {
        return Err(DecodeError::TrailingBytes(body.remaining()));
    }
    Ok(context_id)
}

/// One HTTP Datagram body on a bind session: a remote and its UDP payload.
///
/// The wire form depends on the context (see [`ContextTable::decode_datagram`]
/// / [`ContextTable::encode_datagram`]): an uncompressed context spells the
/// address out, a compressed one leaves it implicit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundDatagram {
    pub context_id: u64,
    pub remote: SocketAddr,
    pub payload: Bytes,
}

/// Per-session table of registered contexts.
///
/// Holds only *acknowledged* contexts as forwarding-ready; a proposed
/// context is pending until [`ack`](Self::ack). The relay is the datagram
/// endpoint, so it validates ids the peer proposes (client-allocated =
/// even) and rejects a redefinition.
#[derive(Debug, Default)]
pub struct ContextTable {
    contexts: std::collections::HashMap<u64, Binding>,
    pending: std::collections::HashMap<u64, Binding>,
}

impl ContextTable {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a peer's `COMPRESSION_ASSIGN`. Client-allocated ids MUST be
    /// even (RFC 9297); a known id cannot be redefined.
    pub fn register(&mut self, assign: CompressionAssign) -> Result<(), ContextError> {
        if assign.context_id % 2 != 0 {
            return Err(ContextError::NotClientAllocated(assign.context_id));
        }
        if self.contexts.contains_key(&assign.context_id)
            || self.pending.contains_key(&assign.context_id)
        {
            return Err(ContextError::Duplicate(assign.context_id));
        }
        self.pending.insert(assign.context_id, assign.binding);
        Ok(())
    }

    /// Promote a pending context to active on its `COMPRESSION_ACK`.
    pub fn ack(&mut self, context_id: u64) -> Result<(), ContextError> {
        let binding = self
            .pending
            .remove(&context_id)
            .ok_or(ContextError::Unknown(context_id))?;
        self.contexts.insert(context_id, binding);
        Ok(())
    }

    /// Retire a context (either state) on `COMPRESSION_CLOSE`.
    pub fn close(&mut self, context_id: u64) {
        self.contexts.remove(&context_id);
        self.pending.remove(&context_id);
    }

    /// The binding of an active context, if any.
    pub fn binding(&self, context_id: u64) -> Option<Binding> {
        self.contexts.get(&context_id).copied()
    }

    /// The active compressed context bound to `remote`, if one exists — the
    /// preferred (smallest) framing for that remote.
    pub fn compressed_context_for(&self, remote: SocketAddr) -> Option<u64> {
        self.contexts
            .iter()
            .find_map(|(id, binding)| match binding {
                Binding::Compressed(addr) if *addr == remote => Some(*id),
                _ => None,
            })
    }

    /// An active uncompressed context, if one is registered — the fallback
    /// framing that spells the address out. `None` once it is closed, which
    /// is what turns the relay into a firewall (design §7.3).
    pub fn uncompressed_context(&self) -> Option<u64> {
        self.contexts
            .iter()
            .find_map(|(id, binding)| match binding {
                Binding::Uncompressed => Some(*id),
                _ => None,
            })
    }

    /// Decode one datagram body against this table. The leading context id
    /// selects the addressing: an uncompressed context reads an explicit
    /// address, a compressed one supplies its bound remote.
    pub fn decode_datagram(&self, mut buf: Bytes) -> Result<BoundDatagram, ContextError> {
        let context_id = read_varint(&mut buf).map_err(ContextError::Decode)?;
        match self.binding(context_id) {
            None => Err(ContextError::Unknown(context_id)),
            Some(Binding::Compressed(remote)) => Ok(BoundDatagram {
                context_id,
                remote,
                payload: buf,
            }),
            Some(Binding::Uncompressed) => {
                let version = get_u8(&mut buf).map_err(ContextError::Decode)?;
                let remote = get_addr(&mut buf, version).map_err(ContextError::Decode)?;
                Ok(BoundDatagram {
                    context_id,
                    remote,
                    payload: buf,
                })
            }
        }
    }

    /// Encode a datagram to `remote` on `context_id`, spelling out the
    /// address only when the context is uncompressed.
    pub fn encode_datagram(
        &self,
        context_id: u64,
        remote: SocketAddr,
        payload: &[u8],
    ) -> Result<Bytes, ContextError> {
        let mut buf = BytesMut::new();
        write_varint(&mut buf, context_id).unwrap();
        match self.binding(context_id) {
            None => return Err(ContextError::Unknown(context_id)),
            Some(Binding::Compressed(_)) => {}
            Some(Binding::Uncompressed) => put_addr(&mut buf, remote),
        }
        buf.extend_from_slice(payload);
        Ok(buf.freeze())
    }
}

/// Errors from context registration and datagram (de)coding.
#[derive(Debug, PartialEq, Eq)]
pub enum ContextError {
    /// A client-allocated context id must be even (RFC 9297).
    NotClientAllocated(u64),
    /// The id is already registered or pending.
    Duplicate(u64),
    /// No such active/pending context.
    Unknown(u64),
    /// The datagram/capsule body was malformed.
    Decode(DecodeError),
}

impl std::fmt::Display for ContextError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotClientAllocated(id) => {
                write!(f, "context id {id} is not even (client-allocated)")
            }
            Self::Duplicate(id) => write!(f, "context id {id} already registered"),
            Self::Unknown(id) => write!(f, "unknown context id {id}"),
            Self::Decode(e) => write!(f, "malformed context datagram: {e}"),
        }
    }
}

// ── address (de)serialization: version (u8) + address + port (u16) ──────

fn put_addr(buf: &mut BytesMut, addr: SocketAddr) {
    match addr.ip() {
        IpAddr::V4(v4) => {
            buf.put_u8(4);
            buf.put_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            buf.put_u8(6);
            buf.put_slice(&v6.octets());
        }
    }
    buf.put_u16(addr.port());
}

fn get_addr(buf: &mut Bytes, version: u8) -> Result<SocketAddr, DecodeError> {
    let ip = match version {
        4 => {
            let mut o = [0u8; 4];
            get_slice(buf, &mut o)?;
            IpAddr::V4(Ipv4Addr::from(o))
        }
        6 => {
            let mut o = [0u8; 16];
            get_slice(buf, &mut o)?;
            IpAddr::V6(Ipv6Addr::from(o))
        }
        other => return Err(DecodeError::InvalidIpVersion(other)),
    };
    if buf.remaining() < 2 {
        return Err(DecodeError::Underflow);
    }
    let port = buf.get_u16();
    Ok(SocketAddr::new(ip, port))
}

fn get_u8(buf: &mut Bytes) -> Result<u8, DecodeError> {
    if !buf.has_remaining() {
        return Err(DecodeError::Underflow);
    }
    Ok(buf.get_u8())
}

fn get_slice(buf: &mut Bytes, out: &mut [u8]) -> Result<(), DecodeError> {
    if buf.remaining() < out.len() {
        return Err(DecodeError::Underflow);
    }
    buf.copy_to_slice(out);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }
    fn v6(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn assign_round_trips_uncompressed_and_compressed() {
        for binding in [
            Binding::Uncompressed,
            Binding::Compressed(v4("192.0.2.45:54321")),
            Binding::Compressed(v6("[2001:db8::1]:443")),
        ] {
            let a = CompressionAssign {
                context_id: 2,
                binding,
            };
            let mut buf = BytesMut::new();
            a.encode(&mut buf);
            // strip the capsule type + length envelope
            let mut b = buf.freeze();
            let ty = read_varint(&mut b).unwrap();
            assert_eq!(ty, CAPSULE_COMPRESSION_ASSIGN);
            let len = read_varint(&mut b).unwrap() as usize;
            let body = b.slice(..len);
            assert_eq!(CompressionAssign::decode(body).unwrap(), a);
        }
    }

    #[test]
    fn ack_and_close_capsules_round_trip() {
        for ty in [CAPSULE_COMPRESSION_ACK, CAPSULE_COMPRESSION_CLOSE] {
            let mut buf = BytesMut::new();
            encode_context_capsule(ty, 6, &mut buf);
            let mut b = buf.freeze();
            assert_eq!(read_varint(&mut b).unwrap(), ty);
            let len = read_varint(&mut b).unwrap() as usize;
            assert_eq!(decode_context_capsule(b.slice(..len)).unwrap(), 6);
        }
    }

    #[test]
    fn table_enforces_parity_and_rejects_duplicates() {
        let mut t = ContextTable::new();
        assert_eq!(
            t.register(CompressionAssign {
                context_id: 3,
                binding: Binding::Uncompressed
            }),
            Err(ContextError::NotClientAllocated(3))
        );
        t.register(CompressionAssign {
            context_id: 2,
            binding: Binding::Uncompressed,
        })
        .unwrap();
        assert_eq!(
            t.register(CompressionAssign {
                context_id: 2,
                binding: Binding::Uncompressed
            }),
            Err(ContextError::Duplicate(2))
        );
    }

    #[test]
    fn context_is_forwarding_ready_only_after_ack() {
        let mut t = ContextTable::new();
        t.register(CompressionAssign {
            context_id: 2,
            binding: Binding::Uncompressed,
        })
        .unwrap();
        assert!(t.binding(2).is_none(), "pending is not active");
        t.ack(2).unwrap();
        assert_eq!(t.binding(2), Some(Binding::Uncompressed));
        assert_eq!(t.ack(4), Err(ContextError::Unknown(4)));
        t.close(2);
        assert!(t.binding(2).is_none());
    }

    #[test]
    fn uncompressed_datagram_carries_the_address_inline() {
        let mut t = ContextTable::new();
        t.register(CompressionAssign {
            context_id: 2,
            binding: Binding::Uncompressed,
        })
        .unwrap();
        t.ack(2).unwrap();

        let remote = v4("198.51.100.7:9000");
        let wire = t.encode_datagram(2, remote, b"inner-quic").unwrap();
        let dg = t.decode_datagram(wire).unwrap();
        assert_eq!(dg.context_id, 2);
        assert_eq!(dg.remote, remote);
        assert_eq!(&dg.payload[..], b"inner-quic");

        // v6 too.
        let r6 = v6("[2001:db8::9]:9000");
        let dg = t
            .decode_datagram(t.encode_datagram(2, r6, b"x").unwrap())
            .unwrap();
        assert_eq!(dg.remote, r6);
    }

    #[test]
    fn compressed_datagram_omits_the_address() {
        let mut t = ContextTable::new();
        let remote = v4("192.0.2.45:54321");
        t.register(CompressionAssign {
            context_id: 4,
            binding: Binding::Compressed(remote),
        })
        .unwrap();
        t.ack(4).unwrap();

        let wire = t.encode_datagram(4, remote, b"payload").unwrap();
        // Only the context-id varint (1 byte) precedes the payload.
        assert_eq!(wire.len(), 1 + b"payload".len());
        let dg = t.decode_datagram(wire).unwrap();
        assert_eq!(dg.remote, remote, "address comes from the context");
        assert_eq!(&dg.payload[..], b"payload");
    }

    #[test]
    fn datagram_on_unknown_context_is_rejected() {
        let t = ContextTable::new();
        let mut buf = BytesMut::new();
        write_varint(&mut buf, 8).unwrap();
        buf.extend_from_slice(b"data");
        assert_eq!(
            t.decode_datagram(buf.freeze()),
            Err(ContextError::Unknown(8))
        );
    }

    #[test]
    fn assign_rejects_trailing_bytes() {
        let mut body = BytesMut::new();
        write_varint(&mut body, 2).unwrap();
        body.put_u8(0); // uncompressed
        body.put_u8(0xff); // stray
        assert!(matches!(
            CompressionAssign::decode(body.freeze()),
            Err(DecodeError::TrailingBytes(1))
        ));
    }
}
