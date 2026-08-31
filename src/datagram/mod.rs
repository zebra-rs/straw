//! HTTP Datagram handling (RFC 9297) for CONNECT-IP (RFC 9484 §6).
//!
//! Over QUIC, an HTTP Datagram rides a QUIC DATAGRAM frame:
//!
//! ```text
//! QUIC DATAGRAM Payload {
//!   Quarter Stream ID (i),      // request stream ID / 4
//!   HTTP Datagram Payload (..), // for connect-ip: Context ID + IP packet
//! }
//!
//! HTTP Datagram Payload {
//!   Context ID (i),             // 0 = full IP packet
//!   Payload (..),
//! }
//! ```

pub mod context;

/// A QUIC connection that can send HTTP Datagrams.
///
/// This object-safe seam lets the CONNECT-IP data plane — the forwarding
/// engine's [`SessionSink`](crate::forwarding::SessionSink) and the client's
/// [`PacketSender`](crate::client::PacketSender) — run over either the proxy's
/// upstream-quinn connection or a strawcat peer's noq connection, without
/// making [`ForwardingEngine`](crate::forwarding::ForwardingEngine) generic.
/// Only the *send* side is abstracted; datagram receive/demux is transport-
/// specific and stays concrete on each path.
pub trait DatagramConn: Send + Sync + std::fmt::Debug {
    /// Queue one datagram for sending (best-effort, like `quinn`/`noq`).
    fn send_datagram(&self, data: Bytes) -> Result<(), crate::error::ProxyError>;
    /// The largest datagram that currently fits, or `None` before the peer
    /// enables QUIC DATAGRAMs.
    fn max_datagram_size(&self) -> Option<usize>;
    /// Close the connection with an application error code and reason.
    fn close(&self, code: u64, reason: &[u8]);
}

impl DatagramConn for quinn::Connection {
    fn send_datagram(&self, data: Bytes) -> Result<(), crate::error::ProxyError> {
        quinn::Connection::send_datagram(self, data)?;
        Ok(())
    }
    fn max_datagram_size(&self) -> Option<usize> {
        quinn::Connection::max_datagram_size(self)
    }
    fn close(&self, code: u64, reason: &[u8]) {
        quinn::Connection::close(self, quinn::VarInt::from_u64(code).unwrap_or(quinn::VarInt::MAX), reason);
    }
}

impl DatagramConn for noq::Connection {
    fn send_datagram(&self, data: Bytes) -> Result<(), crate::error::ProxyError> {
        noq::Connection::send_datagram(self, data)?;
        Ok(())
    }
    fn max_datagram_size(&self) -> Option<usize> {
        noq::Connection::max_datagram_size(self)
    }
    fn close(&self, code: u64, reason: &[u8]) {
        noq::Connection::close(self, noq::VarInt::from_u64(code).unwrap_or(noq::VarInt::MAX), reason);
    }
}

use bytes::{Buf, Bytes, BytesMut};

use crate::capsule::codec::{read_varint, varint_len, write_varint};
use crate::error::DecodeError;

/// Context ID 0: payload is a full IP packet (RFC 9484 §6).
pub const CONTEXT_ID_IP_PACKET: u64 = 0;

/// A stream-scoped HTTP Datagram payload for IP proxying.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IpProxyingDatagram {
    /// VarInt context ID; 0 means the payload is a full IP packet.
    pub context_id: u64,
    /// Full IP packet when `context_id == 0`.
    pub payload: Bytes,
}

impl IpProxyingDatagram {
    /// Wrap an IP packet with context ID 0.
    pub fn ip_packet(packet: impl Into<Bytes>) -> Self {
        Self {
            context_id: CONTEXT_ID_IP_PACKET,
            payload: packet.into(),
        }
    }

    /// Decode from an HTTP Datagram payload (after the Quarter Stream ID).
    pub fn decode(buf: &mut impl Buf) -> Result<Self, DecodeError> {
        let context_id = read_varint(buf)?;
        let payload = buf.copy_to_bytes(buf.remaining());
        Ok(Self {
            context_id,
            payload,
        })
    }

    /// Encode into an HTTP Datagram payload (without the Quarter Stream ID).
    pub fn encode(&self, buf: &mut BytesMut) {
        write_varint(buf, self.context_id).expect("context id fits varint");
        buf.extend_from_slice(&self.payload);
    }

    /// Encoded length (without the Quarter Stream ID).
    pub fn encoded_len(&self) -> usize {
        varint_len(self.context_id).expect("context id fits varint") + self.payload.len()
    }
}

/// Bytes of framing a QUIC DATAGRAM adds around an IP packet on `qsid`:
/// the Quarter Stream ID and the context ID (RFC 9297 §2.1, RFC 9484 §6).
pub fn datagram_overhead(qsid: u64) -> usize {
    // Both lengths are bounded, so the fallbacks are the widest encoding
    // rather than a real possibility.
    varint_len(qsid).unwrap_or(8) + varint_len(CONTEXT_ID_IP_PACKET).unwrap_or(8)
}

/// Largest IP packet that fits in a QUIC DATAGRAM of `max_datagram_size`
/// bytes on `qsid` — the usable tunnel MTU (RFC 9484 §7.2). `None` when the
/// datagram cannot even hold the framing.
pub fn max_ip_packet_size(max_datagram_size: usize, qsid: u64) -> Option<usize> {
    max_datagram_size.checked_sub(datagram_overhead(qsid))
}

/// Compute the Quarter Stream ID for a request stream ID (RFC 9297 §2.1).
pub fn quarter_stream_id(stream_id: u64) -> u64 {
    debug_assert_eq!(
        stream_id % 4,
        0,
        "HTTP Datagrams flow only on client-initiated bidirectional streams"
    );
    stream_id / 4
}

/// Encode a full QUIC DATAGRAM payload: Quarter Stream ID + datagram.
pub fn encode_quic_datagram(qsid: u64, datagram: &IpProxyingDatagram) -> Bytes {
    let cap = varint_len(qsid).expect("qsid fits varint") + datagram.encoded_len();
    let mut buf = BytesMut::with_capacity(cap);
    write_varint(&mut buf, qsid).expect("qsid fits varint");
    datagram.encode(&mut buf);
    buf.freeze()
}

/// Decode a full QUIC DATAGRAM payload into (Quarter Stream ID, datagram).
pub fn decode_quic_datagram(mut buf: Bytes) -> Result<(u64, IpProxyingDatagram), DecodeError> {
    let qsid = read_varint(&mut buf)?;
    let datagram = IpProxyingDatagram::decode(&mut buf)?;
    Ok((qsid, datagram))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_ip_packet_datagram() {
        let packet = Bytes::from_static(&[0x45, 0x00, 0x00, 0x14, 1, 2, 3, 4]);
        let dg = IpProxyingDatagram::ip_packet(packet.clone());

        let wire = encode_quic_datagram(quarter_stream_id(0), &dg);
        let (qsid, decoded) = decode_quic_datagram(wire).unwrap();

        assert_eq!(qsid, 0);
        assert_eq!(decoded.context_id, CONTEXT_ID_IP_PACKET);
        assert_eq!(decoded.payload, packet);
    }

    #[test]
    fn roundtrip_nonzero_stream_and_context() {
        let dg = IpProxyingDatagram {
            context_id: 42,
            payload: Bytes::from_static(b"opaque"),
        };
        // Stream ID 16 -> QSID 4.
        let wire = encode_quic_datagram(quarter_stream_id(16), &dg);
        let (qsid, decoded) = decode_quic_datagram(wire).unwrap();

        assert_eq!(qsid, 4);
        assert_eq!(decoded, dg);
    }

    #[test]
    fn decode_empty_payload() {
        // A datagram carrying only a context ID has an empty payload.
        let mut buf = BytesMut::new();
        write_varint(&mut buf, 7).unwrap(); // qsid
        write_varint(&mut buf, 0).unwrap(); // context id
        let (qsid, dg) = decode_quic_datagram(buf.freeze()).unwrap();
        assert_eq!(qsid, 7);
        assert_eq!(dg.context_id, 0);
        assert!(dg.payload.is_empty());
    }

    #[test]
    fn decode_truncated_fails() {
        let result = decode_quic_datagram(Bytes::new());
        assert!(result.is_err());
    }

    #[test]
    fn overhead_and_usable_size_track_the_varint_widths() {
        // qsid 0 and context 0 are one byte each.
        assert_eq!(datagram_overhead(0), 2);
        assert_eq!(max_ip_packet_size(1200, 0), Some(1198));
        // A qsid past 63 needs two bytes, past 16383 needs four.
        assert_eq!(datagram_overhead(64), 3);
        assert_eq!(datagram_overhead(16384), 5);
        assert_eq!(max_ip_packet_size(1200, 16384), Some(1195));
    }

    #[test]
    fn usable_size_is_none_when_framing_does_not_fit() {
        assert_eq!(max_ip_packet_size(1, 0), None);
        // Exactly the framing leaves room for a zero-length packet.
        assert_eq!(max_ip_packet_size(2, 0), Some(0));
    }

    #[test]
    fn encoded_len_matches() {
        let dg = IpProxyingDatagram {
            context_id: 16384, // needs a 4-byte varint
            payload: Bytes::from_static(&[0; 10]),
        };
        let mut buf = BytesMut::new();
        dg.encode(&mut buf);
        assert_eq!(buf.len(), dg.encoded_len());
    }
}
