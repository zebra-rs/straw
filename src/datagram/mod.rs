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
