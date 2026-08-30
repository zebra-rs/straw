pub mod address_assign;
pub mod address_request;
pub mod codec;
pub mod route_advertisement;

use std::net::IpAddr;

use bytes::{Buf, Bytes, BytesMut};

use crate::error::DecodeError;

use self::codec::{read_varint, write_varint};

/// Capsule type identifiers per RFC 9484 §12.4.
pub const CAPSULE_ADDRESS_ASSIGN: u64 = 0x01;
pub const CAPSULE_ADDRESS_REQUEST: u64 = 0x02;
pub const CAPSULE_ROUTE_ADVERTISEMENT: u64 = 0x03;

/// A decoded capsule.
#[derive(Debug, Clone)]
pub enum Capsule {
    AddressAssign(AddressAssign),
    AddressRequest(AddressRequest),
    RouteAdvertisement(RouteAdvertisement),
    Unknown { type_id: u64, data: Bytes },
}

/// ADDRESS_ASSIGN capsule (§4.7.1).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressAssign {
    pub assigned_addresses: Vec<AssignedAddress>,
}

/// A single assigned address within an ADDRESS_ASSIGN capsule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AssignedAddress {
    /// VarInt: 0 if unprompted, otherwise matches the request.
    pub request_id: u64,
    /// 4 or 6.
    pub ip_version: u8,
    /// The assigned IP address.
    pub ip_address: IpAddr,
    /// Prefix length: 0..32 for IPv4, 0..128 for IPv6.
    pub prefix_length: u8,
}

/// ADDRESS_REQUEST capsule (§4.7.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressRequest {
    pub requested_addresses: Vec<RequestedAddress>,
}

/// A single requested address within an ADDRESS_REQUEST capsule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestedAddress {
    /// VarInt: MUST be nonzero, unique per endpoint.
    pub request_id: u64,
    /// 4 or 6.
    pub ip_version: u8,
    /// The requested IP address. 0.0.0.0 or :: means "server picks".
    pub ip_address: IpAddr,
    /// Prefix length: 0..32 for IPv4, 0..128 for IPv6.
    pub prefix_length: u8,
}

/// ROUTE_ADVERTISEMENT capsule (§4.7.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteAdvertisement {
    pub ip_address_ranges: Vec<IpAddressRange>,
}

/// A single IP address range within a ROUTE_ADVERTISEMENT.
/// Ordering rules (§4.7.3): sorted by (ip_version, ip_protocol, start_ip).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct IpAddressRange {
    pub ip_version: u8,
    pub start_ip: IpAddr,
    pub end_ip: IpAddr,
    pub ip_protocol: u8,
}

/// Widen an address to a u128 for in-version numeric comparison.
fn ip_key(addr: &IpAddr) -> u128 {
    match addr {
        IpAddr::V4(a) => u32::from(*a) as u128,
        IpAddr::V6(a) => u128::from(*a),
    }
}

impl IpAddressRange {
    /// The full range covered by a prefix, for the given protocol scope
    /// (0 = all protocols).
    pub fn from_net(net: ipnet::IpNet, ip_protocol: u8) -> Self {
        Self {
            ip_version: if net.addr().is_ipv4() { 4 } else { 6 },
            start_ip: net.network(),
            end_ip: net.broadcast(),
            ip_protocol,
        }
    }

    /// Whether a packet to `addr` with IP protocol `proto` falls inside
    /// this range (RFC 9484 §4.7.3 matching semantics).
    ///
    /// Per §4.6/§4.7.3, "ICMP traffic is always allowed, regardless of the
    /// value of this field" — the exemption applies to the protocol
    /// dimension only; the address must still match.
    pub fn contains(&self, addr: &IpAddr, proto: u8) -> bool {
        let (version_matches, icmp_proto) = match addr {
            IpAddr::V4(_) => (self.ip_version == 4, 1),
            IpAddr::V6(_) => (self.ip_version == 6, 58),
        };
        version_matches
            && (self.ip_protocol == 0 || self.ip_protocol == proto || proto == icmp_proto)
            && (ip_key(&self.start_ip)..=ip_key(&self.end_ip)).contains(&ip_key(addr))
    }
}

/// Sort ranges by (version, protocol, start) and coalesce overlapping or
/// adjacent ones — ROUTE_ADVERTISEMENT forbids overlaps (RFC 9484 §4.7.3).
pub fn merge_ranges(mut ranges: Vec<IpAddressRange>) -> Vec<IpAddressRange> {
    ranges.sort();
    let mut merged: Vec<IpAddressRange> = Vec::with_capacity(ranges.len());
    for range in ranges {
        if let Some(last) = merged.last_mut()
            && last.ip_version == range.ip_version
            && last.ip_protocol == range.ip_protocol
            && ip_key(&range.start_ip) <= ip_key(&last.end_ip).saturating_add(1)
        {
            if ip_key(&range.end_ip) > ip_key(&last.end_ip) {
                last.end_ip = range.end_ip;
            }
            continue;
        }
        merged.push(range);
    }
    merged
}

/// Decode a capsule from the buffer (type + length + payload envelope).
pub fn decode_capsule(buf: &mut impl Buf) -> Result<Capsule, DecodeError> {
    let capsule_type = read_varint(buf)?;
    let capsule_length = read_varint(buf)? as usize;

    if buf.remaining() < capsule_length {
        return Err(DecodeError::BufferTooShort {
            needed: capsule_length,
            available: buf.remaining(),
        });
    }

    let payload = buf.copy_to_bytes(capsule_length);

    match capsule_type {
        CAPSULE_ADDRESS_ASSIGN => Ok(Capsule::AddressAssign(AddressAssign::decode(&payload)?)),
        CAPSULE_ADDRESS_REQUEST => Ok(Capsule::AddressRequest(AddressRequest::decode(&payload)?)),
        CAPSULE_ROUTE_ADVERTISEMENT => Ok(Capsule::RouteAdvertisement(RouteAdvertisement::decode(
            &payload,
        )?)),
        other => Ok(Capsule::Unknown {
            type_id: other,
            data: payload,
        }),
    }
}

/// Accumulates stream bytes and yields complete capsules.
///
/// The capsule protocol runs on the request stream, where a capsule may
/// arrive split across arbitrary read chunks (or several per chunk). Push
/// every chunk in with [`CapsuleBuffer::push`], then drain complete capsules
/// with [`CapsuleBuffer::next_capsule`].
#[derive(Debug, Default)]
pub struct CapsuleBuffer {
    buf: BytesMut,
}

impl CapsuleBuffer {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append incoming stream bytes.
    pub fn push(&mut self, chunk: impl Buf) {
        let mut chunk = chunk;
        while chunk.has_remaining() {
            let piece = chunk.chunk();
            self.buf.extend_from_slice(piece);
            let len = piece.len();
            chunk.advance(len);
        }
    }

    /// Decode the next complete capsule, or `None` if more bytes are needed.
    ///
    /// An incomplete *envelope* (type/length varints or a partially received
    /// payload) waits for more data. A malformed payload inside a complete
    /// envelope is a hard error — waiting could never fix it.
    pub fn next_capsule(&mut self) -> Result<Option<Capsule>, DecodeError> {
        // Parse the envelope on a peek view so nothing is consumed until the
        // whole capsule is present.
        let mut view = &self.buf[..];
        let Ok(_capsule_type) = read_varint(&mut view) else {
            return Ok(None);
        };
        let Ok(capsule_length) = read_varint(&mut view) else {
            return Ok(None);
        };
        if (view.remaining() as u64) < capsule_length {
            return Ok(None);
        }

        // The full capsule is buffered: any decode failure now is fatal.
        let capsule = decode_capsule(&mut self.buf)?;
        Ok(Some(capsule))
    }
}

/// Encode a capsule into the buffer (type + length + payload envelope).
pub fn encode_capsule(capsule: &Capsule, buf: &mut BytesMut) {
    match capsule {
        Capsule::AddressAssign(c) => c.encode(buf),
        Capsule::AddressRequest(c) => c.encode(buf),
        Capsule::RouteAdvertisement(c) => c.encode(buf),
        Capsule::Unknown { type_id, data } => {
            write_varint(buf, *type_id).unwrap();
            write_varint(buf, data.len() as u64).unwrap();
            buf.extend_from_slice(data);
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use bytes::BytesMut;

    use super::*;

    #[test]
    fn test_decode_address_assign() {
        let original = AddressAssign {
            assigned_addresses: vec![AssignedAddress {
                request_id: 0,
                ip_version: 4,
                ip_address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                prefix_length: 32,
            }],
        };
        let mut buf = BytesMut::new();
        original.encode(&mut buf);

        let capsule = decode_capsule(&mut &buf[..]).unwrap();
        match capsule {
            Capsule::AddressAssign(c) => assert_eq!(c, original),
            _ => panic!("expected AddressAssign"),
        }
    }

    #[test]
    fn test_decode_address_request() {
        let original = AddressRequest {
            requested_addresses: vec![RequestedAddress {
                request_id: 1,
                ip_version: 4,
                ip_address: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                prefix_length: 32,
            }],
        };
        let mut buf = BytesMut::new();
        original.encode(&mut buf);

        let capsule = decode_capsule(&mut &buf[..]).unwrap();
        match capsule {
            Capsule::AddressRequest(c) => assert_eq!(c, original),
            _ => panic!("expected AddressRequest"),
        }
    }

    #[test]
    fn test_decode_route_advertisement() {
        let original = RouteAdvertisement {
            ip_address_ranges: vec![IpAddressRange {
                ip_version: 4,
                start_ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                end_ip: IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
                ip_protocol: 0,
            }],
        };
        let mut buf = BytesMut::new();
        original.encode(&mut buf);

        let capsule = decode_capsule(&mut &buf[..]).unwrap();
        match capsule {
            Capsule::RouteAdvertisement(c) => assert_eq!(c, original),
            _ => panic!("expected RouteAdvertisement"),
        }
    }

    #[test]
    fn test_decode_unknown_capsule() {
        let mut buf = BytesMut::new();
        write_varint(&mut buf, 0xff).unwrap(); // unknown type
        write_varint(&mut buf, 3).unwrap(); // length = 3
        buf.extend_from_slice(&[0xaa, 0xbb, 0xcc]); // payload

        let capsule = decode_capsule(&mut &buf[..]).unwrap();
        match capsule {
            Capsule::Unknown { type_id, data } => {
                assert_eq!(type_id, 0xff);
                assert_eq!(&data[..], &[0xaa, 0xbb, 0xcc]);
            }
            _ => panic!("expected Unknown"),
        }
    }

    #[test]
    fn test_decode_multiple_capsules() {
        let assign = AddressAssign {
            assigned_addresses: vec![AssignedAddress {
                request_id: 0,
                ip_version: 4,
                ip_address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                prefix_length: 32,
            }],
        };
        let route = RouteAdvertisement {
            ip_address_ranges: vec![IpAddressRange {
                ip_version: 4,
                start_ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                end_ip: IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
                ip_protocol: 0,
            }],
        };

        let mut buf = BytesMut::new();
        assign.encode(&mut buf);
        route.encode(&mut buf);

        let mut reader = &buf[..];
        let c1 = decode_capsule(&mut reader).unwrap();
        let c2 = decode_capsule(&mut reader).unwrap();
        assert_eq!(reader.remaining(), 0);

        assert!(matches!(c1, Capsule::AddressAssign(_)));
        assert!(matches!(c2, Capsule::RouteAdvertisement(_)));
    }

    #[test]
    fn test_encode_capsule_roundtrip() {
        let original = Capsule::AddressAssign(AddressAssign {
            assigned_addresses: vec![AssignedAddress {
                request_id: 5,
                ip_version: 6,
                ip_address: IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1)),
                prefix_length: 128,
            }],
        });
        let mut buf = BytesMut::new();
        encode_capsule(&original, &mut buf);

        let decoded = decode_capsule(&mut &buf[..]).unwrap();
        match (&original, &decoded) {
            (Capsule::AddressAssign(a), Capsule::AddressAssign(b)) => assert_eq!(a, b),
            _ => panic!("mismatch"),
        }
    }

    #[test]
    fn test_encode_unknown_capsule_roundtrip() {
        let original = Capsule::Unknown {
            type_id: 0x1234,
            data: Bytes::from_static(&[1, 2, 3, 4, 5]),
        };
        let mut buf = BytesMut::new();
        encode_capsule(&original, &mut buf);

        let decoded = decode_capsule(&mut &buf[..]).unwrap();
        match decoded {
            Capsule::Unknown { type_id, data } => {
                assert_eq!(type_id, 0x1234);
                assert_eq!(&data[..], &[1, 2, 3, 4, 5]);
            }
            _ => panic!("expected Unknown"),
        }
    }

    #[test]
    fn test_range_from_net_and_contains() {
        let net: ipnet::IpNet = "192.168.1.0/24".parse().unwrap();
        let range = IpAddressRange::from_net(net, 0);
        assert_eq!(range.start_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 0)));
        assert_eq!(range.end_ip, IpAddr::V4(Ipv4Addr::new(192, 168, 1, 255)));

        assert!(range.contains(&"192.168.1.7".parse().unwrap(), 6));
        assert!(!range.contains(&"192.168.2.7".parse().unwrap(), 6));
        assert!(!range.contains(&"::1".parse().unwrap(), 6), "wrong version");

        let udp_only = IpAddressRange {
            ip_protocol: 17,
            ..range
        };
        assert!(udp_only.contains(&"192.168.1.7".parse().unwrap(), 17));
        assert!(!udp_only.contains(&"192.168.1.7".parse().unwrap(), 6));
        // RFC 9484: ICMP is always allowed regardless of the protocol
        // scope — but only for in-range addresses.
        assert!(udp_only.contains(&"192.168.1.7".parse().unwrap(), 1));
        assert!(!udp_only.contains(&"192.168.2.7".parse().unwrap(), 1));

        let v6_udp = IpAddressRange::from_net("fd00::/64".parse().unwrap(), 17);
        assert!(v6_udp.contains(&"fd00::7".parse().unwrap(), 58), "ICMPv6");
        assert!(!v6_udp.contains(&"fd00::7".parse().unwrap(), 6));
    }

    #[test]
    fn test_merge_ranges_coalesces_overlaps() {
        let a = IpAddressRange::from_net("10.0.0.0/24".parse().unwrap(), 0);
        let b = IpAddressRange::from_net("10.0.1.0/24".parse().unwrap(), 0); // adjacent
        let c = IpAddressRange::from_net("10.0.0.128/25".parse().unwrap(), 0); // inside a
        let d = IpAddressRange::from_net("172.16.0.0/16".parse().unwrap(), 0); // separate
        let e = IpAddressRange::from_net("fd00::/64".parse().unwrap(), 0); // v6

        let merged = merge_ranges(vec![d.clone(), c, b, a, e.clone()]);
        assert_eq!(merged.len(), 3);
        assert_eq!(merged[0].start_ip, "10.0.0.0".parse::<IpAddr>().unwrap());
        assert_eq!(merged[0].end_ip, "10.0.1.255".parse::<IpAddr>().unwrap());
        assert_eq!(merged[1], d);
        assert_eq!(merged[2], e);

        // Merged output is valid for a ROUTE_ADVERTISEMENT round trip.
        let ra = RouteAdvertisement {
            ip_address_ranges: merged,
        };
        let mut buf = BytesMut::new();
        ra.encode(&mut buf);
        assert!(matches!(
            decode_capsule(&mut &buf[..]).unwrap(),
            Capsule::RouteAdvertisement(_)
        ));
    }

    #[test]
    fn test_capsule_buffer_split_across_chunks() {
        let assign = AddressAssign {
            assigned_addresses: vec![AssignedAddress {
                request_id: 0,
                ip_version: 4,
                ip_address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                prefix_length: 32,
            }],
        };
        let route = RouteAdvertisement {
            ip_address_ranges: vec![IpAddressRange {
                ip_version: 4,
                start_ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
                end_ip: IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
                ip_protocol: 0,
            }],
        };
        let mut wire = BytesMut::new();
        assign.encode(&mut wire);
        route.encode(&mut wire);

        let mut cb = CapsuleBuffer::new();
        // Feed one byte at a time; capsules must pop out exactly twice.
        let mut decoded = Vec::new();
        for byte in wire.iter() {
            cb.push(&[*byte][..]);
            while let Some(c) = cb.next_capsule().unwrap() {
                decoded.push(c);
            }
        }
        assert_eq!(decoded.len(), 2);
        assert!(matches!(decoded[0], Capsule::AddressAssign(_)));
        assert!(matches!(decoded[1], Capsule::RouteAdvertisement(_)));
        // Buffer fully drained.
        assert!(cb.next_capsule().unwrap().is_none());
    }

    #[test]
    fn test_decode_truncated_capsule() {
        let mut buf = BytesMut::new();
        write_varint(&mut buf, 0x01).unwrap(); // type
        write_varint(&mut buf, 100).unwrap(); // length = 100 but no payload

        let result = decode_capsule(&mut &buf[..]);
        assert!(matches!(result, Err(DecodeError::BufferTooShort { .. })));
    }
}
