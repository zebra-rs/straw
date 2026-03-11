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
        CAPSULE_ADDRESS_ASSIGN => {
            Ok(Capsule::AddressAssign(AddressAssign::decode(&payload)?))
        }
        CAPSULE_ADDRESS_REQUEST => {
            Ok(Capsule::AddressRequest(AddressRequest::decode(&payload)?))
        }
        CAPSULE_ROUTE_ADVERTISEMENT => Ok(Capsule::RouteAdvertisement(
            RouteAdvertisement::decode(&payload)?,
        )),
        other => Ok(Capsule::Unknown {
            type_id: other,
            data: payload,
        }),
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
    fn test_decode_truncated_capsule() {
        let mut buf = BytesMut::new();
        write_varint(&mut buf, 0x01).unwrap(); // type
        write_varint(&mut buf, 100).unwrap(); // length = 100 but no payload

        let result = decode_capsule(&mut &buf[..]);
        assert!(matches!(result, Err(DecodeError::BufferTooShort { .. })));
    }
}
