use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::{Buf, BufMut, BytesMut};

use crate::error::DecodeError;

use super::codec::{read_varint, varint_len, write_varint};
use super::{AddressAssign, AssignedAddress};

impl AddressAssign {
    /// Decode an ADDRESS_ASSIGN capsule payload (without the type/length envelope).
    pub fn decode(mut payload: &[u8]) -> Result<Self, DecodeError> {
        let mut assigned_addresses = Vec::new();

        while payload.has_remaining() {
            let addr = decode_assigned_address(&mut payload)?;
            assigned_addresses.push(addr);
        }

        Ok(AddressAssign { assigned_addresses })
    }

    /// Encode this ADDRESS_ASSIGN as a complete capsule (type + length + payload).
    pub fn encode(&self, buf: &mut BytesMut) {
        let payload_len = self.payload_len();
        write_varint(buf, super::CAPSULE_ADDRESS_ASSIGN).unwrap();
        write_varint(buf, payload_len as u64).unwrap();
        for addr in &self.assigned_addresses {
            encode_assigned_address(addr, buf);
        }
    }

    /// Encode only the payload (no type/length envelope).
    pub fn encode_payload(&self, buf: &mut BytesMut) {
        for addr in &self.assigned_addresses {
            encode_assigned_address(addr, buf);
        }
    }

    fn payload_len(&self) -> usize {
        self.assigned_addresses
            .iter()
            .map(assigned_address_len)
            .sum()
    }
}

fn decode_assigned_address(buf: &mut &[u8]) -> Result<AssignedAddress, DecodeError> {
    let request_id = read_varint(buf)?;

    if !buf.has_remaining() {
        return Err(DecodeError::Underflow);
    }
    let ip_version = buf.get_u8();

    let ip_address = decode_ip_address(buf, ip_version)?;

    if !buf.has_remaining() {
        return Err(DecodeError::Underflow);
    }
    let prefix_length = buf.get_u8();

    validate_prefix_length(ip_version, prefix_length)?;

    Ok(AssignedAddress {
        request_id,
        ip_version,
        ip_address,
        prefix_length,
    })
}

fn encode_assigned_address(addr: &AssignedAddress, buf: &mut BytesMut) {
    write_varint(buf, addr.request_id).unwrap();
    buf.put_u8(addr.ip_version);
    match addr.ip_address {
        IpAddr::V4(v4) => buf.put_slice(&v4.octets()),
        IpAddr::V6(v6) => buf.put_slice(&v6.octets()),
    }
    buf.put_u8(addr.prefix_length);
}

fn assigned_address_len(addr: &AssignedAddress) -> usize {
    let ip_len = if addr.ip_version == 4 { 4 } else { 16 };
    // request_id (VarInt) + ip_version (1) + ip_address (4 or 16) + prefix_length (1)
    varint_len(addr.request_id).unwrap() + 1 + ip_len + 1
}

/// Decode an IP address from the buffer based on the version byte.
pub(crate) fn decode_ip_address(buf: &mut &[u8], ip_version: u8) -> Result<IpAddr, DecodeError> {
    match ip_version {
        4 => {
            if buf.remaining() < 4 {
                return Err(DecodeError::BufferTooShort {
                    needed: 4,
                    available: buf.remaining(),
                });
            }
            let mut octets = [0u8; 4];
            buf.copy_to_slice(&mut octets);
            Ok(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        6 => {
            if buf.remaining() < 16 {
                return Err(DecodeError::BufferTooShort {
                    needed: 16,
                    available: buf.remaining(),
                });
            }
            let mut octets = [0u8; 16];
            buf.copy_to_slice(&mut octets);
            Ok(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => Err(DecodeError::InvalidIpVersion(ip_version)),
    }
}

/// Validate that a prefix length is valid for the given IP version.
pub(crate) fn validate_prefix_length(ip_version: u8, prefix_len: u8) -> Result<(), DecodeError> {
    let max = match ip_version {
        4 => 32,
        6 => 128,
        _ => return Err(DecodeError::InvalidIpVersion(ip_version)),
    };
    if prefix_len > max {
        return Err(DecodeError::InvalidPrefixLength {
            ip_version,
            prefix_len,
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_v4_addr(request_id: u64, addr: [u8; 4], prefix_length: u8) -> AssignedAddress {
        AssignedAddress {
            request_id,
            ip_version: 4,
            ip_address: IpAddr::V4(Ipv4Addr::from(addr)),
            prefix_length,
        }
    }

    fn make_v6_addr(request_id: u64, addr: [u8; 16], prefix_length: u8) -> AssignedAddress {
        AssignedAddress {
            request_id,
            ip_version: 6,
            ip_address: IpAddr::V6(Ipv6Addr::from(addr)),
            prefix_length,
        }
    }

    #[test]
    fn test_roundtrip_empty() {
        let original = AddressAssign {
            assigned_addresses: vec![],
        };
        let mut buf = BytesMut::new();
        original.encode_payload(&mut buf);
        assert!(buf.is_empty());
        let decoded = AddressAssign::decode(&buf).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_roundtrip_single_v4() {
        let original = AddressAssign {
            assigned_addresses: vec![make_v4_addr(0, [192, 0, 2, 42], 32)],
        };
        let mut buf = BytesMut::new();
        original.encode_payload(&mut buf);
        let decoded = AddressAssign::decode(&buf).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_roundtrip_single_v6() {
        let mut addr = [0u8; 16];
        addr[0] = 0xfd;
        addr[15] = 0x01;
        let original = AddressAssign {
            assigned_addresses: vec![make_v6_addr(5, addr, 128)],
        };
        let mut buf = BytesMut::new();
        original.encode_payload(&mut buf);
        let decoded = AddressAssign::decode(&buf).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_roundtrip_mixed_v4_v6() {
        let mut v6_addr = [0u8; 16];
        v6_addr[0] = 0x20;
        v6_addr[1] = 0x01;
        let original = AddressAssign {
            assigned_addresses: vec![
                make_v4_addr(0, [10, 0, 0, 1], 24),
                make_v6_addr(1, v6_addr, 64),
                make_v4_addr(2, [172, 16, 0, 1], 16),
            ],
        };
        let mut buf = BytesMut::new();
        original.encode_payload(&mut buf);
        let decoded = AddressAssign::decode(&buf).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_roundtrip_unprompted_and_requested() {
        let original = AddressAssign {
            assigned_addresses: vec![
                make_v4_addr(0, [10, 100, 0, 1], 32), // unprompted (request_id=0)
                make_v4_addr(42, [10, 100, 0, 2], 32), // in response to request 42
            ],
        };
        let mut buf = BytesMut::new();
        original.encode_payload(&mut buf);
        let decoded = AddressAssign::decode(&buf).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_roundtrip_large_request_id() {
        // request_id that requires multi-byte VarInt encoding
        let original = AddressAssign {
            assigned_addresses: vec![make_v4_addr(100_000, [10, 0, 0, 1], 32)],
        };
        let mut buf = BytesMut::new();
        original.encode_payload(&mut buf);
        let decoded = AddressAssign::decode(&buf).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_full_capsule_encode() {
        let original = AddressAssign {
            assigned_addresses: vec![make_v4_addr(0, [192, 0, 2, 42], 32)],
        };
        let mut buf = BytesMut::new();
        original.encode(&mut buf);

        // First byte should be capsule type 0x01
        assert_eq!(buf[0], 0x01);
        // Second byte is payload length (VarInt)
        // payload = varint(0)=1 + ip_version=1 + ipv4=4 + prefix=1 = 7
        assert_eq!(buf[1], 7);
    }

    #[test]
    fn test_invalid_ip_version() {
        // Craft a payload with ip_version=5
        let mut buf = BytesMut::new();
        write_varint(&mut buf, 0).unwrap(); // request_id
        buf.put_u8(5); // invalid ip_version
        buf.put_slice(&[0u8; 4]); // some bytes
        buf.put_u8(32);

        let result = AddressAssign::decode(&buf);
        assert!(matches!(result, Err(DecodeError::InvalidIpVersion(5))));
    }

    #[test]
    fn test_invalid_prefix_length_v4() {
        let mut buf = BytesMut::new();
        write_varint(&mut buf, 0).unwrap();
        buf.put_u8(4);
        buf.put_slice(&[10, 0, 0, 1]);
        buf.put_u8(33); // > 32 for IPv4

        let result = AddressAssign::decode(&buf);
        assert!(matches!(
            result,
            Err(DecodeError::InvalidPrefixLength {
                ip_version: 4,
                prefix_len: 33
            })
        ));
    }

    #[test]
    fn test_invalid_prefix_length_v6() {
        let mut buf = BytesMut::new();
        write_varint(&mut buf, 0).unwrap();
        buf.put_u8(6);
        buf.put_slice(&[0u8; 16]);
        buf.put_u8(129); // > 128 for IPv6

        let result = AddressAssign::decode(&buf);
        assert!(matches!(
            result,
            Err(DecodeError::InvalidPrefixLength {
                ip_version: 6,
                prefix_len: 129
            })
        ));
    }

    #[test]
    fn test_truncated_payload() {
        // Only request_id + ip_version, no IP address bytes
        let mut buf = BytesMut::new();
        write_varint(&mut buf, 0).unwrap();
        buf.put_u8(4);
        // Missing 4 bytes of IPv4 address

        let result = AddressAssign::decode(&buf);
        assert!(matches!(result, Err(DecodeError::BufferTooShort { .. })));
    }

    #[test]
    fn test_prefix_zero() {
        // prefix_length=0 is valid (default route)
        let original = AddressAssign {
            assigned_addresses: vec![make_v4_addr(0, [0, 0, 0, 0], 0)],
        };
        let mut buf = BytesMut::new();
        original.encode_payload(&mut buf);
        let decoded = AddressAssign::decode(&buf).unwrap();
        assert_eq!(original, decoded);
    }
}
