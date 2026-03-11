use std::net::IpAddr;

use bytes::{Buf, BufMut, BytesMut};

use crate::error::DecodeError;

use super::address_assign::{decode_ip_address, validate_prefix_length};
use super::codec::{read_varint, varint_len, write_varint};
use super::{AddressRequest, RequestedAddress};

impl AddressRequest {
    /// Decode an ADDRESS_REQUEST capsule payload (without the type/length envelope).
    pub fn decode(mut payload: &[u8]) -> Result<Self, DecodeError> {
        let mut requested_addresses = Vec::new();

        while payload.has_remaining() {
            let addr = decode_requested_address(&mut payload)?;
            requested_addresses.push(addr);
        }

        if requested_addresses.is_empty() {
            return Err(DecodeError::Underflow);
        }

        Ok(AddressRequest {
            requested_addresses,
        })
    }

    /// Encode this ADDRESS_REQUEST as a complete capsule (type + length + payload).
    pub fn encode(&self, buf: &mut BytesMut) {
        let payload_len = self.payload_len();
        write_varint(buf, super::CAPSULE_ADDRESS_REQUEST).unwrap();
        write_varint(buf, payload_len as u64).unwrap();
        self.encode_payload(buf);
    }

    /// Encode only the payload (no type/length envelope).
    pub fn encode_payload(&self, buf: &mut BytesMut) {
        for addr in &self.requested_addresses {
            encode_requested_address(addr, buf);
        }
    }

    fn payload_len(&self) -> usize {
        self.requested_addresses
            .iter()
            .map(requested_address_len)
            .sum()
    }
}

fn decode_requested_address(buf: &mut &[u8]) -> Result<RequestedAddress, DecodeError> {
    let request_id = read_varint(buf)?;

    if request_id == 0 {
        return Err(DecodeError::InvalidVarInt);
    }

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

    Ok(RequestedAddress {
        request_id,
        ip_version,
        ip_address,
        prefix_length,
    })
}

fn encode_requested_address(addr: &RequestedAddress, buf: &mut BytesMut) {
    write_varint(buf, addr.request_id).unwrap();
    buf.put_u8(addr.ip_version);
    match addr.ip_address {
        IpAddr::V4(v4) => buf.put_slice(&v4.octets()),
        IpAddr::V6(v6) => buf.put_slice(&v6.octets()),
    }
    buf.put_u8(addr.prefix_length);
}

fn requested_address_len(addr: &RequestedAddress) -> usize {
    let ip_len = if addr.ip_version == 4 { 4 } else { 16 };
    varint_len(addr.request_id).unwrap() + 1 + ip_len + 1
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    fn make_v4_req(request_id: u64, addr: [u8; 4], prefix_length: u8) -> RequestedAddress {
        RequestedAddress {
            request_id,
            ip_version: 4,
            ip_address: IpAddr::V4(Ipv4Addr::from(addr)),
            prefix_length,
        }
    }

    fn make_v6_req(request_id: u64, addr: [u8; 16], prefix_length: u8) -> RequestedAddress {
        RequestedAddress {
            request_id,
            ip_version: 6,
            ip_address: IpAddr::V6(Ipv6Addr::from(addr)),
            prefix_length,
        }
    }

    #[test]
    fn test_roundtrip_single_v4() {
        let original = AddressRequest {
            requested_addresses: vec![make_v4_req(1, [10, 0, 0, 1], 32)],
        };
        let mut buf = BytesMut::new();
        original.encode_payload(&mut buf);
        let decoded = AddressRequest::decode(&buf).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_roundtrip_single_v6() {
        let mut addr = [0u8; 16];
        addr[0] = 0xfd;
        let original = AddressRequest {
            requested_addresses: vec![make_v6_req(1, addr, 128)],
        };
        let mut buf = BytesMut::new();
        original.encode_payload(&mut buf);
        let decoded = AddressRequest::decode(&buf).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_roundtrip_wildcard_address() {
        // 0.0.0.0 means "server picks for me"
        let original = AddressRequest {
            requested_addresses: vec![make_v4_req(1, [0, 0, 0, 0], 32)],
        };
        let mut buf = BytesMut::new();
        original.encode_payload(&mut buf);
        let decoded = AddressRequest::decode(&buf).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_roundtrip_multiple() {
        let mut v6_addr = [0u8; 16];
        v6_addr[0] = 0x20;
        v6_addr[1] = 0x01;
        let original = AddressRequest {
            requested_addresses: vec![
                make_v4_req(1, [10, 0, 0, 0], 24),
                make_v6_req(2, v6_addr, 64),
                make_v4_req(3, [0, 0, 0, 0], 32),
            ],
        };
        let mut buf = BytesMut::new();
        original.encode_payload(&mut buf);
        let decoded = AddressRequest::decode(&buf).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_reject_request_id_zero() {
        let mut buf = BytesMut::new();
        write_varint(&mut buf, 0).unwrap(); // request_id = 0 (invalid)
        buf.put_u8(4);
        buf.put_slice(&[10, 0, 0, 1]);
        buf.put_u8(32);

        let result = AddressRequest::decode(&buf);
        assert!(matches!(result, Err(DecodeError::InvalidVarInt)));
    }

    #[test]
    fn test_reject_empty_list() {
        let buf = BytesMut::new();
        let result = AddressRequest::decode(&buf);
        assert!(matches!(result, Err(DecodeError::Underflow)));
    }

    #[test]
    fn test_full_capsule_encode() {
        let original = AddressRequest {
            requested_addresses: vec![make_v4_req(1, [10, 0, 0, 1], 32)],
        };
        let mut buf = BytesMut::new();
        original.encode(&mut buf);

        // First byte should be capsule type 0x02
        assert_eq!(buf[0], 0x02);
        // payload = varint(1)=1 + ip_version=1 + ipv4=4 + prefix=1 = 7
        assert_eq!(buf[1], 7);
    }

    #[test]
    fn test_invalid_ip_version() {
        let mut buf = BytesMut::new();
        write_varint(&mut buf, 1).unwrap();
        buf.put_u8(5); // invalid
        buf.put_slice(&[0u8; 4]);
        buf.put_u8(32);

        let result = AddressRequest::decode(&buf);
        assert!(matches!(result, Err(DecodeError::InvalidIpVersion(5))));
    }

    #[test]
    fn test_invalid_prefix_length() {
        let mut buf = BytesMut::new();
        write_varint(&mut buf, 1).unwrap();
        buf.put_u8(4);
        buf.put_slice(&[10, 0, 0, 1]);
        buf.put_u8(33); // > 32

        let result = AddressRequest::decode(&buf);
        assert!(matches!(
            result,
            Err(DecodeError::InvalidPrefixLength { .. })
        ));
    }

    #[test]
    fn test_truncated_payload() {
        let mut buf = BytesMut::new();
        write_varint(&mut buf, 1).unwrap();
        buf.put_u8(4);
        // Missing IPv4 address bytes

        let result = AddressRequest::decode(&buf);
        assert!(matches!(result, Err(DecodeError::BufferTooShort { .. })));
    }
}
