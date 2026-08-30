use std::net::IpAddr;

use bytes::{Buf, BufMut, BytesMut};

use crate::error::DecodeError;

use super::address_assign::decode_ip_address;
use super::codec::write_varint;
use super::{IpAddressRange, RouteAdvertisement};

impl RouteAdvertisement {
    /// Decode a ROUTE_ADVERTISEMENT capsule payload (without the type/length envelope).
    pub fn decode(mut payload: &[u8]) -> Result<Self, DecodeError> {
        let mut ip_address_ranges = Vec::new();

        while payload.has_remaining() {
            let range = decode_ip_address_range(&mut payload)?;
            ip_address_ranges.push(range);
        }

        // Validate ordering: (ip_version, ip_protocol, start_ip)
        for window in ip_address_ranges.windows(2) {
            if window[0] >= window[1] {
                // The Ord derive on IpAddressRange gives us the right field ordering
                // since fields are declared as: ip_version, start_ip, end_ip, ip_protocol.
                // But the RFC requires ordering by (ip_version, ip_protocol, start_ip),
                // so we check manually.
                let a = &window[0];
                let b = &window[1];
                let a_key = (a.ip_version, a.ip_protocol, &a.start_ip);
                let b_key = (b.ip_version, b.ip_protocol, &b.start_ip);
                if a_key >= b_key {
                    return Err(DecodeError::InvalidVarInt); // reuse as ordering error
                }
            }
        }

        Ok(RouteAdvertisement { ip_address_ranges })
    }

    /// Encode this ROUTE_ADVERTISEMENT as a complete capsule (type + length + payload).
    /// Ranges are sorted before encoding to guarantee the ordering invariant.
    pub fn encode(&self, buf: &mut BytesMut) {
        let mut sorted = self.ip_address_ranges.clone();
        sort_ranges(&mut sorted);

        let payload_len = sorted.iter().map(ip_address_range_len).sum::<usize>();
        write_varint(buf, super::CAPSULE_ROUTE_ADVERTISEMENT).unwrap();
        write_varint(buf, payload_len as u64).unwrap();
        for range in &sorted {
            encode_ip_address_range(range, buf);
        }
    }

    /// Encode only the payload (no type/length envelope).
    /// Ranges are sorted before encoding.
    pub fn encode_payload(&self, buf: &mut BytesMut) {
        let mut sorted = self.ip_address_ranges.clone();
        sort_ranges(&mut sorted);

        for range in &sorted {
            encode_ip_address_range(range, buf);
        }
    }
}

/// Sort ranges by (ip_version, ip_protocol, start_ip) per RFC 9484 §4.7.3.
fn sort_ranges(ranges: &mut [IpAddressRange]) {
    ranges.sort_by(|a, b| {
        a.ip_version
            .cmp(&b.ip_version)
            .then_with(|| a.ip_protocol.cmp(&b.ip_protocol))
            .then_with(|| cmp_ip_addr(&a.start_ip, &b.start_ip))
    });
}

fn cmp_ip_addr(a: &IpAddr, b: &IpAddr) -> std::cmp::Ordering {
    match (a, b) {
        (IpAddr::V4(a), IpAddr::V4(b)) => a.octets().cmp(&b.octets()),
        (IpAddr::V6(a), IpAddr::V6(b)) => a.octets().cmp(&b.octets()),
        (IpAddr::V4(_), IpAddr::V6(_)) => std::cmp::Ordering::Less,
        (IpAddr::V6(_), IpAddr::V4(_)) => std::cmp::Ordering::Greater,
    }
}

fn decode_ip_address_range(buf: &mut &[u8]) -> Result<IpAddressRange, DecodeError> {
    if !buf.has_remaining() {
        return Err(DecodeError::Underflow);
    }
    let ip_version = buf.get_u8();

    let start_ip = decode_ip_address(buf, ip_version)?;
    let end_ip = decode_ip_address(buf, ip_version)?;

    // Validate start <= end
    if cmp_ip_addr(&start_ip, &end_ip) == std::cmp::Ordering::Greater {
        return Err(DecodeError::InvalidVarInt); // reuse as range error
    }

    if !buf.has_remaining() {
        return Err(DecodeError::Underflow);
    }
    let ip_protocol = buf.get_u8();

    Ok(IpAddressRange {
        ip_version,
        start_ip,
        end_ip,
        ip_protocol,
    })
}

fn encode_ip_address_range(range: &IpAddressRange, buf: &mut BytesMut) {
    buf.put_u8(range.ip_version);
    match range.start_ip {
        IpAddr::V4(v4) => buf.put_slice(&v4.octets()),
        IpAddr::V6(v6) => buf.put_slice(&v6.octets()),
    }
    match range.end_ip {
        IpAddr::V4(v4) => buf.put_slice(&v4.octets()),
        IpAddr::V6(v6) => buf.put_slice(&v6.octets()),
    }
    buf.put_u8(range.ip_protocol);
}

fn ip_address_range_len(range: &IpAddressRange) -> usize {
    let ip_len = if range.ip_version == 4 { 4 } else { 16 };
    // ip_version (1) + start_ip (ip_len) + end_ip (ip_len) + ip_protocol (1)
    1 + ip_len + ip_len + 1
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    fn make_v4_range(start: [u8; 4], end: [u8; 4], ip_protocol: u8) -> IpAddressRange {
        IpAddressRange {
            ip_version: 4,
            start_ip: IpAddr::V4(Ipv4Addr::from(start)),
            end_ip: IpAddr::V4(Ipv4Addr::from(end)),
            ip_protocol,
        }
    }

    fn make_v6_range(start: [u8; 16], end: [u8; 16], ip_protocol: u8) -> IpAddressRange {
        IpAddressRange {
            ip_version: 6,
            start_ip: IpAddr::V6(Ipv6Addr::from(start)),
            end_ip: IpAddr::V6(Ipv6Addr::from(end)),
            ip_protocol,
        }
    }

    #[test]
    fn test_roundtrip_empty() {
        let original = RouteAdvertisement {
            ip_address_ranges: vec![],
        };
        let mut buf = BytesMut::new();
        original.encode_payload(&mut buf);
        assert!(buf.is_empty());
        let decoded = RouteAdvertisement::decode(&buf).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_roundtrip_full_tunnel_v4() {
        let original = RouteAdvertisement {
            ip_address_ranges: vec![make_v4_range([0, 0, 0, 0], [255, 255, 255, 255], 0)],
        };
        let mut buf = BytesMut::new();
        original.encode_payload(&mut buf);
        let decoded = RouteAdvertisement::decode(&buf).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_roundtrip_single_v6() {
        let mut start = [0u8; 16];
        start[0] = 0x20;
        start[1] = 0x01;
        let mut end = [0xffu8; 16];
        end[0] = 0x20;
        end[1] = 0x01;

        let original = RouteAdvertisement {
            ip_address_ranges: vec![make_v6_range(start, end, 0)],
        };
        let mut buf = BytesMut::new();
        original.encode_payload(&mut buf);
        let decoded = RouteAdvertisement::decode(&buf).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_roundtrip_specific_protocol() {
        let original = RouteAdvertisement {
            ip_address_ranges: vec![make_v4_range(
                [10, 0, 0, 0],
                [10, 0, 0, 255],
                6, // TCP only
            )],
        };
        let mut buf = BytesMut::new();
        original.encode_payload(&mut buf);
        let decoded = RouteAdvertisement::decode(&buf).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_encode_sorts_ranges() {
        // Input out of order: protocol 17 before protocol 6
        let original = RouteAdvertisement {
            ip_address_ranges: vec![
                make_v4_range([10, 0, 0, 0], [10, 0, 0, 255], 17),
                make_v4_range([10, 0, 0, 0], [10, 0, 0, 255], 6),
            ],
        };
        let mut buf = BytesMut::new();
        original.encode_payload(&mut buf);

        let decoded = RouteAdvertisement::decode(&buf).unwrap();
        // Should be sorted: protocol 6 before 17
        assert_eq!(decoded.ip_address_ranges[0].ip_protocol, 6);
        assert_eq!(decoded.ip_address_ranges[1].ip_protocol, 17);
    }

    #[test]
    fn test_encode_sorts_v4_before_v6() {
        let v6_start = [0u8; 16];
        let mut v6_end = [0u8; 16];
        v6_end[15] = 0xff;

        let original = RouteAdvertisement {
            ip_address_ranges: vec![
                make_v6_range(v6_start, v6_end, 0),
                make_v4_range([10, 0, 0, 0], [10, 0, 0, 255], 0),
            ],
        };
        let mut buf = BytesMut::new();
        original.encode_payload(&mut buf);

        let decoded = RouteAdvertisement::decode(&buf).unwrap();
        assert_eq!(decoded.ip_address_ranges[0].ip_version, 4);
        assert_eq!(decoded.ip_address_ranges[1].ip_version, 6);
    }

    #[test]
    fn test_encode_sorts_by_start_ip() {
        let original = RouteAdvertisement {
            ip_address_ranges: vec![
                make_v4_range([10, 1, 0, 0], [10, 1, 0, 255], 0),
                make_v4_range([10, 0, 0, 0], [10, 0, 0, 255], 0),
            ],
        };
        let mut buf = BytesMut::new();
        original.encode_payload(&mut buf);

        let decoded = RouteAdvertisement::decode(&buf).unwrap();
        assert_eq!(
            decoded.ip_address_ranges[0].start_ip,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 0))
        );
        assert_eq!(
            decoded.ip_address_ranges[1].start_ip,
            IpAddr::V4(Ipv4Addr::new(10, 1, 0, 0))
        );
    }

    #[test]
    fn test_decode_rejects_bad_order() {
        // Manually encode out-of-order ranges (bypass encode which sorts)
        let mut buf = BytesMut::new();
        // Range 1: 10.1.0.0 (comes after 10.0.0.0)
        encode_ip_address_range(&make_v4_range([10, 1, 0, 0], [10, 1, 0, 255], 0), &mut buf);
        // Range 2: 10.0.0.0 (should come first)
        encode_ip_address_range(&make_v4_range([10, 0, 0, 0], [10, 0, 0, 255], 0), &mut buf);

        let result = RouteAdvertisement::decode(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_rejects_start_greater_than_end() {
        let mut buf = BytesMut::new();
        buf.put_u8(4); // ip_version
        buf.put_slice(&[10, 0, 0, 255]); // start
        buf.put_slice(&[10, 0, 0, 0]); // end < start
        buf.put_u8(0);

        let result = RouteAdvertisement::decode(&buf);
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_ip_version() {
        let mut buf = BytesMut::new();
        buf.put_u8(5); // invalid
        buf.put_slice(&[0u8; 8]);
        buf.put_u8(0);

        let result = RouteAdvertisement::decode(&buf);
        assert!(matches!(result, Err(DecodeError::InvalidIpVersion(5))));
    }

    #[test]
    fn test_truncated_payload() {
        let mut buf = BytesMut::new();
        buf.put_u8(4); // ip_version
        buf.put_slice(&[10, 0, 0, 0]); // start only, missing end + protocol

        let result = RouteAdvertisement::decode(&buf);
        assert!(matches!(result, Err(DecodeError::BufferTooShort { .. })));
    }

    #[test]
    fn test_full_capsule_encode() {
        let original = RouteAdvertisement {
            ip_address_ranges: vec![make_v4_range([0, 0, 0, 0], [255, 255, 255, 255], 0)],
        };
        let mut buf = BytesMut::new();
        original.encode(&mut buf);

        // Capsule type 0x03
        assert_eq!(buf[0], 0x03);
        // payload = ip_version(1) + start(4) + end(4) + protocol(1) = 10
        assert_eq!(buf[1], 10);
    }

    #[test]
    fn test_roundtrip_multiple_mixed() {
        // Already in correct order: v4/proto0 < v4/proto6 < v6/proto0
        let v6_start = [0u8; 16];
        let v6_end = [0xffu8; 16];

        let original = RouteAdvertisement {
            ip_address_ranges: vec![
                make_v4_range([0, 0, 0, 0], [255, 255, 255, 255], 0),
                make_v4_range([10, 0, 0, 0], [10, 0, 0, 255], 6),
                make_v6_range(v6_start, v6_end, 0),
            ],
        };
        let mut buf = BytesMut::new();
        original.encode_payload(&mut buf);
        let decoded = RouteAdvertisement::decode(&buf).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn test_single_address_range() {
        // start == end is valid (single address)
        let original = RouteAdvertisement {
            ip_address_ranges: vec![make_v4_range([10, 0, 0, 1], [10, 0, 0, 1], 0)],
        };
        let mut buf = BytesMut::new();
        original.encode_payload(&mut buf);
        let decoded = RouteAdvertisement::decode(&buf).unwrap();
        assert_eq!(original, decoded);
    }
}
