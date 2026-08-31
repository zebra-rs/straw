//! IP packet validation and mutation for forwarding (RFC 9484 §7.2, §11).

use std::net::IpAddr;

use ipnet::IpNet;

use crate::capsule::AssignedAddress;
use crate::error::ForwardingError;

/// Summary of a parsed IP packet header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PacketInfo {
    /// 4 or 6.
    pub version: u8,
    pub src: IpAddr,
    pub dst: IpAddr,
    /// IPv4 Protocol / IPv6 Next Header.
    ///
    /// For IPv6 this is the first Next Header value; extension-header
    /// traversal is deferred (protocol scoping treats 0 as "all" anyway).
    pub protocol: u8,
}

/// Parse and sanity-check a raw IP packet.
pub fn parse_packet(packet: &[u8]) -> Result<PacketInfo, ForwardingError> {
    if packet.is_empty() {
        return Err(ForwardingError::MalformedPacket);
    }
    match packet[0] >> 4 {
        4 => {
            if packet.len() < 20 {
                return Err(ForwardingError::MalformedPacket);
            }
            let ihl = (packet[0] & 0x0f) as usize * 4;
            let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
            if ihl < 20 || total_len < ihl || packet.len() != total_len {
                return Err(ForwardingError::MalformedPacket);
            }
            let src: [u8; 4] = packet[12..16].try_into().unwrap();
            let dst: [u8; 4] = packet[16..20].try_into().unwrap();
            Ok(PacketInfo {
                version: 4,
                src: IpAddr::from(src),
                dst: IpAddr::from(dst),
                protocol: packet[9],
            })
        }
        6 => {
            if packet.len() < 40 {
                return Err(ForwardingError::MalformedPacket);
            }
            let payload_len = u16::from_be_bytes([packet[4], packet[5]]) as usize;
            if packet.len() != 40 + payload_len {
                return Err(ForwardingError::MalformedPacket);
            }
            let src: [u8; 16] = packet[8..24].try_into().unwrap();
            let dst: [u8; 16] = packet[24..40].try_into().unwrap();
            Ok(PacketInfo {
                version: 6,
                src: IpAddr::from(src),
                dst: IpAddr::from(dst),
                protocol: ipv6_final_protocol(packet)?,
            })
        }
        _ => Err(ForwardingError::MalformedPacket),
    }
}

/// Walk the IPv6 extension-header chain to the upper-layer protocol.
///
/// Handles Hop-by-Hop (0), Routing (43), Fragment (44), Auth (51) and
/// Destination Options (60); stops at No Next Header (59). A fragment with
/// nonzero offset hides the real protocol, so the Fragment header itself is
/// reported in that case.
fn ipv6_final_protocol(packet: &[u8]) -> Result<u8, ForwardingError> {
    let mut next = packet[6];
    let mut offset = 40usize;
    // The chain is short in practice; the bound guards malformed loops.
    for _ in 0..8 {
        match next {
            0 | 43 | 60 => {
                // Hdr Ext Len is in 8-octet units, excluding the first 8.
                if packet.len() < offset + 8 {
                    return Err(ForwardingError::MalformedPacket);
                }
                let len = 8 + packet[offset + 1] as usize * 8;
                if packet.len() < offset + len {
                    return Err(ForwardingError::MalformedPacket);
                }
                next = packet[offset];
                offset += len;
            }
            44 => {
                // Fragment header: fixed 8 octets.
                if packet.len() < offset + 8 {
                    return Err(ForwardingError::MalformedPacket);
                }
                let frag_offset = u16::from_be_bytes([packet[offset + 2], packet[offset + 3]]) >> 3;
                if frag_offset != 0 {
                    // Non-first fragment: the upper-layer header is absent.
                    return Ok(44);
                }
                next = packet[offset];
                offset += 8;
            }
            51 => {
                // Authentication header: Payload Len in 4-octet units, +2.
                if packet.len() < offset + 8 {
                    return Err(ForwardingError::MalformedPacket);
                }
                let len = (packet[offset + 1] as usize + 2) * 4;
                if packet.len() < offset + len {
                    return Err(ForwardingError::MalformedPacket);
                }
                next = packet[offset];
                offset += len;
            }
            other => return Ok(other),
        }
    }
    Err(ForwardingError::MalformedPacket)
}

/// Enforce BCP 38: the packet's source must fall within one of the
/// session's assigned addresses (RFC 9484 §11).
pub fn validate_source(
    info: &PacketInfo,
    assigned: &[AssignedAddress],
) -> Result<(), ForwardingError> {
    let allowed = assigned.iter().any(|a| {
        IpNet::new(a.ip_address, a.prefix_length)
            .map(|net| net.contains(&info.src))
            .unwrap_or(false)
    });
    if allowed {
        Ok(())
    } else {
        Err(ForwardingError::SourceAddressViolation(info.src))
    }
}

/// Reject destinations a proxy must not forward to (RFC 9484 §7.2):
/// loopback, link-local, and unspecified addresses.
pub fn validate_destination(dst: &IpAddr) -> Result<(), ForwardingError> {
    let drop = match dst {
        IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_link_local() || v4.is_unspecified() || v4.is_broadcast()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unspecified() || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    };
    if drop {
        Err(ForwardingError::LinkLocalDrop)
    } else {
        Ok(())
    }
}

/// Decrement TTL (IPv4) or Hop Limit (IPv6) in place, acting as one IP hop
/// (RFC 9484 §7.2). Recomputes the IPv4 header checksum.
pub fn decrement_ttl(packet: &mut [u8]) -> Result<(), ForwardingError> {
    if packet.is_empty() {
        return Err(ForwardingError::MalformedPacket);
    }
    match packet[0] >> 4 {
        4 => {
            if packet.len() < 20 {
                return Err(ForwardingError::MalformedPacket);
            }
            if packet[8] <= 1 {
                return Err(ForwardingError::TtlExpired);
            }
            packet[8] -= 1;
            recompute_ipv4_checksum(packet);
            Ok(())
        }
        6 => {
            if packet.len() < 40 {
                return Err(ForwardingError::MalformedPacket);
            }
            if packet[7] <= 1 {
                return Err(ForwardingError::TtlExpired);
            }
            packet[7] -= 1;
            Ok(())
        }
        _ => Err(ForwardingError::MalformedPacket),
    }
}

/// Recompute the IPv4 header checksum in place.
fn recompute_ipv4_checksum(packet: &mut [u8]) {
    let ihl = (packet[0] & 0x0f) as usize * 4;
    packet[10] = 0;
    packet[11] = 0;
    let checksum = ipv4_checksum(&packet[..ihl]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
}

/// Internet checksum (RFC 1071) over a byte slice.
pub fn ipv4_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let (pairs, rest) = data.as_chunks::<2>();
    for pair in pairs {
        sum += u32::from(u16::from_be_bytes(*pair));
    }
    if let [last] = rest {
        sum += u32::from(u16::from_be_bytes([*last, 0]));
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Build a minimal IPv4 ICMP Echo Request/Reply packet.
///
/// Used by the test client and integration tests; the proxy itself never
/// originates traffic in Phase 2.
pub fn build_ipv4_icmp_echo(
    src: std::net::Ipv4Addr,
    dst: std::net::Ipv4Addr,
    is_reply: bool,
    identifier: u16,
    sequence: u16,
    payload: &[u8],
    ttl: u8,
) -> Vec<u8> {
    let icmp_len = 8 + payload.len();
    let total_len = 20 + icmp_len;
    let mut packet = vec![0u8; total_len];

    // IPv4 header.
    packet[0] = 0x45; // version 4, IHL 5
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = ttl;
    packet[9] = 1; // ICMP
    packet[12..16].copy_from_slice(&src.octets());
    packet[16..20].copy_from_slice(&dst.octets());
    let header_checksum = ipv4_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());

    // ICMP echo.
    packet[20] = if is_reply { 0 } else { 8 };
    packet[24..26].copy_from_slice(&identifier.to_be_bytes());
    packet[26..28].copy_from_slice(&sequence.to_be_bytes());
    packet[28..].copy_from_slice(payload);
    let icmp_checksum = ipv4_checksum(&packet[20..]);
    packet[22..24].copy_from_slice(&icmp_checksum.to_be_bytes());

    packet
}

/// ICMPv6 checksum: RFC 1071 fold over the IPv6 pseudo-header (RFC 8200
/// §8.1) plus the ICMPv6 message.
pub fn icmpv6_checksum(src: &std::net::Ipv6Addr, dst: &std::net::Ipv6Addr, icmp: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + icmp.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&(icmp.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 58]); // zeros + Next Header (ICMPv6)
    pseudo.extend_from_slice(icmp);
    ipv4_checksum(&pseudo)
}

/// Build a minimal IPv6 ICMPv6 Echo Request/Reply packet.
pub fn build_ipv6_icmpv6_echo(
    src: std::net::Ipv6Addr,
    dst: std::net::Ipv6Addr,
    is_reply: bool,
    identifier: u16,
    sequence: u16,
    payload: &[u8],
    hop_limit: u8,
) -> Vec<u8> {
    let icmp_len = 8 + payload.len();
    let mut packet = vec![0u8; 40 + icmp_len];

    // IPv6 header.
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(icmp_len as u16).to_be_bytes());
    packet[6] = 58; // ICMPv6
    packet[7] = hop_limit;
    packet[8..24].copy_from_slice(&src.octets());
    packet[24..40].copy_from_slice(&dst.octets());

    // ICMPv6 echo.
    packet[40] = if is_reply { 129 } else { 128 };
    packet[44..46].copy_from_slice(&identifier.to_be_bytes());
    packet[46..48].copy_from_slice(&sequence.to_be_bytes());
    packet[48..].copy_from_slice(payload);
    let checksum = icmpv6_checksum(&src, &dst, &packet[40..]);
    packet[42..44].copy_from_slice(&checksum.to_be_bytes());

    packet
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assigned_v4(addr: [u8; 4]) -> AssignedAddress {
        AssignedAddress {
            request_id: 0,
            ip_version: 4,
            ip_address: IpAddr::from(addr),
            prefix_length: 32,
        }
    }

    fn echo(src: [u8; 4], dst: [u8; 4], ttl: u8) -> Vec<u8> {
        build_ipv4_icmp_echo(src.into(), dst.into(), false, 1, 1, b"ping", ttl)
    }

    #[test]
    fn parse_valid_ipv4() {
        let pkt = echo([10, 100, 0, 2], [192, 0, 2, 1], 64);
        let info = parse_packet(&pkt).unwrap();
        assert_eq!(info.version, 4);
        assert_eq!(info.src, IpAddr::from([10, 100, 0, 2]));
        assert_eq!(info.dst, IpAddr::from([192, 0, 2, 1]));
        assert_eq!(info.protocol, 1);
    }

    #[test]
    fn parse_rejects_length_mismatch() {
        let mut pkt = echo([10, 0, 0, 1], [10, 0, 0, 2], 64);
        pkt.push(0); // trailing junk
        assert!(matches!(
            parse_packet(&pkt),
            Err(ForwardingError::MalformedPacket)
        ));
    }

    #[test]
    fn parse_rejects_bad_version() {
        let pkt = [0x00u8; 20];
        assert!(parse_packet(&pkt).is_err());
    }

    #[test]
    fn parse_valid_ipv6() {
        // 40-byte header + 4-byte payload, next header = UDP (17).
        let mut pkt = vec![0u8; 44];
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&4u16.to_be_bytes());
        pkt[6] = 17;
        pkt[7] = 64;
        pkt[8..24].copy_from_slice(&[0xfd; 16]);
        pkt[24..40].copy_from_slice(&[0xfc; 16]);
        let info = parse_packet(&pkt).unwrap();
        assert_eq!(info.version, 6);
        assert_eq!(info.protocol, 17);
    }

    #[test]
    fn source_validation() {
        let pkt = echo([10, 100, 0, 2], [192, 0, 2, 1], 64);
        let info = parse_packet(&pkt).unwrap();

        assert!(validate_source(&info, &[assigned_v4([10, 100, 0, 2])]).is_ok());
        assert!(matches!(
            validate_source(&info, &[assigned_v4([10, 100, 0, 3])]),
            Err(ForwardingError::SourceAddressViolation(_))
        ));
    }

    #[test]
    fn destination_validation() {
        assert!(validate_destination(&IpAddr::from([192, 0, 2, 1])).is_ok());
        assert!(validate_destination(&IpAddr::from([127, 0, 0, 1])).is_err());
        assert!(validate_destination(&IpAddr::from([169, 254, 0, 1])).is_err());
        assert!(validate_destination(&"fe80::1".parse::<IpAddr>().unwrap()).is_err());
        assert!(validate_destination(&"::1".parse::<IpAddr>().unwrap()).is_err());
        assert!(validate_destination(&"2001:db8::1".parse::<IpAddr>().unwrap()).is_ok());
    }

    #[test]
    fn ttl_decrement_updates_checksum() {
        let mut pkt = echo([10, 0, 0, 1], [192, 0, 2, 1], 64);
        decrement_ttl(&mut pkt).unwrap();
        assert_eq!(pkt[8], 63);
        // A valid IPv4 header sums (including checksum field) to 0xffff,
        // i.e. the RFC 1071 fold over it is zero.
        assert_eq!(ipv4_checksum(&pkt[..20]), 0);
    }

    #[test]
    fn ttl_expired() {
        let mut pkt = echo([10, 0, 0, 1], [192, 0, 2, 1], 1);
        assert!(matches!(
            decrement_ttl(&mut pkt),
            Err(ForwardingError::TtlExpired)
        ));
    }

    #[test]
    fn hop_limit_decrement_ipv6() {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x60;
        pkt[7] = 2;
        decrement_ttl(&mut pkt).unwrap();
        assert_eq!(pkt[7], 1);
        assert!(matches!(
            decrement_ttl(&mut pkt),
            Err(ForwardingError::TtlExpired)
        ));
    }

    #[test]
    fn ipv6_extension_header_walk() {
        // IPv6 + Hop-by-Hop (8 bytes) + Destination Options (8) + UDP.
        let mut pkt = vec![0u8; 40 + 8 + 8 + 8];
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&24u16.to_be_bytes());
        pkt[6] = 0; // Hop-by-Hop
        pkt[7] = 64;
        pkt[40] = 60; // next: Destination Options
        pkt[41] = 0; // 8 bytes
        pkt[48] = 17; // next: UDP
        pkt[49] = 0;
        let info = parse_packet(&pkt).unwrap();
        assert_eq!(info.protocol, 17, "walks past extension headers to UDP");
    }

    #[test]
    fn ipv6_non_first_fragment_reports_fragment_header() {
        // IPv6 + Fragment header with nonzero offset.
        let mut pkt = vec![0u8; 40 + 8 + 4];
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&12u16.to_be_bytes());
        pkt[6] = 44; // Fragment
        pkt[7] = 64;
        pkt[40] = 6; // claims TCP inside
        pkt[42..44].copy_from_slice(&(100u16 << 3).to_be_bytes()); // offset 100
        let info = parse_packet(&pkt).unwrap();
        assert_eq!(info.protocol, 44, "upper-layer header absent");
    }

    #[test]
    fn ipv6_truncated_extension_header_rejected() {
        let mut pkt = vec![0u8; 44];
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&4u16.to_be_bytes());
        pkt[6] = 0; // Hop-by-Hop, but only 4 bytes follow
        assert!(parse_packet(&pkt).is_err());
    }

    #[test]
    fn icmpv6_echo_is_internally_consistent() {
        let src: std::net::Ipv6Addr = "fd00::2".parse().unwrap();
        let dst: std::net::Ipv6Addr = "fd00::3".parse().unwrap();
        let pkt = build_ipv6_icmpv6_echo(src, dst, false, 5, 9, b"ping6", 64);
        let info = parse_packet(&pkt).unwrap();
        assert_eq!(info.version, 6);
        assert_eq!(info.protocol, 58);
        assert_eq!(info.src, IpAddr::from(src));
        // Checksum folds to zero when recomputed over the sent message.
        assert_eq!(icmpv6_checksum(&src, &dst, &pkt[40..]), 0);
    }

    #[test]
    fn icmp_echo_is_internally_consistent() {
        let pkt = echo([10, 100, 0, 2], [10, 100, 0, 3], 64);
        // Both checksums verify (fold to zero).
        assert_eq!(ipv4_checksum(&pkt[..20]), 0);
        assert_eq!(ipv4_checksum(&pkt[20..]), 0);
        assert_eq!(parse_packet(&pkt).unwrap().protocol, 1);
    }
}
