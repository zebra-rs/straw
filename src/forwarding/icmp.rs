//! ICMP error generation (RFC 9484 §7.2: the proxy behaves like a router,
//! so undeliverable packets earn ICMP errors back through the tunnel).
//!
//! Formats: RFC 792 (ICMPv4), RFC 4443 (ICMPv6), RFC 1191 (v4 PMTU).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::packet::{icmpv6_checksum, ipv4_checksum};

/// Which error to report about a dropped packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpErrorKind {
    /// TTL / Hop Limit reached zero in transit.
    TimeExceeded,
    /// No route to the destination.
    NoRoute,
    /// Destination outside the advertised routes (split-tunnel policy).
    AdminProhibited,
    /// Packet exceeds the tunnel MTU.
    PacketTooBig { mtu: u16 },
}

/// The proxy-side addresses ICMP errors originate from.
#[derive(Debug, Clone, Copy)]
pub struct IcmpSource {
    pub v4: Ipv4Addr,
    pub v6: Option<Ipv6Addr>,
}

/// Build an ICMP error packet for `original`, or `None` when no error must
/// be sent (originals that are themselves ICMP errors, bad sources, or a
/// missing v6 gateway).
pub fn build_icmp_error(
    kind: IcmpErrorKind,
    source: IcmpSource,
    original: &[u8],
) -> Option<Vec<u8>> {
    if original.is_empty() {
        return None;
    }
    match original[0] >> 4 {
        4 => build_v4_error(kind, source.v4, original),
        6 => build_v6_error(kind, source.v6?, original),
        _ => None,
    }
}

fn build_v4_error(kind: IcmpErrorKind, gateway: Ipv4Addr, original: &[u8]) -> Option<Vec<u8>> {
    if original.len() < 20 {
        return None;
    }
    let ihl = (original[0] & 0x0f) as usize * 4;
    if ihl < 20 || original.len() < ihl {
        return None;
    }
    let orig_src = Ipv4Addr::from(<[u8; 4]>::try_from(&original[12..16]).unwrap());
    if !valid_error_target(&IpAddr::V4(orig_src)) {
        return None;
    }
    // Never answer an ICMP error with another (RFC 792 / RFC 1122 §3.2.2).
    if original[9] == 1 && original.len() > ihl {
        let icmp_type = original[ihl];
        if matches!(icmp_type, 3 | 4 | 5 | 11 | 12) {
            return None;
        }
    }

    let (icmp_type, code, rest_of_header) = match kind {
        IcmpErrorKind::TimeExceeded => (11u8, 0u8, [0u8; 4]),
        IcmpErrorKind::NoRoute => (3, 0, [0u8; 4]),
        IcmpErrorKind::AdminProhibited => (3, 13, [0u8; 4]),
        IcmpErrorKind::PacketTooBig { mtu } => {
            let mut rest = [0u8; 4];
            rest[2..4].copy_from_slice(&mtu.to_be_bytes());
            (3, 4, rest) // fragmentation needed + next-hop MTU
        }
    };

    // Quote the invoking IP header + 8 bytes of its payload.
    let quoted = &original[..original.len().min(ihl + 8)];
    let icmp_len = 8 + quoted.len();
    let total_len = 20 + icmp_len;
    let mut packet = vec![0u8; total_len];

    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
    packet[8] = 64; // TTL
    packet[9] = 1; // ICMP
    packet[12..16].copy_from_slice(&gateway.octets());
    packet[16..20].copy_from_slice(&orig_src.octets());
    let header_checksum = ipv4_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&header_checksum.to_be_bytes());

    packet[20] = icmp_type;
    packet[21] = code;
    packet[24..28].copy_from_slice(&rest_of_header);
    packet[28..].copy_from_slice(quoted);
    let icmp_checksum = ipv4_checksum(&packet[20..]);
    packet[22..24].copy_from_slice(&icmp_checksum.to_be_bytes());

    Some(packet)
}

fn build_v6_error(kind: IcmpErrorKind, gateway: Ipv6Addr, original: &[u8]) -> Option<Vec<u8>> {
    if original.len() < 40 {
        return None;
    }
    let orig_src = Ipv6Addr::from(<[u8; 16]>::try_from(&original[8..24]).unwrap());
    if !valid_error_target(&IpAddr::V6(orig_src)) {
        return None;
    }
    // ICMPv6 error types are < 128 (RFC 4443 §2.1); never answer one.
    if original[6] == 58 && original.len() > 40 && original[40] < 128 {
        return None;
    }

    let (icmp_type, code, rest_of_header) = match kind {
        IcmpErrorKind::TimeExceeded => (3u8, 0u8, [0u8; 4]),
        IcmpErrorKind::NoRoute => (1, 0, [0u8; 4]),
        IcmpErrorKind::AdminProhibited => (1, 1, [0u8; 4]),
        IcmpErrorKind::PacketTooBig { mtu } => (2, 0, (mtu as u32).to_be_bytes()),
    };

    // Quote the invoking header + 8 bytes; total stays far below 1280.
    let quoted = &original[..original.len().min(48)];
    let icmp_len = 8 + quoted.len();
    let mut packet = vec![0u8; 40 + icmp_len];

    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&(icmp_len as u16).to_be_bytes());
    packet[6] = 58; // ICMPv6
    packet[7] = 64; // Hop Limit
    packet[8..24].copy_from_slice(&gateway.octets());
    packet[24..40].copy_from_slice(&orig_src.octets());

    packet[40] = icmp_type;
    packet[41] = code;
    packet[44..48].copy_from_slice(&rest_of_header);
    packet[48..].copy_from_slice(quoted);
    let checksum = icmpv6_checksum(&gateway, &orig_src, &packet[40..]);
    packet[42..44].copy_from_slice(&checksum.to_be_bytes());

    Some(packet)
}

/// An ICMP error must go to a real unicast sender.
fn valid_error_target(addr: &IpAddr) -> bool {
    match addr {
        IpAddr::V4(a) => {
            !a.is_unspecified() && !a.is_loopback() && !a.is_multicast() && !a.is_broadcast()
        }
        IpAddr::V6(a) => !a.is_unspecified() && !a.is_loopback() && !a.is_multicast(),
    }
}

#[cfg(test)]
mod tests {
    use super::super::packet::{build_ipv4_icmp_echo, build_ipv6_icmpv6_echo, parse_packet};
    use super::*;

    fn source() -> IcmpSource {
        IcmpSource {
            v4: "10.100.0.1".parse().unwrap(),
            v6: Some("fd00::1".parse().unwrap()),
        }
    }

    #[test]
    fn v4_time_exceeded_quotes_original() {
        let orig = build_ipv4_icmp_echo(
            "10.100.0.2".parse().unwrap(),
            "192.0.2.1".parse().unwrap(),
            false,
            1,
            1,
            b"abcdefgh",
            1,
        );
        let err = build_icmp_error(IcmpErrorKind::TimeExceeded, source(), &orig).unwrap();

        let info = parse_packet(&err).unwrap();
        assert_eq!(info.src, "10.100.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(info.dst, "10.100.0.2".parse::<IpAddr>().unwrap());
        assert_eq!(info.protocol, 1);
        assert_eq!(err[20], 11, "Time Exceeded");
        assert_eq!(err[21], 0);
        // Both checksums verify.
        assert_eq!(ipv4_checksum(&err[..20]), 0);
        assert_eq!(ipv4_checksum(&err[20..]), 0);
        // Quoted original: IP header + 8 bytes.
        assert_eq!(&err[28..48], &orig[..20]);
        assert_eq!(&err[48..56], &orig[20..28]);
    }

    #[test]
    fn v4_packet_too_big_carries_mtu() {
        let orig = build_ipv4_icmp_echo(
            "10.100.0.2".parse().unwrap(),
            "192.0.2.1".parse().unwrap(),
            false,
            1,
            1,
            b"",
            64,
        );
        let err =
            build_icmp_error(IcmpErrorKind::PacketTooBig { mtu: 1400 }, source(), &orig).unwrap();
        assert_eq!(err[20], 3);
        assert_eq!(err[21], 4);
        assert_eq!(u16::from_be_bytes([err[26], err[27]]), 1400);
    }

    #[test]
    fn v6_errors_have_valid_checksums() {
        let orig = build_ipv6_icmpv6_echo(
            "fd00::2".parse().unwrap(),
            "2001:db8::1".parse().unwrap(),
            false,
            1,
            1,
            b"payload!",
            1,
        );
        let err = build_icmp_error(IcmpErrorKind::TimeExceeded, source(), &orig).unwrap();
        let info = parse_packet(&err).unwrap();
        assert_eq!(info.protocol, 58);
        assert_eq!(info.src, "fd00::1".parse::<IpAddr>().unwrap());
        assert_eq!(info.dst, "fd00::2".parse::<IpAddr>().unwrap());
        assert_eq!(err[40], 3, "ICMPv6 Time Exceeded");
        let src: Ipv6Addr = "fd00::1".parse().unwrap();
        let dst: Ipv6Addr = "fd00::2".parse().unwrap();
        assert_eq!(icmpv6_checksum(&src, &dst, &err[40..]), 0);
    }

    #[test]
    fn v6_packet_too_big_carries_mtu() {
        let orig = build_ipv6_icmpv6_echo(
            "fd00::2".parse().unwrap(),
            "2001:db8::1".parse().unwrap(),
            false,
            1,
            1,
            b"",
            64,
        );
        let err =
            build_icmp_error(IcmpErrorKind::PacketTooBig { mtu: 1350 }, source(), &orig).unwrap();
        assert_eq!(err[40], 2, "ICMPv6 Packet Too Big");
        assert_eq!(
            u32::from_be_bytes([err[44], err[45], err[46], err[47]]),
            1350
        );
    }

    #[test]
    fn no_error_about_an_icmp_error() {
        // A v4 Destination Unreachable as the "original" packet.
        let echo = build_ipv4_icmp_echo(
            "10.100.0.2".parse().unwrap(),
            "192.0.2.1".parse().unwrap(),
            false,
            1,
            1,
            b"",
            64,
        );
        let unreachable = build_icmp_error(IcmpErrorKind::NoRoute, source(), &echo).unwrap();
        assert!(
            build_icmp_error(IcmpErrorKind::TimeExceeded, source(), &unreachable).is_none(),
            "must not generate ICMP about ICMP errors"
        );

        // Echo requests/replies are fine to report about.
        assert!(build_icmp_error(IcmpErrorKind::TimeExceeded, source(), &echo).is_some());
    }

    #[test]
    fn v6_without_gateway_yields_none() {
        let orig = build_ipv6_icmpv6_echo(
            "fd00::2".parse().unwrap(),
            "2001:db8::1".parse().unwrap(),
            false,
            1,
            1,
            b"",
            64,
        );
        let no_v6 = IcmpSource {
            v4: "10.100.0.1".parse().unwrap(),
            v6: None,
        };
        assert!(build_icmp_error(IcmpErrorKind::NoRoute, no_v6, &orig).is_none());
    }
}
