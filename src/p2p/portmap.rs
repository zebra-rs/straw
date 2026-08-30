//! Explicit port mapping via PCP (RFC 6887) and NAT-PMP (RFC 6886) — P3.
//!
//! Symmetric NATs defeat hole punching, but most consumer routers can be *asked*
//! to install a port forward. A peer requests a UDP mapping for its punch
//! socket's internal port; the router replies with an external (IP, port) that
//! it forwards inbound to that socket. That mapped address is then a candidate
//! the peer advertises — reachable regardless of the NAT's mapping behaviour,
//! because the forward is explicit (design §11 / P3).
//!
//! Both protocols live on UDP port 5351 at the default gateway. PCP is the
//! modern one and is tried first; NAT-PMP is the older fallback that many
//! routers (and Apple's) still speak. The wire encode/decode is pure and
//! unit-tested; `map_udp` does the network I/O.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::time::Duration;

use tokio::net::UdpSocket;

use crate::error::ProxyError;

/// The well-known PCP / NAT-PMP server port at the gateway.
const PORT: u16 = 5351;
/// Per-attempt receive timeout; a couple are tried before giving up.
const ATTEMPT_TIMEOUT: Duration = Duration::from_millis(250);
const ATTEMPTS: usize = 3;
/// IANA protocol number for UDP.
const PROTO_UDP: u8 = 17;

/// A port mapping the gateway installed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mapping {
    /// The externally-reachable address the gateway forwards to our socket.
    pub external: SocketAddr,
    /// How long the gateway will hold it.
    pub lifetime: Duration,
}

/// Request a UDP port mapping for `internal_port` from the default gateway,
/// valid for `lifetime`. Tries PCP, then NAT-PMP. Returns the external address
/// the peer should dial, or an error if no gateway speaks either protocol.
pub async fn map_udp(internal_port: u16, lifetime: Duration) -> Result<Mapping, ProxyError> {
    let gateway = default_gateway()
        .ok_or_else(|| ProxyError::Config("no default IPv4 gateway for port mapping".into()))?;
    map_udp_via(
        SocketAddr::V4(SocketAddrV4::new(gateway, PORT)),
        internal_port,
        lifetime,
    )
    .await
}

/// Request a mapping from a specific PCP/NAT-PMP `server` (the gateway in
/// production; a stub in tests). Tries PCP, then NAT-PMP.
pub async fn map_udp_via(
    server: SocketAddr,
    internal_port: u16,
    lifetime: Duration,
) -> Result<Mapping, ProxyError> {
    let socket = UdpSocket::bind("0.0.0.0:0").await.map_err(ProxyError::Io)?;
    socket.connect(server).await.map_err(ProxyError::Io)?;
    // The source the kernel picked to reach the gateway is our internal IP.
    let client_ip = match socket.local_addr().map_err(ProxyError::Io)?.ip() {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => return Err(ProxyError::Config("port mapping is IPv4-only".into())),
    };
    let secs = lifetime.as_secs().min(u32::MAX as u64) as u32;

    // 1. PCP (preferred).
    let nonce: [u8; 12] = rand_nonce();
    let req = pcp_map_request(client_ip, nonce, internal_port, 0, secs);
    if let Ok(resp) = exchange(&socket, &req).await
        && let Ok((ip, port, life)) = parse_pcp_map(&resp, &nonce)
    {
        return Ok(Mapping {
            external: SocketAddr::new(IpAddr::V4(ip), port),
            lifetime: Duration::from_secs(life as u64),
        });
    }

    // 2. NAT-PMP fallback: external-address request, then the UDP mapping.
    let ext_resp = exchange(&socket, &natpmp_external_request()).await?;
    let ext_ip = parse_natpmp_external(&ext_resp)?;
    let map_resp = exchange(&socket, &natpmp_map_request(internal_port, 0, secs)).await?;
    let (_internal, mapped, life) = parse_natpmp_map(&map_resp)?;
    Ok(Mapping {
        external: SocketAddr::new(IpAddr::V4(ext_ip), mapped),
        lifetime: Duration::from_secs(life as u64),
    })
}

/// Send `req` and return the first response, retrying on timeout.
async fn exchange(socket: &UdpSocket, req: &[u8]) -> Result<Vec<u8>, ProxyError> {
    let mut buf = vec![0u8; 1100];
    for _ in 0..ATTEMPTS {
        socket.send(req).await.map_err(ProxyError::Io)?;
        match tokio::time::timeout(ATTEMPT_TIMEOUT, socket.recv(&mut buf)).await {
            Ok(Ok(n)) => return Ok(buf[..n].to_vec()),
            Ok(Err(e)) => return Err(ProxyError::Io(e)),
            Err(_) => continue, // timed out; retry
        }
    }
    Err(ProxyError::Quic(
        "port-mapping server did not respond".into(),
    ))
}

// --- gateway discovery -----------------------------------------------------

/// The default IPv4 gateway from the kernel routing table (`/proc/net/route`).
fn default_gateway() -> Option<Ipv4Addr> {
    let table = std::fs::read_to_string("/proc/net/route").ok()?;
    parse_default_gateway(&table)
}

/// Parse the default route's gateway from `/proc/net/route` content. The
/// Destination and Gateway columns are little-endian hex IPv4.
fn parse_default_gateway(table: &str) -> Option<Ipv4Addr> {
    for line in table.lines().skip(1) {
        let mut cols = line.split_whitespace();
        let _iface = cols.next()?;
        let dest = cols.next()?;
        let gw = cols.next()?;
        if dest == "00000000" {
            let raw = u32::from_str_radix(gw, 16).ok()?;
            // Columns are little-endian: least-significant byte is the first octet.
            return Some(Ipv4Addr::from(raw.to_le_bytes()));
        }
    }
    None
}

// --- NAT-PMP (RFC 6886) ----------------------------------------------------

/// External-address request: version 0, opcode 0.
fn natpmp_external_request() -> [u8; 2] {
    [0, 0]
}

/// Parse the external-address response (12 bytes): [0, 128, result(2),
/// epoch(4), external_ip(4)].
fn parse_natpmp_external(resp: &[u8]) -> Result<Ipv4Addr, ProxyError> {
    if resp.len() < 12 || resp[0] != 0 || resp[1] != 128 {
        return Err(ProxyError::Quic("bad NAT-PMP external response".into()));
    }
    let result = u16::from_be_bytes([resp[2], resp[3]]);
    if result != 0 {
        return Err(ProxyError::Quic(format!("NAT-PMP error {result}")));
    }
    Ok(Ipv4Addr::new(resp[8], resp[9], resp[10], resp[11]))
}

/// UDP mapping request (12 bytes): version 0, opcode 1 (UDP), reserved(2),
/// internal_port(2), suggested_external(2), lifetime(4).
fn natpmp_map_request(internal: u16, suggested: u16, lifetime: u32) -> [u8; 12] {
    let mut b = [0u8; 12];
    b[1] = 1; // UDP
    b[4..6].copy_from_slice(&internal.to_be_bytes());
    b[6..8].copy_from_slice(&suggested.to_be_bytes());
    b[8..12].copy_from_slice(&lifetime.to_be_bytes());
    b
}

/// Parse the UDP mapping response (16 bytes): [0, 129, result(2), epoch(4),
/// internal(2), mapped_external(2), lifetime(4)] → (internal, mapped, lifetime).
fn parse_natpmp_map(resp: &[u8]) -> Result<(u16, u16, u32), ProxyError> {
    if resp.len() < 16 || resp[0] != 0 || resp[1] != 129 {
        return Err(ProxyError::Quic("bad NAT-PMP map response".into()));
    }
    let result = u16::from_be_bytes([resp[2], resp[3]]);
    if result != 0 {
        return Err(ProxyError::Quic(format!("NAT-PMP map error {result}")));
    }
    let internal = u16::from_be_bytes([resp[8], resp[9]]);
    let mapped = u16::from_be_bytes([resp[10], resp[11]]);
    let lifetime = u32::from_be_bytes([resp[12], resp[13], resp[14], resp[15]]);
    Ok((internal, mapped, lifetime))
}

// --- PCP (RFC 6887) MAP -----------------------------------------------------

/// Build a PCP MAP request (60 bytes): a 24-byte common header + the 36-byte
/// MAP opcode payload. IPv4 addresses travel as IPv4-mapped IPv6.
fn pcp_map_request(
    client_ip: Ipv4Addr,
    nonce: [u8; 12],
    internal_port: u16,
    suggested_port: u16,
    lifetime: u32,
) -> Vec<u8> {
    let mut b = Vec::with_capacity(60);
    // Header.
    b.push(2); // version
    b.push(1); // R=0 | opcode=MAP(1)
    b.extend_from_slice(&[0, 0]); // reserved
    b.extend_from_slice(&lifetime.to_be_bytes());
    b.extend_from_slice(&v4_mapped(client_ip));
    // MAP opcode.
    b.extend_from_slice(&nonce);
    b.push(PROTO_UDP);
    b.extend_from_slice(&[0, 0, 0]); // reserved
    b.extend_from_slice(&internal_port.to_be_bytes());
    b.extend_from_slice(&suggested_port.to_be_bytes());
    b.extend_from_slice(&v4_mapped(Ipv4Addr::UNSPECIFIED)); // no preference
    b
}

/// Parse a PCP MAP response → (external IP, external port, lifetime). Verifies
/// the version, response flag, opcode, success code, and echoed nonce.
fn parse_pcp_map(resp: &[u8], nonce: &[u8; 12]) -> Result<(Ipv4Addr, u16, u32), ProxyError> {
    if resp.len() < 60 || resp[0] != 2 || resp[1] != 0x81 {
        return Err(ProxyError::Quic("bad PCP response".into()));
    }
    let result = resp[3];
    if result != 0 {
        return Err(ProxyError::Quic(format!("PCP error {result}")));
    }
    let lifetime = u32::from_be_bytes([resp[4], resp[5], resp[6], resp[7]]);
    // MAP payload starts at offset 24.
    if &resp[24..36] != nonce {
        return Err(ProxyError::Quic("PCP nonce mismatch".into()));
    }
    let external_port = u16::from_be_bytes([resp[42], resp[43]]);
    let external_ip = v4_from_mapped(&resp[44..60])
        .ok_or_else(|| ProxyError::Quic("PCP returned a non-IPv4 mapping".into()))?;
    Ok((external_ip, external_port, lifetime))
}

/// An IPv4 address as a 16-byte IPv4-mapped IPv6 (`::ffff:a.b.c.d`).
fn v4_mapped(ip: Ipv4Addr) -> [u8; 16] {
    let mut b = [0u8; 16];
    b[10] = 0xff;
    b[11] = 0xff;
    b[12..16].copy_from_slice(&ip.octets());
    b
}

/// Recover an IPv4 address from a 16-byte IPv4-mapped IPv6, if it is one.
fn v4_from_mapped(bytes: &[u8]) -> Option<Ipv4Addr> {
    if bytes.len() != 16 || bytes[10] != 0xff || bytes[11] != 0xff {
        return None;
    }
    Some(Ipv4Addr::new(bytes[12], bytes[13], bytes[14], bytes[15]))
}

fn rand_nonce() -> [u8; 12] {
    use ring::rand::SecureRandom;
    let mut n = [0u8; 12];
    // Failure only on a broken RNG; a zero nonce still functions (it is an
    // anti-spoofing echo, not a secret).
    let _ = ring::rand::SystemRandom::new().fill(&mut n);
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_default_gateway() {
        // Iface Destination Gateway Flags … — default row + a non-default row.
        let table = "Iface\tDestination\tGateway\tFlags\n\
                     eth0\t00000000\t0102A8C0\t0003\n\
                     eth0\t0002A8C0\t00000000\t0001\n";
        // 0102A8C0 little-endian = C0 A8 02 01 = 192.168.2.1
        assert_eq!(
            parse_default_gateway(table),
            Some(Ipv4Addr::new(192, 168, 2, 1))
        );
        assert_eq!(parse_default_gateway("Iface\tDestination\tGateway\n"), None);
    }

    #[test]
    fn natpmp_map_round_trips() {
        let req = natpmp_map_request(41000, 0, 3600);
        assert_eq!(req[0], 0);
        assert_eq!(req[1], 1);
        assert_eq!(u16::from_be_bytes([req[4], req[5]]), 41000);
        assert_eq!(u32::from_be_bytes([req[8], req[9], req[10], req[11]]), 3600);

        // A well-formed success response.
        let mut resp = vec![0u8; 16];
        resp[1] = 129;
        resp[8..10].copy_from_slice(&41000u16.to_be_bytes());
        resp[10..12].copy_from_slice(&50000u16.to_be_bytes());
        resp[12..16].copy_from_slice(&3600u32.to_be_bytes());
        assert_eq!(parse_natpmp_map(&resp).unwrap(), (41000, 50000, 3600));

        resp[3] = 2; // non-zero result
        assert!(parse_natpmp_map(&resp).is_err());
    }

    #[test]
    fn natpmp_external_parses() {
        let mut resp = vec![0u8; 12];
        resp[1] = 128;
        resp[8..12].copy_from_slice(&[198, 51, 100, 7]);
        assert_eq!(
            parse_natpmp_external(&resp).unwrap(),
            Ipv4Addr::new(198, 51, 100, 7)
        );
    }

    #[test]
    fn pcp_map_round_trips() {
        let nonce = [7u8; 12];
        let req = pcp_map_request(Ipv4Addr::new(10, 0, 0, 2), nonce, 41000, 0, 3600);
        assert_eq!(req.len(), 60);
        assert_eq!(req[0], 2);
        assert_eq!(req[1], 1);
        assert_eq!(&req[24..36], &nonce);
        assert_eq!(req[36], PROTO_UDP);
        assert_eq!(u16::from_be_bytes([req[40], req[41]]), 41000);

        // Build a matching success response.
        let mut resp = vec![0u8; 60];
        resp[0] = 2;
        resp[1] = 0x81;
        resp[4..8].copy_from_slice(&3600u32.to_be_bytes());
        resp[24..36].copy_from_slice(&nonce);
        resp[42..44].copy_from_slice(&50000u16.to_be_bytes());
        resp[44..60].copy_from_slice(&v4_mapped(Ipv4Addr::new(198, 51, 100, 7)));
        assert_eq!(
            parse_pcp_map(&resp, &nonce).unwrap(),
            (Ipv4Addr::new(198, 51, 100, 7), 50000, 3600)
        );

        // Nonce mismatch and error code are rejected.
        assert!(parse_pcp_map(&resp, &[9u8; 12]).is_err());
        resp[3] = 2;
        assert!(parse_pcp_map(&resp, &nonce).is_err());
    }

    #[test]
    fn v4_mapping_round_trips() {
        let ip = Ipv4Addr::new(203, 0, 113, 5);
        assert_eq!(v4_from_mapped(&v4_mapped(ip)), Some(ip));
    }
}
