//! STUN (RFC 5389) Binding + NAT behaviour discovery (RFC 5780) — P3.
//!
//! Before punching, a peer can classify its NAT's *mapping behaviour* by probing
//! a dual-address STUN server (the relay runs `stun::serve`) from a
//! fresh socket: is the external mapping the same for every destination
//! (endpoint-independent / cone), or does it change per destination IP
//! (address-dependent) or per destination IP *and* port
//! (address-and-port-dependent / symmetric)? Cone NATs punch with the basic
//! strategy; symmetric NATs do not, so knowing the class up front lets a peer
//! skip a futile 5 s punch and go straight to `--port-map` or the relay.
//!
//! The mapping is a property of the NAT, not of a particular socket, so a fresh
//! probe socket (raw UDP, not the quinn-owned punch socket) yields the answer
//! that applies to the punch socket too.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use tokio::net::UdpSocket;

use crate::error::ProxyError;

/// STUN magic cookie (RFC 5389 §6).
pub const MAGIC_COOKIE: u32 = 0x2112_A442;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;
const ATTR_OTHER_ADDRESS: u16 = 0x802C;
const FAMILY_V4: u8 = 0x01;

const ATTEMPT_TIMEOUT: Duration = Duration::from_millis(300);
const ATTEMPTS: usize = 3;

/// A NAT's mapping behaviour (RFC 5780 §4.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatMapping {
    /// No NAT: the reflexive equals the local address.
    Open,
    /// One external mapping for every destination — a cone NAT. Punchable.
    EndpointIndependent,
    /// The mapping changes with the destination IP (restricted cone).
    AddressDependent,
    /// The mapping changes with destination IP *and* port — symmetric. Not
    /// punchable; use an explicit forward (`--port-map`) or the relay.
    AddressAndPortDependent,
}

impl NatMapping {
    /// Whether the basic outer-socket punch can traverse this NAT.
    pub fn is_punchable(self) -> bool {
        matches!(self, NatMapping::Open | NatMapping::EndpointIndependent)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            NatMapping::Open => "open (no NAT)",
            NatMapping::EndpointIndependent => "endpoint-independent (cone)",
            NatMapping::AddressDependent => "address-dependent (restricted cone)",
            NatMapping::AddressAndPortDependent => "address-and-port-dependent (symmetric)",
        }
    }
}

/// Classify the NAT's mapping behaviour by probing `primary` (a dual-address
/// STUN server) per RFC 5780 §4.3:
///
/// - **Test I** → the primary address; learn our reflexive and the server's
///   `OTHER-ADDRESS` (its alternate IP:port).
/// - **Test II** → the alternate IP:port. Same reflexive ⇒ endpoint-independent.
/// - **Test III** → the primary IP with the alternate port. Same reflexive as
///   Test I ⇒ address-dependent; otherwise address-and-port-dependent.
pub async fn detect_mapping(primary: SocketAddr) -> Result<NatMapping, ProxyError> {
    let socket = UdpSocket::bind("0.0.0.0:0").await.map_err(ProxyError::Io)?;
    let local = socket.local_addr().map_err(ProxyError::Io)?;

    let (ma1, other) = binding(&socket, primary).await?;
    if same_addr(ma1, local) {
        return Ok(NatMapping::Open);
    }
    let Some(other) = other else {
        // A plain STUN server (no OTHER-ADDRESS): we learned the reflexive but
        // cannot classify. Report the safe assumption.
        return Err(ProxyError::Quic(
            "STUN server does not support RFC 5780 (no OTHER-ADDRESS)".into(),
        ));
    };

    let (ma2, _) = binding(&socket, other).await?;
    if same_addr(ma1, ma2) {
        return Ok(NatMapping::EndpointIndependent);
    }

    // Test III: primary IP, alternate port. Same mapping as Test I (same IP,
    // different port) ⇒ the port does not matter ⇒ address-dependent.
    let test3 = SocketAddr::new(primary.ip(), other.port());
    let (ma3, _) = binding(&socket, test3).await?;
    if same_addr(ma1, ma3) {
        Ok(NatMapping::AddressDependent)
    } else {
        Ok(NatMapping::AddressAndPortDependent)
    }
}

/// One Binding transaction: returns (our reflexive XOR-MAPPED-ADDRESS, the
/// server's OTHER-ADDRESS if present).
async fn binding(
    socket: &UdpSocket,
    server: SocketAddr,
) -> Result<(SocketAddr, Option<SocketAddr>), ProxyError> {
    let txid = new_txid();
    let req = encode_binding_request(&txid);
    let mut buf = vec![0u8; 1500];
    for _ in 0..ATTEMPTS {
        socket.send_to(&req, server).await.map_err(ProxyError::Io)?;
        match tokio::time::timeout(ATTEMPT_TIMEOUT, socket.recv_from(&mut buf)).await {
            Ok(Ok((n, _from))) => return parse_binding_response(&buf[..n], &txid),
            Ok(Err(e)) => return Err(ProxyError::Io(e)),
            Err(_) => continue,
        }
    }
    Err(ProxyError::Quic("STUN server did not respond".into()))
}

fn same_addr(a: SocketAddr, b: SocketAddr) -> bool {
    a == b
}

// --- wire codec -------------------------------------------------------------

/// A 20-byte Binding Request with no attributes.
fn encode_binding_request(txid: &[u8; 12]) -> Vec<u8> {
    let mut b = Vec::with_capacity(20);
    b.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
    b.extend_from_slice(&0u16.to_be_bytes()); // length
    b.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    b.extend_from_slice(txid);
    b
}

/// Parse a Binding Success Response: verify the header/cookie/txid, then read
/// XOR-MAPPED-ADDRESS (required) and OTHER-ADDRESS (optional).
fn parse_binding_response(
    buf: &[u8],
    txid: &[u8; 12],
) -> Result<(SocketAddr, Option<SocketAddr>), ProxyError> {
    if buf.len() < 20 {
        return Err(ProxyError::Quic("short STUN response".into()));
    }
    let mtype = u16::from_be_bytes([buf[0], buf[1]]);
    let len = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if mtype != BINDING_SUCCESS || cookie != MAGIC_COOKIE || &buf[8..20] != txid {
        return Err(ProxyError::Quic(
            "not a matching STUN success response".into(),
        ));
    }
    if 20 + len > buf.len() {
        return Err(ProxyError::Quic("STUN length past buffer".into()));
    }

    let mut off = 20;
    let mut mapped = None;
    let mut other = None;
    while off + 4 <= 20 + len {
        let atype = u16::from_be_bytes([buf[off], buf[off + 1]]);
        let alen = u16::from_be_bytes([buf[off + 2], buf[off + 3]]) as usize;
        let val_start = off + 4;
        if val_start + alen > buf.len() {
            break;
        }
        let val = &buf[val_start..val_start + alen];
        match atype {
            ATTR_XOR_MAPPED_ADDRESS => mapped = decode_addr(val, true, txid),
            ATTR_OTHER_ADDRESS => other = decode_addr(val, false, txid),
            _ => {}
        }
        // Attributes are padded to a 4-byte boundary.
        off = val_start + alen.div_ceil(4) * 4;
    }
    let mapped = mapped.ok_or_else(|| ProxyError::Quic("no XOR-MAPPED-ADDRESS".into()))?;
    Ok((mapped, other))
}

/// Decode a (XOR-)MAPPED-ADDRESS / OTHER-ADDRESS value (IPv4 only). When `xor`,
/// the port and address are XOR-folded with the magic cookie (RFC 5389 §15.2).
fn decode_addr(val: &[u8], xor: bool, _txid: &[u8; 12]) -> Option<SocketAddr> {
    if val.len() < 8 || val[1] != FAMILY_V4 {
        return None;
    }
    let mut port = u16::from_be_bytes([val[2], val[3]]);
    let mut octets = [val[4], val[5], val[6], val[7]];
    if xor {
        port ^= (MAGIC_COOKIE >> 16) as u16;
        let a = u32::from_be_bytes(octets) ^ MAGIC_COOKIE;
        octets = a.to_be_bytes();
    }
    Some(SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3])),
        port,
    ))
}

/// Encode a (XOR-)MAPPED-ADDRESS / OTHER-ADDRESS value for `addr` (IPv4).
pub fn encode_addr(addr: SocketAddr, xor: bool) -> Vec<u8> {
    let (ip, mut port) = match addr {
        SocketAddr::V4(v4) => (*v4.ip(), v4.port()),
        SocketAddr::V6(_) => return Vec::new(),
    };
    let mut octets = ip.octets();
    if xor {
        port ^= (MAGIC_COOKIE >> 16) as u16;
        octets = (u32::from_be_bytes(octets) ^ MAGIC_COOKIE).to_be_bytes();
    }
    let mut v = Vec::with_capacity(8);
    v.push(0); // reserved
    v.push(FAMILY_V4);
    v.extend_from_slice(&port.to_be_bytes());
    v.extend_from_slice(&octets);
    v
}

// --- server side (relay) ----------------------------------------------------

/// Run an RFC 5780 STUN server on the diagonal of `primary`/`alternate`: it
/// binds all four `(IP, port)` combinations so a client's three mapping tests
/// each reach a listener, and answers each Binding Request with the client's
/// XOR-MAPPED-ADDRESS plus the OTHER-ADDRESS pointing at the *other* IP and
/// port. Needs the relay's two addresses. Runs until a socket errors.
pub async fn serve(primary: SocketAddr, alternate: SocketAddr) -> Result<(), ProxyError> {
    let (ipa, pa) = (primary.ip(), primary.port());
    let (ipb, pb) = (alternate.ip(), alternate.port());
    // (listen address, its OTHER-ADDRESS = the diagonally-opposite IP:port).
    let combos = [
        (SocketAddr::new(ipa, pa), SocketAddr::new(ipb, pb)),
        (SocketAddr::new(ipa, pb), SocketAddr::new(ipb, pa)),
        (SocketAddr::new(ipb, pa), SocketAddr::new(ipa, pb)),
        (SocketAddr::new(ipb, pb), SocketAddr::new(ipa, pa)),
    ];
    let mut tasks = Vec::new();
    for (listen, other) in combos {
        let sock = UdpSocket::bind(listen).await.map_err(ProxyError::Io)?;
        tracing::info!(%listen, %other, "STUN server socket up");
        tasks.push(tokio::spawn(serve_socket(sock, other)));
    }
    for t in tasks {
        let _ = t.await;
    }
    Ok(())
}

async fn serve_socket(sock: UdpSocket, other: SocketAddr) {
    let mut buf = vec![0u8; 1500];
    loop {
        let (n, from) = match sock.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(_) => return,
        };
        if let Some(txid) = parse_binding_request(&buf[..n]) {
            let resp = encode_binding_response(&txid, from, Some(other));
            let _ = sock.send_to(&resp, from).await;
        }
    }
}

/// If `buf` is a STUN Binding Request with the magic cookie, return its
/// transaction id.
fn parse_binding_request(buf: &[u8]) -> Option<[u8; 12]> {
    if buf.len() < 20 {
        return None;
    }
    let mtype = u16::from_be_bytes([buf[0], buf[1]]);
    let cookie = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    if mtype != BINDING_REQUEST || cookie != MAGIC_COOKIE {
        return None;
    }
    let mut txid = [0u8; 12];
    txid.copy_from_slice(&buf[8..20]);
    Some(txid)
}

/// Build a Binding Success Response carrying XOR-MAPPED-ADDRESS (`mapped`) and,
/// when present, OTHER-ADDRESS (`other`).
fn encode_binding_response(
    txid: &[u8; 12],
    mapped: SocketAddr,
    other: Option<SocketAddr>,
) -> Vec<u8> {
    let mut body = Vec::new();
    let mut push_attr = |atype: u16, val: Vec<u8>| {
        body.extend_from_slice(&atype.to_be_bytes());
        body.extend_from_slice(&(val.len() as u16).to_be_bytes());
        body.extend_from_slice(&val);
        while body.len() % 4 != 0 {
            body.push(0);
        }
    };
    push_attr(ATTR_XOR_MAPPED_ADDRESS, encode_addr(mapped, true));
    if let Some(o) = other {
        push_attr(ATTR_OTHER_ADDRESS, encode_addr(o, false));
    }

    let mut msg = Vec::with_capacity(20 + body.len());
    msg.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
    msg.extend_from_slice(&(body.len() as u16).to_be_bytes());
    msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    msg.extend_from_slice(txid);
    msg.extend_from_slice(&body);
    msg
}

/// A random 96-bit transaction id.
fn new_txid() -> [u8; 12] {
    use ring::rand::SecureRandom;
    let mut t = [0u8; 12];
    let _ = ring::rand::SystemRandom::new().fill(&mut t);
    t
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn binding_request_header() {
        let txid = [7u8; 12];
        let req = encode_binding_request(&txid);
        assert_eq!(req.len(), 20);
        assert_eq!(u16::from_be_bytes([req[0], req[1]]), BINDING_REQUEST);
        assert_eq!(
            u32::from_be_bytes([req[4], req[5], req[6], req[7]]),
            MAGIC_COOKIE
        );
        assert_eq!(&req[8..20], &txid);
    }

    #[test]
    fn xor_mapped_address_round_trips() {
        let addr: SocketAddr = "198.51.100.7:41000".parse().unwrap();
        let val = encode_addr(addr, true);
        // The encoded address (val[4..8]) must not equal the plaintext (XOR-folded).
        assert_ne!(&val[4..8], &[198, 51, 100, 7]);
        assert_eq!(decode_addr(&val, true, &[0u8; 12]), Some(addr));

        // OTHER-ADDRESS is plaintext.
        let plain = encode_addr(addr, false);
        assert_eq!(&plain[4..8], &[198, 51, 100, 7]);
        assert_eq!(decode_addr(&plain, false, &[0u8; 12]), Some(addr));
    }

    #[test]
    fn parses_a_full_response() {
        let txid = [3u8; 12];
        let mapped: SocketAddr = "203.0.113.9:50000".parse().unwrap();
        let other: SocketAddr = "203.0.113.10:3479".parse().unwrap();

        let mut msg = Vec::new();
        msg.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        let body_len_pos = msg.len();
        msg.extend_from_slice(&0u16.to_be_bytes()); // length placeholder
        msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        msg.extend_from_slice(&txid);
        let mut body = Vec::new();
        for (atype, val) in [
            (ATTR_XOR_MAPPED_ADDRESS, encode_addr(mapped, true)),
            (ATTR_OTHER_ADDRESS, encode_addr(other, false)),
        ] {
            body.extend_from_slice(&atype.to_be_bytes());
            body.extend_from_slice(&(val.len() as u16).to_be_bytes());
            body.extend_from_slice(&val);
        }
        let len = body.len() as u16;
        msg[body_len_pos..body_len_pos + 2].copy_from_slice(&len.to_be_bytes());
        msg.extend_from_slice(&body);

        let (got_mapped, got_other) = parse_binding_response(&msg, &txid).unwrap();
        assert_eq!(got_mapped, mapped);
        assert_eq!(got_other, Some(other));

        // A wrong transaction id is rejected.
        assert!(parse_binding_response(&msg, &[9u8; 12]).is_err());
    }

    #[test]
    fn punchability() {
        assert!(NatMapping::EndpointIndependent.is_punchable());
        assert!(NatMapping::Open.is_punchable());
        assert!(!NatMapping::AddressAndPortDependent.is_punchable());
        assert!(!NatMapping::AddressDependent.is_punchable());
    }
}
