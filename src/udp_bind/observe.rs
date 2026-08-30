//! On-path punch observer — relay-assisted symmetric-NAT traversal (design §12).
//!
//! The relay routes packets between the two peers' NATs, so it sees each peer's
//! *peer-facing* source: the mapping the far symmetric NAT created toward the
//! other peer, which neither peer can predict from its own reflexive. A raw
//! `AF_PACKET` capture reads those sources off the wire; the bind session then
//! signals each peer the other's real address (a PEER_REFLEXIVE capsule) to
//! dial. Needs `CAP_NET_RAW`; enabled with `--punch-observe`. Only useful when
//! the relay is L3-on-path between the peers.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::sync::mpsc;

/// A peer's public IP → a sink delivering the *other* peer's observed
/// peer-facing source to that peer's bind session.
type Registry = Arc<DashMap<IpAddr, mpsc::Sender<SocketAddr>>>;

/// Watches forwarded UDP and reports each peer's peer-facing source to the
/// other peer's bind session.
pub struct PunchObserver {
    registry: Registry,
}

impl std::fmt::Debug for PunchObserver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PunchObserver")
            .field("peers", &self.registry.len())
            .finish()
    }
}

impl PunchObserver {
    /// Open the capture socket and start the capture thread.
    pub fn spawn() -> std::io::Result<Arc<Self>> {
        let registry: Registry = Arc::new(DashMap::new());
        let fd = open_capture()?;
        let reg = registry.clone();
        std::thread::Builder::new()
            .name("punch-observer".into())
            .spawn(move || capture_loop(fd, reg))?;
        Ok(Arc::new(Self { registry }))
    }

    /// Deliver observed peer-facing sources destined for `peer_ip` to `tx`.
    pub fn register(&self, peer_ip: IpAddr, tx: mpsc::Sender<SocketAddr>) {
        self.registry.insert(peer_ip, tx);
    }

    /// Stop delivering to a torn-down session.
    pub fn unregister(&self, peer_ip: &IpAddr) {
        self.registry.remove(peer_ip);
    }
}

/// An `AF_PACKET`/`SOCK_DGRAM` socket capturing IPv4 on every interface (the
/// kernel strips the link layer, so reads start at the IP header).
fn open_capture() -> std::io::Result<OwnedFd> {
    const ETH_P_IP: u16 = 0x0800;
    let proto = ETH_P_IP.to_be() as libc::c_int;
    let fd = unsafe { libc::socket(libc::AF_PACKET, libc::SOCK_DGRAM, proto) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // SAFETY: `fd` is a fresh, owned, valid descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

fn capture_loop(fd: OwnedFd, registry: Registry) {
    let raw = fd.as_raw_fd();
    let mut buf = [0u8; 2048];
    // Signal each (dst, src) pair at most once per window so a punch's packet
    // storm does not flood the capsule stream.
    let mut recent: HashMap<(IpAddr, SocketAddr), Instant> = HashMap::new();
    loop {
        let n = unsafe { libc::recv(raw, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
        if n <= 0 {
            continue;
        }
        let Some((src, dst_ip)) = parse_ipv4_udp(&buf[..n as usize]) else {
            continue;
        };
        // Only peer↔peer punches: both ends must be registered peer IPs (a
        // peer↔relay bind flow has the relay's own IP at one end).
        if !registry.contains_key(&src.ip()) || !registry.contains_key(&dst_ip) {
            continue;
        }
        let key = (dst_ip, src);
        let now = Instant::now();
        if recent
            .get(&key)
            .is_some_and(|t| now.duration_since(*t) < Duration::from_secs(2))
        {
            continue;
        }
        recent.insert(key, now);
        if recent.len() > 512 {
            recent.retain(|_, t| now.duration_since(*t) < Duration::from_secs(5));
        }
        if let Some(tx) = registry.get(&dst_ip) {
            tracing::debug!(%src, %dst_ip, "observer: peer-facing source → signal");
            let _ = tx.try_send(src);
        }
    }
}

/// The (source address, destination IP) of an IPv4 UDP packet, or `None` if it
/// is not IPv4/UDP or is truncated.
fn parse_ipv4_udp(pkt: &[u8]) -> Option<(SocketAddr, IpAddr)> {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    if pkt[9] != 17 || pkt.len() < ihl + 4 {
        return None; // not UDP, or no room for the UDP ports
    }
    let src_ip = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst_ip = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    let src_port = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
    Some((
        SocketAddr::new(IpAddr::V4(src_ip), src_port),
        IpAddr::V4(dst_ip),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_udp_datagram() {
        // Minimal IPv4 (IHL=5) + UDP header: src 192.0.2.2:43007 → 192.0.2.6:*.
        let mut pkt = vec![0u8; 28];
        pkt[0] = 0x45; // v4, IHL 5
        pkt[9] = 17; // UDP
        pkt[12..16].copy_from_slice(&[192, 0, 2, 2]);
        pkt[16..20].copy_from_slice(&[192, 0, 2, 6]);
        pkt[20..22].copy_from_slice(&43007u16.to_be_bytes()); // src port
        pkt[22..24].copy_from_slice(&51698u16.to_be_bytes()); // dst port
        let (src, dst) = parse_ipv4_udp(&pkt).unwrap();
        assert_eq!(src, "192.0.2.2:43007".parse().unwrap());
        assert_eq!(dst, "192.0.2.6".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn rejects_non_udp_and_truncated() {
        let mut tcp = vec![0u8; 28];
        tcp[0] = 0x45;
        tcp[9] = 6; // TCP
        assert!(parse_ipv4_udp(&tcp).is_none());
        assert!(parse_ipv4_udp(&[0x45, 0, 0]).is_none());
    }
}
