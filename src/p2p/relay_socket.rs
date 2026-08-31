//! An inner-QUIC transport that runs over a CONNECT-UDP bind session
//! (design §4, Phase B).
//!
//! [`RelaySocket`] implements [`noq::AsyncUdpSocket`], so a whole QUIC
//! endpoint — the peer-to-peer inner connection — can run on top of a bind
//! session instead of a real UDP socket. Each inner-QUIC packet is sent as a
//! bind datagram addressed to the far peer's relay-public address (`paddr`);
//! packets arriving from the relay are delivered back to the inner endpoint.
//! The relay forwards ciphertext it cannot read, which is where the
//! end-to-end privacy win lands (design G1).
//!
//! The inner endpoint sees its own `paddr` as the local address and the far
//! peer's `paddr` as the remote — an ordinary UDP path, ~40–60 bytes smaller
//! MTU (the bind framing).
//!
//! The inner QUIC stack is **noq** (the n0/iroh quinn fork), which straw
//! adopts for its native multipath + NAT-traversal support; the *outer* bind
//! session ([`conn`](RelaySocket::conn)) remains upstream quinn (it is an
//! HTTP/3 CONNECT-UDP connection). This type is the bridge between the two.

use std::collections::HashSet;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::Bytes;
use noq::udp::{RecvMeta, Transmit};
use noq::{AsyncUdpSocket, UdpSender};
use tokio::sync::mpsc;

use crate::udp_bind::context::encode_uncompressed_body;

/// Aborts its task when dropped, so tearing down the socket ends the recv
/// pump and drops the bind request stream (closing the relay session).
#[derive(Debug)]
struct AbortOnDrop(tokio::task::JoinHandle<()>);
impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Encode one inner packet to `dst` as a bind datagram on session `qsid`.
fn frame_bind(qsid: u64, uncompressed: u64, dst: SocketAddr, contents: &[u8]) -> Bytes {
    let body = encode_uncompressed_body(uncompressed, dst, contents);
    let mut wire = bytes::BytesMut::with_capacity(8 + body.len());
    crate::capsule::codec::write_varint(&mut wire, qsid).expect("qsid fits varint");
    wire.extend_from_slice(&body);
    wire.freeze()
}

/// A QUIC socket whose datagrams ride a bind session (design §4).
#[derive(Debug)]
pub struct RelaySocket {
    /// The *outer* bind session (upstream quinn), over which inner packets ride
    /// as CONNECT-UDP bind datagrams.
    conn: quinn::Connection,
    qsid: u64,
    uncompressed: u64,
    local: SocketAddr,
    inbound: Mutex<mpsc::Receiver<(SocketAddr, Bytes)>>,
    _recv: AbortOnDrop,
}

impl RelaySocket {
    /// Wire up a relay socket from a bind session's parts. `recv_task` owns
    /// the request stream (keeping the session open) and feeds `inbound`.
    pub(crate) fn new(
        conn: quinn::Connection,
        qsid: u64,
        uncompressed: u64,
        local: SocketAddr,
        inbound: mpsc::Receiver<(SocketAddr, Bytes)>,
        recv_task: tokio::task::JoinHandle<()>,
    ) -> Self {
        Self {
            conn,
            qsid,
            uncompressed,
            local,
            inbound: Mutex::new(inbound),
            _recv: AbortOnDrop(recv_task),
        }
    }

    /// Build from the shared [`RelayParts`] seam.
    pub(crate) fn from_parts(parts: RelayParts) -> Self {
        Self::new(
            parts.conn,
            parts.qsid,
            parts.uncompressed,
            parts.local,
            parts.rx,
            parts.recv_task,
        )
    }
}

/// The pieces a bind session hands to an inner-QUIC socket: the outer bind
/// connection, its framing params, our relay-public address, and the relay
/// receive pump (channel + its task). Shared by [`RelaySocket`] (relay only)
/// and [`PathMuxSocket`] (relay + direct).
pub struct RelayParts {
    pub conn: quinn::Connection,
    pub qsid: u64,
    pub uncompressed: u64,
    pub local: SocketAddr,
    pub rx: mpsc::Receiver<(SocketAddr, Bytes)>,
    pub recv_task: tokio::task::JoinHandle<()>,
}

/// The send half noq asks for via [`AsyncUdpSocket::create_sender`]. A bind
/// send is a synchronous `send_datagram`, so it is always immediately ready.
#[derive(Debug)]
struct RelaySender {
    conn: quinn::Connection,
    qsid: u64,
    uncompressed: u64,
}

impl UdpSender for RelaySender {
    fn poll_send(
        self: Pin<&mut Self>,
        transmit: &Transmit<'_>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        // max_transmit_segments == 1, so a transmit is one datagram and
        // segment_size is None.
        let wire = frame_bind(
            self.qsid,
            self.uncompressed,
            transmit.destination,
            transmit.contents,
        );
        Poll::Ready(self.conn.send_datagram(wire).map_err(io::Error::other))
    }

    fn max_transmit_segments(&self) -> NonZeroUsize {
        NonZeroUsize::MIN
    }
}

impl AsyncUdpSocket for RelaySocket {
    fn create_sender(&self) -> Pin<Box<dyn UdpSender>> {
        Box::pin(RelaySender {
            conn: self.conn.clone(),
            qsid: self.qsid,
            uncompressed: self.uncompressed,
        })
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let rx = self.inbound.get_mut().unwrap();
        let mut n = 0;
        while n < bufs.len() {
            match rx.poll_recv(cx) {
                Poll::Ready(Some((addr, payload))) => {
                    let len = payload.len().min(bufs[n].len());
                    bufs[n][..len].copy_from_slice(&payload[..len]);
                    // noq's RecvMeta is #[non_exhaustive]; build via Default.
                    let mut m = RecvMeta::default();
                    m.addr = addr;
                    m.len = len;
                    m.stride = len;
                    m.ecn = None;
                    m.dst_ip = Some(self.local.ip());
                    meta[n] = m;
                    n += 1;
                }
                // Deliver whatever is ready; only block when nothing is.
                Poll::Ready(None) => {
                    return if n == 0 {
                        Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "relay session closed",
                        )))
                    } else {
                        Poll::Ready(Ok(n))
                    };
                }
                Poll::Pending => {
                    return if n == 0 {
                        Poll::Pending
                    } else {
                        Poll::Ready(Ok(n))
                    };
                }
            }
        }
        Poll::Ready(Ok(n))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }

    fn may_fragment(&self) -> bool {
        false
    }

    fn max_receive_segments(&self) -> NonZeroUsize {
        NonZeroUsize::MIN
    }
}

/// Build an inner-QUIC endpoint that runs over `socket` (a bind session).
/// Pass `server_config` to accept inner connections (the peer whose role is
/// inner-QUIC *server*, design §2.1); omit it for a dial-only endpoint.
pub fn inner_endpoint(
    socket: RelaySocket,
    server_config: Option<noq::ServerConfig>,
) -> io::Result<noq::Endpoint> {
    noq::Endpoint::new_with_abstract_socket(
        noq::EndpointConfig::default(),
        server_config,
        Box::new(socket),
        Arc::new(noq::TokioRuntime),
    )
}

// ─────────────────────────────────────────────────────────────────────────
// Combined-transport socket (Stage 3): one AsyncUdpSocket carrying both the
// relay path (through the outer bind tunnel) and a direct path (a real UDP
// socket), so a single noq connection holds both and migrates relay→direct
// natively. Sends are routed by destination: an address known to be a *relay*
// remote — the peer's relay-paddr, preset by the dialer and learned from
// relay-pump receives by the acceptor — is tunnelled; **everything else goes
// out the real socket**. Direct-by-default is what makes noq's frame-based
// NAT traversal work unmodified: its probes target peer candidates the
// application never sees (the server learns them from REACH_OUT frames inside
// the QUIC layer), so they cannot be registered ahead of time — but they are
// never a relay-paddr, so the default routes them correctly. Receives from
// both sources are merged, each tagged with its local IP so noq sees two
// distinct paths of one connection.
//
// A bind session serves exactly **one** peer, so there is exactly one relay
// remote: that peer's paddr. The route table is sized to say so — the dialer
// presets it and learns nothing further, the acceptor learns the one source it
// is answering and then stops listening.
//
// That bound is the security property, not an optimisation. The relay's bind
// socket is a public UDP port that accepts from anyone, and it forwards what
// arrives. Without the bound, any spoofed source would be added to the tunnel
// route, and a later NAT-traversal probe aimed at that address would ride the
// relay instead of the real socket — the peer's own candidate could be
// captured this way, wasting the punch. Learning one address closes that: an
// attacker would have to beat the real peer's first packet, on a session whose
// paddr they must already know, and the result is still only inner-QUIC
// ciphertext they cannot read (design G1).
// ─────────────────────────────────────────────────────────────────────────

/// A handle to a [`PathMuxSocket`] owned by the noq endpoint: read the local
/// direct socket's bound address (for candidate gathering by the punch).
#[derive(Clone, Debug)]
pub struct PathMuxHandle {
    direct_local: SocketAddr,
}

impl PathMuxHandle {
    /// The direct socket's local bound address.
    pub fn direct_local(&self) -> SocketAddr {
        self.direct_local
    }

    /// A handle with no socket behind it, so candidate assembly can be tested
    /// against a known port without standing up an endpoint.
    #[cfg(test)]
    pub(crate) fn for_test(direct_local: SocketAddr) -> Self {
        Self { direct_local }
    }
}

/// A noq socket that multiplexes a relay tunnel and a real UDP socket.
#[derive(Debug)]
pub struct PathMuxSocket {
    relay: quinn::Connection,
    qsid: u64,
    uncompressed: u64,
    local: SocketAddr,
    direct: Arc<tokio::net::UdpSocket>,
    direct_local: SocketAddr,
    relay_remotes: Arc<Mutex<HashSet<SocketAddr>>>,
    relay_rx: Mutex<mpsc::Receiver<(SocketAddr, Bytes)>>,
    _recv: AbortOnDrop,
}

/// The send half of a [`PathMuxSocket`]: routes by destination.
#[derive(Debug)]
struct PathMuxSender {
    relay: quinn::Connection,
    qsid: u64,
    uncompressed: u64,
    direct: Arc<tokio::net::UdpSocket>,
    relay_remotes: Arc<Mutex<HashSet<SocketAddr>>>,
}

impl UdpSender for PathMuxSender {
    fn poll_send(
        self: Pin<&mut Self>,
        transmit: &Transmit<'_>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        let via_relay = self
            .relay_remotes
            .lock()
            .unwrap()
            .contains(&transmit.destination);
        if via_relay {
            // Relay path: tunnel through the outer bind connection.
            let wire = frame_bind(
                self.qsid,
                self.uncompressed,
                transmit.destination,
                transmit.contents,
            );
            Poll::Ready(self.relay.send_datagram(wire).map_err(io::Error::other))
        } else {
            // Everything else — including NAT-traversal probes to peer
            // candidates the application never sees — is a direct send.
            match self
                .direct
                .poll_send_to(cx, transmit.contents, transmit.destination)
            {
                Poll::Ready(Ok(_)) => Poll::Ready(Ok(())),
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        }
    }

    fn max_transmit_segments(&self) -> NonZeroUsize {
        NonZeroUsize::MIN
    }
}

impl AsyncUdpSocket for PathMuxSocket {
    fn create_sender(&self) -> Pin<Box<dyn UdpSender>> {
        Box::pin(PathMuxSender {
            relay: self.relay.clone(),
            qsid: self.qsid,
            uncompressed: self.uncompressed,
            direct: self.direct.clone(),
            relay_remotes: self.relay_remotes.clone(),
        })
    }

    fn poll_recv(
        &mut self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut n = 0;
        // 1. Direct socket (real UDP): drain what is ready.
        while n < bufs.len() {
            let mut rb = tokio::io::ReadBuf::new(&mut bufs[n]);
            match self.direct.poll_recv_from(cx, &mut rb) {
                Poll::Ready(Ok(src)) => {
                    let len = rb.filled().len();
                    meta[n] = mk_meta(src, len, self.direct_local.ip());
                    n += 1;
                }
                // A direct-socket error must not tear down the connection (the
                // relay path may still be fine); stop draining it this round.
                Poll::Ready(Err(_)) | Poll::Pending => break,
            }
        }
        // 2. Relay tunnel: drain the pump channel.
        let rx = self.relay_rx.get_mut().unwrap();
        while n < bufs.len() {
            match rx.poll_recv(cx) {
                Poll::Ready(Some((src, payload))) => {
                    let len = payload.len().min(bufs[n].len());
                    bufs[n][..len].copy_from_slice(&payload[..len]);
                    meta[n] = mk_meta(src, len, self.local.ip());
                    // Reply to a tunnelled source through the tunnel. The
                    // acceptor learns the dialer's paddr this way, before it
                    // ever has to send (its first send answers this packet).
                    // Only the first source is learned — see the note above.
                    let mut relay_remotes = self.relay_remotes.lock().unwrap();
                    if relay_remotes.is_empty() {
                        tracing::debug!(%src, "relay path bound to peer");
                        relay_remotes.insert(src);
                    }
                    drop(relay_remotes);
                    n += 1;
                }
                Poll::Ready(None) => {
                    return if n == 0 {
                        Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            "relay session closed",
                        )))
                    } else {
                        Poll::Ready(Ok(n))
                    };
                }
                Poll::Pending => break,
            }
        }
        if n > 0 {
            Poll::Ready(Ok(n))
        } else {
            Poll::Pending
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local)
    }

    fn may_fragment(&self) -> bool {
        false
    }

    fn max_receive_segments(&self) -> NonZeroUsize {
        NonZeroUsize::MIN
    }
}

fn mk_meta(addr: SocketAddr, len: usize, dst_ip: IpAddr) -> RecvMeta {
    let mut m = RecvMeta::default();
    m.addr = addr;
    m.len = len;
    m.stride = len;
    m.ecn = None;
    m.dst_ip = Some(dst_ip);
    m
}

/// Build an inner-QUIC endpoint over a **combined-transport** socket: the relay
/// tunnel (`parts`) plus `direct` (a bound real UDP socket for direct paths).
///
/// `relay_peer` is the far peer's relay-public address for a *dialing*
/// endpoint: its first packet has to be tunnelled, and nothing has arrived yet
/// to learn that from. An accepting endpoint passes `None` — it learns the
/// dialer's paddr from the packet it is answering.
///
/// Returns the endpoint and a [`PathMuxHandle`] for candidate gathering.
pub fn mux_endpoint(
    parts: RelayParts,
    direct: tokio::net::UdpSocket,
    server_config: Option<noq::ServerConfig>,
    relay_peer: Option<SocketAddr>,
) -> io::Result<(noq::Endpoint, PathMuxHandle)> {
    let direct_local = direct.local_addr()?;
    let direct = Arc::new(direct);
    let relay_remotes: Arc<Mutex<HashSet<SocketAddr>>> =
        Arc::new(Mutex::new(relay_peer.into_iter().collect()));
    let socket = PathMuxSocket {
        relay: parts.conn,
        qsid: parts.qsid,
        uncompressed: parts.uncompressed,
        local: parts.local,
        direct,
        direct_local,
        relay_remotes,
        relay_rx: Mutex::new(parts.rx),
        _recv: AbortOnDrop(parts.recv_task),
    };
    let endpoint = noq::Endpoint::new_with_abstract_socket(
        noq::EndpointConfig::default(),
        server_config,
        Box::new(socket),
        Arc::new(noq::TokioRuntime),
    )?;
    Ok((endpoint, PathMuxHandle { direct_local }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    /// The routing decision under test, isolated from the socket: a
    /// destination in the relay set is tunnelled, everything else is sent
    /// direct.
    fn routes_via_relay(set: &Mutex<HashSet<SocketAddr>>, dst: SocketAddr) -> bool {
        set.lock().unwrap().contains(&dst)
    }

    /// What `poll_recv` does when a datagram arrives from the relay pump.
    fn learn(set: &Mutex<HashSet<SocketAddr>>, src: SocketAddr) {
        let mut set = set.lock().unwrap();
        if set.is_empty() {
            set.insert(src);
        }
    }

    #[test]
    fn a_dialer_presets_its_peer_and_learns_nothing_more() {
        let peer = addr("198.51.100.1:30001");
        let set = Mutex::new(HashSet::from([peer]));

        // The preset peer is tunnelled; a candidate address is not.
        assert!(routes_via_relay(&set, peer));
        assert!(!routes_via_relay(&set, addr("203.0.113.9:41000")));

        // Anything the relay forwards afterwards leaves the route untouched.
        learn(&set, addr("203.0.113.9:41000"));
        assert!(!routes_via_relay(&set, addr("203.0.113.9:41000")));
        assert_eq!(set.lock().unwrap().len(), 1);
    }

    #[test]
    fn an_acceptor_learns_one_source_and_a_spoof_cannot_capture_a_candidate() {
        // The acceptor starts empty and binds to the first source it hears,
        // which is the dialer answering through the relay.
        let set = Mutex::new(HashSet::new());
        let peer = addr("198.51.100.1:30001");
        learn(&set, peer);
        assert!(routes_via_relay(&set, peer));

        // The relay's bind port is public, so anyone may send to it. A spoofed
        // source arriving later must NOT become a tunnel route: if it did, and
        // it named the peer's own direct candidate, the punch to that address
        // would be tunnelled back through the relay instead of going out the
        // real socket — capturing the direct path.
        let peer_candidate = addr("203.0.113.9:41000");
        learn(&set, peer_candidate);
        assert!(
            !routes_via_relay(&set, peer_candidate),
            "a later source must not capture the route"
        );
        assert_eq!(set.lock().unwrap().len(), 1, "exactly one relay remote");
    }
}
