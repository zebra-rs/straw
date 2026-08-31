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
use std::time::Duration;

use bytes::Bytes;
use noq::udp::{RecvMeta, Transmit};
use noq::{AsyncUdpSocket, UdpSender};
use tokio::sync::{Notify, mpsc};

use crate::codepoints::CAPSULE_COMPRESSION_CLOSE;
use crate::error::ProxyError;
use crate::udp_bind::context::{Binding, CompressionAssign, ContextTable, encode_context_capsule};

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
///
/// The framing is whatever the context table can carry: a compressed context
/// bound to `dst` if one is active (the post-lockdown steady state, §10.4),
/// otherwise the uncompressed context that spells the address out. `None`
/// means neither exists — after lockdown that is the correct answer for any
/// destination but the peer, and the packet is dropped rather than leaked.
fn frame_bind(
    qsid: u64,
    contexts: &Mutex<ContextTable>,
    dst: SocketAddr,
    contents: &[u8],
) -> Option<Bytes> {
    let body = {
        let table = contexts.lock().unwrap();
        let id = table
            .compressed_context_for(dst)
            .or_else(|| table.uncompressed_context())?;
        table.encode_datagram(id, dst, contents).ok()?
    };
    let mut wire = bytes::BytesMut::with_capacity(8 + body.len());
    crate::capsule::codec::write_varint(&mut wire, qsid).expect("qsid fits varint");
    wire.extend_from_slice(&body);
    Some(wire.freeze())
}

/// A QUIC socket whose datagrams ride a bind session (design §4).
#[derive(Debug)]
pub struct RelaySocket {
    /// The *outer* bind session (upstream quinn), over which inner packets ride
    /// as CONNECT-UDP bind datagrams.
    conn: quinn::Connection,
    qsid: u64,
    contexts: Arc<Mutex<ContextTable>>,
    capsules: mpsc::Sender<Bytes>,
    acked: Arc<Notify>,
    local: SocketAddr,
    inbound: Mutex<mpsc::Receiver<(SocketAddr, Bytes)>>,
    _recv: AbortOnDrop,
}

impl RelaySocket {
    /// Wire up a relay socket from a bind session's parts. `recv_task` owns
    /// the request stream (keeping the session open) and feeds `inbound`.
    /// Build from the shared [`RelayParts`] seam.
    pub(crate) fn from_parts(parts: RelayParts) -> Self {
        Self {
            conn: parts.conn,
            qsid: parts.qsid,
            contexts: parts.contexts,
            capsules: parts.capsules,
            acked: parts.acked,
            local: parts.local,
            inbound: Mutex::new(parts.rx),
            _recv: AbortOnDrop(parts.recv_task),
        }
    }

    /// The §10.4 lockdown for this session, bound to `peer`.
    ///
    /// A relay-only socket talks to one peer as much as a mux does; the
    /// difference is only that nothing here *learns* the address, so the
    /// caller names it.
    pub fn lockdown_for(&self, peer: SocketAddr) -> RelayLockdown {
        RelayLockdown {
            contexts: self.contexts.clone(),
            capsules: self.capsules.clone(),
            acked: self.acked.clone(),
            relay_remotes: Arc::new(Mutex::new(std::iter::once(peer).collect())),
        }
    }
}

/// The pieces a bind session hands to an inner-QUIC socket: the outer bind
/// connection, its framing params, our relay-public address, and the relay
/// receive pump (channel + its task). Shared by [`RelaySocket`] (relay only)
/// and [`PathMuxSocket`] (relay + direct).
pub struct RelayParts {
    pub conn: quinn::Connection,
    pub qsid: u64,
    /// Shared with the session's receive pump: it decodes inbound datagrams
    /// against this table and promotes a context when the relay ACKs it, while
    /// the send half picks its framing from it (§10.4).
    pub contexts: Arc<Mutex<ContextTable>>,
    /// Outbound capsules for the pump to write on the request stream — how
    /// the lockdown sends COMPRESSION_ASSIGN and COMPRESSION_CLOSE.
    pub capsules: mpsc::Sender<Bytes>,
    /// Signalled by the pump whenever a context is acknowledged.
    pub acked: Arc<Notify>,
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
    contexts: Arc<Mutex<ContextTable>>,
}

impl UdpSender for RelaySender {
    fn poll_send(
        self: Pin<&mut Self>,
        transmit: &Transmit<'_>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        // max_transmit_segments == 1, so a transmit is one datagram and
        // segment_size is None.
        let Some(wire) = frame_bind(
            self.qsid,
            &self.contexts,
            transmit.destination,
            transmit.contents,
        ) else {
            // No context can carry it: post-lockdown, to anyone but the peer.
            tracing::trace!(dst = %transmit.destination, "no relay context; dropping");
            return Poll::Ready(Ok(()));
        };
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
            contexts: self.contexts.clone(),
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
    lockdown: Option<RelayLockdown>,
}

impl PathMuxHandle {
    /// The direct socket's local bound address.
    pub fn direct_local(&self) -> SocketAddr {
        self.direct_local
    }

    /// The §10.4 relay lockdown for this session, if it has a relay path.
    pub fn lockdown(&self) -> Option<&RelayLockdown> {
        self.lockdown.as_ref()
    }

    /// A handle with no socket behind it, so candidate assembly can be tested
    /// against a known port without standing up an endpoint.
    #[cfg(test)]
    pub(crate) fn for_test(direct_local: SocketAddr) -> Self {
        Self {
            direct_local,
            lockdown: None,
        }
    }
}

/// The §10.4 lockdown: once a direct path carries the traffic, bind the peer
/// to a *compressed* context and close the uncompressed one.
///
/// The point is the relay's edge. Its bind port is public and forwards what
/// arrives; while an uncompressed context is open, anything that reaches that
/// port is forwarded to us as an inner-QUIC packet to parse. With only a
/// compressed context registered, the relay drops everything that is not from
/// the bound peer, before it ever reaches us.
///
/// The relay path itself is *not* closed — it stays as the permanent fallback
/// (design G3). Lockdown only narrows what may travel it, so a later fallback
/// still works, now with the address elided from every datagram.
#[derive(Clone, Debug)]
pub struct RelayLockdown {
    contexts: Arc<Mutex<ContextTable>>,
    capsules: mpsc::Sender<Bytes>,
    acked: Arc<Notify>,
    relay_remotes: Arc<Mutex<HashSet<SocketAddr>>>,
}

/// How long to wait for the relay's COMPRESSION_ACK before giving up and
/// leaving the uncompressed context open.
const ACK_TIMEOUT: Duration = Duration::from_secs(5);

impl RelayLockdown {
    /// The peer's relay-facing address, once one is known.
    pub fn peer(&self) -> Option<SocketAddr> {
        self.relay_remotes.lock().unwrap().iter().copied().next()
    }

    /// Engage the lockdown: register a compressed context for the peer, wait
    /// for the relay to acknowledge it, then close the uncompressed one.
    ///
    /// Ordering matters and is not an accident: the compressed context has to
    /// be *acknowledged* before the uncompressed one goes, or a fallback in
    /// that window would have no context able to carry it and the relay path
    /// would silently blackhole. On timeout it leaves everything as it was —
    /// an open uncompressed context is a wider attack surface, not a broken
    /// session.
    pub async fn engage(&self) -> Result<SocketAddr, ProxyError> {
        let Some(peer) = self.peer() else {
            return Err(ProxyError::InvalidRequest(
                "no relay remote learned; nothing to bind a context to".into(),
            ));
        };
        let (assign_id, uncompressed) = {
            let mut table = self.contexts.lock().unwrap();
            if table.compressed_context_for(peer).is_some() {
                return Ok(peer); // already engaged
            }
            let uncompressed = table.uncompressed_context().ok_or_else(|| {
                ProxyError::InvalidRequest("uncompressed context already closed".into())
            })?;
            // Client-allocated ids are even (RFC 9297 §3.2).
            let id = uncompressed + 2;
            let assign = CompressionAssign {
                context_id: id,
                binding: Binding::Compressed(peer),
            };
            table
                .register(assign.clone())
                .map_err(|e| ProxyError::InvalidRequest(e.to_string()))?;
            let mut buf = bytes::BytesMut::new();
            assign.encode(&mut buf);
            self.capsules
                .try_send(buf.freeze())
                .map_err(|e| ProxyError::InvalidRequest(format!("capsule queue: {e}")))?;
            (id, uncompressed)
        };

        // Wait for the pump to promote it on COMPRESSION_ACK.
        let activated = tokio::time::timeout(ACK_TIMEOUT, async {
            loop {
                let wait = self.acked.notified();
                if self.contexts.lock().unwrap().binding(assign_id).is_some() {
                    return;
                }
                wait.await;
            }
        })
        .await;
        if activated.is_err() {
            self.contexts.lock().unwrap().close(assign_id);
            return Err(ProxyError::InvalidRequest(
                "relay did not acknowledge the compressed context".into(),
            ));
        }

        // Only now is it safe to drop the uncompressed context.
        let mut buf = bytes::BytesMut::new();
        encode_context_capsule(CAPSULE_COMPRESSION_CLOSE, uncompressed, &mut buf);
        self.capsules
            .try_send(buf.freeze())
            .map_err(|e| ProxyError::InvalidRequest(format!("capsule queue: {e}")))?;
        self.contexts.lock().unwrap().close(uncompressed);
        tracing::info!(%peer, context = assign_id, "relay locked down to the peer (§10.4)");
        Ok(peer)
    }
}

/// A noq socket that multiplexes a relay tunnel and a real UDP socket.
#[derive(Debug)]
pub struct PathMuxSocket {
    relay: quinn::Connection,
    qsid: u64,
    contexts: Arc<Mutex<ContextTable>>,
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
    contexts: Arc<Mutex<ContextTable>>,
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
            let Some(wire) = frame_bind(
                self.qsid,
                &self.contexts,
                transmit.destination,
                transmit.contents,
            ) else {
                tracing::trace!(dst = %transmit.destination, "no relay context; dropping");
                return Poll::Ready(Ok(()));
            };
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
            contexts: self.contexts.clone(),
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
        contexts: parts.contexts.clone(),
        local: parts.local,
        direct,
        direct_local,
        relay_remotes: relay_remotes.clone(),
        relay_rx: Mutex::new(parts.rx),
        _recv: AbortOnDrop(parts.recv_task),
    };
    let endpoint = noq::Endpoint::new_with_abstract_socket(
        noq::EndpointConfig::default(),
        server_config,
        Box::new(socket),
        Arc::new(noq::TokioRuntime),
    )?;
    Ok((
        endpoint,
        PathMuxHandle {
            direct_local,
            lockdown: Some(RelayLockdown {
                contexts: parts.contexts,
                capsules: parts.capsules,
                acked: parts.acked,
                relay_remotes,
            }),
        },
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn table_with(uncompressed: u64, compressed: Option<(u64, SocketAddr)>) -> Mutex<ContextTable> {
        let mut t = ContextTable::new();
        t.register(CompressionAssign {
            context_id: uncompressed,
            binding: Binding::Uncompressed,
        })
        .unwrap();
        t.ack(uncompressed).unwrap();
        if let Some((id, peer)) = compressed {
            t.register(CompressionAssign {
                context_id: id,
                binding: Binding::Compressed(peer),
            })
            .unwrap();
            t.ack(id).unwrap();
        }
        Mutex::new(t)
    }

    /// Framing follows the table, and the choice is what §10.4 turns on: while
    /// the uncompressed context is open every destination is reachable, and
    /// once it is closed only the bound peer is — anything else must be
    /// dropped rather than sent with a framing the relay would refuse.
    #[test]
    fn framing_prefers_the_compressed_context_and_stops_at_lockdown() {
        let peer = addr("198.51.100.7:443");
        let other = addr("203.0.113.9:443");

        // Before lockdown: both destinations ride the uncompressed context,
        // which spells the address out (so the body is longer than the input).
        let open = table_with(2, None);
        let to_peer = frame_bind(4, &open, peer, b"hello").expect("uncompressed carries the peer");
        assert!(
            frame_bind(4, &open, other, b"hello").is_some(),
            "and anyone else"
        );

        // After the compressed context is acked, the peer's datagrams elide
        // the address: same payload, strictly smaller wire.
        let bound = table_with(2, Some((4, peer)));
        let compressed = frame_bind(4, &bound, peer, b"hello").expect("compressed carries it");
        assert!(
            compressed.len() < to_peer.len(),
            "compressed framing should be smaller: {} vs {}",
            compressed.len(),
            to_peer.len()
        );

        // After lockdown — uncompressed closed — only the peer is reachable.
        let locked = table_with(2, Some((4, peer)));
        locked.lock().unwrap().close(2);
        assert!(
            frame_bind(4, &locked, peer, b"hello").is_some(),
            "the relay path must keep working for the peer (design G3)"
        );
        assert!(
            frame_bind(4, &locked, other, b"hello").is_none(),
            "no context can carry anyone else; the packet must be dropped"
        );
    }

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
