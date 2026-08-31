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

use std::io;
use std::net::SocketAddr;
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
        Poll::Ready(
            self.conn
                .send_datagram(wire)
                .map_err(io::Error::other),
        )
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
