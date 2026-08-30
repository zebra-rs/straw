//! An inner-QUIC transport that runs over a CONNECT-UDP bind session
//! (design §4, Phase B).
//!
//! [`RelaySocket`] implements [`quinn::AsyncUdpSocket`], so a whole QUIC
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

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::Bytes;
use quinn::udp::{RecvMeta, Transmit};
use quinn::{AsyncUdpSocket, UdpPoller};
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

/// A QUIC socket whose datagrams ride a bind session (design §4).
#[derive(Debug)]
pub struct RelaySocket {
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
    ) -> Arc<Self> {
        Arc::new(Self {
            conn,
            qsid,
            uncompressed,
            local,
            inbound: Mutex::new(inbound),
            _recv: AbortOnDrop(recv_task),
        })
    }

    /// Encode one inner packet to `dst` as a bind datagram on this session.
    fn frame(&self, dst: SocketAddr, contents: &[u8]) -> Bytes {
        let body = encode_uncompressed_body(self.uncompressed, dst, contents);
        let mut wire = bytes::BytesMut::with_capacity(8 + body.len());
        crate::capsule::codec::write_varint(&mut wire, self.qsid).expect("qsid fits varint");
        wire.extend_from_slice(&body);
        wire.freeze()
    }
}

/// A poller that reports the socket as always writable: a bind send is a
/// synchronous `send_datagram`, which never returns `WouldBlock`.
#[derive(Debug)]
struct AlwaysWritable;
impl UdpPoller for AlwaysWritable {
    fn poll_writable(self: Pin<&mut Self>, _cx: &mut Context) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncUdpSocket for RelaySocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(AlwaysWritable)
    }

    fn try_send(&self, transmit: &Transmit) -> io::Result<()> {
        // quinn is told max_transmit_segments == 1, so a transmit is one
        // datagram; segment_size is therefore None.
        let wire = self.frame(transmit.destination, transmit.contents);
        self.conn
            .send_datagram(wire)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut rx = self.inbound.lock().unwrap();
        let mut n = 0;
        while n < bufs.len() {
            match rx.poll_recv(cx) {
                Poll::Ready(Some((addr, payload))) => {
                    let len = payload.len().min(bufs[n].len());
                    bufs[n][..len].copy_from_slice(&payload[..len]);
                    meta[n] = RecvMeta {
                        addr,
                        len,
                        stride: len,
                        ecn: None,
                        dst_ip: Some(self.local.ip()),
                    };
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

    fn max_transmit_segments(&self) -> usize {
        1
    }

    fn max_receive_segments(&self) -> usize {
        1
    }
}

/// Build an inner-QUIC endpoint that runs over `socket` (a bind session).
/// Pass `server_config` to accept inner connections (the peer whose role is
/// inner-QUIC *server*, design §2.1); omit it for a dial-only endpoint.
pub fn inner_endpoint(
    socket: Arc<RelaySocket>,
    server_config: Option<quinn::ServerConfig>,
) -> io::Result<quinn::Endpoint> {
    quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        server_config,
        socket,
        Arc::new(quinn::TokioRuntime),
    )
}
