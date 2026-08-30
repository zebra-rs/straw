//! QUIC/HTTP-3 listener: accepts connections, demultiplexes datagrams, and
//! dispatches Extended CONNECT requests to the session handler.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use bytes::{Buf, Bytes};
use quinn::crypto::rustls::QuicServerConfig;
use tokio::sync::watch;

use crate::address_pool::AddressPool;
use crate::config::ProxyConfig;
use crate::datagram::CONTEXT_ID_IP_PACKET;
use crate::error::ProxyError;
use crate::forwarding::ForwardingEngine;
use crate::metrics::Metrics;
use crate::session::auth::Authenticator;
use crate::session::{SessionId, SessionManager};

/// Shared state handed to every connection and session task.
#[derive(Debug)]
pub struct ProxyContext {
    pub config: ProxyConfig,
    pub sessions: SessionManager,
    pub pool: AddressPool,
    pub engine: Arc<ForwardingEngine>,
    pub auth: Authenticator,
    pub metrics: Arc<Metrics>,
    /// CONNECT-UDP bind state (the P2P relay); disabled unless configured.
    pub udp_bind: Arc<crate::udp_bind::UdpBindState>,
}

/// Build the QUIC server endpoint (TLS, ALPN h3, DATAGRAM support).
pub fn build_endpoint(
    config: &ProxyConfig,
    tls: rustls::ServerConfig,
) -> Result<quinn::Endpoint, ProxyError> {
    let quic_tls = QuicServerConfig::try_from(tls).map_err(|e| ProxyError::Tls(e.to_string()))?;
    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_tls));

    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        Duration::from_millis(config.idle_timeout_ms)
            .try_into()
            .map_err(|_| ProxyError::Config("idle timeout out of range".into()))?,
    ));
    // QUIC DATAGRAM frames (RFC 9221) are on by default in quinn; size the
    // receive buffer for bursts of MTU-sized packets.
    transport.datagram_receive_buffer_size(Some(config.mtu as usize * 512));
    transport.datagram_send_buffer_size(config.mtu as usize * 512);
    server_config.transport_config(Arc::new(transport));

    let endpoint = quinn::Endpoint::server(server_config, config.listen)?;
    Ok(endpoint)
}

/// Accept QUIC connections until the endpoint closes or shutdown begins.
///
/// On shutdown, established connections receive an HTTP/3 GOAWAY and keep
/// serving in-flight tunnels; the caller enforces the grace period.
pub async fn run_server(
    endpoint: quinn::Endpoint,
    ctx: Arc<ProxyContext>,
    mut shutdown: watch::Receiver<bool>,
) {
    let conn_seq = AtomicU64::new(0);
    loop {
        let incoming = tokio::select! {
            incoming = endpoint.accept() => incoming,
            _ = shutdown.changed() => {
                tracing::info!("shutdown: no longer accepting connections");
                return;
            }
        };
        let Some(incoming) = incoming else { return };

        let seq = conn_seq.fetch_add(1, Ordering::Relaxed);
        let ctx = ctx.clone();
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            match incoming.await {
                Ok(conn) => {
                    let remote = conn.remote_address();
                    tracing::info!(%remote, conn = seq, "connection established");
                    if let Err(e) = handle_connection(conn, seq, ctx, shutdown).await {
                        tracing::debug!(conn = seq, "connection ended: {e}");
                    }
                }
                Err(e) => tracing::debug!("handshake failed: {e}"),
            }
        });
    }
}

/// Reap sessions with no client activity past the configured timeout
/// (Step 26). Dropping the engine sink wakes the session handler, which
/// then runs its normal teardown.
pub fn spawn_idle_reaper(ctx: Arc<ProxyContext>) -> Option<tokio::task::JoinHandle<()>> {
    let timeout = Duration::from_secs(ctx.config.session_idle_timeout_sec);
    if timeout.is_zero() {
        return None;
    }
    let interval = (timeout / 2).clamp(Duration::from_millis(250), Duration::from_secs(30));
    Some(tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            ticker.tick().await;
            for id in ctx.sessions.idle_sessions(timeout) {
                tracing::info!(session = %id, "closing idle session");
                ctx.engine.unregister_session(id);
            }
        }
    }))
}

async fn handle_connection(
    conn: quinn::Connection,
    conn_seq: u64,
    ctx: Arc<ProxyContext>,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), ProxyError> {
    // Keep a raw handle for DATAGRAM I/O before h3 wraps the connection.
    let datagram_conn = conn.clone();
    let demux_ctx = ctx.clone();
    let demux = tokio::spawn(async move {
        run_datagram_demux(datagram_conn, conn_seq, demux_ctx).await;
    });

    let mut h3_conn: h3::server::Connection<h3_quinn::Connection, Bytes> = h3::server::builder()
        .enable_extended_connect(true)
        .enable_datagram(true)
        .build(h3_quinn::Connection::new(conn.clone()))
        .await?;

    let result = loop {
        let resolver = tokio::select! {
            resolver = h3_conn.accept() => resolver,
            _ = shutdown.changed() => {
                // Send GOAWAY: no new requests, existing tunnels continue
                // until the grace period closes the endpoint (Step 29).
                tracing::debug!(conn = conn_seq, "sending GOAWAY");
                if let Err(e) = h3_conn.shutdown(0).await {
                    break Err(e.into());
                }
                continue;
            }
        };
        match resolver {
            Ok(Some(resolver)) => {
                let quinn_conn = conn.clone();
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    let (req, stream) = match resolver.resolve_request().await {
                        Ok(r) => r,
                        Err(e) => {
                            tracing::debug!("failed to resolve request: {e}");
                            return;
                        }
                    };
                    tracing::debug!(method = %req.method(), uri = %req.uri(), "request");
                    let protocol = req
                        .extensions()
                        .get::<h3::ext::Protocol>()
                        .map(|p| p.as_str().to_owned());
                    let result = match protocol.as_deref() {
                        Some(crate::udp_bind::handler::CONNECT_UDP_PROTOCOL) => {
                            crate::udp_bind::handler::handle_connect_udp_bind_stream(
                                req, stream, quinn_conn, conn_seq, ctx,
                            )
                            .await
                        }
                        // connect-ip and everything else the IP handler
                        // validates and rejects as before.
                        _ => {
                            crate::session::handler::handle_connect_ip_stream(
                                req, stream, quinn_conn, conn_seq, ctx,
                            )
                            .await
                        }
                    };
                    if let Err(e) = result {
                        tracing::debug!("session ended with error: {e}");
                    }
                });
            }
            // Client closed the connection cleanly.
            Ok(None) => break Ok(()),
            Err(e) => break Err(e.into()),
        }
    };

    demux.abort();
    result
}

/// Receive QUIC DATAGRAMs for one connection and feed the forwarding engine.
///
/// Wire format (RFC 9297 §2.1 + RFC 9484 §6):
/// `Quarter Stream ID (i) | Context ID (i) | IP packet`.
async fn run_datagram_demux(conn: quinn::Connection, conn_seq: u64, ctx: Arc<ProxyContext>) {
    loop {
        let wire = match conn.read_datagram().await {
            Ok(d) => d,
            Err(e) => {
                tracing::trace!(conn = conn_seq, "datagram demux ended: {e}");
                return;
            }
        };
        // Peek the Quarter Stream ID to route the datagram: a bind session
        // carries compression-context framing (not the IP context), so its
        // datagrams go to that session's bound socket, not the engine.
        let mut cursor = wire.clone();
        let qsid = match crate::capsule::codec::read_varint(&mut cursor) {
            Ok(q) => q,
            Err(e) => {
                tracing::trace!("malformed datagram dropped: {e}");
                continue;
            }
        };
        let session_id = SessionId::compose(conn_seq, qsid * 4);
        if let Some(sink) = ctx.udp_bind.sink(session_id) {
            // Everything after the qsid is the HTTP Datagram body the bind
            // socket decodes; drop on backpressure (datagram semantics).
            let body = wire.slice(wire.len() - cursor.remaining()..);
            let _ = sink.try_send(body);
            continue;
        }
        let (qsid, datagram) = match crate::datagram::decode_quic_datagram(wire) {
            Ok(d) => d,
            Err(e) => {
                tracing::trace!("malformed datagram dropped: {e}");
                continue;
            }
        };
        // Unknown context IDs MUST be silently dropped (RFC 9297 §4).
        if datagram.context_id != CONTEXT_ID_IP_PACKET {
            continue;
        }
        let session_id = SessionId::compose(conn_seq, qsid * 4);
        let Some(assigned) = ctx.sessions.assigned_snapshot(session_id) else {
            tracing::trace!(session = %session_id, "datagram for unknown session dropped");
            continue;
        };
        match ctx
            .engine
            .forward_from_client(session_id, &assigned, datagram.payload)
        {
            Ok(_) => ctx.sessions.touch(session_id),
            Err(e) => tracing::debug!(session = %session_id, "packet dropped: {e}"),
        }
    }
}
