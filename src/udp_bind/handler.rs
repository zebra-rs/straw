//! Per-stream CONNECT-UDP bind request handler (design §3.1, §7).
//!
//! Serves one `:protocol = connect-udp` + `connect-udp-bind: ?1` request:
//! authenticates (mandatory — §7.4), allocates a public (IP, port), binds a
//! [`BindSocket`] to it, answers 200 with `proxy-public-address`, then runs
//! the session — compression-context capsules on the request stream, UDP
//! payloads on the connection's datagrams — until the peer closes it.

use std::sync::{Arc, Mutex};

use bytes::{Bytes, BytesMut};
use http::{Method, Request, Response, StatusCode};
use tokio::sync::mpsc;

use crate::capsule::CapsuleBuffer;
use crate::capsule::codec::write_varint;
use crate::datagram::quarter_stream_id;
use crate::error::ProxyError;
use crate::forwarding::limiter::SessionLimiter;
use crate::server::ProxyContext;
use crate::session::SessionId;
use crate::udp_bind::context::{
    CAPSULE_COMPRESSION_ACK, CAPSULE_COMPRESSION_ASSIGN, CAPSULE_COMPRESSION_CLOSE,
    CompressionAssign, ContextTable, decode_context_capsule, encode_context_capsule,
};
use crate::udp_bind::socket::BindSocket;

/// The connect-udp Extended CONNECT protocol token (RFC 9298 §3).
pub const CONNECT_UDP_PROTOCOL: &str = "connect-udp";

const UDP_PATH_PREFIX: &str = "/.well-known/masque/udp/";
const SESSION_QUEUE_DEPTH: usize = 256;
/// How many allocated ports to try binding before giving up.
const BIND_ATTEMPTS: usize = 16;

type ServerStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

/// Validate and serve one CONNECT-UDP bind request stream.
pub async fn handle_connect_udp_bind_stream(
    req: Request<()>,
    mut stream: ServerStream,
    quinn_conn: quinn::Connection,
    conn_seq: u64,
    ctx: Arc<ProxyContext>,
) -> Result<(), ProxyError> {
    // 1. Validate: connect-udp + bind + capsule protocol + udp path.
    if let Err(e) = validate_request(&req) {
        tracing::debug!("rejecting CONNECT-UDP request: {e}");
        respond(&mut stream, StatusCode::BAD_REQUEST).await?;
        return Err(e);
    }

    // 2. Bind mode must be enabled and authenticated (mandatory — §7.4).
    if !ctx.udp_bind.is_enabled() {
        respond(&mut stream, StatusCode::NOT_IMPLEMENTED).await?;
        return Err(ProxyError::Config("udp_bind is not enabled".into()));
    }
    let peer_cert = quinn_conn
        .peer_identity()
        .and_then(|any| {
            any.downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
                .ok()
        })
        .and_then(|certs| certs.first().cloned());
    if let Err(e) = ctx.auth.authenticate(req.headers(), peer_cert.as_ref()) {
        crate::metrics::Metrics::incr(&ctx.metrics.auth_failures_total);
        tracing::info!("bind authentication failed: {e}");
        respond(&mut stream, StatusCode::UNAUTHORIZED).await?;
        return Err(e);
    }

    // 3. Allocate a public tuple and bind a socket to it. A configured
    // port can be transiently taken (another process, or another relay on
    // the same host in tests), so skip a port whose bind fails and try the
    // next rather than failing the request.
    let allocator = ctx
        .udp_bind
        .allocator()
        .expect("allocator present when enabled")
        .clone();
    let contexts = Arc::new(Mutex::new(ContextTable::new()));
    let (public_addr, bind) = 'bind: {
        for _ in 0..BIND_ATTEMPTS {
            let Some(addr) = allocator.allocate() else {
                respond(&mut stream, StatusCode::SERVICE_UNAVAILABLE).await?;
                return Err(ProxyError::Config("no free bind address".into()));
            };
            match BindSocket::bind(
                addr,
                contexts.clone(),
                ctx.udp_bind.policy().clone(),
                Arc::new(SessionLimiter::new(ctx.udp_bind.egress_limits())),
            )
            .await
            {
                Ok(b) => break 'bind (addr, b),
                Err(e) => {
                    tracing::debug!(%addr, "bind failed, trying another port: {e}");
                    allocator.release(addr);
                }
            }
        }
        respond(&mut stream, StatusCode::SERVICE_UNAVAILABLE).await?;
        return Err(ProxyError::Config(
            "could not bind any allocated port".into(),
        ));
    };
    let bound_addr = bind.public_addr();

    let stream_id = stream.id().into_inner();
    let session_id = SessionId::compose(conn_seq, stream_id);
    let qsid = quarter_stream_id(stream_id);

    // 4. Accept: 200 with connect-udp-bind and the allocated public address.
    stream
        .send_response(
            Response::builder()
                .status(StatusCode::OK)
                .header("capsule-protocol", "?1")
                .header("connect-udp-bind", "?1")
                .header("proxy-public-address", format!("\"{bound_addr}\""))
                .body(())
                .unwrap(),
        )
        .await?;

    // Report the peer's outer source (its server-reflexive candidate for
    // hole punching, design §5.1) once on session open.
    {
        let mut buf = BytesMut::new();
        crate::udp_bind::context::encode_observed_address(quinn_conn.remote_address(), &mut buf);
        stream.send_data(buf.freeze()).await?;
    }

    // 5. Wire the data plane. `to_peer` carries encapsulated datagrams from
    // the socket back to the peer over QUIC; `from_peer` carries the peer's
    // datagrams (routed here by the connection demux) to the socket.
    let (from_peer_tx, from_peer_rx) = mpsc::channel::<Bytes>(SESSION_QUEUE_DEPTH);
    let (to_peer_tx, mut to_peer_rx) = mpsc::channel::<Bytes>(SESSION_QUEUE_DEPTH);
    ctx.udp_bind.register(session_id, from_peer_tx);
    let socket_task = tokio::spawn(bind.run(from_peer_rx, to_peer_tx));

    // Socket → peer: prepend the Quarter Stream ID and send as a datagram.
    let egress_conn = quinn_conn.clone();
    let egress = tokio::spawn(async move {
        while let Some(body) = to_peer_rx.recv().await {
            let mut wire = BytesMut::with_capacity(8 + body.len());
            write_varint(&mut wire, qsid).expect("qsid fits varint");
            wire.extend_from_slice(&body);
            if let Err(e) = egress_conn.send_datagram(wire.freeze()) {
                tracing::trace!("bind datagram send failed: {e}");
            }
        }
    });

    crate::metrics::Metrics::incr(&ctx.metrics.sessions_total);
    tracing::info!(session = %session_id, %bound_addr, "bind session established");

    // 6. Capsule loop: compression-context registration on the stream.
    let result = run_capsules(&mut stream, &contexts).await;

    // Teardown.
    egress.abort();
    socket_task.abort();
    ctx.udp_bind.unregister(session_id);
    allocator.release(public_addr);
    tracing::info!(session = %session_id, "bind session closed");
    result
}

fn validate_request(req: &Request<()>) -> Result<(), ProxyError> {
    if req.method() != Method::CONNECT {
        return Err(ProxyError::InvalidRequest(format!(
            "expected CONNECT, got {}",
            req.method()
        )));
    }
    let protocol = req
        .extensions()
        .get::<h3::ext::Protocol>()
        .ok_or_else(|| ProxyError::InvalidRequest(":protocol missing".into()))?;
    if protocol.as_str() != CONNECT_UDP_PROTOCOL {
        return Err(ProxyError::InvalidRequest(format!(
            "unsupported :protocol {}",
            protocol.as_str()
        )));
    }
    if !header_is(req, "connect-udp-bind", "?1") {
        return Err(ProxyError::InvalidRequest(
            "connect-udp-bind: ?1 header required".into(),
        ));
    }
    if !header_is(req, "capsule-protocol", "?1") {
        return Err(ProxyError::InvalidRequest(
            "capsule-protocol: ?1 header required".into(),
        ));
    }
    if !req.uri().path().starts_with(UDP_PATH_PREFIX) {
        return Err(ProxyError::InvalidRequest(format!(
            "path must start with {UDP_PATH_PREFIX}"
        )));
    }
    Ok(())
}

fn header_is(req: &Request<()>, name: &str, value: &str) -> bool {
    req.headers()
        .get(name)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.trim() == value)
}

/// Process COMPRESSION_ASSIGN/ACK/CLOSE until the peer closes the stream.
/// The relay is the datagram endpoint, so it acknowledges a peer's ASSIGN
/// (activating the context) and applies the peer's CLOSE.
async fn run_capsules(
    stream: &mut ServerStream,
    contexts: &Arc<Mutex<ContextTable>>,
) -> Result<(), ProxyError> {
    let mut buffer = CapsuleBuffer::new();
    loop {
        match stream.recv_data().await? {
            Some(chunk) => {
                buffer.push(chunk);
                while let Some(capsule) = buffer.next_capsule()? {
                    if let crate::capsule::Capsule::Unknown { type_id, data } = capsule {
                        handle_context_capsule(stream, type_id, data, contexts).await?;
                    }
                }
            }
            None => return Ok(()),
        }
    }
}

async fn handle_context_capsule(
    stream: &mut ServerStream,
    type_id: u64,
    data: Bytes,
    contexts: &Arc<Mutex<ContextTable>>,
) -> Result<(), ProxyError> {
    match type_id {
        CAPSULE_COMPRESSION_ASSIGN => {
            let assign = CompressionAssign::decode(data)?;
            let context_id = assign.context_id;
            let outcome = {
                let mut table = contexts.lock().unwrap();
                table.register(assign).and_then(|()| table.ack(context_id))
            };
            match outcome {
                // Acknowledge activation so the peer may use the context.
                Ok(()) => {
                    let mut buf = BytesMut::new();
                    encode_context_capsule(CAPSULE_COMPRESSION_ACK, context_id, &mut buf);
                    stream.send_data(buf.freeze()).await?;
                    tracing::debug!(context_id, "compression context registered");
                }
                Err(e) => tracing::debug!(context_id, "rejecting context: {e}"),
            }
        }
        CAPSULE_COMPRESSION_CLOSE => {
            let context_id = decode_context_capsule(data)?;
            contexts.lock().unwrap().close(context_id);
            tracing::debug!(context_id, "compression context closed");
        }
        // A relay-allocated context would be ACKed by the peer; we allocate
        // none in v1, so a stray ACK is simply ignored (RFC 9297 §3.2).
        CAPSULE_COMPRESSION_ACK => {}
        other => tracing::trace!(type_id = other, "ignoring unknown capsule"),
    }
    Ok(())
}

async fn respond(stream: &mut ServerStream, status: StatusCode) -> Result<(), ProxyError> {
    stream
        .send_response(Response::builder().status(status).body(()).unwrap())
        .await?;
    stream.finish().await?;
    Ok(())
}
