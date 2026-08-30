//! Per-stream CONNECT-IP request handler: tunnel establishment, capsule
//! processing, and the client-bound half of the data plane (design §9).

use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use http::{Method, Request, Response, StatusCode};
use tokio::sync::mpsc;

use crate::capsule::{
    AddressAssign, AssignedAddress, Capsule, CapsuleBuffer, IpAddressRange, RouteAdvertisement,
    encode_capsule, merge_ranges,
};
use crate::datagram::{IpProxyingDatagram, encode_quic_datagram, quarter_stream_id};
use crate::error::ProxyError;
use crate::forwarding::EgressPolicy;
use crate::forwarding::router::entries_from_client_ranges;
use crate::server::ProxyContext;
use crate::session::{SessionId, TunnelSession};
use crate::uri_template::parse_connect_ip_path;

/// The connect-ip Extended CONNECT protocol token (RFC 9484 §4.2).
pub const CONNECT_IP_PROTOCOL: &str = "connect-ip";

/// Depth of the per-session client-bound packet queue.
const SESSION_QUEUE_DEPTH: usize = 256;

type ServerStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

/// Validate and serve one CONNECT-IP request stream, blocking until the
/// tunnel closes. Sends the appropriate HTTP error for invalid requests.
pub async fn handle_connect_ip_stream(
    req: Request<()>,
    mut stream: ServerStream,
    quinn_conn: quinn::Connection,
    conn_seq: u64,
    ctx: Arc<ProxyContext>,
) -> Result<(), ProxyError> {
    // 1. Validate the Extended CONNECT request (RFC 9484 §4.2-4.4).
    let scope = match validate_request(&req) {
        Ok(scope) => scope,
        Err(e) => {
            tracing::debug!("rejecting CONNECT-IP request: {e}");
            let status = match &e {
                ProxyError::InvalidRequest(_) => StatusCode::BAD_REQUEST,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            stream
                .send_response(Response::builder().status(status).body(()).unwrap())
                .await?;
            stream.finish().await?;
            return Err(e);
        }
    };

    let stream_id = stream.id().into_inner();
    let session_id = SessionId::compose(conn_seq, stream_id);
    let qsid = quarter_stream_id(stream_id);

    // 2. Create the session (enforces the session limit).
    let session = TunnelSession::new(session_id, scope);
    if let Err(e) = ctx.sessions.insert(session) {
        stream
            .send_response(
                Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .body(())
                    .unwrap(),
            )
            .await?;
        stream.finish().await?;
        return Err(e);
    }

    // From here on, all exits must run teardown.
    let result = run_tunnel(&mut stream, quinn_conn, session_id, qsid, &ctx).await;

    ctx.pool.release(session_id);
    ctx.engine.route_table().remove_session(session_id);
    ctx.engine.unregister_session(session_id);
    ctx.sessions.remove(session_id);
    tracing::info!(session = %session_id, "tunnel closed");
    result
}

fn validate_request(req: &Request<()>) -> Result<crate::uri_template::RequestScope, ProxyError> {
    if req.method() != Method::CONNECT {
        return Err(ProxyError::InvalidRequest(format!(
            "expected CONNECT, got {}",
            req.method()
        )));
    }
    let protocol = req
        .extensions()
        .get::<h3::ext::Protocol>()
        .ok_or_else(|| ProxyError::InvalidRequest(":protocol pseudo-header missing".into()))?;
    if protocol.as_str() != CONNECT_IP_PROTOCOL {
        return Err(ProxyError::InvalidRequest(format!(
            "unsupported :protocol {}",
            protocol.as_str()
        )));
    }
    // RFC 9484 §4.4: the request MUST declare capsule protocol support.
    let capsule_ok = req
        .headers()
        .get("capsule-protocol")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.trim() == "?1");
    if !capsule_ok {
        return Err(ProxyError::InvalidRequest(
            "capsule-protocol: ?1 header required".into(),
        ));
    }
    parse_connect_ip_path(req.uri().path())
}

async fn run_tunnel(
    stream: &mut ServerStream,
    quinn_conn: quinn::Connection,
    session_id: SessionId,
    qsid: u64,
    ctx: &Arc<ProxyContext>,
) -> Result<(), ProxyError> {
    // 3. Accept the tunnel.
    stream
        .send_response(
            Response::builder()
                .status(StatusCode::OK)
                .header("capsule-protocol", "?1")
                .body(())
                .unwrap(),
        )
        .await?;

    // 4. Allocate addresses (unprompted assignment) and advertise routes.
    let mut assigned: Vec<AssignedAddress> = Vec::new();
    if let Some(a) = ctx.pool.allocate_v4(session_id) {
        assigned.push(a);
    }
    if let Some(a) = ctx.pool.allocate_v6(session_id) {
        assigned.push(a);
    }
    if assigned.is_empty() {
        return Err(ProxyError::PoolExhausted);
    }

    let routes = advertised_routes(ctx);
    send_capsule(
        stream,
        &Capsule::AddressAssign(AddressAssign {
            assigned_addresses: assigned.clone(),
        }),
    )
    .await?;
    send_capsule(
        stream,
        &Capsule::RouteAdvertisement(RouteAdvertisement {
            ip_address_ranges: routes.clone(),
        }),
    )
    .await?;

    // 5. Install forwarding state. The egress policy is exactly what was
    // advertised (RFC 9484 §4.7.3: clients MUST NOT send outside it).
    let (client_tx, mut client_rx) = mpsc::channel::<Bytes>(SESSION_QUEUE_DEPTH);
    for a in &assigned {
        ctx.engine
            .route_table()
            .insert_client_addr(a.ip_address, session_id);
    }
    ctx.engine.register_session(
        session_id,
        client_tx,
        EgressPolicy::new(std::sync::Arc::new(routes.clone())),
    );
    ctx.sessions.set_assigned(session_id, assigned.clone());

    tracing::info!(
        session = %session_id,
        addrs = ?assigned.iter().map(|a| a.ip_address).collect::<Vec<_>>(),
        "tunnel established"
    );

    // 6. Forwarding loop: capsules on the stream, packets to the client.
    let mut capsules = CapsuleBuffer::new();
    loop {
        tokio::select! {
            // Capsule stream from the client.
            data = stream.recv_data() => {
                match data {
                    Ok(Some(chunk)) => {
                        capsules.push(chunk);
                        while let Some(capsule) = capsules.next_capsule()? {
                            handle_capsule(stream, capsule, session_id, &mut assigned, ctx).await?;
                        }
                        ctx.sessions.touch(session_id);
                    }
                    // FIN: the client closed the tunnel.
                    Ok(None) => return Ok(()),
                    Err(e) => return Err(e.into()),
                }
            }
            // Packets routed toward this client (hairpin or TUN ingress).
            packet = client_rx.recv() => {
                let Some(packet) = packet else { return Ok(()) };
                send_packet_datagram(&quinn_conn, qsid, packet);
            }
        }
    }
}

/// Send one IP packet to the client as an HTTP Datagram. Datagrams are
/// best-effort: failures other than connection loss just drop the packet.
fn send_packet_datagram(conn: &quinn::Connection, qsid: u64, packet: Bytes) {
    let datagram = IpProxyingDatagram::ip_packet(packet);
    let wire = encode_quic_datagram(qsid, &datagram);
    if let Some(max) = conn.max_datagram_size()
        && wire.len() > max
    {
        tracing::trace!(
            len = wire.len(),
            max,
            "dropping packet exceeding datagram size"
        );
        return;
    }
    if let Err(e) = conn.send_datagram(wire) {
        tracing::trace!("send_datagram failed: {e}");
    }
}

async fn handle_capsule(
    stream: &mut ServerStream,
    capsule: Capsule,
    session_id: SessionId,
    assigned: &mut Vec<AssignedAddress>,
    ctx: &Arc<ProxyContext>,
) -> Result<(), ProxyError> {
    match capsule {
        // Client requests specific addresses. ADDRESS_ASSIGN is full-state:
        // reply with the complete current assignment set (RFC 9484 §4.7.1).
        Capsule::AddressRequest(req) => {
            for request in &req.requested_addresses {
                if let Some(a) = ctx.pool.allocate_for_request(session_id, request) {
                    ctx.engine
                        .route_table()
                        .insert_client_addr(a.ip_address, session_id);
                    assigned.push(a);
                }
                // Unassignable requests are simply absent from the reply.
            }
            ctx.sessions.set_assigned(session_id, assigned.clone());
            send_capsule(
                stream,
                &Capsule::AddressAssign(AddressAssign {
                    assigned_addresses: assigned.clone(),
                }),
            )
            .await?;
        }
        // Client advertises routes toward its side (site-to-site, Step 22):
        // install them when the operator opted in, full-state semantics.
        Capsule::RouteAdvertisement(ra) => {
            if ctx.config.accept_client_routes {
                let entries = entries_from_client_ranges(
                    session_id,
                    &ra.ip_address_ranges,
                    &ctx.pool.pool_nets(),
                );
                tracing::info!(session = %session_id, ranges = ra.ip_address_ranges.len(),
                    prefixes = entries.len(), "installing client routes");
                ctx.engine
                    .route_table()
                    .replace_session_routes(session_id, entries);
            } else {
                tracing::debug!(session = %session_id, ranges = ra.ip_address_ranges.len(),
                    "client route advertisement recorded (--accept-client-routes off)");
            }
            ctx.sessions
                .set_client_routes(session_id, ra.ip_address_ranges);
        }
        // A client assigning addresses to the proxy end of the tunnel
        // (site-to-site): record them; the proxy does not originate traffic.
        Capsule::AddressAssign(assign) => {
            tracing::debug!(session = %session_id, count = assign.assigned_addresses.len(),
                "client assigned addresses to the proxy");
            ctx.sessions
                .set_proxy_addresses(session_id, assign.assigned_addresses);
        }
        // RFC 9297 §3.2: unknown capsule types MUST be ignored.
        Capsule::Unknown { type_id, .. } => {
            tracing::trace!(session = %session_id, type_id, "ignoring unknown capsule");
        }
    }
    Ok(())
}

async fn send_capsule(stream: &mut ServerStream, capsule: &Capsule) -> Result<(), ProxyError> {
    let mut buf = BytesMut::new();
    encode_capsule(capsule, &mut buf);
    stream.send_data(buf.freeze()).await?;
    Ok(())
}

/// Full-tunnel route advertisement: everything, all protocols (design §6.1).
pub fn full_tunnel_routes(include_v6: bool) -> Vec<IpAddressRange> {
    let mut routes = vec![IpAddressRange {
        ip_version: 4,
        start_ip: "0.0.0.0".parse().unwrap(),
        end_ip: "255.255.255.255".parse().unwrap(),
        ip_protocol: 0,
    }];
    if include_v6 {
        routes.push(IpAddressRange {
            ip_version: 6,
            start_ip: "::".parse().unwrap(),
            end_ip: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap(),
            ip_protocol: 0,
        });
    }
    routes
}

/// The routes this proxy advertises (and enforces) for a session:
/// full-tunnel by default, the configured prefixes in split-tunnel mode.
/// The client address pool is always included so tunnel clients can reach
/// each other and the gateway; overlaps are merged into a valid capsule.
fn advertised_routes(ctx: &Arc<ProxyContext>) -> Vec<IpAddressRange> {
    let mut ranges: Vec<IpAddressRange> = ctx
        .pool
        .pool_nets()
        .into_iter()
        .map(|net| IpAddressRange::from_net(net, 0))
        .collect();

    if ctx.config.split_routes.is_empty() {
        ranges.extend(full_tunnel_routes(ctx.config.ipv6_pool.is_some()));
    } else {
        ranges.extend(
            ctx.config
                .split_routes
                .iter()
                .map(|net| IpAddressRange::from_net(*net, 0)),
        );
    }
    merge_ranges(ranges)
}
