//! Peer-to-peer VPN mode — straw's own RFC 9484 CONNECT-IP stack run over an
//! established strawcat peer connection (design §2.1 "h3 + CONNECT-IP", P3).
//!
//! The listener peer is the tunnel **server**: it assigns the connector an
//! address from a small subnet, stands up a local TUN device and the
//! forwarding engine, and runs the ordinary CONNECT-IP handler over the peer
//! connection. The connector is the **client**: it runs `TunnelClient` over the
//! same connection, receives its address, and pumps IP packets through its own
//! TUN. The result is a real IP tunnel between the two hosts — reusing
//! `capsule/`, `datagram/`, `forwarding/` and `session/` verbatim — that rides
//! whichever path the [`Session`](crate::p2p::session::Session) picked (relay or
//! punched).

use std::sync::{Arc, OnceLock};

use bytes::Bytes;
use ipnet::Ipv4Net;

use crate::address_pool::AddressPool;
use crate::client::{ClientAuth, TunnelClient};
use crate::config::ProxyConfig;
use crate::error::ProxyError;
use crate::forwarding::ForwardingEngine;
use crate::forwarding::icmp::IcmpSource;
use crate::forwarding::limiter::RateLimits;
use crate::forwarding::router::RouteTable;
use crate::forwarding::tun::{TunConfig, spawn_tun};
use crate::iface::{self, InterfaceSetup};
use crate::metrics::Metrics;
use crate::server::ProxyContext;
use crate::session::SessionManager;
use crate::session::auth::{AuthMode, Authenticator};

/// The `:authority` used for the inner CONNECT-IP request (cosmetic — the
/// peer is already SPKI-authenticated at the inner-TLS layer).
const PEER_AUTHORITY: &str = "peer";

/// Run the **server** side over `conn`: assign the connector an address from
/// `subnet`, run a TUN named `tun_name`, and forward until the connection
/// closes. Needs ambient `CAP_NET_ADMIN` (it shells out to `ip`).
pub async fn run_server(
    conn: noq::Connection,
    subnet: Ipv4Net,
    tun_name: String,
    mtu: u16,
) -> Result<(), ProxyError> {
    let ctx = build_context(subnet, tun_name, mtu)?;

    // Uplink: demux inbound QUIC DATAGRAMs to the forwarding engine.
    let demux_ctx = ctx.clone();
    let demux_conn = conn.clone();
    let demux = tokio::spawn(async move { noq_uplink_demux(demux_conn, demux_ctx).await });

    // Serve CONNECT-IP over HTTP/3 on the noq peer connection (h3-noq backend).
    let mut h3_conn = h3::server::builder()
        .enable_extended_connect(true)
        .enable_datagram(true)
        .build(crate::p2p::h3_noq::Connection::new(conn.clone()))
        .await?;
    let dgram: Arc<dyn crate::datagram::DatagramConn> = Arc::new(conn);

    let result = loop {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                let ctx = ctx.clone();
                let dgram = dgram.clone();
                tokio::spawn(async move {
                    let (req, stream) = match resolver.resolve_request().await {
                        Ok(r) => r,
                        Err(e) => {
                            tracing::debug!("failed to resolve request: {e}");
                            return;
                        }
                    };
                    // The peer is already SPKI-authenticated at the inner-TLS
                    // layer, so there is no client certificate to pass here.
                    if let Err(e) = crate::session::handler::handle_connect_ip_stream(
                        req, stream, dgram, None, 0, ctx,
                    )
                    .await
                    {
                        tracing::debug!("VPN session ended with error: {e}");
                    }
                });
            }
            Ok(None) => break Ok(()),
            Err(e) => break Err(e.into()),
        }
    };
    demux.abort();
    result
}

/// Read inbound QUIC DATAGRAMs off the noq peer connection and forward each IP
/// packet to the engine (the VPN server's uplink; mirrors the proxy's demux
/// without the CONNECT-UDP bind path).
async fn noq_uplink_demux(conn: noq::Connection, ctx: Arc<ProxyContext>) {
    use crate::session::SessionId;
    loop {
        let wire = match conn.read_datagram().await {
            Ok(d) => d,
            Err(e) => {
                tracing::trace!("VPN datagram demux ended: {e}");
                return;
            }
        };
        let (qsid, datagram) = match crate::datagram::decode_quic_datagram(wire) {
            Ok(d) => d,
            Err(e) => {
                tracing::trace!("malformed datagram dropped: {e}");
                continue;
            }
        };
        if datagram.context_id != crate::datagram::CONTEXT_ID_IP_PACKET {
            continue;
        }
        let session_id = SessionId::compose(0, qsid * 4);
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

/// Assemble a minimal single-tunnel proxy context (mirrors the relevant part of
/// `main.rs`): an address pool over `subnet`, a TUN device, and a forwarding
/// engine. Authentication is off — the peer is already pinned by inner TLS.
fn build_context(
    subnet: Ipv4Net,
    tun_name: String,
    mtu: u16,
) -> Result<Arc<ProxyContext>, ProxyError> {
    let config = ProxyConfig {
        ipv4_pool: subnet,
        tun: true,
        tun_name: tun_name.clone(),
        mtu,
        auth_mode: AuthMode::None,
        ..ProxyConfig::default()
    };

    let auth = Authenticator::new(AuthMode::None, Vec::new(), Vec::new());
    let metrics = Arc::new(Metrics::default());
    let pool = AddressPool::new(config.ipv4_pool, config.ipv6_pool);
    let route_table = Arc::new(RouteTable::new());

    // The engine is built after the device (it needs the device's sender), so
    // the inline ingress reaches it through a OnceLock set exactly once below.
    let (gateway, prefix) = pool.ipv4_gateway();
    let engine_slot: Arc<OnceLock<Arc<ForwardingEngine>>> = Arc::new(OnceLock::new());
    let ingress = engine_slot.clone();
    let channels = spawn_tun(
        &TunConfig {
            name: tun_name.clone(),
            mtu,
            ipv4: Some((gateway, prefix)),
            ipv6: None,
        },
        move |packet: Bytes| {
            if let Some(engine) = ingress.get()
                && let Err(e) = engine.dispatch_from_network(packet)
            {
                tracing::debug!("network packet dropped: {e}");
            }
        },
    )?;
    tracing::info!(name = %channels.name, %gateway, "VPN server TUN up");

    let icmp_source = IcmpSource {
        v4: gateway,
        v6: None,
    };
    let limits = RateLimits {
        packets_per_sec: 0,
        bytes_per_sec: 0,
    };
    let engine = Arc::new(ForwardingEngine::new(
        route_table,
        Some(channels.to_net),
        mtu,
        icmp_source,
        limits,
        metrics.clone(),
    ));
    let _ = engine_slot.set(engine.clone());

    let sessions = SessionManager::new(config.max_sessions);
    let udp_bind = Arc::new(crate::udp_bind::UdpBindState::disabled());

    Ok(Arc::new(ProxyContext {
        config,
        sessions,
        pool,
        engine,
        auth,
        metrics,
        udp_bind,
    }))
}

/// Run the **client** side over `conn`: request a CONNECT-IP tunnel, apply the
/// assigned address (and routes, unless `no_routes`) to a TUN named `tun_name`,
/// and pump packets until the connection closes. `mtu` overrides the sampled
/// tunnel MTU. Needs ambient `CAP_NET_ADMIN`.
pub async fn run_client(
    conn: noq::Connection,
    tun_name: String,
    mtu: Option<u16>,
    install_routes: bool,
    scope: Option<String>,
) -> Result<(), ProxyError> {
    // Scope the tunnel to the VPN subnet so the server advertises only that
    // route — a full (default) tunnel would capture the peer connection's own
    // transport and dead-lock it (design §8.3 flow scoping).
    let mut client = TunnelClient::over_noq_connection(
        conn,
        PEER_AUTHORITY,
        ClientAuth::None,
        scope.as_deref(),
        None,
    )
    .await?;
    client.wait_for_assignment().await?;

    let sender = client.sender();
    let mtu = match mtu {
        Some(m) => m,
        None => sender
            .max_packet_size()
            .and_then(|m| u16::try_from(m).ok())
            .ok_or_else(|| {
                ProxyError::Config(
                    "peer did not enable QUIC DATAGRAMs; cannot size the tunnel".into(),
                )
            })?,
    };

    let uplink = sender.clone();
    let channels = spawn_tun(
        &TunConfig {
            name: tun_name.clone(),
            mtu,
            ipv4: None,
            ipv6: None,
        },
        move |packet| {
            if let Err(e) = uplink.send_packet(packet) {
                tracing::debug!("packet not sent: {e}");
            }
        },
    )?;
    // macOS may have named the device something other than requested.
    let dev = channels.name.clone();
    tracing::info!(dev = %dev, mtu, "VPN client TUN up");

    // No pin route: the peer connection rides the relay/punch socket, not the
    // TUN, so no advertised route can capture it.
    let mut guard = Some(apply(&client, &dev, install_routes)?);
    client.set_packet_sink(channels.to_net.clone());

    // ADDRESS_ASSIGN / ROUTE_ADVERTISEMENT are full-state: a fresh capsule
    // replaces the installed state whole.
    loop {
        match client.process_next_capsules().await {
            Ok(capsules) => {
                if capsules.iter().any(reconfigures) {
                    drop(guard.take());
                    guard = Some(apply(&client, &dev, install_routes)?);
                }
            }
            Err(e) => {
                tracing::info!("VPN tunnel closed: {e}");
                return Ok(());
            }
        }
    }
}

fn apply(
    client: &TunnelClient,
    dev: &str,
    install_routes: bool,
) -> Result<iface::InterfaceGuard, ProxyError> {
    iface::configure(&InterfaceSetup {
        dev,
        assigned: &client.assigned,
        routes: &client.routes,
        pin: None,
        install_routes,
    })
}

fn reconfigures(capsule: &crate::capsule::Capsule) -> bool {
    use crate::capsule::Capsule;
    matches!(
        capsule,
        Capsule::AddressAssign(_) | Capsule::RouteAdvertisement(_)
    )
}
