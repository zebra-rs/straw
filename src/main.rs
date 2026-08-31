//! straw server binary: RFC 9484 CONNECT-IP proxy.

use std::sync::Arc;
use std::time::Duration;

use straw::address_pool::AddressPool;
use straw::config::ProxyConfig;
use straw::error::ProxyError;
use straw::forwarding::ForwardingEngine;
use straw::forwarding::limiter::RateLimits;
use straw::forwarding::router::RouteTable;
use straw::forwarding::tun::{TunConfig, spawn_tun};
use straw::metrics::Metrics;
use straw::server::{ProxyContext, build_endpoint, run_server, spawn_idle_reaper};
use straw::session::SessionManager;
use straw::session::auth::{AuthMode, Authenticator};
use straw::tls;

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), ProxyError> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "straw=info".into()),
        )
        .init();
    straw::init_crypto();

    // Defaults < --config file < CLI flags (Step 31).
    let config = ProxyConfig::resolve()?;
    config.validate()?;

    // TLS: configured cert or a fresh self-signed one for development.
    let (certs, key) = match (&config.cert, &config.key) {
        (Some(cert), Some(key)) => tls::load_cert_chain(cert, key)?,
        _ => {
            tracing::warn!("no --cert/--key given; using a self-signed certificate");
            let (cert, key) = tls::generate_self_signed_cert(&["localhost"])?;
            (vec![cert], key)
        }
    };
    let tls_config = match (config.auth_mode, &config.client_ca) {
        (AuthMode::Mtls, Some(ca_path)) => {
            use rustls::pki_types::{CertificateDer, pem::PemObject};
            let pem = std::fs::read(ca_path)?;
            let ca_certs: Vec<CertificateDer<'static>> = CertificateDer::pem_slice_iter(&pem)
                .collect::<Result<_, _>>()
                .map_err(|e| ProxyError::Tls(e.to_string()))?;
            tls::build_server_tls_config_with_client_auth(certs, key, ca_certs)?
        }
        _ => tls::build_server_tls_config(certs, key)?,
    };

    let auth = Authenticator::new(
        config.auth_mode,
        config.auth_token.clone(),
        config.basic_credentials()?,
    );
    let metrics = Arc::new(Metrics::default());
    let pool = AddressPool::new(config.ipv4_pool, config.ipv6_pool);
    let route_table = Arc::new(RouteTable::new());

    // Optional kernel TUN device; without it only hairpin forwarding works.
    let mut tun_engine_slot = None;
    let tun_tx = if config.tun {
        let (gateway, prefix) = pool.ipv4_gateway();
        let ipv6 = pool.ipv6_gateway();
        // The engine is built after the device (it needs the device's
        // sender), so the inline ingress reaches it through a OnceLock —
        // set exactly once below, before any traffic can flow.
        let engine_slot: Arc<std::sync::OnceLock<Arc<ForwardingEngine>>> =
            Arc::new(std::sync::OnceLock::new());
        let ingress_engine = engine_slot.clone();
        let channels = spawn_tun(
            &TunConfig {
                name: config.tun_name.clone(),
                mtu: config.mtu,
                ipv4: Some((gateway, prefix)),
                ipv6,
            },
            move |packet| {
                if let Some(engine) = ingress_engine.get()
                    && let Err(e) = engine.dispatch_from_network(packet)
                {
                    tracing::debug!("network packet dropped: {e}");
                }
            },
        )?;
        tracing::info!(name = %channels.name, %gateway, "TUN device up");
        tun_engine_slot = Some(engine_slot);
        Some(channels.to_net)
    } else {
        tracing::info!("running without TUN: client<->client hairpin forwarding only");
        None
    };

    // NAT (Step 27): masquerade pool traffic out the physical interface.
    // The guard removes the rules again on shutdown.
    let _nat_guard = match &config.nat_interface {
        Some(iface) => Some(straw::forwarding::nat::setup_nat(&pool.pool_nets(), iface)?),
        None => None,
    };

    let icmp_source = straw::forwarding::icmp::IcmpSource {
        v4: pool.ipv4_gateway().0,
        v6: pool.ipv6_gateway().map(|(addr, _)| addr),
    };
    let limits = RateLimits {
        packets_per_sec: config.max_packet_rate,
        bytes_per_sec: config.max_byte_rate,
    };
    let engine = Arc::new(ForwardingEngine::new(
        route_table,
        tun_tx,
        config.mtu,
        icmp_source,
        limits,
        metrics.clone(),
    ));
    if let Some(slot) = tun_engine_slot {
        let _ = slot.set(engine.clone());
    }

    let sessions = SessionManager::new(config.max_sessions);
    let endpoint = build_endpoint(&config, tls_config)?;
    tracing::info!(
        listen = %config.listen,
        pool = %config.ipv4_pool,
        auth = ?config.auth_mode,
        "straw proxy listening"
    );

    // CONNECT-UDP bind state (the P2P relay); disabled unless configured.
    let udp_bind = Arc::new(if config.udp_bind {
        use straw::forwarding::limiter::RateLimits;
        use straw::udp_bind::UdpBindState;
        use straw::udp_bind::alloc::PortAllocator;
        use straw::udp_bind::socket::DestinationPolicy;
        let allocator = PortAllocator::new(
            config.udp_bind_public_ips.clone(),
            config.udp_bind_port_lo,
            config.udp_bind_port_hi,
        )
        .map_err(ProxyError::Config)?;
        tracing::info!(
            ips = ?config.udp_bind_public_ips,
            ports = format!("{}-{}", config.udp_bind_port_lo, config.udp_bind_port_hi),
            "CONNECT-UDP bind mode enabled"
        );
        UdpBindState::enabled(
            allocator,
            DestinationPolicy::new(config.udp_bind_allow_dest.clone(), Vec::new()),
            RateLimits {
                packets_per_sec: config.udp_bind_max_pps,
                bytes_per_sec: config.udp_bind_max_bps,
            },
        )
    } else {
        straw::udp_bind::UdpBindState::disabled()
    });

    let grace = Duration::from_secs(config.shutdown_grace_sec);
    let metrics_listen = config.metrics_listen;
    let ctx = Arc::new(ProxyContext {
        config,
        sessions,
        pool,
        engine,
        auth,
        metrics,
        udp_bind,
    });

    // Metrics endpoint (Step 28).
    if let Some(addr) = metrics_listen {
        let listener = tokio::net::TcpListener::bind(addr).await?;
        tracing::info!(%addr, "metrics endpoint up");
        tokio::spawn(straw::metrics::serve_metrics(listener, ctx.clone()));
    }

    // Idle session reaper (Step 26).
    let _reaper = spawn_idle_reaper(ctx.clone());

    // Graceful shutdown (Step 29): SIGINT/SIGTERM -> stop accepting, GOAWAY
    // established connections, drain within the grace period, then close.
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    // RFC 5780 STUN server (NAT behaviour discovery), if configured.
    if let (Some(primary), Some(alternate)) = (ctx.config.stun_addr, ctx.config.stun_alt_addr) {
        tracing::info!(%primary, %alternate, "RFC 5780 STUN server enabled");
        tokio::spawn(async move {
            if let Err(e) = straw::p2p::stun::serve(primary, alternate).await {
                tracing::warn!("STUN server stopped: {e}");
            }
        });
    }

    let server = tokio::spawn(run_server(endpoint.clone(), ctx.clone(), shutdown_rx));

    wait_for_termination().await;
    tracing::info!("shutting down: draining sessions (grace {grace:?})");
    let _ = shutdown_tx.send(true);

    let drained = tokio::time::timeout(grace, async {
        while !ctx.sessions.is_empty() {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .is_ok();
    if !drained {
        tracing::warn!(remaining = ctx.sessions.len(), "grace period expired");
    }

    endpoint.close(0u32.into(), b"server shutdown");
    endpoint.wait_idle().await;
    server.abort();
    Ok(())
}

/// Resolve on SIGINT (ctrl-c) or, on unix, SIGTERM.
async fn wait_for_termination() {
    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}
