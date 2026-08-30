//! straw server binary: RFC 9484 CONNECT-IP proxy.

use std::sync::Arc;

use clap::Parser;
use straw::address_pool::AddressPool;
use straw::config::ProxyConfig;
use straw::error::ProxyError;
use straw::forwarding::ForwardingEngine;
use straw::forwarding::router::RouteTable;
use straw::forwarding::tun::{TunConfig, spawn_tun};
use straw::server::{ProxyContext, build_endpoint, run_server};
use straw::session::SessionManager;
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

    let config = ProxyConfig::parse();
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
    let tls_config = tls::build_server_tls_config(certs, key)?;

    let pool = AddressPool::new(config.ipv4_pool, config.ipv6_pool);
    let route_table = Arc::new(RouteTable::new());

    // Optional kernel TUN device; without it only hairpin forwarding works.
    let mut tun_ingress = None;
    let tun_tx = if config.tun {
        let (gateway, prefix) = pool.ipv4_gateway();
        let channels = spawn_tun(&TunConfig {
            name: config.tun_name.clone(),
            mtu: config.mtu,
            ipv4: Some((gateway, prefix)),
        })?;
        tracing::info!(name = %config.tun_name, %gateway, "TUN device up");
        tun_ingress = Some(channels.from_net);
        Some(channels.to_net)
    } else {
        tracing::info!("running without TUN: client<->client hairpin forwarding only");
        None
    };

    let icmp_source = straw::forwarding::icmp::IcmpSource {
        v4: pool.ipv4_gateway().0,
        v6: pool.ipv6_gateway().map(|(addr, _)| addr),
    };
    let engine = Arc::new(ForwardingEngine::new(
        route_table,
        tun_tx,
        config.mtu,
        icmp_source,
    ));
    if let Some(rx) = tun_ingress {
        tokio::spawn(engine.clone().run_network_ingress(rx));
    }

    let sessions = SessionManager::new(config.max_sessions);
    let endpoint = build_endpoint(&config, tls_config)?;
    tracing::info!(listen = %config.listen, pool = %config.ipv4_pool, "straw proxy listening");

    let ctx = Arc::new(ProxyContext {
        config,
        sessions,
        pool,
        engine,
    });

    tokio::select! {
        _ = run_server(endpoint.clone(), ctx) => {}
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("shutting down");
        }
    }

    endpoint.close(0u32.into(), b"server shutdown");
    endpoint.wait_idle().await;
    Ok(())
}
