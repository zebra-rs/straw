//! strawc — CONNECT-IP client daemon.
//!
//! Establishes an RFC 9484 tunnel to a straw proxy, creates a TUN device,
//! applies the proxy's ADDRESS_ASSIGN and ROUTE_ADVERTISEMENT to the kernel,
//! and pumps IP packets between the device and the tunnel. This is what
//! turns straw from a protocol implementation into a usable VPN.
//!
//! Needs `CAP_NET_ADMIN` (or root) for the TUN device and routing changes:
//!
//! ```text
//! sudo strawc --server-addr 10.0.0.1:4433 --ca-cert proxy.pem
//! ```
//!
//! Everything installed is removed again on SIGINT/SIGTERM.

use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::time::Duration;

use clap::Parser;
use straw::client::{ClientAuth, PacketSender, TlsMode, TunnelClient};
use straw::error::ProxyError;
use straw::forwarding::tun::{TunConfig, spawn_tun};
use straw::iface::{self, InterfaceGuard, InterfaceSetup, configure};

/// Floor for the tunnel MTU; below this IPv6 cannot be carried (RFC 9484 §7.2).
const MIN_IPV6_MTU: u16 = 1280;

/// How often to re-sample the QUIC path MTU.
const MTU_POLL: Duration = Duration::from_secs(5);

/// Smallest gain worth reconfiguring the device for.
const MTU_STEP: u16 = 16;

#[derive(Debug, Parser)]
#[command(name = "strawc", version, about = "straw CONNECT-IP client daemon")]
struct Args {
    /// Proxy address.
    #[arg(long, default_value = "127.0.0.1:4433")]
    server_addr: SocketAddr,

    /// TLS server name (must match the proxy certificate).
    #[arg(long, default_value = "localhost")]
    server_name: String,

    /// Skip TLS certificate verification (testing only).
    #[arg(long)]
    insecure: bool,

    /// Trust this CA / self-signed certificate (PEM).
    #[arg(long, conflicts_with = "insecure")]
    ca_cert: Option<PathBuf>,

    /// Authenticate with this bearer token.
    #[arg(long)]
    bearer_token: Option<String>,

    /// Authenticate with these basic credentials (user:password).
    #[arg(long, conflicts_with = "bearer_token")]
    basic: Option<String>,

    /// Name for the local TUN device.
    #[arg(long, default_value = "strawc0")]
    tun_name: String,

    /// Tunnel MTU. Defaults to the largest IP packet that fits in one QUIC
    /// DATAGRAM on the current path.
    #[arg(long)]
    mtu: Option<u16>,

    /// Configure addresses but install no routes, leaving the system routing
    /// table untouched. Useful for testing the data plane in isolation.
    #[arg(long)]
    no_routes: bool,

    /// Request a tunnel scoped to this target: an IP, a prefix (a.b.c.d/n)
    /// or a hostname the proxy resolves (RFC 9484 §4.6). Only the resulting
    /// routes are installed.
    #[arg(long)]
    scope_target: Option<String>,

    /// Request a tunnel scoped to this IP protocol number. The routing table
    /// cannot express a protocol, so such routes are configured on the device
    /// but not installed; the proxy still enforces the scope.
    #[arg(long)]
    scope_proto: Option<u8>,
}

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
    let args = Args::parse();

    let tls_mode = tls_mode(&args)?;
    let auth = match (&args.bearer_token, &args.basic) {
        (Some(token), _) => ClientAuth::Bearer(token.clone()),
        (_, Some(pair)) => {
            let (user, password) = pair
                .split_once(':')
                .ok_or_else(|| ProxyError::Config("--basic expects user:password".to_string()))?;
            ClientAuth::Basic {
                user: user.to_string(),
                password: password.to_string(),
            }
        }
        _ => ClientAuth::None,
    };

    let mut client = TunnelClient::connect_scoped(
        args.server_addr,
        &args.server_name,
        tls_mode,
        auth,
        args.scope_target.as_deref(),
        args.scope_proto,
    )
    .await?;
    tracing::info!(proxy = %args.server_addr, "tunnel accepted");
    client.wait_for_assignment().await?;

    let sender = client.sender();
    let mtu = tunnel_mtu(&args, &sender)?;

    // The device is created bare; addresses and routes are applied from the
    // capsules, which also lets us configure IPv6 (the tun crate cannot).
    // Uplink packets go straight from the read pump into the tunnel —
    // `send_packet` is synchronous — with no queue or task between.
    let uplink_sender = sender.clone();
    let channels = spawn_tun(
        &TunConfig {
            name: args.tun_name.clone(),
            mtu,
            ipv4: None,
            ipv6: None,
        },
        move |packet| {
            if let Err(e) = uplink_sender.send_packet(packet) {
                tracing::debug!("packet not sent: {e}");
            }
        },
    )?;
    // The device may not have the requested name (macOS names utun devices
    // itself), and everything below configures it by name.
    let dev = channels.name.clone();
    tracing::info!(dev = %dev, mtu, "TUN device up");

    // A proxy reached over loopback needs no pin route (and pinning would
    // fail: the advertised routes never cover 127.0.0.0/8).
    let pin = match args.server_addr.ip() {
        ip if ip.is_loopback() => None,
        ip => Some(ip),
    };
    let mut guard = Some(apply(&client, &dev, pin, !args.no_routes)?);
    report(&client, &dev);

    // Downlink: the connection's demux task feeds the TUN writer directly —
    // no intermediate queue or task (Step 32).
    client.set_packet_sink(channels.to_net.clone());

    // Track the path MTU upward (unless pinned) and widen the device.
    let mut mtu_poll = tokio::time::interval(MTU_POLL);
    mtu_poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut current_mtu = mtu;
    let track_mtu = args.mtu.is_none();

    // Both ADDRESS_ASSIGN and ROUTE_ADVERTISEMENT are full-state (RFC 9484
    // §4.7.1, §4.7.3): a fresh capsule replaces the installed state whole.
    loop {
        tokio::select! {
            _ = wait_for_termination() => {
                tracing::info!("shutting down: removing addresses and routes");
                break;
            }
            _ = mtu_poll.tick(), if track_mtu => {
                if let Some(sampled) = sender.max_packet_size() {
                    let sampled = u16::try_from(sampled).unwrap_or(u16::MAX);
                    if sampled >= current_mtu.saturating_add(MTU_STEP) {
                        match iface::ip(&iface::mtu_args(&dev, sampled)) {
                            Ok(()) => {
                                tracing::info!(dev = %dev, from = current_mtu, to = sampled, "tunnel MTU raised");
                                current_mtu = sampled;
                            }
                            Err(e) => tracing::debug!("could not raise the tunnel MTU: {e}"),
                        }
                    }
                }
            }
            result = client.process_next_capsules() => {
                match result {
                    Ok(capsules) => {
                        if capsules.iter().any(reconfigures) {
                            drop(guard.take());
                            guard = Some(apply(&client, &dev, pin, !args.no_routes)?);
                            report(&client, &dev);
                        }
                    }
                    Err(e) => {
                        tracing::warn!("tunnel closed: {e}");
                        break;
                    }
                }
            }
        }
    }

    drop(guard);
    client.close().await;
    Ok(())
}

/// Capsules that change what the kernel should be configured with.
fn reconfigures(capsule: &straw::capsule::Capsule) -> bool {
    use straw::capsule::Capsule;
    matches!(
        capsule,
        Capsule::AddressAssign(_) | Capsule::RouteAdvertisement(_)
    )
}

fn apply(
    client: &TunnelClient,
    dev: &str,
    pin: Option<IpAddr>,
    install_routes: bool,
) -> Result<InterfaceGuard, ProxyError> {
    configure(&InterfaceSetup {
        dev,
        assigned: &client.assigned,
        routes: &client.routes,
        pin,
        install_routes,
    })
}

/// Largest IP packet the tunnel can carry, or the operator's override.
///
/// quinn's path MTU starts conservative and rises as discovery probes, so
/// sampling at setup yields a safe lower bound; the tracker widens it later.
fn tunnel_mtu(args: &Args, sender: &PacketSender) -> Result<u16, ProxyError> {
    if let Some(mtu) = args.mtu {
        return Ok(mtu);
    }
    let max = sender.max_packet_size().ok_or_else(|| {
        ProxyError::Config("proxy did not enable QUIC DATAGRAMs; cannot size the tunnel".into())
    })?;
    let mtu = u16::try_from(max).unwrap_or(u16::MAX);
    if mtu < MIN_IPV6_MTU {
        tracing::warn!(
            mtu,
            "tunnel MTU is below the IPv6 minimum of {MIN_IPV6_MTU}; IPv6 traffic may not pass"
        );
    }
    Ok(mtu)
}

fn report(client: &TunnelClient, dev: &str) {
    for a in &client.assigned {
        println!("{dev}: {}/{}", a.ip_address, a.prefix_length);
    }
    for r in &client.routes {
        println!(
            "{dev}: route {} - {} proto {}",
            r.start_ip,
            r.end_ip,
            if r.ip_protocol == 0 {
                "any".into()
            } else {
                r.ip_protocol.to_string()
            }
        );
    }
}

fn tls_mode(args: &Args) -> Result<TlsMode, ProxyError> {
    if args.insecure {
        return Ok(TlsMode::Insecure);
    }
    let Some(path) = &args.ca_cert else {
        return Err(ProxyError::Config(
            "pass --insecure or --ca-cert <pem> (the dev server is self-signed)".into(),
        ));
    };
    use rustls::pki_types::{CertificateDer, pem::PemObject};
    let pem = std::fs::read(path)?;
    let cert = CertificateDer::pem_slice_iter(&pem)
        .next()
        .ok_or_else(|| ProxyError::Tls("no certificate in file".into()))?
        .map_err(|e| ProxyError::Tls(e.to_string()))?;
    Ok(TlsMode::Ca(cert))
}

/// Resolve on SIGINT (ctrl-c) or SIGTERM.
async fn wait_for_termination() {
    let mut sigterm = match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
    {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("no SIGTERM handler: {e}");
            let _ = tokio::signal::ctrl_c().await;
            return;
        }
    };
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = sigterm.recv() => {}
    }
}
