//! CONNECT-IP test client: establishes a tunnel to a straw proxy, prints
//! the address assignment, and exchanges ICMP echo packets.
//!
//! Without a TUN device on the server, packets to other tunnel clients (or
//! to the client's own assigned address) hairpin through the proxy — a
//! full data-plane round trip with no privileges needed anywhere:
//!
//! ```text
//! cargo run                       # terminal 1: server
//! cargo run --bin test_client -- --insecure   # terminal 2: self-ping
//! ```

use std::net::{Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use clap::Parser;
use straw::client::{ClientAuth, TlsMode, TunnelClient};
use straw::error::ProxyError;
use straw::forwarding::packet::{build_ipv4_icmp_echo, parse_packet};

#[derive(Debug, Parser)]
#[command(name = "test_client", about = "straw CONNECT-IP test client")]
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

    /// Ping this tunnel address instead of the client's own assigned one.
    #[arg(long)]
    target: Option<Ipv4Addr>,

    /// Number of echo requests to send.
    #[arg(long, default_value_t = 4)]
    count: u16,

    /// Request a tunnel scoped to this target: an IP, a prefix (a.b.c.d/n)
    /// or a hostname the proxy resolves (RFC 9484 §4.6).
    #[arg(long)]
    scope_target: Option<String>,

    /// Request a tunnel scoped to this IP protocol number (6 = TCP, 17 = UDP).
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

    let tls_mode = if args.insecure {
        TlsMode::Insecure
    } else if let Some(path) = &args.ca_cert {
        use rustls::pki_types::{CertificateDer, pem::PemObject};
        let pem = std::fs::read(path)?;
        let cert = CertificateDer::pem_slice_iter(&pem)
            .next()
            .ok_or_else(|| ProxyError::Tls("no certificate in file".into()))?
            .map_err(|e| ProxyError::Tls(e.to_string()))?;
        TlsMode::Ca(cert)
    } else {
        return Err(ProxyError::Config(
            "pass --insecure or --ca-cert <pem> (the dev server is self-signed)".into(),
        ));
    };

    println!(
        "connecting to {} (sni {})...",
        args.server_addr, args.server_name
    );
    let auth = match &args.bearer_token {
        Some(token) => ClientAuth::Bearer(token.clone()),
        None => ClientAuth::None,
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
    println!("tunnel accepted (200, capsule-protocol)");

    client.wait_for_assignment().await?;
    for a in &client.assigned {
        println!(
            "assigned: {}/{} (request_id {})",
            a.ip_address, a.prefix_length, a.request_id
        );
    }
    for r in &client.routes {
        println!(
            "route: {} - {} proto {}",
            r.start_ip,
            r.end_ip,
            if r.ip_protocol == 0 {
                "any".into()
            } else {
                r.ip_protocol.to_string()
            }
        );
    }

    let src = client
        .ipv4_address()
        .ok_or_else(|| ProxyError::Config("no IPv4 address assigned".into()))?;
    let dst = args.target.unwrap_or(src);
    println!(
        "pinging {dst} via tunnel ({})...",
        if args.target.is_some() {
            "hairpin to peer"
        } else {
            "hairpin to self"
        }
    );

    let mut received = 0u16;
    for seq in 1..=args.count {
        let echo = build_ipv4_icmp_echo(src, dst, false, 0x5747, seq, b"straw-ping", 64);
        let started = Instant::now();
        client.send_packet(echo)?;

        // Count only a genuine echo back (a real reply, or the sender's own
        // request looped by a hairpin) — never an ICMP error, so a scope or
        // TTL rejection is reported but fails the run.
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            match tokio::time::timeout(remaining, client.recv_packet()).await {
                Ok(Ok(reply)) => {
                    let info = parse_packet(&reply)?;
                    if is_echo(&reply, &info) {
                        received += 1;
                        println!(
                            "{} bytes from {}: icmp_seq={seq} ttl={} time={:.2?}",
                            reply.len(),
                            info.src,
                            reply[8],
                            started.elapsed()
                        );
                        break;
                    }
                    println!(
                        "icmp_seq={seq}: {} bytes from {}, {}",
                        reply.len(),
                        info.src,
                        describe_icmp(&reply, &info)
                    );
                }
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    println!("icmp_seq={seq} timed out");
                    break;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    println!("{received}/{} packets received", args.count);
    client.close().await;
    if received < args.count {
        std::process::exit(1);
    }
    Ok(())
}

/// An ICMP echo — request (v4 type 8 / v6 128) or reply (0 / 129) — as
/// opposed to an ICMP error. A round trip surfaces one of these: a real
/// responder answers with a reply, a hairpin to the sender's own address
/// loops the request straight back. An error is deliberately not one, so
/// scope and TTL rejections are reported but never counted as delivered.
fn is_echo(packet: &[u8], info: &straw::forwarding::packet::PacketInfo) -> bool {
    match (info.protocol, packet.first().map(|b| b >> 4)) {
        (1, Some(4)) => {
            let ihl = (packet[0] & 0x0f) as usize * 4;
            matches!(packet.get(ihl), Some(0) | Some(8))
        }
        (58, Some(6)) => matches!(packet.get(40), Some(128) | Some(129)),
        _ => false,
    }
}

fn describe_icmp(packet: &[u8], info: &straw::forwarding::packet::PacketInfo) -> String {
    let (ty, code) = match (info.protocol, packet.first().map(|b| b >> 4)) {
        (1, Some(4)) => {
            let ihl = (packet[0] & 0x0f) as usize * 4;
            (packet.get(ihl).copied(), packet.get(ihl + 1).copied())
        }
        (58, Some(6)) => (packet.get(40).copied(), packet.get(41).copied()),
        _ => return format!("protocol {}", info.protocol),
    };
    match (info.protocol, ty, code) {
        (1, Some(3), Some(13)) | (58, Some(1), Some(1)) => {
            "destination administratively prohibited".into()
        }
        (1, Some(3), Some(4)) => "fragmentation needed".into(),
        (1, Some(3), _) | (58, Some(1), _) => "destination unreachable".into(),
        (58, Some(2), _) => "packet too big".into(),
        (1, Some(11), _) | (58, Some(3), _) => "time exceeded".into(),
        (_, Some(t), Some(c)) => format!("icmp type {t} code {c}"),
        _ => "truncated icmp".into(),
    }
}
