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
use straw::client::{TlsMode, TunnelClient};
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

    /// Ping this tunnel address instead of the client's own assigned one.
    #[arg(long)]
    target: Option<Ipv4Addr>,

    /// Number of echo requests to send.
    #[arg(long, default_value_t = 4)]
    count: u16,
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
    let mut client = TunnelClient::connect(args.server_addr, &args.server_name, tls_mode).await?;
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

        match tokio::time::timeout(Duration::from_secs(2), client.recv_packet()).await {
            Ok(Ok(reply)) => {
                let rtt = started.elapsed();
                let info = parse_packet(&reply)?;
                let ttl = reply[8];
                received += 1;
                println!(
                    "{} bytes from {}: icmp_seq={seq} ttl={ttl} time={:.2?}",
                    reply.len(),
                    info.src,
                    rtt
                );
            }
            Ok(Err(e)) => return Err(e),
            Err(_) => println!("icmp_seq={seq} timed out"),
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    println!("{received}/{} packets received", args.count);
    client.close().await;
    Ok(())
}
