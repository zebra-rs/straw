//! Minimal quinn sender/receiver that reports the connection's live path MTU
//! and black-hole-detection count, for measuring MTU recovery under loss.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};

const ALPN: &[u8] = b"mtuprobe";

fn ring() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn transport() -> quinn::TransportConfig {
    let mut t = quinn::TransportConfig::default();
    // Defaults elsewhere: MTUD on, initial/min MTU 1200, upper bound 1452,
    // black-hole cooldown 60s. A generous idle timeout so heavy loss doesn't
    // end the connection before the measurement does.
    t.max_idle_timeout(Some(Duration::from_secs(30).try_into().unwrap()));
    t.keep_alive_interval(Some(Duration::from_secs(2)));
    t
}

#[tokio::main]
async fn main() {
    let a: Vec<String> = std::env::args().collect();
    match a.get(1).map(|s| s.as_str()) {
        Some("server") => server(a[2].parse().unwrap()).await,
        Some("client") => {
            let mbit: u64 = a.get(4).map(|v| v.parse().unwrap()).unwrap_or(0);
            client(a[2].parse().unwrap(), a[3].parse().unwrap(), mbit).await
        }
        _ => eprintln!("usage: mtuprobe server <addr> | mtuprobe client <addr> <secs> [mbit]"),
    }
}

async fn server(addr: SocketAddr) {
    let certified = rcgen::generate_simple_self_signed(vec!["probe".to_string()]).unwrap();
    let cert = certified.cert.der().clone();
    let key = PrivateKeyDer::try_from(certified.signing_key.serialize_der()).unwrap();

    let mut tls = rustls::ServerConfig::builder_with_provider(ring())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .unwrap();
    tls.alpn_protocols = vec![ALPN.to_vec()];

    let qsc = quinn::crypto::rustls::QuicServerConfig::try_from(tls).unwrap();
    let mut sc = quinn::ServerConfig::with_crypto(Arc::new(qsc));
    sc.transport_config(Arc::new(transport()));

    let ep = quinn::Endpoint::server(sc, addr).unwrap();
    eprintln!("listening on {addr}");
    while let Some(inc) = ep.accept().await {
        tokio::spawn(async move {
            let Ok(conn) = inc.await else { return };
            while let Ok(mut s) = conn.accept_uni().await {
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 256 * 1024];
                    while let Ok(Some(_)) = s.read(&mut buf).await {}
                });
            }
        });
    }
}

async fn client(server: SocketAddr, secs: u64, mbit: u64) {
    let mut tls = rustls::ClientConfig::builder_with_provider(ring())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipVerify(ring())))
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];

    let qcc = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
    let mut cc = quinn::ClientConfig::new(Arc::new(qcc));
    cc.transport_config(Arc::new(transport()));

    let mut ep = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap()).unwrap();
    ep.set_default_client_config(cc);
    let conn = ep.connect(server, "probe").unwrap().await.unwrap();

    let start = Instant::now();
    let sampler = conn.clone();
    tokio::spawn(async move {
        println!("t_s,mtu,black_holes,lost_packets,sent_packets,cwnd,rtt_ms");
        let mut tick = tokio::time::interval(Duration::from_millis(500));
        loop {
            tick.tick().await;
            let p = sampler.stats().path;
            println!(
                "{:.1},{},{},{},{},{},{:.1}",
                start.elapsed().as_secs_f64(),
                p.current_mtu,
                p.black_holes_detected,
                p.lost_packets,
                p.sent_packets,
                p.cwnd,
                p.rtt.as_secs_f64() * 1000.0,
            );
        }
    });

    let mut stream = conn.open_uni().await.unwrap();
    let buf = vec![7u8; 256 * 1024];
    let deadline = start + Duration::from_secs(secs);
    let mut bytes: u64 = 0;
    while Instant::now() < deadline {
        if stream.write_all(&buf).await.is_err() {
            break;
        }
        bytes += buf.len() as u64;
        // Pace to a target rate: an unpaced sender overruns the veth and
        // generates its own queue-drop loss, which would mask the netem loss
        // the experiment is actually about.
        if mbit > 0 {
            let target = Duration::from_secs_f64(bytes as f64 / (mbit as f64 * 125_000.0));
            if let Some(d) = target.checked_sub(start.elapsed()) {
                tokio::time::sleep(d).await;
            }
        }
    }
    let _ = stream.finish();
    let p = conn.stats().path;
    eprintln!(
        "final: mtu={} black_holes={} lost={} sent={} bytes={} ({:.2} Gbit/s)",
        p.current_mtu,
        p.black_holes_detected,
        p.lost_packets,
        p.sent_packets,
        bytes,
        (bytes as f64 * 8.0) / start.elapsed().as_secs_f64() / 1e9,
    );
    conn.close(0u32.into(), b"done");
    ep.wait_idle().await;
}

#[derive(Debug)]
struct SkipVerify(Arc<CryptoProvider>);

impl ServerCertVerifier for SkipVerify {
    fn verify_server_cert(
        &self,
        _e: &CertificateDer<'_>,
        _i: &[CertificateDer<'_>],
        _n: &ServerName<'_>,
        _o: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn verify_tls13_signature(
        &self,
        m: &[u8],
        c: &CertificateDer<'_>,
        d: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(m, c, d, &self.0.signature_verification_algorithms)
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
