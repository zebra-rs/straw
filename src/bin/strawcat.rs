//! strawcat — peer-to-peer pipe over the straw relay (design §2.1, §8).
//!
//! Two peers form a mutually authenticated, SPKI-pinned QUIC connection
//! through a straw relay, which only ever forwards ciphertext. The default
//! `strawcat/1` protocol pipes stdin/stdout over a native QUIC stream —
//! netcat over the relay:
//!
//! ```text
//! strawcat genkey > peer.key                       # once, per peer
//! strawcat listen  --relay HOST:PORT --insecure --identity peer.key
//!     → prints a token; feed it to the other side
//! strawcat connect <token> --relay HOST:PORT --insecure --identity peer2.key
//! ```
//!
//! Reaching the relay uses the same `--insecure` / `--ca-cert` trust as
//! `strawc`; the token carries the *peer's* pin and address (auto-pinning
//! the relay from the token is a later refinement).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use std::sync::Arc;
use std::time::Duration;
use straw::client::{ClientAuth, TlsMode};
use straw::error::ProxyError;
use straw::p2p::identity::Identity;

use straw::p2p::peer::{self, RelayAccess};
use straw::p2p::session::{PathState, Session};
use straw::p2p::token::TokenV2;

#[derive(Debug, Parser)]
#[command(
    name = "strawcat",
    version,
    about = "peer-to-peer pipe over a straw relay"
)]
struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Generate a persistent identity (PKCS#8 PEM) on stdout, pin on stderr.
    Genkey,
    /// Listen for one peer and pipe stdin/stdout over the connection.
    Listen(RelayArgs),
    /// Connect to a peer's token and pipe stdin/stdout over the connection.
    Connect {
        /// The `sc2_…` token printed by the listening peer.
        token: String,
        #[command(flatten)]
        relay: RelayArgs,
    },
}

#[derive(Debug, Parser)]
struct RelayArgs {
    /// Relay address (QUIC).
    #[arg(long)]
    relay: SocketAddr,
    /// TLS server name of the relay certificate.
    #[arg(long, default_value = "localhost")]
    server_name: String,
    /// Skip relay certificate verification (testing only).
    #[arg(long)]
    insecure: bool,
    /// Trust this relay CA / self-signed certificate (PEM).
    #[arg(long, conflicts_with = "insecure")]
    ca_cert: Option<PathBuf>,
    /// Bearer token to authenticate to the relay (bind mode needs auth).
    #[arg(long)]
    bearer_token: Option<String>,
    /// Identity PEM (from `genkey`). Omit for an ephemeral identity.
    #[arg(long)]
    identity: Option<PathBuf>,
    /// Token lifetime in seconds (listen only).
    #[arg(long, default_value_t = 86_400)]
    ttl: u64,

    /// Local address the hole-punch socket binds to. Use an interface IP (or
    /// 127.0.0.1 for a same-host demo); 0.0.0.0 advertises no usable host
    /// candidate, leaving only the reflexive/relay paths.
    #[arg(long, default_value = "0.0.0.0:0")]
    punch_addr: std::net::SocketAddr,

    /// Seconds to wait for a direct path before piping over the relay.
    #[arg(long, default_value_t = 5)]
    punch_wait: u64,
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
        .with_writer(std::io::stderr)
        .init();
    straw::init_crypto();

    match Args::parse().command {
        Command::Genkey => {
            let id = Identity::generate()?;
            eprintln!("pin: {}", hex(&id.pin()));
            print!("{}", id.to_pem());
            Ok(())
        }
        Command::Listen(args) => listen(args).await,
        Command::Connect { token, relay } => connect(token, relay).await,
    }
}

async fn listen(args: RelayArgs) -> Result<(), ProxyError> {
    let identity = Arc::new(load_identity(&args.identity)?);
    let listener = peer::listen(relay_access(&args)?, &identity, None).await?;
    let reflexive = listener.reflexive;
    let relay_paddr = listener.paddr;

    // Mint and print a token the other peer connects with. The relay pin and
    // credential are placeholders in v1 (the holder reaches the relay with
    // its own --ca-cert/--insecure); paddr and the peer pin are the essentials.
    let token = TokenV2::issue(
        format!("h3://{}", args.relay),
        [0u8; 32],
        args.bearer_token.clone().unwrap_or_default(),
        identity.pin(),
        vec![listener.paddr.to_string()],
        now(),
        args.ttl,
    );
    eprintln!("token (give this to the other peer):");
    println!("{}", token.encode());
    eprintln!(
        "listening as {} at {} …",
        hex(&identity.pin()),
        listener.paddr
    );

    let conn = listener.accept().await?;
    eprintln!("peer connected via relay: {}", conn.remote_address());
    let session = Session::start(
        conn,
        false,
        identity,
        None,
        args.punch_addr,
        reflexive,
        relay_paddr,
    );
    let best = best_path(&session, args.punch_wait).await;
    // The connecting peer opens the stream; accept it on the chosen path.
    let (send, recv) = best
        .accept_bi()
        .await
        .map_err(|e| ProxyError::Quic(e.to_string()))?;
    pipe_stdio(send, recv).await
}

async fn connect(token: String, args: RelayArgs) -> Result<(), ProxyError> {
    let identity = Arc::new(load_identity(&args.identity)?);
    let token = TokenV2::decode(&token)?;
    if token.is_expired(now()) {
        return Err(ProxyError::InvalidRequest("token has expired".into()));
    }
    let peer_conn = peer::connect(relay_access(&args)?, &identity, &token).await?;
    eprintln!("connected to peer {} via relay", hex(&token.peer_pin()));
    let session = Session::start(
        peer_conn.conn,
        true,
        identity,
        Some(token.peer_pin()),
        args.punch_addr,
        peer_conn.reflexive,
        peer_conn.relay_paddr,
    );
    let best = best_path(&session, args.punch_wait).await;
    let (send, recv) = best
        .open_bi()
        .await
        .map_err(|e| ProxyError::Quic(e.to_string()))?;
    pipe_stdio(send, recv).await
}

/// Wait briefly for a direct path, then return the connection to pipe over,
/// reporting which path won.
async fn best_path(session: &Session, wait_secs: u64) -> quinn::Connection {
    let direct = session.await_direct(Duration::from_secs(wait_secs)).await;
    match session.state() {
        PathState::Direct if direct => eprintln!("path: direct (hole punched)"),
        _ => eprintln!("path: relay (no direct path)"),
    }
    session.connection()
}

/// Pipe stdin → the QUIC send stream and the recv stream → stdout. Both
/// directions run to their own EOF and are awaited independently: the peer
/// finishing its send (recv EOF) must not cut off our still-draining send.
/// Aborting the upload would drop the SendStream unfinished, which quinn turns
/// into a stream *reset* — discarding buffered bytes the peer never receives.
/// So we always let the upload reach stdin EOF and call `finish()`, matching a
/// half-close pipe: the process exits once both halves are done.
async fn pipe_stdio(
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> Result<(), ProxyError> {
    use tokio::io::{AsyncWriteExt, copy};

    let up = tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        let _ = copy(&mut stdin, &mut send).await;
        // Graceful FIN so all buffered bytes are delivered before close.
        let _ = send.finish();
    });
    let down = tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        let _ = copy(&mut recv, &mut stdout).await;
        let _ = stdout.flush().await;
    });
    let _ = tokio::join!(up, down);
    Ok(())
}

fn relay_access(args: &RelayArgs) -> Result<RelayAccess, ProxyError> {
    let tls = if args.insecure {
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
            "pass --insecure or --ca-cert <pem> to reach the relay".into(),
        ));
    };
    let auth = match &args.bearer_token {
        Some(t) => ClientAuth::Bearer(t.clone()),
        None => ClientAuth::None,
    };
    Ok(RelayAccess {
        addr: args.relay,
        server_name: args.server_name.clone(),
        tls,
        auth,
    })
}

fn load_identity(path: &Option<PathBuf>) -> Result<Identity, ProxyError> {
    match path {
        Some(p) => Identity::from_pem(&std::fs::read_to_string(p)?),
        None => Identity::generate(),
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
