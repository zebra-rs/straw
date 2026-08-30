//! Server configuration: clap CLI plus an optional TOML file (design §10).
//!
//! Precedence: CLI flag > file value > built-in default. The file is named
//! with `--config`; every section and key is optional.

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::Deserialize;

use crate::error::ProxyError;
use crate::session::auth::AuthMode;

/// straw — RFC 9484 CONNECT-IP proxy server (IP over MASQUE).
#[derive(Debug, Clone, Parser)]
#[command(name = "straw", version, about)]
pub struct ProxyConfig {
    /// UDP address to listen on for QUIC.
    #[arg(long, default_value = "0.0.0.0:4433")]
    pub listen: SocketAddr,

    /// Path to a PEM certificate chain. Omit to use a self-signed certificate.
    #[arg(long, requires = "key")]
    pub cert: Option<PathBuf>,

    /// Path to the PEM private key for --cert.
    #[arg(long, requires = "cert")]
    pub key: Option<PathBuf>,

    /// IPv4 range to assign client addresses from.
    #[arg(long, default_value = "10.100.0.0/24")]
    pub ipv4_pool: Ipv4Net,

    /// Optional IPv6 range to assign client addresses from (e.g. fd00:6d61:7371::/64).
    #[arg(long)]
    pub ipv6_pool: Option<Ipv6Net>,

    /// Tunnel MTU. Must be >= 1280 to carry IPv6 (RFC 9484 §7.2, §10.1).
    #[arg(long, default_value_t = 1400)]
    pub mtu: u16,

    /// Split-tunnel mode: advertise (and forward for) only these prefixes,
    /// e.g. --split-routes 192.168.0.0/16,10.0.0.0/8. The client address
    /// pool is always advertised too. Empty = full tunnel.
    #[arg(long, value_delimiter = ',')]
    pub split_routes: Vec<IpNet>,

    /// Install routes advertised by clients (site-to-site VPN). Routes
    /// overlapping the address pool are always refused.
    #[arg(long)]
    pub accept_client_routes: bool,

    /// Create a kernel TUN device and forward tunneled packets to the network.
    /// Requires elevated privileges. Without it, only client<->client (hairpin)
    /// forwarding is available.
    #[arg(long)]
    pub tun: bool,

    /// Name for the TUN device (Linux only; macOS assigns utunN automatically).
    #[arg(long, default_value = "straw0")]
    pub tun_name: String,

    /// QUIC max idle timeout in milliseconds.
    #[arg(long, default_value_t = 30_000)]
    pub idle_timeout_ms: u64,

    /// Maximum number of concurrent sessions.
    #[arg(long, default_value_t = 1000)]
    pub max_sessions: usize,

    /// Authentication required from clients.
    #[arg(long, value_enum, default_value_t = AuthMode::None)]
    pub auth_mode: AuthMode,

    /// Accepted bearer token(s) for --auth-mode bearer (comma-separated).
    #[arg(long, value_delimiter = ',')]
    pub auth_token: Vec<String>,

    /// Accepted user:password pair(s) for --auth-mode basic (comma-separated).
    #[arg(long, value_delimiter = ',')]
    pub auth_basic: Vec<String>,

    /// PEM CA bundle that client certificates must chain to (--auth-mode mtls).
    #[arg(long)]
    pub client_ca: Option<PathBuf>,

    /// Close sessions with no client activity for this many seconds; 0 disables.
    #[arg(long, default_value_t = 300)]
    pub session_idle_timeout_sec: u64,

    /// Per-session packet rate limit (packets/sec); 0 = unlimited.
    #[arg(long, default_value_t = 0)]
    pub max_packet_rate: u64,

    /// Per-session byte rate limit (bytes/sec); 0 = unlimited.
    #[arg(long, default_value_t = 0)]
    pub max_byte_rate: u64,

    /// Serve Prometheus metrics on this address (e.g. 127.0.0.1:9090).
    #[arg(long)]
    pub metrics_listen: Option<SocketAddr>,

    /// With --tun on Linux: masquerade pool traffic out this interface and
    /// enable IP forwarding (iptables + sysctl).
    #[arg(long)]
    pub nat_interface: Option<String>,

    /// Seconds to let sessions drain after SIGINT/SIGTERM before closing.
    #[arg(long, default_value_t = 5)]
    pub shutdown_grace_sec: u64,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        // Defaults must stay in sync with the clap attributes above.
        Self {
            listen: "0.0.0.0:4433".parse().unwrap(),
            cert: None,
            key: None,
            ipv4_pool: "10.100.0.0/24".parse().unwrap(),
            ipv6_pool: None,
            mtu: 1400,
            split_routes: Vec::new(),
            accept_client_routes: false,
            tun: false,
            tun_name: "straw0".to_string(),
            idle_timeout_ms: 30_000,
            max_sessions: 1000,
            auth_mode: AuthMode::None,
            auth_token: Vec::new(),
            auth_basic: Vec::new(),
            client_ca: None,
            session_idle_timeout_sec: 300,
            max_packet_rate: 0,
            max_byte_rate: 0,
            metrics_listen: None,
            nat_interface: None,
            shutdown_grace_sec: 5,
        }
    }
}

impl ProxyConfig {
    /// Validate cross-field constraints not expressible in clap.
    pub fn validate(&self) -> Result<(), crate::error::ProxyError> {
        use crate::error::ProxyError;
        if self.mtu < 1280 {
            return Err(ProxyError::Config(format!(
                "MTU {} is below the IPv6 minimum of 1280",
                self.mtu
            )));
        }
        match self.auth_mode {
            AuthMode::Bearer if self.auth_token.is_empty() => {
                return Err(ProxyError::Config(
                    "--auth-mode bearer requires at least one --auth-token".into(),
                ));
            }
            AuthMode::Basic if self.auth_basic.is_empty() => {
                return Err(ProxyError::Config(
                    "--auth-mode basic requires at least one --auth-basic user:pass".into(),
                ));
            }
            AuthMode::Mtls if self.client_ca.is_none() => {
                return Err(ProxyError::Config(
                    "--auth-mode mtls requires --client-ca".into(),
                ));
            }
            _ => {}
        }
        self.basic_credentials()?;
        if self.nat_interface.is_some() && !self.tun {
            return Err(ProxyError::Config("--nat-interface requires --tun".into()));
        }
        Ok(())
    }

    /// Parse --auth-basic entries into (user, password) pairs.
    pub fn basic_credentials(&self) -> Result<Vec<(String, String)>, crate::error::ProxyError> {
        self.auth_basic
            .iter()
            .map(|entry| {
                entry
                    .split_once(':')
                    .map(|(u, p)| (u.to_string(), p.to_string()))
                    .ok_or_else(|| {
                        crate::error::ProxyError::Config(format!(
                            "--auth-basic entry {entry:?} is not user:password"
                        ))
                    })
            })
            .collect()
    }

    /// Resolve the effective configuration from process arguments:
    /// defaults, overlaid by `--config <file>`, overlaid by CLI flags.
    pub fn resolve() -> Result<Self, ProxyError> {
        Self::resolve_from(std::env::args_os())
    }

    /// [`ProxyConfig::resolve`] over explicit arguments (testable).
    pub fn resolve_from<I, T>(args: I) -> Result<Self, ProxyError>
    where
        I: IntoIterator<Item = T>,
        T: Into<std::ffi::OsString> + Clone,
    {
        use clap::{CommandFactory, FromArgMatches};

        let command = Self::command().arg(
            clap::Arg::new("config")
                .long("config")
                .value_name("FILE")
                .help("TOML configuration file; CLI flags override file values")
                .value_parser(clap::value_parser!(PathBuf)),
        );
        let matches = command
            .try_get_matches_from(args)
            .map_err(|e| e.exit_if_help_or_version())?;
        let cli =
            Self::from_arg_matches(&matches).map_err(|e| ProxyError::Config(e.to_string()))?;

        let mut config = Self::default();
        if let Some(path) = matches.get_one::<PathBuf>("config") {
            let text = std::fs::read_to_string(path)?;
            let file: FileConfig = toml::from_str(&text)
                .map_err(|e| ProxyError::Config(format!("{}: {e}", path.display())))?;
            file.apply(&mut config);
        }
        overlay_cli(&mut config, cli, &matches);
        Ok(config)
    }
}

trait ExitIfHelp {
    fn exit_if_help_or_version(self) -> ProxyError;
}

impl ExitIfHelp for clap::Error {
    /// `--help`/`--version` print and exit like plain clap parsing does;
    /// real argument errors surface as configuration errors.
    fn exit_if_help_or_version(self) -> ProxyError {
        use clap::error::ErrorKind;
        match self.kind() {
            ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => self.exit(),
            _ => ProxyError::Config(self.to_string()),
        }
    }
}

/// Copy every CLI-provided flag over the file/default values.
fn overlay_cli(config: &mut ProxyConfig, cli: ProxyConfig, matches: &clap::ArgMatches) {
    let from_cli =
        |id: &str| matches.value_source(id) == Some(clap::parser::ValueSource::CommandLine);
    macro_rules! overlay {
        ($($field:ident),+ $(,)?) => {
            $(if from_cli(stringify!($field)) {
                config.$field = cli.$field;
            })+
        };
    }
    overlay!(
        listen,
        cert,
        key,
        ipv4_pool,
        ipv6_pool,
        mtu,
        split_routes,
        accept_client_routes,
        tun,
        tun_name,
        idle_timeout_ms,
        max_sessions,
        auth_mode,
        auth_token,
        auth_basic,
        client_ca,
        session_idle_timeout_sec,
        max_packet_rate,
        max_byte_rate,
        metrics_listen,
        nat_interface,
        shutdown_grace_sec,
    );
}

/// The `--config` TOML file (design §10). Every key is optional; sections
/// mirror the design document's layout.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileConfig {
    server: Option<ServerSection>,
    quic: Option<QuicSection>,
    tunnel: Option<TunnelSection>,
    address_pool: Option<AddressPoolSection>,
    routing: Option<RoutingSection>,
    auth: Option<AuthSection>,
    limits: Option<LimitsSection>,
    metrics: Option<MetricsSection>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServerSection {
    listen_addr: Option<SocketAddr>,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    shutdown_grace_sec: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct QuicSection {
    max_idle_timeout_ms: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct TunnelSection {
    enabled: Option<bool>,
    device_name: Option<String>,
    mtu: Option<u16>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct AddressPoolSection {
    ipv4_range: Option<Ipv4Net>,
    ipv6_range: Option<Ipv6Net>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RoutingSection {
    split_routes: Option<Vec<IpNet>>,
    accept_client_routes: Option<bool>,
    nat_interface: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthSection {
    mode: Option<AuthMode>,
    bearer_tokens: Option<Vec<String>>,
    basic_credentials: Option<Vec<String>>,
    client_ca: Option<PathBuf>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct LimitsSection {
    max_sessions: Option<usize>,
    session_idle_timeout_sec: Option<u64>,
    max_packet_rate: Option<u64>,
    max_byte_rate: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct MetricsSection {
    listen: Option<SocketAddr>,
}

impl FileConfig {
    fn apply(self, config: &mut ProxyConfig) {
        if let Some(server) = self.server {
            if let Some(v) = server.listen_addr {
                config.listen = v;
            }
            if server.tls_cert.is_some() {
                config.cert = server.tls_cert;
            }
            if server.tls_key.is_some() {
                config.key = server.tls_key;
            }
            if let Some(v) = server.shutdown_grace_sec {
                config.shutdown_grace_sec = v;
            }
        }
        if let Some(quic) = self.quic
            && let Some(v) = quic.max_idle_timeout_ms
        {
            config.idle_timeout_ms = v;
        }
        if let Some(tunnel) = self.tunnel {
            if let Some(v) = tunnel.enabled {
                config.tun = v;
            }
            if let Some(v) = tunnel.device_name {
                config.tun_name = v;
            }
            if let Some(v) = tunnel.mtu {
                config.mtu = v;
            }
        }
        if let Some(pool) = self.address_pool {
            if let Some(v) = pool.ipv4_range {
                config.ipv4_pool = v;
            }
            if pool.ipv6_range.is_some() {
                config.ipv6_pool = pool.ipv6_range;
            }
        }
        if let Some(routing) = self.routing {
            if let Some(v) = routing.split_routes {
                config.split_routes = v;
            }
            if let Some(v) = routing.accept_client_routes {
                config.accept_client_routes = v;
            }
            if routing.nat_interface.is_some() {
                config.nat_interface = routing.nat_interface;
            }
        }
        if let Some(auth) = self.auth {
            if let Some(v) = auth.mode {
                config.auth_mode = v;
            }
            if let Some(v) = auth.bearer_tokens {
                config.auth_token = v;
            }
            if let Some(v) = auth.basic_credentials {
                config.auth_basic = v;
            }
            if auth.client_ca.is_some() {
                config.client_ca = auth.client_ca;
            }
        }
        if let Some(limits) = self.limits {
            if let Some(v) = limits.max_sessions {
                config.max_sessions = v;
            }
            if let Some(v) = limits.session_idle_timeout_sec {
                config.session_idle_timeout_sec = v;
            }
            if let Some(v) = limits.max_packet_rate {
                config.max_packet_rate = v;
            }
            if let Some(v) = limits.max_byte_rate {
                config.max_byte_rate = v;
            }
        }
        if let Some(metrics) = self.metrics
            && metrics.listen.is_some()
        {
            config.metrics_listen = metrics.listen;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_clap() {
        let from_clap = ProxyConfig::parse_from(["straw"]);
        let from_default = ProxyConfig::default();
        assert_eq!(format!("{from_clap:?}"), format!("{from_default:?}"));
    }

    const SAMPLE_TOML: &str = r#"
        [server]
        listen_addr = "0.0.0.0:443"
        tls_cert = "/etc/straw/cert.pem"
        tls_key = "/etc/straw/key.pem"
        shutdown_grace_sec = 10

        [quic]
        max_idle_timeout_ms = 60000

        [tunnel]
        enabled = true
        device_name = "masque0"
        mtu = 1350

        [address_pool]
        ipv4_range = "10.200.0.0/16"
        ipv6_range = "fd00:6d61:7371::/64"

        [routing]
        split_routes = ["192.168.0.0/16", "10.0.0.0/8"]
        accept_client_routes = true
        nat_interface = "eth0"

        [auth]
        mode = "bearer"
        bearer_tokens = ["alpha", "beta"]

        [limits]
        max_sessions = 64
        session_idle_timeout_sec = 120
        max_packet_rate = 50000

        [metrics]
        listen = "127.0.0.1:9090"
    "#;

    #[test]
    fn toml_file_applies_all_sections() {
        let file: FileConfig = toml::from_str(SAMPLE_TOML).unwrap();
        let mut config = ProxyConfig::default();
        file.apply(&mut config);

        assert_eq!(config.listen, "0.0.0.0:443".parse().unwrap());
        assert_eq!(config.cert.as_deref(), Some("/etc/straw/cert.pem".as_ref()));
        assert_eq!(config.shutdown_grace_sec, 10);
        assert_eq!(config.idle_timeout_ms, 60_000);
        assert!(config.tun);
        assert_eq!(config.tun_name, "masque0");
        assert_eq!(config.mtu, 1350);
        assert_eq!(config.ipv4_pool, "10.200.0.0/16".parse().unwrap());
        assert!(config.ipv6_pool.is_some());
        assert_eq!(config.split_routes.len(), 2);
        assert!(config.accept_client_routes);
        assert_eq!(config.nat_interface.as_deref(), Some("eth0"));
        assert_eq!(config.auth_mode, AuthMode::Bearer);
        assert_eq!(config.auth_token, vec!["alpha", "beta"]);
        assert_eq!(config.max_sessions, 64);
        assert_eq!(config.session_idle_timeout_sec, 120);
        assert_eq!(config.max_packet_rate, 50_000);
        assert_eq!(
            config.metrics_listen,
            Some("127.0.0.1:9090".parse().unwrap())
        );
        // Untouched keys keep their defaults.
        assert_eq!(config.max_byte_rate, 0);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn unknown_toml_keys_are_rejected() {
        let result: Result<FileConfig, _> = toml::from_str("[server]\nlisten = \"1.2.3.4:1\"\n");
        assert!(result.is_err(), "typo'd key must not be silently ignored");
    }

    #[test]
    fn cli_overrides_file_overrides_default() {
        let path =
            std::env::temp_dir().join(format!("straw-config-test-{}.toml", std::process::id()));
        std::fs::write(&path, SAMPLE_TOML).unwrap();

        let config = ProxyConfig::resolve_from([
            "straw",
            "--config",
            path.to_str().unwrap(),
            "--mtu",
            "1420",
        ])
        .unwrap();
        std::fs::remove_file(&path).ok();

        assert_eq!(config.mtu, 1420, "CLI beats file");
        assert_eq!(
            config.listen,
            "0.0.0.0:443".parse().unwrap(),
            "file beats default"
        );
        assert_eq!(config.max_byte_rate, 0, "default survives");
    }

    #[test]
    fn resolve_without_config_file_matches_plain_parse() {
        let resolved = ProxyConfig::resolve_from(["straw", "--listen", "127.0.0.1:9999"]).unwrap();
        assert_eq!(resolved.listen, "127.0.0.1:9999".parse().unwrap());
        assert_eq!(resolved.mtu, ProxyConfig::default().mtu);
    }

    #[test]
    fn mtu_validation() {
        let mut cfg = ProxyConfig::default();
        cfg.mtu = 1200;
        assert!(cfg.validate().is_err());
        cfg.mtu = 1280;
        assert!(cfg.validate().is_ok());
    }
}
