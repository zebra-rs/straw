//! Server configuration (CLI via clap; TOML file support planned in Phase 5).

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};

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
        }
    }
}

impl ProxyConfig {
    /// Validate cross-field constraints not expressible in clap.
    pub fn validate(&self) -> Result<(), crate::error::ProxyError> {
        if self.mtu < 1280 {
            return Err(crate::error::ProxyError::Config(format!(
                "MTU {} is below the IPv6 minimum of 1280",
                self.mtu
            )));
        }
        Ok(())
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

    #[test]
    fn mtu_validation() {
        let mut cfg = ProxyConfig::default();
        cfg.mtu = 1200;
        assert!(cfg.validate().is_err());
        cfg.mtu = 1280;
        assert!(cfg.validate().is_ok());
    }
}
