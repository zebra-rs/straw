//! Linux interface configuration, all of it through `ip(8)`.

use std::net::IpAddr;
use std::process::Command;

use ipnet::IpNet;

use super::Cmd;
use crate::error::ProxyError;

/// `ip addr {add,del} <ip>/<len> dev <dev>`.
pub fn addr_cmd(action: &str, dev: &str, addr: IpAddr, prefix_len: u8) -> Cmd {
    Cmd::new(
        "ip",
        [
            "addr".into(),
            action.into(),
            format!("{addr}/{prefix_len}"),
            "dev".into(),
            dev.into(),
        ],
    )
}

/// `ip route {add,del} <prefix> dev <dev>`.
pub fn route_cmd(action: &str, prefix: IpNet, dev: &str) -> Cmd {
    Cmd::new(
        "ip",
        [
            "route".into(),
            action.into(),
            prefix.to_string(),
            "dev".into(),
            dev.into(),
        ],
    )
}

/// `ip route {add,del} <proxy> [via <gw>] dev <dev>` — the host route that
/// keeps the tunnel's own QUIC packets off the tunnel.
pub fn pin_cmd(action: &str, proxy: IpAddr, gateway: Option<IpAddr>, dev: &str) -> Cmd {
    let host_len = if proxy.is_ipv4() { 32 } else { 128 };
    let mut args = vec!["route".into(), action.into(), format!("{proxy}/{host_len}")];
    if let Some(gw) = gateway {
        args.push("via".into());
        args.push(gw.to_string());
    }
    args.push("dev".into());
    args.push(dev.into());
    Cmd::new("ip", args)
}

/// `ip link set dev <dev> mtu <mtu>`.
pub fn mtu_cmd(dev: &str, mtu: u16) -> Cmd {
    Cmd::new(
        "ip",
        [
            "link".into(),
            "set".into(),
            "dev".into(),
            dev.into(),
            "mtu".into(),
            mtu.to_string(),
        ],
    )
}

/// Parse the first line of `ip route get <dst>` into (gateway, device).
///
/// ```text
/// 8.8.8.8 via 10.211.55.1 dev enp0s5 src 10.211.55.100 uid 1000
/// 10.211.55.1 dev enp0s5 src 10.211.55.100 uid 1000
/// ```
///
/// An on-link destination has no `via`, hence the optional gateway.
pub fn parse_route_get(output: &str) -> Option<(Option<IpAddr>, String)> {
    let tokens: Vec<&str> = output.lines().next()?.split_whitespace().collect();
    let after = |key: &str| {
        tokens
            .iter()
            .position(|t| *t == key)
            .and_then(|i| tokens.get(i + 1))
            .copied()
    };
    let dev = after("dev")?.to_string();
    let gateway = after("via").and_then(|s| s.parse().ok());
    Some((gateway, dev))
}

/// Ask the kernel how it currently reaches `dst`, before any tunnel routes
/// exist. Used to pin the proxy to the pre-tunnel path.
pub fn path_to(dst: IpAddr) -> Result<(Option<IpAddr>, String), ProxyError> {
    let out = Command::new("ip")
        .args(["route", "get", &dst.to_string()])
        .output()
        .map_err(|e| ProxyError::Config(format!("failed to run ip route get: {e}")))?;
    if !out.status.success() {
        return Err(ProxyError::Config(format!(
            "ip route get {dst} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    parse_route_get(&String::from_utf8_lossy(&out.stdout))
        .ok_or_else(|| ProxyError::Config(format!("could not parse the current route to {dst}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addr_and_route_commands() {
        assert_eq!(
            addr_cmd("add", "strawc0", "10.100.0.2".parse().unwrap(), 32).to_string(),
            "ip addr add 10.100.0.2/32 dev strawc0"
        );
        assert_eq!(
            route_cmd("add", "10.0.0.0/8".parse().unwrap(), "strawc0").to_string(),
            "ip route add 10.0.0.0/8 dev strawc0"
        );
        assert_eq!(
            mtu_cmd("strawc0", 1400).to_string(),
            "ip link set dev strawc0 mtu 1400"
        );
    }

    #[test]
    fn pin_command_carries_the_gateway_only_when_there_is_one() {
        assert_eq!(
            pin_cmd(
                "add",
                "203.0.113.9".parse().unwrap(),
                Some("192.168.1.1".parse().unwrap()),
                "en0"
            )
            .to_string(),
            "ip route add 203.0.113.9/32 via 192.168.1.1 dev en0"
        );
        // On-link: no via.
        assert_eq!(
            pin_cmd("del", "192.168.1.1".parse().unwrap(), None, "en0").to_string(),
            "ip route del 192.168.1.1/32 dev en0"
        );
    }

    #[test]
    fn route_get_parsing() {
        let (gw, dev) =
            parse_route_get("8.8.8.8 via 10.211.55.1 dev enp0s5 src 10.211.55.100 uid 1000")
                .unwrap();
        assert_eq!(gw, Some("10.211.55.1".parse().unwrap()));
        assert_eq!(dev, "enp0s5");

        let (gw, dev) =
            parse_route_get("10.211.55.1 dev enp0s5 src 10.211.55.100 uid 1000").unwrap();
        assert_eq!(gw, None, "an on-link destination has no gateway");
        assert_eq!(dev, "enp0s5");

        assert_eq!(
            parse_route_get("127.0.0.1 dev lo src 127.0.0.1 uid 1000 \n"),
            Some((None, "lo".to_string()))
        );
        // No `dev` token, and a truncated one, both yield no device.
        assert_eq!(parse_route_get(""), None);
        assert_eq!(parse_route_get("10.0.0.1 proto kernel scope link"), None);
        assert_eq!(parse_route_get("10.0.0.1 dev"), None);
    }
}
