//! macOS interface configuration: `ifconfig(8)` for addresses and MTU,
//! `route(8)` for routes.
//!
//! Two shapes differ from Linux beyond the program name. utun interfaces are
//! point-to-point, so an address is given with a destination rather than as
//! `addr/len` — straw has no peer address (the far side is a tunnel, not a
//! neighbour), so the address points at itself, matching what
//! [`crate::forwarding::tun`] configures at creation. And removal is
//! `-alias`, not a `del` verb.

use std::net::IpAddr;
use std::process::Command;

use ipnet::IpNet;

use super::Cmd;
use crate::error::ProxyError;

/// Netmask for an IPv4 prefix length, as `ifconfig` wants it spelled.
fn netmask(prefix_len: u8) -> String {
    let bits = if prefix_len == 0 {
        0
    } else {
        u32::MAX << (32 - prefix_len.min(32) as u32)
    };
    std::net::Ipv4Addr::from(bits).to_string()
}

/// `ifconfig <dev> inet <ip> <ip> netmask <mask>` (add) or
/// `ifconfig <dev> inet <ip> -alias` (del); `inet6 … prefixlen <len>` for v6.
pub fn addr_cmd(action: &str, dev: &str, addr: IpAddr, prefix_len: u8) -> Cmd {
    let family = if addr.is_ipv4() { "inet" } else { "inet6" };
    let mut args = vec![dev.into(), family.into(), addr.to_string()];
    if action == "add" {
        match addr {
            // Point-to-point: local and destination, then the mask.
            IpAddr::V4(_) => {
                args.push(addr.to_string());
                args.push("netmask".into());
                args.push(netmask(prefix_len));
            }
            IpAddr::V6(_) => {
                args.push("prefixlen".into());
                args.push(prefix_len.to_string());
            }
        }
    } else {
        args.push("-alias".into());
    }
    Cmd::new("ifconfig", args)
}

/// `route -n {add,delete} [-inet6] -net <prefix> -interface <dev>`.
pub fn route_cmd(action: &str, prefix: IpNet, dev: &str) -> Cmd {
    let mut args = vec!["-n".to_string(), verb(action)];
    if let IpNet::V6(_) = prefix {
        args.push("-inet6".into());
    }
    args.push("-net".into());
    args.push(prefix.to_string());
    args.push("-interface".into());
    args.push(dev.into());
    Cmd::new("route", args)
}

/// `route -n {add,delete} [-inet6] -host <proxy> <gw>|-interface <dev>` — the
/// host route that keeps the tunnel's own QUIC packets off the tunnel.
pub fn pin_cmd(action: &str, proxy: IpAddr, gateway: Option<IpAddr>, dev: &str) -> Cmd {
    let mut args = vec!["-n".to_string(), verb(action)];
    if proxy.is_ipv6() {
        args.push("-inet6".into());
    }
    args.push("-host".into());
    args.push(proxy.to_string());
    match gateway {
        // A gateway is given positionally; an on-link destination is reached
        // through the interface instead.
        Some(gw) => args.push(gw.to_string()),
        None => {
            args.push("-interface".into());
            args.push(dev.into());
        }
    }
    Cmd::new("route", args)
}

/// `ifconfig <dev> mtu <mtu>`.
pub fn mtu_cmd(dev: &str, mtu: u16) -> Cmd {
    Cmd::new("ifconfig", [dev.into(), "mtu".into(), mtu.to_string()])
}

/// `route(8)` spells deletion `delete`, where `ip(8)` says `del`.
fn verb(action: &str) -> String {
    match action {
        "add" => "add".to_string(),
        _ => "delete".to_string(),
    }
}

/// Parse `route -n get <dst>` into (gateway, device).
///
/// ```text
///    route to: 8.8.8.8
/// destination: 8.8.8.8
///     gateway: 192.168.1.1
///   interface: en0
/// ```
///
/// An on-link destination has no `gateway:` line, hence the optional gateway.
pub fn parse_route_get(output: &str) -> Option<(Option<IpAddr>, String)> {
    let field = |key: &str| {
        output.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            (name.trim() == key).then(|| value.trim().to_string())
        })
    };
    let dev = field("interface")?;
    let gateway = field("gateway").and_then(|g| g.parse().ok());
    Some((gateway, dev))
}

/// Ask the kernel how it currently reaches `dst`, before any tunnel routes
/// exist. Used to pin the proxy to the pre-tunnel path.
pub fn path_to(dst: IpAddr) -> Result<(Option<IpAddr>, String), ProxyError> {
    let mut args = vec!["-n".to_string(), "get".to_string()];
    if dst.is_ipv6() {
        args.push("-inet6".into());
    }
    args.push(dst.to_string());
    let out = Command::new("route")
        .args(&args)
        .output()
        .map_err(|e| ProxyError::Config(format!("failed to run route get: {e}")))?;
    if !out.status.success() {
        return Err(ProxyError::Config(format!(
            "route -n get {dst} failed: {}",
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
    fn addresses_are_point_to_point_and_removed_with_alias() {
        assert_eq!(
            addr_cmd("add", "utun9", "10.100.0.2".parse().unwrap(), 32).to_string(),
            "ifconfig utun9 inet 10.100.0.2 10.100.0.2 netmask 255.255.255.255"
        );
        assert_eq!(
            addr_cmd("del", "utun9", "10.100.0.2".parse().unwrap(), 32).to_string(),
            "ifconfig utun9 inet 10.100.0.2 -alias"
        );
        assert_eq!(
            addr_cmd("add", "utun9", "fd00::2".parse().unwrap(), 64).to_string(),
            "ifconfig utun9 inet6 fd00::2 prefixlen 64"
        );
    }

    #[test]
    fn routes_use_delete_not_del() {
        assert_eq!(
            route_cmd("add", "10.0.0.0/8".parse().unwrap(), "utun9").to_string(),
            "route -n add -net 10.0.0.0/8 -interface utun9"
        );
        // `ip` says del, `route` says delete; getting this wrong would leave
        // the route installed and fail only at teardown.
        assert_eq!(
            route_cmd("del", "10.0.0.0/8".parse().unwrap(), "utun9").to_string(),
            "route -n delete -net 10.0.0.0/8 -interface utun9"
        );
        assert_eq!(
            route_cmd("add", "fd00::/8".parse().unwrap(), "utun9").to_string(),
            "route -n add -inet6 -net fd00::/8 -interface utun9"
        );
    }

    #[test]
    fn pin_command_uses_a_gateway_or_the_interface() {
        assert_eq!(
            pin_cmd(
                "add",
                "203.0.113.9".parse().unwrap(),
                Some("192.168.1.1".parse().unwrap()),
                "en0"
            )
            .to_string(),
            "route -n add -host 203.0.113.9 192.168.1.1"
        );
        // On-link: there is no gateway to hand route(8), so name the link.
        assert_eq!(
            pin_cmd("del", "192.168.1.1".parse().unwrap(), None, "en0").to_string(),
            "route -n delete -host 192.168.1.1 -interface en0"
        );
    }

    #[test]
    fn mtu_command() {
        assert_eq!(
            mtu_cmd("utun9", 1400).to_string(),
            "ifconfig utun9 mtu 1400"
        );
    }

    /// Parsed from real `route -n get` output on macOS 26.
    #[test]
    fn route_get_parsing() {
        let via_gateway = "   route to: 8.8.8.8\n\
                           destination: 8.8.8.8\n\
                               gateway: 192.168.1.1\n\
                             interface: en0\n\
                                 flags: <UP,GATEWAY,HOST,DONE>\n";
        let (gw, dev) = parse_route_get(via_gateway).unwrap();
        assert_eq!(gw, Some("192.168.1.1".parse().unwrap()));
        assert_eq!(dev, "en0");

        // On-link destinations simply omit the gateway line.
        let on_link = "   route to: 192.168.1.1\n\
                       destination: 192.168.1.1\n\
                         interface: en0\n\
                             flags: <UP,HOST,DONE,LLINFO>\n";
        let (gw, dev) = parse_route_get(on_link).unwrap();
        assert_eq!(gw, None);
        assert_eq!(dev, "en0");

        assert!(parse_route_get("").is_none());
        assert!(
            parse_route_get("route: writing to routing socket: not in table").is_none(),
            "a failed lookup must not parse as a route"
        );
    }

    #[test]
    fn netmask_from_prefix() {
        assert_eq!(netmask(32), "255.255.255.255");
        assert_eq!(netmask(24), "255.255.255.0");
        assert_eq!(netmask(0), "0.0.0.0");
    }
}
