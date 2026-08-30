//! Kernel interface configuration via `ip(8)`.
//!
//! Two callers: `strawc` applies the proxy's ADDRESS_ASSIGN and
//! ROUTE_ADVERTISEMENT to the kernel here (and takes it down again on drop),
//! and the server uses [`ip`] to give its TUN device an IPv6 address, which
//! the `tun` crate cannot do.
//!
//! Shells out the way [`crate::forwarding::nat`] shells out to `iptables`.
//! Every argument vector is built by a pure function, so the interesting
//! logic — range decomposition, default-route splitting, `ip route get`
//! parsing — is unit tested without touching the kernel.
//!
//! Requires `CAP_NET_ADMIN`, the same privilege the TUN device needs.

use std::net::IpAddr;
use std::process::Command;

use ipnet::{IpNet, Ipv4Subnets, Ipv6Subnets};

use crate::capsule::{AssignedAddress, IpAddressRange};
use crate::error::ProxyError;

/// `ip addr {add,del} <ip>/<len> dev <dev>`.
pub fn addr_args(action: &str, dev: &str, addr: IpAddr, prefix_len: u8) -> Vec<String> {
    vec![
        "addr".into(),
        action.into(),
        format!("{addr}/{prefix_len}"),
        "dev".into(),
        dev.into(),
    ]
}

/// `ip route {add,del} <prefix> dev <dev>`.
pub fn route_args(action: &str, prefix: IpNet, dev: &str) -> Vec<String> {
    vec![
        "route".into(),
        action.into(),
        prefix.to_string(),
        "dev".into(),
        dev.into(),
    ]
}

/// `ip route {add,del} <proxy> [via <gw>] dev <dev>` — the host route that
/// keeps the tunnel's own QUIC packets off the tunnel.
pub fn pin_args(action: &str, proxy: IpAddr, gateway: Option<IpAddr>, dev: &str) -> Vec<String> {
    let host_len = if proxy.is_ipv4() { 32 } else { 128 };
    let mut args = vec!["route".into(), action.into(), format!("{proxy}/{host_len}")];
    if let Some(gw) = gateway {
        args.push("via".into());
        args.push(gw.to_string());
    }
    args.push("dev".into());
    args.push(dev.into());
    args
}

/// `ip link set dev <dev> mtu <mtu>`.
pub fn mtu_args(dev: &str, mtu: u16) -> Vec<String> {
    vec![
        "link".into(),
        "set".into(),
        "dev".into(),
        dev.into(),
        "mtu".into(),
        mtu.to_string(),
    ]
}

/// A default route is installed as two halves rather than `0.0.0.0/0`, so
/// the pre-existing default route survives underneath it to carry the
/// tunnel's own QUIC packets. This is the standard VPN redirect-gateway
/// trick: each half is more specific than the default, and both are less
/// specific than the host route pinning the proxy.
pub fn split_default(prefix: IpNet) -> Vec<IpNet> {
    if prefix.prefix_len() != 0 {
        return vec![prefix];
    }
    match prefix {
        IpNet::V4(_) => vec!["0.0.0.0/1".parse().unwrap(), "128.0.0.0/1".parse().unwrap()],
        IpNet::V6(_) => vec!["::/1".parse().unwrap(), "8000::/1".parse().unwrap()],
    }
}

/// Decompose advertised ranges (RFC 9484 §4.7.3) into kernel-installable
/// prefixes.
///
/// Protocol-scoped ranges are skipped: a plain routing table cannot express
/// "only protocol N", and installing the prefix unscoped would send traffic
/// the proxy is going to reject anyway.
pub fn prefixes_from_ranges(ranges: &[IpAddressRange]) -> Vec<IpNet> {
    let mut out: Vec<IpNet> = Vec::new();
    for range in ranges {
        if range.ip_protocol != 0 {
            tracing::warn!(
                ?range,
                "skipping protocol-scoped route: not expressible in the routing table"
            );
            continue;
        }
        let prefixes: Vec<IpNet> = match (range.start_ip, range.end_ip) {
            (IpAddr::V4(start), IpAddr::V4(end)) if start <= end => {
                Ipv4Subnets::new(start, end, 0).map(IpNet::V4).collect()
            }
            (IpAddr::V6(start), IpAddr::V6(end)) if start <= end => {
                Ipv6Subnets::new(start, end, 0).map(IpNet::V6).collect()
            }
            _ => {
                tracing::warn!(?range, "ignoring malformed route range");
                continue;
            }
        };
        for prefix in prefixes {
            out.extend(split_default(prefix));
        }
    }
    out.sort();
    out.dedup();
    out
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

/// What to apply to the client's tunnel interface.
#[derive(Debug)]
pub struct InterfaceSetup<'a> {
    /// TUN device name; must already exist and be up.
    pub dev: &'a str,
    /// Addresses from ADDRESS_ASSIGN.
    pub assigned: &'a [AssignedAddress],
    /// Ranges from ROUTE_ADVERTISEMENT.
    pub routes: &'a [IpAddressRange],
    /// Proxy address to keep reachable outside the tunnel. Skipped when
    /// `None` (e.g. a loopback proxy, which no advertised route covers).
    pub pin: Option<IpAddr>,
    /// Install routes at all; false configures addresses only.
    pub install_routes: bool,
}

/// Kernel state installed by [`configure`]; reverted on drop.
///
/// Routes on the TUN device disappear with the device, so the undo list
/// matters mainly for the pin route, which lives on a physical interface.
#[derive(Debug)]
pub struct InterfaceGuard {
    undo: Vec<Vec<String>>,
}

impl Drop for InterfaceGuard {
    fn drop(&mut self) {
        // Reverse order: the pin route was installed first, so it goes last.
        for args in self.undo.iter().rev() {
            if let Err(e) = ip(args) {
                tracing::debug!("interface cleanup: {e}");
            }
        }
    }
}

/// Apply addresses and routes, returning a guard that removes them again.
///
/// The pin route goes in before any tunnel route, so there is never a moment
/// where a default-route half captures the QUIC connection.
pub fn configure(setup: &InterfaceSetup<'_>) -> Result<InterfaceGuard, ProxyError> {
    let mut guard = InterfaceGuard { undo: Vec::new() };

    if setup.install_routes
        && let Some(proxy) = setup.pin
    {
        let (gateway, dev) = path_to(proxy)?;
        ip(&pin_args("add", proxy, gateway, &dev))?;
        guard.undo.push(pin_args("del", proxy, gateway, &dev));
        tracing::info!(%proxy, ?gateway, dev, "pinned proxy to the pre-tunnel path");
    }

    for a in setup.assigned {
        ip(&addr_args("add", setup.dev, a.ip_address, a.prefix_length))?;
        guard
            .undo
            .push(addr_args("del", setup.dev, a.ip_address, a.prefix_length));
        tracing::info!(addr = %a.ip_address, len = a.prefix_length, dev = setup.dev, "address configured");
    }

    if setup.install_routes {
        for prefix in prefixes_from_ranges(setup.routes) {
            ip(&route_args("add", prefix, setup.dev))?;
            guard.undo.push(route_args("del", prefix, setup.dev));
            tracing::info!(%prefix, dev = setup.dev, "route installed");
        }
    }

    Ok(guard)
}

/// Run `ip` with `args`, turning a non-zero exit into an error carrying
/// stderr. The command name is implicit so callers pass only the verb.
pub fn ip(args: &[String]) -> Result<(), ProxyError> {
    let out = Command::new("ip")
        .args(args)
        .output()
        .map_err(|e| ProxyError::Config(format!("failed to run ip: {e}")))?;
    if !out.status.success() {
        return Err(ProxyError::Config(format!(
            "`ip {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn range(start: &str, end: &str, proto: u8) -> IpAddressRange {
        let start_ip: IpAddr = start.parse().unwrap();
        IpAddressRange {
            ip_version: if start_ip.is_ipv4() { 4 } else { 6 },
            start_ip,
            end_ip: end.parse().unwrap(),
            ip_protocol: proto,
        }
    }

    #[test]
    fn addr_and_route_args() {
        assert_eq!(
            addr_args("add", "strawc0", "10.100.0.2".parse().unwrap(), 32).join(" "),
            "addr add 10.100.0.2/32 dev strawc0"
        );
        assert_eq!(
            route_args("del", "192.168.0.0/16".parse().unwrap(), "strawc0").join(" "),
            "route del 192.168.0.0/16 dev strawc0"
        );
    }

    #[test]
    fn pin_route_with_and_without_gateway() {
        let proxy: IpAddr = "10.211.55.100".parse().unwrap();
        assert_eq!(
            pin_args("add", proxy, Some("10.211.55.1".parse().unwrap()), "enp0s5").join(" "),
            "route add 10.211.55.100/32 via 10.211.55.1 dev enp0s5"
        );
        // On-link proxy: no gateway to go via.
        assert_eq!(
            pin_args("add", proxy, None, "enp0s5").join(" "),
            "route add 10.211.55.100/32 dev enp0s5"
        );
    }

    #[test]
    fn full_tunnel_becomes_two_halves() {
        let ranges = vec![range("0.0.0.0", "255.255.255.255", 0)];
        let prefixes = prefixes_from_ranges(&ranges);
        assert_eq!(
            prefixes,
            vec![
                "0.0.0.0/1".parse::<IpNet>().unwrap(),
                "128.0.0.0/1".parse().unwrap()
            ]
        );
        // Crucially, the default route itself is never installed.
        assert!(!prefixes.iter().any(|p| p.prefix_len() == 0));
    }

    #[test]
    fn v6_default_splits_too() {
        let ranges = vec![range("::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", 0)];
        assert_eq!(
            prefixes_from_ranges(&ranges),
            vec![
                "::/1".parse::<IpNet>().unwrap(),
                "8000::/1".parse().unwrap()
            ]
        );
    }

    #[test]
    fn split_tunnel_ranges_decompose_to_prefixes() {
        let ranges = vec![
            range("10.100.0.0", "10.100.0.255", 0),
            range("192.168.0.0", "192.168.255.255", 0),
        ];
        assert_eq!(
            prefixes_from_ranges(&ranges),
            vec![
                "10.100.0.0/24".parse::<IpNet>().unwrap(),
                "192.168.0.0/16".parse().unwrap()
            ]
        );
    }

    #[test]
    fn protocol_scoped_ranges_are_skipped() {
        // ICMP-only route: the routing table has no protocol selector.
        let ranges = vec![range("10.0.0.0", "10.255.255.255", 1)];
        assert!(prefixes_from_ranges(&ranges).is_empty());
    }

    #[test]
    fn overlapping_ranges_deduplicate() {
        let ranges = vec![
            range("10.0.0.0", "10.255.255.255", 0),
            range("10.0.0.0", "10.255.255.255", 0),
        ];
        assert_eq!(prefixes_from_ranges(&ranges).len(), 1);
    }

    #[test]
    fn malformed_range_is_ignored() {
        // start > end, and a mixed-family range.
        let ranges = vec![
            range("10.0.0.5", "10.0.0.1", 0),
            IpAddressRange {
                ip_version: 4,
                start_ip: "10.0.0.0".parse().unwrap(),
                end_ip: "::1".parse().unwrap(),
                ip_protocol: 0,
            },
        ];
        assert!(prefixes_from_ranges(&ranges).is_empty());
    }

    #[test]
    fn route_get_with_gateway() {
        let out = "8.8.8.8 via 10.211.55.1 dev enp0s5 src 10.211.55.100 uid 1000 \n    cache \n";
        assert_eq!(
            parse_route_get(out),
            Some((Some("10.211.55.1".parse().unwrap()), "enp0s5".to_string()))
        );
    }

    #[test]
    fn route_get_on_link() {
        let out = "10.211.55.1 dev enp0s5 src 10.211.55.100 uid 1000 \n    cache \n";
        assert_eq!(parse_route_get(out), Some((None, "enp0s5".to_string())));
    }

    #[test]
    fn route_get_loopback_and_garbage() {
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
