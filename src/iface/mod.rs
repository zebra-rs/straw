//! Kernel interface configuration: addresses, routes, MTU.
//!
//! Two callers: `strawc` applies the proxy's ADDRESS_ASSIGN and
//! ROUTE_ADVERTISEMENT to the kernel here (and takes it down again on drop),
//! and the server uses it to give its TUN device an IPv6 address, which the
//! `tun` crate cannot do.
//!
//! Shells out, the way [`crate::forwarding::nat`] shells out to `iptables`.
//! Which program it shells out to is the platform's business: Linux does all
//! three jobs with `ip(8)`, macOS needs `ifconfig(8)` for addresses and MTU
//! and `route(8)` for routes. So a command here is a [`Cmd`] — program *and*
//! arguments — rather than an argument vector with the program implied.
//!
//! Every command is built by a pure function, so the interesting logic —
//! range decomposition, default-route splitting, route-lookup parsing — is
//! unit tested per platform without touching the kernel.
//!
//! Requires the privilege the TUN device needs: `CAP_NET_ADMIN` on Linux,
//! root on macOS.

use std::net::IpAddr;
use std::process::Command;

use ipnet::{IpNet, Ipv4Subnets, Ipv6Subnets};

use crate::capsule::{AssignedAddress, IpAddressRange};
use crate::error::ProxyError;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::{addr_cmd, mtu_cmd, path_to, pin_cmd, route_cmd};

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::{addr_cmd, mtu_cmd, path_to, pin_cmd, route_cmd};

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod unsupported;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub use unsupported::{addr_cmd, mtu_cmd, path_to, pin_cmd, route_cmd};

/// A configuration command: which program, and what to pass it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cmd {
    pub program: &'static str,
    pub args: Vec<String>,
}

impl Cmd {
    pub(crate) fn new(program: &'static str, args: impl IntoIterator<Item = String>) -> Self {
        Self {
            program,
            args: args.into_iter().collect(),
        }
    }
}

impl std::fmt::Display for Cmd {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.program, self.args.join(" "))
    }
}

/// Run `cmd`, turning a non-zero exit into an error carrying stderr.
pub fn run(cmd: &Cmd) -> Result<(), ProxyError> {
    let out = Command::new(cmd.program)
        .args(&cmd.args)
        .output()
        .map_err(|e| ProxyError::Config(format!("failed to run {}: {e}", cmd.program)))?;
    if !out.status.success() {
        return Err(ProxyError::Config(format!(
            "`{cmd}` failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
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
    undo: Vec<Cmd>,
}

impl Drop for InterfaceGuard {
    fn drop(&mut self) {
        // Reverse order: the pin route was installed first, so it goes last.
        for cmd in self.undo.iter().rev() {
            if let Err(e) = run(cmd) {
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
        run(&pin_cmd("add", proxy, gateway, &dev))?;
        guard.undo.push(pin_cmd("del", proxy, gateway, &dev));
        tracing::info!(%proxy, ?gateway, dev, "pinned proxy to the pre-tunnel path");
    }

    for a in setup.assigned {
        run(&addr_cmd("add", setup.dev, a.ip_address, a.prefix_length))?;
        guard
            .undo
            .push(addr_cmd("del", setup.dev, a.ip_address, a.prefix_length));
        tracing::info!(addr = %a.ip_address, len = a.prefix_length, dev = setup.dev, "address configured");
    }

    if setup.install_routes {
        for prefix in prefixes_from_ranges(setup.routes) {
            run(&route_cmd("add", prefix, setup.dev))?;
            guard.undo.push(route_cmd("del", prefix, setup.dev));
            tracing::info!(%prefix, dev = setup.dev, "route installed");
        }
    }

    Ok(guard)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn range(start: &str, end: &str, proto: u8) -> IpAddressRange {
        let start_ip: IpAddr = start.parse().unwrap();
        IpAddressRange {
            ip_version: if start_ip.is_ipv4() { 4 } else { 6 },
            start_ip,
            end_ip: end.parse().unwrap(),
            ip_protocol: proto,
        }
    }

    #[test]
    fn a_default_route_is_installed_as_two_halves() {
        assert_eq!(
            split_default("0.0.0.0/0".parse().unwrap()),
            vec![
                "0.0.0.0/1".parse::<IpNet>().unwrap(),
                "128.0.0.0/1".parse().unwrap()
            ]
        );
        assert_eq!(
            split_default("::/0".parse().unwrap()),
            vec![
                "::/1".parse::<IpNet>().unwrap(),
                "8000::/1".parse().unwrap()
            ]
        );
        // Anything more specific is installed as it stands.
        let specific: IpNet = "10.0.0.0/8".parse().unwrap();
        assert_eq!(split_default(specific), vec![specific]);
    }

    #[test]
    fn full_tunnel_becomes_two_halves() {
        let all = prefixes_from_ranges(&[range("0.0.0.0", "255.255.255.255", 0)]);
        assert_eq!(
            all,
            vec![
                "0.0.0.0/1".parse::<IpNet>().unwrap(),
                "128.0.0.0/1".parse().unwrap()
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
}
