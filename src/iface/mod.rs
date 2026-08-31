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

/// What the tunnel interface should look like — the decision, with none of
/// the machinery for carrying it out.
///
/// This is the seam between *deciding* and *realising*, and it exists because
/// the two platforms that realise it could not be less alike. The CLI backends
/// turn this into a sequence of `ifconfig`/`ip`/`route` invocations with an
/// undo list. Apple's NetworkExtension cannot execute anything at all: a
/// provider hands the system one `NEPacketTunnelNetworkSettings` object, which
/// is applied atomically and replaced wholesale — there is no "add one route"
/// and nothing to undo. A plan that is pure data maps onto both;
/// a plan expressed as commands maps onto only one.
///
/// Being pure also makes the interesting part testable without a kernel:
/// `plan` decides everything, and every test below drives it directly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesiredInterface {
    /// Device to configure. Whatever the device actually ended up being
    /// called — see `TunChannels::name`.
    pub dev: String,
    /// Addresses to put on it, as (address, prefix length).
    pub addresses: Vec<(IpAddr, u8)>,
    /// Routes to send through it, already decomposed from the advertised
    /// ranges and already split if they are default routes.
    pub routes: Vec<IpNet>,
    /// An address that must stay reachable *outside* the tunnel — the proxy's
    /// own, or the tunnel's transport captures itself.
    ///
    /// Only the requirement is stated here, not how to meet it, because the
    /// answers differ in kind: a host route over the pre-tunnel path on the
    /// CLI, an excluded route (or nothing at all) under NetworkExtension.
    pub keep_off_tunnel: Option<IpAddr>,
}

/// Decide what the interface should look like. Pure: no I/O, no commands.
pub fn plan(setup: &InterfaceSetup<'_>) -> DesiredInterface {
    DesiredInterface {
        dev: setup.dev.to_string(),
        addresses: setup
            .assigned
            .iter()
            .map(|a| (a.ip_address, a.prefix_length))
            .collect(),
        // `install_routes: false` configures addresses only, so there is
        // nothing to keep off a tunnel that carries nothing.
        routes: if setup.install_routes {
            prefixes_from_ranges(setup.routes)
        } else {
            Vec::new()
        },
        keep_off_tunnel: if setup.install_routes {
            setup.pin
        } else {
            None
        },
    }
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
    realize(&plan(setup))
}

/// The commands that realise `want`, each paired with the command that undoes
/// it, in the order they must be applied.
///
/// Split out from [`realize`] so the ordering can be asserted: the address that
/// must stay off the tunnel is pinned **first**, before any route exists that
/// could capture the tunnel's own transport. That is a correctness property,
/// not a style preference, and a comment saying so is not a test.
///
/// `pin_path` is the pre-tunnel route to that address, which only the kernel
/// can answer — the one piece [`plan`] cannot decide on its own.
fn commands(
    want: &DesiredInterface,
    pin_path: Option<&(IpAddr, (Option<IpAddr>, String))>,
) -> Vec<(Cmd, Cmd)> {
    let mut out = Vec::new();
    if let Some((proxy, (gateway, dev))) = pin_path {
        out.push((
            pin_cmd("add", *proxy, *gateway, dev),
            pin_cmd("del", *proxy, *gateway, dev),
        ));
    }
    for (addr, len) in &want.addresses {
        out.push((
            addr_cmd("add", &want.dev, *addr, *len),
            addr_cmd("del", &want.dev, *addr, *len),
        ));
    }
    for prefix in &want.routes {
        out.push((
            route_cmd("add", *prefix, &want.dev),
            route_cmd("del", *prefix, &want.dev),
        ));
    }
    out
}

/// Carry out a [`DesiredInterface`] with this platform's commands.
///
/// The ordering is the one part that is not mechanical: the address that keeps
/// the proxy off the tunnel goes in **before** any tunnel route, so there is
/// never a moment where a default-route half captures the QUIC connection.
pub fn realize(want: &DesiredInterface) -> Result<InterfaceGuard, ProxyError> {
    // Resolving the pre-tunnel path is the only I/O the plan cannot carry:
    // it has to be asked of the kernel, before any tunnel route exists.
    let pin_path = match want.keep_off_tunnel {
        Some(proxy) => Some((proxy, path_to(proxy)?)),
        None => None,
    };

    let mut guard = InterfaceGuard { undo: Vec::new() };
    for (apply, undo) in commands(want, pin_path.as_ref()) {
        tracing::info!(cmd = %apply, "configuring interface");
        run(&apply)?;
        guard.undo.push(undo);
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

    fn assigned(ip: &str, len: u8) -> AssignedAddress {
        AssignedAddress {
            request_id: 0,
            ip_version: if ip.contains(':') { 6 } else { 4 },
            ip_address: ip.parse().unwrap(),
            prefix_length: len,
        }
    }

    /// The whole point of the split: what the interface should look like is
    /// decided without a kernel, so it can be asserted directly.
    #[test]
    fn plan_decides_addresses_routes_and_what_must_stay_off_the_tunnel() {
        let want = plan(&InterfaceSetup {
            dev: "strawc0",
            assigned: &[assigned("10.100.0.2", 32)],
            routes: &[range("10.0.0.0", "10.255.255.255", 0)],
            pin: Some("203.0.113.9".parse().unwrap()),
            install_routes: true,
        });
        assert_eq!(want.dev, "strawc0");
        assert_eq!(want.addresses, vec![("10.100.0.2".parse().unwrap(), 32)]);
        assert_eq!(want.routes, vec!["10.0.0.0/8".parse::<IpNet>().unwrap()]);
        assert_eq!(want.keep_off_tunnel, Some("203.0.113.9".parse().unwrap()));
    }

    /// `install_routes: false` is address-only. The pin goes with the routes:
    /// nothing is capturing the transport, so nothing needs keeping off it —
    /// and installing a host route on a physical interface anyway would be a
    /// side effect the caller did not ask for.
    #[test]
    fn address_only_setup_plans_no_routes_and_no_pin() {
        let want = plan(&InterfaceSetup {
            dev: "strawc0",
            assigned: &[assigned("10.100.0.2", 32)],
            routes: &[range("0.0.0.0", "255.255.255.255", 0)],
            pin: Some("203.0.113.9".parse().unwrap()),
            install_routes: false,
        });
        assert_eq!(want.addresses.len(), 1, "addresses are still configured");
        assert!(want.routes.is_empty(), "no routes were asked for");
        assert_eq!(
            want.keep_off_tunnel, None,
            "nothing to keep off an empty tunnel"
        );
    }

    /// A full tunnel arrives as a default route and must reach the plan
    /// already split, because a plan carrying 0.0.0.0/0 would be one that
    /// captures the tunnel's own transport on any platform that applies it.
    #[test]
    fn a_full_tunnel_plan_carries_halves_not_a_default_route() {
        let want = plan(&InterfaceSetup {
            dev: "utun9",
            assigned: &[assigned("10.100.0.2", 32)],
            routes: &[range("0.0.0.0", "255.255.255.255", 0)],
            pin: Some("203.0.113.9".parse().unwrap()),
            install_routes: true,
        });
        assert_eq!(
            want.routes,
            vec![
                "0.0.0.0/1".parse::<IpNet>().unwrap(),
                "128.0.0.0/1".parse().unwrap()
            ]
        );
        assert!(
            !want.routes.contains(&"0.0.0.0/0".parse::<IpNet>().unwrap()),
            "a default route must never reach the plan"
        );
    }

    /// The ordering property, asserted rather than commented: whatever must
    /// stay off the tunnel is pinned before any route exists that could
    /// capture the tunnel's own transport, and the undo list unwinds it last.
    #[test]
    fn the_pin_is_applied_before_any_route() {
        let want = plan(&InterfaceSetup {
            dev: "strawc0",
            assigned: &[assigned("10.100.0.2", 32)],
            routes: &[range("0.0.0.0", "255.255.255.255", 0)],
            pin: Some("203.0.113.9".parse().unwrap()),
            install_routes: true,
        });
        let proxy: IpAddr = "203.0.113.9".parse().unwrap();
        let path = (
            proxy,
            (Some("192.168.1.1".parse().unwrap()), "en0".to_string()),
        );
        let cmds = commands(&want, Some(&path));

        let rendered: Vec<String> = cmds.iter().map(|(apply, _)| apply.to_string()).collect();
        assert!(
            rendered[0].contains("203.0.113.9"),
            "the pin must come first, got {rendered:?}"
        );
        let first_route = rendered
            .iter()
            .position(|c| c.contains("0.0.0.0/1"))
            .expect("a default-route half is installed");
        assert!(
            first_route > 0,
            "a route was installed before the pin: {rendered:?}"
        );
        // Addresses land between the two.
        let addr = rendered
            .iter()
            .position(|c| c.contains("10.100.0.2"))
            .expect("the assigned address is configured");
        assert!(addr > 0 && addr < first_route, "{rendered:?}");
    }

    /// Every applied command carries the command that undoes it, or teardown
    /// silently leaves state behind — which matters most for the pin, since it
    /// lives on a physical interface and outlives the TUN device.
    #[test]
    fn every_command_has_an_undo() {
        let want = plan(&InterfaceSetup {
            dev: "strawc0",
            assigned: &[assigned("10.100.0.2", 32)],
            routes: &[range("10.0.0.0", "10.255.255.255", 0)],
            pin: None,
            install_routes: true,
        });
        let cmds = commands(&want, None);
        assert_eq!(cmds.len(), 2, "one address, one route");
        for (apply, undo) in &cmds {
            assert_ne!(
                apply, undo,
                "an undo that repeats the command is not an undo"
            );
            assert_eq!(apply.program, undo.program);
        }
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
