//! NAT setup for TUN egress (Step 27, Linux only): enable IP forwarding
//! and masquerade pool traffic out a physical interface.
//!
//! Shells out to `sysctl` and `iptables`/`ip6tables`; the added rules are
//! removed again on drop. Requires the same privileges as TUN creation.

use ipnet::IpNet;

use crate::error::ProxyError;

/// One `-A POSTROUTING ...` rule, expressed as arguments so the same list
/// serves `-A` (add), `-C` (check) and `-D` (delete).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MasqueradeRule {
    /// `iptables` or `ip6tables`.
    pub command: &'static str,
    pub args: Vec<String>,
}

/// Build the rule set for masquerading `pools` out of `interface`.
pub fn masquerade_rules(pools: &[IpNet], interface: &str) -> Vec<MasqueradeRule> {
    pools
        .iter()
        .map(|pool| MasqueradeRule {
            command: match pool {
                IpNet::V4(_) => "iptables",
                IpNet::V6(_) => "ip6tables",
            },
            args: vec![
                "-t".into(),
                "nat".into(),
                "POSTROUTING".into(),
                "-s".into(),
                pool.to_string(),
                "-o".into(),
                interface.into(),
                "-j".into(),
                "MASQUERADE".into(),
            ],
        })
        .collect()
}

/// sysctl keys that must be 1 for the given pools to route.
pub fn forwarding_sysctls(pools: &[IpNet]) -> Vec<&'static str> {
    let mut keys = Vec::new();
    if pools.iter().any(|p| matches!(p, IpNet::V4(_))) {
        keys.push("net.ipv4.ip_forward=1");
    }
    if pools.iter().any(|p| matches!(p, IpNet::V6(_))) {
        keys.push("net.ipv6.conf.all.forwarding=1");
    }
    keys
}

/// Installed NAT state; removes its rules on drop.
pub struct NatGuard {
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    rules: Vec<MasqueradeRule>,
}

/// Enable forwarding and install masquerade rules (Linux).
#[cfg(target_os = "linux")]
pub fn setup_nat(pools: &[IpNet], interface: &str) -> Result<NatGuard, ProxyError> {
    use std::process::Command;

    for sysctl in forwarding_sysctls(pools) {
        let status = Command::new("sysctl")
            .args(["-w", sysctl])
            .status()
            .map_err(|e| ProxyError::Config(format!("sysctl failed to run: {e}")))?;
        if !status.success() {
            return Err(ProxyError::Config(format!("sysctl -w {sysctl} failed")));
        }
    }

    let rules = masquerade_rules(pools, interface);
    for rule in &rules {
        // Idempotence: skip the append when the rule already exists.
        let exists = Command::new(rule.command)
            .args(with_action(&rule.args, "-C"))
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if exists {
            continue;
        }
        let status = Command::new(rule.command)
            .args(with_action(&rule.args, "-A"))
            .status()
            .map_err(|e| ProxyError::Config(format!("{} failed to run: {e}", rule.command)))?;
        if !status.success() {
            return Err(ProxyError::Config(format!(
                "{} -A POSTROUTING rule failed",
                rule.command
            )));
        }
        tracing::info!(command = rule.command, ?rule.args, "masquerade rule installed");
    }
    Ok(NatGuard { rules })
}

/// NAT is Linux-only, by choice rather than by omission.
///
/// The TUN device it serves does have a macOS backend, so this could be
/// written against pf (`pfctl` anchors, `net.inet.ip.forwarding`) — pf is
/// global, anchor-scoped state, where an iptables rule is deleted by value, so
/// it is real work with a real teardown hazard. It is not planned: straw's
/// deployment runs the **proxy on Linux and the client on macOS**, and nothing
/// on the client masquerades. The error says so rather than implying a
/// port is coming.
#[cfg(not(target_os = "linux"))]
pub fn setup_nat(_pools: &[IpNet], _interface: &str) -> Result<NatGuard, ProxyError> {
    Err(ProxyError::Config(
        "--nat-interface needs iptables and is Linux-only; run the proxy on \
         Linux (macOS is supported as a client: strawc, strawcat)"
            .to_string(),
    ))
}

/// The rule args carry the chain at index 2; the action flag goes before it.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn with_action(args: &[String], action: &str) -> Vec<String> {
    let mut out = Vec::with_capacity(args.len() + 1);
    out.extend_from_slice(&args[..2]); // -t nat
    out.push(action.to_string());
    out.extend_from_slice(&args[2..]); // POSTROUTING -s ... -j MASQUERADE
    out
}

impl Drop for NatGuard {
    fn drop(&mut self) {
        #[cfg(target_os = "linux")]
        for rule in &self.rules {
            let _ = std::process::Command::new(rule.command)
                .args(with_action(&rule.args, "-D"))
                .status();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rules_and_sysctls_for_dual_stack() {
        let pools: Vec<IpNet> = vec![
            "10.100.0.0/24".parse().unwrap(),
            "fd00:6d61:7371::/64".parse().unwrap(),
        ];
        let rules = masquerade_rules(&pools, "eth0");
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].command, "iptables");
        assert_eq!(rules[1].command, "ip6tables");
        assert!(rules[0].args.contains(&"10.100.0.0/24".to_string()));
        assert!(rules[0].args.contains(&"eth0".to_string()));
        assert!(rules[0].args.contains(&"MASQUERADE".to_string()));

        let sysctls = forwarding_sysctls(&pools);
        assert_eq!(
            sysctls,
            vec!["net.ipv4.ip_forward=1", "net.ipv6.conf.all.forwarding=1"]
        );
    }

    #[test]
    fn action_flag_lands_before_chain() {
        let rules = masquerade_rules(&["10.0.0.0/8".parse().unwrap()], "en0");
        let add = with_action(&rules[0].args, "-A");
        assert_eq!(
            add.join(" "),
            "-t nat -A POSTROUTING -s 10.0.0.0/8 -o en0 -j MASQUERADE"
        );
    }
}
