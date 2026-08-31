//! Hole-punch strategy selection (design §5.3, §12).
//!
//! The basic punch reuses the outer bind socket and advertises the
//! relay-observed reflexive, which traverses endpoint-independent (cone) NATs.
//! Symmetric NATs map that one socket to a different external port per
//! destination, so the advertised reflexive is wrong and the punch is blocked.
//! These strategies each attack that differently; the caller picks one.

use std::fmt;
use std::str::FromStr;

/// How a peer attempts to hole-punch past its NAT.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PunchStrategy {
    /// Reuse the outer socket, advertise the relay-observed reflexive. Works on
    /// endpoint-independent (cone) NATs; the relay carries symmetric ones.
    #[default]
    Basic,
    /// Probe a second relay address to classify the NAT's mapping behaviour and,
    /// for a sequential-allocating symmetric NAT, predict and scan the
    /// peer-facing port. Random-allocating NATs fall back fast.
    Predict,
    /// Open several punch sockets, learn each one's reflexive, and punch the
    /// cross-product — the birthday-paradox attack on a random symmetric NAT.
    Birthday,
    /// Let the on-path relay observe each peer's actual peer-facing source (the
    /// mapping the far NAT created toward the other peer) and signal it, so both
    /// sides dial the real address. Traverses symmetric NATs when the relay
    /// routes between the peers.
    RelayAssisted,
}

impl PunchStrategy {
    /// Lower-case kebab name, the CLI/token spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            PunchStrategy::Basic => "basic",
            PunchStrategy::Predict => "predict",
            PunchStrategy::Birthday => "birthday",
            PunchStrategy::RelayAssisted => "relay-assisted",
        }
    }
}

impl fmt::Display for PunchStrategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for PunchStrategy {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "basic" => Ok(PunchStrategy::Basic),
            "predict" => Ok(PunchStrategy::Predict),
            "birthday" => Ok(PunchStrategy::Birthday),
            "relay-assisted" | "relay_assisted" | "relayassisted" => {
                Ok(PunchStrategy::RelayAssisted)
            }
            other => Err(format!(
                "unknown punch strategy {other:?} (basic|predict|birthday|relay-assisted)"
            )),
        }
    }
}

/// Which candidate kinds a peer offers the other (design §5.1, §10.3).
///
/// Host candidates are the local interface addresses. They are what lets two
/// peers on the same LAN — or behind the same NAT, where hairpinning often
/// fails — reach each other without leaving the network. They also disclose
/// the LAN topology to the peer, which is why they are opt-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DirectMode {
    /// Offer the reflexive (and any port-mapped) candidate only. The peer
    /// learns the public address it would reach anyway.
    #[default]
    Reflexive,
    /// Also offer the local interface address, so same-LAN peers connect
    /// locally. Discloses a private address to the (already authenticated,
    /// SPKI-pinned) peer.
    Full,
    /// Offer nothing and never punch: pin the session to the relay path.
    Off,
}

impl DirectMode {
    /// Lower-case name, the CLI spelling.
    pub fn as_str(self) -> &'static str {
        match self {
            DirectMode::Reflexive => "reflexive",
            DirectMode::Full => "full",
            DirectMode::Off => "off",
        }
    }

    /// Whether a host candidate should be gathered and advertised.
    pub fn offers_host(self) -> bool {
        matches!(self, DirectMode::Full)
    }

    /// Whether to attempt a direct path at all.
    pub fn punches(self) -> bool {
        !matches!(self, DirectMode::Off)
    }
}

impl fmt::Display for DirectMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for DirectMode {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "reflexive" => Ok(DirectMode::Reflexive),
            "full" => Ok(DirectMode::Full),
            "off" | "none" | "relay" => Ok(DirectMode::Off),
            other => Err(format!(
                "unknown direct mode {other:?} (reflexive|full|off)"
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_renders_every_variant() {
        for s in [
            PunchStrategy::Basic,
            PunchStrategy::Predict,
            PunchStrategy::Birthday,
            PunchStrategy::RelayAssisted,
        ] {
            assert_eq!(s.as_str().parse::<PunchStrategy>().unwrap(), s);
        }
        assert_eq!(
            "relay_assisted".parse::<PunchStrategy>().unwrap(),
            PunchStrategy::RelayAssisted
        );
        assert!("bogus".parse::<PunchStrategy>().is_err());
        assert_eq!(PunchStrategy::default(), PunchStrategy::Basic);
    }

    #[test]
    fn direct_mode_parses_and_gates_the_right_things() {
        for m in [DirectMode::Reflexive, DirectMode::Full, DirectMode::Off] {
            assert_eq!(m.as_str().parse::<DirectMode>().unwrap(), m);
        }
        // "relay" is the intuitive spelling of pinning to the relay path.
        assert_eq!("relay".parse::<DirectMode>().unwrap(), DirectMode::Off);
        assert!("bogus".parse::<DirectMode>().is_err());

        // Only `full` discloses a LAN address; only `off` skips the punch.
        assert_eq!(DirectMode::default(), DirectMode::Reflexive);
        assert!(!DirectMode::Reflexive.offers_host());
        assert!(DirectMode::Full.offers_host());
        assert!(!DirectMode::Off.offers_host());
        assert!(DirectMode::Reflexive.punches());
        assert!(DirectMode::Full.punches());
        assert!(!DirectMode::Off.punches());
    }
}
