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
}
