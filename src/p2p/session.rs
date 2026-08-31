//! Path management: the RELAY → PUNCHING → DIRECT state machine (design §6).
//!
//! A [`Session`] wraps the inner relay connection (Phase B, never closed) and,
//! once hole punching succeeds, a direct connection. It presents the current
//! best path to the application, keeps trying to reach DIRECT, and falls back
//! to the relay if the direct path dies — transparently, so a caller opening
//! streams on [`Session::connection`] always gets a working path.
//!
//! ```text
//!  RELAY ──punch──► PUNCHING ──validated──► DIRECT
//!    ▲                  │                      │
//!    │  punch failed    │                      │ direct path lost
//!    └──────────────────┘                      │
//!    ▲                                          │
//!    └──────────────────────────────────────────┘   (relay never closed)
//! ```
//!
//! **noq migration, Stage 1.** The inner connection is now [`noq`]. The direct
//! path is being rebuilt on noq's *native* multipath (`Connection::open_path`
//! + NAT-traversal rounds) rather than the previous app-level second QUIC
//! connection raced over the outer socket. Until that lands (Stage 3), a
//! session stays on the relay path; the punch inputs are accepted but parked.
//! The old quinn punch modules (`holepunch`, `punch`) remain in the tree as
//! the reference for that rebuild.

use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Duration;

use tokio::sync::watch;

use std::sync::Arc as StdArc;

use crate::p2p::identity::{Identity, SpkiPin};
use crate::p2p::peer::RelayAccess;
use crate::p2p::strategy::PunchStrategy;

/// Which path a session is currently using.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathState {
    /// Only the relay path (initial, and after a direct path is lost).
    Relay,
    /// Attempting to hole-punch a direct path.
    Punching,
    /// A direct path is up; new streams use it.
    Direct,
}

/// Strategy selection and the extra inputs some strategies need. Bundled so
/// `Session::start` stays readable; `Default` is the plain `basic` punch.
#[derive(Default, Clone)]
pub struct PunchConfig {
    pub strategy: PunchStrategy,
    /// How to reach the relay to open auxiliary bind sessions (predict/birthday).
    pub relay_access: Option<StdArc<RelayAccess>>,
    /// Peer-facing sources the on-path relay signalled (relay-assisted); a
    /// shared list a pump task fills and the punch reads.
    pub peer_reflexive: Option<StdArc<Mutex<Vec<SocketAddr>>>>,
    /// Ask the router (PCP / NAT-PMP) to forward the punch socket, advertising
    /// the mapped address as a candidate (design §11 / P3).
    pub port_map: bool,
}

/// A peer session that manages the relay↔direct path transition.
pub struct Session {
    relay: noq::Connection,
    state_rx: watch::Receiver<PathState>,
    _manager: tokio::task::JoinHandle<()>,
}

impl Session {
    /// Start managing paths for a peer pair. `inner` is the established relay
    /// connection. In Stage 1 the session holds the relay path; native
    /// multipath (Stage 3) will drive the relay→direct upgrade in-protocol.
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        inner: noq::Connection,
        _initiator: bool,
        _identity: StdArc<Identity>,
        _peer_pin: Option<SpkiPin>,
        _punch_endpoint: quinn::Endpoint,
        _reflexive: Option<SocketAddr>,
        _relay_paddr: SocketAddr,
        _cfg: PunchConfig,
    ) -> Self {
        let (state_tx, state_rx) = watch::channel(PathState::Relay);
        let manager = tokio::spawn(manage(inner.clone(), state_tx));
        Self {
            relay: inner,
            state_rx,
            _manager: manager,
        }
    }

    /// The current best path. New streams should be opened on it.
    pub fn connection(&self) -> noq::Connection {
        self.relay.clone()
    }

    /// The current path state.
    pub fn state(&self) -> PathState {
        *self.state_rx.borrow()
    }

    /// The state channel, to observe transitions.
    pub fn state_changes(&self) -> watch::Receiver<PathState> {
        self.state_rx.clone()
    }

    /// Wait until the direct path is up, or `timeout` elapses (returns
    /// whether DIRECT was reached).
    pub async fn await_direct(&self, timeout: Duration) -> bool {
        let mut rx = self.state_rx.clone();
        let wait = async {
            loop {
                if *rx.borrow() == PathState::Direct {
                    return;
                }
                if rx.changed().await.is_err() {
                    return;
                }
            }
        };
        tokio::time::timeout(timeout, wait).await.is_ok() && self.state() == PathState::Direct
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self._manager.abort();
    }
}

/// The manager loop. In Stage 1 it simply holds the state channel alive for
/// the life of the relay connection; Stage 3 restores the punch/promote loop
/// on top of noq native multipath.
async fn manage(inner: noq::Connection, state: watch::Sender<PathState>) {
    let _ = inner.closed().await;
    let _ = state.send(PathState::Relay);
}
