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

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::watch;

use std::sync::Arc as StdArc;

use crate::error::ProxyError;
use crate::p2p::holepunch::{self, Direct};
use crate::p2p::identity::{Identity, SpkiPin};

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

/// Backoff before re-punching after a failed attempt or a lost direct path,
/// while the session is still wanted (design §5.3, "retry … only while
/// traffic is flowing").
const REPUNCH_BACKOFF: Duration = Duration::from_secs(30);

/// The inputs the manager needs to punch, held for the session's life.
struct PunchParams {
    initiator: bool,
    identity: StdArc<Identity>,
    peer_pin: Option<SpkiPin>,
    bind_addr: SocketAddr,
    reflexive: Option<SocketAddr>,
    relay_paddr: SocketAddr,
}

/// A peer session that manages the relay↔direct path transition.
pub struct Session {
    relay: quinn::Connection,
    /// The current direct connection, when DIRECT.
    direct: Arc<Mutex<Option<Direct>>>,
    state_rx: watch::Receiver<PathState>,
    _manager: tokio::task::JoinHandle<()>,
}

impl Session {
    /// Start managing paths for a peer pair. `inner` is the established relay
    /// connection; the manager immediately tries to punch a direct path and
    /// maintains it, falling back to the relay on loss.
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        inner: quinn::Connection,
        initiator: bool,
        identity: StdArc<Identity>,
        peer_pin: Option<SpkiPin>,
        bind_addr: SocketAddr,
        reflexive: Option<SocketAddr>,
        relay_paddr: SocketAddr,
    ) -> Self {
        let (state_tx, state_rx) = watch::channel(PathState::Relay);
        let direct: Arc<Mutex<Option<Direct>>> = Arc::new(Mutex::new(None));
        let params = PunchParams {
            initiator,
            identity,
            peer_pin,
            bind_addr,
            reflexive,
            relay_paddr,
        };
        let manager = tokio::spawn(manage(inner.clone(), params, direct.clone(), state_tx));
        Self {
            relay: inner,
            direct,
            state_rx,
            _manager: manager,
        }
    }

    /// The current best path: the direct connection when DIRECT, else the
    /// relay. New streams should be opened on the returned connection.
    pub fn connection(&self) -> quinn::Connection {
        if let Some(d) = self.direct.lock().unwrap().as_ref() {
            return d.conn.clone();
        }
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
    /// whether DIRECT was reached). Useful for callers that prefer to send
    /// the first bytes over the direct path when it comes up quickly.
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

/// The manager loop: punch, promote to DIRECT, watch for loss, fall back and
/// re-punch. Ends when the relay connection closes (the session is over).
async fn manage(
    inner: quinn::Connection,
    params: PunchParams,
    direct: Arc<Mutex<Option<Direct>>>,
    state: watch::Sender<PathState>,
) {
    loop {
        // Give up managing once the relay path itself is gone.
        if inner.close_reason().is_some() {
            return;
        }

        let _ = state.send(PathState::Punching);
        match holepunch::coordinate(
            &inner,
            params.initiator,
            &params.identity,
            params.peer_pin,
            params.bind_addr,
            params.reflexive,
            params.relay_paddr,
        )
        .await
        {
            Ok(d) => {
                let conn = d.conn.clone();
                *direct.lock().unwrap() = Some(d);
                let _ = state.send(PathState::Direct);
                tracing::info!(remote = %conn.remote_address(), "path upgraded to direct");

                // Hold DIRECT until the connection closes (PTO storm / lost
                // keepalive surface as a connection error here).
                let _ = conn.closed().await;
                *direct.lock().unwrap() = None;
                let _ = state.send(PathState::Relay);
                tracing::info!("direct path lost; back on the relay");
            }
            Err(e) => {
                let _ = state.send(PathState::Relay);
                tracing::debug!("hole punch failed, staying on relay: {e}");
            }
        }

        // Back off before the next attempt, but abandon if the relay closes.
        tokio::select! {
            _ = tokio::time::sleep(REPUNCH_BACKOFF) => {}
            _ = inner.closed() => return,
        }
    }
}
