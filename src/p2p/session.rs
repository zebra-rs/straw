//! Path management: the RELAY → PUNCHING → DIRECT state machine (design §6).
//!
//! A [`Session`] wraps the inner peer connection and drives it from the relay
//! path onto a direct one, keeping the relay as a permanent fallback (design
//! G3). It presents the connection to the application, which never has to know
//! which path is carrying its bytes.
//!
//! ```text
//!  RELAY ──punch──► PUNCHING ──validated──► DIRECT
//!    ▲                  │                      │
//!    │  punch failed    │                      │ direct path lost
//!    └──────────────────┘◄─────────────────────┘
//!            (the relay path is never closed)
//! ```
//!
//! **Stage 3 (noq native multipath).** Relay and direct are two paths of *one*
//! noq connection over the combined-transport socket, not two connections
//! raced at the application level. So a transition is a status change rather
//! than a switchover: a NAT-traversal-validated path arrives as
//! [`PathStatus::Backup`], and this state machine promotes it to `Available`
//! while demoting the relay path — after which noq schedules data on the
//! direct path and holds the relay one idle. Nothing above the connection
//! moves; open streams keep working across the transition.
//!
//! Losing the direct path is symmetric: noq reports `PathEvent::Abandoned`,
//! the relay path goes back to `Available`, and the punch is retried.

use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Duration;

use futures::StreamExt;
use noq::{PathEvent, PathId, PathStatus};
use tokio::sync::watch;

use std::sync::Arc as StdArc;

use crate::p2p::native_punch;
use crate::p2p::peer::RelayAccess;
use crate::p2p::relay_socket::PathMuxHandle;
use crate::p2p::strategy::{DirectMode, PunchStrategy};
use crate::p2p::stun::NatMapping;

/// How long one punch attempt may run before falling back to the relay.
const PUNCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Wait between punch attempts. A NAT binding that was not open on the first
/// try may be later (the peer's own traffic opens it), so retrying is worth
/// the few packets it costs — but not at a rate that looks like a scan.
const RETRY_INTERVAL: Duration = Duration::from_secs(30);

/// How long a `--port-map` forward is requested for, and thus how long a mapped
/// candidate stays valid without renewal.
const PORTMAP_LIFETIME: Duration = Duration::from_secs(3600);

/// Which path a session is currently using.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathState {
    /// Only the relay path (initial, and after a direct path is lost).
    Relay,
    /// Attempting to hole-punch a direct path.
    Punching,
    /// A direct path is up; it carries the data.
    Direct,
}

/// Strategy selection and the extra inputs some strategies need. Bundled so
/// `Session::start` stays readable; `Default` is the plain `basic` punch.
#[derive(Default, Clone)]
pub struct PunchConfig {
    pub strategy: PunchStrategy,
    /// How to reach the relay to open auxiliary bind sessions (predict/birthday).
    pub relay_access: Option<StdArc<RelayAccess>>,
    /// Ask the router (PCP / NAT-PMP) to forward the direct socket, advertising
    /// the mapped address as a candidate (design §11 / P3).
    pub port_map: bool,
    /// Which candidate kinds to offer, and whether to punch at all (§10.3).
    pub direct: DirectMode,
    /// The NAT's mapping behaviour if `--stun-detect` measured it beforehand
    /// (RFC 5780). A verdict that no configured mechanism can traverse lets the
    /// session skip a punch it already knows will fail.
    pub nat_mapping: Option<NatMapping>,
}

/// Whether a measured NAT verdict rules out every mechanism this session has.
///
/// A symmetric mapping defeats the *reflexive* candidate, because the port the
/// relay observed is not the port the peer will see. It does not defeat
/// everything, so this only reports futility when nothing else is in play:
///
/// - `--port-map` installs an explicit forward, which holds whatever the
///   mapping behaviour is;
/// - `--punch-strategy predict` targets sequential-symmetric NATs specifically;
/// - `--direct=full` offers a host candidate, and a peer on the same LAN is
///   reachable without traversing the NAT at all.
///
/// Returns false when no measurement was taken — never skip on a guess.
fn punch_is_futile(cfg: &PunchConfig) -> bool {
    let Some(mapping) = cfg.nat_mapping else {
        return false;
    };
    !mapping.is_punchable()
        && !cfg.port_map
        && cfg.strategy != PunchStrategy::Predict
        && !cfg.direct.offers_host()
}

/// What the punch driver needs about this peer's own addresses.
pub struct PunchInputs {
    /// The combined-transport socket's handle — the direct socket's port is
    /// half of this peer's reflexive candidate.
    pub mux: PathMuxHandle,
    /// The relay's view of this peer's outer source (design §5.1). Its *IP* is
    /// this peer's public IP; the port belongs to the outer bind socket, so
    /// only the IP is reused.
    pub reflexive: Option<SocketAddr>,
    /// The relay's address. Not a candidate — it is the destination whose route
    /// lookup reveals which local interface faces the peer, for the host
    /// candidate under `--direct=full`.
    pub relay_addr: SocketAddr,
}

/// A peer session that manages the relay↔direct path transition.
pub struct Session {
    conn: noq::Connection,
    state_rx: watch::Receiver<PathState>,
    direct: StdArc<Mutex<Option<PathId>>>,
    manager: tokio::task::JoinHandle<()>,
}

impl Session {
    /// Start managing paths for a peer pair. `inner` is the established
    /// connection, on its relay path; `client` marks the inner-QUIC client (the
    /// token holder), which is the side that initiates traversal rounds.
    pub fn start(
        inner: noq::Connection,
        client: bool,
        inputs: PunchInputs,
        cfg: PunchConfig,
    ) -> Self {
        let (state_tx, state_rx) = watch::channel(PathState::Relay);
        let direct = StdArc::new(Mutex::new(None));
        let manager = tokio::spawn(manage(
            inner.clone(),
            client,
            inputs,
            cfg,
            state_tx,
            direct.clone(),
        ));
        Self {
            conn: inner,
            state_rx,
            direct,
            manager,
        }
    }

    /// The promoted direct path, once there is one — for callers that want to
    /// inspect it (`Connection::path_stats`, `rtt`) or close it.
    pub fn direct_path(&self) -> Option<PathId> {
        *self.direct.lock().unwrap()
    }

    /// The peer address the direct path reaches, once there is one. It is the
    /// peer's *own* address — proof the data no longer goes through the relay.
    pub fn direct_remote(&self) -> Option<SocketAddr> {
        self.conn.path(self.direct_path()?)?.remote_address().ok()
    }

    /// The peer connection. It is the same connection whichever path is in use
    /// — the caller opens streams on it and never re-opens them.
    pub fn connection(&self) -> noq::Connection {
        self.conn.clone()
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
        self.manager.abort();
    }
}

/// The manager loop: punch, promote, watch, fall back, repeat.
async fn manage(
    conn: noq::Connection,
    client: bool,
    inputs: PunchInputs,
    cfg: PunchConfig,
    state: watch::Sender<PathState>,
    direct_path: StdArc<Mutex<Option<PathId>>>,
) {
    if !conn.is_multipath_enabled() {
        // Without multipath there is no second path to promote. Not fatal —
        // the relay path carries everything, as it did before Stage 3.
        tracing::warn!("peer did not negotiate multipath; staying on the relay path");
        let _ = conn.closed().await;
        return;
    }
    if !cfg.direct.punches() {
        tracing::info!("--direct=off: pinned to the relay path, not punching");
        let _ = conn.closed().await;
        return;
    }
    if punch_is_futile(&cfg) {
        // Measured, not assumed: --stun-detect classified this NAT and nothing
        // configured can traverse it. Probing anyway would spend the punch
        // window and a few dozen packets to learn what is already known.
        tracing::info!(
            mapping = cfg.nat_mapping.map(|m| m.as_str()),
            "NAT mapping defeats the reflexive candidate and no other mechanism \
             is enabled; staying on the relay (try --port-map, --punch-strategy \
             predict, or --direct=full)"
        );
        let _ = conn.closed().await;
        return;
    }
    warn_unsupported_strategy(cfg.strategy);

    let mapped = if cfg.port_map {
        request_port_map(inputs.mux.direct_local().port()).await
    } else {
        None
    };
    let sources = native_punch::Sources {
        reflexive_ip: inputs.reflexive.map(|r| r.ip()),
        mapped: mapped.map(|m| m.external),
        // Costs a route lookup, so only when the mode asks for it.
        host_ip: cfg
            .direct
            .offers_host()
            .then(|| native_punch::host_ip(inputs.relay_addr))
            .flatten(),
    };
    let mut local = native_punch::candidates(&inputs.mux, sources);
    local.extend(predicted_candidates(&cfg).await);
    local.truncate(crate::p2p::peer::MAX_NAT_ADDRESSES as usize);
    if local.is_empty() {
        tracing::info!("no direct-path candidate for this peer; staying on the relay path");
        let _ = conn.closed().await;
        return;
    }
    tracing::debug!(?local, "advertising direct-path candidates");
    if let Err(e) = native_punch::advertise(&conn, &local) {
        tracing::warn!("could not advertise candidates: {e}");
        let _ = conn.closed().await;
        return;
    }

    loop {
        let _ = state.send(PathState::Punching);
        match native_punch::punch(&conn, client, PUNCH_TIMEOUT).await {
            Ok(direct) => {
                promote(&conn, direct);
                *direct_path.lock().unwrap() = Some(direct);
                let _ = state.send(PathState::Direct);
                await_path_lost(&conn, direct).await;
                tracing::info!(?direct, "direct path lost; falling back to the relay");
                *direct_path.lock().unwrap() = None;
                demote(&conn, direct);
            }
            Err(e) => tracing::debug!("no direct path: {e}"),
        }
        let _ = state.send(PathState::Relay);
        // A closed connection ends the session; otherwise back off and retry.
        tokio::select! {
            _ = conn.closed() => return,
            _ = tokio::time::sleep(RETRY_INTERVAL) => {}
        }
    }
}

/// Make `direct` the path data is scheduled on, and hold the relay path as the
/// backup it now is. Both calls are best-effort: a path that closed between the
/// event and here just means the next loop iteration re-punches.
fn promote(conn: &noq::Connection, direct: PathId) {
    set_status(conn, direct, PathStatus::Available);
    set_status(conn, PathId::ZERO, PathStatus::Backup);
}

/// Restore the relay path as the data path after the direct one is gone.
fn demote(conn: &noq::Connection, direct: PathId) {
    set_status(conn, PathId::ZERO, PathStatus::Available);
    set_status(conn, direct, PathStatus::Backup);
}

fn set_status(conn: &noq::Connection, id: PathId, status: PathStatus) {
    let Some(path) = conn.path(id) else {
        tracing::debug!(?id, "path gone before its status could be set");
        return;
    };
    if let Err(e) = path.set_status(status) {
        tracing::debug!(?id, ?status, "could not set path status: {e}");
    }
}

/// Resolve when `direct` is no longer usable — noq abandoned it (idle timeout,
/// validation failure, the NAT binding lapsing) — or the connection closed.
async fn await_path_lost(conn: &noq::Connection, direct: PathId) {
    let mut events = conn.path_events();
    let abandoned = async {
        while let Some(ev) = events.next().await {
            match ev {
                Ok(PathEvent::Abandoned { id, reason, .. }) if id == direct => {
                    tracing::debug!(?id, ?reason, "direct path abandoned");
                    return;
                }
                // Lagging means an Abandoned may have been dropped; ask the
                // connection directly rather than waiting for an event that
                // has already been and gone.
                Err(_) if conn.path(direct).is_none() => return,
                _ => {}
            }
        }
    };
    tokio::select! {
        _ = abandoned => {}
        _ = conn.closed() => {}
    }
}

/// Ask the router to forward the direct socket (design §11 / P3). A failure is
/// not fatal: the reflexive candidate alone still punches a cone NAT.
async fn request_port_map(port: u16) -> Option<crate::p2p::portmap::Mapping> {
    match crate::p2p::portmap::map_udp(port, PORTMAP_LIFETIME).await {
        Ok(m) => {
            tracing::info!(external = %m.external, "router mapped the direct socket");
            Some(m)
        }
        Err(e) => {
            tracing::warn!("port mapping failed: {e}");
            None
        }
    }
}

/// `predict` samples this peer's NAT and, for a sequential allocator, offers
/// the port it will use toward the peer. It ports to native traversal because
/// a prediction is a claim about *this peer's own* address, which is what the
/// frames carry. Best-effort: a random allocator offers nothing.
async fn predicted_candidates(cfg: &PunchConfig) -> Vec<SocketAddr> {
    if cfg.strategy != PunchStrategy::Predict {
        return Vec::new();
    }
    let Some(relay) = &cfg.relay_access else {
        tracing::warn!("--punch-strategy predict needs relay access to sample the NAT");
        return Vec::new();
    };
    crate::p2p::predict::predicted_candidates(relay).await
}

/// The other two symmetric-NAT strategies do *not* port to native traversal,
/// because the frame exchange carries only a peer's own addresses: `birthday`
/// needs several sockets to punch from, and `relay-assisted` needs the relay to
/// observe the probes, which now go out the direct socket and never reach it.
/// Say so rather than silently doing something else.
fn warn_unsupported_strategy(strategy: PunchStrategy) {
    if matches!(
        strategy,
        PunchStrategy::Birthday | PunchStrategy::RelayAssisted
    ) {
        tracing::warn!(
            ?strategy,
            "strategy does not port to native NAT traversal; using the basic punch \
             (use --port-map, or --punch-strategy predict for a sequential NAT)"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn symmetric() -> PunchConfig {
        PunchConfig {
            nat_mapping: Some(NatMapping::AddressAndPortDependent),
            ..Default::default()
        }
    }

    #[test]
    fn an_unmeasured_nat_is_never_assumed_futile() {
        // No --stun-detect: punch and find out. Skipping on a guess would turn
        // a working direct path into a permanent relay session.
        assert!(!punch_is_futile(&PunchConfig::default()));
    }

    #[test]
    fn a_punchable_nat_is_never_futile() {
        for mapping in [NatMapping::Open, NatMapping::EndpointIndependent] {
            let cfg = PunchConfig {
                nat_mapping: Some(mapping),
                ..Default::default()
            };
            assert!(!punch_is_futile(&cfg), "{mapping:?} is punchable");
        }
    }

    #[test]
    fn a_symmetric_nat_is_futile_only_when_nothing_else_can_help() {
        // Bare symmetric: the reflexive candidate is wrong and nothing else is
        // enabled, so probing would only burn the punch window.
        assert!(punch_is_futile(&symmetric()));

        // Each of these targets the symmetric case in its own way, so the
        // verdict no longer rules the punch out.
        assert!(!punch_is_futile(&PunchConfig {
            port_map: true,
            ..symmetric()
        }));
        assert!(!punch_is_futile(&PunchConfig {
            strategy: PunchStrategy::Predict,
            ..symmetric()
        }));
        assert!(!punch_is_futile(&PunchConfig {
            direct: DirectMode::Full,
            ..symmetric()
        }));
    }

    #[test]
    fn address_dependent_filtering_still_counts_as_unpunchable_mapping() {
        // RFC 5780 separates mapping from filtering; is_punchable() reports on
        // the mapping, and anything past endpoint-independent breaks the
        // reflexive candidate.
        let cfg = PunchConfig {
            nat_mapping: Some(NatMapping::AddressDependent),
            ..Default::default()
        };
        assert!(punch_is_futile(&cfg));
    }
}
