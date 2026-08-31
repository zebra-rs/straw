//! Peer-to-peer direct path (design: `p2p-direct-path-design.md`).
//!
//! Two strawcat peers that would otherwise hairpin through a relay form a
//! direct, end-to-end-encrypted QUIC connection instead, keeping the relay as
//! rendezvous and fallback.
//!
//! The trust model:
//!
//! - [`identity`] — a peer's inner-TLS keypair and its SPKI pin (the
//!   WireGuard-pubkey analogue, RFC 7250 raw public keys).
//! - [`token`] — the `sc2_` capability a peer hands out so the holder can
//!   reach and verify it through the relay (design §3.2).
//! - [`inner_tls`] — the mutually pinned raw-public-key mTLS both ends use.
//!
//! The path, in the order it is built:
//!
//! - [`peer`] — opens a bind session at the relay and forms the inner
//!   connection over it ([`relay_socket`], which carries the relay path *and*
//!   a direct one on a single [`noq::AsyncUdpSocket`]).
//! - [`native_punch`] — upgrades to the direct path using noq's QUIC-layer
//!   NAT-traversal frames (design §0 Stage 3).
//! - [`session`] — the `Relay → Punching → Direct` state machine that promotes
//!   the direct path and falls back to the relay when it is lost.
//! - [`vpn`] — the optional IP-tunnel inner protocol (`strawcat --vpn`), h3 +
//!   CONNECT-IP over the peer connection via [`h3_noq`].
//!
//! [`candidates`], [`wire`], [`holepunch`] and [`punch`] are the **v1**
//! app-level punch, superseded by [`native_punch`] and kept only as the
//! reference for the symmetric-NAT strategies in [`strategy`], which have not
//! been ported to the frame-based exchange.
//!
//! Provisional codepoints live in `crate::codepoints`, so the standards swap
//! is a one-file edit (design §9).

pub mod candidates;
pub mod h3_noq;
pub mod holepunch;
pub mod identity;
pub mod inner_tls;
pub mod native_punch;
pub mod peer;
pub mod portmap;
pub mod punch;
pub mod relay_socket;
pub mod session;
pub mod strategy;
pub mod stun;
pub mod token;
pub mod vpn;
pub mod wire;
