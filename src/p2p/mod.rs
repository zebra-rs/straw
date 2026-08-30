//! Peer-to-peer direct path (design: `p2p-direct-path-design.md`).
//!
//! Two strawcat peers that today hairpin through a relay upgrade to a
//! direct, end-to-end-encrypted QUIC connection, keeping the relay as
//! rendezvous and fallback. This is P1's foundation: the trust model.
//!
//! - [`identity`] — a peer's inner-TLS keypair and its SPKI pin (the
//!   WireGuard-pubkey analogue, RFC 7250 raw public keys).
//! - [`token`] — the `sc2_` capability a peer hands out so the holder can
//!   reach and verify it through the relay (design §3.2).
//!
//! Everything provisional (codepoints, v1 CBOR control messages) will live
//! behind `p2p::wire`; the rendezvous, hole-punching and path-management
//! layers (design §3–6) build on the two modules here.

pub mod candidates;
pub mod identity;
pub mod inner_tls;
pub mod peer;
pub mod relay_socket;
pub mod token;
pub mod wire;
