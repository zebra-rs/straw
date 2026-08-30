//! Relay-side CONNECT-UDP bind support (design §7): the untrusted UDP
//! forwarder half of the P2P direct path.
//!
//! A peer opens an Extended CONNECT with `:protocol = connect-udp` and
//! `connect-udp-bind: ?1`; the relay allocates a public (IP, port), binds a
//! UDP socket to it, and forwards packets both ways — inner-QUIC ciphertext
//! it cannot read (design §4). This is the TURN-equivalent from
//! draft-ietf-masque-connect-udp-listen.
//!
//! This increment lands the two pure, self-contained pieces the rest builds
//! on:
//! - [`context`] — the COMPRESSION_ASSIGN/ACK/CLOSE capsule codec and the
//!   per-session context table (§3.1); also the uncompressed/compressed
//!   HTTP Datagram payload codec that carries remote addresses.
//! - [`alloc`] — public (IP, port) allocation from a configured pool (§7.1).
//!
//! The per-session bound socket and its encap/decap rewrite loop
//! (`socket.rs`), the connect-udp request handler, and the abuse caps (§7.4,
//! §10) build on these next.
//!
//! Provisional codepoints (design §9) are pinned here and in [`context`] so
//! the eventual swap to the finalized listen-draft numbers is one place.

pub mod alloc;
pub mod context;
pub mod socket;
