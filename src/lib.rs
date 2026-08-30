//! straw — an RFC 9484 (CONNECT-IP) proxy server: IP over MASQUE.
//!
//! Protocol stack: IP packets → HTTP Datagrams (RFC 9297) → QUIC DATAGRAM
//! frames (RFC 9221) → HTTP/3 Extended CONNECT (RFC 9114 + RFC 9220) → QUIC.

pub mod address_pool;
pub mod capsule;
pub mod client;
pub mod config;
pub mod datagram;
pub mod error;
pub mod forwarding;
pub mod server;
pub mod session;
pub mod tls;
pub mod uri_template;

/// Install the ring crypto provider as the rustls process default.
///
/// Idempotent: safe to call from multiple binaries/tests.
pub fn init_crypto() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}
