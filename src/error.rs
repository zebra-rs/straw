use std::net::IpAddr;

use thiserror::Error;

/// Errors during capsule/VarInt decoding.
#[derive(Debug, Error)]
pub enum DecodeError {
    #[error("unexpected end of buffer")]
    Underflow,

    #[error("invalid IP version: {0}")]
    InvalidIpVersion(u8),

    #[error("invalid prefix length {prefix_len} for IPv{ip_version}")]
    InvalidPrefixLength { ip_version: u8, prefix_len: u8 },

    #[error("invalid variable-length integer")]
    InvalidVarInt,

    #[error("buffer too short: need {needed} bytes, have {available}")]
    BufferTooShort { needed: usize, available: usize },

    #[error("unexpected trailing bytes: {0} bytes remaining")]
    TrailingBytes(usize),
}

/// Errors during IP packet forwarding.
#[derive(Debug, Error)]
pub enum ForwardingError {
    #[error("malformed IP packet")]
    MalformedPacket,

    #[error("source address {0} not assigned to session")]
    SourceAddressViolation(IpAddr),

    #[error("TTL/Hop Limit expired")]
    TtlExpired,

    #[error("link-local address dropped")]
    LinkLocalDrop,

    #[error("packet exceeds tunnel MTU")]
    MtuExceeded,

    #[error("no route to destination")]
    NoRoute,
}

/// Top-level proxy error.
#[derive(Debug, Error)]
pub enum ProxyError {
    #[error("decode error: {0}")]
    Decode(#[from] DecodeError),

    #[error("forwarding error: {0}")]
    Forwarding(#[from] ForwardingError),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("invalid CONNECT-IP request: {0}")]
    InvalidRequest(String),

    #[error("authentication failed: {0}")]
    AuthFailed(String),

    #[error("session not found: {0}")]
    SessionNotFound(u64),
}
