//! Fallback for platforms with no TUN backend yet.

use bytes::Bytes;

use super::{TunChannels, TunConfig};
use crate::error::ProxyError;

pub fn spawn_tun(
    _cfg: &TunConfig,
    _ingress: impl Fn(Bytes) + Send + 'static,
) -> Result<TunChannels, ProxyError> {
    Err(ProxyError::Config(
        "TUN devices are supported on Linux and macOS only; run without --tun \
         (client<->client hairpin forwarding still works)"
            .to_string(),
    ))
}
