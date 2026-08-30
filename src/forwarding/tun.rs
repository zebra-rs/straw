//! Kernel TUN device I/O behind a pair of channels.
//!
//! The engine never touches the device directly: packets to the network go
//! into a `mpsc::Sender<Bytes>` and packets from the network come out of a
//! `mpsc::Receiver<Vec<u8>>`. Tests substitute plain channels for the device
//! (see `ForwardingEngine`), so everything above this module is portable.
//!
//! Linux-first (design §8.3); macOS utun support is planned later.

use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::Bytes;
use tokio::sync::mpsc;

use crate::error::ProxyError;

/// Configuration for the kernel TUN device.
#[derive(Debug, Clone)]
pub struct TunConfig {
    pub name: String,
    pub mtu: u16,
    /// Address + prefix length to configure on the device (the proxy-side
    /// gateway for the client pool), e.g. 10.100.0.1/24.
    pub ipv4: Option<(Ipv4Addr, u8)>,
    /// IPv6 gateway address + prefix length, e.g. fd00:6d61:7371::1/64.
    /// Applied with `ip(8)`: the `tun` crate configures IPv4 only, and
    /// without this the kernel has no route to the v6 pool, so assigned v6
    /// addresses are unreachable from the network.
    pub ipv6: Option<(Ipv6Addr, u8)>,
}

/// Channel endpoints connecting the forwarding engine to the TUN device.
pub struct TunChannels {
    /// Packets bound for the network (engine → device).
    pub to_net: mpsc::Sender<Bytes>,
    /// Packets arriving from the network (device → engine).
    pub from_net: mpsc::Receiver<Bytes>,
}

/// Depth of the device channels; beyond this, datagrams are dropped.
#[cfg(target_os = "linux")]
const CHANNEL_DEPTH: usize = 1024;

/// Largest single packet accepted from the device, independent of the
/// configured MTU so raising the device MTU at runtime cannot truncate.
#[cfg(target_os = "linux")]
const MAX_PACKET: usize = 65_536;

/// Read buffer size, independent of the configured MTU.
///
/// A buffer sized from `cfg.mtu` silently truncates once the device MTU is
/// raised at runtime (which `strawc` does as QUIC path-MTU discovery ramps),
/// and a truncated IP packet is indistinguishable from a malformed one
/// downstream. One 64 KiB buffer per device costs nothing next to that.
#[cfg(target_os = "linux")]
const READ_BUFFER: usize = 4 * MAX_PACKET;

/// Create the TUN device and spawn its read/write pump tasks.
#[cfg(target_os = "linux")]
pub fn spawn_tun(cfg: &TunConfig) -> Result<TunChannels, ProxyError> {
    use std::sync::Arc;

    let mut config = tun::Configuration::default();
    config.tun_name(&cfg.name).mtu(cfg.mtu).up();
    if let Some((addr, prefix)) = cfg.ipv4 {
        config.address(addr).netmask(prefix_to_netmask(prefix));
    }

    let device = Arc::new(
        tun::create_as_async(&config)
            .map_err(|e| ProxyError::Config(format!("failed to create TUN device: {e}")))?,
    );

    // IPv6 has to go on after creation, via ip(8).
    if let Some((addr, prefix)) = cfg.ipv6 {
        crate::iface::ip(&crate::iface::addr_args(
            "add",
            &cfg.name,
            std::net::IpAddr::V6(addr),
            prefix,
        ))?;
    }

    let (to_net_tx, mut to_net_rx) = mpsc::channel::<Bytes>(CHANNEL_DEPTH);
    let (from_net_tx, from_net_rx) = mpsc::channel::<Bytes>(CHANNEL_DEPTH);

    // Engine → network.
    let writer = device.clone();
    tokio::spawn(async move {
        while let Some(packet) = to_net_rx.recv().await {
            if let Err(e) = writer.send(&packet).await {
                tracing::warn!("TUN write failed: {e}");
                break;
            }
        }
    });

    // Network → engine.
    let reader = device;
    tokio::spawn(async move {
        // One large buffer, split per packet: `split_to(n).freeze()` hands
        // the packet out as `Bytes` without a copy, and a fresh chunk is
        // allocated only when the current one runs low — amortizing what
        // used to be a `to_vec()` allocation per packet (Step 32).
        use bytes::BytesMut;
        let mut buf = BytesMut::with_capacity(READ_BUFFER);
        loop {
            if buf.capacity() < MAX_PACKET {
                buf = BytesMut::with_capacity(READ_BUFFER);
            }
            buf.resize(MAX_PACKET, 0);
            match reader.recv(&mut buf).await {
                Ok(n) if n > 0 => {
                    // Datagram semantics: drop when the engine is congested.
                    let packet = buf.split_to(n).freeze();
                    buf.clear();
                    let _ = from_net_tx.try_send(packet);
                }
                Ok(_) => continue,
                Err(e) => {
                    tracing::warn!("TUN read failed: {e}");
                    break;
                }
            }
        }
    });

    Ok(TunChannels {
        to_net: to_net_tx,
        from_net: from_net_rx,
    })
}

#[cfg(target_os = "linux")]
fn prefix_to_netmask(prefix: u8) -> Ipv4Addr {
    let bits = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix.min(32) as u32)
    };
    Ipv4Addr::from(bits)
}

/// TUN devices are only supported on Linux so far (design §8.3).
#[cfg(not(target_os = "linux"))]
pub fn spawn_tun(_cfg: &TunConfig) -> Result<TunChannels, ProxyError> {
    Err(ProxyError::Config(
        "TUN device support is Linux-only for now; run without --tun \
         (client<->client hairpin forwarding still works)"
            .to_string(),
    ))
}
