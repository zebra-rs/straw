//! macOS TUN backend: utun, plain IP packets, no offload.
//!
//! Three things differ from Linux, and all three simplify the pump:
//!
//! - **No virtio-net header.** utun prefixes each packet with a 4-byte
//!   address family instead, and the `tun` crate adds and strips that itself,
//!   so this pump sees bare IP packets.
//! - **No TSO/GSO.** One read is one packet, so there is nothing to
//!   re-segment — `forwarding::vnet` is not involved at all.
//! - **The kernel names the device.** utun interfaces are `utun<N>` and
//!   nothing else, so a requested name that is not of that form is not
//!   honoured; the device reports back what it actually got.
//!
//! The cost of the simplicity is throughput: every packet is its own read
//! syscall, where Linux amortises a 64 KB aggregate across one.

use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use tokio::sync::mpsc;
use tun::AbstractDevice;

use super::{CHANNEL_DEPTH, MAX_PACKET, READ_BUFFER, TunChannels, TunConfig, prefix_to_netmask};
use crate::error::ProxyError;

/// Create the utun device and spawn its read/write pump tasks.
///
/// `ingress` is called inline from the read pump for every packet arriving
/// from the network. It must not block.
pub fn spawn_tun(
    cfg: &TunConfig,
    ingress: impl Fn(Bytes) + Send + 'static,
) -> Result<TunChannels, ProxyError> {
    if cfg.ipv6.is_some() {
        // The address would have to go on with ifconfig(8) after creation,
        // which is the iface(4) work, not this. Refuse rather than bring the
        // device up silently missing its IPv6 address.
        return Err(ProxyError::Config(
            "IPv6 on the TUN device is not supported on macOS yet".to_string(),
        ));
    }

    let mut config = tun::Configuration::default();
    config.mtu(cfg.mtu).up();
    // Only `utun<N>` is a legal utun name. Asking for anything else is not an
    // error the user can act on — `strawc0` is simply not expressible here —
    // so let the kernel pick the next free unit and report which one.
    if is_utun_name(&cfg.name) {
        config.tun_name(&cfg.name);
    }
    if let Some((addr, prefix)) = cfg.ipv4 {
        // utun is point-to-point: macOS wants a destination as well as a
        // local address. straw's model has no separate peer address — the
        // far side is the tunnel, not a neighbour — so the device points at
        // itself, which is the idiom other utun VPN clients use.
        config
            .address(addr)
            .destination(addr)
            .netmask(prefix_to_netmask(prefix));
    }

    let device = Arc::new(
        tun::create_as_async(&config)
            .map_err(|e| ProxyError::Config(format!("failed to create utun device: {e}")))?,
    );
    let name = device
        .tun_name()
        .map_err(|e| ProxyError::Config(format!("utun device has no name: {e}")))?;
    if name != cfg.name {
        tracing::info!(
            requested = %cfg.name,
            actual = %name,
            "macOS names utun devices itself; using the assigned name"
        );
    }

    let (to_net_tx, mut to_net_rx) = mpsc::channel::<Bytes>(CHANNEL_DEPTH);

    // Engine → network. No framing: the crate prepends the address family.
    let writer = device.clone();
    tokio::spawn(async move {
        while let Some(packet) = to_net_rx.recv().await {
            if let Err(e) = writer.send(&packet).await {
                tracing::warn!("utun write failed: {e}");
                break;
            }
        }
    });

    // Network → engine, one packet per read.
    let reader = device;
    tokio::spawn(async move {
        // Sized independently of the device MTU, as on Linux: `strawc` raises
        // the MTU at runtime, and the crate reads at most what this buffer
        // holds, so a buffer sized from the MTU at startup would truncate
        // every packet the widened device later carries.
        let mut buf = BytesMut::with_capacity(READ_BUFFER);
        loop {
            if buf.capacity() < MAX_PACKET {
                buf = BytesMut::with_capacity(READ_BUFFER);
            }
            buf.resize(MAX_PACKET, 0);
            match reader.recv(&mut buf).await {
                Ok(0) => continue,
                Ok(n) => {
                    let packet = buf.split_to(n);
                    buf.clear();
                    ingress(packet.freeze());
                }
                Err(e) => {
                    tracing::warn!("utun read failed: {e}");
                    break;
                }
            }
        }
    });

    Ok(TunChannels {
        to_net: to_net_tx,
        name,
    })
}

/// Whether `name` is a utun name the kernel will accept: `utun` followed by a
/// unit number and nothing else.
fn is_utun_name(name: &str) -> bool {
    name.strip_prefix("utun")
        .is_some_and(|unit| !unit.is_empty() && unit.chars().all(|c| c.is_ascii_digit()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_utun_names_are_honoured() {
        assert!(is_utun_name("utun0"));
        assert!(is_utun_name("utun12"));
        // The defaults straw ships are not expressible as utun names, which is
        // why the kernel gets to choose instead of this failing.
        assert!(!is_utun_name("straw0"));
        assert!(!is_utun_name("strawc0"));
        // Near misses that would otherwise be passed through and rejected by
        // the crate's own parse.
        assert!(!is_utun_name("utun"));
        assert!(!is_utun_name("utunX"));
        assert!(!is_utun_name("utun1x"));
        assert!(!is_utun_name("Xutun0"));
    }
}
