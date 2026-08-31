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
// GSO re-segmentation is a Linux concern: it is IFF_VNET_HDR that puts a
// virtio-net header on every read. macOS utun has no such header (and no TSO),
// so its pump reads plain IP packets and never needs these.
#[cfg(target_os = "linux")]
use crate::forwarding::vnet::{self, VNET_HDR_LEN, VnetHdr};

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

/// Handle for sending packets out the TUN device (engine → network).
pub struct TunChannels {
    /// Packets bound for the network (engine → device).
    pub to_net: mpsc::Sender<Bytes>,
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
/// `ingress` is called inline from the read pump for every packet arriving
/// from the network — straight into `send_datagram` (strawc) or the
/// forwarding engine (straw), with no intermediate queue or task wakeup
/// (Step 32). It must not block.
pub fn spawn_tun(
    cfg: &TunConfig,
    ingress: impl Fn(Bytes) + Send + 'static,
) -> Result<TunChannels, ProxyError> {
    use std::sync::Arc;

    let mut config = tun::Configuration::default();
    config.tun_name(&cfg.name).mtu(cfg.mtu).up();
    // virtio-net header on every read/write: the price of admission for
    // TSO/GSO offload (Step 32b). Unconditional — supported since 2.6.27 —
    // while the offloads themselves are negotiated below and may fail.
    config.platform_config(|p| {
        p.vnet_hdr(true);
    });
    if let Some((addr, prefix)) = cfg.ipv4 {
        config.address(addr).netmask(prefix_to_netmask(prefix));
    }

    let device = Arc::new(
        tun::create_as_async(&config)
            .map_err(|e| ProxyError::Config(format!("failed to create TUN device: {e}")))?,
    );
    setup_offload(&device);

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

    // Engine → network. Every write carries a null vnet header: the packet
    // came through the tunnel with its checksum already valid.
    let writer = device.clone();
    tokio::spawn(async move {
        use bytes::BytesMut;
        while let Some(packet) = to_net_rx.recv().await {
            let mut framed = BytesMut::with_capacity(VNET_HDR_LEN + packet.len());
            framed.extend_from_slice(&vnet::encode_none());
            framed.extend_from_slice(&packet);
            if let Err(e) = writer.send(&framed).await {
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
        let mut scratch: Vec<Bytes> = Vec::with_capacity(64);
        loop {
            if buf.capacity() < MAX_PACKET {
                buf = BytesMut::with_capacity(READ_BUFFER);
            }
            buf.resize(MAX_PACKET, 0);
            match reader.recv(&mut buf).await {
                Ok(n) if n > VNET_HDR_LEN => {
                    let mut frame = buf.split_to(n);
                    buf.clear();
                    let Some(hdr) = VnetHdr::parse(&frame) else {
                        continue;
                    };
                    let _ = frame.split_to(VNET_HDR_LEN);
                    // A GSO aggregate becomes MTU-sized packets here — one
                    // read syscall carried up to 64 KB of TCP.
                    scratch.clear();
                    match vnet::expand(&hdr, frame.freeze(), &mut scratch) {
                        Ok(()) => {
                            for packet in scratch.drain(..) {
                                ingress(packet);
                            }
                        }
                        Err(e) => {
                            tracing::debug!("dropping TUN frame: {e:?}");
                        }
                    }
                }
                Ok(_) => continue,
                Err(e) => {
                    tracing::warn!("TUN read failed: {e}");
                    break;
                }
            }
        }
    });

    Ok(TunChannels { to_net: to_net_tx })
}

/// Negotiate checksum + TSO offload on the device and pin the vnet header
/// size. Best-effort: on failure the kernel simply never sends GSO frames,
/// and the header handling on both pumps still applies (IFF_VNET_HDR is set
/// at creation and cannot fail per-feature).
#[cfg(target_os = "linux")]
fn setup_offload(device: &tun::AsyncDevice) {
    use std::os::fd::AsRawFd;
    const TUNSETOFFLOAD: libc::c_ulong = 0x4004_54d0;
    const TUNSETVNETHDRSZ: libc::c_ulong = 0x4004_54d8;
    const TUN_F_CSUM: libc::c_uint = 0x01;
    const TUN_F_TSO4: libc::c_uint = 0x02;
    const TUN_F_TSO6: libc::c_uint = 0x04;

    let fd = device.as_raw_fd();
    let hdr_len: libc::c_int = VNET_HDR_LEN as libc::c_int;
    // SAFETY: fd is a live TUN fd owned by `device`; both ioctls only read
    // the pointed-to integer.
    unsafe {
        if libc::ioctl(fd, TUNSETVNETHDRSZ, &hdr_len) != 0 {
            tracing::warn!("TUNSETVNETHDRSZ failed; assuming 10-byte vnet header");
        }
        let offloads = TUN_F_CSUM | TUN_F_TSO4 | TUN_F_TSO6;
        if libc::ioctl(fd, TUNSETOFFLOAD, offloads as libc::c_ulong) != 0 {
            tracing::warn!("TUNSETOFFLOAD failed; running without TSO (per-packet reads)");
        } else {
            tracing::info!("TUN offload enabled (csum + TSO v4/v6)");
        }
    }
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
pub fn spawn_tun(
    _cfg: &TunConfig,
    _ingress: impl Fn(Bytes) + Send + 'static,
) -> Result<TunChannels, ProxyError> {
    Err(ProxyError::Config(
        "TUN device support is Linux-only for now; run without --tun \
         (client<->client hairpin forwarding still works)"
            .to_string(),
    ))
}
