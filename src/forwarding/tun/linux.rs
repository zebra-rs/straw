//! Linux TUN backend: `IFF_VNET_HDR` framing plus TSO/GSO offload.

use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use tokio::sync::mpsc;

use super::{CHANNEL_DEPTH, MAX_PACKET, READ_BUFFER, TunChannels, TunConfig, prefix_to_netmask};
use crate::error::ProxyError;
use crate::forwarding::vnet::{self, VNET_HDR_LEN, VnetHdr};

/// Create the TUN device and spawn its read/write pump tasks.
///
/// `ingress` is called inline from the read pump for every packet arriving
/// from the network — straight into `send_datagram` (strawc) or the
/// forwarding engine (straw), with no intermediate queue or task wakeup
/// (Step 32). It must not block.
pub fn spawn_tun(
    cfg: &TunConfig,
    ingress: impl Fn(Bytes) + Send + 'static,
) -> Result<TunChannels, ProxyError> {
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

    Ok(TunChannels {
        to_net: to_net_tx,
        // Linux honours the requested name verbatim, so it is already correct.
        name: cfg.name.clone(),
    })
}

/// Negotiate checksum + TSO offload on the device and pin the vnet header
/// size. Best-effort: on failure the kernel simply never sends GSO frames,
/// and the header handling on both pumps still applies (IFF_VNET_HDR is set
/// at creation and cannot fail per-feature).
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
