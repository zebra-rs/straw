//! Kernel TUN device I/O behind a pair of channels.
//!
//! The engine never touches the device directly: packets to the network go
//! into a `mpsc::Sender<Bytes>` and packets from the network are handed to an
//! `ingress` closure. Tests substitute plain channels for the device (see
//! `ForwardingEngine`), so everything above this module is portable.
//!
//! Below it, the platforms differ enough that they get their own backends:
//!
//! - [`linux`] — `IFF_VNET_HDR` on every read/write, so reads arrive as GSO
//!   aggregates carrying a virtio-net header and are re-segmented in
//!   [`crate::forwarding::vnet`]. That is where the throughput comes from and
//!   also where most of the complexity is.
//! - [`macos`] — utun, which has neither a virtio-net header nor TSO, so the
//!   pump reads one plain IP packet at a time. Simpler, and slower per packet.
//!
//! Both satisfy the same contract: [`spawn_tun`] creates the device, spawns
//! its two pumps, and returns [`TunChannels`].

use std::net::{Ipv4Addr, Ipv6Addr};

use bytes::Bytes;
use tokio::sync::mpsc;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::spawn_tun;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::spawn_tun;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod unsupported;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub use unsupported::spawn_tun;

/// Configuration for the kernel TUN device.
#[derive(Debug, Clone)]
pub struct TunConfig {
    /// Requested device name. Linux takes it verbatim; macOS requires
    /// `utun<N>` and falls back to a kernel-assigned name for anything else —
    /// see [`TunChannels::name`].
    pub name: String,
    pub mtu: u16,
    /// Address + prefix length to configure on the device (the proxy-side
    /// gateway for the client pool), e.g. 10.100.0.1/24.
    pub ipv4: Option<(Ipv4Addr, u8)>,
    /// IPv6 gateway address + prefix length, e.g. fd00:6d61:7371::1/64.
    pub ipv6: Option<(Ipv6Addr, u8)>,
}

/// Handle for sending packets out the TUN device (engine → network).
pub struct TunChannels {
    /// Packets bound for the network (engine → device).
    pub to_net: mpsc::Sender<Bytes>,
    /// The name the device actually got.
    ///
    /// Not always the requested one: macOS names utun devices itself unless
    /// asked for a specific `utun<N>`. Everything that addresses the device
    /// afterwards — routes, addresses, MTU changes — must use *this*, or it
    /// will configure an interface that does not exist.
    pub name: String,
}

/// Depth of the device channels; beyond this, datagrams are dropped.
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
const CHANNEL_DEPTH: usize = 1024;

/// Largest single packet accepted from the device, independent of the
/// configured MTU so raising the device MTU at runtime cannot truncate.
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
const MAX_PACKET: usize = 65_536;

/// Read buffer size, independent of the configured MTU.
///
/// A buffer sized from `cfg.mtu` silently truncates once the device MTU is
/// raised at runtime (which `strawc` does as QUIC path-MTU discovery ramps),
/// and a truncated IP packet is indistinguishable from a malformed one
/// downstream. One 64 KiB buffer per device costs nothing next to that.
#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
const READ_BUFFER: usize = 4 * MAX_PACKET;

#[cfg_attr(not(any(target_os = "linux", target_os = "macos")), allow(dead_code))]
fn prefix_to_netmask(prefix: u8) -> Ipv4Addr {
    let bits = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix.min(32) as u32)
    };
    Ipv4Addr::from(bits)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netmask_from_prefix() {
        assert_eq!(prefix_to_netmask(24), Ipv4Addr::new(255, 255, 255, 0));
        assert_eq!(prefix_to_netmask(32), Ipv4Addr::new(255, 255, 255, 255));
        assert_eq!(prefix_to_netmask(0), Ipv4Addr::UNSPECIFIED);
        // Nonsense prefixes saturate rather than shifting out of range.
        assert_eq!(prefix_to_netmask(40), Ipv4Addr::new(255, 255, 255, 255));
    }
}
