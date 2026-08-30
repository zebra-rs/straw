//! virtio-net header codec and userspace TSO for the TUN device (Step 32b).
//!
//! With `IFF_VNET_HDR` + `TUNSETOFFLOAD(TUN_F_CSUM|TSO4|TSO6)`, the kernel
//! stops segmenting TCP at the device MTU and hands us one aggregate frame
//! (up to 64 KB) prefixed by a 10-byte `struct virtio_net_hdr` — one read
//! syscall and one trip down the kernel stack per aggregate instead of per
//! MTU packet. The tunnel itself still carries MTU-sized IP packets, so
//! [`expand`] re-segments the aggregate here: per segment, rebuilt IP and
//! TCP headers (length, IPv4 ID, sequence number, flags) and freshly
//! computed checksums — offloaded packets arrive with `NEEDS_CSUM`, i.e.
//! their checksum is NOT filled in.
//!
//! Layout (little-endian fields, `/usr/include/linux/virtio_net.h`):
//!
//! ```text
//! u8 flags; u8 gso_type; u16 hdr_len; u16 gso_size; u16 csum_start; u16 csum_offset;
//! ```

use bytes::{Bytes, BytesMut};

/// `sizeof(struct virtio_net_hdr)`; pinned via `TUNSETVNETHDRSZ`.
pub const VNET_HDR_LEN: usize = 10;

pub const VIRTIO_NET_HDR_F_NEEDS_CSUM: u8 = 1;
pub const VIRTIO_NET_HDR_GSO_NONE: u8 = 0;
pub const VIRTIO_NET_HDR_GSO_TCPV4: u8 = 1;
pub const VIRTIO_NET_HDR_GSO_TCPV6: u8 = 4;
/// ECN bit or'ed into gso_type; irrelevant to re-segmentation.
const VIRTIO_NET_HDR_GSO_ECN: u8 = 0x80;

/// Decoded `virtio_net_hdr`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VnetHdr {
    pub flags: u8,
    pub gso_type: u8,
    pub hdr_len: u16,
    pub gso_size: u16,
    pub csum_start: u16,
    pub csum_offset: u16,
}

impl VnetHdr {
    pub fn parse(buf: &[u8]) -> Option<Self> {
        if buf.len() < VNET_HDR_LEN {
            return None;
        }
        Some(Self {
            flags: buf[0],
            gso_type: buf[1] & !VIRTIO_NET_HDR_GSO_ECN,
            hdr_len: u16::from_le_bytes([buf[2], buf[3]]),
            gso_size: u16::from_le_bytes([buf[4], buf[5]]),
            csum_start: u16::from_le_bytes([buf[6], buf[7]]),
            csum_offset: u16::from_le_bytes([buf[8], buf[9]]),
        })
    }
}

/// The header prepended to every packet written to the device: no offload,
/// checksum already valid (we computed or verified it in the tunnel path).
pub const fn encode_none() -> [u8; VNET_HDR_LEN] {
    [0; VNET_HDR_LEN]
}

/// RFC 1071 internet checksum over `parts`, with `seed` folded in (used for
/// the pseudo-header sum).
fn internet_checksum(seed: u32, parts: &[&[u8]]) -> u16 {
    let mut sum = seed;
    for part in parts {
        let mut chunks = part.chunks_exact(2);
        for c in &mut chunks {
            sum += u32::from(u16::from_be_bytes([c[0], c[1]]));
        }
        if let [last] = chunks.remainder() {
            sum += u32::from(u16::from_be_bytes([*last, 0]));
        }
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Pseudo-header sum (addresses + protocol + length) for the family of the
/// packet in `ip_hdr`.
fn pseudo_sum(ip_hdr: &[u8], l4_len: usize) -> u32 {
    let mut sum: u32 = 0;
    match ip_hdr[0] >> 4 {
        4 => {
            for c in ip_hdr[12..20].chunks_exact(2) {
                sum += u32::from(u16::from_be_bytes([c[0], c[1]]));
            }
            sum += u32::from(ip_hdr[9]); // protocol
        }
        _ => {
            for c in ip_hdr[8..40].chunks_exact(2) {
                sum += u32::from(u16::from_be_bytes([c[0], c[1]]));
            }
            sum += u32::from(ip_hdr[6]); // next header
        }
    }
    sum + l4_len as u32
}

/// Errors from [`expand`]; each maps to a dropped frame, counted upstream.
#[derive(Debug, PartialEq, Eq)]
pub enum VnetError {
    Truncated,
    UnsupportedGso(u8),
    Malformed,
}

/// Turn one frame read from the device (after the vnet header) into
/// ready-to-tunnel IP packets appended to `out`.
///
/// Non-GSO frames pass through, with their checksum completed when the
/// kernel left it partial (`NEEDS_CSUM`). TCP GSO frames are re-segmented
/// at `gso_size` with per-segment headers and checksums:
/// - IPv4: total length, ID incremented per segment, header checksum
/// - IPv6: payload length
/// - TCP: sequence advanced by the payload offset; CWR only on the first
///   segment, FIN/PSH only on the last; checksum over the pseudo-header
pub fn expand(hdr: &VnetHdr, frame: Bytes, out: &mut Vec<Bytes>) -> Result<(), VnetError> {
    match hdr.gso_type {
        VIRTIO_NET_HDR_GSO_NONE => {
            if hdr.flags & VIRTIO_NET_HDR_F_NEEDS_CSUM == 0 {
                out.push(frame);
                return Ok(());
            }
            // Complete the partial checksum in place (the buffer is a fresh
            // split off the read chunk, so this is copy-free).
            let start = hdr.csum_start as usize;
            let at = start + hdr.csum_offset as usize;
            if at + 2 > frame.len() {
                return Err(VnetError::Truncated);
            }
            let mut packet = frame
                .try_into_mut()
                .unwrap_or_else(|shared| BytesMut::from(&shared[..]));
            // The kernel pre-fills the checksum field with the pseudo-header
            // sum, so the plain sum over [csum_start..] is the complement.
            packet[at] = 0;
            packet[at + 1] = 0;
            // Rebuild the pseudo-header sum ourselves rather than trusting
            // the stashed value: it is cheap and independent of kernel
            // quirks. csum_start is the L4 offset.
            let l4_len = packet.len() - start;
            let sum = internet_checksum(pseudo_sum(&packet[..start], l4_len), &[&packet[start..]]);
            packet[at..at + 2].copy_from_slice(&sum.to_be_bytes());
            out.push(packet.freeze());
            Ok(())
        }
        VIRTIO_NET_HDR_GSO_TCPV4 | VIRTIO_NET_HDR_GSO_TCPV6 => segment_tcp(hdr, &frame, out),
        other => Err(VnetError::UnsupportedGso(other)),
    }
}

fn segment_tcp(hdr: &VnetHdr, frame: &[u8], out: &mut Vec<Bytes>) -> Result<(), VnetError> {
    let mss = hdr.gso_size as usize;
    if mss == 0 || frame.is_empty() {
        return Err(VnetError::Malformed);
    }
    // Derive the header split from the packet itself; hdr.hdr_len is only a
    // hint and some paths leave it 0.
    let ip_len = match frame[0] >> 4 {
        4 if frame.len() >= 20 => ((frame[0] & 0x0f) as usize) * 4,
        6 if frame.len() >= 40 => 40, // TSO frames carry no extension headers
        _ => return Err(VnetError::Malformed),
    };
    if frame.len() < ip_len + 20 {
        return Err(VnetError::Truncated);
    }
    let tcp_off = ip_len;
    let tcp_len = ((frame[tcp_off + 12] >> 4) as usize) * 4;
    let headers_len = ip_len + tcp_len;
    if tcp_len < 20 || frame.len() <= headers_len {
        return Err(VnetError::Malformed);
    }
    let (headers, payload) = frame.split_at(headers_len);
    let base_seq = u32::from_be_bytes(headers[tcp_off + 4..tcp_off + 8].try_into().unwrap());
    let base_id = if ip_len >= 20 && frame[0] >> 4 == 4 {
        u16::from_be_bytes([headers[4], headers[5]])
    } else {
        0
    };
    let flags_byte = headers[tcp_off + 13];
    let segments = payload.len().div_ceil(mss);

    for (i, chunk) in payload.chunks(mss).enumerate() {
        let mut seg = BytesMut::with_capacity(headers_len + chunk.len());
        seg.extend_from_slice(headers);
        seg.extend_from_slice(chunk);

        let is_first = i == 0;
        let is_last = i == segments - 1;

        if frame[0] >> 4 == 4 {
            let total = (headers_len + chunk.len()) as u16;
            seg[2..4].copy_from_slice(&total.to_be_bytes());
            let id = base_id.wrapping_add(i as u16);
            seg[4..6].copy_from_slice(&id.to_be_bytes());
            seg[10] = 0;
            seg[11] = 0;
            let ipsum = internet_checksum(0, &[&seg[..ip_len]]);
            seg[10..12].copy_from_slice(&ipsum.to_be_bytes());
        } else {
            let payload_len = (tcp_len + chunk.len()) as u16;
            seg[4..6].copy_from_slice(&payload_len.to_be_bytes());
        }

        let seq = base_seq.wrapping_add((i * mss) as u32);
        seg[tcp_off + 4..tcp_off + 8].copy_from_slice(&seq.to_be_bytes());
        let mut flags = flags_byte;
        if !is_last {
            flags &= !0x09; // FIN | PSH only on the last segment
        }
        if !is_first {
            flags &= !0x80; // CWR only on the first
        }
        seg[tcp_off + 13] = flags;

        seg[tcp_off + 16] = 0;
        seg[tcp_off + 17] = 0;
        let l4_len = tcp_len + chunk.len();
        let sum = internet_checksum(pseudo_sum(&seg[..ip_len], l4_len), &[&seg[tcp_off..]]);
        seg[tcp_off + 16..tcp_off + 18].copy_from_slice(&sum.to_be_bytes());

        out.push(seg.freeze());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference TCP checksum for verification, written independently of
    /// the code under test.
    fn tcp_checksum_valid(packet: &[u8]) -> bool {
        let ip_len = if packet[0] >> 4 == 4 {
            ((packet[0] & 0x0f) as usize) * 4
        } else {
            40
        };
        let l4 = &packet[ip_len..];
        internet_checksum(pseudo_sum(&packet[..ip_len], l4.len()), &[l4]) == 0
    }

    fn ipv4_header_valid(packet: &[u8]) -> bool {
        internet_checksum(0, &[&packet[..20]]) == 0
    }

    /// Build a v4 TCP aggregate as the kernel would hand it to us: header
    /// checksum filled, TCP checksum left partial (we zero it; the code
    /// recomputes from scratch anyway).
    fn tcp4_aggregate(payload_len: usize, flags: u8) -> Vec<u8> {
        let mut p = vec![0u8; 40 + payload_len];
        p[0] = 0x45;
        let total = (40 + payload_len) as u16;
        p[2..4].copy_from_slice(&total.to_be_bytes());
        p[4..6].copy_from_slice(&1000u16.to_be_bytes()); // ID
        p[8] = 64;
        p[9] = 6; // TCP
        p[12..16].copy_from_slice(&[10, 100, 0, 2]);
        p[16..20].copy_from_slice(&[10, 99, 0, 2]);
        let sum = internet_checksum(0, &[&p[..20]]);
        p[10..12].copy_from_slice(&sum.to_be_bytes());
        // TCP header
        p[20..22].copy_from_slice(&5555u16.to_be_bytes());
        p[22..24].copy_from_slice(&80u16.to_be_bytes());
        p[24..28].copy_from_slice(&1_000_000u32.to_be_bytes()); // seq
        p[32] = 5 << 4; // doff = 20
        p[33] = flags;
        for (i, b) in p[40..].iter_mut().enumerate() {
            *b = i as u8;
        }
        p
    }

    fn hdr_tso4(mss: u16) -> VnetHdr {
        VnetHdr {
            flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
            gso_type: VIRTIO_NET_HDR_GSO_TCPV4,
            hdr_len: 40,
            gso_size: mss,
            csum_start: 20,
            csum_offset: 16,
        }
    }

    #[test]
    fn header_round_trips() {
        let mut raw = [0u8; VNET_HDR_LEN];
        raw[0] = VIRTIO_NET_HDR_F_NEEDS_CSUM;
        raw[1] = VIRTIO_NET_HDR_GSO_TCPV4 | VIRTIO_NET_HDR_GSO_ECN;
        raw[2..4].copy_from_slice(&40u16.to_le_bytes());
        raw[4..6].copy_from_slice(&1360u16.to_le_bytes());
        raw[6..8].copy_from_slice(&20u16.to_le_bytes());
        raw[8..10].copy_from_slice(&16u16.to_le_bytes());
        let h = VnetHdr::parse(&raw).unwrap();
        assert_eq!(h.gso_type, VIRTIO_NET_HDR_GSO_TCPV4, "ECN bit masked off");
        assert_eq!((h.hdr_len, h.gso_size), (40, 1360));
        assert_eq!((h.csum_start, h.csum_offset), (20, 16));
        assert!(VnetHdr::parse(&raw[..9]).is_none());
    }

    #[test]
    fn tso4_resegments_with_valid_headers_and_checksums() {
        // 2.5 segments of 1000 bytes: PSH|ACK on the wire.
        let frame = tcp4_aggregate(2500, 0x18);
        let mut out = Vec::new();
        expand(&hdr_tso4(1000), Bytes::from(frame), &mut out).unwrap();
        assert_eq!(out.len(), 3);
        assert_eq!(out[0].len(), 40 + 1000);
        assert_eq!(out[2].len(), 40 + 500);
        for (i, seg) in out.iter().enumerate() {
            assert!(ipv4_header_valid(seg), "segment {i} IP checksum");
            assert!(tcp_checksum_valid(seg), "segment {i} TCP checksum");
            let seq = u32::from_be_bytes(seg[24..28].try_into().unwrap());
            assert_eq!(seq, 1_000_000 + (i as u32) * 1000);
            let id = u16::from_be_bytes([seg[4], seg[5]]);
            assert_eq!(id, 1000 + i as u16);
            let flags = seg[33];
            if i == 2 {
                assert_eq!(flags & 0x08, 0x08, "PSH on the last segment");
            } else {
                assert_eq!(flags & 0x09, 0, "no FIN/PSH mid-burst");
            }
            // Payload content is contiguous across segments.
            assert_eq!(seg[40], ((i * 1000) % 256) as u8);
        }
    }

    #[test]
    fn tso6_resegments_with_valid_checksums() {
        let payload_len = 2200usize;
        let mut p = vec![0u8; 60 + payload_len];
        p[0] = 0x60;
        p[4..6].copy_from_slice(&((20 + payload_len) as u16).to_be_bytes());
        p[6] = 6; // TCP
        p[7] = 64;
        p[8..24].copy_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        p[24..40].copy_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2]);
        p[44..48].copy_from_slice(&7_000u32.to_be_bytes()); // seq
        p[52] = 5 << 4;
        p[53] = 0x10; // ACK
        let hdr = VnetHdr {
            flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
            gso_type: VIRTIO_NET_HDR_GSO_TCPV6,
            hdr_len: 60,
            gso_size: 1000,
            csum_start: 40,
            csum_offset: 16,
        };
        let mut out = Vec::new();
        expand(&hdr, Bytes::from(p), &mut out).unwrap();
        assert_eq!(out.len(), 3);
        for (i, seg) in out.iter().enumerate() {
            assert!(tcp_checksum_valid(seg), "segment {i} TCP checksum");
            let plen = u16::from_be_bytes([seg[4], seg[5]]) as usize;
            assert_eq!(plen + 40, seg.len(), "v6 payload length");
            let seq = u32::from_be_bytes(seg[44..48].try_into().unwrap());
            assert_eq!(seq, 7_000 + (i as u32) * 1000);
        }
    }

    #[test]
    fn non_gso_with_partial_checksum_is_completed() {
        // A UDP packet with NEEDS_CSUM: csum_start 20 (L4), offset 6.
        let mut p = vec![0u8; 28 + 4];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&32u16.to_be_bytes());
        p[8] = 64;
        p[9] = 17;
        p[12..16].copy_from_slice(&[10, 100, 0, 2]);
        p[16..20].copy_from_slice(&[10, 99, 0, 2]);
        let sum = internet_checksum(0, &[&p[..20]]);
        p[10..12].copy_from_slice(&sum.to_be_bytes());
        p[20..22].copy_from_slice(&53u16.to_be_bytes());
        p[22..24].copy_from_slice(&53u16.to_be_bytes());
        p[24..26].copy_from_slice(&12u16.to_be_bytes());
        p[28..32].copy_from_slice(b"ping");
        let hdr = VnetHdr {
            flags: VIRTIO_NET_HDR_F_NEEDS_CSUM,
            gso_type: VIRTIO_NET_HDR_GSO_NONE,
            hdr_len: 0,
            gso_size: 0,
            csum_start: 20,
            csum_offset: 6,
        };
        let mut out = Vec::new();
        expand(&hdr, Bytes::from(p), &mut out).unwrap();
        assert_eq!(out.len(), 1);
        let seg = &out[0];
        let l4 = &seg[20..];
        assert_eq!(
            internet_checksum(pseudo_sum(&seg[..20], l4.len()), &[l4]),
            0,
            "completed UDP checksum verifies"
        );
    }

    #[test]
    fn non_gso_without_flags_passes_through_untouched() {
        let p = Bytes::from_static(&[0x45, 0, 0, 20]);
        let hdr = VnetHdr {
            flags: 0,
            gso_type: VIRTIO_NET_HDR_GSO_NONE,
            hdr_len: 0,
            gso_size: 0,
            csum_start: 0,
            csum_offset: 0,
        };
        let mut out = Vec::new();
        expand(&hdr, p.clone(), &mut out).unwrap();
        assert_eq!(out, vec![p]);
    }

    #[test]
    fn malformed_frames_are_rejected() {
        let mut out = Vec::new();
        // Unknown GSO type.
        let bad = VnetHdr {
            gso_type: 3, // GSO_UDP, not negotiated
            ..hdr_tso4(1000)
        };
        assert_eq!(
            expand(&bad, Bytes::from(tcp4_aggregate(100, 0x10)), &mut out),
            Err(VnetError::UnsupportedGso(3))
        );
        // GSO frame with no payload.
        assert!(expand(&hdr_tso4(1000), Bytes::from(vec![0u8; 40]), &mut out).is_err());
        // mss 0.
        assert!(
            expand(
                &hdr_tso4(0),
                Bytes::from(tcp4_aggregate(100, 0x10)),
                &mut out
            )
            .is_err()
        );
        assert!(out.is_empty());
    }
}
