# The Tunnel MTU

A tunnel's MTU is the largest IP packet it can carry, and for a QUIC-datagram
tunnel that is a moving target. straw treats it as live state rather than a
setup-time constant — getting this wrong blackholes exactly the full-size packets
that matter most.

## Why it moves

One IP packet must fit in one QUIC DATAGRAM frame, so the tunnel MTU is bounded
by `quinn::Connection::max_datagram_size()` minus the HTTP-Datagram framing. But
quinn's path MTU **starts conservative and rises** as its own discovery probes
succeed. A value sampled at connection setup is a safe lower bound, not the truth;
frozen there, the tunnel would silently drop every packet larger than that early
estimate once the path could actually carry more.

## The live MTU

The per-session MTU is held as a live `AtomicUsize` that the session handler
**refreshes** as quinn's path MTU climbs. It is the smaller of the operator's
`--mtu` and what one datagram currently carries. On the client, `strawc` widens
its **TUN device** the same way: a background poll samples `PacketSender::
max_packet_size()` and, when it has risen by a step, runs `ip link set … mtu …`
to grow the device (unless `--mtu` pinned it).

## Oversize packets

A packet arriving from the network that is too big for the current tunnel MTU is
**dropped and counted** in `straw_packets_mtu_dropped_total` — not answered with
an ICMP Packet Too Big. The only source address the proxy could put on such an
ICMP is its own tunnel address, which is a martian to the original sender, so the
message would be useless. Path-MTU discovery *toward the network* is instead the
kernel's job, driven by the TUN device's MTU.

The one exception is a **hairpin between two clients**: there both ends are inside
the tunnel, so an oversize packet does earn a proper ICMP Packet Too Big that the
sending client can act on.

## When the path MTU collapses and stays there

Tracking quinn's path MTU live is the right design, but it inherits whatever
quinn believes — including a mistake. QUIC's black-hole detector watches for
loss bursts that could be explained by a shrunken path and, when it has seen
enough, drops the connection to `min_mtu` (1200) and re-searches after a
cooldown. In the `quinn-proto` **0.11.17 release** that detector never lets go:
once at the floor, every packet is exactly `min_mtu`, and a burst of them is
judged suspicious (`burst.smallest_packet_size < self.min_mtu` — and `1200 <
1200` is false), so the detector re-fires for as long as the transfer lasts.

For straw that is not an abstract QUIC problem. The session MTU is the smaller
of `--mtu` and what one datagram carries, so a connection pinned at the floor
drags the tunnel MTU down with it and holds it there. Worse, the failure is
**silent in both directions**: the proxy drops the now-oversize packets without
ICMP (for the reason above), and `strawc` only ever ratchets its TUN device
*up*, so the client keeps advertising the old, too-large MTU. The origin's TCP
retransmits into a hole and backs off. Measured through a real tunnel, that
shows up as the transfer stalling and never resuming.

straw therefore pins `quinn-proto` to upstream's `0.11.x` branch, which carries
the fix (see `UPSTREAM.md`). `bench/mtu-recovery.sh` is the A/B that
demonstrates it — the release build collapses at t = 49 s and stays at 1200 for
the remaining 152 s with 2463 detections, the branch build never leaves 1452 —
and `bench/MTU-RECOVERY.md` records both the numbers and what the experiment
does *not* establish.

## The relay path is stricter

When two peers tunnel over the [relay](ch-03-02-inner-quic.md), the inner QUIC
connection's packets are each re-wrapped as one *outer* QUIC DATAGRAM. The inner
MTU must therefore fit inside the outer datagram, and quinn's own path-MTU
discovery — left to itself — would probe the inner connection *past* that ceiling,
whereupon those oversize packets fail `send_datagram` and stall the connection
after the handshake. straw pins the relay-path inner MTU to 1200 with discovery
off (`p2p::peer::relay_transport`); the direct (punched) path, running over a
real socket, has no such limit. This is covered in [Inner QUIC Over the
Relay](ch-03-02-inner-quic.md).
