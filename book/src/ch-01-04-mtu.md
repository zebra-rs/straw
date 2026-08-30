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
