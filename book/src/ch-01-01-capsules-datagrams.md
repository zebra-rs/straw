# Capsules and HTTP Datagrams

CONNECT-IP splits its traffic in two: a **reliable control plane** of capsules on
the request stream, and an **unreliable data plane** of HTTP Datagrams. Both are
[RFC 9297](https://www.rfc-editor.org/rfc/rfc9297); straw implements them in the
`capsule/` and `datagram/` modules.

## The Capsule Protocol

A capsule is a QUIC-varint type, a varint length, and a value. straw's
`CapsuleBuffer` accumulates stream bytes and yields whole capsules as they
complete; unknown types are surfaced as `Capsule::Unknown { type_id, data }` so a
handler can decide what to do with a vendor extension.

The CONNECT-IP capsules straw encodes and decodes:

| Capsule | Direction | Purpose |
|---------|-----------|---------|
| `ADDRESS_ASSIGN` | server → client | The client's tunnel address(es), full-state. |
| `ADDRESS_REQUEST` | client → server | Request a specific address (optional). |
| `ROUTE_ADVERTISEMENT` | server → client | The IP ranges to route through the tunnel, full-state. |

Each carries QUIC-varint-encoded IP ranges (`start`, `end`, `ip_protocol`);
`merge_ranges` coalesces adjacent ones. Because assignment and route capsules are
full-state, the client's [`iface`](ch-02-00-strawc.md) layer tears down and
re-applies its kernel state whenever a fresh one arrives, rather than trying to
compute a delta.

## HTTP Datagrams and Context IDs

The data plane is HTTP Datagrams, each prefixed by a **Context ID** that says how
to interpret the payload. straw uses two:

| Context ID | Meaning |
|------------|---------|
| `0` | An IP packet (RFC 9484's default context). |
| `2`+ | Client-allocated *uncompressed* contexts used by the relay's bind mode. |

On the wire an HTTP Datagram inside QUIC is a **Quarter Stream ID** (the request
stream's ID / 4, identifying which tunnel) followed by the Context ID and the
payload. straw's `datagram/` module encodes and decodes this framing; the
connection-level demux reads a raw `quinn` datagram, splits off the Quarter
Stream ID, and routes the rest to the session that owns that stream.

## QUIC DATAGRAM frames

Under the HTTP Datagram sits a
[RFC 9221](https://www.rfc-editor.org/rfc/rfc9221) QUIC DATAGRAM frame —
unreliable, unordered, un-retransmitted. That is exactly right for tunnelled IP:
a dropped inner packet is the inner transport's problem, not the tunnel's, and
retransmitting it would only add head-of-line delay.

straw reaches *beneath* h3 for this: it holds the raw `quinn::Connection` and
calls `send_datagram` / `read_datagram` directly, using h3 only for the control
stream. The receive and send datagram buffers are sized for bursts of MTU-sized
packets (`datagram_receive_buffer_size`, `datagram_send_buffer_size`).

One QUIC DATAGRAM must carry one whole IP packet, so the largest IP packet the
tunnel can move is bounded by `max_datagram_size` minus the framing overhead —
the subject of [The Tunnel MTU](ch-01-04-mtu.md).

## A note on the patched quinn-proto

Sustained datagram overload once tripped an accounting bug in `quinn-proto` that
panicked the tunnel: the 0.11.17 release subtracts a dropped datagram's length
from its buffer accounting twice, so the counter underflows and every later
send panics. straw carried a one-line fix as a vendored copy until upstream
merged the identical change on its `0.11.x` branch, which `[patch.crates-io]`
now tracks; the patch goes away when 0.11.18 releases.
