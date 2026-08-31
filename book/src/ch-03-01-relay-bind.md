# The Relay: CONNECT-UDP Bind Mode

The relay is a `straw` proxy with `--udp-bind` set. Bind mode makes it an
authenticated UDP relay — the MASQUE analogue of a TURN server — that allocates
each peer a public `(IP, port)` and forwards datagrams to and from it. It is off
by default, and enabling it **requires** an auth mode other than `none`.

## Binding a session

A peer opens the relay with a CONNECT-UDP request in **bind** mode (the
`connect-udp` `:protocol` plus the bind extension). The handler
(`udp_bind/handler.rs`) authenticates it, allocates a public address from
`--udp-bind-public-ips` within `--udp-bind-port-lo..hi`
(`udp_bind/alloc.rs`, retrying on a port clash), and replies 200 with the
allocated address in a `proxy-public-address` header.

It then reports, once, the peer's **outer source as the relay sees it** — the
peer's server-reflexive candidate — in an `OBSERVED_ADDRESS` capsule. That single
value is the seed for hole punching: it is the mapping the peer's NAT created
toward the relay.

## The data plane

Each bind session gets a real UDP socket (`udp_bind/socket.rs`). Two directions
run over it:

- **peer → network**: datagrams the peer sends (its inner-QUIC packets) are
  decoded and written to the socket, destined for the address the peer named.
- **network → peer**: packets arriving at the socket are wrapped as HTTP
  Datagrams and delivered back to the peer over QUIC.

Two peers reach *each other* by each sending to the other's relay-public address;
the relay hairpins between the two bind sockets. The relay never decodes the
payload — it is the inner QUIC connection's ciphertext.

## The compression contexts

To avoid repeating the destination address on every datagram, the bind protocol
uses **compression contexts** (provisional capsule types `0x11`–`0x13`:
`COMPRESSION_ASSIGN` / `ACK` / `CLOSE`). A peer registers a context bound to a
specific remote; datagrams on that context carry only the payload. The
*uncompressed* context (id `2`) carries the remote inline for one-off
destinations. These codepoints are provisional; see the
[reference](ch-06-00-reference.md).

## The SSRF guard

An authenticated client asking the relay to send UDP to arbitrary hosts is a
server-side request-forgery risk. The relay's `DestinationPolicy`
(`udp_bind/socket.rs`) **always denies** loopback, RFC 1918, link-local, ULA, and
multicast destinations. `--udp-bind-allow-dest <cidr>` re-permits specific ranges
for a private or single-host relay (design §10.1); a configured deny always beats
an allow. Per-session packet- and byte-rate caps
(`--udp-bind-max-pps` / `--udp-bind-max-bps`) bound the amplification.

## What the relay is for

## Locking the relay down to one peer

While a session has an **uncompressed** context open, every datagram spells its
remote address out — which is what lets a peer talk to many candidates during a
punch, and also means the relay will forward whatever arrives at its public
bind port. Once a direct path carries the traffic, neither is needed.

The peer then registers a **compressed** context bound to the other peer's
relay address and closes the uncompressed one (design §10.4). Two things follow.
Datagrams on the relay path stop carrying an address at all — the context
supplies it. And the relay becomes a firewall: with no uncompressed context and
no compressed match, an inbound packet is dropped at its edge rather than
forwarded as an inner-QUIC packet for the peer to parse.

The relay path is **not** closed — it stays as the permanent fallback. Lockdown
narrows what may travel it, so a later fallback still works. That ordering is
load-bearing: the compressed context has to be *acknowledged* before the
uncompressed one is closed, because a fallback landing in between would have no
context able to carry it, and the relay path would blackhole silently rather
than fail. If the relay never acknowledges, the peer keeps the uncompressed
context: a wider attack surface is better than a broken tunnel.

Two capabilities fall out of bind mode:

1. **Rendezvous + fallback** for strawcat: peers meet here and, if they cannot
   punch a direct path, keep using the relay as a blind forwarder.
2. **The seed for punching**: `OBSERVED_ADDRESS` gives each peer its reflexive
   candidate — the address it advertises to the other side. The relay once
   also observed each peer's *peer-facing* source, for
   [relay-assisted traversal](ch-03-04-symmetric-nat.md); that observer has
   been removed, because probes stopped passing through the relay when the
   punch moved into the QUIC layer.
