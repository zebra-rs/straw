# straw: an RFC 9484 MASQUE proxy

Welcome to an introductory book about *straw*. straw is a from-scratch Rust
implementation of an [RFC 9484](https://www.rfc-editor.org/rfc/rfc9484)
(CONNECT-IP) proxy — an IP-level VPN gateway built on the MASQUE protocol: IP
packets tunnelled over QUIC using HTTP Datagrams and the Capsule Protocol, all
inside HTTP/3.

straw is memory-safe, async to the core (`tokio`), and built one working slice
at a time — from the first Extended CONNECT on the wire to a real user packet
forwarded through a kernel TUN device, and on to two peers behind separate NATs
holding a direct, end-to-end-encrypted tunnel to each other.

## What it does today

straw is three things that share one protocol stack:

1. **A CONNECT-IP proxy** (`straw`). A QUIC/HTTP-3 listener that accepts
   CONNECT-IP tunnels, assigns each client an address, advertises routes, and
   forwards IP packets between the tunnel and a kernel TUN device — with
   longest-prefix routing, TTL handling, ICMP, and optional NAT to the Internet.

2. **A VPN client** (`strawc`). The daemon that stands up the tunnel: it creates
   a TUN device, applies the proxy's assigned addresses and routes via `ip(8)`,
   and pumps packets both ways. A `ping` from behind `strawc` reaches the far
   side of the proxy and back.

3. **A peer-to-peer overlay** (`strawcat`). Two peers rendezvous through a straw
   relay running in **CONNECT-UDP bind mode**, form a mutually
   [SPKI-pinned](https://www.rfc-editor.org/rfc/rfc7250) inner QUIC connection
   the relay cannot read, and — where the NATs allow — **hole-punch** a direct
   path that leaves the relay behind. Over that connection they can pipe stdio
   (`netcat`-style) or run a full IP tunnel between the two hosts.

Every one of these is reproducible from a single command; the
[testing](ch-04-00-testing.md) chapter shows how.

## The protocol stack

straw layers exactly what the standards layer:

```
  IP packets
    │  RFC 9484  CONNECT-IP  (ADDRESS_ASSIGN, ROUTE_ADVERTISEMENT capsules)
  HTTP Datagrams
    │  RFC 9297  HTTP Datagrams + the Capsule Protocol
  QUIC DATAGRAM frames
    │  RFC 9221  unreliable datagrams
  HTTP/3 Extended CONNECT
    │  RFC 9114 + RFC 9220  ( :protocol = connect-ip )
  QUIC
    │  RFC 9000
  UDP
```

The data plane (IP packets) rides QUIC DATAGRAM frames — unreliable, exactly
like the IP it carries — while the control plane (address assignment, routes)
rides reliable capsules on the request stream.

## Why Rust, why QUIC-native

straw parses attacker-adjacent binary on every packet — IP headers, QUIC frames,
capsule varints, CBOR tokens — and does TLS 1.3 cryptography on every handshake.
Rust's memory safety and an `async` runtime let it do that without a class of
bugs that has historically plagued C VPN code.

The QUIC stack is [quinn](https://github.com/quinn-rs/quinn) + `h3` +
`h3-quinn` — pure Rust, tokio-native — chosen over quiche so the whole path is
one async runtime with no FFI boundary. straw reaches *under* h3 for raw
`send_datagram`/`read_datagram` on the data plane, keeping h3 only for the
control stream.

## How to read this book

The [Architecture](ch-00-01-architecture.md) chapter maps the binaries, modules,
and the protocol stack. [Building and Running](ch-00-02-building-and-running.md)
gets a proxy and a client talking on your machine. From there the book follows
the stack: the [CONNECT-IP proxy](ch-01-00-connect-ip.md) and its
[forwarding plane](ch-01-02-forwarding.md), the [VPN client](ch-02-00-strawc.md),
and then the [peer-to-peer direct path](ch-03-00-p2p-overview.md) — the relay,
the punch, and the hard reality of [symmetric NATs](ch-03-04-symmetric-nat.md).
The final part is [configuration](ch-05-00-config-straw.md) and a
[reference](ch-06-00-reference.md) of RFCs and wire codepoints.

> straw is a work in progress. Where a capability is deliberately deferred — the
> v2 standards-codepoint swap, some NAT-traversal cases that no technique solves
> — this book says so plainly rather than implying more than exists.

## License

straw is dual licensed under [MIT](https://github.com/zebra-rs/straw/blob/main/LICENSE-MIT)
or [Apache-2.0](https://github.com/zebra-rs/straw/blob/main/LICENSE-APACHE), at
your option — the same terms as the Rust project itself, and as nearly every
crate straw depends on. Contributions are taken under the same dual license.
