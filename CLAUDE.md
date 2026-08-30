# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**straw** is a Rust implementation of an RFC 9484 (CONNECT-IP) proxy server — an IP-level VPN gateway using the MASQUE protocol over HTTP/3. It tunnels IP packets over QUIC using HTTP Datagrams and the Capsule Protocol.

The design document `rfc9484-proxy-design.md` is the primary reference for architecture, data structures, wire formats, and implementation phases.

## Build Commands

```bash
cargo build            # Build the project
cargo test             # Run all tests
cargo test <test_name> # Run a single test
cargo clippy           # Lint
cargo fmt              # Format code

make -C bdd            # End-to-end BDD suite (needs passwordless sudo)
make -C bdd tunnel_basic     # One feature, by its tag
BDD_KEEP=1 make -C bdd tunnel_mtu   # …leaving namespaces and daemons up
```

Uses Rust edition 2024 (requires nightly or recent stable toolchain). A plain
`cargo test` covers the `straw` package; the `bdd` workspace member's cucumber
test needs root and is run through its Makefile.

## Architecture

The project implements the following protocol stack: IP packets → HTTP Datagrams (RFC 9297) → QUIC DATAGRAM frames (RFC 9221) → HTTP/3 Extended CONNECT (RFC 9114 + RFC 9220) → QUIC (RFC 9000).

Planned module structure (from design doc):
- **server** — QUIC/H3 listener using quinn + h3 + h3-quinn
- **session/** — Per-stream CONNECT-IP tunnel lifecycle, authentication
- **capsule/** — Encode/decode ADDRESS_ASSIGN, ADDRESS_REQUEST, ROUTE_ADVERTISEMENT capsules with QUIC VarInt wire format
- **datagram/** — HTTP Datagram handling, Context ID management
- **forwarding/** — IP packet validation, TTL decrement, TUN device I/O, route table (longest-prefix match)
- **address_pool** — IPv4/IPv6 address allocation per session
- **uri_template** — URI template parsing for `{target}` and `{ipproto}`
- **client** — `TunnelClient`/`Tunnel` (per-connection datagram demux, scoped
  and multi-tunnel connects) plus `PacketSender`, a cloneable send handle
- **iface** — client-side kernel config: applies ADDRESS_ASSIGN/
  ROUTE_ADVERTISEMENT via `ip(8)`, reverts on drop

Binaries: `straw` (proxy), `strawc` (client daemon: TUN device + kernel
routes, the actual VPN client), `test_client` (synthetic-packet harness;
exits non-zero unless every echo got a genuine echo back, so BDD can assert
on it), `strawcat` (P2P peer: `genkey`/`listen`/`connect`, plus `--vpn` IP-tunnel mode).

Key design decisions:
- quinn + h3 stack (pure Rust, async tokio-native) over quiche
- DashMap for concurrent session table
- etherparse for IP packet parsing
- TUN device for kernel-level packet I/O

## BDD suite (`bdd/`)

Cucumber scenarios in `bdd/tests/features/*.feature` run the real binaries in
Linux network namespaces (ported from the zebra-rs BDD framework). Each
feature scopes its namespaces, veths and pid files by its first tag
(`@tunnel_basic` → `tunnel_basic_client`, …) so features run concurrently;
`make -C bdd` runs them 4-way. `make -C bdd stage` copies this worktree's
binaries into `bdd/.stage/bin` and the harness prepends that to PATH, so a run
never tests a stale build. Steps live in `bdd/tests/cucumber.rs`; an unmatched
step fails the scenario rather than being skipped.

## Privileges

Neither `straw` nor `strawc` needs root — both need **ambient**
`CAP_NET_ADMIN` (they shell out to `ip`/`iptables`/`sysctl`, which inherit
only ambient capabilities). `packaging/*.service` set it. Do not add
`ProtectKernelTunables=yes`: the proxy writes `net.ipv4.ip_forward` under NAT.

## Tunnel MTU

The per-session MTU is the smaller of `--mtu` and what one QUIC DATAGRAM
carries, held as a live `AtomicUsize` the session handler refreshes — quinn's
path MTU starts low and rises, so a value frozen at setup blackholes full-size
packets. `strawc` widens its TUN device the same way. Oversize packets from
the network are dropped and counted in `straw_packets_mtu_dropped_total`, not
answered by ICMP (the only source address available there is the proxy's own
tunnel address, a martian to the sender); PMTUD toward the network is the
kernel's job via the device MTU. Hairpin between two clients does earn an ICMP
Packet Too Big, since both ends are inside the tunnel.

## Configuration and flow scoping

`straw --config file.toml` layers a TOML file (keys per `straw.example.toml`)
under the CLI; a flag wins only when actually given (clap `ValueSource`).
A `{target}` prefix is advertised (and enforced) directly, a hostname is
DNS-resolved before the reply (502 on failure), and `{ipproto}` narrows every
range with ICMP still allowed (RFC 9484 §4.6). A scoped session's egress
policy doubles as its ingress filter, so it only hears from within its scope.

## Benchmarks

`sudo bench/iperf-baseline.sh [secs]` measures raw-veth vs through-tunnel
iperf3 throughput across three namespaces; numbers and analysis live in
`bench/BASELINE.md` (baseline: ~4–5 Gbit/s TCP through the tunnel, CPU-bound,
parallel streams don't help; TUN TSO offload engages — 64 KB reads — but
throughput sits at the single-connection QUIC crypto floor, see
bench/BASELINE.md). The TUN device uses IFF_VNET_HDR: every read/write
carries a 10-byte virtio-net header, GSO aggregates are re-segmented in
`forwarding/vnet.rs`. `vendor/quinn-proto` is 0.11.17 with a one-line
fix for an upstream datagram-accounting bug that panicked the tunnel under
sustained datagram overload — drop it when a fixed 0.11.x releases.

## P2P direct path (`src/p2p/`, `src/udp_bind/`)

`strawcat` peers form a mutually SPKI-pinned inner QUIC connection through a
straw relay running CONNECT-UDP **bind mode** (`--udp-bind`, off by default,
auth mandatory), which forwards only ciphertext (design goal G1). Layers:
`udp_bind/` is the relay's bind side (per-session public (IP,port) allocation,
compression-context codec, encap/decap socket loop, connect-udp handler);
`p2p/identity` + `p2p/token` are the trust model (Ed25519 SPKI pin, `sc2_`
CBOR token); `p2p/relay_socket` runs an inner `quinn::AsyncUdpSocket` over a
bind session; `p2p/inner_tls` is RFC 7250 raw-public-key mTLS pinned by SPKI;
`p2p/peer` orchestrates listen/connect. The egress SSRF guard always denies
loopback/RFC1918/etc.; `--udp-bind-allow-dest` re-permits ranges for
private/single-host relays (design §10.1).

P2 hole punching is implemented: `p2p/candidates` + `p2p/wire` gather and
exchange host/reflexive/relay candidates over the inner control stream,
`p2p/punch` does the simultaneous-open DCUtR punch with the §5.3.4 tie-break,
and `p2p/session` is the `Relay→Punching→Direct` path state machine that
promotes on success, reverts + re-punches on loss. On a duplicate success both
sides converge on the connection whose *client* is the lower-pinned peer; a
lone success (asymmetric NAT) is kept regardless of role — never reject the
only working path.

**Relay-path inner MTU is pinned to 1200 with MTU discovery OFF**
(`p2p/peer::relay_transport`). Each inner QUIC packet is re-wrapped as one
outer QUIC DATAGRAM, so the inner MTU must fit inside it; quinn's own path-MTU
discovery would probe the inner connection past that ceiling and those oversize
packets fail `send_datagram`, stalling the connection *after* the handshake.
This only bites once packets exceed ~1200 B, so small-payload tests miss it —
`relay_path_carries_a_large_transfer` guards it with a 256 KiB transfer. The
direct (punched) path has no such limit; it runs over a real socket.

`pipe_stdio` in `strawcat` awaits **both** directions (never aborts the
upload): aborting drops the `SendStream` unfinished, which quinn turns into a
stream reset that discards buffered bytes the peer never sees.

**VPN mode (P3)** — `strawcat --vpn` runs straw's own RFC 9484 CONNECT-IP stack
over the peer connection instead of piping stdio, giving a real IP tunnel
between the two hosts (`src/p2p/vpn.rs`; needs ambient `CAP_NET_ADMIN`). The
listener is the tunnel **server** (`run_server`: a minimal `ProxyContext` + TUN,
runs `server::handle_connection` over the inner conn, assigns from
`--vpn-subnet`, default `10.9.0.0/24`); the connector is the **client**
(`run_client`: `TunnelClient::over_connection` — the h3 client over an existing
`quinn::Connection` — + TUN). The client **scopes the tunnel to the VPN subnet**
(`--vpn-subnet` as the flow scope, §8.3) so the server advertises only that
route — a full/default tunnel would capture the peer connection's own transport
and dead-lock it. It rides whichever path the `Session` picked (relay or
punched). `scripts/vpn-test.sh` is the netns proof: two peers, relay in the
middle, ping across the tunnel.

**The punch reuses the outer bind socket** (`peer::listen`/`connect` expose
`punch_endpoint`, the real UDP socket whose NAT mapping the relay observed as
this peer's reflexive; `coordinate` sets the pinned punch server config on it
and dials the peer from it). So the punch source equals the advertised
reflexive on an endpoint-independent (cone) NAT — no more port prediction. A
fresh socket got a different, unadvertised mapping; the outer socket does not,
because endpoint-independent NATs keep one external port per socket across
destinations.

`scripts/nat-punch-test.sh` is the netns double-NAT harness
(`peerA─natA══relay══natB─peerB`) with two NAT modes, both asserting payload
crosses the double NAT both ways:
- `NAT_MODE=symmetric` (default) — MASQUERADE. Linux's PAT is endpoint-
  DEPENDENT here: it maps the one outer socket to a different external port per
  destination, so the punch is blocked and the relay carries the data
  (best-effort, not asserted). Confirmed by tcpdump.
- `NAT_MODE=cone` (`sudo NAT_MODE=cone …`) — a stateless 1:1 NETMAP:
  endpoint-independent (full-cone) mapping, so the outer-socket punch source
  equals the advertised reflexive and a **direct path is asserted**. The direct
  connection's remote is the peer's *public* address (not the relay), proving
  it bypasses the relay. NETMAP is the reliable way to get EIM in netns —
  conntrack PAT will not preserve a port across destinations even for a fixed
  source port; NETMAP, being stateless, bypasses it.

So real cone NATs (most home routers) punch with the outer-socket reuse alone.

**Symmetric-NAT strategies are selectable** with `strawcat --punch-strategy`
(`p2p::strategy::PunchStrategy`, threaded through `Session::start`'s
`PunchConfig` into `holepunch::coordinate`, which dispatches):
- `basic` (default) — outer-socket reuse; cone NATs.
- `predict` — sample the NAT by opening a few back-to-back aux bind sessions,
  classify the allocation (`classify`), and for a *sequential* allocator
  advertise a predicted peer-facing port range. Sequential-symmetric NATs only;
  a random allocator falls through to the relay. Pure logic is unit-tested.
- `birthday` — open several punch sockets and dial a scan window around every
  peer candidate (`scan_around`), first mutually-open pair wins. A fixed-dial
  birthday attack; feasible only for a narrow external-port range with enough
  sockets, so best-effort.
- `relay-assisted` — needs `--udp-bind-observe` on the relay (`CAP_NET_RAW`).
  An on-path `AF_PACKET` observer (`udp_bind::observe`) reads each peer's
  *peer-facing* source off the forwarded punch packets and signals it to the
  other peer as a PEER_REFLEXIVE capsule (0x15), which dials it.

`strawcat --port-map` (orthogonal to the strategy) asks the router for an
explicit PCP (RFC 6887) / NAT-PMP (RFC 6886) UDP forward (`p2p/portmap.rs`) and
advertises the mapped address as a `Mapped` candidate — the one approach that
*reliably* traverses a symmetric NAT, when the router supports it. Demonstrated
by `sudo PORTMAP=1 scripts/nat-punch-test.sh` (a `scripts/natpmp-stub.py`
responder installs a 1:1 iptables forward; the punch then succeeds through the
symmetric double NAT).

**Honest result: none of these traverse the netns MASQUERADE** — it is the
worst case (address-AND-port-dependent filtering *and* random per-destination
allocation). predict detects "random" and relays; birthday's window is far too
wide; relay-assisted observes and signals correctly (verified) but the sources
are a *moving target* — each new dial makes a new mapping, and Linux's strict
5-tuple reply filtering drops the response, so it never converges. This is the
textbook reason symmetric↔symmetric is the unsolved case and the relay carries
it. Each strategy targets an *easier* symmetric class (sequential allocation /
narrow port range / address-dependent filtering) that a real router may have.
Harness: `STRATEGY=<name>` (relay-assisted also sets `--udp-bind-observe`);
the punch stays best-effort in `symmetric` mode and asserted only in `cone`.

The standards-codepoint swap (§9) is still future work (gated on quinn
extension-frame / transport-param APIs and RFC publication), but **every
provisional codepoint now lives in one registry, `src/codepoints.rs`** — bind
capsule types 0x11–0x15, the `strawcat/1` ALPN, the `sc2_` token marker,
and the documented v2 NAT-traversal frame target — each annotated with its v2
standard and the gate; `udp_bind::context`, `p2p::token`, `p2p::inner_tls`
re-export from it, so the swap is a one-file edit. See
`p2p-direct-path-design.md` §9.

## Key RFCs

| RFC  | Role |
|------|------|
| 9484 | Core protocol (CONNECT-IP) |
| 9297 | HTTP Datagrams / Capsule Protocol |
| 9221 | QUIC DATAGRAM frames |
| 9000 | QUIC transport |
| 9114 | HTTP/3 |
