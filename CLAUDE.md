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
on it), `strawcat` (P2P peer: `genkey`/`listen`/`connect`).

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
private/single-host relays (design §10.1). This is P1 (relay path); hole
punching (P2, §5–6) and the standards-codepoint swap (§9) are future work.
Everything provisional (bind capsule types 0x11–0x13, token format) is
isolated for that swap. See `p2p-direct-path-design.md`.

## Key RFCs

| RFC  | Role |
|------|------|
| 9484 | Core protocol (CONNECT-IP) |
| 9297 | HTTP Datagrams / Capsule Protocol |
| 9221 | QUIC DATAGRAM frames |
| 9000 | QUIC transport |
| 9114 | HTTP/3 |
