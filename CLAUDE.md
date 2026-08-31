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

**Inner QUIC stack = noq.** The peer↔peer inner connection runs on **noq** (the
n0/iroh quinn fork), adopted for its native NAT traversal + multipath +
extension-frame APIs (branch `feature/adopt-iroh-quinn`; see
`p2p-direct-path-design.md` §0). The **outer** bind session, the proxy, and
CONNECT-UDP stay on upstream quinn + h3-quinn; `RelaySocket` bridges the two.
All three stages are done: Stage 1 (inner conn on noq), Stage 2 (VPN over noq
via the `p2p/h3_noq` adapter + a transport-agnostic CONNECT-IP data plane) and
Stage 3 (the direct path on noq native multipath, replacing the app-level
punch). The v1 punch modules (`holepunch`, `punch`, and `candidates`/`wire`'s
control messages) are off the data path — kept as the reference for the
symmetric-NAT strategies, which are not ported (see below).

`strawcat` peers form a mutually SPKI-pinned inner QUIC connection through a
straw relay running CONNECT-UDP **bind mode** (`--udp-bind`, off by default,
auth mandatory), which forwards only ciphertext (design goal G1). Layers:
`udp_bind/` is the relay's bind side (per-session public (IP,port) allocation,
compression-context codec, encap/decap socket loop, connect-udp handler);
`p2p/identity` + `p2p/token` are the trust model (Ed25519 SPKI pin, `sc2_`
CBOR token); `p2p/relay_socket` runs an inner **`noq::AsyncUdpSocket`** over a
bind session (holding the outer `quinn::Connection` — the bridge); `p2p/inner_tls` is RFC 7250 raw-public-key mTLS pinned by SPKI;
`p2p/peer` orchestrates listen/connect. The egress SSRF guard always denies
loopback/RFC1918/etc.; `--udp-bind-allow-dest` re-permits ranges for
private/single-host relays (design §10.1).

**The direct path is a second path of the *same* connection** (Stage 3), not a
second connection. `p2p/relay_socket::PathMuxSocket` is one
`noq::AsyncUdpSocket` carrying both: sends whose destination is a known *relay*
remote are tunnelled through the outer bind session, and **everything else goes
out a real UDP socket**. Direct-by-default is what lets noq's own NAT-traversal
probes work — they target candidates the application never sees, so they cannot
be registered in advance, but they are never a relay-paddr. The dialer presets
the peer's paddr (its first packet must be tunnelled); the acceptor learns it
from the packet it answers.

`p2p/native_punch` drives the punch over noq's **NAT-traversal frames**
(`add_nat_traversal_address` / `initiate_nat_traversal_round`, enabled by
`max_remote_nat_traversal_addresses`): the inner server advertises its
candidates in ADD_ADDRESS, the client advertises its own in REACH_OUT and
probes, and noq opens the validated path itself. Candidate exchange at the QUIC
layer — not on an application stream — is what makes **VPN mode punch**: its
inner protocol is h3, which would read an app-level exchange stream as a
request. This was the reason the v1 exchange had to go.

`p2p/session` is the `Relay→Punching→Direct` state machine. A traversal-opened
path arrives as `PathStatus::Backup`, so the session **promotes** it to
`Available` and demotes path 0 — after which noq schedules data on the direct
path and holds the relay path idle as the permanent fallback (G3, never
closed). On `PathEvent::Abandoned` it restores path 0 and re-punches after 30 s.
Nothing above the connection moves across the transition, so streams in flight
keep working. `Session::direct_remote()` reports the peer address that won,
which `strawcat` prints (`path: direct (hole punched, peer <addr>)`) and both
netns harnesses assert on — a relay address there would mean the path is not
direct.

**Inner MTU is pinned to 1200 with MTU discovery OFF**
(`p2p/peer::relay_transport`). Each inner QUIC packet on the *relay* path is
re-wrapped as one outer QUIC DATAGRAM, so the inner MTU must fit inside it;
path-MTU discovery would probe past that ceiling and those oversize packets
fail `send_datagram`, stalling the connection *after* the handshake. This only
bites once packets exceed ~1200 B, so small-payload tests miss it —
`relay_path_carries_a_large_transfer` guards it with a 256 KiB transfer. MTU
discovery is a connection-wide setting in noq, so the *direct* path is capped
at 1200 too even though a real socket could carry more — correct but
conservative, and worth revisiting if per-path discovery lands.

`pipe_stdio` in `strawcat` awaits **both** directions (never aborts the
upload): aborting drops the `SendStream` unfinished, which quinn turns into a
stream reset that discards buffered bytes the peer never sees.

**VPN mode (P3)** — `strawcat --vpn` runs straw's own RFC 9484 CONNECT-IP stack
over the peer connection instead of piping stdio, giving a real IP tunnel
between the two hosts (`src/p2p/vpn.rs`; needs ambient `CAP_NET_ADMIN`). The
listener is the tunnel **server** (`run_server`: a minimal `ProxyContext` + TUN,
serves CONNECT-IP/h3 over the **noq** peer connection via the `p2p/h3_noq`
adapter + its own datagram demux, assigns from `--vpn-subnet`, default
`10.9.0.0/24`); the connector is the **client** (`run_client`:
`TunnelClient::over_noq_connection` — the h3 client over the existing
`noq::Connection` — + TUN). The CONNECT-IP data plane is transport-agnostic (a
`datagram::DatagramConn` send seam + a stream-generic server handler); proven in
netns by `scripts/vpn-test.sh`. The client **scopes the tunnel to the VPN subnet**
(`--vpn-subnet` as the flow scope, §8.3) so the server advertises only that
route — a full/default tunnel would capture the peer connection's own transport
and dead-lock it. It rides whichever path the `Session` picked, and since
Stage 3 that is normally the **direct** one — `scripts/vpn-test.sh` asserts the
tunnel runs over a path to the peer's own address, then pings across it.

**This peer's candidate is (relay-observed public IP, direct socket port).**
The relay observes the *outer* bind socket's source, so only its IP is reused;
the port comes from the mux's direct socket. That is exact on a port-preserving
(full-cone / NETMAP / explicitly forwarded) NAT, which is the class the punch
targets. `--port-map` adds a PCP/NAT-PMP-forwarded address as a second
candidate, and that one holds even on a symmetric NAT.

**`strawcat --direct` (`p2p::strategy::DirectMode`) picks what is offered:**
- `reflexive` (default) — the public address only.
- `full` — also the **host** candidate, the local interface address, so two
  peers on one LAN (or behind one NAT, where hairpinning often fails) connect
  locally. It discloses a private address to the peer, hence opt-in (§10.3).
  The address comes from `native_punch::host_ip`: a *connected* UDP socket
  toward the relay, which performs the route lookup without sending anything —
  the mux socket is wildcard-bound and so cannot report it.
- `off` — never punch; pin the session to the relay path.

`candidates()` assembles and de-duplicates the set (mapped, then reflexive,
then host), dropping unspecified addresses; behind no NAT the host and
reflexive addresses coincide and only one slot is spent. Harness: `DIRECT=<mode>
sudo scripts/nat-punch-test.sh` — `off` is asserted not to punch even in cone
mode, where it otherwise would.

`scripts/nat-punch-test.sh` is the netns double-NAT harness
(`peerA─natA══relay══natB─peerB`) with two NAT modes, both asserting payload
crosses the double NAT both ways:
- `NAT_MODE=symmetric` (default) — MASQUERADE. Linux's PAT is endpoint-
  DEPENDENT here: it maps a socket to a different external port per
  destination, so the advertised candidate is wrong and the relay carries the
  data (best-effort, not asserted).
- `NAT_MODE=cone` (`sudo NAT_MODE=cone …`) — a stateless 1:1 NETMAP:
  endpoint-independent (full-cone) mapping, so the advertised candidate is
  reachable and a **direct path is asserted**, including that each side's path
  leads to the peer's *public* address (not the relay) — the proof it bypasses
  the relay. NETMAP is the reliable way to get EIM in netns — conntrack PAT
  will not preserve a port across destinations even for a fixed source port;
  NETMAP, being stateless, bypasses it.

So real cone NATs (most home routers) punch with the reflexive candidate alone.

**Symmetric-NAT strategies are NOT ported to the native punch.**
`--punch-strategy` other than `basic` logs a warning and punches basically.
They worked by dialling extra addresses from extra sockets, and the frame
exchange only carries a peer's *own* candidates — a peer cannot inject a
predicted port range, a scan window, or a source the relay observed for the
*other* peer. `--port-map` is orthogonal and unaffected. The v1 code and the
notes below are kept for whoever revisits this:
- `basic` (default) — advertise the reflexive candidate; cone NATs.
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

`strawcat --stun-detect <server>` runs RFC 5780 NAT-behaviour discovery
(`p2p/stun.rs`) against the relay's dual-address STUN server (`straw
--stun-addr/--stun-alt-addr`, four UDP sockets on two IPs) to classify the NAT
(endpoint-independent / address-dependent / address-and-port-dependent) *before*
punching — so a symmetric verdict skips the futile punch and goes to --port-map
or the relay.

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

The standards-codepoint swap (§9) is **done for the NAT-traversal half**: the
app-level CBOR candidate exchange and the raced second connection are gone,
replaced by noq's frames, the `nat_traversal` transport param and multipath.
What remains gated is RFC publication of the listen-draft codepoints, and the
OBSERVED_ADDRESS capsule (the outer session is still upstream quinn). **Every
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
