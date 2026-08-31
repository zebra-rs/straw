# Straw: RFC 9484 CONNECT-IP Proxy — Implementation Plan

## Dependency Graph

```
error.rs (leaf)
  └► capsule/codec.rs (VarInt, capsule framing)
       └► capsule/{address_assign,address_request,route_advertisement}.rs
            └► capsule/mod.rs (Capsule enum, dispatcher)
                 └► datagram/ (Context ID + HTTP Datagram wrapping)

uri_template.rs (leaf)
config.rs (leaf)
address_pool.rs (depends on capsule types)

forwarding/packet.rs (depends on capsule types, etherparse)
  └► forwarding/router.rs (ipnet, dashmap)
       └► forwarding/tun.rs (platform-specific, tokio)
            └► forwarding/mod.rs (orchestrates packet flow)

session/auth.rs (leaf)
  └► session/handler.rs (depends on capsule, datagram, forwarding, address_pool, uri_template)
       └► session/mod.rs (SessionManager with DashMap)

server.rs (depends on session, quinn, h3, h3-quinn)
  └► main.rs (depends on server, config)
```

---

## Phase 1: Foundation

### Step 1: Error Types — `src/error.rs`

- `DecodeError`: Underflow, InvalidIpVersion, InvalidPrefixLength, InvalidVarInt, BufferTooShort, TrailingBytes
- `ForwardingError`: MalformedPacket, SourceAddressViolation, TtlExpired, LinkLocalDrop, MtuExceeded, NoRoute
- `ProxyError`: top-level enum encompassing decode, forwarding, IO, HTTP, QUIC errors
- Use `thiserror` derive macros

### Step 2: VarInt Codec — `src/capsule/codec.rs`

- `read_varint` / `write_varint` / `varint_len` per RFC 9000 Section 16
- 2-bit length prefix (1/2/4/8 byte encodings), max value 2^62−1
- **Tests:** round-trip for boundary values (0, 63, 64, 16383, 16384, etc.), underflow on empty buffer

### Step 3: Capsule Type Definitions — `src/capsule/mod.rs`

- Constants: `CAPSULE_ADDRESS_ASSIGN=0x01`, `CAPSULE_ADDRESS_REQUEST=0x02`, `CAPSULE_ROUTE_ADVERTISEMENT=0x03`
- `Capsule` enum: `AddressAssign`, `AddressRequest`, `RouteAdvertisement`, `Unknown`
- Shared data structs: `AssignedAddress`, `RequestedAddress`, `IpAddressRange`

### Step 4: ADDRESS_ASSIGN — `src/capsule/address_assign.rs`

- Decode: loop over payload → request_id (VarInt), ip_version (u8), IP bytes (4 or 16), prefix_length (u8)
- Encode: type 0x01, computed length, serialized entries
- **Tests:** round-trip with mixed v4/v6, request_id=0 (unprompted) and nonzero

### Step 5: ADDRESS_REQUEST — `src/capsule/address_request.rs`

- Same wire format as ADDRESS_ASSIGN but type=0x02
- Validate: request_id MUST be nonzero, at least one entry required
- **Tests:** round-trip, reject request_id=0, reject empty list

### Step 6: ROUTE_ADVERTISEMENT — `src/capsule/route_advertisement.rs`

- Each range: ip_version, start_ip, end_ip, ip_protocol
- Validate ordering: `(ip_version, ip_protocol, start_ip)`, start ≤ end
- Sort on encode to guarantee invariant
- **Tests:** full-tunnel range, IPv6 ranges, ordering validation

### Step 7: Capsule Dispatcher — expand `src/capsule/mod.rs`

- `decode_capsule`: read type/length VarInts, dispatch to specific decoders, unknown types stored (not rejected per RFC 9297)
- `encode_capsule`: dispatch to specific encoders
- **Tests:** unknown capsule type preserved, multi-capsule buffer decode

### Step 8: URI Template Parser — `src/uri_template.rs`

- Parse `/.well-known/masque/ip/{target}/{ipproto}/`
- Target: `*` → None, IP/prefix → `Target::Prefix(IpNet)`, hostname → `Target::Hostname`
- ipproto: `*` → None, decimal → `Some(u8)`
- Handle percent-encoding
- **Tests:** wildcards, specific IPs, hostnames, invalid paths

---

## Phase 2: Tunnel Core

### Step 9: Add Dependencies to Cargo.toml

- quinn, h3, h3-quinn, tokio (full), rustls, bytes, etherparse, ipnet, dashmap, tracing, tracing-subscriber, clap, thiserror
- Platform-conditional: `tun` crate for Linux
- Pin compatible h3/h3-quinn/quinn versions (pre-1.0 ecosystem)

### Step 10: Configuration — `src/config.rs`

- `ServerConfig` struct matching design doc §10
- CLI args via clap derive: `--listen`, `--cert`, `--key`, `--config`
- Sensible defaults

### Step 11: TLS + QUIC/H3 Server Skeleton — `src/server.rs`

- Load TLS cert/key → rustls ServerConfig with ALPN `h3`
- Enable QUIC DATAGRAM frames in transport config
- quinn::Endpoint accept loop → spawn per-connection tasks
- h3::server::Connection from h3-quinn, accept requests
- Initially: log and respond 501 (tunnel handling in Step 17)

### Step 12: IP Packet Processor — `src/forwarding/packet.rs`

- Extract version, src/dst addr, protocol from raw IP packets
- Source address validation against assigned addresses
- TTL/Hop Limit decrement with IPv4 checksum recomputation
- Link-local traffic detection and drop
- **Tests:** raw packet construction, TTL=1 error, checksum verification

### Step 13: Route Table — `src/forwarding/router.rs`

- `RouteTable`: `RwLock<Vec<RouteEntry>>` + `DashMap<IpAddr, SessionId>` fast-path
- Install/remove session routes, longest-prefix match lookup
- **Tests:** multi-session lookup, longest-prefix match, removal

### Step 14: TUN Device — `src/forwarding/tun.rs`

- Create TUN with `IFF_TUN | IFF_NO_PI`, set MTU ≥ 1280
- Async read/write via `tokio::io::unix::AsyncFd`
- Abstract behind `TunInterface` trait for portability
- Linux and macOS (utun); see `src/forwarding/tun/`

### Step 15: Forwarding Engine — `src/forwarding/mod.rs`

- `ForwardingEngine` holding `Arc<TunDevice>` + `Arc<RouteTable>`
- `client_to_network`: validate → route check → TTL decrement → TUN write
- `network_to_client`: extract dst → route lookup → TTL decrement → return (session_id, packet)
- TUN reader background task dispatching to session channels

### Step 16: Datagram Handler — `src/datagram/mod.rs`, `src/datagram/context.rs`

- `IpProxyingDatagram`: context_id (u64) + payload (Bytes)
- Encode/decode with VarInt context_id prefix
- Phase 2: only context_id=0 (full IP packet)
- **Tests:** round-trip with synthetic payloads

### Step 17: Session Manager + CONNECT-IP Handler — `src/session/mod.rs`, `src/session/handler.rs`

- `SessionManager`: `DashMap<SessionId, TunnelSession>`
- `handle_connect_ip_stream`: validate Extended CONNECT → parse URI → create session → 200 OK → ADDRESS_ASSIGN → ROUTE_ADVERTISEMENT → install routes → forwarding loop (`tokio::select!` over DATAGRAM rx, TUN→client tx, capsule stream) → teardown

### Step 18: Main Entry Point — `src/main.rs`

- Parse config → init tracing → TLS → TUN → AddressPool → RouteTable → SessionManager → start server
- Graceful shutdown on SIGINT/SIGTERM

---

## Phase 3: Full Protocol

### Step 19: Address Pool — `src/address_pool.rs`

- BTreeSet pools for v4/v6, allocate specific or next-available, release on session teardown

### Step 20: IPv6 Dual-Stack

- Verify v6 handling in packet processor (extension headers, no checksum), address pool, capsule encode/decode

### Step 21: Split-Tunnel Routing

- Config: `split_routes` prefix list → scoped ROUTE_ADVERTISEMENT → selective route installation

### Step 22: Site-to-Site VPN

- Bidirectional ADDRESS_REQUEST/ADDRESS_ASSIGN and ROUTE_ADVERTISEMENT processing

### Step 23: ICMP Error Generation — `src/forwarding/icmp.rs`

- TTL expired → ICMP Time Exceeded, MTU exceeded → Packet Too Big, No route → Destination Unreachable
- Include invoking packet header+8 bytes, send back via tunnel

---

## Phase 4: Production Readiness

### Step 24: Authentication — `src/session/auth.rs`

- mTLS (quinn peer_identity), Bearer token, Basic auth; constant-time comparison

### Step 25: Rate Limiting

- Token bucket per session (packets/sec, bytes/sec); silent drop on exceeded

### Step 26: Idle Timeout + Session Cleanup

- Background scan, close idle sessions, release resources

### Step 27: NAT — `src/forwarding/nat.rs`

- iptables MASQUERADE rule on TUN outbound; IP forwarding sysctl

### Step 28: Metrics + Logging

- tracing structured logging, optional Prometheus metrics endpoint

### Step 29: Graceful Shutdown

- SIGINT/SIGTERM → stop accepting → GOAWAY → wait/timeout → cleanup

---

## Phase 5: Advanced (Ongoing)

### Step 30: IP Flow Forwarding (RFC 9484 §8.3)

- Scoped tunneling: `{target}` = specific IP, `{ipproto}` = specific protocol number
- Only forward packets matching the scope
- Multiple concurrent sessions per client with different scopes

### Step 31: Configuration File Support (TOML)

- Full TOML parsing for the config format in design doc §10
- CLI args override config file values

### Step 32: Performance Optimizations

- `recvmmsg`/`sendmmsg` for TUN I/O batching
- Pre-allocated buffer pools (avoid per-packet allocation)
- Consider `io_uring` via `tokio-uring` for Linux 5.10+
- DSCP copying from inner to outer headers
- Zero-copy path: read from TUN directly into DATAGRAM buffer

### Step 33: QUIC-Aware Proxying

- draft-ietf-masque-quic-proxy support — **scoped, deliberately not started**;
  see `docs/quic-aware-proxying.md`. The draft has been in WG last call since
  2025-11 and its IANA section says the capsule codepoints will be replaced
  before publication; there is no public implementation to interoperate with.
  The CID-awareness half would be a bounded piece of work when that settles;
  forwarded mode additionally needs path-validation and migration events that
  quinn does not expose.
- Multi-path QUIC integration — the inner P2P connection already runs on noq
  native multipath (`p2p-direct-path-design.md` §0). Multipath for the *proxy*
  data plane is untouched, and `bench/BASELINE.md` shows extra connections do
  not raise throughput, so it is not a performance argument.

---

## Key Risks

1. **h3 crate API instability** — pre-1.0, Extended CONNECT and DATAGRAM APIs may be incomplete. May need to fork or use lower-level quinn APIs.
2. **DATAGRAM demuxing** — QUIC DATAGRAMs are connection-level; Quarter Stream ID maps to H3 streams. Verify h3 exposes this or implement manually.
3. **TUN portability** — done for Linux and macOS: `forwarding/tun/` splits per platform behind one `spawn_tun` contract. What remains for a usable macOS client is `iface.rs` (ifconfig/route instead of ip(8)) and, for the proxy, pf instead of iptables.
4. **Root privileges** — TUN creation needs CAP_NET_ADMIN. Document and consider fd-passing.
5. **MTU calculation** — Tunnel MTU = QUIC max_datagram_size − overhead. Must be ≥ 1280 for IPv6. Validate at session setup.
