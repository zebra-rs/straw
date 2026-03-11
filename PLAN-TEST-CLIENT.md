# Straw: CONNECT-IP Test Client — Implementation Plan

## Approach

Build the client incrementally alongside the server — both need the same QUIC/H3 stack, and the client is the server's primary test harness. The existing capsule codec is fully reusable.

## File Structure

```
src/
  lib.rs              (NEW) — re-export capsule, error, uri_template as library
  main.rs             (MODIFY) — server binary
  bin/
    test_client.rs    (NEW) — test client binary
  tls.rs              (NEW) — shared TLS utilities (cert loading, self-signed generation)
tests/
  integration.rs      (NEW) — in-process server+client tests
```

## Implementation Steps

### Step 1: Convert to lib+bin crate, add dependencies

- `Cargo.toml`: add quinn, h3, h3-quinn, tokio (full), rustls (ring), rcgen, http, tracing, tracing-subscriber, clap
- `src/lib.rs`: re-export `pub mod capsule; pub mod error; pub mod uri_template;`
- `src/main.rs`: switch to `straw::*` imports

### Step 2: TLS utilities — `src/tls.rs`

- `generate_self_signed_cert()` → `(CertificateDer, PrivateKeyDer)` via rcgen
- `build_server_tls_config(cert, key)` → rustls ServerConfig with ALPN `h3`
- `build_client_tls_config_insecure()` → rustls ClientConfig that skips cert verify (testing)
- `build_client_tls_config_with_ca(ca_cert)` → trusts a specific CA

### Step 3: Minimal server skeleton — `src/server.rs`

Just enough to test the client: QUIC listener → h3 accept → respond 200 to Extended CONNECT with ADDRESS_ASSIGN + ROUTE_ADVERTISEMENT capsules on the stream.

### Step 4: Client QUIC + H3 connection — `src/bin/test_client.rs`

- CLI: `--server-addr`, `--server-name`, `--insecure`, `--ca-cert`
- quinn::Endpoint::client with DATAGRAM enabled
- h3 client builder: `.enable_datagram(true).enable_extended_connect(true)`
- Spawn h3 driver as background task
- **Key**: clone quinn::Connection before wrapping in h3-quinn (Connection is Arc-backed) — need the raw handle for DATAGRAM I/O

### Step 5: Extended CONNECT request

```
:method = CONNECT
:protocol = connect-ip  (via h3::ext::Protocol)
:path = /.well-known/masque/ip/*/*/
capsule-protocol = ?1
```

- Send via `send_request.send_request(req)`
- Verify 200 response with `capsule-protocol: ?1`

### Step 6: Receive and process capsules

- `stream.recv_data()` → decode via `straw::capsule::decode_capsule()`
- Store assigned addresses (from ADDRESS_ASSIGN) and routes (from ROUTE_ADVERTISEMENT) in client state

### Step 7: Send ADDRESS_REQUEST

- Encode via `encode_capsule()`, send via `stream.send_data()`
- Process response ADDRESS_ASSIGN

### Step 8: DATAGRAM I/O for IP packets

HTTP Datagram format: `Quarter Stream ID (VarInt) | Context ID (VarInt) | IP Packet`

- Quarter Stream ID = `stream.id() / 4`
- Context ID = 0 (full IP packet)
- Send via `quinn_conn.send_datagram()`, receive via `quinn_conn.read_datagram()`
- Reuses existing VarInt codec for framing

### Step 9: Synthetic IP packet construction

- Build minimal IPv4 ICMP echo requests using etherparse or hand-crafted bytes
- Source address must match ADDRESS_ASSIGN

### Step 10: Client state machine

- `tokio::select!` over: capsule stream reader, datagram receiver, periodic ping sender
- Log all events for debugging

### Step 11: Integration test harness — `tests/integration.rs`

- Spawn server on random port with self-signed cert
- Connect client, verify: handshake → 200 → ADDRESS_ASSIGN → ROUTE_ADVERTISEMENT → datagram round-trip

---

## Key Risks

1. **h3 Extended CONNECT API** — `:protocol` is set via `h3::ext::Protocol` (used by h3-webtransport). `"connect-ip".parse::<Protocol>()` should work but needs verification.
2. **DATAGRAM demuxing** — h3 may not expose HTTP Datagram API cleanly. Fallback: use quinn raw datagrams + manual Quarter Stream ID framing.
3. **Server dependency** — client can't be fully tested until server exists. Build both in lockstep: minimal server skeleton first (Step 3), then client.

## Suggested Build Order

Steps 1–2 (infra) → Step 3 (minimal server) → Steps 4–5 (client connects) → Steps 6–7 (capsules) → Steps 8–9 (datagrams) → Steps 10–11 (orchestration + integration tests)
