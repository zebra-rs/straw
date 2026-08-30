# Straw P2P Direct Path — Design

Status: **P1 in progress** (trust model landed: `src/p2p/{identity,token}.rs`) · Depends on: `rfc9484-proxy-design.md` (Phases 2–3), `PLAN-TEST-CLIENT.md` · Date: 2026-08-30

This document designs the peer-to-peer extension to straw: two "strawcat" peers that today would exchange packets by hairpin-forwarding through a straw relay upgrade to a **direct, end-to-end encrypted QUIC connection**, keeping the relay as rendezvous and fallback. It closes the two gaps identified against tailcat: (1) the relay sees tunneled plaintext, and (2) the relay stays in the data path forever.

The design deliberately lands the two fixes in separate phases: end-to-end encryption **through** the relay first (P1), the direct path second (P2). P1 alone already changes the trust model — the relay becomes an untrusted UDP forwarder, like DERP.

---

## 1. Overview

### 1.1 Goals

- **G1 — E2E privacy:** the relay must not be able to read traffic between two strawcat peers (today it terminates TLS and sees inner IP packets).
- **G2 — Direct path:** peers behind NATs upgrade to a direct QUIC connection via coordinated hole punching; relay bandwidth is only spent when punching fails.
- **G3 — Relay as permanent fallback:** the relay session is never torn down while the pipe is live; path failure falls back transparently.
- **G4 — Standards trajectory:** wire formats are isolated so we can converge on the IETF drafts as they finalize, without breaking deployed tokens.

### 1.2 Non-Goals

- Full ICE (RFC 8445). We implement the minimal ICE-inspired subset the QUIC NAT traversal draft describes.
- Replacing relay mode. RFC 9484 CONNECT-IP relay mode (the core of straw) remains the default and the fallback.
- Mesh/multi-peer topologies. This design is pairwise; N peers = N pairwise upgrades.

### 1.3 Building Blocks

| Spec | Status (2026-08) | Role here |
|------|------------------|-----------|
| RFC 9298 (CONNECT-UDP) | RFC | Base UDP proxying request the bind extension rides on |
| draft-ietf-masque-connect-udp-listen-16 | WG draft, near last call | Relay allocates a public (IP, port) per peer; forwards UDP to/from arbitrary remotes — the TURN-equivalent |
| draft-seemann-quic-nat-traversal-02 | Individual draft | ADD_ADDRESS / PUNCH_ME_NOW / REMOVE_ADDRESS frames; coordinated punching + migration (v2 target) |
| draft-ietf-quic-address-discovery-00 | WG draft | OBSERVED_ADDRESS frame — reflexive address discovery without STUN (v2 target) |
| RFC 7250 raw public keys / self-signed + SPKI pin | RFC | Peer identity on the inner connection (WireGuard-pubkey equivalent) |

**Draft-risk stance:** codepoints in the listen draft (header `connect-udp-bind`, capsules 0x11–0x13) and the NAT-traversal draft (transport param 0x3d7e9f0bca12fea6, frames 0x3d7e90..94) are provisional. All of them live behind `p2p::wire` (§9) and a token version field (§4.2).

---

## 2. Architecture

Both peers are MASQUE **clients** of the straw relay (outbound-only, NAT-friendly). Between themselves they form one **inner QUIC connection**, end-to-end encrypted, whose packets initially ride through the relay as proxied UDP and later switch to the direct path.

```
              ┌───────────────────────────┐
              │        straw relay        │
              │  CONNECT-UDP + bind ext.  │
              │  (sees only inner-QUIC    │
              │   ciphertext)             │
              └─────▲───────────────▲─────┘
        outer QUIC #1│               │outer QUIC #2
     (CONNECT-UDP,   │               │
      bind, capsules)│               │
              ┌──────┴─────┐   ┌─────┴──────┐
              │  strawcat  │   │  strawcat  │
              │   peer A   │   │   peer B   │
              └──────┬─────┘   └─────┬──────┘
                     │    inner QUIC │
                     └───────────────┘
              Phase B: via relay (proxied UDP)
              Phase D: direct path after hole punch
              (relay path kept as fallback)
```

### 2.1 Connection Roles

- **Outer connections** (peer ↔ relay): standard QUIC + HTTP/3, Extended CONNECT with `:protocol = connect-udp` and the bind extension. Authenticated to the relay (Bearer / mTLS per `rfc9484-proxy-design.md` §11.3).
- **Inner connection** (peer ↔ peer): QUIC with mTLS, both sides pinned by SPKI hash from the token. Role tie-break: the peer with the lexicographically **lower** SPKI SHA-256 acts as inner-QUIC *client*; the other acts as *server*. (The NAT-traversal draft assigns asymmetric duties to client/server, so the tie-break must be deterministic.)
- **Inner protocol**, negotiated by ALPN on the inner connection:
  - `strawcat/1` — raw QUIC streams/datagrams. stdio pipes, port forwarding, SOCKS map to native QUIC streams. No IP layer, no netstack. Default.
  - `h3` + CONNECT-IP — the inner server runs straw's own RFC 9484 stack; full IP tunnel between peers (VPN semantics). Reuses `capsule/`, `datagram/`, `forwarding/` verbatim. Phase P3.

### 2.2 Lifecycle Phases

```
A  Rendezvous     both peers open CONNECT-UDP-bind sessions; relay
                  allocates public (IP,port) per peer; tokens exchanged
B  E2E via relay  inner QUIC handshake peer↔peer through the relay;
                  relay downgraded to ciphertext forwarder      [fixes G1]
C  Hole punch     candidates exchanged INSIDE the inner conn;
                  coordinated simultaneous open on direct path
D  Direct         traffic on direct path; relay session idles as
                  fallback; keepalives maintain the NAT binding  [fixes G2]
```

Failure at C leaves the pipe on the relay path — functionally identical to P1-only operation.

---

## 3. Phase A — Rendezvous

### 3.1 Bind Session Establishment

Each peer sends Extended CONNECT with `:protocol = connect-udp`, URI template variables `target_host = *`, `target_port = *` (percent-encoded `%2A`), and header `connect-udp-bind: ?1`. The relay:

1. Allocates a public (IP, port) tuple for the session and binds a UDP socket to it.
2. Answers 200 with `connect-udp-bind: ?1` and `proxy-public-address: "192.0.2.45:54321", "[2001:db8::1]:54321"`.
3. Forwards any UDP arriving on that tuple to the peer, and any proxied datagram from the peer out of that tuple.

The peer then registers an **uncompressed context** (client-allocated even Context ID, first = 2) via `COMPRESSION_ASSIGN` so datagrams carry explicit remote addresses:

```
COMPRESSION_ASSIGN Capsule {          Uncompressed HTTP Datagram Payload {
  Type (i) = 0x11,                      Context ID (i) = 2,
  Length (i),                           IP Version (8),        // 4 or 6
  Context ID (i),                       IP Address (32..128),
  IP Version (8) = 0,  // uncompressed  UDP Port (16),
}                                       UDP Payload (..),
                                      }
```

`COMPRESSION_ACK (0x12)` confirms; `COMPRESSION_CLOSE (0x13)` retires a context. Closing the uncompressed context turns the relay into a firewall that only forwards for explicitly registered (compressed) remotes — used after Phase D to shrink the attack surface (§10.4).

### 3.2 Token v2

The connection token becomes the capability that carries everything a peer needs to find and authenticate the other. CBOR map, base64url, prefix `sc2_`:

```
Token v2 {
  v:      2,                      // format version
  relay:  "h3://relay.example:443",
  rpin:   h'…',                   // relay cert SPKI SHA-256 (replaces WebPKI)
  auth:   "…",                    // relay bearer credential (scoped, short TTL)
  ppin:   h'…',                   // issuing peer's inner-TLS SPKI SHA-256
  paddr:  "192.0.2.45:54321",     // issuer's proxy-public-address (may repeat per family)
  exp:    1756600000,             // expiry (unix seconds)
}
```

`ppin` is the WireGuard-pubkey analogue: possession of the token lets the holder *reach and verify* the issuer; the issuer verifies the holder's SPKI on the inner handshake (mTLS) — first-connect pin-on-first-use by default, or pre-shared via an out-of-band holder pin embedded when the issuer knows its peer.

---

## 4. Phase B — End-to-End QUIC Through the Relay

> **Status:** transport landed — `src/p2p/relay_socket.rs` runs an inner QUIC
> endpoint over a bind session (`RelaySocket: quinn::AsyncUdpSocket` via
> `Endpoint::new_with_abstract_socket`); an integration test handshakes a
> peer↔peer connection and round-trips a stream through the relay. Inner TLS
> is RFC 7250 raw-public-key mTLS pinned by SPKI (`src/p2p/inner_tls.rs`):
> each peer presents its identity's public key and verifies the other's
> against an expected pin (`ppin`) or trust-on-first-use, a wrong pin failing
> the handshake closed — all covered by integration tests. On a constrained
> real path the outer
> `initial_mtu` may need raising so the first inner Initial (≥1200 B) fits the
> outer datagram (the §12 MTU-squeeze risk); loopback is unaffected.

The dialing peer (token holder) sends the inner QUIC Initial as a proxied datagram on the uncompressed context, addressed to the issuer's `paddr`. The issuer receives it with the dialer's *relay-allocated* source tuple attached, and replies the same way. From the inner QUIC stack's point of view, the relay path is just a UDP path with ~40–60 bytes less MTU.

- **TLS:** mTLS with RFC 7250 raw public keys (preferred; smallest) or self-signed certs; each side verifies the other's SPKI SHA-256 against the pin. No CA, no hostname.
- **The trust win lands here:** the relay forwards inner-QUIC ciphertext it cannot decrypt. Straw's relay role becomes equivalent to DERP — G1 is met before any hole punching exists.
- **MTU (§11.4 of the core design applies):** inner Initials require ≥ 1200-byte UDP payloads. Overheads on the relay path: uncompressed addressing (1 + 4/16 + 2 bytes) + Context ID varint + HTTP/3 datagram framing + outer QUIC. The relay MUST advertise `max_datagram_frame_size` large enough to carry ≥ 1280 bytes of inner payload on a 1500-MTU path; inner endpoints clamp `max_udp_payload_size` ≈ outer capacity − 25 and rely on outer-path DPLPMTUD.
- **Double congestion control:** inner and outer QUIC CCs stack on the relay path. Known MASQUE issue; acceptable because the relay path is meant to be short-lived or low-volume. Do not attempt CC-disable hacks in v1; revisit if P2 punch-failure rates keep long-lived traffic on the relay.

---

## 5. Phase C — Address Discovery and Hole Punching

### 5.1 Candidate Gathering

Each peer gathers, in priority order (ICE-style, host > reflexive > relay):

1. **Host candidates** — local interface addresses. Leaks LAN topology to the peer; gated by `--direct=full` vs. the default `--direct=reflexive` (§10.3).
2. **Server-reflexive candidate** — the source (IP, port) of the peer's *outer* connection as seen by the relay. v1: the relay reports it in a vendor capsule on the bind session (we control both ends, no STUN needed):

```
OBSERVED_ADDRESS Capsule (vendor, provisional codepoint from the
                          RFC 9297 private-use space) {
  Type (i) = TBD,
  Length (i),
  IP Version (8),
  IP Address (32..128),
  UDP Port (16),
}
```

   v2 replaces this with draft-ietf-quic-address-discovery `OBSERVED_ADDRESS` frames on the outer connection once quinn supports it.
3. **Relay candidate** — the `paddr` tuple; always present, already validated (it *is* the Phase B path).

### 5.2 Candidate Exchange — Inside the Inner Connection

Candidates travel on inner-connection control stream 0 as CBOR messages, private to the two peers (the relay never sees them):

```
ADDRESS_CANDIDATE { seq, ip, port, kind: host|reflexive }   // mirrors ADD_ADDRESS
PUNCH { round, pairs: [(local_seq, remote_seq), ...] }      // mirrors PUNCH_ME_NOW
CANDIDATE_RETIRE { seq }                                    // mirrors REMOVE_ADDRESS
```

This is the v1 stand-in for the NAT-traversal draft's QUIC frames, chosen because **quinn has no extension-frame API today** (§12). Semantics are kept 1:1 with the draft — inner *server* offers addresses, inner *client* pairs them with its own and initiates rounds, a higher `round` cancels outstanding probes, and pair count per round respects a concurrency limit (default 4) — so the v2 swap is mechanical.

### 5.3 Punching — Coordinated Simultaneous Open

v1 does **not** migrate the existing inner connection (client-side path probing to a *new remote address* is not exposed by quinn either). Instead, DCUtR-style:

1. Inner client sends `PUNCH { round, pairs }` and immediately dials a **second QUIC connection** (same certs, same ALPN, `probe=1` in ALPN suffix or transport-level marker) from a fresh UDP socket toward each paired remote candidate.
2. Inner server, on receiving `PUNCH`, immediately sends UDP toward the client's paired candidates (its own dial attempts, staggered ~50 ms). Both directions transmitting is what opens the NAT bindings; whichever handshake completes wins.
3. Both sides pin-verify the probe connection exactly as in Phase B. A completed probe = validated direct path.
4. Tie-break on duplicate success (both dials complete): keep the connection whose client role matches the §2.1 tie-break; close the other with a no-error code.

**Round policy:** round 1 = reflexive×reflexive pairs; round 2 (+300 ms) = host pairs (LAN-adjacent peers); round 3 (+1 s) = cross pairs. Give up after 5 s / 3 rounds → stay on relay; retry with exponential backoff (min 30 s) only while traffic is flowing.

**Failure modes accepted:** endpoint-dependent ("symmetric") NAT on both sides will fail and stay on relay — same residual case tailcat has. Port-mapping protocols (PCP / NAT-PMP / UPnP) are a P3 enhancement that rescues part of this class.

---

## 6. Phase D — Path Management

State machine per peer pair:

```
        punch requested        probe validated
 RELAY ─────────────────► PUNCHING ─────────────► DIRECT
   ▲                          │                      │
   │      timeout (5 s /      │                      │  PTO storm /
   │      3 rounds)           │                      │  keepalive loss
   └──────────────────────────┘                      │
   ▲                                                 │
   └─────────────────────────────────────────────────┘
                 fallback (relay session never closed)
```

- **Switchover:** new application streams open on the direct connection; streams in flight on the relay-path connection drain there (both connections share app-level session state in `p2p::mod`). strawcat's pipe use-case makes this trivial — hold stdio data for the ≤ 5 s punch window at startup, then all bytes take the winning path.
- **Keepalives:** direct path sends QUIC PING every 20 s (NAT UDP bindings commonly expire at 30 s). The idle relay path needs only the outer connection's keepalive (quinn `keep_alive_interval`, 15 s) — the bind allocation at the relay must outlive quiet periods.
- **Failure detection:** consecutive PTOs or 2 missed keepalive intervals on the direct path → mark DIRECT dead, shift new traffic to the relay path, re-enter punch backoff.

---

## 7. Relay-Side Changes (straw server)

CONNECT-UDP is a sibling of CONNECT-IP and reuses the existing capsule codec, datagram plumbing, and session manager.

```
src/
├── udp_bind/
│   ├── mod.rs        # connect-udp + bind request handling, Proxy-Public-Address
│   ├── context.rs    # COMPRESSION_ASSIGN/ACK/CLOSE, context table (even/odd rule)
│   ├── socket.rs     # per-session bound UDP socket, encap/decap rewrite loop
│   └── alloc.rs      # public (IP, port) allocation (extends address_pool concepts)
```

Behavioral requirements:

1. **Allocation:** one (IP, port) per bind session from a configured public range; stable for the session lifetime; per-family stability when dual-stack.
2. **Rewrite loop:** socket→session: prepend (Context ID, ver, addr, port) per registered contexts; session→socket: strip and send. Compressed contexts skip the address bytes.
3. **Firewall semantics:** with the uncompressed context closed, drop inbound from unregistered remotes.
4. **Abuse controls (this makes straw an open UDP relay — treat accordingly):** bind mode requires authentication *always* (no anonymous mode); per-session pps + bandwidth caps; per-destination rate caps on outbound; allocation TTL bound to outer-connection liveness. See §10.
5. **Vendor OBSERVED_ADDRESS capsule** (§5.1) emitted once on session open and again whenever the observed 4-tuple changes (client rebind/migration).

Config additions to `masque-proxy.toml`:

```toml
[udp_bind]
enabled = true
public_ips = ["192.0.2.45"]        # allocation pool
port_range = [32768, 60999]
max_sessions_per_client = 4
session_bandwidth_limit = "50Mbps" # relay-path cap; direct path is unmetered by us
```

## 8. Peer-Side Changes (strawcat)

```
src/
├── p2p/
│   ├── mod.rs         # pair session orchestration, path state machine (§6)
│   ├── token.rs       # token v2 encode/decode/expiry (CBOR)
│   ├── identity.rs    # keypair persistence (ephemeral | saved), SPKI pinning
│   ├── candidates.rs  # gathering: ifaces + OBSERVED_ADDRESS capsule
│   ├── punch.rs       # rounds, pairing, simultaneous open, tie-breaks
│   └── wire.rs        # ALL provisional codepoints + v1 CBOR control messages
```

The inner-connection TLS identity mirrors tailcat's key model: ephemeral in-memory keypair by default, `strawcat genkey` for a persistent identity (stable `ppin` across restarts).

## 9. Wire-Format Isolation and the v2 Standards Path

Everything provisional lives in one constant table — the `crate::codepoints` registry — with each item annotated with its v2 target and gate; `p2p::wire`, `udp_bind::context`, `p2p::token` and `p2p::inner_tls` re-export from it. The v2 migration, when the ecosystem is ready, swaps:

| v1 (this design) | v2 (standards) | Gate |
|---|---|---|
| CBOR `ADDRESS_CANDIDATE` / `PUNCH` / `CANDIDATE_RETIRE` on inner stream 0 | ADD_ADDRESS / PUNCH_ME_NOW / REMOVE_ADDRESS frames (0x3d7e90..94), transport param `nat_traversal` | quinn extension-frame + custom-transport-param API |
| Race second connection, app-level switchover | Path validation + connection migration of the single inner connection | quinn client-side probing of new remote paths |
| Vendor OBSERVED_ADDRESS capsule on outer session | draft-ietf-quic-address-discovery OBSERVED_ADDRESS frame | same quinn gate |
| listen-draft codepoints as of -16 | final RFC codepoints | RFC publication |

Tokens carry `v`, so old and new peers fail cleanly, never confusingly.

## 10. Security Considerations

1. **Amplification / relay abuse.** The bind extension lets an authenticated client aim UDP at arbitrary Internet hosts. Mitigations: auth mandatory; egress pps/bandwidth caps (§7.4); response-size accounting per unvalidated destination (≤ 3× until return traffic proves liveness); destination denylist (RFC 1918, relay's own ranges) unless explicitly configured. The NAT-traversal draft's own amplification section is still TODO — our caps must not assume the draft solves it.
2. **Punch storms.** Cap probe pps per round; concurrency limit 4 pairs; rounds are client-initiated only and rate-limited by the inner server's acceptance.
3. **Candidate privacy.** Host candidates reveal LAN addresses to the peer (not to the relay — exchange is E2E). Default `--direct=reflexive`; `--direct=full` opts into host candidates; `--direct=off` pins to relay.
4. **Post-upgrade lockdown.** After DIRECT is stable, close the uncompressed context and register the peer's tuple compressed — the relay then drops all other inbound (firewall semantics), and re-opening costs one capsule round-trip on fallback.
5. **Token hygiene.** Tokens are bearer capabilities: short `exp` by default (24 h), relay credential scoped to bind-mode only, no relay-side account linkage. Revocation = relay credential revocation.
6. **Identity.** SPKI pinning gives WireGuard-equivalent peer identity. Pin-on-first-use is the default UX; security-sensitive callers pre-exchange holder pins.

## 11. Implementation Phases

| Phase | Scope | Depends on | Size |
|-------|-------|-----------|------|
| P0 | Core relay + strawcat client (existing PLAN Phases 2–3 + smoltcp client + hairpin forwarding) | — | already planned |
| P1 ✅ **complete** | `udp_bind/` at relay **(done: `udp_bind/{context,alloc,socket,handler}.rs` + `:protocol` dispatch + demux routing; relays UDP end to end)**; token v2 **(done: `p2p/token.rs`)**; peer identity + SPKI pinning **(done: `p2p/identity.rs`)**; inner QUIC through relay (Phase A+B); `strawcat/1` ALPN pipes | P0 | ~2–3 weeks |
| P2 | OBSERVED_ADDRESS capsule; candidates, punch, path state machine (Phase C+D) | P1 | ~2–3 weeks |
| P3 | Inner CONNECT-IP **(VPN mode done: `strawcat --vpn`, `src/p2p/vpn.rs`)**; PCP/NAT-PMP **(done: `strawcat --port-map`, `p2p/portmap.rs`)**; v2 standards swap as gates clear | P2 | open-ended |

P1 ships user-visible value on its own (E2E privacy; relay = untrusted forwarder). P2 ships the bandwidth/latency win.

## 12. Risks

| Risk | Impact | Position |
|------|--------|----------|
| listen draft codepoint churn before RFC | interop only with ourselves until final | acceptable — both endpoints are ours; isolated in `wire.rs` |
| quinn: no extension frames / custom transport params / remote-path probing | blocks draft-exact v2 | v1 architecture avoids the need entirely; watch upstream, consider contributing |
| symmetric NATs both sides | no direct path | relay fallback is the design, not an error; P3 port mapping recovers some |
| double congestion control on relay path | throughput loss pre-upgrade | accepted for v1; relay path is transitional or low-volume |
| MTU squeeze on relay path (inner 1200-byte floor) | handshake failure on small-MTU outer paths | relay advertises large datagram size; inner clamps `max_udp_payload_size`; document 1400+ MTU requirement for relay deployment |
| open-relay abuse of bind mode | reputational/legal | §10.1 controls; bind mode off by default in config |

## 13. References

- RFC 9298 — Proxying UDP in HTTP
- draft-ietf-masque-connect-udp-listen-16 — Proxying Bound UDP in HTTP
- draft-seemann-quic-nat-traversal-02 — Using QUIC to Traverse NATs
- draft-ietf-quic-address-discovery-00 — QUIC Address Discovery
- RFC 7250 — Raw Public Keys in TLS
- RFC 9484 / 9297 / 9221 / 9000 — per `rfc9484-proxy-design.md` §1.3
- libp2p DCUtR — prior art for coordinated simultaneous open ("hole punching by synchronized dial")
- tailscale/tailcat — prior art for the token + relay + upgrade UX
