# RFCs and Wire Codepoints

## The RFCs straw implements

| RFC | Role in straw |
|-----|---------------|
| [9484](https://www.rfc-editor.org/rfc/rfc9484) | CONNECT-IP — the core proxy protocol: address assignment, route advertisement, IP-over-HTTP. |
| [9297](https://www.rfc-editor.org/rfc/rfc9297) | HTTP Datagrams and the Capsule Protocol — the control/data split. |
| [9221](https://www.rfc-editor.org/rfc/rfc9221) | QUIC DATAGRAM frames — the unreliable data plane. |
| [9114](https://www.rfc-editor.org/rfc/rfc9114) + [9220](https://www.rfc-editor.org/rfc/rfc9220) | HTTP/3 and Extended CONNECT — the `:protocol` handshake. |
| [9000](https://www.rfc-editor.org/rfc/rfc9000) | QUIC transport. |
| [9298](https://www.rfc-editor.org/rfc/rfc9298) | CONNECT-UDP — the relay's bind mode builds on it (with the listen extension). |
| [7250](https://www.rfc-editor.org/rfc/rfc7250) | Raw public keys — the peers' mutual SPKI-pinned inner TLS. |
| [5389](https://www.rfc-editor.org/rfc/rfc5389) + [5780](https://www.rfc-editor.org/rfc/rfc5780) | STUN and NAT behaviour discovery — `--stun-detect`. |
| [6887](https://www.rfc-editor.org/rfc/rfc6887) + [6886](https://www.rfc-editor.org/rfc/rfc6886) | PCP and NAT-PMP — `--port-map`. |
| [4787](https://www.rfc-editor.org/rfc/rfc4787) | NAT behaviour terminology — the mapping/filtering taxonomy. |

## Provisional wire codepoints

Everything provisional lives in one registry, `src/codepoints.rs`, so the v2
standards swap is a single-file edit. Each carries its v2 target and the gate
blocking the swap.

| Codepoint | Value | v2 target | Gate |
|-----------|-------|-----------|------|
| `COMPRESSION_ASSIGN` / `ACK` / `CLOSE` | capsules `0x11`–`0x13` | connect-udp-listen final codepoints | RFC publication |
| `OBSERVED_ADDRESS` | capsule `0x14` | draft-ietf-quic-address-discovery **frame** | quinn frame-extension API |
| `PEER_REFLEXIVE` | capsule `0x15` | none (straw-specific relay-assist) | — |
| NAT-traversal control | CBOR on inner stream 0 | draft-seemann frames (`0x3d7e90`…) + `nat_traversal` transport param | quinn extension-frame API |
| Inner ALPN | `strawcat/1` | unchanged | — |
| Token | `v2` / `sc2_` prefix | TBD | — |

The `v` field in the token is checked first, so a v1 and a v2 peer fail cleanly
rather than confusingly. The full swap plan is in the design document's §9 and
the module doc of `codepoints.rs`.

## Context IDs

| Context ID | Meaning | Source |
|------------|---------|--------|
| `0` | An IP packet. | RFC 9484 default. |
| `2`+ | Client-allocated uncompressed contexts (bind mode). | straw. |

## Default ports (by convention)

straw binds nothing by default; these are the ports the examples and harnesses
use.

| Port | Service |
|------|---------|
| `4433` | QUIC / HTTP-3 (the proxy and the relay). |
| `3478` / `3479` | STUN primary / alternate (`--stun-addr` / `--stun-alt-addr`). |
| `5351` | PCP / NAT-PMP, at the client's default gateway (`--port-map`). |
| `30000`–`40000` | Relay bind-session public ports (`--udp-bind-port-lo/hi`). |

## Further reading in the repository

- `p2p-direct-path-design.md` — the P2P design document (phases, wire formats,
  security).
- `symmetric-nat-traversal.md` — the full account of the NAT taxonomy, the
  strategies, and why symmetric↔symmetric is the hard case.
- `bench/BASELINE.md` — the throughput baseline and its analysis.
- `CLAUDE.md` — a dense orientation for working in the codebase.
