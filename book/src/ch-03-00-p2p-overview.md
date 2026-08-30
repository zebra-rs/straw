# Overview and Trust Model

`strawcat` turns two straw peers and a relay into a peer-to-peer overlay. The
design goal is blunt: the relay should be an **untrusted forwarder** — it moves
ciphertext between two peers and can neither read nor impersonate them. Getting
there needs a trust model that lives entirely at the peers.

## The layers

strawcat builds up in `src/p2p/` (peer side) and `src/udp_bind/` (relay side):

| Layer | Module | What it provides |
|-------|--------|------------------|
| Identity | `p2p/identity` | An Ed25519 keypair and its **SPKI pin** (SHA-256 of the SubjectPublicKeyInfo) — the WireGuard-pubkey analogue. |
| Token | `p2p/token` | The `sc2_` capability a listener hands a dialer: where the relay is, how to pin it, a scoped relay credential, and the issuer's peer pin and address. |
| Relay bind | `udp_bind/` | The relay's CONNECT-UDP bind side: a public `(IP, port)` per session and ciphertext forwarding. |
| Relay socket | `p2p/relay_socket` | A `quinn::AsyncUdpSocket` that runs an inner QUIC connection over a bind session. |
| Inner TLS | `p2p/inner_tls` | RFC 7250 raw-public-key mTLS, mutually pinned by SPKI. |
| Rendezvous | `p2p/peer` | `listen` / `connect`: open a bind session, form the inner connection. |
| Direct path | `p2p/holepunch`, `p2p/punch`, `p2p/session` | Candidate exchange, the punch, and the RELAY → PUNCHING → DIRECT state machine. |

## Identities and pins

Each peer has a persistent Ed25519 identity (`strawcat genkey`). Its **pin** is
the SHA-256 of its raw public key's SPKI — a short, stable fingerprint. Peers
authenticate each other by pin, exactly as WireGuard peers authenticate by public
key: there is no CA, no web-PKI, no names. Pins are compared in constant time.

## The token

A listener mints a token (`TokenV2`) and hands it to a dialer out of band (paste
it, scan it, whatever). It is a compact CBOR map with integer keys, base64url-
encoded behind an `sc2_` prefix, and carries:

- **`relay`, `rpin`** — where the relay is and its certificate pin.
- **`auth`** — a scoped, short-TTL relay credential (bind mode requires auth).
- **`ppin`, `paddr`** — the issuer's peer pin and its relay-public address(es).
- **`v`, `exp`** — a format version (checked first, so a mismatched peer fails
  cleanly) and an expiry.

Nothing in the token lets the relay link accounts; nothing lets a holder
impersonate the issuer.

## The two connections

There are always two QUIC connections in play, and keeping them straight is the
key to the whole design:

- The **outer** connection is peer ↔ relay: ordinary QUIC/H3 in CONNECT-UDP bind
  mode. The relay terminates it and sees only its ciphertext contents.
- The **inner** connection is peer ↔ peer: raw QUIC with RFC 7250 mutual SPKI
  pinning, tunnelled *through* the relay as datagrams. The relay forwards it
  without a key to read it.

Everything after this chapter is about that inner connection: first
[carrying it over the relay](ch-03-02-inner-quic.md), then trying to
[replace the relay with a direct path](ch-03-03-hole-punching.md).
