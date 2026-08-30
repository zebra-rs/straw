# Hole Punching

The relay path works, but it is a detour: every packet crosses the relay twice.
The point of strawcat is to *leave the relay behind* — to open a direct QUIC
connection between the peers. That is hole punching, and it lives in
`p2p/holepunch.rs`, `p2p/punch.rs`, and `p2p/session.rs`.

## Candidate exchange

Over the inner (relay) connection, the two peers exchange **candidates** on a
control stream (`exchange_candidates`): the transport addresses each thinks the
other might reach it at. In ICE-style priority order:

| Kind | What it is | Priority |
|------|-----------|----------|
| `Host` | A local interface address (LAN-adjacent peers). | 126 |
| `Mapped` | An explicit router forward ([PCP/NAT-PMP](ch-03-04-symmetric-nat.md)). | 110 |
| `Reflexive` | The relay's `OBSERVED_ADDRESS` view of the peer's outer source. | 100 |
| `Relay` | The relay-allocated address — always present, never a punch target. | 0 |

The messages are a small CBOR `Control` enum (`Candidate` / `Punch` / `Retire`)
that maps one-to-one onto the draft-seemann NAT-traversal frames a v2 will use.

## The punch: simultaneous open

Both peers then dial each other's candidates *at the same time* while also
accepting — a simultaneous open (`p2p/punch.rs`, `Puncher`). Both directions
transmitting is what opens the NAT bindings; whichever QUIC handshake completes
first is the direct path. The punch reuses the same RFC 7250 pinned identity as
the relay path, so a completed handshake is already an authenticated connection.

Two subtleties make it reliable:

- **Reuse the outer socket.** The punch runs on the *outer bind socket* — the one
  whose mapping the relay observed as the reflexive — not a fresh socket. On an
  endpoint-independent (cone) NAT the outer socket keeps one external port across
  destinations, so the punch's source *equals* the advertised reflexive. A fresh
  socket would get a different, unadvertised mapping and never be reached.
- **The duplicate-success tie-break.** A simultaneous open can complete *two*
  connections (each side's dial). A short grace window collects them; on a
  genuine duplicate both sides keep the **canonical** one — the connection whose
  client is the lower-pinned peer — so they converge without coordination. A lone
  success (asymmetric NAT let only one direction through) is kept regardless of
  role: never reject the only working path.

## The path state machine

`p2p::session::Session` is the RELAY → PUNCHING → DIRECT machine that ties it
together:

```
  RELAY ──punch──▶ PUNCHING ──validated──▶ DIRECT
    ▲                  │                      │
    │  punch failed    │                      │ direct path lost
    └──────────────────┘                      │
    ▲                                          │
    └──────────────────────────────────────────┘   (relay never closed)
```

The manager task punches, promotes to DIRECT on success, and holds it until the
direct connection closes; on loss it reverts to the relay and re-punches after a
backoff. The relay connection is **never closed** — it is the always-available
fallback, so `Session::connection()` can always hand a caller a working path,
direct if one is up and the relay otherwise. A caller can `await_direct` briefly
to prefer sending the first bytes over a direct path if one comes up quickly.

## When it works — and when it doesn't

On loopback and on cone NATs, the punch succeeds and the peers talk directly. On
a **symmetric** NAT the advertised reflexive is not the address the punch will
come from, and the basic punch cannot traverse it. That is the hard case, and it
gets its own chapter: [Symmetric NAT Traversal](ch-03-04-symmetric-nat.md).
