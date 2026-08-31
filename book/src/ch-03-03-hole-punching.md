# Hole Punching

The relay path works, but it is a detour: every packet crosses the relay twice.
The point of strawcat is to *leave the relay behind* — to reach the peer
directly. That is hole punching, and it lives in `p2p/relay_socket.rs`,
`p2p/native_punch.rs` and `p2p/session.rs`.

The direct path is **not a second connection**. Relay and direct are two paths
of the *same* inner QUIC connection, so upgrading to the direct one moves
nothing above the transport: streams in flight keep working, and the
application never learns that anything happened.

## One socket, two paths

`PathMuxSocket` is a single `noq::AsyncUdpSocket` that carries both. It routes
each send by destination:

- a destination known to be a **relay** address — the peer's relay-allocated
  `paddr` — is wrapped as a bind datagram and tunnelled through the outer
  CONNECT-UDP session, exactly as the relay path always was;
- **everything else** goes out a real UDP socket.

Direct-by-default is deliberate. The punch's probes are aimed at peer
candidates that the *QUIC layer* learned and the application never sees, so
they cannot be registered as direct destinations in advance — but they are
never a relay `paddr`, so the default sends them the right way. The dialing
peer presets the peer's `paddr` (its very first packet must be tunnelled); the
accepting peer learns it from the packet it is answering.

Receives from both sources are merged, each tagged with the local IP it arrived
on, so QUIC sees two distinct paths of one connection.

## Candidate exchange, at the QUIC layer

Candidates travel as noq's **NAT-traversal frames**
(draft-seemann-quic-nat-traversal), enabled by setting
`max_remote_nat_traversal_addresses` on the transport config. The roles follow
the draft's asymmetry:

- the inner **server** advertises its candidates in `ADD_ADDRESS` frames;
- the inner **client** learns them, advertises its own in `REACH_OUT`, and
  probes. On a probe response QUIC opens the validated path itself.

A peer's candidate is the relay-observed public **IP** paired with the *direct*
socket's **port**. The relay only ever sees the outer bind socket's source, so
only the IP is reused from it. With `--port-map`, an explicitly forwarded
address is advertised as well.

This exchange used to be a CBOR message on an application stream. Moving it
into the QUIC layer is what lets [VPN mode](ch-03-05-vpn-mode.md) punch at all:
its inner protocol is HTTP/3, which would have read a stray application stream
as a request. One punch driver now serves both inner protocols.

## Promotion: how the upgrade actually happens

A NAT-traversal-validated path arrives with status `Backup`, and QUIC schedules
data on `Available` paths in preference to backup ones. So validation alone
changes nothing — the relay path (path 0, `Available` by default) would keep
carrying the traffic. The upgrade is the **promotion**, and that is
`p2p::session::Session`'s job:

```
  RELAY ──punch──▶ PUNCHING ──validated──▶ DIRECT
    ▲                  │                      │
    │  punch failed    │                      │ direct path lost
    └──────────────────┘◀─────────────────────┘
            (the relay path is never closed)
```

On `PathEvent::Established` for a non-zero path, the session marks the direct
path `Available` and the relay path `Backup`. Data moves to the direct path;
the relay path stays open and kept alive as the fallback. On
`PathEvent::Abandoned` the reverse happens — the relay path goes back to
`Available` and the punch is retried after a backoff.

`Session::connection()` therefore always hands a caller a working connection,
and `await_direct` waits briefly for the upgrade before sending the first
bytes. `Session::direct_remote()` reports which peer address won; `strawcat`
prints it:

```
path: direct (hole punched, peer 192.0.2.6:46853)
```

The address named there is the **peer's**, not the relay's — which is what
makes it a direct path, and what both netns test harnesses assert on.

## When it works — and when it doesn't

On loopback, on a LAN, and on cone NATs, the punch succeeds and the peers talk
directly. On a **symmetric** NAT the advertised candidate is not the address
the peer's packets will arrive from, and the punch cannot traverse it. That is
the hard case, and it gets its own chapter:
[Symmetric NAT Traversal](ch-03-04-symmetric-nat.md).
