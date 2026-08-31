# Symmetric NAT Traversal

Hole punching works when the address a peer *advertises* is the address its punch
packets *come from*. Whether that holds is entirely a property of the NAT. This
chapter is the honest account of what straw does when it does not. A fuller
treatment, with the packet-level evidence, is in the repository's
`symmetric-nat-traversal.md`.

## The taxonomy

A NAT is described on two axes (RFC 4787):

- **Mapping** — the external `(IP, port)` an internal socket is given.
  *Endpoint-independent* (one mapping for every destination — a **cone** NAT) is
  punchable. *Address-and-port-dependent* (a new mapping per destination — a
  **symmetric** NAT) is not: the reflexive learned toward the relay is not the
  mapping used toward the peer.
- **Filtering** — which inbound packets get back in. Endpoint-independent,
  address-dependent, or address-and-port-dependent.

Linux `iptables MASQUERADE` — the NAT straw's test harness uses — is the
worst case: address-and-port-dependent filtering *and* effectively random
per-destination allocation.

## Detect first: `--stun-detect`

Rather than attempt a punch and time out, a peer can classify its NAT up front.
`p2p/stun.rs` is an [RFC 5780](https://www.rfc-editor.org/rfc/rfc5780) client that
probes a dual-address STUN server (the relay, `straw --stun-addr/--stun-alt-addr`)
from a fresh socket and compares the reflexive across three destinations. The
class is a property of the NAT, so a fresh probe socket answers for the punch
socket too. `strawcat --stun-detect <server>` reports it; a symmetric verdict says
to use `--port-map` or expect the relay, instead of burning the punch window.

## The punch strategies, and why three of them are dormant

`strawcat --punch-strategy` was built against the earlier, application-level
punch, which dialled addresses of its own choosing from sockets of its own
choosing:

| Strategy | Targets | Idea |
|----------|---------|------|
| `basic` | cone | Advertise the reflexive candidate. (default) |
| `predict` | sequential-symmetric | Sample the NAT's port allocation with a few aux bind sessions; predict the peer-facing port for a sequential allocator. **Live.** |
| `birthday` | narrow-range random symmetric | Open several sockets and scan a window around every candidate; a fixed-dial birthday attack. **Deleted.** |
| `relay-assisted` | address-dependent-filtering, on-path relay | An on-path relay observer read each peer's peer-facing source off the forwarded packets and signalled it. **Deleted.** |

Since the punch moved into the QUIC layer
([Hole Punching](ch-03-03-hole-punching.md)), the frame exchange carries a
peer's **own** candidate addresses and nothing else. A strategy survives that
move exactly when its idea can be phrased as *"this is another address of
mine"*.

`predict` can: the port a sequential NAT will use toward the peer is still this
peer's own address, so it is advertised like any other candidate, and `predict`
works as it always did.

`birthday` and `relay-assisted` cannot. Birthday needs several sockets to punch
from, and there is now one. Relay-assisted needs the relay to *observe* the
probes in flight, and the probes now go out the direct socket and never pass
through it.

Their code is **gone** — the peer halves with the v1 punch, and relay-assisted's
relay half (the `AF_PACKET` observer, the `--udp-bind-observe` flag, and the
`PEER_REFLEXIVE` capsule it signalled with) once it was clear nothing would ever
consume what it emitted. Keeping a relay that still observed and signalled would
have implied a capability that did not exist. Both names are still accepted on
`--punch-strategy`, warn, and behave as `basic`; the analysis below is the
record, and the implementations are in git history.

That costs less than it sounds, because the honest result was already that
**none of these traverses the random, address-and-port-dependent symmetric
NAT** in the harness. That is a fundamental limit, and why every peer-to-peer
system keeps a relay fallback. Each strategy only pushed the boundary out to an
*easier* symmetric class a real router might have.

## Ask the router: `--port-map`

The one approach that *reliably* beats a symmetric NAT is to stop guessing and
**ask the router to cooperate**. `p2p/portmap.rs` is a
[PCP](https://www.rfc-editor.org/rfc/rfc6887) (with
[NAT-PMP](https://www.rfc-editor.org/rfc/rfc6886) fallback) client: `strawcat
--port-map` requests an explicit UDP forward for the direct socket, and
advertises the router-assigned external address as an extra candidate. Because
the forward is explicit, the peer reaches it regardless of the NAT's mapping
behaviour — when the router speaks PCP or NAT-PMP, which most consumer routers
do. `--port-map` is orthogonal to the strategy, so it is unaffected by the
dormancy above.

The repository's `PORTMAP=1` harness demonstrates this end to end: a PCP/NAT-PMP
responder installs a 1:1 forward in each NAT, and the punch then **succeeds
through the symmetric double NAT**, where every other strategy relays.

## Choosing

In short: **detect** the NAT (`--stun-detect`); if it is a cone, `basic` punches
it; if it is symmetric, `--port-map` beats it when the router cooperates, and
otherwise the relay carries the traffic — always correctly, just not directly.
