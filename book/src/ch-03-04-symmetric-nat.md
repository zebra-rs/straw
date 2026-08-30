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

## The four punch strategies

`strawcat --punch-strategy` selects how the punch attacks a harder NAT
(`p2p::strategy::PunchStrategy`):

| Strategy | Targets | Idea |
|----------|---------|------|
| `basic` | cone | Reuse the outer socket, advertise the reflexive. (default) |
| `predict` | sequential-symmetric | Sample the NAT's port allocation with a few aux bind sessions; predict the peer-facing port for a sequential allocator. |
| `birthday` | narrow-range random symmetric | Open several sockets and scan a window around every candidate; a fixed-dial birthday attack. |
| `relay-assisted` | address-dependent-filtering, on-path relay | The relay (`--udp-bind-observe`) reads each peer's peer-facing source off the forwarded packets and signals it. |

The honest result is that **none of these traverses the random,
address-and-port-dependent symmetric NAT** in the harness — that is a
fundamental limit, and why every peer-to-peer system keeps a relay fallback. Each
strategy pushes the boundary out to an *easier* symmetric class a real router
might have; the relay covers the rest.

## Ask the router: `--port-map`

The one approach that *reliably* beats a symmetric NAT is to stop guessing and
**ask the router to cooperate**. `p2p/portmap.rs` is a
[PCP](https://www.rfc-editor.org/rfc/rfc6887) (with
[NAT-PMP](https://www.rfc-editor.org/rfc/rfc6886) fallback) client: `strawcat
--port-map` requests an explicit UDP forward for the punch socket, and advertises
the router-assigned external address as a `Mapped` candidate. Because the forward
is explicit, the peer reaches it regardless of the NAT's mapping behaviour — when
the router speaks PCP or NAT-PMP, which most consumer routers do.

The repository's `PORTMAP=1` harness demonstrates this end to end: a PCP/NAT-PMP
responder installs a 1:1 forward in each NAT, and the punch then **succeeds
through the symmetric double NAT**, where every other strategy relays.

## Choosing

In short: **detect** the NAT (`--stun-detect`); if it is a cone, `basic` punches
it; if it is symmetric, `--port-map` beats it when the router cooperates, a
matching strategy may beat an easier symmetric NAT, and otherwise the relay
carries the traffic — always correctly, just not directly.
