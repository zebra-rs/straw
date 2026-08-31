# Symmetric NAT traversal in straw

> **Status (2026-08-31): `relay-assisted` and `birthday` have no implementation.**
> The peer halves went with the v1 app-level punch when candidate exchange moved
> to QUIC NAT-traversal frames; relay-assisted's relay half — the `AF_PACKET`
> observer, the `--udp-bind-observe` flag and the `PEER_REFLEXIVE` (`0x15`)
> capsule — was retired afterwards, since nothing could consume what it emitted
> and leaving it implied a capability that did not exist. Both names are still
> accepted on `--punch-strategy`, warn, and fall back to `basic`. Everything
> below is kept as the record of what was built and why it did not converge;
> the code is in git history. `predict` is live.

Technical notes on hole punching between two `strawcat` peers, why the easy
cases work, why symmetric↔symmetric is the hard/unsolved case, and what each of
straw's four punch strategies does about it. Companion to
`p2p-direct-path-design.md` (§5 hole punching, §12 MTU / NAT limits); the code
lives in `src/p2p/` and `src/udp_bind/observe.rs`, and the evidence comes from
the netns harness `scripts/nat-punch-test.sh`.

---

## 1. Background: how a punch is supposed to work

Two peers each open a bind session to a relay (CONNECT-UDP bind mode). The relay
reports back each peer's **server-reflexive address** — the peer's outer source
`(public IP, port)` as the relay observes it — in an `OBSERVED_ADDRESS` capsule.
The peers exchange candidates (host / reflexive / relay) over the inner relay
connection, then perform a **simultaneous open**: both dial each other's
reflexive at once. Both sending is what opens the NAT bindings, and whichever
QUIC handshake completes first is the direct path (see `p2p/holepunch.rs`,
`p2p/punch.rs`).

This works iff the address a peer *advertises* (its reflexive, learned toward
the relay) is the same address its punch packets *actually come from* (toward
the other peer), and iff the far NAT will *accept* those packets. Whether that
holds is entirely a function of the NAT's behaviour.

---

## 2. NAT behaviour taxonomy (RFC 4787)

A NAT is described by two independent axes.

### Mapping behaviour — what external `(IP, port)` an internal socket gets

| Behaviour | External mapping for one internal socket | Reflexive usable for punching? |
|---|---|---|
| **Endpoint-Independent Mapping (EIM)** | one mapping, reused for *every* destination | **Yes** — reflexive == punch source |
| **Address-Dependent Mapping** | a new mapping per destination *IP* | Only within one peer IP |
| **Address-and-Port-Dependent Mapping** | a new mapping per destination *(IP, port)* | **No** — reflexive is toward the relay only |

"**Cone**" NAT = EIM. "**Symmetric**" NAT = address-and-port-dependent mapping.
The reflexive a symmetric NAT hands you is the mapping toward *the relay*; the
mapping toward *the peer* is a different, unadvertised port.

### Filtering behaviour — which inbound packets the NAT lets back in

| Behaviour | Accepts inbound from |
|---|---|
| **Endpoint-Independent Filtering** | anyone, once the socket has sent anything (full cone) |
| **Address-Dependent Filtering** | any port of a peer IP the socket has sent to (restricted cone) |
| **Address-and-Port-Dependent Filtering** | only the exact `(IP, port)` the socket has sent to |

Mapping controls whether the *advertised address is right*; filtering controls
whether the *return packet gets in*. Both matter, and they compound.

### Linux `iptables MASQUERADE` (the netns harness default)

Empirically (measured with tcpdump in `scripts/nat-punch-test.sh`):

- **Mapping: address-and-port-dependent, and effectively random.** The same
  internal socket gets a different external port for each destination, and the
  port is not sequential — observed punch mappings jumped around: `52961`,
  `51347`, `39542`, `18630`, `48068`. It tries to preserve the source port but
  reallocates unpredictably when the tuple is already in use.
- **Filtering: address-and-port-dependent.** conntrack's reply direction is a
  strict 5-tuple match; a reply from the right IP but a different port is
  dropped as invalid.

This is the **worst-case** NAT for hole punching. It is what makes the netns
harness an honest adversary — and why no punch strategy traverses it (§7).

---

## 3. The outer-socket reuse (the cone-NAT fix)

`straw`'s baseline (`strategy = basic`) punches from the **outer bind socket** —
the exact UDP socket whose mapping the relay observed as the reflexive — rather
than a fresh socket. Code: `BindClient::endpoint()` exposes it; `peer::listen`/
`connect` return it as `punch_endpoint`; `holepunch::coordinate` sets the pinned
punch server config on it and dials from it.

Why it matters: on an EIM (cone) NAT the outer socket keeps one external port
across all destinations, so **its punch source equals the advertised
reflexive**. A fresh socket would get a different, unadvertised mapping. Verified
in the harness — peerB used internal port `37115` for *both* its relay
connection (`→ 192.0.2.1:4433`) and its punch (`→ 192.0.2.2:34571`).

Result on the two harness NAT modes:

| `NAT_MODE` | NAT | Outcome |
|---|---|---|
| `cone` | stateless 1:1 NETMAP (EIM, full-cone) | **direct path asserted** — remote is the peer's *public* address, not the relay |
| `symmetric` | MASQUERADE (address-and-port-dependent) | blocked — reflexive ≠ punch source; relay carries the data |

On the EIM side of even the MASQUERADE run, the reuse is visibly correct:
advertised `41837` == actual punch source `41837`. The other side remaps
(`36241` advertised, `52961` actual), which is what defeats it. Real home
routers are mostly cone, so the reuse alone punches them.

---

## 4. The strategies

Selected with `strawcat --punch-strategy <name>` (`p2p::strategy::PunchStrategy`,
threaded through `Session::start`'s `PunchConfig` into `holepunch::coordinate`,
which dispatches). Each targets an *easier* symmetric class than the worst case.

### 4.1 `basic` — outer-socket reuse

§3. Cone NATs. Default.

### 4.2 `predict` — port prediction for *sequential* symmetric NATs

Some symmetric NATs allocate external ports **sequentially** from a global
counter. If so, the port a socket will get for its *next* destination is
predictable from a fresh sample.

Mechanism (`holepunch.rs::strategy_predict`):

1. Open a few (`SAMPLE_COUNT = 3`) back-to-back auxiliary bind sessions and read
   each socket's relay-observed external port.
2. `classify()` the samples: a constant, small inter-sample stride ⇒
   `Sequential { stride }`; anything else ⇒ `Random`.
3. For a sequential allocator, `predict_range()` extrapolates the next port and
   advertises a small ± scan window (`PREDICT_SPAN = 6`) alongside the reflexive.

`classify` / `predict_range` are pure and unit-tested. On a **random** allocator
(Linux MASQUERADE) it detects `Random`, advertises only the reflexive, and falls
through to the relay — honest.

**Needs:** a sequential-allocating symmetric NAT. Some consumer routers qualify.

### 4.3 `birthday` — the birthday-paradox attack for *random* symmetric NATs

If the external-port range is narrow, opening many sockets and guessing many
ports finds a mutually-open pair with birthday-paradox probability.

Mechanism (`holepunch.rs::strategy_birthday`):

1. Open `BIRTHDAY_SOCKETS = 8` extra punch sockets (aux bind sessions), each with
   its own reflexive.
2. Advertise them all; dial a `scan_around()` window (`BIRTHDAY_SCAN = 4`) of
   nearby ports around every peer candidate.
3. Race a puncher on every socket toward every target (`tokio::JoinSet`); the
   first mutually-open pair wins.

Each dial is a **fixed** target, so a pair that mutually opens *stays* open —
unlike relay-assisted's moving target (§4.4). The catch is scale: for a random
range of width `W`, a mutual hit needs on the order of `√W` sockets **and** a
matching scan on both sides. Linux's default range is ~28 000 ports, so 8
sockets is far too few — feasible only against a narrow-range NAT with many
sockets.

**Needs:** a narrow external-port range (and enough sockets). Probabilistic.

### 4.4 `relay-assisted` — on-path relay observes the peer-facing source

If the relay sits **on the network path** between the two NATs (it routes
between them, as in the harness), it can watch the punch packets go by and read
each peer's *actual peer-facing* source — the mapping the far symmetric NAT
created toward the other peer, which neither peer can predict.

Mechanism:

- Relay: `straw --udp-bind-observe` (needs `CAP_NET_RAW`) starts an `AF_PACKET`
  observer (`src/udp_bind/observe.rs`). It parses forwarded IPv4/UDP, and for a
  packet whose **both** endpoints are registered peer public IPs (a peer↔peer
  punch, not a peer↔relay bind flow), it reports the source to the *destination*
  peer's bind session.
- Signalling: the session sends a **`PEER_REFLEXIVE` capsule (type `0x15`)** on
  the bind stream (`udp_bind/context.rs`, written from `run_capsules`).
- Client: `BindClient::into_relay_socket` now also reads stream capsules,
  decodes `PEER_REFLEXIVE`, and pushes the address into a shared list.
- Strategy (`strategy_relay_assisted`): dial the peer's advertised candidates
  first (to *bootstrap* the observation — those packets are what the relay
  sees), then dial each relay-signalled real source as it arrives
  (`Puncher::punch_dynamic`, which keeps taking new targets during the window).

The observation half **works and is verified** — the relay logs each peer's
peer-facing source (e.g. `192.0.2.2:43007`), the client receives the
`PEER_REFLEXIVE`, and the strategy dials it. It does **not** converge on Linux
MASQUERADE; see §5.

**Needs:** an on-path relay, *and* a NAT whose filtering is only
address-dependent (restricted cone) rather than address-and-port-dependent.
Linux MASQUERADE is the latter, so it fails — §5.

### 4.5 `--port-map` — ask the router for an explicit forward (PCP / NAT-PMP)

The strategies above try to *discover* or *guess* a working path through an
uncooperative NAT. Port mapping instead *asks the router to cooperate*: PCP
(RFC 6887) and NAT-PMP (RFC 6886) let a host request an explicit UDP forward
from its gateway. Most consumer routers speak one of them (or UPnP-IGD).

Mechanism (`src/p2p/portmap.rs`, gated by `strawcat --port-map`):

1. Discover the default gateway (`/proc/net/route`); the PCP/NAT-PMP server is
   at `gateway:5351`.
2. Request a UDP mapping for the punch socket's *internal* port — PCP first,
   NAT-PMP as fallback. The router replies with an external `(IP, port)` it now
   forwards, both ways, to that socket.
3. Advertise that external address as a **`Mapped`** candidate (priority above
   reflexive). The peer dials it; the router's forward delivers it to the punch
   socket regardless of the NAT's mapping/filtering behaviour.

This is orthogonal to the punch strategy — combine `--port-map` with `basic`.
It is the one approach that **reliably traverses a symmetric NAT**, because the
forward is explicit rather than inferred. It requires a router that supports
PCP/NAT-PMP and will honour the request.

**Demonstrated end to end.** `sudo PORTMAP=1 NAT_MODE=symmetric
scripts/nat-punch-test.sh` runs a PCP/NAT-PMP responder (`scripts/natpmp-stub.py`)
in each NAT that installs a 1:1 iptables forward on request (DNAT in, SNAT out,
scoped to exclude the relay so the bind connection is untouched). The punch then
**succeeds through the symmetric double NAT** (3/3), where every other strategy
relays — both peers reach `direct (hole punched)` at each other's mapped port.

### 4.6 `--stun-detect` — classify the NAT first (RFC 5780)

Rather than *attempt* a punch and time out, a peer can *classify* its NAT up
front. RFC 5780 NAT-behaviour discovery probes a dual-address STUN server (the
relay, `straw --stun-addr/--stun-alt-addr`) from a fresh socket and compares the
reflexive across three destinations (`src/p2p/stun.rs::detect_mapping`):

- **Test I** → primary; learn the reflexive + the server's `OTHER-ADDRESS`.
- **Test II** → the alternate IP:port; same reflexive ⇒ **endpoint-independent**
  (cone) — punchable.
- **Test III** → primary IP, alternate port; same reflexive as Test I ⇒
  **address-dependent**, else **address-and-port-dependent** (symmetric).

`strawcat --stun-detect <server>` reports the class before connecting; a
symmetric verdict tells the peer (or operator) to use `--port-map` or expect the
relay, instead of burning a 5 s punch window. The mapping is a property of the
NAT, so a fresh probe socket answers for the punch socket too. Verified over
loopback (→ endpoint-independent) and against the netns MASQUERADE (→
address-and-port-dependent).

---

## 5. Why relay-assisted does not converge on Linux MASQUERADE — the "moving target"

Relay-assisted discovers the *current* peer-facing source. The problem is that
under an **address-and-port-dependent** NAT, that source is not stable — every
new dial creates a new mapping, so the target the relay reports has already
moved by the time the peer dials it.

Walk through it (peerA behind natA, peerB behind natB; both symmetric):

```
1. Bootstrap. peerA dials peerB's reflexive Rb → natA makes mapping E_a1
   (toward Rb). peerB dials peerA's reflexive Ra → natB makes E_b1 (toward Ra).
   Neither arrives: natB's Rb mapping is toward the RELAY, expects the relay's
   source; E_a1 ≠ relay → dropped. (Symmetric to the other side.)

2. Observe. The relay sees peerA's packet src=E_a1 dst=Rb and signals peerB
   "peerA is at E_a1"; likewise peerA learns "peerB is at E_b1".

3. Chase. peerA dials peerB@E_b1 → natA makes a NEW mapping E_a2 (toward E_b1).
   peerB dials peerA@E_a1 → natB makes E_b2 (toward E_a1).
     - peerA's packet from E_a2 hits natB:E_b1, whose conntrack expects the reply
       from 192.0.2.2:Ra (E_b1 was created toward Ra). E_a2 ≠ Ra → DROP.
     - Symmetric on the other side.

4. Observe again → peerA@E_a2, peerB@E_b2. Go to 3 with the ports incremented.
```

The iteration is always one mapping behind: to be *accepted* at natB's `E_b1`,
peerA would have to send **from** `Ra` — but `Ra` is peerA's mapping toward the
*relay*, and peerA cannot reuse it for a different destination. A fixed point
(peerA's `E_a` toward peerB's `E_b`, and peerB's `E_b` toward peerA's `E_a`,
mutually) exists, but observation-and-dial never reaches it because each dial to
a new port makes a new mapping. This is the textbook reason **symmetric↔symmetric
is the unsolved case**.

Harness evidence: the relay signalled a *sequence* of sources per peer
(`192.0.2.2:54433`, then `:9323`, …; `192.0.2.6:18630`, then `:55833`, …) — the
moving target — and both peers stayed on the relay.

Why `birthday` escapes this and relay-assisted does not: birthday dials a *fixed*
set of targets in parallel and holds them, so a mutually-open pair, once it
occurs, persists. Relay-assisted *chases* the latest observed source, so it keeps
minting fresh mappings.

Note: relay-assisted **would** work if the peer NATs did address-*dependent*
filtering (restricted cone) — then natB's `E_b1`, having sent toward
`192.0.2.2`, would accept peerA's packet from any port of `192.0.2.2`, and the
response path closes. Many real NATs are restricted cone; Linux MASQUERADE is
not.

---

## 6. Summary: strategy × NAT

| Strategy | Traverses… | netns MASQUERADE result | Demonstrable with |
|---|---|---|---|
| `basic` | EIM / cone | relay (reflexive ≠ punch source) | `NAT_MODE=cone` → **direct asserted** |
| `predict` | sequential-symmetric | relay (detects "random") | a sequential-allocating NAT |
| `birthday` | narrow-range random symmetric | relay (range too wide) | narrow-port NAT + many sockets |
| `relay-assisted` | address-dependent-filtering symmetric, on-path relay | relay (moving target) | restricted-cone NAT + on-path relay |
| `--port-map` | **any NAT whose router speaks PCP/NAT-PMP** | **PUNCHED** (explicit forward) | `PORTMAP=1` → **direct asserted** |

The one universally-true row: **the relay path always carries the data**, both
ways, through the double NAT (asserted by the harness in every mode).

---

## 7. The honest conclusion

There is **no client-side or observation** technique that traverses an
address-and-port-dependent symmetric NAT with random port allocation, short of
impractical brute force. Linux `MASQUERADE` is exactly that NAT, which is why
every *punch* strategy above falls back to the relay against it. The escape
hatch is `--port-map`: if the router speaks PCP/NAT-PMP it installs an explicit
forward and the punch succeeds (demonstrated in `PORTMAP=1`). Otherwise it — and why production peer-to-peer systems (tailscale,
libp2p, WebRTC/ICE) all keep a relay (TURN) fallback and accept that a fraction
of pairs never punch. straw's strategies push the boundary outward to several
*easier* symmetric classes that real routers commonly have; the relay covers the
rest.

---

## 8. Configuration & code map

**CLI**

```
strawcat --punch-strategy basic|predict|birthday|relay-assisted   # peer side
strawcat --port-map                                               # ask the router (PCP/NAT-PMP) for a forward
straw    --udp-bind-observe                                        # relay side (relay-assisted; needs CAP_NET_RAW)
```

**Harness** (`scripts/nat-punch-test.sh`, needs passwordless sudo)

```
sudo scripts/nat-punch-test.sh                                  # symmetric MASQUERADE, basic
sudo NAT_MODE=cone scripts/nat-punch-test.sh                    # EIM 1:1 NETMAP → direct punch asserted
sudo STRATEGY=relay-assisted scripts/nat-punch-test.sh          # also sets --udp-bind-observe
sudo STRATEGY=predict NAT_MODE=symmetric scripts/nat-punch-test.sh
sudo PORTMAP=1 NAT_MODE=symmetric scripts/nat-punch-test.sh    # PCP/NAT-PMP → punch asserted
```

**Code**

| Concern | Location |
|---|---|
| Strategy enum + parsing | `src/p2p/strategy.rs` |
| Dispatch + all four strategies | `src/p2p/holepunch.rs` (`coordinate`, `strategy_*`) |
| Simultaneous open, tie-break, dynamic targets | `src/p2p/punch.rs` (`Puncher`, `punch`, `punch_dynamic`) |
| Outer-socket reuse plumbing | `src/client.rs` (`BindClient::endpoint`), `src/p2p/peer.rs` |
| Relay observer (AF_PACKET) | `src/udp_bind/observe.rs` |
| `PEER_REFLEXIVE` capsule (`0x15`) | `src/udp_bind/context.rs`, written in `handler.rs::run_capsules` |
| Client capsule surfacing | `src/client.rs` (`into_relay_socket`) |
| Session config | `src/p2p/session.rs` (`PunchConfig`) |
| Relay flag | `src/config.rs` (`udp_bind_observe`), `src/main.rs` |
| PCP / NAT-PMP client | `src/p2p/portmap.rs` (`map_udp`); `Mapped` candidate in `p2p/wire.rs` |
| RFC 5780 STUN client + relay server | `src/p2p/stun.rs` (`detect_mapping`, `serve`); `strawcat --stun-detect`, `straw --stun-addr/--stun-alt-addr` |
| Harness PCP/NAT-PMP responder | `scripts/natpmp-stub.py` (`PORTMAP=1`) |

**Wire additions (provisional codepoints, subject to the §9 standards swap)**

- `PEER_REFLEXIVE` capsule, type `0x15`, same address body as `OBSERVED_ADDRESS`
  (`0x14`). Sent by an observing relay on a bind session's stream.

---

## 9. Future work

- **Demonstrate `predict`**: a harness NAT mode emulating a sequential-symmetric
  NAT (hard to configure with netfilter; would need a custom SNAT port sequence).
- **Demonstrate `birthday`**: a harness NAT mode restricting the external-port
  range (`SNAT --to-source IP:lo-hi`) plus a higher, configurable socket count.
- **Restricted-cone mode** to demonstrate `relay-assisted` end to end.
- **STUN-style mapping-behaviour detection** (RFC 5780): probe two relay
  addresses from the outer socket to classify the NAT before choosing a
  strategy, instead of attempting and timing out.
- §6 explicit PUNCH round message + backoff schedule for real-NAT timing.
