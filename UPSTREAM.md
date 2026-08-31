# Upstream gates

Five things in this repo are waiting on someone else. They are collected here
because each one is otherwise a comment in a different file, and "is this still
true?" is a question worth being able to answer in a couple of minutes rather
than by re-deriving it.

Each entry says what we carry, what would let us drop it, and the exact command
that answers whether that has happened.

Last checked: **2026-08-31**.

---

## 1. Vendored `quinn-proto` — a datagram-accounting panic

**What we carry.** `vendor/quinn-proto` is 0.11.17 with one deletion in
`Datagrams::send`: the drop loop subtracted a datagram's length from
`payload_bytes` a *second* time, after `pop_front` had already done it. The
first overfull send buffer underflowed the counter, and every later
`send_datagram` panicked on `expect("datagrams.outgoing.payload_bytes
desynchronized")`, killing the tunnel under sustained datagram load. Found by
the Phase D iperf3 UDP sweep at ~4 Gbit/s.

**What lands it.** Upstream `main` already fixed this by restructuring the loop
into `make_space_for`, which relies on `pop_front` alone. We need a **0.11.x
release** carrying that — 0.11.17 is still the newest.

**Check:**

```bash
cargo search quinn-proto --limit 1     # newer than 0.11.17?
```

If yes: drop the `[patch.crates-io]` entry and `vendor/quinn-proto`, then run
the UDP sweep (`sudo bench/iperf-baseline.sh`) to confirm the panic stays gone.

**Not yet reported upstream.** Nothing in this repo records an issue number.
Worth filing with the reproduction above; see the note at the bottom.

---

## 2. Vendored `h3` — a backported protocol variant

**What we carry.** `vendor/h3` is 0.0.8 with upstream's `ConnectIp` protocol
variant backported.

**What lands it.** hyperium/h3 `master` already has it; we need the **next
release** after 0.0.8.

**Check:**

```bash
cargo search h3 --limit 1              # newer than 0.0.8?
```

---

## 3. Provisional codepoints — RFC publication

**What we carry.** Every provisional wire number lives in `src/codepoints.rs`:
the connect-udp-listen compression capsules `0x11`–`0x13`, `OBSERVED_ADDRESS`
`0x14`, the straw-specific `PEER_REFLEXIVE` `0x15`, the `strawcat/1` ALPN and
the `sc2_` token marker.

**What lands it.** Publication of draft-ietf-masque-connect-udp-listen with
final codepoints. Both endpoints are ours, so the interop cost of being early
is only with our own older builds — and tokens carry a version, so a v1 and a
v2 peer fail cleanly.

`PEER_REFLEXIVE` is different: it is ours, not a draft's, and its only consumer
was the `relay-assisted` punch strategy, which does not port to QUIC-native NAT
traversal. It should be **retired** rather than migrated.

**Check:** the draft's status at
<https://datatracker.ietf.org/doc/draft-ietf-masque-connect-udp-listen/>.

---

## 4. `OBSERVED_ADDRESS` as a capsule rather than a frame

**What we carry.** The relay reports a peer's reflexive address in a vendor
capsule (`0x14`) on the bind session, rather than in
draft-ietf-quic-address-discovery's OBSERVED_ADDRESS **frame**.

**What lands it.** The capsule rides the *outer* session, which is upstream
quinn + h3-quinn and has no extension-frame API. The inner connection already
runs on noq, which does expose `observed_external_addr` — but the inner
connection is not where this address is learned, so adopting noq for the inner
path did not close this. It needs either an extension-frame API in quinn, or
moving the outer session to noq as well.

**Check:**

```bash
# does upstream quinn expose extension frames / custom transport params yet?
cargo search quinn --limit 1
```

---

## 5. `draft-ietf-masque-quic-proxy` — WG last call

**What we carry.** Nothing: `PLAN.md` Step 33 is deliberately not started.

**What lands it.** Publication, or at least exit from WG last call. The draft
has been in last call since 2025-11-03, changed intended status mid-call, and
its IANA section says the capsule codepoints will be replaced before
publication. There is also nothing public to interoperate against.

**Check:** <https://datatracker.ietf.org/doc/draft-ietf-masque-quic-proxy/> —
and see `docs/quic-aware-proxying.md` for what implementing it would involve.

---

## Related but *not* upstream-gated

Two limits look like upstream problems and are not:

- **The 1200-byte inner MTU on the direct path** genuinely is a missing noq API
  (no per-path MTU), and is documented at `p2p::peer::INNER_MTU` with a
  per-session measurement of what it costs. It is listed there rather than here
  because nothing about it is expected to change on someone else's schedule.
- **`birthday` and `relay-assisted` punch strategies** do not work, but not
  because anything upstream is missing: their designs need several sockets, or
  need the relay to observe probes that now travel directly. See
  `book/src/ch-03-04-symmetric-nat.md`.
