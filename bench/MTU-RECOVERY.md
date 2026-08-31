# MTU recovery under loss

Measured 2026-08-31, on the machine described in `BASELINE.md`.

This is the evidence behind `UPSTREAM.md` entry 1 — specifically the *second*
reason we pin `quinn-proto` to upstream's `0.11.x` branch rather than the
0.11.17 release: `dcb9eab`, the black-hole-detector backport. The datagram
panic is the reason the pin exists at all; this is what else it buys.

## The claim being tested

Upstream (quinn-rs/quinn#2791, #2799): once a connection has fallen to
`min_mtu`, full-size (= 1200-byte) loss bursts keep being judged suspicious and
re-trigger the black-hole detector, so the connection stays pinned at the floor
for the rest of a bulk transfer. In 0.11.17's `finish_loss_burst` a burst is
suspicious unless `burst.smallest_packet_size < self.min_mtu` — and at the
floor `1200 < 1200` is false. The branch relaxes both comparisons to `<=` and
lets an equal-size delivery clear preceding bursts.

## Harness

`bench/mtu-recovery.sh` — two namespaces over a veth, the same probe binary
(`bench/mtuprobe`) built twice, against the release and against the branch, run
through one profile:

| phase | what |
|-------|------|
| `[0, T1)` | clean — MTUD raises the path MTU to 1452 |
| `[T1, T2)` | a real black hole — `iptables` drops UDP ≥ 1300 B |
| `[T2, end)` | 3 % random `netem` loss — ordinary lossy bulk transfer |

Loss goes on the *sender's* egress: black-hole detection is driven by a
sender's own lost packets. The sender is paced (200 Mbit/s by default) because
an unpaced one saturates the veth and manufactures its own queue-drop loss,
which swamps the netem loss the experiment is about.

## Result (200 s, 3 % loss, 20 s black hole)

| | 0.11.17 release | 0.11.x branch |
|---|---|---|
| MTU after clean phase | 1452 | 1452 |
| collapse | t = 49 s → 1200 | never |
| recovery | **none in the remaining 152 s** (303/303 samples at the floor) | n/a |
| black holes detected | **2463**, ~15/s, still climbing at the end | **0** |
| measured loss | 3.0 % | 3.0 % |

The counter over time in the release build — 289 at t=60 s, 904 at 100 s, 1671
at 150 s, 2449 at 200 s — is upstream's "thousands per connection". The branch
build absorbed 100 118 lost packets in the same phase without one detection.

**Two things this does not show.** A control run with 3 % loss and *no* black
hole produced zero detections and a steady 1452 on the release build, so
ordinary loss alone is not enough — a black-hole event has to set it up, and
only then does routine loss keep it pinned. And neither build fired *during*
the black-hole window: with every large packet dropped there are no ACKs, so
loss declaration stalls and the collapse landed 9 s after the block lifted.
This measures false-positive pinning, not whether true-positive detection still
works; the fix does make the detector strictly less trigger-happy, and only
upstream's unit tests cover that direction.

## End to end, through the tunnel

`bench/tunnel-mtu-recovery.sh` runs the same profile through `straw` + `strawc`
with iperf3 in reverse (the proxy is the QUIC bulk sender), against two builds
of straw itself. The signal is noisier — TCP's own RTO backoff stalls the
transfer for ~100 s in *any* build — so read the trace after that, not the
average.

| run | build | throughput | stalls (s) |
|-----|-------|-----------|------------|
| 20 s black hole, 200 s | release | 42.7 Mbit/s | 24–123, **155–196** |
| | branch | 61.0 Mbit/s | 23–123 only |
| 5 s black hole, 240 s | release | 25.5 Mbit/s | 23–124, **143–235** |
| | branch | 67.6 Mbit/s | 23–122 only |

Both builds take the first stall and recover from it at ~122 s. Only the
release build then collapses a second time — and that one runs to the end of
the measurement in both pairs, i.e. the tunnel stops passing traffic and does
not come back. n = 2 per build; the direction is consistent but the sample is
small.

`straw_packets_mtu_dropped_total` reaches only 14 (release) versus 5 (branch),
which looks negligible and is not: once the proxy starts dropping oversize
packets there is no ICMP to tell the sender (by design — the only source
address available is a martian to it), so the origin's TCP simply retransmits
into a black hole and backs off. A handful of dropped packets is enough to keep
the connection dead, because after the first few they are the *only* packets in
flight. The client-side TUN MTU is no help as a signal either: `strawc` only
ever ratchets it *up*, so it reads 1412 throughout both runs.
