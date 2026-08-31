# straw throughput baseline (Phase D)

Measured with `bench/iperf-baseline.sh`, iperf3 3.16, release build,
Linux 6.8.0-138-generic, - (12 cores), all namespaces on one host (loopback-class
veth links, so these numbers measure straw's CPU cost, not a network).

Topology: `client ──veth── proxy ──veth── origin`, with strawc's TUN in the
client namespace, straw's TUN + NAT in the proxy namespace. Every tunnel byte
crosses: TUN read → QUIC DATAGRAM (client) → QUIC receive → engine validate →
TUN write → NAT (proxy), and back.

## Results (10 s per run, tunnel MTU 1412)

| case | throughput |
|---|---|
| raw veth, uplink | 130.1 Gbit/s |
| raw veth, downlink | 130.4 Gbit/s |
| tunnel TCP, uplink | 4.23 Gbit/s (311 retrans; iperf snd 3% / rcv 50% CPU) |
| tunnel TCP, downlink | 5.25 Gbit/s (1898 retrans; snd 37% / rcv 4% CPU) |
| tunnel TCP, uplink ×4 | 4.19 Gbit/s aggregate |
| tunnel TCP, downlink ×4 | 5.16 Gbit/s aggregate |
| tunnel UDP @ 1G | 1 Gbit/s, 0% loss, ~1 µs jitter |
| tunnel UDP @ 2G | 2 Gbit/s, 0.13% loss |
| tunnel UDP @ 4G | 4 Gbit/s, 0.44% loss |
| tunnel UDP @ 8G | 8 Gbit/s offered, 36.9% loss (overload; sheds cleanly) |

## Reading

- The tunnel carries ~4–5 Gbit/s TCP against a 130 Gbit/s bare-veth ceiling:
  straw's data plane costs ~25–30× the raw path. Entirely CPU-bound — the
  iperf endpoints are nearly idle; the cycles are in the QUIC/datagram path
  (crypto, per-packet syscalls, per-packet channel hops).
- Parallel streams do **not** help (×4 ≈ ×1): the data plane is serialized
  per connection — one datagram demux task, one TUN pump each side — so
  Step 32's batching (recvmmsg/sendmmsg, GSO/GRO) is where the headroom is,
  not more flows.
- UDP sheds overload cleanly (drop-oldest at the datagram queue) and jitter
  stays ~1 µs up to 4 Gbit/s.

## Crash found and fixed: quinn-proto datagram accounting

The first 4 Gbit/s UDP run killed strawc:
`panicked at quinn-proto-0.11.17/.../datagrams.rs:47: datagrams.outgoing.payload_bytes desynchronized`.

Root cause (upstream bug, read from source): `Datagrams::send` with
`drop=true` pops the oldest queued datagram — `pop_front` already subtracts
its length from `payload_bytes` — then subtracts the length **again**. The
first overfull send buffer underflows the counter, `memory_used()` goes
astronomical, the drop loop drains the queue and the next send panics. Any
sustained datagram overload triggers it, on either end of the tunnel.
Upstream `main` never had it — its loop lives in `make_space_for`, which
relies on `pop_front` alone — but the `0.11.x` release branch kept the
call-site subtraction when that buffer refactor was backported. straw first
carried the one-line deletion as a vendored copy; upstream has since merged
the identical fix on `0.11.x` (quinn-rs/quinn#2806), so `[patch.crates-io]`
now points at that branch instead. With the fix the same sweep runs to
completion with zero panics.

## After Step 32 (direct egress + amortized allocation)

Step 32 removed the per-session queue and handler-task wakeup on the
client-bound path — the engine now encodes and calls `send_datagram`
directly (`SessionSink::Datagram`), with a `Notify` replacing the dropped
channel as the reaper's teardown wake — plus: strawc's downlink demux feeds
the TUN writer channel directly (one task and one hop fewer), the TUN read
pump amortizes its per-packet allocation (`BytesMut` chunk + `split_to`),
and network→client TTL decrement is zero-copy like the other direction.

Re-measured (two runs, same host and method):

| case | before | after |
|---|---|---|
| tunnel TCP, uplink | 4.23 Gbit/s | 4.18–4.27 Gbit/s (unchanged) |
| tunnel TCP, downlink | 5.25 Gbit/s | **5.69–5.70 Gbit/s (+8–9%)** |
| tunnel TCP, downlink ×4 | 5.16 Gbit/s | 5.52–5.57 Gbit/s |
| tunnel UDP @ 4G loss | 0.44% | 0.40% |

The gain lands exactly where the hops were removed (downlink); the uplink
path kept its single TUN-reader→sender hop and is bound by QUIC crypto and
per-datagram sends, as the baseline predicted.

## After TUN offload (IFF_VNET_HDR + TSO) and inline ingress

The device now negotiates `TUNSETOFFLOAD(CSUM|TSO4|TSO6)` with a 10-byte
virtio-net header on every read/write. GSO aggregates are re-segmented in
userspace (`forwarding/vnet.rs`: per-segment IP/TCP headers and checksums,
verified against an independent checksum implementation), and partial
checksums (`NEEDS_CSUM`) are completed before packets enter the tunnel.
Separately, the last per-packet channel hops were inlined: TUN reads now
call straight into `send_datagram` (strawc) / the forwarding engine
(straw) via a sink closure.

Measured effect on the device, uplink iperf3: **63,614 bytes per TUN
packet** — the kernel hands ~64 KB TCP aggregates, ~8.3k reads/s instead
of ~370k — confirming the offload engages fully.

Measured effect on throughput: **none**. Uplink 4.13–4.23 Gbit/s, downlink
5.52–5.61 Gbit/s — within noise of the pre-TSO numbers. The earlier
hypothesis that per-packet TUN syscalls dominate is therefore wrong: with
those syscalls (and the remaining queue hops) eliminated, throughput did
not move, so the bottleneck is the QUIC connection itself — per-packet
AEAD and protocol processing at ~370k tunnel packets/s, the known
single-connection QUIC floor. Both changes stay: they cut kernel-side
work per byte, remove two tasks from the pipeline, and are fully covered
by tests, but further single-tunnel throughput needs parallel QUIC
connections or hardware-offloaded crypto, not more datapath surgery.

## Parallel QUIC connections do not help — the floor is not per-connection

The previous section concluded that "further single-tunnel throughput needs
parallel QUIC connections", and listed that as the top remaining idea. **That
was wrong, and the experiment that would have been built on it is now
unnecessary.**

`iperf-baseline.sh` runs a second `strawc` — its own QUIC connection, its own
tunnel address, its own TUN device, reached by a policy route so its traffic
genuinely leaves through it — and drives both tunnels concurrently:

| | uplink |
|---|---|
| one tunnel, one connection | 4.14–4.29 Gbit/s |
| one connection, 4 iperf streams | 4.25–4.29 Gbit/s |
| **two tunnels, two connections (aggregate)** | **4.16–4.19 Gbit/s** |

Two connections carry what one carries. Whatever the ceiling is, it is not a
per-connection limit, so spreading traffic across connections cannot lift it.

The CPU sample taken across the same run rules out the other easy explanation:

```
straw 242%   strawc 68%   strawc2 57%      (of one core; 12 cores available)
```

Nothing is pinned at a single-threaded 100% wall — `straw` is already using
about 2.4 cores — and the box as a whole is using roughly 3.7 of 12. So this is
neither a per-connection crypto floor nor CPU exhaustion.

**What that leaves is what the two tunnels share**: one proxy process, one
proxy-side TUN device (`straw0`), one NAT path, one origin. The proxy's single
TUN device is the obvious next suspect — every session's packets funnel through
that one fd — but that is a **hypothesis, not a measurement**. Confirming it
means instrumenting the proxy datapath (or testing two proxy instances on
separate TUN devices) rather than reasoning from these numbers.

## Remaining optimization ideas

1. ~~Parallelism across QUIC connections~~ — **refuted above**, do not build it.
2. Find the real serialization point: instrument the proxy datapath, starting
   with the shared TUN device, before optimizing anything.
3. GRO on the write side (coalesce tunnel→kernel TCP segments into
   aggregates) — reduces kernel-side receive cost, not tunnel throughput.
4. io_uring, DSCP copy: only after a workload shows they matter.
