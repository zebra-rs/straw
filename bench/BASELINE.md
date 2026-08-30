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
Upstream `main` has restructured the loop (`make_space_for`) and doesn't
double-subtract; no 0.11.x release carries the fix, so `vendor/quinn-proto`
is 0.11.17 with the one-line patch (see `[patch.crates-io]`). With the patch
the same sweep runs to completion with zero panics.

## Optimization targets (Step 32), in measured order

1. Batched TUN + UDP I/O (recvmmsg/sendmmsg, quinn-udp already does GSO/GRO
   on the QUIC side) — per-packet syscalls dominate at ~350 kpps.
2. Fewer per-packet hops: TUN reader → engine → session channel → datagram
   send is 3 queue crossings per packet each way.
3. Then re-measure before anything fancier (io_uring, DSCP copy).
