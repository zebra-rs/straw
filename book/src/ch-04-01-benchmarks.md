# Benchmarks

`sudo bench/iperf-baseline.sh [secs]` measures throughput two ways across three
network namespaces: a raw veth path (the ceiling) and the same traffic *through*
the tunnel. The numbers and their analysis live in `bench/BASELINE.md`; this
chapter summarises what they say.

## The headline

Through the tunnel, TCP tops out around **4–5 Gbit/s** against a 130 Gbit/s
bare-veth ceiling, so straw's data plane costs ~25–30× the raw path. The cycles
are in that data plane rather than in the network or the iperf endpoints — but
"CPU-bound" in the loose sense is misleading, and the next section is about why:
no process is at a single-core wall, and neither more streams nor more
connections raise the number.

## Where the time goes — two hypotheses, both dead

The instructive results here are what is *not* the bottleneck, and this chapter
has now been wrong twice in the same direction. Both corrections came from
measuring the thing rather than reasoning about it.

**Not per-packet syscalls.** straw's TUN device uses `IFF_VNET_HDR`, so
**TSO/GSO offload engages**: reads off the device come back as 64 KB
super-packets (a single read of ~63,614 bytes was observed), ~8.3k reads/s
instead of ~370k. Throughput did not move at all.

**Not a per-connection crypto floor either.** That was the conclusion drawn from
the previous result, and it predicted something testable: spread the load over
more QUIC connections and the aggregate should rise. `iperf-baseline.sh` runs a
second `strawc` — its own connection, its own tunnel address, its own TUN
device, reached by a policy route so its traffic genuinely leaves through it:

| | uplink |
|---|---|
| one tunnel, one connection | 4.14–4.29 Gbit/s |
| one connection, 4 iperf streams | 4.25–4.29 Gbit/s |
| **two tunnels, two connections (aggregate)** | **4.16–4.19 Gbit/s** |

Two connections carry exactly what one carries. The CPU sample across the same
run rules out the other easy explanation — `straw` 242 %, `strawc` 68 %,
`strawc2` 57 % of one core, so nothing is at a single-threaded wall and the box
is using ~3.7 of 12 cores.

So the ceiling is neither per-connection crypto nor CPU exhaustion. What is left
is **what the two tunnels share**: one proxy process, one proxy-side TUN device
(`straw0`), one NAT path, one origin. The single TUN fd is the obvious next
suspect — but that is a hypothesis, and this chapter has already published two
of those as conclusions. Confirming it means instrumenting the proxy datapath,
or running two proxy instances on separate TUN devices.

## The GSO plumbing

Because the device hands straw GSO aggregates, straw must **re-segment** them
before they become individual QUIC DATAGRAMs — each inner IP packet needs its own
datagram. That happens in `forwarding/vnet.rs`: the 10-byte virtio-net header on
every read/write describes the aggregate, and the re-segmentation splits it back
into MTU-sized packets on the way into the tunnel and reassembles on the way out.

## What this means for tuning

- More parallel streams will not raise throughput.
- **Nor will more connections** — measured, not assumed. Do not build sharding
  across QUIC connections expecting a win.
- The win from TUN offload is real in kernel-side work per byte, but does not
  show up in tunnel throughput.
- The relay path additionally pays double congestion control (inner and outer
  QUIC stack) and the [1200-byte MTU pin](ch-03-02-inner-quic.md); it is meant
  for rendezvous and fallback, and a punched **direct** path is the one to want
  for volume.

## MTU recovery under loss

A second benchmark answers a different question: does the tunnel's MTU survive a
lossy path? `sudo -E env PATH="$PATH" bench/mtu-recovery.sh` builds one probe
binary twice — against the `quinn-proto` release and against the `0.11.x` branch
this repo pins — and drives each through *clean → real black hole → 3 % loss*
in two namespaces.

| | release | 0.11.x branch |
|---|---|---|
| collapse | t = 49 s → 1200 | never |
| recovery | none in the remaining 152 s | n/a |
| black holes detected | 2463, still climbing at the end | 0 |

The release build's detector judges floor-size loss bursts suspicious and
re-fires forever, so the connection never leaves `min_mtu`; that is what the pin
avoids, and why it is worth carrying until 0.11.18 ships.
`bench/tunnel-mtu-recovery.sh` runs the same profile through a real tunnel. Over
five runs per build the release stalls terminally — the tunnel stops passing
traffic and never resumes — in **5 of 5**, the branch in **0 of 5**, at a median
23.5 against 66.7 Mbit/s with no overlap in range. Read the *trace*, not the
average: TCP's own RTO backoff stalls the first ~100 s in either build and has
nothing to do with the fix. Numbers, method and the limits of both benchmarks
are in `bench/MTU-RECOVERY.md`; the consequence for the tunnel is in [The Tunnel
MTU](ch-01-04-mtu.md).
