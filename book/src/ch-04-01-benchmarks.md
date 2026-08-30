# Benchmarks

`sudo bench/iperf-baseline.sh [secs]` measures throughput two ways across three
network namespaces: a raw veth path (the ceiling) and the same traffic *through*
the tunnel. The numbers and their analysis live in `bench/BASELINE.md`; this
chapter summarises what they say.

## The headline

Through the tunnel, TCP tops out around **4–5 Gbit/s**, and the process is
**CPU-bound**. Parallel iperf3 streams do not help: they share one QUIC
connection, and the bottleneck is not the number of flows.

## Where the time goes

The instructive result is what is *not* the bottleneck. straw's TUN device uses
`IFF_VNET_HDR`, so **TSO/GSO offload engages**: reads off the device come back as
64 KB super-packets (a single read of ~63,614 bytes was observed), and the
per-packet syscall and parsing cost is amortised across a whole aggregate. Yet
throughput does not move. The offload removes the syscall overhead, and the
number sits instead at the **single-connection QUIC crypto floor** — the cost of
encrypting and authenticating every byte through one connection's AEAD.

That is the honest ceiling for a single QUIC connection on one core. It is not a
straw-specific inefficiency to be squeezed out; it is the price of the transport
security. Scaling past it means more connections (more cores), which is an
application-level decision, not a datapath tweak.

## The GSO plumbing

Because the device hands straw GSO aggregates, straw must **re-segment** them
before they become individual QUIC DATAGRAMs — each inner IP packet needs its own
datagram. That happens in `forwarding/vnet.rs`: the 10-byte virtio-net header on
every read/write describes the aggregate, and the re-segmentation splits it back
into MTU-sized packets on the way into the tunnel and reassembles on the way out.

## What this means for tuning

- More parallel streams will not raise single-connection throughput.
- The win from TUN offload is real but caps at the crypto floor.
- The relay path additionally pays double congestion control (inner and outer
  QUIC stack) and the [1200-byte MTU pin](ch-03-02-inner-quic.md); it is meant
  for rendezvous and fallback, and a punched **direct** path is the one to want
  for volume.
