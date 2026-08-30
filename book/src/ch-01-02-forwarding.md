# Forwarding, TUN, and NAT

The data plane lives in `forwarding/`. It takes a validated IP packet from a
tunnel and decides where it goes: to another client (hairpin), out to the
network through a TUN device, or back as an ICMP error.

## The forwarding engine

`ForwardingEngine` owns a longest-prefix **route table**, the per-session sinks,
each session's egress policy and rate limiter, and — if configured — a sender to
the TUN device. Two entry points drive it:

- **`dispatch` (uplink)** — a packet from a client session. The engine validates
  it, checks it against the session's egress policy (ingress filtering: a packet
  claiming a source outside the session's scope is dropped as spoofed),
  decrements TTL (emitting **Time Exceeded** at zero), and routes by destination:
  a client address → that session (hairpin); anything else → the TUN.
- **`dispatch_from_network` (downlink)** — a packet read from the TUN. The engine
  routes it to the session that owns the destination address, or drops it if no
  session claims it.

An unroutable destination earns an ICMP **Destination Unreachable**; the ICMP
source is the pool gateway (`forwarding::icmp::IcmpSource`).

## The TUN device

When `--tun` is set, straw opens a kernel TUN device (`forwarding/tun.rs`) and
spawns a read pump and a write pump. The read pump hands each inbound packet to
`dispatch_from_network`; the write pump drains packets the engine sends toward
the network.

The device is opened with **`IFF_VNET_HDR`**: every read and write carries a
10-byte virtio-net header, which lets the kernel hand straw **GSO** super-packets
(up to 64 KB) instead of MTU-sized fragments and offload checksums. straw
re-segments those aggregates in `forwarding/vnet.rs` on the way into the tunnel.
This TSO/GSO offload is why a single read can be tens of kilobytes; see
[Benchmarks](ch-04-01-benchmarks.md) for what it buys and what it doesn't.

## Hairpin between clients

The proxy can run **without** a TUN (`--tun` off): then only client-to-client
*hairpin* forwarding works — packets between two tunnelled clients are routed
directly by the engine, never touching the host network. This is the mode the
P2P [relay](ch-03-01-relay-bind.md) leans on.

## NAT to the Internet

`--nat-interface eth0` installs `iptables` MASQUERADE rules
(`forwarding::nat::setup_nat`) so pool traffic egressing the TUN is source-NATed
out a physical interface and can reach the Internet. The rules are removed again
on shutdown by a guard. Because the proxy writes `net.ipv4.ip_forward` for this,
its systemd unit must **not** set `ProtectKernelTunables=yes`.

## Rate limiting

Each session carries an optional token-bucket limiter
(`forwarding::limiter::RateLimits`, `--max-packet-rate` / `--max-byte-rate`, or
the bind-mode `--udp-bind-max-pps` / `--udp-bind-max-bps`). It is the main
defence against a client using the proxy as an amplifier or flooding the network.
