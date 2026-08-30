# straw

[straw: an RFC 9484 MASQUE proxy](ch-00-00-introduction.md)
- [Architecture](ch-00-01-architecture.md)
- [Building and Running](ch-00-02-building-and-running.md)

## The MASQUE Proxy (CONNECT-IP)

- [The CONNECT-IP Tunnel](ch-01-00-connect-ip.md)
- [Capsules and HTTP Datagrams](ch-01-01-capsules-datagrams.md)
- [Forwarding, TUN, and NAT](ch-01-02-forwarding.md)
- [Flow Scoping](ch-01-03-flow-scoping.md)
- [The Tunnel MTU](ch-01-04-mtu.md)

## The VPN Client

- [strawc: the Client Daemon](ch-02-00-strawc.md)

## The Peer-to-Peer Direct Path (strawcat)

- [Overview and Trust Model](ch-03-00-p2p-overview.md)
- [The Relay: CONNECT-UDP Bind Mode](ch-03-01-relay-bind.md)
- [Inner QUIC Over the Relay](ch-03-02-inner-quic.md)
- [Hole Punching](ch-03-03-hole-punching.md)
- [Symmetric NAT Traversal](ch-03-04-symmetric-nat.md)
- [VPN Mode Between Peers](ch-03-05-vpn-mode.md)

## Testing and Performance

- [The BDD and netns Harnesses](ch-04-00-testing.md)
- [Benchmarks](ch-04-01-benchmarks.md)

## Configuration and Reference

- [Running straw (the Proxy)](ch-05-00-config-straw.md)
- [Running strawc and strawcat](ch-05-01-config-clients.md)
- [RFCs and Wire Codepoints](ch-06-00-reference.md)
