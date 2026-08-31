# VPN Mode Between Peers

The default `strawcat` pipes stdio over the peer connection. With `--vpn` it does
something bigger: it runs straw's *own* CONNECT-IP stack over that connection, so
the two peers form a real IP tunnel between their hosts — reusing the same
`capsule/`, `datagram/`, `forwarding/`, and `session/` code the proxy uses. It is
`p2p/vpn.rs`.

## The two roles

The peer connection is symmetric, but a CONNECT-IP tunnel is not. `--vpn` maps
the strawcat roles onto it:

- The **listener** is the tunnel **server** (`run_server`). It builds a minimal
  `ProxyContext` — an address pool over `--vpn-subnet` (default `10.9.0.0/24`), a
  TUN device, a forwarding engine — and serves CONNECT-IP/h3 over the inner
  **noq** peer connection (via the `p2p::h3_noq` adapter, with its own datagram
  demux). It assigns the connector an address and forwards.
- The **connector** is the tunnel **client** (`run_client`). It runs
  `TunnelClient::over_noq_connection` — the h3 CONNECT-IP client over the
  already-open `noq::Connection` — receives its address, stands up its own TUN, and pumps
  packets, exactly like [`strawc`](ch-02-00-strawc.md).

The tunnel rides whichever path the [`Session`](ch-03-03-hole-punching.md)
picked — normally the direct one. VPN mode is in fact the case that forced the
punch's candidate exchange into the QUIC layer: the inner protocol here is
HTTP/3, and the earlier application-level exchange stream would have arrived at
the h3 server as a malformed request.

## The scoping trap

There is one non-obvious requirement. The client **scopes the tunnel to the VPN
subnet** (`--vpn-subnet` as the flow scope). If it asked for a full/default
tunnel instead, the split-default route would capture the peer connection's *own
transport* — the relay or punch socket the tunnel is carried on — and the tunnel
would dead-lock itself. Scoping to just the VPN subnet keeps the transport
outside the tunnel. This is the same [flow-scoping](ch-01-03-flow-scoping.md)
mechanism the proxy uses, put to a structural purpose.

## Trying it

Both peers pass `--vpn`; the listener also picks the subnet:

```bash
# peer A (server): assigned 10.9.0.1
strawcat listen  --relay <relay>:4433 --insecure --bearer-token s3cret \
    --identity a.key --vpn --vpn-subnet 10.9.0.0/24 --vpn-tun sc0

# peer B (client): assigned 10.9.0.2
strawcat connect <token> --relay <relay>:4433 --insecure --bearer-token s3cret \
    --identity b.key --vpn --vpn-tun sc0
```

Now `ping 10.9.0.1` from peer B travels through the tunnel to peer A and back.
The repository's `scripts/vpn-test.sh` is exactly this, three network namespaces
(`peerA ─ relay ─ peerB`). It asserts both halves: that each peer's path leads
to the *other peer's* address rather than the relay's, and that the ping crosses
the tunnel over it.

## What it is and isn't

This is a genuine point-to-point IP tunnel: two hosts, a shared subnet, kernel
TUN devices on each end, running end-to-end-encrypted over QUIC. It is not (yet)
a multi-peer mesh or a policy-routed VPN — one listener, one connector, one
subnet. Extending it is future work; the pieces (the pool, the forwarding engine,
multiple sessions) are already the proxy's, waiting to be pointed at more peers.
