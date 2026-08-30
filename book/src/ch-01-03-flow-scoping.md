# Flow Scoping

By default a CONNECT-IP tunnel is a full tunnel: the proxy advertises a default
route and the client sends it everything. RFC 9484 §8.3 also allows a **scoped**
tunnel — one restricted to a particular destination and/or IP protocol — and
straw implements it through the request's URI template.

## `{target}` and `{ipproto}`

The CONNECT-IP path is a URI template with two variables straw honours,
`{target}` and `{ipproto}` (parsed in `uri_template`). A client asks for a scope
by filling them in:

- **`{target}`** — a destination. A prefix (`192.0.2.0/24`) or a single IP is
  advertised (and enforced) directly. A hostname is **DNS-resolved before the
  reply**; a failure returns 502 rather than a broken tunnel.
- **`{ipproto}`** — an IP protocol number. It narrows every advertised range to
  that protocol, with ICMP always kept alongside it (RFC 9484 §4.6), so path
  diagnostics still work.

The server resolves the requested scope (`resolve_advertised_routes`), advertises
exactly it in the `ROUTE_ADVERTISEMENT`, and installs it as the session's egress
policy.

## Egress policy is also the ingress filter

The key property is that a scoped session's **egress policy doubles as its
ingress filter**. The ranges the client was told it may send to are the only
ranges it may send *from*, and — crucially — the only ones it will *hear back*
from: the forwarding engine drops any downlink packet whose destination is
outside the session's scope. A scoped session therefore only ever sees traffic
from within its scope, which is what makes scoping a security boundary and not
just a routing convenience.

## Why the P2P VPN uses scoping

Scoping is not only a proxy feature; the peer-to-peer [VPN
mode](ch-03-05-vpn-mode.md) depends on it. When two strawcat peers run a full IP
tunnel between them, the client **scopes the tunnel to the VPN subnet**. If it
requested an unscoped (default) tunnel instead, the split-default route would
capture the peer connection's own transport — the relay or punched socket the
tunnel rides on — and the tunnel would dead-lock itself. Scoping to just the VPN
subnet keeps the transport outside the tunnel.

## Multiple scopes on one connection

A single client connection can carry several scoped tunnels at once (RFC 9484
§8.3): `TunnelClient::open_tunnel` establishes an additional tunnel with its own
scope on the existing connection, each demultiplexed by its own Quarter Stream
ID.
