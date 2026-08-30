# The CONNECT-IP Tunnel

The proxy's core job is [RFC 9484](https://www.rfc-editor.org/rfc/rfc9484):
terminate a CONNECT-IP tunnel, give the client an address, and move IP packets.
This chapter follows one tunnel from the handshake to a forwarded packet.

## Accepting a connection

`straw --listen` builds a QUIC endpoint (`server::build_endpoint`) with the TLS
certificate, ALPN `h3`, and QUIC DATAGRAM frames enabled. `run_server` accepts
connections until shutdown; each becomes a `handle_connection` task.

`handle_connection` keeps a raw clone of the `quinn::Connection` for datagram
I/O, then wraps the connection for HTTP/3 and starts two things:

- a **datagram demux** task that reads QUIC DATAGRAMs, decodes the Quarter
  Stream ID + Context ID, and routes each to the right session's sink; and
- the h3 **accept loop**, which waits for an Extended CONNECT request.

## The Extended CONNECT request

A CONNECT-IP client sends an HTTP/3 Extended CONNECT
([RFC 9220](https://www.rfc-editor.org/rfc/rfc9220)) with `:protocol =
connect-ip` and a URI template path. The server validates the method,
`:protocol`, and the capsule-protocol header, then dispatches by `:protocol`:
`connect-ip` goes to `session::handler::handle_connect_ip_stream`; the relay's
`connect-udp` (bind mode) goes elsewhere ([the relay](ch-03-01-relay-bind.md)).

Before accepting, the handler runs **authentication** (`session::auth`): one of
`none`, HTTP `Bearer`, HTTP `Basic`, or `mtls` (a client certificate verified
against a configured CA). A failure returns the appropriate HTTP status
(401 / 403) rather than a tunnel.

## Assignment and routes

Once accepted (200), the server performs an *unprompted* address assignment: it
allocates an IPv4 and/or IPv6 address for the session from the pool
(`address_pool`), and sends two capsules on the request stream:

- **`ADDRESS_ASSIGN`** — the client's tunnel address(es).
- **`ROUTE_ADVERTISEMENT`** — the IP ranges the client should route through the
  tunnel. For an unscoped tunnel that is the default route (split into two `/1`s
  so it overrides the system default); for a [scoped](ch-01-03-flow-scoping.md)
  tunnel it is just the scope.

Both capsules are **full-state** (RFC 9484 §4.7): a later capsule replaces the
installed state whole, so the client re-applies rather than diffs.

## The forwarding loop

With the client addressed, the server installs forwarding state: it inserts the
client's address(es) into the route table pointing at this session, and records
the session's **egress policy** — exactly the ranges it advertised (RFC 9484
§4.7.3: a client MUST NOT send outside its advertised routes, and the server
enforces it).

From here the session is a pump. Uplink datagrams arrive via the connection
demux and enter the [forwarding engine](ch-01-02-forwarding.md), which validates
the packet, decrements TTL, and routes it — to another session (hairpin), to the
TUN device (out to the network), or to an ICMP reply. Downlink packets from the
TUN are dispatched back to the owning session and sent as datagrams.

The loop also tracks the [tunnel MTU](ch-01-04-mtu.md) — the smaller of the
configured `--mtu` and what one QUIC DATAGRAM currently carries — and refreshes
it as quinn's path MTU rises.

## Teardown

When the request stream or the connection closes, the session handler removes
the route-table entries, releases the pool addresses, and unregisters the demux
sink. Idle sessions are reaped by a background task
(`--session-idle-timeout-sec`). On a graceful shutdown the server sends HTTP/3
GOAWAY and drains established tunnels within a grace period before closing.
