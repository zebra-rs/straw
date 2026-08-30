# Architecture

straw is a single Cargo package (not a workspace): one library crate with the
shared protocol logic, and a handful of binaries under `src/bin/` that wire it
to sockets and devices. A separate `bdd/` workspace member holds the end-to-end
test harness.

## Binaries

| Binary | Role |
|--------|------|
| **`straw`** | The CONNECT-IP proxy: a QUIC/H3 listener that terminates tunnels, assigns addresses, forwards to a TUN, and (optionally) NATs to the Internet. Also runs the P2P **relay** (CONNECT-UDP bind mode) and the RFC 5780 **STUN** server. |
| **`strawc`** | The VPN client daemon: opens a tunnel to a `straw` proxy, creates a TUN device, applies addresses/routes via `ip(8)`, and pumps packets. |
| **`strawcat`** | The peer-to-peer peer: `genkey` / `listen` / `connect`. Pipes stdio or (with `--vpn`) runs an IP tunnel between two peers over the relay or a punched direct path. |
| **`test_client`** | A synthetic-packet harness: sends crafted IP packets through a tunnel and exits non-zero unless every one is genuinely echoed back, so the BDD suite can assert on it. |

Neither `straw` nor `strawc` needs to be root; both need **ambient**
`CAP_NET_ADMIN` (they shell out to `ip`/`iptables`/`sysctl`, which inherit only
ambient capabilities).

## Library modules

The `straw` library groups the stack by concern:

| Module | Responsibility |
|--------|----------------|
| `server` | The QUIC/H3 listener: accept connections, demux datagrams, dispatch CONNECT-IP and CONNECT-UDP requests. Holds the `ProxyContext`. |
| `session/` | Per-stream CONNECT-IP tunnel lifecycle: request validation, authentication, address assignment, the forwarding loop. |
| `capsule/` | Encode/decode the Capsule Protocol: `ADDRESS_ASSIGN`, `ADDRESS_REQUEST`, `ROUTE_ADVERTISEMENT`, with QUIC varint wire format. |
| `datagram/` | HTTP Datagram handling and Context ID management. |
| `forwarding/` | The data plane: IP validation, TTL, ICMP, the TUN device (with GSO/TSO), the longest-prefix route table, and NAT. |
| `address_pool` | Per-session IPv4/IPv6 allocation from configured pools. |
| `uri_template` | Parses the `{target}` / `{ipproto}` URI-template variables for flow scoping. |
| `client` | `TunnelClient`/`Tunnel` (the CONNECT-IP client), `BindClient` (the relay bind client), and `PacketSender`, a cloneable send handle. |
| `iface` | Client-side kernel configuration: applies assignments and routes via `ip(8)`, reverts on drop. |
| `udp_bind/` | The relay's CONNECT-UDP **bind** side: public-address allocation, the compression-context codec, the socket forwarding loop, and the on-path punch observer. |
| `p2p/` | The strawcat peer: identity/token trust model, inner TLS, the relay socket, hole punching and the path state machine, port mapping, and STUN detection. |
| `codepoints` | One registry of every provisional wire codepoint and the v2 standards-swap plan. |

## The data path

For the proxy, a client's uplink packet crosses these layers once each way:

```
   client host                     straw proxy
 ┌────────────┐                  ┌──────────────┐
 │  TUN dev   │                  │ ForwardingEng│─── N6 ──▶ Internet
 │   (strawc) │                  │   + TUN dev  │   (opt. NAT)
 └─────┬──────┘                  └──────▲───────┘
       │ IP packet                      │ IP packet
       ▼                                │
 QUIC DATAGRAM  ── QUIC/H3 (RFC 9484) ──┘
```

The uplink is synchronous end to end: `strawc`'s TUN read pump calls
`PacketSender::send_packet`, which encodes the HTTP Datagram and hands it to
`quinn::Connection::send_datagram` with no queue or task in between. The downlink
is symmetric: the proxy's connection demux decodes each datagram and writes it
straight to the client's TUN.

## The peer-to-peer path

strawcat inverts the roles. Two peers each open a bind session to a relay; the
relay allocates each a public `(IP, port)` and forwards ciphertext between them.
Over that the peers build a second, **inner** QUIC connection — mutually
SPKI-pinned, so the relay is a blind forwarder — and then try to replace it with
a direct path:

```
        ┌─────────── relay (straw --udp-bind) ───────────┐
        │  forwards ciphertext; never sees the inner TLS │
        └───────▲───────────────────────────▲────────────┘
                │ bind session               │ bind session
          ┌─────┴─────┐                ┌──────┴────┐
          │  peer A   │····· punch ····│  peer B   │
          │ strawcat  │  (direct path) │ strawcat  │
          └───────────┘                └───────────┘
```

The [P2P overview](ch-03-00-p2p-overview.md) chapter picks up from here.
