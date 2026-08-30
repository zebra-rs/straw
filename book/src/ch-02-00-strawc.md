# strawc: the Client Daemon

`strawc` is the VPN client — the counterpart to the proxy. It establishes a
CONNECT-IP tunnel, turns the proxy's capsules into real kernel state (a TUN
device, addresses, routes), and pumps packets until it is told to stop.

## The lifecycle

1. **Connect.** `TunnelClient::connect_scoped` builds a client QUIC config (TLS
   trust from `--insecure`, `--ca-cert`, or mTLS), dials the proxy, wraps the
   connection for HTTP/3, and sends the Extended CONNECT — optionally scoped with
   `--scope-target` / `--scope-proto`. It returns once the proxy replies 200.
2. **Wait for the assignment.** `wait_for_assignment` reads capsules until an
   `ADDRESS_ASSIGN` (and route advertisement) have arrived.
3. **Size the tunnel.** The MTU is `--mtu`, or sampled from the connection's
   datagram size (a warning fires if it is below the IPv6 minimum).
4. **Create the device.** `spawn_tun` opens a bare TUN device; the read pump
   feeds each uplink packet straight into `PacketSender::send_packet` — no queue,
   no task in between.
5. **Apply kernel state.** `iface::configure` installs the assigned addresses and
   advertised routes on the device via `ip(8)`, returning an `InterfaceGuard`
   that reverts them on drop.
6. **Wire the downlink.** `set_packet_sink` points the connection's demux at the
   TUN writer, so inbound packets reach the device with no intermediate hop.
7. **Run.** A select loop tracks the MTU upward, re-applies state whenever a fresh
   `ADDRESS_ASSIGN` / `ROUTE_ADVERTISEMENT` arrives (they are full-state), and
   exits on SIGINT/SIGTERM — removing the addresses and routes as it goes.

## The `iface` layer

`iface` is the kernel-configuration seam. It builds `ip` command lines
(`addr_args`, `route_args`, `pin_args`, `mtu_args`) and runs them, recording an
undo list in the `InterfaceGuard`. Routes on a TUN device disappear with the
device, so the undo list matters mainly for the **pin route**.

## The pin route

A full tunnel installs a split-default route (`0.0.0.0/1` + `128.0.0.0/1`) that
captures *all* traffic — including the QUIC connection to the proxy itself, which
would loop the transport into its own tunnel. `strawc` avoids this by **pinning**
the proxy's address to the physical interface first: a host route to the proxy
via the real gateway, installed *before* any tunnel route, so there is never a
moment when a default-route half captures the QUIC connection. A proxy reached
over loopback needs no pin (no advertised route covers `127.0.0.0/8`).

## IPv6 and the bare device

The TUN device is created **bare** — no addresses — and everything is applied
from the capsules. That is deliberate: it lets `strawc` configure IPv6 addresses
too, which the `tun` crate cannot do itself, and it keeps a single code path for
the full-state re-apply.
