# Running straw (the Proxy)

`straw` is configured by CLI flags, optionally layered over a TOML file with
`--config`. A flag wins only when it is actually given (clap `ValueSource`), so
the file provides defaults and the command line overrides them. The TOML keys
mirror the flags; see `straw.example.toml` in the repository.

## Listener and TLS

| Flag | Meaning |
|------|---------|
| `--listen <addr>` | UDP address to listen on for QUIC (required). |
| `--cert <pem>` / `--key <pem>` | Server certificate chain and key. Omit both to use a generated self-signed certificate. |
| `--idle-timeout-ms <n>` | QUIC idle timeout. |
| `--max-sessions <n>` | Cap on concurrent tunnels. |

## Addressing and forwarding

| Flag | Meaning |
|------|---------|
| `--ipv4-pool <cidr>` / `--ipv6-pool <cidr>` | Address pools clients are assigned from. |
| `--mtu <n>` | Tunnel MTU cap (the live MTU is the smaller of this and the datagram size). |
| `--tun` / `--tun-name <name>` | Open a kernel TUN device (without it, only client-to-client hairpin forwarding works). |
| `--nat-interface <iface>` | MASQUERADE pool traffic out this interface (writes `ip_forward`). |
| `--split-routes` | Advertise a split default route. |
| `--accept-client-routes` | Accept routes the client advertises. |
| `--max-packet-rate` / `--max-byte-rate` | Per-session egress caps (0 = unlimited). |

## Authentication

| Flag | Meaning |
|------|---------|
| `--auth-mode <none\|bearer\|basic\|mtls>` | How clients authenticate. |
| `--auth-token <tokens>` | Accepted bearer token(s) for `bearer` (comma-separated). |
| `--auth-basic <user:pass>` | Credentials for `basic`. |
| `--client-ca <pem>` | CA that client certificates must chain to for `mtls`. |

## The P2P relay (CONNECT-UDP bind mode)

| Flag | Meaning |
|------|---------|
| `--udp-bind` | Enable bind mode (the P2P relay). **Requires** an auth mode other than `none`. |
| `--udp-bind-public-ips <ips>` | Public IPs to allocate bind-session `(IP, port)` tuples from. |
| `--udp-bind-port-lo <n>` / `--udp-bind-port-hi <n>` | Bind-session port range. |
| `--udp-bind-allow-dest <cidrs>` | Destination prefixes the SSRF guard re-permits. |
| `--udp-bind-max-pps` / `--udp-bind-max-bps` | Per-session egress caps. |
| `--udp-bind-observe` | On-path punch observer for relay-assisted traversal (needs `CAP_NET_RAW`). |

## The RFC 5780 STUN server

| Flag | Meaning |
|------|---------|
| `--stun-addr <ip:port>` | Primary STUN address. Enabled together with the alternate. |
| `--stun-alt-addr <ip:port>` | Alternate address advertised as `OTHER-ADDRESS`, a different IP *and* port, for the RFC 5780 mapping tests. |

## Operations

| Flag | Meaning |
|------|---------|
| `--config <file>` | Layer a TOML file under the CLI. |
| `--metrics-listen <addr>` | Prometheus metrics endpoint. |
| `--session-idle-timeout-sec <n>` | Idle-session reaper interval. |
| `--shutdown-grace-sec <n>` | Grace period for draining tunnels on shutdown. |

## A relay, fully

A production-style P2P relay with bind mode, STUN behaviour discovery, and the
on-path observer:

```bash
straw \
    --listen 0.0.0.0:4433 \
    --udp-bind --udp-bind-public-ips 203.0.113.10 \
    --udp-bind-port-lo 30000 --udp-bind-port-hi 40000 \
    --auth-mode bearer --auth-token "$RELAY_TOKEN" \
    --udp-bind-observe \
    --stun-addr 203.0.113.10:3478 --stun-alt-addr 203.0.113.11:3479
```
