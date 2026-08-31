# Running strawc and strawcat

## strawc — the VPN client

`strawc` opens a CONNECT-IP tunnel to a `straw` proxy and configures a TUN device
from the assignment.

| Flag | Meaning |
|------|---------|
| `--server-addr <addr>` | The proxy's QUIC address (required). |
| `--server-name <name>` | TLS server name of the proxy certificate. |
| `--insecure` | Skip certificate verification (testing only). |
| `--ca-cert <pem>` | Trust this CA / self-signed certificate. |
| `--bearer-token <t>` / `--basic <user:pass>` | Request credentials. |
| `--tun-name <name>` | TUN device name. |
| `--mtu <n>` | Pin the tunnel MTU (otherwise it is sampled and tracked upward). |
| `--no-routes` | Configure addresses only; install no routes. |
| `--scope-target <t>` | Request a scoped tunnel to an IP, prefix, or hostname. |
| `--scope-proto <n>` | Restrict the tunnel to an IP protocol number. |

```bash
sudo strawc --server-addr proxy.example:4433 --ca-cert proxy-ca.pem --tun-name straw0
```

## strawcat — the peer

`strawcat` has three subcommands: `genkey`, `listen`, and `connect`. `genkey`
writes a persistent identity (PKCS#8 PEM) to stdout and its pin to stderr.
`listen` and `connect` share the relay and peer-to-peer flags below.

### Reaching the relay

| Flag | Meaning |
|------|---------|
| `--relay <addr>` | The relay's QUIC address (required). |
| `--server-name <name>` / `--insecure` / `--ca-cert <pem>` | Relay TLS trust. |
| `--bearer-token <t>` | Relay credential (bind mode requires auth). |
| `--identity <pem>` | Identity from `genkey` (omit for an ephemeral one). |
| `--ttl <secs>` | Token lifetime (`listen` only). |

### Punching and NAT traversal

| Flag | Meaning |
|------|---------|
| `--punch-wait <secs>` | How long to wait for a direct path before using the relay. |
| `--punch-strategy <basic\|predict\|birthday\|relay-assisted>` | The NAT-traversal strategy. Only `basic` is live — the others warn and fall back to it (see [Symmetric NAT Traversal](ch-03-04-symmetric-nat.md)). |
| `--port-map` | Ask the router (PCP / NAT-PMP) for an explicit forward and advertise it. |
| `--stun-detect <server>` | Classify the NAT (RFC 5780) first and report the class. |

### VPN mode

| Flag | Meaning |
|------|---------|
| `--vpn` | Run an IP tunnel between the peers instead of piping stdio. |
| `--vpn-subnet <cidr>` | (`listen`) address pool the connector is assigned from. |
| `--vpn-tun <name>` | TUN device name. |
| `--vpn-mtu <n>` | Override the VPN tunnel MTU. |
| `--vpn-no-routes` | (`connect`) configure the address but install no routes. |

### A full P2P session

```bash
strawcat genkey > peer.key
# Listen (prints a token), detecting the NAT and asking the router for a forward:
strawcat listen --relay relay.example:4433 --bearer-token "$T" --identity peer.key \
    --stun-detect relay.example:3478 --port-map --vpn --vpn-subnet 10.9.0.0/24
# Connect with the token on the other host:
strawcat connect <token> --relay relay.example:4433 --bearer-token "$T" \
    --identity peer2.key --port-map --vpn
```
