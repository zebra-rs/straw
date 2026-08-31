# Building and Running

## Build

straw uses Rust edition 2024 (a recent stable toolchain).

```bash
cargo build            # build all binaries
cargo test             # run the unit + integration tests
cargo clippy           # lint
cargo fmt              # format
```

A plain `cargo test` covers the `straw` library and its integration tests. The
`bdd/` workspace member is an end-to-end cucumber suite that runs the real
binaries in Linux network namespaces; it needs root and is driven through its
own `Makefile` (see [Testing](ch-04-00-testing.md)).

**The first build needs network access to git.** `quinn-proto` is patched to
upstream's `0.11.x` branch rather than the crates.io release — it carries two
fixes straw depends on, and neither is in a release yet (`UPSTREAM.md` entry 1
has the details and the check for when that changes). `Cargo.lock` pins the
exact revision, and the checkout is cached under `CARGO_HOME` afterwards, so
only the first build reaches out.

## A proxy and a client, by hand

The quickest way to see a tunnel is a self-signed proxy and one client. This
needs `CAP_NET_ADMIN` (run under `sudo`, or grant the capability), because both
sides configure a TUN device and routes.

**1. Start the proxy** with a TUN device and an address pool:

```bash
sudo straw \
    --listen 0.0.0.0:4433 \
    --ipv4-pool 10.100.0.0/24 \
    --tun --tun-name straw0
```

The proxy generates a self-signed certificate (omit `--cert`/`--key` to use
one), assigns clients from `10.100.0.0/24`, and forwards through the TUN device
`straw0`. Add `--nat-interface eth0` to masquerade tunnel traffic out to the
Internet.

**2. Connect a client**, trusting the self-signed cert with `--insecure`:

```bash
sudo strawc \
    --server-addr <proxy-ip>:4433 \
    --insecure \
    --tun-name straw0
```

`strawc` prints the address it was assigned and the routes it installed. A
packet sent into `straw0` now travels over QUIC to the proxy and out its TUN.

## A peer-to-peer pipe

For strawcat you need a relay (a `straw` proxy in **bind mode**) and two peers.

**1. Run the relay** with bind mode and an auth token:

```bash
straw --listen 0.0.0.0:4433 \
    --udp-bind --udp-bind-public-ips <relay-public-ip> \
    --udp-bind-port-lo 30000 --udp-bind-port-hi 30999 \
    --auth-mode bearer --auth-token s3cret
```

**2. Each peer makes a key**, then one listens and one connects:

```bash
strawcat genkey > a.key           # on peer A
strawcat genkey > b.key           # on peer B

# peer A prints a token:
strawcat listen  --relay <relay>:4433 --insecure --bearer-token s3cret --identity a.key
# peer B uses that token:
echo hello | strawcat connect <token> --relay <relay>:4433 --insecure --bearer-token s3cret --identity b.key
```

Peer A reads `hello` on stdout. Behind the scenes the two formed a mutually
pinned inner QUIC connection through the relay and — on loopback or a cone
NAT — punched a direct path. Add `--vpn` on both sides to get an IP tunnel
between the hosts instead of a stdio pipe (see [VPN Mode](ch-03-05-vpn-mode.md)).

## Privileges

`straw` and `strawc` do not need to run as `root`, but they do need **ambient**
`CAP_NET_ADMIN`: they invoke `ip`, `iptables`, and `sysctl`, which inherit only
ambient capabilities. The packaging `*.service` units set it. The relay's
on-path punch observer additionally needs `CAP_NET_RAW`
([relay-assisted traversal](ch-03-04-symmetric-nat.md)).
