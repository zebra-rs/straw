# The BDD and netns Harnesses

straw is tested at three levels: unit tests inside the library, integration tests
that stand up real proxies over loopback, and end-to-end harnesses that run the
actual binaries in Linux network namespaces with real NATs.

## Unit and integration tests

`cargo test` runs the `straw` library's unit tests and its integration tests
(`tests/integration.rs`). The integration tests spin up a `TestServer` — a real
`straw` proxy on loopback — and exercise the full stack: address assignment and
routes, datagram hairpin between two clients, flow scoping and ingress
filtering, the auth modes, graceful shutdown, the metrics endpoint, and the whole
peer-to-peer path (bind sessions, inner QUIC over the relay, the punch and its
tie-break, the large-transfer MTU regression, port mapping, and STUN detection).

## The BDD suite

`bdd/` is a cucumber suite ported from the zebra-rs BDD framework. Its scenarios
(`bdd/tests/features/*.feature`) run the real `straw`, `strawc`, and `test_client`
binaries inside Linux network namespaces, so they test genuine kernel TUN I/O,
routing, and NAT — not mocks.

```bash
sudo -E env PATH="$PATH" make -C bdd                  # the whole suite, 4-way parallel
sudo -E env PATH="$PATH" make -C bdd tunnel_basic     # one feature, by its tag
sudo -E env PATH="$PATH" BDD_KEEP=1 make -C bdd tunnel_mtu   # …leaving it up
```

The namespaces need root, and `-E env PATH="$PATH"` is not decoration: root has
no `CARGO_HOME` of its own here, so a bare `sudo make -C bdd` fails at
`cargo: No such file or directory` before a single scenario runs.

Each feature scopes its namespaces, veths, and pid files by its first tag
(`@tunnel_basic` → `tunnel_basic_client`, …) so features run concurrently. `make
-C bdd stage` copies this worktree's binaries into `bdd/.stage/bin` and the
harness prepends that to `PATH`, so a run never tests a stale build. An unmatched
step fails the scenario rather than being skipped. `test_client` is the assertion
engine: it sends synthetic packets through a tunnel and exits non-zero unless
every one is genuinely echoed back.

## The NAT-traversal harnesses

The peer-to-peer path is exercised by dedicated netns scripts that need
passwordless `sudo`.

`scripts/nat-punch-test.sh` builds a **double-NAT** topology —
`peerA ─ natA ══ relay ══ natB ─ peerB`, MASQUERADE on both sides, the relay
routing between them — and asserts the relay data plane carries payload both ways
through the double NAT. The punch itself is reported, and *asserted* only in the
modes where it must succeed:

```bash
sudo scripts/nat-punch-test.sh                     # symmetric MASQUERADE; punch best-effort
sudo NAT_MODE=cone scripts/nat-punch-test.sh       # 1:1 NETMAP (cone); direct punch asserted
sudo PORTMAP=1 scripts/nat-punch-test.sh           # PCP/NAT-PMP forward; direct punch asserted
```

Where the punch is asserted, so is its *destination*: each peer's direct path
must lead to the other peer's public address, never the relay's — otherwise
"direct" would not mean what it says.

`scripts/vpn-test.sh` is the [VPN-mode](ch-03-05-vpn-mode.md) proof:
`peerA ─ relay ─ peerB`, both in `--vpn`, asserting a direct path to the peer
and a ping across the tunnel over it.
`scripts/natpmp-stub.py` is the harness's PCP/NAT-PMP responder, which installs
the 1:1 iptables forward that makes the symmetric-NAT punch succeed.

## Benchmarks

`sudo bench/iperf-baseline.sh` measures throughput through the tunnel;
`sudo -E env PATH="$PATH" bench/mtu-recovery.sh` measures whether a connection's
path MTU recovers after a black-hole detection, as an A/B between two
`quinn-proto` revisions, and `bench/tunnel-mtu-recovery.sh` runs that profile
through a real tunnel. The numbers and their analysis are the next chapter.
