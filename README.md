# straw

A from-scratch Rust implementation of an [RFC 9484](https://www.rfc-editor.org/rfc/rfc9484)
(CONNECT-IP) proxy — an IP-level VPN gateway built on the MASQUE protocol: IP
packets tunnelled over QUIC using HTTP Datagrams and the Capsule Protocol, inside
HTTP/3.

straw is three things that share one protocol stack:

- **`straw`** — the CONNECT-IP proxy: a QUIC/HTTP-3 listener that terminates
  tunnels, assigns addresses, and forwards IP packets through a kernel TUN device
  (with routing, ICMP, and optional NAT). It also runs the peer-to-peer relay and
  the STUN server.
- **`strawc`** — the VPN client daemon: opens a tunnel to a proxy, creates a TUN
  device, applies the assigned addresses and routes, and pumps packets.
- **`strawcat`** — the peer-to-peer peer: two peers rendezvous through a relay,
  form a mutually SPKI-pinned inner QUIC connection (on **noq**, the n0/iroh
  quinn fork straw adopted for native NAT traversal + multipath) the relay cannot
  read, and —
  where the NATs allow — hole-punch a direct path. Over it they pipe stdio or run
  a full IP tunnel between the hosts (`--vpn`).

## Documentation

**📖 The [straw manual](book/) is the primary reference** — a book covering the
proxy, the client, and the peer-to-peer direct path in depth. Build it with
[mdBook](https://rust-lang.github.io/mdBook/):

```bash
cargo install mdbook
cd book && mdbook build      # then open book/index.html
```

See [`book/README.md`](book/README.md) for more. Other in-repo references:

- [`p2p-direct-path-design.md`](p2p-direct-path-design.md) — the peer-to-peer
  design document.
- [`symmetric-nat-traversal.md`](symmetric-nat-traversal.md) — the NAT taxonomy
  and why symmetric↔symmetric is the hard case.
- [`wireguard-comparison.md`](wireguard-comparison.md) — WireGuard versus
  MASQUE CONNECT-IP, including a measured throughput A/B on one host.
- [`iroh-comparison.md`](iroh-comparison.md) — how straw's peer-to-peer path
  relates to iroh, with which it shares a QUIC implementation.
- [`CLAUDE.md`](CLAUDE.md) — a dense orientation for working in the codebase.

## Building

Rust edition 2024 (a recent stable toolchain).

```bash
cargo build            # build all binaries
cargo test             # unit + integration tests
cargo clippy           # lint

make -C bdd            # end-to-end BDD suite (needs passwordless sudo)
```

Neither `straw` nor `strawc` needs root — both need ambient `CAP_NET_ADMIN`. See
[Building and Running](book/src/ch-00-02-building-and-running.md) in the manual
for a first proxy + client and a first peer-to-peer pipe.
