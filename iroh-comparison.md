# straw and iroh

Both projects put two peers behind NATs into direct contact, both are Rust, and
since straw adopted **noq** they run the *same QUIC implementation*. That makes
the comparison worth writing down: the overlap is real, so the differences are
about design intent rather than accident.

**Provenance.** Everything said about straw here is from this tree. The account
of iroh's internals is from general knowledge, not from reading their source
today, and that project moves quickly — treat the iroh column as orientation,
and re-check it before making a decision that depends on it. Where a claim is
an expectation rather than a fact, it says so.

## The shared layer

straw's inner peer↔peer connection runs on [noq](https://github.com/n0-computer/noq),
n0's QUIC implementation — the same transport iroh is built on. straw adopted it
(`p2p-direct-path-design.md` §0) for three things it ships natively:

- the `nat_traversal` transport parameter and the extension frames from
  draft-seemann-quic-nat-traversal,
- native **multipath**, and
- the `AsyncUdpSocket` seam that lets an application supply its own transport.

So when straw punches a hole, `p2p/native_punch.rs` is a *driver* over n0's
frame implementation, not an implementation of its own. The v1 app-level punch
that predated this is deleted; its history is in git and its analysis is in
`symmetric-nat-traversal.md`.

Two more things are the same by convergence rather than by sharing code:

- **Identity.** An ed25519 key *is* the peer's name, carried in RFC 7250
  raw-public-key TLS with no PKI. straw pins the SPKI hash (`p2p/inner_tls.rs`);
  iroh's `NodeId` is the key itself.
- **The arc.** Meet at a relay, learn your reflexive address, punch, upgrade to
  direct, keep the relay as a fallback. straw is not novel here — this is the
  shape Tailscale and WebRTC use too.

Both relays forward only ciphertext they cannot read (straw's design goal G1).

## The differences

| | straw | iroh |
|---|---|---|
| What you get | an **IP tunnel** (RFC 9484 CONNECT-IP) | app-level **streams** to a `NodeId` |
| Relay protocol | MASQUE CONNECT-UDP + connect-udp-listen (RFC 9298 + draft) | iroh-relay, DERP-derived, over HTTP/WebSocket |
| Relay addressing | allocates a routable public **(IP, port)** per session | forwards by **public key** |
| Finding a peer | out-of-band `sc2_` capability token | a discovery system (DNS/pkarr, mDNS, relay) |
| Path switching | noq **multipath**: two real QUIC paths, promote/demote | magicsock swaps transport beneath a synthetic address |
| Above the connection | a VPN, or a stdio pipe | blobs, gossip, docs — a protocol ecosystem |
| Peers per session | one | many, as a mesh |

### The relay model is the deep one

straw's relay is a standards-track MASQUE proxy. A bind session allocates a
real, routable public UDP endpoint, and the relay forwards whatever arrives
there. That is a genuine RFC 9298 proxy — a non-straw client can use it, and the
same binary is also the CONNECT-IP VPN proxy — but it is, by construction, an
open forwarder. Hence:

- auth is **mandatory** in bind mode (`--udp-bind` refuses `--auth-mode none`),
- an egress SSRF guard denies loopback/RFC1918 by default
  (`--udp-bind-allow-dest` re-permits for private relays), and
- the **§10.4 lockdown** exists at all: once a direct path carries the traffic,
  the peer registers a *compressed* context bound to its peer and closes the
  uncompressed one, after which the relay drops everything from anyone else at
  its edge.

iroh's relay has no equivalent exposure. It forwards between authenticated nodes
keyed by public key, so "a stranger sends to your relay address" is not a shape
that exists, and no lockdown is needed. straw pays that cost deliberately, in
exchange for a relay that is a standard proxy rather than a bespoke one.

### Path switching is architecturally different

As I understand it, iroh's magicsock presents QUIC a single stable *synthetic*
address per node and swaps the real transport underneath, so the connection
never observes a path change.

straw does the opposite. `p2p/relay_socket.rs`'s `PathMuxSocket` is one
`AsyncUdpSocket` carrying both transports, and relay and direct are two
**actual QUIC paths** of one connection. `p2p/session.rs` promotes the direct
path to `Available` and demotes the relay to `Backup`, so QUIC's own path
validation and scheduling do the work; the relay path is never closed, and an
`Abandoned` event restores it and re-punches.

Both hide the switch from the application. straw's version leans on multipath
APIs that are still moving (noq 1.2.0 has no per-path MTU, which is why the
inner MTU is pinned at 1200 — see `UPSTREAM.md`). Since noq ships multipath,
iroh may well be converging on the same model; that is an expectation, not a
claim about their current code.

### The payload differs in kind

iroh gives you a connection and lets protocols live above it. straw's P2P mode
carries its **own CONNECT-IP stack** over the peer connection (`p2p/vpn.rs`: h3
over noq through the `p2p/h3_noq` adapter), so what comes out is a TUN device
with kernel routes — not a stream.

That nesting is why constraints appear here that would not arise in iroh: an IP
tunnel inside a QUIC connection that may itself be tunnelled inside another
QUIC connection's datagrams. The 1200-byte inner MTU pin, the flow scoping that
keeps the tunnel from capturing its own transport, and the tunnel-MTU tracking
in `ch-01-04-mtu.md` all follow from it.

## Choosing between them

- Want **application connectivity** between many peers, with discovery, and
  protocols to build on: that is what iroh is for, and straw offers no
  equivalent.
- Want an **IP-level VPN**, or a MASQUE proxy that speaks published RFCs and
  interoperates as one: that is straw, and iroh does not do it.

They are not really competitors; straw uses n0's transport to build a different
kind of thing on top.
