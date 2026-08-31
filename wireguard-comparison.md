# WireGuard and MASQUE (CONNECT-IP)

Both put IP packets inside an authenticated, encrypted UDP flow and hand the
result to a TUN device. From a distance they solve the same problem, and a lot
of the time either would do. The differences are almost entirely about what
else the protocol is asked to carry — and about one thing WireGuard
deliberately refuses to do, which turns out to be the whole reason MASQUE
exists.

**Provenance.** Everything said about straw is measured or read in this tree.
Everything said about WireGuard's *protocol* is from its specification and the
Linux implementation; the throughput numbers for it in
[Performance, measured](#performance-measured) were taken on this host by
`bench/wireguard-vs-straw.sh` and carry the caveats listed there. The
deployment claims in [Ecosystem](#ecosystem-and-maturity) are general
knowledge, not verified today — treat them as orientation.

## What each one is

**WireGuard** is a single, closed protocol. A peer *is* a Curve25519 public
key. The handshake is Noise `IKpsk2`, the AEAD is ChaCha20-Poly1305, the hash
is BLAKE2s, and none of that is negotiated: there are no cipher suites, no
extensions, no version field to argue about. Four message types, fixed sizes,
around 4,000 lines of kernel C, with machine-checked proofs of the handshake.
There is no IETF standards-track RFC — an informational draft was submitted
and expired — so the specification is the paper plus the reference
implementation.

**MASQUE CONNECT-IP** is a profile of HTTP. An extended `CONNECT` request
(RFC 9484) opens an IP tunnel on an HTTP/3 stream; IP packets ride as HTTP
Datagrams (RFC 9297) in QUIC DATAGRAM frames (RFC 9221); a control channel of
capsules on the same stream carries addressing and routes. Crypto is whatever
TLS 1.3 negotiated inside QUIC. It is standards-track, with IANA registries,
and it inherits an entire HTTP stack — for better and for worse.

So: one protocol that does exactly one thing, versus one that is assembled out
of five RFCs and can do several.

## The parts that are genuinely the same

- **The data plane shape.** Read an IP packet from a TUN device, authenticate
  and encrypt it, send one UDP datagram, reverse on the far side. Unreliable,
  unordered, no retransmission of the tunnelled packet. Neither protocol
  reliably delivers your inner packets, and both are right not to.
- **Modern AEAD, 1-RTT, forward secrecy.** Different constructions, same
  guarantees in practice.
- **Roaming works.** Both survive the client's address changing mid-session.
- **The MTU is smaller than you want**, and neither can conjure the missing
  bytes.
- **A userspace TUN device on every platform.** WireGuard has a kernel path on
  Linux; MASQUE has none anywhere.

## Side by side

| | WireGuard | MASQUE CONNECT-IP |
|---|---|---|
| Specification | a paper + one reference implementation | RFC 9484 / 9297 / 9221 over RFC 9000 |
| Crypto | fixed: X25519 + ChaCha20-Poly1305 + BLAKE2s | negotiated: whatever TLS 1.3 offers |
| Identity | the peer's public key | X.509, or raw public keys (RFC 7250) |
| Authorization | `AllowedIPs`, static, out of band | HTTP auth on the request; in-band |
| Addressing | you configure it yourself | `ADDRESS_ASSIGN` / `ADDRESS_REQUEST` capsules |
| Routes | `AllowedIPs`, static | `ROUTE_ADVERTISEMENT` capsule, in-band |
| Transport | UDP only | QUIC, or HTTP/2 over TCP as a fallback |
| On the wire | a distinctive UDP protocol | an ordinary HTTP/3 connection |
| Per-packet overhead | 32 B over UDP | ~30 B on the wire, 40 B budgeted |
| Kernel implementation | yes, on Linux | none |
| Multiplexing | one tunnel per interface | many tunnels, plus CONNECT-UDP/TCP, on one connection |
| Server state | a peer table | a session table, dynamic |
| Code you must trust | ~4k lines | QUIC + TLS + HTTP/3 + capsules |

## Where WireGuard wins

### Attack surface, and being able to read it

Four thousand lines is a quantity a person can audit in an afternoon, and the
handshake has been verified in Tamarin and CryptoVerif. A MASQUE endpoint's
trusted computing base is a QUIC implementation, a TLS implementation, an
HTTP/3 implementation and a capsule parser. straw is a few thousand lines of
its own on top of tens of thousands it did not write. That is not a fatal
objection — those libraries are widely deployed and heavily fuzzed — but it is
a real and permanent difference in what you are trusting, and no amount of
care in straw changes it.

### Silence

An unauthenticated packet to a WireGuard endpoint produces *nothing*. The port
does not answer, so a scanner cannot tell WireGuard from a closed port. Under
load the cookie-reply mechanism makes flooding expensive without ever creating
state. A QUIC server, by contrast, answers: it is discoverable by design,
because it is pretending to be a web server, and pretending requires replying.
straw pays this in a specific place — the relay's bind port is a public
forwarder, which is why §10.4's lockdown exists at all.

### Simplicity as an operational property

`wg genkey`, exchange two public keys, set `AllowedIPs`, done. No certificate,
no expiry, no clock, no CA, no ALPN, no revocation. `AllowedIPs` doubling as
both the route and the ACL — cryptokey routing — is the single best idea in the
protocol: it makes "which packets may this peer send me" and "where do I send
this packet" the same table, so they cannot disagree. MASQUE needs a PKI or an
explicit pinning scheme, an authorization decision, and an address-assignment
protocol, and each of those is a thing that can be misconfigured.

### Efficiency per core

The work per packet is one AEAD call in softirq context, rather than a QUIC
packet's worth of protocol processing in a userspace event loop. On a busy
server with many peers and a multi-queue NIC, that gap is real and compounds.
(It does not show up in the measurement below, for reasons the measurement
explains.)

Note that this is about *cycles*, not bytes: the per-packet **overhead** is
close to a wash, which surprised me — see below.

## Where MASQUE wins

### It survives networks that dislike VPNs

This is the point, and everything else is secondary. WireGuard is trivially
fingerprinted: a fixed first byte, fixed-length handshake packets, a
distinctive UDP flow. Any DPI box can drop it, and many do — corporate
networks, hotel captive portals, and national firewalls all block it, without
needing to break it. WireGuard has no answer: no TCP mode, no obfuscation, no
port 443 story. The ecosystem's workaround is to tunnel WireGuard inside
something else, which is an admission.

MASQUE runs on 443, negotiates the `h3` ALPN, and looks like a browser fetching
a page, because at the protocol level it *is* one. When QUIC is blocked
outright, CONNECT-IP still works over HTTP/2, with the datagrams degraded to
capsules on a reliable stream — head-of-line blocking and TCP-in-TCP, genuinely
worse, but *working* is a different category from *blocked*.

Be precise about what this buys: it defeats **protocol fingerprinting**, not
**traffic analysis**. A sustained, bidirectional, bulk flow to one host for an
hour does not look like browsing no matter what the handshake says, and a
censor willing to block QUIC wholesale, or to run a statistical classifier, is
a different and much harder adversary. What MASQUE removes is the cheap,
deterministic, zero-false-positive signature that gets WireGuard dropped by
default.

### A control plane, in band

WireGuard has no opinion about what address you should use, what routes you
should install, whether you are still authorized, or why a connection was
refused. Everything is static configuration, which is why WireGuard in practice
means WireGuard *plus an orchestrator* — Tailscale, Netbird, Netmaker,
`wg-easy` — that distributes keys and addresses out of band. That layer is
where the operational complexity actually lives; it just isn't WireGuard's.

CONNECT-IP puts it in the protocol. The client asks for an address and the
proxy assigns one; the proxy advertises routes; the request carries
authorization and gets an HTTP status code back when it is refused, with a
reason. straw's flow scoping goes further and makes the request URI itself the
policy: a scoped session's egress filter is also its ingress filter.

### Cipher agility is not just future-proofing

WireGuard's fixed suite means a break is a flag day, and hybrid post-quantum
key exchange can only be approximated by distributing a 32-byte pre-shared key
out of band to every peer pair. TLS 1.3 gets X25519MLKEM768 by upgrading a
library.

It also has a measurable cost today. On this host — an arm64 machine with the
ARMv8 crypto extensions — the two ciphers are not close:

| AEAD | 8 KB blocks |
|---|---|
| AES-128-GCM | 4,312 MB/s |
| ChaCha20-Poly1305 | 1,305 MB/s |

(`openssl speed`, same host.) ChaCha20 was chosen precisely because it is fast
*without* hardware support, which was the right call for phones in 2016. But
where an AES engine exists — every current server CPU — a negotiated suite
picks it up and WireGuard cannot. At tunnel rates this is a few percent of a
core rather than the bottleneck, so it is a footnote, not an argument. It is
still the fixed-suite trade-off showing up as a number.

### One connection, many things

A single QUIC connection can carry several CONNECT-IP tunnels, CONNECT-UDP and
CONNECT-TCP sessions, and ordinary HTTP requests at once, sharing one handshake
and one congestion controller. Proxies chain: a MASQUE tunnel inside a MASQUE
tunnel is just a request. WireGuard's unit is an interface with a peer list;
there is no notion of composing one with another.

straw uses this directly. `strawcat`'s relay is a CONNECT-UDP bind session, and
the peer-to-peer VPN is a CONNECT-IP tunnel nested inside the QUIC connection
that the bind session carries. That nesting is expressible because it is all
HTTP.

## Performance, measured

`bench/wireguard-vs-straw.sh` brings both tunnels up in the *same* three
network namespaces, back to back, and drives them with the same iperf3
profile. Same host, same veths, same NAT, same session — only the tunnel
differs. WireGuard was given straw's live tunnel MTU (1412) so both carry the
same payload per packet.

| case | throughput | cores busy |
|---|---|---|
| raw veth, uplink | 136.7 Gbit/s | 1.88 |
| raw veth, downlink | 137.9 Gbit/s | 1.89 |
| **straw** uplink | **4.27 Gbit/s** | 4.30 |
| **straw** downlink | **5.66 Gbit/s** | 4.17 |
| straw uplink ×4 streams | 4.23 Gbit/s | 4.46 |
| straw downlink ×4 streams | 5.49 Gbit/s | 4.31 |
| **WireGuard** uplink | **2.09 Gbit/s** | 3.72 |
| **WireGuard** downlink | **2.27 Gbit/s** | 3.76 |
| WireGuard uplink ×4 streams | 2.05 Gbit/s | 3.72 |
| WireGuard downlink ×4 streams | 2.14 Gbit/s | 3.76 |

UDP tells the same story: offered 4 Gbit/s, straw carries 4.00 at 0.27 % loss,
WireGuard carries 2.12 at 0.89 %.

These are one run's numbers, but they are not delicate: across three runs straw
held 4.23–4.27 uplink and 5.49–5.66 downlink, WireGuard 2.05–2.09 and
2.14–2.27.

Userspace MASQUE beat in-kernel WireGuard by about 2×. **Do not take that at
face value** — it is a fact about this topology, and the interesting part is
why.

### It is a packet-rate wall, not a byte-rate one

`MTU_SWEEP=1` re-runs the WireGuard leg at three tunnel widths:

| tunnel MTU | throughput | wg0 packet rate |
|---|---|---|
| 1412 | 1.98 Gbit/s | 182,437 pps |
| 1440 | 1.81 Gbit/s | 162,698 pps |
| 8920 | **11.00 Gbit/s** | 155,192 pps |

Throughput moves 6× while the packet rate stays inside a ±8 % band. (The
1412/1440 pair differ by less than run-to-run variance — a second run put 1440
at 2.12 Gbit/s and 191k pps — so the jumbo case is the signal.) Nothing
byte-proportional — not the cipher, not the copies — is the constraint.
Per-CPU sampling during a run names it:

```
all:    %soft 18.64   %idle 69.18
CPU 8:  %soft 91.17   %idle  0.00
```

One softirq core is saturated while the box as a whole is 69 % idle. A single
flow through veth lands on one CPU, and every packet pays a full kernel
traversal there: routing, netfilter, conntrack, veth transmit.

### straw pays that toll 8× less often

The harness counts skbs on both the outer and the inner device, during the
uplink run:

| | outer (veth0) | inner (TUN) |
|---|---|---|
| straw | 45,699 skbs/s, avg **12,454 B** | 8,315 skbs/s, avg **64,219 B** |
| WireGuard | 192,360 skbs/s, avg 1,486 B | 192,360 skbs/s, avg 1,444 B |

WireGuard's two rows are identical: one inner packet in, one outer packet out,
no aggregation anywhere. (Its 1,486-byte frames are also an independent check
on the overhead table above — 1486 − 14 Ethernet − 20 IP − 8 UDP − 1412 inner
= exactly the 32 bytes WireGuard documents.)

straw's rows are not identical. Its TUN device negotiates `IFF_VNET_HDR` with
TSO and reads 64 KB aggregates, and quinn coalesces ~8.6 QUIC packets into one
`sendmsg` with `UDP_SEGMENT`, reassembling with `UDP_GRO` on the far side —
12,454 / 1452 = 8.6, which independently confirms the 1452-byte QUIC packet
derived above.

Per bit carried, WireGuard puts **~8.6× more skbs** through the kernel's packet
path. When that path is the bottleneck, that ratio is the result.

So the honest summary is: *in this topology, at a single flow, batching beats
being in the kernel.* Both numbers are real, and the mechanism generalises —
GSO/GRO is not a namespace artifact, and Linux's in-kernel WireGuard genuinely
has no equivalent batching on its outer UDP path — but the magnitude will not.

### What this measurement cannot tell you

- **Kernel versus userspace is confounded with WireGuard versus MASQUE.** No
  userspace WireGuard (`wireguard-go`, `boringtun`) is installed on this host,
  so the comparison that would isolate the protocol was not run. Against
  `boringtun` the result would very likely look different.
- **One flow, one peer.** WireGuard parallelises across peers; with one peer
  and one flow it does not, and neither does straw (`×4` helps neither). A
  server with a hundred peers is a different measurement entirely.
- **veth in namespaces, not a NIC.** No RSS, no interrupt steering, no driver.
  A real multi-queue NIC spreads the softirq load that pinned one core here, and
  that is exactly where WireGuard's efficiency per core would start to pay.
- **arm64 with AES but not ChaCha acceleration.** This is where the cipher
  table above applies. It is representative of current servers, not of phones.
- **Loopback-class bandwidth.** The 138 Gbit/s ceiling means both legs are
  measuring CPU, not a network. Over any real link that costs less than a few
  Gbit/s, both protocols saturate it and none of this matters.

Reproduce with `sudo bench/wireguard-vs-straw.sh [seconds]`, or
`sudo MTU_SWEEP=1 bench/wireguard-vs-straw.sh` for the packet-rate diagnosis;
`WG_MTU=1440` gives WireGuard its natural width on this path instead of
straw's. straw's own profile is in `bench/BASELINE.md`.

## Where each one bites you

### WireGuard

- **Blocked, not broken.** The failure mode is a silent one: no handshake
  response, no diagnostic, and the protocol offers you nothing to try next.
- **MTU is a guess.** 1420 by convention, and no in-band way to learn better.
  Get it wrong and you get a black hole that looks like a working tunnel until
  someone sends a large packet.
- **`AllowedIPs` conflates two things.** Convenient until you want asymmetric
  policy — "route this here, but do not accept it from there" is not
  expressible.
- **No revocation.** Removing a peer means editing configuration on every peer
  that knows it.
- **Roaming reveals the endpoint.** The peer learns your current public
  address, by design.

### MASQUE

- **The MTU is nested, and the nesting is fragile.** The tunnel MTU is
  whatever one QUIC DATAGRAM can carry *right now*, and QUIC's path MTU starts
  low and rises, so a value sampled at setup blackholes full-size packets
  later. straw holds it as a live `AtomicUsize` for exactly this reason
  (`ch-01-04-mtu.md`). Worse, a bug in the QUIC layer's black-hole detector
  can pin a connection at the 1200-byte floor for the rest of a transfer —
  measured, not hypothetical (`bench/MTU-RECOVERY.md`), and the reason this
  repo pins `quinn-proto` to a branch.
- **Overload needs an explicit policy.** QUIC DATAGRAMs queue, and something
  must decide what to drop. straw drops oldest and counts it; getting this
  wrong panicked the tunnel until an upstream accounting bug was fixed.
- **Congestion control interacts.** The tunnel's own controller sits under the
  tunnelled flow's. Datagrams are not retransmitted, so this is not the
  classic TCP-over-TCP meltdown, but pacing and the datagram queue still shape
  the inner flow in ways a plain packet pipe does not.
- **Certificates.** Expiry, clock skew, chains, and a whole failure genre
  WireGuard simply does not have.
- **Nobody has a kernel implementation**, so the userspace hop is unavoidable
  on every platform.

## Ecosystem and maturity

WireGuard is in the Linux kernel, in every distribution, on every phone, and in
every commercial VPN's client. It is the default answer, and picking anything
else needs a justification.

MASQUE is young — RFC 9484 is from 2023 — but the large deployments are
proxies, not hobby projects: Apple's iCloud Private Relay, Cloudflare's WARP
and Google's IP Protection in Chrome have all been publicly described as using
the MASQUE family. Note that these are mostly CONNECT-UDP rather than
CONNECT-IP; the full IP tunnel has fewer interoperable implementations, and
straw is one of them. (This paragraph is general knowledge; check it before
depending on it.)

## Choosing between them

- **A VPN between machines you control, on networks that let UDP through**:
  WireGuard. Less to run, less to trust, less to get wrong. straw does not
  claim otherwise.
- **A tunnel that has to survive hostile or filtering networks**: MASQUE. This
  is the one thing WireGuard cannot be made to do, and it is not close.
- **A multi-tenant gateway that assigns addresses, authorizes per session, and
  scopes what each client may reach**: MASQUE, because that machinery is in the
  protocol rather than in an orchestrator you also have to operate.
- **Interoperating with someone else's proxy**: MASQUE, because there is a
  specification and a registry to interoperate against.
- **Auditability above all**: WireGuard, decisively.

They also compose. WireGuard inside a MASQUE tunnel is a reasonable design when
you want cryptokey routing but the network only passes 443 — the same shape as
running WireGuard over an obfuscation layer, with a standards-track tunnel in
place of the obfuscator.
