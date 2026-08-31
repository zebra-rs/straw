# QUIC-aware proxying (`draft-ietf-masque-quic-proxy`) — scoping

`PLAN.md` Step 33 lists "draft-ietf-masque-quic-proxy support" as the last
unimplemented item. This note is the scoping pass, so the decision is made once
from evidence rather than re-argued each time someone reads that line.

**Recommendation: do not implement yet.** Not because it is hard — Tier A below
is a bounded, honest feature — but because the codepoints are guaranteed to
change and there is nothing to interoperate against. Revisit when the draft
leaves WG last call.

Assessed against **draft-09** (2026-07-06), read 2026-08-31.

## Status

- In **WG last call since 2025-11-03**, still there four revisions later.
- IESG state is "I-D Exists": never submitted, no shepherd, no responsible AD.
- Intended status was **raised from Experimental to Standards Track in -09**,
  mid-last-call — a sign the shape is still moving.
- The IANA section marks every capsule codepoint provisional and says plainly
  that **"the codepoints below will be replaced with lower values before
  publication."**

## What it actually adds

Two independently negotiated features:

**(a) Connection-ID awareness / target-facing port sharing.** The client
registers, via capsules, the connection IDs its QUIC connection to the target
uses. The proxy can then multiplex several proxied connections onto **one**
proxy→target UDP 4-tuple, demuxing return traffic by destination CID. Traffic
still travels tunnelled in HTTP Datagrams; this is purely a resource saving for
the proxy. Negotiated with `Proxy-QUIC-Port-Sharing: ?1`.

**(b) Forwarded mode.** The proxy assigns **virtual connection IDs**. The client
puts a target VCID in short-header packets sent *directly on the client↔proxy
UDP 4-tuple* — outside HTTP Datagrams entirely — and the proxy swaps VCID for
real CID, applies a negotiated byte transform, and forwards. This removes the
second layer of QUIC encryption and congestion control, saving CPU and
recovering the encapsulation MTU. Negotiated with `Proxy-QUIC-Forwarding: ?1`.

Long-header packets must always be tunnelled, forwarded mode is HTTP/3 only,
and the draft itself warns that removing congestion control on the client↔proxy
hop can make throughput *worse*.

One common fear is misplaced and worth stating: **the proxy never removes header
protection and never decrypts packets.** It reads only the header-form bit and
the connection ID, both RFC 8999 QUIC invariants. The work is byte-level header
surgery on invariant fields, not QUIC crypto.

## What implementing it would cost here

**Tier A — CID awareness only.** Bounded, and entirely above the QUIC stack:

- a capsule codec for ten types, with replies required in receive order and
  `MAX_CONNECTION_IDS` flow control over a shared sequence-number space;
- a CID table with an unusual conflict rule — two CIDs conflict if one is a
  **prefix** of the other, since short headers carry no CID length, so a
  zero-length CID conflicts with everything;
- a socket-model change: a target-facing socket now serves many sessions, so
  inbound datagrams demux by DCID rather than by socket;
- stateless resets from the target, which carry no usable CID, recognised via
  the token the client registered.

This is a plausible piece of work for straw, and it interoperates as a strict
subset — a client may use port sharing with forwarding absent.

**Tier B — forwarded mode.** A different order of difficulty, and the blocking
issue is not in this repo:

- forwarded packets arrive on the proxy's own QUIC socket bearing a CID that
  belongs to no local connection, so they must be intercepted *before* the
  endpoint routes them and injected back bypassing the stack. straw already has
  the shape of this trick in `p2p::relay_socket`, so it is tractable;
- VCID allocation must be coordinated with the QUIC stack's own CID generator
  to avoid conflicts on the shared 4-tuple, and VCIDs must be unpredictable;
- **the blocker:** the proxy must not forward to an unvalidated client address,
  must re-point rules on passive migration while withholding the return
  direction until validation, and must detect *active* migration and tear
  forwarding rules down. quinn exposes neither path-validation state nor
  migration events to the application. That needs quinn-proto surgery or
  upstream API work. (noq's multipath may expose more path state — worth
  checking if this is ever picked up.)

## Prior art

Effectively none that can be interoperated with. A GitHub code search for the
capsule names and the `Proxy-QUIC-Forwarding` header returns nothing;
google/quiche's MASQUE prototype has no CID-registration or forwarded-mode code;
the WG's own interop matrix lists two implementations but records only plain
RFC 9298 tests. The one credible implementation is Apple's closed-source
Network.framework — consistent with two of the three authors being at Apple.

Implementing this would very likely make straw the first public Rust
implementation, with nothing to test against but a client whose behaviour
cannot be inspected.

## If it is picked up

Do Tier A alone, treat `codepoints.rs` as the single place the provisional
capsule types live (as with every other provisional number here), and expect to
change them on publication. Leave Tier B until quinn or noq exposes path
validation and migration events.
