# Inner QUIC Over the Relay

With both peers bound to the relay, strawcat builds the **inner** connection: a
second QUIC connection, peer to peer, tunnelled through the relay as datagrams
and encrypted end to end so the relay stays a blind forwarder.

## The relay socket

quinn drives a connection over anything that implements `AsyncUdpSocket`. straw
provides `p2p::relay_socket::RelaySocket`, an `AsyncUdpSocket` whose "wire" is a
bind session:

- **send** — `try_send` frames the inner packet as a bind datagram (Quarter
  Stream ID + uncompressed body naming the peer's relay-public address) and calls
  `send_datagram` on the *outer* connection.
- **receive** — a pump task reads the outer connection's datagrams, filters by
  Quarter Stream ID, decodes the body, and feeds the inner packet to the inner
  endpoint's receive path.

An inner `quinn::Endpoint` is built over that socket
(`inner_endpoint`, via `Endpoint::new_with_abstract_socket`). To quinn it is an
ordinary connection; underneath, every packet is one outer QUIC DATAGRAM the
relay forwards to the peer.

## Mutual SPKI pinning (RFC 7250)

The inner connection uses **raw public keys**
([RFC 7250](https://www.rfc-editor.org/rfc/rfc7250)) instead of X.509 chains:
each side presents its bare Ed25519 SubjectPublicKeyInfo and pins the other's by
SHA-256. `p2p::inner_tls` builds this with rustls' raw-public-key resolvers and a
`PinVerifier` that implements *both* the server and client certificate-verifier
traits (each peer is simultaneously the inner client on one connection and the
inner server on the other). Verification uses
`verify_tls13_signature_with_raw_key`; QUIC is TLS 1.3 only, so the TLS 1.2 path
is rejected. The ALPN is `strawcat/1`.

Because the pinning is mutual and the keys are the peers' own, the relay — which
only ever sees the ciphertext — can neither read the connection nor stand in the
middle of it.

## The relay-path MTU pin

Nesting QUIC in QUIC datagrams has one sharp edge. Each inner packet must fit in
one outer QUIC DATAGRAM, but quinn's path-MTU discovery, left to itself, probes
the *inner* connection upward until its packets (≈1420 bytes) no longer fit the
outer datagram. Those oversize packets fail `send_datagram`; the handshake — whose
packets are ≤1200 bytes — completes, and then the connection goes dark the moment
real traffic needs a full-size packet.

straw pins the relay-path inner MTU to **1200 with discovery off**
(`p2p::peer::relay_transport`, on both inner client and server configs), plus a
keepalive to hold the idle connection open. A 256 KiB regression transfer
(`relay_path_carries_a_large_transfer`) guards it — small-payload tests never
probe past 1200 and would miss the bug entirely. The **direct** (punched) path
runs over a real socket and has no such limit.

## Piping over the connection

The simplest use of the inner connection is `strawcat`'s default: pipe stdin and
stdout over a bidirectional stream. `pipe_stdio` awaits **both** directions and
never aborts the upload — aborting would drop the `SendStream` unfinished, which
quinn turns into a stream reset that discards buffered bytes the peer never sees.
The richer use — a full IP tunnel — is [VPN mode](ch-03-05-vpn-mode.md).
