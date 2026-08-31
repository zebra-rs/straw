# straw on NetworkExtension (iOS, iPadOS, macOS)

Plan for running straw's client inside Apple's NetworkExtension, targeting
iOS and iPadOS as App Store apps, with a macOS app alongside the existing
developer CLI.

**Decisions taken** (2026-08-31): the iOS client does **CONNECT-IP *and* the P2P
direct path**; distribution is the **App Store**; macOS keeps its root CLI *and*
gains an NE app. Those are the ambitious ends of all three choices, and the plan
below is sized accordingly — §4 is honest about which of them costs the most.

## 0. What is already established

Measured on this machine, not assumed:

- **The library compiles for `aarch64-apple-ios` today**, with no errors and no
  warnings. `ring` builds genuine iOS ARM64 assembly (`armv8-mont-ios64.o`,
  `chacha-armv8-ios64.o`), so the crypto layer is real, not stubbed. The whole
  dependency tree — quinn, noq, h3, rustls, tokio, ciborium — is iOS-clean.
- **Shelling out is confined to two files**: `iface/` and `nat.rs`. Nothing in
  the protocol stack, the forwarding engine, or the P2P path runs a program.
- `nat.rs` is out of scope: the proxy runs on Linux.
- The macOS CLI path (utun + `ifconfig`/`route`) works and is partly verified.

So this is not a port of straw. It is a port of the ~2 files that touch the
kernel, plus packaging.

## 1. Three structural mismatches

### 1.1 A library, not a program

An NE provider is a system-launched **app extension**, not a process with
`main`. straw becomes a `staticlib` linked into it: no CLI parsing, no stdout,
no signals, no `std::process`. Configuration arrives from the container app,
and logs go to `os_log` rather than a `tracing` subscriber writing to stderr.

### 1.2 No commands — settings are declarative

This is the important one, and it makes part of stage 2 the wrong shape.

`iface/` currently produces a `Cmd` (program plus arguments) and runs it. NE
cannot execute anything: the provider hands the system one
`NEPacketTunnelNetworkSettings` object — addresses, included/excluded routes,
MTU, DNS — and the system applies it **atomically**. There is no incremental
"add this route" and no teardown list, because replacing the settings replaces
everything.

The fix is to split what `configure()` decides from how it is realised:

```
prefixes_from_ranges / split_default   (already pure, already shared)
            ↓
      DesiredInterface { addresses, routes, mtu, excluded }
            ↓
   ┌────────┴─────────┐
Linux/macOS CLI      NE
(Cmd sequence,     (one settings object,
 undo list)         handed across FFI)
```

`DesiredInterface` is the new seam. **Done** — `iface::plan` decides,
`iface::commands` turns a plan into (apply, undo) pairs, and `iface::realize`
runs them; `configure` is now `realize(&plan(setup))`. The NE backend will
consume a `DesiredInterface` and build no commands at all.

It paid for itself before any Apple code exists: with the decision separated
from its execution, the ordering property — whatever must stay off the tunnel
is pinned *before* any route that could capture the tunnel's own transport —
became an assertion instead of a comment. Reversing that order in the source
now fails a test showing the default-route halves installed first.

### 1.3 No device — packets arrive by callback

There is no fd to read. `NEPacketTunnelFlow` gives
`readPackets(completionHandler:)`, delivering an **array** of packets with
matching protocol families, and `writePackets(_:withProtocols:)`. So the fourth
`forwarding/tun/` backend is a channel pair driven from Swift, not a device.

Batching is a genuine difference: Linux amortises a 64 KB GSO aggregate over one
syscall, macOS utun reads one packet per syscall, and NE hands over an array per
callback. The `ingress` closure contract already fits — it is called per packet
— but the buffer strategy is Swift's, not ours.

**On the fd trick:** the `tun` crate's iOS backend requires `config.raw_fd`,
which in practice means extracting the utun descriptor from `packetFlow` by KVC
on a private property. It works, and several shipping VPNs do it. It is also
exactly the kind of thing App Review can reject, and it is undocumented, so it
can break in an OS update. **Use the public `packetFlow` API**; revisit only if
profiling shows the callback path is the bottleneck, and never for the App Store
build.

## 2. Constraints that will actually bite

- **Memory.** A packet-tunnel provider runs under a hard cap — small, and
  historically much smaller than an app's. Choosing CONNECT-IP *and* P2P means
  **two QUIC stacks** in that budget: upstream quinn for the proxy/bind session
  and noq for the peer connection, each with rustls and its own buffers. Today's
  defaults are sized for a server: `datagram_send_buffer_size = mtu × 512`
  (~700 KB per connection), a 256 KiB TUN read buffer, a 1024-deep channel.
  These need re-tuning for the extension, and the exact cap must be checked
  against current Apple documentation rather than my recollection of it.
- **Path changes.** Wi-Fi ↔ cellular invalidates sockets. QUIC connection
  migration covers the proxy session, but the P2P mux binds its *own* UDP socket
  for the direct path — on a path change it must be rebound and the punch
  redone. `p2p::session` already re-punches on `PathEvent::Abandoned`; whether
  that fires promptly on iOS is unknown and needs testing on a device.
- **Jetsam and restarts.** The extension can be killed and restarted by the
  system. Session resumption and on-demand rules matter more than they do for a
  CLI that runs until Ctrl-C.
- **The pin route has no NE equivalent.** On the CLI the client installs a host
  route to the proxy over the pre-tunnel path. Under NE the system keeps the
  provider's own traffic outside the tunnel — unless `includeAllNetworks` is
  set, which changes that. The `pin` concept becomes an *excluded route* in the
  settings object, or nothing at all.
- **App Store.** VPN apps face extra review, the Network Extensions capability
  must be granted before anything can be signed, and Apple has historically
  required that VPN apps come from an organization rather than an individual
  developer account. Start the entitlement request early — it gates all device
  testing, not just release.

## 3. Proposed shape

```
straw/                    the existing library — protocol code unchanged
straw-ffi/                new: staticlib, C ABI (or UniFFI), one per platform
  start(config) -> handle
  stop(handle)
  packets_in(handle, &[&[u8]])         from Swift
  callback: packets_out, settings, log  to Swift
apple/
  StrawKit/               Swift wrapper over the C ABI
  PacketTunnelProvider/   NEPacketTunnelProvider subclass (shared iOS + macOS)
  StrawApp/               container app: config, token, start/stop UI
```

New in `straw`: `forwarding/tun/ne.rs` (channel-backed) and `iface/ne.rs`
(returns `DesiredInterface`, executes nothing). Everything else is reuse.

## 4. Staging, cheapest first

1. **`DesiredInterface` refactor** — pure Rust, testable on Linux and macOS
   today, no Apple toolchain. Splits deciding from realising; the CLI backends
   keep behaving identically. *This is the only step that touches shipped code,
   so it goes first and lands on its own.*
2. **`straw-ffi` skeleton** — build a staticlib for the four Apple targets
   (device, simulator, macOS arm64/x86_64), expose start/stop and the packet
   callbacks, and prove it links from a trivial Swift binary.
3. **PacketTunnelProvider, CONNECT-IP only** — the smaller half. Real tunnel to
   a Linux straw proxy from a device. Everything about lifecycle, settings,
   packet pumping and logging is exercised here without the P2P surface.
4. **Add the P2P path** — noq, bind sessions, the punch, under the memory cap
   and across real path changes. Deliberately last: it is the part most likely
   to hit an extension-specific wall, and step 3 keeps working if it does.
5. **macOS NE app** — same provider, packaged for macOS, alongside the CLI.
6. **App Store** — entitlement, review, container-app UI.

The entitlement request in step 6 should be *filed at step 1*, since it gates
device testing.

## 5. Open questions

- ~~**UniFFI or a hand-rolled C ABI?**~~ **Decided: both, split by traffic
  shape** — UniFFI for control and settings, a narrow `extern "C"` pair for
  packets. Reasoning:
  Three things cross the boundary and they could not be less alike: *control*
  (start/stop/status — rare, rich types, wants real error mapping), *settings*
  (the `DesiredInterface` — rare, structured), and *packets* (hot, and just
  bytes). UniFFI earns its keep on the first two, where hand-written Swift
  bindings are where ownership and enum-ABI bugs live. It is the third that
  makes people nervous, and the NE API shape mostly settles it: `readPackets`
  delivers an *array* and `writePackets` takes one, so the boundary is crossed
  per **batch**, not per packet. At 900 Mbit/s of 1400-byte packets — ~80k
  pps — batches of 32 mean ~2.5k crossings/s, where even a microsecond of
  per-call overhead is under 0.3% of a core. The packet path stays a narrow
  `extern "C"` pair so it can be tuned without regenerating bindings. What is
  worth measuring is not call overhead but **copies**: a packet crossing as
  `Data` → `RustBuffer` → `Bytes` can be copied twice, and at 80k pps that is
  real memory bandwidth inside a memory-capped process.
- **Where do credentials live?** Smaller than it first looked: the *library* is
  already storage-agnostic. `Identity::from_pem(&str)`, `TokenV2::decode(&str)`
  and `TlsMode::Ca(CertificateDer)` all take values, not paths — the only
  filesystem access on the client side is `load_identity` in `strawcat.rs`, a
  binary that will not exist on iOS. So the Keychain work lives entirely in
  Swift: read the item, pass a string across FFI. What still needs deciding is
  the *item policy*, and one choice there is load-bearing —
  `kSecAttrAccessible` must be `AfterFirstUnlock`, not `WhenUnlocked`, or an
  on-demand tunnel cannot start after a reboot until the user unlocks the
  device. The container app and the extension are separate processes, so the
  item also needs a shared access group (App Groups entitlement).
  Key hygiene *was* the one real gap; the `zeroize` pass is **done**. See
  `Identity`'s `Drop` for how far it reaches, which is deliberately documented
  as partial: rcgen clears its serialized DER, ring's live signing key is
  beyond reach. Credentials are also redacted from `Debug` on `TokenV2` and
  `ClientAuth`, with tests. `ProxyConfig::auth_token` is the one left; it is
  proxy-side and so Linux-only, and wants a redacting newtype rather than a
  hand-written `Debug` over forty fields.
- **Does the tokio runtime fit the extension's threading model?** The provider
  is callback-driven; straw's stack is `tokio`-native throughout. Almost
  certainly fine with a multi-thread runtime owned by the FFI layer, but worth
  proving in step 2 rather than assuming.
- **What replaces the BDD suite?** There is no netns on iOS. Step 3 wants at
  least one automated device test, or the Apple side stays manually verified
  forever — which is the same trap the macOS port is currently in.
