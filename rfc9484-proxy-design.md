# RFC 9484 CONNECT-IP Proxy Server — Rust Implementation Design

## 1. Overview

This document presents a design for implementing an **RFC 9484 (Proxying IP in HTTP)** proxy server in Rust. The proxy enables IP packet tunneling over HTTP/3, functioning as an IP-level VPN gateway using the MASQUE CONNECT-IP protocol.

### 1.1 Target Use Cases

- **Remote Access VPN** — Clients receive an assigned IP and tunnel all traffic through the proxy (full-tunnel or split-tunnel).
- **Site-to-Site VPN** — Bidirectional IP routing between two networks.
- **IP Flow Forwarding** — Scoped tunneling for specific protocols (e.g., SCTP, ESP, ICMP).

### 1.2 Protocol Stack

```
┌─────────────────────────────────────────────┐
│         IP Packets (tunneled payload)        │
├─────────────────────────────────────────────┤
│   Context ID (0) + HTTP Datagram Payload     │  RFC 9297
├─────────────────────────────────────────────┤
│  QUIC DATAGRAM Frame / STREAM (Capsules)     │  RFC 9221
├─────────────────────────────────────────────┤
│   HTTP/3 Extended CONNECT (:protocol=        │  RFC 9114 + RFC 9220
│       connect-ip, capsule-protocol=?1)       │
├─────────────────────────────────────────────┤
│          QUIC Transport (TLS 1.3)            │  RFC 9000
├─────────────────────────────────────────────┤
│                    UDP                        │
└─────────────────────────────────────────────┘
```

### 1.3 Key RFCs

| RFC    | Title                                    | Role                           |
|--------|------------------------------------------|--------------------------------|
| 9484   | Proxying IP in HTTP                      | Core protocol (CONNECT-IP)     |
| 9297   | HTTP Datagrams and the Capsule Protocol  | Datagram/capsule framing       |
| 9298   | Proxying UDP in HTTP                     | Foundation (CONNECT-UDP)       |
| 9221   | Unreliable Datagram Extension to QUIC    | QUIC DATAGRAM frames           |
| 9000   | QUIC Transport                           | Transport layer                |
| 9114   | HTTP/3                                   | Application protocol           |
| 9220   | Bootstrapping WebSockets with HTTP/3     | Extended CONNECT for HTTP/3    |

---

## 2. Architecture

### 2.1 High-Level Component Diagram

```
                          ┌──────────────────────────────────────────────┐
                          │         RFC 9484 Proxy Server                │
                          │                                              │
  Client ──QUIC/H3──►    │  ┌───────────┐    ┌─────────────────────┐   │
                          │  │  HTTP/3    │    │  Session Manager    │   │
                          │  │  Endpoint  │───►│  (per-stream state) │   │
                          │  └───────────┘    └──────────┬──────────┘   │
                          │                              │              │
                          │       ┌──────────────────────┼──────┐      │
                          │       │                      │      │      │
                          │  ┌────▼─────┐  ┌─────────────▼──┐  │      │
                          │  │ Capsule   │  │  IP Forwarding │  │      │
                          │  │ Processor │  │  Engine         │  │      │
                          │  │ (control) │  │  (data plane)   │  │      │
                          │  └──────────┘  └────────┬────────┘  │      │
                          │                         │           │      │
                          │                    ┌────▼────┐      │      │
                          │                    │   TUN   │      │      │
                          │                    │ Device  │      │      │
                          │                    └────┬────┘      │      │
                          │                         │           │      │
                          │  ┌──────────────────────┼──────┐   │      │
                          │  │   Address Pool &     │      │   │      │
                          │  │   Route Table Manager│      │   │      │
                          │  └─────────────────────────────┘   │      │
                          └──────────────────────────────────────────────┘
                                                    │
                                              ┌─────▼─────┐
                                              │  Network   │
                                              │ (Internet/ │
                                              │  Private)  │
                                              └───────────┘
```

### 2.2 Component Responsibilities

| Component             | Responsibility                                                        |
|-----------------------|-----------------------------------------------------------------------|
| **HTTP/3 Endpoint**   | QUIC listener, TLS termination, HTTP/3 connection & stream mgmt       |
| **Session Manager**   | Per-stream tunnel lifecycle, authentication, request validation        |
| **Capsule Processor** | Encode/decode ADDRESS_ASSIGN, ADDRESS_REQUEST, ROUTE_ADVERTISEMENT    |
| **IP Forwarding Engine** | Parse/validate IP headers, TTL decrement, route lookup, forwarding |
| **TUN Device**        | Kernel-level IP packet I/O for outbound/inbound forwarding            |
| **Address Pool**      | IPv4/IPv6 address allocation and reclamation per session              |
| **Route Table Manager** | Manage per-session and global route entries                         |
| **Auth Module**       | Client authentication (mTLS, Bearer token, HTTP Authorization)        |

---

## 3. Crate Selection

### 3.1 Core Dependencies

| Crate            | Version  | Purpose                                          |
|------------------|----------|--------------------------------------------------|
| `quinn`          | 0.11+    | QUIC transport (async, tokio-native)              |
| `h3`             | 0.0.8+   | HTTP/3 protocol (generic over QUIC impl)          |
| `h3-quinn`       | 0.0.10+  | Glue layer: h3 ↔ quinn                            |
| `h3-datagram`    | 0.0.2+   | HTTP Datagram / Capsule Protocol support          |
| `tokio`          | 1.x      | Async runtime                                     |
| `rustls`         | 0.23+    | TLS 1.3 (used by quinn)                           |
| `bytes`          | 1.x      | Zero-copy buffer management                       |
| `tun-tap`        | (or `tun`)| TUN device creation (Linux)                      |
| `etherparse`     | 0.15+    | IP packet parsing (v4/v6 headers)                 |
| `ipnet`          | 2.x      | IP network/prefix types                           |
| `dashmap`        | 6.x      | Concurrent hash map for session table             |
| `tracing`        | 0.1      | Structured logging                                |
| `clap`           | 4.x      | CLI argument parsing                              |

### 3.2 Rationale: quinn + h3 vs. quiche/tokio-quiche

| Aspect                | quinn + h3                     | quiche / tokio-quiche            |
|-----------------------|--------------------------------|----------------------------------|
| Language              | Pure Rust                      | C core (Rust bindings)           |
| Async Model           | Native tokio                   | Sans-I/O (tokio-quiche wraps)    |
| DATAGRAM support      | Yes (quinn 0.11+)              | Yes                              |
| HTTP/3 Extended CONNECT| Via h3 crate                  | Manual implementation            |
| Ecosystem             | Rust-native, well-maintained   | Cloudflare production-grade      |
| Capsule Protocol      | h3-datagram crate              | Manual                           |

**Recommendation:** Use **quinn + h3 + h3-datagram** for a fully Rust-native stack with strong async ergonomics. Fall back to tokio-quiche if Cloudflare interop is paramount.

---

## 4. Data Structures

### 4.1 Core Types

```rust
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use ipnet::IpNet;
use bytes::{Bytes, BytesMut};

/// Unique identifier for a CONNECT-IP tunnel session.
/// Tied to the HTTP/3 stream that initiated the request.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct SessionId(pub u64);

/// Parsed scope from the CONNECT-IP request URI template.
#[derive(Debug, Clone)]
pub struct RequestScope {
    /// Target host/prefix or None for wildcard (*).
    pub target: Option<Target>,
    /// IP protocol number or None for wildcard (*).
    pub ip_proto: Option<u8>,
}

#[derive(Debug, Clone)]
pub enum Target {
    Hostname(String),
    Prefix(IpNet),
}

/// Per-session tunnel state.
pub struct TunnelSession {
    pub id: SessionId,
    pub scope: RequestScope,
    /// IP addresses assigned to the client.
    pub assigned_addresses: Vec<AssignedAddress>,
    /// Routes advertised to the client.
    pub advertised_routes: Vec<IpAddressRange>,
    /// Routes received from the client (site-to-site).
    pub client_routes: Vec<IpAddressRange>,
    /// Pending ADDRESS_REQUESTs awaiting response.
    pub pending_requests: Vec<AddressRequest>,
    /// Timestamp of last activity for idle timeout.
    pub last_activity: std::time::Instant,
    /// Authentication context.
    pub auth_context: AuthContext,
}
```

### 4.2 Capsule Types (RFC 9484 §4.7)

```rust
/// Capsule type identifiers per RFC 9484 §12.4
pub const CAPSULE_ADDRESS_ASSIGN: u64       = 0x01;
pub const CAPSULE_ADDRESS_REQUEST: u64      = 0x02;
pub const CAPSULE_ROUTE_ADVERTISEMENT: u64  = 0x03;

/// ADDRESS_ASSIGN capsule (§4.7.1)
#[derive(Debug, Clone)]
pub struct AddressAssign {
    pub assigned_addresses: Vec<AssignedAddress>,
}

#[derive(Debug, Clone)]
pub struct AssignedAddress {
    pub request_id: u64,    // VarInt: 0 if unprompted, else matches request
    pub ip_version: u8,     // 4 or 6
    pub ip_address: IpAddr,
    pub prefix_length: u8,
}

/// ADDRESS_REQUEST capsule (§4.7.2)
#[derive(Debug, Clone)]
pub struct AddressRequest {
    pub requested_addresses: Vec<RequestedAddress>,
}

#[derive(Debug, Clone)]
pub struct RequestedAddress {
    pub request_id: u64,    // VarInt: nonzero, unique per endpoint
    pub ip_version: u8,     // 4 or 6
    pub ip_address: IpAddr, // 0.0.0.0/:: means "any"
    pub prefix_length: u8,
}

/// ROUTE_ADVERTISEMENT capsule (§4.7.3)
#[derive(Debug, Clone)]
pub struct RouteAdvertisement {
    pub ip_address_ranges: Vec<IpAddressRange>,
}

/// A single IP address range within a ROUTE_ADVERTISEMENT.
/// Ordering rules (§4.7.3): sorted by (ip_version, ip_protocol, start_ip).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct IpAddressRange {
    pub ip_version: u8,        // 4 or 6
    pub start_ip: IpAddr,
    pub end_ip: IpAddr,        // start <= end
    pub ip_protocol: u8,       // 0 = all protocols
}

/// HTTP Datagram payload for IP proxying (§6)
pub struct IpProxyingDatagram {
    pub context_id: u64,       // VarInt: 0 = IP packet
    pub payload: Bytes,        // Full IP packet when context_id == 0
}
```

### 4.3 Address Pool

```rust
use std::collections::BTreeSet;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Manages a pool of assignable IP addresses.
pub struct AddressPool {
    /// Available IPv4 addresses (e.g., from 10.0.0.0/24).
    ipv4_available: Mutex<BTreeSet<Ipv4Addr>>,
    /// Available IPv6 prefixes (e.g., /128s from fd00::/64).
    ipv6_available: Mutex<BTreeSet<Ipv6Addr>>,
    /// Map from session -> allocated addresses.
    allocations: DashMap<SessionId, Vec<IpAddr>>,
}

impl AddressPool {
    /// Allocate an address for a session.
    /// If the client requested a specific address and it's available, use it.
    /// Otherwise, pick from the pool.
    pub async fn allocate(
        &self,
        session: SessionId,
        request: &RequestedAddress,
    ) -> Option<AssignedAddress> { ... }

    /// Release all addresses for a session on teardown.
    pub async fn release(&self, session: SessionId) { ... }
}
```

---

## 5. Module Structure

```
masque-proxy/
├── Cargo.toml
├── src/
│   ├── main.rs                  # CLI entry point, config loading
│   ├── config.rs                # Server configuration (TOML/CLI)
│   ├── server.rs                # QUIC/H3 listener, connection accept loop
│   ├── session/
│   │   ├── mod.rs               # Session manager (DashMap<SessionId, TunnelSession>)
│   │   ├── handler.rs           # Per-stream CONNECT-IP request handler
│   │   └── auth.rs              # Authentication (mTLS, Bearer, HTTP Auth)
│   ├── capsule/
│   │   ├── mod.rs               # Capsule encode/decode dispatcher
│   │   ├── codec.rs             # Wire format: VarInt + capsule serialization
│   │   ├── address_assign.rs    # ADDRESS_ASSIGN encode/decode
│   │   ├── address_request.rs   # ADDRESS_REQUEST encode/decode
│   │   └── route_advertisement.rs # ROUTE_ADVERTISEMENT encode/decode
│   ├── datagram/
│   │   ├── mod.rs               # HTTP Datagram handling
│   │   └── context.rs           # Context ID management (§5)
│   ├── forwarding/
│   │   ├── mod.rs               # IP forwarding engine
│   │   ├── tun.rs               # TUN device setup & async I/O
│   │   ├── router.rs            # Route table: session -> prefix mapping
│   │   ├── packet.rs            # IP packet parse, validate, TTL decrement
│   │   └── icmp.rs              # ICMP error generation (§7.2.1)
│   ├── address_pool.rs          # IPv4/IPv6 address pool management
│   ├── uri_template.rs          # URI template parsing ({target}, {ipproto})
│   └── error.rs                 # Error types
└── tests/
    ├── capsule_test.rs          # Capsule encode/decode round-trip
    ├── forwarding_test.rs       # Packet validation & routing
    └── integration_test.rs      # End-to-end with mock QUIC client
```

---

## 6. Processing Flow

### 6.1 Connection Setup & Tunnel Establishment

```
Client                              Proxy Server
  │                                      │
  │──── QUIC Handshake (TLS 1.3) ──────►│  server.rs: accept_connection()
  │◄─── QUIC Handshake Complete ────────│
  │                                      │
  │  SETTINGS { H3_DATAGRAM=1 }  ──────►│  Verify ENABLE_CONNECT_PROTOCOL
  │◄── SETTINGS { ENABLE_CONNECT ───────│  + H3_DATAGRAM
  │      _PROTOCOL=1, H3_DATAGRAM=1 }   │
  │                                      │
  │  STREAM(N): HEADERS                  │
  │    :method = CONNECT                 │
  │    :protocol = connect-ip            │  session/handler.rs:
  │    :path = /.well-known/masque/      │    1. Validate Extended CONNECT
  │            ip/{target}/{ipproto}/    │    2. Parse URI template
  │    capsule-protocol = ?1             │    3. Authenticate client
  │  ──────────────────────────────────►│    4. Create TunnelSession
  │                                      │    5. Resolve DNS if target=hostname
  │◄──── STREAM(N): HEADERS ────────────│
  │        :status = 200                 │
  │        capsule-protocol = ?1         │
  │                                      │
  │◄──── STREAM(N): DATA ──────────────│  capsule/: encode ADDRESS_ASSIGN
  │   Capsule: ADDRESS_ASSIGN           │  address_pool.rs: allocate()
  │   (192.0.2.42/32)                   │
  │                                      │
  │◄──── STREAM(N): DATA ──────────────│  capsule/: encode ROUTE_ADVERTISEMENT
  │   Capsule: ROUTE_ADVERTISEMENT      │  forwarding/router.rs: add routes
  │   (0.0.0.0 – 255.255.255.255)      │
  │                                      │
  │══════ Tunnel Active ════════════════│
```

### 6.2 Data Plane: Client → Network

```
Client                     Proxy Server                        Internet
  │                            │                                  │
  │  QUIC DATAGRAM             │                                  │
  │  [QStreamID][CtxID=0]      │                                  │
  │  [Full IP Packet]          │                                  │
  │ ──────────────────────────►│                                  │
  │                            │  datagram/mod.rs:                │
  │                            │    1. Demux by Quarter Stream ID │
  │                            │    2. Parse Context ID (must=0)  │
  │                            │    3. Extract IP packet payload  │
  │                            │                                  │
  │                            │  forwarding/packet.rs:           │
  │                            │    4. Parse IP header            │
  │                            │    5. Validate src addr matches  │
  │                            │       session's assigned addr    │
  │                            │    6. Check route scope          │
  │                            │    7. Decrement TTL/Hop Limit    │
  │                            │                                  │
  │                            │  forwarding/tun.rs:              │
  │                            │    8. Write to TUN device        │
  │                            │                     ─────────────►
  │                            │                                  │
```

### 6.3 Data Plane: Network → Client

```
Internet                   Proxy Server                        Client
  │                            │                                  │
  │  IP Packet                 │                                  │
  │ ──────────────────────────►│  forwarding/tun.rs:              │
  │                            │    1. Read from TUN device       │
  │                            │                                  │
  │                            │  forwarding/router.rs:           │
  │                            │    2. Lookup dst addr → session  │
  │                            │    3. Validate against           │
  │                            │       ROUTE_ADVERTISEMENT        │
  │                            │                                  │
  │                            │  forwarding/packet.rs:           │
  │                            │    4. Decrement TTL              │
  │                            │                                  │
  │                            │  datagram/mod.rs:                │
  │                            │    5. Wrap as HTTP Datagram      │
  │                            │       [CtxID=0][IP Packet]       │
  │                            │                                  │
  │                            │  QUIC DATAGRAM frame             │
  │                            │ ────────────────────────────────►│
```

---

## 7. Capsule Wire Format

### 7.1 Generic Capsule (RFC 9297 §3.2)

```
Capsule {
  Capsule Type (i),     // VarInt
  Capsule Length (i),   // VarInt  
  Capsule Value (..),   // Length bytes
}
```

### 7.2 ADDRESS_ASSIGN (Type=0x01)

```
ADDRESS_ASSIGN Capsule {
  Type (i) = 0x01,
  Length (i),
  Assigned Address (..) ...,     // repeated
}

Assigned Address {
  Request ID (i),       // VarInt: 0 if unprompted
  IP Version (8),       // 4 or 6
  IP Address (32..128), // 4 bytes (v4) or 16 bytes (v6)
  IP Prefix Length (8), // 0..32 (v4) or 0..128 (v6)
}
```

### 7.3 ADDRESS_REQUEST (Type=0x02)

```
ADDRESS_REQUEST Capsule {
  Type (i) = 0x02,
  Length (i),
  Requested Address (..) ...,    // repeated, at least one
}

Requested Address {
  Request ID (i),       // VarInt: nonzero, unique
  IP Version (8),       // 4 or 6
  IP Address (32..128), // 0.0.0.0/:: = "pick for me"
  IP Prefix Length (8),
}
```

### 7.4 ROUTE_ADVERTISEMENT (Type=0x03)

```
ROUTE_ADVERTISEMENT Capsule {
  Type (i) = 0x03,
  Length (i),
  IP Address Range (..) ...,     // repeated, ORDERED
}

IP Address Range {
  IP Version (8),           // 4 or 6
  Start IP Address (32..128),
  End IP Address (32..128), // start <= end
  IP Protocol (8),          // 0 = all protocols
}
```

**Ordering constraint (§4.7.3):** Ranges must be sorted by `(ip_version, ip_protocol, start_ip)` with non-overlapping guarantees.

### 7.5 Codec Implementation Strategy

```rust
// capsule/codec.rs

use bytes::{Buf, BufMut, Bytes, BytesMut};

/// Read a QUIC-style variable-length integer.
pub fn read_varint(buf: &mut impl Buf) -> Result<u64, DecodeError> {
    if !buf.has_remaining() {
        return Err(DecodeError::Underflow);
    }
    let first = buf.get_u8();
    let len = 1 << (first >> 6);
    let mut val = (first & 0x3f) as u64;
    for _ in 1..len {
        val = (val << 8) | buf.get_u8() as u64;
    }
    Ok(val)
}

/// Write a QUIC-style variable-length integer.
pub fn write_varint(buf: &mut impl BufMut, val: u64) { ... }

/// Decode a capsule from the stream.
pub fn decode_capsule(buf: &mut impl Buf) -> Result<Capsule, DecodeError> {
    let capsule_type = read_varint(buf)?;
    let capsule_length = read_varint(buf)? as usize;
    let payload = buf.copy_to_bytes(capsule_length);
    
    match capsule_type {
        CAPSULE_ADDRESS_ASSIGN => {
            Ok(Capsule::AddressAssign(AddressAssign::decode(&payload)?))
        }
        CAPSULE_ADDRESS_REQUEST => {
            Ok(Capsule::AddressRequest(AddressRequest::decode(&payload)?))
        }
        CAPSULE_ROUTE_ADVERTISEMENT => {
            Ok(Capsule::RouteAdvertisement(
                RouteAdvertisement::decode(&payload)?
            ))
        }
        other => Ok(Capsule::Unknown { type_id: other, data: payload }),
    }
}

pub enum Capsule {
    AddressAssign(AddressAssign),
    AddressRequest(AddressRequest),
    RouteAdvertisement(RouteAdvertisement),
    Unknown { type_id: u64, data: Bytes },
}
```

---

## 8. Forwarding Engine Design

### 8.1 Route Table

```rust
// forwarding/router.rs

use ipnet::IpNet;
use dashmap::DashMap;
use std::net::IpAddr;

/// Maps destination IP → SessionId for reverse-path forwarding
/// (network → client direction).
pub struct RouteTable {
    /// Prefix-based routes: longest-prefix match
    /// Key: (prefix, ip_protocol)
    routes: RwLock<Vec<RouteEntry>>,
    /// Fast lookup: assigned client IP → SessionId
    client_addrs: DashMap<IpAddr, SessionId>,
}

#[derive(Debug, Clone)]
pub struct RouteEntry {
    pub prefix: IpNet,
    pub ip_protocol: u8,      // 0 = all
    pub session_id: SessionId,
    pub direction: RouteDirection,
}

#[derive(Debug, Clone)]
pub enum RouteDirection {
    /// Proxy → Client: packets destined for client's assigned addr
    ToClient,
    /// Client → Network: prefixes client can reach through proxy
    ToNetwork,
}

impl RouteTable {
    /// Lookup the session that should receive a packet
    /// destined for `dst_addr` with protocol `proto`.
    pub fn lookup(&self, dst_addr: IpAddr, proto: u8) -> Option<SessionId> {
        // 1. Check client_addrs (fast path for assigned addresses)
        if let Some(session) = self.client_addrs.get(&dst_addr) {
            return Some(*session);
        }
        // 2. Longest-prefix match in route table
        let routes = self.routes.read().unwrap();
        routes.iter()
            .filter(|r| r.prefix.contains(&dst_addr))
            .filter(|r| r.ip_protocol == 0 || r.ip_protocol == proto)
            .max_by_key(|r| r.prefix.prefix_len())
            .map(|r| r.session_id)
    }
}
```

### 8.2 Packet Processing

```rust
// forwarding/packet.rs

use etherparse::{SlicedPacket, IpHeaders};

pub struct PacketProcessor;

impl PacketProcessor {
    /// Validate and prepare an IP packet for forwarding.
    /// Returns the modified packet or an ICMP error to send back.
    pub fn process_outbound(
        packet: &mut [u8],
        session: &TunnelSession,
    ) -> Result<(), ForwardingError> {
        let parsed = SlicedPacket::from_ip(packet)
            .map_err(|_| ForwardingError::MalformedPacket)?;
        
        // 1. Validate source address matches session's assigned address
        let src_addr = Self::extract_src_addr(&parsed)?;
        if !session.assigned_addresses.iter().any(|a| {
            let net = IpNet::new(a.ip_address, a.prefix_length).unwrap();
            net.contains(&src_addr)
        }) {
            return Err(ForwardingError::SourceAddressViolation(src_addr));
        }
        
        // 2. Check destination against advertised routes
        let dst_addr = Self::extract_dst_addr(&parsed)?;
        // (Route check delegated to RouteTable)
        
        // 3. Decrement TTL/Hop Limit (§7.2)
        Self::decrement_ttl(packet)?;
        
        // 4. Drop link-local traffic (§7.2)
        if dst_addr.is_loopback() || Self::is_link_local(&dst_addr) {
            return Err(ForwardingError::LinkLocalDrop);
        }
        
        Ok(())
    }
    
    fn decrement_ttl(packet: &mut [u8]) -> Result<(), ForwardingError> {
        match packet[0] >> 4 {
            4 => {  // IPv4: TTL at offset 8
                if packet[8] <= 1 {
                    return Err(ForwardingError::TtlExpired);
                }
                packet[8] -= 1;
                // Recompute IPv4 header checksum
                Self::recompute_ipv4_checksum(packet);
            }
            6 => {  // IPv6: Hop Limit at offset 7
                if packet[7] <= 1 {
                    return Err(ForwardingError::TtlExpired);
                }
                packet[7] -= 1;
            }
            _ => return Err(ForwardingError::MalformedPacket),
        }
        Ok(())
    }
}
```

### 8.3 TUN Device

```rust
// forwarding/tun.rs

use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub struct TunDevice {
    name: String,
    fd: tokio::fs::File,  // Or platform-specific async TUN wrapper
}

impl TunDevice {
    /// Create and configure a TUN device.
    pub async fn create(name: &str, mtu: u32) -> Result<Self, TunError> {
        // 1. Open /dev/net/tun
        // 2. ioctl TUNSETIFF with IFF_TUN | IFF_NO_PI
        // 3. Set MTU (must be >= 1280 for IPv6, §7.2)
        // 4. Bring interface up
        ...
    }
    
    /// Read one IP packet from the TUN device.
    pub async fn read_packet(&self, buf: &mut [u8]) -> Result<usize, TunError> {
        self.fd.read(buf).await.map_err(TunError::Io)
    }
    
    /// Write one IP packet to the TUN device.
    pub async fn write_packet(&self, packet: &[u8]) -> Result<(), TunError> {
        self.fd.write_all(packet).await.map_err(TunError::Io)
    }
}
```

---

## 9. Session Lifecycle

### 9.1 State Machine

```
                    ┌────────────┐
                    │   IDLE     │  Stream opened, awaiting CONNECT-IP request
                    └─────┬──────┘
                          │ Receive Extended CONNECT
                          │ :protocol = connect-ip
                          ▼
                    ┌────────────┐
                    │ VALIDATING │  Parse URI, authenticate, resolve DNS
                    └─────┬──────┘
                          │ Valid → 200 OK
                          ▼
                    ┌────────────┐
                    │ ASSIGNING  │  Send ADDRESS_ASSIGN + ROUTE_ADVERTISEMENT
                    └─────┬──────┘  Process ADDRESS_REQUEST from client
                          │ 
                          ▼
                    ┌────────────┐
                    │   ACTIVE   │  Forwarding IP packets (DATAGRAMs)
                    └─────┬──────┘  Process capsules for route updates
                          │
              ┌───────────┼───────────┐
              │           │           │
    Stream closed   Idle timeout   Error
              │           │           │
              ▼           ▼           ▼
                    ┌────────────┐
                    │ TEARDOWN   │  Release addresses, remove routes,
                    └────────────┘  close stream
```

### 9.2 Handler Pseudocode

```rust
// session/handler.rs

pub async fn handle_connect_ip_stream(
    stream: h3::server::RequestStream<...>,
    headers: Vec<(String, String)>,
    session_mgr: Arc<SessionManager>,
    addr_pool: Arc<AddressPool>,
    route_table: Arc<RouteTable>,
    tun: Arc<TunDevice>,
) -> Result<(), ProxyError> {
    // 1. Validate Extended CONNECT
    let (method, protocol, path, authority) = parse_headers(&headers)?;
    ensure!(method == "CONNECT" && protocol == "connect-ip");
    
    // 2. Parse URI template → RequestScope
    let scope = uri_template::parse_connect_ip_path(&path)?;
    
    // 3. Authenticate
    let auth = auth::authenticate(&headers).await?;
    
    // 4. DNS resolution if target is hostname
    if let Some(Target::Hostname(ref host)) = scope.target {
        let addrs = tokio::net::lookup_host(host).await?;
        // Store resolved addresses for ROUTE_ADVERTISEMENT
    }
    
    // 5. Create session
    let session_id = SessionId::new();
    let session = TunnelSession::new(session_id, scope.clone(), auth);
    
    // 6. Send 200 OK with capsule-protocol=?1
    stream.send_response(Response::builder().status(200)
        .header("capsule-protocol", "?1")
        .body(()))?;
    
    // 7. Allocate addresses and send ADDRESS_ASSIGN
    let assigned = addr_pool.allocate_for_session(session_id, &scope).await?;
    let assign_capsule = AddressAssign { assigned_addresses: assigned.clone() };
    stream.send_data(capsule::encode(&Capsule::AddressAssign(assign_capsule)))?;
    
    // 8. Build and send ROUTE_ADVERTISEMENT
    let routes = build_routes_for_scope(&scope, &resolved_addrs);
    let route_capsule = RouteAdvertisement { ip_address_ranges: routes.clone() };
    stream.send_data(capsule::encode(&Capsule::RouteAdvertisement(route_capsule)))?;
    
    // 9. Install routes
    route_table.install_session_routes(session_id, &assigned, &routes);
    session_mgr.insert(session_id, session);
    
    // 10. Enter forwarding loop (two concurrent tasks)
    let (datagram_tx, datagram_rx) = tokio::sync::mpsc::channel(256);
    
    tokio::select! {
        // Task A: Client → Network (DATAGRAM/Capsule from stream)
        r = client_to_network(&stream, &session_id, &route_table, &tun) => r?,
        // Task B: Network → Client (TUN → DATAGRAM)
        r = network_to_client(&tun, &session_id, &route_table, &stream) => r?,
        // Task C: Process capsules on the stream (ADDRESS_REQUEST, etc.)
        r = process_capsules(&stream, &session_id, &addr_pool) => r?,
    }
    
    // 11. Teardown
    addr_pool.release(session_id).await;
    route_table.remove_session(session_id);
    session_mgr.remove(session_id);
    
    Ok(())
}
```

---

## 10. Configuration

```toml
# masque-proxy.toml

[server]
listen_addr = "0.0.0.0:443"
tls_cert = "/etc/masque/cert.pem"
tls_key = "/etc/masque/key.pem"

[quic]
max_idle_timeout_ms = 30000
initial_max_data = 10_000_000
initial_max_stream_data = 1_000_000
max_datagram_size = 1350          # Enough for 1280 IPv6 + overhead

[tunnel]
tun_device_name = "masque0"
tun_mtu = 1400                    # Must be >= 1280 (IPv6 minimum)

[address_pool]
ipv4_range = "10.100.0.0/16"     # Assignable IPv4 range
ipv6_range = "fd00:masq::/48"    # Assignable IPv6 range

[routing]
# VPN mode: full-tunnel or split-tunnel
mode = "full-tunnel"              # "full-tunnel" | "split-tunnel"
# For split-tunnel, specify allowed prefixes:
# split_routes = ["192.168.0.0/16", "10.0.0.0/8"]
enable_nat = true                 # SNAT outbound traffic
nat_interface = "eth0"

[auth]
mode = "bearer"                   # "none" | "mtls" | "bearer" | "basic"
bearer_tokens = ["/etc/masque/tokens.json"]
# For mTLS:
# client_ca = "/etc/masque/client-ca.pem"

[limits]
max_sessions = 1000
idle_timeout_sec = 300
max_packet_rate = 100000          # packets/sec per session
```

---

## 11. Security Considerations

### 11.1 Source Address Validation (§11, BCP 38)

The proxy MUST validate that the source address on every tunneled IP packet matches the addresses assigned to that session via ADDRESS_ASSIGN. This prevents IP spoofing through the tunnel.

```rust
// In forwarding/packet.rs
fn validate_source(src: IpAddr, session: &TunnelSession) -> bool {
    session.assigned_addresses.iter().any(|assigned| {
        IpNet::new(assigned.ip_address, assigned.prefix_length)
            .map(|net| net.contains(&src))
            .unwrap_or(false)
    })
}
```

### 11.2 ICMP Forwarding on Shared IPs (§11)

When multiple sessions share an external IP (scoped to different protocols), ICMP packets containing invoking packets MUST be inspected. Only forward to the session whose scope matches the invoking packet's protocol.

### 11.3 Authentication

All CONNECT-IP requests MUST require authentication. Supported mechanisms:

- **Mutual TLS (mTLS):** Client certificate verified during QUIC handshake via rustls `ClientCertVerifier`.
- **Bearer Token:** `Authorization: Bearer <token>` header on the CONNECT-IP request.
- **HTTP Basic Auth:** `Authorization: Basic <base64>` header.

### 11.4 Rate Limiting

Per-session rate limits on packets and bytes to prevent abuse. Implemented as a token-bucket in the forwarding engine.

### 11.5 MTU (§7.2, §10.1)

The proxy MUST ensure the tunnel MTU is at least 1280 bytes for IPv6. If a QUIC DATAGRAM frame cannot carry a 1280-byte IP packet, the stream MUST be aborted. The proxy should send ICMPv6 Packet Too Big for oversized packets rather than fragmenting or using DATAGRAM capsules (which would break unreliability semantics).

---

## 12. Performance Considerations

### 12.1 Congestion Control (§10)

When tunneled traffic uses its own congestion control (TCP/QUIC inside the tunnel), the outer QUIC connection MAY disable congestion control for DATAGRAM frames carrying IP packets. This avoids double congestion control penalties.

Quinn supports this via `SendDatagramError` handling and transport configuration.

### 12.2 Batch I/O

Use `recvmmsg`/`sendmmsg` syscalls for the TUN device and UDP socket to amortize syscall overhead. The `tokio-uring` crate or custom io_uring integration can further improve performance on Linux 5.10+.

### 12.3 Zero-Copy Path

Minimize allocations in the hot data path:

```rust
// Pre-allocate buffers per session
let mut buf = BytesMut::with_capacity(MAX_DATAGRAM_SIZE);

// Read from TUN → directly wrap as HTTP Datagram → send as QUIC DATAGRAM
// Avoid copying IP packet data between buffers
```

### 12.4 DSCP Handling (§10.3)

When congestion control is disabled on outer QUIC, the proxy MAY copy DSCP markings from inner to outer IP headers. Packets with different DSCP markings MUST NOT be coalesced into the same outer packet.

---

## 13. Testing Strategy

| Test Level        | Scope                                              | Tools              |
|-------------------|----------------------------------------------------|--------------------|
| **Unit**          | Capsule encode/decode, VarInt, URI parsing          | `#[cfg(test)]`     |
| **Component**     | Address pool allocation, route table lookup         | Mock sessions      |
| **Integration**   | Full tunnel setup with mock QUIC client             | quinn client + h3  |
| **Interop**       | Against `quic-go/connect-ip-go` and `masque-vpn`   | Network namespaces |
| **Performance**   | Throughput, latency under load                      | `iperf3` over tunnel|
| **Conformance**   | All RFC 9484 §8 examples (VPN, S2S, Flow, Racing)  | Custom test harness|

---

## 14. Implementation Phases

### Phase 1: Foundation (2-3 weeks)
- QUIC/H3 server with quinn + h3
- Extended CONNECT handling for `connect-ip`
- Capsule codec (encode/decode all three types)
- URI template parser

### Phase 2: Tunnel Core (2-3 weeks)
- TUN device management
- Address pool (IPv4)
- Full-tunnel VPN scenario (§8.1)
- IP packet forwarding with source validation

### Phase 3: Full Protocol (2 weeks)
- IPv6 support + dual-stack address pool
- Split-tunnel routing (§8.1)
- Site-to-site VPN (§8.2) — bidirectional ADDRESS_ASSIGN/ROUTE_ADVERTISEMENT
- ICMP error generation (§7.2.1)

### Phase 4: Production Readiness (2 weeks)
- Authentication (mTLS, Bearer)
- Rate limiting, idle timeout
- NAT (iptables integration)
- Metrics, logging, graceful shutdown
- Configuration file support

### Phase 5: Advanced (ongoing)
- IP flow forwarding (§8.3)
- QUIC-aware proxying (draft-ietf-masque-quic-proxy)
- Multi-path QUIC integration
- io_uring based I/O

---

## 15. References

- RFC 9484: Proxying IP in HTTP — https://www.rfc-editor.org/rfc/rfc9484
- RFC 9297: HTTP Datagrams and the Capsule Protocol — https://www.rfc-editor.org/rfc/rfc9297
- RFC 9298: Proxying UDP in HTTP — https://www.rfc-editor.org/rfc/rfc9298
- RFC 9221: Unreliable Datagram Extension to QUIC — https://www.rfc-editor.org/rfc/rfc9221
- RFC 9000: QUIC Transport — https://www.rfc-editor.org/rfc/rfc9000
- RFC 9114: HTTP/3 — https://www.rfc-editor.org/rfc/rfc9114
- quic-go/connect-ip-go (reference impl): https://github.com/quic-go/connect-ip-go
- mqvpn (Multipath QUIC VPN): https://github.com/mp0rta/mqvpn
- quinn (Rust QUIC): https://github.com/quinn-rs/quinn
- h3 (Rust HTTP/3): https://crates.io/crates/h3
