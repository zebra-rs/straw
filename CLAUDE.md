# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**straw** is a Rust implementation of an RFC 9484 (CONNECT-IP) proxy server — an IP-level VPN gateway using the MASQUE protocol over HTTP/3. It tunnels IP packets over QUIC using HTTP Datagrams and the Capsule Protocol.

The design document `rfc9484-proxy-design.md` is the primary reference for architecture, data structures, wire formats, and implementation phases.

## Build Commands

```bash
cargo build            # Build the project
cargo test             # Run all tests
cargo test <test_name> # Run a single test
cargo clippy           # Lint
cargo fmt              # Format code
```

Uses Rust edition 2024 (requires nightly or recent stable toolchain).

## Architecture

The project implements the following protocol stack: IP packets → HTTP Datagrams (RFC 9297) → QUIC DATAGRAM frames (RFC 9221) → HTTP/3 Extended CONNECT (RFC 9114 + RFC 9220) → QUIC (RFC 9000).

Planned module structure (from design doc):
- **server** — QUIC/H3 listener using quinn + h3 + h3-quinn
- **session/** — Per-stream CONNECT-IP tunnel lifecycle, authentication
- **capsule/** — Encode/decode ADDRESS_ASSIGN, ADDRESS_REQUEST, ROUTE_ADVERTISEMENT capsules with QUIC VarInt wire format
- **datagram/** — HTTP Datagram handling, Context ID management
- **forwarding/** — IP packet validation, TTL decrement, TUN device I/O, route table (longest-prefix match)
- **address_pool** — IPv4/IPv6 address allocation per session
- **uri_template** — URI template parsing for `{target}` and `{ipproto}`

Key design decisions:
- quinn + h3 stack (pure Rust, async tokio-native) over quiche
- DashMap for concurrent session table
- etherparse for IP packet parsing
- TUN device for kernel-level packet I/O

## Key RFCs

| RFC  | Role |
|------|------|
| 9484 | Core protocol (CONNECT-IP) |
| 9297 | HTTP Datagrams / Capsule Protocol |
| 9221 | QUIC DATAGRAM frames |
| 9000 | QUIC transport |
| 9114 | HTTP/3 |
