//! End-to-end tests: in-process straw server + CONNECT-IP client(s) over
//! real QUIC on loopback. No TUN device and no privileges required — the
//! data-plane tests use hairpin forwarding between tunnel sessions.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use noq::crypto::rustls::{QuicClientConfig as NoqQuicClientConfig, QuicServerConfig as NoqQuicServerConfig};
use rustls::pki_types::CertificateDer;
use straw::address_pool::AddressPool;
use straw::capsule::{IpAddressRange, RequestedAddress};
use straw::client::{BindClient, ClientAuth, TlsMode, TunnelClient};
use straw::config::ProxyConfig;
use straw::forwarding::ForwardingEngine;
use straw::forwarding::icmp::IcmpSource;
use straw::forwarding::limiter::RateLimits;
use straw::forwarding::packet::{build_ipv4_icmp_echo, build_ipv6_icmpv6_echo, parse_packet};
use straw::forwarding::router::RouteTable;
use straw::metrics::Metrics;
use straw::p2p::identity::Identity;
use straw::p2p::inner_tls;
use straw::p2p::peer::{self, RelayAccess};
use straw::p2p::relay_socket::inner_endpoint;
use straw::p2p::token::TokenV2;
use straw::server::{ProxyContext, build_endpoint, run_server, spawn_idle_reaper};
use straw::session::SessionManager;
use straw::session::auth::Authenticator;
use straw::tls;

struct TestServer {
    addr: SocketAddr,
    cert: CertificateDer<'static>,
    endpoint: quinn::Endpoint,
    ctx: Arc<ProxyContext>,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
}

impl TestServer {
    async fn start() -> Self {
        Self::start_full(|_| {}, None).await
    }

    async fn start_with(customize: impl FnOnce(&mut ProxyConfig)) -> Self {
        Self::start_full(customize, None).await
    }

    async fn start_full(
        customize: impl FnOnce(&mut ProxyConfig),
        client_ca: Option<CertificateDer<'static>>,
    ) -> Self {
        straw::init_crypto();
        // Enable with e.g. RUST_LOG=straw=trace; safe to call repeatedly.
        let _ = tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "off".into()),
            )
            .with_test_writer()
            .try_init();

        let mut config = ProxyConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            ..ProxyConfig::default()
        };
        customize(&mut config);

        let (cert, key) = tls::generate_self_signed_cert(&["localhost"]).unwrap();
        let tls_config = match client_ca {
            Some(ca) => {
                tls::build_server_tls_config_with_client_auth(vec![cert.clone()], key, vec![ca])
                    .unwrap()
            }
            None => tls::build_server_tls_config(vec![cert.clone()], key).unwrap(),
        };

        let auth = Authenticator::new(
            config.auth_mode,
            config.auth_token.clone(),
            config.basic_credentials().unwrap(),
        );
        let metrics = Arc::new(Metrics::default());
        let route_table = Arc::new(RouteTable::new());
        let pool = AddressPool::new(config.ipv4_pool, config.ipv6_pool);
        let icmp_source = IcmpSource {
            v4: pool.ipv4_gateway().0,
            v6: pool.ipv6_gateway().map(|(addr, _)| addr),
        };
        let limits = RateLimits {
            packets_per_sec: config.max_packet_rate,
            bytes_per_sec: config.max_byte_rate,
        };
        let engine = Arc::new(ForwardingEngine::new(
            route_table,
            None,
            config.mtu,
            icmp_source,
            limits,
            metrics.clone(),
        ));
        let sessions = SessionManager::new(config.max_sessions);

        let endpoint = build_endpoint(&config, tls_config).unwrap();
        let addr = endpoint.local_addr().unwrap();

        // Bind mode, built from the (customized) config exactly as main.rs
        // does, so a test enables it by setting config.udp_bind in `customize`.
        let udp_bind = Arc::new(if config.udp_bind {
            use straw::forwarding::limiter::RateLimits;
            use straw::udp_bind::UdpBindState;
            use straw::udp_bind::alloc::PortAllocator;
            use straw::udp_bind::socket::DestinationPolicy;
            let allocator = PortAllocator::new(
                config.udp_bind_public_ips.clone(),
                config.udp_bind_port_lo,
                config.udp_bind_port_hi,
            )
            .unwrap();
            // Tests reach a loopback echo, so permit any destination.
            UdpBindState::enabled(
                allocator,
                DestinationPolicy::allow_all_for_test(),
                RateLimits::default(),
            )
        } else {
            straw::udp_bind::UdpBindState::disabled()
        });

        let ctx = Arc::new(ProxyContext {
            config,
            sessions,
            pool,
            engine,
            auth,
            metrics,
            udp_bind,
        });
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        tokio::spawn(run_server(endpoint.clone(), ctx.clone(), shutdown_rx));
        spawn_idle_reaper(ctx.clone());

        Self {
            addr,
            cert,
            endpoint,
            ctx,
            shutdown_tx,
        }
    }

    async fn client(&self) -> TunnelClient {
        TunnelClient::connect(self.addr, "localhost", TlsMode::Ca(self.cert.clone()))
            .await
            .expect("client connects")
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.endpoint.close(0u32.into(), b"test over");
    }
}

#[tokio::test]
async fn handshake_assignment_and_routes() {
    let server = TestServer::start().await;
    let mut client = server.client().await;

    tokio::time::timeout(Duration::from_secs(5), client.wait_for_assignment())
        .await
        .expect("assignment within 5s")
        .unwrap();

    // First client gets the first usable pool address (.2; .1 is the gateway).
    assert_eq!(client.assigned.len(), 1);
    let a = &client.assigned[0];
    assert_eq!(a.request_id, 0, "unprompted assignment");
    assert_eq!(a.ip_version, 4);
    assert_eq!(a.prefix_length, 32);
    assert_eq!(client.ipv4_address(), Some(Ipv4Addr::new(10, 100, 0, 2)));

    // Full-tunnel route advertisement.
    assert_eq!(client.routes.len(), 1);
    let r = &client.routes[0];
    assert_eq!(r.start_ip, "0.0.0.0".parse::<std::net::IpAddr>().unwrap());
    assert_eq!(
        r.end_ip,
        "255.255.255.255".parse::<std::net::IpAddr>().unwrap()
    );
    assert_eq!(r.ip_protocol, 0);

    client.close().await;
}

#[tokio::test]
async fn datagram_hairpin_self_ping() {
    let server = TestServer::start().await;
    let mut client = server.client().await;
    client.wait_for_assignment().await.unwrap();
    let addr = client.ipv4_address().unwrap();

    // Ping our own tunnel address: the proxy routes it straight back.
    let echo = build_ipv4_icmp_echo(addr, addr, false, 7, 1, b"hello straw", 64);
    client.send_packet(echo.clone()).unwrap();

    let reply = tokio::time::timeout(Duration::from_secs(5), client.recv_packet())
        .await
        .expect("hairpin packet within 5s")
        .unwrap();

    let info = parse_packet(&reply).unwrap();
    assert_eq!(info.src, std::net::IpAddr::from(addr));
    assert_eq!(info.dst, std::net::IpAddr::from(addr));
    assert_eq!(info.protocol, 1, "ICMP");
    assert_eq!(reply[8], 63, "proxy decremented TTL by one hop");
    // Header checksum still verifies after the TTL rewrite.
    assert_eq!(straw::forwarding::packet::ipv4_checksum(&reply[..20]), 0);
    // ICMP payload untouched.
    assert_eq!(&reply[28..], b"hello straw");

    client.close().await;
}

#[tokio::test]
async fn datagram_hairpin_between_two_clients() {
    let server = TestServer::start().await;

    let mut alice = server.client().await;
    alice.wait_for_assignment().await.unwrap();
    let alice_addr = alice.ipv4_address().unwrap();

    let mut bob = server.client().await;
    bob.wait_for_assignment().await.unwrap();
    let bob_addr = bob.ipv4_address().unwrap();

    assert_ne!(alice_addr, bob_addr, "distinct addresses per session");

    // Alice pings Bob through the proxy.
    let echo = build_ipv4_icmp_echo(alice_addr, bob_addr, false, 21, 1, b"hi bob", 64);
    alice.send_packet(echo).unwrap();

    let at_bob = tokio::time::timeout(Duration::from_secs(5), bob.recv_packet())
        .await
        .expect("packet reaches bob within 5s")
        .unwrap();
    let info = parse_packet(&at_bob).unwrap();
    assert_eq!(info.src, std::net::IpAddr::from(alice_addr));
    assert_eq!(info.dst, std::net::IpAddr::from(bob_addr));

    // Bob answers with an echo reply.
    let reply = build_ipv4_icmp_echo(bob_addr, alice_addr, true, 21, 1, b"hi alice", 64);
    bob.send_packet(reply).unwrap();

    let at_alice = tokio::time::timeout(Duration::from_secs(5), alice.recv_packet())
        .await
        .expect("reply reaches alice within 5s")
        .unwrap();
    let info = parse_packet(&at_alice).unwrap();
    assert_eq!(info.src, std::net::IpAddr::from(bob_addr));
    assert_eq!(&at_alice[28..], b"hi alice");

    alice.close().await;
    bob.close().await;
}

#[tokio::test]
async fn address_request_for_specific_ip() {
    let server = TestServer::start().await;
    let mut client = server.client().await;
    client.wait_for_assignment().await.unwrap();
    assert_eq!(client.assigned.len(), 1);

    let wanted: Ipv4Addr = "10.100.0.77".parse().unwrap();
    let assigned = client
        .request_address(RequestedAddress {
            request_id: 5,
            ip_version: 4,
            ip_address: wanted.into(),
            prefix_length: 32,
        })
        .await
        .unwrap();

    // Full-state ADDRESS_ASSIGN: previous address plus the requested one.
    assert_eq!(assigned.len(), 2);
    let new = assigned
        .iter()
        .find(|a| a.request_id == 5)
        .expect("entry answering request 5");
    assert_eq!(new.ip_address, std::net::IpAddr::from(wanted));

    // The new address is routable: ping it from the same tunnel.
    let src = client.ipv4_address().unwrap();
    let echo = build_ipv4_icmp_echo(src, wanted, false, 9, 1, b"second addr", 64);
    client.send_packet(echo).unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(5), client.recv_packet())
        .await
        .expect("packet to second address within 5s")
        .unwrap();
    assert_eq!(
        parse_packet(&reply).unwrap().dst,
        std::net::IpAddr::from(wanted)
    );

    client.close().await;
}

#[tokio::test]
async fn dual_stack_assignment_and_v6_ping() {
    let server = TestServer::start_with(|c| {
        c.ipv6_pool = Some("fd00:6d61:7371::/64".parse().unwrap());
    })
    .await;
    let mut client = server.client().await;
    client.wait_for_assignment().await.unwrap();

    // One v4 + one v6 address.
    assert_eq!(client.assigned.len(), 2);
    let v6 = client
        .assigned
        .iter()
        .find_map(|a| match a.ip_address {
            std::net::IpAddr::V6(addr) => Some(addr),
            _ => None,
        })
        .expect("an IPv6 address is assigned");
    assert_eq!(
        client
            .assigned
            .iter()
            .find(|a| a.ip_version == 6)
            .unwrap()
            .prefix_length,
        128
    );
    // Both address families advertised.
    assert!(client.routes.iter().any(|r| r.ip_version == 4));
    assert!(client.routes.iter().any(|r| r.ip_version == 6));

    // ICMPv6 echo hairpins back, hop limit decremented, checksum intact.
    let echo = build_ipv6_icmpv6_echo(v6, v6, false, 3, 1, b"ping6", 64);
    client.send_packet(echo).unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(5), client.recv_packet())
        .await
        .expect("v6 hairpin within 5s")
        .unwrap();
    let info = parse_packet(&reply).unwrap();
    assert_eq!(info.version, 6);
    assert_eq!(info.protocol, 58);
    assert_eq!(reply[7], 63, "hop limit decremented");
    assert_eq!(
        straw::forwarding::packet::icmpv6_checksum(&v6, &v6, &reply[40..]),
        0
    );

    client.close().await;
}

#[tokio::test]
async fn ttl_expiry_returns_time_exceeded() {
    let server = TestServer::start().await;
    let mut client = server.client().await;
    client.wait_for_assignment().await.unwrap();
    let addr = client.ipv4_address().unwrap();

    // TTL 1 dies at the proxy hop.
    let echo = build_ipv4_icmp_echo(addr, addr, false, 7, 1, b"dying", 1);
    client.send_packet(echo).unwrap();

    let icmp_reply = tokio::time::timeout(Duration::from_secs(5), client.recv_packet())
        .await
        .expect("ICMP within 5s")
        .unwrap();
    let info = parse_packet(&icmp_reply).unwrap();
    assert_eq!(
        info.src,
        "10.100.0.1".parse::<std::net::IpAddr>().unwrap(),
        "error originates from the pool gateway"
    );
    assert_eq!(info.dst, std::net::IpAddr::from(addr));
    assert_eq!(icmp_reply[20], 11, "Time Exceeded");
    // The quoted invoking packet is our echo, TTL still 1.
    assert_eq!(&icmp_reply[28 + 12..28 + 16], &addr.octets());
    assert_eq!(icmp_reply[28 + 8], 1);

    client.close().await;
}

#[tokio::test]
async fn unrouted_destination_returns_unreachable() {
    let server = TestServer::start().await;
    let mut client = server.client().await;
    client.wait_for_assignment().await.unwrap();
    let addr = client.ipv4_address().unwrap();

    // Full-tunnel policy allows it, but with no TUN there is no route.
    let echo = build_ipv4_icmp_echo(addr, "192.0.2.1".parse().unwrap(), false, 7, 1, b"", 64);
    client.send_packet(echo).unwrap();

    let icmp_reply = tokio::time::timeout(Duration::from_secs(5), client.recv_packet())
        .await
        .expect("ICMP within 5s")
        .unwrap();
    assert_eq!(icmp_reply[20], 3, "Destination Unreachable");
    assert_eq!(icmp_reply[21], 0, "net unreachable");

    client.close().await;
}

#[tokio::test]
async fn split_tunnel_scopes_routes_and_prohibits_outside() {
    let server = TestServer::start_with(|c| {
        c.split_routes = vec!["192.0.2.0/24".parse().unwrap()];
    })
    .await;
    let mut client = server.client().await;
    client.wait_for_assignment().await.unwrap();
    let addr = client.ipv4_address().unwrap();

    // Advertised: the pool subnet and the split prefix — not 0.0.0.0/0.
    assert_eq!(client.routes.len(), 2);
    assert!(client.routes.iter().any(|r| r.start_ip
        == "10.100.0.0".parse::<std::net::IpAddr>().unwrap()
        && r.end_ip == "10.100.0.255".parse::<std::net::IpAddr>().unwrap()));
    assert!(
        client
            .routes
            .iter()
            .any(|r| r.start_ip == "192.0.2.0".parse::<std::net::IpAddr>().unwrap())
    );

    // A destination outside the advertisement is administratively prohibited.
    let echo = build_ipv4_icmp_echo(addr, "198.51.100.9".parse().unwrap(), false, 7, 1, b"", 64);
    client.send_packet(echo).unwrap();
    let icmp_reply = tokio::time::timeout(Duration::from_secs(5), client.recv_packet())
        .await
        .expect("ICMP within 5s")
        .unwrap();
    assert_eq!(icmp_reply[20], 3);
    assert_eq!(icmp_reply[21], 13, "administratively prohibited");

    // Hairpin to the client's own pool address still works.
    let echo = build_ipv4_icmp_echo(addr, addr, false, 7, 2, b"pool ok", 64);
    client.send_packet(echo).unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(5), client.recv_packet())
        .await
        .expect("hairpin within 5s")
        .unwrap();
    assert_eq!(&reply[28..], b"pool ok");

    client.close().await;
}

#[tokio::test]
async fn site_to_site_client_routes_forward_between_sessions() {
    let server = TestServer::start_with(|c| {
        c.accept_client_routes = true;
    })
    .await;

    // Bob fronts a LAN and advertises it through his tunnel.
    let mut bob = server.client().await;
    bob.wait_for_assignment().await.unwrap();
    bob.send_route_advertisement(vec![IpAddressRange {
        ip_version: 4,
        start_ip: "192.168.50.0".parse().unwrap(),
        end_ip: "192.168.50.255".parse().unwrap(),
        ip_protocol: 0,
    }])
    .await
    .unwrap();

    let mut alice = server.client().await;
    alice.wait_for_assignment().await.unwrap();
    let alice_addr = alice.ipv4_address().unwrap();

    // Route installation is asynchronous to Alice's ping: retry briefly.
    let lan_host: Ipv4Addr = "192.168.50.7".parse().unwrap();
    let mut delivered = None;
    for seq in 1..=20u16 {
        let echo = build_ipv4_icmp_echo(alice_addr, lan_host, false, 9, seq, b"to the lan", 64);
        alice.send_packet(echo).unwrap();
        match tokio::time::timeout(Duration::from_millis(250), bob.recv_packet()).await {
            Ok(Ok(pkt)) => {
                delivered = Some(pkt);
                break;
            }
            _ => tokio::time::sleep(Duration::from_millis(50)).await,
        }
    }
    let pkt = delivered.expect("packet for Bob's LAN arrives via Bob's tunnel");
    let info = parse_packet(&pkt).unwrap();
    assert_eq!(info.src, std::net::IpAddr::from(alice_addr));
    assert_eq!(info.dst, std::net::IpAddr::from(lan_host));
    assert_eq!(&pkt[28..], b"to the lan");

    alice.close().await;
    bob.close().await;
}

#[tokio::test]
async fn spoofed_source_is_dropped() {
    let server = TestServer::start().await;
    let mut client = server.client().await;
    client.wait_for_assignment().await.unwrap();
    let addr = client.ipv4_address().unwrap();

    // Source address the session was never assigned (BCP 38 violation).
    let spoofed: Ipv4Addr = "10.100.0.200".parse().unwrap();
    let bad = build_ipv4_icmp_echo(spoofed, addr, false, 1, 1, b"spoof", 64);
    client.send_packet(bad).unwrap();

    // Then a legitimate packet.
    let good = build_ipv4_icmp_echo(addr, addr, false, 1, 2, b"legit", 64);
    client.send_packet(good).unwrap();

    // Only the legitimate packet comes back.
    let first = tokio::time::timeout(Duration::from_secs(5), client.recv_packet())
        .await
        .expect("legit packet within 5s")
        .unwrap();
    assert_eq!(&first[28..], b"legit");

    let nothing_else = tokio::time::timeout(Duration::from_millis(300), client.recv_packet()).await;
    assert!(
        nothing_else.is_err(),
        "spoofed packet must not be forwarded"
    );

    client.close().await;
}

// ---------------- Phase 4 ----------------

#[tokio::test]
async fn bearer_auth_enforced() {
    let server = TestServer::start_with(|c| {
        c.auth_mode = straw::session::auth::AuthMode::Bearer;
        c.auth_token = vec!["sekrit".into()];
    })
    .await;

    // No credentials: the proxy answers 401 and no session exists.
    let denied =
        TunnelClient::connect(server.addr, "localhost", TlsMode::Ca(server.cert.clone())).await;
    match denied {
        Err(straw::error::ProxyError::Http(msg)) => assert!(msg.contains("401"), "{msg}"),
        Err(e) => panic!("expected 401 rejection, got error {e}"),
        Ok(_) => panic!("expected 401 rejection, got a tunnel"),
    }
    assert!(server.ctx.sessions.is_empty());
    assert_eq!(
        server
            .ctx
            .metrics
            .auth_failures_total
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );

    // Wrong token: rejected too.
    let wrong = TunnelClient::connect_with(
        server.addr,
        "localhost",
        TlsMode::Ca(server.cert.clone()),
        ClientAuth::Bearer("nope".into()),
    )
    .await;
    assert!(wrong.is_err());

    // Correct token: tunnel established end to end.
    let mut client = TunnelClient::connect_with(
        server.addr,
        "localhost",
        TlsMode::Ca(server.cert.clone()),
        ClientAuth::Bearer("sekrit".into()),
    )
    .await
    .expect("authenticated client connects");
    client.wait_for_assignment().await.unwrap();
    assert!(client.ipv4_address().is_some());
    client.close().await;
}

#[tokio::test]
async fn basic_auth_enforced() {
    let server = TestServer::start_with(|c| {
        c.auth_mode = straw::session::auth::AuthMode::Basic;
        c.auth_basic = vec!["alice:wonder".into()];
    })
    .await;

    let denied = TunnelClient::connect_with(
        server.addr,
        "localhost",
        TlsMode::Ca(server.cert.clone()),
        ClientAuth::Basic {
            user: "alice".into(),
            password: "wrong".into(),
        },
    )
    .await;
    assert!(denied.is_err());

    let mut client = TunnelClient::connect_with(
        server.addr,
        "localhost",
        TlsMode::Ca(server.cert.clone()),
        ClientAuth::Basic {
            user: "alice".into(),
            password: "wonder".into(),
        },
    )
    .await
    .expect("authenticated client connects");
    client.wait_for_assignment().await.unwrap();
    client.close().await;
}

#[tokio::test]
async fn mtls_requires_client_certificate() {
    let (ca, client_cert, client_key) = tls::generate_client_ca_and_cert("straw-client").unwrap();
    let server = TestServer::start_full(
        |c| {
            c.auth_mode = straw::session::auth::AuthMode::Mtls;
            c.client_ca = Some("unused-by-test.pem".into());
        },
        Some(ca.clone()),
    )
    .await;

    // Without a client certificate the TLS handshake itself fails.
    let no_cert =
        TunnelClient::connect(server.addr, "localhost", TlsMode::Ca(server.cert.clone())).await;
    assert!(no_cert.is_err(), "handshake must fail without client cert");

    // With a certificate chaining to the CA, the tunnel works.
    let mut client = TunnelClient::connect(
        server.addr,
        "localhost",
        TlsMode::Mtls {
            ca: server.cert.clone(),
            cert_chain: vec![client_cert],
            key: client_key,
        },
    )
    .await
    .expect("mTLS client connects");
    client.wait_for_assignment().await.unwrap();
    let addr = client.ipv4_address().unwrap();
    let echo = build_ipv4_icmp_echo(addr, addr, false, 1, 1, b"mtls", 64);
    client.send_packet(echo).unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(5), client.recv_packet())
        .await
        .expect("hairpin within 5s")
        .unwrap();
    assert_eq!(&reply[28..], b"mtls");
    client.close().await;
}

#[tokio::test]
async fn idle_sessions_are_reaped() {
    let server = TestServer::start_with(|c| {
        c.session_idle_timeout_sec = 1;
    })
    .await;
    let mut client = server.client().await;
    client.wait_for_assignment().await.unwrap();
    assert_eq!(server.ctx.sessions.len(), 1);

    // Stay silent past the timeout; the reaper (interval 500ms) closes us.
    tokio::time::sleep(Duration::from_millis(2500)).await;
    assert!(
        server.ctx.sessions.is_empty(),
        "idle session must be reaped"
    );

    // The client observes the stream closing.
    let observed = tokio::time::timeout(Duration::from_secs(5), client.process_next_capsules())
        .await
        .expect("stream close observed within 5s");
    assert!(observed.is_err(), "tunnel stream should be closed");
}

#[tokio::test]
async fn metrics_endpoint_reports_counters() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let server = TestServer::start().await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let metrics_addr = listener.local_addr().unwrap();
    tokio::spawn(straw::metrics::serve_metrics(listener, server.ctx.clone()));

    // Generate some traffic first.
    let mut client = server.client().await;
    client.wait_for_assignment().await.unwrap();
    let addr = client.ipv4_address().unwrap();
    let echo = build_ipv4_icmp_echo(addr, addr, false, 1, 1, b"count me", 64);
    client.send_packet(echo).unwrap();
    let _ = tokio::time::timeout(Duration::from_secs(5), client.recv_packet())
        .await
        .unwrap()
        .unwrap();

    let mut socket = tokio::net::TcpStream::connect(metrics_addr).await.unwrap();
    socket
        .write_all(b"GET /metrics HTTP/1.1\r\nhost: test\r\n\r\n")
        .await
        .unwrap();
    let mut response = String::new();
    socket.read_to_string(&mut response).await.unwrap();

    assert!(response.starts_with("HTTP/1.1 200 OK"));
    assert!(response.contains("straw_sessions_total 1"));
    assert!(response.contains("straw_sessions_active 1"));
    assert!(response.contains("straw_packets_hairpin_total 1"));
    client.close().await;
}

#[tokio::test]
async fn graceful_shutdown_keeps_existing_tunnels_until_drained() {
    let server = TestServer::start().await;
    let mut client = server.client().await;
    client.wait_for_assignment().await.unwrap();
    let addr = client.ipv4_address().unwrap();

    // Begin shutdown: GOAWAY goes out, but the in-flight tunnel still works.
    server.shutdown_tx.send(true).unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let echo = build_ipv4_icmp_echo(addr, addr, false, 2, 1, b"draining", 64);
    client.send_packet(echo).unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(5), client.recv_packet())
        .await
        .expect("tunnel alive during grace period")
        .unwrap();
    assert_eq!(&reply[28..], b"draining");

    // Client finishes; the session drains.
    client.close().await;
    for _ in 0..50 {
        if server.ctx.sessions.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(server.ctx.sessions.is_empty(), "sessions drained");
}

// ---------------- Phase 5 ----------------

/// Rewrite an ICMP echo into another IP protocol (fixing the checksum) to
/// fake other transports.
fn with_proto(mut pkt: Vec<u8>, proto: u8) -> Vec<u8> {
    pkt[9] = proto;
    pkt[10] = 0;
    pkt[11] = 0;
    let cs = straw::forwarding::packet::ipv4_checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&cs.to_be_bytes());
    pkt
}

#[tokio::test]
async fn flow_scoped_tunnel_end_to_end() {
    let server = TestServer::start().await;

    // Alice: plain full tunnel; gets the first pool address (.2).
    let mut alice = server.client().await;
    alice.wait_for_assignment().await.unwrap();
    let alice_addr = alice.ipv4_address().unwrap();
    assert_eq!(alice_addr, Ipv4Addr::new(10, 100, 0, 2));

    // Bob: IP flow tunnel scoped to {Alice's address, ICMP only}.
    let mut bob = TunnelClient::connect_scoped(
        server.addr,
        "localhost",
        TlsMode::Ca(server.cert.clone()),
        ClientAuth::None,
        Some("10.100.0.2"),
        Some(1),
    )
    .await
    .expect("scoped tunnel accepted");
    bob.wait_for_assignment().await.unwrap();
    let bob_addr = bob.ipv4_address().unwrap();

    // The advertisement is exactly the scope, not the full tunnel.
    assert_eq!(bob.routes.len(), 1);
    let r = &bob.routes[0];
    assert_eq!(r.start_ip, std::net::IpAddr::from(alice_addr));
    assert_eq!(r.end_ip, std::net::IpAddr::from(alice_addr));
    assert_eq!(r.ip_protocol, 1);

    // In scope: Bob pings Alice through the flow tunnel.
    let echo = build_ipv4_icmp_echo(bob_addr, alice_addr, false, 31, 1, b"scoped", 64);
    bob.send_packet(echo).unwrap();
    let at_alice = tokio::time::timeout(Duration::from_secs(5), alice.recv_packet())
        .await
        .expect("scoped packet reaches alice")
        .unwrap();
    assert_eq!(&at_alice[28..], b"scoped");

    // Alice replies; the reply is from the scope target, so Bob gets it.
    let reply = build_ipv4_icmp_echo(alice_addr, bob_addr, true, 31, 1, b"pong", 64);
    alice.send_packet(reply).unwrap();
    let at_bob = tokio::time::timeout(Duration::from_secs(5), bob.recv_packet())
        .await
        .expect("reply reaches bob")
        .unwrap();
    assert_eq!(&at_bob[28..], b"pong");

    // Out of scope: any other destination is administratively prohibited.
    let stray = build_ipv4_icmp_echo(
        bob_addr,
        "192.0.2.7".parse().unwrap(),
        false,
        31,
        2,
        b"",
        64,
    );
    bob.send_packet(stray).unwrap();
    let icmp_reply = tokio::time::timeout(Duration::from_secs(5), bob.recv_packet())
        .await
        .expect("prohibition ICMP")
        .unwrap();
    assert_eq!(icmp_reply[20], 3);
    assert_eq!(icmp_reply[21], 13, "administratively prohibited");

    alice.close().await;
    bob.close().await;
}

#[tokio::test]
async fn scoped_ingress_blocks_third_parties_but_not_icmp() {
    let server = TestServer::start().await;

    let mut alice = server.client().await; // .2 — the scope target
    alice.wait_for_assignment().await.unwrap();
    let alice_addr = alice.ipv4_address().unwrap();

    // Bob: scoped to {Alice, UDP}.
    let mut bob = TunnelClient::connect_scoped(
        server.addr,
        "localhost",
        TlsMode::Ca(server.cert.clone()),
        ClientAuth::None,
        Some("10.100.0.2"),
        Some(17),
    )
    .await
    .unwrap();
    bob.wait_for_assignment().await.unwrap();
    let bob_addr = bob.ipv4_address().unwrap();

    let mut carol = server.client().await; // full tunnel, third party
    carol.wait_for_assignment().await.unwrap();
    let carol_addr = carol.ipv4_address().unwrap();

    // Carol -> Bob is outside Bob's scope: prohibited (Carol is told).
    let udp = with_proto(
        build_ipv4_icmp_echo(carol_addr, bob_addr, false, 1, 1, b"nope", 64),
        17,
    );
    carol.send_packet(udp).unwrap();
    let icmp_reply = tokio::time::timeout(Duration::from_secs(5), carol.recv_packet())
        .await
        .expect("prohibition ICMP for carol")
        .unwrap();
    assert_eq!(icmp_reply[21], 13);

    // Alice -> Bob as ICMP passes despite the UDP-only scope (RFC 9484:
    // ICMP is always allowed on the protocol dimension).
    let ping = build_ipv4_icmp_echo(alice_addr, bob_addr, false, 2, 1, b"icmp ok", 64);
    alice.send_packet(ping).unwrap();
    let at_bob = tokio::time::timeout(Duration::from_secs(5), bob.recv_packet())
        .await
        .expect("ICMP reaches scoped tunnel")
        .unwrap();
    assert_eq!(&at_bob[28..], b"icmp ok");

    alice.close().await;
    bob.close().await;
    carol.close().await;
}

#[tokio::test]
async fn multiple_scoped_tunnels_on_one_connection() {
    let server = TestServer::start().await;

    // Primary tunnel: full scope, stream 0.
    let mut client = server.client().await;
    client.wait_for_assignment().await.unwrap();
    let primary_addr = client.ipv4_address().unwrap();

    // Second tunnel on the same QUIC connection: scoped to a UDP flow.
    let mut flow = client
        .open_tunnel(ClientAuth::None, Some("192.0.2.9"), Some(17))
        .await
        .expect("second tunnel on the same connection");
    flow.wait_for_assignment().await.unwrap();
    let flow_addr = flow.ipv4_address().unwrap();
    assert_ne!(primary_addr, flow_addr, "each session gets its own address");
    assert_eq!(flow.routes.len(), 1);
    assert_eq!(flow.routes[0].ip_protocol, 17);
    assert_eq!(server.ctx.sessions.len(), 2, "two sessions, one connection");

    // Primary tunnel data plane still works (QSID 0).
    let echo = build_ipv4_icmp_echo(primary_addr, primary_addr, false, 5, 1, b"primary", 64);
    client.send_packet(echo).unwrap();
    let reply = tokio::time::timeout(Duration::from_secs(5), client.recv_packet())
        .await
        .expect("primary hairpin")
        .unwrap();
    assert_eq!(&reply[28..], b"primary");

    // Flow tunnel: in-scope UDP has no route (no TUN), so the proxy answers
    // with Destination Unreachable — delivered on the *flow* tunnel's
    // Quarter Stream ID, proving per-stream datagram demux both ways.
    let udp = with_proto(
        build_ipv4_icmp_echo(
            flow_addr,
            "192.0.2.9".parse().unwrap(),
            false,
            5,
            2,
            b"",
            64,
        ),
        17,
    );
    flow.send_packet(udp).unwrap();
    let icmp_reply = tokio::time::timeout(Duration::from_secs(5), flow.recv_packet())
        .await
        .expect("unreachable ICMP on the flow tunnel")
        .unwrap();
    assert_eq!(icmp_reply[20], 3, "Destination Unreachable");
    assert_eq!(icmp_reply[21], 0, "net unreachable");

    // Closing the flow tunnel leaves the primary session alive.
    flow.close().await;
    for _ in 0..50 {
        if server.ctx.sessions.len() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(server.ctx.sessions.len(), 1);

    client.close().await;
}

#[tokio::test]
async fn hostname_target_is_resolved_before_reply() {
    let server = TestServer::start().await;

    // "localhost" resolves; the advertisement carries the resolved address.
    let mut client = TunnelClient::connect_scoped(
        server.addr,
        "localhost",
        TlsMode::Ca(server.cert.clone()),
        ClientAuth::None,
        Some("localhost"),
        None,
    )
    .await
    .expect("hostname-scoped tunnel accepted");
    client.wait_for_assignment().await.unwrap();
    assert!(
        client
            .routes
            .iter()
            .any(|r| r.start_ip == "127.0.0.1".parse::<std::net::IpAddr>().unwrap()),
        "resolved A record advertised, got {:?}",
        client.routes
    );
    client.close().await;

    // An unresolvable name is rejected with 502 before the tunnel opens.
    let denied = TunnelClient::connect_scoped(
        server.addr,
        "localhost",
        TlsMode::Ca(server.cert.clone()),
        ClientAuth::None,
        Some("does-not-exist.invalid"),
        None,
    )
    .await;
    match denied {
        Err(straw::error::ProxyError::Http(msg)) => assert!(msg.contains("502"), "{msg}"),
        Err(e) => panic!("expected 502, got {e}"),
        Ok(_) => panic!("expected rejection for unresolvable target"),
    }
}

// ── CONNECT-UDP bind (P2P relay, design §3.1, §7) ──────────────────────

fn enable_bind(c: &mut ProxyConfig) {
    c.udp_bind = true;
    c.udp_bind_public_ips = vec!["127.0.0.1".parse().unwrap()];
    // A wide range so the ephemeral allocation always succeeds on a busy host.
    c.udp_bind_port_lo = 20000;
    c.udp_bind_port_hi = 60999;
}

#[tokio::test]
async fn bind_session_relays_udp_both_ways() {
    use tokio::net::UdpSocket;

    // A loopback echo server standing in for an Internet remote.
    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo_addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while let Ok((n, from)) = echo.recv_from(&mut buf).await {
            let _ = echo.send_to(&buf[..n], from).await;
        }
    });

    let server = TestServer::start_with(enable_bind).await;
    let client = BindClient::connect(
        server.addr,
        "localhost",
        TlsMode::Ca(server.cert.clone()),
        ClientAuth::None,
    )
    .await
    .expect("bind session opens");
    // The relay handed back a public address in the configured range.
    assert!(client.public_addr.ip().is_loopback());
    assert!((20000..=60999).contains(&client.public_addr.port()));

    client.send_to(echo_addr, b"p2p-ping").unwrap();
    let (from, payload) = tokio::time::timeout(Duration::from_secs(2), client.recv_from())
        .await
        .expect("echo within 2s")
        .expect("a datagram");
    assert_eq!(from, echo_addr, "reply carries the echo server's address");
    assert_eq!(&payload[..], b"p2p-ping");

    client.close().await;
}

#[tokio::test]
async fn connect_udp_is_refused_when_bind_disabled() {
    // Default server has bind mode off: the request is rejected, not served.
    let server = TestServer::start().await;
    let result = BindClient::connect(
        server.addr,
        "localhost",
        TlsMode::Ca(server.cert.clone()),
        ClientAuth::None,
    )
    .await;
    match result {
        Err(straw::error::ProxyError::Http(msg)) => {
            assert!(
                msg.contains("501"),
                "expected 501 Not Implemented, got {msg}"
            )
        }
        Ok(_) => panic!("expected a 501 rejection, bind succeeded"),
        Err(e) => panic!("expected a 501 rejection, got {e}"),
    }
}

#[tokio::test]
async fn inner_quic_connects_peer_to_peer_through_the_relay() {
    // Two peers, each a bind session at one relay; an inner QUIC connection
    // handshakes and carries a stream between them, the relay forwarding
    // ciphertext it cannot read (design §4, Phase B).
    let server = TestServer::start_with(enable_bind).await;

    let a = BindClient::connect(
        server.addr,
        "localhost",
        TlsMode::Ca(server.cert.clone()),
        ClientAuth::None,
    )
    .await
    .expect("peer A bind");
    let b = BindClient::connect(
        server.addr,
        "localhost",
        TlsMode::Ca(server.cert.clone()),
        ClientAuth::None,
    )
    .await
    .expect("peer B bind");
    let b_pub = b.public_addr;

    let sock_a = a.into_relay_socket(None);
    let sock_b = b.into_relay_socket(None);

    // Inner TLS: self-signed, verification skipped — this test isolates the
    // transport; SPKI-pinned RFC 7250 mTLS is the identity layer on top.
    let (icert, ikey) = straw::tls::generate_self_signed_cert(&["peer"]).unwrap();
    let inner_server = noq::ServerConfig::with_crypto(Arc::new(
        NoqQuicServerConfig::try_from(
            straw::tls::build_server_tls_config(vec![icert], ikey).unwrap(),
        )
        .unwrap(),
    ));
    let ep_b = inner_endpoint(sock_b, Some(inner_server)).unwrap();
    let ep_a = inner_endpoint(sock_a, None).unwrap();

    // B accepts the inner connection.
    let accept = tokio::spawn(async move {
        let incoming = ep_b.accept().await.expect("inner incoming");
        let conn = incoming.await.expect("inner accept");
        let (mut send, mut recv) = conn.accept_bi().await.expect("accept stream");
        let msg = recv.read_to_end(64).await.expect("read");
        send.write_all(&msg).await.expect("echo");
        send.finish().unwrap();
        // Hold the connection open until the client is done.
        conn.closed().await;
    });

    // A dials B at its relay-public address.
    let client_cfg = noq::ClientConfig::new(Arc::new(
        NoqQuicClientConfig::try_from(straw::tls::build_client_tls_config_insecure().unwrap())
            .unwrap(),
    ));
    let conn_a = tokio::time::timeout(
        Duration::from_secs(10),
        ep_a.connect_with(client_cfg, b_pub, "peer").expect("dial"),
    )
    .await
    .expect("inner handshake within 10s")
    .expect("inner connected");

    let (mut send, mut recv) = conn_a.open_bi().await.expect("open stream");
    send.write_all(b"hello-peer").await.unwrap();
    send.finish().unwrap();
    let echoed = recv.read_to_end(64).await.expect("read echo");
    assert_eq!(
        &echoed[..],
        b"hello-peer",
        "stream round-trips peer to peer"
    );

    conn_a.close(0u32.into(), b"done");
    let _ = accept.await;
}

/// Two bind sessions on one relay, an inner endpoint each, dialing B at its
/// paddr with the given inner TLS. Returns (A's connection, B's accepted
/// connection) or the dial error.
async fn dial_inner(
    server: &TestServer,
    client_cfg: noq::ClientConfig,
    server_cfg: noq::ServerConfig,
) -> Result<(noq::Connection, noq::Connection), noq::ConnectionError> {
    let a = BindClient::connect(
        server.addr,
        "localhost",
        TlsMode::Ca(server.cert.clone()),
        ClientAuth::None,
    )
    .await
    .unwrap();
    let b = BindClient::connect(
        server.addr,
        "localhost",
        TlsMode::Ca(server.cert.clone()),
        ClientAuth::None,
    )
    .await
    .unwrap();
    let b_pub = b.public_addr;
    let ep_b = inner_endpoint(b.into_relay_socket(None), Some(server_cfg)).unwrap();
    let ep_a = inner_endpoint(a.into_relay_socket(None), None).unwrap();
    let accept = tokio::spawn(async move {
        let incoming = ep_b.accept().await.expect("incoming");
        incoming.await
    });
    let conn_a = ep_a.connect_with(client_cfg, b_pub, "peer").unwrap().await;
    // Keep endpoint A alive until we have the result.
    let _keep = ep_a;
    match conn_a {
        Ok(a) => Ok((a, accept.await.unwrap().expect("B accepts"))),
        Err(e) => Err(e),
    }
}

fn quic_client(c: rustls::ClientConfig) -> noq::ClientConfig {
    noq::ClientConfig::new(Arc::new(NoqQuicClientConfig::try_from(c).unwrap()))
}
fn quic_server(c: rustls::ServerConfig) -> noq::ServerConfig {
    noq::ServerConfig::with_crypto(Arc::new(NoqQuicServerConfig::try_from(c).unwrap()))
}

#[tokio::test]
async fn inner_quic_mutual_raw_public_key_pinning() {
    // A pins B by B's identity (as a token's ppin would); B accepts A on
    // first use. Both directions authenticate by raw public key (RFC 7250).
    let server = TestServer::start_with(enable_bind).await;
    let id_a = Identity::generate().unwrap();
    let id_b = Identity::generate().unwrap();

    let (client_rustls, a_verifier) = inner_tls::client_config(&id_a, Some(id_b.pin())).unwrap();
    let (server_rustls, b_verifier) = inner_tls::server_config(&id_b, None).unwrap();

    let (conn_a, conn_b) = dial_inner(
        &server,
        quic_client(client_rustls),
        quic_server(server_rustls),
    )
    .await
    .expect("pinned inner handshake succeeds");

    // The pins each side observed match the real identities.
    assert_eq!(a_verifier.learned_pin(), Some(id_b.pin()), "A saw B's key");
    assert_eq!(
        b_verifier.learned_pin(),
        Some(id_a.pin()),
        "B learned A's key (TOFU)"
    );
    assert_eq!(conn_a.peer_identity().is_some(), true);

    // The pipe carries a stream.
    let (mut send, _recv) = conn_a.open_bi().await.unwrap();
    send.write_all(b"authenticated").await.unwrap();
    send.finish().unwrap();
    let (_s, mut r) = conn_b.accept_bi().await.unwrap();
    assert_eq!(&r.read_to_end(32).await.unwrap()[..], b"authenticated");
}

#[tokio::test]
async fn inner_quic_rejects_a_wrong_server_pin() {
    // A pins the WRONG server key; the handshake must fail closed.
    let server = TestServer::start_with(enable_bind).await;
    let id_a = Identity::generate().unwrap();
    let id_b = Identity::generate().unwrap();
    let impostor = Identity::generate().unwrap();

    let (client_rustls, _) = inner_tls::client_config(&id_a, Some(impostor.pin())).unwrap();
    let (server_rustls, _) = inner_tls::server_config(&id_b, None).unwrap();

    let result = dial_inner(
        &server,
        quic_client(client_rustls),
        quic_server(server_rustls),
    )
    .await;
    assert!(result.is_err(), "handshake must fail on a pin mismatch");
}

fn relay_access(server: &TestServer) -> RelayAccess {
    RelayAccess {
        addr: server.addr,
        server_name: "localhost".into(),
        tls: TlsMode::Ca(server.cert.clone()),
        auth: ClientAuth::None,
    }
}

#[tokio::test]
async fn strawcat_peers_pipe_over_a_token() {
    // The issuer listens and mints a token; the holder decodes it and dials
    // back through the relay; a bidi stream carries data both ways.
    let relay = TestServer::start_with(enable_bind).await;
    let issuer = Identity::generate().unwrap();
    let holder = Identity::generate().unwrap();

    let listener = peer::listen(relay_access(&relay), &issuer, None, None)
        .await
        .expect("issuer listens");

    let token = TokenV2::issue(
        "h3://relay.test:443".into(),
        [0u8; 32],
        "relay-bearer".into(),
        issuer.pin(),
        vec![listener.paddr.to_string()],
        1_700_000_000,
        3600,
    );
    let wire = token.encode();
    let decoded = TokenV2::decode(&wire).expect("token round-trips");

    // Listener accept and holder connect must run concurrently to handshake.
    let accept = tokio::spawn(async move { listener.accept().await });
    let holder_conn = peer::connect(relay_access(&relay), &holder, &decoded, None)
        .await
        .expect("holder connects");
    let issuer_conn = accept.await.unwrap().expect("issuer accepts");

    // Holder opens a strawcat/1 stream; issuer echoes.
    let (mut send, mut recv) = holder_conn.conn.open_bi().await.unwrap();
    send.write_all(b"strawcat-hello").await.unwrap();
    send.finish().unwrap();
    let (mut esend, mut erecv) = issuer_conn.accept_bi().await.unwrap();
    let got = erecv.read_to_end(64).await.unwrap();
    assert_eq!(&got[..], b"strawcat-hello");
    esend.write_all(&got).await.unwrap();
    esend.finish().unwrap();
    let echoed = recv.read_to_end(64).await.unwrap();
    assert_eq!(&echoed[..], b"strawcat-hello");
}

#[tokio::test]
async fn relay_path_carries_a_large_transfer() {
    // Regression for the inner-QUIC MTU trap: every inner packet is re-wrapped
    // as one outer QUIC DATAGRAM, so the inner MTU must stay within the outer
    // datagram. quinn's path-MTU discovery would otherwise probe the inner
    // connection past that ceiling; those oversize packets fail send_datagram
    // and the connection stalls after the handshake. A small payload never
    // trips it — only a transfer large enough to send full-size packets does.
    let relay = TestServer::start_with(enable_bind).await;
    let issuer = Identity::generate().unwrap();
    let holder = Identity::generate().unwrap();

    let listener = peer::listen(relay_access(&relay), &issuer, None, None)
        .await
        .expect("issuer listens");
    let token = TokenV2::issue(
        "h3://relay.test:443".into(),
        [0u8; 32],
        "relay-bearer".into(),
        issuer.pin(),
        vec![listener.paddr.to_string()],
        1_700_000_000,
        3600,
    );

    let accept = tokio::spawn(async move { listener.accept().await });
    let holder_conn = peer::connect(relay_access(&relay), &holder, &token, None)
        .await
        .expect("holder connects");
    let issuer_conn = accept.await.unwrap().expect("issuer accepts");

    // 256 KiB, larger than any single inner packet, so full-size packets flow.
    let payload: Vec<u8> = (0..256 * 1024).map(|i| (i % 251) as u8).collect();
    let expected = payload.clone();

    let issuer_echo = tokio::spawn(async move {
        let (mut esend, mut erecv) = issuer_conn.accept_bi().await.unwrap();
        let got = erecv.read_to_end(1024 * 1024).await.unwrap();
        esend.write_all(&got).await.unwrap();
        esend.finish().unwrap();
        // Keep the connection alive until the holder has read the echo.
        issuer_conn.closed().await;
        got
    });

    let round_trip = tokio::time::timeout(Duration::from_secs(15), async move {
        let (mut send, mut recv) = holder_conn.conn.open_bi().await.unwrap();
        send.write_all(&payload).await.unwrap();
        send.finish().unwrap();
        recv.read_to_end(1024 * 1024).await.unwrap()
    })
    .await
    .expect("large transfer completes over the relay within 15s");

    assert_eq!(round_trip.len(), expected.len(), "echo is the full length");
    assert_eq!(round_trip, expected, "256 KiB round-trips byte-for-byte");
    let received = issuer_echo.await.unwrap();
    assert_eq!(received, expected, "issuer received the whole payload");
}

#[tokio::test]
async fn bind_session_reports_the_reflexive_candidate() {
    // The relay reports the peer's outer source as OBSERVED_ADDRESS; the
    // BindClient captures it as its reflexive candidate (design §5.1).
    let server = TestServer::start_with(enable_bind).await;
    let client = BindClient::connect(
        server.addr,
        "localhost",
        TlsMode::Ca(server.cert.clone()),
        ClientAuth::None,
    )
    .await
    .expect("bind session");
    let observed = client
        .observed_addr
        .expect("relay reported an observed address");
    // The client dialed the relay from a loopback ephemeral port; the relay
    // sees exactly that source.
    assert!(observed.ip().is_loopback());
    assert_ne!(observed.port(), 0);
}

#[cfg(any())] // parked during noq migration: direct-path punch → Stage 3 (noq native multipath)
#[tokio::test]
async fn predict_strategy_runs_and_establishes_a_path() {
    // The `predict` strategy samples the NAT via auxiliary bind sessions, then
    // punches. On loopback it still reaches a direct path (the reflexive is
    // directly reachable); this exercises the strategy dispatch and the
    // aux-session sampling against a real relay end to end.
    use std::sync::Arc;
    let relay = TestServer::start_with(enable_bind).await;
    let issuer = Identity::generate().unwrap();
    let holder = Identity::generate().unwrap();

    let listener = peer::listen(relay_access(&relay), &issuer, None, None)
        .await
        .unwrap();
    let issuer_paddr = listener.paddr;
    let issuer_punch = listener.punch_endpoint.clone();
    let issuer_reflexive = listener.reflexive;
    let token = TokenV2::issue(
        "h3://relay.test:443".into(),
        [0u8; 32],
        "auth".into(),
        issuer.pin(),
        vec![issuer_paddr.to_string()],
        1_700_000_000,
        3600,
    );
    let accept = tokio::spawn(async move { listener.accept().await });
    let holder_side = peer::connect(relay_access(&relay), &holder, &token, None)
        .await
        .unwrap();
    let issuer_conn = accept.await.unwrap().unwrap();

    let issuer_id = issuer;
    let holder_id = holder;
    let ra = Arc::new(relay_access(&relay));
    let (issuer_direct, holder_direct) = tokio::join!(
        holepunch::coordinate(holepunch::PunchInputs {
            inner: &issuer_conn,
            initiator: false,
            identity: &issuer_id,
            peer_pin: Some(holder_id.pin()),
            punch_endpoint: issuer_punch,
            reflexive: issuer_reflexive,
            relay: issuer_paddr,
            strategy: PunchStrategy::Predict,
            relay_access: Some(ra.clone()),
            peer_reflexive: None,
            port_map: false,
        }),
        holepunch::coordinate(holepunch::PunchInputs {
            inner: &holder_side.conn,
            initiator: true,
            identity: &holder_id,
            peer_pin: Some(issuer_id.pin()),
            punch_endpoint: holder_side.punch_endpoint.clone(),
            reflexive: holder_side.reflexive,
            relay: issuer_paddr,
            strategy: PunchStrategy::Predict,
            relay_access: Some(ra.clone()),
            peer_reflexive: None,
            port_map: false,
        }),
    );
    let issuer_direct = issuer_direct.expect("issuer gets a direct path (predict)");
    let holder_direct = holder_direct.expect("holder gets a direct path (predict)");
    assert!(issuer_direct.conn.remote_address().ip().is_loopback());

    let (mut s, _r) = holder_direct.conn.open_bi().await.unwrap();
    s.write_all(b"predict!").await.unwrap();
    s.finish().unwrap();
    let (_s2, mut r2) = issuer_direct.conn.accept_bi().await.unwrap();
    assert_eq!(&r2.read_to_end(16).await.unwrap()[..], b"predict!");
}

#[cfg(any())] // parked during noq migration: direct-path punch → Stage 3 (noq native multipath)
#[tokio::test]
async fn peers_upgrade_to_a_direct_path_by_hole_punching() {
    // Full P2 flow: two peers meet through the relay (Phase B), exchange
    // candidates, and hole-punch to a direct connection that bypasses the
    // relay. On loopback there is no NAT, so the "host" candidate (the punch
    // socket) is directly reachable — this proves exchange + simultaneous
    // open + pin end to end.
    let relay = TestServer::start_with(enable_bind).await;
    let issuer = Identity::generate().unwrap();
    let holder = Identity::generate().unwrap();

    // Establish the inner relay connection (Phase B), capturing each side's
    // reflexive address and the relay paddr for candidate gathering.
    let listener = peer::listen(relay_access(&relay), &issuer, None, None)
        .await
        .unwrap();
    let issuer_paddr = listener.paddr;
    let issuer_punch = listener.punch_endpoint.clone();
    let issuer_reflexive = listener.reflexive;
    let token = TokenV2::issue(
        "h3://relay.test:443".into(),
        [0u8; 32],
        "auth".into(),
        issuer.pin(),
        vec![issuer_paddr.to_string()],
        1_700_000_000,
        3600,
    );
    let accept = tokio::spawn(async move { listener.accept().await });
    let holder_side = peer::connect(relay_access(&relay), &holder, &token, None)
        .await
        .unwrap();
    let issuer_conn = accept.await.unwrap().unwrap();

    // Punch. The inner client (holder) is the initiator.
    let issuer_id = issuer;
    let holder_id = holder;
    let (issuer_direct, holder_direct) = tokio::join!(
        holepunch::coordinate(holepunch::PunchInputs {
            inner: &issuer_conn,
            initiator: false,
            identity: &issuer_id,
            peer_pin: Some(holder_id.pin()),
            punch_endpoint: issuer_punch,
            reflexive: issuer_reflexive,
            relay: issuer_paddr,
            strategy: PunchStrategy::Basic,
            relay_access: None,
            peer_reflexive: None,
            port_map: false,
        }),
        holepunch::coordinate(holepunch::PunchInputs {
            inner: &holder_side.conn,
            initiator: true,
            identity: &holder_id,
            peer_pin: Some(issuer_id.pin()),
            punch_endpoint: holder_side.punch_endpoint.clone(),
            reflexive: holder_side.reflexive,
            relay: issuer_paddr,
            strategy: PunchStrategy::Basic,
            relay_access: None,
            peer_reflexive: None,
            port_map: false,
        }),
    );
    let issuer_direct = issuer_direct.expect("issuer gets a direct path");
    let holder_direct = holder_direct.expect("holder gets a direct path");

    // The direct connection is NOT the relay path: its peer address is the
    // other peer's punch socket (loopback), not a relay-allocated port.
    assert!(issuer_direct.conn.remote_address().ip().is_loopback());

    // And it carries data.
    let (mut s, _r) = holder_direct.conn.open_bi().await.unwrap();
    s.write_all(b"direct!").await.unwrap();
    s.finish().unwrap();
    let (_s2, mut r2) = issuer_direct.conn.accept_bi().await.unwrap();
    assert_eq!(&r2.read_to_end(16).await.unwrap()[..], b"direct!");
}

#[cfg(any())] // parked during noq migration: direct-path punch → Stage 3 (noq native multipath)
#[tokio::test]
async fn session_upgrades_to_direct_then_falls_back_on_loss() {
    // The path state machine: RELAY → PUNCHING → DIRECT, connection() tracks
    // the best path, and killing the direct path reverts to the relay.
    let relay = TestServer::start_with(enable_bind).await;
    let issuer = Identity::generate().unwrap();
    let holder = Identity::generate().unwrap();

    let listener = peer::listen(relay_access(&relay), &issuer, None, None)
        .await
        .unwrap();
    let issuer_paddr = listener.paddr;
    let issuer_punch = listener.punch_endpoint.clone();
    let issuer_reflexive = listener.reflexive;
    let token = TokenV2::issue(
        "h3://r:443".into(),
        [0u8; 32],
        "a".into(),
        issuer.pin(),
        vec![issuer_paddr.to_string()],
        1_700_000_000,
        3600,
    );
    let accept = tokio::spawn(async move { listener.accept().await });
    let holder_side = peer::connect(relay_access(&relay), &holder, &token, None)
        .await
        .unwrap();
    let issuer_conn = accept.await.unwrap().unwrap();

    let issuer_pin = issuer.pin();
    let holder_pin = holder.pin();
    let issuer_relay = issuer_conn.clone();
    let issuer_sess = Session::start(
        issuer_conn,
        false,
        Arc::new(issuer),
        Some(holder_pin),
        issuer_punch,
        issuer_reflexive,
        issuer_paddr,
        PunchConfig::default(),
    );
    let holder_sess = Session::start(
        holder_side.conn,
        true,
        Arc::new(holder),
        Some(issuer_pin),
        holder_side.punch_endpoint.clone(),
        holder_side.reflexive,
        issuer_paddr,
        PunchConfig::default(),
    );

    // Both reach DIRECT.
    assert!(
        issuer_sess.await_direct(Duration::from_secs(10)).await,
        "issuer direct"
    );
    assert!(
        holder_sess.await_direct(Duration::from_secs(10)).await,
        "holder direct"
    );
    assert_eq!(issuer_sess.state(), PathState::Direct);

    // connection() now returns the direct path, not the relay.
    let direct = issuer_sess.connection();
    assert!(direct.remote_address().ip().is_loopback());
    assert_ne!(
        direct.stable_id(),
        issuer_relay.stable_id(),
        "distinct from the relay conn"
    );

    // Kill the direct path from the holder side; the issuer session reverts.
    holder_sess.connection().close(0u32.into(), b"drop direct");
    let mut rx_state = PathState::Direct;
    for _ in 0..50 {
        if issuer_sess.state() == PathState::Relay {
            rx_state = PathState::Relay;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(rx_state, PathState::Relay, "issuer fell back to the relay");
    // And connection() is the relay again.
    assert_eq!(
        issuer_sess.connection().stable_id(),
        issuer_relay.stable_id(),
        "back on the relay connection"
    );
}

/// A tiny in-process PCP server that answers one MAP request with a fixed
/// assigned external address (echoing the client's nonce).
async fn pcp_stub(assigned_port: u16, assigned_ip: std::net::Ipv4Addr) -> std::net::SocketAddr {
    use tokio::net::UdpSocket;
    let sock = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = sock.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0u8; 1100];
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                return;
            };
            if n >= 60 && buf[0] == 2 {
                let mut resp = vec![0u8; 60];
                resp[0] = 2;
                resp[1] = 0x81; // response | opcode MAP
                resp[4..8].copy_from_slice(&3600u32.to_be_bytes());
                resp[24..36].copy_from_slice(&buf[24..36]); // echo nonce
                resp[42..44].copy_from_slice(&assigned_port.to_be_bytes());
                resp[54] = 0xff;
                resp[55] = 0xff;
                resp[56..60].copy_from_slice(&assigned_ip.octets());
                let _ = sock.send_to(&resp, from).await;
            }
        }
    });
    addr
}

#[tokio::test]
async fn port_map_requests_a_forward_via_pcp() {
    // The PCP/NAT-PMP client sends a MAP request and returns the router's
    // assigned external address — the candidate a peer behind a symmetric NAT
    // advertises so the far side can reach it through an explicit forward.
    let stub = pcp_stub(50000, "198.51.100.7".parse().unwrap()).await;
    let mapping = straw::p2p::portmap::map_udp_via(stub, 41000, Duration::from_secs(120))
        .await
        .expect("stub grants the mapping");
    assert_eq!(
        mapping.external,
        "198.51.100.7:50000"
            .parse::<std::net::SocketAddr>()
            .unwrap()
    );
}

#[tokio::test]
async fn stun_detects_endpoint_independent_over_loopback() {
    // The relay's RFC 5780 STUN server on two loopback IPs; a client detects
    // its mapping behaviour end to end. Loopback has no NAT, so the reflexive
    // is the same for every destination — endpoint-independent (cone).
    use straw::p2p::stun::{self, NatMapping};
    let primary: std::net::SocketAddr = "127.0.0.1:34790".parse().unwrap();
    let alternate: std::net::SocketAddr = "127.0.0.2:34791".parse().unwrap();
    tokio::spawn(async move {
        let _ = stun::serve(primary, alternate).await;
    });
    // Let the four sockets bind.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mapping = stun::detect_mapping(primary)
        .await
        .expect("detection completes against the STUN server");
    assert_eq!(mapping, NatMapping::EndpointIndependent);
    assert!(mapping.is_punchable());
}
