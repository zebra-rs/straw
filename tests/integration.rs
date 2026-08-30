//! End-to-end tests: in-process straw server + CONNECT-IP client(s) over
//! real QUIC on loopback. No TUN device and no privileges required — the
//! data-plane tests use hairpin forwarding between tunnel sessions.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

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
