//! End-to-end tests: in-process straw server + CONNECT-IP client(s) over
//! real QUIC on loopback. No TUN device and no privileges required — the
//! data-plane tests use hairpin forwarding between tunnel sessions.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use rustls::pki_types::CertificateDer;
use straw::address_pool::AddressPool;
use straw::capsule::{IpAddressRange, RequestedAddress};
use straw::client::{TlsMode, TunnelClient};
use straw::config::ProxyConfig;
use straw::forwarding::ForwardingEngine;
use straw::forwarding::icmp::IcmpSource;
use straw::forwarding::packet::{build_ipv4_icmp_echo, build_ipv6_icmpv6_echo, parse_packet};
use straw::forwarding::router::RouteTable;
use straw::server::{ProxyContext, build_endpoint, run_server};
use straw::session::SessionManager;
use straw::tls;

struct TestServer {
    addr: SocketAddr,
    cert: CertificateDer<'static>,
    endpoint: quinn::Endpoint,
}

impl TestServer {
    async fn start() -> Self {
        Self::start_with(|_| {}).await
    }

    async fn start_with(customize: impl FnOnce(&mut ProxyConfig)) -> Self {
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
        let tls_config = tls::build_server_tls_config(vec![cert.clone()], key).unwrap();

        let route_table = Arc::new(RouteTable::new());
        let pool = AddressPool::new(config.ipv4_pool, config.ipv6_pool);
        let icmp_source = IcmpSource {
            v4: pool.ipv4_gateway().0,
            v6: pool.ipv6_gateway().map(|(addr, _)| addr),
        };
        let engine = Arc::new(ForwardingEngine::new(
            route_table,
            None,
            config.mtu,
            icmp_source,
        ));
        let sessions = SessionManager::new(config.max_sessions);

        let endpoint = build_endpoint(&config, tls_config).unwrap();
        let addr = endpoint.local_addr().unwrap();

        let ctx = Arc::new(ProxyContext {
            config,
            sessions,
            pool,
            engine,
        });
        tokio::spawn(run_server(endpoint.clone(), ctx));

        Self {
            addr,
            cert,
            endpoint,
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
