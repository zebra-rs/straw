//! CONNECT-IP client: connects to a straw proxy, obtains an address
//! assignment, and exchanges IP packets over HTTP Datagrams.
//!
//! One [`TunnelClient`] owns a QUIC connection and its primary [`Tunnel`];
//! additional flow-scoped tunnels (RFC 9484 §8.3) can be opened on the same
//! connection with [`TunnelClient::open_tunnel`]. A per-connection demux
//! task routes incoming datagrams to the right tunnel by Quarter Stream ID.
//!
//! Used by the `test_client` binary and the integration tests; a future
//! `strawcat` peer builds on the same types.

use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use dashmap::DashMap;
use http::{Method, Request, StatusCode};
use quinn::crypto::rustls::QuicClientConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::capsule::{
    AddressRequest, AssignedAddress, Capsule, CapsuleBuffer, IpAddressRange, RequestedAddress,
    encode_capsule,
};
use crate::datagram::{
    CONTEXT_ID_IP_PACKET, IpProxyingDatagram, decode_quic_datagram, encode_quic_datagram,
    max_ip_packet_size, quarter_stream_id,
};
use crate::error::ProxyError;
use crate::tls;

/// How the client validates the server certificate.
pub enum TlsMode {
    /// Skip verification (testing only).
    Insecure,
    /// Trust exactly this CA / self-signed certificate.
    Ca(CertificateDer<'static>),
    /// Trust `ca` and present a client certificate (mTLS).
    Mtls {
        ca: CertificateDer<'static>,
        cert_chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
    },
}

/// Manual `Clone`: `PrivateKeyDer` is not `Clone`, so rebuild it from its DER
/// bytes. Lets a shared `RelayAccess` reconnect auxiliary bind sessions
/// (predict/birthday NAT sampling).
impl Clone for TlsMode {
    fn clone(&self) -> Self {
        use rustls::pki_types::{PrivatePkcs1KeyDer, PrivatePkcs8KeyDer, PrivateSec1KeyDer};
        match self {
            TlsMode::Insecure => TlsMode::Insecure,
            TlsMode::Ca(c) => TlsMode::Ca(c.clone()),
            TlsMode::Mtls {
                ca,
                cert_chain,
                key,
            } => {
                let key: PrivateKeyDer<'static> = match key {
                    PrivateKeyDer::Pkcs1(k) => {
                        PrivatePkcs1KeyDer::from(k.secret_pkcs1_der().to_vec()).into()
                    }
                    PrivateKeyDer::Pkcs8(k) => {
                        PrivatePkcs8KeyDer::from(k.secret_pkcs8_der().to_vec()).into()
                    }
                    PrivateKeyDer::Sec1(k) => {
                        PrivateSec1KeyDer::from(k.secret_sec1_der().to_vec()).into()
                    }
                    _ => unreachable!("PrivateKeyDer variant is exhaustive here"),
                };
                TlsMode::Mtls {
                    ca: ca.clone(),
                    cert_chain: cert_chain.clone(),
                    key,
                }
            }
        }
    }
}

/// Request-level credentials sent with the Extended CONNECT.
#[derive(Debug, Clone, Default)]
pub enum ClientAuth {
    #[default]
    None,
    Bearer(String),
    Basic {
        user: String,
        password: String,
    },
}

type ClientStream = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
type SendRequest = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;
type DatagramDemux = Arc<DashMap<u64, tokio::sync::mpsc::Sender<Bytes>>>;

/// Depth of each tunnel's inbound packet queue.
const TUNNEL_QUEUE_DEPTH: usize = 256;

/// A cloneable send-only handle for a tunnel's datagrams (see
/// [`Tunnel::sender`]).
#[derive(Debug, Clone)]
pub struct PacketSender {
    conn: quinn::Connection,
    qsid: u64,
}

impl PacketSender {
    /// Send one IP packet through the tunnel (context ID 0).
    pub fn send_packet(&self, packet: impl Into<Bytes>) -> Result<(), ProxyError> {
        let datagram = IpProxyingDatagram::ip_packet(packet.into());
        let wire = encode_quic_datagram(self.qsid, &datagram);
        if let Some(max) = self.conn.max_datagram_size()
            && wire.len() > max
        {
            return Err(ProxyError::Forwarding(
                crate::error::ForwardingError::MtuExceeded,
            ));
        }
        self.conn.send_datagram(wire)?;
        Ok(())
    }

    /// Usable tunnel MTU (largest IP packet in one datagram), or `None`
    /// before datagrams are available.
    pub fn max_packet_size(&self) -> Option<usize> {
        max_ip_packet_size(self.conn.max_datagram_size()?, self.qsid)
    }
}

/// One established CONNECT-IP tunnel (a single request stream).
pub struct Tunnel {
    stream: ClientStream,
    conn: quinn::Connection,
    qsid: u64,
    rx: Option<tokio::sync::mpsc::Receiver<Bytes>>,
    demux: DatagramDemux,
    capsules: CapsuleBuffer,
    /// Complete current assignment set (full-state per RFC 9484 §4.7.1).
    pub assigned: Vec<AssignedAddress>,
    /// Routes advertised by the proxy.
    pub routes: Vec<IpAddressRange>,
}

impl Tunnel {
    async fn establish(
        send_request: &mut SendRequest,
        conn: &quinn::Connection,
        demux: &DatagramDemux,
        authority: &str,
        auth: &ClientAuth,
        target: Option<&str>,
        ipproto: Option<u8>,
    ) -> Result<Self, ProxyError> {
        let Ok(protocol) =
            h3::ext::Protocol::from_str(crate::session::handler::CONNECT_IP_PROTOCOL)
        else {
            unreachable!("connect-ip is a valid protocol token");
        };

        let target_segment = match target {
            Some(t) => encode_template_value(t),
            None => "*".to_string(),
        };
        let ipproto_segment = match ipproto {
            Some(p) => p.to_string(),
            None => "*".to_string(),
        };
        let path = format!("/.well-known/masque/ip/{target_segment}/{ipproto_segment}/");

        let mut builder = Request::builder()
            .method(Method::CONNECT)
            .uri(format!("https://{authority}{path}"))
            .header("capsule-protocol", "?1")
            .extension(protocol);
        match auth {
            ClientAuth::None => {}
            ClientAuth::Bearer(token) => {
                builder = builder.header(http::header::AUTHORIZATION, format!("Bearer {token}"));
            }
            ClientAuth::Basic { user, password } => {
                use base64::Engine as _;
                let encoded =
                    base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
                builder = builder.header(http::header::AUTHORIZATION, format!("Basic {encoded}"));
            }
        }
        let request = builder
            .body(())
            .map_err(|e| ProxyError::InvalidRequest(e.to_string()))?;

        let mut stream = send_request.send_request(request).await?;
        let response = stream.recv_response().await?;
        if response.status() != StatusCode::OK {
            return Err(ProxyError::Http(format!(
                "proxy rejected tunnel: {}",
                response.status()
            )));
        }

        let qsid = quarter_stream_id(stream.id().into_inner());
        let (tx, rx) = tokio::sync::mpsc::channel(TUNNEL_QUEUE_DEPTH);
        demux.insert(qsid, tx);

        Ok(Self {
            stream,
            conn: conn.clone(),
            qsid,
            rx: Some(rx),
            demux: demux.clone(),
            capsules: CapsuleBuffer::new(),
            assigned: Vec::new(),
            routes: Vec::new(),
        })
    }

    /// Read capsules until both an address assignment and a route
    /// advertisement have arrived (tunnel setup complete).
    pub async fn wait_for_assignment(&mut self) -> Result<(), ProxyError> {
        while self.assigned.is_empty() || self.routes.is_empty() {
            self.process_next_capsules().await?;
        }
        Ok(())
    }

    /// Receive stream data and fold every complete capsule into the tunnel
    /// state. Returns the capsules processed.
    pub async fn process_next_capsules(&mut self) -> Result<Vec<Capsule>, ProxyError> {
        let mut seen = Vec::new();
        loop {
            match self.stream.recv_data().await? {
                Some(chunk) => {
                    self.capsules.push(chunk);
                    while let Some(capsule) = self.capsules.next_capsule()? {
                        self.apply_capsule(&capsule);
                        seen.push(capsule);
                    }
                    if !seen.is_empty() {
                        return Ok(seen);
                    }
                }
                None => {
                    return Err(ProxyError::Http("proxy closed the tunnel".into()));
                }
            }
        }
    }

    fn apply_capsule(&mut self, capsule: &Capsule) {
        match capsule {
            Capsule::AddressAssign(assign) => {
                // Full-state semantics: replace, don't append.
                self.assigned = assign.assigned_addresses.clone();
            }
            Capsule::RouteAdvertisement(ra) => {
                self.routes = ra.ip_address_ranges.clone();
            }
            _ => {}
        }
    }

    /// First assigned IPv4 address, if any.
    pub fn ipv4_address(&self) -> Option<Ipv4Addr> {
        self.assigned.iter().find_map(|a| match a.ip_address {
            std::net::IpAddr::V4(v4) => Some(v4),
            _ => None,
        })
    }

    /// Advertise routes reachable through this client (site-to-site). The
    /// proxy installs them only when started with --accept-client-routes.
    pub async fn send_route_advertisement(
        &mut self,
        ranges: Vec<IpAddressRange>,
    ) -> Result<(), ProxyError> {
        let capsule = Capsule::RouteAdvertisement(crate::capsule::RouteAdvertisement {
            ip_address_ranges: ranges,
        });
        let mut buf = BytesMut::new();
        encode_capsule(&capsule, &mut buf);
        self.stream.send_data(buf.freeze()).await?;
        Ok(())
    }

    /// Send an ADDRESS_REQUEST and wait for the resulting ADDRESS_ASSIGN.
    pub async fn request_address(
        &mut self,
        request: RequestedAddress,
    ) -> Result<Vec<AssignedAddress>, ProxyError> {
        let capsule = Capsule::AddressRequest(AddressRequest {
            requested_addresses: vec![request],
        });
        let mut buf = BytesMut::new();
        encode_capsule(&capsule, &mut buf);
        self.stream.send_data(buf.freeze()).await?;

        loop {
            let seen = self.process_next_capsules().await?;
            if seen.iter().any(|c| matches!(c, Capsule::AddressAssign(_))) {
                return Ok(self.assigned.clone());
            }
        }
    }

    /// Send one IP packet through the tunnel (context ID 0).
    pub fn send_packet(&self, packet: impl Into<Bytes>) -> Result<(), ProxyError> {
        let datagram = IpProxyingDatagram::ip_packet(packet.into());
        let wire = encode_quic_datagram(self.qsid, &datagram);
        if let Some(max) = self.conn.max_datagram_size()
            && wire.len() > max
        {
            return Err(ProxyError::Forwarding(
                crate::error::ForwardingError::MtuExceeded,
            ));
        }
        self.conn.send_datagram(wire)?;
        Ok(())
    }

    /// Receive the next IP packet addressed to this tunnel.
    pub async fn recv_packet(&mut self) -> Result<Bytes, ProxyError> {
        self.rx
            .as_mut()
            .ok_or_else(|| ProxyError::Http("packet receiver was taken".into()))?
            .recv()
            .await
            .ok_or_else(|| ProxyError::Http("connection closed".into()))
    }

    /// Take the inbound-packet receiver, so a dedicated downlink task can
    /// own it while this tunnel keeps handling capsules (`strawc` runs the
    /// two concurrently). After this, [`recv_packet`] errors.
    pub fn take_packet_rx(&mut self) -> Option<tokio::sync::mpsc::Receiver<Bytes>> {
        self.rx.take()
    }

    /// Route this tunnel's inbound packets straight into `sink` from the
    /// connection's demux task, replacing the internal queue — one less
    /// channel hop and one less task on the downlink path (Step 32).
    /// `strawc` points this at its TUN writer. After this, [`recv_packet`]
    /// errors.
    pub fn set_packet_sink(&mut self, sink: tokio::sync::mpsc::Sender<Bytes>) {
        self.rx = None;
        self.demux.insert(self.qsid, sink);
    }

    /// A cheap, cloneable handle for sending packets on this tunnel from
    /// another task. `quinn::Connection` is `Arc`-backed, so cloning is free.
    pub fn sender(&self) -> PacketSender {
        PacketSender {
            conn: self.conn.clone(),
            qsid: self.qsid,
        }
    }

    /// Largest IP packet that currently fits in one QUIC DATAGRAM — the
    /// usable tunnel MTU (RFC 9484 §7.2), or `None` before the peer enables
    /// datagrams. Tracks quinn's path MTU, which only grows after discovery.
    pub fn max_packet_size(&self) -> Option<usize> {
        max_ip_packet_size(self.conn.max_datagram_size()?, self.qsid)
    }

    /// Close this tunnel's request stream (the connection stays up).
    pub async fn close(mut self) {
        self.demux.remove(&self.qsid);
        let _ = self.stream.finish().await;
    }
}

/// Percent-encode a `{target}` template value: prefix slashes and IPv6
/// colons must be escaped (RFC 9484 §4.6).
fn encode_template_value(value: &str) -> String {
    value.replace('/', "%2F").replace(':', "%3A")
}

/// A QUIC connection to a straw proxy with its primary tunnel.
///
/// Derefs to [`Tunnel`], so the primary tunnel's methods and state are
/// available directly on the client.
pub struct TunnelClient {
    // Held so the sockets outlive the tunnels (None when the connection is
    // supplied externally, e.g. a strawcat peer connection).
    _endpoint: Option<quinn::Endpoint>,
    conn: quinn::Connection,
    // Also held because h3 closes the connection when the last one drops.
    send_request: SendRequest,
    demux: DatagramDemux,
    authority: String,
    tunnel: Tunnel,
}

impl std::ops::Deref for TunnelClient {
    type Target = Tunnel;
    fn deref(&self) -> &Tunnel {
        &self.tunnel
    }
}

impl std::ops::DerefMut for TunnelClient {
    fn deref_mut(&mut self) -> &mut Tunnel {
        &mut self.tunnel
    }
}

impl TunnelClient {
    /// Connect and establish an unscoped tunnel; returns once the proxy
    /// accepts it (200).
    pub async fn connect(
        server_addr: SocketAddr,
        server_name: &str,
        tls_mode: TlsMode,
    ) -> Result<Self, ProxyError> {
        Self::connect_scoped(
            server_addr,
            server_name,
            tls_mode,
            ClientAuth::None,
            None,
            None,
        )
        .await
    }

    /// [`TunnelClient::connect`] with request credentials.
    pub async fn connect_with(
        server_addr: SocketAddr,
        server_name: &str,
        tls_mode: TlsMode,
        auth: ClientAuth,
    ) -> Result<Self, ProxyError> {
        Self::connect_scoped(server_addr, server_name, tls_mode, auth, None, None).await
    }

    /// Connect with an IP flow scope (RFC 9484 §8.3): `target` is a
    /// hostname, IP, or prefix (`"192.0.2.0/24"`), `ipproto` an IP protocol
    /// number; `None` means the `*` wildcard.
    pub async fn connect_scoped(
        server_addr: SocketAddr,
        server_name: &str,
        tls_mode: TlsMode,
        auth: ClientAuth,
        target: Option<&str>,
        ipproto: Option<u8>,
    ) -> Result<Self, ProxyError> {
        let tls_config = match tls_mode {
            TlsMode::Insecure => tls::build_client_tls_config_insecure()?,
            TlsMode::Ca(cert) => tls::build_client_tls_config_with_ca(cert)?,
            TlsMode::Mtls {
                ca,
                cert_chain,
                key,
            } => tls::build_client_tls_config_mtls(ca, cert_chain, key)?,
        };
        let quic_tls =
            QuicClientConfig::try_from(tls_config).map_err(|e| ProxyError::Tls(e.to_string()))?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_tls));

        let mut transport = quinn::TransportConfig::default();
        transport.keep_alive_interval(Some(Duration::from_secs(15)));
        client_config.transport_config(Arc::new(transport));

        let bind: SocketAddr = if server_addr.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let mut endpoint = quinn::Endpoint::client(bind)?;
        endpoint.set_default_client_config(client_config);

        let conn = endpoint.connect(server_addr, server_name)?.await?;

        let authority = format!("{server_name}:{}", server_addr.port());
        Self::from_conn(conn, Some(endpoint), authority, auth, target, ipproto).await
    }

    /// Run the CONNECT-IP client over an already-established QUIC connection —
    /// e.g. a strawcat peer connection (relay or punched). `authority` is the
    /// `:authority` for the request; the connection's lifetime is the caller's.
    pub async fn over_connection(
        conn: quinn::Connection,
        authority: &str,
        auth: ClientAuth,
        target: Option<&str>,
        ipproto: Option<u8>,
    ) -> Result<Self, ProxyError> {
        Self::from_conn(conn, None, authority.to_string(), auth, target, ipproto).await
    }

    /// Wrap `conn` for HTTP/3, start the driver + datagram demux, and establish
    /// the first tunnel. `endpoint` is held only when this owns the socket.
    async fn from_conn(
        conn: quinn::Connection,
        endpoint: Option<quinn::Endpoint>,
        authority: String,
        auth: ClientAuth,
        target: Option<&str>,
        ipproto: Option<u8>,
    ) -> Result<Self, ProxyError> {
        // Wrap for HTTP/3, keeping the raw handle for DATAGRAM I/O.
        let h3_conn = h3_quinn::Connection::new(conn.clone());
        let (mut driver, mut send_request) = h3::client::builder()
            .enable_datagram(true)
            .enable_extended_connect(true)
            .build::<_, _, Bytes>(h3_conn)
            .await?;

        // The driver processes control-stream traffic for the connection.
        tokio::spawn(async move {
            let err = driver.wait_idle().await;
            tracing::debug!("h3 driver finished: {err}");
        });

        // Demux inbound datagrams to tunnels by Quarter Stream ID; ends
        // when the connection closes.
        let demux: DatagramDemux = Arc::new(DashMap::new());
        let demux_conn = conn.clone();
        let demux_map = demux.clone();
        tokio::spawn(async move {
            while let Ok(wire) = demux_conn.read_datagram().await {
                match decode_quic_datagram(wire) {
                    Ok((qsid, datagram)) if datagram.context_id == CONTEXT_ID_IP_PACKET => {
                        if let Some(tx) = demux_map.get(&qsid) {
                            // Datagram semantics: drop on backpressure.
                            let _ = tx.try_send(datagram.payload);
                        }
                    }
                    Ok(_) => {} // unknown context: silently dropped
                    Err(e) => tracing::trace!("malformed datagram dropped: {e}"),
                }
            }
        });

        let tunnel = Tunnel::establish(
            &mut send_request,
            &conn,
            &demux,
            &authority,
            &auth,
            target,
            ipproto,
        )
        .await?;

        Ok(Self {
            _endpoint: endpoint,
            conn,
            send_request,
            demux,
            authority,
            tunnel,
        })
    }

    /// Open an additional tunnel on this connection with its own scope
    /// (multiple concurrent sessions per client, RFC 9484 §8.3).
    pub async fn open_tunnel(
        &mut self,
        auth: ClientAuth,
        target: Option<&str>,
        ipproto: Option<u8>,
    ) -> Result<Tunnel, ProxyError> {
        Tunnel::establish(
            &mut self.send_request,
            &self.conn,
            &self.demux,
            &self.authority.clone(),
            &auth,
            target,
            ipproto,
        )
        .await
    }

    /// Close the primary tunnel and the QUIC connection.
    pub async fn close(self) {
        let TunnelClient { conn, tunnel, .. } = self;
        tunnel.close().await;
        conn.close(0u32.into(), b"done");
    }
}

/// A minimal CONNECT-UDP bind client (design §3.1): opens a bind session at a
/// straw relay, registers the uncompressed context, and exchanges UDP
/// payloads (addressed per datagram) with arbitrary remotes.
///
/// This is the client half the P2P peer (`strawcat`) will build on; for now
/// it exists to drive the relay's bind handler end to end. One bind session
/// per connection, datagrams read straight off the connection.
pub struct BindClient {
    _endpoint: quinn::Endpoint,
    _send_request: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    conn: quinn::Connection,
    stream: ClientStream,
    qsid: u64,
    contexts: crate::udp_bind::context::ContextTable,
    uncompressed: u64,
    /// The relay-allocated public address, from `proxy-public-address`.
    pub public_addr: std::net::SocketAddr,
    /// The peer's outer source as the relay observes it — the server-
    /// reflexive candidate for hole punching (design §5.1), if reported.
    pub observed_addr: Option<std::net::SocketAddr>,
}

impl BindClient {
    /// Open a bind session and register the uncompressed context (id 2).
    pub async fn connect(
        server_addr: SocketAddr,
        server_name: &str,
        tls_mode: TlsMode,
        auth: ClientAuth,
    ) -> Result<Self, ProxyError> {
        use crate::udp_bind::context::{
            Binding, CAPSULE_COMPRESSION_ACK, CAPSULE_OBSERVED_ADDRESS, CompressionAssign,
            FIRST_UNCOMPRESSED_CONTEXT, decode_context_capsule, decode_observed_address,
        };

        let tls_config = match tls_mode {
            TlsMode::Insecure => tls::build_client_tls_config_insecure()?,
            TlsMode::Ca(cert) => tls::build_client_tls_config_with_ca(cert)?,
            TlsMode::Mtls {
                ca,
                cert_chain,
                key,
            } => tls::build_client_tls_config_mtls(ca, cert_chain, key)?,
        };
        let quic_tls =
            QuicClientConfig::try_from(tls_config).map_err(|e| ProxyError::Tls(e.to_string()))?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_tls));
        let mut transport = quinn::TransportConfig::default();
        transport.keep_alive_interval(Some(Duration::from_secs(15)));
        client_config.transport_config(Arc::new(transport));
        let bind: SocketAddr = if server_addr.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };
        let mut endpoint = quinn::Endpoint::client(bind)?;
        endpoint.set_default_client_config(client_config);
        let conn = endpoint.connect(server_addr, server_name)?.await?;

        let h3_conn = h3_quinn::Connection::new(conn.clone());
        let (mut driver, mut send_request) = h3::client::builder()
            .enable_datagram(true)
            .enable_extended_connect(true)
            .build::<_, _, Bytes>(h3_conn)
            .await?;
        tokio::spawn(async move {
            let _ = driver.wait_idle().await;
        });

        let Ok(protocol) =
            h3::ext::Protocol::from_str(crate::udp_bind::handler::CONNECT_UDP_PROTOCOL)
        else {
            unreachable!("connect-udp is a valid protocol token");
        };
        let authority = format!("{server_name}:{}", server_addr.port());
        let mut builder = Request::builder()
            .method(Method::CONNECT)
            .uri(format!(
                "https://{authority}/.well-known/masque/udp/%2A/%2A/"
            ))
            .header("capsule-protocol", "?1")
            .header("connect-udp-bind", "?1")
            .extension(protocol);
        builder = apply_auth(builder, &auth);
        let request = builder
            .body(())
            .map_err(|e| ProxyError::InvalidRequest(e.to_string()))?;

        let mut stream = send_request.send_request(request).await?;
        let response = stream.recv_response().await?;
        if response.status() != StatusCode::OK {
            return Err(ProxyError::Http(format!(
                "relay rejected bind: {}",
                response.status()
            )));
        }
        let public_addr = response
            .headers()
            .get("proxy-public-address")
            .and_then(|v| v.to_str().ok())
            .map(|v| v.trim().trim_matches('"'))
            .and_then(|v| v.parse().ok())
            .ok_or_else(|| ProxyError::Http("relay omitted proxy-public-address".into()))?;

        let qsid = quarter_stream_id(stream.id().into_inner());
        let mut contexts = crate::udp_bind::context::ContextTable::new();
        let uncompressed = FIRST_UNCOMPRESSED_CONTEXT;
        let assign = CompressionAssign {
            context_id: uncompressed,
            binding: Binding::Uncompressed,
        };
        contexts.register(assign.clone()).expect("fresh context");
        let mut buf = BytesMut::new();
        assign.encode(&mut buf);
        stream.send_data(buf.freeze()).await?;

        // Read capsules until the relay's COMPRESSION_ACK, capturing the
        // OBSERVED_ADDRESS (our reflexive candidate) along the way.
        let mut observed_addr = None;
        let mut capsules = CapsuleBuffer::new();
        'ack: loop {
            let Some(chunk) = stream.recv_data().await? else {
                return Err(ProxyError::Http("relay closed before ACK".into()));
            };
            capsules.push(chunk);
            while let Some(capsule) = capsules.next_capsule()? {
                if let Capsule::Unknown { type_id, data } = capsule {
                    match type_id {
                        CAPSULE_OBSERVED_ADDRESS => {
                            observed_addr = decode_observed_address(data).ok();
                        }
                        CAPSULE_COMPRESSION_ACK
                            if decode_context_capsule(data)? == uncompressed =>
                        {
                            contexts.ack(uncompressed).expect("acked our context");
                            break 'ack;
                        }
                        _ => {}
                    }
                }
            }
        }

        Ok(Self {
            _endpoint: endpoint,
            _send_request: send_request,
            conn,
            stream,
            qsid,
            contexts,
            uncompressed,
            public_addr,
            observed_addr,
        })
    }

    /// Send a UDP payload to `remote` through the relay.
    pub fn send_to(&self, remote: SocketAddr, payload: &[u8]) -> Result<(), ProxyError> {
        let body = self
            .contexts
            .encode_datagram(self.uncompressed, remote, payload)
            .map_err(|e| ProxyError::InvalidRequest(e.to_string()))?;
        let mut wire = BytesMut::with_capacity(8 + body.len());
        crate::capsule::codec::write_varint(&mut wire, self.qsid).unwrap();
        wire.extend_from_slice(&body);
        self.conn.send_datagram(wire.freeze())?;
        Ok(())
    }

    /// Receive the next UDP payload and its source, from the relay.
    pub async fn recv_from(&self) -> Result<(SocketAddr, Bytes), ProxyError> {
        use bytes::Buf as _;
        loop {
            let wire = self.conn.read_datagram().await?;
            let mut cursor = wire.clone();
            let qsid = crate::capsule::codec::read_varint(&mut cursor)?;
            if qsid != self.qsid {
                continue;
            }
            let body = wire.slice(wire.len() - cursor.remaining()..);
            match self.contexts.decode_datagram(body) {
                Ok(dg) => return Ok((dg.remote, dg.payload)),
                Err(e) => {
                    tracing::trace!("bind client dropped datagram: {e}");
                    continue;
                }
            }
        }
    }

    /// Close the bind session and connection.
    pub async fn close(mut self) {
        let _ = self.stream.finish().await;
        self.conn.close(0u32.into(), b"done");
    }

    /// Turn this bind session into a [`RelaySocket`](crate::p2p::relay_socket::RelaySocket):
    /// a `quinn::AsyncUdpSocket` an inner-QUIC endpoint runs over (design
    /// §4). The spawned pump owns the request stream — keeping the relay
    /// session open — and decapsulates inbound datagrams into the socket.
    /// A clone of the outer QUIC endpoint (the real UDP socket whose NAT
    /// mapping the relay observed as this peer's reflexive). Reused for the
    /// hole punch so the punch source matches the advertised reflexive
    /// (endpoint-independent NATs keep one mapping per socket across
    /// destinations); a fresh socket would get a different, unadvertised one.
    pub fn endpoint(&self) -> quinn::Endpoint {
        self._endpoint.clone()
    }

    pub fn into_relay_socket(
        self,
        peer_reflexive_sink: Option<Arc<Mutex<Vec<SocketAddr>>>>,
    ) -> Arc<crate::p2p::relay_socket::RelaySocket> {
        use crate::capsule::Capsule;
        use crate::capsule::codec::read_varint;
        use crate::udp_bind::context::{
            CAPSULE_PEER_REFLEXIVE, decode_peer_reflexive, decode_uncompressed_body,
        };
        use bytes::Buf as _;

        let BindClient {
            _endpoint,
            _send_request,
            conn,
            mut stream,
            qsid,
            uncompressed,
            public_addr,
            observed_addr: _,
            contexts: _,
        } = self;
        let (tx, rx) = tokio::sync::mpsc::channel(256);
        let conn_rx = conn.clone();
        let recv = tokio::spawn(async move {
            // Hold the session's resources open for the socket's lifetime and
            // serve two streams: inner-QUIC datagrams (to the relay socket) and
            // control capsules (relay-assisted PEER_REFLEXIVE signals).
            let _endpoint = _endpoint;
            let _send_request = _send_request;
            let mut capsules = crate::capsule::CapsuleBuffer::new();
            loop {
                tokio::select! {
                    dg = conn_rx.read_datagram() => {
                        let Ok(wire) = dg else { return };
                        let mut cursor = wire.clone();
                        let Ok(got) = read_varint(&mut cursor) else { continue };
                        if got != qsid {
                            continue;
                        }
                        let body = wire.slice(wire.len() - cursor.remaining()..);
                        if let Ok((_, remote, payload)) = decode_uncompressed_body(body) {
                            let _ = tx.try_send((remote, payload));
                        }
                    }
                    data = stream.recv_data() => {
                        match data {
                            Ok(Some(chunk)) => {
                                capsules.push(chunk);
                                while let Ok(Some(Capsule::Unknown { type_id, data })) =
                                    capsules.next_capsule()
                                {
                                    if type_id == CAPSULE_PEER_REFLEXIVE
                                        && let Ok(addr) = decode_peer_reflexive(data)
                                        && let Some(sink) = &peer_reflexive_sink
                                    {
                                        tracing::debug!(%addr, "bind: PEER_REFLEXIVE from relay");
                                        let mut v = sink.lock().unwrap();
                                        if !v.contains(&addr) {
                                            v.push(addr);
                                        }
                                    }
                                }
                            }
                            // Stream closed or errored: the session is over.
                            _ => return,
                        }
                    }
                }
            }
        });
        crate::p2p::relay_socket::RelaySocket::new(conn, qsid, uncompressed, public_addr, rx, recv)
    }
}

/// Apply request credentials to an Extended CONNECT builder.
fn apply_auth(builder: http::request::Builder, auth: &ClientAuth) -> http::request::Builder {
    match auth {
        ClientAuth::None => builder,
        ClientAuth::Bearer(token) => {
            builder.header(http::header::AUTHORIZATION, format!("Bearer {token}"))
        }
        ClientAuth::Basic { user, password } => {
            use base64::Engine as _;
            let encoded =
                base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
            builder.header(http::header::AUTHORIZATION, format!("Basic {encoded}"))
        }
    }
}
