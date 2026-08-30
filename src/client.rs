//! CONNECT-IP client: connects to a straw proxy, obtains an address
//! assignment, and exchanges IP packets over HTTP Datagrams.
//!
//! Used by the `test_client` binary and the integration tests; a future
//! `strawcat` peer builds on the same type.

use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use http::{Method, Request, StatusCode};
use quinn::crypto::rustls::QuicClientConfig;
use rustls::pki_types::CertificateDer;

use crate::capsule::{
    AddressRequest, AssignedAddress, Capsule, CapsuleBuffer, IpAddressRange, RequestedAddress,
    encode_capsule,
};
use crate::datagram::{
    CONTEXT_ID_IP_PACKET, IpProxyingDatagram, decode_quic_datagram, encode_quic_datagram,
    quarter_stream_id,
};
use crate::error::ProxyError;
use crate::tls;

/// How the client validates the server certificate.
pub enum TlsMode {
    /// Skip verification (testing only).
    Insecure,
    /// Trust exactly this CA / self-signed certificate.
    Ca(CertificateDer<'static>),
}

type ClientStream = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

/// An established CONNECT-IP tunnel.
pub struct TunnelClient {
    // Held so the sockets outlive the tunnel.
    _endpoint: quinn::Endpoint,
    // Held because h3 closes the connection when the last SendRequest drops.
    _send_request: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    conn: quinn::Connection,
    stream: ClientStream,
    qsid: u64,
    capsules: CapsuleBuffer,
    /// Complete current assignment set (full-state per RFC 9484 §4.7.1).
    pub assigned: Vec<AssignedAddress>,
    /// Routes advertised by the proxy.
    pub routes: Vec<IpAddressRange>,
}

impl TunnelClient {
    /// Connect and send the Extended CONNECT request; returns once the
    /// proxy accepts the tunnel (200).
    pub async fn connect(
        server_addr: SocketAddr,
        server_name: &str,
        tls_mode: TlsMode,
    ) -> Result<Self, ProxyError> {
        let tls_config = match tls_mode {
            TlsMode::Insecure => tls::build_client_tls_config_insecure()?,
            TlsMode::Ca(cert) => tls::build_client_tls_config_with_ca(cert)?,
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

        let Ok(protocol) =
            h3::ext::Protocol::from_str(crate::session::handler::CONNECT_IP_PROTOCOL)
        else {
            unreachable!("connect-ip is a valid protocol token");
        };
        let authority = format!("{server_name}:{}", server_addr.port());
        let request = Request::builder()
            .method(Method::CONNECT)
            .uri(format!("https://{authority}/.well-known/masque/ip/*/*/"))
            .header("capsule-protocol", "?1")
            .extension(protocol)
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
        Ok(Self {
            _endpoint: endpoint,
            _send_request: send_request,
            conn,
            stream,
            qsid,
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

    /// Receive stream data and fold every complete capsule into the client
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
    pub async fn recv_packet(&self) -> Result<Bytes, ProxyError> {
        loop {
            let wire = self.conn.read_datagram().await?;
            match decode_quic_datagram(wire) {
                Ok((qsid, datagram))
                    if qsid == self.qsid && datagram.context_id == CONTEXT_ID_IP_PACKET =>
                {
                    return Ok(datagram.payload);
                }
                Ok(_) => continue, // other stream or unknown context: skip
                Err(e) => {
                    tracing::trace!("malformed datagram dropped: {e}");
                    continue;
                }
            }
        }
    }

    /// Close the tunnel stream and the QUIC connection.
    pub async fn close(mut self) {
        let _ = self.stream.finish().await;
        self.conn.close(0u32.into(), b"done");
    }
}
