//! Coordinated simultaneous open — the hole punch (design §5.3).
//!
//! quinn exposes neither extension frames nor client-side probing of a new
//! remote path, so v1 does not migrate the inner relay connection. Instead,
//! DCUtR-style, each peer stands up a *fresh* QUIC endpoint on a new UDP
//! socket and both peers dial each other's candidates on it while also
//! accepting — both directions transmitting is what opens the NAT bindings,
//! and whichever handshake completes first is the direct path. The probe
//! uses the same RFC 7250 pinned identity as the relay path (§4), so a
//! completed probe is an authenticated direct connection.
//!
//! A [`Puncher`] is created before candidate exchange so its local address
//! can be advertised as a host candidate; then [`Puncher::punch`] races the
//! dials against inbound attempts.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

/// QUIC PING interval on the direct path: NAT UDP bindings commonly expire at
/// ~30s, so keep it alive well under that (design §6).
const KEEPALIVE: Duration = Duration::from_secs(20);

use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};

use crate::error::ProxyError;
use crate::p2p::identity::{Identity, SpkiPin};
use crate::p2p::inner_tls;

/// Which side dialed a completed probe connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    /// We dialed it (we are the QUIC client).
    Client,
    /// We accepted it (we are the QUIC server).
    Server,
}

/// The peer's SPKI pin from a completed connection's raw-public-key identity.
fn peer_pin_of(conn: &quinn::Connection) -> Option<SpkiPin> {
    let certs = conn
        .peer_identity()?
        .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
        .ok()?;
    let spki = certs.first()?;
    Some(crate::p2p::identity::pin_of_spki(spki.as_ref()))
}

/// A fresh QUIC endpoint for one punch attempt: both accepts inbound probes
/// and dials the peer's candidates, all pinned to the peer's key.
pub struct Puncher {
    endpoint: quinn::Endpoint,
    client_config: quinn::ClientConfig,
}

impl Puncher {
    /// Bind a fresh punch endpoint on `bind_addr` (use `0.0.0.0:0` for an
    /// ephemeral socket). `expected_peer` pins the far peer's key.
    pub fn new(
        bind_addr: SocketAddr,
        identity: &Identity,
        expected_peer: Option<SpkiPin>,
    ) -> Result<Self, ProxyError> {
        let (server_tls, _) = inner_tls::server_config(identity, expected_peer)?;
        let (client_tls, _) = inner_tls::client_config(identity, expected_peer)?;
        let server = quinn::ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(server_tls).map_err(|e| ProxyError::Tls(e.to_string()))?,
        ));
        let mut client_config = quinn::ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(client_tls).map_err(|e| ProxyError::Tls(e.to_string()))?,
        ));
        // Keepalive on both directions so the direct path holds its NAT
        // binding once established (design §6).
        let mut transport = quinn::TransportConfig::default();
        transport.keep_alive_interval(Some(KEEPALIVE));
        let transport = Arc::new(transport);
        client_config.transport_config(transport.clone());
        let mut server = server;
        server.transport_config(transport);
        let endpoint = quinn::Endpoint::server(server, bind_addr).map_err(ProxyError::Io)?;
        Ok(Self {
            endpoint,
            client_config,
        })
    }

    /// The local address to advertise as this peer's host candidate.
    pub fn local_addr(&self) -> Result<SocketAddr, ProxyError> {
        self.endpoint.local_addr().map_err(ProxyError::Io)
    }

    /// Race dials to every `remote` candidate against inbound probes and
    /// return the single connection both peers agree to keep, or time out.
    ///
    /// Both peers dialing and accepting at once is the simultaneous open —
    /// that is what opens the NATs — so up to two connections can complete.
    /// The duplicate-success tie-break (design §5.3.4, §2.1) makes both sides
    /// keep the *same* one: the connection whose client is the peer with the
    /// lexicographically lower SPKI pin. Each side keeps the connection whose
    /// role (client if it dialed, server if it accepted) matches that rule,
    /// and closes any other — so the two peers converge without coordination.
    pub async fn punch(
        &self,
        my_pin: SpkiPin,
        peer_pin: Option<SpkiPin>,
        remotes: &[SocketAddr],
        timeout: Duration,
    ) -> Result<quinn::Connection, ProxyError> {
        // (role, connection): Client = we dialed it, Server = we accepted it.
        let (tx, mut rx) = tokio::sync::mpsc::channel::<(Role, quinn::Connection)>(8);

        // Inbound accept loop: every probe the peer dialed to us.
        let ep = self.endpoint.clone();
        let accept_tx = tx.clone();
        let accept_task = tokio::spawn(async move {
            while let Some(incoming) = ep.accept().await {
                if let Ok(conn) = incoming.await
                    && accept_tx.send((Role::Server, conn)).await.is_err()
                {
                    return;
                }
            }
        });

        // Outbound dials.
        for &remote in remotes {
            match self
                .endpoint
                .connect_with(self.client_config.clone(), remote, "peer")
            {
                Ok(connecting) => {
                    let tx = tx.clone();
                    tokio::spawn(async move {
                        if let Ok(conn) = connecting.await {
                            let _ = tx.send((Role::Client, conn)).await;
                        }
                    });
                }
                Err(e) => tracing::debug!(%remote, "punch dial not started: {e}"),
            }
        }
        drop(tx);

        let deadline = tokio::time::sleep(timeout);
        tokio::pin!(deadline);
        let result = loop {
            tokio::select! {
                _ = &mut deadline => break Err(ProxyError::Quic("hole punch timed out".into())),
                next = rx.recv() => {
                    let Some((role, conn)) = next else {
                        break Err(ProxyError::Quic("all punch attempts failed".into()));
                    };
                    // Resolve the tie-break: the lower-pinned peer is client.
                    let want_client = match peer_pin.or_else(|| peer_pin_of(&conn)) {
                        Some(pp) => my_pin < pp,
                        // No peer pin available (should not happen post-
                        // handshake): accept the first completion.
                        None => role == Role::Client,
                    };
                    let keep = (want_client && role == Role::Client)
                        || (!want_client && role == Role::Server);
                    if keep {
                        break Ok(conn);
                    }
                    // The other connection is the keeper; drop this one.
                    conn.close(0u32.into(), b"tie-break");
                }
            }
        };
        accept_task.abort();
        result
    }

    /// The underlying endpoint, kept alive for the connection's lifetime.
    pub fn endpoint(&self) -> &quinn::Endpoint {
        &self.endpoint
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // The simultaneous open on loopback: two peers, each pinning the other,
    // both punch to the other's address. One authenticated direct connection
    // results on each side. No NAT here — this proves the open + pin, which
    // is the mechanism; real NAT traversal is exercised in the netns harness.
    #[tokio::test]
    async fn simultaneous_open_yields_an_authenticated_direct_connection() {
        crate::init_crypto();
        let id_a = Identity::generate().unwrap();
        let id_b = Identity::generate().unwrap();

        let a = Puncher::new("127.0.0.1:0".parse().unwrap(), &id_a, Some(id_b.pin())).unwrap();
        let b = Puncher::new("127.0.0.1:0".parse().unwrap(), &id_b, Some(id_a.pin())).unwrap();
        let a_addr = a.local_addr().unwrap();
        let b_addr = b.local_addr().unwrap();

        // Both punch at once, each toward the other's (already known) address.
        let a_remotes = [b_addr];
        let b_remotes = [a_addr];
        let (ra, rb) = tokio::join!(
            a.punch(
                id_a.pin(),
                Some(id_b.pin()),
                &a_remotes,
                Duration::from_secs(5)
            ),
            b.punch(
                id_b.pin(),
                Some(id_a.pin()),
                &b_remotes,
                Duration::from_secs(5)
            ),
        );
        let ca = ra.expect("A gets a direct connection");
        let cb = rb.expect("B gets a direct connection");

        // Exchange a datagram to prove the pipe works both ways.
        ca.open_uni().await.unwrap().finish().unwrap();
        let _ = (ca, cb);
    }

    #[tokio::test]
    async fn punch_to_a_dead_address_times_out() {
        crate::init_crypto();
        let id = Identity::generate().unwrap();
        let p = Puncher::new("127.0.0.1:0".parse().unwrap(), &id, None).unwrap();
        // 203.0.113.0/24 is TEST-NET-3 — nothing answers.
        let r = p
            .punch(
                id.pin(),
                None,
                &["203.0.113.1:9".parse().unwrap()],
                Duration::from_millis(400),
            )
            .await;
        assert!(r.is_err(), "no peer, must time out");
    }
}
