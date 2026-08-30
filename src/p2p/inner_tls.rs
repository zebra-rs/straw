//! RFC 7250 raw-public-key mTLS for the inner peer-to-peer connection
//! (design §2.1, §3.2, §4).
//!
//! Both peers present their [`Identity`]'s public key as a bare
//! SubjectPublicKeyInfo — no X.509 certificate, no CA, no hostname — and
//! each verifies the other's SPKI against an expected pin (SHA-256 of the
//! SPKI). The pin is the WireGuard-pubkey-equivalent name for the peer: a
//! dialer knows the issuer's pin from the token (`ppin`); the issuer either
//! pins the holder out of band or accepts it on first use (TOFU) and records
//! it. Mutual: the connection authenticates both directions.
//!
//! Built on rustls 0.23's raw-public-key support
//! (`AlwaysResolves{Server,Client}RawPublicKeys` + custom verifiers with
//! `requires_raw_public_keys() == true`).

use std::sync::{Arc, Mutex};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls13_signature_with_raw_key};
use rustls::pki_types::{
    CertificateDer, PrivateKeyDer, ServerName, SubjectPublicKeyInfoDer, UnixTime,
};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::sign::CertifiedKey;
use rustls::{
    ClientConfig, DigitallySignedStruct, DistinguishedName, ServerConfig, SignatureScheme,
};

use crate::error::ProxyError;
use crate::p2p::identity::{Identity, SpkiPin, pin_of_spki, pins_match};

/// ALPN for the raw-QUIC inner protocol (design §2.1): stdio/port-forward
/// pipes over native QUIC streams. Defined in the codepoint registry
/// (`crate::codepoints`) and re-exported here for the v2 swap (§9).
pub use crate::codepoints::ALPN_STRAWCAT;

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A `CertifiedKey` that presents `identity` as a raw public key.
fn raw_public_key(identity: &Identity) -> Result<Arc<CertifiedKey>, ProxyError> {
    let spki = CertificateDer::from(identity.spki_der());
    let key_der = PrivateKeyDer::try_from(identity.key_pair().serialize_der())
        .map_err(|e| ProxyError::Tls(format!("identity key is not valid DER: {e}")))?;
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der)
        .map_err(|e| ProxyError::Tls(format!("cannot sign with identity key: {e}")))?;
    Ok(Arc::new(CertifiedKey {
        cert: vec![spki],
        key: signing_key,
        ocsp: None,
    }))
}

/// Verifies a peer's presented raw public key against a pin: a fixed
/// `expected` pin (from a token, or a pre-shared holder pin), or, when
/// `None`, trust-on-first-use — accept and record the pin so the caller can
/// read it afterward (design §3.2 pin-on-first-use).
#[derive(Debug)]
pub struct PinVerifier {
    provider: Arc<CryptoProvider>,
    expected: Option<SpkiPin>,
    learned: Mutex<Option<SpkiPin>>,
}

impl PinVerifier {
    fn new(expected: Option<SpkiPin>) -> Arc<Self> {
        Arc::new(Self {
            provider: provider(),
            expected,
            learned: Mutex::new(None),
        })
    }

    /// The pin actually presented by the peer (recorded on a successful
    /// handshake) — the value a TOFU caller pins for next time.
    pub fn learned_pin(&self) -> Option<SpkiPin> {
        *self.learned.lock().unwrap()
    }

    /// The pin check shared by both directions: `end_entity` is the peer's
    /// SPKI (RPK mode). Enforce the expected pin, or learn it on first use.
    fn check_pin(&self, end_entity: &CertificateDer<'_>) -> Result<(), rustls::Error> {
        let pin = pin_of_spki(end_entity.as_ref());
        if let Some(expected) = &self.expected
            && !pins_match(&pin, expected)
        {
            return Err(rustls::Error::General(
                "peer public-key pin does not match the expected pin".into(),
            ));
        }
        *self.learned.lock().unwrap() = Some(pin);
        Ok(())
    }

    fn schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.check_pin(end_entity)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // Raw public keys are used only with TLS 1.3 (RFC 7250), and QUIC
        // never negotiates TLS 1.2, so this path is unreachable.
        let _ = (message, cert, dss);
        Err(rustls::Error::General(
            "raw public keys require TLS 1.3".into(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature_with_raw_key(
            message,
            &SubjectPublicKeyInfoDer::from(cert.as_ref()),
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

impl ClientCertVerifier for PinVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.check_pin(end_entity)?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // Raw public keys are used only with TLS 1.3 (RFC 7250), and QUIC
        // never negotiates TLS 1.2, so this path is unreachable.
        let _ = (message, cert, dss);
        Err(rustls::Error::General(
            "raw public keys require TLS 1.3".into(),
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature_with_raw_key(
            message,
            &SubjectPublicKeyInfoDer::from(cert.as_ref()),
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes()
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

/// Inner-QUIC client TLS: present `identity`, verify the server's SPKI
/// against `expected_server_pin` (the token's `ppin`; `None` for TOFU). The
/// returned verifier's [`learned_pin`](PinVerifier::learned_pin) holds what
/// the server actually presented.
pub fn client_config(
    identity: &Identity,
    expected_server_pin: Option<SpkiPin>,
) -> Result<(ClientConfig, Arc<PinVerifier>), ProxyError> {
    let verifier = PinVerifier::new(expected_server_pin);
    let mut config = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| ProxyError::Tls(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(verifier.clone())
        .with_client_cert_resolver(Arc::new(
            rustls::client::AlwaysResolvesClientRawPublicKeys::new(raw_public_key(identity)?),
        ));
    config.alpn_protocols = vec![ALPN_STRAWCAT.to_vec()];
    Ok((config, verifier))
}

/// Inner-QUIC server TLS: present `identity`, verify the client's SPKI
/// against `expected_client_pin` (a pre-shared holder pin; `None` for TOFU).
pub fn server_config(
    identity: &Identity,
    expected_client_pin: Option<SpkiPin>,
) -> Result<(ServerConfig, Arc<PinVerifier>), ProxyError> {
    let verifier = PinVerifier::new(expected_client_pin);
    let mut config = ServerConfig::builder_with_provider(provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| ProxyError::Tls(e.to_string()))?
        .with_client_cert_verifier(verifier.clone())
        .with_cert_resolver(Arc::new(
            rustls::server::AlwaysResolvesServerRawPublicKeys::new(raw_public_key(identity)?),
        ));
    config.alpn_protocols = vec![ALPN_STRAWCAT.to_vec()];
    Ok((config, verifier))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_configs_that_present_raw_public_keys() {
        let id = Identity::generate().unwrap();
        // Both directions build without error and carry the strawcat ALPN.
        let (cc, _) = client_config(&id, Some([0u8; 32])).unwrap();
        assert_eq!(cc.alpn_protocols, vec![ALPN_STRAWCAT.to_vec()]);
        let (sc, _) = server_config(&id, None).unwrap();
        assert_eq!(sc.alpn_protocols, vec![ALPN_STRAWCAT.to_vec()]);
    }

    #[test]
    fn pin_check_enforces_expected_and_learns_on_tofu() {
        let peer = Identity::generate().unwrap();
        let peer_spki = CertificateDer::from(peer.spki_der());

        // Expected-pin mode: the matching pin passes, a wrong one fails.
        let v = PinVerifier::new(Some(peer.pin()));
        assert!(v.check_pin(&peer_spki).is_ok());
        assert_eq!(v.learned_pin(), Some(peer.pin()));

        let wrong = PinVerifier::new(Some([0xff; 32]));
        assert!(wrong.check_pin(&peer_spki).is_err());

        // TOFU: any pin accepted and recorded.
        let tofu = PinVerifier::new(None);
        assert!(tofu.check_pin(&peer_spki).is_ok());
        assert_eq!(tofu.learned_pin(), Some(peer.pin()));
    }
}
