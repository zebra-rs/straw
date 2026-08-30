//! Shared TLS utilities: certificate loading, self-signed generation, and
//! rustls config builders for the QUIC/H3 endpoints.

use std::path::Path;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};

use crate::error::ProxyError;

/// ALPN protocol identifier for HTTP/3.
pub const ALPN_H3: &[u8] = b"h3";

fn ring_provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// Generate a self-signed certificate + private key for the given SANs.
pub fn generate_self_signed_cert(
    subject_alt_names: &[&str],
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), ProxyError> {
    let names: Vec<String> = subject_alt_names.iter().map(|s| s.to_string()).collect();
    let certified = rcgen::generate_simple_self_signed(names)
        .map_err(|e| ProxyError::Tls(format!("self-signed generation failed: {e}")))?;

    let cert = certified.cert.der().clone();
    let key = PrivateKeyDer::try_from(certified.signing_key.serialize_der())
        .map_err(|e| ProxyError::Tls(format!("invalid generated key: {e}")))?;
    Ok((cert, key))
}

/// Load a PEM certificate chain and private key from disk.
pub fn load_cert_chain(
    cert_path: &Path,
    key_path: &Path,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>), ProxyError> {
    let cert_pem = std::fs::read(cert_path)?;
    let key_pem = std::fs::read(key_path)?;

    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile_certs(&cert_pem).map_err(|e| ProxyError::Tls(e.to_string()))?;
    if certs.is_empty() {
        return Err(ProxyError::Tls(format!(
            "no certificates found in {}",
            cert_path.display()
        )));
    }
    let key = rustls_pemfile_key(&key_pem).map_err(|e| ProxyError::Tls(e.to_string()))?;
    Ok((certs, key))
}

// Minimal PEM parsing via rustls-pki-types (avoids a rustls-pemfile dep).
fn rustls_pemfile_certs(
    pem: &[u8],
) -> Result<Vec<CertificateDer<'static>>, rustls::pki_types::pem::Error> {
    use rustls::pki_types::pem::PemObject;
    CertificateDer::pem_slice_iter(pem).collect()
}

fn rustls_pemfile_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>, rustls::pki_types::pem::Error> {
    use rustls::pki_types::pem::PemObject;
    PrivateKeyDer::from_pem_slice(pem)
}

/// Build a rustls server config with ALPN `h3` (TLS 1.3 only, as QUIC requires).
pub fn build_server_tls_config(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<rustls::ServerConfig, ProxyError> {
    let mut config = rustls::ServerConfig::builder_with_provider(ring_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| ProxyError::Tls(e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| ProxyError::Tls(e.to_string()))?;
    config.alpn_protocols = vec![ALPN_H3.to_vec()];
    Ok(config)
}

/// Build a client config that trusts a specific CA/self-signed certificate.
pub fn build_client_tls_config_with_ca(
    ca_cert: CertificateDer<'static>,
) -> Result<ClientConfig, ProxyError> {
    let mut roots = RootCertStore::empty();
    roots
        .add(ca_cert)
        .map_err(|e| ProxyError::Tls(e.to_string()))?;
    let mut config = ClientConfig::builder_with_provider(ring_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| ProxyError::Tls(e.to_string()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN_H3.to_vec()];
    Ok(config)
}

/// Build a client config that skips certificate verification. Testing only.
pub fn build_client_tls_config_insecure() -> Result<ClientConfig, ProxyError> {
    let mut config = ClientConfig::builder_with_provider(ring_provider())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| ProxyError::Tls(e.to_string()))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(SkipServerVerification::new()))
        .with_no_client_auth();
    config.alpn_protocols = vec![ALPN_H3.to_vec()];
    Ok(config)
}

/// A `ServerCertVerifier` that accepts any certificate. Testing only.
#[derive(Debug)]
struct SkipServerVerification(Arc<CryptoProvider>);

impl SkipServerVerification {
    fn new() -> Self {
        Self(ring_provider())
    }
}

impl ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}
