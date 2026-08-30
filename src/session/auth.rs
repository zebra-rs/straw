//! Authentication for CONNECT-IP requests (design §11.3, Phase 4 Step 24).
//!
//! Modes: none (default), Bearer token, HTTP Basic, and mTLS. Credential
//! comparisons are constant-time. mTLS certificate *validation* happens in
//! the TLS handshake (see `tls::build_server_tls_config_with_client_auth`);
//! here it is reduced to "a verified client certificate is present".

use base64::Engine as _;
use clap::ValueEnum;
use http::HeaderMap;
use rustls::pki_types::CertificateDer;

use crate::error::ProxyError;

/// How clients must authenticate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    /// No authentication (development only).
    #[default]
    None,
    /// `Authorization: Bearer <token>` checked against a token list.
    Bearer,
    /// `Authorization: Basic <base64>` checked against user:pass pairs.
    Basic,
    /// A client certificate verified against --client-ca at the TLS layer.
    Mtls,
}

/// Who a session authenticated as.
#[derive(Debug, Clone, Default)]
pub struct AuthContext {
    /// The mechanism that admitted the session ("none", "bearer", ...).
    pub method: &'static str,
    /// Basic username, or the client certificate's SHA-256 fingerprint.
    pub principal: Option<String>,
}

/// Server-side authenticator, built once from the configuration.
#[derive(Debug, Default)]
pub struct Authenticator {
    mode: AuthMode,
    bearer_tokens: Vec<String>,
    /// (user, password) pairs.
    basic_credentials: Vec<(String, String)>,
}

impl Authenticator {
    pub fn new(
        mode: AuthMode,
        bearer_tokens: Vec<String>,
        basic_credentials: Vec<(String, String)>,
    ) -> Self {
        Self {
            mode,
            bearer_tokens,
            basic_credentials,
        }
    }

    /// Authenticate one request. `client_cert` is the TLS-verified peer
    /// certificate, when the connection presented one.
    pub fn authenticate(
        &self,
        headers: &HeaderMap,
        client_cert: Option<&CertificateDer<'_>>,
    ) -> Result<AuthContext, ProxyError> {
        match self.mode {
            AuthMode::None => Ok(AuthContext {
                method: "none",
                principal: None,
            }),
            AuthMode::Bearer => {
                let presented = authorization_value(headers, "Bearer")
                    .ok_or_else(|| ProxyError::AuthFailed("missing bearer token".into()))?;
                // Compare against every token so timing does not reveal
                // which (if any) prefix-matched.
                let mut ok = false;
                for token in &self.bearer_tokens {
                    ok |= constant_time_eq(token.as_bytes(), presented.as_bytes());
                }
                if ok {
                    Ok(AuthContext {
                        method: "bearer",
                        principal: None,
                    })
                } else {
                    Err(ProxyError::AuthFailed("invalid bearer token".into()))
                }
            }
            AuthMode::Basic => {
                let presented = authorization_value(headers, "Basic")
                    .ok_or_else(|| ProxyError::AuthFailed("missing basic credentials".into()))?;
                let decoded = base64::engine::general_purpose::STANDARD
                    .decode(presented)
                    .map_err(|_| ProxyError::AuthFailed("malformed basic credentials".into()))?;
                let decoded = String::from_utf8(decoded)
                    .map_err(|_| ProxyError::AuthFailed("malformed basic credentials".into()))?;
                let (user, pass) = decoded
                    .split_once(':')
                    .ok_or_else(|| ProxyError::AuthFailed("malformed basic credentials".into()))?;

                let mut ok = false;
                let mut matched_user = None;
                for (u, p) in &self.basic_credentials {
                    let hit = constant_time_eq(u.as_bytes(), user.as_bytes())
                        & constant_time_eq(p.as_bytes(), pass.as_bytes());
                    if hit {
                        matched_user = Some(u.clone());
                    }
                    ok |= hit;
                }
                if ok {
                    Ok(AuthContext {
                        method: "basic",
                        principal: matched_user,
                    })
                } else {
                    Err(ProxyError::AuthFailed("invalid basic credentials".into()))
                }
            }
            AuthMode::Mtls => {
                let cert = client_cert
                    .ok_or_else(|| ProxyError::AuthFailed("client certificate required".into()))?;
                Ok(AuthContext {
                    method: "mtls",
                    principal: Some(cert_fingerprint(cert)),
                })
            }
        }
    }
}

/// Extract the value of `Authorization: <scheme> <value>`.
fn authorization_value<'a>(headers: &'a HeaderMap, scheme: &str) -> Option<&'a str> {
    let value = headers.get(http::header::AUTHORIZATION)?.to_str().ok()?;
    let (s, rest) = value.split_once(' ')?;
    if s.eq_ignore_ascii_case(scheme) {
        Some(rest.trim())
    } else {
        None
    }
}

/// SHA-256 fingerprint of a DER certificate, colon-less lowercase hex.
pub fn cert_fingerprint(cert: &CertificateDer<'_>) -> String {
    let digest = ring::digest::digest(&ring::digest::SHA256, cert.as_ref());
    digest.as_ref().iter().map(|b| format!("{b:02x}")).collect()
}

/// Constant-time byte comparison. Length mismatch returns early: lengths
/// are not secret here, contents are.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(value: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(http::header::AUTHORIZATION, value.parse().unwrap());
        h
    }

    #[test]
    fn none_mode_admits_everyone() {
        let auth = Authenticator::default();
        assert!(auth.authenticate(&HeaderMap::new(), None).is_ok());
    }

    #[test]
    fn bearer_token_checked() {
        let auth = Authenticator::new(
            AuthMode::Bearer,
            vec!["sekrit".into(), "other".into()],
            vec![],
        );
        assert_eq!(
            auth.authenticate(&headers("Bearer sekrit"), None)
                .unwrap()
                .method,
            "bearer"
        );
        assert!(auth.authenticate(&headers("Bearer other"), None).is_ok());
        assert!(auth.authenticate(&headers("Bearer wrong"), None).is_err());
        assert!(auth.authenticate(&headers("bearer sekrit"), None).is_ok());
        assert!(auth.authenticate(&HeaderMap::new(), None).is_err());
        assert!(
            auth.authenticate(&headers("Basic sekrit"), None).is_err(),
            "wrong scheme"
        );
    }

    #[test]
    fn basic_credentials_checked() {
        let auth = Authenticator::new(
            AuthMode::Basic,
            vec![],
            vec![("alice".into(), "wonder".into())],
        );
        let encoded = base64::engine::general_purpose::STANDARD.encode("alice:wonder");
        let ctx = auth
            .authenticate(&headers(&format!("Basic {encoded}")), None)
            .unwrap();
        assert_eq!(ctx.method, "basic");
        assert_eq!(ctx.principal.as_deref(), Some("alice"));

        let bad = base64::engine::general_purpose::STANDARD.encode("alice:nope");
        assert!(
            auth.authenticate(&headers(&format!("Basic {bad}")), None)
                .is_err()
        );
        assert!(
            auth.authenticate(&headers("Basic not-base64!!!"), None)
                .is_err()
        );
    }

    #[test]
    fn mtls_requires_certificate() {
        let auth = Authenticator::new(AuthMode::Mtls, vec![], vec![]);
        assert!(auth.authenticate(&HeaderMap::new(), None).is_err());

        let cert = CertificateDer::from(vec![1u8, 2, 3]);
        let ctx = auth.authenticate(&HeaderMap::new(), Some(&cert)).unwrap();
        assert_eq!(ctx.method, "mtls");
        assert_eq!(ctx.principal.as_deref().map(|p| p.len()), Some(64));
    }

    #[test]
    fn constant_time_eq_basics() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(constant_time_eq(b"", b""));
    }
}
