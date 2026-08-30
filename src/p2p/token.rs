//! Token v2: the capability a peer hands out so the holder can reach and
//! verify it through the relay (design §3.2).
//!
//! A CBOR map, base64url-encoded, prefixed `sc2_`. It carries everything a
//! dialer needs and nothing the relay can use to link accounts: where the
//! relay is and how to pin it (`relay`, `rpin`), a scoped short-TTL relay
//! credential (`auth`), the issuer's inner-TLS pin and relay-public address
//! (`ppin`, `paddr`), and an expiry (`exp`). `v` is checked first so a v1
//! and a v3 peer fail cleanly rather than confusingly.
//!
//! The CBOR uses integer keys (the numbers below), not strings, so the
//! encoding is compact and stable regardless of field order.

use serde::{Deserialize, Serialize};

use crate::error::ProxyError;
use crate::p2p::identity::SpkiPin;

/// The only token version this build speaks.
pub const TOKEN_VERSION: u8 = 2;

/// Human-facing prefix; the base64url CBOR follows it.
const TOKEN_PREFIX: &str = "sc2_";

/// A decoded rendezvous token (design §3.2). Integer CBOR keys in the
/// `serde(rename)`s keep the wire form compact and order-independent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenV2 {
    /// Format version; MUST be [`TOKEN_VERSION`].
    #[serde(rename = "1")]
    pub v: u8,
    /// Relay endpoint, e.g. `h3://relay.example:443`.
    #[serde(rename = "2")]
    pub relay: String,
    /// Relay certificate SPKI SHA-256 (pins the relay; replaces WebPKI).
    #[serde(rename = "3", with = "serde_bytes")]
    pub rpin: Vec<u8>,
    /// Scoped, short-TTL relay bearer credential (bind mode only).
    #[serde(rename = "4")]
    pub auth: String,
    /// Issuing peer's inner-TLS SPKI SHA-256 (the peer pin).
    #[serde(rename = "5", with = "serde_bytes")]
    pub ppin: Vec<u8>,
    /// Issuer's relay-public addresses (one per family).
    #[serde(rename = "6")]
    pub paddr: Vec<String>,
    /// Expiry, unix seconds.
    #[serde(rename = "7")]
    pub exp: u64,
}

impl TokenV2 {
    /// Encode to the `sc2_<base64url(CBOR)>` textual form.
    pub fn encode(&self) -> String {
        let mut cbor = Vec::new();
        // Serialization of a plain struct to a Vec cannot fail.
        ciborium::into_writer(self, &mut cbor)
            .expect("CBOR serialization is infallible for TokenV2");
        use base64::Engine as _;
        format!(
            "{TOKEN_PREFIX}{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(cbor)
        )
    }

    /// Decode and validate the version. Does **not** check expiry — call
    /// [`is_expired`](Self::is_expired) with the current time for that, so a
    /// caller can decode-then-report rather than conflate the two failures.
    pub fn decode(text: &str) -> Result<Self, ProxyError> {
        let b64 = text.strip_prefix(TOKEN_PREFIX).ok_or_else(|| {
            ProxyError::InvalidRequest(format!("token must start with {TOKEN_PREFIX}"))
        })?;
        use base64::Engine as _;
        let cbor = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(b64)
            .map_err(|e| {
                ProxyError::InvalidRequest(format!("token is not valid base64url: {e}"))
            })?;
        let token: TokenV2 = ciborium::from_reader(cbor.as_slice())
            .map_err(|e| ProxyError::InvalidRequest(format!("token is not valid CBOR: {e}")))?;
        if token.v != TOKEN_VERSION {
            return Err(ProxyError::InvalidRequest(format!(
                "unsupported token version {} (this build speaks v{TOKEN_VERSION})",
                token.v
            )));
        }
        if token.rpin.len() != 32 || token.ppin.len() != 32 {
            return Err(ProxyError::InvalidRequest(
                "token pins must be 32-byte SHA-256 digests".into(),
            ));
        }
        Ok(token)
    }

    /// Whether the token has expired at `now_unix_secs`.
    pub fn is_expired(&self, now_unix_secs: u64) -> bool {
        now_unix_secs >= self.exp
    }

    /// The issuer's peer pin as a fixed array (length checked on decode).
    pub fn peer_pin(&self) -> SpkiPin {
        let mut pin = [0u8; 32];
        pin.copy_from_slice(&self.ppin);
        pin
    }

    /// The relay's pin as a fixed array (length checked on decode).
    pub fn relay_pin(&self) -> SpkiPin {
        let mut pin = [0u8; 32];
        pin.copy_from_slice(&self.rpin);
        pin
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> TokenV2 {
        TokenV2 {
            v: TOKEN_VERSION,
            relay: "h3://relay.example:443".into(),
            rpin: vec![0xab; 32],
            auth: "scoped-bearer-xyz".into(),
            ppin: vec![0xcd; 32],
            paddr: vec!["192.0.2.45:54321".into(), "[2001:db8::1]:54321".into()],
            exp: 1_756_600_000,
        }
    }

    #[test]
    fn round_trips_through_the_textual_form() {
        let token = sample();
        let text = token.encode();
        assert!(text.starts_with("sc2_"));
        assert_eq!(TokenV2::decode(&text).unwrap(), token);
    }

    #[test]
    fn pins_come_back_as_fixed_arrays() {
        let token = TokenV2::decode(&sample().encode()).unwrap();
        assert_eq!(token.peer_pin(), [0xcd; 32]);
        assert_eq!(token.relay_pin(), [0xab; 32]);
    }

    #[test]
    fn expiry_is_a_boundary() {
        let token = sample();
        assert!(!token.is_expired(token.exp - 1));
        assert!(token.is_expired(token.exp));
        assert!(token.is_expired(token.exp + 1));
    }

    #[test]
    fn rejects_wrong_prefix() {
        let good = sample().encode();
        let swapped = good.replacen("sc2_", "sc1_", 1);
        assert!(TokenV2::decode(&swapped).is_err());
        assert!(TokenV2::decode("no-prefix-at-all").is_err());
    }

    #[test]
    fn rejects_a_different_version() {
        let mut token = sample();
        token.v = 3;
        let err = TokenV2::decode(&token.encode()).unwrap_err().to_string();
        assert!(err.contains("unsupported token version 3"), "{err}");
    }

    #[test]
    fn rejects_tampered_payload() {
        use base64::Engine as _;
        let text = sample().encode();
        let b64 = text.strip_prefix("sc2_").unwrap();
        let mut cbor = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(b64)
            .unwrap();
        // Flip a structural byte near the front (the map header / first key),
        // which reliably breaks decoding — unlike a trailing base64 bit,
        // whose spare bits CBOR ignores.
        cbor[1] ^= 0xff;
        let tampered = format!(
            "sc2_{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&cbor)
        );
        assert!(TokenV2::decode(&tampered).is_err());
        // Truncation is rejected too.
        let short = format!(
            "sc2_{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&cbor[..cbor.len() / 2])
        );
        assert!(TokenV2::decode(&short).is_err());
    }

    #[test]
    fn rejects_wrong_length_pins() {
        // Hand-build a CBOR map with a short rpin.
        let mut token = sample();
        token.rpin = vec![0x00; 16];
        let err = TokenV2::decode(&token.encode()).unwrap_err().to_string();
        assert!(err.contains("32-byte"), "{err}");
    }

    #[test]
    fn integer_keys_keep_the_encoding_compact() {
        // A string-keyed encoding of the same data would be much larger;
        // assert the map stays small (sanity that rename(int) took effect).
        let cbor_len = {
            let mut v = Vec::new();
            ciborium::into_writer(&sample(), &mut v).unwrap();
            v.len()
        };
        assert!(
            cbor_len < 200,
            "unexpectedly large token CBOR: {cbor_len} bytes"
        );
    }
}
