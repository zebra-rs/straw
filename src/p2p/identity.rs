//! A peer's inner-connection TLS identity and its SPKI pin (design §8).
//!
//! The identity is an Ed25519 keypair. Its pin — the SHA-256 of the
//! X.509 SubjectPublicKeyInfo — is the stable, WireGuard-pubkey-equivalent
//! name for the peer: a token carries the issuer's pin (`ppin`), and each
//! side verifies the other's SPKI against the expected pin on the inner
//! mTLS handshake (design §2.1, §3.2). No CA, no hostname.
//!
//! Ephemeral by default (a fresh keypair per process); [`Identity::to_pem`]
//! / [`Identity::from_pem`] persist one so `ppin` is stable across restarts
//! (a future `strawcat genkey`).

use rcgen::{KeyPair, PublicKeyData};
use zeroize::{Zeroize, Zeroizing};

use crate::error::ProxyError;

/// SHA-256 of a SubjectPublicKeyInfo: the pin that names a peer.
pub type SpkiPin = [u8; 32];

/// A peer's inner-TLS keypair.
///
/// The private key is wiped on drop — see the `Drop` impl for exactly how far
/// that reaches, which is less far than it sounds.
pub struct Identity {
    key_pair: KeyPair,
}

impl Drop for Identity {
    /// Wipe the key material this type owns.
    ///
    /// **Partial, deliberately documented as such.** `rcgen`'s `Zeroize` clears
    /// its `serialized_der` — the PKCS#8 copy straw holds — and nothing else.
    /// The live signing key inside `KeyPairKind` belongs to *ring*, which does
    /// not expose a way to wipe it, so that copy outlives this. Clearing the
    /// DER is still worth doing: it is the copy that gets cloned, re-encoded to
    /// PEM, and handed across an FFI boundary, and on iOS it is the one that
    /// would otherwise sit in a reallocated heap block after the tunnel stops.
    fn drop(&mut self) {
        self.key_pair.zeroize();
    }
}

impl Identity {
    /// A fresh ephemeral Ed25519 identity.
    pub fn generate() -> Result<Self, ProxyError> {
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ED25519)
            .map_err(|e| ProxyError::Tls(format!("identity keygen failed: {e}")))?;
        Ok(Self { key_pair })
    }

    /// Load a persisted identity from a PKCS#8 PEM private key.
    pub fn from_pem(pem: &str) -> Result<Self, ProxyError> {
        let key_pair = KeyPair::from_pem(pem)
            .map_err(|e| ProxyError::Tls(format!("invalid identity: {e}")))?;
        Ok(Self { key_pair })
    }

    /// Serialize the private key as PKCS#8 PEM, for persistence.
    /// The private key as PKCS#8 PEM, wiped when the caller drops it.
    ///
    /// `Zeroizing` rather than `String` so persisting an identity cannot leave
    /// the key in a heap block by accident — the caller has to go out of its
    /// way to keep a plain copy.
    pub fn to_pem(&self) -> Zeroizing<String> {
        Zeroizing::new(self.key_pair.serialize_pem())
    }

    /// The X.509 SubjectPublicKeyInfo DER — the public half, as pinned and
    /// as presented in an RFC 7250 raw-public-key handshake.
    pub fn spki_der(&self) -> Vec<u8> {
        self.key_pair.subject_public_key_info()
    }

    /// This identity's pin: SHA-256 of [`spki_der`](Self::spki_der).
    pub fn pin(&self) -> SpkiPin {
        pin_of_spki(&self.spki_der())
    }

    /// The underlying keypair, for building the inner-connection TLS config.
    pub fn key_pair(&self) -> &KeyPair {
        &self.key_pair
    }
}

/// The pin of an SPKI DER blob: SHA-256, as a fixed 32-byte array. The same
/// computation applied to a peer's presented SPKI, to compare against an
/// expected pin.
pub fn pin_of_spki(spki_der: &[u8]) -> SpkiPin {
    let digest = ring::digest::digest(&ring::digest::SHA256, spki_der);
    let mut pin = [0u8; 32];
    pin.copy_from_slice(digest.as_ref());
    pin
}

/// Compare two pins in constant time — the peer's presented pin against the
/// expected one from the token (design §2.1). Length is fixed, so this only
/// guards the byte comparison.
pub fn pins_match(a: &SpkiPin, b: &SpkiPin) -> bool {
    // Constant-time compare over the fixed-length pins.
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_is_stable_across_pem_round_trip() {
        let id = Identity::generate().unwrap();
        let pin = id.pin();
        let pem = id.to_pem();

        let restored = Identity::from_pem(&pem).unwrap();
        assert_eq!(restored.pin(), pin, "pin survives persistence");
        assert_eq!(restored.spki_der(), id.spki_der());
        // And the pin is exactly SHA-256 of the SPKI.
        assert_eq!(pin, pin_of_spki(&id.spki_der()));
    }

    #[test]
    fn distinct_identities_have_distinct_pins() {
        let a = Identity::generate().unwrap().pin();
        let b = Identity::generate().unwrap().pin();
        assert_ne!(a, b);
    }

    #[test]
    fn pins_match_is_exact() {
        let id = Identity::generate().unwrap();
        let mut other = id.pin();
        assert!(pins_match(&id.pin(), &id.pin()));
        other[0] ^= 1;
        assert!(!pins_match(&id.pin(), &other));
    }

    #[test]
    fn rejects_malformed_pem() {
        assert!(Identity::from_pem("not a key").is_err());
    }
}
