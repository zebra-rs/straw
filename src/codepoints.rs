//! Provisional wire codepoints and the v2 standards-swap plan (design §9).
//!
//! Every straw-provisional codepoint — the CONNECT-UDP-listen compression
//! capsules, the vendor address capsules, the inner ALPN, the capability token
//! marker — is gathered here so the v2 migration is a single-file edit and the
//! design doc's "everything provisional behind one constant table" is literally
//! true. Each item's doc gives its provisional value, its v2 standards target,
//! and the gate blocking the swap. The scattered modules re-export from here, so
//! existing `use` paths keep working.
//!
//! ## v2 swap checklist (design §9)
//!
//! | v1 (here) | v2 (standard) | gate |
//! |---|---|---|
//! | compression capsules `0x11`–`0x13` | draft-ietf-masque-connect-udp-listen final codepoints | RFC publication |
//! | `OBSERVED_ADDRESS` capsule `0x14` | draft-ietf-quic-address-discovery OBSERVED_ADDRESS **frame** | quinn frame-extension API |
//! | ~~CBOR `Candidate`/`Punch`/`Retire` on inner stream 0~~ | **done** — noq's NAT-traversal frames + `nat_traversal` transport param | — |
//! | ~~race a second connection + app switchover~~ | **done** — path validation + promotion of the one inner connection | — |
//! | token `v2` / `sc2_` | TBD if a standard token format emerges | — |
//!
//! Tokens carry `v`, so a v1 and a v2 peer fail cleanly rather than confusingly.

// --- CONNECT-UDP listen (bind mode) compression-context capsules -----------
//
// draft-ietf-masque-connect-udp-listen compression contexts. v1 uses the
// provisional values below; v2 adopts the draft's final (RFC-assigned)
// codepoints once it publishes.

/// Register a compression context (provisional; §9).
pub const CAPSULE_COMPRESSION_ASSIGN: u64 = 0x11;
/// Acknowledge a registered context (provisional; §9).
pub const CAPSULE_COMPRESSION_ACK: u64 = 0x12;
/// Retire a context (provisional; §9).
pub const CAPSULE_COMPRESSION_CLOSE: u64 = 0x13;

// --- vendor address capsules ------------------------------------------------

/// The relay's view of the peer's outer source — its server-reflexive candidate
/// (design §5.1). v1: vendor capsule `0x14`. v2: draft-ietf-quic-address-
/// discovery `OBSERVED_ADDRESS` **frame**, once quinn exposes frame extensions.
pub const CAPSULE_OBSERVED_ADDRESS: u64 = 0x14;

// --- inner protocol ---------------------------------------------------------

/// ALPN for the raw-QUIC inner peer protocol (design §2.1). Straw-specific;
/// unchanged in v2.
pub const ALPN_STRAWCAT: &[u8] = b"strawcat/1";

// --- capability token -------------------------------------------------------

/// The only token version this build speaks. v1 = 2. The `v` field lets a v1
/// and a v2 peer reject each other cleanly (design §3.2, §9).
pub const TOKEN_VERSION: u8 = 2;

/// Human-facing token prefix; base64url CBOR follows it.
pub const TOKEN_PREFIX: &str = "sc2_";

// --- NAT-traversal control (v2 target, documented) --------------------------

/// The base of draft-seemann-quic-nat-traversal's frame range
/// (`ADD_ADDRESS`=`0x3d7e90`, `PUNCH_ME_NOW`, `REMOVE_ADDRESS`, …).
///
/// straw no longer encodes this itself: the inner connection runs on noq,
/// which emits the real frames, and the v1 CBOR stand-in has been deleted. The
/// constant stays as the documented codepoint the peers rely on, so a change
/// in the draft is findable from this registry rather than only inside the
/// dependency.
pub const NAT_TRAVERSAL_FRAME_BASE: u64 = 0x3d7e90;

#[cfg(test)]
mod tests {
    use super::*;

    /// The provisional capsule types are distinct and in the expected block.
    #[test]
    fn capsule_codepoints_are_distinct() {
        let all = [
            CAPSULE_COMPRESSION_ASSIGN,
            CAPSULE_COMPRESSION_ACK,
            CAPSULE_COMPRESSION_CLOSE,
            CAPSULE_OBSERVED_ADDRESS,
        ];
        let mut seen = std::collections::HashSet::new();
        for c in all {
            assert!((0x11..=0x15).contains(&c));
            assert!(seen.insert(c), "duplicate capsule codepoint {c:#x}");
        }
    }
}
