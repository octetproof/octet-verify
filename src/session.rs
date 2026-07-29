//! Cross-check the per-login **session-binding** nonce against the signed proof.
//!
//! A `sessionBinding` stage — built with the same chained, hardware-signed
//! machinery as `uploadChallenge` — commits a per-login nonce in-proof via
//! `data_hash = SHA256(preimage)`, where
//!
//! ```text
//! preimage = "octet-session-binding-v1" ‖ uint32_be(len(nonce)) ‖ nonce
//! ```
//!
//! The nonce itself never rides the wire — only its hash, inside the stage. The
//! relying party (which issued the nonce at login) supplies the expected nonce
//! out of band; this check recomputes the preimage over that nonce and confirms
//! it equals the stage the device signed. That binds the proof to one login
//! session, so a proof captured under one login cannot be replayed under another.
//!
//! Because `sessionBinding` is a chained, hardware-signed stage placed before
//! `proofAssembly`, it is already covered by `stage-chain` (linkage),
//! `stage-signatures`, and `chain-assembly` — tampering with it breaks the proof
//! regardless of this check. This check adds the binding to a *specific* nonce.
//!
//! Back-compat: when no expected nonce is supplied the binding cannot be judged,
//! so the check is NOT-CHECKED — the default. An ordinary verification of a proof
//! that predates session binding is therefore unaffected.

use crate::crypto::sha256;
use crate::navigate::LocationProof;
use crate::verify::{Check, Status};

/// Stage that commits the per-login nonce in-proof.
const SESSION_BINDING_STAGE: &str = "sessionBinding";
/// Domain-separation tag for the session-binding preimage. Raw UTF-8, no NUL,
/// not itself length-prefixed — same shape as the `semanticFields` domain tag.
const SESSION_DOMAIN: &[u8] = b"octet-session-binding-v1";

/// The exact bytes the `sessionBinding` stage hashes:
/// `SESSION_DOMAIN ‖ uint32_be(len(nonce)) ‖ nonce`. The u32 big-endian length
/// prefix matches the `semanticFields` framing (not `uploadChallenge`, which
/// hashes the raw nonce) so the two domain-tagged preimages stay consistent.
fn session_preimage(nonce: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(SESSION_DOMAIN.len() + 4 + nonce.len());
    m.extend_from_slice(SESSION_DOMAIN);
    m.extend_from_slice(&(nonce.len() as u32).to_be_bytes());
    m.extend_from_slice(nonce);
    m
}

/// Confirm the proof is bound to `expected_nonce` — the per-login session nonce
/// the relying party issued and supplies here. Returns the `session-binding`
/// check:
///
/// - `Some(nonce)` + `sessionBinding` present + hash matches → `Pass`
/// - `Some` + present + mismatch → `Fail` (proof bound to a different login)
/// - `Some` + stage absent → `Fail` (binding required, proof carries none)
/// - `None` → `NotChecked` (no expected nonce; binding not judged — the default)
pub fn check_session_binding(
    proof: &LocationProof,
    expected_nonce: Option<&[u8]>,
    require: bool,
) -> Check {
    const NAME: &str = "session-binding";
    let nonce = match expected_nonce {
        // No nonce supplied. Back-compat NOT-CHECKED, unless the caller requires
        // the binding (fail-closed) — a consumer verifying a stored/relayed proof
        // that must be session-bound gets a FAIL, not a silent pass.
        None if require => {
            return Check {
                name: NAME,
                status: Status::Fail,
                detail: "session binding required but no session nonce was supplied to check it against".into(),
            }
        }
        None => {
            return Check {
                name: NAME,
                status: Status::NotChecked,
                detail: "no expected session nonce supplied; per-login binding not checked".into(),
            }
        }
        Some(n) => n,
    };

    match proof.stage_attestations.iter().find(|s| s.stage == SESSION_BINDING_STAGE) {
        Some(st) if sha256(&session_preimage(nonce)).as_slice() == st.data_hash.as_slice() => Check {
            name: NAME,
            status: Status::Pass,
            detail: "proof bound to the expected login session (sessionBinding stage matches)".into(),
        },
        Some(_) => Check {
            name: NAME,
            status: Status::Fail,
            detail: "sessionBinding stage does not match the expected session nonce \
                     (proof bound to a different login)"
                .into(),
        },
        None => Check {
            name: NAME,
            status: Status::Fail,
            detail: "session binding required but the proof carries no sessionBinding stage".into(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::navigate::{LocationProof, StageAttestation};

    fn proof_with_session_stage(nonce: &[u8]) -> LocationProof {
        LocationProof {
            stage_attestations: vec![StageAttestation {
                stage: SESSION_BINDING_STAGE.to_string(),
                timestamp_ms: 1,
                data_hash: sha256(&session_preimage(nonce)).to_vec(),
                signature: vec![],
                previous_hash: None,
            }],
            ..Default::default()
        }
    }

    #[test]
    fn no_expected_nonce_is_not_checked() {
        // Default path: without a reference nonce the binding can't be judged.
        let p = proof_with_session_stage(b"login-nonce");
        assert_eq!(check_session_binding(&p, None, false).status, Status::NotChecked);
    }

    #[test]
    fn matching_nonce_passes() {
        let nonce = b"login-nonce-abc";
        let p = proof_with_session_stage(nonce);
        assert_eq!(check_session_binding(&p, Some(nonce), false).status, Status::Pass);
    }

    #[test]
    fn wrong_nonce_fails() {
        let p = proof_with_session_stage(b"login-nonce-abc");
        let c = check_session_binding(&p, Some(b"different-nonce"), false);
        assert_eq!(c.status, Status::Fail);
        assert!(c.detail.contains("different login"), "{}", c.detail);
    }

    #[test]
    fn absent_stage_when_nonce_required_fails() {
        // Caller asserted a session (supplied a nonce) but the proof carries no
        // sessionBinding stage → the requirement is unmet, so FAIL (not a pass).
        let p = LocationProof::default();
        let c = check_session_binding(&p, Some(b"login-nonce"), false);
        assert_eq!(c.status, Status::Fail);
        assert!(c.detail.contains("no sessionBinding stage"), "{}", c.detail);
    }

    /// #15 fail-closed: with `require` set, an unsupplied binding (no nonce) FAILs
    /// instead of NOT-CHECKED — so a consumer that intends freshness never gets a
    /// silent pass. A supplied+matching nonce still PASSes; a supplied nonce over
    /// a proof with no stage still FAILs (unchanged).
    #[test]
    fn require_makes_absent_binding_fail_closed() {
        let bound = proof_with_session_stage(b"login-nonce");

        // No nonce + required → FAIL (was NOT-CHECKED when not required).
        let c = check_session_binding(&bound, None, true);
        assert_eq!(c.status, Status::Fail);
        assert!(c.detail.contains("no session nonce was supplied"), "{}", c.detail);

        // No nonce + not required → NOT-CHECKED (back-compat default).
        assert_eq!(check_session_binding(&bound, None, false).status, Status::NotChecked);

        // Supplied + matching still PASSes regardless of `require`.
        assert_eq!(check_session_binding(&bound, Some(b"login-nonce"), true).status, Status::Pass);

        // Required + a nonce but no sessionBinding stage → FAIL.
        let no_stage = LocationProof::default();
        assert_eq!(check_session_binding(&no_stage, Some(b"login-nonce"), true).status, Status::Fail);
    }

    #[test]
    fn preimage_is_domain_then_u32_len_then_nonce() {
        // Pin the exact framing byte-for-byte so a drift on either side is caught.
        let nonce = b"abc";
        let mut want = Vec::new();
        want.extend_from_slice(b"octet-session-binding-v1");
        want.extend_from_slice(&3u32.to_be_bytes());
        want.extend_from_slice(nonce);
        assert_eq!(session_preimage(nonce), want);
    }
}
