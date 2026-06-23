//! VER-3: cross-check the authenticated envelope **replay-control** fields
//! against the signed proof.
//!
//! In the server-enforced replay design (see `ENVELOPE-REPLAY-FIELDS-SPEC`), the
//! backend enforces single-use / dedup / freshness over values *surfaced on the
//! envelope* — `upload_nonce`, `nullifier`, `signed_timestamp_ms` — treating
//! them as opaque keys without decoding the proof. That is only sound because
//! the **verifier** confirms each surfaced value equals what the proof actually
//! signed. This module is that confirmation.
//!
//! Three bindings (per the SDK sign-off of the field shape):
//!   1. `upload_nonce` is committed in-proof by an `uploadChallenge` stage whose
//!      `data_hash == SHA256(upload_nonce)` — bound iff a nonce is present.
//!   2. `nullifier` equals the proof's own `nullifier` (field 6).
//!   3. `signed_timestamp_ms` equals the **`proofAssembly` stage** timestamp —
//!      the signed time, never the editable top-level `timestamp_ms`.
//!
//! A proof carrying no replay-control is reported NOT-CHECKED (back-compat /
//! pre-challenge proofs); presence is the backend's policy to enforce, not the
//! stateless verifier's.
//!
//! NOTE: extraction of [`ReplayControl`] from the on-wire envelope (proto
//! `ReplayControl` in `--envelope` mode / §5 JSON `replay_control` in backend
//! mode) is wired when the proto vendoring + §5 schema-v2 land (SDK-3). This
//! module is the binding logic + its tests, independent of that surface.

use crate::crypto::sha256;
use crate::navigate::LocationProof;
use crate::verify::{Check, Status};

/// Stage that commits the upload nonce in-proof (`data_hash = SHA256(nonce)`).
const UPLOAD_CHALLENGE_STAGE: &str = "uploadChallenge";
/// Final assembly stage; its signed timestamp is the proof's authenticated time.
const PROOF_ASSEMBLY_STAGE: &str = "proofAssembly";

/// Replay-control values surfaced on the envelope. A plain struct so the binding
/// check is independent of the (not-yet-vendored) proto type; the caller fills
/// it from whichever envelope surface it parsed (proto or §5 JSON).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReplayControl {
    pub upload_nonce: Vec<u8>,
    pub nullifier: Vec<u8>,
    pub signed_timestamp_ms: i64,
}

/// Lift the generated proto `ReplayControl` (carried on `ContinuousProofEnvelope`
/// in `--envelope` mode) into the binding-check input. Same fields and wire
/// values as the §5 JSON surface, so both envelope surfaces feed one check.
impl From<crate::attest::ReplayControl> for ReplayControl {
    fn from(p: crate::attest::ReplayControl) -> Self {
        ReplayControl {
            upload_nonce: p.upload_nonce,
            nullifier: p.nullifier,
            signed_timestamp_ms: p.signed_timestamp_ms,
        }
    }
}

/// Confirm the envelope's `replay_control` is bound to the signed proof. Returns
/// the `replay-binding` check: `Pass` when every present binding holds, `Fail`
/// on any mismatch, `NotChecked` when the envelope carries no replay-control.
pub fn check_replay_binding(proof: &LocationProof, rc: Option<&ReplayControl>) -> Check {
    const NAME: &str = "replay-binding";
    let rc = match rc {
        None => {
            return Check {
                name: NAME,
                status: Status::NotChecked,
                detail: "no replay_control on the envelope (pre-challenge proof); \
                         presence is enforced server-side, not here"
                    .into(),
            }
        }
        Some(rc) => rc,
    };

    let mut problems: Vec<String> = Vec::new();
    let mut bound: Vec<&str> = Vec::new();

    // 1. nonce ↔ uploadChallenge stage (conditional on the nonce being present).
    if rc.upload_nonce.is_empty() {
        problems.push("replay_control present but upload_nonce is empty".into());
    } else {
        match stage(proof, UPLOAD_CHALLENGE_STAGE) {
            Some(st) if sha256(&rc.upload_nonce).as_slice() == st.data_hash.as_slice() => {
                bound.push("nonce↔uploadChallenge")
            }
            Some(_) => {
                problems.push("uploadChallenge stage data_hash != SHA256(upload_nonce)".into())
            }
            None => problems
                .push("upload_nonce present but no uploadChallenge stage binds it in-proof".into()),
        }
    }

    // 2. nullifier echo == the proof's own nullifier.
    if rc.nullifier == proof.nullifier {
        bound.push("nullifier echo");
    } else {
        problems.push("replay_control.nullifier != the proof's signed nullifier".into());
    }

    // 3. signed_timestamp_ms == the proofAssembly stage's signed timestamp.
    match stage(proof, PROOF_ASSEMBLY_STAGE) {
        Some(st) if st.timestamp_ms == rc.signed_timestamp_ms => bound.push("signed-timestamp echo"),
        Some(st) => problems.push(format!(
            "signed_timestamp_ms {} != proofAssembly stage timestamp {}",
            rc.signed_timestamp_ms, st.timestamp_ms
        )),
        None => {
            problems.push("no proofAssembly stage to bind signed_timestamp_ms against".into())
        }
    }

    if problems.is_empty() {
        Check {
            name: NAME,
            status: Status::Pass,
            detail: format!("envelope replay-control bound to the signed proof: {}", bound.join(", ")),
        }
    } else {
        Check { name: NAME, status: Status::Fail, detail: problems.join("; ") }
    }
}

fn stage<'a>(proof: &'a LocationProof, name: &str) -> Option<&'a crate::navigate::StageAttestation> {
    proof.stage_attestations.iter().find(|s| s.stage == name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::navigate::{LocationProof, StageAttestation};

    fn stage_named(name: &str, data: &[u8], ts: i64) -> StageAttestation {
        StageAttestation {
            stage: name.to_string(),
            timestamp_ms: ts,
            data_hash: sha256(data).to_vec(),
            signature: vec![],
            previous_hash: None,
        }
    }

    /// Build a proof that carries a valid replay-control commitment: an
    /// `uploadChallenge` stage over `nonce`, a `proofAssembly` stage at `ts`, and
    /// nullifier `null`.
    fn proof_with(nonce: &[u8], null: &[u8], ts: i64) -> LocationProof {
        LocationProof {
            nullifier: null.to_vec(),
            stage_attestations: vec![
                stage_named(UPLOAD_CHALLENGE_STAGE, nonce, ts),
                stage_named(PROOF_ASSEMBLY_STAGE, b"assembly", ts),
            ],
            ..Default::default()
        }
    }

    fn rc(nonce: &[u8], null: &[u8], ts: i64) -> ReplayControl {
        ReplayControl { upload_nonce: nonce.to_vec(), nullifier: null.to_vec(), signed_timestamp_ms: ts }
    }

    /// Happy path: every surfaced value is bound to the signed proof → Pass.
    /// This is what lets the backend trust the opaque keys it enforced over.
    #[test]
    fn all_three_bindings_hold() {
        let p = proof_with(b"nonce-xyz", b"nullA", 1_700_000_000_000);
        let c = check_replay_binding(&p, Some(&rc(b"nonce-xyz", b"nullA", 1_700_000_000_000)));
        assert_eq!(c.status, Status::Pass);
    }

    /// A nonce that the proof never committed (no `uploadChallenge` hash match)
    /// must FAIL — otherwise an attacker pairs a fresh server nonce with a proof
    /// that didn't sign it.
    #[test]
    fn wrong_nonce_fails_binding() {
        let p = proof_with(b"real-nonce", b"nullA", 1_700_000_000_000);
        let c = check_replay_binding(&p, Some(&rc(b"attacker-nonce", b"nullA", 1_700_000_000_000)));
        assert_eq!(c.status, Status::Fail);
    }

    /// A nonce present in the envelope but with no `uploadChallenge` stage to
    /// bind it → FAIL (the proof doesn't commit to the nonce at all).
    #[test]
    fn nonce_without_upload_challenge_stage_fails() {
        let mut p = proof_with(b"n", b"nullA", 1);
        p.stage_attestations.retain(|s| s.stage != UPLOAD_CHALLENGE_STAGE);
        let c = check_replay_binding(&p, Some(&rc(b"n", b"nullA", 1)));
        assert_eq!(c.status, Status::Fail);
    }

    /// A surfaced nullifier that disagrees with the proof's own nullifier → FAIL
    /// (else the backend dedups on a value the proof didn't sign).
    #[test]
    fn nullifier_echo_mismatch_fails() {
        let p = proof_with(b"n", b"realNull", 1);
        let c = check_replay_binding(&p, Some(&rc(b"n", b"fakeNull", 1)));
        assert_eq!(c.status, Status::Fail);
    }

    /// signed_timestamp_ms must equal the proofAssembly stage's signed time, not
    /// some attacker-chosen value.
    #[test]
    fn timestamp_echo_mismatch_fails() {
        let p = proof_with(b"n", b"nullA", 1_700_000_000_000);
        let c = check_replay_binding(&p, Some(&rc(b"n", b"nullA", 1_699_000_000_000)));
        assert_eq!(c.status, Status::Fail);
    }

    /// No replay-control at all → NOT-CHECKED (back-compat; the backend enforces
    /// presence, the stateless verifier can't).
    #[test]
    fn absent_replay_control_is_not_checked() {
        let p = proof_with(b"n", b"nullA", 1);
        let c = check_replay_binding(&p, None);
        assert_eq!(c.status, Status::NotChecked);
    }

    /// replay_control present but the nonce empty → FAIL (a malformed control,
    /// not a clean "no replay-control" proof).
    #[test]
    fn present_but_empty_nonce_fails() {
        let p = proof_with(b"n", b"nullA", 1);
        let c = check_replay_binding(&p, Some(&rc(b"", b"nullA", 1)));
        assert_eq!(c.status, Status::Fail);
    }

    /// The proto `ReplayControl` (`--envelope` mode) lifts into the binding input
    /// field-for-field, so the same check serves both envelope surfaces.
    #[test]
    fn from_proto_replay_control_preserves_fields() {
        let proto = crate::attest::ReplayControl {
            upload_nonce: b"nonce".to_vec(),
            nullifier: b"null".to_vec(),
            signed_timestamp_ms: 1_700_000_000_000,
        };
        let rc: ReplayControl = proto.into();
        assert_eq!(rc, ReplayControl {
            upload_nonce: b"nonce".to_vec(),
            nullifier: b"null".to_vec(),
            signed_timestamp_ms: 1_700_000_000_000,
        });
    }
}
