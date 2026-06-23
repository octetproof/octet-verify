//! Offline Apple App Attest verification layer (feature `appattest`).
//!
//! Bridges a decoded [`LocationProof`] to the shared `octet-attest-verify`
//! crate: it pulls the App Attest fields off `DeviceAttestation`, supplies the
//! expected app identity, and turns the result into an `app-attest`
//! [`Check`]. We depend on the shared crate rather than re-implementing the
//! attestation crypto here, so the auditable logic lives in exactly one place.

use crate::navigate::LocationProof;
use crate::verify::{Check, Status};
use base64::Engine;
use octet_attest_verify::appattest::{
    verify_assertion, verify_attestation, AcceptEnvironment, AppId, AttestedKey,
};

/// The trusted app identity a proof's attestation must bind to. In the Octet
/// flow this comes from the signed activation-bearer claim; standalone it comes
/// from config.
pub struct Expectation {
    pub app_id: AppId,
    pub accept_env: AcceptEnvironment,
}

impl Expectation {
    pub fn new(team_id: &str, bundle_id: &str, accept_env: AcceptEnvironment) -> Self {
        Expectation {
            app_id: AppId::from_team_and_bundle(team_id, bundle_id),
            accept_env,
        }
    }
}

fn chk(status: Status, detail: impl Into<String>) -> Check {
    Check { name: "app-attest", status, detail: detail.into() }
}

/// Verify the App Attest evidence carried on `proof`.
///
/// `cached` is a key recovered from a previous proof's attestation object, for
/// the assertion-only proofs that follow it within a key's lifetime. For a
/// stateless single-proof check pass `None`; then the proof must carry its own
/// attestation object (the first proof after a key is attested) to be verified.
///
/// Returns the `app-attest` check plus, when an attestation object was verified
/// or an assertion advanced the counter, the [`AttestedKey`] the caller should
/// cache (keyed by `key_id`) for subsequent proofs.
pub fn appattest_check(
    proof: &LocationProof,
    expect: &Expectation,
    cached: Option<&AttestedKey>,
) -> (Check, Option<AttestedKey>) {
    let da = match &proof.device_attestation {
        Some(d) => d,
        None => return (chk(Status::NotChecked, "no device attestation on proof"), None),
    };

    let (nonce, assertion) = match (da.attestation_nonce.as_deref(), da.app_attest_assertion.as_deref()) {
        (Some(n), Some(a)) if !n.is_empty() && !a.is_empty() => (n, a),
        _ => {
            return (
                chk(Status::NotChecked, "no App Attest evidence (Android proof, or pre-attestation)"),
                None,
            )
        }
    };

    // Apple's key identifier rides as a base64 string on the wire.
    let key_id = match base64::engine::general_purpose::STANDARD.decode(&da.key_id) {
        Ok(k) => k,
        Err(_) => return (chk(Status::Fail, "key_id is not valid base64"), None),
    };

    match da.app_attest_attestation.as_deref() {
        // First proof of a key: verify the chain to Apple's root, recover the
        // key, then verify the assertion against it.
        Some(obj) => match verify_attestation(obj, nonce, &expect.app_id, &key_id, expect.accept_env) {
            Ok(key) => match verify_assertion(assertion, nonce, &expect.app_id, &key) {
                Ok(counter) => (
                    chk(Status::Pass,
                        format!("attestation chained to Apple App Attest root; assertion verified (counter {counter})")),
                    Some(AttestedKey { last_counter: counter, ..key }),
                ),
                Err(e) => (chk(Status::Fail, format!("attestation valid but assertion failed: {e}")), None),
            },
            Err(e) => (chk(Status::Fail, format!("attestation verification failed: {e}")), None),
        },
        // Later proof in the key's lifetime: needs the cached key.
        None => match cached {
            None => (
                chk(Status::NotChecked,
                    "assertion present but this proof carries no attestation object and no cached key is available"),
                None,
            ),
            Some(key) => match verify_assertion(assertion, nonce, &expect.app_id, key) {
                Ok(counter) => (
                    chk(Status::Pass, format!("assertion verified against cached key (counter {counter})")),
                    Some(AttestedKey { last_counter: counter, public_key_sec1: key.public_key_sec1.clone() }),
                ),
                Err(e) => (chk(Status::Fail, format!("assertion failed: {e}")), None),
            },
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::navigate::{DeviceAttestation, LocationProof};

    fn expectation() -> Expectation {
        Expectation::new("6ZH5F97PWU", "com.octetproof.tester", AcceptEnvironment::Any)
    }

    fn proof_with(da: Option<DeviceAttestation>) -> LocationProof {
        LocationProof { device_attestation: da, timestamp_ms: 1_700_000_000_000, ..Default::default() }
    }

    #[test]
    fn no_device_attestation_is_not_checked() {
        let (c, key) = appattest_check(&proof_with(None), &expectation(), None);
        assert_eq!(c.status, Status::NotChecked);
        assert!(key.is_none());
    }

    #[test]
    fn no_app_attest_fields_is_not_checked() {
        // An Android proof: device attestation present, but no App Attest fields.
        let da = DeviceAttestation { key_id: "abc".into(), ..Default::default() };
        let (c, _) = appattest_check(&proof_with(Some(da)), &expectation(), None);
        assert_eq!(c.status, Status::NotChecked);
    }

    #[test]
    fn assertion_only_without_cached_key_is_not_checked() {
        let key_id = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);
        let da = DeviceAttestation {
            key_id,
            app_attest_assertion: Some(vec![1, 2, 3]),
            attestation_nonce: Some(vec![9; 32]),
            ..Default::default()
        };
        let (c, key) = appattest_check(&proof_with(Some(da)), &expectation(), None);
        assert_eq!(c.status, Status::NotChecked);
        assert!(key.is_none());
    }

    #[test]
    fn bad_key_id_base64_fails() {
        let da = DeviceAttestation {
            key_id: "!!!not base64!!!".into(),
            app_attest_assertion: Some(vec![1, 2, 3]),
            attestation_nonce: Some(vec![9; 32]),
            app_attest_attestation: Some(vec![0xCB, 0x0B]),
            ..Default::default()
        };
        let (c, _) = appattest_check(&proof_with(Some(da)), &expectation(), None);
        assert_eq!(c.status, Status::Fail);
        assert!(c.detail.contains("base64"));
    }

    #[test]
    fn garbage_attestation_object_fails() {
        let key_id = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);
        let da = DeviceAttestation {
            key_id,
            app_attest_assertion: Some(vec![1, 2, 3]),
            attestation_nonce: Some(vec![9; 32]),
            app_attest_attestation: Some(vec![0, 1, 2, 3]), // not a valid CBOR attestation
            ..Default::default()
        };
        let (c, key) = appattest_check(&proof_with(Some(da)), &expectation(), None);
        assert_eq!(c.status, Status::Fail);
        assert!(key.is_none());
    }
}
