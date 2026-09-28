//! Real-device iOS App Attest green path — the object-bearing,
//! **bound-form** assertion path, executed end-to-end on genuine hardware.
//!
//! Uses `test-vectors/attestation/ios-appattest.bin` — a genuine iPhone 11
//! ( build) FIRST-of-key `LocationProof` from `com.octetproof.sample`
//! (team `6ZH5F97PWU`, env development). Its live App Attest assertion is the
//! bound form: `clientDataHash = SHA256(nonce ‖ SE_signing_key)`, committing
//! the Secure-Enclave key that signs the proof (`certificate_chain[0]`). Before
//! this fixture the iOS object-bearing green path had no executed coverage
//! ( pt 5, "untested green path") — it was verified from source only.
//!
//! iOS carries a raw Secure-Enclave key (no X.509 chain), so `attestation-root`
//! is NOT-CHECKED by design and the hardware-root assurance is `app-attest`
//! (Apple App Attest). There is no attestation-cert validity window, so only
//! proof freshness is time-sensitive — a fixed `now` + a generous window keeps
//! this deterministic (it can't go stale the way an expiring leaf would).
#![cfg(feature = "appattest")]

use octet_verify::appattest_layer::{verify_attested, AcceptEnvironment, Expectation};
use octet_verify::keys::hardware_pubkey_from_cert_chain;
use octet_verify::navigate::LocationProof;
use octet_verify::prost::Message;
use octet_verify::verify::{Status, VerifyOptions};

const PROOF: &[u8] = include_bytes!("../test-vectors/attestation/ios-appattest.bin");

/// Pinned well after the proof's signed time; iOS has no cert validity window, so
/// a generous freshness window is all that is needed for determinism.
const PINNED_NOW_MS: i64 = 1_800_000_000_000;

fn proof() -> LocationProof {
    LocationProof::decode(PROOF).expect("real iOS proof decodes")
}

/// The Secure-Enclave signing key, resolved from the proof's own
/// `certificate_chain[0]` (a raw SEC1 point on iOS) exactly as production does —
/// the key `stage-signatures` verifies against and the key the bound
/// assertion commits to.
fn se_signing_key() -> octet_verify::crypto::P256VerifyingKey {
    let chain = proof()
        .device_attestation
        .expect("has device attestation")
        .certificate_chain;
    hardware_pubkey_from_cert_chain(&chain).expect("SE signing key resolves")
}

/// com.octetproof.sample / team 6ZH5F97PWU. `Any` env keeps the fixture robust;
/// the environment gate itself is exercised in the crate's unit tests.
fn expectation() -> Expectation {
    Expectation::new("6ZH5F97PWU", "com.octetproof.sample", AcceptEnvironment::Any)
}

fn opts(hw: &octet_verify::crypto::P256VerifyingKey, require_attestation: bool) -> VerifyOptions<'_> {
    VerifyOptions {
        now_ms: PINNED_NOW_MS,
        max_age_s: i64::MAX / 2,
        hardware_pubkey: Some(hw),
        hw_key_source: "certificate_chain",
        expect_region: None,
        expect_region_type: None,
        expect_region_contains: None,
        session_nonce: None,
        require_session_binding: false,
        require_schema_v2: false,
        require_attestation,
    }
}

fn status(report: &octet_verify::verify::Report, name: &str) -> Option<Status> {
    report.checks.iter().find(|c| c.name == name).map(|c| c.status)
}

/// The flip: with attestation **required** (RequireBound), a genuine iPhone
/// bound-form proof verifies end-to-end. The object recovers the App Attest key
/// to Apple's root, then the live assertion verifies in the bound form against
/// the SE signing key — the path that had no executed coverage before.
#[test]
fn real_ios_bound_proof_verifies_under_require_attestation() {
    let hw = se_signing_key();
    let report = verify_attested(&proof(), &opts(&hw, true), &expectation());

    let app_attest_detail = report
        .checks
        .iter()
        .find(|c| c.name == "app-attest")
        .map(|c| c.detail.clone())
        .unwrap_or_default();
    assert_eq!(status(&report, "app-attest"), Some(Status::Pass), "app-attest: {app_attest_detail}");
    // iOS: raw Secure-Enclave key, no X.509 chain to a Google root.
    assert_eq!(status(&report, "attestation-root"), Some(Status::NotChecked));
    assert_eq!(status(&report, "device-attestation-sig"), Some(Status::Pass));
    // The fail-closed gate is satisfied by a real, affirmatively-verified attestation.
    assert_eq!(status(&report, "attestation-required"), Some(Status::Pass));

    assert!(report.is_attested(), "a genuine iOS bound proof must be attested");
    assert!(report.is_authentic(), "a genuine iOS proof must be authentic");
}

/// Rollout posture: the same proof also verifies under PreferBound (no
/// `--require-attestation`) — the bound form is accepted, and `is_attested` holds.
#[test]
fn real_ios_bound_proof_also_verifies_under_prefer_bound() {
    let hw = se_signing_key();
    let report = verify_attested(&proof(), &opts(&hw, false), &expectation());
    assert_eq!(status(&report, "app-attest"), Some(Status::Pass));
    assert!(report.is_attested());
    assert!(report.is_authentic());
}

/// The binding must be to *this* proof's signing key: verifying the genuine
/// bound assertion while claiming a DIFFERENT signing key breaks the binding
/// — `app-attest` must not PASS. (This is the borrowed-(nonce, assertion) replay
/// the bound form defeats.) A wrong key also breaks `stage-signatures`, so the
/// proof is not authentic either.
#[test]
fn wrong_signing_key_breaks_the_bound_assertion() {
    // A valid but unrelated P-256 key (not the SE key that signed the proof).
    let wrong = p256::ecdsa::SigningKey::from_slice(&[9u8; 32])
        .unwrap()
        .verifying_key()
        .to_owned();
    let report = verify_attested(&proof(), &opts(&wrong, true), &expectation());
    assert_ne!(
        status(&report, "app-attest"),
        Some(Status::Pass),
        "a bound assertion must not verify against a different signing key"
    );
    assert!(!report.is_attested());
}
