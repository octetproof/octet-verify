//! Tier-2 (gateway-mode, honestly un-attested) golden vectors for the SDK's
//! gateway-mode un-attested option (`osAttestationInGatewayModes`). Real device
//! proofs that deliberately carry NO
//! per-proof OS attestation: `certificate_chain[0]` is a bare x963 device-key
//! point (no App Attest object/assertion on iOS, no X.509 key-attestation chain /
//! Play Integrity on Android), while the device-key/field-2 signature is present
//! and valid. The verifier must accept them as VALID + authentic but
//! `attested:false` — the honest lower tier — and, under `--require-attestation`,
//! REJECT them (the relying-party gate).
//!
//! Provenance (confirmed on the real octet-verify binary before freezing):
//!   * iOS   — iPhone 11, Secure-Enclave bare point. security_level = 3.
//!   * Android — Pixel 9, release-signed, bare point. security_level came out
//!     1 (SOFTWARE): the non-attested key fell back to software on the release
//!     toolchain, NOT the intended StrongBox. This is verifier-INVISIBLE
//!     — octet-verify never reads the proto's self-asserted `security_level` for a
//!     bare-point proof (the only security_level it reads is from the X.509
//!     attestation extension, which a bare point never reaches), so the verdict is
//!     identical to a StrongBox capture. Frozen as the canonical Android Tier-2
//!     vector by maintainer sign-off; when the release-toolchain fix lands, a
//!     StrongBox re-capture replaces it as canonical and this stays as the
//!     "software-fallback" case.
//!
//! The opposite direction of the tier boundary — an *anchored* Android chain →
//! `attestation-root` PASS → `attested:true` — is guarded by
//! `tests/android_app_binding.rs`.
#![cfg(feature = "appattest")]

use octet_verify::appattest_layer::{verify_attested, AcceptEnvironment, Expectation};
use octet_verify::crypto::P256VerifyingKey;
use octet_verify::keys::hardware_pubkey_from_cert_chain;
use octet_verify::navigate::LocationProof;
use octet_verify::prost::Message;
use octet_verify::verify::{Report, Status, VerifyOptions};

const IOS: &[u8] = include_bytes!("../test-vectors/attestation/tier2-gateway-ios-iphone11.bin");
const ANDROID: &[u8] = include_bytes!("../test-vectors/attestation/tier2-gateway-android-pixel9.bin");

fn expectation() -> Expectation {
    Expectation::new("6ZH5F97PWU", "com.octetproof.sample", AcceptEnvironment::Any)
}

fn status(r: &Report, name: &str) -> Option<Status> {
    r.checks.iter().find(|c| c.name == name).map(|c| c.status)
}

/// Resolve the device key from `certificate_chain[0]` exactly as the CLI does
/// (`keys::hardware_pubkey_from_cert_chain`, SEC1-first) — the resolution that
/// must succeed on a bare x963 point for the un-attested tier to verify at all.
fn resolve_key(p: &LocationProof) -> P256VerifyingKey {
    let chain = &p.device_attestation.as_ref().expect("device_attestation").certificate_chain;
    hardware_pubkey_from_cert_chain(chain).expect("bare x963 point resolves via the SEC1-first resolver")
}

fn opts<'a>(hw: &'a P256VerifyingKey, now_ms: i64, require_attestation: bool) -> VerifyOptions<'a> {
    VerifyOptions {
        now_ms,
        max_age_s: i64::MAX / 2, // golden: verifiable forever, freshness must not age out
        hardware_pubkey: Some(hw),
        hw_key_source: "certificate_chain[0]",
        expect_region: None,
        expect_region_type: None,
        expect_region_contains: None,
        session_nonce: None,
        require_session_binding: false,
        require_schema_v2: false,
        require_attestation,
    }
}

/// The shared Tier-2 contract, asserted on each real device vector.
fn assert_tier2(label: &str, bytes: &[u8]) {
    let proof = LocationProof::decode(bytes).unwrap_or_else(|e| panic!("{label} decodes: {e}"));
    let hw = resolve_key(&proof);
    // now safely after the signed time so freshness passes deterministically forever.
    let now_ms = proof.timestamp_ms + 3_600_000;

    let r = verify_attested(&proof, &opts(&hw, now_ms, false), &expectation());
    assert!(r.is_valid(), "{label}: expected VALID");
    assert!(r.is_authentic(), "{label}: expected authentic (signatures verified)");
    assert!(!r.is_attested(), "{label}: must NOT be attested (honest Tier-2)");
    assert_eq!(status(&r, "stage-signatures"), Some(Status::Pass), "{label}: stage-signatures");
    assert_eq!(status(&r, "device-attestation-sig"), Some(Status::Pass), "{label}: device-sig");
    assert_eq!(status(&r, "app-attest"), Some(Status::NotChecked), "{label}: app-attest");
    assert_eq!(status(&r, "attestation-root"), Some(Status::NotChecked), "{label}: attestation-root");
    // Both vectors are semantic-binding-v2 proofs (a 2.0.0 emission property).
    assert!(r.is_semantically_bound(), "{label}: semantic-binding v2");

    // The relying-party gate: --require-attestation turns an un-attested proof
    // into a rejection — exactly what an attestation-mandatory consumer wants.
    let gated = verify_attested(&proof, &opts(&hw, now_ms, true), &expectation());
    assert!(!gated.is_valid(), "{label}: --require-attestation must REJECT a Tier-2 proof");
    assert_eq!(
        status(&gated, "attestation-required"),
        Some(Status::Fail),
        "{label}: attestation-required must FAIL"
    );
}

#[test]
fn ios_tier2_gateway_proof_is_valid_but_unattested() {
    assert_tier2("iOS Tier-2", IOS);
}

#[test]
fn android_tier2_gateway_proof_is_valid_but_unattested() {
    assert_tier2("Android Tier-2", ANDROID);
}

#[test]
fn tier2_vectors_carry_no_attestation_evidence() {
    // Shape guard: the frozen bytes really are the bare-point / no-attestation
    // shape (so a future re-capture that accidentally re-adds evidence is caught).
    for (label, bytes) in [("iOS", IOS), ("Android", ANDROID)] {
        let da = LocationProof::decode(bytes).unwrap().device_attestation.unwrap();
        assert!(da.app_attest_attestation.is_none(), "{label}: no App Attest object");
        assert!(da.app_attest_assertion.is_none(), "{label}: no App Attest assertion");
        assert_eq!(da.certificate_chain.len(), 1, "{label}: single bare point, no chain");
        let leaf = &da.certificate_chain[0];
        assert_eq!(leaf.len(), 65, "{label}: uncompressed x963 point is 65 bytes");
        assert_eq!(leaf[0], 0x04, "{label}: uncompressed SEC1 prefix 0x04");
        // A bare point, not an X.509 cert (which would start with the SEQUENCE tag 0x30).
        assert_ne!(leaf[0], 0x30, "{label}: must be a bare point, not an X.509 leaf");
    }
}
