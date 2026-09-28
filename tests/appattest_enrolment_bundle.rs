//! CLI `--app-attest-enrolment-bundle`: recover an attested key from an
//! out-of-band bundle so an assertion-only iOS proof — one carrying no attestation
//! object, the steady state — reaches `app-attest` PASS via the cached-key path
//! instead of the NOT-CHECKED it reports without it.
//!
//! Fixture reality: the only committed real-device App Attest vector carries
//! a **bound-form** assertion (clientDataHash = SHA256(nonce ‖ SE_key),).
//! A genuine *enrolment* bundle instead carries a **nonce-only** assertion (the
//! one-time bootstrap form) that only a device can produce, so a fully-green
//! enrol→PASS end-to-end awaits a device bundle (the dev E2E). What we can prove
//! with the committed fixture, on real crypto:
//!   * the cached-key path itself yields `app-attest` PASS (`cached_*` below);
//!   * the CLI flag deserializes a proto bundle and drives it through enrolment,
//!     chaining the object to Apple's root (`cli_flag_*` below);
//!   * the flag requires `--app-attest-config` (`*_without_config_*` below).
#![cfg(feature = "appattest")]

use octet_verify::appattest_layer::{
    appattest_check, verify_attested_cached, AcceptEnvironment, Expectation,
};
use octet_verify::crypto::P256VerifyingKey;
use octet_verify::navigate::{DeviceAttestation, LocationProof};
use octet_verify::prost::Message;
use octet_verify::verify::{Status, VerifyOptions};
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_octet-verify");
const PROOF: &[u8] = include_bytes!("../test-vectors/attestation/ios-appattest.bin");

fn expectation() -> Expectation {
    Expectation::new("6ZH5F97PWU", "com.octetproof.sample", AcceptEnvironment::Any)
}

fn full_proof() -> LocationProof {
    LocationProof::decode(PROOF).expect("real iOS proof decodes")
}

/// The Secure-Enclave signing key (certificate_chain[0]) the bound assertion
/// commits to and the field-2 signature is verified against.
fn se_key(proof: &LocationProof) -> P256VerifyingKey {
    let sec1 = &proof
        .device_attestation
        .as_ref()
        .unwrap()
        .certificate_chain[0];
    P256VerifyingKey::from_sec1_bytes(sec1).expect("cert_chain[0] is a SEC1 P-256 point")
}

fn opts<'a>(hw: &'a P256VerifyingKey) -> VerifyOptions<'a> {
    VerifyOptions {
        now_ms: 1_700_000_000_000, // the fixture proof's era; keeps freshness out of the way
        max_age_s: i64::MAX / 2,
        hardware_pubkey: Some(hw),
        hw_key_source: "cert_chain[0] (test)",
        expect_region: None,
        expect_region_type: None,
        expect_region_contains: None,
        session_nonce: None,
        require_session_binding: false,
        require_schema_v2: false,
        require_attestation: false,
    }
}

fn status(report: &octet_verify::verify::Report, name: &str) -> Option<Status> {
    report.checks.iter().find(|c| c.name == name).map(|c| c.status)
}

/// A unique scratch path under the OS temp dir (no tempfile dev-dep needed).
fn tmp(name: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("oxv67-{}-{name}", std::process::id()));
    p
}

/// The fixture proof with the App Attest **object** removed — assertion-only, so
/// only the cached-key path (not the object path) can reach PASS.
fn assertion_only(proof: &LocationProof) -> LocationProof {
    let mut p = proof.clone();
    p.device_attestation.as_mut().unwrap().app_attest_attestation = None;
    p
}

#[test]
fn cached_key_path_yields_app_attest_pass_and_object_path_does_not() {
    // Recover the attested key the way enrolment does — from the object — using the
    // full fixture proof (object path). Seed the counter to 0, exactly as the CLI's
    // stateless enrolment does, so the same-window assertion isn't a replay.
    let proof = full_proof();
    let hw = se_key(&proof);
    let (obj_check, recovered) = appattest_check(&proof, &expectation(), None, Some(&hw.to_sec1_bytes()), false);
    assert_eq!(obj_check.status, Status::Pass, "object path: {}", obj_check.detail);
    let mut key = recovered.expect("object path recovers the attested key");
    key.last_counter = 0;

    // Assertion-only proof + NO cached key → NOT-CHECKED (the gap closes).
    let bare = assertion_only(&proof);
    let (uncached, _) = verify_attested_cached(&bare, &opts(&hw), &expectation(), None);
    assert_eq!(
        status(&uncached, "app-attest"),
        Some(Status::NotChecked),
        "assertion-only proof with no cached key must be NOT-CHECKED"
    );
    assert!(!uncached.is_attested());

    // Same proof + the recovered (cached) key → app-attest PASS, attested true.
    let (cached, _) = verify_attested_cached(&bare, &opts(&hw), &expectation(), Some(&key));
    assert_eq!(
        status(&cached, "app-attest"),
        Some(Status::Pass),
        "cached-key path must PASS an assertion-only proof"
    );
    assert!(cached.is_attested(), "the cached-key PASS must flip the attested bit");
}

#[test]
fn cli_flag_threads_proto_bundle_through_enrolment_to_the_apple_root() {
    // The CLI --app-attest-enrolment-bundle flag: deserialize a proto bundle and
    // drive it through enrolment. We feed the object with its (bound) assertion
    // — a real bundle's assertion is nonce-only, so this correctly stops at the
    // assertion step, but only AFTER the object has chained to Apple's root. That
    // proves the whole new path runs on real data: parse → bundle_from_proto →
    // appattest_enroll → object verified. (The green enrol→PASS is exercised by a
    // device-produced nonce-only bundle in the dev E2E.)
    let proof = full_proof();
    let da = proof.device_attestation.as_ref().unwrap();
    let bundle = DeviceAttestation {
        key_id: da.key_id.clone(),
        app_attest_attestation: da.app_attest_attestation.clone(),
        app_attest_assertion: da.app_attest_assertion.clone(),
        attestation_nonce: da.attestation_nonce.clone(),
        ..Default::default()
    }
    .encode_to_vec();

    let proof_path = tmp("proof.bin");
    let bundle_path = tmp("bundle.proto");
    let cfg_path = tmp("app-attest.toml");
    std::fs::write(&proof_path, assertion_only(&proof).encode_to_vec()).unwrap();
    std::fs::write(&bundle_path, bundle).unwrap();
    std::fs::write(
        &cfg_path,
        "[app_attest]\nteam_id = \"6ZH5F97PWU\"\nbundle_id = \"com.octetproof.sample\"\nenvironment = \"any\"\n",
    )
    .unwrap();

    let out = Command::new(BIN)
        .arg(&proof_path)
        .args(["--app-attest-config", cfg_path.to_str().unwrap()])
        .args(["--app-attest-enrolment-bundle", bundle_path.to_str().unwrap()])
        .args(["--max-age-seconds", "9999999999999"])
        .arg("--json")
        .output()
        .expect("run verifier with bundle");
    let stderr = String::from_utf8_lossy(&out.stderr);
    // The flag ran resolve_enrolment_key → bundle_from_proto → appattest_enroll,
    // and the object chained to Apple's root before the (bound) assertion was
    // rejected under nonce-only enrolment.
    assert!(
        stderr.contains("enrolment bundle failed verification"),
        "the enrolment path must run; stderr:\n{stderr}"
    );
    assert!(
        stderr.contains("attestation valid"),
        "the object must chain to Apple's root; stderr:\n{stderr}"
    );

    for p in [&proof_path, &bundle_path, &cfg_path] {
        let _ = std::fs::remove_file(p);
    }
}

#[test]
fn enrolment_bundle_without_config_is_rejected() {
    // The bundle needs the app identity from the config to verify against, so the
    // flag requires --app-attest-config; supplying it alone is a usage error.
    let bundle_path = tmp("lonely-bundle.proto");
    std::fs::write(&bundle_path, [0u8; 4]).unwrap(); // never parsed — the guard fires first

    let out = Command::new(BIN)
        .arg("/dev/null")
        .args(["--app-attest-enrolment-bundle", bundle_path.to_str().unwrap()])
        .output()
        .expect("run verifier (guard)");
    assert!(!out.status.success(), "must reject bundle without --app-attest-config");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("requires --app-attest-config"),
        "error must name the missing --app-attest-config; stderr:\n{stderr}"
    );

    let _ = std::fs::remove_file(&bundle_path);
}
