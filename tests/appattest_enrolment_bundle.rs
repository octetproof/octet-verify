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
//!
//! The object-only bundle (JSON `v:2` / proto without an assertion) needs no
//! device-made assertion, so it is built from the fixture itself and runs the
//! fully green enrol → assertion-only PASS path, in the library and the CLI
//! (`object_only_*` and `cli_object_only_*` below).
#![cfg(feature = "appattest")]

use octet_verify::appattest_layer::{
    appattest_check, appattest_enroll, bundle_from_json, verify_attested_cached, AcceptEnvironment,
    Expectation,
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
        require_verdict: None,
        validation_window: None,
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

// --- object-only enrolment (JSON v:2 / proto without app_attest_assertion) ---
//
// The committed fixture's object and nonce are a genuine enrolment pair, so an
// object-only bundle built from them is a real one: these run the full
// enrol → assertion-only PASS path on real Apple crypto.

/// The fixture's object, nonce and key_id, with no assertion.
fn object_only_da(proof: &LocationProof) -> DeviceAttestation {
    let da = proof.device_attestation.as_ref().unwrap();
    DeviceAttestation {
        key_id: da.key_id.clone(),
        app_attest_attestation: da.app_attest_attestation.clone(),
        attestation_nonce: da.attestation_nonce.clone(),
        ..Default::default()
    }
}

/// The same bundle as canonical JSON `v:2` (b64url-no-pad, raw key_id bytes).
fn object_only_json(proof: &LocationProof) -> String {
    use base64::Engine;
    let url = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let da = proof.device_attestation.as_ref().unwrap();
    let key_id = base64::engine::general_purpose::STANDARD.decode(&da.key_id).unwrap();
    format!(
        r#"{{"v":2,"key_id":"{}","app_attest_attestation":"{}","attestation_nonce":"{}"}}"#,
        url.encode(key_id),
        url.encode(da.app_attest_attestation.as_ref().unwrap()),
        url.encode(da.attestation_nonce.as_ref().unwrap()),
    )
}

#[test]
fn object_only_bundle_enrols_with_counter_zero_and_passes_a_later_assertion() {
    let proof = full_proof();
    let hw = se_key(&proof);
    let bare = assertion_only(&proof);
    for (form, da) in [
        ("proto", object_only_da(&proof)),
        ("json v:2", bundle_from_json(object_only_json(&proof).as_bytes()).expect("v:2 parses")),
    ] {
        assert_eq!(da.app_attest_assertion, None, "{form}");
        let key = appattest_enroll(&da, &expectation()).unwrap_or_else(|e| panic!("{form}: {e}"));
        assert_eq!(key.last_counter, 0, "{form}: counter baseline is the object's, 0");
        let (report, advanced) = verify_attested_cached(&bare, &opts(&hw), &expectation(), Some(&key));
        assert_eq!(status(&report, "app-attest"), Some(Status::Pass), "{form}");
        assert!(report.is_attested(), "{form}");
        assert!(advanced.expect("PASS returns the advanced key").last_counter > 0, "{form}");
    }
}

#[test]
fn object_only_bundle_is_refused_when_tampered_or_for_another_app() {
    let proof = full_proof();
    // Wrong nonce: the object's Apple nonce no longer matches.
    let mut da = object_only_da(&proof);
    da.attestation_nonce.as_mut().unwrap()[0] ^= 0xFF;
    assert!(appattest_enroll(&da, &expectation()).is_err(), "edited nonce");
    // Wrong key_id: no longer SHA256 of the attested key.
    let mut da = object_only_da(&proof);
    da.key_id = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode([0u8; 32])
    };
    assert!(appattest_enroll(&da, &expectation()).is_err(), "edited key_id");
    // Another app identity.
    let other = Expectation::new("6ZH5F97PWU", "com.example.other", AcceptEnvironment::Any);
    assert!(appattest_enroll(&object_only_da(&proof), &other).is_err(), "other bundle id");
    // No nonce at all.
    let mut da = object_only_da(&proof);
    da.attestation_nonce = None;
    let err = appattest_enroll(&da, &expectation()).unwrap_err().to_string();
    assert!(err.contains("no attestation nonce"), "{err}");
}

#[test]
fn cli_object_only_json_bundle_takes_an_assertion_only_proof_to_pass() {
    let proof = full_proof();
    let proof_path = tmp("oo-proof.bin");
    let bundle_path = tmp("oo-bundle.json");
    let cfg_path = tmp("oo-app-attest.toml");
    std::fs::write(&proof_path, assertion_only(&proof).encode_to_vec()).unwrap();
    std::fs::write(&bundle_path, object_only_json(&proof)).unwrap();
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
        .expect("run verifier with an object-only bundle");
    for p in [&proof_path, &bundle_path, &cfg_path] {
        let _ = std::fs::remove_file(p);
    }
    let json: serde_json::Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("CLI JSON: {e}; stderr:\n{}", String::from_utf8_lossy(&out.stderr)));
    let aa = json["checks"].as_array().unwrap().iter().find(|c| c["name"] == "app-attest").expect("app-attest");
    assert_eq!(aa["status"], "PASS", "{aa}");
    assert_eq!(json["verdict"], "VALID");
}

/// An assertion-only proof carries no object, so `--app-attest-window` dates the
/// enrolment bundle's object, the one the verified key came from.
#[test]
fn cli_app_attest_window_dates_the_enrolment_bundles_object() {
    let proof = full_proof();
    let run = |window: &str, tag: &str| {
        let proof_path = tmp(&format!("aw-{tag}-proof.bin"));
        let bundle_path = tmp(&format!("aw-{tag}-bundle.json"));
        let cfg_path = tmp(&format!("aw-{tag}-app-attest.toml"));
        std::fs::write(&proof_path, assertion_only(&proof).encode_to_vec()).unwrap();
        std::fs::write(&bundle_path, object_only_json(&proof)).unwrap();
        std::fs::write(
            &cfg_path,
            "[app_attest]\nteam_id = \"6ZH5F97PWU\"\nbundle_id = \"com.octetproof.sample\"\nenvironment = \"any\"\n",
        )
        .unwrap();
        let out = Command::new(BIN)
            .arg(&proof_path)
            .args(["--app-attest-config", cfg_path.to_str().unwrap()])
            .args(["--app-attest-enrolment-bundle", bundle_path.to_str().unwrap()])
            .args(["--app-attest-window", window])
            .args(["--max-age-seconds", "9999999999999", "--json"])
            .output()
            .unwrap();
        for p in [&proof_path, &bundle_path, &cfg_path] {
            let _ = std::fs::remove_file(p);
        }
        let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        let line = json["checks"].as_array().unwrap().iter().find(|c| c["name"] == "app-attest-validity").cloned();
        (json["verdict"].clone(), line.expect("app-attest-validity line")["status"].clone())
    };
    assert_eq!(run("leaf/2026-08-24T00:00:00Z", "in"), ("VALID".into(), "PASS".into()));
    assert_eq!(run("leaf/2026-08-27T00:00:00Z", "out"), ("INVALID".into(), "FAIL".into()));
}
