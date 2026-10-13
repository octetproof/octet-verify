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
//! (Apple App Attest). The App Attest chain is verified by signature only: its
//! leaf certificate is valid for about 3 days, but the verifier does not check
//! those dates and reports that as the `app-attest-validity` NOT-CHECKED line. So
//! only proof freshness is time-sensitive here, and a fixed `now` + a generous
//! window keeps this deterministic.
#![cfg(feature = "appattest")]

use octet_verify::appattest_layer::{
    appattest_validity_check, set_app_attest_validity, verify_attested, AcceptEnvironment, AppAttestWindow,
    Expectation, APP_ATTEST_VALIDITY,
};
use octet_verify::keys::hardware_pubkey_from_cert_chain;
use octet_verify::navigate::LocationProof;
use octet_verify::prost::Message;
use octet_verify::verify::{Status, ValidationWindow, VerifyOptions};

const PROOF: &[u8] = include_bytes!("../test-vectors/attestation/ios-appattest.bin");

/// Pinned well after the proof's signed time. App Attest certificate dates are not
/// checked, so a generous freshness window is all that is needed for determinism.
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
        require_verdict: None,
        validation_window: None,
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

/// An `app-attest` PASS verifies the chain's signatures, never its validity dates
/// (the leaf in this vector is valid 2026-08-23 11:13 to 2026-08-26 11:13 UTC, and
/// `now` is pinned years later). The report says so with an `app-attest-validity`
/// NOT-CHECKED line in every mode, without changing the verdict.
#[test]
fn app_attest_pass_reports_validity_dates_as_not_checked() {
    let hw = se_signing_key();
    let p = proof();
    let signed_ms = p
        .stage_attestations
        .iter()
        .map(|s| s.timestamp_ms)
        .max()
        .expect("proof has stages");
    let window = ValidationWindow::new(signed_ms - 300_000, signed_ms + 3_600_000).expect("ordered window");
    let modes: [(&str, VerifyOptions<'_>); 3] = [
        ("default", opts(&hw, false)),
        ("require-attestation", opts(&hw, true)),
        ("window", VerifyOptions { validation_window: Some(window), ..opts(&hw, true) }),
    ];
    for (mode, o) in modes {
        let report = verify_attested(&p, &o, &expectation());
        assert_eq!(status(&report, "app-attest"), Some(Status::Pass), "{mode}");
        let line = report
            .checks
            .iter()
            .find(|c| c.name == APP_ATTEST_VALIDITY)
            .unwrap_or_else(|| panic!("{mode}: no {APP_ATTEST_VALIDITY} line"));
        assert_eq!(line.status, Status::NotChecked, "{mode}");
        assert!(line.detail.contains("validity dates not checked"), "{mode}: {}", line.detail);
        assert!(report.is_valid(), "{mode}: the NOT-CHECKED line must not change the verdict");
        assert!(report.is_attested(), "{mode}");
        assert!(report.is_authentic(), "{mode}");
        if o.require_attestation {
            assert_eq!(status(&report, "attestation-required"), Some(Status::Pass), "{mode}");
        }
    }
}

/// The line accompanies a PASS only: when `app-attest` does not pass, there is no
/// verified chain whose dates could be in question.
#[test]
fn no_validity_line_without_an_app_attest_pass() {
    let wrong = p256::ecdsa::SigningKey::from_slice(&[9u8; 32])
        .unwrap()
        .verifying_key()
        .to_owned();
    let report = verify_attested(&proof(), &opts(&wrong, true), &expectation());
    assert_ne!(status(&report, "app-attest"), Some(Status::Pass));
    assert_eq!(status(&report, APP_ATTEST_VALIDITY), None);
}

/// The CLI runs `appattest_check` itself (not `verify_attested`), so it must add
/// the `app-attest-validity` line too: right after the `app-attest` PASS, with the
/// verdict unchanged.
#[test]
fn cli_reports_validity_dates_as_not_checked_after_app_attest_pass() {
    let cfg = std::env::temp_dir().join(format!("oxv-validity-{}.toml", std::process::id()));
    std::fs::write(
        &cfg,
        "[app_attest]\nteam_id = \"6ZH5F97PWU\"\nbundle_id = \"com.octetproof.sample\"\nenvironment = \"any\"\n",
    )
    .unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_octet-verify"))
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/test-vectors/attestation/ios-appattest.bin"))
        .args(["--app-attest-config", cfg.to_str().unwrap()])
        .args(["--max-age-seconds", "9999999999999"])
        .arg("--json")
        .output()
        .expect("run the CLI");
    let _ = std::fs::remove_file(&cfg);
    let json: serde_json::Value = serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("CLI JSON: {e}; stderr:\n{}", String::from_utf8_lossy(&out.stderr)));
    assert_eq!(json["verdict"], "VALID");
    let checks = json["checks"].as_array().expect("checks array");
    let i = checks.iter().position(|c| c["name"] == "app-attest").expect("app-attest line");
    assert_eq!(checks[i]["status"], "PASS");
    assert_eq!(checks[i + 1]["name"], APP_ATTEST_VALIDITY);
    assert_eq!(checks[i + 1]["status"], "NOT-CHECKED");
}

// --- dating the App Attest chain over a caller-given window ---
//
// This vector's leaf is valid 2026-08-23 11:13:52 to 2026-08-26 11:13:52 UTC; the
// intermediate and root are valid far longer, so the leaf bounds the chain.
const LEAF_NOT_BEFORE_MS: i64 = 1_787_483_632_000;
const LEAF_NOT_AFTER_MS: i64 = 1_787_742_832_000;

fn object() -> Vec<u8> {
    proof().device_attestation.unwrap().app_attest_attestation.unwrap()
}

fn window(lower_ms: Option<i64>, upper_ms: i64) -> AppAttestWindow {
    AppAttestWindow { lower_ms, upper_ms }
}

#[test]
fn validity_window_passes_inside_the_leaf_and_fails_outside() {
    let obj = object();
    let day = 86_400_000;
    // Lower defaults to the leaf's notBefore; an anchor a day later is inside.
    let c = appattest_validity_check(&obj, &window(None, LEAF_NOT_BEFORE_MS + day));
    assert_eq!(c.name, APP_ATTEST_VALIDITY);
    assert_eq!(c.status, Status::Pass, "{}", c.detail);
    assert!(c.detail.contains("the leaf's notBefore") && c.detail.contains("caller's"), "{}", c.detail);
    // Exactly the leaf's notAfter is still inside (inclusive).
    assert_eq!(appattest_validity_check(&obj, &window(None, LEAF_NOT_AFTER_MS)).status, Status::Pass);
    // Anchored after the leaf expired: FAIL at the end.
    let late = appattest_validity_check(&obj, &window(None, LEAF_NOT_AFTER_MS + 1));
    assert_eq!(late.status, Status::Fail);
    assert!(late.detail.contains("at the end"), "{}", late.detail);
    // A given lower bound before the leaf existed: FAIL at the start.
    let early = appattest_validity_check(&obj, &window(Some(LEAF_NOT_BEFORE_MS - 1000), LEAF_NOT_BEFORE_MS + day));
    assert_eq!(early.status, Status::Fail);
    assert!(early.detail.contains("at the start"), "{}", early.detail);
    // Reversed, and an object that is not one.
    let rev = appattest_validity_check(&obj, &window(Some(LEAF_NOT_BEFORE_MS + day), LEAF_NOT_BEFORE_MS));
    assert_eq!(rev.status, Status::Fail);
    assert!(rev.detail.contains("ends before it starts"), "{}", rev.detail);
    assert_eq!(appattest_validity_check(b"junk", &window(None, LEAF_NOT_BEFORE_MS)).status, Status::Fail);
}

#[test]
fn set_app_attest_validity_replaces_the_line_only_after_a_pass() {
    let hw = se_signing_key();
    let mut report = verify_attested(&proof(), &opts(&hw, false), &expectation());
    let n = report.checks.len();
    let dated = appattest_validity_check(&object(), &window(None, LEAF_NOT_BEFORE_MS + 3_600_000));
    assert!(set_app_attest_validity(&mut report, dated));
    assert_eq!(report.checks.len(), n, "replaced, not added");
    assert_eq!(status(&report, APP_ATTEST_VALIDITY), Some(Status::Pass));
    assert!(report.is_valid());
    // A FAIL makes the report invalid.
    let late = appattest_validity_check(&object(), &window(None, LEAF_NOT_AFTER_MS + 1));
    assert!(set_app_attest_validity(&mut report, late));
    assert!(!report.is_valid(), "an attestation anchored after its leaf expired must not verify");
    // No app-attest PASS (wrong app) → no line to replace.
    let other = Expectation::new("6ZH5F97PWU", "com.example.other", AcceptEnvironment::Any);
    let mut failed = verify_attested(&proof(), &opts(&hw, false), &other);
    let dated = appattest_validity_check(&object(), &window(None, LEAF_NOT_BEFORE_MS));
    assert!(!set_app_attest_validity(&mut failed, dated));
    assert_eq!(status(&failed, APP_ATTEST_VALIDITY), None);
}

fn cli(extra: &[&str]) -> (serde_json::Value, String, bool) {
    let cfg = std::env::temp_dir().join(format!("oxv-aaw-{}-{}.toml", std::process::id(), extra.join("_").len()));
    std::fs::write(
        &cfg,
        "[app_attest]\nteam_id = \"6ZH5F97PWU\"\nbundle_id = \"com.octetproof.sample\"\nenvironment = \"any\"\n",
    )
    .unwrap();
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_octet-verify"))
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/test-vectors/attestation/ios-appattest.bin"))
        .args(["--app-attest-config", cfg.to_str().unwrap()])
        .args(["--max-age-seconds", "9999999999999", "--json"])
        .args(extra)
        .output()
        .expect("run the CLI");
    let _ = std::fs::remove_file(&cfg);
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    (serde_json::from_slice(&out.stdout).unwrap_or(serde_json::Value::Null), stderr, out.status.success())
}

fn cli_line(json: &serde_json::Value, name: &str) -> serde_json::Value {
    json["checks"].as_array().unwrap().iter().find(|c| c["name"] == name).cloned().unwrap_or_default()
}

#[test]
fn cli_app_attest_window_dates_the_chain() {
    let (ok, _, _) = cli(&["--app-attest-window", "leaf/2026-08-25T00:00:00Z"]);
    assert_eq!(cli_line(&ok, APP_ATTEST_VALIDITY)["status"], "PASS", "{ok}");
    assert_eq!(ok["verdict"], "VALID");
    let (late, _, _) = cli(&["--app-attest-window", "2026-08-23T12:00:00Z/2026-09-01T00:00:00Z"]);
    assert_eq!(cli_line(&late, APP_ATTEST_VALIDITY)["status"], "FAIL", "{late}");
    assert_eq!(late["verdict"], "INVALID");
}

#[test]
fn cli_app_attest_window_usage_errors() {
    let (_, err, ok) = cli(&["--app-attest-window", "2026-09-01T00:00:00Z/2026-08-25T00:00:00Z"]);
    assert!(!ok && err.contains("start is after end"), "{err}");
    let (_, err, ok) = cli(&["--app-attest-window", "leaf"]);
    assert!(!ok && err.contains("expected <lower|leaf>/<upper>"), "{err}");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_octet-verify"))
        .arg(concat!(env!("CARGO_MANIFEST_DIR"), "/test-vectors/attestation/ios-appattest.bin"))
        .args(["--app-attest-window", "leaf/2026-08-25T00:00:00Z"])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&out.stderr).contains("requires --app-attest-config"));
}
