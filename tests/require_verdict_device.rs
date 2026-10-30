//! `--require-verdict` / `Report::spoofing_verdict` against real-device proofs.
//!
//! The proof-model-v2 captures in `test-vectors/proof-model-v2-device/` carry a
//! signed spoofing verdict: the Pixel 9 proofs are VERIFIED and the iPhone 11
//! proofs PLAUSIBLE. The disc proofs bind a disc query (`query_region` type 4)
//! while keeping the country-level claim, so a PLAUSIBLE disc answer verifies
//! exactly like a VERIFIED one unless the caller gates on the tier.
//!
//! `now_ms` is pinned to each proof's signed `proofAssembly` time.

use octet_verify::keys::hardware_pubkey_from_cert_chain;
use octet_verify::navigate::{LocationProof, LocationProofVerdict};
use octet_verify::prost::Message;
use octet_verify::verify::{verify, Report, RequiredVerdict, Status, VerifyOptions};

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/test-vectors/proof-model-v2-device");

fn load(file: &str) -> LocationProof {
    let bytes = std::fs::read(format!("{DIR}/{file}")).unwrap_or_else(|e| panic!("{file}: {e}"));
    LocationProof::decode(&*bytes).unwrap_or_else(|e| panic!("{file}: decode: {e}"))
}

fn run(proof: &LocationProof, require: Option<RequiredVerdict>) -> Report {
    let chain = &proof.device_attestation.as_ref().unwrap().certificate_chain;
    let hw = hardware_pubkey_from_cert_chain(chain).expect("hw key");
    let assembled = proof
        .stage_attestations
        .iter()
        .find(|s| s.stage == "proofAssembly")
        .expect("proofAssembly stage")
        .timestamp_ms;
    verify(
        proof,
        &VerifyOptions {
            now_ms: assembled + 1_000,
            max_age_s: 300,
            hardware_pubkey: Some(&hw),
            hw_key_source: "certificate_chain[0]",
            expect_region: None,
            expect_region_type: None,
            expect_region_contains: None,
            expect_region_contains_height_m: None,
            session_nonce: None,
            require_session_binding: false,
            require_schema_v2: false,
            require_attestation: false,
            allow_unbound_app_attest: false,
            require_verdict: require,
            validation_window: None,
        },
    )
}

fn status(r: &Report, name: &str) -> Option<Status> {
    r.checks.iter().find(|c| c.name == name).map(|c| c.status)
}

/// A VERIFIED disc answer (Pixel 9) meets `--require-verdict verified`, and its
/// tier is labelled VERIFIED.
#[test]
fn verified_disc_meets_require_verified() {
    let p = load("android-pixel9/disc_inside_100km.bin");
    let r = run(&p, Some(RequiredVerdict::Verified));
    assert_eq!(r.spoofing_verdict(), Some(LocationProofVerdict::Verified));
    assert_eq!(status(&r, "verdict-required"), Some(Status::Pass));
    assert_eq!(status(&r, "verdict-tier"), Some(Status::Pass));
    assert!(r.is_authentic());
}

/// Golden vector: a PLAUSIBLE disc answer (iPhone 11) verifies VALID by default
/// with a `verdict-tier` PASS label (no WARN), FAILs `--require-verdict verified`, and meets
/// `--require-verdict plausible`. Holds for all three disc outcomes.
#[test]
fn plausible_disc_warns_and_fails_require_verified() {
    for file in [
        "ios-iphone11/disc_inside_100km.bin",
        "ios-iphone11/disc_outside_vienna_2km.bin",
        "ios-iphone11/disc_straddle_1m.bin",
    ] {
        let p = load(file);

        let r = run(&p, None);
        assert!(r.is_authentic(), "{file}: VALID without a requirement");
        assert_eq!(r.spoofing_verdict(), Some(LocationProofVerdict::Plausible), "{file}");
        assert_eq!(status(&r, "verdict-tier"), Some(Status::Pass), "{file}");
        assert_eq!(r.count(Status::Warn), 0, "{file}: a PLAUSIBLE disc answer adds no WARN");
        assert_eq!(status(&r, "verdict-required"), None, "{file}");

        let r = run(&p, Some(RequiredVerdict::Verified));
        assert_eq!(status(&r, "verdict-required"), Some(Status::Fail), "{file}");
        assert!(!r.is_valid(), "{file}: PLAUSIBLE must not pass require verified");

        let r = run(&p, Some(RequiredVerdict::Plausible));
        assert_eq!(status(&r, "verdict-required"), Some(Status::Pass), "{file}");
        assert!(r.is_authentic(), "{file}");
    }
}

/// A PLAUSIBLE area proof (no disc query, country level) is not a disc answer:
/// no WARN. The tier is still surfaced and enforceable.
#[test]
fn plausible_area_proof_is_not_flagged_but_is_enforceable() {
    let p = load("ios-iphone11/area_country.bin");
    let r = run(&p, None);
    assert_eq!(r.spoofing_verdict(), Some(LocationProofVerdict::Plausible));
    assert_eq!(status(&r, "verdict-tier"), None);
    let r = run(&p, Some(RequiredVerdict::Verified));
    assert_eq!(status(&r, "verdict-required"), Some(Status::Fail));
}

/// Editing a PLAUSIBLE disc's verdict to VERIFIED breaks the semantic binding,
/// so the verdict is no longer trusted: `spoofing_verdict()` is `None` and the
/// requirement FAILs closed with the unbound detail.
#[test]
fn plausible_edited_to_verified_fails_closed() {
    let mut p = load("ios-iphone11/disc_inside_100km.bin");
    p.spoofing_verdict = LocationProofVerdict::Verified as i32;
    let r = run(&p, Some(RequiredVerdict::Verified));
    assert_eq!(status(&r, "semantic-binding"), Some(Status::Fail));
    assert_eq!(r.spoofing_verdict(), None);
    let c = r.checks.iter().find(|c| c.name == "verdict-required").unwrap();
    assert_eq!(c.status, Status::Fail);
    assert!(c.detail.contains("not semantically bound"), "{}", c.detail);
}
