//! Real-device proofs from **OctetSDK 3.0.0**, verified end to end.
//!
//! Nine signed `LocationProof`s captured on an iPhone 11 (App Attest) and a
//! Pixel 9 (StrongBox): area proofs and `isWithin` country proofs, all with
//! `sdk_version` 3.0.0 and semantic-binding v2 (v3 is dark in 3.0.0). They pin
//! that the current SDK's output verifies here. `now_ms` is pinned to each
//! proof's signed `proofAssembly` time, so a committed proof never goes stale.
//! See `test-vectors/sdk-3.0.0-device/README.md`.

use octet_verify::keys::hardware_pubkey_from_cert_chain;
use octet_verify::navigate::LocationProof;
use octet_verify::prost::Message;
use octet_verify::verify::{verify, Report, SignedLocationVerdict, Status, VerifyOptions};

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/test-vectors/sdk-3.0.0-device");

fn status_of(r: &Report, name: &str) -> Status {
    r.checks.iter().find(|c| c.name == name)
        .unwrap_or_else(|| panic!("report has a `{name}` check")).status
}

fn proof_time_ms(p: &LocationProof) -> i64 {
    p.stage_attestations.iter().find(|s| s.stage == "proofAssembly")
        .map(|s| s.timestamp_ms)
        .expect("proof has a proofAssembly stage")
}

fn vectors() -> Vec<serde_json::Value> {
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(format!("{DIR}/fixtures.json")).unwrap()).unwrap();
    let v = doc["vectors"].as_array().expect("vectors array").clone();
    assert_eq!(v.len(), 9, "expected 9 SDK 3.0.0 device proofs");
    v
}

fn load(file: &str) -> LocationProof {
    let bytes = std::fs::read(format!("{DIR}/{file}")).unwrap_or_else(|e| panic!("{file}: read: {e}"));
    LocationProof::decode(&*bytes).unwrap_or_else(|e| panic!("{file}: decode: {e}"))
}

#[test]
fn sdk_3_0_0_real_device_proofs_verify() {
    for v in vectors() {
        let file = v["file"].as_str().unwrap();
        let proof = load(file);
        assert_eq!(proof.sdk_version, "3.0.0", "{file}: sdk_version");
        assert_eq!(proof.platform, v["platform"].as_str().unwrap(), "{file}: platform");

        let chain = &proof.device_attestation.as_ref()
            .unwrap_or_else(|| panic!("{file}: device_attestation")).certificate_chain;
        let hw = hardware_pubkey_from_cert_chain(chain).unwrap_or_else(|e| panic!("{file}: hw key: {e}"));
        let claimed = Some(v["claimed_region"].as_str().unwrap());
        let opts = VerifyOptions {
            now_ms: proof_time_ms(&proof) + 1_000,
            max_age_s: 300,
            hardware_pubkey: Some(&hw),
            hw_key_source: "certificate_chain[0]",
            // An earth claim has no identifier to match, so it is asserted by type.
            expect_region: claimed.filter(|c| *c != "earth"),
            expect_region_type: claimed.filter(|c| *c == "earth"),
            expect_region_contains: None,
            expect_region_contains_height_m: None,
            session_nonce: None,
            require_session_binding: false,
            require_schema_v2: true,
            require_attestation: false,
            allow_unbound_app_attest: false,
            require_verdict: None,
            validation_window: None,
        };
        let r = verify(&proof, &opts);

        assert!(r.is_valid(), "{file}: expected VALID, failing: {:?}",
            r.checks.iter().filter(|c| c.status == Status::Fail).map(|c| c.name).collect::<Vec<_>>());
        assert_eq!(status_of(&r, "region-claim"), Status::Pass, "{file}: claims {:?}", claimed);
        assert_eq!(status_of(&r, "stage-signatures"), Status::Pass, "{file}: stage signatures");
        assert_eq!(status_of(&r, "semantic-binding"), Status::Pass, "{file}: semantic-binding");
        assert!(r.is_semantically_bound(), "{file}: semantically bound");
        assert_eq!(r.query_region(), None, "{file}: v3 is dark, so no query region is bound");
        let want = match v["location_verdict"].as_str() {
            None => None,
            Some("Inside") => Some(SignedLocationVerdict::Inside),
            Some(other) => panic!("{file}: unexpected verdict {other}"),
        };
        assert_eq!(r.location_verdict(), want, "{file}: signed location verdict");
    }
}

/// A time inside the iOS key's App Attest leaf validity (2026-10-07 13:13:47 to
/// 2026-10-10 13:13:47 UTC): 2026-10-08 00:00 UTC, standing in for the time the
/// enrolment bundle was anchored.
#[cfg(feature = "appattest")]
const ENROLLED_BY_MS: i64 = 1_791_417_600_000;

/// iOS: the key's enrolment bundle (JSON and proto, from the SDK) enrols the App
/// Attest key, and every assertion-only iOS proof then passes App Attest with
/// attestation required (the bound assertion form). Dating the chain shows the
/// window's meaning on real data: the key was attested on 2026-10-07 and its leaf
/// expired on 2026-10-10, before the proofs (2026-10-13), so the window must end
/// at the anchoring time, not at the proof's time.
#[cfg(feature = "appattest")]
#[test]
fn sdk_3_0_0_ios_app_attest_with_the_enrolment_bundle() {
    use octet_verify::appattest_layer::{
        appattest_enroll, appattest_validity_check, bundle_from_json, bundle_from_proto,
        set_app_attest_validity, verify_attested_cached, AcceptEnvironment, AppAttestWindow, Expectation,
    };
    let expect = Expectation::new("6ZH5F97PWU", "com.octetproof.sample", AcceptEnvironment::Any);
    let json = std::fs::read(format!("{DIR}/ios-iphone11/enrolment_bundle.json")).unwrap();
    let proto = std::fs::read(format!("{DIR}/ios-iphone11/enrolment_bundle.pb")).unwrap();
    for (form, bundle) in [("json", bundle_from_json(&json).unwrap()), ("proto", bundle_from_proto(&proto).unwrap())] {
        let object = bundle.app_attest_attestation.clone().expect("bundle carries the attestation object");
        for v in vectors().iter().filter(|v| v["platform"] == "ios") {
            let file = v["file"].as_str().unwrap();
            let label = format!("{file} [{form}]");
            let proof = load(file);
            assert_eq!(proof.device_attestation.as_ref().unwrap().key_id, bundle.key_id, "{label}: same key");
            let key = appattest_enroll(&bundle, &expect).unwrap_or_else(|e| panic!("{label}: enrol: {e}"));
            let chain = &proof.device_attestation.as_ref().unwrap().certificate_chain;
            let hw = hardware_pubkey_from_cert_chain(chain).unwrap();
            let at = proof_time_ms(&proof);
            let opts = VerifyOptions {
                now_ms: at + 1_000,
                max_age_s: 300,
                hardware_pubkey: Some(&hw),
                hw_key_source: "certificate_chain[0]",
                expect_region: None,
                expect_region_type: None,
                expect_region_contains: None,
                expect_region_contains_height_m: None,
                session_nonce: None,
                require_session_binding: false,
                require_schema_v2: true,
                require_attestation: true,
                allow_unbound_app_attest: false,
                require_verdict: None,
                validation_window: None,
            };
            let (mut r, _) = verify_attested_cached(&proof, &opts, &expect, Some(&key));
            assert_eq!(status_of(&r, "app-attest"), Status::Pass, "{label}: app-attest");
            assert_eq!(status_of(&r, "attestation-required"), Status::Pass, "{label}: attestation required");
            assert!(r.is_attested() && r.is_valid(), "{label}: attested and VALID");
            assert_eq!(status_of(&r, "app-attest-validity"), Status::NotChecked, "{label}: undated by default");

            // The window ends when the object was anchored, at enrolment: the leaf
            // (2026-10-07..10) is valid there, so the line PASSes...
            let enrolled = AppAttestWindow { lower_ms: None, upper_ms: ENROLLED_BY_MS };
            assert!(set_app_attest_validity(&mut r, appattest_validity_check(&object, &enrolled)));
            assert_eq!(status_of(&r, "app-attest-validity"), Status::Pass, "{label}: valid when anchored");
            assert!(r.is_valid(), "{label}: still VALID once dated");
            // ...but the proofs were made after the leaf expired, so a window ending
            // at the proof's own time FAILs.
            let at_proof = appattest_validity_check(&object, &AppAttestWindow { lower_ms: None, upper_ms: at });
            assert_eq!(at_proof.status, Status::Fail, "{label}: leaf expired before the proof");
            assert!(at_proof.detail.contains("at the end"), "{label}: {}", at_proof.detail);
        }
    }
}

/// Android: the Keystore chain reaches a Google root and the field-2 signature
/// verifies, both judged at the proof's own signed time.
#[cfg(feature = "appattest")]
#[test]
fn sdk_3_0_0_android_hardware_attestation() {
    use octet_verify::appattest_layer::{attestation_root_check, device_signature_check};
    for v in vectors().iter().filter(|v| v["platform"] == "android") {
        let file = v["file"].as_str().unwrap();
        let proof = load(file);
        let chain = &proof.device_attestation.as_ref().unwrap().certificate_chain;
        let sec1 = hardware_pubkey_from_cert_chain(chain).unwrap().to_sec1_bytes();
        let at = (proof_time_ms(&proof) / 1000) as u64;
        let root = attestation_root_check(&proof, at, None, Some(&sec1));
        assert_eq!(root.status, Status::Pass, "{file}: attestation-root: {}", root.detail);
        let sig = device_signature_check(&proof, Some(&sec1));
        assert_eq!(sig.status, Status::Pass, "{file}: device-attestation-sig: {}", sig.detail);
    }
}
