//! Real-device semantic-binding **v3** proofs, verified end to end.
//!
//! Six signed `LocationProof`s captured on physical phones — an iPhone 11 (App
//! Attest, prod) and a Pixel 9 (StrongBox, dev) — one Country-AT (outside), one
//! Country-GB (inside) and one earth query from each. They pin that a *real*
//! device's v3 proof verifies in this crate with the queried region bound and
//! surfaced: the on-device producer and this verifier agree on live hardware, not
//! just on synthetic vectors.
//!
//! `now_ms` is pinned to each proof's signed `proofAssembly` time, so a committed
//! golden never goes stale. The hardware key is sourced from the proof's
//! `certificate_chain[0]` exactly as the CLI does (raw SEC1 for iOS, the X.509
//! attestation leaf for Android). Hardware **attestation-root** (the Android
//! StrongBox chain to a Google root) is only evaluated with `--features appattest`,
//! so that assertion is gated on the feature; the v3 assertions below hold on every
//! build.

use octet_verify::keys::hardware_pubkey_from_cert_chain;
use octet_verify::navigate::LocationProof;
use octet_verify::prost::Message;
use octet_verify::verify::{verify, Report, SignedLocationVerdict, Status, VerifyOptions};

const FIXTURES: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/test-vectors/semantic-binding-v3-device/fixtures.json");

fn status_of(r: &Report, name: &str) -> Status {
    r.checks.iter().find(|c| c.name == name)
        .unwrap_or_else(|| panic!("report has a `{name}` check")).status
}

fn stage_ts(p: &LocationProof, name: &str) -> i64 {
    p.stage_attestations.iter().find(|s| s.stage == name)
        .map(|s| s.timestamp_ms)
        .unwrap_or_else(|| panic!("proof has a {name} stage"))
}

#[test]
fn semantic_binding_v3_real_device_proofs() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/test-vectors/semantic-binding-v3-device");
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(FIXTURES).expect("fixtures.json")).unwrap();
    let vectors = doc["vectors"].as_array().expect("vectors array");
    assert_eq!(vectors.len(), 6, "expected 6 real-device v3 proofs");

    for v in vectors {
        let file = v["file"].as_str().unwrap();
        let label = format!("{} [{}]", file, v["query"].as_str().unwrap());
        let bytes = std::fs::read(format!("{dir}/{file}")).unwrap_or_else(|e| panic!("{label}: read: {e}"));
        let proof = LocationProof::decode(&*bytes).unwrap_or_else(|e| panic!("{label}: decode: {e}"));

        let chain = &proof.device_attestation.as_ref()
            .unwrap_or_else(|| panic!("{label}: device_attestation")).certificate_chain;
        let hw = hardware_pubkey_from_cert_chain(chain)
            .unwrap_or_else(|e| panic!("{label}: hw key from chain: {e}"));

        let opts = VerifyOptions {
            now_ms: stage_ts(&proof, "proofAssembly") + 1_000,
            max_age_s: 300,
            hardware_pubkey: Some(&hw),
            hw_key_source: "certificate_chain[0]",
            expect_region: None,
            expect_region_type: None,
            expect_region_contains: None,
            session_nonce: None,
            require_session_binding: false,
            require_schema_v2: false,
            require_attestation: false,
            require_verdict: None,
            validation_window: None,
        };
        let r = verify(&proof, &opts);

        // The v3 core — holds on every build.
        assert!(r.is_valid(), "{label}: expected VALID, failing: {:?}",
            r.checks.iter().filter(|c| c.status == Status::Fail).map(|c| c.name).collect::<Vec<_>>());
        assert_eq!(status_of(&r, "stage-signatures"), Status::Pass, "{label}: stage signatures");
        assert_eq!(status_of(&r, "semantic-binding"), Status::Pass, "{label}: semantic-binding (v3)");
        assert_eq!(status_of(&r, "query-region"), Status::Pass, "{label}: query-region");

        // Signed verdict.
        let want_verdict = match v["location_verdict"].as_str().unwrap() {
            "Inside" => SignedLocationVerdict::Inside,
            "Outside" => SignedLocationVerdict::Outside,
            "Indeterminate" => SignedLocationVerdict::Indeterminate,
            other => panic!("{label}: bad expected verdict {other}"),
        };
        assert_eq!(r.location_verdict(), Some(want_verdict), "{label}: location_verdict");

        // Bound queried region, exposed and matching.
        let q = r.query_region().unwrap_or_else(|| panic!("{label}: query_region exposed"));
        assert_eq!(q.region_type, v["query_region_type"].as_u64().unwrap() as u32, "{label}: q_type");
        assert_eq!(hex::encode(&q.region_id), v["query_region_id_hex"].as_str().unwrap(), "{label}: q_id");

        // (The Pixel proofs also chain to a Google attestation root — the hardware
        // attestation layer, not this bare-verify v3 path; `fixtures.json` records
        // it and the CLI confirms it under `--features appattest`. Not asserted here
        // because it is a separate concern from the v3 queried-region binding.)
    }
}
