//! Real-device **proof-model-v2** proofs, verified end to end.
//!
//! Ten signed `LocationProof`s captured on physical phones — an iPhone 11 (App
//! Attest, prod) and a Pixel 9 (StrongBox, dev), five each:
//! - two **area** proofs (`proveArea`): unbound (no `query_region`, verdict
//!   UNSPECIFIED), carrying the phone's country/subdivision claim;
//! - three **disc-verdict** proofs (`proveDiscVerdict`): bound to a disc via v3
//!   `query_region` type 4, with a signed **inside / outside / indeterminate**
//!   verdict (the straddle case).
//!
//! These pin that real-hardware proof-model-v2 output verifies here with the
//! queried region bound and surfaced, and that an unbound area proof is accepted
//! with no query and no verdict. `now_ms` is pinned to each proof's signed
//! `proofAssembly` time so a committed golden never goes stale. The verifier reads
//! the *signed* disc verdict; it does not recompute the geometry.

use octet_verify::keys::hardware_pubkey_from_cert_chain;
use octet_verify::navigate::LocationProof;
use octet_verify::prost::Message;
use octet_verify::verify::{verify, Report, SignedLocationVerdict, Status, VerifyOptions};

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
fn proof_model_v2_real_device_proofs() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/test-vectors/proof-model-v2-device");
    let doc: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(format!("{dir}/fixtures.json")).unwrap()).unwrap();
    let vectors = doc["vectors"].as_array().expect("vectors array");
    assert_eq!(vectors.len(), 10, "expected 10 real-device proof-model-v2 proofs");

    for v in vectors {
        let file = v["file"].as_str().unwrap();
        let kind = v["kind"].as_str().unwrap();
        let label = format!("{file} [{kind}]");
        let bytes = std::fs::read(format!("{dir}/{file}")).unwrap_or_else(|e| panic!("{label}: read: {e}"));
        let proof = LocationProof::decode(&*bytes).unwrap_or_else(|e| panic!("{label}: decode: {e}"));

        let chain = &proof.device_attestation.as_ref()
            .unwrap_or_else(|| panic!("{label}: device_attestation")).certificate_chain;
        let hw = hardware_pubkey_from_cert_chain(chain)
            .unwrap_or_else(|e| panic!("{label}: hw key: {e}"));

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

        assert!(r.is_valid(), "{label}: expected VALID, failing: {:?}",
            r.checks.iter().filter(|c| c.status == Status::Fail).map(|c| c.name).collect::<Vec<_>>());
        assert_eq!(status_of(&r, "stage-signatures"), Status::Pass, "{label}: stage signatures");
        assert_eq!(status_of(&r, "semantic-binding"), Status::Pass, "{label}: semantic-binding");
        assert_eq!(status_of(&r, "query-region"), Status::Pass, "{label}: query-region");

        match kind {
            "area" => {
                // Unbound: no query region, no signed verdict.
                assert_eq!(r.query_region(), None, "{label}: area proof binds no query");
                assert_eq!(r.location_verdict(), None, "{label}: area proof has no signed verdict");
            }
            "disc" => {
                // Bound to the disc; the signed verdict is surfaced.
                let want = match v["location_verdict"].as_str().unwrap() {
                    "Inside" => SignedLocationVerdict::Inside,
                    "Outside" => SignedLocationVerdict::Outside,
                    "Indeterminate" => SignedLocationVerdict::Indeterminate,
                    other => panic!("{label}: bad verdict {other}"),
                };
                assert_eq!(r.location_verdict(), Some(want), "{label}: location_verdict");
                let q = r.query_region().unwrap_or_else(|| panic!("{label}: disc Q exposed"));
                assert_eq!(q.region_type, 4, "{label}: disc query is type 4");
                assert_eq!(hex::encode(&q.region_id), v["query_region"]["region_id_hex"].as_str().unwrap(),
                    "{label}: disc q_id");
            }
            other => panic!("{label}: unknown kind {other}"),
        }
    }
}
