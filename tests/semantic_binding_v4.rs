//! Semantic-binding v4: the proof commits to its licence (field 21).
//!
//! A signed synthetic proof built from the first golden vector in
//! `test-vectors/semantic-binding-v4/vectors.json` runs through the CLI: the
//! committed licence is reported in `--json`, `--expect-license` passes only on
//! the exact licence, and an edited or duplicated field 21 is refused.

use std::fs;
use std::path::Path;
use std::process::Command;

use octet_verify::crypto::sha256;
use octet_verify::navigate::{
    proof_region::Region, DeviceAttestation, DeviceIntegrityVerdict, EllipseRegion, LatLon, LocationProof,
    ProofRegion, RegionRef, StageAttestation,
};
use octet_verify::prost::Message;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_octet-verify");
const VECTORS: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/test-vectors/semantic-binding-v4/vectors.json");
const LICENSE_A: &str = "7c9e6679-7425-40de-944b-e07fc1f90ae7";
const LICENSE_B: &str = "1b4e28ba-2fa1-41d2-883f-0016d3cca427";

fn signed_stage(sk: &SigningKey, name: &str, data_hash: Vec<u8>, prev: Option<Vec<u8>>) -> StageAttestation {
    let mut m = Vec::new();
    m.extend_from_slice(name.as_bytes());
    m.extend_from_slice(&data_hash);
    m.extend_from_slice(&0i64.to_be_bytes());
    if let Some(p) = &prev {
        m.extend_from_slice(p);
    }
    let sig: Signature = sk.sign(&m);
    StageAttestation { stage: name.into(), timestamp_ms: 0, data_hash, signature: sig.to_bytes().to_vec(), previous_hash: prev }
}

/// (signed proof for the `v4_disc_inside` vector, SEC1 key). The semanticFields
/// stage hash is the vector's pinned v4 stage hash.
fn signed_proof() -> (LocationProof, Vec<u8>) {
    let doc: Value = serde_json::from_str(&fs::read_to_string(VECTORS).unwrap()).unwrap();
    let v = &doc["vectors"][0];
    assert_eq!(v["name"], "v4_disc_inside");
    let inp = &v["input"];
    let c = &inp["claimed_region"];
    assert_eq!(c["kind"], "ellipse");

    let sk = SigningKey::from_slice(&[9u8; 32]).unwrap();
    let commitment = hex::decode(inp["commitment_hex"].as_str().unwrap()).unwrap();
    let nullifier = vec![0x1Au8; 32];
    let s0 = signed_stage(&sk, "spoofDetection", sha256(b"verdict").to_vec(), None);
    let sem = hex::decode(v["signed"]["stage_hash_hex"].as_str().unwrap()).unwrap();
    let s1 = signed_stage(&sk, "semanticFields", sem, Some(s0.data_hash.clone()));
    let s2 = signed_stage(&sk, "commitment", sha256(&commitment).to_vec(), Some(s1.data_hash.clone()));
    let s3 = signed_stage(&sk, "nullifier", sha256(&nullifier).to_vec(), Some(s2.data_hash.clone()));
    let concat: Vec<u8> = [&s0, &s1, &s2, &s3].iter().flat_map(|s| s.signature.clone()).collect();
    let asm = signed_stage(&sk, "proofAssembly", sha256(&concat).to_vec(), Some(s3.data_hash.clone()));

    let proof = LocationProof {
        id: "semantic-binding-v4".into(),
        spoofing_verdict: inp["spoofing_verdict"].as_i64().unwrap() as i32,
        level: inp["level"].as_i64().unwrap() as i32,
        position_commitment: commitment,
        nullifier,
        claimed_region: Some(ProofRegion {
            region: Some(Region::Ellipse(EllipseRegion {
                center: Some(LatLon { latitude: c["lat"].as_f64().unwrap(), longitude: c["lon"].as_f64().unwrap() }),
                semi_major_m: c["semi_major_m"].as_f64().unwrap(),
                semi_minor_m: c["semi_minor_m"].as_f64().unwrap(),
                heading_deg: c["heading_deg"].as_f64().unwrap(),
            })),
        }),
        location_verdict: inp["location_verdict"].as_i64().unwrap() as i32,
        query_region: Some(RegionRef {
            region_type: v["query_region"]["region_type"].as_u64().unwrap() as u32,
            region_id: hex::decode(v["query_region"]["region_id_hex"].as_str().unwrap()).unwrap(),
        }),
        device_attestation: Some(DeviceAttestation {
            integrity_verdict: Some(DeviceIntegrityVerdict {
                status: inp["integrity_status"].as_i64().unwrap() as i32,
                ..Default::default()
            }),
            ..Default::default()
        }),
        committed_license_id: LICENSE_A.into(),
        stage_attestations: vec![s0, s1, s2, s3, asm],
        platform: "ios".into(),
        ..Default::default()
    };
    (proof, sk.verifying_key().to_encoded_point(false).as_bytes().to_vec())
}

fn run(dir: &Path, bytes: &[u8], extra: &[&str]) -> (Option<i32>, Value) {
    fs::write(dir.join("proof.bin"), bytes).unwrap();
    let out = Command::new(BIN)
        .arg(dir.join("proof.bin"))
        .args(["--hardware-pubkey", dir.join("hw.pubkey").to_str().unwrap(), "--max-age-seconds", "999999999999", "--json"])
        .args(extra)
        .output()
        .unwrap();
    (out.status.code(), serde_json::from_slice(&out.stdout).unwrap_or(Value::Null))
}

fn check<'a>(j: &'a Value, name: &str) -> &'a Value {
    j["checks"].as_array().unwrap().iter().find(|c| c["name"] == name).unwrap_or_else(|| panic!("no {name} check in {j}"))
}

fn tmpdir(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("octet-verify-v4-{tag}-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn cli_reports_the_committed_licence_and_expect_license_matches_exactly() {
    let (proof, sec1) = signed_proof();
    let dir = tmpdir("expect");
    fs::write(dir.join("hw.pubkey"), &sec1).unwrap();
    let bytes = proof.encode_to_vec();

    let (code, j) = run(&dir, &bytes, &[]);
    assert_eq!(code, Some(0), "{j}");
    assert_eq!(check(&j, "semantic-binding")["status"], "PASS");
    assert_eq!(j["committed_license"], LICENSE_A);
    assert_eq!(j["query_region"]["region_type"], 4);
    assert_eq!(j["location_verdict"], "inside");

    let (code, j) = run(&dir, &bytes, &["--expect-license", LICENSE_A]);
    assert_eq!(code, Some(0), "{j}");
    assert_eq!(check(&j, "license-match")["status"], "PASS");

    let (code, j) = run(&dir, &bytes, &["--expect-license", LICENSE_B]);
    assert_eq!(code, Some(1), "{j}");
    assert_eq!(check(&j, "license-match")["status"], "FAIL");

    // Not normalised: the same licence in uppercase is refused, not matched.
    let (code, j) = run(&dir, &bytes, &["--expect-license", &LICENSE_A.to_uppercase()]);
    assert_eq!(code, Some(1), "{j}");
    assert!(check(&j, "license-match")["detail"].as_str().unwrap().contains("not a canonical"), "{j}");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn an_edited_or_removed_licence_fails_and_reports_none() {
    let (proof, sec1) = signed_proof();
    let dir = tmpdir("edit");
    fs::write(dir.join("hw.pubkey"), &sec1).unwrap();

    for (label, lid) in [("edited", LICENSE_B), ("removed", "")] {
        let mut p = proof.clone();
        p.committed_license_id = lid.into();
        let (code, j) = run(&dir, &p.encode_to_vec(), &["--expect-license", LICENSE_A]);
        assert_eq!(code, Some(1), "{label}: {j}");
        assert_eq!(check(&j, "semantic-binding")["status"], "FAIL", "{label}");
        assert!(j["committed_license"].is_null(), "{label}: {j}");
        assert_eq!(check(&j, "license-match")["status"], "FAIL", "{label}");
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn a_duplicated_field21_is_refused_on_the_wire() {
    let (proof, sec1) = signed_proof();
    let dir = tmpdir("dup");
    fs::write(dir.join("hw.pubkey"), &sec1).unwrap();
    // Append a second field 21 (tag 0xaa 0x01, wire type 2) carrying licence B:
    // prost would keep it, while a first-copy parser would read licence A.
    let mut bytes = proof.encode_to_vec();
    bytes.extend_from_slice(&[0xaa, 0x01, LICENSE_B.len() as u8]);
    bytes.extend_from_slice(LICENSE_B.as_bytes());
    let (code, j) = run(&dir, &bytes, &[]);
    assert_eq!(code, Some(1), "{j}");
    assert!(j.to_string().contains("committed_license_id"), "{j}");
    let _ = fs::remove_dir_all(&dir);
}
