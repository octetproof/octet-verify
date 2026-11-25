//! `claim-privacy` through the CLI: the `claim_privacy` / `grid_level` JSON
//! fields, and `--require-private-claims` turning a legacy claim into a FAIL.

use std::fs;
use std::process::Command;

use octet_verify::navigate::{proof_region::Region, EllipseRegion, LatLon, LocationProof, ProofRegion};
use octet_verify::prost::Message;
use serde_json::Value;

const BIN: &str = env!("CARGO_BIN_EXE_octet-verify");

fn disc(lat: f64, lon: f64, r: f64) -> Vec<u8> {
    LocationProof {
        claimed_region: Some(ProofRegion {
            region: Some(Region::Ellipse(EllipseRegion {
                center: Some(LatLon { latitude: lat, longitude: lon }),
                semi_major_m: r,
                semi_minor_m: r,
                heading_deg: 0.0,
            })),
        }),
        ..Default::default()
    }
    .encode_to_vec()
}

fn run(bytes: &[u8], extra: &[&str]) -> (Option<i32>, Value) {
    let dir = std::env::temp_dir().join(format!("octet-verify-claim-privacy-{}", std::process::id()));
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join(format!("{}.bin", extra.len()));
    fs::write(&path, bytes).unwrap();
    let out = Command::new(BIN).arg(&path).arg("--json").args(extra).output().unwrap();
    let _ = fs::remove_file(&path);
    (out.status.code(), serde_json::from_slice(&out.stdout).unwrap())
}

fn status(j: &Value) -> &str {
    j["checks"].as_array().unwrap().iter().find(|c| c["name"] == "claim-privacy").unwrap()["status"].as_str().unwrap()
}

#[test]
fn json_fields_and_the_require_flag() {
    // A snapped level-10 disc (bucket 50 m, ρ_10 = 78 m).
    let snapped = disc(12.34521484375, 23.45654296875, 128.0);
    let (_, j) = run(&snapped, &[]);
    assert_eq!((j["claim_privacy"].as_str(), j["grid_level"].as_u64()), (Some("snapped"), Some(10)));
    assert_eq!(status(&j), "PASS");
    let (_, j) = run(&snapped, &["--require-private-claims"]);
    assert_eq!(status(&j), "PASS");

    // A device-centred disc: WARN by default, FAIL (exit 1) with the flag.
    let legacy = disc(12.345678901, 23.456789012, 90.0);
    let (_, j) = run(&legacy, &[]);
    assert_eq!((j["claim_privacy"].as_str(), j["grid_level"].as_u64()), (Some("legacy"), None));
    assert_eq!(status(&j), "WARN");
    let (code, j) = run(&legacy, &["--require-private-claims"]);
    assert_eq!(status(&j), "FAIL");
    assert_eq!(code, Some(1));
}
