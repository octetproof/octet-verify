//! CLI wiring for the online Play Integrity check (#12, feature `playintegrity`).
//! The decode logic + §6 mapping are unit-tested in `src/integrity.rs`; here we
//! only confirm the flags reach the check and the no-network paths behave (a
//! green PASS needs a live decode endpoint, exercised in the dev e2e).
#![cfg(feature = "playintegrity")]

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_octet-verify");
// A real proof that decodes + core-verifies (bare-point Android Tier-2 vector).
const PROOF: &[u8] = include_bytes!("../test-vectors/attestation/tier2-gateway-android-pixel9.bin");
const HUGE_MAX_AGE: &str = "9999999999999";

fn tmp(name: &str) -> std::path::PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("oxv12-{}-{name}", std::process::id()));
    std::fs::write(&p, PROOF).unwrap();
    p
}

#[test]
fn incomplete_integrity_config_is_not_checked_without_network() {
    // --integrity-package alone (no url/token) → NOT-CHECKED "incomplete", and it
    // returns before any HTTP, so this needs no endpoint.
    let p = tmp("proof.bin");
    let out = Command::new(BIN)
        .arg(&p)
        .args(["--integrity-package", "com.octetproof.sample"])
        .args(["--max-age-seconds", HUGE_MAX_AGE])
        .arg("--json")
        .output()
        .expect("run verifier");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        s.contains(r#""name": "play-integrity", "status": "NOT-CHECKED""#),
        "expected play-integrity NOT-CHECKED; got:\n{s}"
    );
    assert!(s.contains("incomplete"), "expected an 'incomplete config' detail; got:\n{s}");
    let _ = std::fs::remove_file(&p);
}

#[test]
fn no_integrity_flags_means_no_play_integrity_line() {
    let p = tmp("proof2.bin");
    let out = Command::new(BIN)
        .arg(&p)
        .args(["--max-age-seconds", HUGE_MAX_AGE])
        .arg("--json")
        .output()
        .expect("run verifier");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(
        !s.contains("play-integrity"),
        "no --integrity-* flags ⇒ no play-integrity check should appear; got:\n{s}"
    );
    let _ = std::fs::remove_file(&p);
}
