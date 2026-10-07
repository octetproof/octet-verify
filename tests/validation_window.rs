//! Historical verification of a real Android proof with a validation window.
//!
//! `test-vectors/attestation/pixel9-strongbox.bin` is a genuine Pixel 9
//! (StrongBox) proof whose signed `proofAssembly` time is 2026-07-29T11:42:21.355Z.
//! The certificates in its key-attestation chain are valid for a short period
//! only, so verifying it against the current time FAILs `attestation-root` and
//! `freshness`. A validation window around the signing time makes it VALID again,
//! and a window that extends past the certificates' expiry FAILs at that bound.
#![cfg(feature = "appattest")]

use std::process::Command;

use octet_verify::appattest_layer::attestation_root_check_window;
use octet_verify::keys::hardware_pubkey_from_cert_chain;
use octet_verify::navigate::LocationProof;
use octet_verify::prost::Message;
use octet_verify::verify::{Status, ValidationWindow};

const BIN: &str = env!("CARGO_BIN_EXE_octet-verify");
const VECTOR: &str = "test-vectors/attestation/pixel9-strongbox.bin";
const PROOF: &[u8] = include_bytes!("../test-vectors/attestation/pixel9-strongbox.bin");

/// The proof's signed `proofAssembly` time, Unix milliseconds.
const SIGNED_MS: i64 = 1_785_325_341_355;
/// A day in milliseconds.
const DAY_MS: i64 = 86_400_000;

fn proof() -> LocationProof {
    LocationProof::decode(PROOF).expect("vector decodes")
}

fn signing_key_sec1() -> Vec<u8> {
    let p = proof();
    let chain = &p.device_attestation.as_ref().expect("has device attestation").certificate_chain;
    hardware_pubkey_from_cert_chain(chain).expect("leaf key").to_sec1_bytes().to_vec()
}

fn chain_check(from: i64, to: i64) -> octet_verify::verify::Check {
    let w = ValidationWindow::new(from, to).expect("ordered window");
    attestation_root_check_window(&proof(), w, &[], Some(&signing_key_sec1()))
}

#[test]
fn chain_is_valid_over_a_window_around_the_signing_time() {
    let c = chain_check(SIGNED_MS - 5 * 60_000, SIGNED_MS + 6 * 3_600_000);
    assert_eq!(c.status, Status::Pass, "{}", c.detail);
    assert!(c.detail.contains("valid at both bounds"), "{}", c.detail);
}

#[test]
fn chain_fails_at_a_window_end_past_certificate_expiry() {
    // Ten years later, every certificate in a key-attestation chain has expired.
    let c = chain_check(SIGNED_MS - 5 * 60_000, SIGNED_MS + 3650 * DAY_MS);
    assert_eq!(c.status, Status::Fail, "{}", c.detail);
    assert!(c.detail.contains("at the end of the validation window"), "{}", c.detail);
}

#[test]
fn chain_fails_at_a_window_start_before_certificate_issue() {
    // A year earlier, the device's attestation certificate was not yet issued.
    let c = chain_check(SIGNED_MS - 365 * DAY_MS, SIGNED_MS);
    assert_eq!(c.status, Status::Fail, "{}", c.detail);
    assert!(c.detail.contains("at the start of the validation window"), "{}", c.detail);
}

fn run(args: &[&str]) -> (i32, String) {
    let out = Command::new(BIN).args(args).arg(VECTOR).output().expect("run octet-verify");
    (out.status.code().unwrap_or(-1), String::from_utf8_lossy(&out.stdout).into_owned())
}

#[test]
fn cli_window_verifies_the_archived_proof_as_valid() {
    let (code, out) = run(&["--window", "2026-07-29T11:37:21Z/2026-07-29T17:42:21Z"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("verdict: VALID"), "{out}");
}

#[test]
fn cli_android_window_report_has_no_app_attest_validity_line() {
    // Android chains are date-checked (at both bounds here). The App Attest
    // validity caveat belongs to iOS only.
    let (code, out) = run(&["--window", "2026-07-29T11:37:21Z/2026-07-29T17:42:21Z"]);
    assert_eq!(code, 0, "{out}");
    assert!(!out.contains("app-attest-validity"), "{out}");
    assert!(out.contains("valid at both bounds"), "{out}");
}

#[test]
fn cli_at_the_signing_time_verifies_the_archived_proof_as_valid() {
    let (code, out) = run(&["--at", "2026-07-29T11:42:21.355Z"]);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("verdict: VALID"), "{out}");
}

#[test]
fn cli_without_a_validation_time_rejects_the_archived_proof() {
    // Judged at the wall clock: the attestation certificates have expired and the
    // signed time is stale. Monotonic: once expired, this stays INVALID.
    let (code, out) = run(&[]);
    assert_eq!(code, 1, "{out}");
    assert!(out.contains("verdict: INVALID"), "{out}");
    assert!(out.contains("certificate is expired or not yet valid"), "{out}");
}
