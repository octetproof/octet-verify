//! End-to-end Android app-identity binding against a real device attestation.
//!
//! Uses `test-vectors/attestation/pixel9-strongbox.bin` — a genuine Pixel 9
//! (StrongBox) `LocationProof` whose Keystore attestation chains to a Google
//! hardware-attestation root and carries an `attestationApplicationId`. This
//! exercises the whole `--features appattest` app-binding path against real
//! hardware evidence (not the software-signed `golden/` vectors).
//!
//! Time-pinned: the attestation certs have `notBefore`..`notAfter` windows, so we
//! verify at a fixed instant within them (the capture time). Deterministic, and
//! it never goes stale the way wall-clock verification of an expiring leaf would.
#![cfg(feature = "appattest")]

use octet_verify::appattest_layer::{attestation_root_check, AcceptEnvironment, Expectation};
use octet_verify::navigate::LocationProof;
use octet_verify::prost::Message;
use octet_verify::verify::Status;

const PROOF: &[u8] = include_bytes!("../test-vectors/attestation/pixel9-strongbox.bin");

/// Unix seconds within the captured proof's attestation-cert validity windows.
const PINNED_NOW: u64 = 1_785_327_157;

/// The sample app's (`com.octetproof.sample`) V2 signing-cert SHA-256 — the value
/// Android embeds in the attestation's `signatureDigests`.
const SIGNING_CERT_SHA256: [u8; 32] = [
    0x9b, 0xb2, 0x8a, 0xf9, 0x37, 0xcf, 0x7f, 0x48, 0x6b, 0x25, 0x8d, 0xe8, 0x27, 0xd4, 0x58, 0x39,
    0x56, 0x3f, 0xb8, 0xc6, 0xcb, 0x03, 0x7d, 0x32, 0x72, 0xfc, 0xa1, 0xaa, 0x78, 0x15, 0x9c, 0x4d,
];

fn proof() -> LocationProof {
    LocationProof::decode(PROOF).expect("golden Pixel proof decodes")
}

/// The chain validates to a Google root **and** binds to the expected app — PASS.
#[test]
fn correct_app_identity_passes_app_bound_attestation() {
    let expect = Expectation::new("6ZH5F97PWU", "com.octetproof.sample", AcceptEnvironment::Any)
        .with_android("com.octetproof.sample", SIGNING_CERT_SHA256);
    let c = attestation_root_check(&proof(), PINNED_NOW, expect.android.as_ref());
    assert_eq!(c.status, Status::Pass, "{}", c.detail);
    assert!(c.detail.contains("bound to the expected app identity"), "{}", c.detail);
}

/// A genuine StrongBox chain for the *wrong* app must FAIL (the gap this closes):
/// device hardware is real, but the attested package isn't the one we require.
#[test]
fn wrong_package_fails_even_with_a_genuine_chain() {
    let expect = Expectation::new("6ZH5F97PWU", "com.evil.app", AcceptEnvironment::Any)
        .with_android("com.evil.app", SIGNING_CERT_SHA256);
    let c = attestation_root_check(&proof(), PINNED_NOW, expect.android.as_ref());
    assert_eq!(c.status, Status::Fail, "{}", c.detail);
}

/// A right package but the wrong signing-cert digest also FAILs (both must hold).
#[test]
fn wrong_signing_cert_fails() {
    let expect = Expectation::new("6ZH5F97PWU", "com.octetproof.sample", AcceptEnvironment::Any)
        .with_android("com.octetproof.sample", [0u8; 32]);
    let c = attestation_root_check(&proof(), PINNED_NOW, expect.android.as_ref());
    assert_eq!(c.status, Status::Fail, "{}", c.detail);
}

/// Without an expected identity (opt-out), the hardware root alone still PASSes —
/// back-compat: app-binding is additive, not required unless asked for.
#[test]
fn no_expected_identity_passes_on_hardware_root_alone() {
    let c = attestation_root_check(&proof(), PINNED_NOW, None);
    assert_eq!(c.status, Status::Pass, "{}", c.detail);
    assert!(!c.detail.contains("bound to the expected app identity"), "{}", c.detail);
}
