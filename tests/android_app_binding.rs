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
use octet_verify::keys::hardware_pubkey_from_cert_chain;
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

/// The genuine device signing key, resolved from the proof's own certificate
/// chain exactly as production does — this is the key `stage-signatures` verifies
/// against, and the leaf the attestation attests. Passing it means the
/// attestation binds to the key that actually signed the proof.
fn device_key_sec1() -> Vec<u8> {
    let p = proof();
    let chain = &p.device_attestation.as_ref().expect("has device attestation").certificate_chain;
    hardware_pubkey_from_cert_chain(chain)
        .expect("leaf key resolves")
        .to_sec1_bytes()
        .to_vec()
}

/// The chain validates to a Google root, binds to the expected app, **and** the
/// attested leaf is the signing key — PASS.
#[test]
fn correct_app_identity_passes_app_bound_attestation() {
    let expect = Expectation::new("6ZH5F97PWU", "com.octetproof.sample", AcceptEnvironment::Any)
        .with_android("com.octetproof.sample", SIGNING_CERT_SHA256);
    let dev = device_key_sec1();
    let c = attestation_root_check(&proof(), PINNED_NOW, expect.android.as_ref(), Some(&dev));
    assert_eq!(c.status, Status::Pass, "{}", c.detail);
    assert!(c.detail.contains("bound to the expected app identity"), "{}", c.detail);
}

/// A genuine StrongBox chain for the *wrong* app must FAIL (the gap this closes):
/// device hardware is real, but the attested package isn't the one we require.
#[test]
fn wrong_package_fails_even_with_a_genuine_chain() {
    let expect = Expectation::new("6ZH5F97PWU", "com.evil.app", AcceptEnvironment::Any)
        .with_android("com.evil.app", SIGNING_CERT_SHA256);
    let dev = device_key_sec1();
    let c = attestation_root_check(&proof(), PINNED_NOW, expect.android.as_ref(), Some(&dev));
    assert_eq!(c.status, Status::Fail, "{}", c.detail);
}

/// A right package but the wrong signing-cert digest also FAILs (both must hold).
#[test]
fn wrong_signing_cert_fails() {
    let expect = Expectation::new("6ZH5F97PWU", "com.octetproof.sample", AcceptEnvironment::Any)
        .with_android("com.octetproof.sample", [0u8; 32]);
    let dev = device_key_sec1();
    let c = attestation_root_check(&proof(), PINNED_NOW, expect.android.as_ref(), Some(&dev));
    assert_eq!(c.status, Status::Fail, "{}", c.detail);
}

/// Without an expected identity (opt-out), the hardware root alone still PASSes
/// when the attested leaf is the signing key — back-compat: app-binding is
/// additive, not required unless asked for.
#[test]
fn no_expected_identity_passes_on_hardware_root_alone() {
    let dev = device_key_sec1();
    let c = attestation_root_check(&proof(), PINNED_NOW, None, Some(&dev));
    assert_eq!(c.status, Status::Pass, "{}", c.detail);
    assert!(!c.detail.contains("bound to the expected app identity"), "{}", c.detail);
}

// --- SECURITY (issue): the attested leaf must be the signing key ---

/// The exploit this closes: an attacker borrows this genuine Google-rooted
/// StrongBox chain and attaches it to a proof their *own* key signed. The chain
/// still validates to a Google root, but the attested leaf is not the signing
/// key, so `attestation-root` must FAIL — never confer `is_attested()` on a
/// foreign key. `[0x11; 65]` is not a valid point, so a real attacker key is
/// used: any key other than the genuine leaf.
#[test]
fn borrowed_chain_with_foreign_signing_key_fails() {
    use p256::ecdsa::SigningKey;
    let attacker = SigningKey::from_slice(&[0x11u8; 32]).unwrap();
    let attacker_sec1 = attacker.verifying_key().to_sec1_bytes().to_vec();
    // Sanity: the attacker key is not the genuine leaf.
    assert_ne!(attacker_sec1, device_key_sec1());

    let c = attestation_root_check(&proof(), PINNED_NOW, None, Some(&attacker_sec1));
    assert_eq!(c.status, Status::Fail, "{}", c.detail);
    assert!(c.detail.contains("different key"), "{}", c.detail);
}

/// A valid chain with no signing key to bind it to fails closed — we never
/// vouch for an attestation we cannot tie to the key that signed the proof.
#[test]
fn genuine_chain_with_no_signing_key_fails_closed() {
    let c = attestation_root_check(&proof(), PINNED_NOW, None, None);
    assert_eq!(c.status, Status::Fail, "{}", c.detail);
    assert!(c.detail.contains("no device signing key"), "{}", c.detail);
}

// ---: --require-attestation through the shipping verify_attested_cached path ---

/// A genuine attested proof satisfies require_attestation (attestation-root PASS
/// → is_attested → attestation-required PASS); stripping the chain flips it to
/// FAIL. Exercises the real library enforcement path, not just the helper.
#[test]
fn require_attestation_accepts_attested_rejects_stripped() {
    use octet_verify::appattest_layer::verify_attested_cached;
    use octet_verify::keys::hardware_pubkey_from_cert_chain;
    use octet_verify::verify::VerifyOptions;

    let p = proof();
    let chain = &p.device_attestation.as_ref().unwrap().certificate_chain;
    let dev = hardware_pubkey_from_cert_chain(chain).expect("leaf key resolves");
    let expect = Expectation::new("6ZH5F97PWU", "com.octetproof.sample", AcceptEnvironment::Any);
    let opts = VerifyOptions {
        now_ms: (PINNED_NOW as i64) * 1000,
        max_age_s: i64::MAX / 2,
        hardware_pubkey: Some(&dev),
        hw_key_source: "test",
        expect_region: None,
        expect_region_type: None,
        expect_region_contains: None,
        session_nonce: None,
        require_session_binding: false,
        require_schema_v2: false,
        require_attestation: true,
    };

    let (report, _) = verify_attested_cached(&p, &opts, &expect, None);
    let req = |r: &octet_verify::verify::Report| {
        r.checks.iter().find(|c| c.name == "attestation-required").map(|c| c.status)
    };
    assert_eq!(req(&report), Some(Status::Pass), "genuine attested proof must satisfy require_attestation");
    // Exactly one attestation-required check (no double-enforcement with core).
    assert_eq!(
        report.checks.iter().filter(|c| c.name == "attestation-required").count(),
        1,
        "core cleared its copy; only the layer enforces"
    );

    // Strip the chain: attestation-root → NOT-CHECKED, app-attest → NOT-CHECKED,
    // so is_attested() is false and require_attestation FAILs (the amplifier).
    let mut stripped = p.clone();
    stripped.device_attestation.as_mut().unwrap().certificate_chain.clear();
    let (report2, _) = verify_attested_cached(&stripped, &opts, &expect, None);
    assert_eq!(req(&report2), Some(Status::Fail), "stripped-evidence proof must FAIL require_attestation");
}
