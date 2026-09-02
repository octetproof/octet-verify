//! Out-of-band App Attest key enrolment, end to end.
//!
//! Feed an out-of-band enrolment `bundle.json` plus a **same-key**,
//! assertion-only proof and watch the stranding get fixed:
//!
//!   [3] before enrol → NOT-CHECKED  (an empty key cache can't establish the key)
//!   [4] enrol        → key recovered from the attestation object in the bundle
//!   [5] after enrol  → PASS         (the same proof now verifies against the key)
//!
//! Requires the `appattest` feature:
//!
//! ```sh
//! cargo run --example enroll_e2e --features appattest -- \
//!     bundle.json assertion-only-proof.bin [team_id] [bundle_id]
//! ```
//!
//! `team_id` / `bundle_id` default to the public sample app's identity; pass your
//! own to match the app that produced the bundle.

use octet_attest_verify::appattest::AcceptEnvironment;
use octet_verify::appattest_layer::{appattest_check, appattest_enroll, bundle_from_json, Expectation};
use octet_verify::navigate::LocationProof;
use octet_verify::prost::Message;

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let bundle_path = args.next().ok_or_else(usage)?;
    let proof_path = args.next().ok_or_else(usage)?;
    let team_id = args.next().unwrap_or_else(|| "6ZH5F97PWU".to_string());
    let bundle_id = args.next().unwrap_or_else(|| "com.octetproof.sample".to_string());

    // `Any` accepts both the development and production App Attest environments,
    // so a dev-provisioned device is not rejected on an environment mismatch.
    let expect = Expectation::new(&team_id, &bundle_id, AcceptEnvironment::Any);

    // A later, assertion-only proof from the key: it carries a nonce + assertion
    // but no attestation object, so it can only verify once the key is known.
    let proof = LocationProof::decode(&*std::fs::read(&proof_path)?)?;

    // [3] Empty cache: nothing has established the key yet → NOT-CHECKED.
    // (nonce-only fixtures: no SE signing key, binding not required — #38.)
    let (before, _) = appattest_check(&proof, &expect, None, None, false);
    println!("[3] before enrol: {:<11} {}", before.status.tag(), before.detail);

    // [4] Enrol from the out-of-band JSON bundle: verify its attestation object
    //     against the nonce the bundle carries, and recover the key to cache.
    let da = bundle_from_json(&std::fs::read(&bundle_path)?)?;
    let key = appattest_enroll(&da, &expect)?;
    println!("[4] enrolled:     key recovered (counter {})", key.last_counter);

    // [5] Same proof, now against the cached key → PASS.
    let (after, _) = appattest_check(&proof, &expect, Some(&key), None, false);
    println!("[5] after enrol:  {:<11} {}", after.status.tag(), after.detail);

    Ok(())
}

fn usage() -> anyhow::Error {
    anyhow::anyhow!("usage: enroll_e2e <bundle.json> <assertion-only-proof.bin> [team_id] [bundle_id]")
}
