//! End-to-end **session-binding** gate over a *real* signed proof envelope from
//! the SDK's `prove()` path — the offline half of the E1b verified-proof gate
//! (core owns the live challenge→prove→decide loop; this is the verifier-side
//! check on a captured fixture, no network).
//!
//! `test-vectors/session-binding-e2e/fixtures.json` holds two Tier-2
//! (software-signed, un-attested) `LocationProof` envelopes emitted by the SDK's
//! real `ProofGenerator` for the `geofence_at` policy (Country AT), each bound to
//! the #76 golden nonce: one **Inside** (device in AT) and one **Outside** (device
//! in DE). `proof_bytes_b64` is the exact `URL_SAFE_NO_PAD` bytes `prove()` emits
//! and the backend `/v1/decide` receives.
//!
//! This asserts what the policy engine keys its decision on, over an authentic
//! envelope:
//! - the envelope **verifies for real** — all stage signatures check against the
//!   SEC1 key sourced from `certificate_chain[0]` (Tier-2 needs no hardware root,
//!   so `require_attestation` is off);
//! - it is **session-bound** to the challenge nonce — the `sessionBinding` stage
//!   matches, and its `data_hash` equals the #76 pin `aab74288…`, tying this
//!   end-to-end fixture to the byte-level golden vectors;
//! - the **Inside** envelope is a *permit* shape (valid, region claim = AT,
//!   `location_verdict = Inside`, coverage of the one required region);
//! - the **Outside** envelope is a *deny* shape (`location_verdict = Outside`, and
//!   the AT region-claim fails) yet is still an authentic, session-bound proof —
//!   the denial is geography, not a broken proof.
//!
//! Freshness: `now_ms` is pinned to the envelope's own signed `proofAssembly`
//! time, so a committed golden never goes stale as CI ages — it asserts
//! structural/crypto/verdict correctness, not wall-clock freshness.

use base64::Engine;
use octet_verify::keys::hardware_pubkey_from_cert_chain;
use octet_verify::navigate::LocationProof;
use octet_verify::prost::Message;
use octet_verify::verify::{verify, Report, SignedLocationVerdict, Status, VerifyOptions};

const FIXTURES: &str = "test-vectors/session-binding-e2e/fixtures.json";
/// The #76 golden pin: SHA256("octet-session-binding-v1" ‖ u32be(43) ‖ <nonce>)
/// for the canonical 43-char base64url nonce. The fixture's `sessionBinding`
/// stage must carry exactly this, tying the e2e envelope to the byte-level vectors.
const SESSION_HASH_76: &str = "aab74288842bc907814ef3165cceb829f05aafdcaf9d25563cb137013e3f227f";

fn decode(b64: &str) -> LocationProof {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64)
        .expect("proof_bytes_b64 is URL_SAFE_NO_PAD base64");
    LocationProof::decode(&*bytes).expect("bytes decode as a LocationProof")
}

fn stage_ts(p: &LocationProof, name: &str) -> i64 {
    p.stage_attestations
        .iter()
        .find(|s| s.stage == name)
        .unwrap_or_else(|| panic!("proof has a {name} stage"))
        .timestamp_ms
}

fn session_binding_hash_hex(p: &LocationProof) -> String {
    let sb = p
        .stage_attestations
        .iter()
        .find(|s| s.stage == "sessionBinding")
        .expect("proof has a sessionBinding stage");
    hex::encode(&sb.data_hash)
}

/// Verify the envelope the way the engine's verified path does: key sourced from
/// the proof, session nonce required, no attestation requirement (Tier-2),
/// freshness pinned to the signed proof time. `expect_at` adds the Country-AT
/// region assertion (the required region of `geofence_at`).
fn verify_bound(proof: &LocationProof, nonce: &[u8], expect_at: bool) -> Report {
    let chain = &proof
        .device_attestation
        .as_ref()
        .expect("proof carries a device_attestation")
        .certificate_chain;
    let hw = hardware_pubkey_from_cert_chain(chain)
        .expect("SEC1 key resolves from certificate_chain[0]");
    let opts = VerifyOptions {
        now_ms: stage_ts(proof, "proofAssembly") + 1_000,
        max_age_s: 300,
        hardware_pubkey: Some(&hw),
        hw_key_source: "certificate_chain[0]",
        expect_region: expect_at.then_some("AT"),
        expect_region_type: expect_at.then_some("country"),
        expect_region_contains: None,
        session_nonce: Some(nonce),
        require_session_binding: true,
        require_schema_v2: false,
        require_attestation: false,
    };
    verify(proof, &opts)
}

fn check_status(r: &Report, name: &str) -> Status {
    r.checks
        .iter()
        .find(|c| c.name == name)
        .unwrap_or_else(|| panic!("report has a `{name}` check"))
        .status
}

fn assert_authentic_and_bound(r: &Report, label: &str) {
    // The crypto that makes it a *real* proof, independent of geography.
    assert_eq!(check_status(r, "stage-signatures"), Status::Pass, "{label}: stage signatures must verify");
    assert_eq!(check_status(r, "chain-assembly"), Status::Pass, "{label}: assembly stage must bind all prior signatures");
    assert_eq!(check_status(r, "session-binding"), Status::Pass, "{label}: must be bound to the challenge nonce");
    assert_eq!(check_status(r, "semantic-binding"), Status::Pass, "{label}: v2 semantic binding must hold");
}

#[test]
fn session_binding_e2e_real_envelope() {
    let raw = match std::fs::read_to_string(FIXTURES) {
        Ok(s) => s,
        // The fixture ships publicly via the manifest; if it is ever stripped the
        // gate can't run — skip rather than fail (matches the golden-vector pattern).
        Err(_) => {
            eprintln!("skipping: {FIXTURES} absent");
            return;
        }
    };
    let f: serde_json::Value = serde_json::from_str(&raw).expect("fixtures.json parses");
    let nonce = f["nonce_b64url"].as_str().expect("nonce_b64url").as_bytes().to_vec();

    // The e2e nonce is the #76 canonical string form.
    assert_eq!(nonce.len(), 43, "nonce is the 43-char base64url string");

    // ---- INSIDE: the permit shape ----
    let inside = decode(f["inside"]["proof_bytes_b64"].as_str().expect("inside bytes"));
    assert_eq!(
        session_binding_hash_hex(&inside),
        SESSION_HASH_76,
        "inside sessionBinding data_hash must equal the #76 golden pin"
    );
    let r = verify_bound(&inside, &nonce, true);
    assert_authentic_and_bound(&r, "inside");
    assert!(r.is_valid(), "inside: authentic + Country-AT claim ⇒ valid (permit). failed: {:?}",
        r.checks.iter().filter(|c| c.status == Status::Fail).map(|c| c.name).collect::<Vec<_>>());
    assert_eq!(check_status(&r, "region-claim"), Status::Pass, "inside: region claim is AT");
    assert_eq!(check_status(&r, "region-type"), Status::Pass, "inside: region type is country");
    assert_eq!(r.location_verdict(), Some(SignedLocationVerdict::Inside), "inside: signed verdict Inside");

    // ---- OUTSIDE: the deny shape — authentic + bound, but not in AT ----
    let outside = decode(f["outside"]["proof_bytes_b64"].as_str().expect("outside bytes"));
    assert_eq!(
        session_binding_hash_hex(&outside),
        SESSION_HASH_76,
        "outside sessionBinding data_hash must equal the #76 golden pin"
    );
    let r = verify_bound(&outside, &nonce, true);
    assert_authentic_and_bound(&r, "outside"); // still a real, session-bound proof
    assert_eq!(r.location_verdict(), Some(SignedLocationVerdict::Outside), "outside: signed verdict Outside");
    assert!(!r.is_valid(), "outside: Country-AT required but claim is elsewhere ⇒ denied");
    assert_eq!(check_status(&r, "region-claim"), Status::Fail, "outside: AT region-claim must fail");

    // ---- Negative: the binding is to THIS nonce, not merely present ----
    // Flip one nonce byte; the sessionBinding must no longer match (fail-closed).
    let mut wrong = nonce.clone();
    *wrong.last_mut().unwrap() ^= 0x01;
    let r = verify_bound(&inside, &wrong, true);
    assert_eq!(
        check_status(&r, "session-binding"),
        Status::Fail,
        "a one-byte-different nonce must break the binding (proof is bound to the real challenge nonce)"
    );
    assert!(!r.is_valid(), "wrong nonce ⇒ overall invalid (session binding failed)");
}
