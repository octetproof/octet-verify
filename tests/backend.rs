//! End-to-end harness for the backend fetch mode, driven through the real
//! `octet-verify` binary against an in-process stub HTTP server.
//!
//! These tests encode the load-bearing trust invariant: the backend is
//! untrusted, so the bytes it returns are run through the exact same
//! verification pipeline as a local file, and any tampering or substitution
//! must fail loud. The scenarios:
//!   * success           — well-formed proof decodes + verifies (exit 0).
//!   * tampered bytes     — backend serves a corrupted signature; fail (exit 1).
//!   * re-fetch diff      — same proof_id returns different bytes on a later
//!                          fetch; refetch-consistency FAIL.
//!   * range one-fails    — a range with one bad proof exits non-zero.
//!   * problem+json       — an RFC 7807 error is parsed structurally + surfaced.
//!
//! The whole file compiles only under `--features net` (the binary it drives
//! needs the same feature to have the subcommands at all).
#![cfg(feature = "net")]

use std::io::{BufRead, BufReader, Write};
use std::net::TcpListener;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;

use base64::Engine;
use octet_verify::crypto::sha256;
use octet_verify::navigate::{DeviceAttestation, LocationProof, StageAttestation, ZkProofData};
use octet_verify::prost::Message;
use p256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};

const BIN: &str = env!("CARGO_BIN_EXE_octet-verify");
// ts=0 + a huge max-age keeps freshness deterministic without mocking a clock.
const HUGE_MAX_AGE: &str = "999999999999";

// --- synthetic proof (mirrors tests/golden.rs; kept local so golden.rs and
//     the library stay untouched) ---

fn signed_stage(sk: &SigningKey, name: &str, data: &[u8], ts: i64, prev: Option<Vec<u8>>) -> StageAttestation {
    let data_hash = sha256(data).to_vec();
    let mut m = Vec::new();
    m.extend_from_slice(name.as_bytes());
    m.extend_from_slice(&data_hash);
    m.extend_from_slice(&ts.to_be_bytes());
    if let Some(p) = &prev {
        m.extend_from_slice(p);
    }
    let sig: Signature = sk.sign(&m);
    StageAttestation {
        stage: name.to_string(),
        timestamp_ms: ts,
        data_hash,
        signature: sig.to_bytes().to_vec(),
        previous_hash: prev,
    }
}

/// A self-signed iOS-style proof. The SEC1 hardware key is embedded in the
/// device-attestation certificate chain so the verifier resolves it itself —
/// no `--hardware-pubkey` flag needed, exercising the cert-chain path.
fn build_proof(seed: u8, ts: i64) -> LocationProof {
    let sk = SigningKey::from_slice(&[seed; 32]).unwrap();
    let vk: VerifyingKey = *sk.verifying_key();
    let sec1 = vk.to_encoded_point(false).as_bytes().to_vec();

    let commitment = vec![0xC0u8; 32];
    let nullifier = vec![0x1Au8; 32];
    let zk = vec![0x5Au8; 8];

    let s0 = signed_stage(&sk, "spoofDetection", b"verdict", ts, None);
    let s1 = signed_stage(&sk, "commitment", &commitment, ts, Some(s0.data_hash.clone()));
    let s2 = signed_stage(&sk, "nullifier", &nullifier, ts, Some(s1.data_hash.clone()));
    let s3 = signed_stage(&sk, "zkProof", &zk, ts, Some(s2.data_hash.clone()));
    let mut concat = Vec::new();
    for s in [&s0, &s1, &s2, &s3] {
        concat.extend_from_slice(&s.signature);
    }
    let asm = signed_stage(&sk, "proofAssembly", &concat, ts, Some(s3.data_hash.clone()));

    LocationProof {
        id: "synthetic".into(),
        zk_proof: Some(ZkProofData { proof_bytes: zk, ..Default::default() }),
        position_commitment: commitment,
        nullifier,
        timestamp_ms: ts,
        device_attestation: Some(DeviceAttestation {
            certificate_chain: vec![sec1],
            ..Default::default()
        }),
        stage_attestations: vec![s0, s1, s2, s3, asm],
        platform: "ios".into(),
        ..Default::default()
    }
}

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

// --- stub HTTP server ---

/// A throwaway HTTP/1.1 server bound to an ephemeral localhost port. The
/// handler maps (method, path-without-query) → (status, json body). It serves
/// one request per connection (`Connection: close`) and runs until the test
/// process exits.
struct Stub {
    base_url: String,
}

fn start_stub<F>(handler: F) -> Stub
where
    F: Fn(&str, &str) -> (u16, String) + Send + Sync + 'static,
{
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let base_url = format!("http://{}", listener.local_addr().unwrap());
    let handler = Arc::new(handler);
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            let mut reader = BufReader::new(stream.try_clone().unwrap());

            let mut request_line = String::new();
            if reader.read_line(&mut request_line).is_err() {
                continue;
            }
            let mut parts = request_line.split_whitespace();
            let method = parts.next().unwrap_or("").to_string();
            let full_path = parts.next().unwrap_or("").to_string();
            // Drain headers; we don't need the (empty) request body.
            loop {
                let mut line = String::new();
                match reader.read_line(&mut line) {
                    Ok(0) => break,
                    Ok(_) if line == "\r\n" || line == "\n" => break,
                    Ok(_) => {}
                    Err(_) => break,
                }
            }

            let path = full_path.split('?').next().unwrap_or("");
            let (status, body) = handler(&method, path);
            let reason = reason_phrase(status);
            let resp = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\n\
                 Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(resp.as_bytes());
            let _ = stream.flush();
        }
    });
    Stub { base_url }
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        201 => "Created",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        409 => "Conflict",
        500 => "Internal Server Error",
        _ => "Status",
    }
}

fn auth_ok() -> (u16, String) {
    (
        200,
        r#"{"proof_upload_token":"pup_v1.test-token","expires_at":"2026-06-05T18:24:00Z"}"#
            .to_string(),
    )
}

fn envelope_json(proof_id: &str, proof_bytes_b64: &str) -> String {
    [
        "{\"schema_version\":1",
        &format!("\"proof_id\":\"{proof_id}\""),
        &format!("\"proof_bytes_b64\":\"{proof_bytes_b64}\""),
        "\"license_id\":\"fe680b6e-e6b6-4673-a8e3-c297457999e5\"",
        "\"created_at\":\"2026-06-04T18:24:00Z\"",
        "\"platform\":\"ios\"",
        "\"sdk_version\":\"1.0.0\"",
        "\"proof_schema\":\"octet.proof.LocationProof\"}",
    ]
    .join(",")
}

fn wrapped(proof_id: &str, proof_bytes_b64: &str) -> String {
    format!("{{\"proof\":{}}}", envelope_json(proof_id, proof_bytes_b64))
}

fn problem(status: u16, detail: &str) -> (u16, String) {
    (
        status,
        format!(
            r#"{{"type":"https://octetproof.com/problems/err","title":"Error","status":{status},"detail":"{detail}"}}"#
        ),
    )
}

fn run_cli(args: &[&str]) -> Output {
    Command::new(BIN).args(args).output().expect("failed to run octet-verify")
}

// --- committed golden vectors ---

fn vectors_dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test-vectors/backend")
}

fn load_vector(name: &str) -> String {
    let p = vectors_dir().join(name);
    std::fs::read_to_string(&p).unwrap_or_else(|e| {
        panic!("missing golden vector {p:?}: {e}\nregenerate with: cargo test --features net regenerate_golden_vectors -- --ignored")
    })
}

/// Regenerate the committed `test-vectors/backend/*.json` golden responses.
/// Not run by default (the bytes are deterministic and "signed proofs are
/// forever"); run explicitly after an intentional builder/proto change:
///
///   cargo test --features net regenerate_golden_vectors -- --ignored
#[test]
#[ignore]
fn regenerate_golden_vectors() {
    let dir = vectors_dir();
    std::fs::create_dir_all(&dir).unwrap();

    // success: a fully valid proof.
    let success = wrapped("lp_success", &b64(&build_proof(7, 0).encode_to_vec()));

    // tampered: valid proof with one corrupted stage signature (still decodes).
    let mut t = build_proof(7, 0);
    t.stage_attestations[1].signature[10] ^= 0xFF;
    let tampered = wrapped("lp_tampered", &b64(&t.encode_to_vec()));

    // re-fetch diff: two *different* valid proofs served under the same id.
    let refetch_first = wrapped("lp_diff", &b64(&build_proof(7, 0).encode_to_vec()));
    let refetch_second = wrapped("lp_diff", &b64(&build_proof(9, 0).encode_to_vec()));

    for (name, body) in [
        ("success.json", success),
        ("tampered-bytes.json", tampered),
        ("refetch-first.json", refetch_first),
        ("refetch-second.json", refetch_second),
    ] {
        std::fs::write(dir.join(name), body).unwrap();
    }
}

// --- scenarios ---

#[test]
fn fetch_success_verifies_end_to_end() {
    let body = load_vector("success.json");
    let stub = start_stub(move |method, path| match (method, path) {
        ("POST", "/v1/proofs/auth") => auth_ok(),
        ("GET", "/v1/proofs/lp_success") => (200, body.clone()),
        _ => problem(404, "not found"),
    });

    let out = run_cli(&[
        "fetch", "lp_success",
        "--backend", &stub.base_url,
        "--token", "act_bearer",
        "--max-age-seconds", HUGE_MAX_AGE,
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(0), "expected exit 0\nstdout:{stdout}\nstderr:{}", String::from_utf8_lossy(&out.stderr));
    assert!(stdout.contains("verdict: VALID"), "missing VALID:\n{stdout}");
    assert!(stdout.contains("[       PASS] stage-signatures"), "sigs not verified:\n{stdout}");
    assert!(stdout.contains("[       PASS] refetch-consistency"), "consistency check missing:\n{stdout}");
}

#[test]
fn tampered_backend_bytes_fail_loud() {
    // The committed vector is a valid proof with one corrupted stage signature:
    // it still decodes but no longer verifies against the embedded key. This
    // proves the full pipeline runs over backend-supplied bytes — we trust the
    // bytes, not the backend's framing.
    let body = load_vector("tampered-bytes.json");
    let stub = start_stub(move |method, path| match (method, path) {
        ("POST", "/v1/proofs/auth") => auth_ok(),
        ("GET", "/v1/proofs/lp_tampered") => (200, body.clone()),
        _ => problem(404, "not found"),
    });

    let out = run_cli(&[
        "fetch", "lp_tampered",
        "--backend", &stub.base_url,
        "--token", "act_bearer",
        "--max-age-seconds", HUGE_MAX_AGE,
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "tampered bytes must fail with exit 1\n{stdout}");
    assert!(!stdout.contains("verdict: VALID"), "tampered proof reported VALID:\n{stdout}");
    assert!(stdout.contains("[       FAIL] stage-signatures"), "signature failure not surfaced:\n{stdout}");
}

#[test]
fn refetch_diff_is_caught_via_seen_store() {
    // Same proof_id returns proof A on the first fetch and a *different* valid
    // proof B on the second. Both verify on their own; the only thing that must
    // fail on the second run is refetch-consistency (invariant 4).
    let first_body = load_vector("refetch-first.json");
    let second_body = load_vector("refetch-second.json");
    assert_ne!(first_body, second_body);

    let calls = Arc::new(AtomicUsize::new(0));
    let stub = start_stub(move |method, path| match (method, path) {
        ("POST", "/v1/proofs/auth") => auth_ok(),
        ("GET", "/v1/proofs/lp_diff") => {
            let n = calls.fetch_add(1, Ordering::SeqCst);
            let body = if n == 0 { &first_body } else { &second_body };
            (200, body.clone())
        }
        _ => problem(404, "not found"),
    });

    let store = std::env::temp_dir().join(format!("octet-verify-seen-{}.txt", std::process::id()));
    let store_str = store.to_str().unwrap();
    let _ = std::fs::remove_file(&store);

    let cli_args = [
        "fetch", "lp_diff",
        "--backend", stub.base_url.as_str(),
        "--token", "act_bearer",
        "--seen-store", store_str,
        "--max-age-seconds", HUGE_MAX_AGE,
    ];

    // First fetch: records the byte-hash, passes.
    let first = run_cli(&cli_args);
    let first_out = String::from_utf8_lossy(&first.stdout);
    assert_eq!(first.status.code(), Some(0), "first fetch should pass:\n{first_out}");
    assert!(first_out.contains("[       PASS] refetch-consistency"), "first run consistency:\n{first_out}");

    // Second fetch of the same id returns different bytes → fail loud.
    let second = run_cli(&cli_args);
    let second_out = String::from_utf8_lossy(&second.stdout);
    assert_eq!(second.status.code(), Some(1), "byte substitution must fail:\n{second_out}");
    assert!(second_out.contains("[       FAIL] refetch-consistency"), "substitution not caught:\n{second_out}");

    let _ = std::fs::remove_file(&store);
}

#[test]
fn range_exits_nonzero_when_any_proof_fails() {
    let good_b64 = b64(&build_proof(7, 0).encode_to_vec());
    let mut bad = build_proof(7, 0);
    bad.stage_attestations[2].signature[5] ^= 0xFF;
    let bad_b64 = b64(&bad.encode_to_vec());

    let list = format!(
        "{{\"proofs\":[{},{}],\"next_cursor\":null}}",
        envelope_json("lp_good", &good_b64),
        envelope_json("lp_bad", &bad_b64),
    );
    let stub = start_stub(move |method, path| match (method, path) {
        ("POST", "/v1/proofs/auth") => auth_ok(),
        ("GET", "/v1/proofs") => (200, list.clone()),
        _ => problem(404, "not found"),
    });

    let out = run_cli(&[
        "range",
        "--backend", &stub.base_url,
        "--token", "act_bearer",
        "--since", "2026-06-01T00:00:00Z",
        "--until", "2026-06-30T00:00:00Z",
        "--max-age-seconds", HUGE_MAX_AGE,
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(1), "range with a failing proof must exit 1:\n{stdout}");
    assert!(stdout.contains("lp_good"), "good proof missing from report:\n{stdout}");
    assert!(stdout.contains("lp_bad"), "bad proof missing from report:\n{stdout}");
    assert!(stdout.contains("1 invalid"), "aggregate summary wrong:\n{stdout}");
}

#[test]
fn range_exits_3_when_inconclusive_but_none_invalid() {
    // A range whose worst proof is INCONCLUSIVE (signatures not verified,
    // no cert chain) — but none INVALID — must exit 3, not 0.
    let good_b64 = b64(&build_proof(7, 0).encode_to_vec()); // has cert chain → authentic
    let mut nokey = build_proof(7, 0);
    nokey.device_attestation = Some(DeviceAttestation::default()); // strip key → inconclusive
    let nokey_b64 = b64(&nokey.encode_to_vec());

    let list = format!(
        "{{\"proofs\":[{},{}],\"next_cursor\":null}}",
        envelope_json("lp_good", &good_b64),
        envelope_json("lp_nokey", &nokey_b64),
    );
    let stub = start_stub(move |method, path| match (method, path) {
        ("POST", "/v1/proofs/auth") => auth_ok(),
        ("GET", "/v1/proofs") => (200, list.clone()),
        _ => problem(404, "not found"),
    });

    let out = run_cli(&[
        "range",
        "--backend", &stub.base_url,
        "--token", "act_bearer",
        "--since", "2026-06-07T00:00:00Z",
        "--until", "2026-06-08T00:00:00Z",
        "--max-age-seconds", HUGE_MAX_AGE,
    ]);
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert_eq!(out.status.code(), Some(3), "inconclusive-but-not-invalid range must exit 3:\n{stdout}");
    assert!(stdout.contains("1 authentic"), "summary should count authentic:\n{stdout}");
    assert!(stdout.contains("1 inconclusive"), "summary should count inconclusive:\n{stdout}");
}

#[test]
fn backend_json_valid_false_when_signatures_unverified() {
    // Strip the cert chain so the verifier can't resolve a hardware key →
    // stage-signatures NOT-CHECKED → `valid:false` in the JSONL output.
    // The proof is otherwise structurally fine (would be is_valid()=true).
    let mut proof = build_proof(7, 0);
    proof.device_attestation = Some(DeviceAttestation::default());
    let bytes_b64 = b64(&proof.encode_to_vec());

    let stub = start_stub(move |method, path| match (method, path) {
        ("POST", "/v1/proofs/auth") => auth_ok(),
        ("GET", "/v1/proofs/lp_nokey") => (200, wrapped("lp_nokey", &bytes_b64)),
        _ => problem(404, "not found"),
    });

    let out = run_cli(&[
        "fetch", "lp_nokey",
        "--backend", &stub.base_url,
        "--token", "act_bearer",
        "--json",
        "--max-age-seconds", HUGE_MAX_AGE,
    ]);
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("\"valid\":false"), "unverified sigs must be valid:false:\n{s}");
    assert!(s.contains("\"signatures_verified\":false"), "missing signatures_verified:false:\n{s}");
    assert!(s.contains("INCONCLUSIVE"), "verdict should be INCONCLUSIVE:\n{s}");
}

#[test]
fn problem_json_error_is_parsed_and_surfaced() {
    // A 403 on the auth mint (license revoked, §6.1) must surface the parsed
    // problem+json `detail` — proving we decode RFC 7807 structurally rather
    // than string-matching the raw body.
    let stub = start_stub(move |method, path| match (method, path) {
        ("POST", "/v1/proofs/auth") => problem(403, "license is revoked"),
        _ => problem(404, "not found"),
    });

    let out = run_cli(&[
        "fetch", "lp_anything",
        "--backend", &stub.base_url,
        "--token", "act_bearer",
    ]);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(2), "backend error should exit 2");
    assert!(stderr.contains("HTTP 403"), "status not surfaced:\n{stderr}");
    assert!(stderr.contains("license is revoked"), "problem detail not surfaced:\n{stderr}");
}
