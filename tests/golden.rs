//! End-to-end harness, exercised through the real `octet-verify` binary.
//!
//! Two things run here:
//!   1. a synthetic proof is signed, written out, and verified through the CLI
//!      (proves the whole path: decode → key load → verify → exit code);
//!   2. every committed golden vector under `test-vectors/golden/**` is verified
//!      and must still pass — "signed proofs are forever". Real golden vectors
//!      are produced by the SDK's emit hooks (see test-vectors/golden/README.md).
//!      The synthetic check guarantees the binary works even when no committed
//!      vectors are present.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use octet_verify::crypto::sha256;
use octet_verify::navigate::{DeviceAttestation, LocationProof, StageAttestation, ZkProofData};
use octet_verify::prost::Message;
use p256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};

const BIN: &str = env!("CARGO_BIN_EXE_octet-verify");

fn unique_dir(tag: &str) -> PathBuf {
    let mut d = std::env::temp_dir();
    d.push(format!("octet-verify-{}-{}", tag, std::process::id()));
    fs::create_dir_all(&d).unwrap();
    d
}

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

/// Build a self-signed iOS-style proof and return (proof_bytes, sec1_pubkey).
fn synthetic_proof(ts: i64) -> (Vec<u8>, Vec<u8>) {
    let sk = SigningKey::from_slice(&[7u8; 32]).unwrap();
    let vk: VerifyingKey = *sk.verifying_key();

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

    let proof = LocationProof {
        id: "synthetic".into(),
        zk_proof: Some(ZkProofData { proof_bytes: zk, ..Default::default() }),
        position_commitment: commitment,
        nullifier,
        timestamp_ms: ts,
        device_attestation: Some(DeviceAttestation::default()),
        stage_attestations: vec![s0, s1, s2, s3, asm],
        platform: "ios".into(),
        ..Default::default()
    };
    (proof.encode_to_vec(), vk.to_encoded_point(false).as_bytes().to_vec())
}

fn run_verify(proof: &Path, pubkey: &Path, max_age: &str) -> std::process::Output {
    Command::new(BIN)
        .arg(proof)
        .arg("--hardware-pubkey")
        .arg(pubkey)
        .arg("--max-age-seconds")
        .arg(max_age)
        .output()
        .expect("failed to run octet-verify")
}

#[test]
fn synthetic_proof_verifies_through_cli() {
    let dir = unique_dir("synthetic");
    let proof_path = dir.join("proof.bin");
    let key_path = dir.join("hw.pubkey");

    // ts=0 with a huge max-age keeps freshness deterministic without a clock.
    let (proof_bytes, sec1) = synthetic_proof(0);
    fs::write(&proof_path, &proof_bytes).unwrap();
    fs::write(&key_path, &sec1).unwrap();

    let out = run_verify(&proof_path, &key_path, "999999999999");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(out.status.success(), "expected exit 0, got {:?}\n{}", out.status.code(), stdout);
    assert!(stdout.contains("VALID"), "report missing VALID:\n{stdout}");
    assert!(stdout.contains("[       PASS] stage-signatures"), "signatures not verified:\n{stdout}");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn tampered_proof_is_rejected_through_cli() {
    let dir = unique_dir("tampered");
    let proof_path = dir.join("proof.bin");
    let key_path = dir.join("hw.pubkey");

    let (mut proof_bytes, sec1) = synthetic_proof(0);
    // Flip a byte somewhere in the serialized proof to corrupt a signed field.
    let mid = proof_bytes.len() / 2;
    proof_bytes[mid] ^= 0xFF;
    fs::write(&proof_path, &proof_bytes).unwrap();
    fs::write(&key_path, &sec1).unwrap();

    let out = run_verify(&proof_path, &key_path, "999999999999");
    // Either it no longer decodes (exit 2) or a check fails (exit 1) — never 0.
    assert_ne!(out.status.code(), Some(0), "tampered proof must not verify");

    let _ = fs::remove_dir_all(&dir);
}

/// Every committed golden vector must still verify. Real vectors are emitted by
/// the SDK per release; this guards against wire-breaking changes to the
/// verifier. With no committed vectors the loop is a no-op and the synthetic
/// check above still exercises the full pipeline.
#[test]
fn committed_golden_vectors_still_verify() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("test-vectors/golden");
    let mut checked = 0usize;
    for bin in find_bins(&root) {
        // A sibling .pubkey is used when present; otherwise the verifier pulls
        // the hardware key from the proof's certificate chain (iOS vectors).
        let pubkey = bin.with_extension("pubkey");
        let mut cmd = Command::new(BIN);
        cmd.arg(&bin).arg("--max-age-seconds").arg("9999999999999");
        if pubkey.exists() {
            cmd.arg("--hardware-pubkey").arg(&pubkey);
        }
        let out = cmd.output().expect("failed to run octet-verify");
        let stdout = String::from_utf8_lossy(&out.stdout);
        assert!(out.status.success(), "golden {} failed to verify:\n{}", bin.display(), stdout);
        checked += 1;
    }
    if checked == 0 {
        eprintln!("note: no golden vectors committed yet (SDK emit hooks pending); synthetic checks still cover the binary");
    }
}

/// The `--json` output must report `valid:false` for a proof whose signatures
/// were never cryptographically verified (no key available), and `valid:true`
/// only once the hardware key is supplied. Guards the print_json emitter
/// against re-introducing the false-assurance bug.
#[test]
fn json_valid_reflects_signature_verification() {
    let dir = unique_dir("json-valid");
    let proof_path = dir.join("proof.bin");
    let key_path = dir.join("hw.pubkey");
    let (proof_bytes, sec1) = synthetic_proof(0); // empty cert chain
    fs::write(&proof_path, &proof_bytes).unwrap();
    fs::write(&key_path, &sec1).unwrap();

    // No --hardware-pubkey → stage-signatures NOT-CHECKED → not authentic.
    let out = Command::new(BIN)
        .arg(&proof_path)
        .arg("--json")
        .arg("--max-age-seconds")
        .arg("999999999999")
        .output()
        .expect("run octet-verify");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("\"valid\": false"), "unverified sigs must be valid:false:\n{s}");
    assert!(s.contains("\"signatures_verified\": false"), "missing signatures_verified:false:\n{s}");
    assert!(s.contains("INCONCLUSIVE"), "verdict should be INCONCLUSIVE:\n{s}");

    // With the key → signatures verify → authentic.
    let out2 = Command::new(BIN)
        .arg(&proof_path)
        .arg("--hardware-pubkey")
        .arg(&key_path)
        .arg("--json")
        .arg("--max-age-seconds")
        .arg("999999999999")
        .output()
        .expect("run octet-verify");
    let s2 = String::from_utf8_lossy(&out2.stdout);
    assert!(s2.contains("\"valid\": true"), "verified must be valid:true:\n{s2}");
    assert!(s2.contains("\"signatures_verified\": true"), "{s2}");

    let _ = fs::remove_dir_all(&dir);
}

/// The process exit code is tri-state — 0 authentic, 1 invalid, 3 inconclusive.
/// INCONCLUSIVE (signatures not verified) must NOT exit 0, so
/// `octet-verify … && deploy` can't treat an unverified proof as success.
#[test]
fn exit_code_is_tri_state() {
    let dir = unique_dir("tri-state-exit");
    let proof_path = dir.join("proof.bin");
    let key_path = dir.join("hw.pubkey");
    let wrong_path = dir.join("wrong.pubkey");
    let big = "999999999999";

    let (proof_bytes, sec1) = synthetic_proof(0);
    fs::write(&proof_path, &proof_bytes).unwrap();
    fs::write(&key_path, &sec1).unwrap();
    // A different key → signatures won't verify (decodes fine, check fails).
    let wrong = SigningKey::from_slice(&[9u8; 32]).unwrap();
    let wrong_sec1 = wrong.verifying_key().to_encoded_point(false).as_bytes().to_vec();
    fs::write(&wrong_path, &wrong_sec1).unwrap();

    // No key → stage-signatures NOT-CHECKED → INCONCLUSIVE → exit 3.
    let nc = Command::new(BIN).arg(&proof_path).arg("--max-age-seconds").arg(big).output().unwrap();
    assert_eq!(nc.status.code(), Some(3), "no-key proof must exit 3 (inconclusive), got {:?}", nc.status.code());

    // Correct key → signatures verify → authentic → exit 0.
    let ok = Command::new(BIN).arg(&proof_path).arg("--hardware-pubkey").arg(&key_path).arg("--max-age-seconds").arg(big).output().unwrap();
    assert_eq!(ok.status.code(), Some(0), "verified proof must exit 0");

    // Wrong key → stage-signatures FAIL → INVALID → exit 1.
    let inv = Command::new(BIN).arg(&proof_path).arg("--hardware-pubkey").arg(&wrong_path).arg("--max-age-seconds").arg(big).output().unwrap();
    assert_eq!(inv.status.code(), Some(1), "signature failure must exit 1 (invalid)");

    let _ = fs::remove_dir_all(&dir);
}

fn find_bins(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    if let Ok(entries) = fs::read_dir(dir) {
        for e in entries.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(find_bins(&p));
            } else if p.extension().is_some_and(|x| x == "bin") {
                out.push(p);
            }
        }
    }
    out
}
