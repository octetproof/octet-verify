//! Caller metadata (phase A): the golden vectors in
//! `test-vectors/caller-metadata/vectors.json`, and a signed synthetic proof
//! carrying a `callerMetadata` stage, checked through the library and the CLI.
//!
//! The vectors are the cross-repo source of truth: the iOS and Android SDKs and
//! the on-device verifier test against the same file. See the README there.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use octet_verify::caller_metadata::{
    self as cm, check_caller_metadata, CallerManifest, CallerMetadataInputs, CallerMetadataOutcome, Content,
    ManifestEntry, RequireContent,
};
use octet_verify::crypto::sha256;
use octet_verify::navigate::{DeviceAttestation, LocationProof, StageAttestation};
use octet_verify::prost::Message;
use octet_verify::verify::{verify, Report, Status, VerifyOptions};
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use serde_json::Value;

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/test-vectors/caller-metadata");
const BIN: &str = env!("CARGO_BIN_EXE_octet-verify");

fn doc() -> Value {
    serde_json::from_str(&fs::read_to_string(format!("{DIR}/vectors.json")).unwrap()).unwrap()
}

fn value_of(e: &Value) -> Vec<u8> {
    match (e.get("value_hex"), e.get("value_file")) {
        (Some(h), None) => hex::decode(h.as_str().unwrap()).unwrap(),
        (None, Some(f)) => fs::read(format!("{DIR}/{}", f.as_str().unwrap())).unwrap(),
        _ => panic!("entry needs exactly one of value_hex / value_file: {e}"),
    }
}

/// A committed entry from a preimage vector, digested the way the SDK does it.
/// `value_file` entries go through the streaming reader.
fn committed_entry(e: &Value) -> ManifestEntry {
    let salt = hex::decode(e["salt_hex"].as_str().unwrap()).unwrap();
    let size = e["size"].as_u64().unwrap();
    let entry_digest = match e.get("value_file") {
        Some(f) => {
            let file = fs::File::open(format!("{DIR}/{}", f.as_str().unwrap())).unwrap();
            let (d, n) = cm::entry_digest_reader(&salt, file, u64::MAX).unwrap();
            assert_eq!(n, size, "{e}: streamed size");
            d
        }
        None => {
            let v = value_of(e);
            assert_eq!(v.len() as u64, size, "{e}: size");
            cm::entry_digest(&salt, &v)
        }
    };
    ManifestEntry {
        key: e["key"].as_str().unwrap().to_owned(),
        content_type: e["contentType"].as_str().unwrap().to_owned(),
        size,
        salt,
        entry_digest,
    }
}

#[test]
fn preimage_vectors() {
    let d = doc();
    assert_eq!(d["domain"], "octet-caller-metadata-v1");
    assert_eq!(d["stage"], cm::CALLER_METADATA_STAGE);
    let vectors = d["preimage_vectors"].as_array().unwrap();
    assert!(vectors.len() >= 20, "expected the full preimage vector set");
    let mut hashes = std::collections::HashMap::new();
    for v in vectors {
        let name = v["name"].as_str().unwrap();
        let m = CallerManifest { entries: v["entries"].as_array().unwrap().iter().map(committed_entry).collect() };
        match v["expected"].as_str().unwrap() {
            "VALID" => {
                let digests: Vec<String> = m.entries.iter().map(|e| hex::encode(e.entry_digest)).collect();
                let want: Vec<&str> = v["expected_entry_digests"].as_array().unwrap().iter().map(|x| x.as_str().unwrap()).collect();
                assert_eq!(digests, want, "{name}: entry digests");
                let pre = m.preimage().unwrap_or_else(|e| panic!("{name}: {e}"));
                assert_eq!(hex::encode(&pre), v["preimage_hex"].as_str().unwrap(), "{name}: preimage");
                assert_eq!(hex::encode(sha256(&pre)), v["expected_data_hash"].as_str().unwrap(), "{name}: data_hash");
                assert_eq!(hex::encode(m.stage_hash().unwrap()), v["expected_data_hash"].as_str().unwrap(), "{name}");
                hashes.insert(name.to_owned(), m.stage_hash().unwrap());
            }
            "MANIFEST_INVALID" => {
                assert!(m.validate().is_err(), "{name}: expected MANIFEST_INVALID");
                assert!(m.preimage().is_err(), "{name}: no preimage for an invalid manifest");
            }
            other => panic!("{name}: unexpected {other}"),
        }
    }
    // Injectivity, byte-exact comparison and committed order.
    for (a, b) in [
        ("injectivity_key_value_a", "injectivity_key_value_b"),
        ("injectivity_key_type_a", "injectivity_key_type_b"),
        ("unicode_key_nfc", "unicode_key_nfd"),
        ("single_unsalted", "content_type_case"),
        ("single_unsalted", "salt_16"),
        ("multi_entry", "multi_entry_reordered"),
    ] {
        assert_ne!(hashes[a], hashes[b], "{a} vs {b} must differ");
    }
}

/// The presenter side: a manifest (§5 JSON) and content checked against a
/// stage hash, with the result names the spec freezes.
#[cfg(feature = "caller-metadata")]
#[test]
fn check_vectors() {
    let d = doc();
    let vectors = d["check_vectors"].as_array().unwrap();
    assert!(vectors.len() >= 30, "expected the full check vector set");
    for v in vectors {
        let name = v["name"].as_str().unwrap();
        let proof = match v["stage_data_hash"].as_str() {
            None => LocationProof::default(),
            Some(h) => LocationProof {
                stage_attestations: vec![StageAttestation {
                    stage: cm::CALLER_METADATA_STAGE.into(),
                    timestamp_ms: 1,
                    data_hash: hex::decode(h).unwrap(),
                    signature: vec![],
                    previous_hash: None,
                }],
                ..Default::default()
            },
        };
        let manifest = match &v["manifest"] {
            Value::Null => None,
            m => Some(CallerManifest::from_json(&serde_json::to_vec(m).unwrap())),
        };
        let bytes: Vec<(String, Vec<u8>)> = v["content"]
            .as_object()
            .unwrap()
            .iter()
            .filter(|(_, c)| c.get("value_hex").is_some())
            .map(|(k, c)| (k.clone(), value_of(c)))
            .collect();
        let mut content: Vec<(String, Content)> = bytes.iter().map(|(k, b)| (k.clone(), Content::Bytes(b))).collect();
        for (k, c) in v["content"].as_object().unwrap() {
            if let Some(f) = c.get("value_file") {
                content.push((k.clone(), Content::File(PathBuf::from(format!("{DIR}/{}", f.as_str().unwrap())))));
            }
        }
        for k in v.get("content_unreadable").and_then(Value::as_array).into_iter().flatten() {
            content.push((k.as_str().unwrap().to_owned(), Content::Unavailable("not at hand".into())));
        }
        let require_content = match &v["require_content"] {
            Value::String(s) if s == "all" => RequireContent::All,
            Value::Array(a) if a.is_empty() => RequireContent::None,
            Value::Array(a) => RequireContent::Keys(a.iter().map(|k| k.as_str().unwrap().to_owned()).collect()),
            other => panic!("{name}: require_content {other}"),
        };
        let inputs = CallerMetadataInputs {
            manifest,
            content,
            require_content,
            require_stage: v["require_caller_metadata"].as_bool().unwrap(),
        };
        let r = check_caller_metadata(&proof, &inputs);
        let (want, status) = match v["expected"].as_str().unwrap() {
            "VALID" => (CallerMetadataOutcome::Verified, Status::Pass),
            "CONTENT_MISMATCH" => (CallerMetadataOutcome::ContentMismatch, Status::Fail),
            "MANIFEST_INVALID" => (CallerMetadataOutcome::ManifestInvalid, Status::Fail),
            "CONTENT_UNRESOLVED" => (CallerMetadataOutcome::ContentUnresolved, Status::Warn),
            "NOT_CHECKED" => (CallerMetadataOutcome::NotChecked, Status::NotChecked),
            "FAIL" => (CallerMetadataOutcome::StageMissing, Status::Fail),
            other => panic!("{name}: unexpected {other}"),
        };
        assert_eq!(r.outcome, want, "{name}: {}", r.check.detail);
        assert_eq!(r.check.status, status, "{name}");
        if let Some(code) = want.code() {
            assert!(r.check.detail.starts_with(&format!("{code}: ")), "{name}: {}", r.check.detail);
        }
        if let Some(n) = v.get("expected_by_content") {
            assert_eq!((r.by_content as u64, r.by_digest as u64), (n.as_u64().unwrap(), v["expected_by_digest"].as_u64().unwrap()), "{name}: counts");
            assert!(r.check.detail.contains("matched by content"), "{name}: {}", r.check.detail);
        }
    }
}

// --- a signed synthetic proof carrying a callerMetadata stage ---

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
    StageAttestation { stage: name.into(), timestamp_ms: ts, data_hash, signature: sig.to_bytes().to_vec(), previous_hash: prev }
}

const NOTE: &[u8] = b"Delivered to the front door.";
const PHOTO: &[u8] = &[0xD8; 4096];
const SALT: [u8; 32] = [0x5A; 32];

fn manifest() -> CallerManifest {
    let e = |key: &str, ct: &str, v: &[u8], salt: &[u8]| ManifestEntry {
        key: key.into(),
        content_type: ct.into(),
        size: v.len() as u64,
        salt: salt.to_vec(),
        entry_digest: cm::entry_digest(salt, v),
    };
    CallerManifest { entries: vec![e("note", "text/plain", NOTE, &[]), e("photo", "image/jpeg", PHOTO, &SALT)] }
}

/// (proof, SEC1 key): spoofDetection → callerMetadata → commitment → nullifier
/// → proofAssembly.
fn proof_with_caller_metadata() -> (LocationProof, Vec<u8>) {
    let sk = SigningKey::from_slice(&[7u8; 32]).unwrap();
    let (commitment, nullifier) = (vec![0xC0u8; 32], vec![0x1Au8; 32]);
    let s0 = signed_stage(&sk, "spoofDetection", b"verdict", 0, None);
    let s1 = signed_stage(&sk, cm::CALLER_METADATA_STAGE, &manifest().preimage().unwrap(), 0, Some(s0.data_hash.clone()));
    let s2 = signed_stage(&sk, "commitment", &commitment, 0, Some(s1.data_hash.clone()));
    let s3 = signed_stage(&sk, "nullifier", &nullifier, 0, Some(s2.data_hash.clone()));
    let concat: Vec<u8> = [&s0, &s1, &s2, &s3].iter().flat_map(|s| s.signature.clone()).collect();
    let asm = signed_stage(&sk, "proofAssembly", &concat, 0, Some(s3.data_hash.clone()));
    let proof = LocationProof {
        id: "caller-metadata".into(),
        position_commitment: commitment,
        nullifier,
        timestamp_ms: 0,
        device_attestation: Some(DeviceAttestation::default()),
        stage_attestations: vec![s0, s1, s2, s3, asm],
        platform: "ios".into(),
        ..Default::default()
    };
    (proof, sk.verifying_key().to_encoded_point(false).as_bytes().to_vec())
}

fn core_report(proof: &LocationProof, sec1: &[u8]) -> Report {
    let vk = octet_verify::crypto::P256VerifyingKey::from_sec1_bytes(sec1).unwrap();
    verify(proof, &VerifyOptions {
        now_ms: 0,
        max_age_s: 999_999_999_999,
        hardware_pubkey: Some(&vk),
        hw_key_source: "test",
        expect_region: None,
        expect_region_type: None,
        expect_region_contains: None,
        session_nonce: None,
        require_session_binding: false,
        require_schema_v2: false,
        require_attestation: false,
        require_verdict: None,
        validation_window: None,
    })
}

fn status(r: &Report, name: &str) -> Status {
    r.checks.iter().find(|c| c.name == name).unwrap_or_else(|| panic!("no {name} check")).status
}

#[test]
fn signed_proof_pass_mismatch_unresolved() {
    let (proof, sec1) = proof_with_caller_metadata();
    let base = core_report(&proof, &sec1);
    assert!(base.is_authentic(), "{:?}", base.checks.iter().map(|c| (c.name, c.status)).collect::<Vec<_>>());

    let run = |content: Vec<(String, Content)>, require: RequireContent| {
        let mut r = core_report(&proof, &sec1);
        r.add_caller_metadata(check_caller_metadata(&proof, &CallerMetadataInputs {
            manifest: Some(Ok(manifest())),
            content,
            require_content: require,
            require_stage: true,
        }));
        r
    };

    // PASS: content for both entries → VALID.
    let r = run(vec![("note".into(), Content::Bytes(NOTE)), ("photo".into(), Content::Bytes(PHOTO))], RequireContent::All);
    assert_eq!(status(&r, "caller-metadata"), Status::Pass);
    assert!(r.is_authentic() && r.content_resolved());

    // Digest-only photo is fine unless required.
    let r = run(vec![("note".into(), Content::Bytes(NOTE))], RequireContent::None);
    assert!(r.is_authentic());
    assert!(r.checks.iter().any(|c| c.detail == "1 of 2 entries matched by content, 1 by digest"));

    // Required but not presented → INCONCLUSIVE: valid (nothing failed), not authentic.
    let r = run(vec![("note".into(), Content::Bytes(NOTE))], RequireContent::All);
    assert_eq!(status(&r, "caller-metadata"), Status::Warn);
    assert!(r.is_valid() && r.sigs_verified() && !r.content_resolved() && !r.is_authentic());

    // A wrong value → FAIL: invalid.
    let r = run(vec![("note".into(), Content::Bytes(b"Delivered to the back door."))], RequireContent::All);
    assert_eq!(status(&r, "caller-metadata"), Status::Fail);
    assert!(!r.is_valid() && !r.is_authentic());
}

/// Removing the stage breaks the chain the device signed: the next stage's
/// previous_hash and proofAssembly's binding of every prior signature.
#[test]
fn removing_the_stage_fails_the_chain() {
    let (mut proof, sec1) = proof_with_caller_metadata();
    proof.stage_attestations.retain(|s| s.stage != cm::CALLER_METADATA_STAGE);
    let r = core_report(&proof, &sec1);
    assert_eq!(status(&r, "stage-chain"), Status::Fail);
    assert_eq!(status(&r, "chain-assembly"), Status::Fail);
    assert!(!r.is_valid());
    // Without the stage, the check itself asserts nothing, unless it's required.
    let c = check_caller_metadata(&proof, &CallerMetadataInputs::default());
    assert_eq!(c.outcome, CallerMetadataOutcome::NotChecked);
    let c = check_caller_metadata(&proof, &CallerMetadataInputs { require_stage: true, ..Default::default() });
    assert_eq!(c.check.status, Status::Fail);
}

// --- the CLI ---

fn unique_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("octet-verify-cm-{tag}-{}", std::process::id()));
    fs::create_dir_all(&d).unwrap();
    d
}

fn cli(dir: &Path, extra: &[&str]) -> (Option<i32>, String) {
    let out = Command::new(BIN)
        .arg(dir.join("proof.bin"))
        .args(["--hardware-pubkey", dir.join("hw.pubkey").to_str().unwrap(), "--max-age-seconds", "999999999999"])
        .args(extra)
        .output()
        .unwrap();
    (out.status.code(), String::from_utf8_lossy(&out.stdout).into_owned())
}

fn cli_setup(tag: &str) -> PathBuf {
    let dir = unique_dir(tag);
    let (proof, sec1) = proof_with_caller_metadata();
    fs::write(dir.join("proof.bin"), proof.encode_to_vec()).unwrap();
    fs::write(dir.join("hw.pubkey"), sec1).unwrap();
    dir
}

#[test]
fn cli_without_flags_reports_the_stage_and_stays_valid() {
    let dir = cli_setup("noflags");
    let (code, out) = cli(&dir, &[]);
    assert_eq!(code, Some(0), "{out}");
    assert!(out.contains("NOT-CHECKED] caller-metadata"), "{out}");
    // --require-caller-metadata is satisfied by the stage; content not presented → NOT-CHECKED.
    assert_eq!(cli(&dir, &["--require-caller-metadata"]).0, Some(0));
    // --require-content-all with no manifest → INCONCLUSIVE.
    let (code, out) = cli(&dir, &["--require-content-all"]);
    assert_eq!(code, Some(3), "{out}");
    assert!(out.contains("INCONCLUSIVE (content unresolved)"), "{out}");
    let _ = fs::remove_dir_all(&dir);
}

#[cfg(not(feature = "caller-metadata"))]
#[test]
fn cli_manifest_needs_the_feature() {
    let dir = cli_setup("nofeature");
    fs::write(dir.join("m.json"), "{}").unwrap();
    assert_eq!(cli(&dir, &["--caller-manifest", dir.join("m.json").to_str().unwrap()]).0, Some(2));
    let _ = fs::remove_dir_all(&dir);
}

#[cfg(feature = "caller-metadata")]
#[test]
fn cli_manifest_and_content() {
    let dir = cli_setup("content");
    let m = manifest();
    let json = serde_json::json!({"v": 1, "entries": m.entries.iter().map(|e| serde_json::json!({
        "key": e.key, "contentType": e.content_type, "size": e.size,
        "salt": hex::encode(&e.salt), "sha256": hex::encode(e.entry_digest)})).collect::<Vec<_>>()});
    let mp = dir.join("manifest.json");
    fs::write(&mp, serde_json::to_vec(&json).unwrap()).unwrap();
    fs::write(dir.join("note.txt"), NOTE).unwrap();
    fs::write(dir.join("photo.jpg"), PHOTO).unwrap();
    fs::write(dir.join("wrong.txt"), b"Delivered to the back door.").unwrap();
    let (mp, note, photo, wrong, missing) = (
        mp.to_str().unwrap().to_owned(),
        format!("note={}", dir.join("note.txt").display()),
        format!("photo={}", dir.join("photo.jpg").display()),
        format!("note={}", dir.join("wrong.txt").display()),
        format!("photo={}", dir.join("absent.jpg").display()),
    );

    let (code, out) = cli(&dir, &["--caller-manifest", &mp, "--content", &note, "--content", &photo, "--require-content-all"]);
    assert_eq!(code, Some(0), "{out}");
    assert!(out.contains("2 of 2 entries matched by content, 0 by digest"), "{out}");

    // Required photo missing → INCONCLUSIVE, exit 3; JSON valid:false.
    let (code, out) = cli(&dir, &["--caller-manifest", &mp, "--content", &note, "--require-content", "photo", "--json"]);
    assert_eq!(code, Some(3), "{out}");
    assert!(out.contains("\"verdict\": \"INCONCLUSIVE (content unresolved)\"") && out.contains("\"valid\": false"), "{out}");

    // A file that can't be read → unresolved, exit 3.
    assert_eq!(cli(&dir, &["--caller-manifest", &mp, "--content", &missing]).0, Some(3));

    // Wrong content → INVALID, exit 1, even with another entry unresolved.
    let (code, out) = cli(&dir, &["--caller-manifest", &mp, "--content", &wrong, "--content", &missing]);
    assert_eq!(code, Some(1), "{out}");
    assert!(out.contains("CONTENT_MISMATCH"), "{out}");

    // --content without --caller-manifest is a usage error.
    assert_eq!(cli(&dir, &["--content", &note]).0, Some(2));
    let _ = fs::remove_dir_all(&dir);
}
