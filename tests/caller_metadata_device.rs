//! Caller metadata on **real devices**: proofs from an iPhone 11 (App Attest)
//! and a Pixel 9 (StrongBox), each committing two entries through the signed
//! `callerMetadata` stage: `note` (text/plain, 32-byte salt) and `file`
//! (application/octet-stream, unsalted, 4 KiB). Two sets: phase A (stage only,
//! `test-vectors/caller-metadata-device/`) and phase B (stage plus the readable
//! manifest in field 19, `test-vectors/caller-metadata-device-b/`). They pin that
//! the SDK's on-device encoder and the verifier agree on real output, not only on
//! the golden vectors. `now_ms` is pinned to each proof's signed `proofAssembly`
//! time. See the README in each directory.
#![cfg(feature = "caller-metadata")]

use octet_verify::caller_metadata::{
    check_caller_metadata, CallerManifest, CallerMetadataInputs, CallerMetadataOutcome, Content, RequireContent,
};
use octet_verify::keys::hardware_pubkey_from_cert_chain;
use octet_verify::navigate::LocationProof;
use octet_verify::prost::Message;
use octet_verify::verify::{verify, Report, Status, VerifyOptions};
use std::path::PathBuf;

const ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/test-vectors");
const PLATFORMS: [&str; 2] = ["android", "ios"];
/// Phase A (stage only) and phase B (stage plus field 19), as `platform` prefixes.
const SETS: [(&str, bool); 2] = [("caller-metadata-device", false), ("caller-metadata-device-b", true)];

fn path(platform: &str, file: &str) -> PathBuf {
    let (set, platform) = platform.split_once('/').unwrap_or(("caller-metadata-device", platform));
    PathBuf::from(format!("{ROOT}/{set}/{platform}/{file}"))
}

/// Every device proof as `set/platform`, with whether it carries field 19.
fn all() -> Vec<(String, bool)> {
    SETS.iter().flat_map(|(set, b)| PLATFORMS.iter().map(move |p| (format!("{set}/{p}"), *b))).collect()
}

fn os(name: &str) -> &str {
    name.rsplit('/').next().unwrap()
}

fn load(platform: &str) -> LocationProof {
    LocationProof::decode(&*std::fs::read(path(platform, "proof.bin")).unwrap()).unwrap()
}

fn manifest(platform: &str) -> CallerManifest {
    CallerManifest::from_json(&std::fs::read(path(platform, "manifest.json")).unwrap())
        .unwrap_or_else(|e| panic!("{platform}: manifest: {e}"))
}

fn proof_time_ms(p: &LocationProof) -> i64 {
    p.stage_attestations.iter().find(|s| s.stage == "proofAssembly").map(|s| s.timestamp_ms).unwrap()
}

fn status_of(r: &Report, name: &str) -> Status {
    r.checks.iter().find(|c| c.name == name).unwrap_or_else(|| panic!("report has a `{name}` check")).status
}

/// The base report: VALID with every stage signature verified.
fn base_report(proof: &LocationProof, platform: &str) -> Report {
    let chain = &proof.device_attestation.as_ref().unwrap().certificate_chain;
    let hw = hardware_pubkey_from_cert_chain(chain).unwrap();
    let opts = VerifyOptions {
        now_ms: proof_time_ms(proof) + 1_000,
        max_age_s: 300,
        hardware_pubkey: Some(&hw),
        hw_key_source: "certificate_chain[0]",
        expect_region: Some("country:GB"),
        expect_region_type: None,
        expect_region_contains: None,
        session_nonce: None,
        require_session_binding: false,
        require_schema_v2: true,
        require_attestation: false,
        require_verdict: None,
        validation_window: None,
    };
    let r = verify(proof, &opts);
    assert!(r.is_authentic(), "{platform}: expected VALID with signatures verified");
    r
}

fn inputs(platform: &str, note: PathBuf, file: PathBuf) -> CallerMetadataInputs<'static> {
    CallerMetadataInputs {
        manifest: Some(Ok(manifest(platform))),
        content: vec![("note".into(), Content::File(note)), ("file".into(), Content::File(file))],
        require_content: RequireContent::All,
        require_stage: true,
    }
}

#[test]
fn device_proofs_commit_both_entries() {
    for (name, field19) in all() {
        let platform = name.as_str();
        let proof = load(platform);
        assert!(proof.sdk_version.starts_with("3."), "{platform}: sdk_version {}", proof.sdk_version);
        assert_eq!(proof.platform, os(platform), "{platform}: platform");
        let mut r = base_report(&proof, platform);

        // Phase B: field 19 recomputes the stage and lists the presenter's
        // entries, without the salt. Phase A proofs carry no field 19 and get no line.
        let line = r.checks.iter().find(|c| c.name == "caller-manifest");
        assert_eq!(line.map(|c| c.status), field19.then_some(Status::Pass), "{platform}: caller-manifest");
        assert!(!r.checks.iter().any(|c| c.name == "caller-manifest-locator"), "{platform}: no locator");
        if field19 {
            let listed: Vec<_> = r.caller_manifest().unwrap().entries.iter()
                .map(|e| (e.key.clone(), e.content_type.clone(), e.size, e.sha256.clone(), e.locator.clone())).collect();
            let presented: Vec<_> = manifest(platform).entries.iter()
                .map(|e| (e.key.clone(), e.content_type.clone(), e.size, e.entry_digest.to_vec(), String::new())).collect();
            assert_eq!(listed, presented, "{platform}: field 19 matches the presenter manifest");
        } else {
            assert!(proof.caller_manifest.is_none(), "{platform}: phase A has no field 19");
        }

        let m = manifest(platform);
        let keys: Vec<_> = m.entries.iter().map(|e| (e.key.as_str(), e.content_type.as_str(), e.salt.len())).collect();
        assert_eq!(keys, [("note", "text/plain", 32), ("file", "application/octet-stream", 0)], "{platform}: entries");

        let res = check_caller_metadata(&proof, &inputs(platform, path(platform, "note.txt"), path(platform, "file.value")));
        assert_eq!(res.outcome, CallerMetadataOutcome::Verified, "{platform}: {}", res.check.detail);
        assert_eq!((res.by_content, res.by_digest), (2, 0), "{platform}: both entries by content");
        r.add_caller_metadata(res);
        assert_eq!(status_of(&r, "caller-metadata"), Status::Pass, "{platform}");
        assert!(r.is_authentic(), "{platform}: VALID with caller metadata");
    }
}

#[test]
fn device_proofs_refuse_changed_or_missing_content() {
    let tmp = std::env::temp_dir().join(format!("octet-cm-device-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).unwrap();
    for (name, field19) in all() {
        let platform = name.as_str();
        let proof = load(platform);
        let tag = platform.replace('/', "-");

        // One flipped bit in the salted note.
        let mut note = std::fs::read(path(platform, "note.txt")).unwrap();
        note[0] ^= 1;
        let flipped = tmp.join(format!("{tag}-note.txt"));
        std::fs::write(&flipped, &note).unwrap();
        let res = check_caller_metadata(&proof, &inputs(platform, flipped, path(platform, "file.value")));
        assert_eq!(res.outcome, CallerMetadataOutcome::ContentMismatch, "{platform}: {}", res.check.detail);

        // The other platform's manifest does not recompute this proof's stage.
        // With field 19 it is caught earlier, as differing from the proof's own list.
        let (set, me) = platform.split_once('/').unwrap();
        let other = format!("{set}/{}", PLATFORMS.iter().find(|p| **p != me).unwrap());
        let mut swapped = inputs(platform, path(platform, "note.txt"), path(platform, "file.value"));
        swapped.manifest = Some(Ok(manifest(&other)));
        swapped.content.clear();
        let res = check_caller_metadata(&proof, &swapped);
        let want = if field19 { CallerMetadataOutcome::ManifestMismatch } else { CallerMetadataOutcome::ContentMismatch };
        assert_eq!(res.outcome, want, "{platform}: {}", res.check.detail);

        // A referenced file that can't be read: INCONCLUSIVE, never VALID.
        let res = check_caller_metadata(&proof, &inputs(platform, path(platform, "note.txt"), tmp.join("missing.value")));
        assert_eq!(res.outcome, CallerMetadataOutcome::ContentUnresolved, "{platform}: {}", res.check.detail);
        let mut r = base_report(&proof, platform);
        r.add_caller_metadata(res);
        assert!(r.is_valid() && !r.is_authentic(), "{platform}: unresolved content is INCONCLUSIVE");
    }
    std::fs::remove_dir_all(&tmp).ok();
}

/// Android: the Keystore chain reaches a Google root at the proof's own time.
#[cfg(feature = "appattest")]
#[test]
fn android_device_proof_hardware_attestation() {
    use octet_verify::appattest_layer::{attestation_root_check, device_signature_check};
    for (set, _) in SETS {
        let proof = load(&format!("{set}/android"));
        let chain = &proof.device_attestation.as_ref().unwrap().certificate_chain;
        let sec1 = hardware_pubkey_from_cert_chain(chain).unwrap().to_sec1_bytes();
        let root = attestation_root_check(&proof, (proof_time_ms(&proof) / 1000) as u64, None, Some(&sec1));
        assert_eq!(root.status, Status::Pass, "{set}: attestation-root: {}", root.detail);
        assert_eq!(device_signature_check(&proof, Some(&sec1)).status, Status::Pass, "{set}");
    }
}

/// iOS: each set's same-day enrolment bundle enrols the App Attest key, and the
/// assertion-only proof passes App Attest with attestation required.
#[cfg(feature = "appattest")]
#[test]
fn ios_device_proof_app_attest_with_the_enrolment_bundle() {
    use octet_verify::appattest_layer::{
        appattest_enroll, bundle_from_json, verify_attested_cached, AcceptEnvironment, Expectation,
    };
    let expect = Expectation::new("6ZH5F97PWU", "com.octetproof.sample", AcceptEnvironment::Any);
    for (set, _) in SETS {
        let ios = format!("{set}/ios");
        let bundle = bundle_from_json(&std::fs::read(path(&ios, "enrolment.json")).unwrap()).unwrap();
        let proof = load(&ios);
        assert_eq!(proof.device_attestation.as_ref().unwrap().key_id, bundle.key_id, "same key");
        let key = appattest_enroll(&bundle, &expect).unwrap();
        let hw = hardware_pubkey_from_cert_chain(&proof.device_attestation.as_ref().unwrap().certificate_chain).unwrap();
        let opts = VerifyOptions {
            now_ms: proof_time_ms(&proof) + 1_000,
            max_age_s: 300,
            hardware_pubkey: Some(&hw),
            hw_key_source: "certificate_chain[0]",
            expect_region: None,
            expect_region_type: None,
            expect_region_contains: None,
            session_nonce: None,
            require_session_binding: false,
            require_schema_v2: true,
            require_attestation: true,
            require_verdict: None,
            validation_window: None,
        };
        let (r, _) = verify_attested_cached(&proof, &opts, &expect, Some(&key));
        assert_eq!(status_of(&r, "app-attest"), Status::Pass, "{set}");
        assert_eq!(status_of(&r, "attestation-required"), Status::Pass, "{set}");
        assert!(r.is_attested() && r.is_valid(), "{set}");
    }
}
