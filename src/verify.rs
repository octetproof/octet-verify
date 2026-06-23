//! The verification recipe and its report.
//!
//! What this checks, and why each is honest about its limits, is documented in
//! `VERIFICATION-SPEC.md`. The recipe mirrors the SDK's actual proof-generation
//! code (not the older design doc): the stage attestation chain links each
//! stage to the *previous stage's `data_hash`*, the final `proofAssembly` stage
//! binds every prior signature, and the visible commitment / nullifier / ZK
//! bytes are bound by their own stage hashes. There is no separate "envelope"
//! signature in the wire format; whole-proof, device-identity binding comes
//! from the optional Ed25519 transport signature (see [`verify_transport`]).
//!
//! Crucially, v1 does NOT validate the hardware key up to a Google/Apple
//! attestation root. The stage chain is therefore verified against the key the
//! proof carries — proving internal consistency and that one key signed the
//! whole chain, but not (on its own) that the key is genuine device hardware.
//! That gap is reported as a NOT-CHECKED line so a reader is never misled.

use crate::crypto::{self, Ed25519VerifyingKey, P256VerifyingKey, SigEncoding};
use crate::navigate::{LocationProof, StageAttestation};

/// Outcome of a single check.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Status {
    /// Verified.
    Pass,
    /// Verified to be wrong — the proof is rejected.
    Fail,
    /// Notable but not disqualifying.
    Warn,
    /// Deliberately not performed in this build; assurance not claimed.
    NotChecked,
}

impl Status {
    pub fn tag(self) -> &'static str {
        match self {
            Status::Pass => "PASS",
            Status::Fail => "FAIL",
            Status::Warn => "WARN",
            Status::NotChecked => "NOT-CHECKED",
        }
    }
}

/// A named check and its result.
pub struct Check {
    pub name: &'static str,
    pub status: Status,
    pub detail: String,
}

/// The full result of verifying one proof.
pub struct Report {
    pub checks: Vec<Check>,
}

impl Report {
    fn new() -> Self {
        Report { checks: Vec::new() }
    }

    fn add(&mut self, name: &'static str, status: Status, detail: impl Into<String>) {
        self.checks.push(Check { name, status, detail: detail.into() });
    }

    /// A proof is rejected iff at least one check actively failed. NOT-CHECKED
    /// and WARN never make a proof valid on their own, but they also do not
    /// reject it — the caller surfaces them so the assurance level is explicit.
    pub fn is_valid(&self) -> bool {
        !self.checks.iter().any(|c| c.status == Status::Fail)
    }

    pub fn count(&self, status: Status) -> usize {
        self.checks.iter().filter(|c| c.status == status).count()
    }

    /// True iff the cryptographic stage-signature check actually **passed** —
    /// not merely "did not fail". The iOS / no-hardware-key path leaves it
    /// `NotChecked`, which is not a pass. This is the bit that separates a proof
    /// whose signatures were verified from one that was only structurally sound.
    pub fn sigs_verified(&self) -> bool {
        self.checks
            .iter()
            .any(|c| c.name == "stage-signatures" && c.status == Status::Pass)
    }

    /// Authentic = not rejected **and** signatures cryptographically verified.
    /// This is the bit an automated consumer should gate on. [`is_valid`] alone
    /// is `true` for an unverified-but-not-rejected proof (e.g. no key supplied),
    /// so it must never be treated as "authentic" on its own.
    ///
    /// [`is_valid`]: Report::is_valid
    pub fn is_authentic(&self) -> bool {
        self.is_valid() && self.sigs_verified()
    }
}

/// Inputs to [`verify`]. The hardware key and its provenance are resolved by
/// the caller (from the proof's certificate chain or an explicit flag).
pub struct VerifyOptions<'a> {
    pub now_ms: i64,
    pub max_age_s: i64,
    pub hardware_pubkey: Option<&'a P256VerifyingKey>,
    pub hw_key_source: &'a str,
    pub expect_region: Option<&'a str>,
}

/// Verify a decoded [`LocationProof`] and return a structured [`Report`].
pub fn verify(proof: &LocationProof, opts: &VerifyOptions) -> Report {
    let mut r = Report::new();

    // -- freshness --
    // Judge freshness against the SIGNED stage timestamp (the last stage's
    // `timestamp_ms` is covered by that stage's signature), not the proof-level
    // `timestamp_ms`, which is unbound and freely editable. Editing the unbound
    // field therefore cannot make a stale proof look fresh.
    let signed_ts = proof.stage_attestations.last().map(|s| s.timestamp_ms);
    let ref_ts = signed_ts.unwrap_or(proof.timestamp_ms);
    let age_s = opts.now_ms.saturating_sub(ref_ts) / 1000;
    const FUTURE_SKEW_S: i64 = 60;
    if age_s < -FUTURE_SKEW_S {
        r.add("freshness", Status::Fail,
            format!("signed timestamp is {} s in the future (beyond {FUTURE_SKEW_S} s skew)", -age_s));
    } else if age_s < 0 {
        r.add("freshness", Status::Warn,
            format!("signed timestamp is {} s in the future (within {FUTURE_SKEW_S} s skew)", -age_s));
    } else if age_s > opts.max_age_s {
        r.add("freshness", Status::Fail, format!("stale: {age_s} s old (limit {} s)", opts.max_age_s));
    } else {
        r.add("freshness", Status::Pass, format!("{age_s} s old (limit {} s)", opts.max_age_s));
    }
    // The proof-level `timestamp_ms` is covered by no signature. The freshness
    // verdict above already ignores it; surface any disagreement with the signed
    // stage time as a WARN, because a mismatch means the unbound field was edited.
    if let Some(sts) = signed_ts {
        let drift_ms = sts.saturating_sub(proof.timestamp_ms).unsigned_abs();
        if drift_ms > 1000 {
            r.add("timestamp-binding", Status::Warn, format!(
                "unbound proof-level timestamp_ms disagrees with the signed stage time by \
                 {drift_ms} ms; freshness uses the signed time"));
        }
    }

    // -- nullifier presence (replay token) --
    // Presence only: this asserts a replay token *exists*, not that it is unique
    // across proofs. Authoritative cross-proof uniqueness is enforced server-side
    // at ingest, which is where the cross-proof state lives — a stateless
    // verifier cannot guarantee it. See `--nullifier-store` for a best-effort,
    // single-process local check.
    let nullifier_ok = !proof.nullifier.is_empty() && proof.nullifier.iter().any(|&b| b != 0);
    if nullifier_ok {
        r.add(
            "nullifier",
            Status::Pass,
            format!("replay token present ({} bytes); uniqueness enforced server-side, not here", proof.nullifier.len()),
        );
    } else {
        r.add("nullifier", Status::Fail, "empty or all-zero".to_string());
    }

    // -- stage attestation chain --
    let stages = &proof.stage_attestations;
    if stages.is_empty() {
        r.add("stage-chain", Status::Fail, "no stage attestations; proof carries no authenticity chain");
    } else {
        // linkage (structural)
        match check_linkage(stages) {
            Ok(()) => r.add("stage-chain", Status::Pass, format!("{} stages, hash linkage intact", stages.len())),
            Err(e) => r.add("stage-chain", Status::Fail, e),
        }

        // signatures (cryptographic) — needs key + platform encoding
        match (opts.hardware_pubkey, SigEncoding::for_platform(&proof.platform)) {
            (Some(vk), Ok(enc)) => match check_signatures(stages, vk, enc) {
                Ok(()) => r.add(
                    "stage-signatures",
                    Status::Pass,
                    format!("all {} stage signatures verify ({} key from {})",
                            stages.len(), enc_label(enc), opts.hw_key_source),
                ),
                Err(e) => r.add("stage-signatures", Status::Fail, e),
            },
            (None, _) => r.add(
                "stage-signatures",
                Status::NotChecked,
                format!("no hardware public key available ({})", opts.hw_key_source),
            ),
            (Some(_), Err(e)) => r.add("stage-signatures", Status::Fail, e.to_string()),
        }

        // proofAssembly binds every prior signature
        if stages.len() >= 2 {
            match check_assembly(stages) {
                Ok(()) => r.add("chain-assembly", Status::Pass,
                    format!("final stage binds all {} prior signatures", stages.len() - 1)),
                Err(e) => r.add("chain-assembly", Status::Fail, e),
            }
        } else {
            r.add("chain-assembly", Status::NotChecked, "single-stage chain; nothing to bind");
        }

        // visible fields bound by their own stage hashes
        r.add_field_bindings(proof, stages);
    }

    // -- region claim --
    let label = region_label(proof);
    match opts.expect_region {
        None => r.add("region-claim", Status::Pass, format!("claims {label} (level {})", proof.level)),
        Some(want) => match region_id(proof) {
            Some(id) if id.eq_ignore_ascii_case(want) => {
                r.add("region-claim", Status::Pass, format!("claims {label}, matches expected {want:?}"))
            }
            Some(id) => r.add("region-claim", Status::Fail,
                format!("claims {id:?}, expected {want:?}")),
            None => r.add("region-claim", Status::NotChecked,
                format!("claims {label}; cannot match a string against this region type")),
        },
    }

    // -- explicit NOT-CHECKED caveats (fail loud, never imply more than we did) --
    r.add("attestation-root", Status::NotChecked,
        "hardware key trusted as carried; chain to Google/Apple attestation root not validated (v1)");
    r.add("device-attestation-sig", Status::NotChecked,
        "DeviceAttestation.signature is platform-specific (Android: commitment; iOS: session) and not verified in v1");
    r.add("verdict-binding", Status::NotChecked,
        "spoofing_verdict / confidence / level are bound via stage hashes that need internal serialization to re-derive (Layer 2)");
    match &proof.zk_proof {
        Some(zk) if zk.backend == crate::navigate::ZkBackend::Placeholder as i32 =>
            r.add("zk-proof", Status::NotChecked, "backend is PLACEHOLDER; ZK layer contributes no assurance"),
        Some(zk) => r.add("zk-proof", Status::NotChecked,
            format!("backend {} not verified (no circuit verifier bundled in v1)", zk.backend)),
        None => r.add("zk-proof", Status::NotChecked, "no ZK proof present"),
    }

    r
}

/// Verify the Ed25519 transport signature over the exact serialized proof
/// bytes. This is the one check that binds the *entire* proof to the enrolled
/// device identity, so it is the strongest authenticity signal v1 offers.
pub fn verify_transport(proof_bytes: &[u8], signature: &[u8], vk: &Ed25519VerifyingKey) -> Check {
    match crypto::ed25519_verify(vk, proof_bytes, signature) {
        Ok(()) => Check {
            name: "ed25519-transport",
            status: Status::Pass,
            detail: "transport signature verifies; binds the whole proof to the enrolled device key".into(),
        },
        Err(e) => Check { name: "ed25519-transport", status: Status::Fail, detail: e.to_string() },
    }
}

impl Report {
    fn add_field_bindings(&mut self, proof: &LocationProof, stages: &[StageAttestation]) {
        let mut bound: Vec<&str> = Vec::new();
        let mut mismatches: Vec<String> = Vec::new();
        let mut unbound: Vec<&str> = Vec::new();

        let check = |name: &'static str, present: bool, field: &[u8],
                     bound: &mut Vec<&str>, mism: &mut Vec<String>, unb: &mut Vec<&str>| {
            match stage_by_name(stages, name) {
                Some(st) => {
                    if crypto::sha256(field).as_slice() == st.data_hash.as_slice() {
                        bound.push(name);
                    } else {
                        mism.push(format!("{name} field does not match its stage hash"));
                    }
                }
                // Field is present but no stage binds it: a renamed or omitted
                // binding stage must FAIL, never silently pass. Otherwise the
                // displayed value would go unverified while the proof reads valid.
                None if present => unb.push(name),
                None => {}
            }
        };

        check("commitment", !proof.position_commitment.is_empty(), &proof.position_commitment,
              &mut bound, &mut mismatches, &mut unbound);
        check("nullifier", !proof.nullifier.is_empty(), &proof.nullifier,
              &mut bound, &mut mismatches, &mut unbound);
        if let Some(zk) = &proof.zk_proof {
            check("zkProof", !zk.proof_bytes.is_empty(), &zk.proof_bytes,
                  &mut bound, &mut mismatches, &mut unbound);
        }

        if !mismatches.is_empty() {
            self.add("field-binding", Status::Fail, mismatches.join("; "));
        } else if !unbound.is_empty() {
            self.add("field-binding", Status::Fail, format!(
                "{} present but no signed stage binds {}; a renamed or omitted binding stage cannot pass",
                unbound.join(", "),
                if unbound.len() == 1 { "it" } else { "them" },
            ));
        } else if bound.is_empty() {
            self.add("field-binding", Status::NotChecked, "no commitment/nullifier/zkProof fields present to bind");
        } else {
            self.add("field-binding", Status::Pass, format!("{} bound to signed stage hashes", bound.join(", ")));
        }
    }
}

// --- stage-chain helpers (mirror the SDK's stage-chain construction) ---

/// The exact bytes a stage signs: `stage || data_hash || timestamp_be || prev`,
/// where `previous_hash` is appended only when present (the first stage signs
/// without it — not with 32 zero bytes).
///
/// The timestamp is big-endian, matching the crypto spec and both platforms.
fn stage_message(st: &StageAttestation) -> Vec<u8> {
    let mut m = Vec::with_capacity(st.stage.len() + st.data_hash.len() + 8 + 32);
    m.extend_from_slice(st.stage.as_bytes());
    m.extend_from_slice(&st.data_hash);
    m.extend_from_slice(&st.timestamp_ms.to_be_bytes());
    if let Some(prev) = &st.previous_hash {
        m.extend_from_slice(prev);
    }
    m
}

fn check_linkage(stages: &[StageAttestation]) -> Result<(), String> {
    if let Some(p) = &stages[0].previous_hash {
        if !p.is_empty() {
            return Err("first stage unexpectedly carries a previous_hash".into());
        }
    }
    for i in 0..stages.len() {
        if stages[i].data_hash.len() != 32 {
            return Err(format!(
                "stage {i} ({}) data_hash is {} bytes, expected 32",
                stages[i].stage, stages[i].data_hash.len()
            ));
        }
        if i > 0 {
            match &stages[i].previous_hash {
                None => return Err(format!("stage {i} ({}) missing previous_hash", stages[i].stage)),
                Some(p) if p.as_slice() != stages[i - 1].data_hash.as_slice() => {
                    return Err(format!(
                        "stage {i} ({}) previous_hash does not match stage {} data_hash",
                        stages[i].stage, i - 1
                    ));
                }
                _ => {}
            }
            if stages[i].timestamp_ms < stages[i - 1].timestamp_ms {
                return Err(format!("stage {i} timestamp precedes stage {}", i - 1));
            }
        }
    }
    Ok(())
}

fn check_signatures(stages: &[StageAttestation], vk: &P256VerifyingKey, enc: SigEncoding) -> Result<(), String> {
    for (i, st) in stages.iter().enumerate() {
        if st.signature.is_empty() {
            return Err(format!("stage {i} ({}) has an empty signature", st.stage));
        }
        if crypto::p256_verify(vk, &stage_message(st), &st.signature, enc).is_err() {
            return Err(format!("stage {i} ({}): ECDSA-P256 signature did not verify", st.stage));
        }
    }
    Ok(())
}

/// The final stage's `data_hash` must equal SHA-256 of every prior stage's
/// signature concatenated — this is how `proofAssembly` binds the whole chain.
fn check_assembly(stages: &[StageAttestation]) -> Result<(), String> {
    let (last, prior) = stages.split_last().unwrap();
    let mut concat = Vec::new();
    for st in prior {
        concat.extend_from_slice(&st.signature);
    }
    if crypto::sha256(&concat).as_slice() != last.data_hash.as_slice() {
        return Err(format!(
            "final stage ({}) data_hash != SHA-256(concatenated prior signatures)",
            last.stage
        ));
    }
    Ok(())
}

fn stage_by_name<'a>(stages: &'a [StageAttestation], name: &str) -> Option<&'a StageAttestation> {
    stages.iter().find(|s| s.stage == name)
}

// --- region helpers ---

fn region_label(proof: &LocationProof) -> String {
    use crate::navigate::proof_region::Region::*;
    match proof.claimed_region.as_ref().and_then(|r| r.region.as_ref()) {
        None => "<no region>".into(),
        Some(Earth(_)) => "earth".into(),
        Some(Country(c)) => format!("country:{}", c.iso_code),
        Some(Subdivision(s)) => format!("subdivision:{}", s.iso_code),
        Some(City(c)) => format!("city:{}", c.name),
        Some(Ellipse(_)) => "ellipse".into(),
        Some(H3PolygonSet(_)) => "h3_polygon_set".into(),
        Some(BoundingBox3d(_)) => "bounding_box_3d".into(),
    }
}

/// A string identifier suitable for `--expect-region` comparison, if the region
/// has one (country / subdivision ISO code, or city name).
fn region_id(proof: &LocationProof) -> Option<String> {
    use crate::navigate::proof_region::Region::*;
    match proof.claimed_region.as_ref().and_then(|r| r.region.as_ref())? {
        Country(c) => Some(c.iso_code.clone()),
        Subdivision(s) => Some(s.iso_code.clone()),
        City(c) => Some(c.name.clone()),
        _ => None,
    }
}

fn enc_label(enc: SigEncoding) -> &'static str {
    match enc {
        SigEncoding::Der => "DER",
        SigEncoding::Raw => "raw",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sha256;

    fn stage(name: &str, data: &[u8], ts: i64, prev: Option<Vec<u8>>, sig: Vec<u8>) -> StageAttestation {
        StageAttestation {
            stage: name.to_string(),
            timestamp_ms: ts,
            data_hash: sha256(data).to_vec(),
            signature: sig,
            previous_hash: prev,
        }
    }

    /// Authenticity must require a *passing* signature check, not merely the
    /// absence of a failure. A `NotChecked` stage-signatures line (no key) leaves
    /// the proof `is_valid()` (nothing failed) but NOT `is_authentic()` — this is
    /// the invariant the JSON `valid` field gates on.
    #[test]
    fn authenticity_requires_a_passing_signature_check() {
        // Signatures not checked (no key): valid, but not authentic.
        let mut unchecked = Report::new();
        unchecked.add("stage-chain", Status::Pass, "ok");
        unchecked.add("stage-signatures", Status::NotChecked, "no hardware key");
        assert!(unchecked.is_valid(), "nothing failed → is_valid");
        assert!(!unchecked.sigs_verified());
        assert!(!unchecked.is_authentic(), "unverified signatures are NOT authentic");

        // Signatures verified: authentic.
        let mut verified = Report::new();
        verified.add("stage-chain", Status::Pass, "ok");
        verified.add("stage-signatures", Status::Pass, "all verify");
        assert!(verified.sigs_verified());
        assert!(verified.is_authentic());

        // A failed check: neither valid nor authentic.
        let mut bad = Report::new();
        bad.add("stage-signatures", Status::Fail, "bad signature");
        assert!(!bad.is_valid());
        assert!(!bad.is_authentic());
    }

    /// A correctly linked chain passes linkage; a broken link fails. This
    /// encodes *why* the chain matters: tampering with a stage breaks the
    /// `previous_hash == prior.data_hash` invariant.
    #[test]
    fn linkage_detects_tampering() {
        let s1 = stage("spoofDetection", b"a", 1, None, vec![9; 64]);
        let s2 = stage("commitment", b"b", 2, Some(s1.data_hash.clone()), vec![9; 64]);
        let s3 = stage("nullifier", b"c", 3, Some(s2.data_hash.clone()), vec![9; 64]);
        let good = vec![s1.clone(), s2.clone(), s3.clone()];
        assert!(check_linkage(&good).is_ok());

        // Re-point s3 at the wrong previous hash → linkage must reject.
        let mut bad_s3 = s3.clone();
        bad_s3.previous_hash = Some(sha256(b"not-b").to_vec());
        assert!(check_linkage(&[s1, s2, bad_s3]).is_err());
    }

    /// proofAssembly's data_hash is SHA-256 of the concatenated prior sigs.
    #[test]
    fn assembly_binds_signatures() {
        let s1 = stage("a", b"x", 1, None, vec![1, 2, 3]);
        let s2 = stage("b", b"y", 2, Some(s1.data_hash.clone()), vec![4, 5, 6]);
        // proofAssembly data = s1.sig || s2.sig
        let concat = [s1.signature.clone(), s2.signature.clone()].concat();
        let asm = stage("proofAssembly", &concat, 3, Some(s2.data_hash.clone()), vec![7; 64]);
        assert!(check_assembly(&[s1.clone(), s2.clone(), asm]).is_ok());

        // Wrong assembly data must fail.
        let bad_asm = stage("proofAssembly", b"wrong", 3, Some(s2.data_hash.clone()), vec![7; 64]);
        assert!(check_assembly(&[s1, s2, bad_asm]).is_err());
    }

    // --- full roundtrip with real ECDSA-P256 signatures ---

    use crate::navigate::{DeviceAttestation, LocationProof, ZkProofData};
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};

    fn signed_stage(sk: &SigningKey, name: &str, data: &[u8], ts: i64, prev: Option<Vec<u8>>) -> StageAttestation {
        let data_hash = sha256(data).to_vec();
        let mut m = Vec::new();
        m.extend_from_slice(name.as_bytes());
        m.extend_from_slice(&data_hash);
        m.extend_from_slice(&ts.to_be_bytes());
        if let Some(p) = &prev {
            m.extend_from_slice(p);
        }
        let sig: Signature = sk.sign(&m); // RFC6979 deterministic, SHA-256 prehash
        StageAttestation {
            stage: name.to_string(),
            timestamp_ms: ts,
            data_hash,
            signature: sig.to_bytes().to_vec(), // raw r||s — matches platform "ios"
            previous_hash: prev,
        }
    }

    fn status_of<'a>(r: &'a Report, name: &str) -> Status {
        r.checks.iter().find(|c| c.name == name).map(|c| c.status).unwrap()
    }

    /// Build a real signed proof (iOS-style raw sigs), verify it, then show that
    /// mutating a signed field is detected. This encodes *why* each check
    /// exists: tampering with the commitment breaks field-binding; tampering a
    /// stage signature breaks signature verification.
    fn build_proof(sk: &SigningKey, ts: i64) -> LocationProof {
        let commitment = vec![0xC0u8; 32];
        let nullifier = vec![0x1Au8; 32];
        let zk_bytes = vec![0x5Au8; 8];

        let s0 = signed_stage(sk, "spoofDetection", b"verdict", ts, None);
        let s1 = signed_stage(sk, "commitment", &commitment, ts, Some(s0.data_hash.clone()));
        let s2 = signed_stage(sk, "nullifier", &nullifier, ts, Some(s1.data_hash.clone()));
        let s3 = signed_stage(sk, "zkProof", &zk_bytes, ts, Some(s2.data_hash.clone()));
        let mut concat = Vec::new();
        for s in [&s0, &s1, &s2, &s3] {
            concat.extend_from_slice(&s.signature);
        }
        let asm = signed_stage(sk, "proofAssembly", &concat, ts, Some(s3.data_hash.clone()));

        LocationProof {
            id: "test-proof".into(),
            zk_proof: Some(ZkProofData { proof_bytes: zk_bytes, ..Default::default() }),
            position_commitment: commitment,
            nullifier,
            timestamp_ms: ts,
            device_attestation: Some(DeviceAttestation::default()),
            stage_attestations: vec![s0, s1, s2, s3, asm],
            platform: "ios".into(),
            ..Default::default()
        }
    }

    #[test]
    fn full_roundtrip_verifies_and_tampering_is_caught() {
        let sk = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let vk = *sk.verifying_key();
        let ts = 1_700_000_000_000;
        let opts = |proof: &LocationProof| -> Report {
            verify(proof, &VerifyOptions {
                now_ms: ts,
                max_age_s: 300,
                hardware_pubkey: Some(&vk),
                hw_key_source: "test",
                expect_region: None,
            })
        };

        // Happy path: everything verifies.
        let good = build_proof(&sk, ts);
        let r = opts(&good);
        assert!(r.is_valid(), "expected valid proof");
        assert_eq!(status_of(&r, "stage-signatures"), Status::Pass);
        assert_eq!(status_of(&r, "chain-assembly"), Status::Pass);
        assert_eq!(status_of(&r, "field-binding"), Status::Pass);

        // Tamper the commitment → field-binding must fail.
        let mut t1 = build_proof(&sk, ts);
        t1.position_commitment[0] ^= 0xFF;
        let r1 = opts(&t1);
        assert!(!r1.is_valid());
        assert_eq!(status_of(&r1, "field-binding"), Status::Fail);

        // Tamper a stage signature → signature verification must fail.
        let mut t2 = build_proof(&sk, ts);
        t2.stage_attestations[1].signature[10] ^= 0xFF;
        let r2 = opts(&t2);
        assert!(!r2.is_valid());
        assert_eq!(status_of(&r2, "stage-signatures"), Status::Fail);

        // Verify with the wrong key → signatures must fail.
        let wrong = *SigningKey::from_slice(&[9u8; 32]).unwrap().verifying_key();
        let r3 = verify(&good, &VerifyOptions {
            now_ms: ts, max_age_s: 300, hardware_pubkey: Some(&wrong),
            hw_key_source: "test", expect_region: None,
        });
        assert!(!r3.is_valid());
        assert_eq!(status_of(&r3, "stage-signatures"), Status::Fail);
    }

    /// A field that is present but bound by no stage must FAIL, not silently
    /// pass because *other* fields happen to be bound. Renaming the `commitment`
    /// binding stage leaves `position_commitment` present and unverifiable — the
    /// verifier must refuse to vouch for it.
    #[test]
    fn present_field_with_no_binding_stage_fails() {
        let sk = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let ts = 1_700_000_000_000;
        let mut proof = build_proof(&sk, ts);
        let idx = proof
            .stage_attestations
            .iter()
            .position(|s| s.stage == "commitment")
            .unwrap();
        proof.stage_attestations[idx].stage = "renamed".into();

        let r = verify(&proof, &VerifyOptions {
            now_ms: ts, max_age_s: 300, hardware_pubkey: None,
            hw_key_source: "test", expect_region: None,
        });
        // nullifier + zkProof are still bound, but the unbound commitment must
        // not be papered over.
        assert_eq!(status_of(&r, "field-binding"), Status::Fail);
        assert!(!r.is_valid());
    }

    /// Freshness must be judged on the SIGNED stage timestamp, not the unbound
    /// proof-level `timestamp_ms`. Editing the unbound field to "now" must not
    /// buy freshness for a proof whose signed stages are an hour old.
    #[test]
    fn freshness_judged_on_signed_stage_time_not_unbound_field() {
        let sk = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let now = 1_700_000_000_000i64;
        let stale_ts = now - 3_600_000; // stages signed an hour ago
        let mut proof = build_proof(&sk, stale_ts);
        proof.timestamp_ms = now; // attacker edits the unbound field to look fresh

        let r = verify(&proof, &VerifyOptions {
            now_ms: now, max_age_s: 300, hardware_pubkey: None,
            hw_key_source: "test", expect_region: None,
        });
        assert_eq!(status_of(&r, "freshness"), Status::Fail, "signed time is stale");
        // The edit of the unbound field is surfaced, not ignored.
        assert_eq!(status_of(&r, "timestamp-binding"), Status::Warn);
    }

    /// A signed timestamp far in the future is impossible for a genuine proof
    /// and must FAIL, not merely WARN — a far-future stamp is how a replayed or
    /// fabricated proof tries to stay "fresh" indefinitely.
    #[test]
    fn far_future_signed_timestamp_fails_not_warns() {
        let sk = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let now = 1_700_000_000_000i64;
        let future_ts = now + 3_600_000; // an hour ahead, well beyond clock skew
        let proof = build_proof(&sk, future_ts);

        let r = verify(&proof, &VerifyOptions {
            now_ms: now, max_age_s: 300, hardware_pubkey: None,
            hw_key_source: "test", expect_region: None,
        });
        assert_eq!(status_of(&r, "freshness"), Status::Fail);
    }
}
