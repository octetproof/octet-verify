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

/// The device's inside/outside verdict for the claimed region, exposed **only**
/// when it is cryptographically bound (octet-semantic-binding-v2, #26). The
/// trichotomy is preserved — `Indeterminate` never collapses into a boolean, and
/// "no signed verdict" is `None` from [`Report::location_verdict`], distinct from
/// `Some(Outside)`.
///
/// Reading this out is **not** re-running detection: it is the device's own
/// assertion, cryptographically bound. Independent confirmation (region-membership
/// ZK) is a separate, deferred concern.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignedLocationVerdict {
    Inside,
    Outside,
    Indeterminate,
}

/// The full result of verifying one proof.
pub struct Report {
    pub checks: Vec<Check>,
    /// Whether the caller supplied a region expectation (`--expect-region` or
    /// `--expect-region-type`). Records intent that the `region-claim` /
    /// `region-type` check statuses alone can't convey (both read `Pass` when no
    /// expectation was given). Read via [`Report::region_asserted`].
    region_expectation: bool,
    /// The signed inside/outside verdict, set only when the semantic binding
    /// verified under **v2** and the proof carries a non-UNSPECIFIED verdict.
    /// `None` for v1 / unbound / UNSPECIFIED proofs — "no signed verdict",
    /// distinct from `Some(Outside)` (#26). Read via [`Report::location_verdict`].
    location_verdict: Option<SignedLocationVerdict>,
}

impl Report {
    fn new() -> Self {
        Report { checks: Vec::new(), region_expectation: false, location_verdict: None }
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

    /// True iff the device's **hardware attestation** was affirmatively verified:
    /// the `app-attest` check passed (iOS Apple App Attest → Apple root) or the
    /// `attestation-root` check passed (Android key-attestation chain → Google
    /// root). A distinct, typed signal so an automated consumer never has to
    /// match check names by hand.
    ///
    /// Note: [`verify`] does **not** itself run the offline hardware-attestation
    /// layer — those checks come from `appattest_layer` (feature `appattest`) and
    /// must be appended to the report by the caller (as the CLI does). On a report
    /// from `verify` alone this is therefore always `false`; it becomes meaningful
    /// once the attestation checks are present. The per-proof field-2 signature
    /// (`device-attestation-sig`) is a separate check and is not folded in here.
    pub fn is_attested(&self) -> bool {
        self.checks
            .iter()
            .any(|c| matches!(c.name, "app-attest" | "attestation-root") && c.status == Status::Pass)
    }

    /// True iff the freshness check **passed** (`Status::Pass`) — the proof's
    /// signed timestamp is within the window set by [`VerifyOptions::max_age_s`].
    /// A `Warn` (signed time slightly in the future, within clock skew) is
    /// deliberately NOT treated as fresh; only a clean pass counts. Read
    /// distinctly from authenticity so a consumer can bind freshness to its own
    /// per-decision policy.
    pub fn is_fresh(&self) -> bool {
        self.checks
            .iter()
            .any(|c| c.name == "freshness" && c.status == Status::Pass)
    }

    /// True iff the caller supplied a region expectation (`--expect-region` or
    /// `--expect-region-type`) **and** every region assertion held: `region-claim`
    /// passed and, when a type was expected, `region-type` passed too.
    ///
    /// Distinct from `region-claim`'s raw status, which is `Pass` even when *no*
    /// expectation was given (it then merely reports the claimed region). An
    /// automated consumer asking "was the operator's region policy satisfied?"
    /// should read this rather than string-matching `checks`. Returns `false`
    /// when no expectation was supplied — nothing was asserted, so nothing was
    /// affirmatively satisfied (#40).
    pub fn region_asserted(&self) -> bool {
        if !self.region_expectation {
            return false;
        }
        let claim_ok = self
            .checks
            .iter()
            .any(|c| c.name == "region-claim" && c.status == Status::Pass);
        // At most one `region-type` / `region-contains` check each; `all` is
        // vacuously true when the check is absent.
        let type_ok = self
            .checks
            .iter()
            .filter(|c| c.name == "region-type")
            .all(|c| c.status == Status::Pass);
        let contains_ok = self
            .checks
            .iter()
            .filter(|c| c.name == "region-contains")
            .all(|c| c.status == Status::Pass);
        claim_ok && type_ok && contains_ok
    }

    /// True iff the `semantic-binding` check **passed** — the spoofing verdict,
    /// claimed region, level, device-integrity status, and position commitment
    /// are the exact values that were signed. Those proof fields are only
    /// tamper-evident when this holds: a proof predating semantic-field binding
    /// reports the check `NotChecked` (the fields decode but aren't bound). A
    /// consumer that reads `spoofing_verdict` / `claimed_region` should gate on
    /// `is_authentic() && is_semantically_bound()` and fail closed otherwise.
    ///
    /// Returns **false** for a `city` or `earth` region under preimage v1 (#32):
    /// their geometry — city centre/radius, earth `max_altitude_meters` — is not
    /// covered by the v1 preimage, so the binding is reported `Warn`, not `Pass`,
    /// and a consumer that trusts `CityRegion` coordinates fails closed. Full v1
    /// geometry binding is the later `octet-semantic-binding-v2` lockstep pass.
    pub fn is_semantically_bound(&self) -> bool {
        self.checks
            .iter()
            .any(|c| c.name == "semantic-binding" && c.status == Status::Pass)
    }

    /// The device's **signed** inside/outside verdict for the claimed region
    /// (#26), or `None` when there is no signed verdict — a v1 proof, an unbound
    /// proof, or a v2 proof whose verdict is `UNSPECIFIED`. `None` is distinct
    /// from `Some(Outside)`: a consumer that cannot tell those apart would read a
    /// verdict-less proof as a denial, so this deliberately preserves the
    /// trichotomy (and `Indeterminate` never collapses to a boolean).
    ///
    /// This is the device's cryptographically-bound assertion, surfaced — not an
    /// independent re-derivation of region membership.
    pub fn location_verdict(&self) -> Option<SignedLocationVerdict> {
        self.location_verdict
    }
}

/// Inputs to [`verify`]. The hardware key and its provenance are resolved by
/// the caller (from the proof's certificate chain or an explicit flag).
///
/// `Copy` so a caller that runs the attestation layer can derive a variant with
/// `require_attestation` cleared for its internal core [`verify`] call
/// (`VerifyOptions { require_attestation: false, ..*opts }`) and re-apply the
/// requirement once, after the real attestation checks (see #41).
#[derive(Clone, Copy)]
pub struct VerifyOptions<'a> {
    pub now_ms: i64,
    pub max_age_s: i64,
    pub hardware_pubkey: Option<&'a P256VerifyingKey>,
    pub hw_key_source: &'a str,
    pub expect_region: Option<&'a str>,
    /// Positive region-**type** assertion (issue #40). When set, the
    /// `region-type` check requires the claimed region to be of this oneof type
    /// — one of `earth` / `country` / `subdivision` / `city` / `ellipse` / `h3`
    /// / `bbox` — and FAILs otherwise (including when the proof carries no
    /// region). This is the positive counterpart to [`Self::expect_region`],
    /// which after the #30 fix can only *reject* an identifier-less region; it
    /// lets an operator affirmatively accept a geometric or earth-region proof.
    pub expect_region_type: Option<&'a str>,
    /// Positive region-**containment** assertion (issue #40): `(lat, lon)` in
    /// degrees that the claimed region must contain. This is what makes a
    /// *geometric* proof positively assertable rather than only rejectable —
    /// `--expect-region` matches by name and can't evaluate a geometric region.
    /// Adds a `region-contains` check: `Pass` iff the claimed region contains the
    /// point, `Fail` otherwise (including a named country/subdivision region,
    /// which carries no embedded geometry — use `--expect-region` for those — and
    /// an `h3` region, whose point-containment needs an H3 library not linked in
    /// the lean build). Supported geometrically: `earth`, `city` (disc), `ellipse`,
    /// `bbox`. `None` ⇒ the check is not added.
    pub expect_region_contains: Option<(f64, f64)>,
    /// Per-login session nonce the relying party issued, checked against the
    /// proof's `sessionBinding` stage. `None` ⇒ the binding is NOT-CHECKED
    /// unless `require_session_binding` is set (then absent/unsupplied ⇒ FAIL).
    pub session_nonce: Option<&'a [u8]>,
    /// Require the per-login session binding (fail-closed). When `true`, the
    /// `session-binding` check FAILs — rather than reporting NOT-CHECKED — if the
    /// proof carries no matching commitment (no nonce supplied, or no
    /// `sessionBinding` stage). Off by default (back-compat). Use it when
    /// verifying a stored/relayed proof you require to be session-bound.
    pub require_session_binding: bool,
    /// Transition flag for the schema-v2 mandatory flip. When `false` (the
    /// default posture), the verifier is back-compat: `semantic-binding` (and,
    /// in envelope modes, `replay-binding`) report NOT-CHECKED when the signed
    /// binding material is absent. When `true`, that material becomes
    /// **mandatory** — an absent `semanticFields` stage (or absent envelope
    /// replay-control) FAILs the proof. This is the proof-side equivalent of
    /// requiring schema-v2; arm it in lockstep with the backend's schema-v2
    /// ingest gate. Instantly reversible: set back to `false`.
    pub require_schema_v2: bool,
    /// Require hardware attestation to have **affirmatively verified** (#41).
    /// When `true`, an `attestation-required` check FAILs unless
    /// [`Report::is_attested`] holds — i.e. unless the App Attest (iOS) or the
    /// key-attestation chain (Android) passed. This closes the amplifier where an
    /// attacker strips attestation evidence so the check reports NOT-CHECKED (which
    /// [`Report::is_valid`] ignores) and the proof still passes. Off by default
    /// (back-compat).
    ///
    /// Enforced on **every** entry point, so it can never be silently ignored: a
    /// bare [`verify`] applies it directly (core records no passing attestation,
    /// so it FAILs — [`verify`] is not the attestation entry point), while
    /// [`crate::appattest_layer::verify_attested`] and the CLI clear it for their
    /// internal `verify` call and re-apply it after appending the real attestation
    /// checks. A build without the `appattest` feature cannot verify attestation,
    /// so it always FAILs there. It does not yet require the #38 *bound* assertion
    /// form — that gate lands once the bound-binding rev is in (see #38/#41).
    pub require_attestation: bool,
}

/// Verify a decoded [`LocationProof`] and return a structured [`Report`].
pub fn verify(proof: &LocationProof, opts: &VerifyOptions) -> Report {
    let mut r = Report::new();

    // -- freshness --
    // Judge freshness against the SIGNED stage timestamp, not the proof-level
    // `timestamp_ms`, which is unbound and freely editable. Prefer the
    // `proofAssembly` stage BY NAME (the authenticated proof time) — the stage set
    // is variable (optional uploadChallenge / semanticFields stages), so never key
    // on position; fall back to the last stage, then the unbound field (the proof
    // is already failing if it has no stages at all).
    let signed_ts = stage_by_name(&proof.stage_attestations, "proofAssembly")
        .or_else(|| proof.stage_attestations.last())
        .map(|s| s.timestamp_ms);
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
        Some(want) => {
            let (status, detail) = match_expected_region(proof, want, &label);
            r.add("region-claim", status, detail)
        }
    }

    // Record that the operator asked for *some* region assertion, so
    // `region_asserted()` can distinguish "asserted and held" from the
    // informational `region-claim` Pass emitted when nothing was expected.
    r.region_expectation = opts.expect_region.is_some()
        || opts.expect_region_type.is_some()
        || opts.expect_region_contains.is_some();

    // -- region type (positive assertion; issue #40) --
    // The counterpart to --expect-region: assert the claimed region is OF a
    // given oneof type. Lets an operator affirmatively accept a geometric or
    // earth-region proof, which --expect-region alone can only reject.
    if let Some(want_ty) = opts.expect_region_type {
        match region_type_tag(proof) {
            Some(t) if t.eq_ignore_ascii_case(want_ty) => {
                r.add("region-type", Status::Pass, format!("claimed region is of type {t}"))
            }
            Some(t) => r.add(
                "region-type",
                Status::Fail,
                format!("claimed region type {t:?}, expected {want_ty:?}"),
            ),
            None => r.add(
                "region-type",
                Status::Fail,
                format!("expected region type {want_ty:?} but the proof carries no region"),
            ),
        }
    }

    // -- region contains (positive geometric assertion; issue #40) --
    // Assert the claimed region CONTAINS a given point. This is what makes a
    // geometric proof positively assertable — `--expect-region` matches by name
    // and can only reject an identifier-less region. Unevaluable regions (named
    // country/subdivision with no embedded geometry; h3 without an H3 library)
    // FAIL, per #40's rule that an expectation which cannot be evaluated is not
    // satisfied.
    if let Some((lat, lon)) = opts.expect_region_contains {
        let (status, detail) = region_contains(proof, lat, lon);
        r.add("region-contains", status, detail);
    }

    // -- explicit NOT-CHECKED caveats (fail loud, never imply more than we did) --
    // Under `appattest` the layer pushes a real Pass/Fail for both of these, so
    // the placeholders are emitted only on the default build — a library consumer
    // building `appattest` never sees the stale NOT-CHECKED lines.
    #[cfg(not(feature = "appattest"))]
    r.add("attestation-root", Status::NotChecked,
        "hardware key trusted as carried; chain to Google/Apple attestation root not validated on a default build (build --features appattest)");
    #[cfg(not(feature = "appattest"))]
    r.add("device-attestation-sig", Status::NotChecked,
        "DeviceAttestation.signature not verified in the default build (build --features appattest to verify field 2)");
    r.add_semantic_binding(proof, opts.require_schema_v2);
    // Per-login session binding — checked against the nonce the relying party
    // supplies. NOT-CHECKED (the default) when no nonce is given; when
    // `require_session_binding` is set, an unsupplied/absent binding FAILs. See
    // `session`.
    r.checks.push(crate::session::check_session_binding(
        proof,
        opts.session_nonce,
        opts.require_session_binding,
    ));
    match &proof.zk_proof {
        Some(zk) if zk.backend == crate::navigate::ZkBackend::Placeholder as i32 =>
            r.add("zk-proof", Status::NotChecked, "backend is PLACEHOLDER; ZK layer contributes no assurance"),
        Some(zk) => r.add("zk-proof", Status::NotChecked,
            format!("backend {} not verified (no circuit verifier bundled in v1)", zk.backend)),
        None => r.add("zk-proof", Status::NotChecked, "no ZK proof present"),
    }

    // Fail-closed attestation requirement (#41). Enforced here so a bare
    // `verify()` cannot silently ignore `require_attestation` on any build: core
    // never records a passing `app-attest`/`attestation-root`, so `is_attested()`
    // is false and this FAILs. Callers that DO run the attestation layer
    // (verify_attested_cached / the CLI) clear this flag for their internal
    // `verify()` call and re-apply `require_attestation_check` after appending the
    // real attestation checks, so the requirement is evaluated exactly once,
    // against the true attestation result.
    if opts.require_attestation {
        let c = require_attestation_check(&r);
        r.checks.push(c);
    }

    r
}

/// The `attestation-required` check (#41): `Pass` iff [`Report::is_attested`]
/// holds — a hardware attestation (iOS App Attest or the Android key-attestation
/// chain) affirmatively verified — else `Fail`. Platform-correct: it does not
/// demand that *every* attestation line passed (iOS leaves `attestation-root`
/// NOT-CHECKED, Android leaves `app-attest` NOT-CHECKED), only that one did.
/// Applied by the terminal assembler (core [`verify`] for a bare call, or
/// [`crate::appattest_layer::verify_attested_cached`] / the CLI after they append
/// the real attestation checks). It does not yet require the #38 *bound*
/// assertion form; that gate lands with the bound-binding rev.
pub fn require_attestation_check(report: &Report) -> Check {
    if report.is_attested() {
        Check {
            name: "attestation-required",
            status: Status::Pass,
            detail: "hardware attestation affirmatively verified".into(),
        }
    } else {
        Check {
            name: "attestation-required",
            status: Status::Fail,
            detail: "hardware attestation required (--require-attestation) but none affirmatively \
                     verified (no App Attest / key-attestation PASS — a default build cannot verify \
                     attestation; on iOS pass --app-attest-config)"
                .into(),
        }
    }
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

    /// Confirm the semantic fields — `spoofing_verdict`, `level`, device
    /// `integrity_verdict.status`, `claimed_region`, `position_commitment` — are
    /// the ones signed, by re-deriving the canonical `SEMANTIC_PREIMAGE` and
    /// checking it against the `semanticFields` stage hash. A post-sign edit of
    /// any covered field breaks the hash → FAIL. Absent stage → NOT-CHECKED (a
    /// proof predating semantic-field binding). Replaces the old `verdict-binding`
    /// placeholder.
    fn add_semantic_binding(&mut self, proof: &LocationProof, require_schema_v2: bool) {
        const NAME: &str = "semantic-binding";
        match stage_by_name(&proof.stage_attestations, SEMANTIC_FIELDS_STAGE) {
            // Absent: back-compat NOT-CHECKED, unless the schema-v2 flip is armed —
            // then the binding is mandatory and a proof that predates it FAILs.
            None if require_schema_v2 => self.add(NAME, Status::Fail,
                "no semanticFields stage, but schema-v2 binding is required (require_schema_v2): the spoofing_verdict / region / level / integrity / commitment are unbound"),
            None => self.add(NAME, Status::NotChecked,
                "no semanticFields stage; spoofing_verdict / region / level / integrity / commitment not bound (proof predates semantic-field binding)"),
            // v2 (octet-semantic-binding-v2, #26/#32) — tried first. Binds the
            // city/earth geometry AND the inside/outside verdict that v1 omits, so
            // a match here is FULLY bound and surfaces the signed verdict.
            Some(st) if crypto::sha256(&semantic_preimage_v2(proof)).as_slice() == st.data_hash.as_slice() => {
                self.location_verdict = signed_verdict(proof.location_verdict);
                self.add(NAME, Status::Pass,
                    "spoofing_verdict / region (incl. geometry) / level / integrity / commitment / \
                     location_verdict bound to the signed semanticFields stage (octet-semantic-binding-v2)")
            }
            // v1 — still accepted during the cutover. A city/earth region binds
            // only its *identity*, not its geometry (city centre/radius, earth
            // max_altitude). Report those as Warn with an honest detail so
            // `is_semantically_bound()` returns false and a consumer that trusts
            // the coordinates fails closed (#32). Everything else —
            // country/subdivision (identity IS the region) and the geometric
            // digests ellipse/h3/bbox (every scalar folded) — is fully bound.
            Some(st) if crypto::sha256(&semantic_preimage(proof)).as_slice() == st.data_hash.as_slice() => {
                if region_geometry_bound_v1(proof) {
                    self.add(NAME, Status::Pass,
                        "spoofing_verdict / region / level / integrity / commitment bound to the signed semanticFields stage")
                } else {
                    self.add(NAME, Status::Warn,
                        "spoofing_verdict / region identity / level / integrity / commitment bound, \
                         but region GEOMETRY is NOT covered by preimage v1 (city centre/radius, earth \
                         max_altitude) — not semantically bound (#32); pending octet-semantic-binding-v2")
                }
            }
            Some(_) => self.add(NAME, Status::Fail,
                "semantic fields do not match the signed semanticFields stage (verdict / region / level / integrity / commitment / location_verdict tampered)"),
        }
    }
}

// --- semantic-field binding ---

/// Domain-separation prefix for the semantic-field preimage. Raw UTF-8, no NUL;
/// version-bump if the serialization shape ever changes.
const SEMANTIC_DOMAIN: &[u8] = b"octet-semantic-binding-v1";
/// Stage whose `data_hash` is `SHA256(SEMANTIC_PREIMAGE)`.
const SEMANTIC_FIELDS_STAGE: &str = "semanticFields";

/// Under preimage v1, is the claimed region's **geometry** fully covered by the
/// semantic binding? True for regions whose identity *is* the region
/// (country/subdivision), the geometric digests that fold every scalar
/// (ellipse/h3/bbox), and a no-region proof. False for `city` and `earth`, whose
/// `center_lat/lon/radius_meters` / `max_altitude_meters` are absent from the v1
/// preimage (#32) — so a matching stage must not be reported as fully
/// semantically bound. Folds into the `octet-semantic-binding-v2` pass later.
fn region_geometry_bound_v1(proof: &LocationProof) -> bool {
    use crate::navigate::proof_region::Region::*;
    // Exhaustive on purpose (no wildcard), mirroring `semantic_region`: a new
    // `ProofRegion` oneof arm must compile-error here and force a decision,
    // rather than defaulting to "fully bound" (a silent fail-open).
    match proof.claimed_region.as_ref().and_then(|r| r.region.as_ref()) {
        // Identity IS the region (country/subdivision), or every geometric scalar
        // is folded into the digest (ellipse/h3/bbox), or there is no region.
        None
        | Some(Country(_))
        | Some(Subdivision(_))
        | Some(Ellipse(_))
        | Some(H3PolygonSet(_))
        | Some(BoundingBox3d(_)) => true,
        // v1 preimage omits city centre/radius and earth max_altitude.
        Some(Earth(_)) | Some(City(_)) => false,
    }
}

/// The `claimed_region` contribution to the preimage: `(oneof tag, region_id)`.
/// Named regions use their identity bytes; geometric regions use a canonical
/// 32-byte digest (a canonical form pinned in lockstep with the SDK) so the
/// verifier and both platforms re-derive byte-identically.
fn semantic_region(proof: &LocationProof) -> (u32, Vec<u8>) {
    use crate::navigate::proof_region::Region::*;
    match proof.claimed_region.as_ref().and_then(|r| r.region.as_ref()) {
        None => (0, Vec::new()),
        Some(Earth(_)) => (1, Vec::new()),
        Some(Country(c)) => (2, c.iso_code.clone().into_bytes()),
        Some(City(c)) => (3, c.name.clone().into_bytes()),
        Some(Ellipse(e)) => (4, ellipse_digest(e)),
        Some(H3PolygonSet(h)) => (5, h3_digest(h)),
        Some(BoundingBox3d(b)) => (6, bbox_digest(b)),
        Some(Subdivision(s)) => (7, s.iso_code.clone().into_bytes()),
    }
}

/// f64 → IEEE-754 bits, big-endian (matches the SDK's `doubleToRawLongBits`/
/// `bitPattern` → u64-BE).
fn f64be(v: f64) -> [u8; 8] {
    v.to_be_bytes()
}

/// ellipse(4): `SHA256( f64be(center.lat ‖ lon ‖ semi_major_m ‖ semi_minor_m ‖ heading_deg) )`.
fn ellipse_digest(e: &crate::navigate::EllipseRegion) -> Vec<u8> {
    let (lat, lon) = e.center.as_ref().map(|c| (c.latitude, c.longitude)).unwrap_or((0.0, 0.0));
    let mut m = Vec::with_capacity(40);
    for v in [lat, lon, e.semi_major_m, e.semi_minor_m, e.heading_deg] {
        m.extend_from_slice(&f64be(v));
    }
    crypto::sha256(&m).to_vec()
}

/// h3(5): `SHA256( cell_ids sorted ascending UNSIGNED, each u64-BE )`. `cell_ids`
/// is `fixed64` → `u64`, so the natural sort is already unsigned-ascending.
fn h3_digest(h: &crate::navigate::H3PolygonSet) -> Vec<u8> {
    let mut ids = h.cell_ids.clone();
    ids.sort_unstable();
    let mut m = Vec::with_capacity(ids.len() * 8);
    for id in ids {
        m.extend_from_slice(&id.to_be_bytes());
    }
    crypto::sha256(&m).to_vec()
}

/// bbox(6): `SHA256( f64be of min_lat, max_lat, min_lon, max_lon, min_alt, max_alt )`
/// — proto field order, not grouped by min/max.
fn bbox_digest(b: &crate::navigate::BoundingBox3DRegion) -> Vec<u8> {
    let mut m = Vec::with_capacity(48);
    for v in [b.min_latitude, b.max_latitude, b.min_longitude, b.max_longitude, b.min_altitude, b.max_altitude] {
        m.extend_from_slice(&f64be(v));
    }
    crypto::sha256(&m).to_vec()
}

/// Re-derive the canonical `SEMANTIC_PREIMAGE`: domain-separated, fixed-order,
/// length-prefixed, big-endian — no protobuf re-serialization. Enum values use
/// the WIRE value (e.g. `SUBDIVISION = 6`), which is exactly what we decode.
fn semantic_preimage(proof: &LocationProof) -> Vec<u8> {
    let (region_type, region_id) = semantic_region(proof);
    let integrity_status = proof
        .device_attestation
        .as_ref()
        .and_then(|da| da.integrity_verdict.as_ref())
        .map(|iv| iv.status)
        .unwrap_or(0);

    let mut m = Vec::with_capacity(SEMANTIC_DOMAIN.len() + 24 + region_id.len() + proof.position_commitment.len());
    m.extend_from_slice(SEMANTIC_DOMAIN);
    m.extend_from_slice(&(proof.spoofing_verdict as u32).to_be_bytes());
    m.extend_from_slice(&(proof.level as u32).to_be_bytes());
    m.extend_from_slice(&(integrity_status as u32).to_be_bytes());
    m.extend_from_slice(&region_type.to_be_bytes());
    m.extend_from_slice(&(region_id.len() as u32).to_be_bytes());
    m.extend_from_slice(&region_id);
    m.extend_from_slice(&(proof.position_commitment.len() as u32).to_be_bytes());
    m.extend_from_slice(&proof.position_commitment);
    m
}

/// Domain-separation prefix for the **v2** semantic-field preimage
/// (octet-semantic-binding-v2, #26/#32): binds the city/earth geometry and the
/// inside/outside verdict that v1 omits. Byte-identical across the verifier, both
/// SDK signers, and the SDK's on-device verifier (tracker #54).
const SEMANTIC_DOMAIN_V2: &[u8] = b"octet-semantic-binding-v2";

/// v2 region digest: identical to [`semantic_region`] except `city` folds its
/// geometry (centre + radius) and `earth` folds its altitude cap — the v1 gaps
/// (#32). All other arms already fold their full identity/geometry under v1.
fn semantic_region_v2(proof: &LocationProof) -> (u32, Vec<u8>) {
    use crate::navigate::proof_region::Region::*;
    match proof.claimed_region.as_ref().and_then(|r| r.region.as_ref()) {
        Some(City(c)) => (3, city_digest_v2(c)),
        Some(Earth(e)) => (1, f64be(e.max_altitude_meters).to_vec()),
        _ => semantic_region(proof),
    }
}

/// city(3) v2 digest: `SHA256( u32be(len(name)) ‖ name ‖ f64be(lat) ‖ f64be(lon)
/// ‖ f64be(radius_meters) )`. Length-prefixing the name keeps `(name, geometry)`
/// unambiguous.
fn city_digest_v2(c: &crate::navigate::CityRegion) -> Vec<u8> {
    let name = c.name.as_bytes();
    let mut m = Vec::with_capacity(4 + name.len() + 24);
    m.extend_from_slice(&(name.len() as u32).to_be_bytes());
    m.extend_from_slice(name);
    m.extend_from_slice(&f64be(c.center_lat));
    m.extend_from_slice(&f64be(c.center_lon));
    m.extend_from_slice(&f64be(c.radius_meters));
    crypto::sha256(&m).to_vec()
}

/// v2 preimage: [`semantic_preimage`] under the v2 domain + v2 region digest,
/// with the raw `location_verdict` enum ordinal appended last (#26).
fn semantic_preimage_v2(proof: &LocationProof) -> Vec<u8> {
    let (region_type, region_id) = semantic_region_v2(proof);
    let integrity_status = proof
        .device_attestation
        .as_ref()
        .and_then(|da| da.integrity_verdict.as_ref())
        .map(|iv| iv.status)
        .unwrap_or(0);

    let mut m = Vec::with_capacity(
        SEMANTIC_DOMAIN_V2.len() + 28 + region_id.len() + proof.position_commitment.len(),
    );
    m.extend_from_slice(SEMANTIC_DOMAIN_V2);
    m.extend_from_slice(&(proof.spoofing_verdict as u32).to_be_bytes());
    m.extend_from_slice(&(proof.level as u32).to_be_bytes());
    m.extend_from_slice(&(integrity_status as u32).to_be_bytes());
    m.extend_from_slice(&region_type.to_be_bytes());
    m.extend_from_slice(&(region_id.len() as u32).to_be_bytes());
    m.extend_from_slice(&region_id);
    m.extend_from_slice(&(proof.position_commitment.len() as u32).to_be_bytes());
    m.extend_from_slice(&proof.position_commitment);
    m.extend_from_slice(&(proof.location_verdict as u32).to_be_bytes());
    m
}

/// Map the proto `location_verdict` ordinal to the signed trichotomy. UNSPECIFIED
/// (0) — or any unknown value — is `None`: "no signed verdict" (#26).
fn signed_verdict(v: i32) -> Option<SignedLocationVerdict> {
    match v {
        1 => Some(SignedLocationVerdict::Inside),
        2 => Some(SignedLocationVerdict::Outside),
        3 => Some(SignedLocationVerdict::Indeterminate),
        _ => None,
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

/// The canonical oneof-type tag of the claimed region, or `None` when the proof
/// carries no region. The seven tags match the `--expect-region-type` values.
fn region_type_tag(proof: &LocationProof) -> Option<&'static str> {
    use crate::navigate::proof_region::Region::*;
    Some(match proof.claimed_region.as_ref().and_then(|r| r.region.as_ref())? {
        Earth(_) => "earth",
        Country(_) => "country",
        Subdivision(_) => "subdivision",
        City(_) => "city",
        Ellipse(_) => "ellipse",
        H3PolygonSet(_) => "h3",
        BoundingBox3d(_) => "bbox",
    })
}

/// The `--expect-region-type` values a caller may supply. Exposed so the CLI can
/// reject a typo with a usage error rather than a silent mismatch.
pub const REGION_TYPES: [&str; 7] =
    ["earth", "country", "subdivision", "city", "ellipse", "h3", "bbox"];

/// True iff `s` names a known region type (case-insensitive).
pub fn is_known_region_type(s: &str) -> bool {
    REGION_TYPES.iter().any(|t| t.eq_ignore_ascii_case(s))
}

/// Does the proof's claimed region contain `(lat, lon)` (degrees)? Returns the
/// `region-contains` check status + detail. Geometric regions are evaluated with
/// pure spherical/planar math — no external data, no H3 library:
/// - `earth` always contains (2D; a lat/lon point can't test the altitude cap);
/// - `city` is a disc (centre + radius): haversine distance ≤ radius;
/// - `ellipse` uses a local east/north projection about its centre;
/// - `bbox` is a lat/lon range (altitude not testable from a 2D point).
///
/// Regions with no embedded geometry cannot be evaluated and FAIL (per #40's
/// "unevaluable ⇒ not satisfied"): `country`/`subdivision` carry only an ISO code
/// (use `--expect-region`), and `h3` needs an H3 library the lean build omits.
fn region_contains(proof: &LocationProof, lat: f64, lon: f64) -> (Status, String) {
    use crate::navigate::proof_region::Region::*;
    let at = format!("({lat:.5}, {lon:.5})");
    let yn = |inside: bool, what: &str| {
        if inside {
            (Status::Pass, format!("claimed {what} contains {at}"))
        } else {
            (Status::Fail, format!("claimed {what} does not contain {at}"))
        }
    };
    match proof.claimed_region.as_ref().and_then(|r| r.region.as_ref()) {
        None => (Status::Fail, format!("proof carries no region to contain {at}")),
        Some(Earth(_)) => (Status::Pass, format!("claimed earth region contains {at}")),
        Some(City(c)) => {
            yn(haversine_m(lat, lon, c.center_lat, c.center_lon) <= c.radius_meters, "city disc")
        }
        Some(BoundingBox3d(b)) => yn(
            lat >= b.min_latitude
                && lat <= b.max_latitude
                && lon >= b.min_longitude
                && lon <= b.max_longitude,
            "bounding box",
        ),
        Some(Ellipse(e)) => match ellipse_contains(e, lat, lon) {
            Some(inside) => yn(inside, "ellipse"),
            None => (
                Status::Fail,
                "claimed ellipse is degenerate (missing centre or non-positive axis); cannot evaluate containment".into(),
            ),
        },
        Some(Country(c)) => (
            Status::Fail,
            format!("claimed country {:?} carries no geometry; use --expect-region for named regions", c.iso_code),
        ),
        Some(Subdivision(s)) => (
            Status::Fail,
            format!("claimed subdivision {:?} carries no geometry; use --expect-region for named regions", s.iso_code),
        ),
        Some(H3PolygonSet(_)) => (
            Status::Fail,
            "h3 region point-containment is unsupported in this build (no H3 library); use --expect-region-type h3".into(),
        ),
    }
}

/// Great-circle distance in metres (spherical earth).
fn haversine_m(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    const R_M: f64 = 6_371_000.0;
    let (p1, p2) = (lat1.to_radians(), lat2.to_radians());
    let dlat = (lat2 - lat1).to_radians();
    let dlon = (lon2 - lon1).to_radians();
    let a = (dlat / 2.0).sin().powi(2) + p1.cos() * p2.cos() * (dlon / 2.0).sin().powi(2);
    2.0 * R_M * a.sqrt().atan2((1.0 - a).sqrt())
}

/// Point-in-ellipse via a local equirectangular projection about the centre.
/// `heading_deg` is the bearing (clockwise from north) of the semi-major axis.
/// `None` when the ellipse is degenerate (no centre, or a non-positive semi-axis).
fn ellipse_contains(e: &crate::navigate::EllipseRegion, lat: f64, lon: f64) -> Option<bool> {
    let c = e.center.as_ref()?;
    if e.semi_major_m <= 0.0 || e.semi_minor_m <= 0.0 {
        return None;
    }
    const R_M: f64 = 6_371_000.0;
    let clat = c.latitude.to_radians();
    // Local metres east/north of the centre (equirectangular; fine at ellipse scale).
    let dx = R_M * (lon - c.longitude).to_radians() * clat.cos();
    let dy = R_M * (lat - c.latitude).to_radians();
    // Project onto the major/minor axes. Bearing θ from north ⇒ the semi-major
    // unit vector is (sinθ, cosθ) in (east, north); the minor is (cosθ, −sinθ).
    let th = e.heading_deg.to_radians();
    let u = dx * th.sin() + dy * th.cos(); // along the semi-major axis
    let v = dx * th.cos() - dy * th.sin(); // along the semi-minor axis
    Some((u / e.semi_major_m).powi(2) + (v / e.semi_minor_m).powi(2) <= 1.0)
}

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

/// The typed identifier of the claimed region: `(kind, value)` where `kind` is
/// `"country"` / `"subdivision"` / `"city"`. Geometric regions (earth / ellipse
/// / h3 / bbox) and an absent region have no string identifier and return
/// `None`.
fn typed_region_id(proof: &LocationProof) -> Option<(&'static str, String)> {
    use crate::navigate::proof_region::Region::*;
    match proof.claimed_region.as_ref().and_then(|r| r.region.as_ref())? {
        Country(c) => Some(("country", c.iso_code.clone())),
        Subdivision(s) => Some(("subdivision", s.iso_code.clone())),
        City(c) => Some(("city", c.name.clone())),
        _ => None,
    }
}

/// Split an `--expect-region` value into an optional type prefix and the value:
/// `subdivision:US-CA` → `(Some("subdivision"), "US-CA")`, `US-CA` →
/// `(None, "US-CA")`. Only the three known kinds are recognised as prefixes, so
/// a value that merely contains a colon (an odd city name) is treated as bare.
fn split_region_expectation(want: &str) -> (Option<&'static str>, &str) {
    if let Some((pre, val)) = want.split_once(':') {
        for k in ["country", "subdivision", "city"] {
            if pre.eq_ignore_ascii_case(k) {
                return (Some(k), val);
            }
        }
    }
    (None, want)
}

/// Evaluate an armed `--expect-region` against the proof's claimed region,
/// returning the `region-claim` check status and detail.
///
/// SECURITY (issue #30): an armed expectation that cannot be evaluated is **not
/// satisfied**. A region with no string identifier (earth / ellipse / h3 / bbox)
/// or no region at all is a `Fail`, never `NotChecked` — mapping "cannot
/// evaluate" to `NotChecked` let an armed policy fail open, because
/// `is_valid()` ignores `NotChecked`. This mirrors `--session-nonce`, which
/// already fails closed on the same "nothing to check against" shape.
///
/// `want` may be typed (`country:US`, `subdivision:US-CA`, `city:San Francisco`)
/// to match type *and* value. The bare form (`US-CA`) is a back-compat alias
/// that matches a **country or subdivision** ISO code only — never a city name,
/// so a `CityRegion` named `"us-ca"` no longer satisfies `--expect-region US-CA`
/// (the untyped-namespace collision, same issue).
fn match_expected_region(proof: &LocationProof, want: &str, label: &str) -> (Status, String) {
    let Some((kind, id)) = typed_region_id(proof) else {
        return (
            Status::Fail,
            format!(
                "expected region {want:?} but proof carries a {label} region with no \
                 string identifier to match; refusing to vouch for an unchecked region claim"
            ),
        );
    };
    let (want_kind, want_val) = split_region_expectation(want);
    // An empty expected value (e.g. `--expect-region country:`) can never be a
    // meaningful assertion; refuse it rather than matching an empty identifier.
    if want_val.is_empty() {
        return (
            Status::Fail,
            format!("--expect-region {want:?} has an empty value; refusing to match"),
        );
    }
    let type_ok = match want_kind {
        // Typed: the claimed region's kind must match the requested kind.
        Some(wk) => wk == kind,
        // Bare alias: country/subdivision only — deliberately never a city.
        None => kind == "country" || kind == "subdivision",
    };
    if type_ok && id.eq_ignore_ascii_case(want_val) {
        (Status::Pass, format!("claims {label}, matches expected {want:?}"))
    } else {
        (Status::Fail, format!("claims {label}, expected {want:?}"))
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

    /// `is_fresh` reflects a *passing* freshness check only (Warn ≠ fresh), and
    /// `is_attested` reflects a passing hardware-attestation check (iOS App Attest
    /// or Android attestation-root), independent of authenticity.
    #[test]
    fn is_fresh_and_is_attested_are_distinct_typed_signals() {
        let mut fresh = Report::new();
        fresh.add("freshness", Status::Pass, "ok");
        assert!(fresh.is_fresh());
        assert!(!fresh.is_attested(), "no attestation check present");

        // A Warn freshness (slightly-future within skew) is not "fresh".
        let mut warned = Report::new();
        warned.add("freshness", Status::Warn, "slightly future");
        assert!(!warned.is_fresh());

        // Attested via iOS App Attest.
        let mut ios = Report::new();
        ios.add("app-attest", Status::Pass, "chained to Apple root");
        assert!(ios.is_attested());

        // Attested via Android key-attestation chain.
        let mut android = Report::new();
        android.add("attestation-root", Status::Pass, "chained to Google root");
        assert!(android.is_attested());

        // NOT-CHECKED / Fail attestation is not "attested".
        let mut unattested = Report::new();
        unattested.add("attestation-root", Status::NotChecked, "default build");
        unattested.add("app-attest", Status::Fail, "bad");
        assert!(!unattested.is_attested());
    }

    /// The proof's verdict is read via the prost-generated typed accessor
    /// `spoofing_verdict()` returning `LocationProofVerdict` — the 5-valued
    /// spoof-detection categorical the proof actually carries (no separate
    /// YES/NO/INDETERMINATE field exists). Confirms the accessor for consumers.
    #[test]
    fn spoofing_verdict_typed_accessor_round_trips() {
        use crate::navigate::LocationProofVerdict;
        let p = LocationProof {
            spoofing_verdict: LocationProofVerdict::Verified as i32,
            ..Default::default()
        };
        assert_eq!(p.spoofing_verdict(), LocationProofVerdict::Verified);
        // An unknown/unset value decodes to the 0 variant, never silently to NO.
        let unset = LocationProof::default();
        assert_eq!(unset.spoofing_verdict(), LocationProofVerdict::VerdictUnspecified);
    }

    /// `is_semantically_bound` reflects a passing `semantic-binding` check only —
    /// so a consumer can refuse to trust the verdict/region of a proof whose
    /// fields were never bound (NOT-CHECKED) or were tampered (Fail).
    #[test]
    fn is_semantically_bound_requires_a_passing_check() {
        let mut bound = Report::new();
        bound.add("semantic-binding", Status::Pass, "bound");
        assert!(bound.is_semantically_bound());

        let mut unbound = Report::new();
        unbound.add("semantic-binding", Status::NotChecked, "predates binding");
        assert!(!unbound.is_semantically_bound());

        let mut tampered = Report::new();
        tampered.add("semantic-binding", Status::Fail, "fields tampered");
        assert!(!tampered.is_semantically_bound());
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

    fn status_of(r: &Report, name: &str) -> Status {
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
                expect_region: None, expect_region_type: None, expect_region_contains: None,
                session_nonce: None,
                require_session_binding: false,
                require_schema_v2: false, require_attestation: false,
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
            hw_key_source: "test", expect_region: None, expect_region_type: None, expect_region_contains: None, session_nonce: None,
            require_session_binding: false, require_schema_v2: false, require_attestation: false,
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
            hw_key_source: "test", expect_region: None, expect_region_type: None, expect_region_contains: None, session_nonce: None,
            require_session_binding: false, require_schema_v2: false, require_attestation: false,
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
            hw_key_source: "test", expect_region: None, expect_region_type: None, expect_region_contains: None, session_nonce: None,
            require_session_binding: false, require_schema_v2: false, require_attestation: false,
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
            hw_key_source: "test", expect_region: None, expect_region_type: None, expect_region_contains: None, session_nonce: None,
            require_session_binding: false, require_schema_v2: false, require_attestation: false,
        });
        assert_eq!(status_of(&r, "freshness"), Status::Fail);
    }

    // --- semantic-field binding ---

    use crate::navigate::proof_region::Region;
    use crate::navigate::{CountryRegion, DeviceIntegrityVerdict, ProofRegion};

    /// Build a proof carrying a `semanticFields` stage whose hash matches its
    /// fields (VERIFIED / COUNTRY / `iso` / commitment / integrity status 3).
    fn proof_with_semantic_stage(verdict: i32, level: i32, iso: &str, commitment: Vec<u8>) -> LocationProof {
        let mut proof = LocationProof {
            spoofing_verdict: verdict,
            level,
            position_commitment: commitment,
            claimed_region: Some(ProofRegion {
                region: Some(Region::Country(CountryRegion { iso_code: iso.into() })),
            }),
            device_attestation: Some(DeviceAttestation {
                integrity_verdict: Some(DeviceIntegrityVerdict { status: 3, ..Default::default() }),
                ..Default::default()
            }),
            ..Default::default()
        };
        let preimage = semantic_preimage(&proof);
        proof.stage_attestations.push(StageAttestation {
            stage: SEMANTIC_FIELDS_STAGE.to_string(),
            timestamp_ms: 1,
            data_hash: sha256(&preimage).to_vec(),
            signature: vec![],
            previous_hash: None,
        });
        proof
    }

    fn semantic_status(proof: &LocationProof) -> Status {
        let mut r = Report::new();
        r.add_semantic_binding(proof, false);
        status_of(&r, "semantic-binding")
    }

    /// The bound fields verify; editing any of them after signing breaks the
    /// hash. This is the whole C1 (SUSPICIOUS→VERIFIED) / C2 (region/level
    /// rewrite) edit-attack class flipping VALID→INVALID.
    #[test]
    fn semantic_binding_passes_then_fails_on_tamper() {
        let good = proof_with_semantic_stage(1, 2, "US", vec![0xC0; 16]); // VERIFIED, COUNTRY, US
        assert_eq!(semantic_status(&good), Status::Pass);

        let mut verdict = good.clone();
        verdict.spoofing_verdict = 3; // SUSPICIOUS → VERIFIED edit
        assert_eq!(semantic_status(&verdict), Status::Fail);

        let mut region = good.clone();
        if let Some(Region::Country(c)) = region.claimed_region.as_mut().and_then(|r| r.region.as_mut()) {
            c.iso_code = "FR".into(); // US → FR rewrite
        }
        assert_eq!(semantic_status(&region), Status::Fail);

        let mut level = good.clone();
        level.level = 3;
        assert_eq!(semantic_status(&level), Status::Fail);

        let mut commitment = good.clone();
        commitment.position_commitment[0] ^= 0xFF; // commit-A/display-B
        assert_eq!(semantic_status(&commitment), Status::Fail);
    }

    /// #41: a bare `verify()` with `require_attestation` FAILs closed on ANY
    /// build — core records no passing attestation, so `is_attested()` is false.
    /// This is the fail-open the audit flagged: a public options field must not
    /// silently do nothing on an appattest build.
    #[test]
    fn require_attestation_fails_closed_on_bare_verify() {
        let proof = proof_with_semantic_stage(1, 2, "US", vec![0xC0; 16]);
        let opts = VerifyOptions {
            now_ms: 0,
            max_age_s: i64::MAX / 2,
            hardware_pubkey: None,
            hw_key_source: "test",
            expect_region: None,
            expect_region_type: None, expect_region_contains: None,
            session_nonce: None,
            require_session_binding: false,
            require_schema_v2: false,
            require_attestation: true,
        };
        let r = verify(&proof, &opts);
        assert!(
            r.checks.iter().any(|c| c.name == "attestation-required" && c.status == Status::Fail),
            "require_attestation must FAIL closed on a bare verify()"
        );
        assert!(!r.is_valid());
        // Disarmed: no attestation-required check at all.
        let opts_off = VerifyOptions { require_attestation: false, ..opts };
        assert!(verify(&proof, &opts_off).checks.iter().all(|c| c.name != "attestation-required"));
    }

    /// #41: `require_attestation_check` Passes iff a hardware attestation
    /// affirmatively verified (is_attested), Fails when evidence is merely
    /// NOT-CHECKED — platform-agnostic (either app-attest OR attestation-root).
    #[test]
    fn require_attestation_check_reflects_is_attested() {
        let attested = Report { checks: vec![Check { name: "attestation-root", status: Status::Pass, detail: String::new() }], ..Report::new() };
        assert_eq!(require_attestation_check(&attested).status, Status::Pass);
        // iOS: app-attest PASS also counts (attestation-root stays NOT-CHECKED there).
        let ios = Report { checks: vec![Check { name: "app-attest", status: Status::Pass, detail: String::new() }], ..Report::new() };
        assert_eq!(require_attestation_check(&ios).status, Status::Pass);
        // Only NOT-CHECKED evidence → FAIL (the strip-the-evidence amplifier).
        let bare = Report { checks: vec![Check { name: "attestation-root", status: Status::NotChecked, detail: String::new() }], ..Report::new() };
        assert_eq!(require_attestation_check(&bare).status, Status::Fail);
    }

    /// #40: `region_asserted()` is true only when an expectation was supplied AND
    /// it held — never on the informational `region-claim` Pass emitted when no
    /// expectation was given.
    #[test]
    fn region_asserted_requires_expectation_and_all_region_checks_pass() {
        let claim = |s| Check { name: "region-claim", status: s, detail: String::new() };
        let rtype = |s| Check { name: "region-type", status: s, detail: String::new() };

        // No expectation → not asserted, even though region-claim passed.
        let none = Report { checks: vec![claim(Status::Pass)], region_expectation: false, ..Report::new() };
        assert!(!none.region_asserted());

        // Expectation + region-claim Pass → asserted.
        let ok = Report { checks: vec![claim(Status::Pass)], region_expectation: true, ..Report::new() };
        assert!(ok.region_asserted());

        // Expectation + region-claim Fail → not asserted.
        let failed = Report { checks: vec![claim(Status::Fail)], region_expectation: true, ..Report::new() };
        assert!(!failed.region_asserted());

        // region-type present and failing → not asserted, even with claim Pass.
        let type_fail = Report {
            checks: vec![claim(Status::Pass), rtype(Status::Fail)],
            region_expectation: true,
            ..Report::new()
        };
        assert!(!type_fail.region_asserted());

        // Both region checks pass → asserted.
        let type_ok = Report {
            checks: vec![claim(Status::Pass), rtype(Status::Pass)],
            region_expectation: true,
            ..Report::new()
        };
        assert!(type_ok.region_asserted());
    }

    /// #40 item 4: the unarmed baseline — with no `--expect-region` /
    /// `--expect-region-type` / `--expect-region-contains`, `region-claim` is an
    /// informational PASS (it reports the claimed region), and `region_asserted()`
    /// is false because nothing was asserted. Complements the fail-closed armed
    /// cases; this "no expectation → Pass, not asserted" path was untested.
    #[test]
    fn no_region_expectation_passes_region_claim_and_is_not_asserted() {
        use crate::navigate::{proof_region::Region, CountryRegion, ProofRegion};
        let proof = LocationProof {
            claimed_region: Some(ProofRegion {
                region: Some(Region::Country(CountryRegion { iso_code: "US".into() })),
            }),
            ..Default::default()
        };
        let opts = VerifyOptions {
            now_ms: 0,
            max_age_s: i64::MAX / 2,
            hardware_pubkey: None,
            hw_key_source: "test",
            expect_region: None,
            expect_region_type: None,
            expect_region_contains: None,
            session_nonce: None,
            require_session_binding: false,
            require_schema_v2: false,
            require_attestation: false,
        };
        let report = verify(&proof, &opts);
        assert_eq!(
            report.checks.iter().find(|c| c.name == "region-claim").map(|c| c.status),
            Some(Status::Pass),
            "no expectation ⇒ region-claim is an informational PASS"
        );
        assert!(!report.region_asserted(), "no expectation supplied ⇒ nothing asserted");
    }

    /// #32: a matching semanticFields stage on a city/earth proof binds
    /// identity but NOT geometry under v1, so it reports Warn (not Pass) and
    /// `is_semantically_bound()` is false — while country stays Pass. Warn never
    /// rejects the proof.
    #[test]
    fn semantic_binding_warns_for_unbound_city_earth_geometry() {
        use crate::navigate::{CityRegion, EarthRegion};

        fn with_region(region: Region) -> LocationProof {
            let mut proof = LocationProof {
                spoofing_verdict: 1,
                level: 3,
                position_commitment: vec![0xC0; 16],
                claimed_region: Some(ProofRegion { region: Some(region) }),
                device_attestation: Some(DeviceAttestation {
                    integrity_verdict: Some(DeviceIntegrityVerdict { status: 3, ..Default::default() }),
                    ..Default::default()
                }),
                ..Default::default()
            };
            let preimage = semantic_preimage(&proof);
            proof.stage_attestations.push(StageAttestation {
                stage: SEMANTIC_FIELDS_STAGE.to_string(),
                timestamp_ms: 1,
                data_hash: sha256(&preimage).to_vec(),
                signature: vec![],
                previous_hash: None,
            });
            proof
        }

        let city = with_region(Region::City(CityRegion {
            name: "SF".into(),
            center_lat: 37.77,
            center_lon: -122.42,
            radius_meters: 5000.0,
        }));
        let earth = with_region(Region::Earth(EarthRegion::default()));
        let country = with_region(Region::Country(CountryRegion { iso_code: "US".into() }));

        // City/earth: identity bound, geometry not → Warn.
        assert_eq!(semantic_status(&city), Status::Warn);
        assert_eq!(semantic_status(&earth), Status::Warn);
        // Country: identity IS the region → fully Pass.
        assert_eq!(semantic_status(&country), Status::Pass);

        // Warn must not reject the proof, but is_semantically_bound() is false.
        let mut r = Report::new();
        r.add_semantic_binding(&city, false);
        assert!(r.is_valid(), "Warn must not fail the proof");
        assert!(!r.is_semantically_bound(), "city geometry is not bound under v1 (#32)");

        let mut rc = Report::new();
        rc.add_semantic_binding(&country, false);
        assert!(rc.is_semantically_bound(), "country is fully bound");

        // The Warn path must NOT weaken tamper detection of the *bound* fields:
        // editing the city name / verdict / level / commitment still FAILs (the
        // hash no longer matches). Only the uncovered geometry edit stays Warn.
        let mut renamed = city.clone();
        if let Some(Region::City(c)) = renamed.claimed_region.as_mut().and_then(|r| r.region.as_mut()) {
            c.name = "LA".into(); // bound identity edit
        }
        assert_eq!(semantic_status(&renamed), Status::Fail, "city name is bound; edit must FAIL");

        let mut reverdict = city.clone();
        reverdict.spoofing_verdict = 3;
        assert_eq!(semantic_status(&reverdict), Status::Fail, "verdict is bound; edit must FAIL");

        let mut recommit = city.clone();
        recommit.position_commitment[0] ^= 0xFF;
        assert_eq!(semantic_status(&recommit), Status::Fail, "commitment is bound; edit must FAIL");

        // The documented v1 gap: editing city geometry is NOT detected (stays Warn).
        let mut moved = city.clone();
        if let Some(Region::City(c)) = moved.claimed_region.as_mut().and_then(|r| r.region.as_mut()) {
            c.center_lat = 0.0;
            c.radius_meters = 2e7;
        }
        assert_eq!(semantic_status(&moved), Status::Warn, "geometry edit is the v1 gap: still Warn, not Fail");
    }

    /// #26/#32 — `octet-semantic-binding-v2` binds the city/earth GEOMETRY and the
    /// inside/outside verdict that v1 drops. A v2 proof is fully bound (city/earth
    /// Pass, not Warn), surfaces the signed verdict, and now detects tampering of
    /// the newly-bound fields.
    #[test]
    fn semantic_binding_v2_binds_geometry_and_verdict() {
        use crate::navigate::{
            proof_region::Region, CityRegion, DeviceIntegrityVerdict, EarthRegion, ProofRegion,
        };

        // A v2 proof: stage data_hash = SHA256(semantic_preimage_v2), plus a
        // signed inside/outside verdict.
        fn v2_proof(region: Region, verdict: i32) -> LocationProof {
            let mut proof = LocationProof {
                spoofing_verdict: 1,
                level: 3,
                position_commitment: vec![0xC0; 16],
                claimed_region: Some(ProofRegion { region: Some(region) }),
                location_verdict: verdict,
                device_attestation: Some(DeviceAttestation {
                    integrity_verdict: Some(DeviceIntegrityVerdict { status: 3, ..Default::default() }),
                    ..Default::default()
                }),
                ..Default::default()
            };
            let preimage = semantic_preimage_v2(&proof);
            proof.stage_attestations.push(StageAttestation {
                stage: SEMANTIC_FIELDS_STAGE.to_string(),
                timestamp_ms: 1,
                data_hash: sha256(&preimage).to_vec(),
                signature: vec![],
                previous_hash: None,
            });
            proof
        }

        let city = CityRegion { name: "SF".into(), center_lat: 37.77, center_lon: -122.42, radius_meters: 5000.0 };
        let proof = v2_proof(Region::City(city.clone()), 2 /* OUTSIDE */);

        // City geometry is now bound → PASS (not the v1 Warn), fully bound.
        let mut r = Report::new();
        r.add_semantic_binding(&proof, false);
        assert_eq!(semantic_status(&proof), Status::Pass, "v2 binds city geometry → Pass");
        assert!(r.is_semantically_bound(), "v2 city is fully bound");
        // The signed verdict is surfaced (OUTSIDE), distinct from None/absent.
        assert_eq!(r.location_verdict(), Some(SignedLocationVerdict::Outside));

        // Tampering the newly-bound geometry now FAILs (the v1 gap is closed).
        let mut moved = proof.clone();
        if let Some(Region::City(c)) = moved.claimed_region.as_mut().and_then(|r| r.region.as_mut()) {
            c.radius_meters = 2e7;
        }
        assert_eq!(semantic_status(&moved), Status::Fail, "v2 binds geometry: radius edit must FAIL");

        // Tampering the signed verdict FAILs.
        let mut flipped = proof.clone();
        flipped.location_verdict = 1; // OUTSIDE → INSIDE
        assert_eq!(semantic_status(&flipped), Status::Fail, "v2 binds the verdict: flip must FAIL");

        // Earth v2 binds max_altitude.
        let earth = v2_proof(Region::Earth(EarthRegion { max_altitude_meters: 12000.0 }), 1);
        assert_eq!(semantic_status(&earth), Status::Pass, "v2 binds earth altitude → Pass");
        let mut earth_moved = earth.clone();
        if let Some(Region::Earth(e)) = earth_moved.claimed_region.as_mut().and_then(|r| r.region.as_mut()) {
            e.max_altitude_meters = 99999.0;
        }
        assert_eq!(semantic_status(&earth_moved), Status::Fail, "v2 binds earth max_altitude: edit must FAIL");

        // INDETERMINATE survives as itself; UNSPECIFIED ⇒ no signed verdict (still bound).
        let indet = v2_proof(Region::City(city.clone()), 3);
        let mut ri = Report::new();
        ri.add_semantic_binding(&indet, false);
        assert_eq!(ri.location_verdict(), Some(SignedLocationVerdict::Indeterminate));

        let unspec = v2_proof(Region::City(city), 0);
        let mut ru = Report::new();
        ru.add_semantic_binding(&unspec, false);
        assert_eq!(ru.location_verdict(), None, "UNSPECIFIED ⇒ no signed verdict");
        assert_eq!(semantic_status(&unspec), Status::Pass, "still v2-bound with an UNSPECIFIED verdict");
    }

    /// v1 proofs stay accepted (cutover tolerance) and expose no signed verdict —
    /// absent ⇒ absent (#26).
    #[test]
    fn v1_proof_exposes_no_signed_location_verdict() {
        let proof = proof_with_semantic_stage(1, 3, "US", vec![0xC0; 16]);
        let mut r = Report::new();
        r.add_semantic_binding(&proof, false);
        assert_eq!(semantic_status(&proof), Status::Pass, "v1 country still binds (identity)");
        assert_eq!(r.location_verdict(), None, "v1 proof carries no signed verdict");
    }

    /// CROSS-REPO GOLDEN PIN (#345/#346): `SHA256(semantic_preimage_v2)` must
    /// equal the hex pinned on both signers + an independent Python
    /// reference — byte-identity across all four consumers (#54). Canonical inputs:
    /// commitment = 32×0x11, spoofing_verdict = VERIFIED(1), integrity_status = 3,
    /// city = "Springfield"/39.7817/-89.6501/5000.0, earth max_altitude 10000.0.


    #[test]
    fn semantic_preimage_v2_matches_sdk_golden_vectors() {
        use crate::navigate::{
            proof_region::Region, CityRegion, CountryRegion, DeviceIntegrityVerdict, EarthRegion,
            ProofRegion, SubdivisionRegion,
        };
        fn hex(b: &[u8]) -> String {
            b.iter().map(|x| format!("{x:02x}")).collect()
        }
        fn vector(region: Region, level: i32, verdict: i32) -> String {
            let proof = LocationProof {
                spoofing_verdict: 1,
                level,
                position_commitment: vec![0x11; 32],
                claimed_region: Some(ProofRegion { region: Some(region) }),
                location_verdict: verdict,
                device_attestation: Some(DeviceAttestation {
                    integrity_verdict: Some(DeviceIntegrityVerdict { status: 3, ..Default::default() }),
                    ..Default::default()
                }),
                ..Default::default()
            };
            hex(&sha256(&semantic_preimage_v2(&proof)))
        }
        let city = || Region::City(CityRegion {
            name: "Springfield".into(),
            center_lat: 39.7817,
            center_lon: -89.6501,
            radius_meters: 5000.0,
        });
        // ProofLevel: ON_EARTH=1, COUNTRY=2, CITY=3, SUBDIVISION=6.
        // country = "US", subdivision = "US-CA" (the SDK's canonical values,
        // confirmed against the pinned hex). ProofLevel: ON_EARTH=1, COUNTRY=2,
        // CITY=3, SUBDIVISION=6.
        assert_eq!(
            vector(Region::Country(CountryRegion { iso_code: "US".into() }), 2, 1),
            "3c0a463d570efa6355d140a222ad7cd6e7c70937142d78edcafc7221b50e1abb",
            "country + INSIDE"
        );
        assert_eq!(
            vector(city(), 3, 2),
            "e67ec33b5d20aefc4ffd2ca7ae4166fbb60b4e04265162c071a4253b161ed1bc",
            "city + OUTSIDE (geometry digest)"
        );
        assert_eq!(
            vector(Region::Earth(EarthRegion { max_altitude_meters: 10000.0 }), 1, 3),
            "abb238fce0313c9d063550dca7224fe5c0bd6576583ec172a0d2c86dd699d7fe",
            "earth + INDETERMINATE (max_altitude)"
        );
        assert_eq!(
            vector(Region::Subdivision(SubdivisionRegion { iso_code: "US-CA".into() }), 6, 1),
            "123a9b77dd50ee247862329f9e8bd00222239f72825afa05c5a605d71f89a5dd",
            "subdivision + INSIDE (level ≠ region_type)"
        );
        assert_eq!(
            vector(Region::Country(CountryRegion { iso_code: "US".into() }), 2, 0),
            "4977943b31f37b6cc4ed530f08d7d45efa71b2ff65083556695c9fb2ccbc185a",
            "country + UNSPECIFIED (verdict ordinal 0)"
        );
    }

    /// FULL-PIPELINE v2: a complete signed proof carrying a v2 semanticFields
    /// stage + a populated `location_verdict` verifies end-to-end through
    /// `verify()` — the exact shape of the on-device v2 e2e. Stages sign like the
    /// SDK (iOS raw ECDSA over `stage_message`); the semanticFields stage's
    /// data_hash is `SHA256(semantic_preimage_v2)`.
    #[test]
    fn full_v2_proof_verifies_end_to_end() {
        use crate::navigate::{
            proof_region::Region, CityRegion, DeviceIntegrityVerdict, ProofRegion, ZkProofData,
        };
        use p256::ecdsa::{signature::Signer, Signature, SigningKey};

        let sk = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let vk = *sk.verifying_key();
        let ts = 1_700_000_000_000i64;
        let sign_stage = |name: &str, data: &[u8], prev: Option<Vec<u8>>| -> StageAttestation {
            let st = StageAttestation {
                stage: name.into(),
                timestamp_ms: ts,
                data_hash: sha256(data).to_vec(),
                signature: vec![],
                previous_hash: prev,
            };
            let sig: Signature = sk.sign(&stage_message(&st));
            StageAttestation { signature: sig.to_bytes().to_vec(), ..st }
        };

        let commitment = vec![0xC0u8; 32];
        let nullifier = vec![0x1Au8; 32];
        let zk = vec![0x5Au8; 8];

        // Proof fields first — the v2 preimage is computed from these.
        let mut proof = LocationProof {
            id: "v2-dryrun".into(),
            spoofing_verdict: 1,
            level: 3, // CITY
            claimed_region: Some(ProofRegion {
                region: Some(Region::City(CityRegion {
                    name: "Springfield".into(),
                    center_lat: 39.7817,
                    center_lon: -89.6501,
                    radius_meters: 5000.0,
                })),
            }),
            zk_proof: Some(ZkProofData { proof_bytes: zk.clone(), ..Default::default() }),
            position_commitment: commitment.clone(),
            nullifier: nullifier.clone(),
            timestamp_ms: ts,
            location_verdict: 2, // OUTSIDE
            device_attestation: Some(DeviceAttestation {
                integrity_verdict: Some(DeviceIntegrityVerdict { status: 3, ..Default::default() }),
                ..Default::default()
            }),
            platform: "ios".into(),
            ..Default::default()
        };

        let v2_preimage = semantic_preimage_v2(&proof);
        let s0 = sign_stage("spoofDetection", b"verdict", None);
        let s1 = sign_stage("commitment", &commitment, Some(s0.data_hash.clone()));
        let s2 = sign_stage("nullifier", &nullifier, Some(s1.data_hash.clone()));
        let s3 = sign_stage("zkProof", &zk, Some(s2.data_hash.clone()));
        let s4 = sign_stage("semanticFields", &v2_preimage, Some(s3.data_hash.clone()));
        let mut concat = Vec::new();
        for s in [&s0, &s1, &s2, &s3, &s4] {
            concat.extend_from_slice(&s.signature);
        }
        let asm = sign_stage("proofAssembly", &concat, Some(s4.data_hash.clone()));
        proof.stage_attestations = vec![s0, s1, s2, s3, s4, asm];

        // Dev-only: `OCTET_EMIT_V2=<dir> cargo test full_v2_proof...` writes the
        // synthetic v2 proof + its pubkey so the CLI can be dry-run against it.
        if let Ok(dir) = std::env::var("OCTET_EMIT_V2") {
            use prost::Message;
            std::fs::write(format!("{dir}/v2-proof.bin"), proof.encode_to_vec()).unwrap();
            std::fs::write(format!("{dir}/v2-pubkey.sec1"), vk.to_sec1_bytes()).unwrap();
        }

        let opts = VerifyOptions {
            now_ms: ts,
            max_age_s: i64::MAX / 2,
            hardware_pubkey: Some(&vk),
            hw_key_source: "test",
            expect_region: None,
            expect_region_type: None,
            expect_region_contains: None,
            session_nonce: None,
            require_session_binding: false,
            require_schema_v2: false,
            require_attestation: false,
        };
        let report = verify(&proof, &opts);
        let st = |n: &str| report.checks.iter().find(|c| c.name == n).map(|c| c.status);

        assert_eq!(st("stage-signatures"), Some(Status::Pass), "stages must verify");
        assert_eq!(st("semantic-binding"), Some(Status::Pass), "v2 semantic binding must PASS");
        assert!(report.is_semantically_bound(), "v2 binds city geometry");
        assert_eq!(report.location_verdict(), Some(SignedLocationVerdict::Outside));
        assert!(report.is_authentic(), "a full v2 proof must be authentic");
        assert!(report.is_valid());
        let detail = report
            .checks
            .iter()
            .find(|c| c.name == "semantic-binding")
            .map(|c| c.detail.clone())
            .unwrap_or_default();
        assert!(detail.contains("octet-semantic-binding-v2"), "v2 detail: {detail}");
    }

    /// A proof with no semanticFields stage → NOT-CHECKED, never a pass.
    #[test]
    fn semantic_binding_not_checked_without_stage() {
        let mut proof = proof_with_semantic_stage(1, 2, "US", vec![0xC0; 16]);
        proof.stage_attestations.retain(|s| s.stage != SEMANTIC_FIELDS_STAGE);
        assert_eq!(semantic_status(&proof), Status::NotChecked);
    }

    /// Schema-v2 flip: with `require_schema_v2` armed, a proof lacking the
    /// `semanticFields` stage FAILs instead of NOT-CHECKED — while a proof that
    /// *does* carry a valid stage still PASSes regardless of the flag. Disarmed
    /// (the default) preserves the back-compat NOT-CHECKED, so pre-schema-v2
    /// golden vectors keep verifying.
    #[test]
    fn require_schema_v2_makes_semantic_binding_mandatory() {
        let mut no_stage = proof_with_semantic_stage(1, 2, "US", vec![0xC0; 16]);
        no_stage.stage_attestations.retain(|s| s.stage != SEMANTIC_FIELDS_STAGE);

        let status = |proof: &LocationProof, armed: bool| {
            let mut r = Report::new();
            r.add_semantic_binding(proof, armed);
            status_of(&r, "semantic-binding")
        };

        // Absent stage: disarmed → NOT-CHECKED (back-compat); armed → FAIL.
        assert_eq!(status(&no_stage, false), Status::NotChecked);
        assert_eq!(status(&no_stage, true), Status::Fail);

        // A validly-bound proof PASSes whether or not the flip is armed.
        let bound = proof_with_semantic_stage(1, 2, "US", vec![0xC0; 16]);
        assert_eq!(status(&bound, false), Status::Pass);
        assert_eq!(status(&bound, true), Status::Pass);
    }

    /// Geometric regions are bound via their canonical digest — a matching
    /// semanticFields stage PASSes; tampering a cell id FAILs.
    #[test]
    fn semantic_binding_passes_for_geometric_region() {
        use crate::navigate::H3PolygonSet;
        let mut proof = LocationProof {
            spoofing_verdict: 3,
            level: 3,
            position_commitment: vec![0x01; 16],
            claimed_region: Some(ProofRegion {
                region: Some(Region::H3PolygonSet(H3PolygonSet { cell_ids: vec![5, 3, 9, 1] })),
            }),
            ..Default::default()
        };
        let preimage = semantic_preimage(&proof);
        proof.stage_attestations.push(StageAttestation {
            stage: SEMANTIC_FIELDS_STAGE.to_string(),
            timestamp_ms: 1,
            data_hash: sha256(&preimage).to_vec(),
            signature: vec![],
            previous_hash: None,
        });
        assert_eq!(semantic_status(&proof), Status::Pass);

        let mut tampered = proof.clone();
        if let Some(Region::H3PolygonSet(h)) = tampered.claimed_region.as_mut().and_then(|r| r.region.as_mut()) {
            h.cell_ids.push(99);
        }
        assert_eq!(semantic_status(&tampered), Status::Fail);
    }

    /// Byte-exact cross-platform anchor: the h3 digest must equal the SDK's
    /// golden vector for the same cell ids — proving the unsigned sort + u64-BE +
    /// SHA256 match both platforms.
    #[test]
    fn h3_digest_matches_sdk_golden() {
        use crate::navigate::H3PolygonSet;
        let h = H3PolygonSet {
            cell_ids: vec![0x8528347bfffffff, 0x85283447fffffff, 0x85283473fffffff], // unsorted
        };
        let want: Vec<u8> = (0.."1e624617081f14bf0851f0fa38be06c633c8a5e95fe4837c2c633139a1fe3b92".len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&"1e624617081f14bf0851f0fa38be06c633c8a5e95fe4837c2c633139a1fe3b92"[i..i + 2], 16).unwrap())
            .collect();
        assert_eq!(h3_digest(&h), want, "h3 digest must match the SDK cross-platform golden");
    }

    /// SECURITY (issue #30): an armed `--expect-region` must fail closed. For
    /// every region type with no string identifier — and for a proof with no
    /// region at all — the result is `Fail`, never `NotChecked` (which
    /// `is_valid()` ignores, so the armed policy would fail open). Also covers
    /// the typed form and the closed untyped-namespace collision.
    #[test]
    fn expect_region_fails_closed_and_types_the_comparison() {
        use crate::navigate::{
            proof_region::Region, BoundingBox3DRegion, CityRegion, CountryRegion, EarthRegion,
            EllipseRegion, H3PolygonSet, ProofRegion, SubdivisionRegion,
        };

        fn proof_with(region: Option<Region>) -> LocationProof {
            LocationProof {
                claimed_region: region.map(|r| ProofRegion { region: Some(r) }),
                ..Default::default()
            }
        }
        fn status(p: &LocationProof, want: &str) -> Status {
            match_expected_region(p, want, &region_label(p)).0
        }

        let subdivision =
            proof_with(Some(Region::Subdivision(SubdivisionRegion { iso_code: "US-CA".into() })));
        let country = proof_with(Some(Region::Country(CountryRegion { iso_code: "US".into() })));
        let city = proof_with(Some(Region::City(CityRegion { name: "US-CA".into(), ..Default::default() })));
        let earth = proof_with(Some(Region::Earth(EarthRegion::default())));
        let ellipse = proof_with(Some(Region::Ellipse(EllipseRegion::default())));
        let h3 = proof_with(Some(Region::H3PolygonSet(H3PolygonSet { cell_ids: vec![1] })));
        let bbox = proof_with(Some(Region::BoundingBox3d(BoundingBox3DRegion::default())));
        let none = proof_with(None);

        // Named regions still match — bare (case-insensitive) and typed.
        assert_eq!(status(&subdivision, "US-CA"), Status::Pass);
        assert_eq!(status(&subdivision, "us-ca"), Status::Pass);
        assert_eq!(status(&subdivision, "subdivision:US-CA"), Status::Pass);
        assert_eq!(status(&country, "US"), Status::Pass);
        assert_eq!(status(&country, "country:us"), Status::Pass);
        assert_eq!(status(&city, "city:US-CA"), Status::Pass);

        // Wrong value, or right value with the wrong type, FAIL.
        assert_eq!(status(&subdivision, "FR-75"), Status::Fail);
        assert_eq!(status(&subdivision, "country:US-CA"), Status::Fail);

        // The untyped-namespace collision is closed: a city named "us-ca" no
        // longer satisfies the bare country/subdivision alias.
        assert_eq!(status(&city, "US-CA"), Status::Fail);

        // Fail closed for every identifier-less region (all four geometric
        // variants: earth/ellipse/h3/bbox) and for no region.
        for (p, kind) in [
            (&earth, "earth"),
            (&ellipse, "ellipse"),
            (&h3, "h3"),
            (&bbox, "bounding_box_3d"),
            (&none, "<no region>"),
        ] {
            assert_eq!(status(p, "US-CA"), Status::Fail, "{kind} must FAIL, not NOT-CHECKED");
        }

        // An empty typed value never matches (even a malformed empty-iso proof).
        let empty_country = proof_with(Some(Region::Country(CountryRegion { iso_code: String::new() })));
        assert_eq!(status(&empty_country, "country:"), Status::Fail);

        // Structural guarantee: an armed expectation is never NotChecked.
        for p in [&subdivision, &country, &city, &earth, &ellipse, &h3, &bbox, &none] {
            assert_ne!(status(p, "US-CA"), Status::NotChecked);
        }
    }

    /// #40: `--expect-region-contains` positively asserts a *geometric* region by
    /// point containment — the capability `--expect-region` (name match) can't
    /// provide. Geometric types are evaluated with pure math; regions with no
    /// embedded geometry (named country/subdivision, and h3 without an H3 lib)
    /// FAIL rather than pass, per #40's unevaluable-⇒-not-satisfied rule.
    #[test]
    fn region_contains_evaluates_geometric_regions() {
        use crate::navigate::{
            proof_region::Region, BoundingBox3DRegion, CityRegion, CountryRegion, EarthRegion,
            EllipseRegion, H3PolygonSet, LatLon, ProofRegion, SubdivisionRegion,
        };
        let proof = |region: Region| LocationProof {
            claimed_region: Some(ProofRegion { region: Some(region) }),
            ..Default::default()
        };
        let st = |r: Region, lat: f64, lon: f64| region_contains(&proof(r), lat, lon).0;
        let (sf_lat, sf_lon) = (37.7749, -122.4194); // San Francisco
        let (ny_lat, ny_lon) = (40.7128, -74.0060); // New York (far away)

        // earth contains anything.
        assert_eq!(st(Region::Earth(EarthRegion { max_altitude_meters: 10_000.0 }), ny_lat, ny_lon), Status::Pass);

        // city disc: 5 km radius about SF.
        let city = || Region::City(CityRegion {
            name: "SF".into(), center_lat: sf_lat, center_lon: sf_lon, radius_meters: 5_000.0,
        });
        assert_eq!(st(city(), 37.78, -122.42), Status::Pass); // ~1 km away → inside
        assert_eq!(st(city(), ny_lat, ny_lon), Status::Fail); // NY → outside

        // bbox around SF.
        let bbox = || Region::BoundingBox3d(BoundingBox3DRegion {
            min_latitude: 37.7, max_latitude: 37.8, min_longitude: -122.5, max_longitude: -122.4,
            min_altitude: 0.0, max_altitude: 1_000.0,
        });
        assert_eq!(st(bbox(), sf_lat, sf_lon), Status::Pass);
        assert_eq!(st(bbox(), ny_lat, ny_lon), Status::Fail);

        // ellipse: semi-major 3 km (north, heading 0), semi-minor 1 km (east).
        let ellipse = || Region::Ellipse(EllipseRegion {
            center: Some(LatLon { latitude: sf_lat, longitude: sf_lon }),
            semi_major_m: 3_000.0, semi_minor_m: 1_000.0, heading_deg: 0.0,
        });
        assert_eq!(st(ellipse(), sf_lat + 0.018, sf_lon), Status::Pass); // ~2 km N < 3 km major
        assert_eq!(st(ellipse(), sf_lat, sf_lon + 0.023), Status::Fail); // ~2 km E > 1 km minor

        // degenerate ellipse (non-positive axis) → FAIL.
        let degen = Region::Ellipse(EllipseRegion {
            center: Some(LatLon { latitude: sf_lat, longitude: sf_lon }),
            semi_major_m: 0.0, semi_minor_m: 0.0, heading_deg: 0.0,
        });
        assert_eq!(st(degen, sf_lat, sf_lon), Status::Fail);

        // No embedded geometry → FAIL (use --expect-region for named regions).
        assert_eq!(st(Region::Country(CountryRegion { iso_code: "US".into() }), sf_lat, sf_lon), Status::Fail);
        assert_eq!(st(Region::Subdivision(SubdivisionRegion { iso_code: "US-CA".into() }), sf_lat, sf_lon), Status::Fail);

        // h3 point-containment unsupported in the lean build → FAIL.
        assert_eq!(st(Region::H3PolygonSet(H3PolygonSet { cell_ids: vec![0x8528347bfffffff] }), sf_lat, sf_lon), Status::Fail);

        // No region at all → FAIL.
        let no_region = LocationProof { claimed_region: None, ..Default::default() };
        assert_eq!(region_contains(&no_region, sf_lat, sf_lon).0, Status::Fail);
    }

    /// #40: `--expect-region-type` is a positive type assertion — the
    /// counterpart to `--expect-region`, which can only *reject* an
    /// identifier-less region. Each variant PASSes its own type (case-
    /// insensitive) and FAILs any other; no region FAILs; unarmed emits nothing.
    #[test]
    fn expect_region_type_positively_asserts_each_variant() {
        use crate::navigate::{
            proof_region::Region, BoundingBox3DRegion, CityRegion, CountryRegion, EarthRegion,
            EllipseRegion, H3PolygonSet, ProofRegion, SubdivisionRegion,
        };

        fn proof_with(region: Option<Region>) -> LocationProof {
            LocationProof {
                claimed_region: region.map(|r| ProofRegion { region: Some(r) }),
                ..Default::default()
            }
        }
        fn opts(want_ty: Option<&str>) -> VerifyOptions<'_> {
            VerifyOptions {
                now_ms: 0,
                max_age_s: i64::MAX / 2,
                hardware_pubkey: None,
                hw_key_source: "test",
                expect_region: None,
                expect_region_type: want_ty,
                expect_region_contains: None,
                session_nonce: None,
                require_session_binding: false,
                require_schema_v2: false,
                require_attestation: false,
            }
        }
        fn type_status(p: &LocationProof, want_ty: &str) -> Option<Status> {
            verify(p, &opts(Some(want_ty)))
                .checks
                .into_iter()
                .find(|c| c.name == "region-type")
                .map(|c| c.status)
        }

        let cases = [
            ("earth", proof_with(Some(Region::Earth(EarthRegion::default())))),
            ("country", proof_with(Some(Region::Country(CountryRegion { iso_code: "US".into() })))),
            ("subdivision", proof_with(Some(Region::Subdivision(SubdivisionRegion { iso_code: "US-CA".into() })))),
            ("city", proof_with(Some(Region::City(CityRegion { name: "SF".into(), ..Default::default() })))),
            ("ellipse", proof_with(Some(Region::Ellipse(EllipseRegion::default())))),
            ("h3", proof_with(Some(Region::H3PolygonSet(H3PolygonSet { cell_ids: vec![1] })))),
            ("bbox", proof_with(Some(Region::BoundingBox3d(BoundingBox3DRegion::default())))),
        ];

        for (tag, proof) in &cases {
            assert_eq!(type_status(proof, tag), Some(Status::Pass), "{tag} should match its own type");
            assert_eq!(type_status(proof, &tag.to_uppercase()), Some(Status::Pass), "{tag} case-insensitive");
            for (other, _) in &cases {
                if other != tag {
                    assert_eq!(
                        type_status(proof, other),
                        Some(Status::Fail),
                        "{tag} must FAIL an armed --expect-region-type {other}"
                    );
                }
            }
        }

        // No region → FAIL (fail closed).
        assert_eq!(type_status(&proof_with(None), "earth"), Some(Status::Fail));
        // Unarmed → the region-type check is simply absent.
        assert!(verify(&cases[0].1, &opts(None)).checks.iter().all(|c| c.name != "region-type"));
        // Known-type predicate (drives the CLI usage-error path).
        assert!(is_known_region_type("EARTH") && is_known_region_type("bbox"));
        assert!(!is_known_region_type("province"));
    }

    /// #40: `--expect-region-contains` end-to-end through `verify()` — it adds a
    /// `region-contains` check and drives `region_asserted()`, and is absent when
    /// unarmed.
    #[test]
    fn expect_region_contains_wires_through_verify_and_region_asserted() {
        use crate::navigate::{proof_region::Region, CityRegion, ProofRegion};
        let city = LocationProof {
            claimed_region: Some(ProofRegion {
                region: Some(Region::City(CityRegion {
                    name: "SF".into(),
                    center_lat: 37.7749,
                    center_lon: -122.4194,
                    radius_meters: 5_000.0,
                })),
            }),
            ..Default::default()
        };
        let opts = |contains: Option<(f64, f64)>| VerifyOptions {
            now_ms: 0,
            max_age_s: i64::MAX / 2,
            hardware_pubkey: None,
            hw_key_source: "test",
            expect_region: None,
            expect_region_type: None,
            expect_region_contains: contains,
            session_nonce: None,
            require_session_binding: false,
            require_schema_v2: false,
            require_attestation: false,
        };

        // Point inside → region-contains PASS and the region is asserted.
        let inside = verify(&city, &opts(Some((37.78, -122.42))));
        assert_eq!(
            inside.checks.iter().find(|c| c.name == "region-contains").map(|c| c.status),
            Some(Status::Pass)
        );
        assert!(inside.region_asserted());

        // Point outside → region-contains FAIL and the region is not asserted.
        let outside = verify(&city, &opts(Some((40.7128, -74.0060))));
        assert_eq!(
            outside.checks.iter().find(|c| c.name == "region-contains").map(|c| c.status),
            Some(Status::Fail)
        );
        assert!(!outside.region_asserted());

        // Unarmed → no region-contains check, and nothing asserted.
        let unarmed = verify(&city, &opts(None));
        assert!(unarmed.checks.iter().all(|c| c.name != "region-contains"));
        assert!(!unarmed.region_asserted());
    }

    /// Independently re-derive the session-binding stage hash:
    /// `SHA256("octet-session-binding-v1" ‖ u32_be(len) ‖ nonce)`. Hand-written
    /// here (not via `session::`) so it doubles as a cross-check of that framing.
    fn session_data_hash(nonce: &[u8]) -> Vec<u8> {
        let mut m = Vec::new();
        m.extend_from_slice(b"octet-session-binding-v1");
        m.extend_from_slice(&(nonce.len() as u32).to_be_bytes());
        m.extend_from_slice(nonce);
        sha256(&m).to_vec()
    }

    /// `verify()` threads `VerifyOptions.session_nonce` into the report: absent →
    /// NOT-CHECKED, matching nonce → PASS, wrong nonce → FAIL.
    #[test]
    fn verify_wires_session_binding_check() {
        let nonce = b"login-42";
        let proof = LocationProof {
            stage_attestations: vec![StageAttestation {
                stage: "sessionBinding".into(),
                timestamp_ms: 1,
                data_hash: session_data_hash(nonce),
                signature: vec![],
                previous_hash: None,
            }],
            ..Default::default()
        };
        let run = |sn: Option<&[u8]>| {
            verify(&proof, &VerifyOptions {
                now_ms: 1, max_age_s: 300, hardware_pubkey: None,
                hw_key_source: "test", expect_region: None, expect_region_type: None, expect_region_contains: None, session_nonce: sn,
                require_session_binding: false, require_schema_v2: false, require_attestation: false,
            })
        };
        assert_eq!(status_of(&run(None), "session-binding"), Status::NotChecked);
        assert_eq!(status_of(&run(Some(nonce)), "session-binding"), Status::Pass);
        assert_eq!(status_of(&run(Some(b"wrong")), "session-binding"), Status::Fail);
    }

    /// Freshness keys on the `proofAssembly` stage BY NAME, not the last stage —
    /// a stage appended after `proofAssembly` must not shift the freshness time.
    #[test]
    fn freshness_keys_on_proof_assembly_by_name() {
        let sk = SigningKey::from_slice(&[7u8; 32]).unwrap();
        let now = 1_700_000_000_000i64;
        let mut proof = build_proof(&sk, now - 100_000); // proofAssembly ~100 s old → fresh
        proof.stage_attestations.push(StageAttestation {
            stage: "trailing".into(),
            timestamp_ms: now + 10_000_000, // far future; would flip freshness if used
            data_hash: vec![0u8; 32],
            signature: vec![],
            previous_hash: None,
        });
        let r = verify(&proof, &VerifyOptions {
            now_ms: now, max_age_s: 300, hardware_pubkey: None,
            hw_key_source: "test", expect_region: None, expect_region_type: None, expect_region_contains: None, session_nonce: None,
            require_session_binding: false, require_schema_v2: false, require_attestation: false,
        });
        // Uses proofAssembly's timestamp (fresh), not the trailing stage's.
        assert_eq!(status_of(&r, "freshness"), Status::Pass);
    }
}
