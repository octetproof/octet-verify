//! Offline Apple App Attest verification layer (feature `appattest`).
//!
//! Bridges a decoded [`LocationProof`] to the shared `octet-attest-verify`
//! crate: it pulls the App Attest fields off `DeviceAttestation`, supplies the
//! expected app identity, and turns the result into an `app-attest`
//! [`Check`]. We depend on the shared crate rather than re-implementing the
//! attestation crypto here, so the auditable logic lives in exactly one place.

use crate::navigate::{DeviceAttestation, LocationProof};
use crate::verify::{verify, Check, Report, Status, ValidationWindow, VerifyOptions};
use base64::Engine;
use octet_attest_verify::appattest::{
    attestation_chain_validity, verify_assertion_with_binding, verify_attestation,
    verify_device_signature, AppId, AssertionBinding, AttestedKey,
};
use octet_attest_verify::keyattest::{verify_key_attestation_multi, AttestMode, SecurityLevel};
// Re-export the app-identity types a consumer needs to build an `Expectation`,
// so downstream code needn't depend on `octet-attest-verify` directly.
pub use octet_attest_verify::appattest::AcceptEnvironment;
pub use octet_attest_verify::keyattest::ExpectedAppIdentity;
use sha2::{Digest, Sha256};

/// The trusted app identity a proof's attestation must bind to. In the Octet
/// flow this comes from the signed activation-bearer claim; standalone it comes
/// from config.
///
/// `app_id` / `accept_env` bind the **iOS** App Attest evidence. `android` is the
/// optional **Android** binding: when set, an Android proof's key-attestation
/// must name this package and signing-cert digest (see [`attestation_root_check`]);
/// when `None`, Android is checked to the hardware root only. The proof's evidence
/// shape selects which platform's identity is consulted.
///
/// `android_additional` widens the Android binding to a **set**: a licence that
/// ships several apps (or registers both a release and a debug signing cert)
/// accepts a proof bound to `android` OR to any one of these. Each identity is
/// matched whole — package AND its own cert — never a cross-product of packages
/// and certs (see [`attestation_root_check_multi`]). Empty (the default) is the
/// single-identity binding, unchanged.
pub struct Expectation {
    pub app_id: AppId,
    pub accept_env: AcceptEnvironment,
    pub android: Option<ExpectedAppIdentity>,
    pub android_additional: Vec<ExpectedAppIdentity>,
}

impl Expectation {
    /// iOS App Attest identity; Android binding left off (`android: None`).
    pub fn new(team_id: &str, bundle_id: &str, accept_env: AcceptEnvironment) -> Self {
        Expectation {
            app_id: AppId::from_team_and_bundle(team_id, bundle_id),
            accept_env,
            android: None,
            android_additional: Vec::new(),
        }
    }

    /// Additionally require Android proofs to be bound to this app identity —
    /// the `package_name` and the SHA-256 of the app signing certificate's DER.
    /// Opt-in: without this, Android proofs are checked to the hardware root only.
    pub fn with_android(mut self, package_name: impl Into<String>, signing_cert_sha256: [u8; 32]) -> Self {
        self.android = Some(ExpectedAppIdentity {
            package_name: package_name.into(),
            signing_cert_sha256,
        });
        self
    }

    /// Also accept Android proofs bound to this app identity (match-any over the
    /// set). Sets the primary [`Expectation::android`] identity if none is set
    /// yet, so a chain of `or_android` calls alone builds the whole set.
    pub fn or_android(mut self, package_name: impl Into<String>, signing_cert_sha256: [u8; 32]) -> Self {
        let id = ExpectedAppIdentity {
            package_name: package_name.into(),
            signing_cert_sha256,
        };
        if self.android.is_none() {
            self.android = Some(id);
        } else {
            self.android_additional.push(id);
        }
        self
    }

    /// Every accepted Android app identity: `android` followed by
    /// `android_additional`. Empty ⇒ hardware-root-only.
    pub fn android_identities(&self) -> Vec<ExpectedAppIdentity> {
        self.android
            .iter()
            .chain(&self.android_additional)
            .cloned()
            .collect()
    }
}

/// Name of the NOT-CHECKED line that accompanies every `app-attest` PASS.
pub const APP_ATTEST_VALIDITY: &str = "app-attest-validity";

/// The App Attest chain is verified to Apple's root by signature only. Its
/// validity dates are not checked at any time: the leaf certificate is valid for
/// about 3 days and is issued when the key is attested, usually long before the
/// proof, so judging it at the proof's time would reject almost every
/// assertion-only proof. Checking it at the attestation's own time needs a
/// trusted record of when the attestation happened, which a proof does not carry.
///
/// [`verify_attested_cached`] adds it after an `app-attest` PASS. A caller that
/// runs [`appattest_check`] itself should do the same.
pub fn appattest_validity_not_checked() -> Check {
    Check {
        name: APP_ATTEST_VALIDITY,
        status: Status::NotChecked,
        detail: "App Attest certificate validity dates not checked: the chain's signatures to \
                 Apple's root verified, but the leaf certificate is valid for about 3 days from \
                 attestation, which usually precedes the proof"
            .into(),
    }
}

/// A caller-given window for dating the App Attest chain: Unix milliseconds.
///
/// `upper_ms` is a time the caller trusts the attestation object existed by, such
/// as when it was anchored. `lower_ms` defaults to the leaf certificate's own
/// `notBefore` (about when the key was attested), so without it only the upper
/// bound tests anything. The verifier takes both times as given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppAttestWindow {
    pub lower_ms: Option<i64>,
    pub upper_ms: i64,
}

/// Date-check an App Attest attestation object's chain over `window`: the
/// `app-attest-validity` line, PASS when the leaf, the intermediate and the Apple
/// root are all valid at both bounds, FAIL otherwise. It replaces the NOT-CHECKED
/// line (see [`set_app_attest_validity`]).
///
/// Pass the object the verified key came from: the proof's own object, or the
/// enrolment bundle's. The dates are read without re-verifying the object, so
/// call it only after `app-attest` PASSed on a key from that object. Bounds round
/// outward to whole seconds (lower down, upper up), as for
/// [`attestation_root_check_window`].
pub fn appattest_validity_check(attestation_object: &[u8], window: &AppAttestWindow) -> Check {
    let fail = |detail: String| Check { name: APP_ATTEST_VALIDITY, status: Status::Fail, detail };
    let chain = match attestation_chain_validity(attestation_object) {
        Ok(c) => c,
        Err(e) => return fail(format!("could not read the App Attest chain's dates: {e}")),
    };
    let lower_s = match window.lower_ms {
        Some(ms) => ms.div_euclid(1000).max(0) as u64,
        None => chain.leaf_not_before,
    };
    let upper_s = window.upper_ms.saturating_add(999).div_euclid(1000).max(0) as u64;
    let lower_src = if window.lower_ms.is_some() { "given" } else { "the leaf's notBefore" };
    let span = format!(
        "[{} ({lower_src}), {}] (Unix s; the window's times are the caller's)",
        lower_s, upper_s
    );
    if lower_s > upper_s {
        return fail(format!("App Attest window {span} ends before it starts"));
    }
    let valid = format!("chain valid [{}, {}]", chain.not_before, chain.not_after);
    match (chain.contains(lower_s), chain.contains(upper_s)) {
        (true, true) => Check {
            name: APP_ATTEST_VALIDITY,
            status: Status::Pass,
            detail: format!("App Attest certificate chain valid at both bounds of {span}; {valid}"),
        },
        (false, _) => fail(format!("App Attest certificate chain not valid at the start of {span}; {valid}")),
        (true, false) => fail(format!("App Attest certificate chain not valid at the end of {span}; {valid}")),
    }
}

/// Put `check` (from [`appattest_validity_check`]) in place of the report's
/// `app-attest-validity` NOT-CHECKED line. That line is there only after an
/// `app-attest` PASS, so a report without it is left unchanged and this returns
/// `false`: there is no verified chain to date.
pub fn set_app_attest_validity(report: &mut Report, check: Check) -> bool {
    match report.checks.iter_mut().find(|c| c.name == APP_ATTEST_VALIDITY) {
        Some(line) => {
            *line = check;
            true
        }
        None => false,
    }
}

fn chk(status: Status, detail: impl Into<String>) -> Check {
    Check { name: "app-attest", status, detail: detail.into() }
}

/// How a live iOS App Attest assertion must commit to the key that signs the
/// proof. Since SDK 2.0.0 the assertion's `clientDataHash` is
/// `SHA256(nonce ‖ signing_key)`, so a genuine `(nonce, assertion)` pair can't be
/// replayed under a different signing key. Earlier SDKs signed `SHA256(nonce)`
/// only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AssertionPolicy {
    /// Accept only the bound form. The default: no device on an SDK before
    /// 2.0.0 has been active since 2026-10-07.
    RequireBound,
    /// Also accept the legacy nonce-only form, for verifying proofs archived
    /// from SDKs before 2.0.0. Such an assertion is reported as WARN, not PASS:
    /// it is genuine but not bound to the signing key, so the proof does not
    /// count as attested.
    AllowUnbound,
}

impl AssertionPolicy {
    /// The policy for these options: unbound assertions are allowed only when
    /// the caller opts in and does not also require attestation.
    pub fn from_options(opts: &VerifyOptions) -> Self {
        if opts.allow_unbound_app_attest && !opts.require_attestation {
            AssertionPolicy::AllowUnbound
        } else {
            AssertionPolicy::RequireBound
        }
    }
}

/// How [`appattest_check_da`] checks the assertion: the one-time enrolment
/// snapshot (always nonce-only), or a live proof's assertion.
#[derive(Clone, Copy)]
enum AssertionMode<'a> {
    Enrolment,
    Live { signing_key_sec1: Option<&'a [u8]>, policy: AssertionPolicy },
}

/// Verify `assertion` against `key` under `mode`. `Ok((counter, bound))`, where
/// `bound` is false only for a legacy nonce-only assertion that
/// [`AssertionPolicy::AllowUnbound`] accepted.
fn check_assertion(
    assertion: &[u8],
    nonce: &[u8],
    expect: &Expectation,
    key: &AttestedKey,
    mode: AssertionMode,
) -> Result<(u32, bool), String> {
    let verify = |binding| verify_assertion_with_binding(assertion, nonce, &expect.app_id, key, binding);
    match mode {
        AssertionMode::Enrolment => verify(AssertionBinding::NonceOnly).map(|c| (c, true)).map_err(|e| e.to_string()),
        AssertionMode::Live { signing_key_sec1: Some(sk), policy } => match verify(AssertionBinding::RequireBound { signing_key_sec1: sk }) {
            Ok(c) => Ok((c, true)),
            Err(e) if policy == AssertionPolicy::AllowUnbound => {
                verify(AssertionBinding::NonceOnly).map(|c| (c, false)).map_err(|_| e.to_string())
            }
            Err(e) => Err(e.to_string()),
        },
        AssertionMode::Live { signing_key_sec1: None, .. } => {
            verify(AssertionBinding::NonceOnly).map(|c| (c, false)).map_err(|e| e.to_string())
        }
    }
}

/// The `app-attest` result for a verified assertion: PASS when bound, WARN when
/// a legacy unbound assertion was accepted.
fn assertion_verified(what: String, bound: bool) -> Check {
    if bound {
        chk(Status::Pass, what)
    } else {
        chk(Status::Warn, format!(
            "{what}, in the legacy nonce-only form (SDK before 2.0.0): NOT bound to the proof's signing key, \
             accepted only because unbound assertions are allowed (--allow-unbound-app-attest)"))
    }
}

/// Verify the App Attest evidence carried on `proof`.
///
/// `cached` is a key recovered from a previous proof's attestation object, for
/// the assertion-only proofs that follow it within a key's lifetime. For a
/// stateless single-proof check pass `None`; then the proof must carry its own
/// attestation object (the first proof after a key is attested) to be verified.
///
/// Returns the `app-attest` check plus, when an attestation object was verified
/// or an assertion advanced the counter, the [`AttestedKey`] the caller should
/// cache (keyed by `key_id`) for subsequent proofs.
///
/// `signing_key_sec1` is the proof's Secure-Enclave signing key
/// (`certificate_chain[0]`, resolved by the caller), which the live assertion's
/// `clientDataHash` must commit to. Under [`AssertionPolicy::RequireBound`]
/// (the default) a legacy nonce-only assertion FAILs, and so does a proof with no
/// signing key to bind to. [`AssertionPolicy::AllowUnbound`] accepts a legacy
/// assertion as WARN.
pub fn appattest_check(
    proof: &LocationProof,
    expect: &Expectation,
    cached: Option<&AttestedKey>,
    signing_key_sec1: Option<&[u8]>,
    policy: AssertionPolicy,
) -> (Check, Option<AttestedKey>) {
    match &proof.device_attestation {
        Some(da) => appattest_check_da(da, expect, cached, AssertionMode::Live { signing_key_sec1, policy }),
        None => (chk(Status::NotChecked, "no device attestation on proof"), None),
    }
}

/// Verify a proof **and** its offline hardware attestation in one call — the
/// composed entry for a library consumer (e.g. a server-side decision service)
/// that wants a complete [`Report`] without hand-assembling the attestation
/// checks in the right order.
///
/// Runs [`crate::verify::verify`] (the core: stage signatures, freshness,
/// field/semantic/session bindings, region, wire-format) and then appends the
/// three checks the `appattest` feature adds — the same set, in the same order,
/// the CLI appends:
/// - `app-attest` — iOS Apple App Attest against `expect`;
/// - `attestation-root` — the Android key-attestation chain → the embedded
///   Google root (NOT-CHECKED for the iOS raw Secure-Enclave key);
/// - `device-attestation-sig` — the per-proof field-2 device-key signature.
///
/// The proof's evidence *shape* selects the platform path, so one call handles
/// both platforms; `expect` (an iOS App Attest app identity) is consumed only by
/// the `app-attest` check and ignored on Android. After this,
/// [`Report::is_attested`] is meaningful.
///
/// **Stateless** single-proof check (`cached: None`). An iOS proof that carries
/// only an assertion — i.e. every proof after the once-per-key attestation
/// object — reports `app-attest` NOT-CHECKED here. To attest those, keep a key
/// cache and use [`verify_attested_cached`], which threads the cached key and
/// returns the advanced key to re-persist.
pub fn verify_attested(proof: &LocationProof, opts: &VerifyOptions, expect: &Expectation) -> Report {
    verify_attested_cached(proof, opts, expect, None).0
}

/// [`verify_attested`] with an App Attest **key cache**, for a consumer that
/// verifies a stream of proofs from the same iOS key.
///
/// Pass `cached` = the [`AttestedKey`] recovered from that key's first,
/// attestation-object-bearing proof (via this call with `cached: None`, or via
/// [`appattest_enroll`] on an out-of-band bundle); later assertion-only proofs
/// then verify against it. Returns the report **and** the `AttestedKey` to
/// persist: on success it carries the advanced assertion counter, so re-storing
/// it after each proof keeps the counter monotonic. `None` is returned when no
/// key was recovered/advanced (e.g. Android, or a failed/absent iOS attestation)
/// — in that case keep whatever key you already had.
///
/// Android carries its full attestation on every proof, so it needs no cache;
/// pass `None` and ignore the returned key there.
pub fn verify_attested_cached(
    proof: &LocationProof,
    opts: &VerifyOptions,
    expect: &Expectation,
    cached: Option<&AttestedKey>,
) -> (Report, Option<AttestedKey>) {
    // Clear require_attestation for the core call: this layer appends the real
    // attestation checks below and re-applies the requirement afterward, so core
    // must not also evaluate it (it would FAIL before the attestation checks
    // exist). See.
    let core_opts = VerifyOptions { require_attestation: false, ..*opts };
    let mut report = verify(proof, &core_opts);
    // The key `stage-signatures` verified against (`certificate_chain[0]` on iOS,
    // the attestation leaf on Android). Binds both the Android attestation leaf
    // (issue) and the iOS App Attest assertion (issue) to the key that
    // actually signs each proof.
    let signing_key_sec1 = opts.hardware_pubkey.map(|vk| vk.to_sec1_bytes());

    // iOS App Attest against the cache (Android → NOT-CHECKED, no App Attest
    // fields).: the live assertion's clientDataHash must commit to
    // `signing_key_sec1`, unless the caller allows legacy unbound assertions. The
    // returned key (if any) carries the advanced counter for the caller to persist.
    let (app_attest, updated_key) = appattest_check(
        proof,
        expect,
        cached,
        signing_key_sec1.as_deref(),
        AssertionPolicy::from_options(opts),
    );
    let app_attest_passed = app_attest.status == Status::Pass;
    report.checks.push(app_attest);
    // A PASS above verified signatures only: the App Attest chain's validity dates
    // are never checked. Say so on every attested iOS proof, in every mode, so a
    // reader never takes the PASS as a date check (§4.1).
    if app_attest_passed {
        report.checks.push(appattest_validity_not_checked());
    }
    // Android key-attestation chain → Google root (iOS raw SE key → NOT-CHECKED),
    // bound to one of the expected app identities when any is set, and to the
    // signing key always.
    report.checks.push(attestation_root_check_for(
        proof,
        opts.now_ms,
        opts.validation_window,
        &expect.android_identities(),
        signing_key_sec1.as_deref(),
    ));
    // Per-proof field-2 device-key signature (both platforms).
    report.checks.push(device_signature_check(proof, signing_key_sec1.as_deref()));
    // Fail-closed when attestation is required: the attacker can otherwise
    // strip evidence so a check reports NOT-CHECKED (which is_valid() ignores).
    // Applied here, after the real attestation checks, using the core helper.
    if opts.require_attestation {
        let c = crate::verify::require_attestation_check(&report);
        report.checks.push(c);
    }
    (report, updated_key)
}

/// Compare two SEC1-encoded P-256 public keys for equality, tolerant of
/// compressed vs uncompressed encoding (both sides are parsed to the affine
/// point). A key that does not parse counts as **not** equal — fail closed.
fn sec1_keys_equal(a: &[u8], b: &[u8]) -> bool {
    use p256::ecdsa::VerifyingKey;
    match (VerifyingKey::from_sec1_bytes(a), VerifyingKey::from_sec1_bytes(b)) {
        (Ok(ka), Ok(kb)) => ka == kb,
        _ => false,
    }
}

// NOTE (issue): the iOS App Attest key (`DCAppAttestService`) and the
// Secure-Enclave field-2 signing key (`certificate_chain[0]`,
// `opts.hardware_pubkey`) are two DIFFERENT keys by design — App Attest keys
// cannot sign arbitrary data, so we do NOT require them to be equal (that would
// reject every genuine iOS proof). Instead the SDK commits the SE signing
// key into the live assertion's `clientDataHash` (`SHA256(nonce ‖ SE_pubkey)`)
// and this layer requires that binding ([`AssertionPolicy::RequireBound`], the
// default; [`AssertionPolicy::AllowUnbound`] accepts a legacy assertion as WARN
// for archived proofs). Android's signing-key binding is separate and lives
// in `attestation_root_check` (its StrongBox leaf both signs and is attested).

/// Core of [`appattest_check`] operating directly on a [`DeviceAttestation`],
/// shared with [`appattest_enroll`]. Pass `cached: None` for the object-bearing
/// path (first proof of a key, or an out-of-band enrolment bundle); pass the
/// cached key for the assertion-only proofs that follow in the key's lifetime.
fn appattest_check_da(
    da: &DeviceAttestation,
    expect: &Expectation,
    cached: Option<&AttestedKey>,
    mode: AssertionMode,
) -> (Check, Option<AttestedKey>) {
    let (nonce, assertion) = match (da.attestation_nonce.as_deref(), da.app_attest_assertion.as_deref()) {
        (Some(n), Some(a)) if !n.is_empty() && !a.is_empty() => (n, a),
        _ => {
            return (
                chk(Status::NotChecked, "no App Attest evidence (Android proof, or pre-attestation)"),
                None,
            )
        }
    };

    //: a live assertion must be bound to the Secure-Enclave signing key. With
    // no signing key resolved there is nothing to bind to: fail closed, never a
    // silent downgrade to nonce-only, unless legacy assertions are allowed.
    if let AssertionMode::Live { signing_key_sec1: None, policy: AssertionPolicy::RequireBound } = mode {
        return (
            chk(
                Status::Fail,
                "the iOS assertion must be bound to the proof's signing key, but no device \
                 signing key is available to bind it to",
            ),
            None,
        );
    }

    // Apple's key identifier rides as a base64 string on the wire.
    let key_id = match base64::engine::general_purpose::STANDARD.decode(&da.key_id) {
        Ok(k) => k,
        Err(_) => return (chk(Status::Fail, "key_id is not valid base64"), None),
    };

    match da.app_attest_attestation.as_deref() {
        // First proof of a key: verify the chain to Apple's root, recover the
        // key, then verify the assertion against it.
        Some(obj) => match verify_attestation(obj, nonce, &expect.app_id, &key_id, expect.accept_env) {
            Ok(key) => match check_assertion(assertion, nonce, expect, &key, mode) {
                Ok((counter, bound)) => (
                    assertion_verified(
                        format!("attestation chained to Apple App Attest root; assertion verified (counter {counter})"),
                        bound,
                    ),
                    Some(AttestedKey { last_counter: counter, ..key }),
                ),
                Err(e) => (chk(Status::Fail, format!("attestation valid but assertion failed: {e}")), None),
            },
            Err(e) => (chk(Status::Fail, format!("attestation verification failed: {e}")), None),
        },
        // Later proof in the key's lifetime: needs the cached key.
        None => match cached {
            None => (
                chk(Status::NotChecked,
                    "assertion present but this proof carries no attestation object and no cached key is available"),
                None,
            ),
            Some(key) => {
                // (rec): bind `key_id` to the cached key on the assertion
                // path too. `verify_attestation` enforces `key_id == SHA256(SPKI)`
                // on the object path, but the crate's assertion verify does not —
                // so without this a proof's `key_id` and the key its assertion is
                // checked against are only tied together by the *caller's* cache
                // lookup. Enforce it here so a (key_id, cached-key) pair that does
                // not hash-match is rejected regardless of how the cache was keyed.
                let expected_key_id: [u8; 32] = Sha256::digest(&key.public_key_sec1).into();
                if expected_key_id.as_slice() != key_id.as_slice() {
                    return (
                        chk(Status::Fail,
                            "key_id does not match the cached attested key (SHA-256(SPKI) mismatch)"),
                        None,
                    );
                }
                match check_assertion(assertion, nonce, expect, key, mode) {
                    Ok((counter, bound)) => (
                        assertion_verified(format!("assertion verified against cached key (counter {counter})"), bound),
                        Some(AttestedKey { last_counter: counter, public_key_sec1: key.public_key_sec1.clone() }),
                    ),
                    Err(e) => (chk(Status::Fail, format!("assertion failed: {e}")), None),
                }
            }
        },
    }
}

/// Newest schema version of the **JSON** enrolment bundle this verifier accepts.
/// `v:1` requires `app_attest_assertion`; `v:2` makes it optional (an object-only
/// bundle, see [`appattest_enroll`]). Both are accepted. The proto bundle path
/// evolves via protobuf field numbers, so this version tag is JSON-only.
pub const BUNDLE_SCHEMA_VERSION: u32 = 2;

/// Verify an out-of-band SDK-key **enrolment bundle** and return the
/// [`AttestedKey`] the caller should cache (keyed by `key_id`).
///
/// The bundle is the object-bearing [`DeviceAttestation`] subset
/// `{ key_id, app_attest_attestation, app_attest_assertion, attestation_nonce }`
/// the SDK delivers out of band, so a verifier can bootstrap a device key's
/// hardware root without waiting for the one object-bearing proof to happen to
/// arrive (the fresh-deploy / scale-out / cache-migration stranding this fixes).
///
/// It carries the attestation object together with the original nonce it was
/// attested with (`nonce₀`) and a matching assertion, so enrolment verifies the
/// object against that **embedded nonce** — there is no server challenge. That is
/// safe and is the same trust model [`appattest_check`] already relies on for the
/// first object-bearing proof: the object only recovers/certifies the *public*
/// key, while liveness and anti-replay come from per-proof assertions and the
/// replay-control nonce, never from enrolment.
///
/// A thin wrapper over the object-bearing branch of [`appattest_check`]
/// (`cached: None`): it requires the bundle to carry an attestation object and
/// returns the recovered key on success, or an error describing why the bundle
/// did not verify. The counter of the returned key is whatever the bundled
/// assertion carries — the verifier imposes no snapshot-vs-fresh policy; the SDK
/// owns that decision.
///
/// **Object-only bundle** (no `app_attest_assertion`, JSON `v:2`): the object is
/// verified the same way (Apple root, nonce, app identity, environment, `key_id`)
/// and the key's counter baseline is the object's own, which is 0. Nothing is lost:
/// the enrolment assertion only proved possession of the key once, and every proof
/// verified with the key still needs its own assertion. This is the form a
/// licence backend forwards when it holds the bootstrap object without the SDK's
/// local enrolment assertion.
pub fn appattest_enroll(
    da: &DeviceAttestation,
    expect: &Expectation,
) -> anyhow::Result<AttestedKey> {
    let Some(obj) = da.app_attest_attestation.as_deref().filter(|o| !o.is_empty()) else {
        anyhow::bail!("enrolment bundle carries no App Attest attestation object");
    };
    if da.app_attest_assertion.as_deref().is_none_or(<[u8]>::is_empty) {
        let nonce = da
            .attestation_nonce
            .as_deref()
            .filter(|n| !n.is_empty())
            .ok_or_else(|| anyhow::anyhow!("enrolment bundle carries no attestation nonce"))?;
        let key_id = base64::engine::general_purpose::STANDARD
            .decode(&da.key_id)
            .map_err(|_| anyhow::anyhow!("enrolment bundle key_id is not valid base64"))?;
        return verify_attestation(obj, nonce, &expect.app_id, &key_id, expect.accept_env)
            .map_err(|e| anyhow::anyhow!("enrolment bundle failed verification: attestation verification failed: {e}"));
    }
    // The enrolment snapshot assertion is always nonce-only (a one-time bootstrap,
    // not a per-proof replay vector) — no signing-key binding here.
    let (check, key) = appattest_check_da(da, expect, None, AssertionMode::Enrolment);
    key.ok_or_else(|| anyhow::anyhow!("enrolment bundle failed verification: {}", check.detail))
}

/// Deserialize a **JSON** enrolment bundle (schema `v:1`, or `v:2` with
/// `app_attest_assertion` optional) into a
/// [`DeviceAttestation`] ready for [`appattest_enroll`].
///
/// Every field is **base64url, no padding**, of the raw bytes — including
/// `key_id`, which is `b64url_nopad(raw credential-id bytes)`,
/// *not* the proto's base64-standard string. We re-encode `key_id` back to
/// base64-standard here because that is the on-wire proto-string form the
/// downstream [`appattest_check`] path decodes; the JSON and proto bundle paths
/// therefore converge on identical raw `key_id` bytes and the same cached key.
pub fn bundle_from_json(json: &[u8]) -> anyhow::Result<DeviceAttestation> {
    use anyhow::Context;

    #[derive(serde::Deserialize)]
    struct BundleJson {
        v: u32,
        key_id: String,
        app_attest_attestation: String,
        #[serde(default)]
        app_attest_assertion: Option<String>,
        attestation_nonce: String,
    }

    let b: BundleJson =
        serde_json::from_slice(json).context("enrolment bundle is not valid JSON")?;
    anyhow::ensure!(
        (1..=BUNDLE_SCHEMA_VERSION).contains(&b.v),
        "unsupported enrolment bundle schema version {} (expected 1 to {BUNDLE_SCHEMA_VERSION})",
        b.v,
    );
    anyhow::ensure!(
        b.v >= 2 || b.app_attest_assertion.is_some(),
        "enrolment bundle v:1 requires app_attest_assertion (an object-only bundle is v:2)",
    );

    let url = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let dec = |s: &str, field: &str| -> anyhow::Result<Vec<u8>> {
        url.decode(s)
            .with_context(|| format!("{field} is not valid base64url-no-pad"))
    };

    let key_id_raw = dec(&b.key_id, "key_id")?;
    Ok(DeviceAttestation {
        // Back to base64-standard: the proto-string form appattest_check decodes.
        key_id: base64::engine::general_purpose::STANDARD.encode(key_id_raw),
        app_attest_attestation: Some(dec(&b.app_attest_attestation, "app_attest_attestation")?),
        app_attest_assertion: b
            .app_attest_assertion
            .as_deref()
            .map(|a| dec(a, "app_attest_assertion"))
            .transpose()?,
        attestation_nonce: Some(dec(&b.attestation_nonce, "attestation_nonce")?),
        ..Default::default()
    })
}

/// Deserialize a **proto** enrolment bundle — the `DeviceAttestation` wire bytes
/// from the SDK's `toProto()` parity path — into a [`DeviceAttestation`] ready
/// for [`appattest_enroll`]. `key_id` stays in its existing base64-standard
/// proto-string form, untouched.
pub fn bundle_from_proto(bytes: &[u8]) -> anyhow::Result<DeviceAttestation> {
    use anyhow::Context;
    use prost::Message;
    DeviceAttestation::decode(bytes)
        .context("enrolment bundle is not a valid DeviceAttestation proto")
}

/// Verify the per-proof device-key signature (`DeviceAttestation.signature`,
/// field 2) — the offline check that turns `device-attestation-sig` from
/// `NOT-CHECKED` into a real verdict. It reconstructs the signed challenge from
/// the proof alone (`position_commitment`, `timestamp_ms`, `attestation_nonce`)
/// and verifies field 2 against the device public key — the same hardware key
/// the stage chain is verified against (`device_pubkey_sec1`, resolved by the
/// caller from the cert chain or a supplied key).
///
/// Returns the `device-attestation-sig` check: `Pass`/`Fail` when verifiable,
/// `NOT-CHECKED` when the proof carries no field-2 signature/nonce or no device
/// key is available.
pub fn device_signature_check(
    proof: &LocationProof,
    device_pubkey_sec1: Option<&[u8]>,
) -> Check {
    let d = |status: Status, detail: &str| Check {
        name: "device-attestation-sig",
        status,
        detail: detail.into(),
    };

    let da = match &proof.device_attestation {
        Some(da) if !da.signature.is_empty() => da,
        _ => return d(Status::NotChecked, "no device-attestation signature on proof"),
    };
    let nonce = match da.attestation_nonce.as_deref() {
        Some(n) if !n.is_empty() => n,
        _ => return d(Status::NotChecked, "no attestation nonce; field 2 not bound to a challenge"),
    };
    let pubkey = match device_pubkey_sec1 {
        Some(k) => k,
        None => return d(Status::NotChecked, "no device public key available to verify field 2"),
    };

    match verify_device_signature(
        &proof.position_commitment,
        proof.timestamp_ms,
        nonce,
        pubkey,
        &da.signature,
    ) {
        Ok(()) => d(
            Status::Pass,
            "device key signed this proof's commitment, timestamp, and nonce",
        ),
        Err(e) => d(Status::Fail, &format!("field-2 signature invalid: {e}")),
    }
}

/// The Android key-generation attestation challenge the SDK bakes into the
/// Keystore key at creation time — a constant: `SHA256("navigate-stage-chain-v1")`.
/// Keystore only honours the challenge at key creation, so it is fixed per key;
/// per-proof freshness is the nullifier + replay-control chain's job, not this.
fn android_keygen_challenge() -> [u8; 32] {
    Sha256::digest(b"navigate-stage-chain-v1").into()
}

/// The `attestation-root` check at the time [`VerifyOptions`] selects: at `now_ms`,
/// or over `validation_window` when one is set (see
/// [`attestation_root_check_window`]). Callers that run the attestation layer
/// themselves use this so both modes stay in one place.
pub fn attestation_root_check_for(
    proof: &LocationProof,
    now_ms: i64,
    validation_window: Option<ValidationWindow>,
    expected_apps: &[ExpectedAppIdentity],
    device_pubkey_sec1: Option<&[u8]>,
) -> Check {
    match validation_window {
        Some(w) => attestation_root_check_window(proof, w, expected_apps, device_pubkey_sec1),
        None => {
            let now_unix_secs = (now_ms / 1000).max(0) as u64;
            attestation_root_check_multi(proof, now_unix_secs, expected_apps, device_pubkey_sec1)
        }
    }
}

/// [`attestation_root_check_multi`] over a [`ValidationWindow`]: the chain must be
/// valid at both bounds of the window. A certificate validity period is a single
/// interval, so a chain valid at both bounds was valid at every instant between
/// them, including when the proof was signed. The lower bound rounds down and the
/// upper bound rounds up to whole seconds, so rounding never widens the window.
///
/// PASS needs both bounds to pass. A FAIL at either bound is a FAIL that names the
/// bound. Any other result (for example `NOT-CHECKED` for an iOS proof, which
/// carries no certificate chain) does not depend on time and is returned as is.
pub fn attestation_root_check_window(
    proof: &LocationProof,
    window: ValidationWindow,
    expected_apps: &[ExpectedAppIdentity],
    device_pubkey_sec1: Option<&[u8]>,
) -> Check {
    let lower_s = window.not_before_ms.div_euclid(1000).max(0) as u64;
    let upper_s = (window.not_after_ms.saturating_add(999)).div_euclid(1000).max(0) as u64;
    let at_lower = attestation_root_check_multi(proof, lower_s, expected_apps, device_pubkey_sec1);
    let at_upper = attestation_root_check_multi(proof, upper_s, expected_apps, device_pubkey_sec1);
    let span = format!("[{}, {}]", window.not_before_ms, window.not_after_ms);
    match (at_lower.status, at_upper.status) {
        (Status::Pass, Status::Pass) => Check {
            name: at_upper.name,
            status: Status::Pass,
            detail: format!("{} (valid at both bounds of the validation window {span})", at_upper.detail),
        },
        (Status::Fail, _) => Check {
            name: at_lower.name,
            status: Status::Fail,
            detail: format!("at the start of the validation window {span}: {}", at_lower.detail),
        },
        (_, Status::Fail) => Check {
            name: at_upper.name,
            status: Status::Fail,
            detail: format!("at the end of the validation window {span}: {}", at_upper.detail),
        },
        _ => at_upper,
    }
}

/// Validate the Android hardware key-attestation chain to a Google root
/// (`DeviceAttestation.certificate_chain`), turning `attestation-root` from
/// `NOT-CHECKED` into a real verdict. `now_unix_secs` drives the certificate
/// validity-window checks.
///
/// Only the Android path is an X.509 chain-to-Google-root. iOS carries a **raw
/// Secure Enclave SEC1 key** in `certificate_chain[0]` (the same key
/// `stage-signatures` already verifies against), not a cert chain — so on iOS
/// this reports `NOT-CHECKED` and the hardware-root assurance is the dedicated
/// `app-attest` check (Apple App Attest, see [`appattest_check`]). A proof with
/// no certificate chain at all likewise reports `NOT-CHECKED`.
pub fn attestation_root_check(
    proof: &LocationProof,
    now_unix_secs: u64,
    expected_app: Option<&ExpectedAppIdentity>,
    device_pubkey_sec1: Option<&[u8]>,
) -> Check {
    // Set-of-one (or empty) view over the single identity.
    let expected_apps = expected_app.map(std::slice::from_ref).unwrap_or(&[]);
    attestation_root_check_multi(proof, now_unix_secs, expected_apps, device_pubkey_sec1)
}

/// Like [`attestation_root_check`], but binds the Android chain to ONE OF a set
/// of app identities. The attested `attestationApplicationId` must match a single
/// listed identity in full — its package AND its own signing-cert digest — so a
/// set `{(A, cert1), (B, cert2)}` rejects a proof from `(A, cert2)`. An empty set
/// is the hardware-root-only check (same as `expected_app = None`).
pub fn attestation_root_check_multi(
    proof: &LocationProof,
    now_unix_secs: u64,
    expected_apps: &[ExpectedAppIdentity],
    device_pubkey_sec1: Option<&[u8]>,
) -> Check {
    let c = |status, detail: &str| Check {
        name: "attestation-root",
        status,
        detail: detail.into(),
    };
    let chain = match &proof.device_attestation {
        Some(da) if !da.certificate_chain.is_empty() => &da.certificate_chain,
        _ => {
            return c(
                Status::NotChecked,
                "no certificate chain present to anchor",
            )
        }
    };
    // Discriminate Android (X.509 chain) from iOS (raw SE key) by **shape**, not
    // by the editable `platform` field: a leaf[0] that parses as a SEC1 P-256
    // point is the iOS Secure Enclave key, which has no Google-root chain to walk.
    // Its hardware root is established by the `app-attest` check instead, so we
    // must not X.509-parse it (that FAILs with "expected SEQUENCE, got OCTET
    // STRING") — and must not overstate assurance by passing it here either.
    if p256::ecdsa::VerifyingKey::from_sec1_bytes(&chain[0]).is_ok() {
        return c(
            Status::NotChecked,
            "certificate_chain carries a raw Secure Enclave key (iOS), not an X.509 chain; \
             iOS hardware-root assurance is the app-attest check (Apple App Attest)",
        );
    }
    // `AttestMode::Proof` (2.0.0+): the proof-path posture — the crate's stricter
    // `Bootstrap` mode (verified-boot + revocation) is for licence minting, not
    // proof verification. Behaviour here is unchanged from the pre-2.0 call.
    match verify_key_attestation_multi(
        chain,
        &android_keygen_challenge(),
        now_unix_secs,
        expected_apps,
        AttestMode::Proof,
    ) {
        Ok(att) => {
            // SECURITY (issue): bind the attested leaf to the signing key. A
            // valid Google-rooted chain proves *some* StrongBox/TEE key is genuine
            // hardware; it says nothing about this proof unless that key is the one
            // that signed it. Without this, a genuine chain borrowed from another
            // device's proof confers `is_attested()` on any signing key.
            match device_pubkey_sec1 {
                None => {
                    return c(
                        Status::Fail,
                        "key-attestation chain is valid but no device signing key is \
                         available to bind it to",
                    )
                }
                Some(dev) if !sec1_keys_equal(&att.leaf_pubkey_sec1, dev) => {
                    return c(
                        Status::Fail,
                        "key-attestation chain attests a different key than the one that \
                         signed this proof",
                    )
                }
                Some(_) => {}
            }
            let lvl = match att.security_level {
                SecurityLevel::StrongBox => "StrongBox",
                SecurityLevel::TrustedEnvironment => "TEE",
                SecurityLevel::Software => "software", // rejected in-layer; unreachable
            };
            let app = match expected_apps.len() {
                0 => String::new(),
                1 => "; bound to the expected app identity".into(),
                n => format!("; bound to one of the {n} expected app identities"),
            };
            c(
                Status::Pass,
                &format!(
                    "chain validated to a Google hardware-attestation root; key is {lvl}-backed{app}"
                ),
            )
        }
        Err(e) => c(Status::Fail, &format!("key-attestation chain invalid: {e}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::navigate::{DeviceAttestation, LocationProof};

    fn expectation() -> Expectation {
        Expectation::new("6ZH5F97PWU", "com.octetproof.tester", AcceptEnvironment::Any)
    }

    fn proof_with(da: Option<DeviceAttestation>) -> LocationProof {
        LocationProof { device_attestation: da, timestamp_ms: 1_700_000_000_000, ..Default::default() }
    }

    #[test]
    fn no_device_attestation_is_not_checked() {
        let (c, key) = appattest_check(&proof_with(None), &expectation(), None, None, AssertionPolicy::AllowUnbound);
        assert_eq!(c.status, Status::NotChecked);
        assert!(key.is_none());
    }

    #[test]
    fn no_app_attest_fields_is_not_checked() {
        // An Android proof: device attestation present, but no App Attest fields.
        let da = DeviceAttestation { key_id: "abc".into(), ..Default::default() };
        let (c, _) = appattest_check(&proof_with(Some(da)), &expectation(), None, None, AssertionPolicy::AllowUnbound);
        assert_eq!(c.status, Status::NotChecked);
    }

    #[test]
    fn require_binding_without_signing_key_fails_closed() {
        //: a proof carrying an App Attest assertion, with binding REQUIRED
        // (--require-attestation) but no device signing key resolved, must FAIL —
        // never silently downgrade to the nonce-only form. The require flag is
        // exactly what flips it: the identical proof is NOT-CHECKED without it.
        let key_id = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);
        let da = DeviceAttestation {
            key_id,
            app_attest_assertion: Some(vec![1, 2, 3]),
            attestation_nonce: Some(vec![9; 32]),
            ..Default::default()
        };
        // require_binding = true, no signing key → fail closed.
        let (fail, key) =
            appattest_check(&proof_with(Some(da.clone())), &expectation(), None, None, AssertionPolicy::RequireBound);
        assert_eq!(fail.status, Status::Fail, "{}", fail.detail);
        assert!(fail.detail.contains("no device signing key"), "{}", fail.detail);
        assert!(key.is_none());
        // Same proof, binding NOT required → proceeds (NOT-CHECKED: no cached key).
        let (relaxed, _) =
            appattest_check(&proof_with(Some(da)), &expectation(), None, None, AssertionPolicy::AllowUnbound);
        assert_eq!(relaxed.status, Status::NotChecked);
    }

    /// A synthetic App Attest assertion (CBOR `{signature, authenticatorData}`)
    /// signed by `sk` over `SHA256(authData ‖ clientDataHash)`, as a device makes
    /// it. `signing_key_sec1` selects the bound form; `None` the legacy form.
    fn synthetic_assertion(
        sk: &p256::ecdsa::SigningKey,
        nonce: &[u8],
        signing_key_sec1: Option<&[u8]>,
        counter: u32,
    ) -> Vec<u8> {
        use p256::ecdsa::signature::Signer;
        let mut auth_data = expectation().app_id.0.to_vec();
        auth_data.push(0x40);
        auth_data.extend_from_slice(&counter.to_be_bytes());
        let mut cdh_input = nonce.to_vec();
        cdh_input.extend_from_slice(signing_key_sec1.unwrap_or_default());
        let client_data_hash = Sha256::digest(&cdh_input);
        let to_sign = Sha256::digest([auth_data.as_slice(), &client_data_hash[..]].concat());
        let sig: p256::ecdsa::Signature = sk.sign(&to_sign);
        let der = sig.to_der();
        let bytes = |out: &mut Vec<u8>, b: &[u8]| {
            out.extend_from_slice(&[0x58, b.len() as u8]);
            out.extend_from_slice(b);
        };
        let mut cbor = vec![0xA2, 0x69];
        cbor.extend_from_slice(b"signature");
        bytes(&mut cbor, der.as_bytes());
        cbor.push(0x71);
        cbor.extend_from_slice(b"authenticatorData");
        bytes(&mut cbor, &auth_data);
        cbor
    }

    ///: the bound form PASSes under both policies; the legacy nonce-only form
    /// FAILs by default and is a WARN (not attested) only when unbound
    /// assertions are allowed.
    #[test]
    fn legacy_assertions_fail_by_default_and_warn_when_allowed() {
        let attest_sk = p256::ecdsa::SigningKey::from_slice(&[7u8; 32]).unwrap();
        let attest_pub = attest_sk.verifying_key().to_encoded_point(false).as_bytes().to_vec();
        let cached = AttestedKey { public_key_sec1: attest_pub.clone(), last_counter: 0 };
        let se_pub = p256::ecdsa::SigningKey::from_slice(&[8u8; 32])
            .unwrap()
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let nonce = [9u8; 32];
        let da = |assertion: Vec<u8>| DeviceAttestation {
            key_id: base64::engine::general_purpose::STANDARD.encode(Sha256::digest(&attest_pub)),
            app_attest_assertion: Some(assertion),
            attestation_nonce: Some(nonce.to_vec()),
            ..Default::default()
        };
        let run = |assertion: Vec<u8>, sk: Option<&[u8]>, policy| {
            appattest_check(&proof_with(Some(da(assertion))), &expectation(), Some(&cached), sk, policy)
        };
        let bound = synthetic_assertion(&attest_sk, &nonce, Some(&se_pub), 5);
        let legacy = synthetic_assertion(&attest_sk, &nonce, None, 5);

        for policy in [AssertionPolicy::RequireBound, AssertionPolicy::AllowUnbound] {
            let (c, key) = run(bound.clone(), Some(&se_pub), policy);
            assert_eq!(c.status, Status::Pass, "{policy:?}: {}", c.detail);
            assert_eq!(key.unwrap().last_counter, 5);
        }

        let (c, key) = run(legacy.clone(), Some(&se_pub), AssertionPolicy::RequireBound);
        assert_eq!(c.status, Status::Fail, "{}", c.detail);
        assert!(key.is_none());

        let (c, key) = run(legacy.clone(), Some(&se_pub), AssertionPolicy::AllowUnbound);
        assert_eq!(c.status, Status::Warn, "{}", c.detail);
        assert!(c.detail.contains("NOT bound"), "{}", c.detail);
        assert_eq!(key.unwrap().last_counter, 5, "the counter still advances");

        // Bound to a different signing key: no policy accepts it.
        let other = synthetic_assertion(&attest_sk, &nonce, Some(&[4u8; 65]), 5);
        for policy in [AssertionPolicy::RequireBound, AssertionPolicy::AllowUnbound] {
            assert_eq!(run(other.clone(), Some(&se_pub), policy).0.status, Status::Fail, "{policy:?}");
        }

        // No signing key: FAIL by default, WARN when allowed.
        assert_eq!(run(legacy.clone(), None, AssertionPolicy::RequireBound).0.status, Status::Fail);
        assert_eq!(run(legacy, None, AssertionPolicy::AllowUnbound).0.status, Status::Warn);
    }

    /// Unbound assertions are allowed only on request, and never together with
    /// `require_attestation`.
    #[test]
    fn assertion_policy_from_options() {
        let opts = |allow, require| VerifyOptions {
            now_ms: 0, max_age_s: 0, hardware_pubkey: None, hw_key_source: "test",
            expect_region: None, expect_region_type: None, expect_region_contains: None,
            expect_region_contains_height_m: None, session_nonce: None, require_session_binding: false,
            require_schema_v2: false, require_attestation: require, allow_unbound_app_attest: allow,
            require_verdict: None, validation_window: None,
        };
        assert_eq!(AssertionPolicy::from_options(&opts(false, false)), AssertionPolicy::RequireBound);
        assert_eq!(AssertionPolicy::from_options(&opts(true, false)), AssertionPolicy::AllowUnbound);
        assert_eq!(AssertionPolicy::from_options(&opts(true, true)), AssertionPolicy::RequireBound);
        assert_eq!(AssertionPolicy::from_options(&opts(false, true)), AssertionPolicy::RequireBound);
    }

    #[test]
    fn assertion_only_without_cached_key_is_not_checked() {
        let key_id = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);
        let da = DeviceAttestation {
            key_id,
            app_attest_assertion: Some(vec![1, 2, 3]),
            attestation_nonce: Some(vec![9; 32]),
            ..Default::default()
        };
        let (c, key) = appattest_check(&proof_with(Some(da)), &expectation(), None, None, AssertionPolicy::AllowUnbound);
        assert_eq!(c.status, Status::NotChecked);
        assert!(key.is_none());
    }

    #[test]
    fn cached_path_binds_key_id_to_the_cached_key() {
        // (rec): on the assertion/cached path, `key_id` must hash-match the
        // cached key (SHA-256(SPKI)) — otherwise a (key_id, cached-key) pair that
        // doesn't correspond is rejected before the assertion is even checked.
        use sha2::{Digest, Sha256};
        let cached_pub = vec![4u8; 65]; // opaque "SPKI" bytes; identity is by hash
        let cached = AttestedKey { public_key_sec1: cached_pub.clone(), last_counter: 0 };

        // key_id that does NOT hash to the cached key → FAIL on the binding.
        let mismatched = DeviceAttestation {
            key_id: base64::engine::general_purpose::STANDARD.encode([0u8; 32]),
            app_attest_assertion: Some(vec![1, 2, 3]),
            attestation_nonce: Some(vec![9; 32]),
            ..Default::default()
        };
        let (c, k) =
            appattest_check(&proof_with(Some(mismatched)), &expectation(), Some(&cached), None, AssertionPolicy::AllowUnbound);
        assert_eq!(c.status, Status::Fail, "{}", c.detail);
        assert!(c.detail.contains("key_id does not match"), "{}", c.detail);
        assert!(k.is_none());

        // key_id == SHA-256(cached SPKI) → passes the binding gate, then fails on
        // the garbage assertion: a DIFFERENT error, proving the gate let it past.
        let matching = DeviceAttestation {
            key_id: base64::engine::general_purpose::STANDARD.encode(Sha256::digest(&cached_pub)),
            app_attest_assertion: Some(vec![1, 2, 3]),
            attestation_nonce: Some(vec![9; 32]),
            ..Default::default()
        };
        let (c2, _) =
            appattest_check(&proof_with(Some(matching)), &expectation(), Some(&cached), None, AssertionPolicy::AllowUnbound);
        assert_eq!(c2.status, Status::Fail, "{}", c2.detail);
        assert!(!c2.detail.contains("key_id does not match"), "gate should pass: {}", c2.detail);
        assert!(c2.detail.contains("assertion failed"), "{}", c2.detail);
    }

    #[test]
    fn bad_key_id_base64_fails() {
        let da = DeviceAttestation {
            key_id: "!!!not base64!!!".into(),
            app_attest_assertion: Some(vec![1, 2, 3]),
            attestation_nonce: Some(vec![9; 32]),
            app_attest_attestation: Some(vec![0xCB, 0x0B]),
            ..Default::default()
        };
        let (c, _) = appattest_check(&proof_with(Some(da)), &expectation(), None, None, AssertionPolicy::AllowUnbound);
        assert_eq!(c.status, Status::Fail);
        assert!(c.detail.contains("base64"));
    }

    #[test]
    fn garbage_attestation_object_fails() {
        let key_id = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);
        let da = DeviceAttestation {
            key_id,
            app_attest_assertion: Some(vec![1, 2, 3]),
            attestation_nonce: Some(vec![9; 32]),
            app_attest_attestation: Some(vec![0, 1, 2, 3]), // not a valid CBOR attestation
            ..Default::default()
        };
        let (c, key) = appattest_check(&proof_with(Some(da)), &expectation(), None, None, AssertionPolicy::AllowUnbound);
        assert_eq!(c.status, Status::Fail);
        assert!(key.is_none());
    }

    // --- enrolment bundle: appattest_enroll + bundle deserialization ---

    fn b64url(bytes: &[u8]) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    /// A JSON bundle string with all four fields b64url-no-pad, at schema `v`.
    fn json_bundle(v: u32, key_id: &[u8], obj: &[u8], assertion: &[u8], nonce: &[u8]) -> String {
        format!(
            r#"{{"v":{v},"key_id":"{}","app_attest_attestation":"{}","app_attest_assertion":"{}","attestation_nonce":"{}"}}"#,
            b64url(key_id), b64url(obj), b64url(assertion), b64url(nonce),
        )
    }

    #[test]
    fn bundle_from_json_decodes_fields_and_reencodes_key_id_to_standard() {
        let key_id_raw = [7u8; 32];
        let json = json_bundle(1, &key_id_raw, &[0xCB, 0x0B], &[1, 2, 3], &[9u8; 32]);
        let da = bundle_from_json(json.as_bytes()).unwrap();
        // key_id round-trips back to the raw bytes via base64-STANDARD — the
        // proto-string form the appattest_check path decodes.
        let got = base64::engine::general_purpose::STANDARD.decode(&da.key_id).unwrap();
        assert_eq!(got, key_id_raw);
        assert_eq!(da.app_attest_attestation.as_deref(), Some(&[0xCB, 0x0B][..]));
        assert_eq!(da.app_attest_assertion.as_deref(), Some(&[1, 2, 3][..]));
        assert_eq!(da.attestation_nonce.as_deref(), Some(&[9u8; 32][..]));
    }

    #[test]
    fn bundle_from_json_rejects_wrong_schema_version() {
        for v in [0, 3] {
            let json = json_bundle(v, &[0u8; 32], &[1], &[1], &[1]);
            let err = bundle_from_json(json.as_bytes()).unwrap_err().to_string();
            assert!(err.contains("schema version"), "v:{v}: {err}");
        }
    }

    /// An object-only JSON bundle: `v:2` without `app_attest_assertion`.
    fn object_only_json(v: u32) -> String {
        format!(
            r#"{{"v":{v},"key_id":"{}","app_attest_attestation":"{}","attestation_nonce":"{}"}}"#,
            b64url(&[7u8; 32]), b64url(&[0xCB, 0x0B]), b64url(&[9u8; 32]),
        )
    }

    #[test]
    fn bundle_from_json_v2_makes_the_assertion_optional() {
        let da = bundle_from_json(object_only_json(2).as_bytes()).unwrap();
        assert_eq!(da.app_attest_assertion, None);
        assert_eq!(da.app_attest_attestation.as_deref(), Some(&[0xCB, 0x0B][..]));
        // v:2 still accepts a bundle that does carry one.
        let full = json_bundle(2, &[7u8; 32], &[0xCB, 0x0B], &[1, 2, 3], &[9u8; 32]);
        assert_eq!(bundle_from_json(full.as_bytes()).unwrap().app_attest_assertion.as_deref(), Some(&[1, 2, 3][..]));
    }

    #[test]
    fn bundle_from_json_v1_still_requires_the_assertion() {
        let err = bundle_from_json(object_only_json(1).as_bytes()).unwrap_err().to_string();
        assert!(err.contains("v:1 requires app_attest_assertion"), "{err}");
    }

    #[test]
    fn bundle_from_json_rejects_bad_base64() {
        let json = r#"{"v":1,"key_id":"@@@","app_attest_attestation":"AA","app_attest_assertion":"AA","attestation_nonce":"AA"}"#;
        let err = bundle_from_json(json.as_bytes()).unwrap_err().to_string();
        assert!(err.contains("key_id"), "{err}");
    }

    #[test]
    fn bundle_from_json_key_id_is_b64url_not_standard() {
        // Encoding guard: the JSON key_id is base64url-no-pad of raw bytes, not
        // the proto's base64-standard string. The standard encoding of 32 bytes
        // carries '=' padding, which the url-no-pad decoder rejects.
        let std_key_id = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);
        assert!(std_key_id.contains('='));
        let json = format!(
            r#"{{"v":1,"key_id":"{std_key_id}","app_attest_attestation":"{}","app_attest_assertion":"{}","attestation_nonce":"{}"}}"#,
            b64url(&[1]), b64url(&[1]), b64url(&[1]),
        );
        assert!(bundle_from_json(json.as_bytes()).is_err());
    }

    #[test]
    fn bundle_from_proto_roundtrips_and_matches_json_key_id_bytes() {
        use prost::Message;
        let key_id_raw = [5u8; 16];
        // Proto keeps key_id as its base64-standard string form, untouched.
        let da_in = DeviceAttestation {
            key_id: base64::engine::general_purpose::STANDARD.encode(key_id_raw),
            app_attest_attestation: Some(vec![0xCB, 0x0B]),
            app_attest_assertion: Some(vec![1, 2, 3]),
            attestation_nonce: Some(vec![9; 32]),
            ..Default::default()
        };
        let da = bundle_from_proto(&da_in.encode_to_vec()).unwrap();
        let got = base64::engine::general_purpose::STANDARD.decode(&da.key_id).unwrap();
        assert_eq!(got, key_id_raw, "proto and JSON paths must converge on the same raw key_id");
        assert_eq!(da.app_attest_attestation, Some(vec![0xCB, 0x0B]));
    }

    #[test]
    fn enroll_requires_attestation_object() {
        // Assertion + nonce present but no object: not an enrolment bundle.
        let da = DeviceAttestation {
            key_id: base64::engine::general_purpose::STANDARD.encode([0u8; 32]),
            app_attest_assertion: Some(vec![1, 2, 3]),
            attestation_nonce: Some(vec![9; 32]),
            ..Default::default()
        };
        let err = appattest_enroll(&da, &expectation()).unwrap_err().to_string();
        assert!(err.contains("no App Attest attestation object"), "{err}");
    }

    #[test]
    fn enroll_fails_on_garbage_object() {
        // Object present but not valid CBOR → verification fails, so enrol
        // returns an error rather than a key (never a silent pass).
        let da = DeviceAttestation {
            key_id: base64::engine::general_purpose::STANDARD.encode([0u8; 32]),
            app_attest_attestation: Some(vec![0, 1, 2, 3]),
            app_attest_assertion: Some(vec![1, 2, 3]),
            attestation_nonce: Some(vec![9; 32]),
            ..Default::default()
        };
        assert!(appattest_enroll(&da, &expectation()).is_err());
    }

    #[test]
    fn enroll_via_json_bundle_reaches_verification() {
        // End-to-end plumbing: JSON bundle → DeviceAttestation → appattest_enroll.
        // A real object needs a device, so the garbage object fails verification;
        // this proves the deserialize→enrol path is wired and nonce-bound.
        let json = json_bundle(1, &[0u8; 32], &[0, 1, 2, 3], &[1, 2, 3], &[9u8; 32]);
        let da = bundle_from_json(json.as_bytes()).unwrap();
        assert!(appattest_enroll(&da, &expectation()).is_err());
    }

    // --- verify_attested (composed entry) ---

    #[test]
    fn verify_attested_composes_verify_plus_the_three_attestation_checks() {
        use crate::verify::{verify, VerifyOptions};
        let proof = proof_with(None); // bare proof, no attestation evidence
        let opts = VerifyOptions {
            now_ms: 1_700_000_000_000,
            max_age_s: 300,
            hardware_pubkey: None,
            hw_key_source: "test",
            expect_region: None, expect_region_type: None, expect_region_contains: None, expect_region_contains_height_m: None,
            session_nonce: None,
            require_session_binding: false,
            require_schema_v2: false, require_attestation: false, allow_unbound_app_attest: false, require_verdict: None, validation_window: None,
        };

        let report = verify_attested(&proof, &opts, &expectation());
        let names: Vec<&str> = report.checks.iter().map(|c| c.name).collect();
        for n in ["app-attest", "attestation-root", "device-attestation-sig"] {
            assert!(names.contains(&n), "verify_attested must append {n}; got {names:?}");
        }
        // A bare proof establishes no hardware attestation → fail-closed.
        assert!(!report.is_attested());

        // Contrast: plain verify() does NOT run the attestation layer.
        let plain = verify(&proof, &opts);
        assert!(!plain.checks.iter().any(|c| c.name == "app-attest"));
        assert!(!plain.is_attested());
    }

    #[test]
    fn verify_attested_cached_returns_report_plus_key_and_delegates() {
        use crate::verify::VerifyOptions;
        let proof = proof_with(None);
        let opts = VerifyOptions {
            now_ms: 1_700_000_000_000,
            max_age_s: 300,
            hardware_pubkey: None,
            hw_key_source: "test",
            expect_region: None, expect_region_type: None, expect_region_contains: None, expect_region_contains_height_m: None,
            session_nonce: None,
            require_session_binding: false,
            require_schema_v2: false, require_attestation: false, allow_unbound_app_attest: false, require_verdict: None, validation_window: None,
        };

        // Cached variant returns (Report, Option<AttestedKey>); a bare proof
        // recovers no key, and the same three attestation checks are appended.
        let (report, key) = verify_attested_cached(&proof, &opts, &expectation(), None);
        assert!(key.is_none());
        for n in ["app-attest", "attestation-root", "device-attestation-sig"] {
            assert!(report.checks.iter().any(|c| c.name == n), "missing {n}");
        }

        // verify_attested delegates to the cached path (None) → same checks.
        let plain = verify_attested(&proof, &opts, &expectation());
        for n in ["app-attest", "attestation-root", "device-attestation-sig"] {
            assert!(plain.checks.iter().any(|c| c.name == n), "delegation missing {n}");
        }
    }

    // --- device_signature_check (field 2) ---

    use octet_attest_verify::appattest::{se_client_data_hash, DEVICE_ATTESTATION_DOMAIN};
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};

    /// Build a proof whose field-2 signature is produced the way the SDK does:
    /// ECDSA-P256-SHA256 over `DOMAIN ‖ SHA256(commitment ‖ ts ‖ nonce)`.
    fn signed_field2_proof(sk: &SigningKey, commitment: &[u8], ts: i64, nonce: &[u8]) -> LocationProof {
        let mut msg = DEVICE_ATTESTATION_DOMAIN.to_vec();
        msg.extend_from_slice(&se_client_data_hash(commitment, ts, nonce));
        let sig: Signature = sk.sign(&msg);
        let da = DeviceAttestation {
            signature: sig.to_der().as_bytes().to_vec(),
            attestation_nonce: Some(nonce.to_vec()),
            ..Default::default()
        };
        LocationProof {
            device_attestation: Some(da),
            position_commitment: commitment.to_vec(),
            timestamp_ms: ts,
            ..Default::default()
        }
    }

    #[test]
    fn device_signature_passes_for_valid_field2() {
        let sk = SigningKey::from_slice(&[0x42u8; 32]).unwrap();
        let pk = sk.verifying_key().to_sec1_bytes().to_vec();
        let proof = signed_field2_proof(&sk, &[1, 2, 3], 1_700_000_000_000, &[9u8; 32]);
        let c = device_signature_check(&proof, Some(&pk));
        assert_eq!(c.status, Status::Pass, "{}", c.detail);
    }

    #[test]
    fn device_signature_fails_for_wrong_key() {
        let sk = SigningKey::from_slice(&[0x42u8; 32]).unwrap();
        let other = SigningKey::from_slice(&[0x43u8; 32]).unwrap();
        let pk = other.verifying_key().to_sec1_bytes().to_vec();
        let proof = signed_field2_proof(&sk, &[1, 2, 3], 1_700_000_000_000, &[9u8; 32]);
        assert_eq!(device_signature_check(&proof, Some(&pk)).status, Status::Fail);
    }

    #[test]
    fn device_signature_not_checked_without_pubkey() {
        let sk = SigningKey::from_slice(&[0x42u8; 32]).unwrap();
        let proof = signed_field2_proof(&sk, &[1, 2, 3], 1_700_000_000_000, &[9u8; 32]);
        assert_eq!(device_signature_check(&proof, None).status, Status::NotChecked);
    }

    #[test]
    fn device_signature_not_checked_without_attestation_or_nonce() {
        // No device attestation at all.
        assert_eq!(
            device_signature_check(&proof_with(None), Some(&[4u8; 65])).status,
            Status::NotChecked
        );
        // Signature present but no nonce → field 2 isn't bound to a challenge.
        let da = DeviceAttestation { signature: vec![1, 2, 3], ..Default::default() };
        assert_eq!(
            device_signature_check(&proof_with(Some(da)), Some(&[4u8; 65])).status,
            Status::NotChecked
        );
    }

    // --- attestation_root_check ---

    #[test]
    fn attestation_root_not_checked_without_chain() {
        // No device attestation (e.g. iOS App Attest path or a bare key).
        let c = attestation_root_check(&proof_with(None), 1_700_000_000, None, None);
        assert_eq!(c.status, Status::NotChecked);
        // Device attestation present but empty cert chain → still nothing to anchor.
        let da = DeviceAttestation { key_id: "k".into(), ..Default::default() };
        assert_eq!(
            attestation_root_check(&proof_with(Some(da)), 1_700_000_000, None, None).status,
            Status::NotChecked
        );
    }

    #[test]
    fn attestation_root_fails_for_garbage_chain() {
        // A non-empty but bogus chain must FAIL (not pass, not NOT-CHECKED) — the
        // verifier never vouches for a chain it cannot anchor to a Google root.
        let da = DeviceAttestation {
            certificate_chain: vec![vec![0xDE, 0xAD, 0xBE, 0xEF]],
            ..Default::default()
        };
        let c = attestation_root_check(&proof_with(Some(da)), 1_700_000_000, None, None);
        assert_eq!(c.status, Status::Fail, "{}", c.detail);
    }

    #[test]
    fn attestation_root_not_checked_for_ios_raw_se_key() {
        // iOS puts a raw SEC1 Secure Enclave key in certificate_chain[0]; it must
        // NOT be X.509-parsed (that FAILed every iOS proof). Shape detection →
        // NOT-CHECKED, deferring iOS hardware-root assurance to the app-attest check.
        let sk = SigningKey::from_slice(&[0x42u8; 32]).unwrap();
        let sec1 = sk.verifying_key().to_sec1_bytes().to_vec();
        let da = DeviceAttestation { certificate_chain: vec![sec1], ..Default::default() };
        let c = attestation_root_check(&proof_with(Some(da)), 1_700_000_000, None, None);
        assert_eq!(c.status, Status::NotChecked, "{}", c.detail);
        assert!(c.detail.contains("Secure Enclave"));
    }

    #[test]
    fn with_android_sets_the_expected_identity_opt_in() {
        let e = expectation().with_android("com.octetproof.sample", [7u8; 32]);
        let a = e.android.expect("android identity set");
        assert_eq!(a.package_name, "com.octetproof.sample");
        assert_eq!(a.signing_cert_sha256, [7u8; 32]);
        // new() alone leaves Android binding off.
        assert!(expectation().android.is_none());
        assert!(expectation().android_identities().is_empty());
    }

    #[test]
    fn or_android_builds_the_identity_set_in_order() {
        let e = expectation()
            .or_android("com.octetproof.sample.internal", [1u8; 32])
            .or_android("com.octetproof.sample.studio", [2u8; 32]);
        // The first or_android fills the primary slot, so single-identity
        // consumers reading `android` still see it.
        assert_eq!(e.android.as_ref().unwrap().package_name, "com.octetproof.sample.internal");
        let ids = e.android_identities();
        assert_eq!(ids.len(), 2);
        assert_eq!(ids[1].package_name, "com.octetproof.sample.studio");
        assert_eq!(ids[1].signing_cert_sha256, [2u8; 32]);
        // with_android + or_android compose the same way.
        let e2 = expectation().with_android("a", [1u8; 32]).or_android("b", [2u8; 32]);
        assert_eq!(e2.android_identities().len(), 2);
    }

    #[test]
    fn attestation_root_check_takes_expected_app_and_still_gates_on_the_chain() {
        let expected = ExpectedAppIdentity {
            package_name: "com.octetproof.sample".into(),
            signing_cert_sha256: [0u8; 32],
        };
        // A garbage chain fails regardless of the expected app (chain is checked
        // before the app-identity binding), so supplying it never loosens the gate.
        let da = DeviceAttestation { certificate_chain: vec![vec![0xDE, 0xAD]], ..Default::default() };
        assert_eq!(
            attestation_root_check(&proof_with(Some(da)), 1_700_000_000, Some(&expected), None).status,
            Status::Fail
        );
        // An iOS raw SE key is still NOT-CHECKED with an expected app — the Android
        // path (where app-binding lives) isn't taken for iOS.
        let sk = SigningKey::from_slice(&[0x42u8; 32]).unwrap();
        let sec1 = sk.verifying_key().to_sec1_bytes().to_vec();
        let ios = DeviceAttestation { certificate_chain: vec![sec1], ..Default::default() };
        assert_eq!(
            attestation_root_check(&proof_with(Some(ios)), 1_700_000_000, Some(&expected), None).status,
            Status::NotChecked
        );
    }

    #[test]
    fn android_keygen_challenge_is_the_pinned_constant() {
        // Pin the exact SDK key-generation challenge so a drift on either side is
        // caught: SHA-256("navigate-stage-chain-v1").
        let got = android_keygen_challenge();
        let want: [u8; 32] = Sha256::digest(b"navigate-stage-chain-v1").into();
        assert_eq!(got, want);
    }

    // --- SECURITY (issue): attestation must bind to the signing key ---

    #[test]
    fn sec1_equal_tolerates_compression_and_fails_closed() {
        use p256::ecdsa::{SigningKey, VerifyingKey};
        let vk: VerifyingKey = *SigningKey::from_slice(&[0x7u8; 32]).unwrap().verifying_key();
        let unc = vk.to_encoded_point(false).as_bytes().to_vec();
        let comp = vk.to_encoded_point(true).as_bytes().to_vec();
        assert_ne!(unc, comp, "compressed and uncompressed differ byte-wise");
        assert!(sec1_keys_equal(&unc, &comp), "same key, different encoding, must be equal");

        let other: VerifyingKey = *SigningKey::from_slice(&[0x8u8; 32]).unwrap().verifying_key();
        assert!(!sec1_keys_equal(&unc, other.to_encoded_point(false).as_bytes()));
        // Unparseable bytes are never equal — fail closed.
        assert!(!sec1_keys_equal(&unc, &[0u8; 10]));
    }
}
