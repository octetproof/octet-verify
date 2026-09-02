//! Offline Apple App Attest verification layer (feature `appattest`).
//!
//! Bridges a decoded [`LocationProof`] to the shared `octet-attest-verify`
//! crate: it pulls the App Attest fields off `DeviceAttestation`, supplies the
//! expected app identity, and turns the result into an `app-attest`
//! [`Check`]. We depend on the shared crate rather than re-implementing the
//! attestation crypto here, so the auditable logic lives in exactly one place.

use crate::navigate::{DeviceAttestation, LocationProof};
use crate::verify::{verify, Check, Report, Status, VerifyOptions};
use base64::Engine;
use octet_attest_verify::appattest::{
    verify_assertion_with_binding, verify_attestation, verify_device_signature, AppId,
    AssertionBinding, AttestedKey,
};
use octet_attest_verify::keyattest::{verify_key_attestation, AttestMode, SecurityLevel};
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
pub struct Expectation {
    pub app_id: AppId,
    pub accept_env: AcceptEnvironment,
    pub android: Option<ExpectedAppIdentity>,
}

impl Expectation {
    /// iOS App Attest identity; Android binding left off (`android: None`).
    pub fn new(team_id: &str, bundle_id: &str, accept_env: AcceptEnvironment) -> Self {
        Expectation {
            app_id: AppId::from_team_and_bundle(team_id, bundle_id),
            accept_env,
            android: None,
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
}

fn chk(status: Status, detail: impl Into<String>) -> Check {
    Check { name: "app-attest", status, detail: detail.into() }
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
/// (`certificate_chain[0]`, resolved by the caller) — folded into the live
/// assertion's `clientDataHash` for the #38 binding. `require_binding` (the
/// `--require-attestation` flag) enforces the bound form: with a signing key it
/// selects `RequireBound` (a pre-#317 nonce-only assertion is rejected), else
/// `PreferBound` (rollout: accept either). `None` signing key with
/// `require_binding` fails closed.
pub fn appattest_check(
    proof: &LocationProof,
    expect: &Expectation,
    cached: Option<&AttestedKey>,
    signing_key_sec1: Option<&[u8]>,
    require_binding: bool,
) -> (Check, Option<AttestedKey>) {
    match &proof.device_attestation {
        Some(da) => appattest_check_da(da, expect, cached, signing_key_sec1, require_binding),
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
    // exist). See #41.
    let core_opts = VerifyOptions { require_attestation: false, ..*opts };
    let mut report = verify(proof, &core_opts);
    // The key `stage-signatures` verified against (`certificate_chain[0]` on iOS,
    // the attestation leaf on Android). Binds both the Android attestation leaf
    // (issue #31) and the iOS App Attest assertion (issue #38) to the key that
    // actually signs each proof.
    let signing_key_sec1 = opts.hardware_pubkey.map(|vk| vk.to_sec1_bytes());

    // iOS App Attest against the cache (Android → NOT-CHECKED, no App Attest
    // fields). #38 folds `signing_key_sec1` into the live assertion's
    // clientDataHash; `opts.require_attestation` selects RequireBound (enforce)
    // vs PreferBound (rollout). The returned key (if any) carries the advanced
    // counter for the caller to persist.
    let (app_attest, updated_key) = appattest_check(
        proof,
        expect,
        cached,
        signing_key_sec1.as_deref(),
        opts.require_attestation,
    );
    report.checks.push(app_attest);
    // Android key-attestation chain → Google root (iOS raw SE key → NOT-CHECKED),
    // bound to the expected app identity when `expect.android` is set, and to the
    // signing key always.
    let now_unix_secs = (opts.now_ms / 1000).max(0) as u64;
    report.checks.push(attestation_root_check(
        proof,
        now_unix_secs,
        expect.android.as_ref(),
        signing_key_sec1.as_deref(),
    ));
    // Per-proof field-2 device-key signature (both platforms).
    report.checks.push(device_signature_check(proof, signing_key_sec1.as_deref()));
    // Fail-closed when attestation is required (#41): the attacker can otherwise
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

// NOTE (issue #38): the iOS App Attest key (`DCAppAttestService`) and the
// Secure-Enclave field-2 signing key (`certificate_chain[0]`,
// `opts.hardware_pubkey`) are two DIFFERENT keys by design — App Attest keys
// cannot sign arbitrary data, so we do NOT require them to be equal (that would
// reject every genuine iOS proof). Instead the SDK (#317) commits the SE signing
// key into the live assertion's `clientDataHash` (`SHA256(nonce ‖ SE_pubkey)`)
// and this layer reconstructs that binding via the `AssertionBinding` passed to
// `appattest_check` (PreferBound during rollout, RequireBound under
// `--require-attestation`). Android's signing-key binding is separate and lives
// in `attestation_root_check` (its StrongBox leaf both signs and is attested).

/// Core of [`appattest_check`] operating directly on a [`DeviceAttestation`],
/// shared with [`appattest_enroll`]. Pass `cached: None` for the object-bearing
/// path (first proof of a key, or an out-of-band enrolment bundle); pass the
/// cached key for the assertion-only proofs that follow in the key's lifetime.
fn appattest_check_da(
    da: &DeviceAttestation,
    expect: &Expectation,
    cached: Option<&AttestedKey>,
    signing_key_sec1: Option<&[u8]>,
    require_binding: bool,
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

    // #38: how the live assertion's clientDataHash is reconstructed. The enrol /
    // attestation-object path and pre-#317 SDKs are nonce-only; a #317 live proof
    // folds the Secure-Enclave signing key in. PreferBound accepts either during
    // rollout; RequireBound (the `--require-attestation` flag) enforces the bound
    // form. Binding required but no signing key resolved ⇒ fail closed, never a
    // silent downgrade to nonce-only.
    let binding = match (signing_key_sec1, require_binding) {
        (Some(sk), true) => AssertionBinding::RequireBound { signing_key_sec1: sk },
        (Some(sk), false) => AssertionBinding::PreferBound { signing_key_sec1: sk },
        (None, false) => AssertionBinding::NonceOnly,
        (None, true) => {
            return (
                chk(
                    Status::Fail,
                    "iOS assertion binding required (--require-attestation) but no device \
                     signing key is available to bind the assertion to",
                ),
                None,
            )
        }
    };

    // Apple's key identifier rides as a base64 string on the wire.
    let key_id = match base64::engine::general_purpose::STANDARD.decode(&da.key_id) {
        Ok(k) => k,
        Err(_) => return (chk(Status::Fail, "key_id is not valid base64"), None),
    };

    match da.app_attest_attestation.as_deref() {
        // First proof of a key: verify the chain to Apple's root, recover the
        // key, then verify the assertion against it.
        Some(obj) => match verify_attestation(obj, nonce, &expect.app_id, &key_id, expect.accept_env) {
            Ok(key) => match verify_assertion_with_binding(assertion, nonce, &expect.app_id, &key, binding) {
                Ok(counter) => (
                    chk(Status::Pass,
                        format!("attestation chained to Apple App Attest root; assertion verified (counter {counter})")),
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
                // #41 (rec #5): bind `key_id` to the cached key on the assertion
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
                match verify_assertion_with_binding(assertion, nonce, &expect.app_id, key, binding) {
                    Ok(counter) => (
                        chk(Status::Pass, format!("assertion verified against cached key (counter {counter})")),
                        Some(AttestedKey { last_counter: counter, public_key_sec1: key.public_key_sec1.clone() }),
                    ),
                    Err(e) => (chk(Status::Fail, format!("assertion failed: {e}")), None),
                }
            }
        },
    }
}

/// Schema version of the **JSON** enrolment bundle this verifier accepts. The
/// proto bundle path evolves via protobuf field numbers, so this version tag is
/// JSON-only.
pub const BUNDLE_SCHEMA_VERSION: u32 = 1;

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
pub fn appattest_enroll(
    da: &DeviceAttestation,
    expect: &Expectation,
) -> anyhow::Result<AttestedKey> {
    if da.app_attest_attestation.as_deref().is_none_or(<[u8]>::is_empty) {
        anyhow::bail!("enrolment bundle carries no App Attest attestation object");
    }
    // The enrolment snapshot assertion is always nonce-only (a one-time bootstrap,
    // not a per-proof replay vector) — no signing-key binding here (#38).
    let (check, key) = appattest_check_da(da, expect, None, None, false);
    key.ok_or_else(|| anyhow::anyhow!("enrolment bundle failed verification: {}", check.detail))
}

/// Deserialize a **JSON** enrolment bundle (schema `v:1`) into a
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
        app_attest_assertion: String,
        attestation_nonce: String,
    }

    let b: BundleJson =
        serde_json::from_slice(json).context("enrolment bundle is not valid JSON")?;
    anyhow::ensure!(
        b.v == BUNDLE_SCHEMA_VERSION,
        "unsupported enrolment bundle schema version {} (expected {BUNDLE_SCHEMA_VERSION})",
        b.v,
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
        app_attest_assertion: Some(dec(&b.app_attest_assertion, "app_attest_assertion")?),
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
    match verify_key_attestation(
        chain,
        &android_keygen_challenge(),
        now_unix_secs,
        expected_app,
        AttestMode::Proof,
    ) {
        Ok(att) => {
            // SECURITY (issue #31): bind the attested leaf to the signing key. A
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
            let app = if expected_app.is_some() {
                "; bound to the expected app identity"
            } else {
                ""
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
        let (c, key) = appattest_check(&proof_with(None), &expectation(), None, None, false);
        assert_eq!(c.status, Status::NotChecked);
        assert!(key.is_none());
    }

    #[test]
    fn no_app_attest_fields_is_not_checked() {
        // An Android proof: device attestation present, but no App Attest fields.
        let da = DeviceAttestation { key_id: "abc".into(), ..Default::default() };
        let (c, _) = appattest_check(&proof_with(Some(da)), &expectation(), None, None, false);
        assert_eq!(c.status, Status::NotChecked);
    }

    #[test]
    fn require_binding_without_signing_key_fails_closed() {
        // #38: a proof carrying an App Attest assertion, with binding REQUIRED
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
            appattest_check(&proof_with(Some(da.clone())), &expectation(), None, None, true);
        assert_eq!(fail.status, Status::Fail, "{}", fail.detail);
        assert!(fail.detail.contains("no device signing key"), "{}", fail.detail);
        assert!(key.is_none());
        // Same proof, binding NOT required → proceeds (NOT-CHECKED: no cached key).
        let (relaxed, _) =
            appattest_check(&proof_with(Some(da)), &expectation(), None, None, false);
        assert_eq!(relaxed.status, Status::NotChecked);
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
        let (c, key) = appattest_check(&proof_with(Some(da)), &expectation(), None, None, false);
        assert_eq!(c.status, Status::NotChecked);
        assert!(key.is_none());
    }

    #[test]
    fn cached_path_binds_key_id_to_the_cached_key() {
        // #41 (rec #5): on the assertion/cached path, `key_id` must hash-match the
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
            appattest_check(&proof_with(Some(mismatched)), &expectation(), Some(&cached), None, false);
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
            appattest_check(&proof_with(Some(matching)), &expectation(), Some(&cached), None, false);
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
        let (c, _) = appattest_check(&proof_with(Some(da)), &expectation(), None, None, false);
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
        let (c, key) = appattest_check(&proof_with(Some(da)), &expectation(), None, None, false);
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
        let json = json_bundle(2, &[0u8; 32], &[1], &[1], &[1]);
        let err = bundle_from_json(json.as_bytes()).unwrap_err().to_string();
        assert!(err.contains("schema version"), "{err}");
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
            expect_region: None, expect_region_type: None, expect_region_contains: None,
            session_nonce: None,
            require_session_binding: false,
            require_schema_v2: false, require_attestation: false,
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
            expect_region: None, expect_region_type: None, expect_region_contains: None,
            session_nonce: None,
            require_session_binding: false,
            require_schema_v2: false, require_attestation: false,
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

    // --- SECURITY (issue #31): attestation must bind to the signing key ---

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
