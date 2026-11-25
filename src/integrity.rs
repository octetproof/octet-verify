//! Online Google Play Integrity check (feature `playintegrity`,).
//!
//! **Opt-in, online.** Unlike the offline attestation layer, a Play Integrity
//! token can only be turned into a verdict by Google (keyed to the app's Cloud
//! project). This check therefore calls the first-party decode endpoint
//! (`POST /v1/integrity/decode`) with the **verifier's own** decode-scoped
//! service credential (`octet_svc_`) — never the proof-device's activation
//! bearer — and then runs the shared crate's *offline* primitives
//! (`from_decoded_json` → `check_binding_packages` → `check_freshness`) on the
//! verdict the endpoint returns. The endpoint is content-blind; all judgement
//! (nonce byte-equality, package-set, window freshness) is here.
//!
//! **Key tie.** A proof from SDK 4.0.0 on carries `attestation_nonce_seed`
//! (field 11), and its `attestation_nonce` (field 10) is then
//! `SHA256(seed ‖ P)`, where `P` is the uncompressed point of the P-256 key in
//! `certificate_chain[0]`, the key that signs the proof. The check recomputes
//! that hash, so a token copied into a proof signed by another key FAILs. A tied
//! token may be older than the proof ([`TIED_TOKEN_MAX_AGE_S`]); a token with no
//! seed must be as fresh as the proof itself.
//!
//! Field 11 is not signed, so the tie is only enforced if a proof cannot drop
//! it. A proof bound under semantic-binding v4 (one that commits to a licence)
//! comes only from SDK 4.0.0 or later, which never sends a token without field
//! 11. On such a proof a token with no field 11 FAILs. An empty field 11 FAILs
//! on any proof: a token with no tie carries no field 11, so there is no second
//! way to say "none".
//!
//! Off by default: with no decode config the `play-integrity` check reports
//! `NOT-CHECKED`, and the lean default build pulls none of this. Fail-closed:
//! a bad/unbindable token FAILs; transient or verifier-side conditions are
//! `NOT-CHECKED`, never fail-open. See `spec/integrity-decode.md` §6.

use crate::keys::hardware_pubkey_from_cert_chain;
use crate::navigate::{DeviceAttestation, LocationProof};
use crate::verify::{Check, Status};
use octet_attest_verify::playintegrity::{DeviceIntegrity, IntegrityVerdict};
use std::io::Read;
use std::time::Duration;

const NAME: &str = "play-integrity";
/// Decode responses are small; cap defensively.
const MAX_RESPONSE_BYTES: u64 = 64 * 1024;
/// Contract cap on the token (§4) — don't POST an oversized body.
const MAX_TOKEN_BYTES: usize = 16 * 1024;

/// Age limit for a token tied to the proof's signing key (field 11 present and
/// the tie holds): 60 minutes + 5 minutes margin. It follows the SDK's Play
/// Integrity token refresh window, because the SDK reuses a tied token across
/// proofs until it refreshes it. This is also the default of
/// `--integrity-max-age-seconds`.
pub const TIED_TOKEN_MAX_AGE_S: i64 = 3_900;

/// Config for the online Play Integrity check. Built by the CLI only when all of
/// `--integrity-decode-url`, `--integrity-decode-token`, `--integrity-package`
/// are supplied; absent ⇒ the check is `NOT-CHECKED`.
pub struct IntegrityConfig<'a> {
    /// Decode endpoint base URL (e.g. `https://api.octetproof.com`). `https://`
    /// required — `http://` only for LAN-dev hosts — so the service token is
    /// never sent in cleartext (same policy as backend fetch).
    pub decode_url: &'a str,
    /// The verifier's own decode-scoped service credential (`octet_svc_`), NOT
    /// the device's activation bearer.
    pub service_token: &'a str,
    /// The Android package the token was minted for: sent in the request and the
    /// accepted package for the binding check.
    pub package: &'a str,
    /// Freshness window (milliseconds) for the `timestampMillis` of a token
    /// tied to the proof's signing key (field 11 present and the tie holds).
    pub tied_max_age_ms: i64,
    /// Freshness window (milliseconds) for a token with no field 11. This is
    /// the proof's own age limit, or `tied_max_age_ms` if that is lower.
    pub untied_max_age_ms: i64,
}

/// How field 10 relates to the proof's signing key.
#[derive(Debug, PartialEq)]
enum KeyTie {
    /// No field 11 on a proof not bound under v4: a token from before the tie.
    /// Only the proof's own age limit applies.
    Untied,
    /// Field 11 present and `SHA256(field 11 ‖ P) == field 10`.
    Tied,
    /// Field 11 missing on a v4 proof, empty, or present but the tie does not
    /// hold, or there is no key to tie to.
    Broken(String),
}

/// The nonce a tied token is requested with: `SHA256(seed ‖ key_point)`, where
/// `key_point` is the uncompressed (x963) P-256 point. Same hash as the SDK
/// computes when it requests the token.
fn key_bound_nonce(seed: &[u8], key_point: &[u8]) -> [u8; 32] {
    let mut pre = Vec::with_capacity(seed.len() + key_point.len());
    pre.extend_from_slice(seed);
    pre.extend_from_slice(key_point);
    crate::crypto::sha256(&pre)
}

/// Check field 10 against field 11 and the key in `certificate_chain[0]`.
/// `from_v4_sdk` is true when the proof passed semantic-binding v4, the same
/// marker `claim-privacy` uses for field 20.
fn key_tie(da: &DeviceAttestation, nonce: &[u8], from_v4_sdk: bool) -> KeyTie {
    let seed = match da.attestation_nonce_seed.as_deref() {
        Some([]) => {
            return KeyTie::Broken(
                "attestation_nonce_seed (field 11) is present but empty: a token with no tie \
                 carries no field 11, so there is no second way to say \"none\""
                    .into(),
            )
        }
        Some(s) => s,
        None if from_v4_sdk => {
            return KeyTie::Broken(
                "Play Integrity token with no attestation_nonce_seed (field 11) on a semantic-binding \
                 v4 proof: SDK 4.0.0 or later always ties the token to the signing key, so field 11 \
                 was removed"
                    .into(),
            )
        }
        None => return KeyTie::Untied,
    };
    if da.certificate_chain.is_empty() {
        return KeyTie::Broken(
            "token is tied to a signing key (field 11) but the proof has no certificate_chain".into(),
        );
    }
    let vk = match hardware_pubkey_from_cert_chain(&da.certificate_chain) {
        Ok(vk) => vk,
        Err(_) => {
            return KeyTie::Broken(
                "token is tied to a signing key (field 11) but certificate_chain[0] has no P-256 key"
                    .into(),
            )
        }
    };
    let point = vk.to_encoded_point(false);
    if key_bound_nonce(seed, point.as_bytes()).as_slice() == nonce {
        KeyTie::Tied
    } else {
        KeyTie::Broken(
            "attestation_nonce (field 10) is not SHA256(field 11 ‖ the key in certificate_chain[0]): \
             the token was not requested for this proof's signing key"
                .into(),
        )
    }
}

fn chk(status: Status, detail: impl Into<String>) -> Check {
    Check { name: NAME, status, detail: detail.into() }
}

#[derive(serde::Serialize)]
struct DecodeRequest<'a> {
    integrity_token: &'a str,
    package_name: &'a str,
}

/// The decode call's classified result, decoupled from status mapping so the
/// §6 mapping is unit-testable without HTTP.
enum DecodeOutcome {
    /// `200` — the decoded verdict JSON (carries `tokenPayloadExternal`).
    Ok(String),
    /// `422 integrity_token_invalid` — Google could not decode (deterministic).
    TokenInvalid,
    /// `403 package_not_allowed`.
    PackageNotAllowed,
    /// `422` FastAPI validation error (`detail` is an ARRAY) — OUR request was
    /// malformed. A verifier-side bug, NOT a proof defect.
    BadRequest(String),
    /// `401 bearer_required` / `bearer_invalid` — verifier auth misconfigured.
    Unauthorized(String),
    /// `429 rate_limited`.
    RateLimited,
    /// `503 *` — decode unavailable / not configured (retryable / no assurance).
    Unavailable(String),
    /// Network/transport failure reaching the endpoint.
    Transport(String),
    /// Any other unexpected status.
    Unexpected(u16, String),
}

/// Run the online Play Integrity check for `proof`.
///
/// `committed_license` is [`Report::committed_license`](crate::verify::Report::committed_license)
/// from verifying the same proof: `Some` only when it passed semantic-binding
/// v4, and then a token must carry field 11.
///
/// `NOT-CHECKED` when the proof carries no PI token / nonce; otherwise POSTs the
/// token to the decode endpoint and maps the result per §6.
pub fn play_integrity_check(
    proof: &LocationProof,
    committed_license: Option<&str>,
    cfg: &IntegrityConfig,
    now_ms: i64,
) -> Check {
    run(proof, committed_license.is_some(), cfg, now_ms, |token| decode(cfg, token))
}

/// The check with the decode call passed in, so everything but HTTP is testable.
fn run(
    proof: &LocationProof,
    from_v4_sdk: bool,
    cfg: &IntegrityConfig,
    now_ms: i64,
    decode: impl FnOnce(&str) -> DecodeOutcome,
) -> Check {
    let da = match &proof.device_attestation {
        Some(da) => da,
        None => return chk(Status::NotChecked, "no device attestation on proof"),
    };
    let token = match da.play_integrity_token.as_deref() {
        Some(t) if !t.is_empty() => t,
        _ => return chk(Status::NotChecked, "no Play Integrity token on proof (DeviceAttestation field 4)"),
    };
    if token.len() > MAX_TOKEN_BYTES {
        return chk(Status::Fail, format!("Play Integrity token exceeds the {MAX_TOKEN_BYTES}-byte cap"));
    }
    let nonce = match da.attestation_nonce.as_deref() {
        Some(n) if !n.is_empty() => n,
        _ => return chk(Status::NotChecked, "no attestation_nonce (field 10) to bind the token to"),
    };
    if let Err(e) = check_url_scheme(cfg.decode_url) {
        return chk(Status::NotChecked, format!("verifier misconfigured: {e}"));
    }
    // The tie is checked before the decode call: a broken tie FAILs whatever
    // Google says about the token.
    let (max_age_ms, tie_note) = match key_tie(da, nonce, from_v4_sdk) {
        KeyTie::Tied => (cfg.tied_max_age_ms, "tied to the signing key"),
        KeyTie::Untied => (cfg.untied_max_age_ms, "not tied to the signing key (no field 11)"),
        KeyTie::Broken(why) => return chk(Status::Fail, why),
    };
    let mut c = map_outcome(decode(token), nonce, cfg.package, now_ms, max_age_ms);
    if c.status == Status::Pass {
        c.detail = format!("{}; {tie_note}", c.detail);
    }
    c
}

/// Map a decode outcome + the proof's binding inputs to a `play-integrity`
/// check (§6). Pure — the whole response→status table is tested here without HTTP.
fn map_outcome(
    outcome: DecodeOutcome,
    expected_nonce: &[u8],
    package: &str,
    now_ms: i64,
    max_age_ms: i64,
) -> Check {
    match outcome {
        DecodeOutcome::Ok(body) => match IntegrityVerdict::from_decoded_json(&body) {
            Ok(v) => {
                if let Err(e) = v.check_binding_packages(expected_nonce, Some(&[package])) {
                    return chk(Status::Fail, format!("token does not bind to this proof: {e}"));
                }
                if let Err(e) = v.check_freshness(now_ms, max_age_ms) {
                    return chk(Status::Fail, format!("token freshness: {e}"));
                }
                // Verdict-value policy — gated by the crate's shared reference
                // `check_device_integrity()` (the agreed device-integrity gate):
                // MEETS_DEVICE_INTEGRITY or MEETS_STRONG_INTEGRITY PASS; MEETS_BASIC
                // and no integrity label FAIL, fail-closed. app_recognition and
                // account/licensing verdicts are informational only (surfaced,
                // not gated) — a dev/enterprise/sideloaded genuine app is
                // UNEVALUATED and must not be rejected on that basis.
                match v.check_device_integrity() {
                    Ok(()) => {
                        let level = match v.device_integrity {
                            DeviceIntegrity::MeetsStrong => "MEETS_STRONG_INTEGRITY",
                            _ => "MEETS_DEVICE_INTEGRITY",
                        };
                        chk(
                            Status::Pass,
                            format!(
                                "decoded + bound + {level} (package {package}; app_recognition={:?})",
                                v.app_recognition
                            ),
                        )
                    }
                    Err(_) => match v.device_integrity {
                        DeviceIntegrity::MeetsBasic => chk(
                            Status::Fail,
                            "device integrity is only MEETS_BASIC_INTEGRITY, not MEETS_DEVICE_INTEGRITY/MEETS_STRONG_INTEGRITY",
                        ),
                        _ => chk(Status::Fail, "no device-integrity label (device integrity not met)"),
                    },
                }
            }
            Err(e) => chk(Status::Fail, format!("decoded verdict unparsable: {e}")),
        },
        // Deterministic proof-level failures → FAIL (fail-closed).
        DecodeOutcome::TokenInvalid => chk(
            Status::Fail,
            "Google could not decode the Play Integrity token (integrity_token_invalid)",
        ),
        DecodeOutcome::PackageNotAllowed => chk(
            Status::Fail,
            format!("package {package} is not allowed for the decode project (package_not_allowed)"),
        ),
        // Verifier-side or transient → NOT-CHECKED (no assurance, never fail-open).
        DecodeOutcome::BadRequest(d) => chk(
            Status::NotChecked,
            format!("verifier-side: decode request rejected as malformed — {d}"),
        ),
        DecodeOutcome::Unauthorized(d) => chk(
            Status::NotChecked,
            format!("verifier-side: decode auth rejected — check the service credential ({d})"),
        ),
        DecodeOutcome::RateLimited => {
            chk(Status::NotChecked, "decode rate-limited (rate_limited); no assurance")
        }
        DecodeOutcome::Unavailable(d) => {
            chk(Status::NotChecked, format!("decode service unavailable — {d}"))
        }
        DecodeOutcome::Transport(e) => {
            chk(Status::NotChecked, format!("could not reach the decode endpoint: {e}"))
        }
        DecodeOutcome::Unexpected(code, d) => {
            chk(Status::NotChecked, format!("unexpected decode response {code} — {d}"))
        }
    }
}

/// POST the token to the decode endpoint and classify the HTTP result.
fn decode(cfg: &IntegrityConfig, token: &str) -> DecodeOutcome {
    let url = format!("{}/v1/integrity/decode", cfg.decode_url.trim_end_matches('/'));
    let body = match serde_json::to_string(&DecodeRequest {
        integrity_token: token,
        package_name: cfg.package,
    }) {
        Ok(b) => b,
        Err(e) => return DecodeOutcome::Transport(format!("could not serialize decode request: {e}")),
    };
    let agent = ureq::AgentBuilder::new().timeout(Duration::from_secs(20)).build();
    let resp = agent
        .post(&url)
        .set("Authorization", &format!("Bearer {}", cfg.service_token))
        .set("Content-Type", "application/json")
        .send_string(&body);
    classify(resp)
}

/// Classify a ureq response into a [`DecodeOutcome`]: read the (capped) body and,
/// on an error status, the `detail` field — distinguishing the `integrity_token_invalid`
/// **string** slug from FastAPI's validation **array** (both are 422).
fn classify(resp: Result<ureq::Response, ureq::Error>) -> DecodeOutcome {
    match resp {
        Ok(r) => {
            let status = r.status();
            let body = read_capped(r.into_reader());
            if status == 200 {
                DecodeOutcome::Ok(body)
            } else {
                DecodeOutcome::Unexpected(status, snippet(&body))
            }
        }
        Err(ureq::Error::Status(code, r)) => {
            let body = read_capped(r.into_reader());
            let detail = detail_field(&body);
            match code {
                401 => DecodeOutcome::Unauthorized(detail.unwrap_or_else(|| "bearer".into())),
                403 => match detail.as_deref() {
                    Some("package_not_allowed") => DecodeOutcome::PackageNotAllowed,
                    other => DecodeOutcome::Unexpected(403, other.unwrap_or("").to_string()),
                },
                422 => match detail.as_deref() {
                    // String slug: Google-400 → deterministic token invalid.
                    Some("integrity_token_invalid") => DecodeOutcome::TokenInvalid,
                    // FastAPI validation error: `detail` is an array → our request was malformed.
                    _ if detail_is_array(&body) => DecodeOutcome::BadRequest(snippet(&body)),
                    other => DecodeOutcome::Unexpected(422, other.unwrap_or("").to_string()),
                },
                429 => DecodeOutcome::RateLimited,
                503 => DecodeOutcome::Unavailable(detail.unwrap_or_else(|| "503".into())),
                other => DecodeOutcome::Unexpected(other, detail.unwrap_or_default()),
            }
        }
        Err(ureq::Error::Transport(t)) => DecodeOutcome::Transport(t.to_string()),
    }
}

/// The `detail` field as a string, when the error body is `{ "detail": "<slug>" }`.
/// `None` if absent or not a string (e.g. the FastAPI validation array).
fn detail_field(body: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()?
        .get("detail")?
        .as_str()
        .map(str::to_owned)
}

/// True iff the error body's `detail` is a JSON array (FastAPI validation shape).
fn detail_is_array(body: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("detail").map(|d| d.is_array()))
        .unwrap_or(false)
}

fn snippet(s: &str) -> String {
    let s = s.trim();
    if s.len() <= 200 { s.to_string() } else { format!("{}…", &s[..200]) }
}

fn read_capped<R: Read>(r: R) -> String {
    let mut buf = String::new();
    let _ = r.take(MAX_RESPONSE_BYTES).read_to_string(&mut buf);
    buf
}

/// HTTPS required; plain HTTP only for localhost / RFC1918 LAN-dev hosts — so a
/// typo'd or downgraded URL fails loud rather than shipping the service token in
/// the clear. Mirrors the backend-fetch policy.
fn check_url_scheme(base: &str) -> Result<(), String> {
    if base.strip_prefix("https://").is_some() {
        return Ok(());
    }
    let Some(rest) = base.strip_prefix("http://") else {
        return Err(format!("decode url must start with https:// (or http:// for LAN dev): {base:?}"));
    };
    let host = rest.split(['/', ':']).next().unwrap_or("");
    let lan = host == "localhost"
        || host == "127.0.0.1"
        || host.starts_with("10.")
        || host.starts_with("192.168.")
        || host.starts_with("169.254.");
    if lan {
        Ok(())
    } else {
        Err(format!("plain http:// is only allowed for LAN-dev hosts, not {host:?}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

    /// A decoded verdict body in Google's shape (as the endpoint returns it),
    /// with the nonce base64 of `nonce`, a given package, timestamp, and verdicts.
    fn body(nonce: &[u8], package: &str, ts_ms: i64, device: &str, app: &str) -> String {
        let n = base64::engine::general_purpose::STANDARD.encode(nonce);
        format!(
            r#"{{"tokenPayloadExternal":{{
                "requestDetails":{{"requestPackageName":"{package}","nonce":"{n}","timestampMillis":"{ts_ms}"}},
                "appIntegrity":{{"appRecognitionVerdict":"{app}","packageName":"{package}"}},
                "deviceIntegrity":{{"deviceRecognitionVerdict":["{device}"]}},
                "accountDetails":{{"appLicensingVerdict":"LICENSED"}}
            }}}}"#
        )
    }

    const PKG: &str = "com.octetproof.sample";
    const NONCE: &[u8] = &[0xABu8; 32];
    const TS: i64 = 1_789_000_000_000;
    const NOW: i64 = 1_789_000_030_000; // 30s after the token
    const MAXAGE: i64 = 300_000; // 5 min window

    fn status_of(c: &Check) -> Status {
        c.status
    }

    #[test]
    fn ok_bound_and_fresh_is_pass() {
        let c = map_outcome(
            DecodeOutcome::Ok(body(NONCE, PKG, TS, "MEETS_DEVICE_INTEGRITY", "PLAY_RECOGNIZED")),
            NONCE, PKG, NOW, MAXAGE,
        );
        assert_eq!(status_of(&c), Status::Pass, "{}", c.detail);
    }

    #[test]
    fn ok_strong_integrity_is_pass() {
        // MEETS_STRONG_INTEGRITY folds into the device gate (shared crate policy).
        let c = map_outcome(
            DecodeOutcome::Ok(body(NONCE, PKG, TS, "MEETS_STRONG_INTEGRITY", "PLAY_RECOGNIZED")),
            NONCE, PKG, NOW, MAXAGE,
        );
        assert_eq!(status_of(&c), Status::Pass, "{}", c.detail);
        assert!(c.detail.contains("MEETS_STRONG_INTEGRITY"), "{}", c.detail);
    }

    #[test]
    fn ok_wrong_nonce_is_fail() {
        let c = map_outcome(
            DecodeOutcome::Ok(body(&[0x11; 32], PKG, TS, "MEETS_DEVICE_INTEGRITY", "PLAY_RECOGNIZED")),
            NONCE, PKG, NOW, MAXAGE,
        );
        assert_eq!(status_of(&c), Status::Fail);
        assert!(c.detail.contains("bind"), "{}", c.detail);
    }

    #[test]
    fn ok_wrong_package_is_fail() {
        let c = map_outcome(
            DecodeOutcome::Ok(body(NONCE, "com.evil.app", TS, "MEETS_DEVICE_INTEGRITY", "PLAY_RECOGNIZED")),
            NONCE, PKG, NOW, MAXAGE,
        );
        assert_eq!(status_of(&c), Status::Fail);
    }

    #[test]
    fn ok_stale_is_fail() {
        // now far beyond the window.
        let c = map_outcome(
            DecodeOutcome::Ok(body(NONCE, PKG, TS, "MEETS_DEVICE_INTEGRITY", "PLAY_RECOGNIZED")),
            NONCE, PKG, TS + MAXAGE + 1, MAXAGE,
        );
        assert_eq!(status_of(&c), Status::Fail);
        assert!(c.detail.contains("fresh"), "{}", c.detail);
    }

    #[test]
    fn ok_basic_integrity_is_fail() {
        // Bound + fresh, but only MEETS_BASIC_INTEGRITY → not enough → FAIL.
        let c = map_outcome(
            DecodeOutcome::Ok(body(NONCE, PKG, TS, "MEETS_BASIC_INTEGRITY", "PLAY_RECOGNIZED")),
            NONCE, PKG, NOW, MAXAGE,
        );
        assert_eq!(status_of(&c), Status::Fail);
        assert!(c.detail.contains("MEETS_BASIC"), "{}", c.detail);
    }

    #[test]
    fn ok_no_device_integrity_label_is_fail() {
        // A verdict with no DEVICE/BASIC label (e.g. only virtual) → None → FAIL.
        let c = map_outcome(
            DecodeOutcome::Ok(body(NONCE, PKG, TS, "MEETS_VIRTUAL_INTEGRITY", "PLAY_RECOGNIZED")),
            NONCE, PKG, NOW, MAXAGE,
        );
        assert_eq!(status_of(&c), Status::Fail);
    }

    #[test]
    fn ok_app_recognition_does_not_gate() {
        // UNEVALUATED app recognition (dev build not on Play) still PASSes when
        // device integrity is met and the token binds — app_recognition is
        // informational, not a gate.
        let c = map_outcome(
            DecodeOutcome::Ok(body(NONCE, PKG, TS, "MEETS_DEVICE_INTEGRITY", "UNEVALUATED")),
            NONCE, PKG, NOW, MAXAGE,
        );
        assert_eq!(status_of(&c), Status::Pass, "{}", c.detail);
    }

    #[test]
    fn ok_garbage_body_is_fail() {
        let c = map_outcome(DecodeOutcome::Ok("not json".into()), NONCE, PKG, NOW, MAXAGE);
        assert_eq!(status_of(&c), Status::Fail);
    }

    #[test]
    fn token_invalid_is_fail() {
        assert_eq!(status_of(&map_outcome(DecodeOutcome::TokenInvalid, NONCE, PKG, NOW, MAXAGE)), Status::Fail);
    }

    #[test]
    fn package_not_allowed_is_fail() {
        assert_eq!(
            status_of(&map_outcome(DecodeOutcome::PackageNotAllowed, NONCE, PKG, NOW, MAXAGE)),
            Status::Fail
        );
    }

    #[test]
    fn verifier_side_and_transient_are_not_checked() {
        for o in [
            DecodeOutcome::BadRequest("[{loc:body}]".into()),
            DecodeOutcome::Unauthorized("bearer_invalid".into()),
            DecodeOutcome::RateLimited,
            DecodeOutcome::Unavailable("integrity_decode_unavailable".into()),
            DecodeOutcome::Unavailable("integrity_decode_not_configured".into()),
            DecodeOutcome::Transport("connection refused".into()),
            DecodeOutcome::Unexpected(418, "teapot".into()),
        ] {
            assert_eq!(status_of(&map_outcome(o, NONCE, PKG, NOW, MAXAGE)), Status::NotChecked);
        }
    }

    #[test]
    fn classify_distinguishes_the_two_422_shapes() {
        // The core §6 nuance: string slug vs validation array, both 422.
        assert_eq!(detail_field(r#"{"detail":"integrity_token_invalid"}"#).as_deref(), Some("integrity_token_invalid"));
        assert!(!detail_is_array(r#"{"detail":"integrity_token_invalid"}"#));
        assert!(detail_is_array(r#"{"detail":[{"loc":["body","package_name"],"msg":"field required"}]}"#));
        assert_eq!(detail_field(r#"{"detail":[{"loc":["body"]}]}"#), None); // array → not a string slug
    }

    // --- Key tie (field 11), the same cases as the SDK's own tests ---

    /// A self-signed P-256 test certificate and its uncompressed point (the
    /// fixture `keys.rs` tests use).
    const CERT_B64: &str = "MIIBjTCCATOgAwIBAgIUUmrrHypvK5MliIkDfzBtSSIlc24wCgYIKoZIzj0EAwIwHDEaMBgGA1UEAwwRb2N0ZXQtdmVyaWZ5LXRlc3QwHhcNMjYwNjEwMTgxODU5WhcNMjYwNjExMTgxODU5WjAcMRowGAYDVQQDDBFvY3RldC12ZXJpZnktdGVzdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABMUrsLvgoS7C2WIVLXxrqv88u9A7cG9A1qSIeKN/DXOt1z61lKKL59Bvk6FyKrPE3eVjzPVQkh4kVDGBD+Omk0qjUzBRMB0GA1UdDgQWBBQv1un+9O/mvh24rEBxAN68yqn1XTAfBgNVHSMEGDAWgBQv1un+9O/mvh24rEBxAN68yqn1XTAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQCdyPJ9t7q4A9akk/JB4MiPY0Co64WkJWesuaIZbZhr2gIgXgLDk68G/glculfO2eMtE9lDi7ifshCTKQ/6qMei/wU=";
    const CERT_POINT_HEX: &str = "04c52bb0bbe0a12ec2d962152d7c6baaff3cbbd03b706f40d6a48878a37f0d73add73eb594a28be7d06f93a1722ab3c4dde563ccf550921e245431810fe3a6934a";
    const SEED: &[u8] = &[0x5Au8; 32];
    const MIN: i64 = 60_000;

    fn cert() -> Vec<u8> {
        base64::engine::general_purpose::STANDARD.decode(CERT_B64).unwrap()
    }

    fn cfg() -> IntegrityConfig<'static> {
        IntegrityConfig {
            decode_url: "https://api.octetproof.com",
            service_token: "unused",
            package: PKG,
            tied_max_age_ms: TIED_TOKEN_MAX_AGE_S * 1000,
            untied_max_age_ms: MAXAGE,
        }
    }

    fn proof(nonce: &[u8], seed: Option<&[u8]>, chain: Vec<Vec<u8>>) -> LocationProof {
        LocationProof {
            device_attestation: Some(DeviceAttestation {
                play_integrity_token: Some("token".into()),
                attestation_nonce: Some(nonce.to_vec()),
                attestation_nonce_seed: seed.map(<[u8]>::to_vec),
                certificate_chain: chain,
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    /// Run the check on `p` (not bound under v4) with a decoded token of the
    /// given age that carries `nonce`.
    fn run_aged(p: &LocationProof, nonce: &[u8], age_ms: i64, c: &IntegrityConfig) -> Check {
        run(p, false, c, TS + age_ms, |_| {
            DecodeOutcome::Ok(body(nonce, PKG, TS, "MEETS_DEVICE_INTEGRITY", "PLAY_RECOGNIZED"))
        })
    }

    fn tied_nonce() -> [u8; 32] {
        key_bound_nonce(SEED, &hex::decode(CERT_POINT_HEX).unwrap())
    }

    #[test]
    fn shared_vector_matches_the_sdk() {
        // The SDK's shared test value: seed 0..31, point 0x04 ‖ 1..64.
        let seed: Vec<u8> = (0u8..32).collect();
        let mut point = vec![0x04u8];
        point.extend(1u8..=64);
        assert_eq!(
            hex::encode(key_bound_nonce(&seed, &point)),
            "caadfdee7131b5b3c5d9385ad6b87855ab8c0d02d27e6df34e840beb9c34e295"
        );
    }

    #[test]
    fn tied_token_59_minutes_old_passes() {
        let n = tied_nonce();
        let c = run_aged(&proof(&n, Some(SEED), vec![cert()]), &n, 59 * MIN, &cfg());
        assert_eq!(c.status, Status::Pass, "{}", c.detail);
        assert!(c.detail.contains("tied to the signing key"), "{}", c.detail);
    }

    #[test]
    fn tied_token_66_minutes_old_fails() {
        let n = tied_nonce();
        let c = run_aged(&proof(&n, Some(SEED), vec![cert()]), &n, 66 * MIN, &cfg());
        assert_eq!(c.status, Status::Fail);
        assert!(c.detail.contains("fresh"), "{}", c.detail);
    }

    #[test]
    fn untied_token_4_minutes_old_passes() {
        let c = run_aged(&proof(NONCE, None, vec![cert()]), NONCE, 4 * MIN, &cfg());
        assert_eq!(c.status, Status::Pass, "{}", c.detail);
        assert!(c.detail.contains("not tied"), "{}", c.detail);
    }

    #[test]
    fn untied_token_6_minutes_old_fails() {
        let c = run_aged(&proof(NONCE, None, vec![cert()]), NONCE, 6 * MIN, &cfg());
        assert_eq!(c.status, Status::Fail);
        assert!(c.detail.contains("fresh"), "{}", c.detail);
    }

    // --- Field 11 removed or emptied ---

    #[test]
    fn v4_proof_with_a_token_but_no_field_11_fails_at_any_age() {
        // Field 11 is unsigned. Copy a genuine token, drop field 11, and without
        // this rule the proof would pass as untied. A v4 proof comes only from
        // SDK 4.0.0 or later, which never sends a token without field 11, so its
        // absence there means it was removed. Fails before the decode call, so a
        // fresh token from Google cannot rescue it.
        for age in [0, MIN, 4 * MIN, 59 * MIN] {
            let c = run(&proof(NONCE, None, vec![cert()]), true, &cfg(), TS + age, |_| {
                panic!("a v4 proof with no field 11 must fail before the decode call")
            });
            assert_eq!(c.status, Status::Fail, "age {age}: {}", c.detail);
            assert!(c.detail.contains("field 11") && c.detail.contains("v4"), "{}", c.detail);
        }
    }

    #[test]
    fn v4_marker_comes_from_the_reports_committed_licence() {
        // The public entry point takes the report's committed licence, which is
        // Some only after a semantic-binding v4 pass (as claim-privacy reads it).
        let p = proof(NONCE, None, vec![cert()]);
        let c = play_integrity_check(&p, Some("7c9e6679-7425-40de-944b-e07fc1f90ae7"), &cfg(), TS);
        assert_eq!(c.status, Status::Fail, "{}", c.detail);
        assert!(c.detail.contains("field 11"), "{}", c.detail);
    }

    #[test]
    fn non_v4_proof_with_no_field_11_keeps_the_proofs_age_limit() {
        // Earlier SDKs never sent field 11, so their tokens stay valid, held to
        // the proof's own limit (5 min here) and not the tied 65 min.
        let p = proof(NONCE, None, vec![cert()]);
        let ok = run_aged(&p, NONCE, 4 * MIN, &cfg());
        assert_eq!(ok.status, Status::Pass, "{}", ok.detail);
        assert!(ok.detail.contains("not tied"), "{}", ok.detail);
        let stale = run_aged(&p, NONCE, 6 * MIN, &cfg());
        assert_eq!(stale.status, Status::Fail);
        assert!(stale.detail.contains("fresh"), "{}", stale.detail);
    }

    #[test]
    fn empty_field_11_fails_with_or_without_v4() {
        // An empty field 11 is neither a tie nor "no tie": a token with no tie
        // carries no field 11 at all. Accepting empty as untied would give a
        // second way to say "none", so it fails, like an empty licence under v4.
        for v4 in [false, true] {
            let c = run(&proof(NONCE, Some(&[]), vec![cert()]), v4, &cfg(), TS, |_| {
                panic!("an empty field 11 must fail before the decode call")
            });
            assert_eq!(c.status, Status::Fail, "v4={v4}: {}", c.detail);
            assert!(c.detail.contains("present but empty"), "{}", c.detail);
        }
    }

    #[test]
    fn v4_proof_with_a_good_tie_still_gets_the_tied_limit() {
        // The new rule only demands field 11; a correct tie on a v4 proof
        // behaves exactly as before.
        let n = tied_nonce();
        let p = proof(&n, Some(SEED), vec![cert()]);
        let c = run(&p, true, &cfg(), TS + 59 * MIN, |_| {
            DecodeOutcome::Ok(body(&n, PKG, TS, "MEETS_DEVICE_INTEGRITY", "PLAY_RECOGNIZED"))
        });
        assert_eq!(c.status, Status::Pass, "{}", c.detail);
        assert!(c.detail.contains("tied to the signing key"), "{}", c.detail);
    }

    #[test]
    fn tied_token_with_a_seed_for_another_key_fails_at_any_age() {
        // Field 10 made with a different key: a genuine token moved onto this proof.
        let mut other = hex::decode(CERT_POINT_HEX).unwrap();
        other[64] ^= 1;
        let n = key_bound_nonce(SEED, &other);
        for age in [0, MIN, 59 * MIN] {
            let c = run(&proof(&n, Some(SEED), vec![cert()]), false, &cfg(), TS + age, |_| {
                panic!("a broken tie must fail before the decode call")
            });
            assert_eq!(c.status, Status::Fail);
            assert!(c.detail.contains("field 11"), "{}", c.detail);
        }
    }

    #[test]
    fn tied_token_with_no_certificate_chain_fails() {
        let n = tied_nonce();
        let c = run_aged(&proof(&n, Some(SEED), vec![]), &n, MIN, &cfg());
        assert_eq!(c.status, Status::Fail);
        assert!(c.detail.contains("no certificate_chain"), "{}", c.detail);
    }

    #[test]
    fn tied_token_with_a_non_p256_leaf_fails() {
        let n = tied_nonce();
        let c = run_aged(&proof(&n, Some(SEED), vec![vec![1, 2, 3]]), &n, MIN, &cfg());
        assert_eq!(c.status, Status::Fail);
        assert!(c.detail.contains("no P-256 key"), "{}", c.detail);
    }

    #[test]
    fn tied_token_with_a_raw_point_leaf_passes() {
        // certificate_chain[0] may hold the point itself, as the SDK also accepts.
        let n = tied_nonce();
        let leaf = hex::decode(CERT_POINT_HEX).unwrap();
        let c = run_aged(&proof(&n, Some(SEED), vec![leaf]), &n, MIN, &cfg());
        assert_eq!(c.status, Status::Pass, "{}", c.detail);
    }

    #[test]
    fn a_lower_explicit_limit_applies_to_tied_tokens_too() {
        // --integrity-max-age-seconds 120: both limits become 120 s.
        let low = IntegrityConfig { tied_max_age_ms: 120_000, untied_max_age_ms: 120_000, ..cfg() };
        let n = tied_nonce();
        let c = run_aged(&proof(&n, Some(SEED), vec![cert()]), &n, 3 * MIN, &low);
        assert_eq!(c.status, Status::Fail);
    }

    #[test]
    fn url_scheme_guard() {
        assert!(check_url_scheme("https://api.octetproof.com").is_ok());
        assert!(check_url_scheme("http://localhost:8080").is_ok());
        assert!(check_url_scheme("http://127.0.0.1").is_ok());
        assert!(check_url_scheme("http://api.octetproof.com").is_err()); // cleartext to a public host
        assert!(check_url_scheme("ftp://x").is_err());
    }
}
