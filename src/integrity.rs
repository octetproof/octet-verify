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
//! Off by default: with no decode config the `play-integrity` check reports
//! `NOT-CHECKED`, and the lean default build pulls none of this. Fail-closed:
//! a bad/unbindable token FAILs; transient or verifier-side conditions are
//! `NOT-CHECKED`, never fail-open. See `spec/integrity-decode.md` §6.

use crate::navigate::LocationProof;
use crate::verify::{Check, Status};
use octet_attest_verify::playintegrity::{DeviceIntegrity, IntegrityVerdict};
use std::io::Read;
use std::time::Duration;

const NAME: &str = "play-integrity";
/// Decode responses are small; cap defensively.
const MAX_RESPONSE_BYTES: u64 = 64 * 1024;
/// Contract cap on the token (§4) — don't POST an oversized body.
const MAX_TOKEN_BYTES: usize = 16 * 1024;

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
    /// Freshness window (milliseconds) for the token's `timestampMillis`.
    pub max_age_ms: i64,
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
/// `NOT-CHECKED` when the proof carries no PI token / nonce; otherwise POSTs the
/// token to the decode endpoint and maps the result per §6.
pub fn play_integrity_check(proof: &LocationProof, cfg: &IntegrityConfig, now_ms: i64) -> Check {
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
    let outcome = decode(cfg, token);
    map_outcome(outcome, nonce, cfg.package, now_ms, cfg.max_age_ms)
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

    #[test]
    fn url_scheme_guard() {
        assert!(check_url_scheme("https://api.octetproof.com").is_ok());
        assert!(check_url_scheme("http://localhost:8080").is_ok());
        assert!(check_url_scheme("http://127.0.0.1").is_ok());
        assert!(check_url_scheme("http://api.octetproof.com").is_err()); // cleartext to a public host
        assert!(check_url_scheme("ftp://x").is_err());
    }
}
