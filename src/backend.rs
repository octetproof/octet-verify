//! Transport client for the Octet proof ingestion API (untrusted backend).
//!
//! **Trust boundary (load-bearing — read before changing anything here).**
//! The backend is transport + index only. This module's entire job is to
//! return *bytes* and the routing metadata around them. It asserts nothing
//! about validity. Every field the backend hands us — `ingested_at`,
//! `created_at`, `platform`, `proof_schema` — is treated as untrusted display
//! metadata and never feeds a verdict. The only thing that produces a verdict
//! is [`crate::verify::verify`], run over the decoded `proof_bytes`, against
//! the kid registry embedded in this binary. See VERIFICATION-SPEC.md
//! "Backend fetch mode" for the full set of invariants.
//!
//! Concretely, that means:
//!   * We decode `proof_bytes_b64` and return the raw bytes; the caller runs
//!     the same pipeline it would for a local file.
//!   * We never parse the proof here, never compare backend metadata to proof
//!     contents, never short-circuit a check because the backend "said so".
//!   * Re-fetch consistency (invariant 4) is enforced caller-side against a
//!     byte-hash, not against any backend-supplied identity.

use std::io::Read;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use base64::Engine;
use serde::Deserialize;

/// Per the spec the token TTL is 24h and clients SHOULD refresh at T-30min.
/// We track mint time on a monotonic clock and re-mint past this threshold,
/// rather than trusting the backend-supplied `expires_at` for security
/// decisions. A reactive re-mint on any 401 is the real safety net.
const TOKEN_REFRESH_AFTER: Duration = Duration::from_secs((24 * 60 - 30) * 60);

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const TOTAL_TIMEOUT: Duration = Duration::from_secs(30);

/// Default page size for range queries (1–100, default 25).
const RANGE_PAGE_LIMIT: usize = 100;

// --- wire types: upload envelope + response shapes ---
//
// We deserialize leniently: only `proof_id` and `proof_bytes_b64` are load-
// bearing for the verifier. The rest are optional display metadata so a minor
// backend schema addition never breaks a fetch.

/// The upload envelope as returned by the query endpoints.
#[derive(Debug, Clone, Deserialize)]
pub struct Envelope {
    pub proof_id: String,
    pub proof_bytes_b64: String,
    #[serde(default)]
    pub license_id: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub platform: Option<String>,
    #[serde(default)]
    pub sdk_version: Option<String>,
    #[serde(default)]
    pub proof_schema: Option<String>,
    /// Schema-v2 replay-control object (absent on v1 / pre-challenge proofs).
    /// Backend-supplied and untrusted like the rest of the envelope; the verifier
    /// binds it to the signed proof rather than trusting it.
    #[serde(default, rename = "replay_control")]
    pub replay_control_json: Option<ReplayControlJson>,
}

/// The `replay_control` object as it appears on the wire (base64url-no-pad
/// strings + an integer ms timestamp). Decoded into [`crate::replay::ReplayControl`]
/// by [`Envelope::replay_control`].
#[derive(Debug, Clone, Deserialize)]
pub struct ReplayControlJson {
    #[serde(default)]
    pub upload_nonce: String,
    #[serde(default)]
    pub nullifier: String,
    #[serde(default)]
    pub signed_timestamp_ms: i64,
}

impl Envelope {
    /// Decode the `replay_control` object (if present) into the verifier's
    /// [`crate::replay::ReplayControl`]. Absent ⇒ `None` (back-compat → the
    /// binding check reports NOT-CHECKED). `upload_nonce` / `nullifier` are
    /// base64url-no-pad per spec; a field that doesn't decode yields empty bytes,
    /// which the binding cross-check rejects — it never silently passes.
    pub fn replay_control(&self) -> Option<crate::replay::ReplayControl> {
        self.replay_control_json.as_ref().map(|rc| crate::replay::ReplayControl {
            upload_nonce: decode_b64_lenient(&rc.upload_nonce),
            nullifier: decode_b64_lenient(&rc.nullifier),
            signed_timestamp_ms: rc.signed_timestamp_ms,
        })
    }

    /// Decode `proof_bytes_b64` into the raw proto bytes. The spec mandates
    /// base64-url-no-pad (RFC 4648 §5); we accept the common variants too,
    /// because byte tampering is caught downstream by signature verification,
    /// not by encoding strictness — so being permissive here only ever lets a
    /// well-formed proof through, never a forged one.
    pub fn proof_bytes(&self) -> Result<Vec<u8>> {
        let s = self.proof_bytes_b64.trim();
        let engines: [base64::engine::GeneralPurpose; 2] = [
            base64::engine::general_purpose::URL_SAFE_NO_PAD,
            base64::engine::general_purpose::STANDARD,
        ];
        for eng in &engines {
            if let Ok(bytes) = eng.decode(s) {
                return Ok(bytes);
            }
        }
        bail!("proof {}: proof_bytes_b64 is not valid base64", self.proof_id)
    }
}

/// Best-effort base64 decode (url-no-pad per spec, standard accepted) returning
/// empty bytes on failure. Used for replay-control fields, where a malformed
/// value is caught by the binding cross-check (empty never matches the signed
/// proof) rather than aborting the fetch.
fn decode_b64_lenient(s: &str) -> Vec<u8> {
    let s = s.trim();
    for eng in [
        base64::engine::general_purpose::URL_SAFE_NO_PAD,
        base64::engine::general_purpose::STANDARD,
    ] {
        if let Ok(b) = eng.decode(s) {
            return b;
        }
    }
    Vec::new()
}

#[derive(Debug, Deserialize)]
struct ProofWrapper {
    proof: Envelope,
}

#[derive(Debug, Deserialize)]
struct ListResponse {
    #[serde(default)]
    proofs: Vec<Envelope>,
    #[serde(default)]
    next_cursor: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AuthResponse {
    proof_upload_token: String,
    #[serde(default)]
    expires_at: Option<String>,
}

/// RFC 7807 `application/problem+json`. We parse it structurally — never by
/// matching on a human-readable string — so the backend can reword a `detail`
/// without breaking us, and so spec-defined extension members (e.g.
/// `min_envelope_schema_version`) are available without guesswork.
#[derive(Debug, Deserialize, Default)]
pub struct Problem {
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub status: Option<u16>,
    #[serde(rename = "type", default)]
    pub type_uri: Option<String>,
}

/// Max bytes of a backend-supplied `problem+json` string we echo to the console.
const DETAIL_DISPLAY_LIMIT: usize = 512;

/// Cap on the response body we buffer into memory, for every `net` GET.
///
/// ureq's own default read limit is 10 MiB, and until now that was the only
/// bound: `into_string()` would read up to 10 MiB before any of our size
/// handling ran (, Zellic backend-SSRF finding rec — a memory-DoS
/// residual on the `net` endpoints). The largest legitimate single response is
/// one `RANGE_PAGE_LIMIT`-sized page (100 proofs; a proof envelope with a full
/// hardware-attestation chain is tens of KiB), i.e. low single-digit MiB, so
/// 8 MiB leaves generous headroom while sitting below ureq's limit. A body past
/// the cap is truncated and then fails to parse as JSON downstream — fail-closed,
/// which is the correct outcome for an over-large or hostile response.
const MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;

impl Problem {
    fn summary(&self) -> String {
        let raw = match (&self.title, &self.detail) {
            (_, Some(d)) => d.as_str(),
            (Some(t), None) => t.as_str(),
            (None, None) => "(no problem detail)",
        };
        bound_and_sanitize(raw)
    }
}

/// Neutralise a backend-supplied string before it reaches the operator's
/// console: render control/escape bytes visible (an untrusted `detail` must not
/// be able to inject terminal escapes) and cap the length (ureq reads up to
/// 10 MiB, which we must not print whole). Byte-truncation on a char boundary.
fn bound_and_sanitize(s: &str) -> String {
    let mut out = String::with_capacity(s.len().min(DETAIL_DISPLAY_LIMIT) + 16);
    let mut truncated = false;
    for c in s.chars() {
        if out.len() >= DETAIL_DISPLAY_LIMIT {
            truncated = true;
            break;
        }
        // Escape C0 controls (< 0x20), DEL, and the C1 range (0x7f..=0x9f) so a
        // backend-supplied string can never smuggle a terminal control sequence.
        if (c as u32) < 0x20 || (0x7f..=0x9f).contains(&(c as u32)) {
            out.push_str(&format!("\\x{:02x}", c as u32));
        } else {
            out.push(c);
        }
    }
    if truncated {
        out.push_str(" …[truncated]");
    }
    out
}

/// A non-2xx HTTP response, with the status code preserved so the caller can
/// distinguish 401 (→ re-mint) from 404 (→ "no such proof") etc.
#[derive(Debug)]
pub struct HttpError {
    pub status: u16,
    pub problem: Option<Problem>,
}

impl std::fmt::Display for HttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let detail = self
            .problem
            .as_ref()
            .map(Problem::summary)
            .unwrap_or_else(|| "(no problem+json body)".to_string());
        write!(f, "backend returned HTTP {}: {}", self.status, detail)
    }
}

impl std::error::Error for HttpError {}

// --- client ---

/// A connection to one backend, holding the activation bearer and the most
/// recently minted `proof_upload_token`.
pub struct Backend {
    base: String,
    agent: ureq::Agent,
    activation_bearer: String,
    token: Option<MintedToken>,
}

struct MintedToken {
    value: String,
    minted: Instant,
    /// Backend-reported expiry, kept for display only — never trusted for
    /// refresh decisions (we use `minted` + `TOKEN_REFRESH_AFTER`).
    expires_at: Option<String>,
}

impl Backend {
    /// Connect to `base_url`, holding `activation_bearer` for minting upload
    /// tokens. No network call happens here; the token is minted lazily on the
    /// first request. Rejects plaintext URLs outside the LAN-dev allowlist.
    ///
    /// SECURITY (`redirects(0)`, load-bearing): [`check_url_scheme`] validates
    /// only `base_url`. ureq follows up to 5 redirects by default, and a redirect
    /// target is *not* re-checked — so an untrusted backend could 3xx us to an
    /// arbitrary host/port/scheme inside the auditor's network (SSRF) and, via a
    /// hostless `Location`, panic the process. The API is a fixed set of endpoints
    /// on one origin, so there is no legitimate redirect to follow: we disable
    /// redirect following entirely. A 3xx then surfaces as an error rather than a
    /// second request.
    pub fn connect(base_url: &str, activation_bearer: &str) -> Result<Self> {
        check_url_scheme(base_url)?;
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(CONNECT_TIMEOUT)
            .timeout(TOTAL_TIMEOUT)
            .redirects(0)
            .build();
        Ok(Backend {
            base: base_url.trim_end_matches('/').to_string(),
            agent,
            activation_bearer: activation_bearer.to_string(),
            token: None,
        })
    }

    /// Backend-reported token expiry of the currently-held token, if any.
    /// For human display only.
    pub fn token_expiry(&self) -> Option<&str> {
        self.token.as_ref().and_then(|t| t.expires_at.as_deref())
    }

    /// Mint (or re-use) a `proof_upload_token`, refreshing it if it is older
    /// than [`TOKEN_REFRESH_AFTER`].
    fn ensure_token(&mut self) -> Result<()> {
        let needs_mint = match &self.token {
            None => true,
            Some(t) => t.minted.elapsed() >= TOKEN_REFRESH_AFTER,
        };
        if needs_mint {
            self.mint()?;
        }
        Ok(())
    }

    /// Force a fresh mint — used reactively on a 401.
    fn force_refresh(&mut self) -> Result<()> {
        self.mint()
    }

    fn mint(&mut self) -> Result<()> {
        let url = format!("{}/v1/proofs/auth", self.base);
        let resp = self
            .agent
            .post(&url)
            .set("Authorization", &format!("Bearer {}", self.activation_bearer))
            .call();
        let body = read_response(resp).context("minting proof_upload_token (POST /v1/proofs/auth)")?;
        let auth: AuthResponse = decode_json(&body, "POST /v1/proofs/auth")?;
        self.token = Some(MintedToken {
            value: auth.proof_upload_token,
            minted: Instant::now(),
            expires_at: auth.expires_at,
        });
        Ok(())
    }

    /// Issue an authenticated GET, retrying once with a freshly-minted token on
    /// a 401. `query` pairs are URL-encoded by the agent.
    fn get(&mut self, path: &str, query: &[(&str, &str)]) -> Result<String, GetError> {
        self.ensure_token().map_err(GetError::Other)?;
        match self.get_once(path, query) {
            Err(GetError::Http(e)) if e.status == 401 => {
                // Token may have expired early or been revoked — re-mint once.
                self.force_refresh().map_err(GetError::Other)?;
                self.get_once(path, query)
            }
            other => other,
        }
    }

    fn get_once(&self, path: &str, query: &[(&str, &str)]) -> Result<String, GetError> {
        let token = self
            .token
            .as_ref()
            .ok_or_else(|| GetError::Other(anyhow!("no upload token minted")))?;
        let url = format!("{}{}", self.base, path);
        let mut req = self
            .agent
            .get(&url)
            .set("Authorization", &format!("Bearer {}", token.value));
        for (k, v) in query {
            req = req.query(k, v);
        }
        read_response(req.call()).map_err(|e| match e.downcast::<HttpError>() {
            Ok(h) => GetError::Http(h),
            Err(other) => GetError::Other(other),
        })
    }

    /// `GET /v1/proofs/{proof_id}` — a single proof. 403/404 → "not found"
    /// (the spec collapses 403 into 404 to avoid cross-license leakage).
    pub fn fetch_one(&mut self, proof_id: &str) -> Result<Envelope> {
        // Validate at the trust boundary before interpolating into the path.
        // `proof_id` is interpolated unencoded, so an id carrying `?`/`#`/`../`
        // could otherwise reach other paths or queries on the same backend.
        // (`//host` cannot escape the origin — the base already carries the
        // authority — but path/query traversal is still worth refusing.)
        if !valid_proof_id(proof_id) {
            bail!(
                "invalid proof id {proof_id:?}: expected 1-128 chars of \
                 [A-Za-z0-9_.:-]"
            );
        }
        let path = format!("/v1/proofs/{}", proof_id);
        match self.get(&path, &[]) {
            Ok(body) => {
                let w: ProofWrapper = decode_json(&body, "GET /v1/proofs/{id}")?;
                Ok(w.proof)
            }
            Err(GetError::Http(e)) if e.status == 404 || e.status == 403 => {
                bail!("no proof with id {proof_id:?} available to this license")
            }
            Err(e) => Err(e.into()),
        }
    }

    /// `GET /v1/proofs/latest` — the most recent proof, or `None` on 404
    /// (no proofs ingested for this license yet).
    pub fn fetch_latest(&mut self) -> Result<Option<Envelope>> {
        match self.get("/v1/proofs/latest", &[]) {
            Ok(body) => {
                let w: ProofWrapper = decode_json(&body, "GET /v1/proofs/latest")?;
                Ok(Some(w.proof))
            }
            Err(GetError::Http(e)) if e.status == 404 => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// `GET /v1/proofs?since&until` — every proof in the window, following
    /// `next_cursor` pagination to exhaustion. Newest-first per the spec.
    pub fn fetch_range(&mut self, since: Option<&str>, until: Option<&str>) -> Result<Vec<Envelope>> {
        let limit = RANGE_PAGE_LIMIT.to_string();
        let mut out = Vec::new();
        let mut cursor: Option<String> = None;
        loop {
            let mut query: Vec<(&str, &str)> = vec![("limit", &limit)];
            if let Some(s) = since {
                query.push(("since", s));
            }
            if let Some(u) = until {
                query.push(("until", u));
            }
            if let Some(c) = &cursor {
                query.push(("cursor", c));
            }
            let body = self.get("/v1/proofs", &query)?;
            let page: ListResponse = decode_json(&body, "GET /v1/proofs")?;
            out.extend(page.proofs);
            match page.next_cursor {
                Some(next) if !next.is_empty() => cursor = Some(next),
                _ => break,
            }
        }
        Ok(out)
    }
}

/// Internal GET outcome that preserves the HTTP status for retry/branching.
enum GetError {
    Http(HttpError),
    Other(anyhow::Error),
}

impl From<GetError> for anyhow::Error {
    fn from(e: GetError) -> Self {
        match e {
            GetError::Http(h) => h.into(),
            GetError::Other(o) => o,
        }
    }
}

/// Decode a JSON response body into `T` without leaking the (untrusted, up to
/// 10 MiB) body through the error. serde's own error embeds the offending value
/// verbatim, so a malformed 2xx/3xx body would otherwise be echoed whole to the
/// operator's console. Report only the endpoint, the parse position, the body
/// length, and a bounded + sanitized snippet.
fn decode_json<T: serde::de::DeserializeOwned>(body: &str, endpoint: &str) -> Result<T> {
    serde_json::from_str::<T>(body).map_err(|e| {
        anyhow!(
            "decoding {endpoint} response failed at line {} column {} ({} byte body): {}",
            e.line(),
            e.column(),
            body.len(),
            bound_and_sanitize(body),
        )
    })
}

/// Read at most `cap` bytes from `r` into a String (see [`MAX_RESPONSE_BYTES`]).
/// Kept as a small generic so the cap itself is unit-testable without HTTP.
fn read_capped<R: std::io::Read>(r: R, cap: u64) -> std::io::Result<String> {
    let mut buf = String::new();
    r.take(cap).read_to_string(&mut buf)?;
    Ok(buf)
}

/// Turn a ureq result into a body string, mapping any non-2xx into an
/// [`HttpError`] carrying the parsed `problem+json` (when present). Both the
/// success and the error body are bounded to [`MAX_RESPONSE_BYTES`] — the read
/// itself, not just its later display.
fn read_response(resp: Result<ureq::Response, ureq::Error>) -> Result<String> {
    match resp {
        Ok(r) => read_capped(r.into_reader(), MAX_RESPONSE_BYTES)
            .context("reading response body"),
        Err(ureq::Error::Status(status, r)) => {
            let body = read_capped(r.into_reader(), MAX_RESPONSE_BYTES).unwrap_or_default();
            let problem = serde_json::from_str::<Problem>(&body).ok();
            Err(HttpError { status, problem }.into())
        }
        Err(ureq::Error::Transport(t)) => {
            Err(anyhow!("transport error talking to backend: {t}"))
        }
    }
}

/// Enforce the plaintext allowlist: HTTPS is always allowed; plain
/// HTTP only for localhost / RFC1918 LAN-dev hosts. Everything else is
/// rejected, so a typo'd or downgraded production URL fails loud rather than
/// shipping bearer tokens in the clear.
fn check_url_scheme(base: &str) -> Result<()> {
    if base.strip_prefix("https://").is_some() {
        return Ok(());
    }
    let Some(rest) = base.strip_prefix("http://") else {
        bail!("backend url must start with https:// (or http:// for LAN dev): {base:?}");
    };

    // Take the authority (up to the first '/') and strip an optional ":port".
    // CRITICAL: the LAN-dev allowlist matches a *parsed* IPv4 address, never a
    // string prefix. Prefix-matching the host (`starts_with("10.")`) would let an
    // attacker-controlled DNS name like `10.evil.com` / `127.foo.com` through and
    // ship the bearer token over plaintext. IPv6 literals are not parsed here, so
    // `http://[..]` fails closed (rejected), which is the safe default.
    let authority = rest.split('/').next().unwrap_or("");
    let host = authority.rsplit_once(':').map_or(authority, |(h, _)| h);

    let lan = host == "localhost"
        || host.parse::<std::net::Ipv4Addr>().is_ok_and(|ip| {
            let o = ip.octets();
            ip.is_loopback()                       // 127.0.0.0/8
                || o[0] == 10                      // 10.0.0.0/8
                || (o[0] == 192 && o[1] == 168)    // 192.168.0.0/16
        });
    if lan {
        return Ok(());
    }
    bail!(
        "refusing plaintext http:// to non-LAN host {host:?}: use https://. Plain \
         http is allowed only for LAN dev — localhost, or a literal IP in \
         127.0.0.0/8, 10.0.0.0/8, or 192.168.0.0/16."
    )
}

/// A `proof_id` safe to interpolate into `/v1/proofs/{id}` without encoding.
/// Restricted to the characters real ids use so `?`, `#`, `/`, whitespace and
/// control bytes cannot re-target the request. Bounded length as a DoS guard.
/// An all-dots id (`.`, `..`, …) is rejected: `.` is allowed inside a real id,
/// but a bare dot-segment is normalised by URL parsing into a different path
/// (`/v1/` or `/v1/proofs/`), so it must not stand alone as the whole id.
fn valid_proof_id(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && !s.bytes().all(|b| b == b'.')
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.' | b':'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_proof_id_accepts_real_ids_rejects_traversal() {
        assert!(valid_proof_id("lp_abc123"));
        assert!(valid_proof_id("lp-1.2:3"));
        assert!(valid_proof_id(&"a".repeat(128)));
        // Empty, over-length, and any path/query/authority metacharacter.
        assert!(!valid_proof_id(""));
        assert!(!valid_proof_id(&"a".repeat(129)));
        assert!(!valid_proof_id("../..//evil.example/x"));
        assert!(!valid_proof_id("a/b"));
        assert!(!valid_proof_id("a?b=c"));
        assert!(!valid_proof_id("a#frag"));
        assert!(!valid_proof_id("a b"));
        assert!(!valid_proof_id("a\nb"));
        //: a bare dot-segment normalises to a different path — reject.
        assert!(!valid_proof_id("."));
        assert!(!valid_proof_id(".."));
        assert!(!valid_proof_id("..."));
        // ...but a dot inside a real id is still fine.
        assert!(valid_proof_id("lp.1"));
    }

    #[test]
    fn problem_detail_is_bounded_and_escaped() {
        // Control/escape bytes are rendered visible, not passed through.
        let p = Problem {
            title: None,
            detail: Some("boom\u{1b}[31m\u{7f}".into()),
            status: Some(500),
            type_uri: None,
        };
        let s = p.summary();
        assert!(!s.contains('\u{1b}'), "escape byte must not survive: {s:?}");
        assert!(s.contains("\\x1b") && s.contains("\\x7f"));
        // A 10 KiB detail is capped well under ureq's 10 MiB read limit.
        let big = Problem {
            title: None,
            detail: Some("A".repeat(10_000)),
            status: Some(500),
            type_uri: None,
        };
        let s = big.summary();
        assert!(s.len() <= DETAIL_DISPLAY_LIMIT + 32);
        assert!(s.ends_with("…[truncated]"));
        //: C1 controls (U+0080–U+009F) must also be escaped, not passed through.
        let c1 = Problem {
            title: None,
            detail: Some("x\u{9b}y\u{9d}z".into()), // CSI, OSC
            status: Some(500),
            type_uri: None,
        };
        let s = c1.summary();
        assert!(!s.contains('\u{9b}') && !s.contains('\u{9d}'), "C1 must not survive: {s:?}");
        assert!(s.contains("\\x9b") && s.contains("\\x9d"));
    }

    #[test]
    fn decode_json_error_does_not_echo_the_whole_body() {
        //: a malformed 2xx/3xx body must not be echoed verbatim — the error
        // reports length + a bounded snippet, not the whole (up to 10 MiB) body.
        let body = format!("\"{}\"", "P".repeat(10_000)); // valid JSON string, wrong type
        let err = decode_json::<ProofWrapper>(&body, "GET /v1/proofs/{id}").unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("10002 byte body"), "must report body length: {msg}");
        assert!(msg.len() < 1024, "must be bounded, got {} bytes", msg.len());
        assert!(!msg.contains(&"P".repeat(1000)), "must not echo the full body");
    }

    #[test]
    fn url_scheme_allows_https_and_lan_http_only() {
        assert!(check_url_scheme("https://api.octetproof.com").is_ok());
        assert!(check_url_scheme("http://localhost:8000").is_ok());
        assert!(check_url_scheme("http://127.0.0.1:8000").is_ok());
        assert!(check_url_scheme("http://10.0.0.5:8000").is_ok());
        assert!(check_url_scheme("http://192.168.1.20:8000/").is_ok());
        // Plaintext to a public host must be refused — bearer tokens ride here.
        assert!(check_url_scheme("http://api.octetproof.com").is_err());
        assert!(check_url_scheme("http://8.8.8.8").is_err());
        assert!(check_url_scheme("ftp://nope").is_err());

        // SECURITY regression: a hostname that merely *starts with* an allowed
        // prefix is an attacker-controlled DNS name, NOT an RFC1918 IP, and must
        // be refused — otherwise the bearer token ships over plaintext.
        assert!(check_url_scheme("http://10.evil.com").is_err());
        assert!(check_url_scheme("http://127.attacker.com").is_err());
        assert!(check_url_scheme("http://192.168.evil.com").is_err());
        assert!(check_url_scheme("http://10.0.0.5.attacker.com").is_err());
        assert!(check_url_scheme("http://localhost.attacker.com").is_err());
        assert!(check_url_scheme("http://10.evil.com:8000/v1/proofs/auth").is_err());
        // 172.16/12 is RFC1918 but outside the documented allowlist.
        assert!(check_url_scheme("http://172.16.0.1").is_err());
    }

    #[test]
    fn proof_bytes_decodes_url_and_standard_base64() {
        let raw = b"\x00\x01\x02hello-proof-bytes\xff";
        let url_no_pad = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
        let std_pad = base64::engine::general_purpose::STANDARD.encode(raw);
        for enc in [url_no_pad, std_pad] {
            let env = Envelope {
                proof_id: "lp_test".into(),
                proof_bytes_b64: enc,
                license_id: None,
                created_at: None,
                platform: None,
                sdk_version: None,
                proof_schema: None,
                replay_control_json: None,
            };
            assert_eq!(env.proof_bytes().unwrap(), raw);
        }
    }

    #[test]
    fn problem_summary_prefers_detail() {
        let p = Problem {
            title: Some("Conflict".into()),
            detail: Some("proof_id exists with different bytes".into()),
            status: Some(409),
            type_uri: None,
        };
        assert_eq!(p.summary(), "proof_id exists with different bytes");
    }

    /// A v2 envelope's `replay_control` parses and its base64url-no-pad fields
    /// decode to the exact bytes the binding check will compare against; a v1
    /// envelope (key absent) yields `None` → the NOT-CHECKED back-compat path.
    #[test]
    fn replay_control_parses_and_decodes() {
        let nonce = b"\x10\x20\x30nonce";
        let null = b"\xaa\xbbnull";
        let nonce_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce);
        let null_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(null);
        let json = format!(
            r#"{{"proof_id":"lp1","proof_bytes_b64":"AA","schema_version":2,
                "replay_control":{{"upload_nonce":"{nonce_b64}","nullifier":"{null_b64}",
                "signed_timestamp_ms":1700000000000}}}}"#
        );
        let env: Envelope = serde_json::from_str(&json).unwrap();
        let rc = env.replay_control().expect("v2 envelope has replay_control");
        assert_eq!(rc.upload_nonce, nonce);
        assert_eq!(rc.nullifier, null);
        assert_eq!(rc.signed_timestamp_ms, 1_700_000_000_000);

        // v1: replay_control key absent → None.
        let v1: Envelope =
            serde_json::from_str(r#"{"proof_id":"lp0","proof_bytes_b64":"AA"}"#).unwrap();
        assert!(v1.replay_control().is_none());
    }

    #[test]
    fn read_capped_truncates_an_oversized_body() {
        // An unbounded (here, effectively infinite) body is read only up to the
        // cap, not whole — the memory-DoS guard on the net endpoints.
        let cap = 4096u64;
        let s = read_capped(std::io::repeat(b'x'), cap).unwrap();
        assert_eq!(s.len() as u64, cap);
    }

    #[test]
    fn read_capped_passes_a_normal_body_through_untouched() {
        let body = br#"{"proof_id":"lp0","proof_bytes_b64":"AA"}"#;
        let s = read_capped(&body[..], MAX_RESPONSE_BYTES).unwrap();
        assert_eq!(s, r#"{"proof_id":"lp0","proof_bytes_b64":"AA"}"#);
    }
}
