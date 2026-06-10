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
}

impl Envelope {
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

impl Problem {
    fn summary(&self) -> String {
        match (&self.title, &self.detail) {
            (_, Some(d)) => d.clone(),
            (Some(t), None) => t.clone(),
            (None, None) => "(no problem detail)".to_string(),
        }
    }
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
    pub fn connect(base_url: &str, activation_bearer: &str) -> Result<Self> {
        check_url_scheme(base_url)?;
        let agent = ureq::AgentBuilder::new()
            .timeout_connect(CONNECT_TIMEOUT)
            .timeout(TOTAL_TIMEOUT)
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
        let auth: AuthResponse = serde_json::from_str(&body)
            .context("decoding /v1/proofs/auth response")?;
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
        let path = format!("/v1/proofs/{}", proof_id);
        match self.get(&path, &[]) {
            Ok(body) => {
                let w: ProofWrapper =
                    serde_json::from_str(&body).context("decoding GET /v1/proofs/{id} response")?;
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
                let w: ProofWrapper = serde_json::from_str(&body)
                    .context("decoding GET /v1/proofs/latest response")?;
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
            let page: ListResponse =
                serde_json::from_str(&body).context("decoding GET /v1/proofs response")?;
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

/// Turn a ureq result into a body string, mapping any non-2xx into an
/// [`HttpError`] carrying the parsed `problem+json` (when present).
fn read_response(resp: Result<ureq::Response, ureq::Error>) -> Result<String> {
    match resp {
        Ok(r) => r
            .into_string()
            .context("reading response body"),
        Err(ureq::Error::Status(status, r)) => {
            let body = r.into_string().unwrap_or_default();
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

#[cfg(test)]
mod tests {
    use super::*;

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
}
