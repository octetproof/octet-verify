//! Browser verdict profile (feature `browser`).
//!
//! Verifies the octet browser product's signed **verdict token** (a compact JWS)
//! and the session chain inside it, against published keys. Verification only:
//! whether the browser's signals are true is out of scope, as is the opaque,
//! partner-scoped `deviceKey`. See VERIFICATION-SPEC.md, "Browser verdict profile".
//!
//! Inputs: the verdict token and the verdict JWKS (live, or the archive for a
//! stored token whose key has rotated); optionally the challenge token the
//! partner kept from `POST /v1/challenge` plus the challenge JWKS, and an edge
//! log line `{"octetChain":{"sid","env","s2","kid","ts"}}` (raw, with the edge's
//! log prefix, or the JSON alone).
//!
//! Optionally, the keys are checked against octet's **root manifest**: a
//! compact JWS signed by an offline root (pinned, never fetched from the
//! server being checked) that lists every verdict and challenge key.
//!
//! Each check reports VERIFIED / FAILED / NOT-CHECKED / WARN, or ATTESTED for a
//! link octet verified but a third party cannot (the S1 device signature, and
//! the anchor receipts, which name the user's IP).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Accepted JWS `typ` values; the suffix versions the claim set.
const VERDICT_TYPS: [(&str, u8); 3] = [
    ("octet-browser-verdict+jwt;v=1", 1),
    ("octet-browser-verdict+jwt;v=2", 2),
    ("octet-browser-verdict+jwt;v=3", 3),
];
const VERDICT_ISS: &str = "octet-browser";
const VERDICT_PURPOSE: &str = "browser-verdict";
const CHALLENGE_PURPOSE: &str = "browser-challenge";
const CHALLENGE_TYP: &str = "octet-browser-challenge";
const CHAIN_TAG: &[u8] = b"octet-browser-chain-v1";
const PASETO_HEADER: &str = "v4.public.";
/// Clock tolerance for the time windows, seconds.
const SKEW_S: i64 = 60;
/// JavaScript's `Number.MAX_SAFE_INTEGER`: the signer refuses larger `s1.t`.
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// Published live verdict JWKS.
pub const VERDICT_JWKS_URL: &str = "https://geo.octetproof.com/.well-known/browser-verdict-jwks.json";
/// Published verdict key archive (every key octet has signed with).
pub const VERDICT_JWKS_ARCHIVE_URL: &str =
    "https://geo.octetproof.com/.well-known/browser-verdict-jwks-archive.json";
/// Published root manifest (compact JWS; its payload is the manifest bytes).
pub const MANIFEST_URL: &str = "https://geo.octetproof.com/.well-known/octet-browser-manifest.json.jws";
/// octet's pinned offline roots, as `{"roots":[...]}` (octet-browser
/// `keys/octet-root.json`). Added at the first root ceremony (2026-10-12): two
/// ES256 keys, each generated on its own YubiKey (PIV slot 9c) and attested by
/// Yubico; either may sign a manifest.
pub const PINNED_ROOTS_JSON: &str = r#"{"roots":[
{"kty":"EC","crv":"P-256","kid":"octet-root-a-2026-10","x":"-TTm69g0eOIcWb-I9gVwsZCsSNTSPJIjmuJQetUVO7o","y":"SfDnpa7Jtnw8FDYvcPnZUJZN8D2wQSztUMlucUHyM6A","octet_purpose":"octet-root"},
{"kty":"EC","crv":"P-256","kid":"octet-root-b-2026-10","x":"Nl3Zsqh92UZPPCVGqpQYPP-pZoKI7_YNhGG4qaS4qM8","y":"6MdPuYVrKIeDV4_gSDfqL5EnABIwXSyjo8-gd3i9TtM","octet_purpose":"octet-root"}
]}"#;
const MANIFEST_TYP: &str = "octet-browser-manifest";
const ROOT_JWS_TYP: &str = "octet-root+jws;v=1";
const ROOT_PURPOSE: &str = "octet-root";
const DAY_S: i64 = 86_400;
/// octet-browser warns this long before a manifest's `exp`...
const MANIFEST_WARN_BEFORE_S: i64 = 30 * DAY_S;
/// ...and geo refuses to boot this long after it.
const MANIFEST_GRACE_S: i64 = 14 * DAY_S;
/// A manifest may claim at most this lifetime.
const MANIFEST_MAX_LIFETIME_S: i64 = 400 * DAY_S;

/// Published challenge JWKS.
pub const CHALLENGE_JWKS_URL: &str = "https://geo.octetproof.com/.well-known/browser-challenge-jwks.json";

/// Result of one browser-profile check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BrowserStatus {
    Verified,
    Failed,
    NotChecked,
    /// Holds, but needs attention (e.g. a manifest past `exp`, within grace).
    Warning,
    /// Octet verified this link; a third party cannot re-check it.
    Attested,
}

impl BrowserStatus {
    pub fn tag(self) -> &'static str {
        match self {
            BrowserStatus::Verified => "VERIFIED",
            BrowserStatus::Failed => "FAILED",
            BrowserStatus::NotChecked => "NOT-CHECKED",
            BrowserStatus::Warning => "WARN",
            BrowserStatus::Attested => "ATTESTED",
        }
    }
}

#[derive(Clone, Debug)]
pub struct BrowserCheck {
    pub name: &'static str,
    pub status: BrowserStatus,
    pub detail: String,
}

/// A published key: a JWK plus octet's archive fields.
#[derive(Clone, Debug)]
pub struct Jwk {
    pub kid: String,
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: Option<String>,
    pub alg: Option<String>,
    pub purpose: Option<String>,
    /// Archive: when octet started / stopped signing with the key (epoch s).
    pub not_before: Option<i64>,
    pub not_after: Option<i64>,
    /// Archive: set when the key is revoked; tokens issued at or after it are untrusted.
    pub revoked_at: Option<i64>,
}

/// Parse a JWK Set (`{"keys":[...]}`), live or archive.
pub fn parse_jwks(json: &str) -> Result<Vec<Jwk>, String> {
    let v: Value = serde_json::from_str(json).map_err(|e| format!("JWKS is not JSON: {e}"))?;
    jwk_list(&v, "keys", "JWKS")
}

/// Parse the pinned roots, `{"roots":[...]}`: EC P-256 keys only, and a key
/// that names a purpose must name `octet-root`.
pub fn parse_roots(json: &str) -> Result<Vec<Jwk>, String> {
    let v: Value = serde_json::from_str(json).map_err(|e| format!("roots file is not JSON: {e}"))?;
    let roots = jwk_list(&v, "roots", "roots")?;
    for r in &roots {
        if (r.kty.as_str(), r.crv.as_str()) != ("EC", "P-256") {
            return Err(format!("root {:?} is not an EC P-256 key", r.kid));
        }
        if r.purpose.as_deref().is_some_and(|p| p != ROOT_PURPOSE) {
            return Err(format!("root {:?} is not published for {ROOT_PURPOSE:?}", r.kid));
        }
    }
    Ok(roots)
}

fn jwk_list(v: &Value, field: &str, what: &str) -> Result<Vec<Jwk>, String> {
    let keys = v.get(field).and_then(Value::as_array).ok_or_else(|| format!("{what} has no \"{field}\" array"))?;
    keys.iter().enumerate().map(|(i, k)| jwk(k, &format!("{what} {field}[{i}]"))).collect()
}

fn jwk(k: &Value, at: &str) -> Result<Jwk, String> {
    let s = |f: &str| k.get(f).and_then(Value::as_str).map(str::to_owned);
    let n = |f: &str| k.get(f).and_then(Value::as_i64);
    let req = |f: &str| s(f).ok_or_else(|| format!("{at} has no \"{f}\""));
    let revoked = s("octet_status").as_deref() == Some("revoked");
    let revoked_at = n("octet_revoked_at");
    if revoked != revoked_at.is_some() {
        return Err(format!("{at}: octet_status \"revoked\" and octet_revoked_at go together"));
    }
    Ok(Jwk {
        kid: req("kid")?,
        kty: req("kty")?,
        crv: req("crv")?,
        x: req("x")?,
        y: s("y"),
        alg: s("alg"),
        purpose: s("octet_purpose"),
        not_before: n("octet_not_before"),
        not_after: n("octet_not_after"),
        revoked_at,
    })
}

/// Same public key: key type, curve and coordinates.
fn same_key(a: &Jwk, b: &Jwk) -> bool {
    (&a.kty, &a.crv, &a.x, &a.y) == (&b.kty, &b.crv, &b.x, &b.y)
}

/// A verified root manifest.
#[derive(Clone, Debug)]
pub struct Manifest {
    pub seq: u64,
    pub iat: i64,
    pub exp: i64,
    /// The pinned root that signed it.
    pub root_kid: String,
    pub verdict_keys: Vec<Jwk>,
    pub challenge_keys: Vec<Jwk>,
    /// Roots that may sign the next manifest.
    pub roots: Vec<String>,
}

/// Verify a root manifest JWS against pinned `roots` and parse it.
///
/// The header must be exactly `{"alg":"ES256","typ":"octet-root+jws;v=1","kid"}`
/// (any other field is refused), the kid must name a pinned root, and the
/// signature is ES256 raw `r‖s`. The payload must be `typ
/// "octet-browser-manifest"`, `v` 1, with integer `seq` / `iat` / `exp`
/// (`exp - iat` at most 400 days) and non-empty `roots`. Expiry and rollback
/// are judged by the caller (see [`verify_browser_verdict`]).
pub fn verify_manifest(jws: &str, roots: &[Jwk]) -> Result<Manifest, String> {
    let parts: Vec<&str> = jws.trim().split('.').collect();
    let [h, p, s] = parts[..] else { return Err("manifest is not a compact JWS".into()) };
    let header = json_object(&b64(h).map_err(|e| format!("manifest header {e}"))?, "manifest header")?;
    let obj = header.as_object().expect("json_object returns an object");
    if let Some(extra) = obj.keys().find(|k| !["alg", "typ", "kid"].contains(&k.as_str())) {
        return Err(format!("manifest header has an unexpected field {extra:?}"));
    }
    if obj.get("alg").and_then(Value::as_str) != Some("ES256") || obj.get("typ").and_then(Value::as_str) != Some(ROOT_JWS_TYP) {
        return Err(format!("manifest header must be alg ES256, typ {ROOT_JWS_TYP}"));
    }
    let kid = obj.get("kid").and_then(Value::as_str).ok_or("manifest header has no kid")?;
    let mut it = roots.iter().filter(|r| r.kid == kid);
    let root = it.next().ok_or_else(|| format!("manifest is signed by {kid:?}, which is not a pinned root"))?;
    if it.next().is_some() {
        return Err(format!("more than one pinned root has kid {kid:?}"));
    }
    let PubKey::P256(vk) = pub_key(root)? else { return Err(format!("root {kid:?} is not P-256")) };
    let sig = b64(s).map_err(|e| format!("manifest signature {e}"))?;
    let sig = p256::ecdsa::Signature::from_slice(&sig).map_err(|_| "manifest signature is not 64-byte r‖s")?;
    {
        use p256::ecdsa::signature::Verifier;
        vk.verify(format!("{h}.{p}").as_bytes(), &sig)
            .map_err(|_| format!("manifest signature does not verify with root {kid:?}"))?;
    }
    let m = json_object(&b64(p).map_err(|e| format!("manifest payload {e}"))?, "manifest")?;
    if m.get("typ").and_then(Value::as_str) != Some(MANIFEST_TYP) || m.get("v").and_then(Value::as_u64) != Some(1) {
        return Err(format!("manifest is not typ {MANIFEST_TYP:?} v=1"));
    }
    let seq = m.get("seq").and_then(Value::as_u64).filter(|n| *n > 0).ok_or("manifest seq is not a positive integer")?;
    let (Some(iat), Some(exp)) = (int(&m, "iat"), int(&m, "exp")) else {
        return Err("manifest has no integer iat/exp".into());
    };
    if exp <= iat || exp - iat > MANIFEST_MAX_LIFETIME_S {
        return Err(format!("manifest lifetime {iat}..{exp} is not within 400 days"));
    }
    let next_roots: Vec<String> = m
        .get("roots")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).map(str::to_owned).collect())
        .unwrap_or_default();
    if next_roots.is_empty() {
        return Err("manifest names no roots for the next manifest".into());
    }
    Ok(Manifest {
        seq,
        iat,
        exp,
        root_kid: kid.to_owned(),
        verdict_keys: jwk_list(&m, "verdictKeys", "manifest")?,
        challenge_keys: jwk_list(&m, "challengeKeys", "manifest")?,
        roots: next_roots,
    })
}

/// Inputs to [`verify_browser_verdict`].
pub struct BrowserVerdictInputs<'a> {
    pub verdict_token: &'a str,
    pub verdict_keys: &'a [Jwk],
    pub challenge_token: Option<&'a str>,
    pub challenge_keys: Option<&'a [Jwk]>,
    /// The edge log line, `{"octetChain":{...}}`, optionally with the edge's log
    /// prefix (e.g. Go's `2026/10/02 12:28:09 `) in front.
    pub edge_log: Option<&'a str>,
    /// Verification time, epoch seconds (expiry reports and the manifest window).
    pub now_unix: i64,
    /// The root manifest JWS. `None` ⇒ the manifest checks are NOT-CHECKED.
    pub manifest: Option<&'a str>,
    /// Pinned roots (never taken from the server being checked). Empty ⇒ the
    /// manifest checks are NOT-CHECKED.
    pub roots: &'a [Jwk],
    /// The highest manifest `seq` already seen; a lower one is a rollback and FAILS.
    pub min_manifest_seq: Option<u64>,
}

/// The result: every check, plus the signed claims when the JWS verified.
pub struct BrowserReport {
    pub checks: Vec<BrowserCheck>,
    /// Claims, present only when the verdict signature verified.
    pub claims: Option<Value>,
    /// The `v` of the verdict `typ`, when recognised.
    pub version: Option<u8>,
    /// The licence the challenge names, when the session link verified.
    pub lid: Option<String>,
    /// The `seq` of the manifest, when it verified (persist the highest seen).
    pub manifest_seq: Option<u64>,
}

impl BrowserReport {
    /// No check failed AND the verdict signature verified.
    pub fn is_valid(&self) -> bool {
        self.checks.iter().all(|c| c.status != BrowserStatus::Failed)
            && self.status("verdict-jws") == Some(BrowserStatus::Verified)
    }

    /// The signed `clientNetMatch` (v=3): whether the report came from the
    /// client network the partner's backend saw. `None` when the token didn't
    /// verify or carries no such claim. `Some(false)` is a valid result.
    pub fn client_net_match(&self) -> Option<bool> {
        self.claims.as_ref()?.get("clientNetMatch")?.as_bool()
    }

    pub fn status(&self, name: &str) -> Option<BrowserStatus> {
        self.checks.iter().find(|c| c.name == name).map(|c| c.status)
    }

    fn add(&mut self, name: &'static str, status: BrowserStatus, detail: impl Into<String>) {
        self.checks.push(BrowserCheck { name, status, detail: detail.into() });
    }
}

fn b64(s: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD.decode(s).map_err(|e| format!("not base64url without padding: {e}"))
}

fn digest32(v: Option<&Value>, name: &str) -> Result<[u8; 32], String> {
    let s = v.and_then(Value::as_str).ok_or_else(|| format!("{name} is missing"))?;
    b64(s)
        .map_err(|e| format!("{name}: {e}"))?
        .try_into()
        .map_err(|_| format!("{name} is not a 32-byte digest"))
}

fn sha256(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

/// Recompute `chain_root` over a `chain` claim (octet-browser `chain.ts`):
///
/// ```text
/// SHA-256( "octet-browser-chain-v1" ‖ s0 ‖ u32be(len(reports))
///          ‖ for each report: s1.bundle ‖ u64be(s1.t) ‖ s1.sig ‖ env ‖ (s2.h | 32×0x00)
///          ‖ (rcpt | 32×0x00) )
/// ```
///
/// Every digest is its 32 raw bytes; `rcpt` comes once, after the reports.
pub fn chain_root(chain: &Value) -> Result<[u8; 32], String> {
    if chain.get("v").and_then(Value::as_u64) != Some(1) {
        return Err("chain.v is not 1".into());
    }
    let reports = chain.get("reports").and_then(Value::as_array).ok_or("chain.reports is missing")?;
    let n = u32::try_from(reports.len()).map_err(|_| "chain has too many reports")?;
    let mut h = Sha256::new();
    h.update(CHAIN_TAG);
    h.update(digest32(chain.get("s0"), "chain.s0")?);
    h.update(n.to_be_bytes());
    for (i, r) in reports.iter().enumerate() {
        let s1 = r.get("s1");
        let t = s1
            .and_then(|s| s.get("t"))
            .and_then(Value::as_u64)
            .filter(|t| *t <= MAX_SAFE_INTEGER)
            .ok_or_else(|| format!("reports[{i}].s1.t is not a time in ms"))?;
        h.update(digest32(s1.and_then(|s| s.get("bundle")), &format!("reports[{i}].s1.bundle"))?);
        h.update(t.to_be_bytes());
        h.update(digest32(s1.and_then(|s| s.get("sig")), &format!("reports[{i}].s1.sig"))?);
        h.update(digest32(r.get("env"), &format!("reports[{i}].env"))?);
        match r.get("s2") {
            Some(s2) => h.update(digest32(s2.get("h"), &format!("reports[{i}].s2.h"))?),
            None => h.update([0u8; 32]),
        }
    }
    match chain.get("rcpt") {
        Some(_) => h.update(digest32(chain.get("rcpt"), "chain.rcpt")?),
        None => h.update([0u8; 32]),
    }
    Ok(h.finalize().into())
}

enum PubKey {
    Ed25519(ed25519_dalek::VerifyingKey),
    P256(p256::ecdsa::VerifyingKey),
}

fn pub_key(k: &Jwk) -> Result<PubKey, String> {
    let coord = |s: &str, name: &str| -> Result<[u8; 32], String> {
        b64(s)
            .map_err(|e| format!("key {:?} {name}: {e}", k.kid))?
            .try_into()
            .map_err(|_| format!("key {:?} {name} is not 32 bytes", k.kid))
    };
    match (k.kty.as_str(), k.crv.as_str()) {
        ("OKP", "Ed25519") => ed25519_dalek::VerifyingKey::from_bytes(&coord(&k.x, "x")?)
            .map(PubKey::Ed25519)
            .map_err(|e| format!("key {:?} is not an Ed25519 point: {e}", k.kid)),
        ("EC", "P-256") => {
            let y = k.y.as_deref().ok_or_else(|| format!("key {:?} has no y", k.kid))?;
            let mut sec1 = vec![0x04];
            sec1.extend_from_slice(&coord(&k.x, "x")?);
            sec1.extend_from_slice(&coord(y, "y")?);
            p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1)
                .map(PubKey::P256)
                .map_err(|_| format!("key {:?} is not a P-256 point", k.kid))
        }
        (kty, crv) => Err(format!("key {:?} has unsupported kty/crv {kty}/{crv}", k.kid)),
    }
}

/// The key named `kid` in `keys`, refusing duplicates and keys published for
/// another purpose (a challenge key must never verify a verdict).
fn find_key<'k>(keys: &'k [Jwk], kid: &str, purpose: &str) -> Result<&'k Jwk, String> {
    let mut it = keys.iter().filter(|k| k.kid == kid);
    let k = it.next().ok_or_else(|| format!("no published key has kid {kid:?}"))?;
    if it.next().is_some() {
        return Err(format!("more than one published key has kid {kid:?}"));
    }
    if let Some(p) = &k.purpose {
        if p != purpose {
            return Err(format!("key {kid:?} is published for {p:?}, not {purpose:?}"));
        }
    }
    Ok(k)
}

fn json_object(bytes: &[u8], what: &str) -> Result<Value, String> {
    let v: Value = serde_json::from_slice(bytes).map_err(|e| format!("{what} is not JSON: {e}"))?;
    if v.is_object() {
        Ok(v)
    } else {
        Err(format!("{what} is not a JSON object"))
    }
}

/// Check 1: the verdict JWS. Returns (version, claims, key) on success.
fn verify_jws<'k>(token: &str, keys: &'k [Jwk]) -> Result<(u8, Value, &'k Jwk), String> {
    let parts: Vec<&str> = token.trim().split('.').collect();
    let [h, p, s] = parts[..] else { return Err("not a compact JWS (three dot-separated parts)".into()) };
    let header = json_object(&b64(h).map_err(|e| format!("header {e}"))?, "header")?;
    let typ = header.get("typ").and_then(Value::as_str).unwrap_or_default();
    let version = VERDICT_TYPS
        .iter()
        .find(|(t, _)| *t == typ)
        .map(|(_, v)| *v)
        .ok_or_else(|| format!("typ {typ:?} is not octet-browser-verdict+jwt;v=1|2|3"))?;
    let kid = header.get("kid").and_then(Value::as_str).ok_or("header has no kid")?;
    let alg = header.get("alg").and_then(Value::as_str).ok_or("header has no alg")?;
    let key = find_key(keys, kid, VERDICT_PURPOSE)?;
    if key.alg.as_deref().is_some_and(|a| a != alg) {
        return Err(format!("header alg {alg} does not match key {kid:?} alg {}", key.alg.as_deref().unwrap_or("")));
    }
    let sig = b64(s).map_err(|e| format!("signature {e}"))?;
    let input = format!("{h}.{p}");
    // The alg must match the key type, so a token cannot pick a weaker check.
    let good = match (alg, pub_key(key)?) {
        ("EdDSA", PubKey::Ed25519(vk)) => {
            let sig = ed25519_dalek::Signature::from_slice(&sig).map_err(|_| "EdDSA signature is not 64 bytes")?;
            vk.verify_strict(input.as_bytes(), &sig).is_ok()
        }
        ("ES256", PubKey::P256(vk)) => {
            use p256::ecdsa::signature::Verifier;
            // JWS ES256 is IEEE P1363: raw r‖s, 64 bytes (not DER).
            let sig = p256::ecdsa::Signature::from_slice(&sig).map_err(|_| "ES256 signature is not 64-byte r‖s")?;
            vk.verify(input.as_bytes(), &sig).is_ok()
        }
        (alg, _) => return Err(format!("alg {alg} does not match the key type of {kid:?} ({}/{})", key.kty, key.crv)),
    };
    if !good {
        return Err(format!("{alg} signature does not verify under key {kid:?}"));
    }
    let claims = json_object(&b64(p).map_err(|e| format!("claims {e}"))?, "claims")?;
    let iss = claims.get("iss").and_then(Value::as_str).unwrap_or_default();
    if iss != VERDICT_ISS {
        return Err(format!("iss {iss:?} is not {VERDICT_ISS:?}"));
    }
    Ok((version, claims, key))
}

/// PASETO v4.public verify (PAE, Ed25519, footer `{"kid"}`, no implicit
/// assertion). Returns the claims and the footer kid.
fn verify_challenge(token: &str, keys: &[Jwk]) -> Result<(Value, String), String> {
    let rest = token.trim().strip_prefix(PASETO_HEADER).ok_or("challenge is not a v4.public PASETO")?;
    let (body, footer_b64) = rest.split_once('.').ok_or("challenge has no footer (the kid is required)")?;
    let body = b64(body).map_err(|e| format!("challenge body {e}"))?;
    let footer = b64(footer_b64).map_err(|e| format!("challenge footer {e}"))?;
    if body.len() < 64 {
        return Err("challenge body is shorter than a signature".into());
    }
    let (m, sig) = body.split_at(body.len() - 64);
    let kid = json_object(&footer, "challenge footer")?
        .get("kid")
        .and_then(Value::as_str)
        .ok_or("challenge footer has no kid")?
        .to_owned();
    let key = find_key(keys, &kid, CHALLENGE_PURPOSE)?;
    let PubKey::Ed25519(vk) = pub_key(key)? else {
        return Err(format!("challenge key {kid:?} is not Ed25519"));
    };
    let pae = pae(&[PASETO_HEADER.as_bytes(), m, &footer, b""]);
    let sig = ed25519_dalek::Signature::from_slice(sig).map_err(|_| "challenge signature is not 64 bytes")?;
    vk.verify_strict(&pae, &sig).map_err(|_| format!("challenge signature does not verify under key {kid:?}"))?;
    Ok((json_object(m, "challenge claims")?, kid))
}

/// PASETO Pre-Authentication Encoding: LE64(n) ‖ for each part: LE64(len) ‖ part.
fn pae(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = (parts.len() as u64).to_le_bytes().to_vec();
    for p in parts {
        out.extend_from_slice(&(p.len() as u64).to_le_bytes());
        out.extend_from_slice(p);
    }
    out
}

fn int(v: &Value, f: &str) -> Option<i64> {
    v.get(f).and_then(Value::as_i64)
}

/// Verify a browser verdict token and its chain. See the module docs.
pub fn verify_browser_verdict(inp: &BrowserVerdictInputs) -> BrowserReport {
    use BrowserStatus::*;
    let mut r = BrowserReport { checks: Vec::new(), claims: None, version: None, lid: None, manifest_seq: None };

    // 1. Verdict JWS: typ, alg/key match, signature, iss.
    let (version, claims, key) = match verify_jws(inp.verdict_token, inp.verdict_keys) {
        Ok(ok) => ok,
        Err(e) => {
            r.add("verdict-jws", Failed, e);
            for name in ["root-manifest", "manifest-verdict-key", "key-validity", "verdict-expiry", "chain-root",
                         "session-link", "manifest-challenge-key", "edge-link", "s1-device-signature", "anchor-receipts"] {
                r.add(name, NotChecked, "the verdict token did not verify");
            }
            return r;
        }
    };
    r.version = Some(version);
    r.add("verdict-jws", Verified, format!("typ v={version}, {} signature under key {:?}, iss {VERDICT_ISS}",
        key.alg.as_deref().unwrap_or(if key.kty == "EC" { "ES256" } else { "EdDSA" }), key.kid));
    let iat = int(&claims, "iat");

    // 1b. The root manifest, and the verdict key's listing in it.
    let manifest = check_manifest(&mut r, inp);
    let mut validity_key = key;
    let mut validity_src = "";
    match &manifest {
        None => r.add("manifest-verdict-key", NotChecked, "no verified root manifest"),
        Some(m) => match m.verdict_keys.iter().find(|k| k.kid == key.kid) {
            Some(entry) if same_key(entry, key) => {
                r.add("manifest-verdict-key", Verified, format!("key {:?} is listed in root manifest seq {}", key.kid, m.seq));
                validity_key = entry;
                validity_src = " (per the root-signed manifest)";
            }
            Some(_) => r.add("manifest-verdict-key", Failed, format!(
                "key {:?} is listed in the root manifest with DIFFERENT key material", key.kid)),
            None => r.add("manifest-verdict-key", Failed, format!(
                "key {:?} is not in root manifest seq {}: not a key octet's root vouches for", key.kid, m.seq)),
        },
    }
    let key = validity_key;

    // 1c. Archive key window and revocation.
    match (key.not_before, iat) {
        (None, _) if key.revoked_at.is_none() => r.add("key-validity", NotChecked, format!(
            "key {:?} publishes no signing window (octet_not_before); the archive JWKS carries one for a key that has it",
            key.kid)),
        (_, None) => r.add("key-validity", Failed, "verdict has no integer iat"),
        (nb, Some(iat)) => {
            let nb_ok = nb.is_none_or(|nb| iat >= nb - SKEW_S);
            let na_ok = key.not_after.is_none_or(|na| iat <= na + SKEW_S);
            let rev_ok = key.revoked_at.is_none_or(|ra| iat < ra);
            if !rev_ok {
                r.add("key-validity", Failed, format!("key {:?} was revoked at {} and the verdict was issued at {iat}", key.kid, key.revoked_at.unwrap_or_default()));
            } else if !(nb_ok && na_ok) {
                r.add("key-validity", Failed, format!("iat {iat} is outside key {:?}'s signing window {}..{} (±{SKEW_S} s)",
                    key.kid, nb.map_or("-".into(), |v| v.to_string()), key.not_after.map_or("now".into(), |v| v.to_string())));
            } else {
                r.add("key-validity", Verified, format!("iat {iat} lies in key {:?}'s signing window{}{validity_src}", key.kid,
                    if key.revoked_at.is_some() { ", before its revocation" } else { "" }));
            }
        }
    }

    // Expiry: a stored token is expected to be expired, so this never fails it.
    match (iat, int(&claims, "exp")) {
        (Some(iat), Some(exp)) if exp < iat => r.add("verdict-expiry", Failed, format!("exp {exp} is before iat {iat}")),
        (Some(_), Some(exp)) if inp.now_unix <= exp + SKEW_S => r.add("verdict-expiry", Verified, format!("unexpired (exp {exp})")),
        (Some(_), Some(exp)) => r.add("verdict-expiry", NotChecked, format!(
            "expired at {exp}: fine for a stored record, but refuse it for a live decision")),
        _ => r.add("verdict-expiry", Failed, "verdict has no integer iat/exp"),
    }

    // 2. Chain integrity (v=3).
    let chain = claims.get("chain");
    let mut chain_ok = false;
    if version < 3 {
        r.add("chain-root", NotChecked, format!("v={version} tokens carry no chain"));
    } else {
        match (chain, claims.get("chain_root").and_then(Value::as_str)) {
            (Some(c), Some(claimed)) => match (chain_root(c), b64(claimed)) {
                (Ok(root), Ok(claimed_bytes)) if claimed_bytes == root => {
                    chain_ok = true;
                    let n = c.get("reports").and_then(Value::as_array).map_or(0, Vec::len);
                    let rcpt = if c.get("rcpt").is_some() { "rcpt" } else { "no rcpt" };
                    r.add("chain-root", Verified, format!("chain_root recomputed over s0, {n} report(s) and {rcpt}"));
                }
                (Ok(root), _) => r.add("chain-root", Failed, format!(
                    "chain_root claim {claimed:?} does not match the recomputed {:?}", URL_SAFE_NO_PAD.encode(root))),
                (Err(e), _) => r.add("chain-root", Failed, format!("chain is malformed: {e}")),
            },
            _ => r.add("chain-root", Failed, "a v=3 token must carry chain and chain_root"),
        }
    }
    let chain = chain.filter(|_| chain_ok);
    let not_v3 = |r: &mut BrowserReport, name| r.add(name, NotChecked, if version < 3 {
        format!("v={version} tokens carry no chain")
    } else {
        "the chain did not verify".to_string()
    });

    // 3. Session link (challenge token).
    match (inp.challenge_token, chain) {
        (None, _) => r.add("session-link", NotChecked, "no challenge token supplied"),
        (Some(_), None) => not_v3(&mut r, "session-link"),
        (Some(ct), Some(chain)) => match session_link(ct, inp.challenge_keys, chain, &claims, iat) {
            Ok((lid, detail)) => {
                r.lid = Some(lid);
                r.add("session-link", Verified, detail);
            }
            Err((status, e)) => r.add("session-link", status, e),
        },
    }

    // 3b. The challenge key's listing in the root manifest.
    let challenge_kid = inp.challenge_token.and_then(challenge_kid);
    match (&manifest, r.status("session-link"), challenge_kid) {
        (None, _, _) => r.add("manifest-challenge-key", NotChecked, "no verified root manifest"),
        (Some(_), Some(Verified), Some(kid)) => {
            let used = inp.challenge_keys.and_then(|ks| ks.iter().find(|k| k.kid == kid));
            let m = manifest.as_ref().expect("checked above");
            match (used, m.challenge_keys.iter().find(|k| k.kid == kid)) {
                (Some(u), Some(e)) if same_key(u, e) => r.add("manifest-challenge-key", Verified,
                    format!("challenge key {kid:?} is listed in root manifest seq {}", m.seq)),
                (Some(_), Some(_)) => r.add("manifest-challenge-key", Failed,
                    format!("challenge key {kid:?} is listed in the root manifest with DIFFERENT key material")),
                _ => r.add("manifest-challenge-key", Failed,
                    format!("challenge key {kid:?} is not in root manifest seq {}", m.seq)),
            }
        }
        _ => r.add("manifest-challenge-key", NotChecked, "the session link did not verify"),
    }

    // 4. Edge link (edge log line).
    match (inp.edge_log, chain) {
        (None, _) => r.add("edge-link", NotChecked, "no edge log line supplied"),
        (Some(_), None) => not_v3(&mut r, "edge-link"),
        (Some(line), Some(chain)) => match edge_link(line, chain) {
            Ok(detail) => r.add("edge-link", Verified, detail),
            Err(e) => r.add("edge-link", Failed, e),
        },
    }

    // 5. Attested links: octet verified them; a third party cannot re-check.
    match chain {
        None => {
            not_v3(&mut r, "s1-device-signature");
            not_v3(&mut r, "anchor-receipts");
        }
        Some(c) => {
            let n = c.get("reports").and_then(Value::as_array).map_or(0, Vec::len);
            r.add("s1-device-signature", Attested, format!(
                "attested by octet: it verified the device signature over {n} report bundle(s); needs the device key to re-check"));
            if c.get("rcpt").is_some() {
                r.add("anchor-receipts", Attested,
                    "attested by octet: it verified the anchor receipts; they name the user's IP, so only their digest is published");
            } else {
                r.add("anchor-receipts", NotChecked, "the chain carries no anchor receipts");
            }
        }
    }

    r.claims = Some(claims);
    r
}

fn session_link(
    token: &str,
    keys: Option<&[Jwk]>,
    chain: &Value,
    claims: &Value,
    iat: Option<i64>,
) -> Result<(String, String), (BrowserStatus, String)> {
    use BrowserStatus::*;
    let fail = |e: String| (Failed, e);
    let s0 = digest32(chain.get("s0"), "chain.s0").map_err(fail)?;
    if sha256(token.trim().as_bytes()) != s0 {
        return Err(fail("SHA-256 of the challenge token does not equal chain.s0".into()));
    }
    let keys = keys.ok_or((NotChecked, "s0 matches, but no challenge JWKS was supplied to verify the challenge".to_string()))?;
    let (c, kid) = verify_challenge(token, keys).map_err(fail)?;
    if c.get("typ").and_then(Value::as_str) != Some(CHALLENGE_TYP) || c.get("v").and_then(Value::as_u64) != Some(1) {
        return Err(fail(format!("challenge claims are not typ {CHALLENGE_TYP:?} v=1")));
    }
    let want = claims.get("sessionRef").and_then(Value::as_str);
    let got = c.get("sessionRef").and_then(Value::as_str);
    if want.is_none() || got != want {
        return Err(fail(format!("challenge sessionRef {got:?} does not equal the verdict's {want:?}")));
    }
    let lid = c.get("lid").and_then(Value::as_str).ok_or_else(|| fail("challenge has no lid".into()))?.to_owned();
    let (Some(ci), Some(ce), Some(vi)) = (int(&c, "iat"), int(&c, "exp"), iat) else {
        return Err(fail("challenge or verdict has no integer iat/exp".into()));
    };
    if vi < ci || vi > ce + SKEW_S {
        return Err(fail(format!("verdict iat {vi} is outside [challenge iat {ci}, challenge exp {ce} + {SKEW_S} s]")));
    }
    Ok((lid.clone(), format!(
        "SHA-256(challenge) = s0; challenge signed by {kid:?}; sessionRef matches; lid {lid}; verdict iat within the challenge's life")))
}

/// The edge log line's JSON object. Accepts the line as the edge writes it,
/// with a log prefix such as Go's `2026/10/02 12:28:09 ` before the object, so
/// a partner can paste it straight from their logs.
fn edge_log_json(line: &str) -> Result<Value, String> {
    let line = line.trim();
    let start = line.find('{').ok_or("edge log line has no JSON object")?;
    serde_json::from_str(&line[start..]).map_err(|e| format!("edge log line is not JSON: {e}"))
}

fn edge_link(line: &str, chain: &Value) -> Result<String, String> {
    let v = edge_log_json(line)?;
    let o = v.get("octetChain").ok_or("edge log line has no octetChain object")?;
    let field = |f: &str| o.get(f).and_then(Value::as_str).ok_or_else(|| format!("octetChain has no {f}"));
    let (env, s2, kid) = (field("env")?, field("s2")?, field("kid")?);
    let reports = chain.get("reports").and_then(Value::as_array).ok_or("chain has no reports")?;
    let hit = reports.iter().position(|r| {
        r.get("env").and_then(Value::as_str) == Some(env)
            && r.get("s2").and_then(|s| s.get("h")).and_then(Value::as_str) == Some(s2)
            && r.get("s2").and_then(|s| s.get("kid")).and_then(Value::as_str) == Some(kid)
    });
    match hit {
        Some(i) => Ok(format!("edge log matches reports[{i}] (env, s2.h and kid {kid:?})")),
        None => Err("no report in the chain matches the edge log's env, s2 and kid".into()),
    }
}

/// The `root-manifest` check. Returns the manifest only when it can be trusted
/// (VERIFIED or WARN), so the key checks never lean on a FAILED one.
fn check_manifest(r: &mut BrowserReport, inp: &BrowserVerdictInputs) -> Option<Manifest> {
    use BrowserStatus::*;
    if inp.roots.is_empty() {
        r.add("root-manifest", NotChecked,
            "no pinned octet root to verify a manifest with");
        return None;
    }
    let Some(jws) = inp.manifest else {
        r.add("root-manifest", NotChecked, "no root manifest available");
        return None;
    };
    let m = match verify_manifest(jws, inp.roots) {
        Ok(m) => m,
        Err(e) => {
            r.add("root-manifest", Failed, e);
            return None;
        }
    };
    if let Some(min) = inp.min_manifest_seq.filter(|min| m.seq < *min) {
        r.add("root-manifest", Failed, format!("manifest seq {} is lower than {min} already seen: rollback", m.seq));
        return None;
    }
    r.manifest_seq = Some(m.seq);
    let now = inp.now_unix;
    let signed = format!("seq {} signed by pinned root {:?}", m.seq, m.root_kid);
    if now > m.exp + MANIFEST_GRACE_S {
        r.add("root-manifest", Failed, format!(
            "{signed} expired at {} and is past the 14-day grace: a stale key list (refused)", m.exp));
        return None;
    }
    if now > m.exp {
        r.add("root-manifest", Warning, format!("{signed} expired at {}; within the 14-day grace", m.exp));
    } else if now > m.exp - MANIFEST_WARN_BEFORE_S {
        r.add("root-manifest", Verified, format!("{signed}; expires soon, at {}", m.exp));
    } else {
        r.add("root-manifest", Verified, format!("{signed}; valid until {}", m.exp));
    }
    Some(m)
}

/// The `kid` in a PASETO challenge's footer, without verifying it.
fn challenge_kid(token: &str) -> Option<String> {
    let footer = token.trim().strip_prefix(PASETO_HEADER)?.split_once('.')?.1;
    let f: Value = serde_json::from_slice(&b64(footer).ok()?).ok()?;
    f.get("kid").and_then(Value::as_str).map(str::to_owned)
}
