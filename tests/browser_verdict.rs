//! Browser verdict profile against the shared golden vector
//! (`test-vectors/browser-verdict-chain/chain-vector.json`), plus negative cases
//! built from throwaway keys (a real verdict can't be re-signed).
#![cfg(feature = "browser")]

use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;
use octet_verify::browser::{chain_root, parse_jwks, verify_browser_verdict, BrowserStatus, BrowserVerdictInputs, Jwk};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use BrowserStatus::*;

fn vector() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/test-vectors/browser-verdict-chain/chain-vector.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn jwks(keys: &[&Value]) -> Vec<Jwk> {
    parse_jwks(&json!({ "keys": keys }).to_string()).unwrap()
}

fn sha(b: &[u8]) -> Vec<u8> {
    Sha256::digest(b).to_vec()
}

fn claims_of(token: &str) -> Value {
    serde_json::from_slice(&B64.decode(token.split('.').nth(1).unwrap()).unwrap()).unwrap()
}

struct Run<'a> {
    token: &'a str,
    vkeys: Vec<Jwk>,
    challenge: Option<&'a str>,
    ckeys: Option<Vec<Jwk>>,
    edge: Option<String>,
    now: i64,
}

impl Run<'_> {
    fn go(&self) -> octet_verify::browser::BrowserReport {
        verify_browser_verdict(&BrowserVerdictInputs {
            verdict_token: self.token,
            verdict_keys: &self.vkeys,
            challenge_token: self.challenge,
            challenge_keys: self.ckeys.as_deref(),
            edge_log: self.edge.as_deref(),
            now_unix: self.now, manifest: None, roots: &[], min_manifest_seq: None,
        })
    }
}

fn golden_run(v: &Value) -> Run<'_> {
    Run {
        token: v["verdictToken"].as_str().unwrap(),
        vkeys: jwks(&[&v["verdictJwk"]]),
        challenge: Some(v["challengeToken"].as_str().unwrap()),
        ckeys: Some(jwks(&[&v["challengeJwk"]])),
        edge: Some(json!({ "octetChain": v["edgeChainLog"] }).to_string()),
        now: claims_of(v["verdictToken"].as_str().unwrap())["iat"].as_i64().unwrap(),
    }
}

// --- the golden vector -------------------------------------------------------

#[test]
fn golden_vector_verifies_every_link() {
    let v = vector();
    let r = golden_run(&v).go();
    let st = |n| r.status(n).unwrap_or_else(|| panic!("no {n} check"));
    assert_eq!(st("verdict-jws"), Verified, "{:?}", r.checks);
    assert_eq!(st("chain-root"), Verified, "{:?}", r.checks);
    assert_eq!(st("session-link"), Verified, "{:?}", r.checks);
    assert_eq!(st("edge-link"), Verified, "{:?}", r.checks);
    assert_eq!(st("verdict-expiry"), Verified);
    assert_eq!(st("s1-device-signature"), Attested);
    assert_eq!(st("anchor-receipts"), Attested);
    // A live JWK carries no archive window.
    assert_eq!(st("key-validity"), NotChecked);
    assert!(r.is_valid());
    assert_eq!(r.version, Some(3));
    assert_eq!(r.lid.as_deref(), Some("27196c57-1a2b-42f9-819e-5327ae7a15d0"));
}

#[test]
fn golden_chain_root_matches_the_vector() {
    let v = vector();
    let root = chain_root(&v["chain"]).unwrap();
    assert_eq!(B64.encode(root), v["chain_root"].as_str().unwrap());
    // And the token's signed chain is the vector's chain.
    let c = claims_of(v["verdictToken"].as_str().unwrap());
    assert_eq!(c["chain"], v["chain"]);
    assert_eq!(c["chain_root"], v["chain_root"]);
}

/// Every chain digest rebuilds from the raw inputs exactly as octet-browser's
/// `buildChain` derives it. This pins the field definitions, not just the root.
#[test]
fn golden_chain_digests_rebuild_from_inputs() {
    let v = vector();
    let i = &v["inputs"];
    let c = &v["chain"];
    let rep = &c["reports"][0];
    let e = |b: &[u8]| B64.encode(sha(b));
    assert_eq!(e(v["challengeToken"].as_str().unwrap().as_bytes()), c["s0"]);
    assert_eq!(e(i["s1"]["bundleJson"].as_str().unwrap().as_bytes()), rep["s1"]["bundle"]);
    assert_eq!(e(&B64.decode(i["s1"]["sig"].as_str().unwrap()).unwrap()), rep["s1"]["sig"]);
    assert_eq!(i["s1"]["t"], rep["s1"]["t"]);
    assert_eq!(e(i["body"].as_str().unwrap().as_bytes()), rep["env"]);
    assert_eq!(e(i["s2Token"].as_str().unwrap().as_bytes()), rep["s2"]["h"]);
    let mut leaves: Vec<Vec<u8>> =
        i["receipts"].as_array().unwrap().iter().map(|t| sha(t.as_str().unwrap().as_bytes())).collect();
    leaves.sort();
    assert_eq!(e(&leaves.concat()), c["rcpt"]);
}

// --- golden-vector negatives ------------------------------------------------

#[test]
fn optional_links_are_not_checked_when_their_inputs_are_absent() {
    let v = vector();
    let mut run = golden_run(&v);
    run.challenge = None;
    run.edge = None;
    let r = run.go();
    assert_eq!(r.status("session-link"), Some(NotChecked));
    assert_eq!(r.status("edge-link"), Some(NotChecked));
    assert!(r.is_valid());
}

#[test]
fn wrong_challenge_fails_the_session_link() {
    let v = vector();
    let other = format!("{}x", v["challengeToken"].as_str().unwrap());
    let mut run = golden_run(&v);
    run.challenge = Some(&other);
    let r = run.go();
    assert_eq!(r.status("session-link"), Some(Failed));
    assert!(!r.is_valid());
}

#[test]
fn challenge_without_its_jwks_is_not_checked() {
    let v = vector();
    let mut run = golden_run(&v);
    run.ckeys = None;
    assert_eq!(run.go().status("session-link"), Some(NotChecked));
}

#[test]
fn challenge_key_cannot_verify_the_verdict() {
    // The challenge JWK is published for browser-challenge, so it must not be
    // accepted as a verdict key even under the verdict's kid.
    let v = vector();
    let mut k = v["challengeJwk"].clone();
    k["kid"] = v["verdictJwk"]["kid"].clone();
    let mut run = golden_run(&v);
    run.vkeys = jwks(&[&k]);
    let r = run.go();
    assert_eq!(r.status("verdict-jws"), Some(Failed));
    assert!(r.checks[0].detail.contains("browser-challenge"), "{}", r.checks[0].detail);
}

#[test]
fn edge_log_that_matches_no_report_fails() {
    let v = vector();
    let mut log = v["edgeChainLog"].clone();
    log["s2"] = json!(B64.encode([7u8; 32]));
    let mut run = golden_run(&v);
    run.edge = Some(json!({ "octetChain": log }).to_string());
    assert_eq!(run.go().status("edge-link"), Some(Failed));
    // Wrong kid alone also fails.
    let mut log = v["edgeChainLog"].clone();
    log["kid"] = json!("edge-other");
    run.edge = Some(json!({ "octetChain": log }).to_string());
    assert_eq!(run.go().status("edge-link"), Some(Failed));
}

#[test]
fn tampered_claims_fail_the_signature() {
    let v = vector();
    let t = v["verdictToken"].as_str().unwrap();
    let parts: Vec<&str> = t.split('.').collect();
    let mut c = claims_of(t);
    c["alarm"] = json!("high");
    let forged = format!("{}.{}.{}", parts[0], B64.encode(c.to_string()), parts[2]);
    let mut run = golden_run(&v);
    run.token = &forged;
    let r = run.go();
    assert_eq!(r.status("verdict-jws"), Some(Failed));
    assert!(r.claims.is_none(), "claims of an unverified token must not be exposed");
    assert_eq!(r.status("chain-root"), Some(NotChecked));
}

#[test]
fn stored_token_reports_expiry_without_failing() {
    let v = vector();
    let mut run = golden_run(&v);
    run.now += 10 * 365 * 86_400;
    let r = run.go();
    assert_eq!(r.status("verdict-expiry"), Some(NotChecked));
    assert!(r.is_valid());
}

// --- tokens signed with throwaway keys --------------------------------------

const ED_SEED: [u8; 32] = [0x42; 32];

fn ed_jwk(kid: &str, extra: Value) -> Value {
    let sk = ed25519_dalek::SigningKey::from_bytes(&ED_SEED);
    let mut k = json!({
        "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig", "kid": kid,
        "x": B64.encode(sk.verifying_key().as_bytes()), "octet_purpose": "browser-verdict",
    });
    k.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
    k
}

fn ed_token(header: Value, claims: Value) -> String {
    use ed25519_dalek::Signer;
    let input = format!("{}.{}", B64.encode(header.to_string()), B64.encode(claims.to_string()));
    let sig = ed25519_dalek::SigningKey::from_bytes(&ED_SEED).sign(input.as_bytes());
    format!("{input}.{}", B64.encode(sig.to_bytes()))
}

fn base_claims(v: &Value, iat: i64) -> Value {
    let mut c = claims_of(v["verdictToken"].as_str().unwrap());
    c["iat"] = json!(iat);
    c["exp"] = json!(iat + 300);
    c
}

fn run_own(token: &str, keys: Vec<Value>, now: i64) -> octet_verify::browser::BrowserReport {
    let keys = jwks(&keys.iter().collect::<Vec<_>>());
    verify_browser_verdict(&BrowserVerdictInputs {
        verdict_token: token,
        verdict_keys: &keys,
        challenge_token: None,
        challenge_keys: None,
        edge_log: None,
        now_unix: now, manifest: None, roots: &[], min_manifest_seq: None,
    })
}

const H: fn(&str) -> Value = |typ| json!({ "alg": "EdDSA", "typ": typ, "kid": "k1" });
const T: i64 = 1_790_935_202;

#[test]
fn all_three_claim_versions_verify_and_older_ones_carry_no_chain() {
    let v = vector();
    for (typ, ver) in [("octet-browser-verdict+jwt;v=1", 1), ("octet-browser-verdict+jwt;v=2", 2)] {
        let mut c = base_claims(&v, T);
        c.as_object_mut().unwrap().remove("chain");
        c.as_object_mut().unwrap().remove("chain_root");
        let r = run_own(&ed_token(H(typ), c), vec![ed_jwk("k1", json!({}))], T);
        assert_eq!(r.status("verdict-jws"), Some(Verified), "{:?}", r.checks);
        assert_eq!(r.version, Some(ver));
        assert_eq!(r.status("chain-root"), Some(NotChecked));
        assert!(r.is_valid());
    }
}

#[test]
fn wrong_typ_iss_and_alg_are_refused() {
    let v = vector();
    let keys = || vec![ed_jwk("k1", json!({}))];
    let c = base_claims(&v, T);
    let r = run_own(&ed_token(H("octet-browser-verdict+jwt;v=5"), c.clone()), keys(), T);
    assert_eq!(r.status("verdict-jws"), Some(Failed));
    // v=4 is known, but a v=3 claim set under it lacks stage and revision.
    let r = run_own(&ed_token(H("octet-browser-verdict+jwt;v=4"), c.clone()), keys(), T);
    assert_eq!((r.status("verdict-jws"), r.status("verdict-stage")), (Some(Verified), Some(Failed)));
    let r = run_own(&ed_token(H("JWT"), c.clone()), keys(), T);
    assert_eq!(r.status("verdict-jws"), Some(Failed));

    let mut bad_iss = c.clone();
    bad_iss["iss"] = json!("someone-else");
    let r = run_own(&ed_token(H("octet-browser-verdict+jwt;v=3"), bad_iss), keys(), T);
    assert_eq!(r.status("verdict-jws"), Some(Failed));

    // alg ES256 on an Ed25519 key: refused, never downgraded to a weaker check.
    let h = json!({ "alg": "ES256", "typ": "octet-browser-verdict+jwt;v=3", "kid": "k1" });
    let mut key = ed_jwk("k1", json!({}));
    key.as_object_mut().unwrap().remove("alg");
    let r = run_own(&ed_token(h, c.clone()), vec![key], T);
    assert_eq!(r.status("verdict-jws"), Some(Failed));
    let h = json!({ "alg": "none", "typ": "octet-browser-verdict+jwt;v=3", "kid": "k1" });
    let r = run_own(&ed_token(h, c), keys(), T);
    assert_eq!(r.status("verdict-jws"), Some(Failed));
}

#[test]
fn v3_without_a_chain_fails_and_a_mismatched_root_fails() {
    let v = vector();
    let keys = || vec![ed_jwk("k1", json!({}))];
    let mut c = base_claims(&v, T);
    c.as_object_mut().unwrap().remove("chain_root");
    let r = run_own(&ed_token(H("octet-browser-verdict+jwt;v=3"), c), keys(), T);
    assert_eq!(r.status("chain-root"), Some(Failed));

    // A signed chain whose root claim doesn't match it.
    let mut c = base_claims(&v, T);
    c["chain"]["reports"][0]["s1"]["t"] = json!(1_790_935_201_201u64);
    let r = run_own(&ed_token(H("octet-browser-verdict+jwt;v=3"), c), keys(), T);
    assert_eq!(r.status("chain-root"), Some(Failed));
    assert_eq!(r.status("s1-device-signature"), Some(NotChecked));
}

#[test]
fn archive_window_and_revocation() {
    let v = vector();
    let tok = |iat| ed_token(H("octet-browser-verdict+jwt;v=3"), base_claims(&v, iat));
    let win = json!({ "octet_not_before": T - 1000, "octet_not_after": T + 1000 });
    // Inside the window.
    assert_eq!(run_own(&tok(T), vec![ed_jwk("k1", win.clone())], T).status("key-validity"), Some(Verified));
    // Within the 60 s tolerance at either edge.
    assert_eq!(run_own(&tok(T - 1059), vec![ed_jwk("k1", win.clone())], T).status("key-validity"), Some(Verified));
    assert_eq!(run_own(&tok(T + 1059), vec![ed_jwk("k1", win.clone())], T).status("key-validity"), Some(Verified));
    // Outside it.
    assert_eq!(run_own(&tok(T - 1061), vec![ed_jwk("k1", win.clone())], T).status("key-validity"), Some(Failed));
    assert_eq!(run_own(&tok(T + 1061), vec![ed_jwk("k1", win)], T).status("key-validity"), Some(Failed));
    // Current archive key: no not_after.
    let cur = json!({ "octet_not_before": T - 1000 });
    assert_eq!(run_own(&tok(T + 99_999), vec![ed_jwk("k1", cur)], T).status("key-validity"), Some(Verified));
    // Revoked: tokens issued before revocation keep verifying; at/after it fail.
    let rev = json!({ "octet_not_before": T - 1000, "octet_status": "revoked", "octet_revoked_at": T });
    assert_eq!(run_own(&tok(T - 1), vec![ed_jwk("k1", rev.clone())], T).status("key-validity"), Some(Verified));
    let r = run_own(&tok(T), vec![ed_jwk("k1", rev)], T);
    assert_eq!(r.status("key-validity"), Some(Failed));
    assert!(!r.is_valid());
}

#[test]
fn malformed_archive_revocation_is_rejected_at_parse() {
    let k = ed_jwk("k1", json!({ "octet_status": "revoked" }));
    assert!(parse_jwks(&json!({ "keys": [k] }).to_string()).is_err());
}

#[test]
fn duplicate_kid_is_refused() {
    let v = vector();
    let t = ed_token(H("octet-browser-verdict+jwt;v=3"), base_claims(&v, T));
    let r = run_own(&t, vec![ed_jwk("k1", json!({})), ed_jwk("k1", json!({}))], T);
    assert_eq!(r.status("verdict-jws"), Some(Failed));
}

#[test]
fn es256_p1363_verifies_and_der_is_refused() {
    use p256::ecdsa::{signature::Signer, Signature, SigningKey};
    let v = vector();
    let sk = SigningKey::from_slice(&[0x11; 32]).unwrap();
    let pt = sk.verifying_key().to_encoded_point(false);
    let key = json!({
        "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": "kms-1",
        "x": B64.encode(pt.x().unwrap()), "y": B64.encode(pt.y().unwrap()), "octet_purpose": "browser-verdict",
    });
    let h = json!({ "alg": "ES256", "typ": "octet-browser-verdict+jwt;v=3", "kid": "kms-1" });
    let input = format!("{}.{}", B64.encode(h.to_string()), B64.encode(base_claims(&v, T).to_string()));
    let sig: Signature = sk.sign(input.as_bytes());

    let p1363 = format!("{input}.{}", B64.encode(sig.to_bytes()));
    let r = run_own(&p1363, vec![key.clone()], T);
    assert_eq!(r.status("verdict-jws"), Some(Verified), "{:?}", r.checks);
    assert_eq!(r.status("chain-root"), Some(Verified));

    let der = format!("{input}.{}", B64.encode(sig.to_der().as_bytes()));
    assert_eq!(run_own(&der, vec![key.clone()], T).status("verdict-jws"), Some(Failed));

    // EdDSA header against the EC key: refused.
    let h2 = json!({ "alg": "EdDSA", "typ": "octet-browser-verdict+jwt;v=3", "kid": "kms-1" });
    let mut k2 = key;
    k2.as_object_mut().unwrap().remove("alg");
    let t2 = ed_token(h2, base_claims(&v, T));
    assert_eq!(run_own(&t2, vec![k2], T).status("verdict-jws"), Some(Failed));
}

/// A PASETO v4.public challenge signed with a throwaway key, then a v=3 verdict
/// whose chain.s0 commits to it: the session link verifies, and each claim rule
/// (typ/v, sessionRef, the verdict iat window) fails it when broken.
#[test]
fn session_link_claim_rules() {
    use ed25519_dalek::Signer;
    let v = vector();
    let csk = ed25519_dalek::SigningKey::from_bytes(&[0x24; 32]);
    let ckey = json!({
        "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "kid": "ch-1",
        "x": B64.encode(csk.verifying_key().as_bytes()), "octet_purpose": "browser-challenge",
    });
    let paseto = |claims: Value| {
        let m = claims.to_string().into_bytes();
        let f = br#"{"kid":"ch-1"}"#.to_vec();
        let mut pae = 4u64.to_le_bytes().to_vec();
        for p in [b"v4.public.".as_slice(), &m, &f, b""] {
            pae.extend_from_slice(&(p.len() as u64).to_le_bytes());
            pae.extend_from_slice(p);
        }
        let sig = csk.sign(&pae).to_bytes();
        format!("v4.public.{}.{}", B64.encode([m, sig.to_vec()].concat()), B64.encode(f))
    };
    let challenge = |over: Value| {
        let mut c = json!({ "v": 1, "typ": "octet-browser-challenge", "nonce": "n", "lid": "lid-1",
                            "sessionRef": "ref-chain-vector", "iat": T - 10, "exp": T + 590 });
        c.as_object_mut().unwrap().extend(over.as_object().unwrap().clone());
        paseto(c)
    };
    let verdict_for = |ch: &str, iat: i64| {
        let mut c = base_claims(&v, iat);
        c["chain"]["s0"] = json!(B64.encode(sha(ch.as_bytes())));
        c["chain_root"] = json!(B64.encode(chain_root(&c["chain"]).unwrap()));
        ed_token(H("octet-browser-verdict+jwt;v=3"), c)
    };
    let check = |ch: &str, iat: i64| {
        let tok = verdict_for(ch, iat);
        let vk = jwks(&[&ed_jwk("k1", json!({}))]);
        let ck = jwks(&[&ckey]);
        let r = verify_browser_verdict(&BrowserVerdictInputs {
            verdict_token: &tok, verdict_keys: &vk, challenge_token: Some(ch),
            challenge_keys: Some(&ck), edge_log: None, now_unix: iat, manifest: None, roots: &[], min_manifest_seq: None,
        });
        (r.status("session-link").unwrap(), r.lid.clone(), r.checks.iter().find(|c| c.name == "session-link").unwrap().detail.clone())
    };

    let good = challenge(json!({}));
    let (s, lid, d) = check(&good, T);
    assert_eq!(s, Verified, "{d}");
    assert_eq!(lid.as_deref(), Some("lid-1"));
    // Verdict iat at the window edges: challenge iat, and challenge exp + 60 s.
    assert_eq!(check(&good, T - 10).0, Verified);
    assert_eq!(check(&good, T + 650).0, Verified);
    assert_eq!(check(&good, T - 11).0, Failed);
    assert_eq!(check(&good, T + 651).0, Failed);
    // Claim rules.
    assert_eq!(check(&challenge(json!({ "sessionRef": "someone-else" })), T).0, Failed);
    assert_eq!(check(&challenge(json!({ "typ": "octet-browser-verdict" })), T).0, Failed);
    assert_eq!(check(&challenge(json!({ "v": 2 })), T).0, Failed);
    // A challenge signed under a verdict-purpose key is refused.
    let mut wrong = ckey.clone();
    wrong["octet_purpose"] = json!("browser-verdict");
    let tok = verdict_for(&good, T);
    let vk = jwks(&[&ed_jwk("k1", json!({}))]);
    let ck = jwks(&[&wrong]);
    let r = verify_browser_verdict(&BrowserVerdictInputs {
        verdict_token: &tok, verdict_keys: &vk, challenge_token: Some(&good),
        challenge_keys: Some(&ck), edge_log: None, now_unix: T, manifest: None, roots: &[], min_manifest_seq: None,
    });
    assert_eq!(r.status("session-link"), Some(Failed));
}

// --- the real dev vector (octet-dev, full path: S0, S1 sealed, S2 edge-signed) ---

fn dev_vector() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/test-vectors/browser-verdict-chain/dev-vector.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn dev_run(d: &Value, keys: &str, edge: &str) -> octet_verify::browser::BrowserReport {
    let vk = parse_jwks(&d[keys].to_string()).unwrap();
    let ck = parse_jwks(&d["challengeJwks"].to_string()).unwrap();
    verify_browser_verdict(&BrowserVerdictInputs {
        verdict_token: d["token"].as_str().unwrap(),
        verdict_keys: &vk,
        challenge_token: Some(d["challenge"].as_str().unwrap()),
        challenge_keys: Some(&ck),
        edge_log: Some(d[edge].as_str().unwrap()),
        // The token lives 5 minutes; the vector pins the check time.
        now_unix: d["nowForChecks"].as_i64().unwrap(), manifest: None, roots: &[], min_manifest_seq: None,
    })
}

/// A real verdict from the dev stack verifies end to end, against the live
/// key list and the archive, with the edge log line either raw (with Go's
/// timestamp prefix, as partners copy it from their logs) or as bare JSON.
#[test]
fn dev_vector_verifies_every_link() {
    let d = dev_vector();
    for keys in ["verdictJwks", "verdictJwksArchive"] {
        for edge in ["edgeLogLine", "edgeLogJson"] {
            let r = dev_run(&d, keys, edge);
            let st = |n| r.status(n).unwrap_or_else(|| panic!("no {n} check"));
            assert_eq!(st("verdict-jws"), Verified, "{keys}/{edge}: {:?}", r.checks);
            assert_eq!(st("chain-root"), Verified, "{keys}/{edge}: {:?}", r.checks);
            assert_eq!(st("session-link"), Verified, "{keys}/{edge}: {:?}", r.checks);
            assert_eq!(st("edge-link"), Verified, "{keys}/{edge}: {:?}", r.checks);
            assert_eq!(st("verdict-expiry"), Verified);
            assert_eq!(st("s1-device-signature"), Attested);
            // expect.rcpt is false: this session had no anchor receipts.
            assert_eq!(st("anchor-receipts"), NotChecked);
            assert!(r.is_valid(), "{keys}/{edge}");
            assert_eq!(r.version, Some(3));
            assert_eq!(r.lid.as_deref(), d["lid"].as_str());
            assert_eq!(r.client_net_match(), Some(true));
        }
    }
}

#[test]
fn dev_vector_matches_its_expected_values() {
    let d = dev_vector();
    let token = d["token"].as_str().unwrap();
    let header: Value = serde_json::from_slice(&B64.decode(token.split('.').next().unwrap()).unwrap()).unwrap();
    let e = &d["expect"];
    assert_eq!(header["alg"], e["alg"]);
    assert_eq!(header["typ"], e["typ"]);
    let c = claims_of(token);
    assert_eq!(B64.encode(chain_root(&c["chain"]).unwrap()), e["chain_root"].as_str().unwrap());
    assert_eq!(c["chain"]["reports"].as_array().unwrap().len() as u64, e["reports"].as_u64().unwrap());
    assert_eq!(c["chain"].get("rcpt").is_some(), e["rcpt"].as_bool().unwrap());
    assert_eq!(c["sessionRef"], d["sessionRef"]);
    // Built under the v=3 rules: no clientNet; clientNetMatch from a loopback clientIp.
    assert!(c.get("clientNet").is_none(), "v=3 carries no clientNet");
    assert_eq!(c["clientNetMatch"], e["clientNetMatch"]);
    // The verdict fields beside the token are the signed ones.
    for f in ["country", "confidence", "alarm", "deviceKey"] {
        assert_eq!(c[f], d["verdictResponse"][f], "{f}");
    }
}

/// The edge log parser takes the raw line or the JSON alone, and a raw line for
/// another session's report still fails the link.
#[test]
fn dev_vector_edge_log_forms() {
    let d = dev_vector();
    let raw = d["edgeLogLine"].as_str().unwrap();
    assert!(!raw.starts_with('{'), "the raw line carries the edge's log prefix");
    let mut other = d.clone();
    // Swap the env digest for another valid-looking one.
    let env = serde_json::from_str::<Value>(d["edgeLogJson"].as_str().unwrap()).unwrap()["octetChain"]["env"]
        .as_str().unwrap().to_string();
    other["edgeLogLine"] = json!(raw.replace(&env, &B64.encode([9u8; 32])));
    assert_eq!(dev_run(&other, "verdictJwks", "edgeLogLine").status("edge-link"), Some(Failed));
    // No JSON object at all.
    other["edgeLogLine"] = json!("2026/10/02 12:28:09 nothing here");
    assert_eq!(dev_run(&other, "verdictJwks", "edgeLogLine").status("edge-link"), Some(Failed));
}

/// Past the 5-minute life the same token is a stored record: expiry is
/// reported NOT-CHECKED, and everything else still verifies.
#[test]
fn dev_vector_as_a_stored_record() {
    let mut d = dev_vector();
    d["nowForChecks"] = json!(d["nowForChecks"].as_i64().unwrap() + 86_400);
    let r = dev_run(&d, "verdictJwksArchive", "edgeLogLine");
    assert_eq!(r.status("verdict-expiry"), Some(NotChecked));
    assert!(r.is_valid());
}

// --- root manifest ------------------------------------------------------------

use octet_verify::browser::{parse_roots, verify_manifest};

fn manifest_vector() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/test-vectors/browser-verdict-chain/manifest-vector.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn vector_roots(mv: &Value) -> Vec<Jwk> {
    parse_roots(&json!({ "roots": [mv["root"]] }).to_string()).unwrap()
}

/// The dev-stack verdict, checked with the root manifest that lists its keys.
fn dev_with_manifest(jws: &str, roots: &[Jwk], now: i64, min_seq: Option<u64>) -> octet_verify::browser::BrowserReport {
    let d = dev_vector();
    let vk = parse_jwks(&d["verdictJwksArchive"].to_string()).unwrap();
    let ck = parse_jwks(&d["challengeJwks"].to_string()).unwrap();
    verify_browser_verdict(&BrowserVerdictInputs {
        verdict_token: d["token"].as_str().unwrap(),
        verdict_keys: &vk,
        challenge_token: Some(d["challenge"].as_str().unwrap()),
        challenge_keys: Some(&ck),
        edge_log: Some(d["edgeLogLine"].as_str().unwrap()),
        now_unix: now,
        manifest: Some(jws),
        roots,
        min_manifest_seq: min_seq,
    })
}

#[test]
fn manifest_vector_verifies_with_its_root() {
    let mv = manifest_vector();
    let m = verify_manifest(mv["jws"].as_str().unwrap(), &vector_roots(&mv)).unwrap();
    let e = &mv["expect"];
    assert_eq!(m.seq, e["seq"].as_u64().unwrap());
    assert_eq!((m.iat, m.exp), (e["iat"].as_i64().unwrap(), e["exp"].as_i64().unwrap()));
    assert_eq!(m.root_kid, e["header"]["kid"].as_str().unwrap());
    // The payload is the manifest bytes exactly.
    let payload = B64.decode(mv["jws"].as_str().unwrap().split('.').nth(1).unwrap()).unwrap();
    assert_eq!(payload, mv["manifestJson"].as_str().unwrap().as_bytes());
    assert_eq!(m.roots, vec!["root-dev-1".to_string()]);
}

/// The dev verdict + the manifest: every key is root-vouched, and key-validity
/// now runs (from the manifest entry) instead of reading NOT-CHECKED.
#[test]
fn manifest_lists_the_dev_keys_and_drives_key_validity() {
    let mv = manifest_vector();
    let r = dev_with_manifest(mv["jws"].as_str().unwrap(), &vector_roots(&mv), mv["expect"]["nowOk"].as_i64().unwrap(), None);
    let st = |n| r.status(n).unwrap_or_else(|| panic!("no {n} check"));
    assert_eq!(st("root-manifest"), Verified, "{:?}", r.checks);
    assert_eq!(st("manifest-verdict-key"), Verified);
    assert_eq!(st("manifest-challenge-key"), Verified);
    assert_eq!(st("key-validity"), Verified, "{:?}", r.checks);
    assert!(r.checks.iter().any(|c| c.name == "key-validity" && c.detail.contains("root-signed manifest")));
    assert_eq!(r.manifest_seq, Some(1));
    assert!(r.is_valid());
}

#[test]
fn manifest_expiry_windows() {
    let mv = manifest_vector();
    let (jws, roots, e) = (mv["jws"].as_str().unwrap(), vector_roots(&mv), &mv["expect"]);
    let at = |k: &str| dev_with_manifest(jws, &roots, e[k].as_i64().unwrap(), None);
    let detail = |r: &octet_verify::browser::BrowserReport| r.checks.iter().find(|c| c.name == "root-manifest").unwrap().detail.clone();

    let r = at("nowExpiring");
    assert_eq!(r.status("root-manifest"), Some(Verified));
    assert!(detail(&r).contains("expires soon"), "{}", detail(&r));

    let r = at("nowExpired");
    assert_eq!(r.status("root-manifest"), Some(Warning));
    assert_eq!(r.status("manifest-verdict-key"), Some(Verified), "a manifest in grace still vouches");
    assert!(r.is_valid(), "a WARN does not reject");

    // Past the 14-day grace: a stale key list, refused (freeze-attack bound).
    let r = at("nowRefused");
    assert_eq!(r.status("root-manifest"), Some(Failed), "{}", detail(&r));
    assert_eq!(r.status("manifest-verdict-key"), Some(NotChecked));
    assert!(!r.is_valid());
}

#[test]
fn manifest_rollback_and_absence() {
    let mv = manifest_vector();
    let (jws, roots) = (mv["jws"].as_str().unwrap(), vector_roots(&mv));
    let now = mv["expect"]["nowOk"].as_i64().unwrap();
    // Equal seq is fine; a lower one is a rollback.
    assert_eq!(dev_with_manifest(jws, &roots, now, Some(1)).status("root-manifest"), Some(Verified));
    let r = dev_with_manifest(jws, &roots, now, Some(2));
    assert_eq!(r.status("root-manifest"), Some(Failed));
    assert_eq!(r.manifest_seq, None, "a rolled-back seq is not reported for persisting");
    // No pinned root, or no manifest: NOT-CHECKED, and the old behaviour holds.
    let r = dev_with_manifest(jws, &[], now, None);
    assert_eq!(r.status("root-manifest"), Some(NotChecked));
    assert_eq!(r.status("manifest-verdict-key"), Some(NotChecked));
    assert_eq!(r.status("key-validity"), Some(NotChecked));
    assert!(r.is_valid());
}

// --- production roots (first root ceremony, 2026-10-12) -----------------------

/// The production seq 1 manifest exactly as committed in octet-browser
/// (`keys/octet-browser-manifest.json.jws`, trailing newline included).
const PROD_MANIFEST: &str = include_str!("../test-vectors/browser-verdict-chain/prod-manifest-seq1.json.jws");
const ROOT_A: &str = "octet-root-a-2026-10";
const ROOT_B: &str = "octet-root-b-2026-10";

fn pinned() -> Vec<Jwk> {
    parse_roots(octet_verify::browser::PINNED_ROOTS_JSON).unwrap()
}

#[test]
fn pinned_roots_are_the_ceremony_keys() {
    let roots = pinned();
    let kids: Vec<&str> = roots.iter().map(|r| r.kid.as_str()).collect();
    assert_eq!(kids, [ROOT_A, ROOT_B]);
    // The public keys attested by Yubico on each root's YubiKey.
    assert_eq!(roots[0].x, "-TTm69g0eOIcWb-I9gVwsZCsSNTSPJIjmuJQetUVO7o");
    assert_eq!(roots[0].y.as_deref(), Some("SfDnpa7Jtnw8FDYvcPnZUJZN8D2wQSztUMlucUHyM6A"));
    assert_eq!(roots[1].x, "Nl3Zsqh92UZPPCVGqpQYPP-pZoKI7_YNhGG4qaS4qM8");
    assert_eq!(roots[1].y.as_deref(), Some("6MdPuYVrKIeDV4_gSDfqL5EnABIwXSyjo8-gd3i9TtM"));
    assert!(roots.iter().all(|r| r.purpose.as_deref() == Some("octet-root")));
}

#[test]
fn prod_manifest_verifies_with_the_pinned_roots() {
    let hex = |b: &[u8]| hex::encode(b);
    // The bytes are the ones octet-browser recorded at the ceremony.
    assert_eq!(hex(&Sha256::digest(PROD_MANIFEST)), "98c9f12c2ed1f81b2d032e3376a96c6e255aa4608ea32fb0ad252f72216bce41");
    assert_eq!(hex(&Sha256::digest(PROD_MANIFEST.trim_end())), "a3dd8c373876d55edaf163d44da520863f43a76163dc8d23bc870950342c2dcb");

    let m = verify_manifest(PROD_MANIFEST, &pinned()).unwrap();
    assert_eq!(m.seq, 1);
    assert_eq!(m.root_kid, ROOT_A);
    assert_eq!((m.iat, m.exp), (1_791_798_127, 1_823_334_127)); // 2026-10-12 .. 2027-10-12
    assert_eq!(m.roots, [ROOT_A, ROOT_B]);
    let kids = |k: &[Jwk]| k.iter().map(|j| j.kid.clone()).collect::<Vec<_>>();
    assert_eq!(kids(&m.verdict_keys), ["octet-browser-verdict-2026-09"]);
    assert_eq!(kids(&m.challenge_keys), ["octet-browser-challenge-2026-10"]);
    assert_eq!(m.verdict_keys[0].not_before, Some(1_790_696_802));
}

#[test]
fn prod_manifest_needs_root_a_and_the_exact_bytes() {
    let roots = pinned();
    // Root B alone cannot stand in for root A.
    let only_b: Vec<Jwk> = roots.iter().filter(|r| r.kid == ROOT_B).cloned().collect();
    assert!(verify_manifest(PROD_MANIFEST, &only_b).unwrap_err().contains("not a pinned root"));
    // A changed payload or signature does not verify.
    let parts: Vec<&str> = PROD_MANIFEST.trim().split('.').collect();
    let mut payload = B64.decode(parts[1]).unwrap();
    let kid = b"octet-browser-verdict-2026-09";
    let at = payload.windows(kid.len()).position(|w| w == kid).unwrap() + kid.len() - 1;
    payload[at] = b'8';
    let forged = format!("{}.{}.{}", parts[0], B64.encode(&payload), parts[2]);
    assert!(verify_manifest(&forged, &roots).unwrap_err().contains("does not verify"));
    let mut sig = B64.decode(parts[2]).unwrap();
    sig[10] ^= 1;
    let forged = format!("{}.{}.{}", parts[0], parts[1], B64.encode(&sig));
    assert!(verify_manifest(&forged, &roots).is_err());
    // The dev manifest is not signed by a production root.
    assert!(verify_manifest(manifest_vector()["jws"].as_str().unwrap(), &roots).is_err());
}

/// Production pins refuse a dev-stack verdict: its key is not in the manifest.
#[test]
fn prod_manifest_refuses_the_dev_verdict_key() {
    let r = dev_with_manifest(PROD_MANIFEST, &pinned(), 1_791_798_127 + 86_400, None);
    assert_eq!(r.status("root-manifest"), Some(Verified), "{:?}", r.checks);
    assert_eq!(r.status("manifest-verdict-key"), Some(Failed));
    assert_eq!(r.manifest_seq, Some(1));
    assert!(!r.is_valid());
}

// Manifests signed with a throwaway root, for the negatives.

const OWN_ROOT_SEED: [u8; 32] = [0x77; 32];

fn own_root(kid: &str) -> Value {
    let sk = p256::ecdsa::SigningKey::from_slice(&OWN_ROOT_SEED).unwrap();
    let pt = sk.verifying_key().to_encoded_point(false);
    json!({ "kty": "EC", "crv": "P-256", "kid": kid, "x": B64.encode(pt.x().unwrap()),
            "y": B64.encode(pt.y().unwrap()), "octet_purpose": "octet-root" })
}

fn sign_manifest(header: Value, manifest: &Value, der: bool) -> String {
    use p256::ecdsa::{signature::Signer, Signature};
    let input = format!("{}.{}", B64.encode(header.to_string()), B64.encode(manifest.to_string()));
    let sig: Signature = p256::ecdsa::SigningKey::from_slice(&OWN_ROOT_SEED).unwrap().sign(input.as_bytes());
    let sig = if der { sig.to_der().as_bytes().to_vec() } else { sig.to_bytes().to_vec() };
    format!("{input}.{}", B64.encode(sig))
}

fn dev_manifest() -> Value {
    let mut m: Value = serde_json::from_str(manifest_vector()["manifestJson"].as_str().unwrap()).unwrap();
    m["roots"] = json!(["own-root"]);
    m
}

const ROOT_HDR: fn() -> Value = || json!({ "alg": "ES256", "typ": "octet-root+jws;v=1", "kid": "own-root" });

fn own(m: &Value) -> String {
    sign_manifest(ROOT_HDR(), m, false)
}

fn own_roots() -> Vec<Jwk> {
    parse_roots(&json!({ "roots": [own_root("own-root")] }).to_string()).unwrap()
}

#[test]
fn manifest_header_and_payload_rules() {
    let roots = own_roots();
    let m = dev_manifest();
    assert!(verify_manifest(&own(&m), &roots).is_ok());

    // Only alg/typ/kid in the header.
    let mut h = ROOT_HDR();
    h["x5c"] = json!(["x"]);
    assert!(verify_manifest(&sign_manifest(h, &m, false), &roots).unwrap_err().contains("unexpected field"));
    let mut h = ROOT_HDR();
    h["typ"] = json!("JWT");
    assert!(verify_manifest(&sign_manifest(h, &m, false), &roots).is_err());
    // A DER signature (as the YubiKey writes it) must be converted to r‖s.
    assert!(verify_manifest(&sign_manifest(ROOT_HDR(), &m, true), &roots).is_err());
    // An unpinned root, even one the manifest itself names.
    let mut h = ROOT_HDR();
    h["kid"] = json!("someone-else");
    assert!(verify_manifest(&sign_manifest(h, &m, false), &roots).unwrap_err().contains("not a pinned root"));
    // Payload rules.
    for (field, bad) in [("typ", json!("other")), ("v", json!(2)), ("seq", json!(0)), ("roots", json!([]))] {
        let mut b = m.clone();
        b[field] = bad;
        assert!(verify_manifest(&own(&b), &roots).is_err(), "{field}");
    }
    let mut long = m.clone();
    long["exp"] = json!(m["iat"].as_i64().unwrap() + 401 * 86_400);
    assert!(verify_manifest(&own(&long), &roots).unwrap_err().contains("400 days"));
    // A root file entry published for another purpose is refused.
    let mut wrong = own_root("own-root");
    wrong["octet_purpose"] = json!("browser-verdict");
    assert!(parse_roots(&json!({ "roots": [wrong] }).to_string()).is_err());
}

#[test]
fn keys_must_be_listed_with_the_same_material() {
    let roots = own_roots();
    let now = manifest_vector()["expect"]["nowOk"].as_i64().unwrap();

    // Verdict key missing from the manifest.
    let mut m = dev_manifest();
    m["verdictKeys"] = json!([]);
    let r = dev_with_manifest(&own(&m), &roots, now, None);
    assert_eq!(r.status("manifest-verdict-key"), Some(Failed));
    assert!(!r.is_valid());

    // Same kid, different key material: a substituted key.
    let mut m = dev_manifest();
    m["verdictKeys"][0]["x"] = json!(B64.encode([1u8; 32]));
    assert_eq!(dev_with_manifest(&own(&m), &roots, now, None).status("manifest-verdict-key"), Some(Failed));

    // Challenge key missing.
    let mut m = dev_manifest();
    m["challengeKeys"] = json!([]);
    let r = dev_with_manifest(&own(&m), &roots, now, None);
    assert_eq!(r.status("manifest-challenge-key"), Some(Failed));
    assert_eq!(r.status("manifest-verdict-key"), Some(Verified));

    // The manifest's validity fields win: revoked before the token's iat.
    let iat = claims_of(dev_vector()["token"].as_str().unwrap())["iat"].as_i64().unwrap();
    let mut m = dev_manifest();
    m["verdictKeys"][0]["octet_status"] = json!("revoked");
    m["verdictKeys"][0]["octet_revoked_at"] = json!(iat - 1);
    assert_eq!(dev_with_manifest(&own(&m), &roots, now, None).status("key-validity"), Some(Failed));
}

/// clientNetMatch is reported as signed: false is a result, not a failure, and
/// a token without it reports None. A challenge's opaque `cn` claim is ignored.
#[test]
fn client_net_match_is_reported_as_signed() {
    let v = vector();
    for (val, want) in [(Some(true), Some(true)), (Some(false), Some(false)), (None, None)] {
        let mut c = base_claims(&v, T);
        if let Some(b) = val {
            c["clientNetMatch"] = json!(b);
        }
        let r = run_own(&ed_token(H("octet-browser-verdict+jwt;v=3"), c), vec![ed_jwk("k1", json!({}))], T);
        assert_eq!(r.client_net_match(), want);
        assert!(r.is_valid(), "clientNetMatch {val:?} must not affect validity");
    }
    // An unverified token exposes nothing.
    let mut c = base_claims(&v, T);
    c["clientNetMatch"] = json!(true);
    let t = ed_token(H("octet-browser-verdict+jwt;v=3"), c);
    let parts: Vec<&str> = t.split('.').collect();
    let forged = format!("{}.{}.{}", parts[0], parts[1], B64.encode([0u8; 64]));
    assert_eq!(run_own(&forged, vec![ed_jwk("k1", json!({}))], T).client_net_match(), None);
}

/// The dev challenge carries the opaque `cn` tag: it is ignored, and s0 is
/// still the SHA-256 of the whole challenge token, tag included.
#[test]
fn dev_challenge_cn_tag_is_opaque_and_covered_by_s0() {
    let d = dev_vector();
    let ch = d["challenge"].as_str().unwrap();
    let body = B64.decode(ch.split('.').nth(2).unwrap()).unwrap();
    let claims: Value = serde_json::from_slice(&body[..body.len() - 64]).unwrap();
    assert!(claims["cn"].is_string(), "the vector's challenge carries cn");
    let c = claims_of(d["token"].as_str().unwrap());
    assert_eq!(B64.encode(sha(ch.as_bytes())), c["chain"]["s0"].as_str().unwrap());
}

// --- production verdict-key rotation to Cloud KMS (seq 2 → seq 3, 2026-10-19) --

const PROD_SEQ2: &str = include_str!("../test-vectors/browser-verdict-chain/prod-manifest-seq2.json.jws");
const PROD_SEQ3: &str = include_str!("../test-vectors/browser-verdict-chain/prod-manifest-seq3.json.jws");
const FILE_KEY: &str = "octet-browser-verdict-2026-09";
const KMS_KEY: &str = "octet-browser-verdict-2026-10";
/// The switch: 2026-10-19 15:00 UK. The file key's `octet_not_after`, the KMS key's `octet_not_before`.
const SWITCH: i64 = 1_792_418_400;

fn prod_verdict(name: &str) -> Value {
    let path = format!("{}/test-vectors/browser-verdict-chain/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// A production verdict file checked end to end under `manifest`, at its own iat.
fn prod_run(v: &Value, manifest: &str, roots: &[Jwk]) -> octet_verify::browser::BrowserReport {
    let m = verify_manifest(manifest, roots).unwrap();
    let token = v["token"].as_str().unwrap();
    verify_browser_verdict(&BrowserVerdictInputs {
        verdict_token: token,
        verdict_keys: &m.verdict_keys,
        challenge_token: v["challenge"].as_str(),
        challenge_keys: Some(&m.challenge_keys),
        edge_log: None,
        now_unix: claims_of(token)["iat"].as_i64().unwrap() + 60,
        manifest: Some(manifest),
        roots,
        min_manifest_seq: None,
    })
}

#[test]
fn prod_manifests_seq2_and_seq3_rotate_to_the_kms_key() {
    let hex = |b: &[u8]| hex::encode(b);
    assert_eq!(hex(&Sha256::digest(PROD_SEQ2)), "01907d63f689caafbda90b89eb07e4fa8266e5a4825da6ee8a037762ded44843");
    assert_eq!(hex(&Sha256::digest(PROD_SEQ3)), "11cefca4b908c15f779daac61fb680b0d1cafac8a8330fab7c2e45d305316e5b");
    // geo serves seq 3 without the trailing newline.
    assert_eq!(hex(&Sha256::digest(PROD_SEQ3.trim_end())), "371d729f1fe63eda9466101f2e750cd72bb45e5444cf6e9e3904a58325b94cab");

    let roots = pinned();
    let s2 = verify_manifest(PROD_SEQ2, &roots).unwrap();
    let s3 = verify_manifest(PROD_SEQ3, &roots).unwrap();
    assert_eq!((s2.seq, s3.seq), (2, 3));
    assert_eq!((s2.root_kid.as_str(), s3.root_kid.as_str()), (ROOT_A, ROOT_A));
    assert_eq!((s2.roots.clone(), s3.roots.clone()), (vec![ROOT_A.to_string(), ROOT_B.into()], vec![ROOT_A.to_string(), ROOT_B.into()]));

    // seq 2: the file key alone, open-ended.
    assert_eq!(s2.verdict_keys.len(), 1);
    assert_eq!((s2.verdict_keys[0].kid.as_str(), s2.verdict_keys[0].not_after), (FILE_KEY, None));

    // seq 3: the file key ends at the switch, the KMS key starts there.
    let key = |kid: &str| s3.verdict_keys.iter().find(|k| k.kid == kid).unwrap();
    assert_eq!(s3.verdict_keys.len(), 2);
    let (file, kms) = (key(FILE_KEY), key(KMS_KEY));
    assert_eq!((file.x.as_str(), file.not_before, file.not_after), (s2.verdict_keys[0].x.as_str(), Some(1_790_696_802), Some(SWITCH)));
    assert_eq!((kms.kty.as_str(), kms.crv.as_str(), kms.alg.as_deref()), ("EC", "P-256", Some("ES256")));
    assert_eq!((kms.not_before, kms.not_after, kms.revoked_at), (Some(SWITCH), None, None));
    assert!(file.revoked_at.is_none());
}

#[test]
fn prod_kms_verdict_verifies_under_seq3() {
    let v = prod_verdict("prod-verdict-2026-10-kms.json");
    assert!(claims_of(v["token"].as_str().unwrap())["iat"].as_i64().unwrap() > SWITCH);
    let r = prod_run(&v, PROD_SEQ3, &pinned());
    assert!(r.is_valid(), "{:?}", r.checks);
    assert_eq!(r.version, Some(3));
    assert_eq!(r.manifest_seq, Some(3));
    for check in ["verdict-jws", "root-manifest", "manifest-verdict-key", "key-validity", "chain-root", "session-link", "manifest-challenge-key"] {
        assert_eq!(r.status(check), Some(Verified), "{check}: {:?}", r.checks);
    }
    let jws = r.checks.iter().find(|c| c.name == "verdict-jws").unwrap();
    assert!(jws.detail.contains("ES256") && jws.detail.contains(KMS_KEY), "{}", jws.detail);
    assert_eq!(r.claims.as_ref().unwrap()["country"], "GB");
}

#[test]
fn prod_file_key_verdict_from_before_the_switch_still_verifies_under_seq3() {
    let v = prod_verdict("prod-verdict-2026-09-before-kms.json");
    assert!(claims_of(v["token"].as_str().unwrap())["iat"].as_i64().unwrap() < SWITCH);
    let r = prod_run(&v, PROD_SEQ3, &pinned());
    assert!(r.is_valid(), "{:?}", r.checks);
    assert_eq!(r.status("key-validity"), Some(Verified));
    let jws = r.checks.iter().find(|c| c.name == "verdict-jws").unwrap();
    assert!(jws.detail.contains("EdDSA") && jws.detail.contains(FILE_KEY), "{}", jws.detail);
}

/// Before seq 3, no manifest vouches for the KMS key: a published key list that
/// already carries it does not help while the manifest is seq 2.
#[test]
fn prod_kms_verdict_is_refused_under_seq2() {
    let v = prod_verdict("prod-verdict-2026-10-kms.json");
    let roots = pinned();
    let published = verify_manifest(PROD_SEQ3, &roots).unwrap();
    let s2 = verify_manifest(PROD_SEQ2, &roots).unwrap();
    let token = v["token"].as_str().unwrap();
    let r = verify_browser_verdict(&BrowserVerdictInputs {
        verdict_token: token,
        verdict_keys: &published.verdict_keys,
        challenge_token: v["challenge"].as_str(),
        challenge_keys: Some(&s2.challenge_keys),
        edge_log: None,
        now_unix: claims_of(token)["iat"].as_i64().unwrap() + 60,
        manifest: Some(PROD_SEQ2),
        roots: &roots,
        min_manifest_seq: None,
    });
    assert_eq!(r.status("verdict-jws"), Some(Verified), "{:?}", r.checks);
    assert_eq!(r.status("manifest-verdict-key"), Some(Failed), "{:?}", r.checks);
    assert!(!r.is_valid());
}

/// The cut-over on a real token: had the file key's window closed before this
/// verdict was issued, the verdict is refused. seq 3's payload is re-signed by a
/// throwaway root with the file key's `octet_not_after` moved before its iat.
#[test]
fn prod_file_key_verdict_is_refused_once_its_window_has_closed() {
    let v = prod_verdict("prod-verdict-2026-09-before-kms.json");
    let iat = claims_of(v["token"].as_str().unwrap())["iat"].as_i64().unwrap();
    let mut m: Value = serde_json::from_slice(&B64.decode(PROD_SEQ3.trim().split('.').nth(1).unwrap()).unwrap()).unwrap();
    for k in m["verdictKeys"].as_array_mut().unwrap() {
        if k["kid"] == FILE_KEY {
            k["octet_not_after"] = json!(iat - 3_600);
        }
    }
    let r = prod_run(&v, &own(&m), &own_roots());
    assert_eq!(r.status("key-validity"), Some(Failed), "{:?}", r.checks);
    assert!(!r.is_valid());
}

/// A verifier that has seen seq 3 refuses a replayed seq 2.
#[test]
fn prod_seq2_is_a_rollback_after_seq3() {
    let v = prod_verdict("prod-verdict-2026-09-before-kms.json");
    let roots = pinned();
    let m = verify_manifest(PROD_SEQ2, &roots).unwrap();
    let token = v["token"].as_str().unwrap();
    let r = verify_browser_verdict(&BrowserVerdictInputs {
        verdict_token: token,
        verdict_keys: &m.verdict_keys,
        challenge_token: v["challenge"].as_str(),
        challenge_keys: Some(&m.challenge_keys),
        edge_log: None,
        now_unix: claims_of(token)["iat"].as_i64().unwrap() + 60,
        manifest: Some(PROD_SEQ2),
        roots: &roots,
        min_manifest_seq: Some(3),
    });
    assert_eq!(r.status("root-manifest"), Some(Failed), "{:?}", r.checks);
    assert!(!r.is_valid());
}

// --- v=4: the early verdict -------------------------------------------------

use octet_verify::browser::{
    verify_browser_verdict_with, BrowserReport, BrowserVerdictOptions, SessionRevisions, VerdictStage,
};

const V4: &str = "octet-browser-verdict+jwt;v=4";

fn browser_vector(name: &str) -> Value {
    let path = format!("{}/test-vectors/browser-verdict-chain/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

/// The vectors' test-only key: its seed is SHA-256 of the file's `seedLabel`.
fn golden_test_key(v: &Value) -> Vec<Jwk> {
    let seed: [u8; 32] = Sha256::digest(v["seedLabel"].as_str().unwrap().as_bytes()).into();
    let pk = ed25519_dalek::SigningKey::from_bytes(&seed).verifying_key();
    assert_eq!(B64.encode(pk.as_bytes()), v4_vectors()["publicJwk"]["x"].as_str().unwrap(), "seed derivation");
    jwks(&[&v4_vectors()["publicJwk"]])
}

fn v4_vectors() -> Value {
    browser_vector("verdict-v4-vectors.json")
}

fn run_with(token: &str, keys: &[Jwk], now: i64, prior: Option<SessionRevisions>) -> BrowserReport {
    verify_browser_verdict_with(
        &BrowserVerdictInputs {
            verdict_token: token,
            verdict_keys: keys,
            challenge_token: None,
            challenge_keys: None,
            edge_log: None,
            now_unix: now,
            manifest: None,
            roots: &[],
            min_manifest_seq: None,
        },
        &BrowserVerdictOptions { prior },
    )
}

/// The three valid v=4 tokens from octet-browser. Their chain digests are
/// placeholders, so `chain-root` FAILS by design: these vectors pin the token
/// profile, and the real-chain tokens below pin the whole check.
#[test]
fn v4_vectors_valid_tokens_carry_their_stage() {
    let v = v4_vectors();
    let keys = golden_test_key(&v);
    for (name, stage, status, fin) in [
        ("provisional", VerdictStage::Provisional, Warning, false),
        ("final", VerdictStage::Final, Verified, true),
        ("incomplete", VerdictStage::Final, Warning, false),
    ] {
        let t = &v["valid"][name];
        let token = t["token"].as_str().unwrap();
        assert_eq!(claims_of(token), t["claims"], "{name}: claims as listed");
        let r = run_with(token, &keys, t["claims"]["iat"].as_i64().unwrap(), None);
        assert_eq!(r.status("verdict-jws"), Some(Verified), "{name}: {:?}", r.checks);
        assert_eq!(r.version, Some(4));
        assert_eq!(r.status("verdict-stage"), Some(status), "{name}: {:?}", r.checks);
        assert_eq!(r.stage(), Some(stage), "{name}");
        assert_eq!(r.revision(), t["claims"]["revision"].as_u64(), "{name}");
        assert_eq!(r.incomplete(), name == "incomplete", "{name}");
        assert_eq!(r.is_final(), fin, "{name}");
        assert_eq!(r.status("chain-root"), Some(Failed), "{name}: placeholder chain digests");
    }
}

#[test]
fn v4_vectors_invalid_tokens_fail_the_stage_check() {
    let v = v4_vectors();
    let keys = golden_test_key(&v);
    let invalid = v["invalid"].as_array().unwrap();
    assert_eq!(invalid.len(), 5);
    for t in invalid {
        let name = t["name"].as_str().unwrap();
        let token = t["token"].as_str().unwrap();
        let r = run_with(token, &keys, claims_of(token)["iat"].as_i64().unwrap(), None);
        assert_eq!(r.status("verdict-jws"), Some(Verified), "{name}: genuinely signed");
        assert_eq!(r.status("verdict-stage"), Some(Failed), "{name}: {:?}", r.checks);
        assert!(!r.is_valid() && !r.passes_gate(true), "{name}");
    }
}

/// A licence not opted in keeps getting this exact v=3 token: it verifies as
/// before and gets no `verdict-stage` line.
#[test]
fn v3_golden_token_is_unchanged() {
    let v = browser_vector("verdict-v3-golden.json");
    let keys = golden_test_key(&v);
    let token = v["token"].as_str().unwrap();
    assert_eq!(claims_of(token), v["claims"]);
    let r = run_with(token, &keys, v["claims"]["iat"].as_i64().unwrap(), None);
    assert_eq!(r.status("verdict-jws"), Some(Verified), "{:?}", r.checks);
    assert_eq!(r.version, Some(3));
    assert_eq!(r.status("verdict-stage"), None);
    assert_eq!((r.stage(), r.revision(), r.incomplete()), (None, None, false));
    assert!(r.is_final());
}

// v=4 tokens over the golden vector's real chain, signed with a throwaway key.

/// The golden chain with `n` reports (copies of its one report, each with its
/// own `s1.t`) and a matching `chain_root`.
fn v4_claims(stage: &str, revision: Value, reports: usize, confidence: f64) -> Value {
    let mut c = base_claims(&vector(), T);
    let one = c["chain"]["reports"][0].clone();
    c["chain"]["reports"] = Value::Array(
        (0..reports)
            .map(|i| {
                let mut r = one.clone();
                r["s1"]["t"] = json!(one["s1"]["t"].as_u64().unwrap() + 1_000 * i as u64);
                r
            })
            .collect(),
    );
    c["chain_root"] = json!(B64.encode(chain_root(&c["chain"]).unwrap()));
    c["stage"] = json!(stage);
    c["revision"] = revision;
    c["confidence"] = json!(confidence);
    c
}

fn own_v4(c: Value, prior: Option<SessionRevisions>) -> BrowserReport {
    let keys = jwks(&[&ed_jwk("k1", json!({}))]);
    run_with(&ed_token(H(V4), c), &keys, T, prior)
}

#[test]
fn v4_with_a_real_chain_verifies_and_gates() {
    // 1 provisional: valid, but not a pass for a gated action by default.
    let r = own_v4(v4_claims("provisional", json!(1), 1, 0.7), None);
    assert!(r.is_valid(), "{:?}", r.checks);
    assert_eq!(r.status("chain-root"), Some(Verified));
    assert_eq!(r.status("verdict-stage"), Some(Warning));
    assert!(!r.is_final() && !r.passes_gate(false) && r.passes_gate(true));

    // 2 final over both reports: the verdict.
    let r = own_v4(v4_claims("final", json!(2), 2, 0.9), None);
    assert!(r.is_valid(), "{:?}", r.checks);
    assert_eq!(r.status("verdict-stage"), Some(Verified));
    assert!(r.is_final() && r.passes_gate(false));

    // 1 final from one complete report (passive mode).
    let r = own_v4(v4_claims("final", json!(1), 1, 0.9), None);
    assert!(r.is_valid() && r.passes_gate(false), "{:?}", r.checks);

    // 2 final + incomplete over layer 1: valid, no stronger than provisional.
    let mut c = v4_claims("final", json!(2), 1, 0.7);
    c["incomplete"] = json!(true);
    let r = own_v4(c, None);
    assert!(r.is_valid(), "{:?}", r.checks);
    assert_eq!(r.status("verdict-stage"), Some(Warning));
    assert!(r.incomplete() && !r.is_final() && !r.passes_gate(false) && r.passes_gate(true));
}

#[test]
fn v4_profile_rules() {
    let fails = |c: Value, why: &str| {
        let r = own_v4(c, None);
        assert_eq!(r.status("verdict-stage"), Some(Failed), "{why}: {:?}", r.checks);
        assert!(!r.is_valid(), "{why}");
    };
    // Layer 1 only means one report.
    fails(v4_claims("provisional", json!(1), 2, 0.7), "provisional over two reports");
    let mut c = v4_claims("final", json!(2), 2, 0.7);
    c["incomplete"] = json!(true);
    fails(c, "incomplete final over two reports");
    fails(v4_claims("final", json!(2), 3, 0.9), "final over three reports");
    // The provisional confidence cap, which an incomplete final keeps.
    fails(v4_claims("provisional", json!(1), 1, 0.9), "provisional above 0.7");
    let mut c = v4_claims("final", json!(2), 1, 0.9);
    c["incomplete"] = json!(true);
    fails(c, "incomplete final above 0.7");
    // incomplete is absent or true, and only on a final.
    let mut c = v4_claims("final", json!(2), 2, 0.9);
    c["incomplete"] = json!(false);
    fails(c, "incomplete: false");
    // revision is an integer of 1 or more.
    for bad in [json!(0), json!(1.5), json!("2"), json!(-1)] {
        fails(v4_claims("final", bad.clone(), 1, 0.9), &format!("revision {bad}"));
    }
    let mut c = v4_claims("final", json!(1), 1, 0.9);
    c.as_object_mut().unwrap().remove("revision");
    fails(c, "no revision");
    fails(v4_claims("draft", json!(1), 1, 0.7), "stage draft");
    // A v=3 token never carries the v=4 claims.
    let mut c = base_claims(&vector(), T);
    c["revision"] = json!(1);
    let keys = jwks(&[&ed_jwk("k1", json!({}))]);
    let r = run_with(&ed_token(H("octet-browser-verdict+jwt;v=3"), c), &keys, T, None);
    assert_eq!(r.status("verdict-stage"), Some(Failed), "{:?}", r.checks);
}

#[test]
fn v4_revisions_only_go_up_and_a_session_has_one_final() {
    let prov = || v4_claims("provisional", json!(1), 1, 0.7);
    let fin = |rev: u64| v4_claims("final", json!(rev), 2, 0.9);

    // 1 provisional, then 2 final: each accepted, and the state follows.
    let r = own_v4(prov(), None);
    let s1 = r.next_revisions(None).unwrap();
    assert_eq!(s1, SessionRevisions { highest: 1, final_revision: None });
    let r = own_v4(fin(2), Some(s1));
    assert_eq!(r.status("verdict-stage"), Some(Verified), "{:?}", r.checks);
    let s2 = r.next_revisions(Some(s1)).unwrap();
    assert_eq!(s2, SessionRevisions { highest: 2, final_revision: Some(2) });

    // The provisional again, after the final: a lower revision.
    let r = own_v4(prov(), Some(s2));
    assert_eq!(r.status("verdict-stage"), Some(Failed), "{:?}", r.checks);
    assert_eq!(r.next_revisions(Some(s2)), None, "a refused token changes nothing");
    // The same final again is fine; a second final is not.
    assert_eq!(own_v4(fin(2), Some(s2)).status("verdict-stage"), Some(Verified));
    assert_eq!(own_v4(fin(3), Some(s2)).status("verdict-stage"), Some(Failed));
    assert_eq!(own_v4(v4_claims("provisional", json!(3), 1, 0.7), Some(s2)).status("verdict-stage"), Some(Failed));

    // A higher provisional replaces a lower one before the final.
    let r = own_v4(v4_claims("provisional", json!(2), 1, 0.7), Some(s1));
    assert_eq!(r.status("verdict-stage"), Some(Warning));
    // v=3 tokens carry no revisions.
    let keys = jwks(&[&ed_jwk("k1", json!({}))]);
    let r = run_with(&ed_token(H("octet-browser-verdict+jwt;v=3"), base_claims(&vector(), T)), &keys, T, Some(s2));
    assert!(r.is_valid() && r.next_revisions(Some(s2)).is_none());
}

/// The CLI: exit 3 for a provisional verdict unless --accept-provisional, and the
/// revision store refusing a lower revision.
#[test]
fn v4_cli_exit_codes_and_revision_store() {
    let dir = std::env::temp_dir().join(format!("octet-v4-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let jwks_file = dir.join("jwks.json");
    std::fs::write(&jwks_file, json!({ "keys": [ed_jwk("k1", json!({}))] }).to_string()).unwrap();
    let roots = dir.join("roots.json");
    std::fs::write(&roots, r#"{"roots":[]}"#).unwrap();
    let store = dir.join("revisions.json");
    let run = |c: Value, extra: &[&str]| {
        let token = ed_token(H(V4), c);
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_octet-verify"))
            .arg("browser-verdict")
            .arg(&token)
            .args(["--jwks", jwks_file.to_str().unwrap(), "--roots", roots.to_str().unwrap(), "--now", &T.to_string()])
            .args(extra)
            .output()
            .unwrap();
        (out.status.code(), String::from_utf8_lossy(&out.stdout).into_owned())
    };
    let prov = || v4_claims("provisional", json!(1), 1, 0.7);
    let fin = || v4_claims("final", json!(2), 2, 0.9);

    let (code, out) = run(prov(), &[]);
    assert_eq!(code, Some(3), "{out}");
    assert!(out.contains("INCONCLUSIVE") && out.contains("stage=provisional revision=1"), "{out}");
    assert_eq!(run(prov(), &["--accept-provisional"]).0, Some(0));
    assert_eq!(run(fin(), &[]).0, Some(0));
    let (code, out) = run(v4_claims("provisional", json!(1), 2, 0.7), &[]);
    assert_eq!(code, Some(1), "{out}");

    let (_, json_out) = run(prov(), &["--json"]);
    let j: Value = serde_json::from_str(&json_out).unwrap();
    assert_eq!((j["stage"].as_str(), j["revision"].as_u64(), j["incomplete"].as_bool()), (Some("provisional"), Some(1), Some(false)));
    assert_eq!((j["verdict"].as_str(), j["passes_gate"].as_bool(), j["valid"].as_bool()), (Some("INCONCLUSIVE"), Some(false), Some(true)));

    // The store: provisional 1, final 2, then the provisional again is refused.
    let s = ["--revision-store", store.to_str().unwrap()];
    assert_eq!(run(prov(), &s).0, Some(3));
    assert_eq!(run(fin(), &s).0, Some(0));
    let kept: Value = serde_json::from_str(&std::fs::read_to_string(&store).unwrap()).unwrap();
    let session = claims_of(vector()["verdictToken"].as_str().unwrap())["sessionRef"].as_str().unwrap().to_owned();
    assert_eq!(kept[&session], json!({ "highest": 2, "final": 2 }));
    let (code, out) = run(prov(), &s);
    assert_eq!(code, Some(1), "{out}");
    assert!(out.contains("lower than revision 2"), "{out}");
    std::fs::remove_dir_all(&dir).ok();
}
