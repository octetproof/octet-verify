//! Transparency log inclusion against the production log's vector pack
//! (`test-vectors/tlog-prod/`, copied unchanged from the log's generator), plus
//! witness and manifest cases built from throwaway keys.
#![cfg(feature = "browser")]

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD as B64};
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use octet_verify::browser::{parse_roots, PINNED_ROOTS_JSON};
use octet_verify::tlog::*;
use serde_json::{json, Value};

fn read(rel: &str) -> String {
    std::fs::read_to_string(format!("{}/test-vectors/{rel}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

fn pack(rel: &str) -> String {
    read(&format!("tlog-prod/{rel}"))
}

fn json_of(rel: &str) -> Value {
    serde_json::from_str(&pack(rel)).unwrap()
}

fn prod_policy() -> CheckpointPolicy {
    CheckpointPolicy { logs: vec![NoteKey::from_vkey(PROD_LOG_VKEY).unwrap()], ..Default::default() }
}

#[test]
fn the_pinned_key_is_the_published_log_key() {
    let p = json_of("pack.json");
    assert_eq!(p["origin"], PROD_LOG_ORIGIN);
    assert_eq!(p["log_key"]["vkey"], PROD_LOG_VKEY);
    let jwk = &json_of("log-key.json")["keys"][0];
    assert_eq!((jwk["kid"].as_str(), jwk["octet_origin"].as_str()), (Some("tlog-7cbbf8dc"), Some(PROD_LOG_ORIGIN)));
    let from_jwk = NoteKey::new(PROD_LOG_ORIGIN, 1, &B64.decode(jwk["x"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(from_jwk.vkey(), PROD_LOG_VKEY);
}

#[test]
fn every_leaf_is_in_the_signed_checkpoint() {
    let p = json_of("pack.json");
    let cp = verify_checkpoint(&pack("checkpoint"), &prod_policy()).unwrap();
    assert_eq!((cp.head.size, cp.head.root_b64()), (7, p["root"].as_str().unwrap().to_owned()));
    assert_eq!(cp.log_vkey, PROD_LOG_VKEY);

    let entries = json_of("entries.json");
    for e in entries.as_array().unwrap() {
        let i = e["index"].as_u64().unwrap();
        let b = parse_bundle(&pack(&format!("inclusion/leaf-{i}.json"))).unwrap();
        assert_eq!(b.checkpoint, pack("checkpoint"));
        assert_eq!(to_hex(&leaf_hash(&b.entry)), e["leaf_hash"].as_str().unwrap());
        let v = verify_bundle(&b, &prod_policy()).unwrap_or_else(|err| panic!("leaf {i}: {err}"));
        assert_eq!((v.index, v.checkpoint.head.size), (i, 7));
        assert_eq!(v.entry.kind(), e["kind"].as_str().unwrap());
        match &v.entry {
            Entry::Manifest { seq, iat, kid, sha256 } => {
                let body = &e["body"];
                assert_eq!(Some(*seq), body["seq"].as_u64());
                assert_eq!(Some(*iat), body["iat"].as_u64());
                assert_eq!(Some(kid.as_str()), body["kid"].as_str());
                // The manifest files this repo already ships are the logged ones.
                let jws = read(&format!("browser-verdict-chain/prod-manifest-seq{seq}.json.jws"));
                assert_eq!(&manifest_sha256(&jws), sha256, "seq {seq}");
            }
            Entry::Release { tag, commit, files } => {
                assert_eq!(Some(tag.as_str()), e["tag"].as_str());
                assert_eq!(Some(commit.as_str()), e["commit"].as_str());
                let want: std::collections::BTreeMap<String, String> =
                    serde_json::from_value(e["body"]["files"].clone()).unwrap();
                assert_eq!(files, &want);
            }
        }
    }
}

#[test]
fn every_earlier_tree_head_is_consistent_with_the_checkpoint() {
    let cp = verify_checkpoint(&pack("checkpoint"), &prod_policy()).unwrap().head;
    for m in 1..=6 {
        let c = parse_consistency(&pack(&format!("consistency/{m}-7.json"))).unwrap();
        assert!(verify_consistency(c.first, c.second, &c.first_root, &c.second_root, &c.proof), "{m} -> 7");
        let kept = TreeHead { origin: PROD_LOG_ORIGIN.into(), size: m, root: c.first_root };
        check_consistency(&kept, &cp, Some(&c)).unwrap();
        // Kept the newer head, and the bundle brings the older one: same proof.
        check_consistency(&cp, &kept, Some(&c)).unwrap();
        assert!(check_consistency(&kept, &cp, None).unwrap_err().contains("is needed"));
    }
    // Published heads 4, 5 and 6 are the ones the log signed before.
    for (m, root) in [
        (4, "Z5AhyFNaJj0uSUz6dYs+xrh1AJgo5I0tqtYxxNxJDgc="),
        (5, "PDOSVjBDv98mh0grjAzTvlAtjuFiTtDQqq2b6GmhB28="),
        (6, "B4/Sje3RJSjlJTx4WXivosNG2mUtf3NmxJTTluSw66I="),
    ] {
        assert_eq!(STANDARD.encode(parse_consistency(&pack(&format!("consistency/{m}-7.json"))).unwrap().first_root), root);
    }
    let mut forked = cp.clone();
    forked.root[0] ^= 1;
    assert!(check_consistency(&cp, &forked, None).unwrap_err().contains("forked"));
}

/// octet-verify's maintainers run this witness for the log.
const WITNESS_VKEY: &str = PROD_WITNESS_VKEY;

#[test]
fn the_checkpoint_is_cosigned_by_the_witness() {
    let policy = |quorum, now| CheckpointPolicy {
        witnesses: vec![NoteKey::from_vkey(WITNESS_VKEY).unwrap()],
        quorum,
        now_unix: Some(now),
        ..prod_policy()
    };
    // Cosigned at 2026-11-05T09:34:12Z.
    let cp = verify_checkpoint(&pack("checkpoint"), &policy(1, 1_793_871_252)).unwrap();
    assert_eq!(cp.cosigned, vec![("witness.octetproof.com/octet-verify".to_string(), 1_793_871_252)]);
    // Every bundle carries the same cosigned note.
    let b = parse_bundle(&pack("inclusion/leaf-6.json")).unwrap();
    assert!(verify_bundle(&b, &policy(1, 1_793_871_252)).is_ok());
    // A verifier whose clock is more than 5 minutes behind refuses it.
    assert!(verify_checkpoint(&pack("checkpoint"), &policy(1, 1_793_871_252 - 301)).unwrap_err().contains("from the future"));
}

#[test]
fn every_bad_case_is_refused() {
    let dir = format!("{}/test-vectors/tlog-prod/bad", env!("CARGO_MANIFEST_DIR"));
    let mut n = 0;
    for f in std::fs::read_dir(dir).unwrap() {
        let c: Value = serde_json::from_str(&std::fs::read_to_string(f.unwrap().path()).unwrap()).unwrap();
        let case = c["case"].as_str().unwrap();
        match c["type"].as_str().unwrap() {
            "inclusion" => {
                let b = parse_bundle(&c["bundle"].to_string()).unwrap();
                let err = verify_bundle(&b, &prod_policy()).unwrap_err();
                // Not required, but the messages match the log's own verifier.
                assert_eq!(err, c["expect_error"].as_str().unwrap(), "{case}");
            }
            "consistency" => {
                let p = parse_consistency(&c["consistency"].to_string()).unwrap();
                assert!(!verify_consistency(p.first, p.second, &p.first_root, &p.second_root, &p.proof), "{case}");
                let signed = verify_checkpoint(&pack("checkpoint"), &prod_policy()).unwrap().head;
                let kept = TreeHead { origin: PROD_LOG_ORIGIN.into(), size: p.first, root: p.first_root };
                assert!(check_consistency(&kept, &signed, Some(&p)).is_err(), "{case}");
            }
            t => panic!("{case}: unknown type {t}"),
        }
        n += 1;
    }
    assert_eq!(n, 10);
}

#[test]
fn bundles_are_refused_for_shape() {
    let good: Value = json_of("inclusion/leaf-3.json");
    let with = |k: &str, v: Value| {
        let mut b = good.clone();
        b[k] = v;
        parse_bundle(&b.to_string())
    };
    assert!(parse_bundle(&good.to_string()).is_ok());
    assert!(with("v", json!(2)).unwrap_err().contains("version"));
    assert!(with("verdict", json!({})).unwrap_err().contains("verdict proofs"));
    assert!(with("extra", json!(1)).unwrap_err().contains("unexpected field"));
    assert!(with("index", json!(-1)).is_err());
    assert!(with("path", json!(["AAAA"])).unwrap_err().contains("32-byte"));
    assert!(with("path", json!(vec!["x"; 65])).unwrap_err().contains("longer"));
    // A different, unpinned log key refuses the real checkpoint.
    let other = NoteKey::new(PROD_LOG_ORIGIN, 1, SigningKey::from_bytes(&[9; 32]).verifying_key().as_bytes()).unwrap();
    let p = CheckpointPolicy { logs: vec![other], ..Default::default() };
    let err = verify_bundle(&parse_bundle(&good.to_string()).unwrap(), &p).unwrap_err();
    assert_eq!(err, "the proof does not verify: no known key signed the note");
    let none = CheckpointPolicy::default();
    assert_eq!(verify_bundle(&parse_bundle(&good.to_string()).unwrap(), &none).unwrap_err(), "no log key is pinned");
}

// Size 9 (`tlog-prod/seq4/`): root manifest seq 4, the first to list logKeys,
// logged as leaf 8 and cosigned by the witness.

fn seq4(rel: &str) -> String {
    pack(&format!("seq4/{rel}"))
}

/// The witness cosigned the size-9 checkpoint at 2026-11-11T10:54:26Z.
const SIZE9_COSIGNED: u64 = 1_794_394_466;

fn seq4_policy() -> CheckpointPolicy {
    let roots = parse_roots(PINNED_ROOTS_JSON).unwrap();
    let (_, keys) = log_keys_from_manifest(&seq4("root-manifest-seq4.jws"), &roots).unwrap();
    CheckpointPolicy {
        logs: keys,
        witnesses: vec![NoteKey::from_vkey(WITNESS_VKEY).unwrap()],
        quorum: 1,
        now_unix: Some(SIZE9_COSIGNED),
    }
}

#[test]
fn seq4_lists_the_log_key_and_is_in_the_log() {
    let roots = parse_roots(PINNED_ROOTS_JSON).unwrap();
    let jws = seq4("root-manifest-seq4.jws");
    let (m, keys) = log_keys_from_manifest(&jws, &roots).unwrap();
    assert_eq!((m.seq, m.root_kid.as_str()), (4, "octet-root-a-2026-10"));
    assert_eq!(keys.iter().map(NoteKey::vkey).collect::<Vec<_>>(), vec![PROD_LOG_VKEY.to_string()]);
    // The log records the JWS as served, without the file's trailing newline.
    assert_eq!(manifest_sha256(&jws), "b2e4b63257a85792466dc7599dbb4033e12879f88ff1ecb39cbb475d66338e35");

    let cp = verify_checkpoint(&seq4("checkpoint-size9"), &seq4_policy()).unwrap();
    assert_eq!((cp.head.size, cp.head.root_b64().as_str()), (9, "GMudzry+Vj6uq7D1Pc9wiAWV3czfLNWNd2IKdcTd6YA="));
    assert_eq!(cp.cosigned, vec![("witness.octetproof.com/octet-verify".to_string(), SIZE9_COSIGNED)]);

    let leaf = |f: &str| {
        let b = parse_bundle(&seq4(f)).unwrap();
        assert_eq!(b.checkpoint, seq4("checkpoint-size9"));
        verify_bundle(&b, &seq4_policy()).unwrap_or_else(|e| panic!("{f}: {e}"))
    };
    let v = leaf("inclusion-leaf-8-seq4.json");
    assert_eq!((v.index, v.checkpoint.head.size), (8, 9));
    match &v.entry {
        Entry::Manifest { seq, iat, kid, sha256 } => {
            assert_eq!((*seq, *iat as i64, kid.as_str()), (4, m.iat, "octet-root-a-2026-10"));
            assert_eq!(sha256, &manifest_sha256(&jws));
        }
        e => panic!("leaf 8 is {}", e.kind()),
    }
    let v = leaf("inclusion-leaf-7-v1.10.0.json");
    assert_eq!((v.index, v.entry.kind()), (7, "release"));
    assert!(matches!(&v.entry, Entry::Release { tag, .. } if tag == "v1.10.0"));
}

#[test]
fn the_size_9_head_extends_the_heads_before_it() {
    let cp7 = verify_checkpoint(&pack("checkpoint"), &prod_policy()).unwrap().head;
    let cp9 = verify_checkpoint(&seq4("checkpoint-size9"), &seq4_policy()).unwrap().head;
    let c79 = parse_consistency(&seq4("7-9.json")).unwrap();
    assert_eq!((c79.first, c79.second), (7, 9));
    check_consistency(&cp7, &cp9, Some(&c79)).unwrap();
    assert!(check_consistency(&cp7, &cp9, None).unwrap_err().contains("is needed"));

    // Size 8 is the head the witness kept before it cosigned size 9. Its root
    // is the sibling on leaf 8's path: the first 8 leaves form a full subtree.
    let c89 = parse_consistency(&seq4("8-9.json")).unwrap();
    let kept8 = TreeHead { origin: PROD_LOG_ORIGIN.into(), size: 8, root: c89.first_root };
    check_consistency(&kept8, &cp9, Some(&c89)).unwrap();
    assert_eq!(parse_bundle(&seq4("inclusion-leaf-8-seq4.json")).unwrap().path, vec![c89.first_root]);
    assert!(check_consistency(&kept8, &cp9, Some(&c79)).is_err(), "the 7 -> 9 proof does not start at 8");
}

// A log and witnesses with throwaway keys.

const ORIGIN: &str = "example.test/log";

fn sig_line(name: &str, key_id: &[u8; 4], sig: &[u8]) -> String {
    format!("\u{2014} {name} {}\n", STANDARD.encode([&key_id[..], sig].concat()))
}

fn signed_checkpoint(log: &SigningKey, size: u64, root: [u8; 32], witnesses: &[(&str, &SigningKey, u64)]) -> String {
    let text = format!("{ORIGIN}\n{size}\n{}\n", STANDARD.encode(root));
    let k = NoteKey::new(ORIGIN, 1, log.verifying_key().as_bytes()).unwrap();
    let mut note = format!("{text}\n{}", sig_line(ORIGIN, &k.key_id, &log.sign(text.as_bytes()).to_bytes()));
    for (name, w, t) in witnesses {
        let wk = NoteKey::new(name, 4, w.verifying_key().as_bytes()).unwrap();
        let sig = w.sign(format!("cosignature/v1\ntime {t}\n{text}").as_bytes());
        note += &sig_line(name, &wk.key_id, &[&t.to_be_bytes()[..], &sig.to_bytes()].concat());
    }
    note
}

#[test]
fn a_witness_quorum_is_enforced() {
    let log = SigningKey::from_bytes(&[1; 32]);
    let (w1, w2) = (SigningKey::from_bytes(&[2; 32]), SigningKey::from_bytes(&[3; 32]));
    let wkey = |n: &str, k: &SigningKey| NoteKey::new(n, 4, k.verifying_key().as_bytes()).unwrap();
    let policy = |quorum| CheckpointPolicy {
        logs: vec![NoteKey::new(ORIGIN, 1, log.verifying_key().as_bytes()).unwrap()],
        witnesses: vec![wkey("w1.test", &w1), wkey("w2.test", &w2)],
        quorum,
        now_unix: Some(2_000_000_000),
    };
    let root = leaf_hash(b"x");
    let both = signed_checkpoint(&log, 1, root, &[("w1.test", &w1, 1_900_000_000), ("w2.test", &w2, 1_900_000_001)]);
    let cp = verify_checkpoint(&both, &policy(2)).unwrap();
    assert_eq!(cp.cosigned.len(), 2);
    let one = signed_checkpoint(&log, 1, root, &[("w1.test", &w1, 1_900_000_000)]);
    assert!(verify_checkpoint(&one, &policy(1)).is_ok());
    assert!(verify_checkpoint(&one, &policy(2)).unwrap_err().contains("1 of 2 witnesses"));
    // The same witness twice counts once.
    let twice = signed_checkpoint(&log, 1, root, &[("w1.test", &w1, 1_900_000_000), ("w1.test", &w1, 1_900_000_005)]);
    assert!(verify_checkpoint(&twice, &policy(2)).unwrap_err().contains("1 of 2"));
    // From the future.
    let future = signed_checkpoint(&log, 1, root, &[("w1.test", &w1, 2_000_000_301)]);
    assert!(verify_checkpoint(&future, &policy(1)).unwrap_err().contains("from the future"));
    // Witnesses alone are not the log.
    let text = format!("{ORIGIN}\n1\n{}\n", STANDARD.encode(root));
    let only_witness = {
        let full = signed_checkpoint(&log, 1, root, &[("w1.test", &w1, 1_900_000_000)]);
        let lines: Vec<&str> = full.lines().collect();
        format!("{text}\n{}\n", lines.last().unwrap())
    };
    assert!(verify_checkpoint(&only_witness, &policy(0)).unwrap_err().contains("the log did not sign"));
    // A tampered cosignature refuses the note.
    let mut b = both.into_bytes();
    let n = b.len();
    b[n - 3] = if b[n - 3] == b'A' { b'B' } else { b'A' };
    assert!(verify_checkpoint(&String::from_utf8(b).unwrap(), &policy(0)).unwrap_err().contains("w2.test does not verify"));
}

#[test]
fn log_keys_come_from_a_verified_manifest() {
    use p256::ecdsa::{signature::Signer as _, Signature};
    // The real seq 3 manifest predates logKeys.
    let roots = parse_roots(PINNED_ROOTS_JSON).unwrap();
    let seq3 = read("browser-verdict-chain/prod-manifest-seq3.json.jws");
    let (m, keys) = log_keys_from_manifest(&seq3, &roots).unwrap();
    assert_eq!((m.seq, keys.len()), (3, 0));

    // A manifest with logKeys, signed by a throwaway root.
    let sk = p256::ecdsa::SigningKey::from_slice(&[0x77; 32]).unwrap();
    let pt = sk.verifying_key().to_encoded_point(false);
    let root = json!({ "kty": "EC", "crv": "P-256", "kid": "own-root", "x": B64.encode(pt.x().unwrap()),
        "y": B64.encode(pt.y().unwrap()), "octet_purpose": "octet-root" });
    let own = parse_roots(&json!({ "roots": [root] }).to_string()).unwrap();
    let sign = |manifest: &Value| {
        let h = json!({ "alg": "ES256", "typ": "octet-root+jws;v=1", "kid": "own-root" });
        let input = format!("{}.{}", B64.encode(h.to_string()), B64.encode(manifest.to_string()));
        let sig: Signature = sk.sign(input.as_bytes());
        format!("{input}.{}", B64.encode(sig.to_bytes()))
    };
    let log_jwk = json_of("log-key.json")["keys"][0].clone();
    let mut m = json!({ "typ": "octet-browser-manifest", "v": 1, "seq": 4, "iat": 1_800_000_000, "exp": 1_820_000_000,
        "roots": ["own-root"], "verdictKeys": [], "challengeKeys": [], "logKeys": [log_jwk] });
    let (_, keys) = log_keys_from_manifest(&sign(&m), &own).unwrap();
    assert_eq!(keys.iter().map(NoteKey::vkey).collect::<Vec<_>>(), vec![PROD_LOG_VKEY.to_string()]);
    let policy = CheckpointPolicy { logs: keys, ..Default::default() };
    assert!(verify_bundle(&parse_bundle(&pack("inclusion/leaf-5.json")).unwrap(), &policy).is_ok());

    m["logKeys"][0]["octet_purpose"] = json!("browser-verdict");
    assert!(log_keys_from_manifest(&sign(&m), &own).unwrap_err().contains("logKeys[0]"));
    // The same manifest is refused under the real pinned roots.
    m["logKeys"][0]["octet_purpose"] = json!("tlog");
    assert!(log_keys_from_manifest(&sign(&m), &roots).is_err());
}

#[test]
fn the_cli_checks_a_bundle_and_moves_the_kept_head_forward() {
    let dir = std::env::temp_dir().join(format!("octet-tlog-cli-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let state = dir.join("head.json");
    let v = |rel: &str| format!("{}/test-vectors/{rel}", env!("CARGO_MANIFEST_DIR"));
    let run = |args: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_octet-verify")).arg("tlog").args(args).output().unwrap().status.code()
    };
    let c4: Value = json_of("consistency/4-7.json");
    let kept = json!({ "origin": PROD_LOG_ORIGIN, "size": 4, "root": c4["first_root"] });
    std::fs::write(&state, kept.to_string()).unwrap();
    let leaf4 = v("tlog-prod/inclusion/leaf-4.json");
    let st = state.to_str().unwrap();
    assert_eq!(run(&[&leaf4, "--state", st]), Some(1), "no consistency proof");
    let server = json_of("entries.json")[4]["body"]["files"]["server"].as_str().unwrap().to_owned();
    assert_eq!(run(&[&leaf4, "--sha256", &server, "--name", "SHA256SUMS"]), Some(1), "wrong file name");
    assert_eq!(run(&[&leaf4, "--state", st, "--consistency", &v("tlog-prod/consistency/4-7.json"), "--sha256", &server, "--name", "server"]), Some(0));
    let head: Value = serde_json::from_str(&std::fs::read_to_string(&state).unwrap()).unwrap();
    assert_eq!(head["size"], 7);
    assert_eq!(run(&[&v("tlog-prod/inclusion/leaf-0.json"), "--state", st]), Some(0), "same size, same root");
    let seq1 = v("browser-verdict-chain/prod-manifest-seq1.json.jws");
    assert_eq!(run(&[&v("tlog-prod/inclusion/leaf-0.json"), "--manifest", &seq1, "--artifact", &seq1]), Some(0));
    assert_eq!(run(&[&v("tlog-prod/inclusion/leaf-1.json"), "--artifact", &seq1]), Some(1), "seq 2's leaf is not seq 1");
    let bad = dir.join("bad.json");
    std::fs::write(&bad, json_of("bad/tampered-entry.json")["bundle"].to_string()).unwrap();
    assert_eq!(run(&[bad.to_str().unwrap()]), Some(1));
    assert_eq!(run(&[&leaf4, "--quorum", "2"]), Some(2), "quorum above the witnesses");
    assert_eq!(run(&[&leaf4, "--witness", PROD_LOG_VKEY]), Some(2), "a log key is not a witness key");

    // The log's witness is required by default; --quorum 0 opts out.
    let uncosigned = dir.join("uncosigned.json");
    let mut b = json_of("inclusion/leaf-4.json");
    let note = b["checkpoint"].as_str().unwrap();
    let without: String = note.lines().filter(|l| !l.contains("witness.octetproof.com")).map(|l| format!("{l}\n")).collect();
    assert_ne!(without, note);
    b["checkpoint"] = json!(without);
    std::fs::write(&uncosigned, b.to_string()).unwrap();
    let uncosigned = uncosigned.to_str().unwrap();
    assert_eq!(run(&[&leaf4]), Some(0), "cosigned by the built-in witness");
    assert_eq!(run(&[uncosigned]), Some(1), "no cosignature");
    assert_eq!(run(&[uncosigned, "--quorum", "0"]), Some(0), "explicit opt-out");
    let other = NoteKey::new("w.test", 4, SigningKey::from_bytes(&[5; 32]).verifying_key().as_bytes()).unwrap().vkey();
    assert_eq!(run(&[&leaf4, "--witness", &other]), Some(1), "--witness replaces the built-in one");

    // Seq 4: the log key from the manifest, the witness required, from size 7 to 9.
    let (seq4, leaf8) = (v("tlog-prod/seq4/root-manifest-seq4.jws"), v("tlog-prod/seq4/inclusion-leaf-8-seq4.json"));
    let now = SIZE9_COSIGNED.to_string();
    let strict = |extra: &[&str]| {
        let mut a = vec![leaf8.as_str(), "--manifest", &seq4, "--artifact", &seq4, "--witness", WITNESS_VKEY, "--quorum", "1"];
        a.extend_from_slice(extra);
        run(&a)
    };
    assert_eq!(strict(&["--now", &now, "--state", st]), Some(1), "no consistency proof from 7");
    let c79 = v("tlog-prod/seq4/7-9.json");
    let early = (SIZE9_COSIGNED - 301).to_string();
    assert_eq!(strict(&["--now", &early, "--state", st, "--consistency", &c79]), Some(1), "cosigned in the future");
    assert_eq!(strict(&["--now", &now, "--state", st, "--consistency", &c79]), Some(0));
    let head: Value = serde_json::from_str(&std::fs::read_to_string(&state).unwrap()).unwrap();
    assert_eq!(head["size"], 9);
    // The same, with the witness and quorum left to their defaults.
    assert_eq!(run(&[&leaf8, "--manifest", &seq4, "--artifact", &seq4, "--now", &now, "--state", st]), Some(0));
    assert_eq!(run(&[&leaf8, "--manifest", &seq4, "--artifact", &seq1]), Some(1), "leaf 8 is not seq 1");
    std::fs::remove_dir_all(&dir).unwrap();
}
