//! Transparency log inclusion (feature `browser`).
//!
//! octet logs its public objects (root manifests, browser releases) in a C2SP
//! tlog-tiles log at `https://log.octetproof.com/browser`. This module checks,
//! offline, that an entry is in that log: from a proof bundle
//!
//! ```text
//! {"v":1, "index", "size", "entry": b64url, "path": [b64url], "checkpoint": signed note}
//! ```
//!
//! 1. the checkpoint is a C2SP signed note (c2sp.org/signed-note) signed by a
//!    pinned log key (Ed25519, type 0x01) for the log's origin, plus a quorum of
//!    witness cosignatures (type 0x04) when witnesses are pinned;
//! 2. `SHA-256(0x00 ‖ entry)` walks `path` to the checkpoint's root at `size`
//!    (RFC 9162 §2.1.3.2);
//! 3. the entry is `"octet-tlog/v1\n" ‖ kind ‖ "\n" ‖ canonical JSON`, of kind
//!    `manifest` or `release`.
//!
//! A tree head kept from before is carried forward only through an RFC 9162
//! consistency proof (§2.1.4.2) to the new checkpoint.
//!
//! The log key is taken from the root manifest's `logKeys` (the offline root
//! vouches for it). Until a manifest lists one, the current production key is
//! pinned here, [`PROD_LOG_VKEY`]. See VERIFICATION-SPEC.md, "Transparency log
//! inclusion".

use crate::browser::{verify_manifest, Jwk, Manifest};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// The production log's origin.
pub const PROD_LOG_ORIGIN: &str = "log.octetproof.com/browser";
/// The production log key (kid `tlog-7cbbf8dc`), used when no root manifest
/// that lists `logKeys` is given.
pub const PROD_LOG_VKEY: &str = "log.octetproof.com/browser+7cbbf8dc+AY+W5wQKXobt/BXgqsq9u2NFLZbHdW/BUeS/lqu3DFHm";
/// The witness octet-verify's maintainers run for the production log. The log
/// requires its cosignature (quorum 1) since 10 Nov 2026.
pub const PROD_WITNESS_VKEY: &str = "witness.octetproof.com/octet-verify+33161baf+BCnmA+Bq5n8tdIGwP6g+tyvTFPdZNfXBU3mWhV9MYZPK";

const ENTRY_TAG: &str = "octet-tlog/v1";
const SIG_ED25519: u8 = 0x01;
const SIG_COSIGNATURE: u8 = 0x04;
/// Verifiers must accept at least 16 signatures on a note; more than this is refused.
const MAX_SIGS: usize = 64;
/// A path longer than this cannot belong to a tree of at most 2^63 leaves.
const MAX_PATH: usize = 64;
/// Sizes, indices and cosignature times stay within JavaScript's safe integers.
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;
/// A cosignature may be at most this far ahead of the verification time, seconds.
const COSIGNATURE_SKEW_S: u64 = 300;
const LOG_PURPOSE: &str = "tlog";

/// A note verifier key: `(name, key ID, signature type, Ed25519 public key)`.
#[derive(Clone, Debug)]
pub struct NoteKey {
    pub name: String,
    pub key_id: [u8; 4],
    /// 0x01: the log's signature. 0x04: a witness cosignature.
    pub sig_type: u8,
    key: VerifyingKey,
}

impl NoteKey {
    pub fn new(name: &str, sig_type: u8, public_key: &[u8]) -> Result<Self, String> {
        check_key_name(name)?;
        if sig_type != SIG_ED25519 && sig_type != SIG_COSIGNATURE {
            return Err(format!("unsupported signature type 0x{sig_type:02x}"));
        }
        let raw: [u8; 32] = public_key.try_into().map_err(|_| "an Ed25519 public key is 32 bytes")?;
        let key = VerifyingKey::from_bytes(&raw).map_err(|_| "not an Ed25519 public key")?;
        let mut h = Sha256::new();
        h.update(name.as_bytes());
        h.update([b'\n', sig_type]);
        h.update(raw);
        let key_id = h.finalize()[..4].try_into().expect("4 bytes");
        Ok(NoteKey { name: name.to_owned(), key_id, sig_type, key })
    }

    /// Parse a vkey, `<name>+<hex key ID>+base64(type ‖ public key)`.
    pub fn from_vkey(vkey: &str) -> Result<Self, String> {
        let (name, rest) = vkey.split_once('+').ok_or("not a vkey")?;
        let (id_hex, b64) = rest.split_once('+').ok_or("not a vkey")?;
        if id_hex.len() != 8 || !id_hex.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
            return Err("not a vkey".into());
        }
        let raw = b64_std(b64)?;
        let (&sig_type, key) = raw.split_first().ok_or("not a vkey")?;
        let k = NoteKey::new(name, sig_type, key)?;
        if to_hex(&k.key_id) != id_hex {
            return Err("the vkey key ID does not match its key".into());
        }
        Ok(k)
    }

    pub fn vkey(&self) -> String {
        let mut raw = vec![self.sig_type];
        raw.extend_from_slice(self.key.as_bytes());
        format!("{}+{}+{}", self.name, to_hex(&self.key_id), STANDARD.encode(raw))
    }

    /// `Some(None)`: a valid log signature. `Some(Some(t))`: a valid cosignature
    /// made at `t`. `None`: it does not verify.
    fn verify(&self, text: &str, sig: &[u8]) -> Option<Option<u64>> {
        if self.sig_type == SIG_ED25519 {
            let sig = Signature::from_slice(sig).ok()?;
            return self.key.verify_strict(text.as_bytes(), &sig).ok().map(|_| None);
        }
        if sig.len() != 8 + 64 {
            return None;
        }
        let t = u64::from_be_bytes(sig[..8].try_into().expect("8 bytes"));
        if t > MAX_SAFE_INTEGER {
            return None;
        }
        let sig = Signature::from_slice(&sig[8..]).ok()?;
        let msg = format!("cosignature/v1\ntime {t}\n{text}");
        self.key.verify_strict(msg.as_bytes(), &sig).ok().map(|_| Some(t))
    }
}

/// A key name: non-empty, at most 255 bytes, no whitespace, `+` or control character.
fn check_key_name(name: &str) -> Result<(), String> {
    let bad = |c: char| c.is_whitespace() || c == '+' || c == '\u{feff}' || c.is_control();
    if name.is_empty() || name.len() > 255 || name.chars().any(bad) {
        return Err(format!("bad key name {name:?}"));
    }
    Ok(())
}

/// Standard base64 with padding, canonical only.
fn b64_std(s: &str) -> Result<Vec<u8>, String> {
    let b = STANDARD.decode(s).map_err(|_| "not canonical base64")?;
    if STANDARD.encode(&b) != s {
        return Err("not canonical base64".into());
    }
    Ok(b)
}

fn b64url(s: &str, what: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD.decode(s).map_err(|_| format!("{what} is not base64url without padding"))
}

fn hash32(s: &str, what: &str) -> Result<[u8; 32], String> {
    b64url(s, what)?.try_into().map_err(|_| format!("{what} is not a 32-byte hash"))
}

fn root32(s: &str, what: &str) -> Result<[u8; 32], String> {
    b64_std(s).map_err(|e| format!("{what}: {e}"))?.try_into().map_err(|_| format!("{what} is not a 32-byte hash"))
}

/// Verify a signed note against `known` keys. A signature by an unknown key is
/// skipped; one by a known key must verify, or the note is refused; at least one
/// known key must have signed. Returns the text and, per known key that signed
/// (by index into `known`), the cosignature time.
pub fn verify_note(note: &str, known: &[NoteKey]) -> Result<(String, BTreeMap<usize, Option<u64>>), String> {
    let control = |c: char| (c < ' ' && c != '\n') || c == '\u{7f}';
    if note.chars().any(control) {
        return Err("note has a control character".into());
    }
    if !note.ends_with('\n') {
        return Err("note must end in a newline".into());
    }
    let cut = note.rfind("\n\n").ok_or("note has no signature block")?;
    let text = &note[..cut + 1];
    let lines: Vec<&str> = note[cut + 2..].split_terminator('\n').collect();
    if lines.is_empty() {
        return Err("note has no signatures".into());
    }
    if lines.len() > MAX_SIGS {
        return Err("too many signatures".into());
    }
    let mut signed = BTreeMap::new();
    for line in lines {
        let rest = line.strip_prefix("\u{2014} ").ok_or("bad signature line")?;
        let (name, sig_b64) = rest.split_once(' ').ok_or("bad signature line")?;
        if name.is_empty() || sig_b64.is_empty() || sig_b64.contains(char::is_whitespace) {
            return Err("bad signature line".into());
        }
        check_key_name(name)?;
        let raw = b64_std(sig_b64)?;
        if raw.len() < 5 {
            return Err("signature too short".into());
        }
        let Some(i) = known.iter().position(|k| k.name == name && k.key_id[..] == raw[..4]) else { continue };
        let t = known[i].verify(text, &raw[4..]).ok_or_else(|| format!("the signature by {name} does not verify"))?;
        signed.insert(i, t);
    }
    if signed.is_empty() {
        return Err("no known key signed the note".into());
    }
    Ok((text.to_owned(), signed))
}

/// A signed tree head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TreeHead {
    pub origin: String,
    pub size: u64,
    pub root: [u8; 32],
}

impl TreeHead {
    /// The root as the checkpoint writes it: standard base64.
    pub fn root_b64(&self) -> String {
        STANDARD.encode(self.root)
    }
}

/// Parse checkpoint text: exactly `origin\nsize\nroot\n`, no extension lines.
pub fn parse_checkpoint_text(text: &str) -> Result<TreeHead, String> {
    let lines: Vec<&str> = text.split('\n').collect();
    let [origin, size, root, ""] = lines[..] else {
        return Err("a checkpoint is exactly three lines (no extension lines)".into());
    };
    check_key_name(origin)?;
    Ok(TreeHead { origin: origin.to_owned(), size: safe_int(size).ok_or("bad tree size")?, root: root32(root, "root hash")? })
}

fn safe_int(s: &str) -> Option<u64> {
    let canonical = s == "0" || (!s.is_empty() && !s.starts_with('0') && s.bytes().all(|c| c.is_ascii_digit()));
    s.parse().ok().filter(|n| canonical && *n <= MAX_SAFE_INTEGER)
}

/// Which keys a checkpoint must be signed by.
#[derive(Clone, Debug, Default)]
pub struct CheckpointPolicy {
    /// The log keys (type 0x01), each named by its origin. Any one may sign.
    pub logs: Vec<NoteKey>,
    /// Witness keys (type 0x04).
    pub witnesses: Vec<NoteKey>,
    /// How many distinct witnesses must have cosigned.
    pub quorum: usize,
    /// Verification time, epoch seconds: refuses a cosignature from the future.
    pub now_unix: Option<u64>,
}

/// A checkpoint that verified.
#[derive(Clone, Debug)]
pub struct VerifiedCheckpoint {
    pub head: TreeHead,
    /// The vkey of the log key that signed it.
    pub log_vkey: String,
    /// Each witness that cosigned, with its cosignature time.
    pub cosigned: Vec<(String, u64)>,
}

/// Verify a checkpoint with one log key and the policy's witnesses.
fn verify_checkpoint_with(note: &str, log: &NoteKey, p: &CheckpointPolicy) -> Result<VerifiedCheckpoint, String> {
    if log.sig_type != SIG_ED25519 {
        return Err("the log key must be type 0x01".into());
    }
    let known: Vec<NoteKey> = std::iter::once(log.clone()).chain(p.witnesses.iter().cloned()).collect();
    let (text, signed) = verify_note(note, &known)?;
    let head = parse_checkpoint_text(&text)?;
    if head.origin != log.name {
        return Err(format!("origin {} is not the pinned log {}", head.origin, log.name));
    }
    if !signed.contains_key(&0) {
        return Err("the log did not sign this checkpoint".into());
    }
    let mut cosigned = Vec::new();
    for (i, t) in signed.into_iter().filter(|(i, _)| *i > 0) {
        let w = &known[i];
        let Some(t) = t.filter(|_| w.sig_type == SIG_COSIGNATURE) else { continue };
        if p.now_unix.is_some_and(|now| t > now + COSIGNATURE_SKEW_S) {
            return Err(format!("the cosignature by {} is from the future", w.name));
        }
        if !cosigned.iter().any(|(n, _)| n == &w.name) {
            cosigned.push((w.name.clone(), t));
        }
    }
    if cosigned.len() < p.quorum {
        return Err(format!("{} of {} witnesses cosigned", cosigned.len(), p.quorum));
    }
    Ok(VerifiedCheckpoint { head, log_vkey: log.vkey(), cosigned })
}

/// Verify a checkpoint against any of the policy's log keys.
pub fn verify_checkpoint(note: &str, p: &CheckpointPolicy) -> Result<VerifiedCheckpoint, String> {
    first_that_verifies(p, |log| verify_checkpoint_with(note, log, p))
}

fn first_that_verifies<T>(p: &CheckpointPolicy, f: impl Fn(&NoteKey) -> Result<T, String>) -> Result<T, String> {
    if p.logs.is_empty() {
        return Err("no log key is pinned".into());
    }
    let mut reasons: Vec<String> = Vec::new();
    for log in &p.logs {
        match f(log) {
            Ok(v) => return Ok(v),
            Err(e) if !reasons.contains(&e) => reasons.push(e),
            Err(_) => {}
        }
    }
    Err(format!("the proof does not verify: {}", reasons.join("; ")))
}

/// RFC 9162 leaf hash, `SHA-256(0x00 ‖ entry)`.
pub fn leaf_hash(entry: &[u8]) -> [u8; 32] {
    Sha256::new().chain_update([0u8]).chain_update(entry).finalize().into()
}

fn node_hash(l: &[u8; 32], r: &[u8; 32]) -> [u8; 32] {
    Sha256::new().chain_update([1u8]).chain_update(l).chain_update(r).finalize().into()
}

/// RFC 9162 §2.1.3.2: does `leaf` at `index` lead through `path` to `root` at `size`?
pub fn verify_inclusion(index: u64, size: u64, leaf: &[u8; 32], path: &[[u8; 32]], root: &[u8; 32]) -> bool {
    if index >= size {
        return false;
    }
    let (mut fnode, mut snode, mut r) = (index, size - 1, *leaf);
    for p in path {
        if snode == 0 {
            return false;
        }
        if fnode & 1 == 1 || fnode == snode {
            r = node_hash(p, &r);
            while fnode & 1 == 0 && fnode != 0 {
                fnode >>= 1;
                snode >>= 1;
            }
        } else {
            r = node_hash(&r, p);
        }
        fnode >>= 1;
        snode >>= 1;
    }
    snode == 0 && r == *root
}

/// RFC 9162 §2.1.4.2: is the tree of `first` leaves with `first_root` a prefix of
/// the tree of `second` leaves with `second_root`?
pub fn verify_consistency(first: u64, second: u64, first_root: &[u8; 32], second_root: &[u8; 32], proof: &[[u8; 32]]) -> bool {
    if first == 0 || first > second {
        return false;
    }
    if first == second {
        return proof.is_empty() && first_root == second_root;
    }
    let mut path = Vec::with_capacity(proof.len() + 1);
    if first.is_power_of_two() {
        path.push(*first_root);
    }
    path.extend_from_slice(proof);
    let Some((start, rest)) = path.split_first() else { return false };
    let (mut fnode, mut snode) = (first - 1, second - 1);
    while fnode & 1 == 1 {
        fnode >>= 1;
        snode >>= 1;
    }
    let (mut fr, mut sr) = (*start, *start);
    for c in rest {
        if snode == 0 {
            return false;
        }
        if fnode & 1 == 1 || fnode == snode {
            fr = node_hash(c, &fr);
            sr = node_hash(c, &sr);
            while fnode & 1 == 0 && fnode != 0 {
                fnode >>= 1;
                snode >>= 1;
            }
        } else {
            sr = node_hash(&sr, c);
        }
        fnode >>= 1;
        snode >>= 1;
    }
    snode == 0 && fr == *first_root && sr == *second_root
}

/// A decoded log entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Entry {
    /// A root manifest: its `seq` and `iat`, the root kid that signed it, and the
    /// SHA-256 (hex) of its compact JWS (trimmed).
    Manifest { seq: u64, iat: u64, kid: String, sha256: String },
    /// A browser release: tag, commit, and file name → SHA-256 hex.
    Release { tag: String, commit: String, files: BTreeMap<String, String> },
}

impl Entry {
    pub fn kind(&self) -> &'static str {
        match self {
            Entry::Manifest { .. } => "manifest",
            Entry::Release { .. } => "release",
        }
    }
}

/// JSON with sorted keys and no whitespace: strings, safe integers, booleans,
/// arrays and objects.
fn canonical_json(v: &Value, out: &mut String) -> Result<(), String> {
    match v {
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::String(s) => out.push_str(&serde_json::to_string(s).expect("a string serialises")),
        Value::Number(n) => match (n.as_u64(), n.as_i64()) {
            (Some(u), _) if u <= MAX_SAFE_INTEGER => out.push_str(&u.to_string()),
            (None, Some(i)) if i >= -(MAX_SAFE_INTEGER as i64) => out.push_str(&i.to_string()),
            _ => return Err("canonical JSON takes safe integers only".into()),
        },
        Value::Array(a) => {
            out.push('[');
            for (i, x) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                canonical_json(x, out)?;
            }
            out.push(']');
        }
        Value::Object(o) => {
            let mut keys: Vec<&String> = o.keys().collect();
            keys.sort();
            out.push('{');
            for (i, k) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).expect("a string serialises"));
                out.push(':');
                canonical_json(&o[k], out)?;
            }
            out.push('}');
        }
        Value::Null => return Err("canonical JSON cannot encode null".into()),
    }
    Ok(())
}

fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

fn only_fields(o: &serde_json::Map<String, Value>, fields: &[&str], kind: &str) -> Result<(), String> {
    match o.keys().find(|k| !fields.contains(&k.as_str())) {
        Some(k) => Err(format!("{kind} entry has an unexpected field {k:?}")),
        None => Ok(()),
    }
}

/// `vX.Y.Z` with an optional `-prerelease` of `[0-9A-Za-z.-]`.
fn is_release_tag(tag: &str) -> bool {
    let Some(rest) = tag.strip_prefix('v') else { return false };
    let (core, pre) = match rest.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (rest, None),
    };
    let nums: Vec<&str> = core.split('.').collect();
    nums.len() == 3
        && nums.iter().all(|n| !n.is_empty() && n.bytes().all(|c| c.is_ascii_digit()))
        && pre.is_none_or(|p| !p.is_empty() && p.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'.' || c == b'-'))
}

/// Decode an entry. Only the canonical encoding of a `manifest` or `release`
/// entry, with exactly its fields, is accepted.
pub fn decode_entry(bytes: &[u8]) -> Result<Entry, String> {
    let s = std::str::from_utf8(bytes).map_err(|_| "not an octet log entry")?;
    let rest = s.strip_prefix(ENTRY_TAG).and_then(|r| r.strip_prefix('\n')).ok_or("not an octet log entry")?;
    let (kind, body) = rest.split_once('\n').ok_or("not an octet log entry")?;
    match kind {
        "manifest" | "release" => {}
        "list" | "verdict-hour" => return Err(format!("this verifier does not decode {kind} entries yet")),
        _ => return Err("not an octet log entry".into()),
    }
    let v: Value = serde_json::from_str(body).map_err(|_| "entry body is not JSON")?;
    let mut canonical = String::new();
    canonical_json(&v, &mut canonical)?;
    if canonical != body {
        return Err("entry is not canonical".into());
    }
    let o = v.as_object().ok_or("entry body is not a JSON object")?;
    let str_of = |f: &str| o.get(f).and_then(Value::as_str);
    let int_of = |f: &str| o.get(f).and_then(Value::as_u64).filter(|n| (1..=MAX_SAFE_INTEGER).contains(n));
    if kind == "manifest" {
        only_fields(o, &["seq", "iat", "kid", "sha256"], kind)?;
        let seq = int_of("seq").ok_or("manifest seq must be a positive integer")?;
        let iat = int_of("iat").ok_or("manifest iat must be epoch seconds")?;
        let kid = str_of("kid")
            .filter(|k| (1..=64).contains(&k.len()) && k.bytes().all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c)))
            .ok_or("manifest kid must be a root kid")?;
        let sha256 = str_of("sha256").filter(|h| is_hex(h, 64)).ok_or("manifest sha256 must be SHA-256 hex")?;
        return Ok(Entry::Manifest { seq, iat, kid: kid.to_owned(), sha256: sha256.to_owned() });
    }
    only_fields(o, &["tag", "commit", "files"], kind)?;
    let tag = str_of("tag").filter(|t| is_release_tag(t)).ok_or("release tag must be vX.Y.Z")?;
    let commit = str_of("commit").filter(|c| is_hex(c, 40)).ok_or("release commit must be a full SHA-1")?;
    let files = o.get("files").and_then(Value::as_object).filter(|f| !f.is_empty()).ok_or("release files must be SHA-256 hex")?;
    let mut out = BTreeMap::new();
    for (name, h) in files {
        let plain = (1..=128).contains(&name.len()) && name.bytes().all(|c| c.is_ascii_alphanumeric() || b"._+-".contains(&c));
        if !plain {
            return Err("release file names must be plain file names".into());
        }
        let h = h.as_str().filter(|h| is_hex(h, 64)).ok_or("release files must be SHA-256 hex")?;
        out.insert(name.clone(), h.to_owned());
    }
    Ok(Entry::Release { tag: tag.to_owned(), commit: commit.to_owned(), files: out })
}

/// An offline inclusion proof, as octet's log hands it out.
#[derive(Clone, Debug)]
pub struct ProofBundle {
    pub index: u64,
    pub size: u64,
    pub entry: Vec<u8>,
    pub path: Vec<[u8; 32]>,
    /// The signed checkpoint note.
    pub checkpoint: String,
}

fn safe_u64(v: Option<&Value>, what: &str) -> Result<u64, String> {
    v.and_then(Value::as_u64).filter(|n| *n <= MAX_SAFE_INTEGER).ok_or_else(|| format!("{what} is not a non-negative integer"))
}

fn hash_list(v: Option<&Value>, what: &str) -> Result<Vec<[u8; 32]>, String> {
    let a = v.and_then(Value::as_array).ok_or_else(|| format!("{what} is not an array"))?;
    if a.len() > MAX_PATH {
        return Err(format!("{what} is longer than {MAX_PATH} hashes"));
    }
    a.iter()
        .enumerate()
        .map(|(i, h)| hash32(h.as_str().unwrap_or(""), &format!("{what}[{i}]")))
        .collect()
}

/// Parse a proof bundle, `{v: 1, index, size, entry, path, checkpoint}`. A
/// bundle that carries a `verdict` proof (a verdict token in an hour batch) is
/// refused: this verifier does not check those yet.
pub fn parse_bundle(json: &str) -> Result<ProofBundle, String> {
    let v: Value = serde_json::from_str(json).map_err(|e| format!("proof bundle is not JSON: {e}"))?;
    let o = v.as_object().ok_or("proof bundle is not a JSON object")?;
    if o.contains_key("verdict") {
        return Err("this verifier does not check verdict proofs yet".into());
    }
    only_fields(o, &["v", "index", "size", "entry", "path", "checkpoint"], "proof bundle")?;
    if o.get("v").and_then(Value::as_u64) != Some(1) {
        return Err("unknown bundle version".into());
    }
    Ok(ProofBundle {
        index: safe_u64(o.get("index"), "index")?,
        size: safe_u64(o.get("size"), "size")?,
        entry: b64url(o.get("entry").and_then(Value::as_str).ok_or("bundle has no entry")?, "entry")?,
        path: hash_list(o.get("path"), "path")?,
        checkpoint: o.get("checkpoint").and_then(Value::as_str).ok_or("bundle has no checkpoint")?.to_owned(),
    })
}

/// A proof bundle that verified.
#[derive(Clone, Debug)]
pub struct VerifiedBundle {
    pub index: u64,
    pub entry: Entry,
    pub checkpoint: VerifiedCheckpoint,
}

/// Verify a proof bundle: the checkpoint against the policy, the inclusion path
/// to its root, then the entry. Any failure refuses the bundle.
pub fn verify_bundle(b: &ProofBundle, p: &CheckpointPolicy) -> Result<VerifiedBundle, String> {
    first_that_verifies(p, |log| {
        let cp = verify_checkpoint_with(&b.checkpoint, log, p)?;
        if cp.head.size != b.size {
            return Err(format!("the proof is for size {}, the checkpoint is {}", b.size, cp.head.size));
        }
        if !verify_inclusion(b.index, b.size, &leaf_hash(&b.entry), &b.path, &cp.head.root) {
            return Err("the inclusion proof does not lead to the checkpoint root".into());
        }
        Ok(VerifiedBundle { index: b.index, entry: decode_entry(&b.entry)?, checkpoint: cp })
    })
}

/// An RFC 9162 consistency proof between two tree heads.
#[derive(Clone, Debug)]
pub struct ConsistencyProof {
    pub first: u64,
    pub second: u64,
    pub first_root: [u8; 32],
    pub second_root: [u8; 32],
    pub proof: Vec<[u8; 32]>,
}

/// Parse `{first, second, first_root, second_root, proof}`: roots in standard
/// base64, proof hashes in base64url.
pub fn parse_consistency(json: &str) -> Result<ConsistencyProof, String> {
    let v: Value = serde_json::from_str(json).map_err(|e| format!("consistency proof is not JSON: {e}"))?;
    let o = v.as_object().ok_or("consistency proof is not a JSON object")?;
    only_fields(o, &["first", "second", "first_root", "second_root", "proof"], "consistency proof")?;
    let root = |f: &str| root32(o.get(f).and_then(Value::as_str).unwrap_or(""), f);
    Ok(ConsistencyProof {
        first: safe_u64(o.get("first"), "first")?,
        second: safe_u64(o.get("second"), "second")?,
        first_root: root("first_root")?,
        second_root: root("second_root")?,
        proof: hash_list(o.get("proof"), "proof")?,
    })
}

/// Is `current` consistent with the tree head kept from before? Equal sizes need
/// equal roots; otherwise `proof` must lead from the smaller head to the larger
/// one. Both heads must be the same log's.
pub fn check_consistency(kept: &TreeHead, current: &TreeHead, proof: Option<&ConsistencyProof>) -> Result<(), String> {
    if kept.origin != current.origin {
        return Err(format!("the kept tree head is for {}, the checkpoint for {}", kept.origin, current.origin));
    }
    if kept.size == current.size {
        return if kept.root == current.root {
            Ok(())
        } else {
            Err(format!("the log has two different roots for size {}: it forked", kept.size))
        };
    }
    let (old, new) = if kept.size < current.size { (kept, current) } else { (current, kept) };
    let p = proof.ok_or_else(|| format!("a consistency proof from size {} to {} is needed", old.size, new.size))?;
    if (p.first, p.second) != (old.size, new.size) {
        return Err(format!("the consistency proof is from size {} to {}, not {} to {}", p.first, p.second, old.size, new.size));
    }
    if p.first_root != old.root || p.second_root != new.root {
        return Err("the consistency proof is for other roots".into());
    }
    if !verify_consistency(p.first, p.second, &p.first_root, &p.second_root, &p.proof) {
        return Err(format!("the consistency proof from size {} to {} does not verify", old.size, new.size));
    }
    Ok(())
}

/// Verify a root manifest with the pinned `roots` and return it with the log
/// keys its `logKeys` lists (empty when it lists none). Each must be an Ed25519
/// public JWK with `octet_purpose` "tlog" and the `octet_origin` it signs as.
pub fn log_keys_from_manifest(jws: &str, roots: &[Jwk]) -> Result<(Manifest, Vec<NoteKey>), String> {
    let manifest = verify_manifest(jws, roots)?;
    let payload = jws.trim().split('.').nth(1).ok_or("manifest is not a compact JWS")?;
    let m: Value = serde_json::from_slice(&b64url(payload, "manifest payload")?).map_err(|_| "manifest is not JSON")?;
    let Some(list) = m.get("logKeys") else { return Ok((manifest, Vec::new())) };
    let list = list.as_array().ok_or("manifest logKeys is not an array")?;
    let mut keys = Vec::new();
    for (i, k) in list.iter().enumerate() {
        let s = |f: &str| k.get(f).and_then(Value::as_str);
        let ok = s("kty") == Some("OKP") && s("crv") == Some("Ed25519") && s("octet_purpose") == Some(LOG_PURPOSE) && k.get("d").is_none();
        let (Some(x), Some(origin), true) = (s("x"), s("octet_origin"), ok) else {
            return Err(format!("manifest logKeys[{i}] is not an Ed25519 public JWK with octet_purpose \"tlog\" and octet_origin"));
        };
        let raw = b64url(x, &format!("manifest logKeys[{i}].x"))?;
        keys.push(NoteKey::new(origin, SIG_ED25519, &raw).map_err(|e| format!("manifest logKeys[{i}]: {e}"))?);
    }
    Ok((manifest, keys))
}

/// The SHA-256 (hex) a `manifest` entry records for a root manifest JWS file.
pub fn manifest_sha256(jws: &str) -> String {
    to_hex(&Sha256::digest(jws.trim().as_bytes()))
}

/// Lowercase hex.
pub fn to_hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(b: u8) -> [u8; 32] {
        leaf_hash(&[b])
    }

    /// The largest power of two below `n` (n > 1).
    fn split(n: usize) -> usize {
        1 << (usize::BITS - 1 - (n - 1).leading_zeros())
    }

    /// Root of leaves `l` by RFC 9162 §2.1.1.
    fn root(l: &[[u8; 32]]) -> [u8; 32] {
        if l.len() == 1 {
            return l[0];
        }
        let k = split(l.len());
        node_hash(&root(&l[..k]), &root(&l[k..]))
    }

    fn inclusion_path(l: &[[u8; 32]], m: usize) -> Vec<[u8; 32]> {
        if l.len() == 1 {
            return vec![];
        }
        let k = split(l.len());
        if m < k {
            let mut p = inclusion_path(&l[..k], m);
            p.push(root(&l[k..]));
            p
        } else {
            let mut p = inclusion_path(&l[k..], m - k);
            p.push(root(&l[..k]));
            p
        }
    }

    fn subproof(m: usize, l: &[[u8; 32]], complete: bool) -> Vec<[u8; 32]> {
        let n = l.len();
        if m == n {
            return if complete { vec![] } else { vec![root(l)] };
        }
        let k = split(n);
        if m <= k {
            let mut p = subproof(m, &l[..k], complete);
            p.push(root(&l[k..]));
            p
        } else {
            let mut p = subproof(m - k, &l[k..], false);
            p.push(root(&l[..k]));
            p
        }
    }

    #[test]
    fn inclusion_and_consistency_hold_for_every_size_up_to_33() {
        let leaves: Vec<[u8; 32]> = (0..33u8).map(h).collect();
        for n in 1..=leaves.len() {
            let r = root(&leaves[..n]);
            for i in 0..n {
                let p = inclusion_path(&leaves[..n], i);
                assert!(verify_inclusion(i as u64, n as u64, &leaves[i], &p, &r), "leaf {i} of {n}");
                assert!(!verify_inclusion(i as u64, n as u64, &h(200), &p, &r));
                if n > 1 {
                    assert!(!verify_inclusion(((i + 1) % n) as u64, n as u64, &leaves[i], &p, &r));
                    let mut short = p.clone();
                    short.pop();
                    assert!(!verify_inclusion(i as u64, n as u64, &leaves[i], &short, &r));
                }
                let mut long = p.clone();
                long.push(r);
                assert!(!verify_inclusion(i as u64, n as u64, &leaves[i], &long, &r));
            }
            for m in 1..=n {
                let rm = root(&leaves[..m]);
                let p = subproof(m, &leaves[..n], true);
                assert!(verify_consistency(m as u64, n as u64, &rm, &r, &p), "{m} -> {n}");
                if m < n {
                    assert!(!verify_consistency(m as u64, n as u64, &h(201), &r, &p));
                    assert!(!verify_consistency(m as u64, n as u64, &rm, &h(201), &p));
                    let mut bad = p.clone();
                    bad[0][0] ^= 1;
                    assert!(!verify_consistency(m as u64, n as u64, &rm, &r, &bad));
                }
            }
        }
        assert!(!verify_consistency(0, 3, &h(0), &h(0), &[]));
        assert!(!verify_inclusion(0, 0, &h(0), &[], &h(0)));
    }

    #[test]
    fn entries_must_be_canonical_with_exactly_their_fields() {
        let ok = br#"octet-tlog/v1
manifest
{"iat":1,"kid":"octet-root-a-2026-10","seq":4,"sha256":"0000000000000000000000000000000000000000000000000000000000000000"}"#;
        assert!(matches!(decode_entry(ok), Ok(Entry::Manifest { seq: 4, .. })));
        let reordered = String::from_utf8_lossy(ok).replace(r#""iat":1,"kid":"octet-root-a-2026-10""#, r#""kid":"octet-root-a-2026-10","iat":1"#);
        assert_eq!(decode_entry(reordered.as_bytes()).unwrap_err(), "entry is not canonical");
        let spaced = String::from_utf8_lossy(ok).replace(r#""iat":1"#, r#""iat": 1"#);
        assert_eq!(decode_entry(spaced.as_bytes()).unwrap_err(), "entry is not canonical");
        let extra = String::from_utf8_lossy(ok).replace(r#"{"iat":1"#, r#"{"extra":true,"iat":1"#);
        assert!(decode_entry(extra.as_bytes()).unwrap_err().contains("unexpected field"));
        let float = String::from_utf8_lossy(ok).replace(r#""iat":1"#, r#""iat":1.0"#);
        assert!(decode_entry(float.as_bytes()).is_err());
        assert!(decode_entry(b"octet-tlog/v1\nlist\n{}").unwrap_err().contains("does not decode"));
        assert!(decode_entry(b"octet-tlog/v2\nmanifest\n{}").is_err());
        assert!(is_release_tag("v1.8.1") && is_release_tag("v2.0.0-rc.1"));
        assert!(!is_release_tag("1.8.1") && !is_release_tag("v1.8") && !is_release_tag("v1.8.1-"));
    }

    #[test]
    fn the_pinned_vkey_parses_and_round_trips() {
        let k = NoteKey::from_vkey(PROD_LOG_VKEY).unwrap();
        assert_eq!((k.name.as_str(), k.sig_type, to_hex(&k.key_id)), (PROD_LOG_ORIGIN, SIG_ED25519, "7cbbf8dc".to_string()));
        assert_eq!(k.vkey(), PROD_LOG_VKEY);
        assert!(NoteKey::from_vkey(&PROD_LOG_VKEY.replace("+7cbbf8dc+", "+7cbbf8dd+")).is_err());
    }

    #[test]
    fn checkpoints_have_no_extension_lines_or_noncanonical_sizes() {
        let r = STANDARD.encode([0u8; 32]);
        assert!(parse_checkpoint_text(&format!("o\n6\n{r}\n")).is_ok());
        assert!(parse_checkpoint_text(&format!("o\n6\n{r}\next\n")).is_err());
        assert!(parse_checkpoint_text(&format!("o\n06\n{r}\n")).is_err());
        assert!(parse_checkpoint_text(&format!("o\n+6\n{r}\n")).is_err());
        assert!(parse_checkpoint_text(&format!("o\n9007199254740992\n{r}\n")).is_err());
    }
}
