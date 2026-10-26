//! Cross-check **caller metadata** — content an integrator bound into a proof —
//! against the signed proof (phase A of the caller-metadata binding spec).
//!
//! A `callerMetadata` stage, chained and hardware-signed like every other stage,
//! commits the caller's content by digest only: `data_hash = SHA256(preimage)`,
//! where
//!
//! ```text
//! preimage = "octet-caller-metadata-v1"
//!          ‖ u32_be(entry_count)
//!          ‖ for each entry, in the caller's order:
//!              u32_be(len(key)) ‖ key
//!            ‖ u32_be(len(contentType)) ‖ contentType
//!            ‖ u64_be(size)
//!            ‖ u32_be(32) ‖ entry_digest
//! entry_digest = SHA256(salt ‖ value)    salt ∈ {0, 16, 32} bytes, size = len(value)
//! ```
//!
//! The stage holds only a hash, so whoever presents the proof hands over a
//! [`CallerManifest`] (key, contentType, size, salt and entry digest per entry,
//! in preimage order) plus, per key, the content itself or nothing (digest
//! only). This module recomputes the preimage from the manifest, checks it
//! against the stage, and checks each presented value against its entry digest.
//!
//! The salt is not in the preimage: `entry_digest` commits to it, and the signed
//! `size` fixes where the salt ends and the value begins.
//!
//! Like `sessionBinding`, the stage is covered by `stage-chain`,
//! `stage-signatures` and `chain-assembly`, so removing or editing it breaks the
//! proof regardless of this check. This check adds the binding to *specific*
//! content.
//!
//! The check is separate from [`crate::verify::verify`] (its inputs are not in
//! `VerifyOptions`): run [`check_caller_metadata`] and add the result with
//! [`crate::verify::Report::add_caller_metadata`]. An unresolved entry makes the
//! report INCONCLUSIVE — see [`crate::verify::Report::content_resolved`].
//!
//! **Phase B.** A proof may also list its committed entries readably in
//! `LocationProof` field 19 (`caller_manifest`: key, contentType, size and entry
//! digest per entry, no salt, no value, plus an optional `locator`). Field 19 is
//! not signed; [`check_caller_manifest`] recomputes the stage hash from it, and
//! `verify` adds that `caller-manifest` line whenever the proof carries field 19.
//! A presenter manifest handed over for such a proof must agree with field 19
//! entry by entry (`MANIFEST_MISMATCH` otherwise). The `locator` is outside the
//! preimage: an unauthenticated hint that never affects a result.

use std::io::Read;
use std::path::PathBuf;

use sha2::{Digest, Sha256};

use crate::navigate::LocationProof;
use crate::verify::{Check, Status};

/// Stage that commits the caller's content in-proof.
pub const CALLER_METADATA_STAGE: &str = "callerMetadata";
/// Domain-separation tag opening the preimage. Raw ASCII, no NUL, not itself
/// length-prefixed (the `sessionBinding` / `semanticFields` shape).
pub const CALLER_METADATA_DOMAIN: &[u8] = b"octet-caller-metadata-v1";
/// At most this many entries (and at least one).
pub const MAX_ENTRIES: usize = 16;
/// A key is 1 to 64 bytes of UTF-8.
pub const MAX_KEY_LEN: usize = 64;
/// A contentType is 1 to 127 bytes.
pub const MAX_CONTENT_TYPE_LEN: usize = 127;
/// The preimage is at most 16 KiB.
pub const MAX_PREIMAGE_LEN: usize = 16 * 1024;
/// The allowed salt lengths, in bytes.
pub const SALT_LENS: [usize; 3] = [0, 16, 32];

const NAME: &str = "caller-metadata";
const STREAM_BUF: usize = 64 * 1024;

/// One committed entry, as the presenter's manifest lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ManifestEntry {
    pub key: String,
    pub content_type: String,
    /// `len(value)`, without the salt.
    pub size: u64,
    /// 0, 16 or 32 bytes. Travels with the content, never in the proof.
    pub salt: Vec<u8>,
    /// `SHA256(salt ‖ value)`.
    pub entry_digest: [u8; 32],
}

/// The presenter's manifest: the committed entries in preimage order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CallerManifest {
    pub entries: Vec<ManifestEntry>,
}

impl CallerManifest {
    /// Enforce the spec's limits: 1 to 16 entries, unique 1–64-byte keys, a
    /// 1–127-byte RFC 6838 `type/subtype` contentType, and a 0, 16 or 32-byte
    /// salt. A breach is an error, never a truncation.
    pub fn validate(&self) -> Result<(), String> {
        let n = self.entries.len();
        if !(1..=MAX_ENTRIES).contains(&n) {
            return Err(format!("{n} entries; a manifest has 1 to {MAX_ENTRIES}"));
        }
        for (i, e) in self.entries.iter().enumerate() {
            let at = format!("entry {i} ({:?})", e.key);
            if !(1..=MAX_KEY_LEN).contains(&e.key.len()) {
                return Err(format!("{at}: key is {} bytes; it must be 1 to {MAX_KEY_LEN}", e.key.len()));
            }
            if !(1..=MAX_CONTENT_TYPE_LEN).contains(&e.content_type.len()) {
                return Err(format!(
                    "{at}: contentType is {} bytes; it must be 1 to {MAX_CONTENT_TYPE_LEN}",
                    e.content_type.len()
                ));
            }
            if !is_media_type(&e.content_type) {
                return Err(format!("{at}: contentType {:?} is not an RFC 6838 type/subtype", e.content_type));
            }
            if !SALT_LENS.contains(&e.salt.len()) {
                return Err(format!("{at}: salt is {} bytes; it must be 0, 16 or 32", e.salt.len()));
            }
            if self.entries[..i].iter().any(|p| p.key == e.key) {
                return Err(format!("{at}: duplicate key"));
            }
        }
        Ok(())
    }

    /// The exact bytes the `callerMetadata` stage hashes. Validates first.
    pub fn preimage(&self) -> Result<Vec<u8>, String> {
        self.validate()?;
        let mut m = Vec::with_capacity(CALLER_METADATA_DOMAIN.len() + 4 + self.entries.len() * 128);
        m.extend_from_slice(CALLER_METADATA_DOMAIN);
        m.extend_from_slice(&(self.entries.len() as u32).to_be_bytes());
        for e in &self.entries {
            m.extend_from_slice(&(e.key.len() as u32).to_be_bytes());
            m.extend_from_slice(e.key.as_bytes());
            m.extend_from_slice(&(e.content_type.len() as u32).to_be_bytes());
            m.extend_from_slice(e.content_type.as_bytes());
            m.extend_from_slice(&e.size.to_be_bytes());
            m.extend_from_slice(&32u32.to_be_bytes());
            m.extend_from_slice(&e.entry_digest);
        }
        // Unreachable under the other limits (16 maximal entries are ~4 KiB),
        // but the spec states it, so enforce it.
        if m.len() > MAX_PREIMAGE_LEN {
            return Err(format!("preimage is {} bytes; at most {MAX_PREIMAGE_LEN}", m.len()));
        }
        Ok(m)
    }

    /// `SHA256(preimage)`: what the `callerMetadata` stage's `data_hash` must be.
    pub fn stage_hash(&self) -> Result<[u8; 32], String> {
        Ok(Sha256::digest(self.preimage()?).into())
    }

    /// Parse the portable presenter manifest:
    /// `{"v":1,"entries":[{"key","contentType","size","salt","sha256"}]}`, with
    /// `salt` and `sha256` in hex (`salt` may be empty) and entries in preimage
    /// order. Every field is required; an unknown field or a `v` other than 1 is
    /// an error. Limits are checked by [`CallerManifest::validate`], not here.
    #[cfg(feature = "caller-metadata")]
    pub fn from_json(bytes: &[u8]) -> Result<Self, String> {
        use serde_json::Value;
        let v: Value = serde_json::from_slice(bytes).map_err(|e| format!("manifest is not JSON: {e}"))?;
        let top = v.as_object().ok_or("manifest is not a JSON object")?;
        if let Some(k) = top.keys().find(|k| !["v", "entries"].contains(&k.as_str())) {
            return Err(format!("manifest has an unknown field {k:?}"));
        }
        if top.get("v").and_then(Value::as_u64) != Some(1) {
            return Err("manifest \"v\" is not 1".into());
        }
        let list = top.get("entries").and_then(Value::as_array).ok_or("manifest has no \"entries\" array")?;
        let mut entries = Vec::with_capacity(list.len());
        for (i, e) in list.iter().enumerate() {
            let o = e.as_object().ok_or_else(|| format!("entry {i} is not an object"))?;
            const FIELDS: [&str; 5] = ["key", "contentType", "size", "salt", "sha256"];
            if let Some(k) = o.keys().find(|k| !FIELDS.contains(&k.as_str())) {
                return Err(format!("entry {i} has an unknown field {k:?}"));
            }
            let s = |f: &str| {
                o.get(f).and_then(Value::as_str).ok_or_else(|| format!("entry {i} has no string \"{f}\""))
            };
            let size = o.get("size").and_then(Value::as_u64).ok_or_else(|| format!("entry {i} has no integer \"size\""))?;
            let salt = from_hex(s("salt")?).map_err(|e| format!("entry {i} salt: {e}"))?;
            let digest = from_hex(s("sha256")?).map_err(|e| format!("entry {i} sha256: {e}"))?;
            let entry_digest: [u8; 32] =
                digest.try_into().map_err(|d: Vec<u8>| format!("entry {i} sha256 is {} bytes, not 32", d.len()))?;
            entries.push(ManifestEntry {
                key: s("key")?.to_owned(),
                content_type: s("contentType")?.to_owned(),
                size,
                salt,
                entry_digest,
            });
        }
        Ok(CallerManifest { entries })
    }
}

/// RFC 6838 §4.2 `type-name "/" subtype-name`: each a restricted-name (first
/// char ALPHA/DIGIT, then ALPHA/DIGIT/`!#$&-^_.+`), no parameters. Compared byte
/// for byte elsewhere; case is preserved, not folded.
fn is_media_type(s: &str) -> bool {
    let restricted = |p: &str| {
        let b = p.as_bytes();
        !b.is_empty()
            && b[0].is_ascii_alphanumeric()
            && b.iter().all(|c| c.is_ascii_alphanumeric() || b"!#$&-^_.+".contains(c))
    };
    matches!(s.split_once('/'), Some((t, st)) if restricted(t) && restricted(st))
}

#[cfg(feature = "caller-metadata")]
fn from_hex(s: &str) -> Result<Vec<u8>, String> {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) {
        return Err("odd-length hex".into());
    }
    let nib = |c: u8| match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err("not hex".to_string()),
    };
    b.chunks(2).map(|p| Ok((nib(p[0])? << 4) | nib(p[1])?)).collect()
}

/// `SHA256(salt ‖ value)`.
pub fn entry_digest(salt: &[u8], value: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(salt);
    h.update(value);
    h.finalize().into()
}

/// Stream `SHA256(salt ‖ value)` over a reader with bounded memory, returning
/// the digest and `len(value)`. Stops reading once more than `limit` bytes have
/// been seen (the digest is then meaningless; the length says why).
pub fn entry_digest_reader(salt: &[u8], mut r: impl Read, limit: u64) -> std::io::Result<([u8; 32], u64)> {
    let mut h = EntryHasher::new(salt);
    let mut buf = vec![0u8; STREAM_BUF];
    loop {
        let k = match r.read(&mut buf) {
            Ok(0) => break,
            Ok(k) => k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        };
        h.update(&buf[..k]);
        if h.n > limit {
            break;
        }
    }
    Ok(h.finalize())
}

/// Content presented for one key.
pub enum Content<'a> {
    /// The value's bytes.
    Bytes(&'a [u8]),
    /// A file holding the value, streamed.
    File(PathBuf),
    /// The value, hashed by the verifying party itself with an [`EntryHasher`]
    /// (for example a browser page streaming a large file in chunks), as
    /// `(SHA256(salt ‖ value), len(value))`. It counts as content, so build it
    /// only from bytes you read yourself, never from a digest someone handed you:
    /// a presenter's own digest is what the manifest already carries.
    Hashed { entry_digest: [u8; 32], size: u64 },
    /// Content was referenced but could not be obtained (a failed locator fetch,
    /// say); the string says why. The entry is unresolved.
    Unavailable(String),
}

/// Incremental `SHA256(salt ‖ value)` with bounded memory, for a caller that
/// reads the value in chunks (a browser page slicing a `File`, say). Feed the
/// entry's salt from the presenter manifest, then the value; the result goes
/// into [`Content::Hashed`].
pub struct EntryHasher {
    h: Sha256,
    n: u64,
}

impl EntryHasher {
    pub fn new(salt: &[u8]) -> Self {
        let mut h = Sha256::new();
        h.update(salt);
        EntryHasher { h, n: 0 }
    }

    pub fn update(&mut self, chunk: &[u8]) {
        self.h.update(chunk);
        self.n += chunk.len() as u64;
    }

    /// `(SHA256(salt ‖ value), len(value))`.
    pub fn finalize(self) -> ([u8; 32], u64) {
        (self.h.finalize().into(), self.n)
    }
}

/// Which entries the verifier must see as content, not just as a digest.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum RequireContent {
    /// Digest-only entries are fine (the default).
    #[default]
    None,
    /// These keys (`--require-content <key>`).
    Keys(Vec<String>),
    /// Every entry (`--require-content-all`).
    All,
}

/// What the presenter handed over, plus the relying party's requirements.
#[derive(Default)]
pub struct CallerMetadataInputs<'a> {
    /// The presenter manifest, or the reason it could not be parsed (reported
    /// as `MANIFEST_INVALID`). `None`: no manifest was presented.
    pub manifest: Option<Result<CallerManifest, String>>,
    /// Content per key. Keys absent here are digest-only.
    pub content: Vec<(String, Content<'a>)>,
    pub require_content: RequireContent,
    /// `require_caller_metadata`: a proof without the stage FAILs instead of
    /// NOT-CHECKED.
    pub require_stage: bool,
}

/// The typed result of [`check_caller_metadata`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallerMetadataOutcome {
    /// PASS: the manifest recomputes the stage, and every presented value matches.
    Verified,
    /// NOT-CHECKED: no stage (asserts nothing), or nothing was presented.
    NotChecked,
    /// FAIL: `require_caller_metadata` (or required content) but no stage.
    StageMissing,
    /// FAIL `CONTENT_MISMATCH`.
    ContentMismatch,
    /// FAIL `MANIFEST_INVALID`.
    ManifestInvalid,
    /// FAIL `MANIFEST_MISMATCH`: the presenter manifest differs from the proof's
    /// own field 19.
    ManifestMismatch,
    /// INCONCLUSIVE `CONTENT_UNRESOLVED` (exit 3); never VALID.
    ContentUnresolved,
}

impl CallerMetadataOutcome {
    /// The spec's result name, where it has one.
    pub fn code(self) -> Option<&'static str> {
        match self {
            Self::ContentMismatch => Some("CONTENT_MISMATCH"),
            Self::ManifestInvalid => Some("MANIFEST_INVALID"),
            Self::ManifestMismatch => Some("MANIFEST_MISMATCH"),
            Self::ContentUnresolved => Some("CONTENT_UNRESOLVED"),
            _ => None,
        }
    }

    fn status(self) -> Status {
        match self {
            Self::Verified => Status::Pass,
            Self::NotChecked => Status::NotChecked,
            // WARN is reserved for this outcome on the `caller-metadata` check,
            // which is how `Report::content_resolved` recognises it.
            Self::ContentUnresolved => Status::Warn,
            Self::StageMissing | Self::ContentMismatch | Self::ManifestInvalid | Self::ManifestMismatch => Status::Fail,
        }
    }
}

/// The result of [`check_caller_metadata`]: the typed outcome, entry counts, and
/// the `caller-metadata` report line.
pub struct CallerMetadataResult {
    pub outcome: CallerMetadataOutcome,
    /// Entries whose presented value matched.
    pub by_content: usize,
    /// Entries accepted on their digest alone.
    pub by_digest: usize,
    pub check: Check,
}

fn result(outcome: CallerMetadataOutcome, detail: String) -> CallerMetadataResult {
    let detail = match outcome.code() {
        Some(c) => format!("{c}: {detail}"),
        None => detail,
    };
    CallerMetadataResult {
        outcome,
        by_content: 0,
        by_digest: 0,
        check: Check { name: NAME, status: outcome.status(), detail },
    }
}

/// Check the proof's `callerMetadata` stage against the presented manifest and
/// content. Worst state wins: any mismatch FAILs; otherwise an unresolved entry
/// is INCONCLUSIVE; otherwise PASS.
pub fn check_caller_metadata(proof: &LocationProof, inputs: &CallerMetadataInputs) -> CallerMetadataResult {
    use CallerMetadataOutcome::*;
    let stage = proof.stage_attestations.iter().find(|s| s.stage == CALLER_METADATA_STAGE);
    let presented = inputs.manifest.is_some() || !inputs.content.is_empty();

    let Some(stage) = stage else {
        return if inputs.require_stage || inputs.require_content != RequireContent::None {
            result(StageMissing, "caller metadata required but the proof carries no callerMetadata stage".into())
        } else if presented {
            // Like a supplied session nonce over a proof without sessionBinding:
            // the presenter asserts content the proof does not commit.
            result(ContentMismatch, "content was presented but the proof carries no callerMetadata stage, so it commits none".into())
        } else {
            result(NotChecked, "proof carries no callerMetadata stage; it asserts no caller content".into())
        };
    };

    let manifest = match &inputs.manifest {
        None if !inputs.content.is_empty() => {
            return result(ContentUnresolved, "content was presented without a manifest, so it can't be matched to the stage".into())
        }
        None if inputs.require_content != RequireContent::None => {
            return result(ContentUnresolved, "content is required but no manifest was presented".into())
        }
        None => {
            return result(NotChecked, "proof commits caller content (callerMetadata stage); no manifest presented, content not checked".into())
        }
        Some(Err(e)) => return result(ManifestInvalid, e.clone()),
        Some(Ok(m)) => m,
    };

    let stage_hash = match manifest.stage_hash() {
        Ok(h) => h,
        Err(e) => return result(ManifestInvalid, e),
    };
    for (i, (key, _)) in inputs.content.iter().enumerate() {
        if !manifest.entries.iter().any(|e| &e.key == key) {
            return result(ManifestInvalid, format!("content supplied for key {key:?}, which the manifest does not list"));
        }
        if inputs.content[..i].iter().any(|(k, _)| k == key) {
            return result(ManifestInvalid, format!("content supplied twice for key {key:?}"));
        }
    }
    // Phase B: a proof that lists its own manifest (field 19) must agree with
    // the presenter's, entry by entry, before any content is looked at.
    if let Some(field) = &proof.caller_manifest {
        let diff = match manifest_from_proof(field) {
            Ok(own) => first_difference(manifest, &own),
            Err(e) => Some(format!("field 19 is not a valid manifest ({e})")),
        };
        if let Some(d) = diff {
            return result(ManifestMismatch, format!("the presenter manifest differs from field 19: {d}"));
        }
    }
    if stage_hash.as_slice() != stage.data_hash.as_slice() {
        return result(ContentMismatch, "the manifest does not recompute the callerMetadata stage hash".into());
    }
    if let RequireContent::Keys(keys) = &inputs.require_content {
        if let Some(k) = keys.iter().find(|k| !manifest.entries.iter().any(|e| &e.key == *k)) {
            return result(ContentMismatch, format!("content is required for key {k:?}, which the proof does not commit"));
        }
    }

    let required = |key: &str| match &inputs.require_content {
        RequireContent::None => false,
        RequireContent::All => true,
        RequireContent::Keys(k) => k.iter().any(|x| x == key),
    };
    let (mut by_content, mut by_digest) = (0, 0);
    let (mut mismatched, mut unresolved) = (Vec::new(), Vec::new());
    for e in &manifest.entries {
        let content = inputs.content.iter().find(|(k, _)| k == &e.key).map(|(_, c)| c);
        let got = match content {
            None if required(&e.key) => {
                unresolved.push(format!("{:?}: required but not presented", e.key));
                continue;
            }
            None => {
                by_digest += 1;
                continue;
            }
            Some(Content::Unavailable(why)) => {
                unresolved.push(format!("{:?}: {why}", e.key));
                continue;
            }
            Some(Content::Bytes(b)) => Ok((entry_digest(&e.salt, b), b.len() as u64)),
            Some(Content::Hashed { entry_digest, size }) => Ok((*entry_digest, *size)),
            Some(Content::File(p)) => std::fs::File::open(p)
                .and_then(|f| entry_digest_reader(&e.salt, f, e.size))
                .map_err(|err| format!("{:?}: can't read {}: {err}", e.key, p.display())),
        };
        match got {
            Err(why) => unresolved.push(why),
            Ok((_, n)) if n > e.size => mismatched.push(format!("{:?}: value is longer than its size, {} bytes", e.key, e.size)),
            Ok((_, n)) if n != e.size => mismatched.push(format!("{:?}: value is {n} bytes, its size is {}", e.key, e.size)),
            Ok((d, _)) if d != e.entry_digest => mismatched.push(format!("{:?}: SHA256(salt ‖ value) does not match its entry digest", e.key)),
            Ok(_) => by_content += 1,
        }
    }

    let total = manifest.entries.len();
    let mut r = if !mismatched.is_empty() {
        result(ContentMismatch, mismatched.join("; "))
    } else if !unresolved.is_empty() {
        result(ContentUnresolved, format!("{} of {total} entries unresolved: {}", unresolved.len(), unresolved.join("; ")))
    } else {
        result(Verified, format!("{by_content} of {total} entries matched by content, {by_digest} by digest"))
    };
    r.by_content = by_content;
    r.by_digest = by_digest;
    r
}

// --- phase B: the readable manifest in `LocationProof` field 19 ---------------

const MANIFEST_NAME: &str = "caller-manifest";
const LOCATOR_NAME: &str = "caller-manifest-locator";
/// A locator longer than this is reported (it is never a reason to fail).
pub const MAX_LOCATOR_LEN: usize = 256;

/// Field 19 as a [`CallerManifest`], each salt empty: the salt never travels in
/// the proof and is not in the preimage, so the stage hash recomputes without it.
/// An entry whose `sha256` is not 32 bytes is an error.
pub fn manifest_from_proof(m: &crate::navigate::CallerManifest) -> Result<CallerManifest, String> {
    let entries = m
        .entries
        .iter()
        .enumerate()
        .map(|(i, e)| {
            let entry_digest: [u8; 32] = e.sha256.as_slice().try_into().map_err(|_| {
                format!("entry {i} ({:?}): sha256 is {} bytes, not 32", e.key, e.sha256.len())
            })?;
            Ok(ManifestEntry {
                key: e.key.clone(),
                content_type: e.content_type.clone(),
                size: e.size,
                salt: Vec::new(),
                entry_digest,
            })
        })
        .collect::<Result<_, String>>()?;
    Ok(CallerManifest { entries })
}

/// Where two manifests first differ in what the stage commits (key, contentType,
/// size, entry digest; count and order included). The salt is not compared: it
/// is never in field 19.
fn first_difference(a: &CallerManifest, b: &CallerManifest) -> Option<String> {
    if a.entries.len() != b.entries.len() {
        return Some(format!("{} entries against {}", a.entries.len(), b.entries.len()));
    }
    a.entries.iter().zip(&b.entries).enumerate().find_map(|(i, (x, y))| {
        let field = if x.key != y.key {
            "key"
        } else if x.content_type != y.content_type {
            "contentType"
        } else if x.size != y.size {
            "size"
        } else if x.entry_digest != y.entry_digest {
            "sha256"
        } else {
            return None;
        };
        Some(format!("entry {i} ({:?}) differs in {field}", x.key))
    })
}

fn manifest_check(status: Status, detail: String) -> Check {
    Check { name: MANIFEST_NAME, status, detail }
}

/// The `caller-manifest` check: does field 19 list exactly what the signed
/// `callerMetadata` stage commits?
///
/// - PASS: its entries pass the limits and recompute the stage hash.
/// - FAIL `MANIFEST_INVALID`: an entry breaks a limit, repeats a key, or carries
///   a `sha256` that is not 32 bytes.
/// - FAIL `MANIFEST_MISMATCH`: the hash differs, field 19 is present without the
///   stage, or `presenter` (a presenter manifest, when one was handed over)
///   differs from it.
/// - NOT-CHECKED: the proof has no field 19.
///
/// `locator` never affects the result: it is outside the signature, so anyone
/// holding the proof could change it. See [`check_manifest_locators`].
pub fn check_caller_manifest(proof: &LocationProof, presenter: Option<&CallerManifest>) -> Check {
    let Some(field) = &proof.caller_manifest else {
        return manifest_check(Status::NotChecked, "proof carries no caller manifest (field 19)".into());
    };
    let invalid = |e: String| manifest_check(Status::Fail, format!("MANIFEST_INVALID: field 19: {e}"));
    let mismatch = |e: String| manifest_check(Status::Fail, format!("MANIFEST_MISMATCH: {e}"));
    let m = match manifest_from_proof(field) {
        Ok(m) => m,
        Err(e) => return invalid(e),
    };
    let hash = match m.stage_hash() {
        Ok(h) => h,
        Err(e) => return invalid(e),
    };
    match proof.stage_attestations.iter().find(|s| s.stage == CALLER_METADATA_STAGE) {
        None => return mismatch("field 19 is present but the proof carries no callerMetadata stage".into()),
        Some(st) if st.data_hash.as_slice() != hash.as_slice() => {
            return mismatch("field 19 does not recompute the callerMetadata stage hash".into())
        }
        Some(_) => {}
    }
    if let Some(d) = presenter.and_then(|p| first_difference(p, &m)) {
        return mismatch(format!("the presenter manifest differs from field 19: {d}"));
    }
    let listed: Vec<String> = field
        .entries
        .iter()
        .map(|e| {
            let hint = if e.locator.is_empty() { String::new() } else { format!(", locator hint {:?}", short(&e.locator)) };
            format!("{:?} ({}, {} bytes{hint})", e.key, e.content_type, e.size)
        })
        .collect();
    manifest_check(
        Status::Pass,
        format!(
            "field 19 lists {} entr{} and recomputes the callerMetadata stage: {}",
            listed.len(),
            if listed.len() == 1 { "y" } else { "ies" },
            listed.join(", ")
        ),
    )
}

fn short(s: &str) -> String {
    match s.char_indices().nth(64) {
        Some((at, _)) => format!("{}…", &s[..at]),
        None => s.to_owned(),
    }
}

/// Why a locator looks like more than an opaque identifier: longer than
/// [`MAX_LOCATOR_LEN`], or a URL (`scheme:`) carrying a query or userinfo — the
/// shape of a pre-signed URL or an embedded credential.
pub fn locator_concern(locator: &str) -> Option<&'static str> {
    if locator.len() > MAX_LOCATOR_LEN {
        return Some("longer than 256 bytes");
    }
    let (scheme, rest) = locator.split_once(':')?;
    let is_scheme = scheme.as_bytes().first().is_some_and(u8::is_ascii_alphabetic)
        && scheme.bytes().all(|c| c.is_ascii_alphanumeric() || b"+.-".contains(&c));
    if !is_scheme {
        return None;
    }
    if rest.contains('?') {
        return Some("a URL with a query string");
    }
    let authority = rest.strip_prefix("//").map(|a| a.split(['/', '?', '#']).next().unwrap_or(""));
    if authority.is_some_and(|a| a.contains('@')) {
        return Some("a URL with userinfo");
    }
    None
}

/// A WARN line `caller-manifest-locator` when any field-19 locator looks like a
/// credential (see [`locator_concern`]); `None` otherwise. Never a FAIL: the
/// locator is unsigned, and failing on it would let anyone holding the proof
/// break it. It is also not the `caller-metadata` WARN, so it leaves
/// [`crate::verify::Report::content_resolved`] untouched.
pub fn check_manifest_locators(proof: &LocationProof) -> Option<Check> {
    let field = proof.caller_manifest.as_ref()?;
    let flagged: Vec<String> = field
        .entries
        .iter()
        .filter_map(|e| locator_concern(&e.locator).map(|why| format!("{:?}: {why}", e.key)))
        .collect();
    (!flagged.is_empty()).then(|| Check {
        name: LOCATOR_NAME,
        status: Status::Warn,
        detail: format!(
            "locator should be an opaque identifier, never a credential (it is unsigned and archived with the proof): {}",
            flagged.join("; ")
        ),
    })
}

/// The lines [`crate::verify::verify`] adds for a proof that carries field 19:
/// `caller-manifest`, plus `caller-manifest-locator` when a locator looks like a
/// credential. Nothing for a proof without field 19, so its report is unchanged.
pub fn caller_manifest_checks(proof: &LocationProof) -> Vec<Check> {
    if proof.caller_manifest.is_none() {
        return Vec::new();
    }
    let mut v = vec![check_caller_manifest(proof, None)];
    v.extend(check_manifest_locators(proof));
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::navigate::StageAttestation;

    fn entry(key: &str, ct: &str, value: &[u8], salt: &[u8]) -> ManifestEntry {
        ManifestEntry {
            key: key.into(),
            content_type: ct.into(),
            size: value.len() as u64,
            salt: salt.to_vec(),
            entry_digest: entry_digest(salt, value),
        }
    }

    fn proof_with_stage(m: &CallerManifest) -> LocationProof {
        LocationProof {
            stage_attestations: vec![StageAttestation {
                stage: CALLER_METADATA_STAGE.into(),
                timestamp_ms: 1,
                data_hash: m.stage_hash().unwrap().to_vec(),
                signature: vec![],
                previous_hash: None,
            }],
            ..Default::default()
        }
    }

    #[test]
    fn preimage_framing_is_pinned() {
        let m = CallerManifest { entries: vec![entry("k", "a/b", b"v", b"")] };
        let mut want = b"octet-caller-metadata-v1".to_vec();
        want.extend_from_slice(&1u32.to_be_bytes());
        want.extend_from_slice(&1u32.to_be_bytes());
        want.extend_from_slice(b"k");
        want.extend_from_slice(&3u32.to_be_bytes());
        want.extend_from_slice(b"a/b");
        want.extend_from_slice(&1u64.to_be_bytes());
        want.extend_from_slice(&32u32.to_be_bytes());
        want.extend_from_slice(&entry_digest(b"", b"v"));
        assert_eq!(m.preimage().unwrap(), want);
    }

    #[test]
    fn media_type_shape() {
        for ok in ["text/plain", "image/jpeg", "application/vnd.api+json", "TEXT/Plain", "x/y"] {
            assert!(is_media_type(ok), "{ok}");
        }
        for bad in ["", "text", "/plain", "text/", "text/plain; charset=utf-8", "text/pl ain", "a/b/c", "-a/b"] {
            assert!(!is_media_type(bad), "{bad}");
        }
    }

    #[test]
    fn streamed_digest_matches_and_stops_past_the_limit() {
        let value = vec![7u8; 200_000];
        let (d, n) = entry_digest_reader(b"salt-salt-salt-1", &value[..], value.len() as u64).unwrap();
        assert_eq!((d, n), (entry_digest(b"salt-salt-salt-1", &value), 200_000));
        let (_, n) = entry_digest_reader(b"", &value[..], 10).unwrap();
        assert!(n > 10 && n <= STREAM_BUF as u64, "{n}");
    }

    #[test]
    fn outcomes_on_a_bare_stage() {
        let m = CallerManifest { entries: vec![entry("note", "text/plain", b"hi", b"")] };
        let p = proof_with_stage(&m);
        let run = |inputs: CallerMetadataInputs| check_caller_metadata(&p, &inputs);

        let r = run(CallerMetadataInputs { manifest: Some(Ok(m.clone())), content: vec![("note".into(), Content::Bytes(b"hi"))], ..Default::default() });
        assert_eq!((r.outcome, r.check.status, r.by_content), (CallerMetadataOutcome::Verified, Status::Pass, 1));

        let r = run(CallerMetadataInputs { manifest: Some(Ok(m.clone())), content: vec![("note".into(), Content::Bytes(b"ho"))], ..Default::default() });
        assert_eq!(r.outcome, CallerMetadataOutcome::ContentMismatch);
        assert!(r.check.detail.starts_with("CONTENT_MISMATCH: "), "{}", r.check.detail);

        let r = run(CallerMetadataInputs { manifest: Some(Ok(m.clone())), require_content: RequireContent::All, ..Default::default() });
        assert_eq!((r.outcome, r.check.status), (CallerMetadataOutcome::ContentUnresolved, Status::Warn));

        let r = run(CallerMetadataInputs { manifest: Some(Ok(m.clone())), content: vec![("note".into(), Content::File("/nonexistent/caller-metadata".into()))], ..Default::default() });
        assert_eq!(r.outcome, CallerMetadataOutcome::ContentUnresolved);

        assert_eq!(run(CallerMetadataInputs::default()).outcome, CallerMetadataOutcome::NotChecked);

        let none = LocationProof::default();
        let r = check_caller_metadata(&none, &CallerMetadataInputs { require_stage: true, ..Default::default() });
        assert_eq!((r.outcome, r.check.status), (CallerMetadataOutcome::StageMissing, Status::Fail));
        assert_eq!(check_caller_metadata(&none, &CallerMetadataInputs::default()).outcome, CallerMetadataOutcome::NotChecked);
    }

    fn field19(m: &CallerManifest, locator: &str) -> crate::navigate::CallerManifest {
        crate::navigate::CallerManifest {
            entries: m
                .entries
                .iter()
                .map(|e| crate::navigate::CallerManifestEntry {
                    key: e.key.clone(),
                    content_type: e.content_type.clone(),
                    size: e.size,
                    sha256: e.entry_digest.to_vec(),
                    locator: locator.into(),
                })
                .collect(),
        }
    }

    #[test]
    fn field19_recomputes_the_stage_without_the_salt() {
        let salt = [9u8; 16];
        let m = CallerManifest { entries: vec![entry("note", "text/plain", b"hi", &salt), entry("f", "a/b", b"x", b"")] };
        let mut p = proof_with_stage(&m);
        assert_eq!(check_caller_manifest(&p, None).status, Status::NotChecked);
        assert!(caller_manifest_checks(&p).is_empty(), "no line without field 19");

        p.caller_manifest = Some(field19(&m, ""));
        let c = check_caller_manifest(&p, None);
        assert_eq!(c.status, Status::Pass, "{}", c.detail);
        assert_eq!(check_caller_manifest(&p, Some(&m)).status, Status::Pass);

        // A presenter manifest that differs (here: a dropped entry).
        let one = CallerManifest { entries: m.entries[..1].to_vec() };
        let c = check_caller_manifest(&p, Some(&one));
        assert!(c.status == Status::Fail && c.detail.starts_with("MANIFEST_MISMATCH: "), "{}", c.detail);
        let r = check_caller_metadata(&p, &CallerMetadataInputs { manifest: Some(Ok(one)), ..Default::default() });
        assert_eq!((r.outcome, r.check.status), (CallerMetadataOutcome::ManifestMismatch, Status::Fail));

        // The matching presenter manifest still checks content as in phase A.
        let r = check_caller_metadata(&p, &CallerMetadataInputs {
            manifest: Some(Ok(m.clone())),
            content: vec![("note".into(), Content::Bytes(b"hi"))],
            ..Default::default()
        });
        assert_eq!((r.outcome, r.by_content, r.by_digest), (CallerMetadataOutcome::Verified, 1, 1));

        // A changed digest, and field 19 without the stage.
        let mut bad = field19(&m, "");
        bad.entries[1].sha256[0] ^= 1;
        p.caller_manifest = Some(bad);
        assert!(check_caller_manifest(&p, None).detail.starts_with("MANIFEST_MISMATCH: "));
        let bare = LocationProof { caller_manifest: Some(field19(&m, "")), ..Default::default() };
        assert!(check_caller_manifest(&bare, None).detail.contains("no callerMetadata stage"));

        // A 31-byte digest is invalid, not a mismatch.
        let mut short_digest = field19(&m, "");
        short_digest.entries[0].sha256.pop();
        p.caller_manifest = Some(short_digest);
        assert!(check_caller_manifest(&p, None).detail.starts_with("MANIFEST_INVALID: "));
    }

    #[test]
    fn a_credential_like_locator_warns_and_never_fails() {
        for (loc, flagged) in [
            ("", false),
            ("obj_7f3a9c", false),
            ("vault:object/7f3a9c", false),
            ("https://files.example/a/b", false),
            ("https://files.example/a?X-Amz-Signature=abc", true),
            ("https://user:pw@files.example/a", true),
            ("s3://bucket/key?token=1", true),
            ("not a url ? at all", false),
        ] {
            assert_eq!(locator_concern(loc).is_some(), flagged, "{loc:?}");
        }
        assert!(locator_concern(&"a".repeat(257)).is_some());
        assert!(locator_concern(&"a".repeat(256)).is_none());

        let m = CallerManifest { entries: vec![entry("note", "text/plain", b"hi", b"")] };
        let mut p = proof_with_stage(&m);
        p.caller_manifest = Some(field19(&m, "https://files.example/a?sig=1"));
        let lines = caller_manifest_checks(&p);
        assert_eq!(lines.len(), 2);
        assert_eq!((lines[0].name, lines[0].status), ("caller-manifest", Status::Pass));
        assert_eq!((lines[1].name, lines[1].status), ("caller-manifest-locator", Status::Warn));
    }

    /// A value hashed in chunks by the caller matches like bytes, and a wrong
    /// salt, a wrong size or a changed chunk is a mismatch.
    #[test]
    fn chunk_hashed_content_matches_like_bytes() {
        let salt = [7u8; 32];
        let value: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let m = CallerManifest { entries: vec![entry("video", "video/mp4", &value, &salt)] };
        let proof = proof_with_stage(&m);
        let hashed = |salt: &[u8], value: &[u8]| {
            let mut h = EntryHasher::new(salt);
            for chunk in value.chunks(65_536) {
                h.update(chunk);
            }
            let (entry_digest, size) = h.finalize();
            Content::Hashed { entry_digest, size }
        };
        assert_eq!(EntryHasher::new(&salt).finalize().1, 0);
        let run = |c: Content<'static>| {
            check_caller_metadata(
                &proof,
                &CallerMetadataInputs {
                    manifest: Some(Ok(m.clone())),
                    content: vec![("video".into(), c)],
                    require_content: RequireContent::All,
                    require_stage: true,
                },
            )
        };
        let ok = run(hashed(&salt, &value));
        assert_eq!(ok.outcome, CallerMetadataOutcome::Verified, "{}", ok.check.detail);
        assert_eq!((ok.by_content, ok.by_digest), (1, 0));

        assert_eq!(run(hashed(&[], &value)).outcome, CallerMetadataOutcome::ContentMismatch);
        assert_eq!(run(hashed(&salt, &value[1..])).outcome, CallerMetadataOutcome::ContentMismatch);
        let mut changed = value.clone();
        changed[150_000] ^= 1;
        assert_eq!(run(hashed(&salt, &changed)).outcome, CallerMetadataOutcome::ContentMismatch);
    }
}
