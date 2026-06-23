# Changelog

All notable changes to `octet-verify` are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/); versioning is
[SemVer](https://semver.org/).

## [Unreleased]

### Added
- Optional `appattest` feature: offline Apple App Attest verification of the
  attestation evidence on `DeviceAttestation`, via the shared
  `octet-attest-verify` crate (attestation object chained to Apple's root +
  assertion signature/counter). Surfaces an `app-attest` check. Off by default —
  the lean default verifier pulls no X.509/CBOR surface.
- `--app-attest-config <file>` CLI flag: verify a proof's App Attest evidence
  against the expected app identity in a shared TOML config (one location, no
  hardcoding). Reported NOT-CHECKED on a default (non-`appattest`) build.

### Hardening
- **Freshness is judged on the signed stage timestamp**, not the proof-level
  `timestamp_ms`. The top-level field is covered by no signature; editing it can
  no longer make a stale proof read as fresh. A signed timestamp beyond a small
  clock-skew allowance in the future now **fails** (previously only warned), and
  a divergent unbound `timestamp_ms` is surfaced as a warning.
- **A present field bound by no stage now fails** instead of being silently
  reported NOT-CHECKED. If a proof carries a commitment / nullifier / ZK value
  but the corresponding binding stage was renamed or omitted, the verifier
  refuses to vouch for the unverifiable value rather than passing on the strength
  of the other bound fields.
- **Output is hardened against terminal/JSON injection.** Attacker-influenced
  strings (stage names, region labels, backend-supplied ids) can no longer emit
  raw control or ANSI/OSC escape bytes: JSON output escapes all control
  characters (valid `jq` / `json.loads` input) and human output renders them as
  visible `\xHH`.
- **Refetch-consistency / seen-store dedup now hashes a signature-canonicalized
  proof.** ECDSA admits two valid signatures per message, so a genuine proof has
  a byte-distinct but equally valid twin; the dedup hash now normalizes
  signatures to low-S first, so a twin can no longer pose as different proof
  bytes. Signature *verification* still accepts both forms (Android Keystore
  emits high-S), so this changes only the dedup hash, never a verdict.
- **A smuggled duplicate of a non-repeated proto field is now rejected.** proto3
  silently keeps the *last* value when a singular field (e.g. `timestamp_ms`,
  `platform`) appears twice on the wire, so an appended copy can make this
  verifier and another parser disagree. A new `wire-format` check scans the
  top-level `LocationProof` fields and FAILs on a duplicate of any field the
  schema declares non-repeated; legitimately-repeated fields
  (`stage_attestations`) and unknown field numbers are left alone.

## [1.0.0]

First public release: a standalone, independent verifier for Octet
`LocationProof` artifacts.

### Verification
- Local-file verification (`.bin` / stdin): Ed25519 / ECDSA-P256 signatures,
  stage hash-chain linkage, `proofAssembly` binding, commitment/nullifier/ZK
  field bindings, freshness, optional cross-run replay, and the claimed region —
  all against an embedded key registry. No proof-creation or spoof-detection
  logic is included.
- Backend fetch mode (`fetch` / `watch` / `range`, behind the `net` Cargo
  feature): pulls proofs from the Octet proof ingestion API and runs the
  identical local pipeline. The backend is treated as untrusted; no backend-
  supplied field affects a verdict.

### Machine-readable output (`--json`)
- **`valid` reports authenticity**, not mere structural validity: it is `true`
  only when the proof is not rejected **and** its stage signatures were
  cryptographically verified. A structurally-sound but signature-`NOT-CHECKED`
  proof (e.g. no hardware key) reports `valid: false` / `verdict:
  "INCONCLUSIVE …"`, so a consumer keying on `valid` cannot be misled into
  accepting an unverified proof.
- Added `signatures_verified` (bool) and kept `verdict` (tri-state string) so
  the `VALID` / `INCONCLUSIVE` / `INVALID` states stay distinguishable.

### CLI exit codes
- **Tri-state and authenticity-gated:** `0` authentic · `1` invalid · `2` error ·
  `3` inconclusive (structurally valid but signatures not verified). `INCONCLUSIVE`
  is never `0`, so an exit-status gate (`octet-verify … && deploy`) cannot accept
  an unverified proof. `range` / `watch` return the worst proof observed (any
  `1` → `1`, else any `3` → `3`, else `0`). Both the exit code and the JSON
  `valid` field are safe authenticity gates.

### Hardening
- Hardware-key extraction from an Android certificate now **parses the leaf's
  SubjectPublicKeyInfo** (via `x509-cert`) and asserts `id-ecPublicKey` /
  `prime256v1`, instead of byte-scanning for a `03 42 00 04` pattern that could
  match a decoy elsewhere in the certificate. The raw-SEC1 fast path (iOS) is
  unchanged. (Extraction correctness only — attestation-root chain validation
  is out of scope for v1.)
- Replay handling documented honestly: the `nullifier` check is **presence-only**
  (a token exists), not a cross-proof uniqueness guarantee; `--nullifier-store`
  is a best-effort, single-process, non-atomic local convenience. Authoritative
  cross-proof uniqueness is enforced server-side at ingest.

### Security
- Plaintext-URL guard parses the host as a literal IPv4 address before allowing
  `http://` for LAN-dev ranges (loopback / `10.0.0.0/8` / `192.168.0.0/16`) —
  attacker-controlled hostnames like `10.evil.com` are refused, so a bearer
  token is never shipped in the clear to a non-LAN host.
