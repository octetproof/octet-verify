# Changelog

All notable changes to `octet-verify` are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/); versioning is
[SemVer](https://semver.org/).

## [1.1.0] - 2026-06-25

Adds the proof-binding layers the v1.0.0 NOTE anticipated — device attestation,
per-proof replay control, and semantic-field binding — plus verifier-hardening
fixes. All additive and back-compat: a genuine v1.0.0-era proof verifies
unchanged; new checks report NOT-CHECKED until a proof carries the corresponding
signed material, and only tampered or malformed proofs are newly rejected. See
`VERIFICATION-SPEC.md` for the full checks.

### Added
- **Semantic-field binding** — the spoofing verdict, region, level, device
  integrity status, and the position commitment are now bound to the signed
  proof. Editing any of them after signing (flipping a verdict, rewriting the
  region or level, swapping the committed location) is rejected. Covers every
  region type, including geometric regions. A proof carrying no such binding
  reports NOT-CHECKED.
- **Replay-control binding** (backend-fetch and `--envelope` modes) — when an
  envelope carries replay-control values (a per-proof upload nonce, the
  nullifier, and the signed timestamp), the verifier confirms they match what
  the proof actually signed. The backend stays untrusted: a tampered value fails
  the check. Absent on older proofs → NOT-CHECKED.
- **Optional `appattest` feature** — offline hardware-attestation verification
  via the `octet-attest-verify` crate. On iOS, Apple App Attest to Apple's
  embedded root (`--app-attest-config`); on Android, the key-attestation
  certificate chain to an embedded, fingerprint-pinned Google root (TEE/StrongBox
  required). Under the feature the `attestation-root` and device-attestation
  signature checks become real Pass/Fail instead of NOT-CHECKED;
  `--skip-hardware-attestation` scopes a build back to core verification. Off by
  default, so the lean default build pulls no extra surface. Online revocation is
  not consulted (offline by design).

### Hardening
- Freshness is judged on the proof's signed timestamp, not the unbound top-level
  field; a far-future timestamp now fails.
- A field that carries no signed binding (commitment / nullifier / ZK) now fails
  instead of passing quietly.
- Verifier output is escaped against terminal / JSON injection from
  attacker-influenced strings.
- Cross-run dedup is robust to ECDSA signature malleability.
- A proof that smuggles a duplicate of a non-repeated field is rejected.

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
