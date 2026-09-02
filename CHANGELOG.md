# Changelog

All notable changes to `octet-verify` are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/); versioning is
[SemVer](https://semver.org/).

## [1.3.0] - 2026-09-02

Folds a post-1.2.0 security-hardening cluster and semantic-binding-v2 verifier
support into one release. Additive and back-compat: a genuine pre-1.3.0 proof
verifies unchanged, the new geometry/verdict bindings are understood but not
required (their transition flag stays off by default), and only tampered or
malformed proofs are newly rejected. Security hardening in this release resolves
findings from an external audit by [Zellic](https://zellic.io) (the team behind
V12.sh); we thank them for the review and remediation guidance.

### Added
- **Semantic-binding v2 (opt-in wire, v1-tolerant).** The verifier understands
  the `octet-semantic-binding-v2` `semanticFields` preimage, which additionally
  binds city-region geometry and earth altitude and a signed inside/outside
  `location_verdict`. `Report::location_verdict()` exposes it and `--json` emits
  `location_verdict`. v1 proofs verify unchanged (v2 is tried first, then v1);
  requiring v2 is the existing `--require-schema-v2` flag, still off by default.
- **`--expect-region-type`** and **`--expect-region-contains <lat>,<lon>`** —
  positively assert a geometric or earth region (by type, or by point containment
  for earth / city / ellipse / bbox), so such a proof can be *satisfied* rather
  than only rejected. (h3 containment is a follow-up.)
- **`--require-attestation`** (feature `appattest`) — fail closed when hardware
  attestation is required, so a required attestation check cannot be dropped
  without failing the proof. Off by default.
- **`--android-app-identity <package>,<cert_sha256_hex>`** — require an Android
  proof to name the expected app, not merely chain to a Google hardware root.
- **Typed verification bits in `--json`** — `region_asserted`, `attested`, and
  `semantically_bound` are emitted as booleans, and an `appattest` build always
  emits the `app-attest` line, so automation need not string-match `checks`.

### Changed
- **`octet-attest-verify` dependency v1.1.0 → v2.2.0** (published crates.io
  2.2.0), pinned as a tag-matched git rev plus `Cargo.lock` — reproducible and
  content-addressed. Brings the certificate chain-extension fix and the iOS
  Secure-Enclave key binding below.

### Security
- **Hardware attestation is bound to the signing key.** On both iOS and Android
  the verifier now requires the attested secure-hardware key to be the exact key
  that signed the proof, and reports attestation only for that key; a supplied
  `--hardware-pubkey` that disagrees with the attested key is refused.
- **Region assertion fails closed.** An armed `--expect-region` that cannot be
  evaluated now fails instead of passing silently, and the comparison is typed
  (country / subdivision / city) so a city name can no longer satisfy a
  country/subdivision code.
- **Honest semantic-binding coverage.** Under the v1 preimage, city centre/radius
  and earth altitude are reported as *not* covered (WARN) instead of implied
  signed; v2 binds them (see Added), and a consumer relying on those coordinates
  fails closed until then.
- **Backend-fetch hardening (`--features net`).** Redirect following is disabled
  so a backend response cannot steer a fetch to an unintended host; backend error
  output is bounded and sanitized before display; the proof identifier is
  validated at the trust boundary; and the documented exit-code contract is
  preserved even on an unexpected dependency panic.

## [1.2.0] - 2026-07-29

### Added
- **Android app-identity binding (opt-in)** under `--features appattest`.
  `Expectation` gains `android: Option<ExpectedAppIdentity>` (set via
  `.with_android(package_name, signing_cert_sha256)`); `attestation_root_check`
  and `verify_attested(_cached)` thread it through so an Android proof's
  key-attestation must also name the expected package and carry the expected
  signing-cert SHA-256, not just chain to a Google hardware root. On mismatch (or
  an absent/unparseable app id when one is required) the `attestation-root` check
  FAILs, gating `is_attested()`. Opt-in and back-compat: with no Android identity
  supplied, Android behaves exactly as before (hardware root only). iOS is
  unchanged (already app-bound via App Attest). Requires `octet-attest-verify`
  v1.1.0.
- **Per-login session binding** — a new `session-binding` check confirms a proof
  is bound to the login session it was produced under, closing a replay across
  logins. The SDK commits a per-login nonce in a signed `sessionBinding` stage
  (`data_hash = SHA256("octet-session-binding-v1" ‖ uint32_be(len) ‖ nonce)`);
  the relying party supplies the nonce it issued at login (library:
  `VerifyOptions.session_nonce`; CLI: `--session-nonce <hex>`), and the verifier
  recomputes the stage over it. Matches → PASS; wrong nonce or missing stage when
  a nonce is supplied → FAIL. Additive and back-compat: with no expected nonce
  supplied the check is NOT-CHECKED, so existing proofs verify unchanged. The
  nonce never rides the wire — only its hash, inside the signed stage. A
  `VerifyOptions.require_session_binding` flag (CLI `--require-session-binding`)
  makes it **fail-closed** — an unsupplied/absent binding FAILs instead of
  NOT-CHECKED — for a consumer that requires a stored/relayed proof to be
  session-bound.
- **Typed `Report` accessors + a composed attestation entry for library
  consumers.** So an automated consumer reads distinct verification outcomes
  without matching check names by hand, `Report` gains `is_attested()` (hardware
  attestation passed — iOS App Attest or the Android key-attestation chain),
  `is_fresh()` (the freshness check passed; a within-skew "future" `Warn` is not
  fresh), and `is_semantically_bound()` (the spoofing verdict / region / level /
  integrity / commitment are the signed values — required before trusting those
  fields), alongside the existing `is_valid` / `is_authentic`. New
  `appattest_layer::verify_attested(proof, opts, &expect)` (feature `appattest`)
  runs `verify()` and appends the offline hardware-attestation checks in one
  call, so the returned report's `is_attested()` is populated. Additive; no wire
  change, no new dependencies.
- **`appattest_layer::verify_attested_cached`** (feature `appattest`) — a
  cache-aware variant of `verify_attested` for a consumer verifying a stream of
  proofs from the same iOS App Attest key. It threads a cached `AttestedKey` into
  the App Attest check (so assertion-only proofs after the once-per-key
  attestation object still attest) and returns the advanced key to re-persist,
  keeping the assertion counter monotonic. `verify_attested` is now this with an
  empty cache. Android needs no cache.
- **App Attest key-enrolment entrypoint** (`--features appattest`) — a new
  library entrypoint, `appattest_layer::appattest_enroll`, verifies an
  out-of-band enrolment bundle (the object-bearing `DeviceAttestation` subset:
  `key_id`, the App Attest attestation object, an assertion, and the original
  attestation nonce the object was attested with) and returns the attested key
  to cache. This lets a verifier bootstrap a device key's hardware root from an
  explicitly-delivered bundle instead of depending on the once-per-key
  attestation object riding a submitted proof — so a fresh or scaled-out
  verifier with an empty key cache can still establish the key rather than
  stranding it. The bundle deserializes from JSON (`bundle_from_json`, schema
  `v:1`, every field base64url-no-pad) or protobuf (`bundle_from_proto`).
  Enrolment verifies the object against the nonce carried in the bundle (no
  server challenge); this only recovers the device's public key, while liveness
  and anti-replay remain the job of per-proof assertions and replay control.
  Purely additive: no proof-wire change, and no change to what an existing proof
  verifies.

### Changed
- **Schema-v2 mandatory flip — opt-in transition flag.** A new
  `VerifyOptions.require_schema_v2` (CLI: `--require-schema-v2`) turns the two
  back-compat NOT-CHECKED bindings into hard failures: when armed, a proof with
  no `semanticFields` stage FAILs `semantic-binding`, and (in `--envelope` /
  fetch modes) an envelope carrying no replay-control FAILs `replay-binding` —
  the proof-side equivalent of requiring schema-v2. **Off by default**, so
  existing proofs (incl. the committed golden vectors) verify unchanged. Arm it
  in lockstep with the backend's schema-v2 ingest gate and set it back to
  `false` to roll back instantly; schema-v2 shipped with SDK 1.1.0, so the
  effective minimum SDK when armed is 1.1.0.

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
