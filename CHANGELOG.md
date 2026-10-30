# Changelog

All notable changes to `octet-verify` are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/); versioning is
[SemVer](https://semver.org/).

## [1.9.0] - 2026-10-30

S2 grid regions (tags 8 and 9), the signed highres location uncertainty, and
iOS App Attest assertions bound to the signing key by default.

### Changed
- **iOS App Attest assertions must be bound to the signing key by default.** A
  live assertion's `clientDataHash` must be `SHA256(nonce ‖
  certificate_chain[0])`, which SDKs have emitted since 2.0.0. The legacy
  nonce-only form now FAILs `app-attest` in every mode, not only under
  `--require-attestation`, so a genuine assertion can't be replayed under
  another signing key. No device on an older SDK has been active on production
  since 2026-10-07. For proofs archived from those SDKs,
  `--allow-unbound-app-attest` (`VerifyOptions::allow_unbound_app_attest`)
  accepts the legacy form as a WARN: valid, but not attested.
  `appattest_check` now takes an `AssertionPolicy` in place of its
  `require_binding` flag.

### Added
- **Location uncertainty (field 20).** Highres proofs carry a signed
  `LocationUncertainty`: the estimator's statistical region and coverage, an
  optional vertical interval, the calibration status, and an optional
  protection failure risk. A new `uncertainty-binding` check recomputes its
  `octet-uncertainty-binding-v1` preimage and compares it with the signed
  `uncertaintyFields` stage; an edited, stripped or unsigned uncertainty FAILs
  (VERIFICATION-SPEC §2.1c). The `uncertainty` module exposes the preimage. A
  proof from an early highres build that put the uncertainty at tag 18 (now
  `query_region`) fails to decode, so it is never misread.
- **S2 cell sets (region tag 8).** A `cell_set` region is a union of S2 cells at
  mixed levels. It must be canonical (exactly its own S2 normalisation:
  non-empty, at most 16,384 cells, valid ids, sorted, disjoint, no 4 siblings
  left unmerged), which a new `cell-set` check reports. Its digest,
  `SHA256("octet-region-cellset-v1" ‖ u32be(n) ‖ u64be(id)ⁿ)`, joins the
  semantic binding and `query_region_ref` (`region_type` 8), and
  `--expect-region-contains` evaluates it in every build.
  `--expect-region-type cellset` accepts it. The new `s2` module exposes the
  cell-id helpers, the point → leaf-cell mapping, `check_canonical`,
  `normalize`, `cell_set_digest` and the Spatial ID height-bin index
  `f_index`. Golden vectors from the reference Go S2 library are in
  `test-vectors/s2-region/`.
- **S2 voxel sets (region tag 9).** A `voxel_set` region is S2 cells, each with
  one or more ranges of WGS84 ellipsoidal height in Spatial ID bins
  (`S2Voxel{cell_id, f_zoom, f_min, f_max}`, the interval
  `[f_min·2^(25−f_zoom), (f_max+1)·2^(25−f_zoom))` metres, `f_zoom` 0–32). It
  must be canonical (at most 16,384 entries, sorted by cell and then height,
  each interval at its coarsest zoom, one cell's intervals neither overlapping
  nor touching, cells disjoint, no 4 siblings with identical heights left
  unmerged, and at least one entry bounded in height, since all heights
  everywhere is a cell set), which a new `voxel-set` check reports. Its digest,
  `SHA256("octet-region-voxelset-v1" ‖ u32be(n) ‖ {u64be cell ‖ u32be f_zoom ‖
  i64be f_min ‖ i64be f_max}ⁿ)`, joins the semantic binding and
  `query_region_ref` (`region_type` 9). `--expect-region-contains` takes an
  optional height (`<lat>,<lon>,<h>`) and a voxel set FAILs without one;
  `VerifyOptions` gains `expect_region_contains_height_m` for it.
  `--expect-region-type voxelset` accepts it. The `s2` module adds
  `check_voxel_canonical`, `normalize_voxels`, `voxel_set_digest` and
  `voxel_set_contains`.

## [1.8.0] - 2026-10-26

### Added
- **Browser verdict `v=4`, the early verdict.** The browser profile accepts
  `octet-browser-verdict+jwt;v=4`: the `v=3` claims plus `stage`
  (`provisional` or `final`), `revision` and `incomplete`, checked by a new
  `verdict-stage` line. It FAILS a missing or invalid claim, `incomplete` other
  than `true` on a final token, a provisional or incomplete-final token whose
  chain has other than one report or whose confidence is above 0.7, a lower
  revision than one already accepted for the session, a second final, and any
  `v=1`–`v=3` token carrying the new claims. A provisional or incomplete-final
  verdict reads WARN: genuine, but not a pass for a gated action.
  `BrowserReport` gains `stage()`, `revision()`, `incomplete()`, `is_final()`,
  `passes_gate()` and `next_revisions()`; `verify_browser_verdict_with` takes
  the session's `SessionRevisions`. `BrowserVerdictInputs` is unchanged. CLI:
  exit 3 for a verdict that is not final unless `--accept-provisional`, and
  `--revision-store <file>`; `--json` adds `verdict`, `passes_gate`, `stage`,
  `revision` and `incomplete`. Vectors from octet-browser:
  `verdict-v4-vectors.json` and `verdict-v3-golden.json`.
- **Caller metadata (phase A).** Checks content an integrator bound into a proof
  against its hardware-signed `callerMetadata` stage, following the frozen
  caller-metadata binding spec. New `caller_metadata` module: the preimage, the
  limits, a streaming entry digest, and `check_caller_metadata`, reported as the
  `caller-metadata` check with the results `CONTENT_MISMATCH` and
  `MANIFEST_INVALID` (FAIL) and `CONTENT_UNRESOLVED` (INCONCLUSIVE, exit 3).
  `Report::content_resolved()` is new, and `Report::is_authentic()` now also
  requires it; reports without caller metadata are unchanged. `VerifyOptions`
  is unchanged. CLI: `--caller-manifest` and `--content <key>=<file>` (new
  feature `caller-metadata`, which adds the JSON manifest parser),
  `--require-content <key>`, `--require-content-all` and
  `--require-caller-metadata`. `caller_metadata::EntryHasher` hashes a value in
  chunks with bounded memory, and `Content::Hashed` hands the result to the
  check, for callers that read content themselves (a browser page with a large
  file). Golden vectors in `test-vectors/caller-metadata/`
  pin the preimage, the limits and every result, for the SDKs to test against.
- **Caller metadata (phase B): the readable manifest in `LocationProof` field
  19.** New proto messages `CallerManifest` / `CallerManifestEntry` (key,
  contentType, size, entry digest and an optional `locator`; no salt, no value).
  `verify()` adds a `caller-manifest` line whenever a proof carries field 19:
  PASS when it recomputes the signed `callerMetadata` stage, FAIL
  `MANIFEST_MISMATCH` or `MANIFEST_INVALID` otherwise; proofs without field 19
  get no new line. A presenter manifest must agree with field 19
  (`caller-metadata` FAIL `MANIFEST_MISMATCH` otherwise). `locator` is unsigned
  and never affects a result; a credential-shaped one gets a separate
  `caller-manifest-locator` WARN. New `Report::caller_manifest()`, and the JSON
  output gains `caller_manifest`. `wire-format` refuses a duplicated field 19.
  Vectors in `test-vectors/caller-metadata/field19.json` pin the encoded bytes
  and every result.
- **Browser verdict-key rotation vectors** (`test-vectors/browser-verdict-chain`):
  production root manifests seq 2 and seq 3, and one production verdict signed
  on each side of the 2026-10-19 switch from the file key to the Cloud KMS key
  (ES256). Tests check that both verify under seq 3, that the KMS verdict is
  refused under seq 2, that a closed key window refuses the older verdict, and
  that seq 2 is a rollback once seq 3 has been seen.
- **Caller-metadata real-device test vectors**
  (`test-vectors/caller-metadata-device`): one proof each from an iPhone 11 and
  a Pixel 9, each committing a salted text entry and an unsalted 4 KiB file.
  A second set (`test-vectors/caller-metadata-device-b`) adds the readable
  manifest in field 19. `tests/caller_metadata_device.rs` checks both sets match
  by content, that field 19 recomputes the stage and equals the presenter
  manifest, that changed, swapped or unreadable content is refused, and each
  phone's hardware attestation.
- **OctetSDK 3.0.0 real-device test vectors** (`test-vectors/sdk-3.0.0-device`):
  nine proofs from an iPhone 11 and a Pixel 9 (area and `isWithin` country
  proofs, semantic-binding v2), all VALID. `tests/sdk_3_0_0_device.rs` checks
  them at their own signed time, including the Android hardware attestation
  and, with the key's enrolment bundle, iOS App Attest and its date window.

### Changed
- **`Report::is_authentic()` also requires caller content to be resolved.** A
  report whose `caller-metadata` check is `CONTENT_UNRESOLVED` is INCONCLUSIVE
  (exit 3), never VALID. Reports without caller metadata are unchanged.

### Fixed
- **Duplicate-field guard covers `location_verdict` (17) and `query_region` (18).**
  A proof carrying a second copy of either is refused by `wire-format`, as for
  every other singular field, so no parser can read a different signed verdict
  or region than the one checked.

## [1.7.0] - 2026-10-12

### Added
- **Object-only App Attest enrolment.** An enrolment bundle may now carry the
  attestation object, its nonce and `key_id` without an assertion: JSON `v:2`
  (where `app_attest_assertion` is optional), or a proto bundle without it. The
  object is verified as before (Apple root, nonce, app identity, environment,
  `key_id`), and the key's counter baseline is the object's own, 0. Every proof
  verified with the key still needs its own assertion, so nothing is lost. This
  is the form a licence backend holds when it forwards a bootstrap object without
  the SDK's local enrolment assertion. `--app-attest-enrolment-bundle` and
  `appattest_enroll` accept it; `v:1` still requires the assertion.
  `BUNDLE_SCHEMA_VERSION` is now 2 (the newest accepted). Covered end to end on
  the real iPhone 11 object: enrolment, then an assertion-only proof to PASS, in
  the library and the CLI; an edited nonce, an edited `key_id` and another app
  identity are refused.
- **Date-check the App Attest chain over a caller-given window:**
  `--app-attest-window <lower|leaf>/<upper>`. The App Attest chain is still
  verified by signature only on its own, because its leaf is valid for about 3
  days from attestation. A caller that holds a trusted time the attestation object
  existed by (such as when it was anchored) passes it as `<upper>`; `<lower>` is a
  time or `leaf`, the leaf certificate's own notBefore. After an `app-attest`
  PASS, `app-attest-validity` then PASSes when the leaf, the intermediate and the
  Apple root are all valid at both bounds, and FAILs otherwise, making the proof
  INVALID. It dates the object the verified key came from: the proof's own, or the
  enrolment bundle's. Library: `AppAttestWindow`, `appattest_validity_check` and
  `set_app_attest_validity`. Spec: VERIFICATION-SPEC.md §4.1. Needs
  `octet-attest-verify` 2.5.0 (`attestation_chain_validity`). Covered on the real
  iPhone 11 object (leaf valid 2026-08-23 to 2026-08-26): inside, the inclusive
  edge, after expiry, before issue, reversed, malformed, and through an
  enrolment bundle.

### Changed
- **The browser verdict profile now pins octet's production roots.** octet's
  first root ceremony (2026-10-12) created two offline roots,
  `octet-root-a-2026-10` and `octet-root-b-2026-10`: ES256 keys, each generated
  on its own YubiKey and attested by Yubico. They are built in as
  `browser::PINNED_ROOTS_JSON`. `browser-verdict` therefore checks the root
  manifest by default: it fetches the published manifest (with `net`; pass
  `--manifest <file>` otherwise), and `root-manifest`, `manifest-verdict-key` and
  `manifest-challenge-key` now report VERIFIED or FAILED instead of NOT-CHECKED.
  A verdict key or challenge key the manifest does not list now FAILS. If the
  manifest can't be fetched, `root-manifest` stays NOT-CHECKED, as before.
  `--roots <file>` still overrides the pins. The production seq 1 manifest
  is a new test vector (`test-vectors/browser-verdict-chain/prod-manifest-seq1.json.jws`).
- **`octet-attest-verify` dependency v2.4.1 → v2.5.0**, for
  `attestation_chain_validity`. No other behaviour change.

### Fixed
- **The CLI now prints the `app-attest-validity` NOT-CHECKED line** after an
  `app-attest` PASS, as 1.6.0 described. In 1.6.0 only library callers of
  `verify_attested` / `verify_attested_cached` got it; the CLI's
  `--app-attest-config` path left it out. No verdict changes. Library:
  `appattest_layer::appattest_validity_not_checked()` is now public, for callers
  that run `appattest_check` themselves.
- **The published source's `Cargo.lock` builds with `--locked` again.** From
  1.5.0, the published source carried a `Cargo.lock` whose `octet-attest-verify`
  git source had lost part of its revision, so `cargo build --locked` failed on
  it. The crates.io package was not affected.

## [1.6.0] - 2026-10-06

### Added
- **Historical verification: `--at` and `--window`.** `freshness` and
  `attestation-root` can now be judged at a validation instant or over a
  validation window instead of the current time. Certificates in an Android
  key-attestation chain can be valid for only days, so an archived proof judged
  today failed `attestation-root` and `freshness` although it was authentic when
  made. With `--window <from>/<to>`, `freshness` PASSes when the signed
  `proofAssembly` time lies inside the window (60 s skew), and `attestation-root`
  PASSes only when the chain is valid at both bounds. Times are RFC 3339 or Unix
  milliseconds. Both flags also apply in backend fetch mode. Library:
  `VerifyOptions::validation_window` with `ValidationWindow`, and
  `appattest_layer::{attestation_root_check_for, attestation_root_check_window}`.
  Spec: VERIFICATION-SPEC.md §4.1. Covered by `tests/validation_window.rs` on a
  real Pixel 9 proof: VALID over a window around its signing time, INVALID at the
  current time.
- **`app-attest-validity` NOT-CHECKED line.** The App Attest chain is verified to
  Apple's root by signature only: its validity dates are not checked in any mode.
  Its leaf certificate is valid for about 3 days from attestation, which usually
  precedes the proof. Every `app-attest` PASS is now followed by an
  `app-attest-validity` NOT-CHECKED line that says so, so a historical iOS
  verdict is never read as a date check. No verdict changes: `is_valid()` and
  `--require-attestation` ignore NOT-CHECKED lines. Library:
  `appattest_layer::APP_ATTEST_VALIDITY`. Spec: VERIFICATION-SPEC.md §4.1 and §5.
  Covered by `tests/ios_app_attest.rs` (default, required-attestation and window
  modes) and `tests/validation_window.rs` (absent on Android).
- **Browser verdict profile: `octet-verify browser-verdict`** (new `browser`
  feature; `net` adds JWKS-by-URL). Verifies the octet browser product's signed
  verdict token (compact JWS, `typ octet-browser-verdict+jwt;v=1|2|3`, EdDSA or
  ES256 with the alg bound to the key) against the live or archive verdict JWKS,
  including the archive signing window and revocation. For `v=3` it recomputes
  `chain_root`. With the partner's challenge token it checks the session link
  (s0, PASETO v4.public signature, sessionRef, licence, time window); with an
  edge log line, the edge link. The S1 device signature and anchor receipts are
  reported as ATTESTED (by octet), never VERIFIED. Library:
  `browser::verify_browser_verdict`. Spec: VERIFICATION-SPEC.md §9. Golden
  vectors shared with octet-browser in `test-vectors/browser-verdict-chain/`:
  a deterministic one, a real dev-stack verdict, and a root manifest. The signed `clientNetMatch` is reported as `client_net_match` (`false` is a
  result, not a failure). `--edge-log` takes the edge
  log line raw, log prefix included, as partners copy it from their logs.
  - **Root manifest** (`--roots`, `--manifest`, `--manifest-seq-store`,
    `--min-manifest-seq`): verifies octet's offline-root-signed manifest
    (pinned roots only, strict 3-field header, ES256 `r‖s`, rollback via the
    highest `seq` seen, expiry: WARN within a 14-day grace, FAILED after), then
    requires the verdict and challenge keys to be listed with the same key
    material, and takes `key-validity` from the manifest entry. No production
    roots are pinned yet, so without `--roots` it reads NOT-CHECKED.
- **Multi-identity Android app binding.** A licence that ships several apps, or
  registers both a release and a debug signing cert, can now accept a proof bound
  to any one of a set of app identities. Each identity matches whole: its package
  AND its own cert. A set `{(A, cert1), (B, cert2)}` rejects a proof from
  `(A, cert2)`; it never matches a cross-product of packages and certs.
  - `--android-app-identity` is repeatable.
  - `attestation_root_check_multi(proof, now, &[ExpectedAppIdentity], key)`.
    `attestation_root_check` is unchanged and is the set-of-one case.
  - `Expectation::or_android(pkg, cert)` adds an identity to the set;
    `Expectation::android_identities()` returns it. `verify_attested_cached`
    binds to the whole set.
  - Golden vectors over a real Pixel 9 StrongBox chain pin the mixed-cert
    cross-product reject, the match-one accept, and both single-swap rejects.
- **Enforce the signed spoofing-verdict tier.** A disc answer can be signed
  VERIFIED or PLAUSIBLE, and both verify, so a consumer that checks only `valid`
  accepts a PLAUSIBLE disc as if it were VERIFIED.
  - `--require-verdict verified|plausible` / `VerifyOptions::require_verdict`
    (`RequiredVerdict::{Verified, Plausible}`) adds a `verdict-required` check.
    It FAILs when the signed verdict is below the tier, and fails closed when
    `semantic-binding` did not pass. Off by default.
  - `Report::spoofing_verdict()` and a `spoofing_verdict` JSON field return the
    verdict only when it is semantically bound (else `null`).
  - A `verdict-tier` line labels a disc answer's signed tier (level
    `CONTINUOUS_AREA`, or a bound disc query region: the proof-model-v2
    `proveDiscVerdict` shape, which keeps the country-level claim). VERIFIED and
    PLAUSIBLE are a PASS label, not a WARN: until the SDK's verdict ladder
    reaches VERIFIED, nearly every disc answer is PLAUSIBLE, so a WARN would be
    noise. SUSPICIOUS and NOT_PROVABLE are a WARN. To refuse PLAUSIBLE, use
    `--require-verdict verified`.
  - Real-device vectors: the iPhone 11 proof-model-v2 discs (PLAUSIBLE) fail
    `verified` and meet `plausible`; the Pixel 9 discs (VERIFIED) meet `verified`.
- **H3 point-in-region containment** for `--expect-region-contains` against an
  `h3_polygon_set` region, behind a new opt-in `h3` feature (pure-Rust `h3o`).
  The region is the filled union of its cells: a point is inside iff some
  listed cell contains it at that cell's own resolution, so mixed and
  compacted sets work. An empty set or any invalid cell index FAILs closed.
  Without the feature, h3 containment still FAILs closed, as before.
  - Golden vectors in `test-vectors/h3-containment/` are generated with the
    reference H3 C library and checked against `h3o`. They cover in/out of
    cell, mixed and compacted resolutions, a pentagon, a shared boundary
    vertex, duplicates, and the malformed-set FAILs.

### Changed
- **`octet-attest-verify` dependency v2.3.2 → v2.4.1**, for its per-identity
  match-any `verify_key_attestation_multi`. No behaviour change for a single
  identity or none.
- **`rustls` 0.23.40 → 0.23.45** in `Cargo.lock` (the `net` feature's HTTPS
  client), for an advisory on TLS 1.3 handshake messages accepted across
  encryption-level boundaries. Library consumers resolve their own `rustls`;
  update it there too.

Additive: existing callers of `attestation_root_check`, `with_android` and
`Expectation.android` compile and behave as before, and with no new option set a
proof verifies as before. A disc answer gains an informational `verdict-tier`
line: PASS for VERIFIED / PLAUSIBLE, WARN only for SUSPICIOUS / NOT_PROVABLE. Three
struct-literal caveats: `VerifyOptions` gains `require_verdict` (add
`require_verdict: None`) and `validation_window` (add `validation_window: None`),
and `Expectation` gains `android_additional` (use `Expectation::new`, or add
`android_additional: Vec::new()`).

## [1.5.0] - 2026-09-28

Additive and back-compat: the public API a 1.3/1.4 consumer uses (`verify`,
`VerifyOptions`, `Report::location_verdict`, the `appattest_*` functions) is
unchanged, and a genuine pre-1.5.0 proof verifies exactly as before — v3 is tried
first, then falls back to v2/v1. (The App Attest `RequireBound` and
`require_schema_v2` default-posture flips are **not** in this release; they are
deferred to a later version, gated on the client fleet aging past the pre-2.0.0
SDK, so that re-verifying genuine older/stored proofs does not start failing.)

### Added
- **Semantic-binding v3 — the queried region is bound into the proof.**
  A new `LocationProof.query_region` (field 18, `RegionRef { region_type, region_id }`)
  carries a *reference* to the region a proof's `location_verdict` answers about,
  signed under a new `octet-semantic-binding-v3` preimage (the v2 body verbatim,
  then `q_type ‖ len(q_id) ‖ q_id`). This lets a consumer read a signed
  INSIDE/OUTSIDE for a *specific* region — the only way to decide a disc, which a
  country-level claim can't derive.
  - `verify()` tries v3 → v2 → v1. On a v3 match it exposes the bound region via
    **`Report::query_region()`** (only when v3 verified) alongside
    `location_verdict()`, and adds a `query-region` check enforcing: a present
    query must carry an answer (one-way presence rule — a verdict without a bound
    query is allowed, e.g. a city query); a present `region_type` must be one of
    country/subdivision/earth/ellipse/h3/bbox with a well-formed `region_id`
    (a present `q_type` of 0 or city → FAIL). Stripping or editing field 18 breaks
    the v3 hash and cannot fall back to v2/v1 (different domain) → FAIL, never a
    silent downgrade.
  - **`query_region_ref(region)`** — the single canonical reference digest a
    consumer computes for a region R it cares about; on equality with a proof's
    exposed query region, the signed verdict answers `within(R)` directly. A disc
    is `ellipse(lat, lon, r, r, heading = +0.0)`; a city has no reference (unbound).
  - CLI: **`--expect-query-region <spec>`** (`earth` / `country:AT` /
    `subdivision:US-NY` / `disc:<lat>,<lon>,<r_m>` /
    `ellipse:<lat>,<lon>,<smaj_m>,<smin_m>,<heading>`) asserts the proof's bound
    query region equals that region; JSON output gains a `query_region` field.

## [1.4.0] - 2026-09-18

Adds opt-in online Google Play Integrity verification, a CLI path for verifying
assertion-only iOS proofs via an App Attest enrolment bundle, and documented
Tier-2 (gateway-mode) un-attested proof support. Additive and back-compat: a
genuine pre-1.4.0 proof verifies unchanged; the new checks are opt-in.

### Added
- **Online Google Play Integrity check (`--features playintegrity`,).** Opt-in
  and networked: with `--integrity-decode-url`, `--integrity-decode-token` (the
  verifier's OWN decode-scoped `octet_svc_` credential — never a device bearer),
  and `--integrity-package`, the verifier POSTs the proof's PI token to the
  first-party decode endpoint, then verifies the returned verdict binds to the
  proof (random-nonce byte-equality + package), is fresh (window + 60s forward
  skew), and meets `MEETS_DEVICE_INTEGRITY` — emitting a `play-integrity` check.
  A FAIL rejects the proof; auth / rate-limit / unavailable / malformed-request /
  transport are `NOT-CHECKED` (never fail-open). Off by default → `NOT-CHECKED`;
  the lean build has no PI surface. app-recognition is informational; licensing
  ignored. Decode/verdict primitives come from the shared `octet-attest-verify`
  crate; only the offline judgement runs here.
- **Tier-2 (gateway-mode) un-attested proofs — documented + pinned.** Committed
  real-device golden vectors (iPhone 11, Pixel 9) for honestly-un-attested proofs
  (a bare device-key point in `certificate_chain[0]`, no App Attest / Play
  Integrity) and a blessing test pinning them as `valid` / authentic /
  `attested:false`; INTEGRATION.md gains a Tier-2 section (gate on `attested`, not
  `valid`/exit 0; mandatory-attestation is an upstream policy). Supports
  gateway-mode un-attested proofs. No verifier behavior change — such proofs
  already verified this way.
- **`--app-attest-enrolment-bundle <file>`.** Verify an assertion-only iOS proof
  (one carrying no attestation object — the steady state) to `app-attest` PASS
  from the CLI by supplying the out-of-band App Attest enrolment bundle (proto or
  JSON, auto-detected), instead of reporting `NOT-CHECKED`. Previously only the
  embedded library could recover the key this way. Requires `--app-attest-config`
  and a `--features appattest` build.

## [1.3.0] - 2026-09-02

Folds a post-1.2.0 security-hardening cluster and semantic-binding-v2 verifier
support into one release. Additive and back-compat: a genuine pre-1.3.0 proof
verifies unchanged, the new geometry/verdict bindings are understood but not
required (their transition flag stays off by default), and only tampered or
malformed proofs are newly rejected. Security hardening in this release resolves
findings from [V12](https://v12.sh/).

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
