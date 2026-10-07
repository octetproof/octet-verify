# Octet Proof Verification Spec

This is the public contract `octet-verify` implements: the exact bytes that are
signed, the algorithms, and what a verifier can and cannot conclude. It is
derived from the SDK's proof-generation code, and contains **only** information
needed to *verify* a proof — no spoof-detection logic, signal weights, or
verdict thresholds. A signing *format* is not a secret (Kerckhoffs's principle);
the security of a proof rests on private keys that never leave the device.

`spec_version: 1`. When the signing layouts below change, this number is bumped
and a golden test vector for the prior version is retained forever.

---

## 1. Keys

| Key | Type | Signs | Where the public key is |
|---|---|---|---|
| Hardware attestation key | EC P-256 (secp256r1), ECDSA-SHA256 | every stage attestation | `device_attestation.certificate_chain[0]` |
| Device signer key | Ed25519 | the transport envelope | enrolled out-of-band (pairing) |

The hardware key lives in Android Keystore (StrongBox/TEE) or the iOS Secure
Enclave. `certificate_chain[0]` is a raw SEC1 point on iOS and an X.509 leaf
certificate on Android (the P-256 point sits in its SubjectPublicKeyInfo).

ECDSA signatures are **DER-encoded on Android** and **raw 64-byte `r‖s` on
iOS**; the encoding is selected by the `LocationProof.platform` field
(`"android"` / `"ios"`).

### 1.1 Hardware attestation (feature `appattest`)

A default build trusts only the key the proof *carries* (§5). Built with
`--features appattest`, the verifier additionally establishes — **offline** —
that the signing key is genuine secure hardware, on both platforms:

- **iOS — App Attest** (the `app-attest` check). The App Attest evidence is
  verified to Apple's App Attest root, **embedded in the binary** (no network
  call): chain, nonce, app/team identifiers, and the attested public key. An
  expected app/team identity is supplied via `--app-attest-config`. iOS carries a
  raw Secure Enclave key in `certificate_chain[0]` (not an X.509 chain), so the
  Android-style `attestation-root` line is `NOT-CHECKED` on iOS — App Attest is
  the iOS hardware root, and the two are told apart by key *shape*, not the
  editable `platform` field.
- **Android — key attestation** (the `attestation-root` check). The
  `device_attestation.certificate_chain` is validated leaf → … → an embedded,
  fingerprint-pinned Google hardware-attestation root (both the RSA-4096 root and
  the ECDSA P-384 root effective 2026-02-01); the leaf's Key Attestation extension
  must carry the expected key-generation challenge and a TEE / StrongBox security
  level. This flips the `attestation-root` line to a real Pass/Fail.
- On either platform the resolved hardware key then verifies
  `device_attestation.signature` (the field-2 device signature), turning that
  NOT-CHECKED line into a real Pass/Fail.

All of this is delegated to the public `octet-attest-verify` crate rather than
duplicated here. Absent the feature, these checks are NOT-CHECKED;
`--skip-hardware-attestation` scopes an `appattest` build back to core
verification. What is **not** done even under the feature: online revocation
(Google's certificate status list) and the deeper verified-boot fields — see §5.

---

## 2. Stage attestation chain

A proof carries `repeated StageAttestation stage_attestations`. Each stage is
signed by the hardware key over:

```
m = stage_utf8 || data_hash || timestamp_ms_be || previous_hash
sig = ECDSA-P256-SHA256(hardware_key, m)
```

- `data_hash = SHA-256(stage_data)`, 32 bytes (the wire `data_hash` field).
- `timestamp_ms` is the 8-byte millisecond timestamp, **big-endian** on both
  platforms.
- `previous_hash` is appended **only when present**. The first stage signs
  without it — it is *not* zero-filled.
- ECDSA `S` may be high or low: Android (SunEC) emits non-normalized
  signatures, iOS (CryptoKit) emits low-S. Both are valid; the verifier
  normalizes `S` before checking.

**Linkage.** The first stage carries no `previous_hash`; every later stage's
`previous_hash` equals the **previous stage's `data_hash`**. Timestamps are
non-decreasing.

**To verify a stage signature** the verifier needs only the wire
`StageAttestation` fields — never the stage's preimage data. So this spec does
not, and need not, describe how each stage's `data_hash` preimage is built
inside the SDK.

**Assembly.** The final stage is `proofAssembly`; its `data_hash` equals
`SHA-256(` concatenation of every prior stage's `signature` `)`. This binds the
whole chain into one value.

**Field binding.** Three stages' preimages *are* visible wire fields, so the
verifier re-derives and checks them:

| stage name   | `data_hash` must equal      |
|--------------|------------------------------|
| `commitment` | `SHA-256(position_commitment)` |
| `nullifier`  | `SHA-256(nullifier)`         |
| `zkProof`    | `SHA-256(zk_proof.proof_bytes)` |

**Platform-agnostic by design.** As of v1.0.0 both platforms emit the same
stage set (including `deviceAttestation`). The verifier does not rely on that:
the rules above (linkage, assembly, field binding) hold for any stage set, so it
never assumes a fixed stage count or order and MUST NOT hard-code either
platform's stage list.

### 2.1 Semantic-field binding (`semanticFields` stage)

The three bindings above cover opaque blobs (commitment / nullifier / ZK). The
human-meaningful fields — the spoofing verdict, claimed region, trust level,
device-integrity status, and the position commitment — are bound by a dedicated
`semanticFields` stage whose `data_hash` is `SHA-256` over a canonical preimage:

```
preimage = DOMAIN_TAG || verdict || level || integrity || region || commitment
```

The fields are length-prefixed and concatenated in a fixed order under a
domain-separation tag, so the byte layout is unambiguous and shared verbatim with
the SDK (cross-checked against the SDK's golden vector). The region component
covers the region **identity** for every region type, and the full **geometry**
for ellipse / H3 cell set / bounding box (each folds every scalar into a stable
digest, so an edited polygon is caught too). Editing a bound field after signing
changes the preimage, so the re-derived hash no longer matches the signed stage
and the proof is rejected.

**v1 coverage gap.** Under preimage v1, a `CityRegion`'s `center_lat` /
`center_lon` / `radius_meters` and an `EarthRegion`'s `max_altitude_meters` are
**not** in the preimage — only the city *name* / the earth *tag* are. Editing
those geometry fields is therefore NOT detected. To avoid overclaiming, a
matched city/earth `semanticFields` stage is reported `WARN` (not `PASS`) and
`Report::is_semantically_bound()` returns `false` for it, so a consumer that
trusts city coordinates fails closed. Binding city/earth geometry is the later
`octet-semantic-binding-v2` pass (verifier + both SDK signers, in lockstep).

A proof carrying no `semanticFields` stage reports NOT-CHECKED for this binding.

---

## 3. Transport signature (optional)

For session/continuous delivery a proof is wrapped:

```
ContinuousProofEnvelope { bytes proof_bytes; bytes proof_signature; }
```

`proof_signature = Ed25519(device_signer_key, proof_bytes)` over the exact
serialized `LocationProof`. Verifying it against the enrolled Ed25519 public key
binds the entire proof — every visible field — to the device identity. This is
the strongest authenticity signal the verifier offers and the only one that does
not depend on trusting the proof-embedded hardware key.

### 3.1 Replay-control binding

In backend-fetch and `--envelope` modes the surrounding envelope may surface
per-proof replay-control values — an upload nonce, the nullifier, and the signed
timestamp — alongside the proof. These are convenience surfaces and the backend
is untrusted (§7), so the verifier does not take them on faith: it confirms each
one matches what the proof *signed* (the nonce against the proof's upload-stage
hash, the nullifier against the signed `nullifier` field, the timestamp against
the signed stage timestamp). A value the backend altered fails the check; an
envelope that carries none reports NOT-CHECKED.

---

## 4. Verification recipe

1. Decode `LocationProof` (or unwrap `ContinuousProofEnvelope`).
2. **Freshness:** judge age against the **signed** stage timestamp — the
   `proofAssembly` stage's `timestamp_ms` (looked up by name), not the unbound
   top-level `LocationProof.timestamp_ms`, which carries no signature and is
   freely editable. Reject if older than the window (default 300 s) or more than
   a small skew into the future; a divergent top-level `timestamp_ms` is surfaced
   as a warning. To verify an old proof, judge it at a validation time or window
   instead of the current time (§4.1).
3. **Replay (presence only):** assert `nullifier` is non-zero — i.e. a replay
   token is *present*. This is **not** a cross-proof uniqueness guarantee: a
   stateless verifier cannot prove a token was never used elsewhere.
   Authoritative uniqueness is enforced **server-side at ingest**, where the
   cross-proof state lives. `--nullifier-store` adds a best-effort,
   single-process local "seen before?" check (a flat hex file); it is not atomic
   across concurrent invocations and is not the authoritative defense.
4. **Stage linkage** (§2).
5. **Stage signatures:** verify every stage `sig` against the hardware key,
   with the platform's encoding (§1).
6. **Assembly:** `proofAssembly.data_hash == SHA-256(concat prior sigs)` (§2).
7. **Field binding:** the three checks in §2. A field that is *present* but bound
   by no stage **fails** — the verifier will not vouch for an unverifiable value.
8. **Semantic-field binding:** if a `semanticFields` stage is present, re-derive
   the canonical semantic preimage (§2.1) and check it against the stage hash, so
   a post-sign edit of the verdict / region / level / integrity / commitment is
   rejected. Absent → NOT-CHECKED.
9. **Replay-control binding:** if the envelope carries `replay_control`, confirm
   the surfaced nonce / nullifier / timestamp match what the proof signed (§3.1).
   Absent → NOT-CHECKED.
10. **Wire-format:** reject a proof that smuggles a duplicate of a non-repeated
    top-level field (a last-wins parser-differential guard).
11. **Region:** report `claimed_region` / `level`; optionally assert expected.
12. **Transport signature** (§3), when an envelope and Ed25519 key are supplied.
13. **Hardware attestation** (feature `appattest`), all offline (§1.1):
    `attestation-root` validates the **Android** chain to an embedded Google root
    (iOS, carrying a raw Secure Enclave key, is NOT-CHECKED here); `app-attest`
    validates **iOS** App Attest to Apple's embedded root, by signature only
    (`app-attest-validity` NOT-CHECKED, §4.1); and
    `device-attestation-sig` verifies the field-2 device signature on both. All
    NOT-CHECKED on a default build or under `--skip-hardware-attestation`.

Any failure rejects the proof. Checks that are deliberately skipped (§5) are
reported as NOT-CHECKED — never silently treated as passes.

### 4.1 Historical verification (validation time)

Two checks depend on time: `freshness` and, under `appattest`, `attestation-root`
(each certificate in an Android key-attestation chain has a validity period). By
default both are judged at the current time. Certificates in a key-attestation
chain can be valid for only days, so an archived Android proof judged today FAILs
`attestation-root` and `freshness` although nothing about it changed.

The verifier can judge both at a point or an interval established from outside
evidence instead:

| Input | CLI | Library | Effect |
|---|---|---|---|
| Validation instant | `--at <time>` | `VerifyOptions::now_ms` | `freshness` and `attestation-root` are judged at that instant, with the usual `--max-age-seconds` window. |
| Validation window | `--window <from>/<to>` | `VerifyOptions::validation_window` | `freshness` PASSes when the signed `proofAssembly` time lies inside `[from, to]` (60 s skew at each end), and `--max-age-seconds` does not apply. `attestation-root` PASSes only when the chain is valid at both bounds. |

A time is RFC 3339 (`2026-07-29T11:42:21Z`, optional fractional seconds, `Z` or a
`±HH:MM` offset) or an integer number of Unix milliseconds. `--at` and `--window`
are mutually exclusive, and both apply in backend fetch mode (§7).

A window states when the proof can have been signed: no earlier than `from`, no
later than `to`. Typical evidence is the time a server issued the upload nonce
the proof embeds (lower bound) and a trusted timestamp over the stored proof
(upper bound). A certificate validity period is a single interval, so a chain
valid at both bounds was valid at every instant between them, including the
moment the proof was signed. A FAIL names the bound it failed at.

The verdict is only as good as the window. A window taken from the proof's own
signed time proves nothing, because the device chose that time. Use bounds that
come from independent evidence, and record which evidence they came from next to
the verdict.

`app-attest` (iOS) is verified by signature only, in every mode. The App Attest
leaf certificate is valid for about 3 days from attestation, and the attestation
usually happens at enrolment, long before the proof, so judging its dates at the
proof's time would reject almost every assertion-only proof. The verifier
therefore does not check App Attest validity dates at any time. Every
`app-attest` PASS comes with an `app-attest-validity` NOT-CHECKED line that says
so. Checking those dates at the attestation's own time needs a trusted record of
when the attestation happened, which a proof does not carry. Android
`attestation-root` chains are date-checked: at the current time by default, at
`--at`, or at both bounds of `--window`.

---

## 5. Out of scope / conditional (reported as NOT-CHECKED)

- **Hardware-key authenticity on a default build.** Without `--features appattest`
  the verifier does not establish that the signing key is genuine device hardware:
  a passing stage chain proves the proof is internally consistent and signed by
  the key it *carries*. Under the feature this is established — App Attest (iOS)
  or the Google-rooted key-attestation chain (Android), §1.1 — so it is
  conditional, not unconditionally out of scope.
- **App Attest certificate validity dates.** The App Attest chain is verified to
  Apple's root by signature, but its validity dates are not checked (§4.1). Every
  `app-attest` PASS is followed by an `app-attest-validity` NOT-CHECKED line.
- **`device_attestation.signature`.** The field-2 device signature is verified
  under `--features appattest` on both platforms (the per-proof binding is
  cross-platform); NOT-CHECKED on a default build.
- **Online revocation.** Even under `--features appattest`, Google's certificate
  status list (`android.googleapis.com/attestation/status`) is not consulted — a
  fully-offline verifier cannot — so an Android key revoked *after* issuance is
  not detected. The deeper verified-boot / `RootOfTrust` fields are likewise not
  yet enforced; the attested security level already establishes hardware backing.
- **Verdict / region / level / integrity / commitment binding.** Now checked via
  the `semanticFields` stage when the proof carries one (§2.1); a proof predating
  that stage reports NOT-CHECKED.
- **ZK proof.** The current backend is a placeholder; the ZK layer contributes
  no assurance until real circuits and a bundled verifier ship.

---

## 6. Wire schema

The vendored, public-safe subset of the proof schema lives in `proto/octet/`:
the `LocationProof` message and what it needs to decode, plus only the verdict
enum and the transport envelope. The SDK's internal detection types are not
vendored, and a few internal-only fields are dropped or genericized — but every
field's wire number and type is unchanged, so decoding is byte-for-byte exact.
Drift against the SDK's upstream schema is guarded in the SDK monorepo's CI, so
this vendored subset stays wire-compatible.

---

## 7. Backend fetch mode (`--features net`)

The `fetch`, `watch`, and `range` subcommands retrieve proofs from the Octet
proof ingestion API instead of a local file. They are compiled only with
`--features net`; the default build has no networking or JSON dependency, so the
crypto path the public is asked to trust stays minimal.

**The backend is untrusted — this is the load-bearing rule.** The backend is
transport + index only. This verifier treats every API response as nothing more
than "here are some bytes":

1. It base64-decodes `proof_bytes_b64` and runs the **identical** §4 pipeline it
   runs for a local file, against the kid registry embedded in this binary.
2. No backend-supplied field — `ingested_at`, `created_at`, `platform`,
   `proof_schema` — ever contributes to a verdict. Such fields are echoed only
   as explicitly-labelled untrusted display metadata.
3. The uploaded payload is a bare `octet.proof.LocationProof` (no transport
   envelope), so the §3 transport-signature check does not apply in this mode.
4. **Re-fetch consistency (invariant 4).** A `refetch-consistency` check records
   `sha256(proof_bytes)` per `proof_id`. Within a run, and across runs when
   `--seen-store <file>` is given, a `proof_id` that returns *different* bytes
   than first seen is a hard FAIL — the backend substituted bytes. `watch`
   re-prints a proof only when its bytes change; `range` exits non-zero if any
   proof (including a substitution) fails.

The trust anchor is the embedded kid registry, updated only via verifier
releases — never by anything the backend says. Auth is a scoped
`proof_upload_token` minted from the activation bearer (`--token`); it is
re-minted reactively on a 401 and proactively before its 24h TTL. Plain `http://`
is refused except for LAN-dev hosts (localhost, `127.*`, `10.*`, `192.168.*`),
so a downgraded production URL fails loud rather than shipping a bearer token in
the clear.

---

## 8. Machine-readable output (`--json`)

`--json` emits one JSON object per proof (newline-delimited / JSONL for
`range` and `watch`). The fields an automated consumer must understand:

| Field | Meaning |
|---|---|
| `valid` | **Authenticity** — `true` only if the proof was *not rejected* **and** its stage signatures were cryptographically verified. This is the bit to gate on. It is `false` for a proof whose signatures were `NOT-CHECKED` (e.g. no hardware key available), even though no check actively failed. |
| `signatures_verified` | The cryptographic bit on its own: `true` iff the `stage-signatures` check passed. |
| `verdict` | Tri-state string: `"VALID"`, `"INCONCLUSIVE (signatures not verified)"`, or `"INVALID"`. Lets a careful consumer distinguish "unverified" from "rejected". |
| `checks` | The full per-check array (`name` / `status` / `detail`). |

**`valid` is authenticity, not structural validity.** A structurally-sound proof
whose signatures were never checked reports `valid: false` / `verdict:
"INCONCLUSIVE …"` — it must never be treated as authentic. (The human-readable
output already reflects this with the `INCONCLUSIVE` headline; the JSON `valid`
field was aligned to it so a consumer keying on `valid` cannot be misled.)

### Exit codes

The process exit code is tri-state and authenticity-gated — `INCONCLUSIVE` is
never `0`, so `octet-verify … && deploy` cannot accept an unverified proof:

| Code | Meaning |
|---|---|
| `0` | **Authentic** — not rejected and signatures cryptographically verified (`VALID`). |
| `1` | **Invalid** — a check actively failed (`INVALID`). |
| `2` | Usage / IO / decode / backend error. |
| `3` | **Inconclusive** — structurally valid but signatures not verified (`INCONCLUSIVE`, e.g. no hardware key). |

For `range` / `watch`, the code reflects the worst proof observed: any `1` → `1`,
else any `3` → `3`, else `0`. Both the exit code and the JSON `valid` field are
safe authenticity gates for automation.

---

## 9. Browser verdict profile (`browser-verdict`, `--features browser`)

A separate profile from the `LocationProof` verifier above. It verifies the octet
browser product's **signed verdict token** and the session chain inside it,
against octet's published keys. It is verification only: it does not judge
whether the browser's signals were true.

```
octet-verify browser-verdict <verdict-token> [--jwks <url|file> | --archive]
    [--challenge <token> [--challenge-jwks <url|file>]] [--edge-log <line|@file>]
    [--roots <file>] [--manifest <url|file>] [--manifest-seq-store <file>]
    [--min-manifest-seq <n>] [--now <unix-seconds>] [--json]
```

A URL needs `--features net`; a JWKS file works offline. The library entry point
is `browser::verify_browser_verdict`.

### 9.1 Inputs

| Input | Required | Source |
|---|---|---|
| Verdict token | yes | the compact JWS octet returned beside the verdict |
| Verdict JWKS | yes | live: `https://geo.octetproof.com/.well-known/browser-verdict-jwks.json`; archive (every key octet has signed with, for a stored token whose key has rotated): `…/browser-verdict-jwks-archive.json` |
| Challenge token | no | the PASETO v4.public token the partner kept from `POST /v1/challenge` |
| Challenge JWKS | with the challenge | `…/.well-known/browser-challenge-jwks.json` |
| Edge log line | no | `{"octetChain":{"sid","env","s2","kid","ts"}}`, logged by the partner's edge. The raw line is accepted as the edge writes it, log prefix included (e.g. `2026/10/02 12:28:09 {"octetChain":…}`): the JSON starts at the first `{`. |

A key whose `octet_purpose` is set must match its use (`browser-verdict` or
`browser-challenge`), so a challenge key never verifies a verdict. Two keys with
the same `kid` are refused.

### 9.2 Checks

Each check reports `VERIFIED`, `FAILED`, `NOT-CHECKED`, `WARN` (the root
manifest only, §9.3), or `ATTESTED` (5 below).
The verdict passes when no check FAILED and `verdict-jws` VERIFIED. If
`verdict-jws` fails, every other check is NOT-CHECKED and the claims are not
reported.

1. **`verdict-jws`.** `typ` is `octet-browser-verdict+jwt;v=1`, `v=2` or `v=3`
   (the suffix versions the claim set). The key is the one the header `kid`
   names, and the `alg` must match it: `ES256` with an EC P-256 key (signature
   is IEEE P1363 raw `r‖s`, 64 bytes, not DER) or `EdDSA` with an OKP Ed25519
   key. Any other pairing is refused, as is a header `alg` that differs from the
   JWK's `alg`. The signature covers the ASCII `b64url(header).b64url(claims)`.
   `iss` is `octet-browser`.
   - **`key-validity`** (archive keys). When the key carries `octet_not_before`,
     the verdict `iat` must lie within `octet_not_before … octet_not_after`
     (±60 s; no `octet_not_after` for the current key). A key with
     `octet_status: "revoked"` fails any token with `iat ≥ octet_revoked_at`.
     A live key carries no window: NOT-CHECKED.
   - **`verdict-expiry`.** VERIFIED while `now ≤ exp + 60 s`. An expired token
     is NOT-CHECKED, not FAILED: a stored record is expected to be expired, but
     a live decision should refuse it. `exp < iat` FAILS.
2. **`chain-root`** (`v=3`). Recompute `chain_root` from the signed `chain`
   claim and compare. Every digest is decoded to its 32 raw bytes:

   ```
   chain_root = base64url_nopad(SHA-256(
       "octet-browser-chain-v1"            UTF-8, no terminator
     ‖ s0                                  32 bytes
     ‖ u32be(len(reports))
     ‖ for each report, in order:
         s1.bundle                         32 bytes
       ‖ u64be(s1.t)                       the S1 signing time, ms (≤ 2^53 − 1)
       ‖ s1.sig                            32 bytes
       ‖ env                               32 bytes
       ‖ s2.h, or 32 zero bytes when the report has no s2
     ‖ rcpt, or 32 zero bytes when absent   once, after the reports
   ))
   ```

   `chain.v` must be `1`. A `v=3` token without `chain` and `chain_root` FAILS.
   `v=1` and `v=2` tokens carry no chain: NOT-CHECKED, along with checks 3–5.
3. **`session-link`** (with the challenge token).
   - `base64url(SHA-256(UTF-8 challenge token)) == chain.s0`;
   - the challenge verifies as PASETO `v4.public`: Ed25519 over
     `PAE("v4.public.", m, footer, "")`, the footer is `{"kid"}` naming a key in
     the challenge JWKS, and there is no implicit assertion;
   - its claims have `typ == "octet-browser-challenge"`, `v == 1`, and a
     `sessionRef` equal to the verdict's;
   - the verdict `iat` lies within `[challenge iat, challenge exp + 60 s]`.

   The challenge's `lid` (the licence) is reported. A challenge without its JWKS
   is NOT-CHECKED.
4. **`edge-link`** (with the edge log line). Some report `i` has
   `env == reports[i].env`, `s2 == reports[i].s2.h` and
   `kid == reports[i].s2.kid`.
5. **Attested links.** `s1-device-signature` (octet verified the device's S1
   signature over each `s1.bundle`) and `anchor-receipts` (the receipts behind
   `rcpt`, which name the user's IP) are reported as **ATTESTED**, meaning
   "attested by octet". A third party cannot re-check them, so they are never
   VERIFIED.

The digests themselves are defined as: `s0 = SHA-256(challenge token)`,
`s1.bundle = SHA-256(signed bundle JSON)`, `s1.sig = SHA-256(raw S1 signature)`,
`env = SHA-256(request body)`, `s2.h = SHA-256(edge signature token)`, and
`rcpt = SHA-256(concatenation of SHA-256(receipt token), sorted bytewise)`.

### 9.3 Root manifest

Every key list above is served by octet's geo server, so on its own it is only as
trustworthy as that server. octet's **offline root** (a P-256 key on a hardware
token, never on a server) signs one **manifest** listing every verdict key and
every challenge key. When a manifest is checked, a key the root didn't list is
refused.

- **Where:** `https://geo.octetproof.com/.well-known/octet-browser-manifest.json.jws`,
  a compact JWS whose payload is the manifest bytes exactly.
- **Roots are pinned, never fetched** from the server being checked: built into
  the binary (`browser::PINNED_ROOTS_JSON`, none yet; they are added at octet's
  first root ceremony) or passed with `--roots <file>` (`{"roots":[...]}`, EC
  P-256 JWKs, `octet_purpose` `octet-root`). Without a pinned root the manifest
  checks are NOT-CHECKED and nothing is fetched.

**`root-manifest`:**

1. The header is exactly `{"alg":"ES256","typ":"octet-root+jws;v=1","kid"}`;
   any other field is refused. `kid` must name a pinned root. The signature is
   ES256 raw `r‖s` over `b64url(header).b64url(payload)` (not DER).
2. The payload has `typ "octet-browser-manifest"`, `v` 1, a positive integer
   `seq`, integer `iat` / `exp` with `exp − iat` ≤ 400 days, and a non-empty
   `roots` (the roots that may sign the next manifest).
3. **Rollback:** a `seq` lower than the highest already seen FAILS. The
   verifier is stateless, so the caller keeps that number
   (`min_manifest_seq` in, `manifest_seq` out; `--manifest-seq-store <file>` in
   the CLI). The server does not track it.
4. **Expiry:** VERIFIED until `exp` (the detail notes the last 30 days); **WARN**
   after `exp` within a 14-day grace (the window in which octet's server still
   runs); **FAILED** after that. A long-expired manifest is a stale key list, and
   expiry is what bounds a freeze attack (serving an old list after a key is
   revoked).

**`manifest-verdict-key`:** the verdict token's `kid` must be in `verdictKeys`
with the same key material (`kty`, `crv`, `x`, `y`), else FAILED. The entry's
`octet_not_before` / `octet_not_after` / `octet_status` then drive `key-validity`
(§9.2), which therefore runs instead of reading NOT-CHECKED.

**`manifest-challenge-key`:** the same for the challenge's footer `kid` against
`challengeKeys`, once the session link verified.

A manifest that FAILS is not used for the key checks (they read NOT-CHECKED);
one in its WARN grace still is.

### 9.4 Out of scope

- Whether the browser's signals, and so the verdict (`alarm`, `confidence`,
  `country`), are true. The token proves octet said it, not that it is right.
- The `deviceKey`: an opaque, partner-scoped identifier.
- `clientNetMatch` (`v=3`, optional boolean): whether the report came from the
  client network the partner's backend saw. octet makes the comparison; no token
  carries the network, so there is nothing to recompute. It is reported as
  signed, and `false` is a valid result, not a verification failure. Absent when
  the partner sent no client IP.
- `clientNet` (older `v=1` / `v=2` tokens only): an opaque informational claim.
  It is never decoded or printed. A challenge's optional `cn` claim (a keyed
  per-licence tag) is likewise opaque and ignored; `s0` still covers the whole
  challenge token.
- That the `sessionRef` is one the partner issued, and replay of an old token:
  the partner checks both against its own records.

### 9.5 Output and exit codes

`--json` emits `valid`, `version` (the `typ` suffix), `lid` (when the session
link verified), `manifest_seq` (when the root manifest verified),
`client_net_match` (the signed `clientNetMatch`, or `null`), `claims`
(only when `verdict-jws` VERIFIED) and `checks`
(`name` / `status` / `detail`). Exit codes: `0` no check failed, `1` a check
failed, `2` usage, IO or JWKS error.

Golden vectors in `test-vectors/browser-verdict-chain/`: `chain-vector.json`
(deterministic, shared with octet-browser's server and edge), `dev-vector.json`
(a real verdict from octet-browser's dev stack, through S0, S1, S2 and the edge
log; verify it at its `nowForChecks`), and `manifest-vector.json` (a root manifest signed by the dev root `root-dev-1`,
which production never trusts, with timestamps for each expiry window).
