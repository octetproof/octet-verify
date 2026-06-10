# Octet Proof Verification Spec (v1)

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

---

## 3. Transport signature (optional)

For session/continuous delivery a proof is wrapped:

```
ContinuousProofEnvelope { bytes proof_bytes; bytes proof_signature; }
```

`proof_signature = Ed25519(device_signer_key, proof_bytes)` over the exact
serialized `LocationProof`. Verifying it against the enrolled Ed25519 public key
binds the entire proof — every visible field — to the device identity. This is
the strongest authenticity signal v1 offers and the only one that does not
depend on trusting the proof-embedded hardware key.

---

## 4. Verification recipe (v1)

1. Decode `LocationProof` (or unwrap `ContinuousProofEnvelope`).
2. **Freshness:** reject if `|now − timestamp_ms| > window` (default 300 s).
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
7. **Field binding:** the three checks in §2.
8. **Region:** report `claimed_region` / `level`; optionally assert expected.
9. **Transport signature** (§3), when an envelope and Ed25519 key are supplied.

Any failure rejects the proof. Checks that are deliberately skipped (§5) are
reported as NOT-CHECKED — never silently treated as passes.

---

## 5. Out of scope in v1 (reported as NOT-CHECKED)

- **Hardware-key authenticity.** The Android certificate chain is not validated
  to Google's attestation root, and iOS App Attest is not checked. So a passing
  stage chain proves the proof is internally consistent and signed by the key it
  *carries* — not that the key is genuine device hardware. Establishing that is
  the job of a later attestation-root layer, or of the transport signature (§3).
- **`device_attestation.signature`.** Platform-specific (Android binds the
  commitment; iOS is the integrity-gate session signature); not verified in v1.
- **Verdict / confidence / level binding.** These are bound via stage hashes
  whose preimages require internal serialization to re-derive (a later layer).
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
