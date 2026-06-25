# Integrating `octet-verify`

This guide is for people who want to **independently verify** Octet location
proofs — auditors, integrators, or anyone holding a license who wants to confirm
that proofs attributed to it are authentic and untampered, without trusting
Octet's servers to vouch for them.

`octet-verify` does one thing: it takes proof bytes, checks the cryptography,
and tells you — precisely — what it could and could not confirm. It never
re-runs Octet's spoof detection and never asks a server whether a proof is
"valid." The trust anchor is the public-key (kid) registry compiled into the
binary you build.

- [Building](#building)
- [Verifying a local proof file](#verifying-a-local-proof-file)
- [Fetching from the backend](#fetching-from-the-backend) — `fetch` / `watch` / `range`
- [Reading the verdict](#reading-the-verdict) ← start here if you just ran it
- [The trust model in practice](#the-trust-model-in-practice)
- [Exit codes & scripting](#exit-codes--scripting)

## Building

The core verifier is offline and dependency-light:

```sh
cargo build --release
./target/release/octet-verify --help
```

The backend subcommands (`fetch`, `watch`, `range`) talk to the network, so they
are **opt-in at build time** behind the `net` feature:

```sh
cargo build --release --features net
```

If you run a backend subcommand against a binary built without `net`, it tells
you and exits — it never silently no-ops.

Offline Apple App Attest verification is a second opt-in feature, `appattest`
(see [App Attest](#app-attest-optional---features-appattest) under *Reading the
verdict*). It is independent of `net`; combine them if you want both:

```sh
cargo build --release --features net,appattest
```

## Verifying a local proof file

If you already have proof bytes (a `.bin` exported by the SDK, or piped in):

```sh
octet-verify proof.bin
cat proof.bin | octet-verify --json
```

Everything below about [reading the verdict](#reading-the-verdict) applies
identically — backend mode just sources the same bytes over HTTP.

## Fetching from the backend

All three subcommands take a backend base URL and your **activation bearer**;
the CLI exchanges that bearer for a short-lived, upload-scoped token
(`POST /v1/proofs/auth`) and refreshes it automatically. You never pass the
upload token directly.

```sh
export OCTET_BACKEND="https://api.octetproof.com"
export OCTET_TOKEN="<your activation bearer>"
```

> Plain `http://` is refused except for LAN-dev hosts (`localhost`, `127.*`,
> `10.*`, `192.168.*`). A downgraded production URL fails loud rather than
> sending your bearer token in the clear.

> **Proofs are short-lived.** The backend retains a proof for a limited window
> (currently ~24h after upload) and then purges it, so fetch and verify
> promptly — an aged-out `proof_id` returns `404`. This is a backend operational
> policy, not part of the verifier's contract, and may change.

### `fetch` — one proof by id

```sh
octet-verify fetch lp_01HN8K2M7Q9X3P4R5S6T7U8V9W \
  --backend "$OCTET_BACKEND" --token "$OCTET_TOKEN"
```

### `watch` — live audit

Polls for the newest proof and verifies each new one as it arrives — handy while
demoing or while a device is actively generating proofs. Runs until you press
Ctrl-C; the process then exits with the **last proof's verdict**.

```sh
octet-verify watch --backend "$OCTET_BACKEND" --token "$OCTET_TOKEN" --interval 5
```

### `range` — verify a time window

Verifies every proof in a `created_at` window (RFC 3339), paginating
automatically, and **exits non-zero if any proof fails** — the building block of
a batch audit. Because the backend only retains proofs for ~24h (see above), a
range is bounded in practice to the last day's uploads, not long-range history.

```sh
octet-verify range \
  --backend "$OCTET_BACKEND" --token "$OCTET_TOKEN" \
  --since 2026-06-07T00:00:00Z --until 2026-06-08T00:00:00Z \
  --seen-store audit-seen.txt --max-age-seconds 90000
```

Two flags worth calling out for ranges:

- `--max-age-seconds` — proofs are freshness-checked against *now*. Retained
  proofs can be up to ~24h old, which trips the default 300s window, so set this
  a little above the retention window (above: `90000` ≈ 25h) so a
  legitimately-recent proof isn't flagged stale.
- `--seen-store <file>` — records `proof_id → sha256(bytes)` so that if the
  backend ever returns *different* bytes for an id you've seen before, it fails
  loud (see [trust model](#the-trust-model-in-practice)). Reuse the same file
  across runs to make that guarantee span audits.

## Reading the verdict

A run prints one block per proof. Here's a passing one:

```
── proof lp_success ──
  backend metadata (untrusted): platform=ios created_at=2026-06-04T18:24:00Z schema=octet.proof.LocationProof
  verdict: VALID
    [       PASS] freshness              42 s old (limit 300 s)
    [       PASS] nullifier              replay token present (32 bytes); uniqueness enforced server-side, not here
    [       PASS] stage-chain            6 stages, hash linkage intact
    [       PASS] stage-signatures       all 6 stage signatures verify (raw key from certificate_chain)
    [       PASS] chain-assembly         final stage binds all 5 prior signatures
    [       PASS] field-binding          commitment, nullifier, zkProof bound to signed stage hashes
    [       PASS] semantic-binding       spoofing_verdict / region / level / integrity / commitment bound to the signed semanticFields stage
    [       PASS] region-claim           claims country:US (level 2)
    [       PASS] wire-format            no duplicate non-repeated proto fields
    [       PASS] replay-binding         envelope replay-control bound to the signed proof: nonce↔uploadChallenge, nullifier echo, signed-timestamp echo
    [NOT-CHECKED] attestation-root       hardware key trusted as carried; chain to Google/Apple attestation root not validated on a default build (build --features appattest)
    [NOT-CHECKED] device-attestation-sig DeviceAttestation.signature not verified in the default build (build --features appattest to verify field 2)
    [NOT-CHECKED] zk-proof               backend is PLACEHOLDER; ZK layer contributes no assurance
    [       PASS] refetch-consistency    first sighting of this proof_id; byte-hash recorded
```

### The headline

| Verdict | Meaning |
|---|---|
| **`VALID`** | Every check that was performed passed, **and** the stage signatures were cryptographically verified. The proof is internally consistent and signed by the key it carries. |
| **`INCONCLUSIVE (signatures not verified)`** | Nothing failed, but the hardware public key wasn't available, so signatures couldn't be checked. Not a pass — supply the key (see below). |
| **`INVALID`** | At least one check **failed**. The proof is rejected. |

### What a passing verdict does — and does not — mean

A `VALID` result means: *this proof is internally consistent and self-signed by
the key embedded in it* (every stage links to the previous, the assembly stage
binds all prior signatures, the visible commitment/nullifier/ZK bytes match their
signed hashes, and the semantic fields — verdict, region, level, integrity, and
committed position — are the ones that were signed, so a post-sign edit of any of
them is rejected).

On a **default build** it does **not** mean the signing key is proven to be
genuine device hardware. That's why some lines read `NOT-CHECKED` rather than
`PASS` — and the tool says so out loud instead of quietly counting them as wins:

- **`attestation-root`** and **`device-attestation-sig`** — `NOT-CHECKED` on a
  default build; build with `--features appattest` (see below) to validate the
  hardware attestation offline, turning these into real `PASS`/`FAIL`.
- **`zk-proof`** — placeholder ZK backend contributes no assurance yet.

`NOT-CHECKED` never fails a proof and never makes one valid; it's there so you
know the exact boundary of what was confirmed.

### Hardware attestation (optional, `--features appattest`)

You can additionally prove the signing key is genuine secure hardware,
**offline** — vendor roots are embedded in the binary, so no network call is
made:

- **iOS** — Apple App Attest evidence verified to Apple's embedded root (pass an
  app/team identity via `--app-attest-config`).
- **Android** — the Keystore certificate chain validated to an embedded,
  fingerprint-pinned Google hardware-attestation root, with a TEE / StrongBox
  security level required on the leaf.

```sh
cargo build --release --features appattest
octet-verify <id> ... --app-attest-config app-attest.toml
```

Under the feature both `attestation-root` and `device-attestation-sig` become
real `PASS`/`FAIL`; without it they stay `NOT-CHECKED` — never silently treated
as a pass. `--skip-hardware-attestation` scopes an `appattest` build back to core
verification (handy for a legacy or synthetic proof that carries no real chain).
Online revocation (Google's status list) is **not** consulted even under the
feature — see [`VERIFICATION-SPEC.md`](VERIFICATION-SPEC.md) §5.

### A failing verdict

```
── proof lp_tampered ──
  backend metadata (untrusted): platform=ios created_at=2026-06-04T18:24:00Z schema=octet.proof.LocationProof
  verdict: INVALID
    ...
    [       FAIL] stage-signatures       stage 1 (commitment): ECDSA-P256 signature did not verify
    [       FAIL] chain-assembly         final stage (proofAssembly) data_hash != SHA-256(concatenated prior signatures)
    ...
```

Each `FAIL` names exactly what broke. A signature failure like the above is what
you'd see if the proof bytes were altered after signing — the signatures no
longer match the content.

### Supplying the hardware key

iOS proofs may not carry a certificate chain. If you see
`INCONCLUSIVE`/`stage-signatures … no hardware public key available`, pass the
enrolled key:

```sh
octet-verify fetch <id> --backend "$OCTET_BACKEND" --token "$OCTET_TOKEN" \
  --hardware-pubkey device.pubkey
```

### Asserting a region

To fail unless the proof claims a specific region (ISO country/subdivision code
or city name):

```sh
octet-verify fetch <id> ... --expect-region US-CA
```

### JSON output

`--json` emits one JSON object per proof, newline-delimited (JSONL) — one line
per proof, so `range`/`watch` stream cleanly into `jq`:

```json
{"proof_id":"lp_success","verdict":"VALID","valid":true,"signatures_verified":true,"checks":[{"name":"freshness","status":"PASS","detail":"..."}, ...],"backend_meta_untrusted":{"platform":"ios","created_at":"2026-06-04T18:24:00Z"}}
```

```sh
# valid:true means authentic — gate your automation on it
octet-verify range ... --json | jq -c 'select(.valid == false) | .proof_id'
```

**Gate automation on `valid`.** It is `true` only when the proof is not rejected
*and* its signatures were cryptographically verified — so a structurally-sound
but signature-`NOT-CHECKED` proof (e.g. no hardware key) reports `valid:false` /
`verdict:"INCONCLUSIVE …"`, never a false positive. `signatures_verified` exposes
the crypto bit directly, and `verdict` carries the tri-state string if you need
to tell `INCONCLUSIVE` from `INVALID`. (The process exit code is authenticity-gated
too — see [Exit codes](#exit-codes--scripting) — so either signal is a safe gate.)

Note `backend_meta_untrusted`: those fields are echoed for convenience only and
played **no part** in the verdict.

## The trust model in practice

The backend is **untrusted**. `octet-verify` treats every API response as
nothing more than "here are some bytes":

1. It decodes the proof bytes and runs the **same** checks it runs for a local
   file, against the kid registry compiled into your binary — never against
   anything the server asserts.
2. No backend-supplied field (`ingested_at`, `created_at`, `platform`, …) ever
   affects a verdict.
3. **Re-fetch consistency:** with `--seen-store`, if a `proof_id` you've already
   seen comes back with different bytes, that's a hard `FAIL` — the server
   substituted content. This is your defense against a compromised or buggy
   backend swapping a proof.

So a compromised backend can withhold or drop proofs, but it cannot make
`octet-verify` accept a forged or altered one. If you want that guarantee to be
ironclad, build the binary yourself from source you've read.

## Exit codes & scripting

| Code | Meaning |
|---|---|
| `0` | **Authentic** — not rejected *and* signatures cryptographically verified. |
| `1` | **Invalid** — a check actively failed (includes a re-fetch byte mismatch). |
| `2` | Usage, I/O, decode, or backend error (e.g. a `4xx`/`5xx` surfaced from `application/problem+json`). |
| `3` | **Inconclusive** — structurally valid but signatures not verified (e.g. no hardware key). Never `0`. |

Exit `0` is a safe authenticity gate — an unverified (`INCONCLUSIVE`) proof exits
`3`, never `0`. For `range`, the code reflects the worst proof in the window (any
`1` → `1`, else any `3` → `3`, else `0`), so a CI audit is just:

```sh
octet-verify range --backend "$OCTET_BACKEND" --token "$OCTET_TOKEN" \
  --since "$SINCE" --until "$UNTIL" --seen-store audit-seen.txt --max-age-seconds 90000 \
  || echo "AUDIT FAILED — see report above"
```

For the byte-exact signing contract every check implements, see
[`VERIFICATION-SPEC.md`](VERIFICATION-SPEC.md) (§7 covers backend fetch mode).
