# octet-verify

An **independent, open verifier** for Octet `LocationProof` artifacts. It reads
a proof and checks that it is authentic and untampered — signatures, hash-chain
linkage, field bindings, freshness — and prints exactly what it did and did not
verify. It is meant to be read: you should be able to audit this code and trust
that a proof you check is what it claims to be, without trusting us.

It contains **none** of the SDK's proof-*creation* logic: no spoof-detection
heuristics, no signal weights, no verdict thresholds. A verifier checks
authenticity and integrity; it does not re-run detection. That boundary is what
lets this be public.

## Build & run

```sh
cargo build --release
./target/release/octet-verify proof.bin
cat proof.bin | ./target/release/octet-verify --json
./target/release/octet-verify --help
```

Exit codes: `0` valid · `1` invalid (a check failed) · `2` usage/IO/decode.

### Backend fetch mode (optional, `--features net`)

The `fetch` / `watch` / `range` subcommands pull proofs from the Octet proof
ingestion API and verify them end-to-end. This path is **opt-in at build time**
so the default verifier stays dependency-clean — the crypto code the public
audits pulls no networking or JSON stack.

```sh
cargo build --release --features net
octet-verify fetch <proof-id> --backend https://api.octetproof.com --token <activation-bearer>
octet-verify watch            --backend https://api.octetproof.com --token <bearer>   # live audit
octet-verify range --since 2026-06-01T00:00:00Z --until 2026-07-01T00:00:00Z \
            --backend https://api.octetproof.com --token <bearer> --seen-store seen.txt
```

The backend is **untrusted**: fetched bytes go through the same pipeline as a
local file, and no backend-supplied field affects the verdict. See
[`VERIFICATION-SPEC.md`](VERIFICATION-SPEC.md) §7 for the contract and
[`INTEGRATION.md`](INTEGRATION.md) for a consumer's how-to (worked examples and
how to read a verdict). Default release builds (and any public-release
artifacts) should be built **without** this feature.

## What it verifies

- stage attestation chain linkage and each per-stage hardware **ECDSA-P256**
  signature (DER on Android, raw on iOS, selected by the proof's `platform`);
- the `proofAssembly` stage binding every prior stage signature;
- `commitment` / `nullifier` / ZK-bytes bound to their signed stage hashes;
- **semantic-field binding** — the spoofing verdict, region, trust level, device
  integrity, and committed position bound to the signed proof, so editing any of
  them after signing is rejected (every region type, including geometric);
- **replay-control binding** — when a fetched/enveloped proof carries per-proof
  replay-control values, they are checked against what the proof actually signed;
- a **wire-format guard** that rejects a proof smuggling a duplicate top-level
  field;
- freshness (judged on the proof's *signed* timestamp), and optional cross-run
  replay (`--nullifier-store`);
- the **Ed25519 transport signature** when given an envelope and the enrolled
  key (`--envelope --ed25519-pubkey …`) — this binds the *whole* proof to the
  device identity and is the strongest authenticity signal here;
- **Hardware attestation**, offline, when built `--features appattest`: on iOS,
  **Apple App Attest** to Apple's embedded root (with `--app-attest-config`); on
  Android, the **key-attestation certificate chain** to an embedded Google
  hardware-attestation root; and the device-attestation signature on either
  platform — all becoming real Pass/Fail. See
  [Hardware attestation](#hardware-attestation-optional---features-appattest) below.

## What it does NOT verify — and says so

Every skipped check is printed as `NOT-CHECKED`, never as a pass:

- **Hardware-key authenticity on a default build.** Without `--features appattest`
  the verifier does not establish that the signing key is genuine device hardware
  — a passing stage chain proves only that the proof is internally consistent and
  signed by the key it *carries*. Build `--features appattest` (below), or use the
  Ed25519 transport signature, for device-identity assurance.
- **Online revocation.** Even under `appattest`, Google's certificate status list
  is not consulted (a fully-offline verifier cannot), so an Android key revoked
  after issuance is not detected. The ZK proof (placeholder backend) is also
  `NOT-CHECKED`. See [`VERIFICATION-SPEC.md`](VERIFICATION-SPEC.md).

### Hardware attestation (optional, `--features appattest`)

Opt-in at build time, like backend fetch. It pulls in the public
`octet-attest-verify` crate to verify, **offline** (vendor roots embedded; no
network call):

- **iOS** — Apple App Attest evidence to Apple's root;
- **Android** — the Keystore certificate chain to an embedded, fingerprint-pinned
  Google hardware-attestation root (RSA-4096 + the ECDSA P-384 root effective
  2026-02-01), plus the leaf's TEE / StrongBox security level;
- the device-attestation signature (field 2) on either platform.

```sh
cargo build --release --features appattest
octet-verify proof.bin --app-attest-config app-attest.toml   # iOS app identity
# --skip-hardware-attestation scopes an appattest build back to core verification
```

## Trust model in one line

A passing `octet-verify` run means: *this proof is internally consistent and
self-signed by the key it carries (plus, if an envelope was supplied, bound to
the enrolled device identity; plus, under `--features appattest`, a key proven to
be genuine secure hardware — Secure Enclave on iOS, TEE / StrongBox on Android)*
— and, on a default build, **not** that the signing key is rooted in genuine
hardware.

## Layout

- `proto/` — the vendored, public-safe subset of the proof wire schema.
- `src/` — `crypto` (ECDSA/Ed25519/SHA-256), `keys`, `verify`, the CLI, and
  `backend` (the untrusted-API client, `--features net` only).
- `VERIFICATION-SPEC.md` — the byte-exact signing contract this implements
  (§7 covers backend fetch mode).
- `test-vectors/golden/` — real signed proofs kept verifiable forever.
- `test-vectors/backend/` — golden proof-ingestion-API responses for the fetch path.

## License

Licensed under the **Apache License 2.0** — see [`LICENSE`](LICENSE) and
[`NOTICE`](NOTICE). Copyright 2026 Understone, Inc. d/b/a Octet.
