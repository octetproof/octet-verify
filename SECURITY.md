# Security model and reporting

## What a passing verification means

`octet-verify` confirms that a `LocationProof`:

- is internally consistent — its stage attestation chain links correctly and
  the final stage binds every prior signature;
- is signed throughout by **one** P-256 key — the one the proof carries;
- has its `commitment`, `nullifier`, and ZK bytes bound to that signed chain;
- is fresh (within the configured window) and, optionally, not a replay;
- and — only when an envelope and the enrolled Ed25519 key are supplied — is
  bound in its entirety to that device identity by the transport signature.

## What it deliberately does NOT establish (v1)

- **That the signing key is genuine device hardware.** The Android certificate
  chain is not validated to Google's hardware-attestation root, and iOS App
  Attest is not verified. Without that, the stage signatures prove the proof is
  self-consistent and self-signed — an attacker who fabricates a proof can sign
  it with their own key and embed that key. The *only* v1 check that resists
  this is the Ed25519 transport signature against a key you enrolled
  out-of-band. Treat a proof verified without it as integrity-checked, not
  authenticated.
- The meaning of `device_attestation.signature`, the spoofing verdict /
  confidence / level fields, and the ZK proof. These are reported as
  NOT-CHECKED.

These limits are printed on every run and detailed in `VERIFICATION-SPEC.md`.
They are documented gaps (attestation-root validation, ZK verification are
out of scope for v1), not hidden ones.

## Non-leakage

This crate intentionally excludes all proof-creation logic — no spoof-detection
identifiers, no detection heuristics, none of the SDK's internal wire types. It
depends only on the public, vendored proof schema under `proto/` and the
published verification contract; nothing here can reconstruct how a proof is
produced.

## Reporting a vulnerability

Report suspected verification weaknesses — a forged proof that passes, a valid
proof that fails, or any signature-handling flaw — privately to
**security@octetproof.com**. Please include a minimal proof artifact and the
exact `octet-verify` invocation. Do not open a public issue for a verification
bypass until it has been triaged.
