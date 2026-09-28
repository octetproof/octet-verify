# Real-device attestation fixtures

Genuine, physical-device `LocationProof` artifacts that carry **real hardware
attestation evidence** — unlike `../golden/` (software-signed, deterministic,
`attestation-root` NOT-CHECKED). These exercise the `--features appattest` layer
end to end against genuine Apple / Google output.

## `pixel9-strongbox.bin`

A `LocationProof` captured from the sample app (`com.octetproof.sample`) on a
Pixel 9 (StrongBox-backed key). Verified: `attestation-root PASS` (chain →
Google hardware-attestation root, StrongBox), `device-attestation-sig PASS`,
schema-v2 semantic binding.

Expected Android app identity (asserted by `tests/android_app_binding.rs`):
- `package_name` = `com.octetproof.sample`
- `signing_cert_sha256` = `9bb28af937cf7f486b258de827d45839563fb8c6cb037d3272fca1aa78159c4d`

**Time-pinned.** The attestation certificates have `notBefore`..`notAfter`
windows, so the app-binding test pins verification time to a fixed instant
within those windows (the capture time) — deterministic, and it never goes stale
the way wall-clock verification of an expiring leaf would.

## `ios-appattest.bin`

A `LocationProof` captured from the sample app (`com.octetproof.sample`, team
`6ZH5F97PWU`, env `development`) on an iPhone 11 (`` SDK build). It is a
**first-of-key** proof, so it carries the Apple App Attest **attestation object**
(the object-bearing green path), and its live per-proof assertion is the **
bound form**: `clientDataHash = SHA256(nonce ‖ SE_signing_key)`, committing the
Secure-Enclave key in `certificate_chain[0]` that signs the proof.

Exercised by `tests/ios_app_attest.rs`: `app-attest PASS` (object → Apple App
Attest root → recovered key → bound assertion verified under **RequireBound**),
`device-attestation-sig PASS`, `attestation-root NOT-CHECKED` (iOS carries a raw
Secure-Enclave key, not an X.509 chain — hardware-root assurance is `app-attest`).
This is the iOS half of /: before this fixture the object-bearing green
path was verified from source only.

**Centre coarsened.** The `claimed_region.city` centre is rounded to one decimal
place (~11 km). Region geometry is not covered by the v1 semantic preimage — the
verifier reports `region GEOMETRY is NOT covered` — so the centre is unsigned,
carries no verification weight, and rewriting it breaks no signature or hash:
every check status is identical before and after, and the byte length is
unchanged. It was a real position on a real device and this fixture is public, so
it is held to the granularity the 50 km claimed radius already implies.
`tests/fixture_precision.rs` enforces that bound for every shipped fixture.

**Not time-pinned to a cert window** (iOS attestation has no X.509 validity
window); only proof freshness is time-sensitive, so the test uses a fixed `now`
with a generous freshness window.
