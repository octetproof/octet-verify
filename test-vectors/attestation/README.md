# Real-device attestation fixtures

Genuine, physical-device `LocationProof` artifacts that carry a **real hardware
key-attestation chain** — unlike `../golden/` (software-signed, deterministic,
`attestation-root` NOT-CHECKED). These exercise the `--features appattest` layer
end to end: the chain validates to an embedded Google root, and the Android
app-identity binding (`attestationApplicationId`) is checked against the
producing app.

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
