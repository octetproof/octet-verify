# OctetSDK 3.0.0 — real-device proofs

Signed `LocationProof`s produced by **OctetSDK 3.0.0** on physical phones, so a
verifier release can show it verifies the current SDK's output end to end.

## What's here

Seven proofs captured 2026-10-13 and two more on 2026-10-15, all with
`sdk_version` `3.0.0`, from an internal debug build of the sample app against a
development licence. Both phones were in
the United Kingdom.

| file | platform | kind | claim | signed verdict |
|---|---|---|---|---|
| `android-pixel9/area_country.bin` | Android (StrongBox) | area | earth (level 1) | — |
| `android-pixel9/area_subdivision.bin` | Android | area | country:GB | — |
| `android-pixel9/within_country_gb.bin` | Android | within GB | country:GB | Inside |
| `android-pixel9-2026-10-15/area_country.bin` | Android | area | country:GB | — |
| `android-pixel9-2026-10-15/within_country_gb.bin` | Android | within GB | country:GB | Inside |
| `ios-iphone11/area_country.bin` | iOS (App Attest) | area | country:GB | — |
| `ios-iphone11/area_subdivision.bin` | iOS | area | country:GB | — |
| `ios-iphone11/within_country_gb.bin` | iOS | within GB | country:GB | Inside |
| `ios-iphone11/within_country_gb_first_call.bin` | iOS | within GB | country:GB | Inside |

- The Android `area_country` proof claims **earth**, not the country: the SDK
  could not resolve the region yet just after start, so it proved the coarser
  claim. A coarser claim is still an honest proof, and it verifies. That was an
  SDK bug, since fixed; the 2026-10-15 recapture in `android-pixel9-2026-10-15/`
  comes from a build with the fix, and its `area_country` proof claims the
  country. The earlier proof stays as a vector for an earth claim.

- Direct transport, OS attestation on. Semantic binding is **v2**: v3 is off in
  3.0.0, so the SDK returns no disc proofs and there are none here.
- In the UK a subdivision request returns a country-level proof, so both `area_*`
  proofs claim the country.
- The iOS proofs carry the App Attest **assertion** only; the key's attestation
  object went with an earlier proof. `ios-iphone11/enrolment_bundle.json` (`v:1`)
  and `enrolment_bundle.pb` are that key's enrolment bundle from the same build
  and phone (`com.octetproof.sample`, team `6ZH5F97PWU`). It certifies only the
  public key. With it, every iOS proof passes `app-attest`.
- The key was attested on 2026-10-07; its App Attest leaf is valid until
  2026-10-10 13:13:47 UTC, before the proofs were made (2026-10-13). So
  `--app-attest-window` must end at the time the bundle was anchored (any time up
  to 2026-10-10 PASSes), not at the proof's time (which FAILs "at the end").
- `android-pixel9/area_country.bin` carries a `timestamp-binding` WARN: its
  unsigned proof-level `timestamp_ms` is 5.5 s from the signed stage time.
  Freshness uses the signed time, so it does not affect the verdict.

## What the harness asserts

`tests/sdk_3_0_0_device.rs` decodes each proof, takes the hardware key from
`certificate_chain[0]`, pins `now_ms` to the signed `proofAssembly` time, and
asserts:

- `sdk_version` is `3.0.0`;
- the proof is VALID, with `region-claim` (the recorded claim), `stage-signatures`
  and `semantic-binding` PASS, under `require_schema_v2`;
- an area proof binds no query and has no signed verdict; a `within` proof's
  signed verdict is Inside;
- with `appattest`: on Android, `attestation-root` (the Keystore chain to a
  Google root, at the proof's own time) and `device-attestation-sig` PASS; on
  iOS, the enrolment bundle (JSON and proto) enrols the key, every proof passes
  `app-attest` and `attestation-required` (bound assertion form), and the App
  Attest chain PASSes over a window ending 2026-10-08 and FAILs over one ending
  at the proof's time.
