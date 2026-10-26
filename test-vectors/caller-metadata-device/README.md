# Caller metadata — real-device proofs

Two signed `LocationProof`s that commit caller content through the
`callerMetadata` stage, produced on physical phones by an internal debug build of
the OctetSDK sample app (2026-10-19, development licence). Both phones were in the
United Kingdom; both proofs claim `country:GB`. Test content only.

Each proof commits two entries, in this order:

| key | contentType | salt | value file | size |
|---|---|---|---|---|
| `note` | `text/plain` | 32 bytes | `note.txt` | 40 |
| `file` | `application/octet-stream` | none | `file.value` | 4096 |

| dir | device | files |
|---|---|---|
| `android/` | Pixel 9 (StrongBox) | `proof.bin`, `manifest.json`, `note.txt`, `file.value` |
| `ios/` | iPhone 11 (App Attest, development) | the same, plus `enrolment.json` |

- `manifest.json` is the presenter manifest (`v:1`, lowercase hex). Its salt for
  `note` is the one the app used; the salt never travels in the proof.
- The content files hold exactly the committed bytes. `file.value` is named so
  it is not mistaken for a proof.
- The iOS proof carries an App Attest assertion only. `enrolment.json` is the
  key's enrolment bundle (`com.octetproof.sample`, team `6ZH5F97PWU`). The key was
  attested on 2026-10-07 and its leaf is valid until 2026-10-10, so an
  `--app-attest-window` must end at the time the bundle was anchored, not at the
  proof's time.

## What the harness asserts

`tests/caller_metadata_device.rs` (feature `caller-metadata`):

- each proof is VALID with every stage signature verified, under
  `require_schema_v2`;
- the manifest recomputes the stage, and both entries match by content, with
  content required for every entry (`caller-metadata` PASS, 2 of 2 by content);
- a flipped bit in `note` gives `CONTENT_MISMATCH`, the other phone's manifest
  gives `CONTENT_MISMATCH`, and an unreadable content file gives
  `CONTENT_UNRESOLVED`, which leaves the report INCONCLUSIVE;
- with `appattest` as well: Android's Keystore chain reaches a Google root, and
  the iOS proof passes `app-attest` and `attestation-required` through the
  enrolment bundle.

From the CLI:

    octet-verify proof.bin --max-age-seconds 86400 --caller-manifest manifest.json \
      --content note=note.txt --content file=file.value --require-caller-metadata
