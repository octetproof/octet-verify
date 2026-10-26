# Caller metadata, phase B — real-device proofs

Two signed `LocationProof`s that commit caller content through the
`callerMetadata` stage **and** carry the readable manifest in field 19
(`caller_manifest`). Produced on physical phones by an internal debug build of
the OctetSDK sample app (2026-10-19, development licence). Both phones were in
the United Kingdom; both proofs claim `country:GB`. Test content only.

Each proof commits the same two entries as the phase A set in
`../caller-metadata-device/`, in this order:

| key | contentType | salt | value file | size |
|---|---|---|---|---|
| `note` | `text/plain` | 32 bytes | `note.txt` | 40 |
| `file` | `application/octet-stream` | none | `file.value` | 4096 |

| dir | device | files |
|---|---|---|
| `android/` | Pixel 9 (StrongBox) | `proof.bin`, `manifest.json`, `note.txt`, `file.value` |
| `ios/` | iPhone 11 (App Attest, development) | the same, plus `enrolment.json` |

- Field 19 lists `{key, contentType, size, sha256}` per entry, with no salt and
  no locator. It recomputes the stage on its own, so `caller-manifest` PASSes
  without the presenter.
- `manifest.json` is the presenter manifest. It carries the salt for `note`, so
  only it lets the content be checked. Its entries equal field 19's.
- `file.value` is named so it is not mistaken for a proof.
- `enrolment.json` is the iOS App Attest key's enrolment bundle
  (`com.octetproof.sample`, team `6ZH5F97PWU`), from the same day.

## What the harness asserts

`tests/caller_metadata_device.rs` runs this set next to the phase A one:

- each proof is VALID with every stage signature verified, and `caller-manifest`
  PASSes with field 19 equal to the presenter manifest minus the salts;
- `caller-metadata` PASSes with content required for every entry (2 of 2);
- a flipped bit in `note` gives `CONTENT_MISMATCH`, the other phone's manifest
  gives `MANIFEST_MISMATCH` (it differs from field 19), and an unreadable file
  gives `CONTENT_UNRESOLVED`;
- with `appattest`: Android's Keystore chain reaches a Google root, and the iOS
  proof passes `app-attest` through the enrolment bundle.

From the CLI:

    octet-verify proof.bin --max-age-seconds 86400 --caller-manifest manifest.json \
      --content note=note.txt --content file=file.value --require-caller-metadata
