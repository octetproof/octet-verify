# Caller-metadata golden vectors

Cross-repo source of truth for **caller metadata** (phase A of the
caller-metadata binding spec): the exact bytes the SDK hashes into a proof's
`callerMetadata` stage, the limits, and the result a verifier gives for a
presented manifest and content. The iOS SDK, the Android SDK, the on-device
`Octet.verify` and this verifier all test against these files, so the
**producer** and the **checker** cannot drift apart silently.

## The contract

```text
preimage = "octet-caller-metadata-v1"            raw ASCII, no NUL, no length prefix
         ‖ u32_be(entry_count)
         ‖ for each entry, in the caller's order:
             u32_be(len(key)) ‖ key              UTF-8, byte for byte
           ‖ u32_be(len(contentType)) ‖ contentType
           ‖ u64_be(size)                        len(value), without the salt
           ‖ u32_be(32) ‖ entry_digest

entry_digest = SHA256(salt ‖ value)              salt is 0, 16 or 32 bytes
data_hash    = SHA256(preimage)                  == the callerMetadata stage's data_hash
```

The salt is **not** in the preimage. `entry_digest` commits to it and the signed
`size` fixes where it ends, so a salt never travels inside a proof.

Limits: 1 to 16 entries; unique keys of 1 to 64 bytes; a contentType of 1 to 127
bytes that is an RFC 6838 `type/subtype` (restricted-name characters, no
parameters); a salt of 0, 16 or 32 bytes; a preimage of at most 16 KiB. The
preimage limit can't be reached while the other limits hold (16 maximal entries
come to about 4 KiB), so no vector breaks it alone; `limits_at_maximum` shows
the largest valid preimage.

## Files

- `vectors.json` — two lists, all hex lowercase:
  - **`preimage_vectors`**: what the device commits. Each has `entries`
    (`{key, contentType, value_hex | value_file, size, salt_hex}`), and either
    `expected_entry_digests`, `preimage_hex` and `expected_data_hash` with
    `expected: "VALID"`, or `expected: "MANIFEST_INVALID"` for an input that
    breaks a limit (the SDK must refuse it with a typed error, never truncate).
  - **`check_vectors`**: what the verifier sees. `stage_data_hash` is the signed
    stage (`null`: the proof has no `callerMetadata` stage); `manifest` is the
    presenter manifest exactly as the spec defines it (`null`: none presented);
    `content` maps a key to `value_hex` or `value_file` (absent keys are
    digest-only); `content_unreadable` lists keys whose content was referenced
    but can't be read; `require_content` is `[]`, a list of keys, or `"all"`;
    `require_caller_metadata` is a boolean. `expected` is the result, and a
    `VALID` vector also gives `expected_by_content` / `expected_by_digest`.
- `large-256k.value` — the 256 KiB value for `large_streamed_value`, read through
  the streaming path.
- `field19.json` — phase B, the readable manifest in `LocationProof` field 19:

  ```proto
  message CallerManifest      { repeated CallerManifestEntry entries = 1; }
  message CallerManifestEntry { string key = 1; string content_type = 2; uint64 size = 3;
                                bytes sha256 = 4; string locator = 5; }
  ```

  Each vector has `field19` (the entries, `sha256` as hex), `caller_manifest_hex`
  (the encoded `CallerManifest`, proto3 rules: empty and zero fields omitted, so
  an empty `locator` is not on the wire), `stage_data_hash` (`null`: no stage),
  `presenter_manifest` (`null`: none handed over), `expected` (the
  `caller-manifest` result: `PASS`, `MANIFEST_MISMATCH` or `MANIFEST_INVALID`)
  and `locator_warning` (whether a `caller-manifest-locator` WARN accompanies
  it). `source` gives each committed item's value and salt, so every digest
  recomputes as `SHA256(salt ‖ value)`. Salts never appear in field 19, and the
  stage recomputes without them. The SDKs' encoders must produce
  `caller_manifest_hex` byte for byte.

## Results

| `expected` | Verifier result |
|---|---|
| `VALID` | `caller-metadata` PASS |
| `CONTENT_MISMATCH` | FAIL (proof INVALID, exit 1) |
| `MANIFEST_INVALID` | FAIL (proof INVALID, exit 1) |
| `CONTENT_UNRESOLVED` | INCONCLUSIVE (exit 3), never VALID |
| `NOT_CHECKED` | NOT-CHECKED |
| `FAIL` | the stage is required but absent |

Worst state wins: any FAIL gives INVALID, otherwise an unresolved entry gives
INCONCLUSIVE. An entry presented as digest only is not unresolved.

## Notes

- Salts here are fixed byte patterns so the file is reproducible. Real salts are
  random (the SDK's salt helper makes 32 bytes).
- A removed stage is a proof-level property: the next stage's `previous_hash`
  and `proofAssembly` no longer match, so `stage-chain` and `chain-assembly`
  FAIL. `tests/caller_metadata.rs` checks that on a signed synthetic proof; the
  `stage_absent*` vectors cover what the `caller-metadata` check reports for a
  proof without the stage.
- `locator` is outside the preimage and unsigned, so it never changes a result:
  `locator_changed_still_passes` carries a locator the stage never saw, and the
  three `locator_*` warning vectors still PASS.

## Who consumes this

- `tests/caller_metadata.rs` here (preimage vectors in every build, check
  vectors with `--features caller-metadata`), and `tests/caller_metadata_field19.rs`
  for `field19.json` (every build; prost must re-encode each vector's entries to
  `caller_manifest_hex`).
- The iOS and Android SDKs mirror this file and must produce byte-identical
  preimages and refuse every `MANIFEST_INVALID` input.
