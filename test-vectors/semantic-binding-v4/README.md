# Semantic-binding v4 golden vectors (committed licence)

Cross-repo source of truth for the **octet-semantic-binding-v4** preimage: the
binding that commits a proof to the licence the SDK was activated for, so a proof
made under one licence can't be presented under another. Pinned here and mirrored
byte for byte by both SDK platforms.

## The contract

```text
preimage  = "octet-semantic-binding-v4"
          ‖ u32be(spoofing_verdict) ‖ u32be(level) ‖ u32be(integrity_status)
          ‖ u32be(region_type) ‖ u32be(len(region_id)) ‖ region_id        // claimed_region
          ‖ u32be(len(commitment)) ‖ position_commitment
          ‖ u32be(location_verdict)
          ‖ u32be(q_type) ‖ u32be(len(q_id)) ‖ q_id                       // query_region (v3)
          ‖ u32be(len(lid)) ‖ lid                                         // NEW: committed licence
data_hash = SHA256(preimage)                                              // the semanticFields stage hash
```

Everything between the domain tag and `lid` is the **v3 preimage body verbatim**
(see `../semantic-binding-v3/`). `lid` is `committed_license_id` (field 21) as
UTF-8: a canonical lowercase hyphenated UUID, 36 bytes. v4 always carries one.

## Files

- `vectors.json`: the six vectors.
- `generate.py`: derives them from the frozen v3 vectors' preimage bytes, with no
  code shared with the verifier. Run from the repository root:
  `python3 -I test-vectors/semantic-binding-v4/generate.py > test-vectors/semantic-binding-v4/vectors.json`.

Each vector has:
- `input` and `query_region`: the fields of its v3 base vector (`base_v3_vector`);
- `signed`: what the device signed: `domain`, `committed_license_id` (`null` for
  a v3 proof), `preimage_hex` and `stage_hash_hex`;
- `presented_license_id`: field 21 as the verifier receives it (`null` = absent);
- `expect`: `pass` or `fail`.

The two licence ids are synthetic.

## Coverage

| Vector | Signed | Presented | Expect |
|---|---|---|---|
| `v4_disc_inside` | v4, disc query, INSIDE, licence A | A | pass |
| `v4_country_outside` | v4, country AT query, GB claim, OUTSIDE, licence B | B | pass |
| `v4_no_query` | v4, background proof (`q_type = 0`, field 18 absent), licence A | A | pass |
| `tamper_license_edited` | v4, licence A | B | fail |
| `tamper_license_removed` | v4, licence A | absent | fail |
| `tamper_license_on_v3` | v3 (no licence) | A | fail |

Shape failures (empty, uppercase, unhyphenated, wrong length) are verifier unit
tests, not vectors.

## What consumes this

- **Verifier** (this repo): the `src/verify.rs` unit test
  `semantic_binding_v4_golden_vectors` rebuilds each proof, asserts the signed
  preimage bytes and hash, then checks the presented proof PASSes with the
  licence exposed, or FAILs with none. `tests/semantic_binding_v4.rs` runs a
  signed proof built from `v4_disc_inside` through the CLI.
- **SDK**: signs v4 on both platforms and mirrors this table.

Regenerating a vector means changing the contract: do it in lockstep with the
SDK, never to make one side go green.
