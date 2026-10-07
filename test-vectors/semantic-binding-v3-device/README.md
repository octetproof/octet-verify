# Semantic-binding v3 — real-device golden proofs

Real-hardware proofs that pin **semantic-binding v3** (the queried-region binding,
) end to end: a proof produced on a physical phone verifies in this crate with
the queried region bound, surfaced, and byte-identical to the synthetic
`../semantic-binding-v3/` vectors. This is the on-device counterpart to the
synthetic generator — the producer and this verifier agree on live hardware.

## What's here

Six signed `LocationProof`s captured 2026-09-28, three queries from each of two
phones (both physically in London, so the device claim is `country:GB`):

| device | attestation | `country_at` | `country_gb` | `earth_default` |
|---|---|---|---|---|
| iPhone 11 | App Attest (prod) | Outside, Q `2/4154` | Inside, Q `2/4742` | Inside, Q `1/40c3880000000000` |
| Pixel 9 | StrongBox (dev) | Outside, Q `2/4154` | Inside, Q `2/4742` | Inside, Q `1/40c3880000000000` |

- `*.bin` — the raw `LocationProof` bytes (the file name is the **queried** region).
- `fixtures.json` — the expected `location_verdict` and `query_region`
  `{region_type, region_id_hex}` per proof (`2/4154` = country `AT`, `2/4742` =
  country `GB`, `1/40c38800…` = `earth` at the default 10000 m altitude).

## What the harness asserts

`tests/semantic_binding_v3_device.rs` decodes each proof, sources the hardware key
from `certificate_chain[0]` (raw SEC1 for iOS, the X.509 attestation leaf for
Android), pins `now_ms` to the signed `proofAssembly` time (so a committed golden
never goes stale), and asserts: `VALID`, `stage-signatures` PASS, `semantic-binding`
PASS (v3), `query-region` PASS, and that the surfaced `location_verdict` +
`query_region` match the table above.

## Notes

- **Attestation is a separate concern.** The Pixel proofs also chain to a Google
  attestation root (StrongBox), which `fixtures.json` records and the CLI confirms
  under `--features appattest`; the harness doesn't assert it because it belongs to
  the hardware-attestation layer, not the v3 queried-region binding. On iOS,
  `app-attest` is NOT-CHECKED from the proof alone — the attestation object arrives
  separately.
- The Pixel proofs are from after the Android attestation-challenge fix (a proof
  key re-created with a random challenge previously made `attestation-root` FAIL
  with "challenge mismatch").
- **No disc vector yet** — disc proofs change shape under the next proof model
  revision and will arrive with that work.

"Signed proofs are forever": regenerating these means a fresh device capture, done
in lockstep with the SDK, never to make a check go green.
