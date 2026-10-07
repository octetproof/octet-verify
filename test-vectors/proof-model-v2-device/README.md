# Proof-model-v2 — real-device golden proofs

Real-hardware proofs that pin **proof model v2** (the `proveArea` / `proveDiscVerdict`
split,) end to end: an unbound **area** proof and bound **disc-verdict** proofs
produced on a physical phone verify in this crate, with the queried disc bound and
surfaced. The on-device counterpart to `../semantic-binding-v3/disc-verdict.json`.

## What's here

Ten signed `LocationProof`s captured 2026-09-29, five each from two phones (both in
London, so the device claim is `country:GB`):

| proof | kind | bound? | verdict |
|---|---|---|---|
| `area_country` | area | no (`q_type=0`) | — (UNSPECIFIED) |
| `area_subdivision` | area | no | — (coarsens to country GB) |
| `disc_inside_100km` | disc | yes (type 4) | Inside |
| `disc_outside_vienna_2km` | disc | yes (type 4) | Outside |
| `disc_straddle_1m` | disc | yes (type 4) | Indeterminate |

- iPhone 11 (App Attest, prod) + Pixel 9 (StrongBox, dev).
- `*.bin` — raw `LocationProof` bytes; `fixtures.json` — expected `kind`,
  `location_verdict` and (disc only) `query_region {region_type, region_id_hex}`.
- The **Vienna 2 km disc** binds `q_id e8658ae8…` on **both** phones — the same
  reference as the synthetic `disc_verdict_*_clear` vectors, a cross-check that the
  device and the generator agree on the disc digest.

## What the harness asserts

`tests/proof_model_v2_device.rs` decodes each proof, sources the hardware key from
`certificate_chain[0]`, pins `now_ms` to the signed `proofAssembly` time, and
asserts `VALID` + `stage-signatures` + `semantic-binding` + `query-region` PASS,
then:
- **area:** no `query_region`, no signed verdict (the unbound `proveArea` shape);
- **disc:** the signed `location_verdict` (Inside / Outside / **Indeterminate** for
  the straddle) and the exposed `query_region` (type 4) match the table.

The verifier reads the **signed** disc verdict — it does not recompute the
haversine / `k` / tie rule (that model is the SDK producer + the engine's
consistency check). "Signed proofs are forever": regenerating means a fresh device
capture, in lockstep with the SDK.
