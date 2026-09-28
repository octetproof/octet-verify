# Semantic-binding v3 golden vectors (queried region)

Cross-repo source of truth for the **octet-semantic-binding-v3** preimage — the
binding that carries the *queried* region Q into a proof so a consumer can read a
signed INSIDE/OUTSIDE for a specific region. Produced byte-identical by an
independent generator and both SDK platforms; frozen here as the verifier's parity
fixture. A framing drift on any side fails CI on both repos rather than on-device.

## The contract

```text
preimage  = "octet-semantic-binding-v3"
          ‖ u32be(spoofing_verdict) ‖ u32be(level) ‖ u32be(integrity_status)
          ‖ u32be(region_type) ‖ u32be(len(region_id)) ‖ region_id        // claimed_region (v2 table)
          ‖ u32be(len(commitment)) ‖ position_commitment
          ‖ u32be(location_verdict)
          ‖ u32be(q_type) ‖ u32be(len(q_id)) ‖ q_id                       // NEW: query_region
data_hash = SHA256(preimage)                                              // the semanticFields stage hash
```

The body up to `location_verdict` is the **v2 preimage verbatim**; v3 only swaps
the domain tag and appends Q. `q_type` is the `ProofRegion` oneof tag and `q_id`
is that region's v2 `region_id`; **no bound query ⇒ `q_type = 0`, empty `q_id`**
(and field 18 absent). A **disc** is `ellipse(lat, lon, r, r, heading = +0.0)`; a
**city** query is unbound (no v2 `region_id`).

## File

`vectors.json` — 9 vectors. Each has:
- `input` — the fields that go into the preimage (`spoofing_verdict`, `level`,
  `integrity_status`, `commitment_hex`, `claimed_region`, `location_verdict`, and
  the `query` region, or `null`);
- `query_region` — the bound reference `{ region_type, region_id_hex }`, or `null`;
- `preimage_hex` — the full v3 preimage;
- `stage_hash_hex` — its SHA-256 (the `semanticFields` stage's `data_hash`).

## Coverage

- `disc_inside` / `disc_outside` — an ellipse (disc) query with an INSIDE / OUTSIDE
  verdict; the only region kind whose containment a country claim can't derive.
- `country_at_claim_gb` — a Country **AT** query with a **GB** claim → OUTSIDE
  (the consistency case, now exact).
- `subdivision_us_ny` — a Subdivision **US-NY** query, INSIDE.
- `earth_default` — an `earth` query at the default 10000 m altitude, INSIDE.
- `no_query` — a background proof: no `query`, `location_verdict` UNSPECIFIED,
  field 18 absent (`q_type = 0`).
- `disc_fractional_m` / `disc_fractional_km` — the same disc expressed in metres
  and kilometres; both normalise to `1500.5 m` and so **share one `q_id`**
  (`225ce79b…`), pinning that the reference is canonical in metres.
- `tamper_query_region` — the query edited after signing: `stage_hash_hex` is the
  *original*'s, so re-deriving over the edited Q must **not** match → FAIL.

## What consumes this

- **Verifier** (this repo): `src/verify.rs` unit test `semantic_binding_v3_golden_vectors`
  rebuilds each proof, asserts its `semantic_preimage_v3` bytes equal `preimage_hex`,
  its SHA-256 equals `stage_hash_hex` (and, for the tamper vector, does *not*), that
  `query_region_ref` reproduces each `query_region`, and that the full check PASSes
  (with Q exposed) / FAILs (tamper) as expected.
- **SDK**: emits and verifies v3 on both platforms and mirrors this same table, so
  the on-device producer and this verifier are pinned to one another.

Regenerating a vector means changing the contract — do it in lockstep with the
SDK, never to make one side go green.
