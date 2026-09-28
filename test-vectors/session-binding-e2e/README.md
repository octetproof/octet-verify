# Session-binding E2E golden fixture

The **offline half of the E1b verified-proof gate**. Core owns the live
challenge→prove→decide loop in its acceptance CI; this is the verifier-side check
on a captured fixture — a *real* signed proof envelope from the SDK's `prove()`
path verifies, is bound to the challenge nonce, and yields the expected verdict —
with no network.

## What's here

`fixtures.json` holds two Tier-2 (**software-signed, un-attested**)
`LocationProof` envelopes emitted by the SDK's real `ProofGenerator` for the
`geofence_at` policy (required region: Country **AT**), each bound to the
canonical #76 session nonce:

- `inside` — device in AT → `location_verdict = Inside` (the **permit** shape).
- `outside` — device in DE → `location_verdict = Outside`, region claim ≠ AT (the
  **deny** shape), yet still an authentic, session-bound proof.

`proof_bytes_b64` is the exact `URL_SAFE_NO_PAD` bytes `prove()` emits and the
backend `/v1/decide` receives.

## Provenance

Emitted by the **Octet SDK's on-device proof generator** — the same code path a
real device runs, with a software signer and an injected country estimate for a
deterministic off-device capture. The nonce is the 43-char base64url string from
the `../session-binding` golden vector; both envelopes' `sessionBinding.data_hash`
equals the pin `aab74288842bc907814ef3165cceb829f05aafdcaf9d25563cb137013e3f227f`,
tying this end-to-end fixture to the byte-level session-binding vectors.

Signatures are randomized and stage timestamps are wall-clock, so these are a
captured snapshot — "signed proofs are forever": regenerating them is a new
capture, done in lockstep with the SDK, never to make a check go green.

## What the harness asserts

`tests/session_binding_e2e.rs` decodes each envelope and verifies it the way the
engine's verified path does — key sourced from `certificate_chain[0]` (SEC1
bare-65B point), `require_session_binding = true`, `require_attestation = false`
(Tier-2 carries no hardware root), `now_ms` pinned to the signed `proofAssembly`
time (so a committed golden never goes stale; it asserts crypto/structure/verdict,
not wall-clock freshness):

- **authentic + bound** (both): all stage signatures verify, `chain-assembly`
  binds them, `session-binding` matches, v2 `semantic-binding` holds;
- **inside**: `is_valid()`, `region-claim` = AT, `region-type` = country,
  `location_verdict = Inside` — the one required region covered (permit);
- **outside**: `location_verdict = Outside` and the AT `region-claim` **fails**
  (`is_valid()` false) — denied on geography, not on a broken proof;
- **negative**: flipping one nonce byte breaks `session-binding` (fail-closed) —
  the proof is bound to *this* challenge nonce, not merely carrying a stage.

Related: `../session-binding/` (the byte-level `nonce → data_hash` vectors this
fixture's `sessionBinding` stage is pinned to).
