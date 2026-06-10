# Backend golden vectors

Canned proof-ingestion query-API responses (a `{ "proof": ... }` wrapper around
a single proof envelope), used by `tests/backend.rs` to drive the `fetch` /
`range` subcommands through an in-process stub HTTP server.

These exist to pin the **trust boundary**: the backend is untrusted, so the
`proof_bytes_b64` inside each response is decoded and run through the exact same
local verification pipeline as a local file. The verdict must depend only on the
proof bytes — never on the surrounding envelope metadata.

| File | proof_id | What it asserts |
|---|---|---|
| `success.json` | `lp_success` | A well-formed proof decodes and verifies → exit 0. |
| `tampered-bytes.json` | `lp_tampered` | A valid proof with one corrupted stage signature — still decodes, but `stage-signatures` FAILs → exit 1 (fail loud). |
| `refetch-first.json` / `refetch-second.json` | `lp_diff` | Two *different* valid proofs served under the same id. Each verifies alone; fetching both against one `--seen-store` trips `refetch-consistency` → exit 1. |

The proof bytes are deterministic (fixed signing seed, RFC 6979 ECDSA, stable
proto encoding), so these files are stable — "signed proofs are forever."
Regenerate only after an intentional change to the proof builder or wire schema:

```
cargo test --features net regenerate_golden_vectors -- --ignored
```
