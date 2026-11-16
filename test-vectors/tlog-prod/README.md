# Transparency log — vectors from the production log

Vectors from octet's production transparency log, `https://log.octetproof.com/browser`,
taken on 5 Nov 2026 when it held 7 entries, as the log's own generator wrote them.
The files are copied unchanged; never edit them. Nothing here is secret: the log and
its keys are public. `tests/tlog_vectors.rs` checks them.

| | |
|---|---|
| Origin | `log.octetproof.com/browser` |
| Log key | kid `tlog-7cbbf8dc`, vkey `log.octetproof.com/browser+7cbbf8dc+AY+W5wQKXobt/BXgqsq9u2NFLZbHdW/BUeS/lqu3DFHm` (`log-key.json`) |
| Signed head | size 7, root `vgC2zqVLlqf/Z3/theDaMVwkPODG9uFrTFvyz/epLMI=` (`checkpoint`, byte for byte as served) |
| Witness | `witness.octetproof.com/octet-verify+33161baf+BCnmA+Bq5n8tdIGwP6g+tyvTFPdZNfXBU3mWhV9MYZPK`, cosigned 2026-11-05T09:34:12Z |

| Index | Kind | Content |
|---|---|---|
| 0–2 | manifest | root manifests `seq 1`–`3`; their JWS files are `../browser-verdict-chain/prod-manifest-seq{1,2,3}.json.jws` |
| 3–6 | release | v1.7.0, v1.8.0, v1.8.1, v1.9.1 |

| File | What |
|---|---|
| `checkpoint` | the signed size-7 checkpoint, with the log's signature and the witness's cosignature |
| `inclusion/leaf-<i>.json` | the proof bundle for entry `i` against `checkpoint` |
| `entries.json` | each entry decoded, with its leaf hash |
| `consistency/<m>-7.json` | the consistency proof from size `m` to 7. Only size 7 is signed here; the roots of sizes 1–6 are derived from the entries, and 3 to 6 are the roots the log signed before |
| `bad/*.json` | ten cases that must be refused: `type` `inclusion` (a bundle, with the log verifier's error, which this verifier matches) or `consistency` (a proof that must not verify) |
| `log-key.json` | the log key as a JWK |
| `pack.json` | origin, key, size, root and the generator's file list (its `tree-heads.json` is not copied) |

A changed origin line is reported as a failed signature: the log signs the text the
origin is part of.

## `seq4/`: size 9

Sent by the log's maintainers on 11 Nov 2026, after root manifest `seq 4` was logged,
and copied unchanged (`SHA256SUMS` lists them). The pack above stays at size 7.

| | |
|---|---|
| Signed head | size 9, root `GMudzry+Vj6uq7D1Pc9wiAWV3czfLNWNd2IKdcTd6YA=`, cosigned by the witness 2026-11-11T10:54:26Z |
| Leaf 7 | release v1.10.0 |
| Leaf 8 | root manifest `seq 4`, signed by `octet-root-a-2026-10`: the first that lists the log key in `logKeys` |

| File | What |
|---|---|
| `root-manifest-seq4.jws` | the signed manifest, with a trailing newline; the log records it trimmed, as served (SHA-256 `b2e4b632…`) |
| `checkpoint-size9` | the size-9 checkpoint as served, with the log's signature and the witness's cosignature |
| `inclusion-leaf-7-v1.10.0.json`, `inclusion-leaf-8-seq4.json` | the proof bundles for leaves 7 and 8 against `checkpoint-size9` |
| `7-9.json`, `8-9.json` | consistency proofs from sizes 7 and 8 to 9 |
