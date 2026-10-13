# Browser verdict chain — golden vectors

Vectors copied verbatim from octet-browser. Do not edit them here.

## `prod-manifest-seq1.json.jws`

octet's first **production** root manifest (`seq` 1, issued 2026-10-12, expires
2027-10-12), byte for byte as committed in octet-browser
(`keys/octet-browser-manifest.json.jws`, with its trailing newline; SHA-256
`98c9f12c2ed1f81b2d032e3376a96c6e255aa4608ea32fb0ad252f72216bce41`). The served
copy has no trailing newline (SHA-256
`a3dd8c373876d55edaf163d44da520863f43a76163dc8d23bc870950342c2dcb`); both verify
the same way. It is signed by the pinned root `octet-root-a-2026-10` and lists
the production verdict key `octet-browser-verdict-2026-09`, the challenge key
`octet-browser-challenge-2026-10` and the anchors `lon1`, `chs1` and
`sin1-prod-2026-09`. The roots for the next manifest are root A and root B.

## `manifest-vector.json`

A root manifest (`seq` 1) listing octet-browser's dev verdict and challenge keys,
signed by octet-browser's committed **dev** root `root-dev-1` (ES256; the
signature was made on a hardware token as DER and converted to JOSE `r‖s`).
Production never trusts this root. It carries the root JWK, the JWS, the exact
manifest bytes, and `nowOk` / `nowExpiring` / `nowExpired` / `nowRefused`
timestamps for the expiry windows.

## `dev-vector.json`

A real `v=3` verdict from octet-browser's dev stack (main `f1877b7`): an S0
challenge (carrying the opaque `cn` tag), an S1-sealed report, an S2 signature
by edge kid `edge-dev`, and the edge's chain log. Signed EdDSA with the dev key
`octet-browser-verdict-dev-2026-09`. Built under the current `v=3` rules: no
`clientNet`, and `clientNetMatch: true` (the partner side sent a loopback client
IP and the report arrived from loopback). It holds the token, the verdict key
list and archive, the challenge and its key list, the edge log line both raw
(with the Go log prefix) and as bare JSON, and the expected values. The token
lives 5 minutes, so verify it at `nowForChecks`. The dev archive entry has no
`octet_not_before` (dev runs without an archive file), so `key-validity` reads
NOT-CHECKED unless the root manifest supplies the window.

## `chain-vector.json`

Copied verbatim from octet-browser
(`apps/server/test/vectors/chain-vector.json`). It is the shared source of
truth for the browser verdict profile: octet-browser's server builds it, its Go
edge checks the edge log line against it, and this verifier checks all of it.
Do not edit it here. Regenerate it in octet-browser and copy it again.

It holds:

- `verdictJwk` and `verdictToken`: a deterministic EdDSA (Ed25519) verdict
  token, `typ octet-browser-verdict+jwt;v=3`, whose claims carry `chain` and
  `chain_root`;
- `challengeJwk` and `challengeToken`: the session's PASETO v4.public challenge;
- `chain` and `chain_root`: the chain as signed, and its expected root;
- `edgeChainLog`: the edge's log line for the session's one report;
- `inputs`: the raw values the chain digests are computed from (bundle JSON,
  S1 signature, request body, S2 token, anchor receipts).

`tests/browser_verdict.rs` verifies the token, recomputes `chain_root`,
rebuilds every chain digest from `inputs`, and checks the session and edge
links. An ES256 sample can join it from a real dev token: ECDSA tokens from
the KMS signer are not deterministic, so they can't be generated here.
