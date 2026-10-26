# Browser verdict chain — golden vectors

Vectors copied verbatim from octet-browser. Do not edit them here.

## `verdict-v4-vectors.json` and `verdict-v3-golden.json`

From octet-browser `apps/server/test/vectors/` at main `0788e27`, for the `v=4`
early-verdict profile. Both are signed with a test-only Ed25519 key whose seed is
SHA-256 of the file's `seedLabel`, used nowhere else; its public JWK is
`publicJwk`. The chain digests are placeholders, so `chain-root` FAILS on them by
design: they pin the token profile, not the chain (`chain-vector.json` pins that).

- `verdict-v4-vectors.json`: three valid tokens (`provisional` revision 1,
  `final` revision 2 over two reports, and `final` revision 2 with
  `incomplete: true`), each with its claims, and five that break the profile: no
  `stage`, a bad `stage`, `revision` 0, `incomplete` on a provisional token, and a
  `v=3` token carrying `stage`.
- `verdict-v3-golden.json`: the `v=3` token captured before `v=4` existed, which
  a licence not opted in must keep getting byte for byte.

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

## `prod-manifest-seq2.json.jws` and `prod-manifest-seq3.json.jws`

The next two production manifests, byte for byte as committed in octet-browser
(trailing newline included), both signed by root A with root A and root B as the
next roots.

- **seq 2** (issued 2026-10-16, SHA-256
  `01907d63f689caafbda90b89eb07e4fa8266e5a4825da6ee8a037762ded44843`) adds the
  `internalSha256`, `licenceKeys`, `readKeys`, `edgeCaSha256` and `listKeys`
  sections, which this verifier does not read, and drops the anchors and
  calibration. Its only verdict key is still `octet-browser-verdict-2026-09`.
- **seq 3** (issued 2026-10-19, SHA-256
  `11cefca4b908c15f779daac61fb680b0d1cafac8a8330fab7c2e45d305316e5b`; served
  without the newline as `371d729f1fe63eda9466101f2e750cd72bb45e5444cf6e9e3904a58325b94cab`)
  rotates the verdict key to Cloud KMS at `1792418400` (2026-10-19 15:00 UK):
  `octet-browser-verdict-2026-09` gets that time as `octet_not_after`, and the
  new ES256 key `octet-browser-verdict-2026-10` gets it as `octet_not_before`.

## `prod-verdict-2026-10-kms.json` and `prod-verdict-2026-09-before-kms.json`

Two production `v=3` verdicts from test sessions (a staff browser through the
demo licence), copied verbatim from octet-browser. Each holds the session
reference, the S0 challenge, the coarse verdict and the token; the token's
`chain.s0` is the SHA-256 of that challenge. The demo sends no client IP, so
there is no `clientNetMatch`.

- `prod-verdict-2026-10-kms.json`: signed ES256 by the KMS key after the switch
  (`iat` 1792418601).
- `prod-verdict-2026-09-before-kms.json`: signed EdDSA by the file key just
  before it (`iat` 1792418155).

Both verify end to end under seq 3. The KMS verdict is refused under seq 2,
which does not list its key.

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
