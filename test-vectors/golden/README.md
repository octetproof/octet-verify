# Golden proof vectors

Real, SDK-emitted `LocationProof` artifacts kept verifiable **forever**. Every
release should add one per platform; `tests/golden.rs` verifies all of them on
every build, so a change that would make an old proof unverifiable fails loudly.
A signed proof is a promise — if we can't verify yesterday's proof today, we've
broken the wire.

## Layout

```
golden/<sdk_version>/<platform>-<name>.bin       serialized LocationProof
golden/<sdk_version>/<platform>-<name>.pubkey    hardware P-256 key (raw SEC1 or hex)
golden/<sdk_version>/<platform>-<name>.json      expected summary (informational)
```

`tests/golden.rs` finds every `*.bin`, expects a sibling `*.pubkey`, and runs
`octet-verify` against it with a wide freshness window (goldens are historical).

## Provenance

Vectors are emitted by the Octet SDK's own test hooks against the tagged source
of each release, using a software-backed signer (so they're produced
deterministically in CI, not from a physical device — that's exactly why the
verifier reports `NOT-CHECKED` for the platform-attestation root on these
vectors). Octet refreshes them with each release.

Outside contributors extending the verifier without regenerating vectors can
rely on the synthetic round-trip in `tests/golden.rs`, which exercises the
binary independently.
