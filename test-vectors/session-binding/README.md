# Session-binding golden vectors

Cross-repo source of truth for the **session-binding** preimage: the exact bytes
the SDK hashes into a proof's `sessionBinding` stage, and that this verifier
recomputes to confirm a proof is bound to one login session.

The nonce never rides the wire — only its hash does, inside the stage. The
relying party issues the nonce at login and supplies it out of band; the verifier
recomputes `data_hash` over that nonce and checks it against the stage the device
signed. These vectors pin that computation so the **producer (SDK)** and the
**checker (verifier)** cannot drift apart silently.

## The contract

```text
preimage  = "octet-session-binding-v1" ‖ uint32_be(len(nonce)) ‖ nonce
data_hash = SHA256(preimage)     // == the sessionBinding stage's data_hash
```

- `"octet-session-binding-v1"` is the raw UTF-8 domain tag — no trailing NUL, and
  it is **not** itself length-prefixed.
- `uint32_be(len(nonce))` is the nonce length as a **big-endian** `u32` (4 bytes).
- `nonce` is the raw nonce bytes, appended verbatim. Bytes that happen to look
  like text (`utf8_text` below) are still hashed as raw bytes — never decoded.

This is the `semanticFields` framing (domain ‖ u32-BE length ‖ payload), **not**
the `uploadChallenge` framing (which hashes the raw nonce with no prefix).

## Which bytes are the "nonce" — the wire representation (load-bearing)

The verifier is representation-agnostic: `check_session_binding` hashes exactly
the `session_nonce` bytes it is handed, with no base64 decode. So the producer
(SDK), the verifier's caller (policy engine), and any test must all agree on
**which bytes** the `nonce` is — this is a caller convention, not something the
crate re-derives.

**Canonical convention (E1b): the nonce is the base64url challenge STRING as
transmitted, hashed as its ASCII/UTF-8 bytes — not the decoded raw bytes.** The
challenge endpoint returns `nonce` as a base64url string (43 chars for a 32-byte
value); the engine binds `session_nonce = challenge.nonce.as_bytes()` — those 43
ASCII bytes. So the preimage is
`"octet-session-binding-v1" ‖ u32be(43) ‖ <ascii of "AAECAwQ…">`.

Binding the **decoded** 32 bytes instead produces a *different* `data_hash`, so a
producer that decodes-then-binds will `Fail` against an engine that binds the
string. The `b64url_string_form_demo` vector pins this exact case (and its
`comment` records the wrong-form hash for contrast). The other vectors pin the
preimage *function* over arbitrary byte inputs and are representation-neutral;
`utf8_text` also demonstrates that text-looking bytes are hashed **raw, never
decoded**.

## Files

- `vectors.json` — the pinned table. Each entry is
  `{ name, nonce_hex, expected_data_hash, comment }`, with `nonce_hex` and
  `expected_data_hash` in lowercase hex. An empty `nonce_hex` means a 0-byte
  nonce.

## Who consumes this

- **Verifier** (this repo): `tests/session_binding_vectors.rs` builds a proof
  whose `sessionBinding` stage carries each vector's `expected_data_hash`, then
  asserts the real `octet_verify::session::check_session_binding` recomputes the
  same bytes (a `Pass`), and that a one-byte-different nonce `Fail`s. A framing
  drift on the verifier side fails CI here.
- **SDK**: mirrors the same table in its own test suite (Kotlin/Swift), asserting
  its on-device producer emits `expected_data_hash` for each `nonce_hex`. A
  framing drift on the producer side fails CI there.

Both sides read the *same* `nonce -> data_hash` pairs, so the two independent
implementations are pinned to one another. Regenerating a vector means changing
the contract — do it in lockstep with the SDK, never to make one side go green.

## Coverage rationale

- `empty` — 0-byte nonce: the length prefix is `00000000`, nonce absent.
- `abc` — matches the `src/session.rs` unit test, so the table and the unit test
  agree.
- `login_nonce_16` — a typical 16-byte per-login nonce.
- `all_ff_8` — high bytes, catches sign/byte-order mistakes.
- `utf8_text` — text-looking bytes, pins "raw bytes, never decoded".
- `len_256_endianness` — a 256-byte nonce (length `0x00000100`) whose big-endian
  vs little-endian prefix differ, catching a wrong `u32` endianness.
- `b64url_string_form_demo` — the canonical E1b wire form: a 43-char base64url
  challenge string bound as its ASCII bytes (length `0x0000002b`), pinning
  "hash the transmitted string, not the decoded 32 bytes" (see the section
  above).
