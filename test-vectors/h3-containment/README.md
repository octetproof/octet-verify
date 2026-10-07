# H3 region containment — golden vectors

Vectors for `--expect-region-contains <lat>,<lon>` against a proof whose claimed
region is an `h3_polygon_set`.

## Semantics

- The region is the **filled union** of its cells.
- A point is inside iff some listed cell `C` satisfies
  `latLngToCell(point, res(C)) == C`, at `C`'s own resolution. Mixed and
  compacted resolutions are allowed; no single resolution is assumed.
- Cell ids are standard H3 v4 cell indexes (mode 1).
- **Fail closed:** an empty set, or any id that is not a valid H3 v4 cell
  (including a directed-edge index), FAILs the check, even when another listed
  cell contains the point.
- A point on a shared boundary belongs to exactly one H3 cell; it is inside iff
  that cell is listed.

## Files

- `vectors.json`: 17 vectors. `cell_ids_hex` are hex strings, because a 64-bit
  index exceeds JavaScript's 2^53. `point` is `[lat, lon]` in degrees and
  `point_f64_bits_hex` is the exact IEEE-754 bit pattern of each coordinate. Use
  the bits, so the boundary-vertex point parses bit-exactly.
- `generate.py`: the generator. It uses the reference H3 C library through the
  `h3` Python binding (`pip install 'h3>=4,<5'`):
  `python generate.py > vectors.json`.

## Cross-implementation check

The vectors come from the reference C library, and the verifier evaluates them
with the pure-Rust `h3o` crate (`--features h3`). `tests/h3_containment.rs`
asserts that the two agree on every vector. Without the `h3` feature the same
test asserts that every vector FAILs, because the lean build cannot evaluate h3
containment.

Never edit an `expect` value to make a test pass. Regenerate from the reference
library, and treat a disagreement as a bug in one of the two implementations.
