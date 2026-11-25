# S2 region — golden vectors

Vectors for the S2 grid: the `cell_set` region (proof region tag 8), the 3D
`voxel_set` (tag 9) and the height-bin index. The verifier generates them and the
SDK mirrors them.

## Source

`vectors.json` is produced by `generate/` with the reference Go S2 library,
`github.com/golang/geo`, at the version pinned in `generate/go.mod`:

    cd generate && go run . > ../vectors.json

The verifier checks its own port (`src/s2.rs`) against every vector in
`tests/s2_region.rs`, and the semantic-binding vector in `src/verify.rs`. Never
edit a value to make a test pass. Regenerate it, and treat a disagreement as a
bug in one of the two implementations.

## Encoding

- Cell ids are 16-digit hex strings, because a 64-bit id exceeds JavaScript's
  2^53.
- Every point has `point` (`[lat, lon]` in degrees) and `point_f64_bits_hex`,
  the exact IEEE-754 bits of each coordinate. Parse the bits.
- `xyz_f64_bits_hex` is the reference's unit vector for the point.

## Edge points

`sin` and `cos` are not correctly rounded, and platforms differ by an ulp. A
point within about 1e-15 of a cell edge can therefore land in the neighbouring
leaf. Vectors marked `"edge": true` sit on a cell edge, vertex or face boundary:

- check them from `xyz_f64_bits_hex`. Mapping a vector to a cell needs only
  division, `sqrt` and `floor`, which are exact, so every implementation agrees;
- don't expect the lat/lon path to match on them. `vertex_1_of_member` is a real
  case: Go's `cos` and the verifier's `libm` differ in the last bit, and the
  point lands in different leaves.

For such points, the verifier's answer is the authoritative one.

## Sections

| section | what it pins |
|---|---|
| `points` | 65 points (named, edge cases, 48 random): the leaf, its token, and the containing cell at every level 0–30 |
| `validity` | valid and invalid ids (the 6 faces, 0, faces 6 and 7, the sentinel, an odd trailing-zero count) and their levels |
| `hierarchy` | one cell per level 0, 1, 5, 12, 20, 29, 30: token, `range_min`, `range_max`, parent and the 4 children |
| `f_index` | `f = floor(h · 2^(zoom − 25))` for ellipsoidal height `h` in metres, valid iff `abs(h) < 2^25`; includes negatives, `-0.0`, bin edges and the range limits |
| `canonical` | input lists → canonical or not, plus the S2 normalisation where all ids are valid |
| `digests` | cell lists → `SHA256("octet-region-cellset-v1" ‖ u32be(n) ‖ u64be(id)ⁿ)` |
| `containment` | `(cells, point) → inside`: mixed levels, gaps, cell vertices, poles, whole faces, random sets |
| `preimage_v3` | a full semantic-binding v3 preimage with a cell-set claim and a cell-set query, its stage hash and the `query_region_ref` id |
| `voxel_set` | tag 9, below |
| `cellset_verdict` | the cell-set verdict, below |

## Canonical form (tag 8)

A cell set is canonical iff it is non-empty, has at most 16,384 cells, every id
is valid, and it equals its own S2 normalisation: sorted ascending, pairwise
disjoint, with no 4 children of one cell left unmerged. The verifier rejects a
non-canonical set; it does not normalise it.

## Voxel sets (tag 9)

`voxel_set` holds its own sections. An entry is
`{cell_hex, f_zoom, f_min, f_max}`: the cell × the heights
`[f_min · 2^(25 − f_zoom), (f_max + 1) · 2^(25 − f_zoom))` metres, WGS84
ellipsoidal. The canonical rule is in `VERIFICATION-SPEC.md` §2.1b.

| section | what it pins |
|---|---|
| `canonical` | input lists → canonical or not, plus the normalisation where every entry is valid: zoom-mixing sort order, coarsest zoom, touching and overlapping intervals, contained cells, sibling merges with identical and different heights, full-height entries, bounds, and 16 random overlapping lists |
| `digests` | entry lists → `SHA256("octet-region-voxelset-v1" ‖ u32be(n) ‖ {u64be cell ‖ u32be f_zoom ‖ i64be f_min ‖ i64be f_max}ⁿ)` |
| `containment` | `(entries, point, h) → inside`, including bin edges, negative heights and `-0.0`. `"h": null` means no height was given: containment must FAIL |
| `preimage_v3` | a full v3 preimage with a voxel-set claim and a voxel-set query |

A normalisation whose every entry covers all heights is listed but is not a
canonical voxel set: that region is sent as a `cell_set`.

The generator normalises with its own algorithm: it cuts the height axis at
every entry bound, takes each segment's footprint as a normalised
`s2.CellUnion`, and splits the footprints with the library's intersection and
difference. The verifier's `normalize_voxels` refines nested cells instead, so
agreement is a cross-check.

## Cell-set verdict

`cellset_verdict` pins the answer to "is the device's accuracy cap inside,
outside or across this canonical cell set?" (the cell form of the disc verdict).
The section carries the constants `k` (2), `r_m` (6,371,000) and
`edge_margin_chord` (1e-13), and the `cases`.

The rule, as the generator computes it (`generate/verdict.go`):

- The cap around P has angular radius `θ = k · h / r_m`, computed in that
  order, and squared chord `ℓ² = (2 · sin(θ / 2))²`.
- A cell is **touched** when it contains `leaf(P)`, or its squared chord
  distance from P (`Cell.Distance`: 0 inside the closed cell, otherwise to the
  nearest edge as a segment, endpoints included) is `< ℓ²`.
- The **descent** is normative: from the 6 faces, a touched cell is marked
  *in* if the set contains it, *out* if the set does not intersect it, and
  otherwise its 4 children are visited. INSIDE if nothing is out, OUTSIDE if
  nothing is in, INDETERMINATE otherwise.
- h missing, NaN, infinite or negative, or `θ ≥ π`: INDETERMINATE. `-0.0` is
  not negative, so it is h = 0: the answer is `leaf(P)` alone.

Each case has `cells_hex`, `point` and `xyz_f64_bits_hex` (use the xyz bits),
`h_m` and `h_f64_bits_hex` (use the bits; `h_m` is null and the bits absent when
h is missing, and `h_m` is null with the bits present when h is not finite),
`theta_rad` and `cap_length2` with their bits (null when the input alone decides
INDETERMINATE), `verdict`, and `min_margin_chord`: the smallest `|√d² − ℓ|` over
the distances the descent computed that could decide a touch. Cells containing
`leaf(P)` don't count, and with `ℓ = 0` nothing does (`d < 0` never holds).

`"edge": true` marks a case whose `min_margin_chord` is at most 1e-13. Distances
are not computed bit for bit alike everywhere (the reference may fuse
multiply-adds, and `sin` differs by an ulp), so an implementation must match
every case not marked `edge`; edge cases are informative. For the same reason
`min_margin_chord` can differ in its last bits when the generator runs on
another architecture (this file was generated on arm64, where Go fuses
multiply-adds); the verdicts and edge flags do not. An implementation that
stops the descent early computes a subset of the distances, so it still matches
every non-edge case.

The cases cover a coarse cell's centre, an edge straddled and touched exactly
from inside and outside (and 1e-9 in chord, about 6 mm, either side), a face
boundary, a cube corner, both poles, mixed levels with a finer neighbour, a gap,
h = 0 on cell vertices, h missing or invalid, caps near and beyond π, leaf
cells smaller than the cap, and 64 random sets and caps.

`src/s2.rs` (`cell_set_verdict`) is an independent port; `tests/s2_region.rs`
checks it against every case: θ bit for bit, `ℓ²` within 2 ulps, the edge flag,
and the verdict of every non-edge case.
