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
