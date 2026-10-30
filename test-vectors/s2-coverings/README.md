# S2 coverings — country vectors from the policy engine

`coverings.json` holds S2 coverings of countries, made by the Octet policy engine
from its bundled map data (Natural Earth 1:50m) with the reference Go S2 library,
`github.com/golang/geo`, at the same version as `../s2-region/generate/`. The file
is copied here unchanged; never edit it. Its `geodata_version` identifies the map
data.

Each covering is the coverer's **normalised** cell union (`outer`: cells touching
the country; `inner`: cells wholly inside), so it is a canonical tag 8 cell set.
`tests/s2_coverings.rs` checks every full list for canonical form and its
`digest_hex`, `SHA256("octet-region-cellset-v1" ‖ u32be(n) ‖ u64be(id)ⁿ)`, and
that `exceeds_max_entries` agrees with the 16,384-cell cap.

| Name | Cells | List |
|---|---|---|
| `GB_L10_inner` / `GB_L10_outer` | 630 / 762 | full |
| `US_L13_inner` / `US_L13_outer` | 51,999 / 54,668 | digest only: above the cap, so used only as a `query_region` digest |

`params` records the coverer's `min_level`, `max_level`, `level_mod` and
`max_cells` (0 = no budget).
