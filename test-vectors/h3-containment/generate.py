"""Generate octet-verify h3 containment golden vectors with the reference H3 C
library (Uber h3 v4, via the `h3` Python binding). Semantics under test:
inside iff exists C in cells: latlng_to_cell(point, res(C)) == C."""
import json, struct, h3
bits = lambda f: format(struct.unpack(">Q", struct.pack(">d", f))[0], "016x")
I = lambda c: int(c, 16)
H = lambda c: c if isinstance(c, str) else format(c, 'x')

def inside(cells, lat, lon):
    return any(h3.latlng_to_cell(lat, lon, h3.get_resolution(c)) == c for c in cells)

V = []
def vec(name, note, cells, lat, lon, expect=None):
    if expect is None:
        assert all(h3.is_valid_cell(c) for c in cells) and cells
        expect = "PASS" if inside(cells, lat, lon) else "FAIL"
    V.append({"name": name, "note": note, "cell_ids_hex": [H(c) for c in cells],
              "point": [lat, lon],
              "point_f64_bits_hex": [bits(lat), bits(lon)], "expect": expect})

SF = (37.7749, -122.4194); LDN = (51.5074, -0.1278); PAR = (48.8566, 2.3522)
sf10 = h3.latlng_to_cell(*SF, 10); ldn10 = h3.latlng_to_cell(*LDN, 10)
sf5 = h3.latlng_to_cell(*SF, 5)

vec("in_cell_res10", "point inside the single listed res-10 cell", [sf10], *SF)
vec("out_of_cell_res10", "point far outside the single listed cell", [sf10], *LDN)
nb = [c for c in h3.grid_ring(sf10, 1)][0]
vec("adjacent_cell_not_listed", "point in a neighbour of the listed cell", [sf10], *h3.cell_to_latlng(nb))

# mixed / compacted resolutions
mixed = [sf5, ldn10]
vec("mixed_res_coarse_hit", "res-5 cell covers SF in a mixed {res5, res10} set", mixed, *SF)
vec("mixed_res_fine_hit", "res-10 cell covers London in the same mixed set", mixed, *LDN)
vec("mixed_res_miss", "Paris is in neither cell of the mixed set", mixed, *PAR)
# compacted: the 7 res-10 children of a res-9 cell compact to that res-9 cell;
# list the compacted res-9 parent next to unrelated fine cells, and test a point
# whose own res-10 cell is NOT listed but whose res-9 parent is.
p9 = h3.cell_to_parent(sf10, 9)
kids = h3.cell_to_children(p9, 10)
assert h3.compact_cells(kids) == [p9]
other_kid = [k for k in kids if k != sf10][0]
compacted = [p9, ldn10]
vec("compacted_parent_covers_unlisted_child", "res-9 parent (compacted form of its 7 children) contains a point in an unlisted res-10 child", compacted, *h3.cell_to_latlng(other_kid))
vec("compacted_vs_uncompacted_agree", "the uncompacted 7 children give the same answer for that point", list(kids), *h3.cell_to_latlng(other_kid))

# pentagon
pent = [c for c in h3.get_pentagons(4)][0]
vec("pentagon_centre", "centre of a res-4 pentagon cell", [pent], *h3.cell_to_latlng(pent))
pnb = list(h3.grid_ring(pent, 1))[0]
vec("pentagon_neighbour", "centre of a neighbour of the pentagon (not listed)", [pent], *h3.cell_to_latlng(pnb))

# boundary point: a vertex of sf10 is shared by 3 cells; H3 assigns it to exactly one.
vlat, vlon = h3.cell_to_boundary(sf10)[0]
owner = h3.latlng_to_cell(vlat, vlon, 10)
sharers = [c for c in h3.grid_disk(sf10, 1)
           if any(abs(a-vlat) < 1e-9 and abs(b-vlon) < 1e-9 for a, b in h3.cell_to_boundary(c))]
assert owner in sharers and len(sharers) == 3, (owner, sharers)
non_owner = [c for c in sharers if c != owner]
vec("boundary_vertex_owner", "shared vertex of 3 cells; listing its owning cell contains it", [owner], vlat, vlon)
vec("boundary_vertex_non_owners", "the same vertex with only the 2 non-owning sharers listed", non_owner, vlat, vlon)

vec("duplicates_harmless", "a repeated cell id behaves set-wise", [sf10, sf10], *SF)

# fail-closed: malformed sets FAIL regardless of the point
V.append({"name": "empty_set", "note": "no cells: malformed region", "cell_ids_hex": [], "point": list(SF), "point_f64_bits_hex": [bits(SF[0]), bits(SF[1])], "expect": "FAIL"})
assert not h3.is_valid_cell("0")
V.append({"name": "invalid_zero_index", "note": "0 is not a valid H3 cell", "cell_ids_hex": ["0"], "point": list(SF), "point_f64_bits_hex": [bits(SF[0]), bits(SF[1])], "expect": "FAIL"})
# an H3 *edge* index (mode 2) is a valid H3 index but not a cell
edge = h3.cells_to_directed_edge(sf10, nb)
assert h3.is_valid_directed_edge(edge) and not h3.is_valid_cell(edge)
V.append({"name": "edge_index_not_a_cell", "note": "a directed-edge index (mode 2) is not a cell", "cell_ids_hex": [edge], "point": list(SF), "point_f64_bits_hex": [bits(SF[0]), bits(SF[1])], "expect": "FAIL"})
V.append({"name": "invalid_poisons_valid_hit", "note": "fail closed: one invalid index FAILs the set even though a valid cell contains the point", "cell_ids_hex": [sf10, "0"], "point": list(SF), "point_f64_bits_hex": [bits(SF[0]), bits(SF[1])], "expect": "FAIL"})

doc = {
  "note": "Golden vectors for --expect-region-contains against an h3_polygon_set region. Generated with the reference H3 C library v" + h3.__version__ + " (Python binding). Semantics: the region is the filled union of the cells; a point is inside iff some cell C has latLngToCell(point, res(C)) == C at C's own resolution. Malformed sets (empty, or any index that is not a valid H3 v4 cell) FAIL closed. cell_ids are hex strings (64-bit; exceeds JS 2^53). point is [lat, lon] in degrees; point_f64_bits_hex is the exact IEEE-754 bit pattern of each (use it, so a boundary point survives parsing bit-exactly). Never edit an expect value to make a test pass: regenerate from the reference library.",
  "generator": "h3 " + h3.__version__,
  "vectors": V,
}
print(json.dumps(doc, indent=2))
