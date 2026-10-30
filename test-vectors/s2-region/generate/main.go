// Command generate writes the S2 region golden vectors (vectors.json) from the
// reference Go S2 library, github.com/golang/geo, at the version pinned in
// go.mod. The verifier checks its own port against every vector.
//
//	go run . > ../vectors.json
package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"math/rand"
	"os"

	"github.com/golang/geo/s2"
)

const (
	cellSetDomain = "octet-region-cellset-v1"
	semanticV3    = "octet-semantic-binding-v3"
	maxEntries    = 16384
	tagCellSet    = 8
)

func hx(id s2.CellID) string { return fmt.Sprintf("%016x", uint64(id)) }

func hxs(ids []s2.CellID) []string {
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = hx(id)
	}
	return out
}

func bitsOf(v float64) string { return fmt.Sprintf("%016x", math.Float64bits(v)) }

func leaf(lat, lon float64) s2.CellID { return s2.CellIDFromLatLng(s2.LatLngFromDegrees(lat, lon)) }

// xyzBits is the reference's unit vector for the point. Mapping it to a cell
// needs no trigonometry, so it pins edge points exactly on every platform.
func xyzBits(lat, lon float64) [3]string {
	p := s2.PointFromLatLng(s2.LatLngFromDegrees(lat, lon))
	return [3]string{bitsOf(p.X), bitsOf(p.Y), bitsOf(p.Z)}
}

type point struct {
	Name  string     `json:"name"`
	Point [2]float64 `json:"point"`
	Bits  [2]string  `json:"point_f64_bits_hex"`
	XYZ   [3]string  `json:"xyz_f64_bits_hex"`
	Edge  bool       `json:"edge,omitempty"`
	Leaf  string     `json:"leaf_hex"`
	Token string     `json:"leaf_token"`
	// Levels[L] is the level-L cell containing the point, L = 0..30.
	Levels []string `json:"levels_hex"`
}

func mkPoint(name string, lat, lon float64, edge bool) point {
	l := leaf(lat, lon)
	levels := make([]string, 31)
	for L := 0; L <= 30; L++ {
		levels[L] = hx(l.Parent(L))
	}
	return point{name, [2]float64{lat, lon}, [2]string{bitsOf(lat), bitsOf(lon)}, xyzBits(lat, lon), edge, hx(l), l.ToToken(), levels}
}

type validity struct {
	Name  string `json:"name"`
	ID    string `json:"id_hex"`
	Valid bool   `json:"valid"`
	Level *int   `json:"level,omitempty"`
}

type hierarchy struct {
	ID       string   `json:"id_hex"`
	Token    string   `json:"token"`
	Level    int      `json:"level"`
	RangeMin string   `json:"range_min_hex"`
	RangeMax string   `json:"range_max_hex"`
	Parent   *string  `json:"parent_hex"`
	Children []string `json:"children_hex"`
}

type fIndex struct {
	H     float64 `json:"h"`
	HBits string  `json:"h_f64_bits_hex"`
	Zoom  int     `json:"zoom"`
	Valid bool    `json:"valid"`
	F     *int64  `json:"f,omitempty"`
}

type canonical struct {
	Name       string   `json:"name"`
	Input      []string `json:"input_hex"`
	Canonical  bool     `json:"canonical"`
	Normalized []string `json:"normalized_hex,omitempty"`
}

type digest struct {
	Name   string   `json:"name"`
	Cells  []string `json:"cells_hex"`
	Digest string   `json:"digest_hex"`
}

type containment struct {
	Name   string     `json:"name"`
	Cells  []string   `json:"cells_hex"`
	Point  [2]float64 `json:"point"`
	Bits   [2]string  `json:"point_f64_bits_hex"`
	XYZ    [3]string  `json:"xyz_f64_bits_hex"`
	Edge   bool       `json:"edge,omitempty"`
	Inside bool       `json:"inside"`
}

type preimage struct {
	Name            string   `json:"name"`
	Spoofing        uint32   `json:"spoofing_verdict"`
	Level           uint32   `json:"level"`
	Integrity       uint32   `json:"integrity_status"`
	Commitment      string   `json:"commitment_hex"`
	ClaimedCells    []string `json:"claimed_cells_hex"`
	LocationVerdict uint32   `json:"location_verdict"`
	QueryCells      []string `json:"query_cells_hex"`
	QueryRegionID   string   `json:"query_region_id_hex"`
	Preimage        string   `json:"preimage_hex"`
	StageHash       string   `json:"stage_hash_hex"`
}

func cellSetDigest(ids []s2.CellID) []byte {
	h := sha256.New()
	h.Write([]byte(cellSetDomain))
	binary.Write(h, binary.BigEndian, uint32(len(ids)))
	for _, id := range ids {
		binary.Write(h, binary.BigEndian, uint64(id))
	}
	return h.Sum(nil)
}

func u32(b []byte, v uint32) []byte { return binary.BigEndian.AppendUint32(b, v) }

// isCanonical: non-empty, at most maxEntries, every id valid, and the list is
// exactly its own S2 normalisation (sorted, disjoint, no 4 siblings).
func isCanonical(ids []s2.CellID) bool {
	if len(ids) == 0 || len(ids) > maxEntries {
		return false
	}
	for _, id := range ids {
		if !id.IsValid() {
			return false
		}
	}
	n := normalized(ids)
	if len(n) != len(ids) {
		return false
	}
	for i := range n {
		if n[i] != ids[i] {
			return false
		}
	}
	return true
}

func normalized(ids []s2.CellID) []s2.CellID {
	cu := s2.CellUnion(append([]s2.CellID(nil), ids...))
	cu.Normalize()
	return []s2.CellID(cu)
}

func main() {
	// --- points ---
	var points []point
	named := []struct {
		name     string
		lat, lon float64
		edge     bool
	}{
		{"london", 51.5074, -0.1278, false},
		{"tokyo", 35.6762, 139.6503, false},
		{"sydney", -33.8688, 151.2093, false},
		{"new_york", 40.7128, -74.0060, false},
		{"sao_paulo", -23.5505, -46.6333, false},
		{"reykjavik", 64.1466, -21.9426, false},
		{"null_island", 0, 0, true},
		{"north_pole", 90, 0, true},
		{"south_pole", -90, 0, true},
		{"antimeridian_east", 0, 180, true},
		{"antimeridian_west", 0, -180, true},
		{"antimeridian_near_east", 10, 179.9999999, false},
		{"antimeridian_near_west", 10, -179.9999999, false},
		{"face_edge_0_1", 0, 45, true},
		{"cube_corner", 35.26438968275465, 45, true},
		{"near_face_edge", 0.0001, 44.9999, false},
		{"lon_negative_zero", 12.5, math.Copysign(0, -1), false},
	}
	for _, p := range named {
		points = append(points, mkPoint(p.name, p.lat, p.lon, p.edge))
	}
	rng := rand.New(rand.NewSource(20261026))
	for i := 0; i < 48; i++ {
		lat := math.Asin(2*rng.Float64()-1) * 180 / math.Pi
		lon := 360*rng.Float64() - 180
		points = append(points, mkPoint(fmt.Sprintf("random_%02d", i), lat, lon, false))
	}

	london := leaf(51.5074, -0.1278)

	// --- validity ---
	lvl := func(id s2.CellID) *int { l := id.Level(); return &l }
	var vals []validity
	addValid := func(name string, id s2.CellID) {
		v := validity{Name: name, ID: hx(id), Valid: id.IsValid()}
		if v.Valid {
			v.Level = lvl(id)
		}
		vals = append(vals, v)
	}
	for f := 0; f < 6; f++ {
		addValid(fmt.Sprintf("face_%d", f), s2.CellIDFromFace(f))
	}
	addValid("london_leaf", london)
	addValid("london_l12", london.Parent(12))
	addValid("zero", s2.CellID(0))
	addValid("face_6", s2.CellID(uint64(6)<<61|1<<60))
	addValid("face_7", s2.CellID(uint64(7)<<61|1<<60))
	addValid("sentinel", s2.SentinelCellID)
	{
		x := uint64(london.Parent(12))
		lsb := x & -x
		addValid("odd_trailing_zeros", s2.CellID((x&^lsb)|lsb>>1))
	}
	addValid("lsb_at_bit_1", s2.CellID(0x2))

	// --- hierarchy ---
	var hier []hierarchy
	for _, L := range []int{0, 1, 5, 12, 20, 29, 30} {
		id := london.Parent(L)
		h := hierarchy{ID: hx(id), Token: id.ToToken(), Level: L, RangeMin: hx(id.RangeMin()), RangeMax: hx(id.RangeMax())}
		if L > 0 {
			p := hx(id.Parent(L - 1))
			h.Parent = &p
		}
		if L < 30 {
			ch := id.Children()
			h.Children = hxs(ch[:])
		}
		hier = append(hier, h)
	}

	// --- f-index: f = floor(h * 2^(zoom-25)), valid iff |h| < 2^25 ---
	var fs []fIndex
	addF := func(h float64, zoom int) {
		v := fIndex{H: h, HBits: bitsOf(h), Zoom: zoom, Valid: math.Abs(h) < 1<<25 && !math.IsNaN(h)}
		if v.Valid {
			f := int64(math.Floor(math.Ldexp(h, zoom-25)))
			v.F = &f
		}
		fs = append(fs, v)
	}
	for _, h := range []float64{0, math.Copysign(0, -1), 1, -1, 0.5, -0.5, 119.99, 120, 128, -128, 4095.999, 4096, 8848.86, -430.5, 33554431.999, -33554432, 33554432, -33554432.001, 1e-9, -1e-9} {
		for _, z := range []int{0, 1, 13, 18, 20, 25, 32} {
			addF(h, z)
		}
	}

	// --- canonicalisation ---
	var cans []canonical
	addCan := func(name string, ids []s2.CellID) {
		c := canonical{Name: name, Input: hxs(ids), Canonical: isCanonical(ids)}
		ok := len(ids) > 0
		for _, id := range ids {
			ok = ok && id.IsValid()
		}
		if ok {
			c.Normalized = hxs(normalized(ids))
		}
		cans = append(cans, c)
	}
	p12 := london.Parent(12)
	ch12 := p12.Children()
	sib := ch12[0].Children()
	addCan("single_cell", []s2.CellID{p12})
	addCan("mixed_levels_sorted_disjoint", []s2.CellID{ch12[0], ch12[1].Children()[2], ch12[3]})
	addCan("unsorted", []s2.CellID{ch12[3], ch12[0]})
	addCan("duplicate", []s2.CellID{ch12[0], ch12[0]})
	addCan("contained", []s2.CellID{ch12[0], sib[1]})
	addCan("four_siblings_unmerged", []s2.CellID{ch12[0], ch12[1], ch12[2], ch12[3]})
	addCan("four_grandchildren_cascade", []s2.CellID{sib[0], sib[1], sib[2], sib[3], ch12[1], ch12[2], ch12[3]})
	addCan("three_siblings", []s2.CellID{ch12[0], ch12[1], ch12[2]})
	addCan("all_six_faces", []s2.CellID{s2.CellIDFromFace(0), s2.CellIDFromFace(1), s2.CellIDFromFace(2), s2.CellIDFromFace(3), s2.CellIDFromFace(4), s2.CellIDFromFace(5)})
	addCan("empty", []s2.CellID{})
	addCan("invalid_id", []s2.CellID{ch12[0], s2.CellID(0)})
	addCan("leaf_cells", []s2.CellID{london, leaf(35.6762, 139.6503)})
	addCan("across_faces", []s2.CellID{leaf(40.7128, -74.0060).Parent(8), london.Parent(8), leaf(-33.8688, 151.2093).Parent(8)})

	// --- digests ---
	var digs []digest
	addDig := func(name string, ids []s2.CellID) {
		digs = append(digs, digest{name, hxs(ids), hex.EncodeToString(cellSetDigest(ids))})
	}
	addDig("single_cell", []s2.CellID{p12})
	addDig("mixed_levels", []s2.CellID{ch12[0], ch12[1].Children()[2], ch12[3]})
	addDig("leaf_cells", normalized([]s2.CellID{london, leaf(35.6762, 139.6503)}))
	addDig("all_six_faces", []s2.CellID{s2.CellIDFromFace(0), s2.CellIDFromFace(1), s2.CellIDFromFace(2), s2.CellIDFromFace(3), s2.CellIDFromFace(4), s2.CellIDFromFace(5)})

	// --- containment ---
	var conts []containment
	addCont := func(name string, ids []s2.CellID, lat, lon float64, edge bool) {
		cu := s2.CellUnion(ids)
		in := cu.ContainsCellID(leaf(lat, lon))
		conts = append(conts, containment{name, hxs(ids), [2]float64{lat, lon}, [2]string{bitsOf(lat), bitsOf(lon)}, xyzBits(lat, lon), edge, in})
	}
	region := []s2.CellID{ch12[0], ch12[1].Children()[2], ch12[3]}
	centre := func(id s2.CellID) (float64, float64) {
		ll := s2.LatLngFromPoint(s2.CellFromCellID(id).Center())
		return ll.Lat.Degrees(), ll.Lng.Degrees()
	}
	vertex := func(id s2.CellID, k int) (float64, float64) {
		ll := s2.LatLngFromPoint(s2.CellFromCellID(id).Vertex(k))
		return ll.Lat.Degrees(), ll.Lng.Degrees()
	}
	for i, c := range []s2.CellID{ch12[0], ch12[1].Children()[2], ch12[3]} {
		lat, lon := centre(c)
		addCont(fmt.Sprintf("mixed_centre_of_member_%d", i), region, lat, lon, false)
	}
	for i, c := range []s2.CellID{ch12[1].Children()[0], ch12[1].Children()[3], ch12[2]} {
		lat, lon := centre(c)
		addCont(fmt.Sprintf("mixed_centre_of_gap_%d", i), region, lat, lon, false)
	}
	{
		lat, lon := centre(p12.Parent(10).Children()[0])
		if p12.Parent(10).Children()[0].Contains(p12) {
			lat, lon = centre(p12.Parent(10).Children()[3])
		}
		addCont("mixed_far_outside", region, lat, lon, false)
	}
	addCont("london_leaf_in_l12", []s2.CellID{p12}, 51.5074, -0.1278, false)
	addCont("tokyo_not_in_london_l12", []s2.CellID{p12}, 35.6762, 139.6503, false)
	for k := 0; k < 4; k++ {
		lat, lon := vertex(ch12[0], k)
		addCont(fmt.Sprintf("vertex_%d_of_member", k), region, lat, lon, true)
	}
	faces := []s2.CellID{s2.CellIDFromFace(0), s2.CellIDFromFace(1), s2.CellIDFromFace(2), s2.CellIDFromFace(3), s2.CellIDFromFace(4), s2.CellIDFromFace(5)}
	addCont("whole_sphere_north_pole", faces, 90, 0, true)
	addCont("face_2_only_north_pole", []s2.CellID{s2.CellIDFromFace(2)}, 90, 0, true)
	addCont("face_5_only_south_pole", []s2.CellID{s2.CellIDFromFace(5)}, -90, 0, true)
	addCont("face_0_only_tokyo", []s2.CellID{s2.CellIDFromFace(0)}, 35.6762, 139.6503, false)
	for i := 0; i < 24; i++ {
		lat := math.Asin(2*rng.Float64()-1) * 180 / math.Pi
		lon := 360*rng.Float64() - 180
		set := normalized([]s2.CellID{leaf(lat+0.01*rng.NormFloat64(), lon+0.01*rng.NormFloat64()).Parent(10 + rng.Intn(6)), leaf(lat, lon).Parent(8 + rng.Intn(8))})
		if rng.Intn(2) == 0 {
			set = normalized([]s2.CellID{leaf(lat+0.2, lon+0.2).Parent(12)})
		}
		addCont(fmt.Sprintf("random_%02d", i), set, lat, lon, false)
	}

	// --- semantic-binding v3 preimage with a type-8 claim and query ---
	claim := []s2.CellID{london.Parent(16)}
	query := normalized([]s2.CellID{ch12[0], ch12[1], ch12[2]})
	commit := make([]byte, 32)
	for i := range commit {
		commit[i] = 0xab
	}
	cd, qd := cellSetDigest(claim), cellSetDigest(query)
	var pre []byte
	pre = append(pre, semanticV3...)
	pre = u32(pre, 1) // spoofing
	pre = u32(pre, 4) // level CONTINUOUS_AREA
	pre = u32(pre, 2) // integrity
	pre = u32(pre, tagCellSet)
	pre = u32(pre, uint32(len(cd)))
	pre = append(pre, cd...)
	pre = u32(pre, uint32(len(commit)))
	pre = append(pre, commit...)
	pre = u32(pre, 1) // INSIDE
	pre = u32(pre, tagCellSet)
	pre = u32(pre, uint32(len(qd)))
	pre = append(pre, qd...)
	sum := sha256.Sum256(pre)
	pres := []preimage{{
		Name: "cellset_claim_cellset_query_inside", Spoofing: 1, Level: 4, Integrity: 2,
		Commitment: hex.EncodeToString(commit), ClaimedCells: hxs(claim), LocationVerdict: 1,
		QueryCells: hxs(query), QueryRegionID: hex.EncodeToString(qd),
		Preimage: hex.EncodeToString(pre), StageHash: hex.EncodeToString(sum[:]),
	}}

	vox := voxelVectors(london, rng)

	out := map[string]any{
		"note":           "S2 region golden vectors (tag 8 cellSet, tag 9 voxelSet). Generated by generate/ from github.com/golang/geo; do not edit by hand.",
		"generator":      "github.com/golang/geo v0.0.0-20261026081726-9e1e803a26c2",
		"cellset_domain": cellSetDomain,
		"max_entries":    maxEntries,
		"points":         points,
		"validity":       vals,
		"hierarchy":      hier,
		"f_index":        fs,
		"canonical":      cans,
		"digests":        digs,
		"containment":    conts,
		"preimage_v3":    pres,
		"voxel_set":      vox,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		panic(err)
	}
}
