package main

// Tag 9 voxel-set vectors. The canonical form is computed here with a different
// algorithm from the verifier's: the height axis is cut into elementary
// segments, each segment's footprint is a normalised s2.CellUnion, and the
// footprints are split into pieces with one height set each through the
// library's own intersection and difference. Each piece's cells are then the
// maximal cells with that height set.

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math"
	"math/rand"
	"sort"

	"github.com/golang/geo/s2"
)

const (
	voxelSetDomain = "octet-region-voxelset-v1"
	maxFZoom       = 32
	tagVoxelSet    = 9
)

type voxel struct {
	Cell s2.CellID
	Zoom int
	FMin int64
	FMax int64
}

type voxelJSON struct {
	Cell string `json:"cell_hex"`
	Zoom int    `json:"f_zoom"`
	FMin int64  `json:"f_min"`
	FMax int64  `json:"f_max"`
}

func vj(vs []voxel) []voxelJSON {
	out := make([]voxelJSON, len(vs))
	for i, v := range vs {
		out[i] = voxelJSON{hx(v.Cell), v.Zoom, v.FMin, v.FMax}
	}
	return out
}

// lo and hi bound the entry in zoom-32 bins, by multiplication: [lo, hi).
func (v voxel) lo() int64 { return v.FMin * (int64(1) << (maxFZoom - v.Zoom)) }
func (v voxel) hi() int64 { return (v.FMax + 1) * (int64(1) << (maxFZoom - v.Zoom)) }

func (v voxel) boundsOK() bool {
	if v.Zoom < 0 || v.Zoom > maxFZoom {
		return false
	}
	n := int64(1) << v.Zoom
	return -n <= v.FMin && v.FMin <= v.FMax && v.FMax <= n-1
}

func (v voxel) fullHeight() bool { return v.lo() == -(1<<32) && v.hi() == 1<<32 }

// fromInterval writes [lo, hi) at the only zoom that writes it exactly with
// the coarsest bins.
func fromInterval(c s2.CellID, lo, hi int64) voxel {
	z := maxFZoom
	for z > 0 {
		b := int64(1) << (maxFZoom - z + 1)
		if lo%b != 0 || hi%b != 0 {
			break
		}
		z--
	}
	b := int64(1) << (maxFZoom - z)
	return voxel{c, z, lo / b, hi/b - 1}
}

type ival struct{ lo, hi int64 }

// voxelNormalize returns the canonical spelling of the region (ignoring the
// entry cap and the all-full-height rule). ok is false if an entry is invalid
// or the list is empty.
func voxelNormalize(vs []voxel) ([]voxel, bool) {
	if len(vs) == 0 {
		return nil, false
	}
	var cuts []int64
	for _, v := range vs {
		if !v.Cell.IsValid() || !v.boundsOK() {
			return nil, false
		}
		cuts = append(cuts, v.lo(), v.hi())
	}
	sort.Slice(cuts, func(i, j int) bool { return cuts[i] < cuts[j] })
	var segs []ival
	for i := 1; i < len(cuts); i++ {
		if cuts[i] > cuts[i-1] {
			segs = append(segs, ival{cuts[i-1], cuts[i]})
		}
	}
	// Footprint of each segment.
	foot := make([]s2.CellUnion, len(segs))
	var all s2.CellUnion
	for k, s := range segs {
		var cu s2.CellUnion
		for _, v := range vs {
			if v.lo() <= s.lo && s.hi <= v.hi() {
				cu = append(cu, v.Cell)
			}
		}
		cu.Normalize()
		foot[k] = cu
		all = s2.CellUnionFromUnion(all, cu)
	}
	// Split into pieces by membership in each footprint.
	type piece struct {
		cells s2.CellUnion
		in    []bool
	}
	pieces := []piece{{all, make([]bool, len(segs))}}
	for k := range segs {
		var next []piece
		for _, p := range pieces {
			a := s2.CellUnionFromIntersection(p.cells, foot[k])
			a.Normalize()
			d := s2.CellUnionFromDifference(p.cells, foot[k])
			d.Normalize()
			if len(a) > 0 {
				in := append([]bool(nil), p.in...)
				in[k] = true
				next = append(next, piece{a, in})
			}
			if len(d) > 0 {
				next = append(next, piece{d, append([]bool(nil), p.in...)})
			}
		}
		pieces = next
	}
	var out []voxel
	for _, p := range pieces {
		var ivs []ival
		for k, s := range segs {
			if !p.in[k] {
				continue
			}
			if n := len(ivs); n > 0 && ivs[n-1].hi == s.lo {
				ivs[n-1].hi = s.hi
			} else {
				ivs = append(ivs, s)
			}
		}
		if len(ivs) == 0 {
			panic("piece with no heights")
		}
		for _, c := range p.cells {
			for _, iv := range ivs {
				out = append(out, fromInterval(c, iv.lo, iv.hi))
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Cell != out[j].Cell {
			return out[i].Cell < out[j].Cell
		}
		return out[i].lo() < out[j].lo()
	})
	return out, true
}

func voxelEqual(a, b []voxel) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// voxelCanonical: the list is its own normalisation, within the cap, and at
// least one entry is bounded in height.
func voxelCanonical(vs []voxel) bool {
	n, ok := voxelNormalize(vs)
	if !ok || len(vs) > maxEntries || !voxelEqual(n, vs) {
		return false
	}
	for _, v := range vs {
		if !v.fullHeight() {
			return true
		}
	}
	return false
}

func voxelSetDigest(vs []voxel) []byte {
	h := sha256.New()
	h.Write([]byte(voxelSetDomain))
	binary.Write(h, binary.BigEndian, uint32(len(vs)))
	for _, v := range vs {
		binary.Write(h, binary.BigEndian, uint64(v.Cell))
		binary.Write(h, binary.BigEndian, uint32(v.Zoom))
		binary.Write(h, binary.BigEndian, v.FMin)
		binary.Write(h, binary.BigEndian, v.FMax)
	}
	return h.Sum(nil)
}

// voxelContains: the point's leaf lies in an entry's cell and the height's bin
// at that entry's zoom lies in [f_min, f_max].
func voxelContains(vs []voxel, lat, lon, h float64) bool {
	l := leaf(lat, lon)
	for _, v := range vs {
		if !v.Cell.Contains(l) {
			continue
		}
		f := int64(math.Floor(math.Ldexp(h, v.Zoom-25)))
		if v.FMin <= f && f <= v.FMax {
			return true
		}
	}
	return false
}

type voxelCanonicalCase struct {
	Name       string      `json:"name"`
	Input      []voxelJSON `json:"input"`
	Canonical  bool        `json:"canonical"`
	Normalized []voxelJSON `json:"normalized,omitempty"`
}

type voxelDigestCase struct {
	Name    string      `json:"name"`
	Entries []voxelJSON `json:"entries"`
	Digest  string      `json:"digest_hex"`
}

type voxelContainmentCase struct {
	Name    string      `json:"name"`
	Entries []voxelJSON `json:"entries"`
	Point   [2]float64  `json:"point"`
	Bits    [2]string   `json:"point_f64_bits_hex"`
	XYZ     [3]string   `json:"xyz_f64_bits_hex"`
	H       *float64    `json:"h"`
	HBits   *string     `json:"h_f64_bits_hex"`
	Inside  bool        `json:"inside"`
}

type voxelPreimage struct {
	Name            string      `json:"name"`
	Spoofing        uint32      `json:"spoofing_verdict"`
	Level           uint32      `json:"level"`
	Integrity       uint32      `json:"integrity_status"`
	Commitment      string      `json:"commitment_hex"`
	Claimed         []voxelJSON `json:"claimed_entries"`
	LocationVerdict uint32      `json:"location_verdict"`
	Query           []voxelJSON `json:"query_entries"`
	QueryRegionID   string      `json:"query_region_id_hex"`
	Preimage        string      `json:"preimage_hex"`
	StageHash       string      `json:"stage_hash_hex"`
}

func voxelVectors(london s2.CellID, rng *rand.Rand) map[string]any {
	p12 := london.Parent(12)
	ch := p12.Children()
	g := ch[0].Children()
	full := func(c s2.CellID) voxel { return voxel{c, 0, -1, 0} }
	// below120 is [0 m, 120 m) at the coarsest zoom that writes it: 120 m is
	// 15 bins of 8 m (zoom 22), so the entry is zoom 22, f 0..14.
	below120 := func(c s2.CellID) voxel { return voxel{c, 22, 0, 14} }

	var cans []voxelCanonicalCase
	add := func(name string, vs []voxel) {
		c := voxelCanonicalCase{Name: name, Input: vj(vs), Canonical: voxelCanonical(vs)}
		if n, ok := voxelNormalize(vs); ok {
			c.Normalized = vj(n)
		}
		cans = append(cans, c)
	}
	add("single_entry", []voxel{below120(p12)})
	add("mixed_zoom_sorted_by_lo", []voxel{{p12, 10, 5, 5}, {p12, 3, 1, 1}})
	add("mixed_zoom_sorted_by_raw_f_min", []voxel{{p12, 3, 1, 1}, {p12, 10, 5, 5}})
	add("negative_heights", []voxel{{p12, 20, -3, -1}, {p12, 20, 4, 4}})
	add("not_coarsest_zoom", []voxel{{p12, 23, 0, 29}})
	add("coarsest_zoom_after_reduction", []voxel{{p12, 22, 0, 14}})
	add("touching_intervals", []voxel{{p12, 22, 0, 14}, {p12, 22, 15, 15}})
	add("overlapping_intervals", []voxel{{p12, 22, 0, 10}, {p12, 22, 5, 20}})
	add("gap_between_intervals", []voxel{{p12, 22, 0, 3}, {p12, 22, 5, 9}})
	add("duplicate_entry", []voxel{below120(p12), below120(p12)})
	add("contained_cell", []voxel{below120(ch[0]), below120(g[1])})
	add("contained_cell_extra_height", []voxel{below120(ch[0]), {g[1], 22, 0, 30}})
	add("four_siblings_identical_lists", []voxel{below120(ch[0]), below120(ch[1]), below120(ch[2]), below120(ch[3])})
	add("four_siblings_different_lists", []voxel{below120(ch[0]), below120(ch[1]), below120(ch[2]), {ch[3], 22, 0, 30}})
	add("four_grandchildren_cascade", []voxel{below120(g[0]), below120(g[1]), below120(g[2]), below120(g[3]), below120(ch[1]), below120(ch[2]), below120(ch[3])})
	add("full_height_mixed_with_bounded", []voxel{full(ch[0]), below120(ch[1])})
	add("all_full_height", []voxel{full(ch[0]), full(ch[1])})
	add("unsorted_cells", []voxel{below120(ch[3]), below120(ch[0])})
	add("full_range_zoom_32", []voxel{{p12, 32, -(1 << 32), 1<<32 - 1}})
	add("max_zoom_single_bin", []voxel{{p12, 32, 7, 7}})
	add("f_zoom_33", []voxel{{p12, 33, 0, 0}})
	add("f_min_above_f_max", []voxel{{p12, 22, 5, 4}})
	add("f_max_out_of_range", []voxel{{p12, 2, 0, 4}})
	add("f_min_out_of_range", []voxel{{p12, 2, -5, 0}})
	add("invalid_cell", []voxel{{s2.CellID(0), 22, 0, 14}})
	add("empty", []voxel{})

	var digs []voxelDigestCase
	addDig := func(name string, vs []voxel) {
		digs = append(digs, voxelDigestCase{name, vj(vs), hex.EncodeToString(voxelSetDigest(vs))})
	}
	addDig("single_entry", []voxel{below120(p12)})
	addDig("negative_heights", []voxel{{p12, 20, -3, -1}, {p12, 20, 4, 4}})
	addDig("full_height_mixed_with_bounded", []voxel{full(ch[0]), below120(ch[1])})

	var conts []voxelContainmentCase
	addCont := func(name string, vs []voxel, lat, lon float64, h *float64) {
		c := voxelContainmentCase{Name: name, Entries: vj(vs), Point: [2]float64{lat, lon},
			Bits: [2]string{bitsOf(lat), bitsOf(lon)}, XYZ: xyzBits(lat, lon), H: h}
		if h != nil {
			b := bitsOf(*h)
			c.HBits = &b
			c.Inside = voxelContains(vs, lat, lon, *h)
		}
		conts = append(conts, c)
	}
	hp := func(h float64) *float64 { return &h }
	centre := func(id s2.CellID) (float64, float64) {
		ll := s2.LatLngFromPoint(s2.CellFromCellID(id).Center())
		return ll.Lat.Degrees(), ll.Lng.Degrees()
	}
	airfield := []voxel{full(ch[0]), below120(ch[1])}
	lat0, lon0 := centre(ch[0])
	lat1, lon1 := centre(ch[1])
	lat2, lon2 := centre(ch[2])
	addCont("full_height_cell_high", airfield, lat0, lon0, hp(30000))
	addCont("full_height_cell_deep", airfield, lat0, lon0, hp(-30000))
	addCont("bounded_cell_ground", airfield, lat1, lon1, hp(0))
	addCont("bounded_cell_below_top", airfield, lat1, lon1, hp(119.99))
	addCont("bounded_cell_at_top", airfield, lat1, lon1, hp(120))
	addCont("bounded_cell_negative", airfield, lat1, lon1, hp(-0.001))
	addCont("bounded_cell_negative_zero", airfield, lat1, lon1, hp(math.Copysign(0, -1)))
	addCont("outside_footprint", airfield, lat2, lon2, hp(50))
	addCont("no_height", airfield, lat1, lon1, nil)
	two := []voxel{{p12, 20, -3, -1}, {p12, 20, 4, 4}}
	latp, lonp := centre(p12)
	for _, h := range []float64{-97, -96, -95.99, -1e-9, 0, 127.99, 128, 159.99, 160} {
		addCont(fmt.Sprintf("two_bands_h_%v", h), two, latp, lonp, hp(h))
	}
	for i := 0; i < 8; i++ {
		lat := math.Asin(2*rng.Float64()-1) * 180 / math.Pi
		lon := 360*rng.Float64() - 180
		c := leaf(lat, lon).Parent(8 + rng.Intn(8))
		// f_min in [-2^z + 1, 2^z - 6] keeps the test height, up to one bin
		// below and two above, inside |h| < 2^25.
		z := 5 + rng.Intn(21)
		n := int64(1) << z
		fmin := -n + 1 + rng.Int63n(2*n-6)
		vs, ok := voxelNormalize([]voxel{{c, z, fmin, fmin + rng.Int63n(4)}})
		if !ok {
			panic("random voxel out of range")
		}
		f := float64(fmin) * math.Ldexp(1, 25-z)
		addCont(fmt.Sprintf("random_%02d", i), vs, lat, lon, hp(f+math.Ldexp(rng.Float64()*3-1, 25-z)))
	}

	// Random overlapping lists: nested cells under one level-12 cell and
	// overlapping intervals at mixed zooms, normalised by the algorithm above.
	for i := 0; i < 16; i++ {
		var vs []voxel
		for k := 0; k < 3+rng.Intn(10); k++ {
			c := p12
			for d := rng.Intn(4); d > 0; d-- {
				c = c.Children()[rng.Intn(4)]
			}
			z := 18 + rng.Intn(7)
			fmin := int64(rng.Intn(16)) - 4
			vs = append(vs, voxel{c, z, fmin, fmin + int64(rng.Intn(6))})
		}
		add(fmt.Sprintf("random_%02d", i), vs)
	}

	// A v3 preimage with a voxel-set claim and a voxel-set query.
	claim := []voxel{{london.Parent(16), 25, 40, 42}}
	query := airfield
	commit := make([]byte, 32)
	for i := range commit {
		commit[i] = 0xcd
	}
	cd, qd := voxelSetDigest(claim), voxelSetDigest(query)
	var pre []byte
	pre = append(pre, semanticV3...)
	pre = u32(pre, 1) // spoofing
	pre = u32(pre, 4) // level CONTINUOUS_AREA
	pre = u32(pre, 2) // integrity
	pre = u32(pre, tagVoxelSet)
	pre = u32(pre, uint32(len(cd)))
	pre = append(pre, cd...)
	pre = u32(pre, uint32(len(commit)))
	pre = append(pre, commit...)
	pre = u32(pre, 1) // INSIDE
	pre = u32(pre, tagVoxelSet)
	pre = u32(pre, uint32(len(qd)))
	pre = append(pre, qd...)
	sum := sha256.Sum256(pre)
	for _, vs := range [][]voxel{claim, query} {
		if !voxelCanonical(vs) {
			panic("preimage set is not canonical")
		}
	}

	return map[string]any{
		"voxelset_domain": voxelSetDomain,
		"max_entries":     maxEntries,
		"max_f_zoom":      maxFZoom,
		"canonical":       cans,
		"digests":         digs,
		"containment":     conts,
		"preimage_v3": []voxelPreimage{{
			Name: "voxelset_claim_voxelset_query_inside", Spoofing: 1, Level: 4, Integrity: 2,
			Commitment: hex.EncodeToString(commit), Claimed: vj(claim), LocationVerdict: 1,
			Query: vj(query), QueryRegionID: hex.EncodeToString(qd),
			Preimage: hex.EncodeToString(pre), StageHash: hex.EncodeToString(sum[:]),
		}},
	}
}
