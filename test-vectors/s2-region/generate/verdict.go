package main

// The cell-set verdict (section cellset_verdict): is the accuracy cap around P,
// angular radius θ = K·h/R, inside, outside or across a canonical cell set S?
// The answer is computed by the normative descent: from the 6 faces, for each
// cell x the cap touches (x contains leaf(P), or Cell.Distance(P) < ℓ² on
// squared chords), mark in if S contains x, out if S does not intersect x,
// else recurse into x's children.

import (
	"fmt"
	"math"
	"math/rand"

	"github.com/golang/geo/s1"
	"github.com/golang/geo/s2"
)

const (
	verdictK      = 2.0
	verdictR      = 6371000.0
	edgeMarginCh  = 1e-13 // |√d² − ℓ| in chord length
	verdictSeed   = 20261120
	randomVerdict = 64
)

type cellsetVerdict struct {
	Name   string     `json:"name"`
	Cells  []string   `json:"cells_hex"`
	Point  [2]float64 `json:"point"`
	XYZ    [3]string  `json:"xyz_f64_bits_hex"`
	H      *float64   `json:"h_m"`
	HBits  *string    `json:"h_f64_bits_hex"`
	Theta  *float64   `json:"theta_rad"`
	TBits  *string    `json:"theta_f64_bits_hex"`
	L2     *float64   `json:"cap_length2"`
	L2Bits *string    `json:"cap_length2_f64_bits_hex"`
	// Verdict is INSIDE, OUTSIDE or INDETERMINATE.
	Verdict string `json:"verdict"`
	Edge    bool   `json:"edge,omitempty"`
	// MinMargin is the smallest |√d² − ℓ| over the descent's distance
	// decisions (informative); null when no distance decided anything.
	MinMargin *float64 `json:"min_margin_chord"`
}

// hInput is h as the device reports it: nil when missing.
type hInput struct {
	v *float64
}

func hOf(v float64) hInput { return hInput{&v} }

var hMissing = hInput{}

// cellsetVerdictOf runs the descent. It returns the verdict, θ and ℓ² (nil when
// the input alone makes it INDETERMINATE), and the smallest chord margin over
// every distance that could decide a touch: cells not containing leaf(P), with
// ℓ > 0 (with ℓ = 0, d < 0 never holds whatever the rounding).
func cellsetVerdictOf(set []s2.CellID, p s2.Point, h hInput) (string, *float64, *float64, *float64) {
	if h.v == nil || math.IsNaN(*h.v) || math.IsInf(*h.v, 0) || *h.v < 0 {
		return "INDETERMINATE", nil, nil, nil
	}
	theta := verdictK * *h.v / verdictR
	if !(theta < math.Pi) {
		return "INDETERMINATE", &theta, nil, nil
	}
	l2 := float64(s1.ChordAngleFromAngle(s1.Angle(theta)))
	ell := math.Sqrt(l2)
	cu := s2.CellUnion(set)
	leafP := s2.CellFromPoint(p).ID()
	deepest := 0
	for _, c := range set {
		deepest = max(deepest, c.Level())
	}
	in, out := false, false
	var minMargin *float64
	var visit func(x s2.CellID)
	visit = func(x s2.CellID) {
		containsLeaf := x.Contains(leafP)
		d := float64(s2.CellFromCellID(x).Distance(p))
		if !containsLeaf && l2 > 0 {
			m := math.Abs(math.Sqrt(d) - ell)
			if minMargin == nil || m < *minMargin {
				minMargin = &m
			}
		}
		if !(containsLeaf || d < l2) {
			return
		}
		if cu.ContainsCellID(x) {
			in = true
			return
		}
		if !cu.IntersectsCellID(x) {
			out = true
			return
		}
		if x.Level() >= deepest {
			panic(fmt.Sprintf("descent below the deepest level at %s", x.ToToken()))
		}
		ch := x.Children()
		for _, c := range ch {
			visit(c)
		}
	}
	for f := 0; f < 6; f++ {
		visit(s2.CellIDFromFace(f))
	}
	v := "INDETERMINATE"
	switch {
	case !out:
		v = "INSIDE"
	case !in:
		v = "OUTSIDE"
	}
	return v, &theta, &l2, minMargin
}

func fptr(v float64) *float64 { return &v }
func sptr(s string) *string   { return &s }

func mkVerdict(name string, set []s2.CellID, lat, lon float64, h hInput) cellsetVerdict {
	if !isCanonical(set) {
		panic(name + ": set is not canonical")
	}
	p := s2.PointFromLatLng(s2.LatLngFromDegrees(lat, lon))
	return mkVerdictAt(name, set, [2]float64{lat, lon}, p, h)
}

func mkVerdictAt(name string, set []s2.CellID, ll [2]float64, p s2.Point, h hInput) cellsetVerdict {
	v, theta, l2, margin := cellsetVerdictOf(set, p, h)
	c := cellsetVerdict{
		Name: name, Cells: hxs(set), Point: ll,
		XYZ:     [3]string{bitsOf(p.X), bitsOf(p.Y), bitsOf(p.Z)},
		Verdict: v, MinMargin: margin,
	}
	if h.v != nil {
		c.HBits = sptr(bitsOf(*h.v))
		if !math.IsNaN(*h.v) && !math.IsInf(*h.v, 0) {
			c.H = fptr(*h.v)
		}
	}
	if theta != nil {
		c.Theta, c.TBits = theta, sptr(bitsOf(*theta))
	}
	if l2 != nil {
		c.L2, c.L2Bits = l2, sptr(bitsOf(*l2))
	}
	c.Edge = margin != nil && *margin <= edgeMarginCh
	return c
}

// hForChord is the h whose cap has chord length ell: θ = 2·asin(ell/2), h = θ·R/K.
func hForChord(ell float64) float64 {
	return 2 * math.Asin(ell/2) * verdictR / verdictK
}

func latLonOf(p s2.Point) (float64, float64) {
	ll := s2.LatLngFromPoint(p)
	return ll.Lat.Degrees(), ll.Lng.Degrees()
}

// nudge moves p towards axis by eps and renormalises.
func nudge(p s2.Point, axis s2.Point, eps float64) s2.Point {
	return s2.Point{Vector: p.Add(axis.Mul(eps)).Normalize()}
}

func verdictVectors(london s2.CellID) []cellsetVerdict {
	var vs []cellsetVerdict
	add := func(c cellsetVerdict) { vs = append(vs, c) }
	at := func(name string, set []s2.CellID, p s2.Point, h hInput) {
		lat, lon := latLonOf(p)
		add(mkVerdictAt(name, set, [2]float64{lat, lon}, p, h))
	}

	p12 := london.Parent(12)
	ch12 := p12.Children()
	centre := func(id s2.CellID) s2.Point { return s2.CellFromCellID(id).Center() }

	// Inside one coarse cell, far from its edges (a level-12 cell is ~2 km).
	at("coarse_cell_centre_h50", []s2.CellID{p12}, centre(p12), hOf(50))
	at("coarse_cell_centre_h0", []s2.CellID{p12}, centre(p12), hOf(0))
	at("coarse_cell_centre_h2000_straddles", []s2.CellID{p12}, centre(p12), hOf(2000))
	at("coarse_cell_centre_small_set_elsewhere", []s2.CellID{london.Parent(20)}, centre(p12), hOf(50))

	// Straddling an edge between a set cell and a non-set cell: P 1 m inside
	// ch12[0]'s boundary, caps below and above that distance.
	{
		set := []s2.CellID{ch12[0]}
		cell := s2.CellFromCellID(ch12[0])
		c := centre(ch12[0])
		// Walk from the centre towards vertex 0 until 1 m from the boundary.
		v0 := cell.Vertex(0)
		lo, hi := 0.0, 1.0
		var p s2.Point
		for i := 0; i < 200; i++ {
			mid := (lo + hi) / 2
			p = s2.Point{Vector: c.Mul(1 - mid).Add(v0.Mul(mid)).Normalize()}
			b := math.Sqrt(float64(cell.BoundaryDistance(p)))
			if b > 1.0/verdictR {
				lo = mid
			} else {
				hi = mid
			}
		}
		b := math.Sqrt(float64(cell.BoundaryDistance(p)))
		at("near_edge_inside_small_cap", set, p, hOf(hForChord(b)/4))
		at("near_edge_straddles", set, p, hOf(hForChord(b)*4))

		// Touching the edge exactly, from inside: the cap's chord equals the
		// distance to the boundary (edge), and 1e-9 (about 6 mm) either side.
		at("touch_from_inside_exact", set, p, hOf(hForChord(b)))
		at("touch_from_inside_short", set, p, hOf(hForChord(b-1e-9)))
		at("touch_from_inside_over", set, p, hOf(hForChord(b+1e-9)))

		// From outside: P mirrored across the nearest edge region, in a
		// neighbour; distance to ch12[0] as the cap.
		q := s2.Point{Vector: c.Mul(-0.02).Add(v0.Mul(1.02)).Normalize()}
		if cell.ContainsPoint(q) {
			panic("outside point is inside")
		}
		d := math.Sqrt(float64(cell.Distance(q)))
		at("touch_from_outside_exact", set, q, hOf(hForChord(d)))
		at("touch_from_outside_short", set, q, hOf(hForChord(d-1e-9)))
		at("touch_from_outside_over", set, q, hOf(hForChord(d+1e-9)))
	}

	// Across a face boundary (lon 45 on the equator joins faces 0 and 1).
	{
		p := s2.PointFromLatLng(s2.LatLngFromDegrees(0.001, 44.9999))
		own := s2.CellFromPoint(p).ID().Parent(10)
		other := s2.CellFromPoint(s2.PointFromLatLng(s2.LatLngFromDegrees(0.001, 45.0001))).ID().Parent(10)
		if own.Face() == other.Face() {
			panic("face boundary case on one face")
		}
		at("face_boundary_own_face_only", normalized([]s2.CellID{own}), p, hOf(10))
		at("face_boundary_cap_crosses", normalized([]s2.CellID{own}), p, hOf(50))
		at("face_boundary_both_faces", normalized([]s2.CellID{own, other}), p, hOf(50))
		at("face_boundary_other_face_only", normalized([]s2.CellID{other}), p, hOf(5))
	}

	// At a cube corner: (1,1,1)/√3 joins faces 0, 1 and 2.
	{
		corner := s2.Point{Vector: s2.Point{}.Vector}
		corner.X, corner.Y, corner.Z = 1, 1, 1
		corner = s2.Point{Vector: corner.Normalize()}
		var three []s2.CellID
		for _, axis := range []s2.Point{{Vector: s2.PointFromCoords(1, 0, 0).Vector}, {Vector: s2.PointFromCoords(0, 1, 0).Vector}, {Vector: s2.PointFromCoords(0, 0, 1).Vector}} {
			three = append(three, s2.CellFromPoint(nudge(corner, axis, 1e-9)).ID().Parent(8))
		}
		p := nudge(corner, s2.PointFromCoords(1, 0, 0), 1e-9)
		at("cube_corner_all_three_cells", normalized(three), p, hOf(100))
		at("cube_corner_two_cells", normalized(three[:2]), p, hOf(100))
		at("cube_corner_one_cell_h0", normalized(three[:1]), p, hOf(0))
	}

	// At a pole: the north pole is the centre of face 2 and a vertex of four
	// cells at every level.
	{
		pole := s2.PointFromCoords(0, 0, 1)
		// VertexNeighbors(10) on a level-11 cell gives the four level-10 cells
		// around its vertex nearest the pole, which is the pole itself.
		four := s2.CellFromPoint(pole).ID().Parent(11).VertexNeighbors(10)
		at("north_pole_four_cells", normalized(four), pole, hOf(100))
		at("north_pole_one_cell", normalized(four[:1]), pole, hOf(100))
		at("north_pole_h0_leaf_cell", normalized([]s2.CellID{s2.CellFromPoint(pole).ID().Parent(10)}), pole, hOf(0))
		sp := s2.PointFromCoords(0, 0, -1)
		at("south_pole_face5", []s2.CellID{s2.CellIDFromFace(5)}, sp, hOf(1000))
	}

	// Mixed levels, with the cap reaching into a finer neighbour.
	{
		region := []s2.CellID{ch12[0], ch12[1].Children()[2], ch12[3]}
		fine := ch12[1].Children()[2]
		at("mixed_fine_member_small_cap", region, centre(fine), hOf(20))
		at("mixed_fine_member_reaches_gap", region, centre(fine), hOf(400))
		at("mixed_coarse_member_centre", region, centre(ch12[0]), hOf(50))
		// A gap: two members with a hole between them.
		gap := ch12[2]
		at("gap_centre_small_cap", region, centre(gap), hOf(20))
		at("gap_centre_reaches_members", region, centre(gap), hOf(1500))
		at("gap_far_outside", region, centre(p12.Parent(10).Children()[0].Children()[0]), hOf(50))
	}

	// h = 0 on a cell boundary: the answer is leaf(P) alone.
	{
		region := []s2.CellID{ch12[0], ch12[1].Children()[2], ch12[3]}
		for k := 0; k < 4; k++ {
			at(fmt.Sprintf("h0_vertex_%d_of_member", k), region, s2.CellFromCellID(ch12[0]).Vertex(k), hOf(0))
		}
	}

	// h missing, negative, not finite: INDETERMINATE.
	at("h_missing", []s2.CellID{p12}, centre(p12), hMissing)
	at("h_negative", []s2.CellID{p12}, centre(p12), hOf(-1))
	at("h_negative_zero", []s2.CellID{p12}, centre(p12), hOf(math.Copysign(0, -1)))
	at("h_nan", []s2.CellID{p12}, centre(p12), hOf(math.NaN()))
	at("h_infinite", []s2.CellID{p12}, centre(p12), hOf(math.Inf(1)))

	// A very large cap.
	{
		faces := []s2.CellID{s2.CellIDFromFace(0), s2.CellIDFromFace(1), s2.CellIDFromFace(2), s2.CellIDFromFace(3), s2.CellIDFromFace(4), s2.CellIDFromFace(5)}
		hNearPi := (math.Pi - 1e-6) * verdictR / verdictK
		at("large_cap_whole_sphere", faces, centre(p12), hOf(hNearPi))
		at("large_cap_one_face", faces[:1], centre(p12), hOf(hNearPi))
		at("large_cap_far_small_set_straddles", []s2.CellID{leafOf(-33.8688, 151.2093).Parent(12)}, centre(p12), hOf(hNearPi))
		at("cap_theta_at_least_pi", faces, centre(p12), hOf(math.Pi*verdictR/verdictK))
		at("cap_theta_above_pi", faces, centre(p12), hOf(2.1e7))
	}

	// Leaf cells smaller than the cap.
	{
		p := s2.PointFromLatLng(s2.LatLngFromDegrees(51.5074, -0.1278))
		l := s2.CellFromPoint(p).ID()
		nb := l.EdgeNeighbors()
		set := normalized([]s2.CellID{l, nb[0], nb[1]})
		at("leaf_cells_h1_straddles", set, p, hOf(1))
		at("leaf_cells_h0_inside", set, p, hOf(0))
		at("leaf_cells_h0_outside", normalized([]s2.CellID{nb[0]}), p, hOf(0))
		at("leaf_cells_far_h1_outside", normalized([]s2.CellID{l.Parent(20).EdgeNeighbors()[0].ChildBeginAtLevel(30)}), p, hOf(1))
	}

	// Random sets and caps.
	rng := rand.New(rand.NewSource(verdictSeed))
	for i := 0; i < randomVerdict; i++ {
		lat := math.Asin(2*rng.Float64()-1) * 180 / math.Pi
		lon := 360*rng.Float64() - 180
		p := s2.PointFromLatLng(s2.LatLngFromDegrees(lat, lon))
		base := s2.CellFromPoint(p).ID()
		var ids []s2.CellID
		lvl := 6 + rng.Intn(12)
		for _, n := range base.Parent(lvl).EdgeNeighbors() {
			if rng.Intn(2) == 0 {
				ids = append(ids, n.ChildBeginAtLevel(min(30, lvl+rng.Intn(4))))
			}
		}
		if rng.Intn(3) > 0 {
			ids = append(ids, base.Parent(lvl+rng.Intn(3)))
		}
		if len(ids) == 0 {
			ids = append(ids, base.Parent(lvl).EdgeNeighbors()[rng.Intn(4)])
		}
		set := normalized(ids)
		// A cap from 0 to about twice the level's cell size, mostly small.
		cellM := 1e7 / math.Exp2(float64(lvl))
		u := rng.Float64()
		h := math.Round(cellM*u*u*u*100) / 100
		if rng.Intn(8) == 0 {
			h = 0
		}
		add(mkVerdict(fmt.Sprintf("random_%02d", i), set, lat, lon, hOf(h)))
	}
	return vs
}

func leafOf(lat, lon float64) s2.CellID { return leaf(lat, lon) }
