//! S2 regions: the `cell_set` (proof region tag 8) and the 3D `voxel_set`
//! (tag 9).
//!
//! A cell set is a union of S2 cells (<https://s2geometry.io>) at mixed levels.
//! On the wire it must be **canonical**: exactly its own S2 normalisation
//! (sorted ascending, pairwise disjoint, no 4 sibling cells left unmerged), so
//! one region has exactly one encoding and one digest. The verifier rejects a
//! non-canonical set; it never normalises one silently.
//!
//! Only the small part of S2 the verifier needs is here: cell-id validity and
//! hierarchy, the point → leaf-cell mapping (the quadratic projection and the
//! Hilbert curve, ported from the reference implementation), the canonical-form
//! check, the digest, and containment, which is a binary search over leaf
//! ranges. `test-vectors/s2-region/` pins all of it against the reference Go
//! library.
//!
//! A voxel set adds height: each entry is a cell and an interval of WGS84
//! ellipsoidal height in Spatial ID bins (`f_zoom`, `f_min`, `f_max`). Its
//! canonical form is the maximal cells over which the height set is constant,
//! each with its maximal intervals at the coarsest zoom that writes them.

use crate::crypto;
use crate::navigate::S2Voxel;

/// Domain label of the tag 8 region digest.
pub const CELL_SET_DOMAIN: &[u8] = b"octet-region-cellset-v1";

/// Most entries a cell set may carry. Provisional, pending the engine's
/// measurements of real country coverings.
pub const MAX_CELL_SET_ENTRIES: usize = 16_384;

/// Deepest S2 level (leaf cells, about 1 cm).
pub const MAX_LEVEL: u32 = 30;

const POS_BITS: u32 = 2 * MAX_LEVEL + 1;
const MAX_SIZE: i64 = 1 << MAX_LEVEL;
const LOOKUP_BITS: u32 = 4;
const SWAP_MASK: usize = 0x01;
const INVERT_MASK: usize = 0x02;

fn lsb(id: u64) -> u64 {
    id & id.wrapping_neg()
}

/// Is `id` a valid S2 cell id: face 0–5 and the lowest set bit at an even
/// position (which also rules out 0)?
pub fn is_valid(id: u64) -> bool {
    (id >> POS_BITS) < 6 && lsb(id) & 0x1555_5555_5555_5555 != 0
}

/// Level of a valid cell id, 0 (a cube face) to 30 (a leaf).
pub fn level(id: u64) -> u32 {
    MAX_LEVEL - id.trailing_zeros() / 2
}

/// Smallest leaf id inside the cell.
pub fn range_min(id: u64) -> u64 {
    id - (lsb(id) - 1)
}

/// Largest leaf id inside the cell.
pub fn range_max(id: u64) -> u64 {
    id + (lsb(id) - 1)
}

/// Does cell `a` contain cell `b` (or equal it)?
pub fn contains(a: u64, b: u64) -> bool {
    range_min(a) <= b && b <= range_max(a)
}

/// The ancestor of `id` at `level` (which must not be deeper than `id`'s).
pub fn parent(id: u64, level: u32) -> u64 {
    let l = 1u64 << (2 * (MAX_LEVEL - level));
    (id & l.wrapping_neg()) | l
}

/// The 4 children of a non-leaf cell, in Hilbert order.
pub fn children(id: u64) -> [u64; 4] {
    let l = lsb(id);
    let step = l >> 1;
    let first = id - l + (l >> 2);
    [first, first + step, first + 2 * step, first + 3 * step]
}

/// The S2 token: the id in hex with trailing zeros stripped (`"X"` for 0).
pub fn token(id: u64) -> String {
    let s = format!("{id:016x}");
    let t = s.trim_end_matches('0');
    if t.is_empty() { "X".into() } else { t.into() }
}

// --- point → leaf cell ---

/// The Hilbert lookup table: 4 bits of i, 4 bits of j and 2 orientation bits →
/// 8 bits of curve position and 2 orientation bits.
fn lookup_pos() -> &'static [u16; 1 << (2 * LOOKUP_BITS + 2)] {
    static TABLE: std::sync::OnceLock<[u16; 1 << (2 * LOOKUP_BITS + 2)]> = std::sync::OnceLock::new();
    TABLE.get_or_init(|| {
        const POS_TO_IJ: [[usize; 4]; 4] = [[0, 1, 3, 2], [0, 2, 3, 1], [3, 2, 0, 1], [3, 1, 0, 2]];
        const POS_TO_ORIENTATION: [usize; 4] = [SWAP_MASK, 0, 0, INVERT_MASK | SWAP_MASK];
        fn fill(t: &mut [u16; 1024], level: u32, i: usize, j: usize, orig: usize, pos: usize, orient: usize) {
            if level == LOOKUP_BITS {
                let ij = (i << LOOKUP_BITS) + j;
                t[(ij << 2) + orig] = ((pos << 2) + orient) as u16;
                return;
            }
            let r = POS_TO_IJ[orient];
            for k in 0..4 {
                fill(t, level + 1, (i << 1) + (r[k] >> 1), (j << 1) + (r[k] & 1), orig, (pos << 2) + k,
                    orient ^ POS_TO_ORIENTATION[k]);
            }
        }
        let mut t = [0u16; 1024];
        for o in 0..4 {
            fill(&mut t, 0, 0, 0, o, 0, o);
        }
        t
    })
}

fn uv_to_st(u: f64) -> f64 {
    if u >= 0.0 { 0.5 * (1.0 + 3.0 * u).sqrt() } else { 1.0 - 0.5 * (1.0 - 3.0 * u).sqrt() }
}

fn st_to_ij(s: f64) -> i64 {
    ((MAX_SIZE as f64 * s).floor() as i64).clamp(0, MAX_SIZE - 1)
}

fn face_ij_to_leaf(face: usize, i: i64, j: i64) -> u64 {
    let table = lookup_pos();
    let mut n = (face as u64) << (POS_BITS - 1);
    let mut bits = face & SWAP_MASK;
    let mask = (1i64 << LOOKUP_BITS) - 1;
    for k in (0..8).rev() {
        bits += (((i >> (k * LOOKUP_BITS)) & mask) as usize) << (LOOKUP_BITS + 2);
        bits += (((j >> (k * LOOKUP_BITS)) & mask) as usize) << 2;
        bits = table[bits] as usize;
        n |= ((bits >> 2) as u64) << (k * 2 * LOOKUP_BITS);
        bits &= SWAP_MASK | INVERT_MASK;
    }
    n * 2 + 1
}

/// The leaf cell containing the point at `(lat, lon)` degrees, computed as the
/// reference implementation does. S2 cells are closed, so a point on a shared
/// edge goes to one deterministic side. `None` for a non-finite point.
///
/// `sin`/`cos` are not correctly rounded, and platforms differ by an ulp. The
/// pure-Rust `libm` gives this verifier the same answer on every target (CLI,
/// server, browser). Another implementation can still land a point within about
/// 1e-15 of a cell edge in the neighbouring leaf; for those points this
/// verifier's answer is the authoritative one. [`leaf_from_xyz`] is exact.
pub fn leaf_from_lat_lng(lat: f64, lon: f64) -> Option<u64> {
    if !lat.is_finite() || !lon.is_finite() {
        return None;
    }
    let (phi, theta) = (lat.to_radians(), lon.to_radians());
    let cos_phi = libm::cos(phi);
    leaf_from_xyz(libm::cos(theta) * cos_phi, libm::sin(theta) * cos_phi, libm::sin(phi))
}

/// The leaf cell containing the direction `(x, y, z)` (not necessarily unit
/// length). Only division, `sqrt` and `floor`, all exact in IEEE 754, so every
/// conforming implementation agrees bit for bit. `None` for a zero or
/// non-finite vector.
pub fn leaf_from_xyz(x: f64, y: f64, z: f64) -> Option<u64> {
    if !(x.is_finite() && y.is_finite() && z.is_finite()) || (x == 0.0 && y == 0.0 && z == 0.0) {
        return None;
    }
    // Face: the largest absolute component, ties broken as the reference does.
    let (ax, ay, az) = (x.abs(), y.abs(), z.abs());
    let axis = if ax > ay { if ax > az { 0 } else { 2 } } else if ay > az { 1 } else { 2 };
    let negative = [x, y, z][axis] < 0.0;
    let face = axis + if negative { 3 } else { 0 };
    let (u, v) = match face {
        0 => (y / x, z / x),
        1 => (-x / y, z / y),
        2 => (-x / z, -y / z),
        3 => (z / x, y / x),
        4 => (z / y, -x / y),
        _ => (-y / z, -x / z),
    };
    Some(face_ij_to_leaf(face, st_to_ij(uv_to_st(u)), st_to_ij(uv_to_st(v))))
}

// --- cell sets ---

/// Why a cell set is not canonical. `Err` from [`check_canonical`].
pub fn check_canonical(ids: &[u64]) -> Result<(), String> {
    if ids.is_empty() {
        return Err("the cell set is empty".into());
    }
    if ids.len() > MAX_CELL_SET_ENTRIES {
        return Err(format!("the cell set has {} entries, more than {MAX_CELL_SET_ENTRIES}", ids.len()));
    }
    for (k, &id) in ids.iter().enumerate() {
        if !is_valid(id) {
            return Err(format!("entry {k} ({id:016x}) is not a valid S2 cell id"));
        }
        if k == 0 {
            continue;
        }
        let prev = ids[k - 1];
        if range_max(prev) >= range_min(id) {
            return Err(format!(
                "entry {k} ({id:016x}) is out of order or overlaps entry {} ({prev:016x})",
                k - 1
            ));
        }
        if k >= 3 && are_siblings(&ids[k - 3..=k]) {
            return Err(format!("entries {}–{k} are the 4 children of one cell and must be merged into it", k - 3));
        }
    }
    Ok(())
}

/// Are these 4 cells (sorted, disjoint) the complete children of one parent?
fn are_siblings(four: &[u64]) -> bool {
    let l = level(four[0]);
    l > 0 && four.iter().all(|&c| level(c) == l && parent(c, l - 1) == parent(four[0], l - 1))
}

/// The S2 normalisation of a set of valid cell ids: sorted, with contained cells
/// dropped and complete groups of 4 siblings merged into their parent,
/// repeatedly. A canonical set is its own normalisation. For signers and tests;
/// the verifier only checks.
pub fn normalize(ids: &[u64]) -> Vec<u64> {
    let mut sorted = ids.to_vec();
    sorted.sort_unstable();
    let mut out: Vec<u64> = Vec::with_capacity(sorted.len());
    for mut id in sorted {
        if out.last().is_some_and(|&last| contains(last, id)) {
            continue;
        }
        while out.last().is_some_and(|&last| contains(id, last)) {
            out.pop();
        }
        while out.len() >= 3 && {
            let n = out.len();
            are_siblings(&[out[n - 3], out[n - 2], out[n - 1], id])
        } {
            out.truncate(out.len() - 3);
            id = parent(id, level(id) - 1);
        }
        out.push(id);
    }
    out
}

/// The tag 8 region digest: `SHA256("octet-region-cellset-v1" ‖ u32be(n) ‖
/// u64be(id)ⁿ)`, over the ids in wire (canonical) order.
pub fn cell_set_digest(ids: &[u64]) -> [u8; 32] {
    let mut m = Vec::with_capacity(CELL_SET_DOMAIN.len() + 4 + 8 * ids.len());
    m.extend_from_slice(CELL_SET_DOMAIN);
    m.extend_from_slice(&(ids.len() as u32).to_be_bytes());
    for id in ids {
        m.extend_from_slice(&id.to_be_bytes());
    }
    crypto::sha256(&m)
}

/// Does the canonical cell set `ids` contain the leaf cell `leaf`? A binary
/// search over the sorted, disjoint leaf ranges.
pub fn cell_set_contains_leaf(ids: &[u64], leaf: u64) -> bool {
    let k = ids.partition_point(|&c| range_max(c) < leaf);
    k < ids.len() && range_min(ids[k]) <= leaf
}

/// Height-bin index in the Spatial ID convention: `floor(h · 2^(zoom − 25))`
/// for an ellipsoidal height `h` in metres, `|h| < 2^25`. Exact in f64, because
/// scaling by a power of two is exact. `None` outside the range or for NaN.
pub fn f_index(h: f64, zoom: u32) -> Option<i64> {
    if h.is_nan() || h.abs() >= (1u64 << 25) as f64 {
        return None;
    }
    // 2^(zoom − 25) built from its exponent bits, so the scaling is exact.
    let scale = f64::from_bits(((1023 + zoom as i64 - 25) as u64) << 52);
    Some((h * scale).floor() as i64)
}

// --- voxel sets (tag 9) ---

/// Domain label of the tag 9 region digest.
pub const VOXEL_SET_DOMAIN: &[u8] = b"octet-region-voxelset-v1";

/// Finest height zoom: bins of 2^(25 − 32) m, about 8 mm.
pub const MAX_F_ZOOM: u32 = 32;

/// The whole height range `[-2^25, 2^25)` m, in zoom-32 bins.
const ALL_HEIGHTS: (i64, i64) = (-(1 << 32), 1 << 32);

/// Lower bound of an entry's height interval in zoom-32 bins,
/// `f_min · 2^(32 − f_zoom)`. Defined by multiplication so every language
/// computes the same value for a negative `f_min`. The entry must be in bounds.
pub fn voxel_lo(v: &S2Voxel) -> i64 {
    v.f_min * (1i64 << (MAX_F_ZOOM - v.f_zoom))
}

/// Exclusive upper bound in zoom-32 bins, `(f_max + 1) · 2^(32 − f_zoom)`.
pub fn voxel_hi(v: &S2Voxel) -> i64 {
    (v.f_max + 1) * (1i64 << (MAX_F_ZOOM - v.f_zoom))
}

/// `0 ≤ f_zoom ≤ 32` and `−2^f_zoom ≤ f_min ≤ f_max ≤ 2^f_zoom − 1`.
fn voxel_bounds_ok(v: &S2Voxel) -> bool {
    if v.f_zoom > MAX_F_ZOOM {
        return false;
    }
    let n = 1i64 << v.f_zoom;
    -n <= v.f_min && v.f_min <= v.f_max && v.f_max < n
}

fn is_full_height(v: &S2Voxel) -> bool {
    (voxel_lo(v), voxel_hi(v)) == ALL_HEIGHTS
}

/// `(f_zoom, f_min, f_max)`, the part of an entry compared between siblings.
fn heights(v: &S2Voxel) -> (u32, i64, i64) {
    (v.f_zoom, v.f_min, v.f_max)
}

/// Why a voxel set is not canonical. `Err` from [`check_voxel_canonical`].
///
/// Canonical means: non-empty and at most [`MAX_CELL_SET_ENTRIES`] entries;
/// every cell valid and every interval in bounds and at its coarsest zoom;
/// sorted by `(cell_id, lo)`; one cell's intervals neither overlap nor touch;
/// distinct cells disjoint; no 4 siblings with identical interval lists; and at
/// least one entry bounded in height (a set covering all heights is a tag 8
/// cell set).
pub fn check_voxel_canonical(vs: &[S2Voxel]) -> Result<(), String> {
    if vs.is_empty() {
        return Err("the voxel set is empty".into());
    }
    if vs.len() > MAX_CELL_SET_ENTRIES {
        return Err(format!("the voxel set has {} entries, more than {MAX_CELL_SET_ENTRIES}", vs.len()));
    }
    for (k, v) in vs.iter().enumerate() {
        if !is_valid(v.cell_id) {
            return Err(format!("entry {k} ({:016x}) is not a valid S2 cell id", v.cell_id));
        }
        if !voxel_bounds_ok(v) {
            return Err(format!(
                "entry {k} has f_zoom {}, f_min {}, f_max {}: out of bounds",
                v.f_zoom, v.f_min, v.f_max
            ));
        }
        if v.f_zoom > 0 && v.f_min & 1 == 0 && v.f_max & 1 == 1 {
            return Err(format!("entry {k} is not at its coarsest zoom (f_zoom {} can be reduced)", v.f_zoom));
        }
        if k == 0 {
            continue;
        }
        let prev = &vs[k - 1];
        if prev.cell_id == v.cell_id {
            if voxel_lo(v) <= voxel_hi(prev) {
                return Err(format!(
                    "entry {k} is out of order with, overlaps or touches entry {} in cell {:016x}",
                    k - 1,
                    v.cell_id
                ));
            }
        } else if range_max(prev.cell_id) >= range_min(v.cell_id) {
            return Err(format!(
                "entry {k} ({:016x}) is out of order or overlaps entry {} ({:016x})",
                v.cell_id,
                k - 1,
                prev.cell_id
            ));
        }
    }
    let groups: Vec<&[S2Voxel]> = vs.chunk_by(|a, b| a.cell_id == b.cell_id).collect();
    for (k, four) in groups.windows(4).enumerate() {
        let cells = [four[0][0].cell_id, four[1][0].cell_id, four[2][0].cell_id, four[3][0].cell_id];
        let same = four[1..].iter().all(|g| g.iter().map(heights).eq(four[0].iter().map(heights)));
        if same && are_siblings(&cells) {
            return Err(format!(
                "cells {k}–{} are the 4 children of one cell with identical heights and must be merged into it",
                k + 3
            ));
        }
    }
    if vs.iter().all(is_full_height) {
        return Err("every entry covers all heights; send the region as a cell set (tag 8)".into());
    }
    Ok(())
}

/// Sorted, merged intervals in zoom-32 bins: overlapping or touching ones join.
fn merge_intervals(mut ivs: Vec<(i64, i64)>) -> Vec<(i64, i64)> {
    ivs.sort_unstable();
    let mut out: Vec<(i64, i64)> = Vec::with_capacity(ivs.len());
    for (lo, hi) in ivs {
        match out.last_mut() {
            Some(last) if lo <= last.1 => last.1 = last.1.max(hi),
            _ => out.push((lo, hi)),
        }
    }
    out
}

/// `[lo, hi)` in zoom-32 bins as one entry at the coarsest zoom that writes it.
fn voxel_from_interval(cell_id: u64, lo: i64, hi: i64) -> S2Voxel {
    let mut z = MAX_F_ZOOM;
    while z > 0 {
        let b = 1i64 << (MAX_F_ZOOM - z + 1);
        if lo % b != 0 || hi % b != 0 {
            break;
        }
        z -= 1;
    }
    let b = 1i64 << (MAX_F_ZOOM - z);
    S2Voxel { cell_id, f_zoom: z, f_min: lo / b, f_max: hi / b - 1 }
}

/// Split `cell` around the listed cells strictly inside it (`inner`, sorted by
/// `(range_min, larger first)`), pushing disjoint cells with their full height
/// sets to `out` in cell-id order.
fn refine(cell: u64, heights: Vec<(i64, i64)>, inner: &[(u64, Vec<(i64, i64)>)], out: &mut Vec<(u64, Vec<(i64, i64)>)>) {
    if inner.is_empty() {
        out.push((cell, heights));
        return;
    }
    for child in children(cell) {
        let s = inner.partition_point(|d| range_min(d.0) < range_min(child));
        let e = inner.partition_point(|d| range_min(d.0) <= range_max(child));
        let sub = &inner[s..e];
        match sub.first() {
            None => out.push((child, heights.clone())),
            Some(first) if first.0 == child => {
                let joined = merge_intervals(heights.iter().chain(&first.1).copied().collect());
                refine(child, joined, &sub[1..], out);
            }
            Some(_) => refine(child, heights.clone(), sub, out),
        }
    }
}

/// The canonical spelling of the region a list of entries covers: the maximal
/// cells over which the height set is constant, each with its maximal
/// intervals at their coarsest zoom. `Err` for an empty list or an invalid
/// entry. The cap and the all-heights rule are not applied: if every entry of
/// the result covers all heights, the region is the tag 8 cell set of its
/// cells. For signers and tests; the verifier only checks.
pub fn normalize_voxels(vs: &[S2Voxel]) -> Result<Vec<S2Voxel>, String> {
    if vs.is_empty() {
        return Err("the voxel set is empty".into());
    }
    if let Some(k) = vs.iter().position(|v| !is_valid(v.cell_id) || !voxel_bounds_ok(v)) {
        return Err(format!("entry {k} is not a valid cell and height interval"));
    }
    // One entry per listed cell, ancestors before their descendants.
    let mut sorted: Vec<&S2Voxel> = vs.iter().collect();
    sorted.sort_unstable_by_key(|v| (range_min(v.cell_id), std::cmp::Reverse(range_max(v.cell_id))));
    let cells: Vec<(u64, Vec<(i64, i64)>)> = sorted
        .chunk_by(|a, b| a.cell_id == b.cell_id)
        .map(|g| (g[0].cell_id, merge_intervals(g.iter().map(|v| (voxel_lo(v), voxel_hi(v))).collect())))
        .collect();
    let mut parts = Vec::new();
    let mut k = 0;
    while k < cells.len() {
        let top = cells[k].0;
        let end = k + 1 + cells[k + 1..].partition_point(|d| range_min(d.0) <= range_max(top));
        refine(top, cells[k].1.clone(), &cells[k + 1..end], &mut parts);
        k = end;
    }
    let mut merged: Vec<(u64, Vec<(i64, i64)>)> = Vec::with_capacity(parts.len());
    for (mut id, ivs) in parts {
        while merged.len() >= 3 && {
            let n = merged.len();
            are_siblings(&[merged[n - 3].0, merged[n - 2].0, merged[n - 1].0, id])
                && merged[n - 3..].iter().all(|m| m.1 == ivs)
        } {
            merged.truncate(merged.len() - 3);
            id = parent(id, level(id) - 1);
        }
        merged.push((id, ivs));
    }
    Ok(merged
        .into_iter()
        .flat_map(|(id, ivs)| ivs.into_iter().map(move |(lo, hi)| voxel_from_interval(id, lo, hi)))
        .collect())
}

/// The tag 9 region digest: `SHA256("octet-region-voxelset-v1" ‖ u32be(n) ‖
/// {u64be(cell_id) ‖ u32be(f_zoom) ‖ i64be(f_min) ‖ i64be(f_max)}ⁿ)`, over the
/// entries in wire (canonical) order.
pub fn voxel_set_digest(vs: &[S2Voxel]) -> [u8; 32] {
    let mut m = Vec::with_capacity(VOXEL_SET_DOMAIN.len() + 4 + 28 * vs.len());
    m.extend_from_slice(VOXEL_SET_DOMAIN);
    m.extend_from_slice(&(vs.len() as u32).to_be_bytes());
    for v in vs {
        m.extend_from_slice(&v.cell_id.to_be_bytes());
        m.extend_from_slice(&v.f_zoom.to_be_bytes());
        m.extend_from_slice(&v.f_min.to_be_bytes());
        m.extend_from_slice(&v.f_max.to_be_bytes());
    }
    crypto::sha256(&m)
}

/// Does the canonical voxel set contain the leaf cell `leaf` at ellipsoidal
/// height `h` metres? Finds the one cell holding the leaf by binary search, then
/// checks `h`'s bin at each of its entries' zooms. `None` when `h` is NaN or
/// `|h| ≥ 2^25`.
pub fn voxel_set_contains(vs: &[S2Voxel], leaf: u64, h: f64) -> Option<bool> {
    f_index(h, 0)?;
    let k = vs.partition_point(|v| range_max(v.cell_id) < leaf);
    if k == vs.len() || range_min(vs[k].cell_id) > leaf {
        return Some(false);
    }
    let cell = vs[k].cell_id;
    Some(vs[k..].iter().take_while(|v| v.cell_id == cell).any(|v| {
        let f = f_index(h, v.f_zoom).expect("h checked above");
        v.f_min <= f && f <= v.f_max
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn faces_are_valid_and_level_zero() {
        for f in 0..6u64 {
            let id = (f << POS_BITS) + (1 << 60);
            assert!(is_valid(id));
            assert_eq!(level(id), 0);
        }
        assert!(!is_valid(0));
        assert!(!is_valid(u64::MAX));
    }

    /// Normalising never changes which (leaf, height) points are covered, and
    /// always yields a canonical set. Random nested cells and overlapping
    /// intervals at mixed zooms, probed at random leaves and heights.
    #[test]
    fn normalize_voxels_preserves_the_region() {
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        let mut rnd = |n: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % n
        };
        let top = parent(leaf_from_lat_lng(51.5074, -0.1278).unwrap(), 10);
        for _ in 0..200 {
            let mut vs = Vec::new();
            for _ in 0..1 + rnd(8) {
                let mut c = top;
                for _ in 0..rnd(5) {
                    c = children(c)[rnd(4) as usize];
                }
                let z = rnd(33) as u32;
                let n = 1i64 << z;
                let f_min = (rnd(2 * n as u64) as i64) - n;
                let f_max = (f_min + rnd(5) as i64).min(n - 1);
                vs.push(S2Voxel { cell_id: c, f_zoom: z, f_min, f_max });
            }
            let norm = normalize_voxels(&vs).unwrap();
            if !norm.iter().all(is_full_height) {
                check_voxel_canonical(&norm).unwrap();
            }
            assert_eq!(normalize_voxels(&norm).unwrap(), norm);
            let covers = |set: &[S2Voxel], leaf: u64, h: f64| {
                set.iter().any(|v| {
                    let f = f_index(h, v.f_zoom).unwrap();
                    contains(v.cell_id, leaf) && v.f_min <= f && f <= v.f_max
                })
            };
            for _ in 0..50 {
                let leaf = range_min(top) + 2 * rnd((range_max(top) - range_min(top)) / 2);
                // Heights near the entries' bounds, where an off-by-one shows.
                let v = &vs[rnd(vs.len() as u64) as usize];
                let b = f64::from_bits(((1023 + 25 - v.f_zoom as i64) as u64) << 52);
                let edge = if rnd(2) == 0 { v.f_min } else { v.f_max + 1 } as f64 * b;
                let h = (edge + (rnd(5) as f64 - 2.0) * b / 4.0).clamp(-33_554_431.0, 33_554_431.0);
                assert_eq!(covers(&norm, leaf, h), covers(&vs, leaf, h), "{vs:?} at {leaf:016x}, {h}");
                if !norm.iter().all(is_full_height) {
                    assert_eq!(voxel_set_contains(&norm, leaf, h), Some(covers(&vs, leaf, h)));
                }
            }
        }
    }

    #[test]
    fn normalize_merges_cascading_siblings() {
        let leaf = leaf_from_lat_lng(51.5074, -0.1278).unwrap();
        let p = parent(leaf, 12);
        let c = children(p);
        let g = children(c[0]);
        let input = [g[3], c[2], g[0], c[1], g[1], c[3], g[2]];
        assert_eq!(normalize(&input), vec![p]);
        assert!(check_canonical(&input).is_err());
        assert!(check_canonical(&[p]).is_ok());
    }
}
