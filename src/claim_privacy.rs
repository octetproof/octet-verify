//! Claim privacy: does a city, disc or box claim disclose the device's position?
//!
//! From SDK 4.0.0 these claims are built on a fixed lat/lon grid with step
//! `2^-L` degrees, never centred on the device. The snapped form is recognised
//! from the claim alone, with no position and no data file:
//!
//! - **city**: `name == "auto"`, `radius_meters == 50000`, and the centre is a
//!   level-2 cell centre (`4·lat − 0.5` and `4·lon − 0.5` are integers in range);
//! - **disc** (`EllipseRegion`): equal axes, `heading_deg` bit-equal to `+0.0`,
//!   exactly one level `L` in 3…12 whose cell centre the centre is, and
//!   `R − ρ_L` on the accuracy ladder;
//! - **box** (`BoundingBox3DRegion`): the four horizontal bounds are multiples of
//!   `2^-12`° and both altitude bounds are multiples of 64 m.
//!
//! Anything else of those three kinds is **legacy**: an authentic proof from an
//! earlier SDK whose claim is centred on the device. Country, subdivision, earth,
//! H3 and S2 claims are not centred on the device and are not classified.
//!
//! The classification is about disclosure, not authenticity: the claim's geometry
//! is covered by the semantic binding, so editing a legacy claim into snapped form
//! breaks that binding instead.

use crate::navigate::{proof_region::Region, BoundingBox3DRegion, CityRegion, EllipseRegion, ProofRegion};

/// The pinned tables, shared with the SDK's vectors.
pub(crate) mod tables {
    /// `ρ_L`: the largest distance from a level-`L` cell centre to any point in
    /// the cell, rounded up to whole metres plus 1 m, for `L` = 2…12. A pinned
    /// table, never recomputed, so every implementation agrees on the bytes.
    pub const RHO_M: [(u32, f64); 11] = [
        (2, 19_658.0),
        (3, 9_830.0),
        (4, 4_916.0),
        (5, 2_459.0),
        (6, 1_230.0),
        (7, 616.0),
        (8, 309.0),
        (9, 155.0),
        (10, 78.0),
        (11, 40.0),
        (12, 21.0),
    ];

    /// The accuracy buckets, in metres.
    pub const LADDER_M: [f64; 13] = [
        10.0, 20.0, 50.0, 100.0, 200.0, 500.0, 1_000.0, 2_000.0, 5_000.0, 10_000.0, 20_000.0, 50_000.0, 100_000.0,
    ];
}
use tables::{LADDER_M, RHO_M};

const CITY_LEVEL: u32 = 2;
const CITY_RADIUS_M: f64 = 50_000.0;
const CITY_NAME: &str = "auto";
const DISC_LEVELS: std::ops::RangeInclusive<u32> = 3..=12;
const BOX_LEVEL: i32 = 12;
const VERTICAL_STEP_M: f64 = 64.0;

/// How a claim discloses the device's position.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClaimPrivacy {
    /// Built on the grid: discloses the grid cell, not the position. For a disc,
    /// the grid level it was snapped to.
    Snapped { grid_level: Option<u32> },
    /// Centred on the device (SDK before 4.0.0): the claim discloses the position.
    Legacy,
    /// Not a city, disc or box claim, so not centred on the device.
    NotApplicable,
}

impl ClaimPrivacy {
    /// `SNAPPED`, `LEGACY` or `NOT_APPLICABLE`, as in the shared vectors.
    pub fn label(self) -> &'static str {
        match self {
            ClaimPrivacy::Snapped { .. } => "SNAPPED",
            ClaimPrivacy::Legacy => "LEGACY",
            ClaimPrivacy::NotApplicable => "NOT_APPLICABLE",
        }
    }
}

/// Classify a claimed region. `None` (no region) is not applicable.
pub fn classify(region: Option<&ProofRegion>) -> ClaimPrivacy {
    match region.and_then(|r| r.region.as_ref()) {
        Some(Region::City(c)) => snapped_or_legacy(city_snapped(c)),
        Some(Region::Ellipse(e)) => match disc_level(e) {
            Some(l) => ClaimPrivacy::Snapped { grid_level: Some(l) },
            None => ClaimPrivacy::Legacy,
        },
        Some(Region::BoundingBox3d(b)) => snapped_or_legacy(box_snapped(b)),
        _ => ClaimPrivacy::NotApplicable,
    }
}

fn snapped_or_legacy(snapped: bool) -> ClaimPrivacy {
    if snapped {
        ClaimPrivacy::Snapped { grid_level: None }
    } else {
        ClaimPrivacy::Legacy
    }
}

/// Is `x` a level-`level` cell centre, `(i + 0.5) / 2^level` with `i` in
/// `[−half·2^level, half·2^level − 1]`? Scaling by a power of two and
/// subtracting 0.5 are exact for every in-range value, so this is a test on the
/// exact bits, never a tolerance.
fn is_cell_centre(x: f64, level: u32, half_range_deg: f64) -> bool {
    let n = f64::from(1u32 << level);
    let t = x * n - 0.5;
    t.is_finite() && t == t.floor() && t >= -half_range_deg * n && t <= half_range_deg * n - 1.0
}

fn city_snapped(c: &CityRegion) -> bool {
    c.name == CITY_NAME
        && c.radius_meters == CITY_RADIUS_M
        && is_cell_centre(c.center_lat, CITY_LEVEL, 90.0)
        && is_cell_centre(c.center_lon, CITY_LEVEL, 180.0)
}

/// The grid level of a snapped disc, or `None` when the disc is legacy.
fn disc_level(e: &EllipseRegion) -> Option<u32> {
    let centre = e.center.as_ref()?;
    if e.semi_major_m != e.semi_minor_m || e.heading_deg.to_bits() != 0.0f64.to_bits() {
        return None;
    }
    let mut levels = DISC_LEVELS
        .filter(|&l| is_cell_centre(centre.latitude, l, 90.0) && is_cell_centre(centre.longitude, l, 180.0));
    let level = levels.next()?;
    if levels.next().is_some() {
        return None; // can't happen for a cell centre; refuse rather than guess
    }
    let rho = RHO_M.iter().find(|(l, _)| *l == level)?.1;
    let bucket = e.semi_major_m - rho;
    LADDER_M.contains(&bucket).then_some(level)
}

fn box_snapped(b: &BoundingBox3DRegion) -> bool {
    let on_grid = |x: f64| {
        let t = x * 2f64.powi(BOX_LEVEL);
        t.is_finite() && t == t.floor()
    };
    let on_step = |z: f64| {
        let t = z / VERTICAL_STEP_M;
        t.is_finite() && t == t.floor()
    };
    [b.min_latitude, b.max_latitude, b.min_longitude, b.max_longitude].into_iter().all(on_grid)
        && on_step(b.min_altitude)
        && on_step(b.max_altitude)
}

/// Does field 20's `nominal_region` disclose the device position? From SDK
/// 4.0.0 it is an ellipse with no centre (axes and heading only): the claim
/// says where, field 20 only the shape of the uncertainty. A centre, any other
/// shape, or no region at all counts as disclosing (or invalid).
pub fn nominal_region_discloses(region: Option<&ProofRegion>) -> bool {
    !matches!(region.and_then(|r| r.region.as_ref()), Some(Region::Ellipse(e)) if e.center.is_none())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::navigate::LatLon;

    fn disc(lat: f64, lon: f64, r: f64) -> ProofRegion {
        ProofRegion {
            region: Some(Region::Ellipse(EllipseRegion {
                center: Some(LatLon { latitude: lat, longitude: lon }),
                semi_major_m: r,
                semi_minor_m: r,
                heading_deg: 0.0,
            })),
        }
    }

    /// The pinned ρ table matches the spec's closed form,
    /// `ceil(2·R_E·asin(√2·sin(s_L/4))) + 1`, for every level.
    #[test]
    fn rho_table_matches_the_closed_form() {
        for (l, rho) in RHO_M {
            let s = (2f64.powi(-(l as i32))).to_radians();
            let want = (2.0 * 6_371_000.0 * (2f64.sqrt() * (s / 4.0).sin()).asin()).ceil() + 1.0;
            assert_eq!(rho, want, "level {l}");
        }
    }

    /// A negative-zero heading, a missing centre, a centre outside the grid's
    /// range, and a non-finite radius are all legacy.
    #[test]
    fn edge_cases_are_legacy() {
        let mut r = disc(12.34521484375, 23.45654296875, 128.0);
        assert_eq!(classify(Some(&r)), ClaimPrivacy::Snapped { grid_level: Some(10) });
        if let Some(Region::Ellipse(e)) = r.region.as_mut() {
            e.heading_deg = -0.0;
        }
        assert_eq!(classify(Some(&r)), ClaimPrivacy::Legacy, "-0.0 heading");
        let none = ProofRegion {
            region: Some(Region::Ellipse(EllipseRegion { center: None, semi_major_m: 128.0, semi_minor_m: 128.0, heading_deg: 0.0 })),
        };
        assert_eq!(classify(Some(&none)), ClaimPrivacy::Legacy, "no centre");
        // (90 + 2^-11): a level-10 centre one row above the top of the grid.
        assert_eq!(classify(Some(&disc(90.00048828125, 0.00048828125, 128.0))), ClaimPrivacy::Legacy, "beyond the pole");
        assert_eq!(classify(Some(&disc(12.34521484375, 23.45654296875, f64::INFINITY))), ClaimPrivacy::Legacy);
        assert_eq!(classify(None), ClaimPrivacy::NotApplicable);
    }
}
