//! The signed binding of `LocationProof.uncertainty` (field 20): the
//! `uncertaintyFields` stage hash is `SHA256(preimage)`, with
//!
//! ```text
//! "octet-uncertainty-binding-v1"
//! ‖ u32be(nominal_region case) ‖ u32be(32) ‖ region_digest
//! ‖ u32be(nominal_coverage_ppm)
//! ‖ u32be(has_vertical) [‖ f64be(center) ‖ f64be(below) ‖ f64be(above) ‖ u32be(coverage_ppm)]
//! ‖ u32be(len(profile)) ‖ profile
//! ‖ u32be(calibration_status)
//! ‖ u32be(has_risk) [‖ u32be(protection_failure_risk_ppm)]
//! ‖ i64be(estimate_timestamp_ms)
//! ```
//!
//! `region_digest` is SHA-256 over the region's numbers: an ellipse's centre
//! lat, lon, semi-major, semi-minor and heading (f64be); an H3 set's cell ids
//! sorted unsigned (u64be); a 3D box's min/max lat, lon, altitude (f64be). Any
//! other region type, and any value outside the rules below, has no preimage, so
//! the binding fails. The rules mirror the SDK's, which refuses to sign such a
//! value.

use crate::navigate::{proof_region::Region, LocationUncertainty, UncertaintyCalibrationStatus};
use sha2::{Digest, Sha256};

/// The `StageAttestation.stage` name that binds the uncertainty.
pub const UNCERTAINTY_FIELDS_STAGE: &str = "uncertaintyFields";
const DOMAIN: &[u8] = b"octet-uncertainty-binding-v1";
const PPM: u32 = 1_000_000;

fn need(ok: bool, what: &str) -> Result<(), String> {
    if ok {
        Ok(())
    } else {
        Err(what.to_string())
    }
}

/// The binding preimage, or why the value can't have been signed.
pub fn binding_preimage(u: &LocationUncertainty) -> Result<Vec<u8>, String> {
    let region = u
        .nominal_region
        .as_ref()
        .and_then(|r| r.region.as_ref())
        .ok_or("no nominal_region")?;
    need(u.nominal_coverage_ppm <= PPM, "nominal_coverage_ppm above 1,000,000")?;
    need(u.estimate_timestamp_ms >= 0, "negative estimate_timestamp_ms")?;
    let profile = &u.calibration_profile_sha256;
    need(profile.is_empty() || profile.len() == 32, "calibration_profile_sha256 is not 32 bytes")?;
    let risk = u.protection_failure_risk_ppm;
    match UncertaintyCalibrationStatus::try_from(u.calibration_status) {
        Ok(UncertaintyCalibrationStatus::UncertaintyUncalibrated) => {
            need(profile.is_empty(), "uncalibrated but carries a calibration profile")?;
            need(risk.is_none(), "uncalibrated but carries a protection failure risk")?;
        }
        Ok(UncertaintyCalibrationStatus::UncertaintyNominalCalibrated) => {
            need(profile.len() == 32, "nominal-calibrated without a calibration profile")?;
            need(u.nominal_coverage_ppm > 0, "nominal-calibrated with zero coverage")?;
            need(risk.is_none(), "nominal-calibrated but carries a protection failure risk")?;
        }
        Ok(UncertaintyCalibrationStatus::UncertaintyProtectionCalibrated) => {
            need(profile.len() == 32, "protection-calibrated without a calibration profile")?;
            need(u.nominal_coverage_ppm > 0, "protection-calibrated with zero coverage")?;
            need(risk.is_some(), "protection-calibrated without a protection failure risk")?;
        }
        _ => return Err("calibration_status is not usable".into()),
    }

    let (case, digest) = region_digest(region)?;
    let mut out = DOMAIN.to_vec();
    out.extend_from_slice(&case.to_be_bytes());
    out.extend_from_slice(&(digest.len() as u32).to_be_bytes());
    out.extend_from_slice(&digest);
    out.extend_from_slice(&u.nominal_coverage_ppm.to_be_bytes());
    match &u.vertical_interval {
        Some(v) => {
            need(v.center_altitude_meters.is_finite(), "vertical centre is not finite")?;
            need(v.below_meters.is_finite() && v.below_meters >= 0.0, "vertical below is negative or not finite")?;
            need(v.above_meters.is_finite() && v.above_meters >= 0.0, "vertical above is negative or not finite")?;
            need(v.coverage_ppm <= PPM, "vertical coverage_ppm above 1,000,000")?;
            out.extend_from_slice(&1u32.to_be_bytes());
            for x in [v.center_altitude_meters, v.below_meters, v.above_meters] {
                out.extend_from_slice(&x.to_be_bytes());
            }
            out.extend_from_slice(&v.coverage_ppm.to_be_bytes());
        }
        None => out.extend_from_slice(&0u32.to_be_bytes()),
    }
    out.extend_from_slice(&(profile.len() as u32).to_be_bytes());
    out.extend_from_slice(profile);
    out.extend_from_slice(&(u.calibration_status as u32).to_be_bytes());
    match risk {
        Some(r) => {
            need((1..=PPM).contains(&r), "protection_failure_risk_ppm outside 1..1,000,000")?;
            out.extend_from_slice(&1u32.to_be_bytes());
            out.extend_from_slice(&r.to_be_bytes());
        }
        None => out.extend_from_slice(&0u32.to_be_bytes()),
    }
    out.extend_from_slice(&u.estimate_timestamp_ms.to_be_bytes());
    Ok(out)
}

/// `(oneof case number, SHA-256 of the region's numbers)`.
fn region_digest(region: &Region) -> Result<(u32, Vec<u8>), String> {
    let mut h = Sha256::new();
    let case = match region {
        Region::Ellipse(e) => {
            let (lat, lon) = e.center.as_ref().map(|c| (c.latitude, c.longitude)).unwrap_or((0.0, 0.0));
            need(lat.is_finite() && (-90.0..=90.0).contains(&lat), "ellipse latitude out of range")?;
            need(lon.is_finite() && (-180.0..=180.0).contains(&lon), "ellipse longitude out of range")?;
            need(e.semi_major_m.is_finite() && e.semi_major_m > 0.0, "ellipse semi-major not positive")?;
            need(e.semi_minor_m.is_finite() && e.semi_minor_m > 0.0, "ellipse semi-minor not positive")?;
            need(e.semi_major_m >= e.semi_minor_m, "ellipse semi-major below semi-minor")?;
            need(
                e.heading_deg.is_finite() && (0.0..360.0).contains(&e.heading_deg),
                "ellipse heading outside [0, 360)",
            )?;
            for x in [lat, lon, e.semi_major_m, e.semi_minor_m, e.heading_deg] {
                h.update(x.to_be_bytes());
            }
            4
        }
        Region::H3PolygonSet(s) => {
            let mut ids = s.cell_ids.clone();
            need(!ids.is_empty() && ids.iter().all(|&c| c != 0), "H3 set empty or has a zero cell")?;
            ids.sort_unstable();
            need(ids.windows(2).all(|w| w[0] != w[1]), "H3 set has a duplicate cell")?;
            for c in ids {
                h.update(c.to_be_bytes());
            }
            5
        }
        Region::BoundingBox3d(b) => {
            for lat in [b.min_latitude, b.max_latitude] {
                need(lat.is_finite() && (-90.0..=90.0).contains(&lat), "box latitude out of range")?;
            }
            for lon in [b.min_longitude, b.max_longitude] {
                need(lon.is_finite() && (-180.0..=180.0).contains(&lon), "box longitude out of range")?;
            }
            need(b.min_altitude.is_finite() && b.max_altitude.is_finite(), "box altitude not finite")?;
            need(
                b.min_latitude <= b.max_latitude && b.min_longitude <= b.max_longitude && b.min_altitude <= b.max_altitude,
                "box min above max",
            )?;
            for x in [b.min_latitude, b.max_latitude, b.min_longitude, b.max_longitude, b.min_altitude, b.max_altitude] {
                h.update(x.to_be_bytes());
            }
            6
        }
        _ => return Err("nominal_region must be an ellipse, H3 set or 3D box".into()),
    };
    Ok((case, h.finalize().to_vec()))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::navigate::{EllipseRegion, LatLon, ProofRegion, VerticalUncertaintyInterval};

    /// The SDK's cross-platform golden: a protection-calibrated ellipse.
    pub(crate) fn golden() -> LocationUncertainty {
        LocationUncertainty {
            nominal_region: Some(ProofRegion {
                region: Some(Region::Ellipse(EllipseRegion {
                    center: Some(LatLon { latitude: 52.0, longitude: 13.0 }),
                    semi_major_m: 1.2,
                    semi_minor_m: 0.8,
                    heading_deg: 20.0,
                })),
            }),
            nominal_coverage_ppm: 950_000,
            vertical_interval: Some(VerticalUncertaintyInterval {
                center_altitude_meters: 42.0,
                below_meters: 2.0,
                above_meters: 3.0,
                coverage_ppm: 950_000,
            }),
            calibration_profile_sha256: (0u8..32).collect(),
            calibration_status: UncertaintyCalibrationStatus::UncertaintyProtectionCalibrated as i32,
            protection_failure_risk_ppm: Some(50_000),
            estimate_timestamp_ms: 1_234_567_890,
        }
    }

    #[test]
    fn matches_the_sdk_golden_preimage() {
        let want = concat!(
            "6f637465742d756e6365727461696e74792d62696e64696e672d7631",
            "00000004", "00000020",
            "1075c28ea5c0b960cc37af743d907be4192b9b82a983e23a8b5f2c79a36be7be",
            "000e7ef0", "00000001",
            "4045000000000000", "4000000000000000", "4008000000000000",
            "000e7ef0", "00000020",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "00000003", "00000001", "0000c350", "00000000499602d2",
        );
        assert_eq!(hex::encode(binding_preimage(&golden()).unwrap()), want);
    }

    #[test]
    fn values_the_sdk_refuses_to_sign_have_no_preimage() {
        let mut u = golden();
        u.protection_failure_risk_ppm = None;
        assert!(binding_preimage(&u).is_err());
        let mut u = golden();
        u.calibration_status = UncertaintyCalibrationStatus::UncertaintyCalibrationUnspecified as i32;
        assert!(binding_preimage(&u).is_err());
        let mut u = golden();
        u.nominal_coverage_ppm = PPM + 1;
        assert!(binding_preimage(&u).is_err());
        let mut u = golden();
        u.nominal_region = Some(ProofRegion { region: Some(Region::Earth(Default::default())) });
        assert!(binding_preimage(&u).is_err());
        let mut u = golden();
        u.calibration_status = UncertaintyCalibrationStatus::UncertaintyUncalibrated as i32;
        assert!(binding_preimage(&u).is_err(), "uncalibrated with a profile and a risk");
        u.calibration_profile_sha256.clear();
        u.protection_failure_risk_ppm = None;
        assert!(binding_preimage(&u).is_ok());
    }
}
