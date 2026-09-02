//! Shipped fixtures must not disclose a precise capture position.
//!
//! Every `test-vectors/**/*.bin` is published to the public mirror and to
//! crates.io. A real-device capture carries whatever the device measured, and a
//! region's geometry is NOT covered by the v1 semantic preimage (the verifier
//! reports it as `region GEOMETRY is NOT covered`), so those coordinates are
//! unsigned, unverifiable, and load-bearing for nothing — while still pointing
//! at wherever the phone actually was, to whatever precision the device fixed.
//!
//! A byte-level scan cannot catch this, because it cannot decode a protobuf.
//! This test is the layer that can, so it is deliberately feature-independent:
//! it runs in the default build, and therefore in CI.
//!
//! Coarsen a new fixture rather than relaxing this test. One decimal place of
//! latitude/longitude is ~11 km, which is well inside the radius any of our
//! fixtures claim, so nothing about a fixture's purpose needs finer than that.

use octet_verify::navigate::{proof_region::Region, LocationProof};
use octet_verify::prost::Message;
use std::path::{Path, PathBuf};

/// Max decimal places allowed on a shipped latitude/longitude. 1 dp is ~11 km.
const MAX_DECIMAL_PLACES: u32 = 1;

fn bin_fixtures(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("test-vectors/ is readable").flatten() {
        let path = entry.path();
        if path.is_dir() {
            bin_fixtures(&path, out);
        } else if path.extension().is_some_and(|e| e == "bin") {
            out.push(path);
        }
    }
}

/// True when `v` survives a round-trip through `MAX_DECIMAL_PLACES`, i.e. it
/// carries no finer precision than we allow.
fn is_coarse(v: f64) -> bool {
    let scale = 10f64.powi(MAX_DECIMAL_PLACES as i32);
    (v - (v * scale).round() / scale).abs() < 1e-9
}

/// The offending value is deliberately NOT in the message. A failing run writes
/// this to a CI log, and on the public mirror those logs are public, so printing
/// the coordinate would leak the very position the test exists to keep out.
/// (CodeQL's `rust/cleartext-logging` flagged exactly that, correctly.) The file
/// and field name are enough to find it locally.
fn check(label: &str, fixture: &Path, v: f64) {
    assert!(
        is_coarse(v),
        "{}: {label} carries more than {MAX_DECIMAL_PLACES} decimal place(s), so it \
         discloses a real capture position; shipped fixtures are limited to ~{:.0} km \
         granularity. Round it to {MAX_DECIMAL_PLACES} decimal place(s) instead of \
         relaxing this test — region geometry is not covered by the signed preimage, so \
         rewriting it breaks no signature. The value is not printed here on purpose: a \
         CI log is public.",
        fixture.display(),
        111.32 / 10f64.powi(MAX_DECIMAL_PLACES as i32),
    );
}

#[test]
fn shipped_fixtures_disclose_no_precise_position() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("test-vectors");
    let mut fixtures = Vec::new();
    bin_fixtures(&root, &mut fixtures);
    fixtures.sort();
    assert!(!fixtures.is_empty(), "found no .bin fixtures — did the walk break?");

    for f in &fixtures {
        let bytes = std::fs::read(f).expect("fixture is readable");
        let proof = LocationProof::decode(&*bytes)
            .unwrap_or_else(|e| panic!("{}: does not decode as LocationProof: {e}", f.display()));

        let Some(region) = proof.claimed_region.and_then(|r| r.region) else { continue };
        match region {
            // Coarse by construction: an ISO code, or an altitude ceiling.
            Region::Country(_) | Region::Subdivision(_) | Region::Earth(_) => {}
            Region::City(c) => {
                check("city.center_lat", f, c.center_lat);
                check("city.center_lon", f, c.center_lon);
            }
            Region::Ellipse(e) => {
                if let Some(c) = e.center {
                    check("ellipse.center.lat", f, c.latitude);
                    check("ellipse.center.lon", f, c.longitude);
                }
            }
            Region::BoundingBox3d(b) => {
                check("bbox.min_latitude", f, b.min_latitude);
                check("bbox.max_latitude", f, b.max_latitude);
                check("bbox.min_longitude", f, b.min_longitude);
                check("bbox.max_longitude", f, b.max_longitude);
            }
            // No fixture uses h3 yet. Resolution 15 is ~1 m across, so an h3
            // fixture would need its own precision rule; fail loudly rather
            // than wave it through.
            Region::H3PolygonSet(_) => panic!(
                "{}: h3 region in a shipped fixture — extend this guard with an h3 \
                 resolution bound before shipping it",
                f.display()
            ),
        }
    }

    eprintln!("checked {} shipped .bin fixtures", fixtures.len());
}
