//! Country coverings from the policy engine, checked as S2 cell sets (tag 8).
//!
//! `test-vectors/s2-coverings/coverings.json` is the engine's file, copied
//! unchanged. Its coverings come from the reference Go S2 coverer, so each full
//! list must pass this verifier's canonical-form check as it is and hash to the
//! recorded digest. A digest-only covering is too large for a proof and travels
//! as a `query_region` digest.

use octet_verify::s2;
use serde_json::Value;

fn doc() -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/test-vectors/s2-coverings/coverings.json");
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn cells(c: &Value) -> Option<Vec<u64>> {
    let list = c.get("cells_hex")?.as_array().unwrap();
    Some(list.iter().map(|h| u64::from_str_radix(h.as_str().unwrap(), 16).unwrap()).collect())
}

#[test]
fn the_file_uses_this_verifiers_digest_and_cap() {
    let d = doc();
    assert_eq!(d["cellset_domain"].as_str().unwrap().as_bytes(), s2::CELL_SET_DOMAIN);
    assert_eq!(d["max_entries"].as_u64().unwrap() as usize, s2::MAX_CELL_SET_ENTRIES);
    assert!(d["geodata_version"].as_str().unwrap().starts_with("sha256:"));
}

#[test]
fn full_coverings_are_canonical_and_match_their_digests() {
    let d = doc();
    let coverings = d["coverings"].as_array().unwrap();
    assert!(coverings.iter().any(|c| c.get("cells_hex").is_some()), "need at least one full list");
    assert!(coverings.iter().any(|c| c.get("cells_hex").is_none()), "need at least one digest-only covering");
    for c in coverings {
        let name = c["name"].as_str().unwrap();
        let count = c["count"].as_u64().unwrap() as usize;
        assert_eq!(c["exceeds_max_entries"].as_bool().unwrap(), count > s2::MAX_CELL_SET_ENTRIES, "{name}");
        let Some(ids) = cells(c) else { continue };
        assert_eq!(ids.len(), count, "{name}: count");
        s2::check_canonical(&ids).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(hex::encode(s2::cell_set_digest(&ids)), c["digest_hex"].as_str().unwrap(), "{name}: digest");
    }
}

/// The inner covering lies inside the outer one, and a few landmarks fall
/// where they should at level 10 (about 10 km cells).
#[test]
fn gb_inner_lies_inside_outer() {
    let d = doc();
    let get = |name: &str| {
        let c = d["coverings"].as_array().unwrap().iter().find(|c| c["name"] == name).unwrap();
        cells(c).unwrap()
    };
    let (inner, outer) = (get("GB_L10_inner"), get("GB_L10_outer"));
    assert!(inner.iter().all(|&c| s2::cell_set_contains_leaf(&outer, s2::range_min(c))
        && s2::cell_set_contains_leaf(&outer, s2::range_max(c))));
    for (place, lat, lon, in_inner, in_outer) in [
        ("london", 51.5074, -0.1278, true, true),
        ("belfast", 54.5973, -5.9301, false, true),
        ("paris", 48.8566, 2.3522, false, false),
        ("dublin", 53.3498, -6.2603, false, false),
    ] {
        let leaf = s2::leaf_from_lat_lng(lat, lon).unwrap();
        assert_eq!(s2::cell_set_contains_leaf(&inner, leaf), in_inner, "{place} inner");
        assert_eq!(s2::cell_set_contains_leaf(&outer, leaf), in_outer, "{place} outer");
    }
}
