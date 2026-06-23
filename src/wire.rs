//! Wire-format guard: reject duplicate occurrences of non-repeated (`singular`)
//! fields at the top level of a serialized `LocationProof`.
//!
//! proto3 (and prost) silently keep the **last** value when a non-repeated
//! scalar/message field appears more than once on the wire. An attacker can
//! append a second copy of, say, `timestamp_ms` so that prost — and therefore
//! this verifier — sees one value while a different parser, or a human reading
//! the first copy, sees another. That parser-differential is a field-smuggling
//! surface. We refuse any proof that carries a duplicate of a field the schema
//! declares non-repeated.
//!
//! Scope is the **top level** of `LocationProof`. The only legitimately-repeated
//! field there is `stage_attestations` (10); every other known field number is
//! singular. Unknown field numbers are deliberately left alone — proto3
//! forward-compat permits them and we cannot assert their cardinality. Nested
//! messages are not recursed (a documented limit, not an oversight): the fields
//! this verifier actually reads to reach a verdict live at the top level.

/// `LocationProof` field numbers the schema declares **non-repeated**. A second
/// occurrence of any of these on the wire is a smuggling attempt. (Field 10,
/// `stage_attestations`, is `repeated` and intentionally absent; reserved 9/14/15
/// are absent — an unknown/reserved number is not flagged here.)
const SINGULAR_FIELDS: &[u32] = &[1, 2, 3, 4, 5, 6, 7, 8, 11, 12, 13, 16];

/// Human name for a singular `LocationProof` field, for a clear rejection.
pub fn field_name(n: u32) -> &'static str {
    match n {
        1 => "id",
        2 => "claimed_region",
        3 => "level",
        4 => "zk_proof",
        5 => "position_commitment",
        6 => "nullifier",
        7 => "timestamp_ms",
        8 => "device_attestation",
        11 => "spoofing_verdict",
        12 => "sdk_version",
        13 => "platform",
        16 => "previous_token_hash",
        _ => "?",
    }
}

/// Read a base-128 varint, advancing `pos`. `None` on truncation or a varint
/// longer than 64 bits (both impossible in bytes prost already decoded; we still
/// fail safe rather than panic).
fn read_varint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let mut result = 0u64;
    let mut shift = 0u32;
    loop {
        let b = *buf.get(*pos)?;
        *pos += 1;
        result |= u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Some(result);
        }
        shift += 7;
        if shift >= 64 {
            return None;
        }
    }
}

/// Skip one field's payload given its wire type, advancing `pos`. Returns `false`
/// if the payload is truncated or the wire type is one we don't walk (groups).
fn skip_payload(buf: &[u8], pos: &mut usize, wire_type: u8) -> bool {
    match wire_type {
        0 => read_varint(buf, pos).is_some(), // varint
        1 => advance(buf, pos, 8),            // 64-bit
        5 => advance(buf, pos, 4),            // 32-bit
        2 => match read_varint(buf, pos) {
            // length-delimited
            Some(len) => advance(buf, pos, len as usize),
            None => false,
        },
        _ => false, // 3/4 = deprecated groups, or invalid — stop the scan
    }
}

fn advance(buf: &[u8], pos: &mut usize, n: usize) -> bool {
    match pos.checked_add(n) {
        Some(end) if end <= buf.len() => {
            *pos = end;
            true
        }
        _ => false,
    }
}

/// Return the singular `LocationProof` field numbers that appear more than once
/// at the top level of `proof_bytes`, sorted ascending. Empty ⇒ clean.
///
/// A malformed/truncated wire stops the scan early and returns what was found so
/// far; the function never panics. (The caller has already `decode`d these bytes
/// with prost, so a well-formed proof walks to completion.)
pub fn duplicate_singular_fields(proof_bytes: &[u8]) -> Vec<u32> {
    use std::collections::HashMap;
    let mut counts: HashMap<u32, u32> = HashMap::new();
    let mut pos = 0usize;
    while pos < proof_bytes.len() {
        let Some(tag) = read_varint(proof_bytes, &mut pos) else { break };
        let field = (tag >> 3) as u32;
        let wire_type = (tag & 0x7) as u8;
        if field == 0 {
            break; // field number 0 is invalid
        }
        *counts.entry(field).or_insert(0) += 1;
        if !skip_payload(proof_bytes, &mut pos, wire_type) {
            break;
        }
    }
    let mut dups: Vec<u32> = SINGULAR_FIELDS
        .iter()
        .copied()
        .filter(|f| counts.get(f).copied().unwrap_or(0) > 1)
        .collect();
    dups.sort_unstable();
    dups
}

#[cfg(test)]
mod tests {
    use super::*;

    // Wire encoding helpers (field<<3 | wire_type, then payload).
    // tag for a varint field n: n<<3 | 0; for length-delimited: n<<3 | 2.

    /// timestamp_ms (field 7, varint) twice = smuggling → flagged. This is the
    /// headline C22 vector: prost keeps the last value while an earlier parser
    /// sees the first.
    #[test]
    fn flags_duplicate_singular_varint_field() {
        let bytes = vec![0x38, 0x01, 0x38, 0x02]; // field 7 = 1, field 7 = 2
        assert_eq!(duplicate_singular_fields(&bytes), vec![7]);
    }

    /// stage_attestations (field 10, length-delimited) is `repeated` — appearing
    /// many times is normal and must NOT be flagged, or every real proof breaks.
    #[test]
    fn allows_legitimately_repeated_field() {
        let bytes = vec![0x52, 0x00, 0x52, 0x00]; // two empty field-10 entries
        assert!(duplicate_singular_fields(&bytes).is_empty());
    }

    /// A well-formed single-occurrence proof is clean.
    #[test]
    fn clean_proof_has_no_duplicates() {
        // field 7 (varint) once + field 13 (platform, len-delim "ios") once.
        let bytes = vec![0x38, 0x01, 0x6A, 0x03, b'i', b'o', b's'];
        assert!(duplicate_singular_fields(&bytes).is_empty());
    }

    /// Unknown field numbers have unknowable cardinality (proto3 forward-compat),
    /// so a duplicated *unknown* field is left alone — we only reject duplicates
    /// of fields the schema declares singular.
    #[test]
    fn ignores_duplicate_unknown_field() {
        // field 20 (unknown), varint, twice. tag = 20<<3 = 160 → varint 0xA0 0x01.
        let bytes = vec![0xA0, 0x01, 0x05, 0xA0, 0x01, 0x06];
        assert!(duplicate_singular_fields(&bytes).is_empty());
    }

    /// Two distinct singular fields each duplicated → both reported, sorted.
    #[test]
    fn reports_multiple_duplicated_singular_fields_sorted() {
        // field 13 (platform) ×2, field 7 (timestamp_ms) ×2, interleaved.
        let bytes = vec![
            0x6A, 0x01, b'a', // field 13
            0x38, 0x01, // field 7
            0x6A, 0x01, b'b', // field 13 again
            0x38, 0x02, // field 7 again
        ];
        assert_eq!(duplicate_singular_fields(&bytes), vec![7, 13]);
    }

    /// A truncated length-delimited payload stops the scan without panicking.
    #[test]
    fn truncated_wire_does_not_panic() {
        let bytes = vec![0x6A, 0x05, b'i', b'o']; // claims len 5, only 2 bytes
        let _ = duplicate_singular_fields(&bytes); // must not panic
    }
}
