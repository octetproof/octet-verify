//! Golden vectors that pin the **session-binding** preimage byte-for-byte across
//! the SDK (nonce producer) and this verifier (nonce checker).
//!
//! The contract, from `src/session.rs`:
//!
//! ```text
//! preimage    = "octet-session-binding-v1" ‖ uint32_be(len(nonce)) ‖ nonce
//! data_hash   = SHA256(preimage)          // the sessionBinding stage's data_hash
//! ```
//!
//! Each vector fixes `nonce -> data_hash`. The SDK mirrors the same table in its
//! own test suite, so a drift on either side of the framing (domain tag, the u32
//! length prefix, its endianness, or raw-vs-decoded nonce bytes) is caught in CI
//! on both repos rather than on-device.
//!
//! How the assertion pins the hash without exposing a private helper: we build a
//! proof whose `sessionBinding` stage carries `data_hash = <expected from file>`,
//! then ask the real `check_session_binding` to judge it against the vector's
//! nonce. A `Pass` means the verifier **independently recomputed the same 32
//! bytes** the file records — i.e. the verifier's preimage framing equals the
//! pinned value. A one-byte perturbation of the nonce must then `Fail`, proving
//! the binding is actually a function of the nonce and not trivially accepted.

use octet_verify::navigate::{LocationProof, StageAttestation};
use octet_verify::session::check_session_binding;
use octet_verify::verify::Status;

const VECTORS_JSON: &str = include_str!("../test-vectors/session-binding/vectors.json");

/// A proof carrying exactly one `sessionBinding` stage whose `data_hash` is the
/// supplied bytes. Everything else is default — this exercises only the binding
/// check, which looks the stage up by name and compares its `data_hash`.
fn proof_with_binding(data_hash: Vec<u8>) -> LocationProof {
    LocationProof {
        stage_attestations: vec![StageAttestation {
            stage: "sessionBinding".to_string(),
            timestamp_ms: 1,
            data_hash,
            signature: vec![],
            previous_hash: None,
        }],
        ..Default::default()
    }
}

#[test]
fn session_binding_golden_vectors() {
    let file: serde_json::Value =
        serde_json::from_str(VECTORS_JSON).expect("vectors.json parses");
    let vectors = file["vectors"]
        .as_array()
        .expect("vectors.json has a `vectors` array");
    assert!(
        !vectors.is_empty(),
        "session-binding vectors.json carries no vectors"
    );

    for v in vectors {
        let name = v["name"].as_str().expect("vector has a name");
        let nonce_hex = v["nonce_hex"].as_str().expect("vector has nonce_hex");
        let expected_hex = v["expected_data_hash"]
            .as_str()
            .expect("vector has expected_data_hash");

        let nonce = hex::decode(nonce_hex)
            .unwrap_or_else(|e| panic!("vector {name}: bad nonce_hex: {e}"));
        let expected = hex::decode(expected_hex)
            .unwrap_or_else(|e| panic!("vector {name}: bad expected_data_hash: {e}"));
        assert_eq!(
            expected.len(),
            32,
            "vector {name}: expected_data_hash must be 32 bytes (SHA-256)"
        );

        // POSITIVE: the verifier recomputes SHA256(preimage(nonce)) and it must
        // equal the file's expected_data_hash — otherwise this Fails, catching a
        // framing drift on the verifier side.
        let bound = proof_with_binding(expected.clone());
        let c = check_session_binding(&bound, Some(&nonce), true);
        assert_eq!(
            c.status,
            Status::Pass,
            "vector {name}: verifier's recomputed data_hash does not match the pinned \
             expected_data_hash ({expected_hex}) — {}",
            c.detail
        );

        // NEGATIVE: perturb the nonce by one byte; the pinned data_hash must no
        // longer match, proving the binding is a function of the nonce.
        let mut other = nonce.clone();
        match other.last_mut() {
            Some(b) => *b ^= 0x01,
            None => other.push(0x00), // empty nonce: any non-empty nonce differs
        }
        let c = check_session_binding(&bound, Some(&other), true);
        assert_eq!(
            c.status,
            Status::Fail,
            "vector {name}: a one-byte-different nonce still matched the pinned hash \
             (binding is not nonce-sensitive)"
        );
    }
}
