//! Independent verifier for Octet `LocationProof` artifacts.
//!
//! This crate decodes a proof from its protobuf wire bytes and checks that it
//! is **authentic and untampered** — the hardware-key stage-attestation chain
//! and device-attestation envelope signature, the optional Ed25519 transport
//! signature, freshness, replay, and the region the proof claims.
//!
//! It deliberately knows **nothing** about how a proof is produced: no
//! spoof-detection heuristics, no signal weights, no verdict thresholds. The
//! verdict baked into a proof is trusted as a signed value; this verifier
//! confirms the signatures over it, not the judgement behind it. That boundary
//! is what lets the crate be published without leaking proof-creation IP.
//!
//! The exact byte-layouts of every signature input are documented in
//! `VERIFICATION-SPEC.md`, which is the public contract this code implements.
//!
//! # Modules
//! - [`navigate`] / [`attest`] — generated wire types (mirror of `proto/`).
//! - [`crypto`] — ECDSA-P256 / Ed25519 / SHA-256 primitives.
//! - [`keys`] — sourcing the hardware and Ed25519 public keys.
//! - [`verify`] — the verification recipe and its report.

pub mod navigate {
    //! Proof wire types emitted by the Octet SDK on-device (upstream proto
    //! package `octet.proof`). The module keeps the `navigate` name for
    //! source-compat; the wire schema it mirrors is the public proof contract.
    include!(concat!(env!("OUT_DIR"), "/octet.proof.rs"));
}

pub mod attest {
    //! Continuous-proof transport envelope.
    include!(concat!(env!("OUT_DIR"), "/octet.attest.rs"));
}

pub mod crypto;
pub mod keys;
pub mod verify;
pub mod wire;

/// Offline Apple App Attest verification, via the shared `octet-attest-verify`
/// crate. Compiled only with `--features appattest`.
#[cfg(feature = "appattest")]
pub mod appattest_layer;

/// Transport client for the (untrusted) Octet proof ingestion API.
///
/// Compiled only with `--features net`. This module fetches *bytes* and routing
/// metadata; it performs no validation. Fetched proof bytes are handed to
/// [`verify`] exactly as a local file's bytes would be — see VERIFICATION-SPEC.md
/// "Backend fetch mode" for the trust model.
#[cfg(feature = "net")]
pub mod backend;

// Re-export prost so downstream code can encode/decode without pinning a
// matching prost version of its own.
pub use prost;
