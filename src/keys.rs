//! Sourcing the public keys a proof is verified against.
//!
//! Two keys matter:
//!   * the hardware attestation key (EC P-256) that signs the stage chain and
//!     the device-attestation envelope, and
//!   * the device signer key (Ed25519) that signs the transport envelope.
//!
//! Neither is secret. The hardware key arrives either inside the proof (the
//! Android certificate chain) or out-of-band from the device's enrollment
//! bundle (iOS, which carries no certificate chain in the current wire format).
//! This module never handles private keys.

use anyhow::{anyhow, Context, Result};
use std::path::Path;

use crate::crypto::{Ed25519VerifyingKey, P256VerifyingKey};

/// Extract the hardware P-256 public key from `certificate_chain[0]`.
///
/// The two platforms populate this field differently:
///   * iOS stores the Secure-Enclave public key directly as a raw SEC1 point.
///   * Android stores an X.509 certificate chain (leaf → … → Google root); the
///     leaf's SubjectPublicKeyInfo carries the P-256 key.
/// So we try to read the bytes as a raw SEC1 point first, then fall back to
/// pulling the point out of the certificate's SubjectPublicKeyInfo.
///
/// v1 reads only this key; it does **not** validate the Android chain up to
/// Google's hardware-attestation root, nor an iOS App Attest object. The
/// certificate is parsed (structurally) solely to extract the leaf's
/// SubjectPublicKeyInfo — extraction only. Validating the chain up to a
/// hardware-attestation root is out of scope for v1. Callers must report
/// attestation-root validation as not performed so the assurance level is never
/// overstated.
pub fn hardware_pubkey_from_cert_chain(chain: &[Vec<u8>]) -> Result<P256VerifyingKey> {
    let leaf = chain
        .first()
        .ok_or_else(|| anyhow!("certificate_chain is empty"))?;
    // Fast path: iOS stores the Secure-Enclave key as a raw SEC1 point.
    if let Ok(vk) = P256VerifyingKey::from_sec1_bytes(leaf) {
        return Ok(vk);
    }
    // Certificate path (Android): parse the leaf and pull the key from its SPKI.
    if let Some(vk) = p256_key_from_cert(leaf) {
        return Ok(vk);
    }
    Err(anyhow!(
        "certificate_chain[0] is neither a raw SEC1 point nor a certificate with an \
         extractable P-256 key; pass --hardware-pubkey"
    ))
}

/// Extract the P-256 public key from a DER X.509 certificate's
/// SubjectPublicKeyInfo — properly parsed, not byte-scanned.
///
/// We assert the SPKI algorithm is `id-ecPublicKey` on the `prime256v1` named
/// curve, then take `subjectPublicKey` as the SEC1 point. Anything else (RSA,
/// Ed25519, other curves) returns `None`, even if a `03 42 00 04` byte sequence
/// happens to appear elsewhere in the certificate (e.g. inside an extension) —
/// a structural parse cannot be fooled by such a decoy the way a byte-scan can.
///
/// Scope: extraction only. This does NOT validate the certificate chain up to an
/// Apple/Google attestation root; chain validation is out of scope for v1.
fn p256_key_from_cert(der: &[u8]) -> Option<P256VerifyingKey> {
    use x509_cert::der::{oid::ObjectIdentifier, Decode};
    use x509_cert::Certificate;

    // X9.62 / SEC2 object identifiers.
    const ID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
    const PRIME256V1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");

    let cert = Certificate::from_der(der).ok()?;
    let spki = cert.tbs_certificate.subject_public_key_info;

    if spki.algorithm.oid != ID_EC_PUBLIC_KEY {
        return None;
    }
    // EC keys carry the named curve as the algorithm parameters.
    let curve: ObjectIdentifier = spki.algorithm.parameters?.decode_as().ok()?;
    if curve != PRIME256V1 {
        return None;
    }
    let point = spki.subject_public_key.as_bytes()?;
    P256VerifyingKey::from_sec1_bytes(point).ok()
}

/// Load a hardware P-256 public key from a file. Accepts either a raw SEC1
/// point (compressed 33 / uncompressed 65 bytes) or its hex encoding.
pub fn load_hardware_pubkey(path: &Path) -> Result<P256VerifyingKey> {
    let bytes = read_key_bytes(path)?;
    P256VerifyingKey::from_sec1_bytes(&bytes)
        .context("file is not a valid SEC1-encoded P-256 public key")
}

/// Load a device-signer Ed25519 public key from a file. Accepts either the raw
/// 32-byte key or its hex encoding.
pub fn load_ed25519_pubkey(path: &Path) -> Result<Ed25519VerifyingKey> {
    let bytes = read_key_bytes(path)?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("Ed25519 public key must be 32 bytes, got {}", bytes.len()))?;
    Ed25519VerifyingKey::from_bytes(&arr).context("not a valid Ed25519 public key")
}

/// Read a key file as raw bytes, transparently hex-decoding it when the whole
/// file is hex digits (plus surrounding whitespace).
fn read_key_bytes(path: &Path) -> Result<Vec<u8>> {
    let raw = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    if let Some(decoded) = try_decode_hex(&raw) {
        return Ok(decoded);
    }
    Ok(raw)
}

/// Decode `raw` as ASCII hex iff every non-whitespace byte is a hex digit and
/// the digit count is even. Returns `None` otherwise (treat as binary).
fn try_decode_hex(raw: &[u8]) -> Option<Vec<u8>> {
    let digits: Vec<u8> = raw
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    if digits.is_empty() || digits.len() % 2 != 0 || !digits.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    let mut out = Vec::with_capacity(digits.len() / 2);
    for pair in digits.chunks_exact(2) {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_roundtrip() {
        let decoded = try_decode_hex(b"04ab\nCD ef").unwrap();
        assert_eq!(decoded, vec![0x04, 0xab, 0xcd, 0xef]);
    }

    #[test]
    fn binary_with_high_bytes_is_not_hex() {
        // A raw SEC1 point starts with 0x04, which is not an ASCII hex digit.
        assert!(try_decode_hex(&[0x04, 0xde, 0xad]).is_none());
    }

    #[test]
    fn odd_hex_is_rejected() {
        assert!(try_decode_hex(b"abc").is_none());
    }

    use base64::Engine;

    // A real P-256 self-signed certificate (openssl) and its raw SEC1 point.
    const P256_CERT_B64: &str = "MIIBjTCCATOgAwIBAgIUUmrrHypvK5MliIkDfzBtSSIlc24wCgYIKoZIzj0EAwIwHDEaMBgGA1UEAwwRb2N0ZXQtdmVyaWZ5LXRlc3QwHhcNMjYwNjEwMTgxODU5WhcNMjYwNjExMTgxODU5WjAcMRowGAYDVQQDDBFvY3RldC12ZXJpZnktdGVzdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABMUrsLvgoS7C2WIVLXxrqv88u9A7cG9A1qSIeKN/DXOt1z61lKKL59Bvk6FyKrPE3eVjzPVQkh4kVDGBD+Omk0qjUzBRMB0GA1UdDgQWBBQv1un+9O/mvh24rEBxAN68yqn1XTAfBgNVHSMEGDAWgBQv1un+9O/mvh24rEBxAN68yqn1XTAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIQCdyPJ9t7q4A9akk/JB4MiPY0Co64WkJWesuaIZbZhr2gIgXgLDk68G/glculfO2eMtE9lDi7ifshCTKQ/6qMei/wU=";
    const P256_POINT_HEX: &str = "04c52bb0bbe0a12ec2d962152d7c6baaff3cbbd03b706f40d6a48878a37f0d73add73eb594a28be7d06f93a1722ab3c4dde563ccf550921e245431810fe3a6934a";
    // An Ed25519 self-signed certificate carrying a `03 42 00 04` + 64-byte
    // decoy inside a custom extension (the SPKI itself is Ed25519, not EC).
    const ED_DECOY_CERT_B64: &str = "MIIBUzCCAQWgAwIBAgIUA9RrifyS+R65B6RoxSWTTIl/A8swBQYDK2VwMBAxDjAMBgNVBAMMBWRlY295MB4XDTI2MDYxMDE4MTg1OVoXDTI2MDYxMTE4MTg1OVowEDEOMAwGA1UEAwwFZGVjb3kwKjAFBgMrZXADIQDWIv0WKji5ICsO0A02R7p7Xi90UBunocxgjQvC+lYd86NxMG8wTgYGKgMEBQYHBEQDQgAEAQIDBAUGBwgJCgsMDQ4PEBESExQVFhcYGRobHB0eHyAhIiMkJSYnKCkqKywtLi8wMTIzNDU2Nzg5Ojs8PT4/QDAdBgNVHQ4EFgQU2Z2ewWBun+MuNIZ0+e3g6c2XrLkwBQYDK2VwA0EAYw5QDwkuBNsBtO4oJZ7nuiu9rEH8XskXWWNI/v1EAYXL7LpkBU98N0de9mFzczUffTUhednt3IgM/IJXdLI2CQ==";

    fn b64(s: &str) -> Vec<u8> {
        base64::engine::general_purpose::STANDARD.decode(s).unwrap()
    }

    /// The structured parse extracts the key from the leaf's SPKI.
    #[test]
    fn extracts_p256_key_from_certificate_spki() {
        let cert = b64(P256_CERT_B64);
        let expected =
            P256VerifyingKey::from_sec1_bytes(&try_decode_hex(P256_POINT_HEX.as_bytes()).unwrap())
                .unwrap();
        assert!(
            p256_key_from_cert(&cert) == Some(expected),
            "must extract the SPKI key from a real P-256 certificate"
        );
        // And the chain entry point resolves it without --hardware-pubkey.
        assert!(hardware_pubkey_from_cert_chain(&[cert]).is_ok());
    }

    /// A `03 42 00 04` decoy in a (non-EC) certificate's extension must NOT be
    /// extracted — the old byte-scan would have returned the decoy bytes; the
    /// structured parse sees the SPKI is Ed25519 and returns `None`.
    #[test]
    fn decoy_point_in_extension_is_not_extracted() {
        let cert = b64(ED_DECOY_CERT_B64);
        // Sanity: the decoy pattern really is present in the certificate bytes.
        assert!(cert.windows(4).any(|w| w == [0x03, 0x42, 0x00, 0x04]));
        // ...yet nothing is extracted, because the real SPKI is not a P-256 key.
        assert!(p256_key_from_cert(&cert).is_none(), "decoy must not be extracted");
        assert!(hardware_pubkey_from_cert_chain(&[cert]).is_err());
    }

    /// The raw-SEC1 fast path (iOS Secure-Enclave case) still works.
    #[test]
    fn raw_sec1_point_fast_path() {
        let point = try_decode_hex(P256_POINT_HEX.as_bytes()).unwrap();
        assert!(hardware_pubkey_from_cert_chain(&[point]).is_ok());
    }
}
