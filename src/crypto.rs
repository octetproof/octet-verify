//! Cryptographic primitives used by the verifier.
//!
//! Only standard, public algorithms appear here: ECDSA over NIST P-256 with
//! SHA-256, Ed25519, and SHA-256. There is nothing secret in this file — the
//! security of a proof rests on the device's private keys, which never leave
//! the device and are never needed to *verify*.

use anyhow::{anyhow, bail, Context, Result};
use sha2::{Digest, Sha256};

pub use ed25519_dalek::VerifyingKey as Ed25519VerifyingKey;
pub use p256::ecdsa::VerifyingKey as P256VerifyingKey;

use ed25519_dalek::Signature as Ed25519Signature;
use p256::ecdsa::{signature::Verifier as _, Signature as P256Signature};

/// SHA-256 digest of `data`.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// How a platform encodes its ECDSA signatures on the wire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SigEncoding {
    /// ASN.1 DER — Android Keystore (`Signature.getInstance("SHA256withECDSA")`).
    Der,
    /// Raw 64-byte `r || s` — iOS CryptoKit (`P256.Signing`).
    Raw,
}

impl SigEncoding {
    /// Choose the encoding from `LocationProof.platform`. An unknown platform
    /// is an error, never a silent default — the caller surfaces it.
    pub fn for_platform(platform: &str) -> Result<Self> {
        match platform {
            "android" => Ok(SigEncoding::Der),
            "ios" => Ok(SigEncoding::Raw),
            other => Err(anyhow!(
                "unknown platform {other:?}; cannot choose an ECDSA signature encoding"
            )),
        }
    }
}

/// Verify an ECDSA-P256-SHA256 signature over `msg`.
///
/// `msg` is the raw signing input; SHA-256 prehashing is applied internally,
/// matching how both SDKs sign (`SHA256withECDSA` on Android, CryptoKit's
/// `signature(for:)` on iOS). Returns `Ok(())` only for a valid signature.
pub fn p256_verify(vk: &P256VerifyingKey, msg: &[u8], sig: &[u8], enc: SigEncoding) -> Result<()> {
    let signature = match enc {
        SigEncoding::Der => {
            P256Signature::from_der(sig).context("malformed DER ECDSA signature")?
        }
        SigEncoding::Raw => {
            if sig.len() != 64 {
                bail!("raw ECDSA signature must be 64 bytes, got {}", sig.len());
            }
            P256Signature::from_slice(sig).context("malformed raw ECDSA signature")?
        }
    };
    // Accept either S parity. `(r, s)` and `(r, n - s)` are both valid ECDSA
    // signatures; some platforms emit the non-normalized (high-S) form — notably
    // Android's Keystore / SunEC `SHA256withECDSA`, whereas iOS CryptoKit emits
    // low-S. Normalizing to low-S before verifying makes us accept both, as a
    // verifier should. (Found via a real Android golden vector.)
    let signature = signature.normalize_s().unwrap_or(signature);
    vk.verify(msg, &signature)
        .map_err(|_| anyhow!("ECDSA-P256 signature did not verify"))
}

/// Re-encode `sig` with its `S` value normalized to the low (canonical) half of
/// the curve order, in the same wire encoding it came in.
///
/// ECDSA admits two valid signatures per message — `(r, s)` and `(r, n - s)` —
/// so an attacker can mint a byte-distinct *twin* of a genuine signature that
/// still verifies. Verification accepts both (Android Keystore legitimately
/// emits high-S; see [`p256_verify`]), but any byte-identity heuristic (e.g. the
/// refetch-consistency / seen-store proof hash) must canonicalize first so a
/// twin can't pose as fresh bytes. Returns the input unchanged if it does not
/// parse as `enc` — canonicalization is a best-effort hashing aid, never a gate.
pub fn canonical_sig(sig: &[u8], enc: SigEncoding) -> Vec<u8> {
    let parsed = match enc {
        SigEncoding::Der => P256Signature::from_der(sig).ok(),
        SigEncoding::Raw => {
            if sig.len() == 64 {
                P256Signature::from_slice(sig).ok()
            } else {
                None
            }
        }
    };
    match parsed {
        Some(s) => {
            let n = s.normalize_s().unwrap_or(s);
            match enc {
                SigEncoding::Der => n.to_der().as_bytes().to_vec(),
                SigEncoding::Raw => n.to_bytes().to_vec(),
            }
        }
        None => sig.to_vec(),
    }
}

/// Verify an Ed25519 signature over `msg`.
pub fn ed25519_verify(vk: &Ed25519VerifyingKey, msg: &[u8], sig: &[u8]) -> Result<()> {
    let signature =
        Ed25519Signature::from_slice(sig).context("malformed Ed25519 signature (need 64 bytes)")?;
    vk.verify_strict(msg, &signature)
        .map_err(|_| anyhow!("Ed25519 signature did not verify"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_known_answer() {
        // SHA-256("abc") — FIPS 180-4 example.
        let got = sha256(b"abc");
        let want =
            hex_lit("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(got.as_slice(), want.as_slice());
    }

    #[test]
    fn unknown_platform_is_error() {
        assert!(SigEncoding::for_platform("symbian").is_err());
        assert_eq!(SigEncoding::for_platform("android").unwrap(), SigEncoding::Der);
        assert_eq!(SigEncoding::for_platform("ios").unwrap(), SigEncoding::Raw);
    }

    /// The whole point of canonicalization: an ECDSA S-malleated twin —
    /// byte-distinct but equally valid — must collapse to the *same* canonical
    /// bytes, so it can't slip past a byte-hash dedup. (Android emits high-S, so
    /// we can't simply reject it; we canonicalize the hash instead.)
    #[test]
    fn canonical_sig_collapses_high_s_twin() {
        use p256::ecdsa::{signature::Signer, Signature, SigningKey};

        let sk = SigningKey::from_slice(&[3u8; 32]).unwrap();
        let sig: Signature = sk.sign(b"malleability"); // canonical low-S
        // Build the (r, n - s) twin.
        let twin = Signature::from_scalars(sig.r(), -sig.s()).unwrap();
        assert_ne!(sig.to_bytes(), twin.to_bytes(), "twin must be byte-distinct");

        let a = canonical_sig(&sig.to_bytes(), SigEncoding::Raw);
        let b = canonical_sig(&twin.to_bytes(), SigEncoding::Raw);
        assert_eq!(a, b, "high-S twin must canonicalize to the low-S form");
    }

    fn hex_lit(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }
}
