//! Public-key encoding helpers and software signature verification.
//!
//! Nothing in this module touches private or secret key material: it converts
//! signature encodings (PKCS#11 raw `r || s` ⇄ DER), builds
//! `SubjectPublicKeyInfo` structures from public key components exported by
//! the token, and verifies signatures with those public keys.

use base64::{Engine, engine::general_purpose::STANDARD};
use p256::{
    ecdsa::signature::Verifier,
    pkcs8::{DecodePublicKey, EncodePublicKey},
};

use crate::backend::SignAlgorithm;

/// Errors from encoding / decoding public-key structures.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EncodingError {
    #[error("malformed ECDSA signature: {0}")]
    MalformedSignature(&'static str),
    #[error("malformed public key: {0}")]
    MalformedPublicKey(String),
}

/// DER-encoded OID 1.2.840.10045.3.1.7 (prime256v1 / NIST P-256), as stored in `CKA_EC_PARAMS`.
pub const P256_EC_PARAMS: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
/// DER-encoded OID 1.3.101.112 (id-Ed25519), as stored in `CKA_EC_PARAMS`.
pub const ED25519_EC_PARAMS_OID: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];
/// DER PrintableString "edwards25519": the alternative curve-name form PKCS#11 3.0 allows.
pub const ED25519_EC_PARAMS_NAME: &[u8] = b"\x13\x0cedwards25519";

/// P-256 scalar / coordinate size in bytes.
pub const P256_SCALAR_LEN: usize = 32;

fn der_len(len: usize, out: &mut Vec<u8>) {
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xff {
        out.extend_from_slice(&[0x81, len as u8]);
    } else {
        // ECDSA signatures for any standard curve are far below 64 KiB.
        out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
    }
}

fn der_unsigned_integer(bytes: &[u8], out: &mut Vec<u8>) {
    // Minimal encoding: strip leading zeros, keep at least one byte, and add a
    // 0x00 pad if the high bit is set (DER INTEGERs are signed).
    let first_non_zero = bytes
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(bytes.len().saturating_sub(1));
    let trimmed = &bytes[first_non_zero.min(bytes.len().saturating_sub(1))..];
    let pad = trimmed.first().is_some_and(|b| b & 0x80 != 0);
    out.push(0x02);
    der_len(trimmed.len() + usize::from(pad), out);
    if pad {
        out.push(0);
    }
    out.extend_from_slice(trimmed);
}

/// Convert a PKCS#11 `CKM_ECDSA` signature (`r || s`, each the size of the
/// curve order) to the ASN.1 DER `Ecdsa-Sig-Value` used by X.509, TLS, JOSE
/// (after conversion), OpenSSL, Go, Java, ... .
pub fn ecdsa_raw_to_der(raw: &[u8]) -> Result<Vec<u8>, EncodingError> {
    if raw.is_empty() || !raw.len().is_multiple_of(2) {
        return Err(EncodingError::MalformedSignature("raw signature length must be even"));
    }
    let (r, s) = raw.split_at(raw.len() / 2);
    let mut body = Vec::with_capacity(raw.len() + 6);
    der_unsigned_integer(r, &mut body);
    der_unsigned_integer(s, &mut body);
    let mut out = Vec::with_capacity(body.len() + 3);
    out.push(0x30);
    der_len(body.len(), &mut out);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Minimal DER reader for one TLV. Returns (tag, value, rest).
fn read_tlv(input: &[u8]) -> Result<(u8, &[u8], &[u8]), EncodingError> {
    let err = EncodingError::MalformedSignature;
    let (&tag, rest) = input.split_first().ok_or(err("truncated"))?;
    let (&first, rest) = rest.split_first().ok_or(err("truncated"))?;
    let (len, rest) = match first {
        l if l < 0x80 => (l as usize, rest),
        0x81 => {
            let (&l, rest) = rest.split_first().ok_or(err("truncated"))?;
            if l < 0x80 {
                return Err(err("non-minimal length"));
            }
            (l as usize, rest)
        }
        0x82 => {
            if rest.len() < 2 {
                return Err(err("truncated"));
            }
            let l = (usize::from(rest[0]) << 8) | usize::from(rest[1]);
            if l < 0x100 {
                return Err(err("non-minimal length"));
            }
            (l, &rest[2..])
        }
        _ => return Err(err("unsupported length encoding")),
    };
    if rest.len() < len {
        return Err(err("truncated"));
    }
    Ok((tag, &rest[..len], &rest[len..]))
}

fn integer_to_fixed(value: &[u8], width: usize) -> Result<Vec<u8>, EncodingError> {
    let err = EncodingError::MalformedSignature;
    if value.is_empty() {
        return Err(err("empty integer"));
    }
    if value[0] & 0x80 != 0 {
        return Err(err("negative integer"));
    }
    if value.len() > 1 && value[0] == 0 && value[1] & 0x80 == 0 {
        return Err(err("non-minimal integer"));
    }
    let value = if value[0] == 0 && value.len() > 1 {
        &value[1..]
    } else {
        value
    };
    if value.len() > width {
        return Err(err("integer too large for curve"));
    }
    let mut out = vec![0u8; width - value.len()];
    out.extend_from_slice(value);
    Ok(out)
}

/// Convert a DER `Ecdsa-Sig-Value` back to fixed-width `r || s`
/// (needed to feed a signature to PKCS#11 `C_Verify`).
pub fn ecdsa_der_to_raw(der: &[u8], scalar_len: usize) -> Result<Vec<u8>, EncodingError> {
    let err = EncodingError::MalformedSignature;
    let (tag, seq, trailing) = read_tlv(der)?;
    if tag != 0x30 || !trailing.is_empty() {
        return Err(err("expected a single SEQUENCE"));
    }
    let (tag_r, r, rest) = read_tlv(seq)?;
    let (tag_s, s, rest) = read_tlv(rest)?;
    if tag_r != 0x02 || tag_s != 0x02 || !rest.is_empty() {
        return Err(err("expected two INTEGERs"));
    }
    let mut out = integer_to_fixed(r, scalar_len)?;
    out.extend(integer_to_fixed(s, scalar_len)?);
    Ok(out)
}

/// PKCS#11 returns `CKA_EC_POINT` DER-wrapped in an OCTET STRING (per the
/// spec); some tokens return the raw point. Accept both, given the expected
/// raw length.
pub fn unwrap_ec_point(attr: &[u8], raw_len: usize) -> Result<&[u8], EncodingError> {
    if attr.len() == raw_len {
        return Ok(attr);
    }
    if raw_len < 0x80 && attr.len() == raw_len + 2 && attr[0] == 0x04 && usize::from(attr[1]) == raw_len {
        return Ok(&attr[2..]);
    }
    Err(EncodingError::MalformedPublicKey(format!(
        "unexpected CKA_EC_POINT length {} (expected {raw_len})",
        attr.len()
    )))
}

/// Build SPKI DER for a P-256 key from its SEC1 uncompressed point.
pub fn p256_spki_from_point(point: &[u8]) -> Result<Vec<u8>, EncodingError> {
    let pk = p256::PublicKey::from_sec1_bytes(point).map_err(|e| EncodingError::MalformedPublicKey(e.to_string()))?;
    pk.to_public_key_der()
        .map(|d| d.as_bytes().to_vec())
        .map_err(|e| EncodingError::MalformedPublicKey(e.to_string()))
}

/// Build SPKI DER for an Ed25519 key from its 32-byte encoding.
pub fn ed25519_spki_from_bytes(bytes: &[u8]) -> Result<Vec<u8>, EncodingError> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| EncodingError::MalformedPublicKey("Ed25519 key must be 32 bytes".into()))?;
    let vk =
        ed25519_dalek::VerifyingKey::from_bytes(&arr).map_err(|e| EncodingError::MalformedPublicKey(e.to_string()))?;
    ed25519_dalek::pkcs8::EncodePublicKey::to_public_key_der(&vk)
        .map(|d| d.as_bytes().to_vec())
        .map_err(|e| EncodingError::MalformedPublicKey(e.to_string()))
}

/// Build SPKI DER for an RSA key from big-endian modulus and public exponent.
pub fn rsa_spki_from_components(modulus: &[u8], exponent: &[u8]) -> Result<Vec<u8>, EncodingError> {
    let pk = rsa::RsaPublicKey::new(
        rsa::BigUint::from_bytes_be(modulus),
        rsa::BigUint::from_bytes_be(exponent),
    )
    .map_err(|e| EncodingError::MalformedPublicKey(e.to_string()))?;
    rsa::pkcs8::EncodePublicKey::to_public_key_der(&pk)
        .map(|d| d.as_bytes().to_vec())
        .map_err(|e| EncodingError::MalformedPublicKey(e.to_string()))
}

/// PEM-encode an SPKI (`-----BEGIN PUBLIC KEY-----`).
pub fn spki_der_to_pem(der: &[u8]) -> String {
    let b64 = STANDARD.encode(der);
    let mut pem = String::with_capacity(b64.len() + 64);
    pem.push_str("-----BEGIN PUBLIC KEY-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        // base64 output is ASCII, so this cannot fail.
        pem.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        pem.push('\n');
    }
    pem.push_str("-----END PUBLIC KEY-----\n");
    pem
}

/// Verify `signature` over `message` using a DER SPKI public key, entirely in
/// software. Returns `Ok(false)` for a well-formed request whose signature
/// does not verify (including undecodable signatures), and `Err` if the public
/// key does not match the algorithm.
pub fn verify_with_spki(
    algorithm: SignAlgorithm,
    spki_der: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<bool, EncodingError> {
    let key_err = |e: String| EncodingError::MalformedPublicKey(e);
    match algorithm {
        SignAlgorithm::EcdsaP256Sha256 => {
            let vk = p256::ecdsa::VerifyingKey::from_public_key_der(spki_der).map_err(|e| key_err(e.to_string()))?;
            let Ok(sig) = p256::ecdsa::Signature::from_der(signature) else {
                return Ok(false);
            };
            Ok(vk.verify(message, &sig).is_ok())
        }
        SignAlgorithm::Ed25519 => {
            let vk =
                <ed25519_dalek::VerifyingKey as ed25519_dalek::pkcs8::DecodePublicKey>::from_public_key_der(spki_der)
                    .map_err(|e| key_err(e.to_string()))?;
            let Ok(sig) = ed25519_dalek::Signature::from_slice(signature) else {
                return Ok(false);
            };
            Ok(vk.verify_strict(message, &sig).is_ok())
        }
        SignAlgorithm::RsaPssSha256 => {
            let pk = <rsa::RsaPublicKey as rsa::pkcs8::DecodePublicKey>::from_public_key_der(spki_der)
                .map_err(|e| key_err(e.to_string()))?;
            let vk = rsa::pss::VerifyingKey::<sha2::Sha256>::new(pk);
            let Ok(sig) = rsa::pss::Signature::try_from(signature) else {
                return Ok(false);
            };
            Ok(vk.verify(message, &sig).is_ok())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::{SigningKey, signature::Signer};

    fn test_signing_key() -> SigningKey {
        SigningKey::from_slice(&[7u8; 32]).unwrap()
    }

    #[test]
    fn raw_to_der_matches_rustcrypto() {
        let sk = test_signing_key();
        for i in 0..64u32 {
            let sig: p256::ecdsa::Signature = sk.sign(&i.to_be_bytes());
            let raw = sig.to_bytes();
            let der = ecdsa_raw_to_der(&raw).unwrap();
            assert_eq!(der, sig.to_der().as_bytes(), "iteration {i}");
            assert_eq!(ecdsa_der_to_raw(&der, P256_SCALAR_LEN).unwrap(), &raw[..]);
        }
    }

    #[test]
    fn raw_to_der_handles_high_bit_and_leading_zeros() {
        let mut raw = vec![0u8; 64];
        raw[0] = 0x80; // r: high bit set → needs 0x00 pad
        raw[63] = 0x01; // s: 31 leading zeros → 1 byte
        let der = ecdsa_raw_to_der(&raw).unwrap();
        assert_eq!(&der[..5], &[0x30, 0x26, 0x02, 0x21, 0x00]);
        assert_eq!(&der[der.len() - 3..], &[0x02, 0x01, 0x01]);
        assert_eq!(ecdsa_der_to_raw(&der, 32).unwrap(), raw);
    }

    #[test]
    fn der_parser_rejects_garbage() {
        assert!(ecdsa_raw_to_der(&[]).is_err());
        assert!(ecdsa_raw_to_der(&[1, 2, 3]).is_err());
        assert!(ecdsa_der_to_raw(&[], 32).is_err());
        assert!(ecdsa_der_to_raw(&[0x30, 0x03, 0x02, 0x01], 32).is_err());
        // trailing data
        assert!(ecdsa_der_to_raw(&[0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x00], 32).is_err());
        // negative integer
        assert!(ecdsa_der_to_raw(&[0x30, 0x06, 0x02, 0x01, 0x81, 0x02, 0x01, 0x01], 32).is_err());
        // integer wider than the curve
        let mut big = vec![0x30, 0x25, 0x02, 0x21, 0x01];
        big.extend([0u8; 32]);
        big.extend([0x02, 0x01, 0x01]);
        big[1] = (big.len() - 2) as u8;
        assert!(ecdsa_der_to_raw(&big, 32).is_err());
    }

    #[test]
    fn ec_point_unwrapping() {
        let raw = [4u8; 65];
        assert_eq!(unwrap_ec_point(&raw, 65).unwrap(), &raw);
        let mut wrapped = vec![0x04, 65];
        wrapped.extend_from_slice(&raw);
        assert_eq!(unwrap_ec_point(&wrapped, 65).unwrap(), &raw);
        assert!(unwrap_ec_point(&[0u8; 10], 65).is_err());
    }

    #[test]
    fn software_verify_ecdsa() {
        let sk = test_signing_key();
        let point = sk.verifying_key().to_encoded_point(false);
        let spki = p256_spki_from_point(point.as_bytes()).unwrap();
        let sig: p256::ecdsa::Signature = sk.sign(b"hello");
        let der = sig.to_der();
        let alg = SignAlgorithm::EcdsaP256Sha256;
        assert!(verify_with_spki(alg, &spki, b"hello", der.as_bytes()).unwrap());
        assert!(!verify_with_spki(alg, &spki, b"hellO", der.as_bytes()).unwrap());
        assert!(!verify_with_spki(alg, &spki, b"hello", b"not der").unwrap());
        // Wrong algorithm for this key → error, not `false`.
        assert!(verify_with_spki(SignAlgorithm::Ed25519, &spki, b"hello", der.as_bytes()).is_err());
        assert!(spki_der_to_pem(&spki).starts_with("-----BEGIN PUBLIC KEY-----\n"));
    }

    #[test]
    fn software_verify_ed25519() {
        use ed25519_dalek::Signer as _;
        let sk = ed25519_dalek::SigningKey::from_bytes(&[9u8; 32]);
        let spki = ed25519_spki_from_bytes(sk.verifying_key().as_bytes()).unwrap();
        let sig = sk.sign(b"msg").to_bytes();
        assert!(verify_with_spki(SignAlgorithm::Ed25519, &spki, b"msg", &sig).unwrap());
        assert!(!verify_with_spki(SignAlgorithm::Ed25519, &spki, b"msh", &sig).unwrap());
        assert!(!verify_with_spki(SignAlgorithm::Ed25519, &spki, b"msg", &sig[..10]).unwrap());
    }
}
