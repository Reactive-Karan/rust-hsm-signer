//! Key backend abstraction.
//!
//! HTTP handlers only ever see `Arc<dyn KeyBackend>`. Two implementations are
//! provided:
//!
//! * [`pkcs11::Pkcs11Backend`] — the real thing: keys live in a PKCS#11 token
//!   (SoftHSM2 in development, a hardware HSM in production) and every private
//!   / secret key operation happens inside the token.
//! * [`mock::SoftwareMockBackend`] — in-memory software keys, used for unit
//!   tests and for running the API without an HSM.

pub mod instrumented;
pub mod mock;
pub mod pkcs11;

use std::{fmt, str::FromStr};

use async_trait::async_trait;
use serde::Serialize;
use zeroize::Zeroizing;

pub use crate::error::BackendError;

/// Signature algorithms exposed by the API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignAlgorithm {
    /// ECDSA over NIST P-256 with SHA-256. Signature: ASN.1 DER `Ecdsa-Sig-Value`.
    EcdsaP256Sha256,
    /// Pure Ed25519 (RFC 8032). Signature: 64 raw bytes.
    Ed25519,
    /// RSASSA-PSS, SHA-256, MGF1-SHA-256, 32-byte salt. Signature: k raw bytes.
    RsaPssSha256,
}

impl SignAlgorithm {
    pub const ALL: [SignAlgorithm; 3] = [Self::EcdsaP256Sha256, Self::Ed25519, Self::RsaPssSha256];

    pub fn as_str(self) -> &'static str {
        match self {
            Self::EcdsaP256Sha256 => "ECDSA_P256_SHA256",
            Self::Ed25519 => "ED25519",
            Self::RsaPssSha256 => "RSA_PSS_SHA256",
        }
    }

    /// The key type a key must have to be used with this algorithm.
    pub fn key_type(self) -> KeyType {
        match self {
            Self::EcdsaP256Sha256 => KeyType::EcP256,
            Self::Ed25519 => KeyType::Ed25519,
            Self::RsaPssSha256 => KeyType::Rsa,
        }
    }
}

impl fmt::Display for SignAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Error returned when parsing an unknown algorithm name.
#[derive(Debug, thiserror::Error)]
#[error("unsupported algorithm `{0}`")]
pub struct UnsupportedAlgorithm(pub String);

impl FromStr for SignAlgorithm {
    type Err = UnsupportedAlgorithm;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::ALL
            .into_iter()
            .find(|a| a.as_str() == s)
            .ok_or_else(|| UnsupportedAlgorithm(s.to_string()))
    }
}

/// Kind of key held by a backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KeyType {
    EcP256,
    Ed25519,
    Rsa,
    #[serde(rename = "AES_256")]
    Aes256,
}

impl KeyType {
    pub fn is_asymmetric(self) -> bool {
        !matches!(self, Self::Aes256)
    }
}

/// What a key may be used for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyUsage {
    Sign,
    EncryptDecrypt,
    WrapUnwrap,
}

/// Public metadata about a key (never contains key material).
#[derive(Debug, Clone, Serialize)]
pub struct KeyDescriptor {
    pub key_id: String,
    pub key_type: KeyType,
    pub usage: KeyUsage,
    /// Hex-encoded CKA_ID (PKCS#11 backend) or a synthetic id (mock).
    pub object_id: String,
    /// Security-relevant attributes as reported by the token.
    pub attributes: KeyAttributes,
}

/// Security attributes of a private/secret key, as reported by the backend.
#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
pub struct KeyAttributes {
    pub token: bool,
    pub private: bool,
    pub sensitive: bool,
    pub extractable: bool,
    pub always_sensitive: bool,
    pub never_extractable: bool,
}

/// A public key exported from the backend, as DER `SubjectPublicKeyInfo`.
#[derive(Debug, Clone)]
pub struct PublicKeyInfo {
    pub key_id: String,
    pub key_type: KeyType,
    pub spki_der: Vec<u8>,
}

impl PublicKeyInfo {
    /// PEM (`-----BEGIN PUBLIC KEY-----`) encoding of the SPKI.
    pub fn to_pem(&self) -> String {
        crate::crypto::spki_der_to_pem(&self.spki_der)
    }
}

/// Output of an AES-256-GCM encryption.
#[derive(Debug, Clone)]
pub struct AeadCiphertext {
    /// 96-bit random IV, generated per call.
    pub iv: Vec<u8>,
    /// Ciphertext with the 128-bit authentication tag appended.
    pub ciphertext: Vec<u8>,
}

/// Output of an envelope encryption: a fresh data-encryption key (DEK) was
/// generated inside the HSM, used to encrypt the payload and then exported
/// only in wrapped form (encrypted under a key-encryption key that never
/// leaves the HSM).
#[derive(Debug, Clone)]
pub struct Envelope {
    pub wrapped_key: Vec<u8>,
    pub iv: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// Name of the key-wrapping scheme used for envelopes.
pub const WRAP_ALGORITHM: &str = "AES_KEY_WRAP_PAD";
/// Name of the AEAD used for encrypt/decrypt and envelopes.
pub const AEAD_ALGORITHM: &str = "AES_256_GCM";
/// AES-GCM IV length in bytes (96 bits, as recommended by NIST SP 800-38D).
pub const GCM_IV_LEN: usize = 12;
/// AES-GCM tag length in bytes.
pub const GCM_TAG_LEN: usize = 16;

/// Plaintext returned by decryption; wiped from memory on drop.
pub type Plaintext = Zeroizing<Vec<u8>>;

/// The operations the service needs from a key store.
///
/// Implementations must never expose private or secret key material: only
/// signatures, ciphertexts, wrapped keys and public keys leave the backend.
#[async_trait]
pub trait KeyBackend: Send + Sync + 'static {
    /// Short identifier for logs/metrics (`pkcs11`, `mock`).
    fn name(&self) -> &'static str;

    /// Sign `payload` with the private key labelled `key_id`.
    ///
    /// Returns the signature in the API encoding documented on [`SignAlgorithm`].
    async fn sign(&self, key_id: &str, algorithm: SignAlgorithm, payload: Vec<u8>) -> Result<Vec<u8>, BackendError>;

    /// Verify a signature *inside the backend* (PKCS#11 `C_Verify`).
    ///
    /// The API verifies in software with the exported public key by default;
    /// this is offered as a cross-check.
    async fn verify(
        &self,
        key_id: &str,
        algorithm: SignAlgorithm,
        payload: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<bool, BackendError>;

    /// Export the public half of an asymmetric key.
    async fn public_key(&self, key_id: &str) -> Result<PublicKeyInfo, BackendError>;

    /// AES-256-GCM encrypt with the secret key `key_id`.
    async fn encrypt(&self, key_id: &str, plaintext: Plaintext, aad: Vec<u8>) -> Result<AeadCiphertext, BackendError>;

    /// AES-256-GCM decrypt with the secret key `key_id`.
    async fn decrypt(
        &self,
        key_id: &str,
        iv: Vec<u8>,
        ciphertext: Vec<u8>,
        aad: Vec<u8>,
    ) -> Result<Plaintext, BackendError>;

    /// Envelope-encrypt: generate an ephemeral DEK in the backend, encrypt with
    /// it, and return the DEK wrapped under `wrapping_key_id`.
    async fn envelope_encrypt(
        &self,
        wrapping_key_id: &str,
        plaintext: Plaintext,
        aad: Vec<u8>,
    ) -> Result<Envelope, BackendError>;

    /// Envelope-decrypt: unwrap the DEK *into* the backend as a
    /// non-extractable key, decrypt with it, destroy it.
    async fn envelope_decrypt(
        &self,
        wrapping_key_id: &str,
        envelope: Envelope,
        aad: Vec<u8>,
    ) -> Result<Plaintext, BackendError>;

    /// Describe all keys known to the backend.
    async fn list_keys(&self) -> Result<Vec<KeyDescriptor>, BackendError>;

    /// Readiness probe: can we get a usable (logged-in) session right now?
    async fn health_check(&self) -> Result<(), BackendError>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn algorithm_round_trip() {
        for alg in SignAlgorithm::ALL {
            assert_eq!(alg.as_str().parse::<SignAlgorithm>().unwrap(), alg);
        }
        assert!("ecdsa_p256_sha256".parse::<SignAlgorithm>().is_err());
        assert!("HS256".parse::<SignAlgorithm>().is_err());
    }

    #[test]
    fn key_types() {
        assert_eq!(SignAlgorithm::EcdsaP256Sha256.key_type(), KeyType::EcP256);
        assert!(KeyType::Rsa.is_asymmetric());
        assert!(!KeyType::Aes256.is_asymmetric());
    }
}
