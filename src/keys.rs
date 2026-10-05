//! The key catalog: which keys the service expects, how they are named and
//! what they may be used for.
//!
//! Keys are addressed by a stable `key_id`, stored in the token as `CKA_LABEL`.
//! Each key also gets a deterministic `CKA_ID` (first 16 bytes of
//! SHA-256(label)), shared by the private and public halves of a key pair, as
//! is conventional for PKCS#11 tooling (p11tool, OpenSSL providers, ...).

use sha2::{Digest, Sha256};

use crate::backend::{KeyType, KeyUsage};

/// Default ECDSA P-256 signing key (the one from the assignment).
pub const EC_SIGNING_KEY: &str = "arkion-intermediate-prod";
/// Default Ed25519 signing key.
pub const ED25519_SIGNING_KEY: &str = "arkion-ed25519-prod";
/// Default RSA-PSS signing key.
pub const RSA_SIGNING_KEY: &str = "arkion-rsa-pss-prod";
/// Default AES-256 data encryption key (AES-GCM encrypt/decrypt).
pub const DATA_KEY: &str = "arkion-data-key";
/// Default AES-256 key-encryption key (wrap/unwrap only).
pub const WRAPPING_KEY: &str = "arkion-wrapping-key";

/// RSA modulus size for provisioned RSA keys.
pub const RSA_MODULUS_BITS: u64 = 3072;

/// Description of one key the service manages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeySpec {
    pub label: String,
    pub key_type: KeyType,
    pub usage: KeyUsage,
}

impl KeySpec {
    pub fn new(label: impl Into<String>, key_type: KeyType, usage: KeyUsage) -> Self {
        Self {
            label: label.into(),
            key_type,
            usage,
        }
    }

    /// Stable `CKA_ID`: first 16 bytes of SHA-256 over the label.
    pub fn object_id(&self) -> Vec<u8> {
        object_id_for(&self.label)
    }
}

/// Stable `CKA_ID` derived from a key label.
pub fn object_id_for(label: &str) -> Vec<u8> {
    Sha256::digest(label.as_bytes())[..16].to_vec()
}

/// The set of keys to provision / expose.
#[derive(Debug, Clone)]
pub struct KeyCatalog {
    specs: Vec<KeySpec>,
}

impl KeyCatalog {
    pub fn new(specs: Vec<KeySpec>) -> Self {
        Self { specs }
    }

    pub fn specs(&self) -> &[KeySpec] {
        &self.specs
    }

    pub fn get(&self, label: &str) -> Option<&KeySpec> {
        self.specs.iter().find(|s| s.label == label)
    }
}

impl Default for KeyCatalog {
    fn default() -> Self {
        Self::new(vec![
            KeySpec::new(EC_SIGNING_KEY, KeyType::EcP256, KeyUsage::Sign),
            KeySpec::new(ED25519_SIGNING_KEY, KeyType::Ed25519, KeyUsage::Sign),
            KeySpec::new(RSA_SIGNING_KEY, KeyType::Rsa, KeyUsage::Sign),
            KeySpec::new(DATA_KEY, KeyType::Aes256, KeyUsage::EncryptDecrypt),
            KeySpec::new(WRAPPING_KEY, KeyType::Aes256, KeyUsage::WrapUnwrap),
        ])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn object_ids_are_stable_and_distinct() {
        let catalog = KeyCatalog::default();
        let ids: std::collections::HashSet<_> = catalog.specs().iter().map(KeySpec::object_id).collect();
        assert_eq!(ids.len(), catalog.specs().len());
        assert_eq!(object_id_for(EC_SIGNING_KEY), object_id_for(EC_SIGNING_KEY));
        assert_eq!(object_id_for(EC_SIGNING_KEY).len(), 16);
        assert!(catalog.get(DATA_KEY).is_some());
    }
}
