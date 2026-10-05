//! In-memory software backend.
//!
//! **Not for production.** Keys are random per process and held in ordinary
//! memory (zeroized on drop). It implements exactly the same contract and
//! output encodings as the PKCS#11 backend so handlers can be tested without
//! an HSM, and it can inject artificial latency or failures for tests.

use std::{
    collections::BTreeMap,
    sync::{Mutex, OnceLock},
    time::Duration,
};

use aes_gcm::{
    Aes256Gcm, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use async_trait::async_trait;
use ed25519_dalek::Signer as _;
use p256::ecdsa::signature::RandomizedSigner;
use rand_core::OsRng;
use zeroize::Zeroizing;

use super::{
    AeadCiphertext, BackendError, Envelope, GCM_IV_LEN, KeyAttributes, KeyBackend, KeyDescriptor, KeyType, KeyUsage,
    Plaintext, PublicKeyInfo, SignAlgorithm,
};
use crate::{crypto, keys::KeyCatalog};

enum MockKey {
    EcP256(p256::ecdsa::SigningKey),
    Ed25519(ed25519_dalek::SigningKey),
    /// RSA key generation is slow, so it happens lazily on first use.
    Rsa(OnceLock<rsa::RsaPrivateKey>),
    Aes {
        key: Zeroizing<[u8; 32]>,
        usage: KeyUsage,
    },
}

impl MockKey {
    fn key_type(&self) -> KeyType {
        match self {
            Self::EcP256(_) => KeyType::EcP256,
            Self::Ed25519(_) => KeyType::Ed25519,
            Self::Rsa(_) => KeyType::Rsa,
            Self::Aes { .. } => KeyType::Aes256,
        }
    }

    fn rsa(cell: &OnceLock<rsa::RsaPrivateKey>) -> &rsa::RsaPrivateKey {
        cell.get_or_init(|| {
            rsa::RsaPrivateKey::new(&mut OsRng, crate::keys::RSA_MODULUS_BITS as usize).expect("RSA key generation")
        })
    }
}

fn random_bytes<const N: usize>() -> Result<[u8; N], BackendError> {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).map_err(|e| BackendError::Internal(format!("OS RNG failure: {e}")))?;
    Ok(buf)
}

/// Behaviour knobs for tests.
#[derive(Default)]
struct Faults {
    latency: Option<Duration>,
    fail_with: Option<fn() -> BackendError>,
}

/// Software implementation of [`KeyBackend`].
pub struct SoftwareMockBackend {
    keys: BTreeMap<String, MockKey>,
    faults: Mutex<Faults>,
}

impl SoftwareMockBackend {
    /// Create a backend holding a fresh random key for every entry of `catalog`.
    pub fn new(catalog: &KeyCatalog) -> Self {
        let keys = catalog
            .specs()
            .iter()
            .map(|spec| {
                let key = match spec.key_type {
                    KeyType::EcP256 => MockKey::EcP256(p256::ecdsa::SigningKey::random(&mut OsRng)),
                    KeyType::Ed25519 => MockKey::Ed25519(ed25519_dalek::SigningKey::from_bytes(
                        &random_bytes::<32>().expect("OS RNG"),
                    )),
                    KeyType::Rsa => MockKey::Rsa(OnceLock::new()),
                    KeyType::Aes256 => MockKey::Aes {
                        key: Zeroizing::new(random_bytes::<32>().expect("OS RNG")),
                        usage: spec.usage,
                    },
                };
                (spec.label.clone(), key)
            })
            .collect();
        Self {
            keys,
            faults: Mutex::new(Faults::default()),
        }
    }

    /// Add artificial latency to every operation (for concurrency tests).
    pub fn set_latency(&self, latency: Option<Duration>) {
        self.faults.lock().expect("faults lock").latency = latency;
    }

    /// Make every subsequent operation fail with the error produced by `f`.
    pub fn fail_with(&self, f: Option<fn() -> BackendError>) {
        self.faults.lock().expect("faults lock").fail_with = f;
    }

    async fn inject_faults(&self) -> Result<(), BackendError> {
        let (latency, fail_with) = {
            let f = self.faults.lock().expect("faults lock");
            (f.latency, f.fail_with)
        };
        if let Some(d) = latency {
            tokio::time::sleep(d).await;
        }
        match fail_with {
            Some(f) => Err(f()),
            None => Ok(()),
        }
    }

    fn key(&self, key_id: &str) -> Result<&MockKey, BackendError> {
        self.keys
            .get(key_id)
            .ok_or_else(|| BackendError::KeyNotFound(key_id.to_string()))
    }

    fn aes_key(&self, key_id: &str, usage: KeyUsage, operation: &'static str) -> Result<Aes256Gcm, BackendError> {
        match self.key(key_id)? {
            MockKey::Aes { key, usage: u } if *u == usage => Aes256Gcm::new_from_slice(key.as_slice())
                .map_err(|_| BackendError::Internal("invalid AES key length".into())),
            _ => Err(BackendError::UnsupportedOperation {
                key_id: key_id.to_string(),
                operation,
            }),
        }
    }

    fn signing_key(&self, key_id: &str, algorithm: SignAlgorithm) -> Result<&MockKey, BackendError> {
        let key = self.key(key_id)?;
        if key.key_type() != algorithm.key_type() {
            return Err(BackendError::KeyAlgorithmMismatch {
                key_id: key_id.to_string(),
                algorithm: algorithm.to_string(),
            });
        }
        Ok(key)
    }
}

fn gcm_seal(cipher: &Aes256Gcm, plaintext: &[u8], aad: &[u8]) -> Result<AeadCiphertext, BackendError> {
    let iv = random_bytes::<GCM_IV_LEN>()?;
    let ciphertext = cipher
        .encrypt(&Nonce::from(iv), Payload { msg: plaintext, aad })
        .map_err(|_| BackendError::Internal("AES-GCM encryption failed".into()))?;
    Ok(AeadCiphertext {
        iv: iv.to_vec(),
        ciphertext,
    })
}

fn gcm_open(cipher: &Aes256Gcm, iv: &[u8], ciphertext: &[u8], aad: &[u8]) -> Result<Plaintext, BackendError> {
    let iv: [u8; GCM_IV_LEN] = iv
        .try_into()
        .map_err(|_| BackendError::InvalidInput(format!("iv must be {GCM_IV_LEN} bytes")))?;
    cipher
        .decrypt(&Nonce::from(iv), Payload { msg: ciphertext, aad })
        .map(Zeroizing::new)
        .map_err(|_| BackendError::IntegrityCheckFailed)
}

#[async_trait]
impl KeyBackend for SoftwareMockBackend {
    fn name(&self) -> &'static str {
        "mock"
    }

    async fn sign(&self, key_id: &str, algorithm: SignAlgorithm, payload: Vec<u8>) -> Result<Vec<u8>, BackendError> {
        self.inject_faults().await?;
        Ok(match self.signing_key(key_id, algorithm)? {
            MockKey::EcP256(sk) => {
                let sig: p256::ecdsa::Signature = sk.sign(&payload);
                // Same encoding path as the HSM backend: raw r||s → DER.
                crypto::ecdsa_raw_to_der(&sig.to_bytes()).map_err(|e| BackendError::Internal(e.to_string()))?
            }
            MockKey::Ed25519(sk) => sk.sign(&payload).to_bytes().to_vec(),
            MockKey::Rsa(cell) => {
                let sk = rsa::pss::BlindedSigningKey::<sha2::Sha256>::new(MockKey::rsa(cell).clone());
                let sig = sk.sign_with_rng(&mut OsRng, &payload);
                rsa::signature::SignatureEncoding::to_vec(&sig)
            }
            MockKey::Aes { .. } => unreachable!("signing_key checks the key type"),
        })
    }

    async fn verify(
        &self,
        key_id: &str,
        algorithm: SignAlgorithm,
        payload: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<bool, BackendError> {
        self.signing_key(key_id, algorithm)?;
        let pk = self.public_key(key_id).await?;
        crypto::verify_with_spki(algorithm, &pk.spki_der, &payload, &signature)
            .map_err(|e| BackendError::Internal(e.to_string()))
    }

    async fn public_key(&self, key_id: &str) -> Result<PublicKeyInfo, BackendError> {
        self.inject_faults().await?;
        let internal = |e: crypto::EncodingError| BackendError::Internal(e.to_string());
        let key = self.key(key_id)?;
        let spki_der = match key {
            MockKey::EcP256(sk) => {
                crypto::p256_spki_from_point(sk.verifying_key().to_encoded_point(false).as_bytes()).map_err(internal)?
            }
            MockKey::Ed25519(sk) => crypto::ed25519_spki_from_bytes(sk.verifying_key().as_bytes()).map_err(internal)?,
            MockKey::Rsa(cell) => {
                use rsa::traits::PublicKeyParts;
                let pk = MockKey::rsa(cell).to_public_key();
                crypto::rsa_spki_from_components(&pk.n().to_bytes_be(), &pk.e().to_bytes_be()).map_err(internal)?
            }
            MockKey::Aes { .. } => {
                return Err(BackendError::UnsupportedOperation {
                    key_id: key_id.to_string(),
                    operation: "public key export",
                });
            }
        };
        Ok(PublicKeyInfo {
            key_id: key_id.to_string(),
            key_type: key.key_type(),
            spki_der,
        })
    }

    async fn encrypt(&self, key_id: &str, plaintext: Plaintext, aad: Vec<u8>) -> Result<AeadCiphertext, BackendError> {
        self.inject_faults().await?;
        let cipher = self.aes_key(key_id, KeyUsage::EncryptDecrypt, "encrypt")?;
        gcm_seal(&cipher, &plaintext, &aad)
    }

    async fn decrypt(
        &self,
        key_id: &str,
        iv: Vec<u8>,
        ciphertext: Vec<u8>,
        aad: Vec<u8>,
    ) -> Result<Plaintext, BackendError> {
        self.inject_faults().await?;
        let cipher = self.aes_key(key_id, KeyUsage::EncryptDecrypt, "decrypt")?;
        gcm_open(&cipher, &iv, &ciphertext, &aad)
    }

    async fn envelope_encrypt(
        &self,
        wrapping_key_id: &str,
        plaintext: Plaintext,
        aad: Vec<u8>,
    ) -> Result<Envelope, BackendError> {
        self.inject_faults().await?;
        let kek = self.aes_key(wrapping_key_id, KeyUsage::WrapUnwrap, "wrap")?;
        let dek_bytes = Zeroizing::new(random_bytes::<32>()?);
        let dek = Aes256Gcm::new_from_slice(dek_bytes.as_slice()).map_err(|e| BackendError::Internal(e.to_string()))?;
        let sealed = gcm_seal(&dek, &plaintext, &aad)?;
        // The mock wraps with AES-GCM (iv || ct) instead of RFC 5649; the
        // wrapped blob is opaque to clients either way.
        let wrapped = gcm_seal(&kek, dek_bytes.as_slice(), b"")?;
        let mut wrapped_key = wrapped.iv;
        wrapped_key.extend(wrapped.ciphertext);
        Ok(Envelope {
            wrapped_key,
            iv: sealed.iv,
            ciphertext: sealed.ciphertext,
        })
    }

    async fn envelope_decrypt(
        &self,
        wrapping_key_id: &str,
        envelope: Envelope,
        aad: Vec<u8>,
    ) -> Result<Plaintext, BackendError> {
        self.inject_faults().await?;
        let kek = self.aes_key(wrapping_key_id, KeyUsage::WrapUnwrap, "unwrap")?;
        if envelope.wrapped_key.len() <= GCM_IV_LEN {
            return Err(BackendError::IntegrityCheckFailed);
        }
        let (iv, ct) = envelope.wrapped_key.split_at(GCM_IV_LEN);
        let dek_bytes = gcm_open(&kek, iv, ct, b"")?;
        let dek = Aes256Gcm::new_from_slice(&dek_bytes).map_err(|_| BackendError::IntegrityCheckFailed)?;
        gcm_open(&dek, &envelope.iv, &envelope.ciphertext, &aad)
    }

    async fn list_keys(&self) -> Result<Vec<KeyDescriptor>, BackendError> {
        Ok(self
            .keys
            .iter()
            .enumerate()
            .map(|(i, (label, key))| KeyDescriptor {
                key_id: label.clone(),
                key_type: key.key_type(),
                usage: match key {
                    MockKey::Aes { usage, .. } => *usage,
                    _ => KeyUsage::Sign,
                },
                object_id: format!("mock-{i}"),
                attributes: KeyAttributes {
                    token: false,
                    private: true,
                    sensitive: true,
                    extractable: false,
                    always_sensitive: true,
                    never_extractable: true,
                },
            })
            .collect())
    }

    async fn health_check(&self) -> Result<(), BackendError> {
        self.inject_faults().await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn backend() -> SoftwareMockBackend {
        SoftwareMockBackend::new(&KeyCatalog::default())
    }

    #[tokio::test]
    async fn ecdsa_sign_and_verify() {
        let b = backend();
        let alg = SignAlgorithm::EcdsaP256Sha256;
        let sig = b.sign("arkion-intermediate-prod", alg, b"data".to_vec()).await.unwrap();
        assert_eq!(sig[0], 0x30, "DER SEQUENCE");
        let pk = b.public_key("arkion-intermediate-prod").await.unwrap();
        assert!(crypto::verify_with_spki(alg, &pk.spki_der, b"data", &sig).unwrap());
        assert!(
            b.verify("arkion-intermediate-prod", alg, b"data".to_vec(), sig)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn ed25519_sign_and_verify() {
        let b = backend();
        let sig = b
            .sign("arkion-ed25519-prod", SignAlgorithm::Ed25519, b"x".to_vec())
            .await
            .unwrap();
        assert_eq!(sig.len(), 64);
        let pk = b.public_key("arkion-ed25519-prod").await.unwrap();
        assert!(crypto::verify_with_spki(SignAlgorithm::Ed25519, &pk.spki_der, b"x", &sig).unwrap());
    }

    #[tokio::test]
    async fn errors() {
        let b = backend();
        assert!(matches!(
            b.sign("nope", SignAlgorithm::Ed25519, vec![]).await,
            Err(BackendError::KeyNotFound(_))
        ));
        assert!(matches!(
            b.sign("arkion-intermediate-prod", SignAlgorithm::Ed25519, vec![]).await,
            Err(BackendError::KeyAlgorithmMismatch { .. })
        ));
        assert!(matches!(
            b.public_key("arkion-data-key").await,
            Err(BackendError::UnsupportedOperation { .. })
        ));
        assert!(matches!(
            b.encrypt("arkion-wrapping-key", Zeroizing::new(vec![1]), vec![]).await,
            Err(BackendError::UnsupportedOperation { .. })
        ));
    }

    #[tokio::test]
    async fn aes_gcm_round_trip_and_tamper() {
        let b = backend();
        let ct = b
            .encrypt("arkion-data-key", Zeroizing::new(b"secret".to_vec()), b"aad".to_vec())
            .await
            .unwrap();
        assert_eq!(ct.iv.len(), GCM_IV_LEN);
        let pt = b
            .decrypt("arkion-data-key", ct.iv.clone(), ct.ciphertext.clone(), b"aad".to_vec())
            .await
            .unwrap();
        assert_eq!(pt.as_slice(), b"secret");
        let wrong_aad = b
            .decrypt("arkion-data-key", ct.iv.clone(), ct.ciphertext.clone(), b"AAD".to_vec())
            .await;
        assert!(matches!(wrong_aad, Err(BackendError::IntegrityCheckFailed)));
    }

    #[tokio::test]
    async fn envelope_round_trip() {
        let b = backend();
        let env = b
            .envelope_encrypt("arkion-wrapping-key", Zeroizing::new(b"payload".to_vec()), vec![])
            .await
            .unwrap();
        let pt = b
            .envelope_decrypt("arkion-wrapping-key", env.clone(), vec![])
            .await
            .unwrap();
        assert_eq!(pt.as_slice(), b"payload");
        let mut bad = env;
        bad.wrapped_key[GCM_IV_LEN] ^= 1;
        assert!(matches!(
            b.envelope_decrypt("arkion-wrapping-key", bad, vec![]).await,
            Err(BackendError::IntegrityCheckFailed)
        ));
    }

    #[tokio::test]
    async fn fault_injection() {
        let b = backend();
        b.fail_with(Some(|| BackendError::PoolExhausted));
        assert!(matches!(b.health_check().await, Err(BackendError::PoolExhausted)));
        b.fail_with(None);
        assert!(b.health_check().await.is_ok());
    }
}
