//! PKCS#11 backend (SoftHSM2 or any PKCS#11 v2.40+/3.x token).
//!
//! Every private/secret key operation executes inside the token. The process
//! only ever handles: payload digests / payloads, signatures, ciphertexts,
//! wrapped (encrypted) keys and public keys.

pub mod objects;
pub mod pool;
pub mod token;

use std::{collections::HashMap, path::Path, sync::Arc, sync::RwLock, time::Duration};

use async_trait::async_trait;
use cryptoki::{
    context::{CInitializeArgs, CInitializeFlags, Pkcs11},
    error::{Error as CkError, RvError},
    mechanism::{
        Mechanism, MechanismType,
        aead::GcmParams,
        eddsa::{EddsaParams, EddsaSignatureScheme},
        rsa::{PkcsMgfType, PkcsPssParams},
    },
    object::{Attribute, AttributeType, ObjectClass, ObjectHandle},
    session::Session,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use self::{
    objects::{CkContext, HandleCache, ObjKind, ProvisionOutcome},
    pool::{PoolSettings, SessionPool, is_session_fatal},
};
use super::{
    AeadCiphertext, BackendError, Envelope, GCM_IV_LEN, GCM_TAG_LEN, KeyBackend, KeyDescriptor, KeyType, KeyUsage,
    Plaintext, PublicKeyInfo, SignAlgorithm,
};
use crate::{config::HsmConfig, crypto, keys::KeyCatalog, metrics::Metrics};

/// Error raised inside a blocking PKCS#11 closure.
#[derive(Debug)]
pub enum OpError {
    /// Domain error decided by our own logic (unknown key, wrong type, ...).
    Backend(BackendError),
    /// Raw PKCS#11 failure, classified later.
    Pkcs11 { function: &'static str, err: CkError },
}

impl From<BackendError> for OpError {
    fn from(e: BackendError) -> Self {
        Self::Backend(e)
    }
}

impl OpError {
    fn into_backend(self, key_id: &str) -> BackendError {
        match self {
            Self::Backend(e) => e,
            Self::Pkcs11 { function, err } => map_ck_error(function, &err, key_id),
        }
    }
}

/// Translate PKCS#11 return values into domain errors.
fn map_ck_error(function: &'static str, err: &CkError, key_id: &str) -> BackendError {
    let rv = match err {
        CkError::Pkcs11(rv, _) => *rv,
        other => {
            return BackendError::Hsm {
                operation: function,
                detail: format!("{other:?}"),
            };
        }
    };
    match rv {
        // Integrity failures on decrypt / unwrap: client-supplied data is bad.
        RvError::EncryptedDataInvalid
        | RvError::EncryptedDataLenRange
        | RvError::WrappedKeyInvalid
        | RvError::WrappedKeyLenRange
            if matches!(function, "C_Decrypt" | "C_UnwrapKey") =>
        {
            BackendError::IntegrityCheckFailed
        }
        // Tokens disagree on how to report a failed GCM tag / RFC 5649
        // integrity check: SoftHSM 2.7 uses CKR_FUNCTION_FAILED for C_Decrypt,
        // SoftHSM 2.6 CKR_GENERAL_ERROR, and both use CKR_GENERAL_ERROR for
        // C_UnwrapKey. For these data-dependent calls (whose *Init already
        // succeeded) treat them as integrity failures.
        RvError::FunctionFailed | RvError::GeneralError if matches!(function, "C_Decrypt" | "C_UnwrapKey") => {
            BackendError::IntegrityCheckFailed
        }
        RvError::KeyFunctionNotPermitted | RvError::KeyTypeInconsistent => BackendError::UnsupportedOperation {
            key_id: key_id.to_string(),
            operation: function_operation(function),
        },
        RvError::DataLenRange | RvError::DataInvalid | RvError::MechanismParamInvalid => {
            BackendError::InvalidInput(format!("rejected by the HSM ({function})"))
        }
        RvError::TokenNotPresent
        | RvError::TokenNotRecognized
        | RvError::DeviceRemoved
        | RvError::SessionHandleInvalid
        | RvError::SessionClosed
        | RvError::UserNotLoggedIn
        | RvError::CryptokiNotInitialized => BackendError::Unavailable(format!("{function}: {rv:?}")),
        other => BackendError::Hsm {
            operation: function,
            detail: format!("{other:?}"),
        },
    }
}

fn function_operation(function: &str) -> &'static str {
    match function {
        "C_Sign" | "C_SignInit" => "sign",
        "C_Verify" | "C_VerifyInit" => "verify",
        "C_Encrypt" | "C_EncryptInit" => "encrypt",
        "C_Decrypt" | "C_DecryptInit" => "decrypt",
        "C_WrapKey" => "wrap",
        "C_UnwrapKey" => "unwrap",
        _ => "requested",
    }
}

/// Destroys a session object when dropped (used for ephemeral DEKs).
struct SessionObjectGuard<'a> {
    session: &'a Session,
    handle: ObjectHandle,
}

impl Drop for SessionObjectGuard<'_> {
    fn drop(&mut self) {
        if let Err(e) = self.session.destroy_object(self.handle) {
            tracing::warn!(error = ?e, "failed to destroy ephemeral key object");
        }
    }
}

/// Load and initialize a PKCS#11 module.
///
/// `CKR_CRYPTOKI_ALREADY_INITIALIZED` is accepted so several backends (e.g.
/// in tests) can share one module inside a process.
pub fn load_module(path: &Path) -> Result<Pkcs11, BackendError> {
    let ctx = Pkcs11::new(path).map_err(|e| BackendError::Unavailable(format!("cannot load PKCS#11 module: {e:?}")))?;
    match ctx.initialize(CInitializeArgs::new(CInitializeFlags::OS_LOCKING_OK)) {
        Ok(()) | Err(CkError::Pkcs11(RvError::CryptokiAlreadyInitialized, _)) => {}
        Err(e) => return Err(BackendError::Unavailable(format!("C_Initialize failed: {e:?}"))),
    }
    // Never unload the module: PKCS#11 libraries (SoftHSM among them) register
    // C++ static destructors / atexit handlers, and `dlclose`-ing them before
    // process exit crashes the process when those handlers run. Keeping one
    // reference alive for the life of the process pins the library in memory.
    std::mem::forget(ctx.clone());
    Ok(ctx)
}

/// HSM-backed implementation of [`KeyBackend`].
pub struct Pkcs11Backend {
    pool: Arc<SessionPool>,
    handles: Arc<HandleCache>,
    public_keys: RwLock<HashMap<String, PublicKeyInfo>>,
    catalog: KeyCatalog,
    op_timeout: Duration,
}

impl Pkcs11Backend {
    /// Load the module from `config` and build a backend.
    pub fn connect(config: &HsmConfig, catalog: KeyCatalog, metrics: Arc<Metrics>) -> Result<Self, BackendError> {
        let ctx = load_module(&config.module_path)?;
        Ok(Self::with_context(ctx, config, catalog, metrics))
    }

    /// Build a backend on an already-initialized module.
    pub fn with_context(ctx: Pkcs11, config: &HsmConfig, catalog: KeyCatalog, metrics: Arc<Metrics>) -> Self {
        let pool = SessionPool::new(
            ctx,
            PoolSettings {
                token_label: config.token_label.clone(),
                user_pin: config.user_pin.clone(),
                size: config.pool_size,
                max_waiters: config.max_waiters,
                acquire_timeout: config.acquire_timeout,
            },
            metrics,
        );
        Self {
            pool,
            handles: Arc::new(HandleCache::default()),
            public_keys: RwLock::new(HashMap::new()),
            catalog,
            op_timeout: config.op_timeout,
        }
    }

    /// The session pool (exposed for tests and diagnostics).
    pub fn pool(&self) -> &Arc<SessionPool> {
        &self.pool
    }

    /// Open all pool sessions up front. **Blocking.**
    pub fn warm_up(&self) -> Result<(), BackendError> {
        self.pool.warm_up()
    }

    /// Create every key of the catalog that does not exist yet. **Blocking.**
    ///
    /// Uses a dedicated R/W session (pool sessions are read-only).
    pub fn provision(&self) -> Result<Vec<(String, ProvisionOutcome)>, BackendError> {
        let slot = self.pool.slot()?;
        let session = self
            .pool
            .context()
            .open_rw_session(slot)
            .map_err(|e| BackendError::Unavailable(format!("C_OpenSession (R/W) failed: {e:?}")))?;
        pool::login_user(&session, self.pool.user_pin())
            .map_err(|e| BackendError::Unavailable(format!("C_Login failed: {e:?}")))?;
        let mut outcomes = Vec::new();
        for spec in self.catalog.specs() {
            let outcome = objects::provision_key(&session, spec).map_err(|e| e.into_backend(&spec.label))?;
            tracing::info!(key_id = %spec.label, key_type = ?spec.key_type, ?outcome, "provisioned key");
            outcomes.push((spec.label.clone(), outcome));
        }
        self.handles.clear();
        Ok(outcomes)
    }

    /// Run `f` with a pooled session on Tokio's blocking pool.
    ///
    /// * waits for a session with backpressure (see [`SessionPool::acquire`]);
    /// * bounds the PKCS#11 call with `HSM_OP_TIMEOUT_MS` (the blocking call
    ///   cannot be cancelled, but the caller is released and the session is
    ///   returned to the pool when the call eventually completes);
    /// * if the token reports the session as dead, discards it and retries
    ///   once on a fresh session.
    async fn run<T, F>(&self, operation: &'static str, key_id: &str, f: F) -> Result<T, BackendError>
    where
        T: Send + 'static,
        F: Fn(&Session, &HandleCache) -> Result<T, OpError> + Send + Sync + 'static,
    {
        let f = Arc::new(f);
        for attempt in 0..2 {
            let mut guard = self.pool.acquire().await?;
            let f = Arc::clone(&f);
            let handles = Arc::clone(&self.handles);
            let span = tracing::info_span!("pkcs11.call", otel.name = operation, attempt);
            let task = tokio::task::spawn_blocking(move || {
                let _entered = span.entered();
                let session = match guard.session() {
                    Ok(s) => s,
                    Err(e) => return Err(OpError::Backend(e)),
                };
                let result = f(session, &handles);
                if let Err(OpError::Pkcs11 { function, err }) = &result
                    && is_session_fatal(function, err)
                {
                    guard.discard_all();
                }
                result
            });
            let outcome = match tokio::time::timeout(self.op_timeout, task).await {
                Err(_elapsed) => return Err(BackendError::OperationTimeout),
                Ok(Err(join_err)) => return Err(BackendError::Internal(format!("PKCS#11 task failed: {join_err}"))),
                Ok(Ok(outcome)) => outcome,
            };
            match outcome {
                Ok(v) => return Ok(v),
                Err(OpError::Pkcs11 { function, err }) if attempt == 0 && is_session_fatal(function, &err) => {
                    tracing::warn!(function, error = ?err, "HSM session invalid; retrying on a fresh session");
                    if matches!(
                        err,
                        CkError::Pkcs11(RvError::TokenNotPresent | RvError::DeviceRemoved, _)
                    ) {
                        self.handles.clear();
                    }
                }
                Err(e) => return Err(e.into_backend(key_id)),
            }
        }
        Err(BackendError::Unavailable("HSM session invalid after retry".into()))
    }

    fn sign_mechanism(algorithm: SignAlgorithm) -> Mechanism<'static> {
        match algorithm {
            // Hash on the host, sign the digest in the HSM (CKM_ECDSA).
            SignAlgorithm::EcdsaP256Sha256 => Mechanism::Ecdsa,
            // Pure EdDSA must see the whole message (no pre-hash).
            SignAlgorithm::Ed25519 => Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Pure)),
            // Host-side SHA-256, then CKM_RSA_PKCS_PSS over the digest.
            SignAlgorithm::RsaPssSha256 => Mechanism::RsaPkcsPss(PkcsPssParams {
                hash_alg: MechanismType::SHA256,
                mgf: PkcsMgfType::MGF1_SHA256,
                s_len: 32.into(),
            }),
        }
    }

    /// Bytes handed to `C_Sign`/`C_Verify`: the SHA-256 digest for ECDSA and
    /// RSA-PSS (so large payloads never cross the PKCS#11 boundary and the
    /// mechanism works on HSMs lacking combined hash-and-sign mechanisms),
    /// the full message for Ed25519.
    fn to_be_signed(algorithm: SignAlgorithm, payload: Vec<u8>) -> Vec<u8> {
        match algorithm {
            SignAlgorithm::EcdsaP256Sha256 | SignAlgorithm::RsaPssSha256 => Sha256::digest(&payload).to_vec(),
            SignAlgorithm::Ed25519 => payload,
        }
    }

    fn gcm_encrypt(
        session: &Session,
        key: ObjectHandle,
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<AeadCiphertext, OpError> {
        // Fresh 96-bit IV from the HSM's RNG for every message.
        let mut iv = [0u8; GCM_IV_LEN];
        session.generate_random_slice(&mut iv).ck("C_GenerateRandom")?;
        let mut iv_param = iv;
        let params = GcmParams::new(&mut iv_param, aad, ((GCM_TAG_LEN * 8) as u64).into()).ck("GcmParams")?;
        let ciphertext = session
            .encrypt(&Mechanism::AesGcm(params), key, plaintext)
            .ck("C_Encrypt")?;
        Ok(AeadCiphertext {
            iv: iv.to_vec(),
            ciphertext,
        })
    }

    fn gcm_decrypt(
        session: &Session,
        key: ObjectHandle,
        iv: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
    ) -> Result<Plaintext, OpError> {
        let mut iv = iv.to_vec();
        let params = GcmParams::new(&mut iv, aad, ((GCM_TAG_LEN * 8) as u64).into()).ck("GcmParams")?;
        session
            .decrypt(&Mechanism::AesGcm(params), key, ciphertext)
            .map(Zeroizing::new)
            .ck("C_Decrypt")
    }
}

fn check_gcm_input(iv: &[u8], ciphertext: &[u8]) -> Result<(), BackendError> {
    if iv.len() != GCM_IV_LEN {
        return Err(BackendError::InvalidInput(format!("iv must be {GCM_IV_LEN} bytes")));
    }
    if ciphertext.len() < GCM_TAG_LEN {
        return Err(BackendError::InvalidInput(
            "ciphertext is shorter than the GCM tag".into(),
        ));
    }
    Ok(())
}

#[async_trait]
impl KeyBackend for Pkcs11Backend {
    fn name(&self) -> &'static str {
        "pkcs11"
    }

    async fn sign(&self, key_id: &str, algorithm: SignAlgorithm, payload: Vec<u8>) -> Result<Vec<u8>, BackendError> {
        let tbs = Self::to_be_signed(algorithm, payload);
        let label = key_id.to_string();
        self.run("C_Sign", key_id, move |session, handles| {
            let kind = ObjKind::Private(algorithm.key_type());
            let raw = handles.with_key(session, &label, kind, |key| {
                session.sign(&Self::sign_mechanism(algorithm), key, &tbs).ck("C_Sign")
            })?;
            match algorithm {
                SignAlgorithm::EcdsaP256Sha256 => {
                    crypto::ecdsa_raw_to_der(&raw).map_err(|e| OpError::Backend(BackendError::Internal(e.to_string())))
                }
                SignAlgorithm::Ed25519 | SignAlgorithm::RsaPssSha256 => Ok(raw),
            }
        })
        .await
    }

    async fn verify(
        &self,
        key_id: &str,
        algorithm: SignAlgorithm,
        payload: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<bool, BackendError> {
        let signature = match algorithm {
            SignAlgorithm::EcdsaP256Sha256 => match crypto::ecdsa_der_to_raw(&signature, crypto::P256_SCALAR_LEN) {
                Ok(raw) => raw,
                Err(_) => return Ok(false),
            },
            _ => signature,
        };
        let tbs = Self::to_be_signed(algorithm, payload);
        let label = key_id.to_string();
        self.run("C_Verify", key_id, move |session, handles| {
            let kind = ObjKind::Public(algorithm.key_type());
            handles.with_key(session, &label, kind, |key| {
                match session.verify(&Self::sign_mechanism(algorithm), key, &tbs, &signature) {
                    Ok(()) => Ok(true),
                    Err(CkError::Pkcs11(RvError::SignatureInvalid | RvError::SignatureLenRange, _)) => Ok(false),
                    Err(e) => Err(e).ck("C_Verify"),
                }
            })
        })
        .await
    }

    async fn public_key(&self, key_id: &str) -> Result<PublicKeyInfo, BackendError> {
        if let Some(pk) = self.public_keys.read().expect("pubkey cache").get(key_id) {
            return Ok(pk.clone());
        }
        let label = key_id.to_string();
        let pk = self
            .run("C_GetAttributeValue", key_id, move |session, handles| {
                // Determine the key type from the public key object present.
                for kt in [KeyType::EcP256, KeyType::Ed25519, KeyType::Rsa] {
                    match handles.find(session, &label, ObjKind::Public(kt)) {
                        Ok(handle) => {
                            let spki_der = objects::export_public_key(session, handle, kt)?;
                            return Ok(PublicKeyInfo {
                                key_id: label.clone(),
                                key_type: kt,
                                spki_der,
                            });
                        }
                        Err(OpError::Backend(
                            BackendError::KeyNotFound(_) | BackendError::UnsupportedOperation { .. },
                        )) => {}
                        Err(e) => return Err(e),
                    }
                }
                Err(handles
                    .find(session, &label, ObjKind::Secret)
                    .map(|_| {
                        OpError::Backend(BackendError::UnsupportedOperation {
                            key_id: label.clone(),
                            operation: "public key export",
                        })
                    })
                    .unwrap_or_else(|e| e))
            })
            .await?;
        self.public_keys
            .write()
            .expect("pubkey cache")
            .insert(key_id.to_string(), pk.clone());
        Ok(pk)
    }

    async fn encrypt(&self, key_id: &str, plaintext: Plaintext, aad: Vec<u8>) -> Result<AeadCiphertext, BackendError> {
        let label = key_id.to_string();
        self.run("C_Encrypt", key_id, move |session, handles| {
            handles.with_key(session, &label, ObjKind::Secret, |key| {
                Self::gcm_encrypt(session, key, &plaintext, &aad)
            })
        })
        .await
    }

    async fn decrypt(
        &self,
        key_id: &str,
        iv: Vec<u8>,
        ciphertext: Vec<u8>,
        aad: Vec<u8>,
    ) -> Result<Plaintext, BackendError> {
        check_gcm_input(&iv, &ciphertext)?;
        let label = key_id.to_string();
        self.run("C_Decrypt", key_id, move |session, handles| {
            handles.with_key(session, &label, ObjKind::Secret, |key| {
                Self::gcm_decrypt(session, key, &iv, &ciphertext, &aad)
            })
        })
        .await
    }

    async fn envelope_encrypt(
        &self,
        wrapping_key_id: &str,
        plaintext: Plaintext,
        aad: Vec<u8>,
    ) -> Result<Envelope, BackendError> {
        let label = wrapping_key_id.to_string();
        self.run("C_WrapKey", wrapping_key_id, move |session, handles| {
            handles.with_key(session, &label, ObjKind::Secret, |kek| {
                // 1. Ephemeral DEK generated inside the HSM as a session object.
                let dek = session
                    .generate_key(&Mechanism::AesKeyGen, &objects::ephemeral_dek_template())
                    .ck("C_GenerateKey")?;
                let _dek_guard = SessionObjectGuard { session, handle: dek };
                // 2. Encrypt the payload with the DEK, inside the HSM.
                let sealed = Self::gcm_encrypt(session, dek, &plaintext, &aad)?;
                // 3. Export the DEK only wrapped under the KEK (RFC 5649).
                let wrapped_key = session.wrap_key(&Mechanism::AesKeyWrapPad, kek, dek).ck("C_WrapKey")?;
                // 4. `_dek_guard` destroys the DEK object on return.
                Ok(Envelope {
                    wrapped_key,
                    iv: sealed.iv,
                    ciphertext: sealed.ciphertext,
                })
            })
        })
        .await
    }

    async fn envelope_decrypt(
        &self,
        wrapping_key_id: &str,
        envelope: Envelope,
        aad: Vec<u8>,
    ) -> Result<Plaintext, BackendError> {
        check_gcm_input(&envelope.iv, &envelope.ciphertext)?;
        if envelope.wrapped_key.len() < 16 || !envelope.wrapped_key.len().is_multiple_of(8) {
            return Err(BackendError::IntegrityCheckFailed);
        }
        let label = wrapping_key_id.to_string();
        self.run("C_UnwrapKey", wrapping_key_id, move |session, handles| {
            // Unwrap into the HSM as a non-extractable, decrypt-only session key.
            let dek = handles.with_key(session, &label, ObjKind::Secret, |kek| {
                session
                    .unwrap_key(
                        &Mechanism::AesKeyWrapPad,
                        kek,
                        &envelope.wrapped_key,
                        &objects::unwrapped_dek_template(),
                    )
                    .ck("C_UnwrapKey")
            })?;
            let _dek_guard = SessionObjectGuard { session, handle: dek };
            Self::gcm_decrypt(session, dek, &envelope.iv, &envelope.ciphertext, &aad)
        })
        .await
    }

    async fn list_keys(&self) -> Result<Vec<KeyDescriptor>, BackendError> {
        self.run("C_FindObjects", "*", move |session, _handles| {
            let mut out = Vec::new();
            for class in [ObjectClass::PRIVATE_KEY, ObjectClass::SECRET_KEY] {
                for handle in session.find_objects(&[Attribute::Class(class)]).ck("C_FindObjects")? {
                    let attrs = session
                        .get_attributes(
                            handle,
                            &[
                                AttributeType::Label,
                                AttributeType::Id,
                                AttributeType::KeyType,
                                AttributeType::Sign,
                                AttributeType::Wrap,
                                AttributeType::EcParams,
                            ],
                        )
                        .ck("C_GetAttributeValue")?;
                    let (mut label, mut id, mut ck_type, mut sign, mut wrap, mut ec_params) =
                        (String::new(), Vec::new(), None, false, false, Vec::new());
                    for a in attrs {
                        match a {
                            Attribute::Label(v) => label = String::from_utf8_lossy(&v).into_owned(),
                            Attribute::Id(v) => id = v,
                            Attribute::KeyType(t) => ck_type = Some(t),
                            Attribute::Sign(v) => sign = v,
                            Attribute::Wrap(v) => wrap = v,
                            Attribute::EcParams(v) => ec_params = v,
                            _ => {}
                        }
                    }
                    let key_type = match ck_type {
                        Some(t) if t == cryptoki::object::KeyType::EC && ec_params == crypto::P256_EC_PARAMS => {
                            KeyType::EcP256
                        }
                        Some(t) if t == cryptoki::object::KeyType::EC_EDWARDS => KeyType::Ed25519,
                        Some(t) if t == cryptoki::object::KeyType::RSA => KeyType::Rsa,
                        Some(t) if t == cryptoki::object::KeyType::AES => KeyType::Aes256,
                        _ => continue, // not a key type this service handles
                    };
                    let usage = match (sign, wrap) {
                        (true, _) => KeyUsage::Sign,
                        (false, true) => KeyUsage::WrapUnwrap,
                        (false, false) => KeyUsage::EncryptDecrypt,
                    };
                    out.push(KeyDescriptor {
                        key_id: label,
                        key_type,
                        usage,
                        object_id: id.iter().map(|b| format!("{b:02x}")).collect(),
                        attributes: objects::read_key_attributes(session, handle)?,
                    });
                }
            }
            out.sort_by(|a, b| a.key_id.cmp(&b.key_id));
            Ok(out)
        })
        .await
    }

    async fn health_check(&self) -> Result<(), BackendError> {
        self.run("C_GetSessionInfo", "-", |session, _| {
            let info = session.get_session_info().ck("C_GetSessionInfo")?;
            use cryptoki::session::SessionState;
            match info.session_state() {
                SessionState::RoUser | SessionState::RwUser => Ok(()),
                state => Err(OpError::Pkcs11 {
                    function: "C_GetSessionInfo",
                    err: CkError::Pkcs11(RvError::UserNotLoggedIn, cryptoki::context::Function::GetSessionInfo),
                })
                .inspect_err(|_| tracing::warn!(?state, "pooled session is not logged in")),
            }
        })
        .await
    }
}
