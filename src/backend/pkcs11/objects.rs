//! PKCS#11 object templates, lookup and provisioning.

use std::{collections::HashMap, sync::RwLock};

use cryptoki::{
    error::{Error as CkError, RvError},
    mechanism::Mechanism,
    object::{Attribute, AttributeType, KeyType as CkKeyType, ObjectClass, ObjectHandle},
    session::Session,
};

use super::OpError;
use crate::{
    backend::{BackendError, KeyAttributes, KeyType, KeyUsage},
    crypto,
    keys::{KeySpec, RSA_MODULUS_BITS},
};

/// Which PKCS#11 object of a key we are looking for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ObjKind {
    Private(KeyType),
    Public(KeyType),
    Secret,
}

impl ObjKind {
    fn class(self) -> ObjectClass {
        match self {
            Self::Private(_) => ObjectClass::PRIVATE_KEY,
            Self::Public(_) => ObjectClass::PUBLIC_KEY,
            Self::Secret => ObjectClass::SECRET_KEY,
        }
    }

    fn key_type(self) -> CkKeyType {
        match self {
            Self::Private(kt) | Self::Public(kt) => ck_key_type(kt),
            Self::Secret => CkKeyType::AES,
        }
    }

    /// Search template: label + class + key type.
    fn template(self, label: &str) -> Vec<Attribute> {
        vec![
            Attribute::Class(self.class()),
            Attribute::KeyType(self.key_type()),
            Attribute::Label(label.as_bytes().to_vec()),
        ]
    }
}

fn ck_key_type(kt: KeyType) -> CkKeyType {
    match kt {
        KeyType::EcP256 => CkKeyType::EC,
        KeyType::Ed25519 => CkKeyType::EC_EDWARDS,
        KeyType::Rsa => CkKeyType::RSA,
        KeyType::Aes256 => CkKeyType::AES,
    }
}

/// Wrap a cryptoki result with the PKCS#11 function name for diagnostics.
pub trait CkContext<T> {
    fn ck(self, function: &'static str) -> Result<T, OpError>;
}

impl<T> CkContext<T> for Result<T, CkError> {
    fn ck(self, function: &'static str) -> Result<T, OpError> {
        self.map_err(|err| OpError::Pkcs11 { function, err })
    }
}

/// Cache of `(label, kind) → object handle`.
///
/// Token-object handles are valid across all sessions of the application, so
/// one lookup serves every pooled session. Entries are evicted when the token
/// reports `CKR_OBJECT_HANDLE_INVALID` / `CKR_KEY_HANDLE_INVALID` (e.g. key
/// deleted and re-created by an operator) and looked up again.
#[derive(Default)]
pub struct HandleCache {
    map: RwLock<HashMap<(String, ObjKind), ObjectHandle>>,
}

impl HandleCache {
    fn get(&self, label: &str, kind: ObjKind) -> Option<ObjectHandle> {
        self.map
            .read()
            .expect("handle cache lock")
            .get(&(label.to_string(), kind))
            .copied()
    }

    fn insert(&self, label: &str, kind: ObjKind, handle: ObjectHandle) {
        self.map
            .write()
            .expect("handle cache lock")
            .insert((label.to_string(), kind), handle);
    }

    fn evict(&self, label: &str, kind: ObjKind) {
        self.map
            .write()
            .expect("handle cache lock")
            .remove(&(label.to_string(), kind));
    }

    pub fn clear(&self) {
        self.map.write().expect("handle cache lock").clear();
    }

    /// Find a key object, using the cache when possible.
    pub fn find(&self, session: &Session, label: &str, kind: ObjKind) -> Result<ObjectHandle, OpError> {
        if let Some(handle) = self.get(label, kind) {
            return Ok(handle);
        }
        let handle = find_unique(session, label, kind)?.ok_or_else(|| not_found_error(session, label, kind))?;
        if let ObjKind::Private(KeyType::EcP256) = kind {
            // CKK_EC covers every curve: make sure this one really is P-256.
            let params = get_bytes(session, handle, AttributeType::EcParams)?;
            if params != crypto::P256_EC_PARAMS {
                return Err(OpError::Backend(BackendError::KeyAlgorithmMismatch {
                    key_id: label.to_string(),
                    algorithm: "ECDSA_P256_SHA256".into(),
                }));
            }
        }
        self.insert(label, kind, handle);
        Ok(handle)
    }

    /// Run `op` with the key's handle; if the cached handle turned out to be
    /// stale, evict it, look the key up again and retry once.
    pub fn with_key<T>(
        &self,
        session: &Session,
        label: &str,
        kind: ObjKind,
        mut op: impl FnMut(ObjectHandle) -> Result<T, OpError>,
    ) -> Result<T, OpError> {
        let handle = self.find(session, label, kind)?;
        match op(handle) {
            Err(OpError::Pkcs11 {
                err:
                    CkError::Pkcs11(
                        RvError::ObjectHandleInvalid
                        | RvError::KeyHandleInvalid
                        | RvError::WrappingKeyHandleInvalid
                        | RvError::UnwrappingKeyHandleInvalid,
                        _,
                    ),
                ..
            }) => {
                tracing::info!(key_id = label, "cached key handle is stale; looking the key up again");
                self.evict(label, kind);
                let handle = self.find(session, label, kind)?;
                op(handle)
            }
            other => other,
        }
    }
}

fn find_unique(session: &Session, label: &str, kind: ObjKind) -> Result<Option<ObjectHandle>, OpError> {
    let handles = session.find_objects(&kind.template(label)).ck("C_FindObjects")?;
    match handles.as_slice() {
        [] => Ok(None),
        [one] => Ok(Some(*one)),
        _ => Err(OpError::Backend(BackendError::Internal(format!(
            "{} objects match label `{label}` ({kind:?}); refusing to guess",
            handles.len()
        )))),
    }
}

/// Distinguish "no such key" from "key exists but is the wrong type".
///
/// Private objects are invisible without a logged-in user, so if the login
/// state was lost (HSM restart, `C_Logout`, ...) a missing key is reported as
/// `CKR_USER_NOT_LOGGED_IN` instead, which makes the pool recycle the session
/// and log in again rather than answering 404.
fn not_found_error(session: &Session, label: &str, kind: ObjKind) -> OpError {
    use cryptoki::session::SessionState;
    if let Ok(info) = session.get_session_info()
        && !matches!(info.session_state(), SessionState::RoUser | SessionState::RwUser)
    {
        return OpError::Pkcs11 {
            function: "C_FindObjects",
            err: CkError::Pkcs11(RvError::UserNotLoggedIn, cryptoki::context::Function::FindObjects),
        };
    }
    let exists = session
        .find_objects(&[Attribute::Label(label.as_bytes().to_vec())])
        .map(|h| !h.is_empty())
        .unwrap_or(false);
    let err = match (exists, kind) {
        (false, _) => BackendError::KeyNotFound(label.to_string()),
        (true, ObjKind::Private(kt)) => BackendError::KeyAlgorithmMismatch {
            key_id: label.to_string(),
            algorithm: crate::backend::SignAlgorithm::ALL
                .into_iter()
                .find(|a| a.key_type() == kt)
                .map_or_else(|| format!("{kt:?}"), |a| a.to_string()),
        },
        (true, ObjKind::Public(_)) => BackendError::UnsupportedOperation {
            key_id: label.to_string(),
            operation: "public key export",
        },
        (true, ObjKind::Secret) => BackendError::UnsupportedOperation {
            key_id: label.to_string(),
            operation: "symmetric encryption / wrapping",
        },
    };
    OpError::Backend(err)
}

pub fn get_bytes(session: &Session, handle: ObjectHandle, attr: AttributeType) -> Result<Vec<u8>, OpError> {
    let attrs = session.get_attributes(handle, &[attr]).ck("C_GetAttributeValue")?;
    attrs
        .into_iter()
        .find_map(|a| match a {
            Attribute::EcPoint(v)
            | Attribute::EcParams(v)
            | Attribute::Modulus(v)
            | Attribute::PublicExponent(v)
            | Attribute::Label(v)
            | Attribute::Id(v)
            | Attribute::Value(v) => Some(v),
            _ => None,
        })
        .ok_or_else(|| OpError::Backend(BackendError::Internal(format!("attribute {attr:?} not available"))))
}

/// Read the security-relevant boolean attributes of a key object.
pub fn read_key_attributes(session: &Session, handle: ObjectHandle) -> Result<KeyAttributes, OpError> {
    let attrs = session
        .get_attributes(
            handle,
            &[
                AttributeType::Token,
                AttributeType::Private,
                AttributeType::Sensitive,
                AttributeType::Extractable,
                AttributeType::AlwaysSensitive,
                AttributeType::NeverExtractable,
            ],
        )
        .ck("C_GetAttributeValue")?;
    let mut out = KeyAttributes {
        token: false,
        private: false,
        sensitive: false,
        extractable: true,
        always_sensitive: false,
        never_extractable: false,
    };
    for a in attrs {
        match a {
            Attribute::Token(v) => out.token = v,
            Attribute::Private(v) => out.private = v,
            Attribute::Sensitive(v) => out.sensitive = v,
            Attribute::Extractable(v) => out.extractable = v,
            Attribute::AlwaysSensitive(v) => out.always_sensitive = v,
            Attribute::NeverExtractable(v) => out.never_extractable = v,
            _ => {}
        }
    }
    Ok(out)
}

/// Build the SPKI of a key pair's public half.
pub fn export_public_key(session: &Session, handle: ObjectHandle, key_type: KeyType) -> Result<Vec<u8>, OpError> {
    let enc = |e: crypto::EncodingError| OpError::Backend(BackendError::Internal(e.to_string()));
    match key_type {
        KeyType::EcP256 => {
            let point = get_bytes(session, handle, AttributeType::EcPoint)?;
            crypto::p256_spki_from_point(crypto::unwrap_ec_point(&point, 65).map_err(enc)?).map_err(enc)
        }
        KeyType::Ed25519 => {
            let point = get_bytes(session, handle, AttributeType::EcPoint)?;
            crypto::ed25519_spki_from_bytes(crypto::unwrap_ec_point(&point, 32).map_err(enc)?).map_err(enc)
        }
        KeyType::Rsa => {
            let n = get_bytes(session, handle, AttributeType::Modulus)?;
            let e = get_bytes(session, handle, AttributeType::PublicExponent)?;
            crypto::rsa_spki_from_components(&n, &e).map_err(enc)
        }
        KeyType::Aes256 => Err(OpError::Backend(BackendError::Internal(
            "AES keys have no public key".into(),
        ))),
    }
}

/// Attributes shared by every long-term private / secret key we create.
///
/// * `CKA_TOKEN`       — persistent object stored in the token.
/// * `CKA_PRIVATE`     — only visible after `C_Login`.
/// * `CKA_SENSITIVE`   — value can never be read in plaintext.
/// * `CKA_EXTRACTABLE` — false: cannot even be exported *wrapped*.
///   Once false it can never be set back to true (PKCS#11 §4.4).
fn protected_key_attributes(spec: &KeySpec) -> Vec<Attribute> {
    vec![
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Label(spec.label.as_bytes().to_vec()),
        Attribute::Id(spec.object_id()),
    ]
}

/// Templates for a non-exportable key pair. Returns (mechanism, public, private).
pub fn key_pair_templates(spec: &KeySpec) -> (Mechanism<'static>, Vec<Attribute>, Vec<Attribute>) {
    let mut public = vec![
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::Verify(true),
        Attribute::Label(spec.label.as_bytes().to_vec()),
        Attribute::Id(spec.object_id()),
    ];
    let mut private = protected_key_attributes(spec);
    private.extend([
        Attribute::Sign(true),
        Attribute::Decrypt(false),
        Attribute::Unwrap(false),
    ]);
    let mechanism = match spec.key_type {
        KeyType::EcP256 => {
            public.push(Attribute::EcParams(crypto::P256_EC_PARAMS.to_vec()));
            private.push(Attribute::Derive(false));
            Mechanism::EccKeyPairGen
        }
        KeyType::Ed25519 => {
            public.push(Attribute::EcParams(crypto::ED25519_EC_PARAMS_OID.to_vec()));
            private.push(Attribute::Derive(false));
            Mechanism::EccEdwardsKeyPairGen
        }
        KeyType::Rsa => {
            public.extend([
                Attribute::ModulusBits(RSA_MODULUS_BITS.into()),
                Attribute::PublicExponent(vec![0x01, 0x00, 0x01]),
                Attribute::Encrypt(false),
            ]);
            Mechanism::RsaPkcsKeyPairGen
        }
        KeyType::Aes256 => unreachable!("AES keys are not key pairs"),
    };
    (mechanism, public, private)
}

/// Template for a non-exportable AES-256 key with the given usage.
pub fn aes_key_template(spec: &KeySpec) -> Vec<Attribute> {
    let mut t = protected_key_attributes(spec);
    let (crypt, wrap) = match spec.usage {
        KeyUsage::EncryptDecrypt => (true, false),
        KeyUsage::WrapUnwrap => (false, true),
        KeyUsage::Sign => (false, false),
    };
    t.extend([
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(CkKeyType::AES),
        Attribute::ValueLen(32.into()),
        Attribute::Encrypt(crypt),
        Attribute::Decrypt(crypt),
        Attribute::Wrap(wrap),
        Attribute::Unwrap(wrap),
        Attribute::Sign(false),
        Attribute::Verify(false),
        Attribute::Derive(false),
    ]);
    t
}

/// Template for an *ephemeral* data-encryption key generated for envelope
/// encryption: a session object (destroyed with the session or explicitly),
/// sensitive, and extractable **only** so it can be wrapped once.
pub fn ephemeral_dek_template() -> Vec<Attribute> {
    vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(CkKeyType::AES),
        Attribute::ValueLen(32.into()),
        Attribute::Token(false),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(true),
        Attribute::Encrypt(true),
        Attribute::Decrypt(false),
    ]
}

/// Template for a DEK unwrapped back into the HSM: session object,
/// sensitive, **non-extractable**, decrypt-only.
pub fn unwrapped_dek_template() -> Vec<Attribute> {
    vec![
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(CkKeyType::AES),
        Attribute::Token(false),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Extractable(false),
        Attribute::Encrypt(false),
        Attribute::Decrypt(true),
    ]
}

/// Result of provisioning one key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvisionOutcome {
    Created,
    AlreadyPresent,
}

/// Create `spec` in the token unless it already exists. Requires a R/W,
/// logged-in session. Idempotent.
pub fn provision_key(session: &Session, spec: &KeySpec) -> Result<ProvisionOutcome, OpError> {
    let lookup = match spec.key_type {
        KeyType::Aes256 => ObjKind::Secret,
        kt => ObjKind::Private(kt),
    };
    if find_unique(session, &spec.label, lookup)?.is_some() {
        if lookup != ObjKind::Secret && find_unique(session, &spec.label, ObjKind::Public(spec.key_type))?.is_none() {
            tracing::warn!(key_id = %spec.label, "private key present but public key object missing");
        }
        return Ok(ProvisionOutcome::AlreadyPresent);
    }
    if !session
        .find_objects(&[Attribute::Label(spec.label.as_bytes().to_vec())])
        .ck("C_FindObjects")?
        .is_empty()
    {
        return Err(OpError::Backend(BackendError::Internal(format!(
            "label `{}` is already used by an object of a different type",
            spec.label
        ))));
    }
    match spec.key_type {
        KeyType::Aes256 => {
            session
                .generate_key(&Mechanism::AesKeyGen, &aes_key_template(spec))
                .ck("C_GenerateKey")?;
        }
        _ => {
            let (mechanism, public, private) = key_pair_templates(spec);
            session
                .generate_key_pair(&mechanism, &public, &private)
                .ck("C_GenerateKeyPair")?;
        }
    }
    Ok(ProvisionOutcome::Created)
}
