//! HSM-backed signing and key-management service.
//!
//! Module map:
//!
//! | module        | responsibility                                              |
//! |---------------|-------------------------------------------------------------|
//! | [`config`]    | environment-driven configuration (PIN via file/env)         |
//! | [`error`]     | domain errors and their HTTP mapping                        |
//! | [`backend`]   | `KeyBackend` trait, PKCS#11 + mock implementations          |
//! | [`keys`]      | key catalog: labels, CKA_IDs, key types, usages             |
//! | [`crypto`]    | DER/SPKI encoding and software signature verification       |
//! | [`api`]       | Axum router and handlers                                    |
//! | [`metrics`]   | Prometheus metrics                                          |
//! | [`telemetry`] | structured logging, tracing spans, optional OTLP export     |

pub mod api;
pub mod backend;
pub mod config;
pub mod crypto;
pub mod error;
pub mod keys;
pub mod metrics;
pub mod telemetry;
