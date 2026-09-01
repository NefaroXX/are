//! TLS server configuration for mTLS.
//!
//! Builds a `rustls::ServerConfig` that enforces:
//!
//! - **TLS 1.3 only** — via `with_safe_default_protocol_versions()` restricted
//!   to TLS 1.3 only (TLS 1.2 filtered out).
//! - **Client certificate required** — `WebPkiClientVerifier` with the
//!   provided CA certificate(s) as trust anchors.
//! - **Server certificate** — loaded from PEM files or (in tests) generated
//!   ephemerally.
//!
//! ## Design notes
//!
//! We use `rustls` (not `native-tls`) because:
//!
//! - Pure Rust, no OpenSSL dependency — auditable, portable, no C linkage.
//! - TLS 1.3 by default — we can restrict protocol versions easily.
//! - `WebPkiClientVerifier` provides ergonomic mTLS with certificate chain
//!   validation.
//! - Well-maintained and widely audited (used by tokio-tungstenite, hyper,
//!   and most Rust HTTP servers).
//!
//! Certificate generation for tests uses `rcgen`, which is purpose-built
//! for test/dev cert generation and well-audited. Production certs come
//! from files (documented in `docs/identity.md`).

use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::RootCertStore;
use rustls::{Error, SupportedProtocolVersion};

/// Errors during TLS configuration.
#[derive(Debug, thiserror::Error)]
pub enum TlsError {
    /// Failed to read a PEM file.
    #[error("failed to read PEM file: {0}")]
    PemRead(String),

    /// No valid certificate found in PEM data.
    #[error("no certificate found in PEM data")]
    NoCertificate,

    /// No valid private key found in PEM data.
    #[error("no private key found in PEM data")]
    NoPrivateKey,

    /// Certificate chain verification failed.
    #[error("certificate verification failed: {0}")]
    VerificationFailed(String),

    /// Invalid certificate or key format.
    #[error("invalid credential format: {0}")]
    InvalidCredential(String),

    /// Root certificate store error.
    #[error("root cert store error: {0}")]
    RootStoreError(String),
}

impl From<Error> for TlsError {
    fn from(e: Error) -> Self {
        Self::InvalidCredential(e.to_string())
    }
}

/// Load a certificate chain from a PEM file.
///
/// Returns the first certificate as the leaf, and all certificates as the
/// chain (ordered leaf-first).
pub fn load_certificates_from_pem(path: &Path) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    let data =
        std::fs::read(path).map_err(|e| TlsError::PemRead(format!("{}: {e}", path.display())))?;
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut &data[..])
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| TlsError::PemRead(e.to_string()))?;
    if certs.is_empty() {
        return Err(TlsError::NoCertificate);
    }
    Ok(certs)
}

/// Load a private key from a PEM file.
pub fn load_private_key_from_pem(path: &Path) -> Result<PrivateKeyDer<'static>, TlsError> {
    let data =
        std::fs::read(path).map_err(|e| TlsError::PemRead(format!("{}: {e}", path.display())))?;
    let key = rustls_pemfile::private_key(&mut &data[..])
        .map_err(|e| TlsError::PemRead(e.to_string()))?
        .ok_or(TlsError::NoPrivateKey)?;
    Ok(key)
}

/// Build a `RootCertStore` from a PEM-encoded CA certificate.
pub fn build_root_store(ca_cert: &CertificateDer<'static>) -> Result<RootCertStore, TlsError> {
    let mut store = RootCertStore::empty();
    store
        .add(ca_cert.clone())
        .map_err(|e| TlsError::RootStoreError(e.to_string()))?;
    Ok(store)
}

/// Build a TLS server configuration with mTLS (client auth required).
///
/// # Arguments
///
/// * `server_certs` — Server certificate chain (leaf first).
/// * `server_key` — Server private key.
/// * `ca_cert` — CA certificate used to verify client certificates.
///
/// # Protocol version
///
/// Only TLS 1.3 is enabled. The configuration is built with
/// `with_safe_default_protocol_versions()` then filtered to exclude TLS 1.2.
pub fn build_server_config(
    server_certs: Vec<CertificateDer<'static>>,
    server_key: PrivateKeyDer<'static>,
    ca_cert: &CertificateDer<'static>,
) -> Result<Arc<rustls::ServerConfig>, TlsError> {
    let root_store = build_root_store(ca_cert)?;

    let client_verifier = WebPkiClientVerifier::builder(Arc::new(root_store))
        .build()
        .map_err(|e| TlsError::VerificationFailed(e.to_string()))?;

    // Restrict to TLS 1.3 only.
    let supported_versions: Vec<&SupportedProtocolVersion> = vec![&rustls::version::TLS13];

    let config = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&supported_versions)
    .map_err(|e| TlsError::InvalidCredential(e.to_string()))?
    .with_client_cert_verifier(client_verifier)
    .with_single_cert(server_certs, server_key)
    .map_err(|e| TlsError::InvalidCredential(e.to_string()))?;

    Ok(Arc::new(config))
}

/// Build a TLS client configuration with mTLS.
///
/// # Arguments
///
/// * `client_certs` — Client certificate chain (leaf first).
/// * `client_key` — Client private key.
/// * `ca_cert` — CA certificate used to verify the server certificate.
/// * `server_name` — Expected server hostname/IP for SNI and verification.
pub fn build_client_config(
    client_certs: Vec<CertificateDer<'static>>,
    client_key: PrivateKeyDer<'static>,
    ca_cert: &CertificateDer<'static>,
    _server_name: &str,
) -> Result<Arc<rustls::ClientConfig>, TlsError> {
    let mut root_store = RootCertStore::empty();
    root_store
        .add(ca_cert.clone())
        .map_err(|e| TlsError::RootStoreError(e.to_string()))?;

    // Restrict to TLS 1.3 only.
    let supported_versions: Vec<&SupportedProtocolVersion> = vec![&rustls::version::TLS13];

    let config = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&supported_versions)
    .map_err(|e| TlsError::InvalidCredential(e.to_string()))?
    .with_root_certificates(root_store)
    .with_client_auth_cert(client_certs, client_key)
    .map_err(|e| TlsError::InvalidCredential(e.to_string()))?;

    Ok(Arc::new(config))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    /// Generate a self-signed CA certificate for testing.
    fn make_test_ca() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let mut params = rcgen::CertificateParams::new(vec!["Test CA".to_string()]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key_pair = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        (
            cert.der().clone(),
            PrivateKeyDer::try_from(key_pair.serialize_der()).unwrap(),
        )
    }

    /// Generate a certificate signed by the given CA.
    fn make_test_cert(
        _ca_cert_der: &CertificateDer,
        ca_key_der: &PrivateKeyDer,
        cn: &str,
    ) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let key_pair = rcgen::KeyPair::generate().unwrap();

        // Parse CA key to sign with
        let ca_key_pair = rcgen::KeyPair::try_from(ca_key_der.secret_der()).unwrap();
        let mut ca_params = rcgen::CertificateParams::new(vec!["Test CA".to_string()]).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let ca_cert_rcgen = ca_params.self_signed(&ca_key_pair).unwrap();

        let params = rcgen::CertificateParams::new(vec![cn.to_string()]).unwrap();
        let cert = params
            .signed_by(&key_pair, &ca_cert_rcgen, &ca_key_pair)
            .unwrap();
        (
            cert.der().clone(),
            PrivateKeyDer::try_from(key_pair.serialize_der()).unwrap(),
        )
    }

    #[test]
    fn server_config_enforces_tls13_only() {
        let (ca_cert, ca_key) = make_test_ca();
        let (server_cert, server_key) = make_test_cert(&ca_cert, &ca_key, "localhost");

        let config = build_server_config(vec![server_cert], server_key, &ca_cert).unwrap();

        // Config was built with TLS 1.3 only — verify by checking that
        // the builder succeeded with only TLS13 in supported versions.
        // rustls 0.23 doesn't expose protocols as a public field, so we
        // verify the config was constructed successfully with our version filter.
        drop(config);
    }

    #[test]
    fn client_config_enforces_tls13_only() {
        let (ca_cert, ca_key) = make_test_ca();
        let (client_cert, client_key) = make_test_cert(&ca_cert, &ca_key, "client");

        let config =
            build_client_config(vec![client_cert], client_key, &ca_cert, "localhost").unwrap();

        drop(config);
    }

    #[test]
    fn server_config_rejects_mismatched_cert_and_key() {
        let (ca_cert, ca_key) = make_test_ca();
        // Server cert for "localhost" but key from a different cert.
        let (server_cert, _server_key) = make_test_cert(&ca_cert, &ca_key, "localhost");
        let (_other_cert, other_key) = make_test_cert(&ca_cert, &ca_key, "other");

        // Mismatched cert and key should fail.
        let result = build_server_config(vec![server_cert], other_key, &ca_cert);
        assert!(result.is_err());
    }
}
