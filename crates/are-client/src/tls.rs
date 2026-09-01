//! TLS client configuration for mTLS.
//!
//! Builds a `rustls::ClientConfig` that enforces:
//!
//! - **TLS 1.3 only** — same protocol restriction as the server.
//! - **Server certificate verification** — validates against the provided
//!   CA certificate.
//! - **Client certificate** — presented for mutual authentication.
//!
//! See `are-daemon/src/tls.rs` for the design rationale (rustls choice,
//! protocol version enforcement).

use std::path::Path;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::RootCertStore;
use rustls::SupportedProtocolVersion;

/// Errors during client TLS configuration.
#[derive(Debug, thiserror::Error)]
pub enum ClientTlsError {
    /// Failed to read a PEM file.
    #[error("failed to read PEM file: {0}")]
    PemRead(String),

    /// No valid certificate found in PEM data.
    #[error("no certificate found in PEM data")]
    NoCertificate,

    /// No valid private key found in PEM data.
    #[error("no private key found in PEM data")]
    NoPrivateKey,

    /// Invalid server name.
    #[error("invalid server name: {0}")]
    InvalidServerName(String),

    /// TLS configuration error.
    #[error("TLS config error: {0}")]
    ConfigError(String),
}

/// Load client certificates from a PEM file.
pub fn load_client_certificates(
    path: &Path,
) -> Result<Vec<CertificateDer<'static>>, ClientTlsError> {
    let data = std::fs::read(path)
        .map_err(|e| ClientTlsError::PemRead(format!("{}: {e}", path.display())))?;
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut &data[..])
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| ClientTlsError::PemRead(e.to_string()))?;
    if certs.is_empty() {
        return Err(ClientTlsError::NoCertificate);
    }
    Ok(certs)
}

/// Load a client private key from a PEM file.
pub fn load_client_key(path: &Path) -> Result<PrivateKeyDer<'static>, ClientTlsError> {
    let data = std::fs::read(path)
        .map_err(|e| ClientTlsError::PemRead(format!("{}: {e}", path.display())))?;
    let key = rustls_pemfile::private_key(&mut &data[..])
        .map_err(|e| ClientTlsError::PemRead(e.to_string()))?
        .ok_or(ClientTlsError::NoPrivateKey)?;
    Ok(key)
}

/// Build a client TLS configuration with mTLS.
///
/// # Arguments
///
/// * `client_certs` — Client certificate chain (leaf first).
/// * `client_key` — Client private key.
/// * `ca_cert` — CA certificate for verifying the server.
/// * `server_name` — Expected server hostname/IP for SNI.
pub fn build_client_config(
    client_certs: Vec<CertificateDer<'static>>,
    client_key: PrivateKeyDer<'static>,
    ca_cert: &CertificateDer<'static>,
    server_name: &str,
) -> Result<(Arc<rustls::ClientConfig>, ServerName<'static>), ClientTlsError> {
    let mut root_store = RootCertStore::empty();
    root_store
        .add(ca_cert.clone())
        .map_err(|e| ClientTlsError::ConfigError(e.to_string()))?;

    let server_name = ServerName::try_from(server_name.to_string())
        .map_err(|e| ClientTlsError::InvalidServerName(e.to_string()))?;

    // Restrict to TLS 1.3 only.
    let supported_versions: Vec<&SupportedProtocolVersion> = vec![&rustls::version::TLS13];

    let config = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&supported_versions)
    .map_err(|e| ClientTlsError::ConfigError(e.to_string()))?
    .with_root_certificates(root_store)
    .with_client_auth_cert(client_certs, client_key)
    .map_err(|e| ClientTlsError::ConfigError(e.to_string()))?;

    Ok((Arc::new(config), server_name))
}
