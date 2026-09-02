//! Secure client connection and RPC methods.
//!
//! `SecureClient` establishes a TLS 1.3 mTLS connection to a daemon and
//! provides typed RPC methods. For Gate 3, the only method is
//! `get_environment_info`.

use std::path::Path;
use std::sync::Arc;

use are_core::{
    EnvironmentId, GetEnvironmentInfoRequest, GetEnvironmentInfoResponse, RpcRequest, RpcResponse,
    RpcResponsePayload,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use tokio::io;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::framing;
use crate::tls::{self, ClientTlsError};

/// Errors during client operations.
#[derive(Debug, thiserror::Error)]
pub enum ConnectionError {
    /// TLS configuration or handshake failed.
    #[error("TLS error: {0}")]
    Tls(#[from] ClientTlsError),

    /// TCP connection failed.
    #[error("connection failed: {0}")]
    Tcp(#[from] std::io::Error),

    /// The daemon rejected the request.
    #[error("request failed: {0}")]
    RequestFailed(String),

    /// The server returned an RPC-level error.
    #[error("RPC error: {0}")]
    RpcError(String),

    /// The response type did not match expectations.
    #[error("unexpected response type")]
    UnexpectedResponse,
}

/// A secure client for connecting to an ARE daemon.
///
/// Uses TLS 1.3 mTLS for authentication and length-prefixed JSON for
/// framing. The client loads certificates from PEM files.
pub struct SecureClient {
    tls_config: Arc<rustls::ClientConfig>,
    server_name: ServerName<'static>,
    server_addr: String,
}

impl SecureClient {
    /// Create a new `SecureClient` from PEM file paths.
    pub fn from_pem_files(
        client_cert_path: &Path,
        client_key_path: &Path,
        ca_cert_path: &Path,
        server_addr: &str,
        server_name: &str,
    ) -> Result<Self, ConnectionError> {
        let client_certs = tls::load_client_certificates(client_cert_path)?;
        let client_key = tls::load_client_key(client_key_path)?;
        let ca_data = std::fs::read_to_string(ca_cert_path)
            .map_err(|e| ClientTlsError::PemRead(format!("{}: {e}", ca_cert_path.display())))?;
        let ca_cert = rustls_pemfile::certs(&mut ca_data.as_bytes())
            .next()
            .ok_or(ClientTlsError::NoCertificate)?
            .map_err(|e| ClientTlsError::PemRead(e.to_string()))?;

        Self::new(client_certs, client_key, ca_cert, server_addr, server_name)
    }

    /// Create a new `SecureClient` from in-memory credentials.
    pub fn new(
        client_certs: Vec<CertificateDer<'static>>,
        client_key: PrivateKeyDer<'static>,
        ca_cert: CertificateDer<'static>,
        server_addr: &str,
        server_name: &str,
    ) -> Result<Self, ConnectionError> {
        let (tls_config, sn) =
            tls::build_client_config(client_certs, client_key, &ca_cert, server_name)?;

        Ok(Self {
            tls_config,
            server_name: sn,
            server_addr: server_addr.to_string(),
        })
    }

    /// Connect to the daemon, send a `GetEnvironmentInfo` request, and
    /// return the response.
    ///
    /// This is the primary Gate 3 method. It establishes a fresh TLS
    /// connection per call — persistent connections are deferred to later
    /// gates.
    pub async fn get_environment_info(
        &self,
        environment_id: &EnvironmentId,
    ) -> Result<GetEnvironmentInfoResponse, ConnectionError> {
        let response = self
            .send_rpc(RpcRequest::GetEnvironmentInfo(GetEnvironmentInfoRequest {
                environment_id: environment_id.clone(),
            }))
            .await?;

        match response.result {
            Ok(RpcResponsePayload::GetEnvironmentInfo(info)) => Ok(info),
            Err(e) => Err(ConnectionError::RpcError(e.to_string())),
            _ => Err(ConnectionError::UnexpectedResponse),
        }
    }

    /// Read a file from the remote environment.
    pub async fn read_file(
        &self,
        req: are_core::ReadFileRequest,
    ) -> Result<are_core::ReadFileResponse, ConnectionError> {
        let response = self.send_rpc(RpcRequest::ReadFile(req)).await?;

        match response.result {
            Ok(RpcResponsePayload::ReadFile(resp)) => Ok(resp),
            Err(e) => Err(ConnectionError::RpcError(e.to_string())),
            _ => Err(ConnectionError::UnexpectedResponse),
        }
    }

    /// List the contents of a remote directory.
    pub async fn list_directory(
        &self,
        req: are_core::ListDirectoryRequest,
    ) -> Result<are_core::ListDirectoryResponse, ConnectionError> {
        let response = self.send_rpc(RpcRequest::ListDirectory(req)).await?;

        match response.result {
            Ok(RpcResponsePayload::ListDirectory(resp)) => Ok(resp),
            Err(e) => Err(ConnectionError::RpcError(e.to_string())),
            _ => Err(ConnectionError::UnexpectedResponse),
        }
    }

    /// Get metadata about a file or directory in the remote environment.
    pub async fn file_metadata(
        &self,
        req: are_core::GetFileMetadataRequest,
    ) -> Result<are_core::GetFileMetadataResponse, ConnectionError> {
        let response = self.send_rpc(RpcRequest::GetFileMetadata(req)).await?;

        match response.result {
            Ok(RpcResponsePayload::GetFileMetadata(resp)) => Ok(resp),
            Err(e) => Err(ConnectionError::RpcError(e.to_string())),
            _ => Err(ConnectionError::UnexpectedResponse),
        }
    }

    /// Send an RPC request and return the response.
    async fn send_rpc(&self, request: RpcRequest) -> Result<RpcResponse, ConnectionError> {
        // Establish TCP connection.
        let tcp = TcpStream::connect(&self.server_addr).await?;

        // TLS handshake with mTLS.
        let connector = TlsConnector::from(Arc::clone(&self.tls_config));
        let tls_stream = connector
            .connect(self.server_name.clone(), tcp)
            .await
            .map_err(|e| ClientTlsError::ConfigError(format!("TLS handshake failed: {e}")))?;

        // Split into independent read/write halves.
        let (read_half, write_half) = io::split(tls_stream);
        let mut reader = io::BufReader::new(read_half);
        let mut writer = io::BufWriter::new(write_half);

        framing::write_message(&mut writer, &request).await?;
        Ok(framing::read_message(&mut reader).await?)
    }
}
