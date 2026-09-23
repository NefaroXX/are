//! Error types for the agent adapter.

use are_core::RpcError;
use are_client::ConnectionError;
use std::io;
use thiserror::Error;

/// Errors that can occur when using the agent adapter.
#[derive(Debug, Error)]
pub enum AgentAdapterError {
    /// Connection to the daemon failed.
    #[error("connection failed: {0}")]
    Connection(#[from] ConnectionError),

    /// RPC request was rejected by the daemon.
    #[error("RPC error: {0}")]
    Rpc(#[from] RpcError),

    /// I/O error (local file read for upload, etc.)
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    /// Session not found.
    #[error("session not found: {0}")]
    SessionNotFound(String),

    /// Process not found.
    #[error("process not found: {0}")]
    ProcessNotFound(String),

    /// The environment doesn't support the requested capability.
    #[error("capability not available: {0}")]
    CapabilityNotAvailable(String),

    /// Invalid request parameters.
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// Operation timed out.
    #[error("operation timed out: {0}")]
    Timeout(String),

    /// JSON serialization error.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

impl From<AgentAdapterError> for RpcError {
    fn from(err: AgentAdapterError) -> Self {
        RpcError::InternalError(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display() {
        let err = AgentAdapterError::CapabilityNotAvailable("process.execute".into());
        assert!(format!("{err}").contains("process.execute"));
    }
}