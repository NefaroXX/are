//! # are-client
//!
//! Remote environment client — provides the transport abstraction and session
//! client logic that agents use to interact with remote environments.
//!
//! ## Constraints
//!
//! This crate **must not** execute local shell commands or perform implicit
//! local filesystem access. All operations target the remote environment.
//!
//! ## Gate 3 scope
//!
//! Gate 3 implements `SecureClient` for mTLS connections with
//! `GetEnvironmentInfo` RPC. No filesystem, process, or session operations
//! exist yet.

pub mod connection;
pub mod framing;
pub mod tls;

use are_core::{EnvironmentId, SessionId};

/// Trait for connecting to a remote environment.
///
/// Implementations handle transport (TLS, protocol framing) but never
/// fall back to local execution.
#[allow(dead_code)]
pub trait EnvironmentClient {
    /// Connect to the given environment.
    fn connect(&self, env_id: &EnvironmentId) -> Result<(), ClientError>;

    /// Open a session within a connected environment.
    fn open_session(&self, env_id: &EnvironmentId) -> Result<SessionId, ClientError>;

    /// Disconnect from all environments.
    fn disconnect(&self) -> Result<(), ClientError>;
}

/// Error type for client operations.
#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("connection failed: {0}")]
    ConnectionFailed(String),

    #[error("session error: {0}")]
    SessionError(String),

    #[error("transport error: {0}")]
    TransportError(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_error_display() {
        let err = ClientError::ConnectionFailed("timeout".into());
        assert!(format!("{err}").contains("timeout"));
    }
}
