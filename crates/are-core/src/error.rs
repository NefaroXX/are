//! Core error types for domain operations.

use crate::Capability;

/// Error type for core domain operations.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    /// An invalid environment identifier was provided.
    #[error("invalid environment id: {0}")]
    InvalidEnvironmentId(String),

    /// An invalid session identifier was provided.
    #[error("invalid session id: {0}")]
    InvalidSessionId(String),

    /// An invalid process identifier was provided.
    #[error("invalid process id: {0}")]
    InvalidProcessId(String),

    /// An unrecognized capability string was encountered.
    #[error("invalid capability: {0}")]
    InvalidCapability(String),

    /// A request failed validation.
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// A required capability is not granted.
    #[error("missing required capability: {0:?}")]
    MissingCapability(Capability),

    /// An identity or credential failed validation.
    #[error("invalid identity: {0}")]
    InvalidIdentity(String),
}
