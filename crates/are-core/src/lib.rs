//! # are-core
//!
//! Domain models, identifiers, request/response types, and error types for
//! the Agent Remote Environment system.
//!
//! ## Forbidden dependencies
//!
//! This crate must **never** depend on or reference:
//!
//! - Networking (tokio, hyper, reqwest, tonic, rustls, etc.)
//! - Filesystem access (std::fs, tokio::fs)
//! - Process execution (std::process, tokio::process)
//! - TLS implementation
//!
//! It is a pure domain-model crate. All I/O lives in other crates.

use serde::{Deserialize, Serialize};
use std::fmt;

// ---------------------------------------------------------------------------
// Identifier newtypes
// ---------------------------------------------------------------------------

/// Unique identifier for a remote environment (e.g. "dev-vm", "prod-web-01").
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EnvironmentId(String);

impl EnvironmentId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EnvironmentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Unique identifier for a session within an environment.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(String);

impl SessionId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Unique identifier for a process within a session.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessId(String);

impl ProcessId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProcessId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

// ---------------------------------------------------------------------------
// Capabilities
// ---------------------------------------------------------------------------

/// A capability that can be granted to a client for an environment.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Capability {
    FilesystemRead,
    FilesystemWrite,
    FilesystemList,
    ProcessExecute,
    ProcessInspect,
    ProcessTerminate,
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Error type for core domain operations.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    #[error("invalid environment id: {0}")]
    InvalidEnvironmentId(String),

    #[error("invalid session id: {0}")]
    InvalidSessionId(String),

    #[error("missing required capability: {0:?}")]
    MissingCapability(Capability),
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn environment_id_roundtrip() {
        let id = EnvironmentId::new("dev-vm");
        assert_eq!(id.as_str(), "dev-vm");
        assert_eq!(format!("{id}"), "dev-vm");
    }

    #[test]
    fn session_id_roundtrip() {
        let id = SessionId::new("sess-001");
        assert_eq!(id.as_str(), "sess-001");
        assert_eq!(format!("{id}"), "sess-001");
    }

    #[test]
    fn process_id_roundtrip() {
        let id = ProcessId::new("proc-001");
        assert_eq!(id.as_str(), "proc-001");
        assert_eq!(format!("{id}"), "proc-001");
    }

    #[test]
    fn capability_variant_exists() {
        let cap = Capability::FilesystemRead;
        match cap {
            Capability::FilesystemRead => {}
            _ => panic!("unexpected variant"),
        }
    }
}
