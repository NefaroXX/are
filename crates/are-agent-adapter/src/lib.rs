//! # are-agent-adapter
//!
//! High-level Environment abstraction for AI agents backed by ARE daemon.
//!
//! This crate provides the `RemoteEnvironment` implementation that agents use
//! to interact with remote environments. All operations route through the
//! ARE daemon — no local fallback exists.

pub mod environment;
pub mod session;
pub mod process;
pub mod error;

use are_core::{EnvironmentId, SessionId, CapabilitySet};

pub use error::AgentAdapterError;
pub use environment::RemoteEnvironment;
pub use session::SessionHandle;
pub use process::{ProcessHandle, ProcessOutput};

/// Trait representing an environment that agents can interact with.
///
/// This is the primary abstraction — agents should only depend on this trait,
/// not on the concrete `RemoteEnvironment` implementation. This allows
/// testing with mocks and future alternative implementations.
#[async_trait::async_trait]
pub trait Environment: Send + Sync {
    /// Unique identifier for this environment.
    fn environment_id(&self) -> &EnvironmentId;

    /// Capabilities advertised by this environment.
    fn capabilities(&self) -> &CapabilitySet;

    /// Read a file from the environment.
    async fn read_file(&self, path: &str) -> Result<Vec<u8>, AgentAdapterError>;

    /// Write a file to the environment (create or replace).
    async fn write_file(&self, path: &str, content: &[u8]) -> Result<FileWriteResult, AgentAdapterError>;

    /// List a directory in the environment.
    async fn list_directory(&self, path: &str) -> Result<Vec<DirectoryEntry>, AgentAdapterError>;

    /// Get metadata about a file or directory.
    async fn file_metadata(&self, path: &str) -> Result<FileMetadata, AgentAdapterError>;

    /// Execute a program in the environment (structured, no shell).
    async fn execute(&self, request: ExecuteRequest) -> Result<ProcessHandle, AgentAdapterError>;

    /// Create a new session in this environment.
    async fn create_session(&self, config: SessionConfig) -> Result<SessionHandle, AgentAdapterError>;

    /// Resume an existing session by ID.
    async fn resume_session(&self, session_id: &SessionId) -> Result<SessionHandle, AgentAdapterError>;

    /// List all live sessions in this environment.
    async fn list_sessions(&self) -> Result<Vec<SessionHandle>, AgentAdapterError>;

    /// Terminate a session (cascades to its processes).
    async fn terminate_session(&self, session_id: &SessionId) -> Result<(), AgentAdapterError>;
}

/// Result of a file write operation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileWriteResult {
    /// Number of bytes written.
    pub bytes_written: u64,
    /// Blake3 hash of the written content.
    pub content_hash: String,
}

/// Directory entry returned by list_directory.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DirectoryEntry {
    /// Entry name (basename only).
    pub name: String,
    /// Whether this entry is a directory.
    pub is_dir: bool,
    /// Size in bytes (for files).
    pub size: Option<u64>,
    /// Blake3 hash (for files).
    pub content_hash: Option<String>,
}

/// File metadata.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FileMetadata {
    /// Whether the path is a directory.
    pub is_dir: bool,
    /// Size in bytes.
    pub size: u64,
    /// Blake3 content hash (for files).
    pub content_hash: Option<String>,
    /// Last modified timestamp (Unix epoch seconds).
    pub modified: u64,
}

/// Request to execute a program.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ExecuteRequest {
    /// Program to execute (e.g., "cargo", "git", "nginx").
    pub program: String,
    /// Arguments to pass to the program.
    pub args: Vec<String>,
    /// Working directory (environment-relative). Empty = session working directory.
    pub working_directory: String,
    /// Environment variables to set.
    pub env_vars: std::collections::HashMap<String, String>,
    /// Session to run in (optional — creates ephemeral session if omitted).
    pub session_id: Option<SessionId>,
}

/// Configuration for creating a session.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
pub struct SessionConfig {
    /// Initial working directory (environment-relative).
    pub working_directory: String,
    /// Environment variables to set in the session.
    pub env_vars: std::collections::HashMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execute_request_serialization() {
        let req = ExecuteRequest {
            program: "cargo".into(),
            args: vec!["test".into()],
            working_directory: ".".into(),
            env_vars: std::collections::HashMap::new(),
            session_id: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("cargo"));
        assert!(json.contains("test"));
    }
}