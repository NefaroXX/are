//! Request and response types for environment operations.
//!
//! All types in this module are transport-independent: they carry no
//! knowledge of SSH, TCP, TLS, or HTTP. Implementations map these to
//! whatever wire format the transport uses.
//!
//! # Public API surface (Gate 5)
//!
//! `ReadFile`, `ListDirectory`, `GetFileMetadata`, `Execute`,
//! `ProcessStatus`, `TerminateProcess`, and `WaitProcess` are part of the
//! stable public API. `WriteFile` remains gated behind
//! `#[cfg(any(test, feature = "future"))]` and is not re-exported from the
//! crate root. It belongs to Gate 7.
//!
//! Processes are keyed by `(environment_id, process_id)` in daemon memory.
//! Sessions do not exist yet (Gate 6 will bind processes to sessions);
//! no session types are introduced here.

use std::collections::HashMap;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::EnvironmentId;
use crate::ProcessId;

// ---------------------------------------------------------------------------
// Shared types
// ---------------------------------------------------------------------------

/// Metadata about a file or directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileMetadata {
    /// Size in bytes.
    pub size: u64,
    /// Last modification time, if available.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub modified_at: Option<SystemTime>,
    /// Whether this entry is a directory.
    pub is_dir: bool,
    /// Whether this entry is a regular file.
    pub is_file: bool,
}

/// A single entry returned by directory listing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DirectoryEntry {
    /// File or directory name (not the full path).
    pub name: String,
    /// Full path relative to the environment root.
    pub path: String,
    /// Metadata about the entry.
    pub metadata: FileMetadata,
}

/// Current state of a process.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessState {
    /// The process is still running.
    Running,
    /// The process exited with the given exit code (including non-zero
    /// crashes — any exit observed via `wait()` maps here).
    Exited { code: i32 },
    /// The process never produced an exit code: it failed to spawn, was
    /// killed by a signal, or the daemon lost track of it.
    Failed { message: String },
}

// ---------------------------------------------------------------------------
// ReadFile
// ---------------------------------------------------------------------------

/// Request to read a file from the environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadFileRequest {
    /// Target environment.
    pub environment_id: EnvironmentId,
    /// Environment-relative path, resolved against the daemon's configured
    /// allowed roots. Absolute host paths are rejected by default; see
    /// `docs/decisions/002-path-semantics.md`.
    pub path: String,
}

impl ReadFileRequest {
    /// Validate the request fields.
    pub fn validate(&self) -> Result<(), crate::CoreError> {
        if self.path.is_empty() {
            return Err(crate::CoreError::InvalidRequest(
                "path must not be empty".into(),
            ));
        }
        Ok(())
    }
}

/// Response from reading a file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadFileResponse {
    /// File content as raw bytes.
    pub content: Vec<u8>,
    /// Metadata about the file.
    pub metadata: FileMetadata,
}

// ---------------------------------------------------------------------------
// WriteFile (Future gate — not part of stable API)
// ---------------------------------------------------------------------------

/// Request to write a file to the environment.
///
/// **Not part of the public API.** Gated behind `feature = "future"`.
/// Will become stable in Gate 7.
#[cfg(any(test, feature = "future"))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteFileRequest {
    pub environment_id: EnvironmentId,
    /// Environment-relative path, resolved against allowed roots.
    /// Must not escape the environment boundary.
    pub path: String,
    pub content: Vec<u8>,
    /// If `false`, fail when the file already exists.
    pub overwrite: bool,
}

#[cfg(any(test, feature = "future"))]
impl WriteFileRequest {
    pub fn validate(&self) -> Result<(), crate::CoreError> {
        if self.path.is_empty() {
            return Err(crate::CoreError::InvalidRequest(
                "path must not be empty".into(),
            ));
        }
        Ok(())
    }
}

/// Response from writing a file.
///
/// **Not part of the public API.** Gated behind `feature = "future"`.
#[cfg(any(test, feature = "future"))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteFileResponse {
    pub metadata: FileMetadata,
}

// ---------------------------------------------------------------------------
// GetFileMetadata
// ---------------------------------------------------------------------------

/// Request to get metadata about a file or directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetFileMetadataRequest {
    /// Target environment.
    pub environment_id: EnvironmentId,
    /// Environment-relative path, resolved against the daemon's configured
    /// allowed roots. Absolute host paths are rejected by default; see
    /// `docs/decisions/002-path-semantics.md`.
    pub path: String,
}

impl GetFileMetadataRequest {
    /// Validate the request fields.
    pub fn validate(&self) -> Result<(), crate::CoreError> {
        if self.path.is_empty() {
            return Err(crate::CoreError::InvalidRequest(
                "path must not be empty".into(),
            ));
        }
        Ok(())
    }
}

/// Response from getting file metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetFileMetadataResponse {
    /// Metadata about the file or directory.
    pub metadata: FileMetadata,
}

// ---------------------------------------------------------------------------
// ListDirectory
// ---------------------------------------------------------------------------

/// Request to list the contents of a directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListDirectoryRequest {
    pub environment_id: EnvironmentId,
    /// Environment-relative path, resolved against the daemon's configured
    /// allowed roots. Absolute host paths are rejected by default.
    pub path: String,
}

impl ListDirectoryRequest {
    pub fn validate(&self) -> Result<(), crate::CoreError> {
        if self.path.is_empty() {
            return Err(crate::CoreError::InvalidRequest(
                "path must not be empty".into(),
            ));
        }
        Ok(())
    }
}

/// Response from listing a directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListDirectoryResponse {
    pub entries: Vec<DirectoryEntry>,
}

// ---------------------------------------------------------------------------
// Execute (Gate 5 — stable API)
// ---------------------------------------------------------------------------

/// Request to execute a process in the environment.
///
/// Uses structured execution (no shell string interpolation) per the
/// project's non-negotiable design rules. There is deliberately no
/// `execute_shell("arbitrary string")`: `program` is spawned directly
/// without shell metacharacter interpretation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecuteRequest {
    pub environment_id: EnvironmentId,
    /// Program to execute (e.g. `"cargo"`, `"git"`).
    pub program: String,
    /// Arguments to pass to the program.
    pub args: Vec<String>,
    /// Environment-relative working directory, resolved against allowed
    /// roots. Must not escape the environment boundary.
    pub working_directory: String,
    /// Environment variables to set.
    pub env_vars: HashMap<String, String>,
}

impl ExecuteRequest {
    /// Upper bound for env var names/values is enforced by the daemon's
    /// process manager; this only checks structural validity.
    pub fn validate(&self) -> Result<(), crate::CoreError> {
        if self.program.is_empty() {
            return Err(crate::CoreError::InvalidRequest(
                "program must not be empty".into(),
            ));
        }
        if self.program.contains('\0') {
            return Err(crate::CoreError::InvalidRequest(
                "program must not contain NUL".into(),
            ));
        }
        if self.working_directory.is_empty() {
            return Err(crate::CoreError::InvalidRequest(
                "working_directory must not be empty".into(),
            ));
        }
        for arg in &self.args {
            if arg.contains('\0') {
                return Err(crate::CoreError::InvalidRequest(
                    "args must not contain NUL".into(),
                ));
            }
        }
        for (key, value) in &self.env_vars {
            if key.is_empty() {
                return Err(crate::CoreError::InvalidRequest(
                    "env var key must not be empty".into(),
                ));
            }
            if key.contains('=') || key.contains('\0') {
                return Err(crate::CoreError::InvalidRequest(format!(
                    "invalid env var key: {key:?}"
                )));
            }
            if value.contains('\0') {
                return Err(crate::CoreError::InvalidRequest(format!(
                    "env var value for {key:?} must not contain NUL"
                )));
            }
        }
        Ok(())
    }
}

/// Response from executing a process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecuteResponse {
    /// Identifier of the created process.
    pub process_id: ProcessId,
}

// ---------------------------------------------------------------------------
// ProcessStatus (Gate 5 — stable API)
// ---------------------------------------------------------------------------

/// Request to query process status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessStatusRequest {
    pub environment_id: EnvironmentId,
    pub process_id: ProcessId,
}

/// Response containing process status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessStatusResponse {
    pub state: ProcessState,
}

// ---------------------------------------------------------------------------
// TerminateProcess (Gate 5 — stable API)
// ---------------------------------------------------------------------------

/// Request to terminate a process.
///
/// Gate 5 has no SIGTERM/SIGKILL distinction yet (both terminate
/// forcefully; see the daemon's process manager). The `force` flag is
/// accepted for forward compatibility with Gate 12 (signals).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerminateProcessRequest {
    pub environment_id: EnvironmentId,
    pub process_id: ProcessId,
    /// If `true`, force-kill; otherwise terminate gracefully.
    /// Currently both paths are forceful — documented, not silent.
    pub force: bool,
}

/// Response from terminating a process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerminateProcessResponse {
    /// Whether the process was successfully terminated.
    /// `false` means it had already exited.
    pub terminated: bool,
}

// ---------------------------------------------------------------------------
// WaitProcess (Gate 5 — stable API)
// ---------------------------------------------------------------------------

/// Maximum `timeout_secs` accepted by [`WaitProcessRequest`].
pub const MAX_WAIT_TIMEOUT_SECS: u64 = 3600;

/// Request to wait for a process to exit, up to a timeout.
///
/// Blocks until the process exits or the timeout elapses, then returns a
/// snapshot of the capped captured output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WaitProcessRequest {
    pub environment_id: EnvironmentId,
    pub process_id: ProcessId,
    /// Maximum seconds to wait. `None` waits indefinitely (the daemon's
    /// configured default applies; callers behind a single-request
    /// connection should prefer an explicit timeout).
    pub timeout_secs: Option<u64>,
}

impl WaitProcessRequest {
    pub fn validate(&self) -> Result<(), crate::CoreError> {
        if let Some(timeout) = self.timeout_secs {
            if timeout > MAX_WAIT_TIMEOUT_SECS {
                return Err(crate::CoreError::InvalidRequest(format!(
                    "timeout_secs {timeout} exceeds maximum {MAX_WAIT_TIMEOUT_SECS}"
                )));
            }
        }
        Ok(())
    }
}

/// Response from waiting on a process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WaitProcessResponse {
    /// Captured stdout, capped by the daemon's per-stream output limit.
    pub stdout: Vec<u8>,
    /// Captured stderr, capped by the daemon's per-stream output limit.
    pub stderr: Vec<u8>,
    /// Exit code if the process exited normally. `None` when the wait
    /// timed out or the process failed without an exit code.
    pub exit_code: Option<i32>,
    /// `true` if the timeout elapsed before the process exited.
    pub timed_out: bool,
    /// `true` if output exceeded the daemon's cap and was truncated.
    pub truncated: bool,
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::{EnvironmentId, ProcessId};

    fn eid() -> EnvironmentId {
        EnvironmentId::new("test-env")
    }

    fn pid() -> ProcessId {
        ProcessId::new("proc-1")
    }

    fn file_meta() -> FileMetadata {
        FileMetadata {
            size: 100,
            modified_at: None,
            is_dir: false,
            is_file: true,
        }
    }

    // ---- Request validation ----

    #[test]
    fn read_file_validate_valid() {
        let req = ReadFileRequest {
            environment_id: eid(),
            path: "/tmp/test".into(),
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn read_file_validate_empty_path() {
        let req = ReadFileRequest {
            environment_id: eid(),
            path: String::new(),
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn write_file_validate_valid() {
        let req = WriteFileRequest {
            environment_id: eid(),
            path: "/tmp/test".into(),
            content: vec![1, 2, 3],
            overwrite: true,
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn write_file_validate_empty_path() {
        let req = WriteFileRequest {
            environment_id: eid(),
            path: String::new(),
            content: vec![],
            overwrite: false,
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn get_file_metadata_validate_valid() {
        let req = GetFileMetadataRequest {
            environment_id: eid(),
            path: "/tmp/test".into(),
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn get_file_metadata_validate_empty_path() {
        let req = GetFileMetadataRequest {
            environment_id: eid(),
            path: String::new(),
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn list_dir_validate_valid() {
        let req = ListDirectoryRequest {
            environment_id: eid(),
            path: "/tmp".into(),
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn list_dir_validate_empty_path() {
        let req = ListDirectoryRequest {
            environment_id: eid(),
            path: String::new(),
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn execute_validate_valid() {
        let req = ExecuteRequest {
            environment_id: eid(),
            program: "cargo".into(),
            args: vec!["test".into()],
            working_directory: "/workspace".into(),
            env_vars: HashMap::new(),
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn execute_validate_empty_program() {
        let req = ExecuteRequest {
            environment_id: eid(),
            program: String::new(),
            args: vec![],
            working_directory: "/workspace".into(),
            env_vars: HashMap::new(),
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn execute_validate_empty_working_dir() {
        let req = ExecuteRequest {
            environment_id: eid(),
            program: "ls".into(),
            args: vec![],
            working_directory: String::new(),
            env_vars: HashMap::new(),
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn execute_validate_rejects_bad_env_keys() {
        let base = || ExecuteRequest {
            environment_id: eid(),
            program: "cargo".into(),
            args: vec![],
            working_directory: "/workspace".into(),
            env_vars: HashMap::new(),
        };
        // Empty key.
        let mut req = base();
        req.env_vars.insert(String::new(), "v".into());
        assert!(req.validate().is_err());
        // Key containing '='.
        let mut req = base();
        req.env_vars.insert("A=B".into(), "v".into());
        assert!(req.validate().is_err());
        // NUL in key / value / arg / program.
        let mut req = base();
        req.env_vars.insert("A\0".into(), "v".into());
        assert!(req.validate().is_err());
        let mut req = base();
        req.env_vars.insert("A".into(), "v\0".into());
        assert!(req.validate().is_err());
        let mut req = base();
        req.args.push("a\0".into());
        assert!(req.validate().is_err());
        let mut req = base();
        req.program = "a\0".into();
        assert!(req.validate().is_err());
    }

    #[test]
    fn wait_validate_timeout_bounds() {
        let base = || WaitProcessRequest {
            environment_id: eid(),
            process_id: pid(),
            timeout_secs: None,
        };
        assert!(base().validate().is_ok());
        let mut req = base();
        req.timeout_secs = Some(0);
        assert!(req.validate().is_ok());
        let mut req = base();
        req.timeout_secs = Some(MAX_WAIT_TIMEOUT_SECS);
        assert!(req.validate().is_ok());
        let mut req = base();
        req.timeout_secs = Some(MAX_WAIT_TIMEOUT_SECS + 1);
        assert!(req.validate().is_err());
    }

    // ---- Serialization roundtrips ----

    #[test]
    fn read_request_response_roundtrip() {
        let req = ReadFileRequest {
            environment_id: eid(),
            path: "/src/main.rs".into(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: ReadFileRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, back);

        let resp = ReadFileResponse {
            content: b"hello".to_vec(),
            metadata: file_meta(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: ReadFileResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(resp, back);
    }

    #[test]
    fn write_request_response_roundtrip() {
        let req = WriteFileRequest {
            environment_id: eid(),
            path: "/tmp/out".into(),
            content: vec![10, 20],
            overwrite: true,
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: WriteFileRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, back);

        let resp = WriteFileResponse {
            metadata: file_meta(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: WriteFileResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(resp, back);
    }

    #[test]
    fn list_directory_roundtrip() {
        let req = ListDirectoryRequest {
            environment_id: eid(),
            path: "/home".into(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: ListDirectoryRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, back);

        let resp = ListDirectoryResponse {
            entries: vec![DirectoryEntry {
                name: "user".into(),
                path: "/home/user".into(),
                metadata: FileMetadata {
                    size: 0,
                    modified_at: None,
                    is_dir: true,
                    is_file: false,
                },
            }],
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: ListDirectoryResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(resp, back);
    }

    #[test]
    fn get_file_metadata_roundtrip() {
        let req = GetFileMetadataRequest {
            environment_id: eid(),
            path: "/src/main.rs".into(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: GetFileMetadataRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, back);

        let resp = GetFileMetadataResponse {
            metadata: file_meta(),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: GetFileMetadataResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(resp, back);
    }

    #[test]
    fn execute_roundtrip() {
        let req = ExecuteRequest {
            environment_id: eid(),
            program: "cargo".into(),
            args: vec!["build".into()],
            working_directory: "/workspace".into(),
            env_vars: HashMap::from([("RUST_LOG".into(), "debug".into())]),
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: ExecuteRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, back);

        let resp = ExecuteResponse { process_id: pid() };
        let json = serde_json::to_string(&resp).unwrap();
        let back: ExecuteResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(resp, back);
    }

    #[test]
    fn process_status_roundtrip() {
        let req = ProcessStatusRequest {
            environment_id: eid(),
            process_id: pid(),
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: ProcessStatusRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, back);

        let states = [
            ProcessState::Running,
            ProcessState::Exited { code: 0 },
            ProcessState::Failed {
                message: "spawn failed".into(),
            },
        ];
        for state in &states {
            let resp = ProcessStatusResponse {
                state: state.clone(),
            };
            let json = serde_json::to_string(&resp).unwrap();
            let back: ProcessStatusResponse = serde_json::from_str(&json).unwrap();
            assert_eq!(*state, back.state);
        }
    }

    #[test]
    fn terminate_roundtrip() {
        let req = TerminateProcessRequest {
            environment_id: eid(),
            process_id: pid(),
            force: true,
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: TerminateProcessRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, back);

        let resp = TerminateProcessResponse { terminated: true };
        let json = serde_json::to_string(&resp).unwrap();
        let back: TerminateProcessResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(resp, back);
    }

    #[test]
    fn wait_roundtrip() {
        let req = WaitProcessRequest {
            environment_id: eid(),
            process_id: pid(),
            timeout_secs: Some(30),
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: WaitProcessRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, back);

        let resp = WaitProcessResponse {
            stdout: b"out".to_vec(),
            stderr: b"err".to_vec(),
            exit_code: Some(0),
            timed_out: false,
            truncated: false,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: WaitProcessResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(resp, back);
    }
}
