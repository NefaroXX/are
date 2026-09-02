//! Request and response types for environment operations.
//!
//! All types in this module are transport-independent: they carry no
//! knowledge of SSH, TCP, TLS, or HTTP. Implementations map these to
//! whatever wire format the transport uses.
//!
//! # Public API surface (Gate 3.5)
//!
//! Only `ReadFile` and `ListDirectory` are part of the stable public API.
//! `WriteFile`, `Execute`, `ProcessStatus`, and `TerminateProcess` are
//! gated behind `#[cfg(any(test, feature = "future"))]` and not re-exported
//! from the crate root. They belong to future gates (5 and 7).

#[cfg(any(test, feature = "future"))]
use std::collections::HashMap;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::EnvironmentId;
#[cfg(any(test, feature = "future"))]
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
///
/// **Not part of the public API.** Gated behind `feature = "future"`.
#[cfg(any(test, feature = "future"))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessState {
    /// The process is still running.
    Running,
    /// The process exited with the given exit code.
    Exited { code: i32 },
    /// The process terminated abnormally with the given signal/code.
    Failed { code: i32 },
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
/// Will become stable in Gate 5.
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
// Execute (Future gate — not part of stable API)
// ---------------------------------------------------------------------------

/// Request to execute a process in the environment.
///
/// Uses structured execution (no shell string interpolation) per the
/// project's non-negotiable design rules.
///
/// **Not part of the public API.** Gated behind `feature = "future"`.
/// Will become stable in Gate 7.
#[cfg(any(test, feature = "future"))]
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

#[cfg(any(test, feature = "future"))]
impl ExecuteRequest {
    pub fn validate(&self) -> Result<(), crate::CoreError> {
        if self.program.is_empty() {
            return Err(crate::CoreError::InvalidRequest(
                "program must not be empty".into(),
            ));
        }
        if self.working_directory.is_empty() {
            return Err(crate::CoreError::InvalidRequest(
                "working_directory must not be empty".into(),
            ));
        }
        Ok(())
    }
}

/// Response from executing a process.
///
/// **Not part of the public API.** Gated behind `feature = "future"`.
#[cfg(any(test, feature = "future"))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecuteResponse {
    /// Identifier of the created process.
    pub process_id: ProcessId,
}

// ---------------------------------------------------------------------------
// ProcessStatus (Future gate — not part of stable API)
// ---------------------------------------------------------------------------

/// Request to query process status.
///
/// **Not part of the public API.** Gated behind `feature = "future"`.
#[cfg(any(test, feature = "future"))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessStatusRequest {
    pub environment_id: EnvironmentId,
    pub process_id: ProcessId,
}

/// Response containing process status.
///
/// **Not part of the public API.** Gated behind `feature = "future"`.
#[cfg(any(test, feature = "future"))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessStatusResponse {
    pub state: ProcessState,
}

// ---------------------------------------------------------------------------
// TerminateProcess (Future gate — not part of stable API)
// ---------------------------------------------------------------------------

/// Request to terminate a process.
///
/// **Not part of the public API.** Gated behind `feature = "future"`.
#[cfg(any(test, feature = "future"))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerminateProcessRequest {
    pub environment_id: EnvironmentId,
    pub process_id: ProcessId,
    /// If `true`, send `SIGKILL`; otherwise send `SIGTERM`.
    pub force: bool,
}

/// Response from terminating a process.
///
/// **Not part of the public API.** Gated behind `feature = "future"`.
#[cfg(any(test, feature = "future"))]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerminateProcessResponse {
    /// Whether the process was successfully terminated.
    pub terminated: bool,
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
            ProcessState::Failed { code: 137 },
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
}
