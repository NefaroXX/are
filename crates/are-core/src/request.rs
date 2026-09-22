//! Request and response types for environment operations.
//!
//! All types in this module are transport-independent: they carry no
//! knowledge of SSH, TCP, TLS, or HTTP. Implementations map these to
//! whatever wire format the transport uses.
//!
//! # Public API surface (Gate 6)
//!
//! `ReadFile`, `ListDirectory`, `GetFileMetadata`, `Execute`,
//! `ProcessStatus`, `TerminateProcess`, `WaitProcess`, `CreateSession`,
//! `GetSession`, `ListSessions`, and `TerminateSession` are part of the
//! stable public API. `WriteFile` remains gated behind
//! `#[cfg(any(test, feature = "future"))]` and is not re-exported from the
//! crate root. It belongs to Gate 7.
//!
//! Processes are keyed by `(environment_id, session_id, process_id)` in
//! daemon memory. Every process operation requires a live session: the
//! session carries the working directory and environment variables the
//! process inherits.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::EnvironmentId;
use crate::ProcessId;
use crate::SessionId;

/// Current Unix timestamp in whole seconds.
///
/// `SystemTime::now` performs no I/O (no filesystem, network, or process
/// access), so this helper is legal in `are-core`. Timestamps are `u64`
/// seconds — not `SystemTime` — because `SystemTime` serde is
/// platform-fragile (Gate 1 lesson). Returns `0` if the clock is before
/// the epoch (should never happen; fail-safe, not fail-silent — callers
/// treat `0` as "unknown time").
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

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

/// Validate environment variable keys and values shared by
/// [`ExecuteRequest`] and [`CreateSessionRequest`].
///
/// Rejects empty keys, keys containing `=` or NUL, oversized keys/values,
/// NUL values, and a client-supplied `PATH`. `PATH` is rejected because the
/// daemon resolves bare program names against its own trusted `PATH`;
/// accepting a client `PATH` would let callers redirect bare names at
/// attacker-controlled directories. Trusted `PATH` customization comes from
/// daemon configuration only. Dynamic-loader keys (`LD_*`/`DYLD_*`) are NOT
/// rejected here — they are stripped at spawn time (defense in depth: strip
/// at session creation AND at spawn merge).
fn validate_env_vars(env_vars: &HashMap<String, String>) -> Result<(), crate::CoreError> {
    if env_vars.len() > MAX_EXEC_ENV_VARS {
        return Err(crate::CoreError::InvalidRequest(format!(
            "too many env vars: {} exceeds maximum {MAX_EXEC_ENV_VARS}",
            env_vars.len()
        )));
    }
    for (key, value) in env_vars {
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
        if key.len() > MAX_EXEC_ENV_KEY_LEN {
            return Err(crate::CoreError::InvalidRequest(format!(
                "env var key {key:?} exceeds maximum length {MAX_EXEC_ENV_KEY_LEN}"
            )));
        }
        if value.len() > MAX_EXEC_ENV_VALUE_LEN {
            return Err(crate::CoreError::InvalidRequest(format!(
                "env var value for {key:?} exceeds maximum length {MAX_EXEC_ENV_VALUE_LEN}"
            )));
        }
        if value.contains('\0') {
            return Err(crate::CoreError::InvalidRequest(format!(
                "env var value for {key:?} must not contain NUL"
            )));
        }
        if key == "PATH" {
            return Err(crate::CoreError::InvalidRequest(
                "env var PATH must not be supplied: programs resolve against the daemon's trusted PATH".into(),
            ));
        }
    }
    Ok(())
}

/// Maximum number of arguments accepted in an [`ExecuteRequest`].
pub const MAX_EXEC_ARGS: usize = 256;
/// Maximum length in bytes of a single argument.
pub const MAX_EXEC_ARG_LEN: usize = 32 * 1024;
/// Maximum number of environment variables accepted in an
/// [`ExecuteRequest`].
pub const MAX_EXEC_ENV_VARS: usize = 128;
/// Maximum length in bytes of a single env var key.
pub const MAX_EXEC_ENV_KEY_LEN: usize = 4 * 1024;
/// Maximum length in bytes of a single env var value.
pub const MAX_EXEC_ENV_VALUE_LEN: usize = 1024 * 1024;

/// Request to execute a process in the environment.
///
/// Uses structured execution (no shell string interpolation) per the
/// project's non-negotiable design rules. There is deliberately no
/// `execute_shell("arbitrary string")`: `program` is spawned directly
/// without shell metacharacter interpretation.
///
/// # Gate 6 session binding
///
/// Every execution requires a live [`SessionId`]: creation fails with
/// `SessionNotFound`/`SessionExpired` when the session is unknown or aged
/// out. The session supplies:
///
/// - **Working directory.** An empty `working_directory` (`""`) means
///   "inherit the session's working directory". A non-empty value is
///   resolved env-relative per ADR-002 (same boundary rules as sessions).
/// - **Environment.** Merge order is daemon environment < session env <
///   request env (request wins on key conflicts). The request and session
///   layers are sanitized (`PATH` rejected at validation, `LD_*`/`DYLD_*`
///   stripped at spawn); the daemon's own inherited base environment is NOT
///   sanitized (documented Gate 5 decision: the base is trusted config, and
///   `PATH` lookup for bare program names requires it).
///
/// Request-size bounds (enforced by [`ExecuteRequest::validate`]) keep a
/// single request from forcing unbounded daemon allocations:
/// at most [`MAX_EXEC_ARGS`] args of [`MAX_EXEC_ARG_LEN`] bytes each, and
/// at most [`MAX_EXEC_ENV_VARS`] env vars with keys/values capped at
/// [`MAX_EXEC_ENV_KEY_LEN`]/[`MAX_EXEC_ENV_VALUE_LEN`] bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecuteRequest {
    pub environment_id: EnvironmentId,
    /// Session the process belongs to. Must be live at creation.
    pub session_id: SessionId,
    /// Program to execute (e.g. `"cargo"`, `"git"`).
    pub program: String,
    /// Arguments to pass to the program.
    pub args: Vec<String>,
    /// Environment-relative working directory, resolved against allowed
    /// roots. Empty (`""`) inherits the session's working directory.
    /// Must not escape the environment boundary.
    pub working_directory: String,
    /// Environment variables to set (one-shot overrides on top of the
    /// session env; same key rules, including `PATH` rejection).
    pub env_vars: HashMap<String, String>,
}

impl ExecuteRequest {
    /// Validate structural shape plus request-size bounds.
    ///
    /// Rejects oversized arg/env payloads (see `MAX_EXEC_*`), NUL bytes,
    /// malformed env keys, and a client-supplied `PATH` (the daemon
    /// resolves programs against its own trusted `PATH`; accepting a
    /// client `PATH` would let callers redirect bare program names at
    /// attacker-controlled directories).
    ///
    /// An empty `working_directory` is VALID (means "inherit the session's
    /// directory"); NUL bytes in it are still rejected.
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
        if self.working_directory.contains('\0') {
            return Err(crate::CoreError::InvalidRequest(
                "working_directory must not contain NUL".into(),
            ));
        }
        if self.args.len() > MAX_EXEC_ARGS {
            return Err(crate::CoreError::InvalidRequest(format!(
                "too many args: {} exceeds maximum {MAX_EXEC_ARGS}",
                self.args.len()
            )));
        }
        for arg in &self.args {
            if arg.contains('\0') {
                return Err(crate::CoreError::InvalidRequest(
                    "args must not contain NUL".into(),
                ));
            }
            if arg.len() > MAX_EXEC_ARG_LEN {
                return Err(crate::CoreError::InvalidRequest(format!(
                    "arg exceeds maximum length {MAX_EXEC_ARG_LEN}"
                )));
            }
        }
        validate_env_vars(&self.env_vars)
    }
}

/// Response from executing a process.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecuteResponse {
    /// Identifier of the created process.
    pub process_id: ProcessId,
}

// ---------------------------------------------------------------------------
// ProcessStatus (Gate 5 — stable API, Gate 6 session binding)
// ---------------------------------------------------------------------------

/// Request to query process status.
///
/// Lookup key is `(environment_id, session_id, process_id)`; a session
/// mismatch yields `NotFound` (indistinguishable from an unknown process
/// id — no oracle into other sessions' processes).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessStatusRequest {
    pub environment_id: EnvironmentId,
    pub session_id: SessionId,
    pub process_id: ProcessId,
}

/// Response containing process status.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessStatusResponse {
    pub state: ProcessState,
}

// ---------------------------------------------------------------------------
// TerminateProcess (Gate 5 — stable API, Gate 6 session binding)
// ---------------------------------------------------------------------------

/// Request to terminate a process.
///
/// Lookup key is `(environment_id, session_id, process_id)`; a session
/// mismatch yields `NotFound` (no oracle).
///
/// Gate 5 has no SIGTERM/SIGKILL distinction yet (both terminate
/// forcefully; see the daemon's process manager). The `force` flag is
/// accepted for forward compatibility with Gate 12 (signals).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerminateProcessRequest {
    pub environment_id: EnvironmentId,
    pub session_id: SessionId,
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
// Sessions (Gate 6 — stable API)
// ---------------------------------------------------------------------------

/// Request to create a persistent session in the environment.
///
/// The session becomes the carrier of working directory and environment
/// state: processes spawned into it inherit both (see [`ExecuteRequest`]).
/// Sessions live in daemon memory and survive client disconnects (every RPC
/// is already a fresh TLS connection); they do NOT survive daemon restarts
/// (memory-only, like processes — documented, not promised).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateSessionRequest {
    pub environment_id: EnvironmentId,
    /// Environment-relative working directory, resolved against allowed
    /// roots at creation (must exist and be a directory). `None` means the
    /// environment default (`"."`).
    pub working_directory: Option<String>,
    /// Environment variables for the session. Same key rules as
    /// [`ExecuteRequest`] (including `PATH` rejection — trusted `PATH`
    /// comes from daemon config only).
    pub env_vars: HashMap<String, String>,
}

impl CreateSessionRequest {
    /// Validate env keys/values plus the optional working directory shape.
    ///
    /// `Some("")` is rejected (empty means "inherit", which is meaningless
    /// at creation — pass `None` for the default). Existence, directoryness,
    /// and boundary checks happen daemon-side against the filesystem.
    pub fn validate(&self) -> Result<(), crate::CoreError> {
        if let Some(workdir) = &self.working_directory {
            if workdir.is_empty() {
                return Err(crate::CoreError::InvalidRequest(
                    "working_directory must not be empty: pass None for the default".into(),
                ));
            }
            if workdir.contains('\0') {
                return Err(crate::CoreError::InvalidRequest(
                    "working_directory must not contain NUL".into(),
                ));
            }
        }
        validate_env_vars(&self.env_vars)
    }
}

/// A persistent session: working directory + environment + processes.
///
/// Returned by creation and by `GetSession` (the resume operation).
/// Timestamps are Unix seconds (see [`now_secs`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionInfo {
    /// Session identity (CSPRNG `sess-<32hex>`, unguessable like proc ids).
    pub session_id: SessionId,
    /// Environment this session belongs to.
    pub environment_id: EnvironmentId,
    /// Environment-relative working directory (as supplied at creation).
    /// Processes with an empty request workdir inherit this.
    pub working_directory: String,
    /// Session environment variables (sanitized copy).
    pub env_vars: HashMap<String, String>,
    /// Creation time, Unix seconds.
    pub created_at: u64,
    /// Last activity time, Unix seconds. Bumped on every session-scoped
    /// operation (create/get/execute/status/wait/terminate); drives idle
    /// expiry. Listing sessions does NOT bump activity.
    pub last_activity: u64,
    /// Owning principal, if bound. `None` means a legacy single-principal
    /// session with no owner check (current behavior: every client may
    /// address every session by unguessable id). Gate 8 binds this to the
    /// client-certificate identity and enforces ownership.
    #[serde(default)]
    pub owner: Option<String>,
}

/// Response containing the created session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateSessionResponse {
    pub session: SessionInfo,
}

/// Request to fetch a session by id — this IS the resume operation.
///
/// `create → disconnect → reconnect → get` recovers working directory and
/// env state. Returns `SessionExpired` when the session aged out (the entry
/// is removed), `SessionNotFound` when the id is unknown.
///
/// `environment_id` scopes the lookup: a session that belongs to a
/// different environment misses with `NotFound` (same rule as process
/// ops — no cross-environment oracle).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetSessionRequest {
    pub environment_id: EnvironmentId,
    pub session_id: SessionId,
}

/// Response containing the resumed session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetSessionResponse {
    pub session: SessionInfo,
}

/// Request to list live sessions in an environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListSessionsRequest {
    pub environment_id: EnvironmentId,
}

/// Response with the live sessions for the environment.
///
/// Expired sessions are purged opportunistically before listing and never
/// appear here. Listing bumps no activity timestamps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListSessionsResponse {
    pub sessions: Vec<SessionInfo>,
}

/// Request to terminate a session.
///
/// Cascades: all session processes are killed best-effort (direct children
/// only — inherited from the Gate 5 terminate limitation), then the session
/// is removed. Kill-then-remove ordering means a crash between the two
/// leaves either a dead session entry or orphaned processes, both of which
/// fail closed on next access.
///
/// `environment_id` scopes the operation like [`GetSessionRequest`]: a
/// session in another environment misses with `NotFound`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerminateSessionRequest {
    pub environment_id: EnvironmentId,
    pub session_id: SessionId,
}

/// Response from terminating a session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TerminateSessionResponse {
    /// Number of session processes the cascade killed. Counts live kills
    /// only: already-terminal entries are not signaled and not counted.
    pub terminated_processes: usize,
}

// ---------------------------------------------------------------------------
// Execute (Gate 5 — stable API, Gate 6 session binding)
// ---------------------------------------------------------------------------

/// Minimum `timeout_secs` accepted by [`WaitProcessRequest`].
pub const MIN_WAIT_TIMEOUT_SECS: u64 = 1;

/// Maximum `timeout_secs` accepted by [`WaitProcessRequest`].
pub const MAX_WAIT_TIMEOUT_SECS: u64 = 3600;

/// Request to wait for a process to exit, up to a timeout.
///
/// Blocks until the process exits or the timeout elapses, then returns a
/// snapshot of the capped captured output.
///
/// Lookup key is `(environment_id, session_id, process_id)`; a session
/// mismatch yields `NotFound` (no oracle).
///
/// The timeout is **required** (`1..=3600` seconds): indefinite waits are
/// rejected because a single-request transport must always make progress.
/// There is no `None`/infinite variant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WaitProcessRequest {
    pub environment_id: EnvironmentId,
    pub session_id: SessionId,
    pub process_id: ProcessId,
    /// Maximum seconds to wait, `1..=3600`.
    pub timeout_secs: u64,
}

impl WaitProcessRequest {
    pub fn validate(&self) -> Result<(), crate::CoreError> {
        if self.timeout_secs < MIN_WAIT_TIMEOUT_SECS {
            return Err(crate::CoreError::InvalidRequest(format!(
                "timeout_secs {} is below minimum {MIN_WAIT_TIMEOUT_SECS}: wait requires an explicit timeout",
                self.timeout_secs
            )));
        }
        if self.timeout_secs > MAX_WAIT_TIMEOUT_SECS {
            return Err(crate::CoreError::InvalidRequest(format!(
                "timeout_secs {} exceeds maximum {MAX_WAIT_TIMEOUT_SECS}",
                self.timeout_secs
            )));
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

    fn sid() -> SessionId {
        SessionId::new("sess-1")
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
            session_id: sid(),
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
            session_id: sid(),
            program: String::new(),
            args: vec![],
            working_directory: "/workspace".into(),
            env_vars: HashMap::new(),
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn execute_validate_empty_working_dir_inherits_session() {
        // Gate 6: empty working_directory means "inherit the session's
        // directory", so it validates � the daemon resolves it.
        let req = ExecuteRequest {
            environment_id: eid(),
            session_id: sid(),
            program: "ls".into(),
            args: vec![],
            working_directory: String::new(),
            env_vars: HashMap::new(),
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn execute_validate_rejects_nul_working_dir() {
        let req = ExecuteRequest {
            environment_id: eid(),
            session_id: sid(),
            program: "ls".into(),
            args: vec![],
            working_directory: "a b".into(),
            env_vars: HashMap::new(),
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn execute_validate_rejects_bad_env_keys() {
        let base = || ExecuteRequest {
            environment_id: eid(),
            session_id: sid(),
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
    fn execute_validate_rejects_oversized_payloads() {
        let base = || ExecuteRequest {
            environment_id: eid(),
            session_id: sid(),
            program: "cargo".into(),
            args: vec![],
            working_directory: "/workspace".into(),
            env_vars: HashMap::new(),
        };
        // Too many args.
        let mut req = base();
        req.args = vec!["a".into(); MAX_EXEC_ARGS + 1];
        assert!(req.validate().is_err());
        // Arg at the bound is fine; one byte over is not.
        let mut req = base();
        req.args = vec!["a".repeat(MAX_EXEC_ARG_LEN)];
        assert!(req.validate().is_ok());
        let mut req = base();
        req.args = vec!["a".repeat(MAX_EXEC_ARG_LEN + 1)];
        assert!(req.validate().is_err());
        // Too many env vars.
        let mut req = base();
        for i in 0..=MAX_EXEC_ENV_VARS {
            req.env_vars.insert(format!("K{i}"), "v".into());
        }
        assert!(req.validate().is_err());
        // Oversized key / value.
        let mut req = base();
        req.env_vars
            .insert("k".repeat(MAX_EXEC_ENV_KEY_LEN + 1), "v".into());
        assert!(req.validate().is_err());
        let mut req = base();
        req.env_vars
            .insert("K".into(), "v".repeat(MAX_EXEC_ENV_VALUE_LEN + 1));
        assert!(req.validate().is_err());
        // Boundary values are accepted.
        let mut req = base();
        req.env_vars.insert(
            "k".repeat(MAX_EXEC_ENV_KEY_LEN),
            "v".repeat(MAX_EXEC_ENV_VALUE_LEN),
        );
        assert!(req.validate().is_ok());
    }

    #[test]
    fn execute_validate_rejects_client_supplied_path() {
        let mut req = ExecuteRequest {
            environment_id: eid(),
            session_id: sid(),
            program: "cargo".into(),
            args: vec![],
            working_directory: "/workspace".into(),
            env_vars: HashMap::new(),
        };
        req.env_vars.insert("PATH".into(), "/tmp/evil".into());
        let err = req.validate().unwrap_err();
        assert!(format!("{err}").contains("PATH"));
    }

    #[test]
    fn wait_validate_timeout_bounds() {
        let base = |timeout: u64| WaitProcessRequest {
            environment_id: eid(),
            session_id: sid(),
            process_id: pid(),
            timeout_secs: timeout,
        };
        assert!(base(0).validate().is_err());
        assert!(base(MIN_WAIT_TIMEOUT_SECS).validate().is_ok());
        assert!(base(MAX_WAIT_TIMEOUT_SECS).validate().is_ok());
        assert!(base(MAX_WAIT_TIMEOUT_SECS + 1).validate().is_err());
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
            session_id: sid(),
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
            session_id: sid(),
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
            session_id: sid(),
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
            session_id: sid(),
            process_id: pid(),
            timeout_secs: 30,
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

    // ---- Sessions (Gate 6) ----

    fn session_info() -> SessionInfo {
        SessionInfo {
            session_id: sid(),
            environment_id: eid(),
            working_directory: ".".into(),
            env_vars: HashMap::from([("FOO".into(), "bar".into())]),
            created_at: 1_000_000,
            last_activity: 1_000_100,
            owner: None,
        }
    }

    #[test]
    fn create_session_validate_valid() {
        let req = CreateSessionRequest {
            environment_id: eid(),
            working_directory: Some(".".into()),
            env_vars: HashMap::new(),
        };
        assert!(req.validate().is_ok());
        let req = CreateSessionRequest {
            environment_id: eid(),
            working_directory: None,
            env_vars: HashMap::from([("FOO".into(), "bar".into())]),
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn create_session_validate_rejects_empty_some_workdir() {
        let req = CreateSessionRequest {
            environment_id: eid(),
            working_directory: Some(String::new()),
            env_vars: HashMap::new(),
        };
        assert!(req.validate().is_err());
    }

    #[test]
    fn create_session_validate_rejects_path_env() {
        let req = CreateSessionRequest {
            environment_id: eid(),
            working_directory: None,
            env_vars: HashMap::from([("PATH".into(), "/tmp/evil".into())]),
        };
        let err = req.validate().unwrap_err();
        assert!(format!("{err}").contains("PATH"));
    }

    #[test]
    fn create_session_validate_rejects_bad_env_keys() {
        for (k, v) in [
            (String::new(), "v".to_string()),
            ("A=B".to_string(), "v".to_string()),
            ("A ".to_string(), "v".to_string()),
            ("A".to_string(), "v ".to_string()),
        ] {
            let req = CreateSessionRequest {
                environment_id: eid(),
                working_directory: None,
                env_vars: HashMap::from([(k, v)]),
            };
            assert!(req.validate().is_err());
        }
    }

    #[test]
    fn session_info_roundtrip() {
        let info = session_info();
        let json = serde_json::to_string(&info).unwrap();
        let back: SessionInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(info, back);
    }

    #[test]
    fn session_info_owner_defaults_to_none_for_legacy_json() {
        // Back-compat: pre-owner JSON (no `owner` key) must parse with
        // `owner == None` via `#[serde(default)]`.
        let legacy = serde_json::json!({
            "session_id": "sess-1",
            "environment_id": "test-env",
            "working_directory": ".",
            "env_vars": {},
            "created_at": 1_000_000,
            "last_activity": 1_000_100,
        });
        let back: SessionInfo = serde_json::from_value(legacy).unwrap();
        assert_eq!(back.owner, None);
        let owned = session_info_with_owner();
        let json = serde_json::to_string(&owned).unwrap();
        let back: SessionInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(back.owner.as_deref(), Some("client-a"));
    }

    fn session_info_with_owner() -> SessionInfo {
        SessionInfo {
            owner: Some("client-a".into()),
            ..session_info()
        }
    }

    #[test]
    fn session_requests_roundtrip() {
        let cases = [
            serde_json::to_string(&CreateSessionRequest {
                environment_id: eid(),
                working_directory: Some("sub".into()),
                env_vars: HashMap::new(),
            })
            .unwrap(),
            serde_json::to_string(&GetSessionRequest {
                environment_id: eid(),
                session_id: sid(),
            })
            .unwrap(),
            serde_json::to_string(&GetSessionResponse {
                session: session_info(),
            })
            .unwrap(),
            serde_json::to_string(&ListSessionsRequest {
                environment_id: eid(),
            })
            .unwrap(),
            serde_json::to_string(&ListSessionsResponse {
                sessions: vec![session_info()],
            })
            .unwrap(),
            serde_json::to_string(&TerminateSessionRequest {
                environment_id: eid(),
                session_id: sid(),
            })
            .unwrap(),
            serde_json::to_string(&TerminateSessionResponse {
                terminated_processes: 2,
            })
            .unwrap(),
        ];
        // Each serializes; spot-check deserialization of each type.
        let back: CreateSessionRequest = serde_json::from_str(&cases[0]).unwrap();
        assert_eq!(back.working_directory.as_deref(), Some("sub"));
        let back: GetSessionRequest = serde_json::from_str(&cases[1]).unwrap();
        assert_eq!(back.session_id, sid());
        let back: GetSessionResponse = serde_json::from_str(&cases[2]).unwrap();
        assert_eq!(back.session, session_info());
        let back: ListSessionsRequest = serde_json::from_str(&cases[3]).unwrap();
        assert_eq!(back.environment_id, eid());
        let back: ListSessionsResponse = serde_json::from_str(&cases[4]).unwrap();
        assert_eq!(back.sessions, vec![session_info()]);
        let back: TerminateSessionRequest = serde_json::from_str(&cases[5]).unwrap();
        assert_eq!(back.session_id, sid());
        let back: TerminateSessionResponse = serde_json::from_str(&cases[6]).unwrap();
        assert_eq!(back.terminated_processes, 2);
    }

    #[test]
    fn now_secs_is_sane() {
        // Sanity only: nonzero and nondecreasing across calls.
        let a = now_secs();
        assert!(
            a > 1_700_000_000,
            "now_secs should be a real Unix time, got {a}"
        );
        let b = now_secs();
        assert!(b >= a);
    }
}
