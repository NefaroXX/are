//! Transport-independent environment operations trait.
//!
//! This trait defines the full set of operations an agent can perform on
//! a remote environment. Implementations handle transport (SSH, TCP, TLS,
//! etc.) but the trait itself carries no transport knowledge.
//!
//! # Object safety
//!
//! This trait uses `#[async_trait]` for ergonomic async methods. It is
//! **not** object-safe by default. Callers that need dynamic dispatch
//! should use `Box<dyn Environment>` after adding the trait's object-safe
//! supertraits. This limitation may be revisited when Rust stabilizes
//! `async fn` in `dyn Trait`.

use crate::request::*;
use crate::CoreError;
use async_trait::async_trait;

/// Operations available on a remote environment.
///
/// Every method is transport-independent: the same trait is used for local,
/// remote, and future container implementations. No implementation may
/// silently fall back to local execution.
///
/// Only `write_file` remains gated behind `feature = "future"` (Gate 7).
/// Process operations (`execute`, `process_status`, `terminate_process`,
/// `wait_process`) are session-bound as of Gate 6: every process request
/// carries a `session_id`, and session operations (`create_session`,
/// `get_session`, `list_sessions`, `terminate_session`) manage the
/// sessions processes belong to.
#[async_trait]
#[allow(dead_code)]
pub trait Environment: Send + Sync {
    /// Create a persistent session (working directory + env state).
    async fn create_session(
        &self,
        req: CreateSessionRequest,
    ) -> Result<CreateSessionResponse, CoreError>;

    /// Fetch a session by id — the resume operation.
    async fn get_session(&self, req: GetSessionRequest) -> Result<GetSessionResponse, CoreError>;

    /// List live sessions in an environment.
    async fn list_sessions(
        &self,
        req: ListSessionsRequest,
    ) -> Result<ListSessionsResponse, CoreError>;

    /// Terminate a session, cascading to its processes.
    async fn terminate_session(
        &self,
        req: TerminateSessionRequest,
    ) -> Result<TerminateSessionResponse, CoreError>;

    /// Read the contents of a file.
    async fn read_file(&self, req: ReadFileRequest) -> Result<ReadFileResponse, CoreError>;

    /// Write content to a file.
    #[cfg(any(test, feature = "future"))]
    async fn write_file(&self, req: WriteFileRequest) -> Result<WriteFileResponse, CoreError>;

    /// List the entries in a directory.
    async fn list_directory(
        &self,
        req: ListDirectoryRequest,
    ) -> Result<ListDirectoryResponse, CoreError>;

    /// Get metadata about a file or directory.
    async fn file_metadata(
        &self,
        req: GetFileMetadataRequest,
    ) -> Result<GetFileMetadataResponse, CoreError>;

    /// Execute a process in the environment (structured, no shell).
    async fn execute(&self, req: ExecuteRequest) -> Result<ExecuteResponse, CoreError>;

    /// Query the status of a running or completed process.
    async fn process_status(
        &self,
        req: ProcessStatusRequest,
    ) -> Result<ProcessStatusResponse, CoreError>;

    /// Terminate a process. The `force` flag selects force-kill vs
    /// graceful termination where the backend distinguishes them
    /// (Gate 5 backends are forceful on both paths — documented).
    async fn terminate_process(
        &self,
        req: TerminateProcessRequest,
    ) -> Result<TerminateProcessResponse, CoreError>;

    /// Wait for a process to exit, up to a timeout, returning the
    /// capped captured output.
    async fn wait_process(&self, req: WaitProcessRequest)
        -> Result<WaitProcessResponse, CoreError>;
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::{EnvironmentId, ProcessId, SessionId, SessionInfo};

    /// Minimal mock that compiles the trait — proves it is implementable.
    struct MockEnvironment;

    #[async_trait]
    impl Environment for MockEnvironment {
        async fn create_session(
            &self,
            _req: CreateSessionRequest,
        ) -> Result<CreateSessionResponse, CoreError> {
            Ok(CreateSessionResponse {
                session: SessionInfo {
                    session_id: SessionId::new("sess-mock"),
                    environment_id: EnvironmentId::new("mock-env"),
                    working_directory: ".".into(),
                    env_vars: std::collections::HashMap::new(),
                    created_at: 0,
                    last_activity: 0,
                    owner: None,
                },
            })
        }

        async fn get_session(
            &self,
            req: GetSessionRequest,
        ) -> Result<GetSessionResponse, CoreError> {
            Ok(GetSessionResponse {
                session: SessionInfo {
                    session_id: req.session_id,
                    environment_id: EnvironmentId::new("mock-env"),
                    working_directory: ".".into(),
                    env_vars: std::collections::HashMap::new(),
                    created_at: 0,
                    last_activity: 0,
                    owner: None,
                },
            })
        }

        async fn list_sessions(
            &self,
            _req: ListSessionsRequest,
        ) -> Result<ListSessionsResponse, CoreError> {
            Ok(ListSessionsResponse { sessions: vec![] })
        }

        async fn terminate_session(
            &self,
            _req: TerminateSessionRequest,
        ) -> Result<TerminateSessionResponse, CoreError> {
            Ok(TerminateSessionResponse {
                terminated_processes: 0,
            })
        }

        async fn read_file(&self, _req: ReadFileRequest) -> Result<ReadFileResponse, CoreError> {
            Ok(ReadFileResponse {
                content: b"mock".to_vec(),
                metadata: FileMetadata {
                    size: 4,
                    modified_at: None,
                    is_dir: false,
                    is_file: true,
                },
            })
        }

        #[cfg(any(test, feature = "future"))]
        async fn write_file(&self, _req: WriteFileRequest) -> Result<WriteFileResponse, CoreError> {
            Ok(WriteFileResponse {
                metadata: FileMetadata {
                    size: 0,
                    modified_at: None,
                    is_dir: false,
                    is_file: true,
                },
            })
        }
        async fn list_directory(
            &self,
            _req: ListDirectoryRequest,
        ) -> Result<ListDirectoryResponse, CoreError> {
            Ok(ListDirectoryResponse { entries: vec![] })
        }

        async fn file_metadata(
            &self,
            _req: GetFileMetadataRequest,
        ) -> Result<GetFileMetadataResponse, CoreError> {
            Ok(GetFileMetadataResponse {
                metadata: FileMetadata {
                    size: 0,
                    modified_at: None,
                    is_dir: false,
                    is_file: true,
                },
            })
        }

        async fn execute(&self, _req: ExecuteRequest) -> Result<ExecuteResponse, CoreError> {
            Ok(ExecuteResponse {
                process_id: ProcessId::new("mock-proc"),
            })
        }

        async fn process_status(
            &self,
            _req: ProcessStatusRequest,
        ) -> Result<ProcessStatusResponse, CoreError> {
            Ok(ProcessStatusResponse {
                state: ProcessState::Running,
            })
        }

        async fn terminate_process(
            &self,
            _req: TerminateProcessRequest,
        ) -> Result<TerminateProcessResponse, CoreError> {
            Ok(TerminateProcessResponse { terminated: true })
        }

        async fn wait_process(
            &self,
            _req: WaitProcessRequest,
        ) -> Result<WaitProcessResponse, CoreError> {
            Ok(WaitProcessResponse {
                stdout: b"mock".to_vec(),
                stderr: vec![],
                exit_code: Some(0),
                timed_out: false,
                truncated: false,
            })
        }
    }

    /// Proves the trait is implementable — MockEnvironment satisfies all bounds.
    #[test]
    fn mock_environment_implements_trait() {
        fn assert_env_impl<T: Environment>() {}
        assert_env_impl::<MockEnvironment>();
    }
}
