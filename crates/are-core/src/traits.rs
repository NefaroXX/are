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
#[async_trait]
#[allow(dead_code)]
pub trait Environment: Send + Sync {
    /// Read the contents of a file.
    async fn read_file(&self, req: ReadFileRequest) -> Result<ReadFileResponse, CoreError>;

    /// Write content to a file.
    async fn write_file(&self, req: WriteFileRequest) -> Result<WriteFileResponse, CoreError>;

    /// List the entries in a directory.
    async fn list_directory(
        &self,
        req: ListDirectoryRequest,
    ) -> Result<ListDirectoryResponse, CoreError>;

    /// Execute a process in the environment.
    async fn execute(&self, req: ExecuteRequest) -> Result<ExecuteResponse, CoreError>;

    /// Query the status of a running or completed process.
    async fn process_status(
        &self,
        req: ProcessStatusRequest,
    ) -> Result<ProcessStatusResponse, CoreError>;

    /// Terminate a process (SIGTERM) or force-kill it (SIGKILL).
    async fn terminate_process(
        &self,
        req: TerminateProcessRequest,
    ) -> Result<TerminateProcessResponse, CoreError>;
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::ProcessId;

    /// Minimal mock that compiles the trait — proves it is implementable.
    struct MockEnvironment;

    #[async_trait]
    impl Environment for MockEnvironment {
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
    }

    /// Proves the trait is implementable — MockEnvironment satisfies all bounds.
    #[test]
    fn mock_environment_implements_trait() {
        fn assert_env_impl<T: Environment>() {}
        assert_env_impl::<MockEnvironment>();
    }
}
