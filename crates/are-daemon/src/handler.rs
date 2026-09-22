//! Request dispatch and handler for the daemon.
//!
//! Handles `RpcRequest` variants and returns `RpcResponse` values.
//! Gate 3 handles `GetEnvironmentInfo`. Gate 4 adds `ReadFile`,
//! `ListDirectory`, and `GetFileMetadata`. Gate 5 adds `Execute`,
//! `ProcessStatus`, `TerminateProcess`, and `WaitProcess`.
//!
//! The handler is synchronous; async backends (filesystem, processes) are
//! driven via `tokio::task::block_in_place` + `block_on`, matching the
//! established Gate 4 pattern. This requires a multi-threaded Tokio
//! runtime (the daemon's `#[tokio::main]` default).

use std::sync::Arc;

use are_core::{
    CapabilitySet, EnvironmentId, GetEnvironmentInfoRequest, GetEnvironmentInfoResponse, Platform,
    RpcError, RpcRequest, RpcResponse, RpcResponsePayload,
};

use crate::fs::{FilesystemBackend, FsError};
use crate::process::{ProcessError, ProcessManager};

/// Daemon state needed to handle requests.
pub struct DaemonState {
    /// The environment this daemon serves.
    pub environment_id: EnvironmentId,
    /// Machine hostname.
    pub machine_name: String,
    /// Daemon version string.
    pub daemon_version: String,
    /// Operations this environment advertises as available.
    ///
    /// This is NOT per-client authorization — all clients see the same set.
    /// Per-client capability enforcement arrives in Gate 8.
    pub advertised_capabilities: CapabilitySet,
    /// Platform type.
    pub platform: Platform,
    /// Filesystem backend (None for backward-compatible tests without FS).
    pub fs: Option<FilesystemBackend>,
    /// Process manager (None when process execution is not configured).
    ///
    /// The manager is shared across connections: the process table lives in
    /// daemon memory, so a client can disconnect and a new connection can
    /// still query processes by id. It does NOT survive daemon restarts.
    /// Gate 6 will bind processes to sessions.
    pub proc: Option<Arc<ProcessManager>>,
}

impl DaemonState {
    /// Create a new `DaemonState` with the given configuration.
    pub fn new(
        environment_id: EnvironmentId,
        machine_name: String,
        daemon_version: String,
        advertised_capabilities: CapabilitySet,
        platform: Platform,
    ) -> Self {
        Self {
            environment_id,
            machine_name,
            daemon_version,
            advertised_capabilities,
            platform,
            fs: None,
            proc: None,
        }
    }

    /// Create a new `DaemonState` with a filesystem backend.
    pub fn with_fs(
        environment_id: EnvironmentId,
        machine_name: String,
        daemon_version: String,
        advertised_capabilities: CapabilitySet,
        platform: Platform,
        fs: FilesystemBackend,
    ) -> Self {
        Self {
            environment_id,
            machine_name,
            daemon_version,
            advertised_capabilities,
            platform,
            fs: Some(fs),
            proc: None,
        }
    }

    /// Attach a process manager (builder style, mirrors `with_fs` usage).
    pub fn with_proc(mut self, proc: Arc<ProcessManager>) -> Self {
        self.proc = Some(proc);
        self
    }

    /// Handle an RPC request and return a response.
    pub fn handle(&self, request: RpcRequest) -> RpcResponse {
        match request {
            RpcRequest::GetEnvironmentInfo(req) => {
                let result = self.handle_get_environment_info(req);
                RpcResponse {
                    result: result.map(RpcResponsePayload::GetEnvironmentInfo),
                }
            }
            RpcRequest::ReadFile(req) => {
                let result = self.handle_read_file(req);
                RpcResponse {
                    result: result.map(RpcResponsePayload::ReadFile),
                }
            }
            RpcRequest::ListDirectory(req) => {
                let result = self.handle_list_directory(req);
                RpcResponse {
                    result: result.map(RpcResponsePayload::ListDirectory),
                }
            }
            RpcRequest::GetFileMetadata(req) => {
                let result = self.handle_get_file_metadata(req);
                RpcResponse {
                    result: result.map(RpcResponsePayload::GetFileMetadata),
                }
            }
            RpcRequest::Execute(req) => {
                let result = self.handle_execute(req);
                RpcResponse {
                    result: result.map(RpcResponsePayload::Execute),
                }
            }
            RpcRequest::ProcessStatus(req) => {
                let result = self.handle_process_status(req);
                RpcResponse {
                    result: result.map(RpcResponsePayload::ProcessStatus),
                }
            }
            RpcRequest::TerminateProcess(req) => {
                let result = self.handle_terminate_process(req);
                RpcResponse {
                    result: result.map(RpcResponsePayload::TerminateProcess),
                }
            }
            RpcRequest::WaitProcess(req) => {
                let result = self.handle_wait_process(req);
                RpcResponse {
                    result: result.map(RpcResponsePayload::WaitProcess),
                }
            }
        }
    }

    fn handle_get_environment_info(
        &self,
        req: GetEnvironmentInfoRequest,
    ) -> Result<GetEnvironmentInfoResponse, RpcError> {
        // Validate that the requested environment matches this daemon's env.
        if req.environment_id != self.environment_id {
            return Err(RpcError::InvalidRequest(format!(
                "requested environment '{}' does not match daemon environment '{}'",
                req.environment_id, self.environment_id
            )));
        }

        Ok(GetEnvironmentInfoResponse {
            environment_id: self.environment_id.clone(),
            machine_name: self.machine_name.clone(),
            operating_system: std::env::consts::OS.to_string(),
            daemon_version: self.daemon_version.clone(),
            advertised_capabilities: self.advertised_capabilities.clone(),
            platform: self.platform.clone(),
        })
    }

    fn handle_read_file(
        &self,
        req: are_core::ReadFileRequest,
    ) -> Result<are_core::ReadFileResponse, RpcError> {
        if req.environment_id != self.environment_id {
            return Err(RpcError::InvalidRequest(format!(
                "requested environment '{}' does not match daemon environment '{}'",
                req.environment_id, self.environment_id
            )));
        }

        let fs = self
            .fs
            .as_ref()
            .ok_or_else(|| RpcError::InternalError("filesystem backend not configured".into()))?;

        let req_clone = req.clone();
        // Block on async FS operation within the sync handler.
        let (content, metadata) = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { fs.read_file(&req_clone.path).await })
        })
        .map_err(|e| fs_error_to_rpc(e, &req.path))?;

        Ok(are_core::ReadFileResponse { content, metadata })
    }

    fn handle_list_directory(
        &self,
        req: are_core::ListDirectoryRequest,
    ) -> Result<are_core::ListDirectoryResponse, RpcError> {
        if req.environment_id != self.environment_id {
            return Err(RpcError::InvalidRequest(format!(
                "requested environment '{}' does not match daemon environment '{}'",
                req.environment_id, self.environment_id
            )));
        }

        let fs = self
            .fs
            .as_ref()
            .ok_or_else(|| RpcError::InternalError("filesystem backend not configured".into()))?;

        let req_clone = req.clone();
        let entries = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { fs.list_directory(&req_clone.path).await })
        })
        .map_err(|e| fs_error_to_rpc(e, &req.path))?;

        Ok(are_core::ListDirectoryResponse { entries })
    }

    fn handle_get_file_metadata(
        &self,
        req: are_core::GetFileMetadataRequest,
    ) -> Result<are_core::GetFileMetadataResponse, RpcError> {
        if req.environment_id != self.environment_id {
            return Err(RpcError::InvalidRequest(format!(
                "requested environment '{}' does not match daemon environment '{}'",
                req.environment_id, self.environment_id
            )));
        }

        let fs = self
            .fs
            .as_ref()
            .ok_or_else(|| RpcError::InternalError("filesystem backend not configured".into()))?;

        let req_clone = req.clone();
        let metadata = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { fs.file_metadata(&req_clone.path).await })
        })
        .map_err(|e| fs_error_to_rpc(e, &req.path))?;

        Ok(are_core::GetFileMetadataResponse { metadata })
    }

    /// Require the process backend and check the environment binding first,
    /// mirroring the filesystem handlers.
    fn require_proc(
        &self,
        environment_id: &EnvironmentId,
    ) -> Result<Arc<ProcessManager>, RpcError> {
        if *environment_id != self.environment_id {
            return Err(RpcError::InvalidRequest(format!(
                "requested environment '{environment_id}' does not match daemon environment '{}'",
                self.environment_id
            )));
        }
        self.proc
            .clone()
            .ok_or_else(|| RpcError::InternalError("process backend not configured".into()))
    }

    fn handle_execute(
        &self,
        req: are_core::ExecuteRequest,
    ) -> Result<are_core::ExecuteResponse, RpcError> {
        let proc = self.require_proc(&req.environment_id)?;
        let process_id = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async { proc.start(req).await })
        })
        .map_err(process_error_to_rpc)?;
        Ok(are_core::ExecuteResponse { process_id })
    }

    fn handle_process_status(
        &self,
        req: are_core::ProcessStatusRequest,
    ) -> Result<are_core::ProcessStatusResponse, RpcError> {
        let proc = self.require_proc(&req.environment_id)?;
        proc.status(&req).map_err(process_error_to_rpc)
    }

    fn handle_terminate_process(
        &self,
        req: are_core::TerminateProcessRequest,
    ) -> Result<are_core::TerminateProcessResponse, RpcError> {
        let proc = self.require_proc(&req.environment_id)?;
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async { proc.terminate(req).await })
        })
        .map_err(process_error_to_rpc)
    }

    fn handle_wait_process(
        &self,
        req: are_core::WaitProcessRequest,
    ) -> Result<are_core::WaitProcessResponse, RpcError> {
        let proc = self.require_proc(&req.environment_id)?;
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async { proc.wait(req).await })
        })
        .map_err(process_error_to_rpc)
    }
}

/// Map a process error to an RPC error, preserving the error category so
/// clients can distinguish policy rejection (`DeniedExecutable`), unknown
/// ids (`NotFound`), malformed requests (`InvalidRequest`), and daemon
/// failures (`InternalError`).
fn process_error_to_rpc(err: ProcessError) -> RpcError {
    match err {
        ProcessError::InvalidRequest(msg) => RpcError::InvalidRequest(msg),
        ProcessError::EnvironmentMismatch(msg) => RpcError::InvalidRequest(msg),
        ProcessError::DeniedExecutable(msg) => RpcError::DeniedExecutable(msg),
        ProcessError::NotFound(msg) => RpcError::NotFound(msg),
        ProcessError::Io(msg) => RpcError::InternalError(msg),
        ProcessError::Internal(msg) => RpcError::InternalError(msg),
    }
}

/// Map a filesystem error to an RPC error, preserving the error category.
fn fs_error_to_rpc(err: FsError, path: &str) -> RpcError {
    match &err {
        FsError::InvalidPath(msg) => RpcError::InvalidRequest(format!("{path}: {msg}")),
        FsError::FilesystemEscape(msg) => {
            RpcError::InternalError(format!("filesystem escape blocked: {msg}"))
        }
        FsError::NotFound(_) => RpcError::InternalError(format!("{path}: not found")),
        FsError::PermissionDenied(_) => {
            RpcError::InternalError(format!("{path}: permission denied"))
        }
        FsError::NotADirectory(_) => RpcError::InternalError(format!("{path}: not a directory")),
        FsError::IsADirectory(_) => RpcError::InternalError(format!("{path}: is a directory")),
        FsError::FileTooLarge { path, size, limit } => RpcError::InternalError(format!(
            "file too large: {path} is {size} bytes, limit is {limit} bytes"
        )),
        FsError::Io(msg) => RpcError::InternalError(format!("{path}: I/O error: {msg}")),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use are_core::Capability;

    use crate::fs::FilesystemConfig;
    use crate::process::{ProcessConfig, ProcessManager};

    fn test_state() -> DaemonState {
        let mut caps = CapabilitySet::default();
        caps.insert(Capability::FilesystemRead);
        caps.insert(Capability::ProcessExecute);

        DaemonState::new(
            EnvironmentId::new("test-env"),
            "test-host".into(),
            "0.1.0".into(),
            caps,
            Platform::Debian,
        )
    }

    #[test]
    fn handle_get_environment_info_matching_env() {
        let state = test_state();
        let req = RpcRequest::GetEnvironmentInfo(GetEnvironmentInfoRequest {
            environment_id: EnvironmentId::new("test-env"),
        });

        let resp = state.handle(req);
        match resp.result {
            Ok(RpcResponsePayload::GetEnvironmentInfo(info)) => {
                assert_eq!(info.environment_id.as_str(), "test-env");
                assert_eq!(info.machine_name, "test-host");
                assert_eq!(info.daemon_version, "0.1.0");
                assert_eq!(info.platform, Platform::Debian);
                assert!(info
                    .advertised_capabilities
                    .contains(&Capability::FilesystemRead));
                assert!(info
                    .advertised_capabilities
                    .contains(&Capability::ProcessExecute));
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[test]
    fn handle_get_environment_info_wrong_env() {
        let state = test_state();
        let req = RpcRequest::GetEnvironmentInfo(GetEnvironmentInfoRequest {
            environment_id: EnvironmentId::new("wrong-env"),
        });

        let resp = state.handle(req);
        assert!(resp.result.is_err());
        match resp.result {
            Err(RpcError::InvalidRequest(msg)) => {
                assert!(msg.contains("does not match"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn handle_read_file_without_fs_backend() {
        let state = test_state();
        let req = RpcRequest::ReadFile(are_core::ReadFileRequest {
            environment_id: EnvironmentId::new("test-env"),
            path: "test.txt".into(),
        });

        let resp = state.handle(req);
        assert!(resp.result.is_err());
        match resp.result {
            Err(RpcError::InternalError(msg)) => {
                assert!(msg.contains("filesystem backend not configured"));
            }
            other => panic!("expected InternalError, got {other:?}"),
        }
    }

    #[test]
    fn handle_list_directory_without_fs_backend() {
        let state = test_state();
        let req = RpcRequest::ListDirectory(are_core::ListDirectoryRequest {
            environment_id: EnvironmentId::new("test-env"),
            path: ".".into(),
        });

        let resp = state.handle(req);
        assert!(resp.result.is_err());
        match resp.result {
            Err(RpcError::InternalError(msg)) => {
                assert!(msg.contains("filesystem backend not configured"));
            }
            other => panic!("expected InternalError, got {other:?}"),
        }
    }

    #[test]
    fn handle_get_file_metadata_without_fs_backend() {
        let state = test_state();
        let req = RpcRequest::GetFileMetadata(are_core::GetFileMetadataRequest {
            environment_id: EnvironmentId::new("test-env"),
            path: "test.txt".into(),
        });

        let resp = state.handle(req);
        assert!(resp.result.is_err());
        match resp.result {
            Err(RpcError::InternalError(msg)) => {
                assert!(msg.contains("filesystem backend not configured"));
            }
            other => panic!("expected InternalError, got {other:?}"),
        }
    }

    #[test]
    fn handle_read_file_wrong_env() {
        let state = test_state();
        let req = RpcRequest::ReadFile(are_core::ReadFileRequest {
            environment_id: EnvironmentId::new("wrong-env"),
            path: "test.txt".into(),
        });

        let resp = state.handle(req);
        assert!(resp.result.is_err());
        match resp.result {
            Err(RpcError::InvalidRequest(msg)) => {
                assert!(msg.contains("does not match"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn handle_list_directory_wrong_env() {
        let state = test_state();
        let req = RpcRequest::ListDirectory(are_core::ListDirectoryRequest {
            environment_id: EnvironmentId::new("wrong-env"),
            path: ".".into(),
        });

        let resp = state.handle(req);
        assert!(resp.result.is_err());
        match resp.result {
            Err(RpcError::InvalidRequest(msg)) => {
                assert!(msg.contains("does not match"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn handle_get_file_metadata_wrong_env() {
        let state = test_state();
        let req = RpcRequest::GetFileMetadata(are_core::GetFileMetadataRequest {
            environment_id: EnvironmentId::new("wrong-env"),
            path: "test.txt".into(),
        });

        let resp = state.handle(req);
        assert!(resp.result.is_err());
        match resp.result {
            Err(RpcError::InvalidRequest(msg)) => {
                assert!(msg.contains("does not match"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    // ---- Gate 5: process dispatch ----

    /// Build a `DaemonState` wired with a filesystem backend rooted at a
    /// temp dir and a permissive process manager.
    fn proc_state() -> (tempfile::TempDir, DaemonState) {
        let tmp = tempfile::TempDir::new().unwrap();
        let fs =
            FilesystemBackend::new(FilesystemConfig::new(&[tmp.path().to_path_buf()]).unwrap());
        let proc = Arc::new(ProcessManager::new(
            EnvironmentId::new("test-env"),
            ProcessConfig::default(),
            Some(fs.clone()),
        ));
        let mut caps = CapabilitySet::default();
        caps.insert(Capability::ProcessExecute);
        caps.insert(Capability::ProcessInspect);
        caps.insert(Capability::ProcessTerminate);
        let state = DaemonState::with_fs(
            EnvironmentId::new("test-env"),
            "test-host".into(),
            "0.1.0".into(),
            caps,
            Platform::Debian,
            fs,
        )
        .with_proc(proc);
        (tmp, state)
    }

    #[test]
    fn handle_execute_wrong_env_rejected_first() {
        let (_tmp, state) = proc_state();
        let req = RpcRequest::Execute(are_core::ExecuteRequest {
            environment_id: EnvironmentId::new("wrong-env"),
            program: "shutdown".into(),
            args: vec![],
            working_directory: ".".into(),
            env_vars: std::collections::HashMap::new(),
        });

        let resp = state.handle(req);
        match resp.result {
            Err(RpcError::InvalidRequest(msg)) => assert!(msg.contains("does not match")),
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn handle_execute_without_proc_backend() {
        let state = test_state();
        let req = RpcRequest::Execute(are_core::ExecuteRequest {
            environment_id: EnvironmentId::new("test-env"),
            program: "cargo".into(),
            args: vec![],
            working_directory: ".".into(),
            env_vars: std::collections::HashMap::new(),
        });

        let resp = state.handle(req);
        match resp.result {
            Err(RpcError::InternalError(msg)) => {
                assert!(msg.contains("process backend not configured"));
            }
            other => panic!("expected InternalError, got {other:?}"),
        }
    }

    #[test]
    fn handle_process_status_without_proc_backend() {
        let state = test_state();
        let req = RpcRequest::ProcessStatus(are_core::ProcessStatusRequest {
            environment_id: EnvironmentId::new("test-env"),
            process_id: are_core::ProcessId::new("proc-000001"),
        });

        let resp = state.handle(req);
        assert!(matches!(resp.result, Err(RpcError::InternalError(_))));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn handle_execute_denied_maps_to_denied_executable() {
        let (_tmp, state) = proc_state();
        let req = RpcRequest::Execute(are_core::ExecuteRequest {
            environment_id: EnvironmentId::new("test-env"),
            program: "shutdown".into(),
            args: vec![],
            working_directory: ".".into(),
            env_vars: std::collections::HashMap::new(),
        });

        let resp = state.handle(req);
        match resp.result {
            Err(RpcError::DeniedExecutable(msg)) => assert!(msg.contains("shutdown")),
            other => panic!("expected DeniedExecutable, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn handle_process_status_unknown_id_maps_to_not_found() {
        let (_tmp, state) = proc_state();
        let req = RpcRequest::ProcessStatus(are_core::ProcessStatusRequest {
            environment_id: EnvironmentId::new("test-env"),
            process_id: are_core::ProcessId::new("proc-999999"),
        });

        let resp = state.handle(req);
        assert!(matches!(resp.result, Err(RpcError::NotFound(_))));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn handle_wait_rejects_timeout_over_bound() {
        let (_tmp, state) = proc_state();
        let req = RpcRequest::WaitProcess(are_core::WaitProcessRequest {
            environment_id: EnvironmentId::new("test-env"),
            process_id: are_core::ProcessId::new("proc-000001"),
            timeout_secs: Some(are_core::MAX_WAIT_TIMEOUT_SECS + 1),
        });

        let resp = state.handle(req);
        assert!(matches!(resp.result, Err(RpcError::InvalidRequest(_))));
    }

    #[tokio::test(flavor = "multi_thread")]
    #[cfg(unix)]
    async fn handle_execute_wait_status_happy_path() {
        let (_tmp, state) = proc_state();
        if !std::path::Path::new("/bin/echo").exists() {
            return;
        }

        // Start.
        let req = RpcRequest::Execute(are_core::ExecuteRequest {
            environment_id: EnvironmentId::new("test-env"),
            program: "/bin/echo".into(),
            args: vec!["hello".into()],
            working_directory: ".".into(),
            env_vars: std::collections::HashMap::new(),
        });
        let resp = state.handle(req);
        let process_id = match resp.result {
            Ok(RpcResponsePayload::Execute(exec)) => exec.process_id,
            other => panic!("expected Execute response, got {other:?}"),
        };

        // Wait.
        let req = RpcRequest::WaitProcess(are_core::WaitProcessRequest {
            environment_id: EnvironmentId::new("test-env"),
            process_id: process_id.clone(),
            timeout_secs: Some(10),
        });
        let resp = state.handle(req);
        match resp.result {
            Ok(RpcResponsePayload::WaitProcess(wait)) => {
                assert_eq!(wait.stdout, b"hello\n");
                assert_eq!(wait.exit_code, Some(0));
                assert!(!wait.timed_out);
            }
            other => panic!("expected WaitProcess response, got {other:?}"),
        }

        // Status.
        let req = RpcRequest::ProcessStatus(are_core::ProcessStatusRequest {
            environment_id: EnvironmentId::new("test-env"),
            process_id,
        });
        let resp = state.handle(req);
        match resp.result {
            Ok(RpcResponsePayload::ProcessStatus(status)) => {
                assert_eq!(status.state, are_core::ProcessState::Exited { code: 0 });
            }
            other => panic!("expected ProcessStatus response, got {other:?}"),
        }
    }
}
