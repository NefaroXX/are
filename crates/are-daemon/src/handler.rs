//! Request dispatch and handler for the daemon.
//!
//! Handles `RpcRequest` variants and returns `RpcResponse` values.
//! Gate 3 handles `GetEnvironmentInfo`. Gate 4 adds `ReadFile`,
//! `ListDirectory`, and `GetFileMetadata`.

use are_core::{
    CapabilitySet, EnvironmentId, GetEnvironmentInfoRequest, GetEnvironmentInfoResponse, Platform,
    RpcError, RpcRequest, RpcResponse, RpcResponsePayload,
};

use crate::fs::{FilesystemBackend, FsError};

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
        }
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
}
