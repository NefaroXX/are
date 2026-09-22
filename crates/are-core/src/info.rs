//! GetEnvironmentInfo request/response types and RPC framing envelope.
//!
//! These types are transport-independent: they carry no knowledge of TLS,
//! TCP, or HTTP. They represent the domain-level data exchanged between
//! client and daemon for environment metadata queries.
//!
//! The RPC envelope wraps typed request/response payloads. Gate 3 uses a
//! sequential one-request-per-connection model; correlation IDs are not
//! needed and not included.

use serde::{Deserialize, Serialize};

use crate::{
    CapabilitySet, CoreError, EnvironmentId, ExecuteRequest, ExecuteResponse,
    GetFileMetadataRequest, GetFileMetadataResponse, ListDirectoryRequest, ListDirectoryResponse,
    Platform, ProcessStatusRequest, ProcessStatusResponse, ReadFileRequest, ReadFileResponse,
    TerminateProcessRequest, TerminateProcessResponse, WaitProcessRequest, WaitProcessResponse,
};

// ---------------------------------------------------------------------------
// GetEnvironmentInfo
// ---------------------------------------------------------------------------

/// Request to retrieve metadata about a remote environment.
///
/// The `environment_id` must match the daemon's configured environment.
/// This is Gate 3's only operational request — no filesystem, process, or
/// session operations are implemented yet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetEnvironmentInfoRequest {
    /// The environment to query. Must match the daemon's environment.
    pub environment_id: EnvironmentId,
}

impl GetEnvironmentInfoRequest {
    /// Validate the request fields.
    ///
    /// # Errors
    ///
    /// Returns `CoreError::InvalidRequest` if the environment_id is empty
    /// (in practice, `EnvironmentId` validation prevents this, but we check
    /// defensively).
    pub fn validate(&self) -> Result<(), CoreError> {
        // EnvironmentId validation already prevents empty/invalid ids,
        // but this is a belt-and-suspenders check.
        if self.environment_id.as_str().is_empty() {
            return Err(CoreError::InvalidRequest(
                "environment_id must not be empty".into(),
            ));
        }
        Ok(())
    }
}

/// Response containing metadata about a remote environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetEnvironmentInfoResponse {
    /// The environment's unique identifier.
    pub environment_id: EnvironmentId,
    /// Machine hostname (e.g. "dev-vm", "prod-web-01").
    pub machine_name: String,
    /// Operating system name (e.g. "linux", "debian").
    pub operating_system: String,
    /// Daemon software version (crate version string).
    pub daemon_version: String,
    /// Operations this environment advertises as available.
    ///
    /// This is NOT per-client authorization — all clients see the same set.
    /// Per-client capability enforcement arrives in Gate 8.
    pub advertised_capabilities: CapabilitySet,
    /// Platform type (Debian, Ubuntu, GenericLinux, etc.).
    pub platform: Platform,
}

// ---------------------------------------------------------------------------
// RPC Envelope
// ---------------------------------------------------------------------------

/// An RPC request wrapping a typed payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "payload")]
pub enum RpcRequest {
    /// Retrieve environment metadata.
    #[serde(rename = "get_environment_info")]
    GetEnvironmentInfo(GetEnvironmentInfoRequest),
    /// Read a file from the environment.
    #[serde(rename = "read_file")]
    ReadFile(ReadFileRequest),
    /// List directory contents.
    #[serde(rename = "list_directory")]
    ListDirectory(ListDirectoryRequest),
    /// Get file/directory metadata.
    #[serde(rename = "get_file_metadata")]
    GetFileMetadata(GetFileMetadataRequest),
    /// Execute a process (structured execution, no shell).
    #[serde(rename = "execute")]
    Execute(ExecuteRequest),
    /// Query process status.
    #[serde(rename = "process_status")]
    ProcessStatus(ProcessStatusRequest),
    /// Terminate a process.
    #[serde(rename = "terminate_process")]
    TerminateProcess(TerminateProcessRequest),
    /// Wait for a process to exit, up to a timeout.
    #[serde(rename = "wait_process")]
    WaitProcess(WaitProcessRequest),
}

/// An RPC response wrapping a typed result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcResponse {
    /// The result payload, or an error.
    pub result: Result<RpcResponsePayload, RpcError>,
}

/// Successful RPC response payloads.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum RpcResponsePayload {
    /// Environment metadata response.
    #[serde(rename = "get_environment_info")]
    GetEnvironmentInfo(GetEnvironmentInfoResponse),
    /// File read response.
    #[serde(rename = "read_file")]
    ReadFile(ReadFileResponse),
    /// Directory listing response.
    #[serde(rename = "list_directory")]
    ListDirectory(ListDirectoryResponse),
    /// File metadata response.
    #[serde(rename = "get_file_metadata")]
    GetFileMetadata(GetFileMetadataResponse),
    /// Process creation response.
    #[serde(rename = "execute")]
    Execute(ExecuteResponse),
    /// Process status response.
    #[serde(rename = "process_status")]
    ProcessStatus(ProcessStatusResponse),
    /// Process termination response.
    #[serde(rename = "terminate_process")]
    TerminateProcess(TerminateProcessResponse),
    /// Process wait response (capped captured output).
    #[serde(rename = "wait_process")]
    WaitProcess(WaitProcessResponse),
}

/// RPC-level error, distinct from `CoreError` (which is domain-level).
///
/// `RpcError` represents transport/framing/protocol failures. `CoreError`
/// is carried inside a successful RPC response as a domain-level failure.
#[derive(Debug, Clone, thiserror::Error, Serialize, Deserialize)]
#[serde(tag = "code", content = "message")]
pub enum RpcError {
    /// The request payload could not be deserialized.
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// The daemon does not recognize this request type.
    #[error("unknown request type: {0}")]
    UnknownRequestType(String),

    /// The requested process (or other resource) does not exist.
    /// Distinct from `InternalError` so clients can distinguish
    /// "unknown id" from daemon failures.
    #[error("not found: {0}")]
    NotFound(String),

    /// The requested executable is denied by the daemon's execution policy.
    /// Distinct from `InvalidRequest` so clients can distinguish policy
    /// rejection from malformed requests.
    #[error("executable denied by policy: {0}")]
    DeniedExecutable(String),

    /// An internal daemon error occurred.
    #[error("internal error: {0}")]
    InternalError(String),
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn get_environment_info_request_validate_ok() {
        let req = GetEnvironmentInfoRequest {
            environment_id: EnvironmentId::new("test-env"),
        };
        assert!(req.validate().is_ok());
    }

    #[test]
    fn get_environment_info_request_serde_roundtrip() {
        let req = GetEnvironmentInfoRequest {
            environment_id: EnvironmentId::new("dev-vm"),
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: GetEnvironmentInfoRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, back);
    }

    #[test]
    fn get_environment_info_response_serde_roundtrip() {
        let mut caps = CapabilitySet::default();
        caps.insert(crate::Capability::FilesystemRead);
        caps.insert(crate::Capability::ProcessExecute);

        let resp = GetEnvironmentInfoResponse {
            environment_id: EnvironmentId::new("prod-01"),
            machine_name: "prod-01".into(),
            operating_system: "linux".into(),
            daemon_version: "0.1.0".into(),
            advertised_capabilities: caps,
            platform: Platform::Debian,
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: GetEnvironmentInfoResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(resp, back);
    }

    #[test]
    fn rpc_request_serde_roundtrip() {
        let req = RpcRequest::GetEnvironmentInfo(GetEnvironmentInfoRequest {
            environment_id: EnvironmentId::new("dev"),
        });
        let json = serde_json::to_string(&req).unwrap();
        let back: RpcRequest = serde_json::from_str(&json).unwrap();
        // Compare via JSON since RpcRequest doesn't derive PartialEq
        let json2 = serde_json::to_string(&back).unwrap();
        assert_eq!(json, json2);
    }

    #[test]
    fn rpc_response_serde_roundtrip() {
        let mut caps = CapabilitySet::default();
        caps.insert(crate::Capability::FilesystemRead);

        let resp = RpcResponse {
            result: Ok(RpcResponsePayload::GetEnvironmentInfo(
                GetEnvironmentInfoResponse {
                    environment_id: EnvironmentId::new("dev"),
                    machine_name: "dev".into(),
                    operating_system: "linux".into(),
                    daemon_version: "0.1.0".into(),
                    advertised_capabilities: caps,
                    platform: Platform::GenericLinux,
                },
            )),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: RpcResponse = serde_json::from_str(&json).unwrap();
        let json2 = serde_json::to_string(&back).unwrap();
        assert_eq!(json, json2);
    }

    #[test]
    fn rpc_error_serde_roundtrip() {
        let err = RpcError::InvalidRequest("bad payload".into());
        let json = serde_json::to_string(&err).unwrap();
        let back: RpcError = serde_json::from_str(&json).unwrap();
        assert_eq!(format!("{err}"), format!("{back}"));
    }

    #[test]
    fn rpc_error_new_variants_roundtrip() {
        for err in [
            RpcError::NotFound("proc-1".into()),
            RpcError::DeniedExecutable("shutdown".into()),
        ] {
            let json = serde_json::to_string(&err).unwrap();
            let back: RpcError = serde_json::from_str(&json).unwrap();
            assert_eq!(format!("{err}"), format!("{back}"));
        }
    }

    #[test]
    fn rpc_request_read_file_roundtrip() {
        let req = RpcRequest::ReadFile(ReadFileRequest {
            environment_id: EnvironmentId::new("dev"),
            path: "/src/main.rs".into(),
        });
        let json = serde_json::to_string(&req).unwrap();
        let back: RpcRequest = serde_json::from_str(&json).unwrap();
        let json2 = serde_json::to_string(&back).unwrap();
        assert_eq!(json, json2);
    }

    #[test]
    fn rpc_request_list_directory_roundtrip() {
        let req = RpcRequest::ListDirectory(ListDirectoryRequest {
            environment_id: EnvironmentId::new("dev"),
            path: "/src".into(),
        });
        let json = serde_json::to_string(&req).unwrap();
        let back: RpcRequest = serde_json::from_str(&json).unwrap();
        let json2 = serde_json::to_string(&back).unwrap();
        assert_eq!(json, json2);
    }

    #[test]
    fn rpc_request_get_file_metadata_roundtrip() {
        let req = RpcRequest::GetFileMetadata(GetFileMetadataRequest {
            environment_id: EnvironmentId::new("dev"),
            path: "/src/main.rs".into(),
        });
        let json = serde_json::to_string(&req).unwrap();
        let back: RpcRequest = serde_json::from_str(&json).unwrap();
        let json2 = serde_json::to_string(&back).unwrap();
        assert_eq!(json, json2);
    }

    #[test]
    fn rpc_request_execute_roundtrip() {
        let req = RpcRequest::Execute(ExecuteRequest {
            environment_id: EnvironmentId::new("dev"),
            program: "cargo".into(),
            args: vec!["test".into()],
            working_directory: ".".into(),
            env_vars: std::collections::HashMap::new(),
        });
        let json = serde_json::to_string(&req).unwrap();
        let back: RpcRequest = serde_json::from_str(&json).unwrap();
        let json2 = serde_json::to_string(&back).unwrap();
        assert_eq!(json, json2);
    }

    #[test]
    fn rpc_request_process_status_roundtrip() {
        let req = RpcRequest::ProcessStatus(ProcessStatusRequest {
            environment_id: EnvironmentId::new("dev"),
            process_id: crate::ProcessId::new("proc-1"),
        });
        let json = serde_json::to_string(&req).unwrap();
        let back: RpcRequest = serde_json::from_str(&json).unwrap();
        let json2 = serde_json::to_string(&back).unwrap();
        assert_eq!(json, json2);
    }

    #[test]
    fn rpc_request_terminate_process_roundtrip() {
        let req = RpcRequest::TerminateProcess(TerminateProcessRequest {
            environment_id: EnvironmentId::new("dev"),
            process_id: crate::ProcessId::new("proc-1"),
            force: false,
        });
        let json = serde_json::to_string(&req).unwrap();
        let back: RpcRequest = serde_json::from_str(&json).unwrap();
        let json2 = serde_json::to_string(&back).unwrap();
        assert_eq!(json, json2);
    }

    #[test]
    fn rpc_request_wait_process_roundtrip() {
        let req = RpcRequest::WaitProcess(WaitProcessRequest {
            environment_id: EnvironmentId::new("dev"),
            process_id: crate::ProcessId::new("proc-1"),
            timeout_secs: Some(30),
        });
        let json = serde_json::to_string(&req).unwrap();
        let back: RpcRequest = serde_json::from_str(&json).unwrap();
        let json2 = serde_json::to_string(&back).unwrap();
        assert_eq!(json, json2);
    }

    #[test]
    fn rpc_response_process_roundtrip() {
        let cases = [
            RpcResponsePayload::Execute(ExecuteResponse {
                process_id: crate::ProcessId::new("proc-1"),
            }),
            RpcResponsePayload::ProcessStatus(ProcessStatusResponse {
                state: crate::ProcessState::Running,
            }),
            RpcResponsePayload::TerminateProcess(TerminateProcessResponse { terminated: true }),
            RpcResponsePayload::WaitProcess(WaitProcessResponse {
                stdout: b"out".to_vec(),
                stderr: vec![],
                exit_code: Some(0),
                timed_out: false,
                truncated: false,
            }),
        ];
        for payload in cases {
            let resp = RpcResponse {
                result: Ok(payload),
            };
            let json = serde_json::to_string(&resp).unwrap();
            let back: RpcResponse = serde_json::from_str(&json).unwrap();
            let json2 = serde_json::to_string(&back).unwrap();
            assert_eq!(json, json2);
        }
    }

    #[test]
    fn rpc_response_read_file_roundtrip() {
        let resp = RpcResponse {
            result: Ok(RpcResponsePayload::ReadFile(ReadFileResponse {
                content: b"hello".to_vec(),
                metadata: crate::request::FileMetadata {
                    size: 5,
                    modified_at: None,
                    is_dir: false,
                    is_file: true,
                },
            })),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: RpcResponse = serde_json::from_str(&json).unwrap();
        let json2 = serde_json::to_string(&back).unwrap();
        assert_eq!(json, json2);
    }

    #[test]
    fn rpc_response_list_directory_roundtrip() {
        let resp = RpcResponse {
            result: Ok(RpcResponsePayload::ListDirectory(ListDirectoryResponse {
                entries: vec![],
            })),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: RpcResponse = serde_json::from_str(&json).unwrap();
        let json2 = serde_json::to_string(&back).unwrap();
        assert_eq!(json, json2);
    }

    #[test]
    fn rpc_response_get_file_metadata_roundtrip() {
        let resp = RpcResponse {
            result: Ok(RpcResponsePayload::GetFileMetadata(
                GetFileMetadataResponse {
                    metadata: crate::request::FileMetadata {
                        size: 100,
                        modified_at: None,
                        is_dir: false,
                        is_file: true,
                    },
                },
            )),
        };
        let json = serde_json::to_string(&resp).unwrap();
        let back: RpcResponse = serde_json::from_str(&json).unwrap();
        let json2 = serde_json::to_string(&back).unwrap();
        assert_eq!(json, json2);
    }
}
