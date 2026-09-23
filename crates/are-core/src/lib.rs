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

#![forbid(unsafe_code)]

mod capability;
mod environment;
mod error;
mod grant;
mod identity;
mod ids;
mod info;
mod platform;
mod request;
mod traits;

pub use capability::{Capability, CapabilitySet};
pub use environment::{Environment, EnvironmentMetadata};
pub use error::CoreError;
pub use grant::{
    grants_allow_exec, grants_allow_fs, grants_allow_inspect, grants_allow_terminate,
    normalize_grant_root, normalize_program_name, root_covers, FsGrantKind, Grant,
};
pub use identity::{
    EnrollmentCredential, MachineIdentity, RevocationReason, TrustAnchor, ENROLLMENT_MAX_TTL_SECS,
};
pub use ids::{EnvironmentId, ProcessId, SessionId};
pub use info::{
    GetEnvironmentInfoRequest, GetEnvironmentInfoResponse, RpcError, RpcRequest, RpcResponse,
    RpcResponsePayload,
};
pub use platform::Platform;
pub use request::{
    is_valid_hash, now_secs, CreateDirectoryRequest, CreateDirectoryResponse, CreateSessionRequest,
    CreateSessionResponse, DeleteRequest, DeleteResponse, DirectoryEntry, ExecuteRequest,
    ExecuteResponse, FileMetadata, GetFileMetadataRequest, GetFileMetadataResponse,
    GetSessionRequest, GetSessionResponse, ListDirectoryRequest, ListDirectoryResponse,
    ListSessionsRequest, ListSessionsResponse, ProcessState, ProcessStatusRequest,
    ProcessStatusResponse, ReadFileRequest, ReadFileResponse, RenameRequest, RenameResponse,
    SessionInfo, TerminateProcessRequest, TerminateProcessResponse, TerminateSessionRequest,
    TerminateSessionResponse, WaitProcessRequest, WaitProcessResponse, WriteFileRequest,
    WriteFileResponse, HASH_HEX_LEN, MAX_EXEC_ARGS, MAX_EXEC_ARG_LEN, MAX_EXEC_ENV_KEY_LEN,
    MAX_EXEC_ENV_VALUE_LEN, MAX_EXEC_ENV_VARS, MAX_WAIT_TIMEOUT_SECS, MIN_WAIT_TIMEOUT_SECS,
};
pub use traits::Environment as EnvironmentOps;
