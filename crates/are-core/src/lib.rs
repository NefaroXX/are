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
mod identity;
mod ids;
mod info;
mod platform;
mod request;
mod traits;

pub use capability::{Capability, CapabilitySet};
pub use environment::{Environment, EnvironmentMetadata};
pub use error::CoreError;
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
    DirectoryEntry, FileMetadata, ListDirectoryRequest, ListDirectoryResponse, ReadFileRequest,
    ReadFileResponse,
};
pub use traits::Environment as EnvironmentOps;
