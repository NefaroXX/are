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
mod ids;
mod platform;
mod request;
mod traits;

pub use capability::{Capability, CapabilitySet};
pub use environment::{Environment, EnvironmentMetadata};
pub use error::CoreError;
pub use ids::{EnvironmentId, ProcessId, SessionId};
pub use platform::Platform;
pub use request::*;
pub use traits::Environment as EnvironmentOps;
