//! Identifier newtypes with validation.
//!
//! Identifiers must be non-empty, at most 64 bytes, and composed of
//! ASCII lowercase alphanumeric characters, hyphens, underscores, or dots.

use serde::{Deserialize, Serialize};
use std::fmt;

use crate::CoreError;

/// Maximum byte length for identifiers.
const MAX_ID_LENGTH: usize = 64;

/// Returns `true` if the byte is in `[a-z0-9-_.]`.
fn is_valid_id_byte(b: u8) -> bool {
    matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.')
}

/// Validate a raw identifier string. Returns `Ok(())` or a descriptive `Err`.
fn validate_id_bytes(raw: &str) -> Result<(), String> {
    if raw.is_empty() {
        return Err("must not be empty".into());
    }
    if raw.len() > MAX_ID_LENGTH {
        return Err(format!(
            "length {} exceeds maximum {MAX_ID_LENGTH}",
            raw.len()
        ));
    }
    if !raw.bytes().all(is_valid_id_byte) {
        return Err("contains invalid characters (allowed: [a-z0-9-_.])".into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// EnvironmentId
// ---------------------------------------------------------------------------

/// Unique identifier for a remote environment (e.g. `"dev-vm"`, `"prod-web-01"`).
///
/// Valid identifiers are non-empty, at most 64 bytes, and contain only
/// lowercase ASCII alphanumeric characters, hyphens, underscores, or dots.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EnvironmentId(String);

impl EnvironmentId {
    /// Create an `EnvironmentId`, returning an error if the value is invalid.
    pub fn try_new(id: impl Into<String>) -> Result<Self, CoreError> {
        let raw = id.into();
        validate_id_bytes(&raw).map_err(CoreError::InvalidEnvironmentId)?;
        Ok(Self(raw))
    }

    /// Create an `EnvironmentId` without validation.
    ///
    /// # Panics
    ///
    /// Panics if the identifier is invalid. Intended for test code and
    /// other contexts where the input is statically known to be valid.
    #[allow(clippy::expect_used)]
    pub fn new(id: impl Into<String>) -> Self {
        Self::try_new(id).expect("invariant: EnvironmentId::new called with invalid id")
    }

    /// Access the raw identifier string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for EnvironmentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

// ---------------------------------------------------------------------------
// SessionId
// ---------------------------------------------------------------------------

/// Unique identifier for a session within an environment.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(String);

impl SessionId {
    /// Create a `SessionId`, returning an error if the value is invalid.
    pub fn try_new(id: impl Into<String>) -> Result<Self, CoreError> {
        let raw = id.into();
        validate_id_bytes(&raw).map_err(CoreError::InvalidSessionId)?;
        Ok(Self(raw))
    }

    /// Create a `SessionId` without validation.
    ///
    /// # Panics
    ///
    /// Panics if the identifier is invalid. Intended for test code only.
    #[allow(clippy::expect_used)]
    pub fn new(id: impl Into<String>) -> Self {
        Self::try_new(id).expect("invariant: SessionId::new called with invalid id")
    }

    /// Access the raw identifier string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

// ---------------------------------------------------------------------------
// ProcessId
// ---------------------------------------------------------------------------

/// Unique identifier for a process within a session.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessId(String);

impl ProcessId {
    /// Create a `ProcessId`, returning an error if the value is invalid.
    pub fn try_new(id: impl Into<String>) -> Result<Self, CoreError> {
        let raw = id.into();
        validate_id_bytes(&raw).map_err(CoreError::InvalidProcessId)?;
        Ok(Self(raw))
    }

    /// Create a `ProcessId` without validation.
    ///
    /// # Panics
    ///
    /// Panics if the identifier is invalid. Intended for test code only.
    #[allow(clippy::expect_used)]
    pub fn new(id: impl Into<String>) -> Self {
        Self::try_new(id).expect("invariant: ProcessId::new called with invalid id")
    }

    /// Access the raw identifier string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProcessId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    // ---- EnvironmentId ----

    #[test]
    fn env_id_try_new_valid() {
        let id = EnvironmentId::try_new("dev-vm").unwrap();
        assert_eq!(id.as_str(), "dev-vm");
    }

    #[test]
    fn env_id_try_new_with_dots_underscores() {
        let id = EnvironmentId::try_new("prod.web_01").unwrap();
        assert_eq!(id.as_str(), "prod.web_01");
    }

    #[test]
    fn env_id_try_new_empty_is_err() {
        assert!(EnvironmentId::try_new("").is_err());
    }

    #[test]
    fn env_id_try_new_too_long_is_err() {
        let long = "a".repeat(65);
        assert!(EnvironmentId::try_new(&long).is_err());
    }

    #[test]
    fn env_id_try_new_max_length_is_ok() {
        let max = "a".repeat(64);
        assert!(EnvironmentId::try_new(&max).is_ok());
    }

    #[test]
    fn env_id_try_new_invalid_charset_is_err() {
        assert!(EnvironmentId::try_new("has space").is_err());
        assert!(EnvironmentId::try_new("UPPER").is_err());
        assert!(EnvironmentId::try_new("slash/slash").is_err());
        assert!(EnvironmentId::try_new("colon:bad").is_err());
    }

    #[test]
    fn env_id_new_valid() {
        let id = EnvironmentId::new("test-vm");
        assert_eq!(id.as_str(), "test-vm");
    }

    #[test]
    #[should_panic(expected = "invariant: EnvironmentId::new called with invalid id")]
    fn env_id_new_invalid_panics() {
        let _ = EnvironmentId::new("");
    }

    #[test]
    fn env_id_display() {
        let id = EnvironmentId::new("my-env");
        assert_eq!(format!("{id}"), "my-env");
    }

    #[test]
    fn env_id_serde_roundtrip() {
        let id = EnvironmentId::new("roundtrip-env");
        let json = serde_json::to_string(&id).unwrap();
        let back: EnvironmentId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    // ---- SessionId ----

    #[test]
    fn session_id_try_new_valid() {
        let id = SessionId::try_new("sess-001").unwrap();
        assert_eq!(id.as_str(), "sess-001");
    }

    #[test]
    fn session_id_try_new_empty_is_err() {
        assert!(SessionId::try_new("").is_err());
    }

    #[test]
    fn session_id_display() {
        let id = SessionId::new("s1");
        assert_eq!(format!("{id}"), "s1");
    }

    #[test]
    fn session_id_serde_roundtrip() {
        let id = SessionId::new("sess-rt");
        let json = serde_json::to_string(&id).unwrap();
        let back: SessionId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    // ---- ProcessId ----

    #[test]
    fn process_id_try_new_valid() {
        let id = ProcessId::try_new("proc-42").unwrap();
        assert_eq!(id.as_str(), "proc-42");
    }

    #[test]
    fn process_id_try_new_empty_is_err() {
        assert!(ProcessId::try_new("").is_err());
    }

    #[test]
    fn process_id_display() {
        let id = ProcessId::new("p1");
        assert_eq!(format!("{id}"), "p1");
    }

    #[test]
    fn process_id_serde_roundtrip() {
        let id = ProcessId::new("proc-rt");
        let json = serde_json::to_string(&id).unwrap();
        let back: ProcessId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }
}
