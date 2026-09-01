//! Environment domain model.

use serde::{Deserialize, Serialize};

use crate::{CapabilitySet, CoreError, EnvironmentId, Platform};

/// Metadata associated with an environment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentMetadata {
    /// ISO 8601 timestamp of environment creation.
    pub created_at: String,
    /// Semantic version of the environment configuration.
    pub version: String,
}

/// A remote environment: the core domain entity.
///
/// An `Environment` represents a single remote machine or container that an
/// agent can interact with. It carries identity, platform information,
/// granted capabilities, and descriptive metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Environment {
    /// Unique identifier for this environment.
    pub id: EnvironmentId,
    /// Human-readable name (must not be empty).
    pub name: String,
    /// Operating system / platform type.
    pub platform: Platform,
    /// Capabilities granted on this environment.
    pub capabilities: CapabilitySet,
    /// Additional metadata.
    pub metadata: EnvironmentMetadata,
}

impl Environment {
    /// Validate that all fields are internally consistent.
    pub fn validate(&self) -> Result<(), CoreError> {
        if self.name.is_empty() {
            return Err(CoreError::InvalidRequest(
                "environment name must not be empty".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::{Capability, EnvironmentId, Platform};

    fn make_env(name: &str) -> Environment {
        Environment {
            id: EnvironmentId::new("test-env"),
            name: name.to_owned(),
            platform: Platform::Debian,
            capabilities: CapabilitySet::from_iter([Capability::FilesystemRead]),
            metadata: EnvironmentMetadata {
                created_at: "2026-01-01T00:00:00Z".into(),
                version: "0.1.0".into(),
            },
        }
    }

    #[test]
    fn environment_validate_valid() {
        let env = make_env("my-env");
        assert!(env.validate().is_ok());
    }

    #[test]
    fn environment_validate_empty_name() {
        let mut env = make_env("ok");
        env.name = String::new();
        assert!(env.validate().is_err());
    }

    #[test]
    fn environment_serde_roundtrip() {
        let env = make_env("roundtrip");
        let json = serde_json::to_string(&env).unwrap();
        let back: Environment = serde_json::from_str(&json).unwrap();
        assert_eq!(env, back);
    }
}
