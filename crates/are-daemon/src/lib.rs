//! # are-daemon
//!
//! The `ared` daemon — handles authentication, authorization, session
//! management, process management, and filesystem operations on the
//! remote machine.

use are_core::{EnvironmentId, SessionId};

/// Daemon configuration.
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct DaemonConfig {
    /// The environment this daemon serves.
    pub environment_id: EnvironmentId,
    /// The port to listen on.
    pub port: u16,
    /// Maximum concurrent sessions.
    pub max_sessions: usize,
}

/// Session manager tracking active sessions.
#[derive(Debug)]
#[allow(dead_code)]
pub struct SessionManager {
    config: DaemonConfig,
    next_id: usize,
}

#[allow(dead_code)]
impl SessionManager {
    /// Create a new session manager with the given config.
    pub fn new(config: DaemonConfig) -> Self {
        Self { config, next_id: 1 }
    }

    /// Create a new session. Returns a SessionId.
    pub fn create_session(&mut self) -> SessionId {
        let id = SessionId::new(format!("sess-{}", self.next_id));
        self.next_id += 1;
        id
    }

    /// Check if we're at capacity.
    pub fn is_at_capacity(&self) -> bool {
        false // stub
    }
}

/// Entry point for the daemon binary.
pub fn run(_config: DaemonConfig) -> Result<(), DaemonError> {
    // Placeholder — actual implementation in later gates.
    Ok(())
}

/// Error type for daemon operations.
#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error("bind failed: {0}")]
    BindFailed(String),

    #[error("session limit reached")]
    SessionLimitReached,

    #[error("unauthorized")]
    Unauthorized,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_manager_creates_sessions() {
        let config = DaemonConfig {
            environment_id: EnvironmentId::new("test"),
            port: 9000,
            max_sessions: 10,
        };
        let mut mgr = SessionManager::new(config);
        let sid = mgr.create_session();
        assert!(!sid.as_str().is_empty());
    }

    #[test]
    fn not_at_capacity_by_default() {
        let config = DaemonConfig {
            environment_id: EnvironmentId::new("test"),
            port: 9000,
            max_sessions: 1,
        };
        let mgr = SessionManager::new(config);
        assert!(!mgr.is_at_capacity());
    }
}
