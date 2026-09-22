//! # are-daemon
//!
//! The `ared` daemon — handles authentication, authorization, session
//! management, process management, and filesystem operations on the
//! remote machine.
//!
//! ## Gate 3 scope
//!
//! Gate 3 implements only:
//!
//! - TLS 1.3 mTLS listener
//! - `GetEnvironmentInfo` RPC
//! - Wire protocol (length-prefixed JSON over TLS TCP)
//!
//! No filesystem, process, or session operations are implemented yet.
//! Protocol selection is documented in `tls.rs` and `framing.rs`.

pub mod framing;
pub mod fs;
pub mod handler;
pub mod process;
pub mod server;
pub mod tls;

use are_core::{CapabilitySet, EnvironmentId, Platform};

/// Daemon configuration.
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    /// The environment this daemon serves.
    pub environment_id: EnvironmentId,
    /// The port to listen on.
    pub port: u16,
    /// Maximum concurrent sessions.
    pub max_sessions: usize,
    /// Path to server certificate PEM file.
    pub server_cert_path: Option<String>,
    /// Path to server private key PEM file.
    pub server_key_path: Option<String>,
    /// Path to CA certificate PEM file (for client verification).
    pub client_ca_path: Option<String>,
    /// Allowed root directory for filesystem operations.
    /// If None, defaults to the current working directory.
    pub allowed_root: Option<std::path::PathBuf>,
    /// Allowed program basenames for process execution (Gate 5 allow list).
    /// `None` means permissive development mode: any non-denied program may
    /// run (with a warning logged per spawn). The deny list
    /// (shutdown/reboot/poweroff/halt/init) is always enforced and is not
    /// configurable here.
    pub allowed_executables: Option<Vec<String>>,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            environment_id: EnvironmentId::new("default"),
            port: 9000,
            max_sessions: 64,
            server_cert_path: None,
            server_key_path: None,
            client_ca_path: None,
            allowed_root: None,
            allowed_executables: None,
        }
    }
}

/// Error type for daemon operations.
#[derive(Debug, thiserror::Error)]
pub enum DaemonError {
    #[error("bind failed: {0}")]
    BindFailed(String),

    #[error("TLS configuration failed: {0}")]
    TlsConfig(String),

    #[error("session limit reached")]
    SessionLimitReached,

    #[error("unauthorized")]
    Unauthorized,
}

/// Build a `DaemonState` from config, using the machine's hostname and
/// OS information.
pub fn build_daemon_state(config: &DaemonConfig) -> crate::handler::DaemonState {
    let machine_name = hostname::get()
        .map(|h| h.to_string_lossy().into_owned())
        .unwrap_or_else(|_| "unknown".into());

    let operating_system = std::env::consts::OS.to_string();
    let platform = detect_platform(&operating_system);

    let mut advertised_capabilities = CapabilitySet::default();
    // Gate 5: advertise only capabilities with enforceable handlers.
    // read_file → FilesystemRead, list_directory → FilesystemList,
    // file_metadata is an attribute read and maps to FilesystemRead.
    // execute → ProcessExecute, process_status → ProcessInspect,
    // terminate_process/wait_process → ProcessTerminate.
    // FilesystemWrite stays OUT (Gate 7).
    advertised_capabilities.insert(are_core::Capability::FilesystemRead);
    advertised_capabilities.insert(are_core::Capability::FilesystemList);
    advertised_capabilities.insert(are_core::Capability::ProcessExecute);
    advertised_capabilities.insert(are_core::Capability::ProcessInspect);
    advertised_capabilities.insert(are_core::Capability::ProcessTerminate);

    // Build filesystem backend if allowed_root is configured.
    let fs = config.allowed_root.as_ref().and_then(|root| {
        match crate::fs::FilesystemConfig::new(std::slice::from_ref(root)) {
            Ok(fs_config) => Some(crate::fs::FilesystemBackend::new(fs_config)),
            Err(e) => {
                eprintln!("WARNING: failed to configure filesystem backend: {e}");
                None
            }
        }
    });

    // Build the process manager: same environment binding, same filesystem
    // resolver for working-directory confinement, allow list from config.
    let mut proc_config = crate::process::ProcessConfig::default();
    if let Some(allowed) = &config.allowed_executables {
        proc_config.allowed_executables = Some(allowed.iter().cloned().collect());
    }
    let proc_manager = std::sync::Arc::new(crate::process::ProcessManager::new(
        config.environment_id.clone(),
        proc_config,
        fs.clone(),
    ));

    let mut state = crate::handler::DaemonState::new(
        config.environment_id.clone(),
        machine_name,
        env!("CARGO_PKG_VERSION").to_string(),
        advertised_capabilities,
        platform,
    );
    state.fs = fs;
    state.proc = Some(proc_manager);
    state
}

/// Detect the platform from the OS string.
fn detect_platform(os: &str) -> Platform {
    match os {
        "linux" => {
            // Try to detect distro from /etc/os-release
            if let Ok(content) = std::fs::read_to_string("/etc/os-release") {
                let lower = content.to_lowercase();
                if lower.contains("debian") {
                    return Platform::Debian;
                }
                if lower.contains("ubuntu") {
                    return Platform::Ubuntu;
                }
            }
            Platform::GenericLinux
        }
        other => Platform::Unknown(other.to_string()),
    }
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
    pub fn create_session(&mut self) -> are_core::SessionId {
        let id = are_core::SessionId::new(format!("sess-{}", self.next_id));
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

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn session_manager_creates_sessions() {
        let config = DaemonConfig {
            environment_id: EnvironmentId::new("test"),
            ..Default::default()
        };
        let mut mgr = SessionManager::new(config);
        let sid = mgr.create_session();
        assert!(!sid.as_str().is_empty());
    }

    #[test]
    fn not_at_capacity_by_default() {
        let config = DaemonConfig {
            environment_id: EnvironmentId::new("test"),
            max_sessions: 1,
            ..Default::default()
        };
        let mgr = SessionManager::new(config);
        assert!(!mgr.is_at_capacity());
    }

    #[test]
    fn build_daemon_state_uses_crate_version() {
        let config = DaemonConfig::default();
        let state = build_daemon_state(&config);
        assert_eq!(state.daemon_version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn build_daemon_state_has_all_capabilities() {
        let config = DaemonConfig::default();
        let state = build_daemon_state(&config);
        // Gate 5: only capabilities with enforceable handlers are advertised.
        assert!(state
            .advertised_capabilities
            .contains(&are_core::Capability::FilesystemRead));
        assert!(state
            .advertised_capabilities
            .contains(&are_core::Capability::FilesystemList));
        assert!(state
            .advertised_capabilities
            .contains(&are_core::Capability::ProcessExecute));
        assert!(state
            .advertised_capabilities
            .contains(&are_core::Capability::ProcessInspect));
        assert!(state
            .advertised_capabilities
            .contains(&are_core::Capability::ProcessTerminate));
        // FilesystemWrite is NOT advertised (Gate 7).
        assert!(!state
            .advertised_capabilities
            .contains(&are_core::Capability::FilesystemWrite));
        assert_eq!(state.advertised_capabilities.len(), 5);
    }

    #[test]
    fn build_daemon_state_with_valid_root() {
        let tmp = tempfile::TempDir::new().unwrap();
        let config = DaemonConfig {
            allowed_root: Some(tmp.path().to_path_buf()),
            ..Default::default()
        };
        let state = build_daemon_state(&config);
        assert!(state.fs.is_some());
    }

    #[test]
    fn build_daemon_state_without_root() {
        let config = DaemonConfig::default();
        let state = build_daemon_state(&config);
        assert!(state.fs.is_none());
    }

    #[test]
    fn build_daemon_state_wires_process_manager() {
        let tmp = tempfile::TempDir::new().unwrap();
        let config = DaemonConfig {
            allowed_root: Some(tmp.path().to_path_buf()),
            allowed_executables: Some(vec!["cargo".into(), "git".into()]),
            ..Default::default()
        };
        let state = build_daemon_state(&config);
        let proc = state.proc.expect("process manager must be wired");
        let allowed = proc
            .config()
            .allowed_executables
            .as_ref()
            .expect("allow list must be set");
        assert!(allowed.contains("cargo"));
        assert!(allowed.contains("git"));
    }

    #[test]
    fn build_daemon_state_process_manager_without_allow_list() {
        let config = DaemonConfig::default();
        let state = build_daemon_state(&config);
        let proc = state.proc.expect("process manager must be wired");
        assert!(proc.config().allowed_executables.is_none());
    }
}
