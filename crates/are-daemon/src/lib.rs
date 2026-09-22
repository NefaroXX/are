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
pub mod session;
pub mod tls;

use are_core::{CapabilitySet, EnvironmentId, Platform};

/// Daemon configuration.
///
/// `max_processes_per_session` is the single source of truth for the
/// per-session process cap: `build_daemon_state` copies it into BOTH
/// `SessionConfig` and `ProcessConfig`.
#[derive(Debug, Clone)]
pub struct DaemonConfig {
    /// The environment this daemon serves.
    pub environment_id: EnvironmentId,
    /// The port to listen on.
    pub port: u16,
    /// Maximum live sessions (Gate 6 session table bound).
    pub max_sessions: usize,
    /// Maximum processes per session (live + retained terminal), enforced
    /// by the process manager at spawn. `None` selects the default
    /// (`DEFAULT_MAX_PROCESSES_PER_SESSION`, currently 32).
    pub max_processes_per_session: Option<usize>,
    /// Session idle timeout in seconds (Gate 6 expiry).
    pub session_idle_timeout_secs: u64,
    /// Session maximum lifetime in seconds since creation (Gate 6 expiry).
    pub session_max_lifetime_secs: u64,
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
    /// `None` means NO allow list: with `permissive_exec == false` (the
    /// default) the daemon is fail-closed and refuses every spawn. The
    /// deny list (shutdown/reboot/poweroff/halt/init, plus `.exe` and
    /// case variants) is always enforced and is not configurable here.
    pub allowed_executables: Option<Vec<String>>,
    /// Explicit opt-in to allow-anything (non-denied) execution when no
    /// allow list is configured. Development only: every spawn is logged
    /// at warn level. See `--permissive-exec`.
    pub permissive_exec: bool,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            environment_id: EnvironmentId::new("default"),
            port: 9000,
            max_sessions: 64,
            max_processes_per_session: None,
            session_idle_timeout_secs: crate::session::DEFAULT_SESSION_IDLE_TIMEOUT_SECS,
            session_max_lifetime_secs: crate::session::DEFAULT_SESSION_MAX_LIFETIME_SECS,
            server_cert_path: None,
            server_key_path: None,
            client_ca_path: None,
            allowed_root: None,
            allowed_executables: None,
            permissive_exec: false,
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
    // Capabilities are derived from the backends actually constructed
    // below: no fs backend → no Filesystem* caps; no proc manager → no
    // Process* caps. Advertising a handler that is not wired would lie to
    // clients and turn every call into an InternalError.

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
    if fs.is_some() {
        advertised_capabilities.insert(are_core::Capability::FilesystemRead);
        advertised_capabilities.insert(are_core::Capability::FilesystemList);
    }
    // The process manager is always wired below, so Process* capabilities
    // are always advertised. If that ever becomes conditional, gate these
    // inserts on the manager actually existing.
    advertised_capabilities.insert(are_core::Capability::ProcessExecute);
    advertised_capabilities.insert(are_core::Capability::ProcessInspect);
    advertised_capabilities.insert(are_core::Capability::ProcessTerminate);

    // Build the process manager: same environment binding, same filesystem
    // resolver for working-directory confinement, allow list from config.
    let per_session_cap = config
        .max_processes_per_session
        .unwrap_or(crate::session::DEFAULT_MAX_PROCESSES_PER_SESSION);
    let mut proc_config = crate::process::ProcessConfig::default();
    if let Some(allowed) = &config.allowed_executables {
        proc_config.allowed_executables = Some(allowed.iter().cloned().collect());
    }
    proc_config.permissive = config.permissive_exec;
    proc_config.max_processes_per_session = per_session_cap;
    if config.permissive_exec {
        eprintln!(
            "WARNING: --permissive-exec is set: any non-denied program may run (development only)"
        );
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
    state.fs = fs.clone();
    state.proc = Some(proc_manager);
    // Sessions share the environment binding and filesystem resolver
    // (session working directories resolve against the same allowed roots).
    // The per-session process cap comes from the same `DaemonConfig`
    // source as the process manager's cap above (single source of truth).
    let session_config = crate::session::SessionConfig {
        idle_timeout_secs: config.session_idle_timeout_secs,
        max_lifetime_secs: config.session_max_lifetime_secs,
        max_sessions: config.max_sessions,
        max_processes_per_session: per_session_cap,
    };
    state.sessions = Some(std::sync::Arc::new(crate::session::SessionManager::new(
        config.environment_id.clone(),
        session_config,
        fs,
    )));
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
    fn session_defaults_match_session_config() {
        let config = DaemonConfig::default();
        assert_eq!(
            config.session_idle_timeout_secs,
            crate::session::DEFAULT_SESSION_IDLE_TIMEOUT_SECS
        );
        assert_eq!(
            config.session_max_lifetime_secs,
            crate::session::DEFAULT_SESSION_MAX_LIFETIME_SECS
        );
        assert_eq!(config.max_sessions, crate::session::DEFAULT_MAX_SESSIONS);
    }

    #[test]
    fn build_daemon_state_wires_session_manager() {
        let tmp = tempfile::TempDir::new().unwrap();
        let config = DaemonConfig {
            allowed_root: Some(tmp.path().to_path_buf()),
            ..Default::default()
        };
        let state = build_daemon_state(&config);
        let sessions = state.sessions.expect("session manager must be wired");
        assert_eq!(
            sessions.config().idle_timeout_secs,
            config.session_idle_timeout_secs
        );
        assert_eq!(
            sessions.config().max_lifetime_secs,
            config.session_max_lifetime_secs
        );
        assert_eq!(sessions.config().max_sessions, config.max_sessions);
        assert_eq!(
            sessions.config().max_processes_per_session,
            crate::session::DEFAULT_MAX_PROCESSES_PER_SESSION
        );
        let proc = state.proc.expect("process manager must be wired");
        assert_eq!(
            proc.config().max_processes_per_session,
            crate::session::DEFAULT_MAX_PROCESSES_PER_SESSION
        );
    }

    #[test]
    fn build_daemon_state_copies_per_session_cap_to_both_managers() {
        let tmp = tempfile::TempDir::new().unwrap();
        let config = DaemonConfig {
            allowed_root: Some(tmp.path().to_path_buf()),
            max_processes_per_session: Some(7),
            ..Default::default()
        };
        let state = build_daemon_state(&config);
        let sessions = state.sessions.expect("session manager must be wired");
        let proc = state.proc.expect("process manager must be wired");
        assert_eq!(sessions.config().max_processes_per_session, 7);
        assert_eq!(proc.config().max_processes_per_session, 7);
    }

    #[test]
    fn build_daemon_state_uses_crate_version() {
        let config = DaemonConfig::default();
        let state = build_daemon_state(&config);
        assert_eq!(state.daemon_version, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn build_daemon_state_has_all_capabilities() {
        let tmp = tempfile::TempDir::new().unwrap();
        let config = DaemonConfig {
            allowed_root: Some(tmp.path().to_path_buf()),
            ..Default::default()
        };
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
    fn build_daemon_state_derives_caps_from_backends() {
        // No allowed_root → no fs backend → no Filesystem* capabilities,
        // but Process* capabilities (manager always wired) remain.
        let config = DaemonConfig::default();
        let state = build_daemon_state(&config);
        assert!(state.fs.is_none());
        assert!(!state
            .advertised_capabilities
            .contains(&are_core::Capability::FilesystemRead));
        assert!(!state
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
        assert_eq!(state.advertised_capabilities.len(), 3);
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
        // Fail-closed: no allow list + no permissive opt-in.
        assert!(!proc.config().permissive);
    }

    #[test]
    fn build_daemon_state_permissive_exec_opt_in() {
        let config = DaemonConfig {
            permissive_exec: true,
            ..Default::default()
        };
        let state = build_daemon_state(&config);
        let proc = state.proc.expect("process manager must be wired");
        assert!(proc.config().permissive);
    }
}
