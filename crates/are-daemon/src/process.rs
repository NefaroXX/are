//! Secure structured process execution backend (Gate 5).
//!
//! This is the highest-risk feature implemented so far. The rules:
//!
//! - **Structured execution only.** There is deliberately no
//!   `execute_shell("arbitrary string")`. Programs are spawned directly via
//!   `tokio::process::Command` with an explicit argv — shell metacharacters
//!   in `program` or `args` are passed literally and never interpreted.
//! - **Ownership: Environment → Session → Process.** Sessions do not exist
//!   yet (Gate 6). Processes are keyed by `(environment_id, process_id)` in
//!   daemon memory. The process table survives client disconnects (a new
//!   connection can query by id) but NOT daemon restarts.
//! - **Executable policy.** Every spawn is checked against a deny list
//!   (always enforced) and an optional allow list (when configured, the
//!   program basename must be listed). Matching is by **basename** only:
//!   `/usr/bin/cargo` and `cargo` are treated identically. Canonical-path
//!   verification is deferred to Gate 8 (capabilities).
//! - **Working directory confinement.** The requested working directory is
//!   resolved through the existing [`FilesystemBackend`](crate::fs::resolve),
//!   reusing its boundary enforcement (traversal, symlink escape, TOCTOU
//!   mitigation). It must exist and be a directory.
//! - **Bounded output.** Stdout/stderr are each capped at
//!   `max_output_bytes` (default 8 MiB per stream). Excess bytes are
//!   discarded and the `truncated` flag is set, so a verbose child cannot
//!   exhaust daemon memory.
//! - **No signal distinction yet.** `tokio`'s kill is forceful (SIGKILL on
//!   Unix); graceful vs forceful termination arrives with Gate 12
//!   (signals). Both `force` values currently terminate forcefully —
//!   documented, not silent.
//!
//! Environment variables from the request are applied on top of the
//! daemon's inherited environment (PATH lookup for bare program names
//! requires it). Per-process env scoping arrives with sessions (Gate 6).

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use are_core::{
    EnvironmentId, ExecuteRequest, ProcessId, ProcessState, ProcessStatusRequest,
    ProcessStatusResponse, TerminateProcessRequest, TerminateProcessResponse, WaitProcessRequest,
    WaitProcessResponse,
};
use tokio::io::AsyncReadExt;
use tokio::process::{Child, ChildStderr, ChildStdout};

use crate::fs::FilesystemBackend;

/// Default per-stream output cap: 8 MiB.
pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 8 * 1024 * 1024;

/// Programs that are always denied, matched by basename.
const DEFAULT_DENIED_EXECUTABLES: &[&str] = &["shutdown", "reboot", "poweroff", "halt", "init"];

/// How often the supervisor polls `try_wait()` and how often `wait()` /
/// `terminate()` poll process state.
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// How long `terminate()` waits for the child to die after requesting the
/// kill before returning (the kill has been issued either way).
const TERMINATE_GRACE: Duration = Duration::from_secs(5);

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from process operations.
#[derive(Debug, thiserror::Error)]
pub enum ProcessError {
    /// The request failed validation.
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// The request's environment does not match the managed environment.
    #[error("environment mismatch: {0}")]
    EnvironmentMismatch(String),

    /// The program is rejected by the executable policy.
    #[error("executable denied by policy: {0}")]
    DeniedExecutable(String),

    /// No process with this id is known.
    #[error("process not found: {0}")]
    NotFound(String),

    /// An OS I/O error occurred.
    #[error("process I/O error: {0}")]
    Io(String),

    /// An internal daemon error occurred (spawn failure, poisoned lock…).
    #[error("internal process error: {0}")]
    Internal(String),
}

// ---------------------------------------------------------------------------
// Configuration and policy
// ---------------------------------------------------------------------------

/// Execution policy and resource limits for the process manager.
#[derive(Debug, Clone)]
pub struct ProcessConfig {
    /// Allowed program basenames. `None` means permissive development mode
    /// (any non-denied program may run, with a `tracing::warn!` per spawn).
    /// `Some(set)` requires the program basename to be a member — an empty
    /// set denies everything.
    pub allowed_executables: Option<HashSet<String>>,
    /// Denied program basenames. Always enforced, checked before the allow
    /// list. Defaults to shutdown/reboot/poweroff/halt/init.
    pub denied_executables: HashSet<String>,
    /// Per-stream output cap in bytes (stdout and stderr each).
    pub max_output_bytes: usize,
    /// Default wait timeout in seconds when the request leaves
    /// `timeout_secs` empty. `None` waits indefinitely.
    pub default_timeout_secs: Option<u64>,
}

impl Default for ProcessConfig {
    fn default() -> Self {
        Self {
            allowed_executables: None,
            denied_executables: DEFAULT_DENIED_EXECUTABLES
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            default_timeout_secs: None,
        }
    }
}

impl ProcessConfig {
    /// Build a config with an allow list of program basenames plus the
    /// default deny list.
    pub fn with_allow_list(names: &[&str]) -> Self {
        Self {
            allowed_executables: Some(names.iter().map(|s| (*s).to_string()).collect()),
            ..Self::default()
        }
    }

    /// Check a program against the execution policy.
    ///
    /// Matching is by basename (see [`program_basename`]). The deny list is
    /// always enforced; the allow list applies when configured.
    pub fn check_policy(&self, program: &str) -> Result<(), ProcessError> {
        let base = program_basename(program);
        if self.denied_executables.contains(base) {
            return Err(ProcessError::DeniedExecutable(format!(
                "program {base:?} is denied by execution policy"
            )));
        }
        if let Some(allowed) = &self.allowed_executables {
            if !allowed.contains(base) {
                return Err(ProcessError::DeniedExecutable(format!(
                    "program {base:?} is not in the allowed executable list"
                )));
            }
        } else {
            tracing::warn!(
                program = %program,
                "no allowed_executables configured; permitting execution (development mode)"
            );
        }
        Ok(())
    }
}

/// Extract the basename of a program string, splitting on both `/` and `\`
/// so Windows-style paths match on any host.
///
/// Gate 5 compares basenames only. An allow entry of `cargo` matches both
/// `cargo` and `/usr/bin/cargo`; a deny entry of `shutdown` matches
/// `./shutdown` and `C:\Windows\shutdown.exe`'s basename (`shutdown.exe`
/// does NOT match `shutdown` — exact basename equality is required).
pub fn program_basename(program: &str) -> &str {
    program.rsplit(['/', '\\']).next().unwrap_or(program)
}

// ---------------------------------------------------------------------------
// Managed process state
// ---------------------------------------------------------------------------

/// Mutable state of one managed process, guarded by a plain (blocking)
/// mutex that is only ever held for short, non-async critical sections.
#[derive(Debug)]
struct ManagedState {
    status: ProcessState,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    truncated: bool,
}

/// One entry in the process table.
struct ProcessEntry {
    environment_id: EnvironmentId,
    program: String,
    started_at: SystemTime,
    state: Mutex<ManagedState>,
    /// Set by `terminate()`; observed by the supervisor task, which owns
    /// the `Child` and performs the actual kill.
    kill_requested: AtomicBool,
}

// ---------------------------------------------------------------------------
// ProcessManager
// ---------------------------------------------------------------------------

/// Owns the daemon's process table: `(environment_id, process_id)` keys.
///
/// The table lives in daemon memory: it survives client disconnects (any
/// new connection can query by id) but NOT daemon restarts. Gate 6 will
/// bind processes to sessions; no session types are introduced here.
///
/// All locks are plain `std` mutexes held only for short critical sections
/// (never across `.await`), so blocking handlers and async tasks can share
/// the table safely.
pub struct ProcessManager {
    environment_id: EnvironmentId,
    config: ProcessConfig,
    fs: Option<FilesystemBackend>,
    processes: Mutex<HashMap<ProcessId, Arc<ProcessEntry>>>,
    next_id: AtomicU64,
}

impl ProcessManager {
    /// Create a manager for one environment.
    ///
    /// `fs` resolves working directories with boundary enforcement. If
    /// `None`, `start()` fails — there is no unconstrained fallback.
    pub fn new(
        environment_id: EnvironmentId,
        config: ProcessConfig,
        fs: Option<FilesystemBackend>,
    ) -> Self {
        Self {
            environment_id,
            config,
            fs,
            processes: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
        }
    }

    /// Access the execution policy configuration.
    pub fn config(&self) -> &ProcessConfig {
        &self.config
    }

    /// Start a process from a structured request.
    ///
    /// The program is spawned directly — never via a shell. See the module
    /// docs for the full security contract.
    pub async fn start(&self, req: ExecuteRequest) -> Result<ProcessId, ProcessError> {
        req.validate()
            .map_err(|e| ProcessError::InvalidRequest(e.to_string()))?;
        if req.environment_id != self.environment_id {
            return Err(ProcessError::EnvironmentMismatch(format!(
                "requested environment '{}' does not match managed environment '{}'",
                req.environment_id, self.environment_id
            )));
        }
        self.config.check_policy(&req.program)?;

        let fs = self
            .fs
            .as_ref()
            .ok_or_else(|| ProcessError::Internal("filesystem backend not configured".into()))?;
        let workdir: PathBuf = fs
            .resolve(&req.working_directory)
            .map_err(|e| ProcessError::InvalidRequest(format!("invalid working_directory: {e}")))?;
        let meta = tokio::fs::metadata(&workdir)
            .await
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => ProcessError::InvalidRequest(format!(
                    "working_directory '{}' does not exist",
                    req.working_directory
                )),
                std::io::ErrorKind::PermissionDenied => {
                    ProcessError::InvalidRequest("working_directory permission denied".into())
                }
                _ => ProcessError::Io(format!("working_directory error: {e}")),
            })?;
        if !meta.is_dir() {
            return Err(ProcessError::InvalidRequest(format!(
                "working_directory '{}' is not a directory",
                req.working_directory
            )));
        }

        // INVARIANT: structured execution only. `Command::new(program)` with
        // `.args(args)` spawns the binary directly via exec — no shell is
        // ever involved, so shell metacharacters (`;`, `$()`, backticks,
        // `|`, `&&`, …) in `program` or `args` are passed literally to the
        // child. NEVER introduce `sh -c`, `cmd /c`, or equivalent here.
        let mut cmd = tokio::process::Command::new(&req.program);
        cmd.args(&req.args)
            .current_dir(&workdir)
            .envs(&req.env_vars)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // The child must outlive client connections: dropping the last
            // `Child` handle must not kill it (reconnect + query by id).
            .kill_on_drop(false);

        let mut child = cmd.spawn().map_err(|e| {
            ProcessError::Internal(format!("failed to spawn {:?}: {e}", req.program))
        })?;
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();

        let n = self.next_id.fetch_add(1, Ordering::SeqCst);
        let id = ProcessId::try_new(format!("proc-{n:06}"))
            .map_err(|e| ProcessError::Internal(format!("failed to allocate process id: {e}")))?;

        let entry = Arc::new(ProcessEntry {
            environment_id: req.environment_id.clone(),
            program: req.program.clone(),
            started_at: SystemTime::now(),
            state: Mutex::new(ManagedState {
                status: ProcessState::Running,
                stdout: Vec::new(),
                stderr: Vec::new(),
                truncated: false,
            }),
            kill_requested: AtomicBool::new(false),
        });
        {
            let mut table = self
                .processes
                .lock()
                .map_err(|_| ProcessError::Internal("process table poisoned".into()))?;
            table.insert(id.clone(), Arc::clone(&entry));
        }

        tracing::info!(
            process_id = %id,
            program = %req.program,
            workdir = %workdir.display(),
            "process started"
        );
        tokio::spawn(supervise(
            entry,
            child,
            stdout,
            stderr,
            self.config.max_output_bytes,
        ));

        Ok(id)
    }

    /// Query the current status of a process (never blocks).
    pub fn status(
        &self,
        req: &ProcessStatusRequest,
    ) -> Result<ProcessStatusResponse, ProcessError> {
        let entry = self.lookup(&req.environment_id, &req.process_id)?;
        let guard = entry
            .state
            .lock()
            .map_err(|_| ProcessError::Internal("process state poisoned".into()))?;
        tracing::debug!(
            process_id = %req.process_id,
            program = %entry.program,
            age_secs = entry.started_at.elapsed().map(|d| d.as_secs()).unwrap_or(0),
            state = ?guard.status,
            "process status"
        );
        Ok(ProcessStatusResponse {
            state: guard.status.clone(),
        })
    }

    /// Wait for a process to exit, up to the requested (or configured
    /// default) timeout, returning the capped captured output.
    pub async fn wait(&self, req: WaitProcessRequest) -> Result<WaitProcessResponse, ProcessError> {
        req.validate()
            .map_err(|e| ProcessError::InvalidRequest(e.to_string()))?;
        let entry = self.lookup(&req.environment_id, &req.process_id)?;
        let timeout = req.timeout_secs.or(self.config.default_timeout_secs);
        let deadline = timeout.map(|s| Instant::now() + Duration::from_secs(s));
        loop {
            let (status, stdout, stderr, truncated) = {
                let guard = entry
                    .state
                    .lock()
                    .map_err(|_| ProcessError::Internal("process state poisoned".into()))?;
                (
                    guard.status.clone(),
                    guard.stdout.clone(),
                    guard.stderr.clone(),
                    guard.truncated,
                )
            };
            match status {
                ProcessState::Running => {
                    if deadline.is_some_and(|d| Instant::now() >= d) {
                        return Ok(WaitProcessResponse {
                            stdout,
                            stderr,
                            exit_code: None,
                            timed_out: true,
                            truncated,
                        });
                    }
                    tokio::time::sleep(POLL_INTERVAL).await;
                }
                ProcessState::Exited { code } => {
                    return Ok(WaitProcessResponse {
                        stdout,
                        stderr,
                        exit_code: Some(code),
                        timed_out: false,
                        truncated,
                    });
                }
                ProcessState::Failed { .. } => {
                    return Ok(WaitProcessResponse {
                        stdout,
                        stderr,
                        exit_code: None,
                        timed_out: false,
                        truncated,
                    });
                }
            }
        }
    }

    /// Terminate a process.
    ///
    /// Gate 5 has no SIGTERM/SIGKILL distinction: both paths issue a
    /// forceful kill (SIGKILL on Unix). Signal semantics arrive with
    /// Gate 12. Returns `terminated: true` when the process was running
    /// and a kill was issued (it is dead or will die imminently — confirm
    /// via `status`/`wait`); `false` when it had already exited.
    pub async fn terminate(
        &self,
        req: TerminateProcessRequest,
    ) -> Result<TerminateProcessResponse, ProcessError> {
        let entry = self.lookup(&req.environment_id, &req.process_id)?;
        {
            let guard = entry
                .state
                .lock()
                .map_err(|_| ProcessError::Internal("process state poisoned".into()))?;
            if guard.status != ProcessState::Running {
                return Ok(TerminateProcessResponse { terminated: false });
            }
        }
        if req.force {
            tracing::debug!(process_id = %req.process_id, "force terminate requested");
        } else {
            // Honest limitation: no graceful path exists yet (Gate 12).
            tracing::debug!(
                process_id = %req.process_id,
                "graceful terminate requested; performing forceful kill (no SIGTERM distinction in Gate 5)"
            );
        }
        entry.kill_requested.store(true, Ordering::SeqCst);
        let deadline = Instant::now() + TERMINATE_GRACE;
        loop {
            {
                let guard = entry
                    .state
                    .lock()
                    .map_err(|_| ProcessError::Internal("process state poisoned".into()))?;
                if guard.status != ProcessState::Running {
                    return Ok(TerminateProcessResponse { terminated: true });
                }
            }
            if Instant::now() >= deadline {
                // Kill issued; the supervisor will reap imminently.
                return Ok(TerminateProcessResponse { terminated: true });
            }
            tokio::time::sleep(POLL_INTERVAL).await;
        }
    }

    /// Look up a process, enforcing the environment binding.
    fn lookup(
        &self,
        environment_id: &EnvironmentId,
        process_id: &ProcessId,
    ) -> Result<Arc<ProcessEntry>, ProcessError> {
        let table = self
            .processes
            .lock()
            .map_err(|_| ProcessError::Internal("process table poisoned".into()))?;
        let entry = table
            .get(process_id)
            .ok_or_else(|| ProcessError::NotFound(format!("unknown process id '{process_id}'")))?;
        if entry.environment_id != *environment_id {
            return Err(ProcessError::EnvironmentMismatch(format!(
                "process '{process_id}' does not belong to environment '{environment_id}'"
            )));
        }
        Ok(Arc::clone(entry))
    }
}

// ---------------------------------------------------------------------------
// Supervisor task (owns the Child)
// ---------------------------------------------------------------------------

/// Background task that owns the `Child`, collects capped output, and
/// records the final state. It lives as long as the daemon, independent of
/// any client connection — this is what makes reconnect-by-id work.
async fn supervise(
    entry: Arc<ProcessEntry>,
    mut child: Child,
    stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
    max_output_bytes: usize,
) {
    let out_task = tokio::spawn(read_capped(
        stdout,
        Arc::clone(&entry),
        StreamKind::Stdout,
        max_output_bytes,
    ));
    let err_task = tokio::spawn(read_capped(
        stderr,
        Arc::clone(&entry),
        StreamKind::Stderr,
        max_output_bytes,
    ));

    // Poll for exit; `try_wait` never blocks, so the kill flag is always
    // observed promptly. `wait().await` cannot be used here because the
    // `Child` is owned solely by this task while `terminate()` must be able
    // to request a kill concurrently.
    let final_status: ProcessState = loop {
        if entry.kill_requested.load(Ordering::SeqCst) {
            // Best-effort forceful kill (SIGKILL on Unix); the loop below
            // reaps the child and records the outcome.
            if let Err(e) = child.start_kill() {
                tracing::debug!("start_kill failed (child may have exited): {e}");
            }
        }
        match child.try_wait() {
            Ok(Some(status)) => {
                break match status.code() {
                    Some(code) => ProcessState::Exited { code },
                    None => ProcessState::Failed {
                        message: "process terminated by signal".into(),
                    },
                };
            }
            Ok(None) => tokio::time::sleep(POLL_INTERVAL).await,
            Err(e) => {
                break ProcessState::Failed {
                    message: format!("failed to wait for child: {e}"),
                };
            }
        }
    };

    // Drain the readers (pipes close after exit, so this terminates) before
    // publishing the final state — `wait()` then returns complete output.
    let _ = out_task.await;
    let _ = err_task.await;
    if let Ok(mut guard) = entry.state.lock() {
        guard.status = final_status;
    }
}

/// Which pipe a reader task is draining.
#[derive(Debug, Clone, Copy)]
enum StreamKind {
    Stdout,
    Stderr,
}

/// Read a pipe to EOF, appending to the shared capped buffer.
async fn read_capped(
    pipe: Option<impl tokio::io::AsyncRead + Unpin>,
    entry: Arc<ProcessEntry>,
    kind: StreamKind,
    max_output_bytes: usize,
) {
    let Some(mut pipe) = pipe else { return };
    let mut chunk = [0u8; 8192];
    loop {
        match pipe.read(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => {
                let Ok(mut guard) = entry.state.lock() else {
                    break;
                };
                let target = match kind {
                    StreamKind::Stdout => &mut guard.stdout,
                    StreamKind::Stderr => &mut guard.stderr,
                };
                let room = max_output_bytes.saturating_sub(target.len());
                if room == 0 {
                    guard.truncated = true;
                    continue;
                }
                let take = n.min(room);
                target.extend_from_slice(&chunk[..take]);
                if take < n {
                    guard.truncated = true;
                }
            }
            Err(_) => break,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests (policy only — spawn tests live in tests/process_gate5.rs)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    #[test]
    fn basename_splits_unix_and_windows() {
        assert_eq!(program_basename("cargo"), "cargo");
        assert_eq!(program_basename("/usr/bin/cargo"), "cargo");
        assert_eq!(program_basename("./shutdown"), "shutdown");
        assert_eq!(
            program_basename("C:\\Windows\\System32\\cmd.exe"),
            "cmd.exe"
        );
        assert_eq!(program_basename("..\\reboot"), "reboot");
    }

    #[test]
    fn default_config_denies_shutdown_family() {
        let config = ProcessConfig::default();
        for prog in ["shutdown", "reboot", "poweroff", "halt", "init"] {
            assert!(
                matches!(
                    config.check_policy(prog),
                    Err(ProcessError::DeniedExecutable(_))
                ),
                "{prog} must be denied"
            );
        }
        // Basename matching: paths ending in a denied name are denied too.
        assert!(matches!(
            config.check_policy("/sbin/shutdown"),
            Err(ProcessError::DeniedExecutable(_))
        ));
    }

    #[test]
    fn default_config_is_permissive_with_warning() {
        let config = ProcessConfig::default();
        assert!(config.check_policy("cargo").is_ok());
        assert!(config.check_policy("/usr/bin/git").is_ok());
    }

    #[test]
    fn allow_list_restricts_to_members() {
        let config = ProcessConfig::with_allow_list(&["git"]);
        assert!(config.check_policy("git").is_ok());
        assert!(config.check_policy("/usr/bin/git").is_ok());
        assert!(matches!(
            config.check_policy("cargo"),
            Err(ProcessError::DeniedExecutable(_))
        ));
    }

    #[test]
    fn deny_list_wins_over_allow_list() {
        let mut config = ProcessConfig::with_allow_list(&["shutdown"]);
        // Explicitly allowed AND denied → denied.
        assert!(matches!(
            config.check_policy("shutdown"),
            Err(ProcessError::DeniedExecutable(_))
        ));
        // Empty allow list denies everything.
        config.allowed_executables = Some(HashSet::new());
        assert!(matches!(
            config.check_policy("cargo"),
            Err(ProcessError::DeniedExecutable(_))
        ));
    }

    #[test]
    fn default_output_cap_is_8mib() {
        assert_eq!(ProcessConfig::default().max_output_bytes, 8 * 1024 * 1024);
    }
}
