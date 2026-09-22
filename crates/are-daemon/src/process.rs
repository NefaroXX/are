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
//! - **Executable policy (fail-closed).** Every spawn is checked against a
//!   deny list (always enforced) and an allow list. When no allow list is
//!   configured the manager refuses to spawn anything unless explicit
//!   opt-in `permissive` mode is set (development only). Matching is by
//!   **normalized basename** (lowercase, `.exe` suffix stripped) — see
//!   [`ProcessConfig::check_policy`]. KNOWN LIMITATION: basename matching
//!   is bypassable by renamed copies and `PATH` shadowing; Gate 8 must do
//!   canonical-path allowlisting (+hash pinning).
//! - **Environment sanitization.** Request-supplied `PATH` is rejected
//!   outright (programs resolve against the daemon's trusted `PATH`);
//!   loader-influencing keys (`LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`,
//!   and all `LD_*` / `DYLD_*` keys) are stripped from the child
//!   environment. The child otherwise inherits the daemon's environment
//!   (`env_clear()` is NOT applied); per-process env scoping arrives with
//!   sessions (Gate 6).
//! - **Working directory confinement.** The requested working directory is
//!   resolved through the existing [`FilesystemBackend`](crate::fs::resolve),
//!   reusing its boundary enforcement (traversal, symlink escape, TOCTOU
//!   mitigation). It must exist and be a directory. Remote-facing errors
//!   are generic (no canonical paths leak to clients); full paths appear
//!   only in server-side `tracing` logs.
//! - **Bounded output.** Stdout/stderr are each capped at
//!   `max_output_bytes` (default 8 MiB per stream). Excess bytes are
//!   discarded and the `truncated` flag is set, so a verbose child cannot
//!   exhaust daemon memory.
//! - **Bounded process table.** At most `max_processes` entries (default
//!   128) are retained. Spawning past the bound first evicts expired
//!   terminal entries (older than `retention_secs`, default 1h), then the
//!   oldest terminal entries; if every entry is still live the spawn is
//!   refused with [`ProcessError::TooManyProcesses`]. Eviction drops the
//!   table reference (and with it the retained output); in-flight waiters
//!   holding an `Arc` still complete. Live entries are never evicted.
//! - **Bounded pipe drain.** After the child exits, pipes are drained for
//!   at most `drain_timeout_secs` (default 5s): a detached descendant
//!   holding stdout/stderr open cannot wedge the entry in `Running`
//!   forever. On timeout the drain stops, `truncated` is set, and the
//!   final state is published with whatever was captured.
//! - **Unpredictable ids.** Process ids are `proc-` + 32 lowercase hex
//!   chars from a CSPRNG (`getrandom`), not sequential counters.
//! - **No signal distinction yet.** `tokio`'s kill is forceful (SIGKILL on
//!   Unix); graceful vs forceful termination arrives with Gate 12
//!   (signals). Both `force` values currently terminate forcefully —
//!   documented, not silent.
//! - **Terminate scope.** [`ProcessManager::terminate`] signals only the
//!   direct child (no process-group kill); grandchildren survive. See the
//!   method docs.
//!
//! Environment variables from the request are applied on top of the
//! daemon's inherited environment (PATH lookup for bare program names
//! requires it), minus the sanitized keys above. Per-process env scoping
//! arrives with sessions (Gate 6).

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
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
use tokio::sync::Notify;

use crate::fs::{FilesystemBackend, FsError};

/// Default per-stream output cap: 8 MiB.
pub const DEFAULT_MAX_OUTPUT_BYTES: usize = 8 * 1024 * 1024;

/// Default cap on retained process-table entries.
pub const DEFAULT_MAX_PROCESSES: usize = 128;

/// Default retention for terminal entries, in seconds (1 hour).
pub const DEFAULT_RETENTION_SECS: u64 = 3600;

/// Default bound on post-exit pipe draining, in seconds.
pub const DEFAULT_DRAIN_TIMEOUT_SECS: u64 = 5;

/// Programs that are always denied, matched by normalized basename.
const DEFAULT_DENIED_EXECUTABLES: &[&str] = &["shutdown", "reboot", "poweroff", "halt", "init"];

/// How often the supervisor polls `try_wait()`.
const POLL_INTERVAL: Duration = Duration::from_millis(10);

/// How long `terminate()` waits for the child to die after requesting the
/// kill before returning (the kill has been issued either way).
const TERMINATE_GRACE: Duration = Duration::from_secs(5);

/// Exact environment keys stripped from the child environment (dynamic
/// loader influence). See [`sanitize_env`].
const STRIPPED_ENV_EXACT: &[&str] = &["LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT"];

/// Environment key prefixes stripped from the child environment.
const STRIPPED_ENV_PREFIXES: &[&str] = &["LD_", "DYLD_"];

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

    /// Execution is refused because no allow list is configured and
    /// permissive mode is off (fail-closed default).
    #[error("execution refused by policy: {0}")]
    PolicyDenied(String),

    /// The process table is full of live processes; the spawn was refused
    /// rather than evicting running work.
    #[error("too many processes: {0}")]
    TooManyProcesses(String),

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
    /// Allowed program basenames. `None` means NO allow list is
    /// configured. Combined with `permissive == false` (the default) the
    /// manager is fail-closed: every spawn is refused with
    /// [`ProcessError::PolicyDenied`]. Set `permissive = true` (dev only)
    /// to restore the old allow-anything behavior, or provide `Some(set)`
    /// to require membership (an empty set denies everything).
    pub allowed_executables: Option<HashSet<String>>,
    /// Explicit opt-in to allow-anything (non-denied) execution when no
    /// allow list is configured. Default `false`. Development only: every
    /// spawn is logged at warn level.
    pub permissive: bool,
    /// Denied program basenames. Always enforced, checked before the allow
    /// list. Defaults to shutdown/reboot/poweroff/halt/init. Compared by
    /// normalized basename (see [`check_policy` normalization][ProcessConfig::check_policy]).
    pub denied_executables: HashSet<String>,
    /// Per-stream output cap in bytes (stdout and stderr each).
    pub max_output_bytes: usize,
    /// Maximum retained process-table entries. Spawning past this bound
    /// evicts terminal entries (expired first, then oldest); if all
    /// entries are live the spawn fails with
    /// [`ProcessError::TooManyProcesses`].
    pub max_processes: usize,
    /// Age in seconds after which a terminal entry becomes eligible for
    /// opportunistic eviction. Retained entries keep metadata plus the
    /// (already capped) output; eviction drops both.
    pub retention_secs: u64,
    /// Bound in seconds on post-exit pipe draining. A detached descendant
    /// holding stdout/stderr open cannot delay the final state longer
    /// than this; on timeout the drain stops, `truncated` is set, and the
    /// final state is published with whatever was captured.
    pub drain_timeout_secs: u64,
}

impl Default for ProcessConfig {
    fn default() -> Self {
        Self {
            allowed_executables: None,
            permissive: false,
            denied_executables: DEFAULT_DENIED_EXECUTABLES
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            max_processes: DEFAULT_MAX_PROCESSES,
            retention_secs: DEFAULT_RETENTION_SECS,
            drain_timeout_secs: DEFAULT_DRAIN_TIMEOUT_SECS,
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
    /// Matching is by **normalized basename**: [`program_basename`] split,
    /// lowercased, with a trailing `.exe` stripped — so `shutdown.exe`,
    /// `SHUTDOWN`, and `/sbin/shutdown` are all denied by the default deny
    /// list, and an allow entry of `git` also matches `git.exe`. Allow-list
    /// entries are normalized the same way before comparison.
    ///
    /// The deny list is always enforced; the allow list applies when
    /// configured. With no allow list and `permissive == false` every
    /// program is refused ([`ProcessError::PolicyDenied`], fail-closed).
    ///
    /// KNOWN LIMITATION (honest): basename-only matching is bypassable by
    /// renamed copies (`cp /sbin/shutdown /tmp/totally-fine`) and by `PATH`
    /// shadowing. This policy is a tripwire against accidents, not a
    /// sandbox. Gate 8 must do canonical-path allowlisting (+hash pinning).
    pub fn check_policy(&self, program: &str) -> Result<(), ProcessError> {
        let base = normalized_basename(program);
        if self
            .denied_executables
            .iter()
            .any(|d| normalize_exe_name(d) == base)
        {
            return Err(ProcessError::DeniedExecutable(format!(
                "program {base:?} is denied by execution policy"
            )));
        }
        if let Some(allowed) = &self.allowed_executables {
            if !allowed.iter().any(|a| normalize_exe_name(a) == base) {
                return Err(ProcessError::DeniedExecutable(format!(
                    "program {base:?} is not in the allowed executable list"
                )));
            }
        } else if self.permissive {
            tracing::warn!(
                program = %program,
                "no allowed_executables configured; permitting execution (explicit permissive development mode)"
            );
        } else {
            return Err(ProcessError::PolicyDenied(
                "no allowed executables configured".into(),
            ));
        }
        Ok(())
    }
}

/// Extract the basename of a program string, splitting on both `/` and `\`
/// so Windows-style paths match on any host.
///
/// Gate 5 compares basenames only. An allow entry of `cargo` matches both
/// `cargo` and `/usr/bin/cargo`.
pub fn program_basename(program: &str) -> &str {
    program.rsplit(['/', '\\']).next().unwrap_or(program)
}

/// Normalize a basename for policy comparison: ASCII-lowercase with a
/// single trailing `.exe` stripped.
///
/// Normalization exists so the deny list cannot be trivially bypassed by
/// case or extension on Windows (`shutdown.exe`, `SHUTDOWN.EXE`). It is
/// NOT a sandbox boundary — see the known-limitation note on
/// [`ProcessConfig::check_policy`].
fn normalize_exe_name(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    lower.strip_suffix(".exe").unwrap_or(&lower).to_string()
}

/// Basename + normalization in one step: the canonical form the policy
/// compares.
fn normalized_basename(program: &str) -> String {
    normalize_exe_name(program_basename(program))
}

/// Returns `true` for terminal states (output complete, final).
fn is_terminal(status: &ProcessState) -> bool {
    !matches!(status, ProcessState::Running)
}

/// Filter request-supplied environment variables for the child.
///
/// Removes dynamic-loader-influencing keys — exactly `LD_PRELOAD`,
/// `LD_LIBRARY_PATH`, `LD_AUDIT`, plus any key starting with `LD_` or
/// `DYLD_` — silently (count reported at debug level). `PATH` is NOT
/// handled here: it is rejected outright during validation (and
/// defense-in-depth in [`ProcessManager::start`]) because accepting a
/// client `PATH` would let callers redirect bare program names at
/// attacker-controlled directories. Everything else passes through on top
/// of the daemon's inherited environment.
fn sanitize_env(env_vars: &HashMap<String, String>) -> HashMap<String, String> {
    let mut out = HashMap::with_capacity(env_vars.len());
    let mut stripped = 0usize;
    for (key, value) in env_vars {
        if STRIPPED_ENV_EXACT.contains(&key.as_str())
            || STRIPPED_ENV_PREFIXES
                .iter()
                .any(|prefix| key.starts_with(prefix))
        {
            stripped += 1;
            continue;
        }
        out.insert(key.clone(), value.clone());
    }
    if stripped > 0 {
        tracing::debug!(
            stripped,
            "removed dynamic-loader environment keys from child environment"
        );
    }
    out
}

/// Allocate an unpredictable process id: `proc-` + 32 lowercase hex chars
/// from a CSPRNG (`getrandom`). Sequential ids would let any client guess
/// other clients' ids and poll/terminate their processes; 128 bits of
/// randomness make guessing infeasible.
fn alloc_process_id() -> Result<ProcessId, ProcessError> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes)
        .map_err(|e| ProcessError::Internal(format!("failed to generate process id: {e}")))?;
    let mut hex = String::with_capacity(32);
    for byte in bytes {
        hex.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        hex.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    ProcessId::try_new(format!("proc-{hex}"))
        .map_err(|e| ProcessError::Internal(format!("failed to allocate process id: {e}")))
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
    /// When the supervisor published the final state (`None` while
    /// running). Drives retention eviction.
    finished_at: Option<SystemTime>,
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
    /// Signaled by the supervisor when the final state is published.
    /// `wait()`/`terminate()` park on this instead of cloning output on
    /// every poll.
    notify: Notify,
}

// ---------------------------------------------------------------------------
// ProcessManager
// ---------------------------------------------------------------------------

/// Owns the daemon's process table: `(environment_id, process_id)` keys.
///
/// The table lives in daemon memory: it survives client disconnects (any
/// new connection can query by id) but NOT daemon restarts. Gate 6 will
/// bind processes to sessions; no session types are introduced here.
/// Retention is bounded (see [`ProcessConfig::max_processes`]): eviction
/// drops the table reference and the retained output with it, but waiters
/// that already hold an `Arc` still complete normally.
///
/// All locks are plain `std` mutexes held only for short critical sections
/// (never across `.await`), so blocking handlers and async tasks can share
/// the table safely.
pub struct ProcessManager {
    environment_id: EnvironmentId,
    config: ProcessConfig,
    fs: Option<FilesystemBackend>,
    processes: Mutex<HashMap<ProcessId, Arc<ProcessEntry>>>,
}

impl ProcessManager {
    /// Create a manager for one environment.
    ///
    /// `fs` resolves working directories with boundary enforcement. If
    /// `None`, `start()` fails — there is no unconstrained fallback.
    ///
    /// A fail-closed configuration (no allow list, `permissive == false`)
    /// is legal to construct but refuses every spawn; an error is logged
    /// here so the misconfiguration is visible at startup, not just at
    /// first-spawn time.
    pub fn new(
        environment_id: EnvironmentId,
        config: ProcessConfig,
        fs: Option<FilesystemBackend>,
    ) -> Self {
        if config.allowed_executables.is_none() && !config.permissive {
            tracing::error!(
                "process manager has no allowed_executables and permissive mode is off: \
                 all process spawns will be refused (fail-closed); \
                 configure --allow-exec or --permissive-exec"
            );
        }
        Self {
            environment_id,
            config,
            fs,
            processes: Mutex::new(HashMap::new()),
        }
    }

    /// Access the execution policy configuration.
    pub fn config(&self) -> &ProcessConfig {
        &self.config
    }

    /// Number of entries currently retained in the process table
    /// (running + retained terminal). Bounded by
    /// [`ProcessConfig::max_processes`].
    pub fn process_count(&self) -> usize {
        self.processes.lock().map(|t| t.len()).unwrap_or(0)
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
        // Defense in depth: `ExecuteRequest::validate` already rejects
        // `PATH`; refuse again here so a future validation change cannot
        // silently re-open PATH redirection.
        if req.env_vars.contains_key("PATH") {
            return Err(ProcessError::InvalidRequest(
                "env var PATH must not be supplied: programs resolve against the daemon's trusted PATH".into(),
            ));
        }

        let fs = self
            .fs
            .as_ref()
            .ok_or_else(|| ProcessError::Internal("filesystem backend not configured".into()))?;
        // Remote-facing workdir errors are generic: canonical paths must
        // not reach clients. Full detail goes to server-side logs.
        let workdir: PathBuf = fs.resolve(&req.working_directory).map_err(|e| {
            tracing::debug!("workdir resolve failed: {e}");
            match e {
                FsError::FilesystemEscape(_) => ProcessError::InvalidRequest(
                    "working_directory escapes allowed boundary".into(),
                ),
                _ => ProcessError::InvalidRequest("invalid working_directory".into()),
            }
        })?;
        let meta = tokio::fs::metadata(&workdir)
            .await
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => {
                    tracing::debug!(workdir = %workdir.display(), "workdir does not exist");
                    ProcessError::InvalidRequest("working_directory does not exist".into())
                }
                std::io::ErrorKind::PermissionDenied => {
                    tracing::debug!(workdir = %workdir.display(), "workdir permission denied");
                    ProcessError::InvalidRequest("working_directory permission denied".into())
                }
                _ => ProcessError::Io(format!("working_directory error: {e}")),
            })?;
        if !meta.is_dir() {
            tracing::debug!(workdir = %workdir.display(), "workdir is not a directory");
            return Err(ProcessError::InvalidRequest(
                "working_directory is not a directory".into(),
            ));
        }

        // INVARIANT: structured execution only. `Command::new(program)` with
        // `.args(args)` spawns the binary directly via exec — no shell is
        // ever involved, so shell metacharacters (`;`, `$()`, backticks,
        // `|`, `&&`, …) in `program` or `args` are passed literally to the
        // child. NEVER introduce `sh -c`, `cmd /c`, or equivalent here.
        let mut cmd = tokio::process::Command::new(&req.program);
        cmd.args(&req.args)
            .current_dir(&workdir)
            .envs(sanitize_env(&req.env_vars))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // The child must outlive client connections: dropping the last
            // `Child` handle must not kill it (reconnect + query by id).
            .kill_on_drop(false);

        let entry = Arc::new(ProcessEntry {
            environment_id: req.environment_id.clone(),
            program: req.program.clone(),
            started_at: SystemTime::now(),
            state: Mutex::new(ManagedState {
                status: ProcessState::Running,
                stdout: Vec::new(),
                stderr: Vec::new(),
                truncated: false,
                finished_at: None,
            }),
            kill_requested: AtomicBool::new(false),
            notify: Notify::new(),
        });
        // Reserve the table slot BEFORE spawning, in a single critical
        // section: a full table refuses without orphaning a child, and
        // concurrent spawns cannot overshoot the bound between a separate
        // check and insert. `Command::spawn` is synchronous, so no `.await`
        // happens while the table lock is held.
        let id = {
            let mut table = self
                .processes
                .lock()
                .map_err(|_| ProcessError::Internal("process table poisoned".into()))?;
            make_room_for_spawn(&mut table, &self.config)?;
            let mut chosen = None;
            for _ in 0..8 {
                let candidate = alloc_process_id()?;
                if !table.contains_key(&candidate) {
                    chosen = Some(candidate);
                    break;
                }
            }
            let id = chosen.ok_or_else(|| {
                ProcessError::Internal("repeated process id collisions; refusing spawn".into())
            })?;
            table.insert(id.clone(), Arc::clone(&entry));
            id
        };

        let mut child = cmd.spawn().map_err(|e| {
            // Spawn failed after reservation: release the slot so a failed
            // spawn does not consume table capacity.
            if let Ok(mut table) = self.processes.lock() {
                table.remove(&id);
            }
            ProcessError::Internal(format!("failed to spawn {:?}: {e}", req.program))
        })?;
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();

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
            Duration::from_secs(self.config.drain_timeout_secs),
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

    /// Wait for a process to exit, up to the requested timeout, returning
    /// the capped captured output.
    ///
    /// The loop parks on the entry's [`Notify`][Notify] and clones stdout /
    /// stderr exactly once, on the return path — never per poll.
    pub async fn wait(&self, req: WaitProcessRequest) -> Result<WaitProcessResponse, ProcessError> {
        req.validate()
            .map_err(|e| ProcessError::InvalidRequest(e.to_string()))?;
        let entry = self.lookup(&req.environment_id, &req.process_id)?;
        let deadline = Instant::now() + Duration::from_secs(req.timeout_secs);
        loop {
            // One short critical section. Buffers are cloned only on a
            // return path (terminal state or expired deadline).
            {
                let guard = entry
                    .state
                    .lock()
                    .map_err(|_| ProcessError::Internal("process state poisoned".into()))?;
                match &guard.status {
                    ProcessState::Running => {}
                    ProcessState::Exited { code } => {
                        let code = *code;
                        return Ok(WaitProcessResponse {
                            stdout: guard.stdout.clone(),
                            stderr: guard.stderr.clone(),
                            exit_code: Some(code),
                            timed_out: false,
                            truncated: guard.truncated,
                        });
                    }
                    ProcessState::Failed { .. } => {
                        return Ok(WaitProcessResponse {
                            stdout: guard.stdout.clone(),
                            stderr: guard.stderr.clone(),
                            exit_code: None,
                            timed_out: false,
                            truncated: guard.truncated,
                        });
                    }
                }
            }
            if Instant::now() >= deadline {
                let guard = entry
                    .state
                    .lock()
                    .map_err(|_| ProcessError::Internal("process state poisoned".into()))?;
                return Ok(WaitProcessResponse {
                    stdout: guard.stdout.clone(),
                    stderr: guard.stderr.clone(),
                    exit_code: None,
                    timed_out: true,
                    truncated: guard.truncated,
                });
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            // Park until the supervisor publishes the final state (or the
            // deadline elapses). Spurious wakeups just re-check above.
            let _ = tokio::time::timeout(remaining, entry.notify.notified()).await;
        }
    }

    /// Terminate a process.
    ///
    /// Only the **direct child** is signaled — there is no process-group
    /// kill, so grandchildren the child spawned (detached or not) survive.
    /// A detached descendant holding stdout/stderr open additionally delays
    /// only the pipe drain (bounded by `drain_timeout_secs`), never the
    /// final state: the entry still transitions to terminal on time.
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
        // Park on the supervisor's notification instead of polling output.
        let _ = tokio::time::timeout(TERMINATE_GRACE, async {
            loop {
                {
                    let guard = entry
                        .state
                        .lock()
                        .map_err(|_| ProcessError::Internal("process state poisoned".into()))?;
                    if guard.status != ProcessState::Running {
                        return Ok::<(), ProcessError>(());
                    }
                }
                entry.notify.notified().await;
            }
        })
        .await;
        // Kill issued; the supervisor will reap imminently.
        Ok(TerminateProcessResponse { terminated: true })
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

/// Make room for one new entry: evict expired terminal entries first, then
/// the oldest terminal entries, until `len < max_processes`. Live entries
/// are never evicted; if everything is live the spawn is refused with
/// [`ProcessError::TooManyProcesses`] rather than dropping running work.
///
/// Evicted entries lose their retained output with the table reference
/// (callers already holding an `Arc` — e.g. an in-flight `wait()` — still
/// complete normally).
fn make_room_for_spawn(
    table: &mut HashMap<ProcessId, Arc<ProcessEntry>>,
    config: &ProcessConfig,
) -> Result<(), ProcessError> {
    evict_expired_terminal_entries(table, config.retention_secs);
    if table.len() < config.max_processes {
        return Ok(());
    }
    evict_oldest_terminal_entries(table, config.max_processes);
    if table.len() >= config.max_processes {
        return Err(ProcessError::TooManyProcesses(format!(
            "process table full ({} entries, all live): refusing spawn",
            table.len()
        )));
    }
    Ok(())
}

/// Drop terminal entries whose final state is older than `retention_secs`.
fn evict_expired_terminal_entries(
    table: &mut HashMap<ProcessId, Arc<ProcessEntry>>,
    retention_secs: u64,
) {
    let now = SystemTime::now();
    let expired: Vec<ProcessId> = table
        .iter()
        .filter_map(|(id, entry)| {
            let guard = entry.state.lock().ok()?;
            if !is_terminal(&guard.status) {
                return None;
            }
            let finished = guard.finished_at?;
            let age = now.duration_since(finished).unwrap_or(Duration::ZERO);
            (age.as_secs() > retention_secs).then(|| id.clone())
        })
        .collect();
    let count = expired.len();
    for id in expired {
        table.remove(&id);
    }
    if count > 0 {
        tracing::debug!(evicted = count, "evicted expired terminal process entries");
    }
}

/// Drop the oldest terminal entries until `len < max`. Live entries are
/// never candidates, even if they are the oldest in the table.
fn evict_oldest_terminal_entries(
    table: &mut HashMap<ProcessId, Arc<ProcessEntry>>,
    max_processes: usize,
) {
    let mut terminal: Vec<(SystemTime, ProcessId)> = table
        .iter()
        .filter_map(|(id, entry)| {
            let guard = entry.state.lock().ok()?;
            if !is_terminal(&guard.status) {
                return None;
            }
            // `finished_at` is always set together with the terminal
            // status under the same lock; treat a missing stamp as
            // maximally old so it is evicted first.
            Some((
                guard.finished_at.unwrap_or(SystemTime::UNIX_EPOCH),
                id.clone(),
            ))
        })
        .collect();
    terminal.sort_by_key(|(finished, _)| *finished);
    let mut evicted = 0usize;
    for (_, id) in terminal {
        if table.len() < max_processes {
            break;
        }
        table.remove(&id);
        evicted += 1;
    }
    if evicted > 0 {
        tracing::debug!(
            evicted,
            "evicted oldest terminal process entries to bound table"
        );
    }
}

// ---------------------------------------------------------------------------
// Supervisor task (owns the Child)
// ---------------------------------------------------------------------------

/// Background task that owns the `Child`, collects capped output, and
/// records the final state. It lives as long as the daemon, independent of
/// any client connection — this is what makes reconnect-by-id work.
///
/// The final state is ALWAYS published: after the child exits, pipes are
/// drained for at most `drain_timeout` (a detached descendant holding them
/// open cannot wedge the entry in `Running` forever), then the status is
/// recorded and waiters are woken — even if the drain timed out.
async fn supervise(
    entry: Arc<ProcessEntry>,
    mut child: Child,
    stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
    max_output_bytes: usize,
    drain_timeout: Duration,
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
            // reaps the child and records the outcome. Only the direct
            // child is signaled — no process-group kill (grandchildren
            // survive; see `terminate()` docs).
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

    // Bounded drain (pipes normally close after exit, so this is instant;
    // a descendant holding them open only costs `drain_timeout`), then
    // ALWAYS publish the final state.
    await_drain(&entry, out_task, err_task, drain_timeout).await;
    if let Ok(mut guard) = entry.state.lock() {
        guard.status = final_status;
        guard.finished_at = Some(SystemTime::now());
    }
    entry.notify.notify_waiters();
}

/// Join the pipe-reader tasks with a bound. Returns `true` when both
/// readers reached EOF in time. On timeout the readers are aborted, the
/// entry is flagged `truncated` (drain incomplete — whatever was captured
/// is kept), and the caller must still publish the final state.
async fn await_drain(
    entry: &Arc<ProcessEntry>,
    out_task: tokio::task::JoinHandle<()>,
    err_task: tokio::task::JoinHandle<()>,
    timeout: Duration,
) -> bool {
    let out_abort = out_task.abort_handle();
    let err_abort = err_task.abort_handle();
    let joined = async {
        let _ = out_task.await;
        let _ = err_task.await;
    };
    if tokio::time::timeout(timeout, joined).await.is_ok() {
        return true;
    }
    out_abort.abort();
    err_abort.abort();
    if let Ok(mut guard) = entry.state.lock() {
        guard.truncated = true;
    }
    tracing::debug!("pipe drain timed out; published partial output with truncated=true");
    false
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

    fn running_entry() -> Arc<ProcessEntry> {
        Arc::new(ProcessEntry {
            environment_id: EnvironmentId::new("test-env"),
            program: "test".into(),
            started_at: SystemTime::now(),
            state: Mutex::new(ManagedState {
                status: ProcessState::Running,
                stdout: Vec::new(),
                stderr: Vec::new(),
                truncated: false,
                finished_at: None,
            }),
            kill_requested: AtomicBool::new(false),
            notify: Notify::new(),
        })
    }

    fn terminal_entry(age_secs: u64) -> Arc<ProcessEntry> {
        Arc::new(ProcessEntry {
            environment_id: EnvironmentId::new("test-env"),
            program: "test".into(),
            started_at: SystemTime::now(),
            state: Mutex::new(ManagedState {
                status: ProcessState::Exited { code: 0 },
                stdout: b"out".to_vec(),
                stderr: Vec::new(),
                truncated: false,
                finished_at: SystemTime::now().checked_sub(Duration::from_secs(age_secs)),
            }),
            kill_requested: AtomicBool::new(false),
            notify: Notify::new(),
        })
    }

    fn table_with(
        entries: Vec<(ProcessId, Arc<ProcessEntry>)>,
    ) -> HashMap<ProcessId, Arc<ProcessEntry>> {
        entries.into_iter().collect()
    }

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
    fn deny_list_catches_exe_and_case_variants() {
        let config = ProcessConfig::with_allow_list(&["git"]);
        for prog in [
            "shutdown.exe",
            "SHUTDOWN",
            "Shutdown.ExE",
            "C:\\Windows\\System32\\shutdown.exe",
            "/sbin/SHUTDOWN",
        ] {
            assert!(
                matches!(
                    config.check_policy(prog),
                    Err(ProcessError::DeniedExecutable(_))
                ),
                "{prog} must be denied"
            );
        }
    }

    #[test]
    fn allow_list_matches_normalized_names() {
        let config = ProcessConfig::with_allow_list(&["git"]);
        assert!(config.check_policy("git").is_ok());
        assert!(config.check_policy("/usr/bin/git").is_ok());
        // Same normalization applies to allow entries.
        assert!(config.check_policy("GIT.EXE").is_ok());
    }

    #[test]
    fn default_config_is_fail_closed() {
        let config = ProcessConfig::default();
        assert!(!config.permissive);
        assert!(matches!(
            config.check_policy("cargo"),
            Err(ProcessError::PolicyDenied(_))
        ));
        assert!(matches!(
            config.check_policy("/usr/bin/git"),
            Err(ProcessError::PolicyDenied(_))
        ));
    }

    #[test]
    fn permissive_mode_restores_allow_anything() {
        let config = ProcessConfig {
            permissive: true,
            ..ProcessConfig::default()
        };
        assert!(config.check_policy("cargo").is_ok());
        assert!(config.check_policy("/usr/bin/git").is_ok());
        // The deny list still applies in permissive mode.
        assert!(matches!(
            config.check_policy("shutdown"),
            Err(ProcessError::DeniedExecutable(_))
        ));
        assert!(matches!(
            config.check_policy("shutdown.exe"),
            Err(ProcessError::DeniedExecutable(_))
        ));
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
    fn sanitize_env_strips_loader_keys() {
        let env: HashMap<String, String> = HashMap::from([
            ("LD_PRELOAD".into(), "/tmp/evil.so".into()),
            ("LD_LIBRARY_PATH".into(), "/tmp/evil".into()),
            ("LD_AUDIT".into(), "/tmp/audit.so".into()),
            ("LD_CUSTOM".into(), "x".into()),
            ("DYLD_INSERT_LIBRARIES".into(), "/tmp/evil.dylib".into()),
            ("DYLD_FALLBACK_LIBRARY_PATH".into(), "/tmp".into()),
            ("RUST_LOG".into(), "debug".into()),
            ("PATH_LIKE".into(), "kept".into()),
        ]);
        let clean = sanitize_env(&env);
        assert_eq!(clean.len(), 2);
        assert_eq!(clean.get("RUST_LOG").map(String::as_str), Some("debug"));
        assert_eq!(clean.get("PATH_LIKE").map(String::as_str), Some("kept"));
    }

    #[test]
    fn expired_terminal_entries_are_evictable() {
        let mut table = table_with(vec![
            (ProcessId::new("proc-old"), terminal_entry(7200)),
            (ProcessId::new("proc-fresh"), terminal_entry(10)),
            (ProcessId::new("proc-live"), running_entry()),
        ]);
        evict_expired_terminal_entries(&mut table, 3600);
        assert!(!table.contains_key(&ProcessId::new("proc-old")));
        assert!(table.contains_key(&ProcessId::new("proc-fresh")));
        assert!(table.contains_key(&ProcessId::new("proc-live")));
    }

    #[test]
    fn oldest_terminal_evicted_first_and_live_never() {
        let mut table = table_with(vec![
            (ProcessId::new("proc-old"), terminal_entry(100)),
            (ProcessId::new("proc-new"), terminal_entry(10)),
            (ProcessId::new("proc-live"), running_entry()),
        ]);
        // Full table (3 entries, max=3): must drop exactly one terminal
        // entry — the oldest — to make room for a single new spawn.
        evict_oldest_terminal_entries(&mut table, 3);
        assert_eq!(table.len(), 2);
        assert!(!table.contains_key(&ProcessId::new("proc-old")));
        assert!(table.contains_key(&ProcessId::new("proc-new")));
        assert!(table.contains_key(&ProcessId::new("proc-live")));
    }

    #[test]
    fn make_room_refuses_when_all_live() {
        let config = ProcessConfig {
            max_processes: 2,
            ..ProcessConfig::default()
        };
        let mut table = table_with(vec![
            (ProcessId::new("proc-a"), running_entry()),
            (ProcessId::new("proc-b"), running_entry()),
        ]);
        let err = make_room_for_spawn(&mut table, &config).unwrap_err();
        assert!(matches!(err, ProcessError::TooManyProcesses(_)));
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn allocated_ids_are_unique_and_well_formed() {
        let mut seen = HashSet::new();
        for _ in 0..100 {
            let id = alloc_process_id().expect("alloc");
            assert!(id.as_str().starts_with("proc-"));
            assert_eq!(id.as_str().len(), "proc-".len() + 32);
            assert!(id
                .as_str()
                .chars()
                .skip("proc-".len())
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
            assert!(seen.insert(id.as_str().to_string()), "id collision");
        }
    }

    #[test]
    fn default_output_cap_is_8mib() {
        assert_eq!(ProcessConfig::default().max_output_bytes, 8 * 1024 * 1024);
    }

    #[test]
    fn default_table_bounds() {
        let config = ProcessConfig::default();
        assert_eq!(config.max_processes, DEFAULT_MAX_PROCESSES);
        assert_eq!(config.retention_secs, DEFAULT_RETENTION_SECS);
        assert_eq!(config.drain_timeout_secs, DEFAULT_DRAIN_TIMEOUT_SECS);
    }

    #[tokio::test]
    async fn bounded_drain_returns_when_readers_never_finish() {
        // Hermetic: pending reader tasks stand in for pipes held open by a
        // detached descendant. Works on every platform (no child needed).
        let entry = running_entry();
        let out_task = tokio::spawn(async { std::future::pending::<()>().await });
        let err_task = tokio::spawn(async { std::future::pending::<()>().await });
        let start = Instant::now();
        let drained = await_drain(&entry, out_task, err_task, Duration::from_millis(100)).await;
        assert!(!drained);
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "drain must be bounded, took {:?}",
            start.elapsed()
        );
        let guard = entry.state.lock().expect("state");
        assert!(guard.truncated, "timed-out drain must flag truncated");
    }

    #[tokio::test]
    async fn bounded_drain_fast_path_when_readers_done() {
        let entry = running_entry();
        let out_task = tokio::spawn(async {});
        let err_task = tokio::spawn(async {});
        let drained = await_drain(&entry, out_task, err_task, Duration::from_secs(5)).await;
        assert!(drained);
        let guard = entry.state.lock().expect("state");
        assert!(!guard.truncated);
    }
}
