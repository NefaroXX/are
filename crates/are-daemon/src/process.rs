//! Secure structured process execution backend (Gate 5, session-bound in Gate 6).
//!
//! This is the highest-risk feature implemented so far. The rules:
//!
//! - **Structured execution only.** There is deliberately no
//!   `execute_shell("arbitrary string")`. Programs are spawned directly via
//!   `tokio::process::Command` with an explicit argv — shell metacharacters
//!   in `program` or `args` are passed literally and never interpreted.
//! - **Ownership: Environment → Session → Process.** Processes are keyed by
//!   `(environment_id, session_id, process_id)` in daemon memory. A lookup
//!   with the wrong session yields `NotFound`, indistinguishable from an
//!   unknown process id — no oracle into other sessions. The process table
//!   survives client disconnects (a new connection can query by id) but NOT
//!   daemon restarts. Session liveness is checked by the handler BEFORE
//!   every process operation (`touch`); the manager trusts the provided
//!   [`SessionInfo`](are_core::SessionInfo) and records its id. RACE NOTE:
//!   a session terminated between the handler's liveness check and `start`
//!   leaves a process in a just-terminated session; that process is then
//!   unreachable (its status/wait/terminate checks fail on the dead
//!   session). If it already exited, its terminal entry ages out by
//!   retention; if still live it survives until the next expiry sweep kills
//!   it — benign and fail-closed, never silently leaked by an expiry path
//!   that skips the kill.
//! - **Executable policy (fail-closed).** Every spawn is checked against a
//!   deny list (always enforced) and an allow list. When no allow list is
//!   configured the manager refuses to spawn anything unless explicit
//!   opt-in `permissive` mode is set (development only). Matching is by
//!   **normalized basename** (lowercase, `.exe` suffix stripped) — see
//!   [`ProcessConfig::check_policy`]. KNOWN LIMITATION: basename matching
//!   is bypassable by renamed copies and `PATH` shadowing; canonical-path
//!   allowlisting (+hash pinning) remains future work (deferred past Gate
//!   8 — grants match the same normalized basenames).
//! - **Environment sanitization and merge.** Merge order is daemon
//!   environment < session env < request env (request wins on conflicts).
//!   Request- and session-supplied `PATH` are rejected outright (programs
//!   resolve against the daemon's trusted `PATH`); loader-influencing keys
//!   (`LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_AUDIT`, and all `LD_*` / `DYLD_*`
//!   keys) are stripped from the child environment at session creation AND
//!   re-stripped at spawn merge (defense in depth). The child otherwise
//!   inherits the daemon's environment (`env_clear()` is NOT applied).
//! - **Working directory confinement + inheritance.** An empty request
//!   workdir (`""`) inherits the session's working directory; a non-empty
//!   one is resolved env-relative per ADR-002. Either way the effective
//!   directory is resolved through the existing
//!   [`FilesystemBackend`](crate::fs::resolve), reusing its boundary
//!   enforcement (traversal, symlink escape, TOCTOU mitigation). It must
//!   exist and be a directory. Remote-facing errors are generic (no
//!   canonical paths leak to clients); full paths appear only in
//!   server-side `tracing` logs.
//! - **Bounded output.** Stdout/stderr are each capped at
//!   `max_output_bytes` (default 8 MiB per stream). Excess bytes are
//!   discarded and the `truncated` flag is set, so a verbose child cannot
//!   exhaust daemon memory. These caps bound memory, not the wire: the
//!   transport-layer response-size guard (`framing::write_message_sized` →
//!   clean `RpcError::InternalError`) is the backstop that keeps even two
//!   full streams transmittable as a clean RPC error.
//! - **Bounded process table.** At most `max_processes` entries (default
//!   128) are retained, plus at most `max_processes_per_session` per
//!   session (default 32, live + retained terminal). Spawning past the
//!   global bound first evicts expired terminal entries (older than
//!   `retention_secs`, default 1h), then the oldest terminal entries; if
//!   every entry is still live the spawn is refused with
//!   [`ProcessError::TooManyProcesses`]. Eviction drops the table reference
//!   (and with it the retained output); in-flight waiters holding an `Arc`
//!   still complete. Live entries are never evicted. Eviction stays GLOBAL
//!   oldest-terminal-first: sessions share one pool (per-session retention
//!   accounting is deferred — a busy session's terminal entries may evict
//!   another session's).
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
//!   direct child (no process-group kill); grandchildren survive. Session
//!   termination cascades with the same direct-children-only limitation. See
//!   the method docs.
//!
//! Environment variables from the session and the request are applied on top
//! of the daemon's inherited environment (PATH lookup for bare program
//! names requires it), minus the sanitized keys above.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use are_core::{
    EnvironmentId, ExecuteRequest, ProcessId, ProcessState, ProcessStatusRequest,
    ProcessStatusResponse, SessionId, SessionInfo, TerminateProcessRequest,
    TerminateProcessResponse, WaitProcessRequest, WaitProcessResponse,
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
    /// Maximum retained entries per session (live + retained terminal).
    /// A spawn that would exceed this for its session is refused with
    /// [`ProcessError::TooManyProcesses`] even when the global table has
    /// room. Defaults to
    /// [`DEFAULT_MAX_PROCESSES_PER_SESSION`](crate::session::DEFAULT_MAX_PROCESSES_PER_SESSION).
    pub max_processes_per_session: usize,
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
            max_processes_per_session: crate::session::DEFAULT_MAX_PROCESSES_PER_SESSION,
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
    /// entries are normalized the same way before comparison. The single
    /// canonical normalization is [`are_core::normalize_program_name`],
    /// shared with Gate 8 grant matching so policy and grants cannot drift.
    ///
    /// The deny list is always enforced; the allow list applies when
    /// configured. With no allow list and `permissive == false` every
    /// program is refused ([`ProcessError::PolicyDenied`], fail-closed).
    ///
    /// KNOWN LIMITATION (honest): basename-only matching is bypassable by
    /// renamed copies (`cp /sbin/shutdown /tmp/totally-fine`) and by `PATH`
    /// shadowing. This policy is a tripwire against accidents, not a
    /// sandbox. Canonical-path allowlisting (+hash pinning) remains future
    /// work (deferred past Gate 8).
    pub fn check_policy(&self, program: &str) -> Result<(), ProcessError> {
        let base = are_core::normalize_program_name(program);
        if self
            .denied_executables
            .iter()
            .any(|d| are_core::normalize_program_name(d) == base)
        {
            return Err(ProcessError::DeniedExecutable(format!(
                "program {base:?} is denied by execution policy"
            )));
        }
        if let Some(allowed) = &self.allowed_executables {
            if !allowed
                .iter()
                .any(|a| are_core::normalize_program_name(a) == base)
            {
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

/// Returns `true` for terminal states (output complete, final).
fn is_terminal(status: &ProcessState) -> bool {
    !matches!(status, ProcessState::Running)
}

/// Filter environment variables for the child.
///
/// Removes dynamic-loader-influencing keys — exactly `LD_PRELOAD`,
/// `LD_LIBRARY_PATH`, `LD_AUDIT`, plus any key starting with `LD_` or
/// `DYLD_` — silently (count reported at debug level). `PATH` is NOT
/// handled here: it is rejected outright during validation (and
/// defense-in-depth in [`ProcessManager::start`]) because accepting a
/// client `PATH` would let callers redirect bare program names at
/// attacker-controlled directories. Everything else passes through on top
/// of the daemon's inherited environment.
///
/// `pub(crate)` so session creation can apply the same filter to stored
/// session env (the spawn merge re-applies it — defense in depth).
pub(crate) fn sanitize_env(env_vars: &HashMap<String, String>) -> HashMap<String, String> {
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

/// Merge session env under request env (request wins on conflicts),
/// then sanitize the union. `PATH` in either layer is a validation-time
/// rejection, not a silent strip; loader keys are stripped here even
/// though session creation stripped them too (defense in depth: stored
/// session env is trusted-but-verified at every spawn).
fn merge_session_env(
    session_env: &HashMap<String, String>,
    request_env: &HashMap<String, String>,
) -> HashMap<String, String> {
    let mut merged = HashMap::with_capacity(session_env.len() + request_env.len());
    for (key, value) in session_env {
        merged.insert(key.clone(), value.clone());
    }
    for (key, value) in request_env {
        merged.insert(key.clone(), value.clone());
    }
    sanitize_env(&merged)
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
///
/// Identity lives in the table key
/// (`(environment_id, session_id, process_id)`), not in this struct — the
/// entry holds only execution state.
struct ProcessEntry {
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

/// Table key: `(environment_id, session_id, process_id)`. A lookup with a
/// mismatched session misses exactly like an unknown process id — no
/// oracle into other sessions' processes.
type ProcessKey = (EnvironmentId, SessionId, ProcessId);

// ---------------------------------------------------------------------------
// ProcessManager
// ---------------------------------------------------------------------------

/// Owns the daemon's process table: `(environment_id, session_id,
/// process_id)` keys.
///
/// The table lives in daemon memory: it survives client disconnects (any
/// new connection can query by id) but NOT daemon restarts. Every entry
/// belongs to a session; session liveness is enforced by the handler before
/// any operation reaches this manager.
///
/// Retention is bounded (see [`ProcessConfig::max_processes`]): eviction
/// drops the table reference and the retained output with it, but waiters
/// that already hold an `Arc` still complete normally. Eviction is global
/// oldest-terminal-first across all sessions (shared pool).
///
/// All locks are plain `std` mutexes held only for short critical sections
/// (never across `.await`), so blocking handlers and async tasks can share
/// the table safely.
pub struct ProcessManager {
    environment_id: EnvironmentId,
    config: ProcessConfig,
    fs: Option<FilesystemBackend>,
    processes: Mutex<HashMap<ProcessKey, Arc<ProcessEntry>>>,
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

    /// Start a process from a structured request into a live session.
    ///
    /// `session` must be the live [`SessionInfo`](are_core::SessionInfo) the
    /// handler just touched (liveness checked pre-call; see the module docs
    /// for the benign TOCTOU note). `req.session_id` must match
    /// `session.session_id` — a mismatch is a programmer error
    /// (`Internal`), NOT a client oracle: cross-session lookups miss with
    /// `NotFound` in `status`/`wait`/`terminate`, never with a distinctive
    /// error.
    ///
    /// The program is spawned directly — never via a shell. See the module
    /// docs for the full security contract (env merge order, workdir
    /// inheritance, per-session cap).
    pub async fn start(
        &self,
        req: ExecuteRequest,
        session: &SessionInfo,
    ) -> Result<ProcessId, ProcessError> {
        req.validate()
            .map_err(|e| ProcessError::InvalidRequest(e.to_string()))?;
        if req.environment_id != self.environment_id {
            return Err(ProcessError::EnvironmentMismatch(format!(
                "requested environment '{}' does not match managed environment '{}'",
                req.environment_id, self.environment_id
            )));
        }
        if req.session_id != session.session_id {
            return Err(ProcessError::Internal(
                "session binding mismatch: touched session differs from request session".into(),
            ));
        }
        if session.environment_id != self.environment_id {
            return Err(ProcessError::Internal(
                "session belongs to a different environment".into(),
            ));
        }
        self.config.check_policy(&req.program)?;
        // Defense in depth: validation already rejects `PATH` in both the
        // request and session layers; refuse again here so a future
        // validation change cannot silently re-open PATH redirection.
        if req.env_vars.contains_key("PATH") || session.env_vars.contains_key("PATH") {
            return Err(ProcessError::InvalidRequest(
                "env var PATH must not be supplied: programs resolve against the daemon's trusted PATH".into(),
            ));
        }

        // Empty request workdir inherits the session's directory; either
        // way the effective directory is resolved with boundary
        // enforcement. The session workdir was validated at creation and is
        // re-resolved here (no stale canonical paths cross the boundary).
        let effective_workdir = if req.working_directory.is_empty() {
            session.working_directory.clone()
        } else {
            req.working_directory.clone()
        };
        let fs = self
            .fs
            .as_ref()
            .ok_or_else(|| ProcessError::Internal("filesystem backend not configured".into()))?;
        // Remote-facing workdir errors are generic: canonical paths must
        // not reach clients. Full detail goes to server-side logs.
        let workdir: PathBuf = fs.resolve(&effective_workdir).map_err(|e| {
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
            // Merge order: daemon env (inherited) < session env < request
            // env. Sanitized at every spawn (defense in depth over the
            // session-creation strip).
            .envs(merge_session_env(&session.env_vars, &req.env_vars))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // The child must outlive client connections: dropping the last
            // `Child` handle must not kill it (reconnect + query by id).
            .kill_on_drop(false);

        let entry = Arc::new(ProcessEntry {
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
        // happens while the table lock is held. Expired terminal entries
        // are purged BEFORE the per-session cap check: retention reaping
        // lives in `make_room_for_spawn`, so checking the cap first would
        // dead-end a session that holds only retention-expired terminals
        // (spawn refused forever, reaping never reached). Then the global
        // bound applies with oldest-terminal eviction.
        let id = {
            let mut table = self
                .processes
                .lock()
                .map_err(|_| ProcessError::Internal("process table poisoned".into()))?;
            evict_expired_terminal_entries(&mut table, self.config.retention_secs);
            let session_count = table
                .keys()
                .filter(|(env, sess, _)| *env == req.environment_id && *sess == req.session_id)
                .count();
            if session_count >= self.config.max_processes_per_session {
                return Err(ProcessError::TooManyProcesses(format!(
                    "session '{}' holds {} processes (cap {}): refusing spawn",
                    req.session_id, session_count, self.config.max_processes_per_session
                )));
            }
            make_room_for_spawn(&mut table, &self.config)?;
            let mut chosen: Option<ProcessKey> = None;
            for _ in 0..8 {
                let candidate = alloc_process_id()?;
                let candidate_key = (
                    req.environment_id.clone(),
                    req.session_id.clone(),
                    candidate,
                );
                if !table.contains_key(&candidate_key) {
                    chosen = Some(candidate_key);
                    break;
                }
            }
            let chosen_key = chosen.ok_or_else(|| {
                ProcessError::Internal("repeated process id collisions; refusing spawn".into())
            })?;
            let pid = chosen_key.2.clone();
            table.insert(chosen_key, Arc::clone(&entry));
            pid
        };

        let mut child = cmd.spawn().map_err(|e| {
            // Spawn failed after reservation: release the slot so a failed
            // spawn does not consume table capacity.
            if let Ok(mut table) = self.processes.lock() {
                table.remove(&(
                    req.environment_id.clone(),
                    req.session_id.clone(),
                    id.clone(),
                ));
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
    ///
    /// Lookup key is `(environment_id, session_id, process_id)`: a session
    /// mismatch misses exactly like an unknown id (`NotFound` — no oracle).
    pub fn status(
        &self,
        req: &ProcessStatusRequest,
    ) -> Result<ProcessStatusResponse, ProcessError> {
        let entry = self.lookup(&req.environment_id, &req.session_id, &req.process_id)?;
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
        let entry = self.lookup(&req.environment_id, &req.session_id, &req.process_id)?;
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
        let entry = self.lookup(&req.environment_id, &req.session_id, &req.process_id)?;
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

    /// Look up a process by its full `(environment_id, session_id,
    /// process_id)` key. Any miss — unknown id OR session mismatch — yields
    /// `NotFound` with no distinction (no oracle into other sessions).
    fn lookup(
        &self,
        environment_id: &EnvironmentId,
        session_id: &SessionId,
        process_id: &ProcessId,
    ) -> Result<Arc<ProcessEntry>, ProcessError> {
        let table = self
            .processes
            .lock()
            .map_err(|_| ProcessError::Internal("process table poisoned".into()))?;
        let entry = table
            .get(&(
                environment_id.clone(),
                session_id.clone(),
                process_id.clone(),
            ))
            .ok_or_else(|| ProcessError::NotFound(format!("unknown process id '{process_id}'")))?;
        Ok(Arc::clone(entry))
    }

    /// Number of table entries (live + retained terminal) belonging to one
    /// session. Used by tests and the per-session spawn cap path.
    pub fn count_for_session(&self, session_id: &SessionId) -> usize {
        self.processes
            .lock()
            .map(|table| {
                table
                    .keys()
                    .filter(|(_, sess, _)| *sess == *session_id)
                    .count()
            })
            .unwrap_or(0)
    }

    /// Best-effort kill of every LIVE process in a session
    /// (session-termination / session-expiry cascade). Sets the kill flag on
    /// each `Running` session entry and returns how many live kills were
    /// issued — already-terminal entries are neither signaled nor counted
    /// (counts live kills only). Only direct children are signaled (no
    /// process-group kill; grandchildren survive — the inherited Gate 5
    /// limitation). The supervisor tasks own the actual kills and reap
    /// imminently; terminal entries age out by retention.
    pub fn kill_session_processes(
        &self,
        environment_id: &EnvironmentId,
        session_id: &SessionId,
    ) -> usize {
        let targets: Vec<Arc<ProcessEntry>> = self
            .processes
            .lock()
            .map(|table| {
                table
                    .iter()
                    .filter(|((env, sess, _), _)| *env == *environment_id && *sess == *session_id)
                    .map(|(_, entry)| Arc::clone(entry))
                    .collect()
            })
            .unwrap_or_default();
        let mut count = 0usize;
        for entry in targets {
            let running = entry
                .state
                .lock()
                .map(|guard| guard.status == ProcessState::Running)
                .unwrap_or(false);
            if running {
                entry.kill_requested.store(true, Ordering::SeqCst);
                count += 1;
            }
        }
        if count > 0 {
            tracing::info!(
                session_id = %session_id,
                processes = count,
                "session cascade: kill requested for session processes"
            );
        }
        count
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
    table: &mut HashMap<ProcessKey, Arc<ProcessEntry>>,
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
    table: &mut HashMap<ProcessKey, Arc<ProcessEntry>>,
    retention_secs: u64,
) {
    let now = SystemTime::now();
    let expired: Vec<ProcessKey> = table
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
    table: &mut HashMap<ProcessKey, Arc<ProcessEntry>>,
    max_processes: usize,
) {
    let mut terminal: Vec<(SystemTime, ProcessKey)> = table
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

    fn test_session() -> SessionId {
        SessionId::new("sess-test")
    }

    fn test_key(pid: &str) -> ProcessKey {
        (
            EnvironmentId::new("test-env"),
            test_session(),
            ProcessId::new(pid),
        )
    }

    fn running_entry() -> Arc<ProcessEntry> {
        Arc::new(ProcessEntry {
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
        entries: Vec<(ProcessKey, Arc<ProcessEntry>)>,
    ) -> HashMap<ProcessKey, Arc<ProcessEntry>> {
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
            (test_key("proc-old"), terminal_entry(7200)),
            (test_key("proc-fresh"), terminal_entry(10)),
            (test_key("proc-live"), running_entry()),
        ]);
        evict_expired_terminal_entries(&mut table, 3600);
        assert!(!table.contains_key(&test_key("proc-old")));
        assert!(table.contains_key(&test_key("proc-fresh")));
        assert!(table.contains_key(&test_key("proc-live")));
    }

    #[test]
    fn oldest_terminal_evicted_first_and_live_never() {
        let mut table = table_with(vec![
            (test_key("proc-old"), terminal_entry(100)),
            (test_key("proc-new"), terminal_entry(10)),
            (test_key("proc-live"), running_entry()),
        ]);
        // Full table (3 entries, max=3): must drop exactly one terminal
        // entry — the oldest — to make room for a single new spawn.
        evict_oldest_terminal_entries(&mut table, 3);
        assert_eq!(table.len(), 2);
        assert!(!table.contains_key(&test_key("proc-old")));
        assert!(table.contains_key(&test_key("proc-new")));
        assert!(table.contains_key(&test_key("proc-live")));
    }

    #[test]
    fn make_room_refuses_when_all_live() {
        let config = ProcessConfig {
            max_processes: 2,
            ..ProcessConfig::default()
        };
        let mut table = table_with(vec![
            (test_key("proc-a"), running_entry()),
            (test_key("proc-b"), running_entry()),
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
        assert_eq!(
            config.max_processes_per_session,
            crate::session::DEFAULT_MAX_PROCESSES_PER_SESSION
        );
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
