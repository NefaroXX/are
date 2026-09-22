//! Persistent agent sessions (Gate 6).
//!
//! Sessions are first-class: `Environment → Sessions → Processes`. Each
//! session carries a working directory and environment variables that
//! processes spawned into it inherit.
//!
//! # Persistence model (honest)
//!
//! Sessions live in **daemon memory**, addressable by id across connections
//! (every RPC is already a fresh TLS connection, so "client reconnect does
//! not invalidate session identity" means exactly this: no per-connection
//! state). Sessions do NOT survive daemon restarts — memory-only, like
//! processes. Connection loss changes nothing daemon-side: processes keep
//! running under their session; reconnect + `GetSession` resumes.
//!
//! # Expiry (lazy only — no background reaper)
//!
//! A session expires when its idle time exceeds `idle_timeout_secs`
//! (time since `last_activity`) or its age exceeds `max_lifetime_secs`
//! (time since `created_at`). Expiry is checked **on access** (`get`,
//! `touch`, `create` purge, `list` purge): an expired entry is removed and
//! the caller gets [`SessionError::Expired`]. There are deliberately no
//! background threads — reaping work happens on the request path, so expiry
//! observability is "next access after the deadline", not "at the deadline".
//!
//! KNOWN LEAK (expiry oracle): `NotFound` (never existed / terminated) vs
//! `Expired` (was once live) lets any client confirm an id was once live.
//! Gate 8 must return generic `NotFound` to non-owners once
//! [`SessionInfo`](are_core::SessionInfo)`.owner` is bound to the
//! client-cert identity, and add a cross-client indistinguishability test.
//! No behavior change today: owner binding does not exist yet.
//!
//! NO EXPIRY PATH SILENTLY ORPHANS LIVE CHILDREN: every expiry removal is
//! reported up to the handler (`get`/`touch` via `Expired`, `create`/`list`
//! via the returned purged ids, `terminate` via `Expired`), and the handler
//! best-effort kills that session's processes before returning. Live
//! processes therefore never become unaddressable table residents.
//!
//! # Concurrency
//!
//! Plain `std` mutexes held only for short critical sections (never across
//! `.await`), matching the process manager. Session ids are
//! `sess-` + 32 lowercase hex chars from a CSPRNG (`getrandom`) —
//! unguessable like process ids, so one client cannot guess another's
//! session and hijack it (session hijacking is a Gate 8 adversarial-test
//! item; unguessable ids are the Gate 6 baseline).
//!
//! # Cascade ordering
//!
//! `terminate` removes the session record; the caller (handler) kills
//! session processes via the process manager BEFORE removing the session
//! (kill-then-remove). A crash between the two leaves either a dead session
//! entry or orphaned processes — both fail closed on next access (session
//! ops check liveness first; orphaned processes are unreachable without a
//! live session id). NOTE: unreachable LIVE processes do NOT "age out by
//! retention" — retention evicts terminal entries only — so the handler
//! must kill on every expiry path (see above); only already-terminal
//! orphans age out.

use std::collections::HashMap;
use std::sync::Mutex;

use are_core::{now_secs, CreateSessionRequest, EnvironmentId, SessionId, SessionInfo};

use crate::fs::FilesystemBackend;

/// Default idle timeout: 1 hour.
pub const DEFAULT_SESSION_IDLE_TIMEOUT_SECS: u64 = 3600;

/// Default maximum session lifetime: 24 hours.
pub const DEFAULT_SESSION_MAX_LIFETIME_SECS: u64 = 86400;

/// Default cap on live sessions.
pub const DEFAULT_MAX_SESSIONS: usize = 64;

/// Default cap on processes per session (live + retained terminal).
pub const DEFAULT_MAX_PROCESSES_PER_SESSION: usize = 32;

/// Session lifecycle configuration.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Idle expiry in seconds: a session untouched for longer than this is
    /// expired on next access. Compared with strict `>` so a timeout of `N`
    /// still allows an age of exactly `N`.
    pub idle_timeout_secs: u64,
    /// Maximum lifetime in seconds since creation, regardless of activity.
    pub max_lifetime_secs: u64,
    /// Maximum live sessions. Creating past this bound first purges expired
    /// entries; if still full the creation is refused with
    /// [`SessionError::TooManySessions`].
    pub max_sessions: usize,
    /// Maximum processes per session (live + retained terminal un-evicted).
    /// Enforced by the process manager at spawn; populated from
    /// [`DaemonConfig`](crate::DaemonConfig), which is the single source of
    /// truth for both managers (see `build_daemon_state`).
    pub max_processes_per_session: usize,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            idle_timeout_secs: DEFAULT_SESSION_IDLE_TIMEOUT_SECS,
            max_lifetime_secs: DEFAULT_SESSION_MAX_LIFETIME_SECS,
            max_sessions: DEFAULT_MAX_SESSIONS,
            max_processes_per_session: DEFAULT_MAX_PROCESSES_PER_SESSION,
        }
    }
}

/// Errors from session operations.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// The request failed validation.
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    /// The request's environment does not match the managed environment.
    #[error("environment mismatch: {0}")]
    EnvironmentMismatch(String),

    /// No session with this id is known (never existed or terminated).
    /// NOTE: distinct from [`SessionError::Expired`], which leaks that the
    /// id was once live (expiry oracle). Gate 8 must return generic
    /// `NotFound` to non-owners; add a cross-client indistinguishability
    /// test then.
    #[error("session not found: {0}")]
    NotFound(String),

    /// The session expired (idle timeout or maximum lifetime). The entry
    /// has been removed; the client must create a new session. The handler
    /// best-effort kills this session's processes before surfacing this
    /// error, so no expiry path silently orphans live children.
    #[error("session expired: {0}")]
    Expired(String),

    /// The session table is full (all live); creation refused rather than
    /// dropping live sessions.
    #[error("too many sessions: {0}")]
    TooManySessions(String),

    /// An internal daemon error occurred (id generation, poisoned lock…).
    #[error("internal session error: {0}")]
    Internal(String),
}

/// One stored session: metadata only. Processes live in the process manager
/// keyed by `(environment_id, session_id, process_id)`.
#[derive(Debug, Clone)]
struct SessionRecord {
    info: SessionInfo,
}

/// Returns `true` when the record is expired at `now_secs`.
fn is_expired(info: &SessionInfo, config: &SessionConfig, now: u64) -> bool {
    let idle = now.saturating_sub(info.last_activity);
    let age = now.saturating_sub(info.created_at);
    idle > config.idle_timeout_secs || age > config.max_lifetime_secs
}

/// Allocate an unpredictable session id: `sess-` + 32 lowercase hex chars
/// from a CSPRNG (`getrandom`). Sequential ids would let any client guess
/// other clients' sessions and resume/hijack them; 128 bits of randomness
/// make guessing infeasible.
fn alloc_session_id() -> Result<SessionId, SessionError> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes)
        .map_err(|e| SessionError::Internal(format!("failed to generate session id: {e}")))?;
    let mut hex = String::with_capacity(32);
    for byte in bytes {
        hex.push(char::from_digit(u32::from(byte >> 4), 16).unwrap_or('0'));
        hex.push(char::from_digit(u32::from(byte & 0x0f), 16).unwrap_or('0'));
    }
    SessionId::try_new(format!("sess-{hex}"))
        .map_err(|e| SessionError::Internal(format!("failed to allocate session id: {e}")))
}

/// Strip dynamic-loader-influencing keys from stored session env
/// (defense in depth: the spawn path re-sanitizes the merged env again).
/// `PATH` is never present here — it is rejected at validation.
///
/// Reuses the process manager's [`sanitize_env`](crate::process::sanitize_env)
/// so the strip set cannot drift between session creation and spawn merge.
fn sanitize_stored_env(env_vars: &HashMap<String, String>) -> HashMap<String, String> {
    crate::process::sanitize_env(env_vars)
}

/// Owns the daemon's session table: `SessionId → SessionRecord`.
///
/// Memory-only: survives client disconnects (any new connection resumes by
/// id) but NOT daemon restarts. See the module docs for the expiry and
/// cascade contracts.
pub struct SessionManager {
    environment_id: EnvironmentId,
    config: SessionConfig,
    fs: Option<FilesystemBackend>,
    sessions: Mutex<HashMap<SessionId, SessionRecord>>,
}

impl SessionManager {
    /// Create a manager for one environment.
    ///
    /// `fs` resolves session working directories with boundary enforcement.
    /// If `None`, `create()` fails — there is no unconstrained fallback.
    pub fn new(
        environment_id: EnvironmentId,
        config: SessionConfig,
        fs: Option<FilesystemBackend>,
    ) -> Self {
        Self {
            environment_id,
            config,
            fs,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Access the session configuration.
    pub fn config(&self) -> &SessionConfig {
        &self.config
    }

    /// Number of sessions currently retained (live + not-yet-purged).
    /// Expired-but-unaccessed entries count until their next access purges
    /// them — this is the lazy-expiry contract, not a leak.
    pub fn session_count(&self) -> usize {
        self.sessions.lock().map(|t| t.len()).unwrap_or(0)
    }

    /// Create a session from a request.
    ///
    /// Validates env keys (same rules as execution, including `PATH`
    /// rejection), resolves the working directory through the filesystem
    /// backend (default `"."`; must exist and be a directory), enforces the
    /// session count bound (expired entries purged first), and allocates a
    /// CSPRNG id.
    ///
    /// Returns the new session plus the ids purged by the pre-creation
    /// expiry sweep. The caller (handler) must best-effort kill each purged
    /// session's processes: purged sessions may still own live children,
    /// and without the kill they would become unaddressable orphans.
    pub fn create(
        &self,
        req: CreateSessionRequest,
    ) -> Result<(SessionInfo, Vec<SessionId>), SessionError> {
        req.validate()
            .map_err(|e| SessionError::InvalidRequest(e.to_string()))?;
        if req.environment_id != self.environment_id {
            return Err(SessionError::EnvironmentMismatch(format!(
                "requested environment '{}' does not match managed environment '{}'",
                req.environment_id, self.environment_id
            )));
        }
        let fs = self.fs.as_ref().ok_or_else(|| {
            SessionError::InvalidRequest("filesystem backend not configured".into())
        })?;
        let workdir_rel = req.working_directory.as_deref().unwrap_or(".");
        // Resolve + validate now (fail fast): the relative string is stored
        // and re-resolved at every spawn, so a later deletion fails closed
        // at spawn time rather than using a stale directory.
        let workdir = fs.resolve(workdir_rel).map_err(|e| {
            tracing::debug!("session workdir resolve failed: {e}");
            SessionError::InvalidRequest("invalid working_directory".into())
        })?;
        let meta = std::fs::metadata(&workdir).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => {
                tracing::debug!(workdir = %workdir.display(), "session workdir does not exist");
                SessionError::InvalidRequest("working_directory does not exist".into())
            }
            std::io::ErrorKind::PermissionDenied => {
                tracing::debug!(workdir = %workdir.display(), "session workdir permission denied");
                SessionError::InvalidRequest("working_directory permission denied".into())
            }
            _ => SessionError::InvalidRequest(format!("working_directory error: {e}")),
        })?;
        if !meta.is_dir() {
            tracing::debug!(workdir = %workdir.display(), "session workdir is not a directory");
            return Err(SessionError::InvalidRequest(
                "working_directory is not a directory".into(),
            ));
        }
        // Defense in depth: `validate()` already rejects `PATH`; refuse
        // again so a future validation change cannot silently re-open PATH
        // redirection through sessions.
        if req.env_vars.contains_key("PATH") {
            return Err(SessionError::InvalidRequest(
                "env var PATH must not be supplied: programs resolve against the daemon's trusted PATH".into(),
            ));
        }

        let now = now_secs();
        let mut table = self
            .sessions
            .lock()
            .map_err(|_| SessionError::Internal("session table poisoned".into()))?;
        let purged = purge_expired_locked(&mut table, &self.config, now);
        if table.len() >= self.config.max_sessions {
            return Err(SessionError::TooManySessions(format!(
                "session table full ({} live sessions): refusing creation",
                table.len()
            )));
        }
        let mut chosen = None;
        for _ in 0..8 {
            let candidate = alloc_session_id()?;
            if !table.contains_key(&candidate) {
                chosen = Some(candidate);
                break;
            }
        }
        let id = chosen.ok_or_else(|| {
            SessionError::Internal("repeated session id collisions; refusing creation".into())
        })?;
        let info = SessionInfo {
            session_id: id.clone(),
            environment_id: req.environment_id.clone(),
            working_directory: workdir_rel.to_string(),
            env_vars: sanitize_stored_env(&req.env_vars),
            created_at: now,
            last_activity: now,
            // Gate 8 binds this to the client-cert identity. `None` today
            // means legacy single-principal: no owner check.
            owner: None,
        };
        table.insert(id, SessionRecord { info: info.clone() });
        tracing::info!(
            session_id = %info.session_id,
            workdir = %workdir_rel,
            "session created"
        );
        Ok((info, purged))
    }

    /// Fetch a session by id — the resume operation.
    ///
    /// Lazy expiry: an expired entry is REMOVED and [`SessionError::Expired`]
    /// is returned. Otherwise `last_activity` is bumped and a clone is
    /// returned. A fresh client handle (simulating disconnect/reconnect)
    /// resumes fine: identity lives in this table, not in any connection.
    pub fn get(&self, session_id: &SessionId) -> Result<SessionInfo, SessionError> {
        let now = now_secs();
        let mut table = self
            .sessions
            .lock()
            .map_err(|_| SessionError::Internal("session table poisoned".into()))?;
        let record = table
            .get_mut(session_id)
            .ok_or_else(|| SessionError::NotFound(format!("unknown session id '{session_id}'")))?;
        if is_expired(&record.info, &self.config, now) {
            table.remove(session_id);
            tracing::debug!(session_id = %session_id, "session expired on access; entry removed");
            return Err(SessionError::Expired(format!(
                "session '{session_id}' expired"
            )));
        }
        record.info.last_activity = now;
        Ok(record.info.clone())
    }

    /// Alias for [`SessionManager::get`] used by session-scoped process
    /// operations: every execute/status/wait/terminate proves liveness, so
    /// all of them bump activity. Listing does NOT touch (read-only scan).
    pub fn touch(&self, session_id: &SessionId) -> Result<SessionInfo, SessionError> {
        self.get(session_id)
    }

    /// List live sessions for an environment.
    ///
    /// Purges expired entries first (opportunistic), returns live ones for
    /// the environment, bumps nothing. Also returns the purged ids so the
    /// caller (handler) can best-effort kill their processes — see
    /// [`SessionManager::create`].
    pub fn list(&self, environment_id: &EnvironmentId) -> (Vec<SessionInfo>, Vec<SessionId>) {
        let now = now_secs();
        let mut table = match self.sessions.lock() {
            Ok(table) => table,
            Err(_) => return (Vec::new(), Vec::new()),
        };
        let purged = purge_expired_locked(&mut table, &self.config, now);
        let live = table
            .values()
            .filter(|record| record.info.environment_id == *environment_id)
            .map(|record| record.info.clone())
            .collect();
        (live, purged)
    }

    /// Remove a session without touching processes.
    ///
    /// The handler kills session processes FIRST via the process manager,
    /// then calls this (kill-then-remove). Expired entries are removed and
    /// reported as [`SessionError::Expired`], not `NotFound`.
    pub fn terminate(&self, session_id: &SessionId) -> Result<(), SessionError> {
        let now = now_secs();
        let mut table = self
            .sessions
            .lock()
            .map_err(|_| SessionError::Internal("session table poisoned".into()))?;
        let record = table
            .get(session_id)
            .ok_or_else(|| SessionError::NotFound(format!("unknown session id '{session_id}'")))?;
        if is_expired(&record.info, &self.config, now) {
            table.remove(session_id);
            tracing::debug!(session_id = %session_id, "expired session terminated; entry removed");
            return Err(SessionError::Expired(format!(
                "session '{session_id}' expired"
            )));
        }
        table.remove(session_id);
        tracing::info!(session_id = %session_id, "session terminated");
        Ok(())
    }
}

/// Drop expired entries, returning the purged ids so the caller can
/// best-effort kill their processes. Called on creation (before the capacity
/// check) and on listing — the "no background reaper" half of lazy expiry.
fn purge_expired_locked(
    table: &mut HashMap<SessionId, SessionRecord>,
    config: &SessionConfig,
    now: u64,
) -> Vec<SessionId> {
    let expired: Vec<SessionId> = table
        .iter()
        .filter(|(_, record)| is_expired(&record.info, config, now))
        .map(|(id, _)| id.clone())
        .collect();
    let count = expired.len();
    for id in &expired {
        table.remove(id);
    }
    if count > 0 {
        tracing::debug!(evicted = count, "purged expired sessions");
    }
    expired
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use std::collections::{HashMap, HashSet};

    fn test_env() -> EnvironmentId {
        EnvironmentId::new("test-env")
    }

    fn test_manager(config: SessionConfig) -> (tempfile::TempDir, SessionManager) {
        let tmp = tempfile::TempDir::new().expect("temp dir");
        let fs = FilesystemBackend::new(
            crate::fs::FilesystemConfig::new(&[tmp.path().to_path_buf()]).expect("fs config"),
        );
        let mgr = SessionManager::new(test_env(), config, Some(fs));
        (tmp, mgr)
    }

    fn create_req(workdir: Option<&str>, env: HashMap<String, String>) -> CreateSessionRequest {
        CreateSessionRequest {
            environment_id: test_env(),
            working_directory: workdir.map(str::to_string),
            env_vars: env,
        }
    }

    #[test]
    fn create_get_roundtrip_preserves_workdir_and_env() {
        let (_tmp, mgr) = test_manager(SessionConfig::default());
        let (info, purged) = mgr
            .create(create_req(
                Some("."),
                HashMap::from([("FOO".into(), "bar".into())]),
            ))
            .unwrap();
        assert!(purged.is_empty());
        assert!(info.session_id.as_str().starts_with("sess-"));
        assert_eq!(info.working_directory, ".");
        assert_eq!(info.env_vars.get("FOO").map(String::as_str), Some("bar"));
        assert!(info.created_at > 0);
        assert_eq!(info.last_activity, info.created_at);

        // Resume: a fresh handle on the same manager recovers identity.
        let resumed = mgr.get(&info.session_id).unwrap();
        assert_eq!(resumed.session_id, info.session_id);
        assert_eq!(resumed.working_directory, ".");
        assert_eq!(resumed.env_vars.get("FOO").map(String::as_str), Some("bar"));
        assert!(resumed.last_activity >= info.last_activity);
    }

    #[test]
    fn create_defaults_workdir_to_dot() {
        let (_tmp, mgr) = test_manager(SessionConfig::default());
        let (info, _) = mgr.create(create_req(None, HashMap::new())).unwrap();
        assert_eq!(info.working_directory, ".");
        assert_eq!(info.owner, None);
    }

    #[test]
    fn create_rejects_unknown_workdir() {
        let (_tmp, mgr) = test_manager(SessionConfig::default());
        let err = mgr
            .create(create_req(Some("no-such-dir"), HashMap::new()))
            .unwrap_err();
        assert!(matches!(err, SessionError::InvalidRequest(_)));
    }

    #[test]
    fn create_rejects_path_env() {
        let (_tmp, mgr) = test_manager(SessionConfig::default());
        let err = mgr
            .create(create_req(
                None,
                HashMap::from([("PATH".into(), "/tmp/evil".into())]),
            ))
            .unwrap_err();
        assert!(matches!(err, SessionError::InvalidRequest(_)));
    }

    #[test]
    fn create_strips_loader_keys() {
        let (_tmp, mgr) = test_manager(SessionConfig::default());
        let (info, _) = mgr
            .create(create_req(
                None,
                HashMap::from([
                    ("LD_PRELOAD".into(), "/tmp/evil.so".into()),
                    ("DYLD_INSERT_LIBRARIES".into(), "/tmp/evil.dylib".into()),
                    ("KEEP".into(), "yes".into()),
                ]),
            ))
            .unwrap();
        assert!(!info.env_vars.contains_key("LD_PRELOAD"));
        assert!(!info.env_vars.contains_key("DYLD_INSERT_LIBRARIES"));
        assert_eq!(info.env_vars.get("KEEP").map(String::as_str), Some("yes"));
    }

    #[test]
    fn get_unknown_id_is_not_found() {
        let (_tmp, mgr) = test_manager(SessionConfig::default());
        let err = mgr.get(&SessionId::new("sess-nope")).unwrap_err();
        assert!(matches!(err, SessionError::NotFound(_)));
    }

    #[test]
    fn idle_expiry_removes_entry() {
        let (_tmp, mgr) = test_manager(SessionConfig {
            idle_timeout_secs: 1,
            max_lifetime_secs: 86400,
            ..SessionConfig::default()
        });
        let (info, _) = mgr.create(create_req(None, HashMap::new())).unwrap();
        std::thread::sleep(std::time::Duration::from_secs(2));
        let err = mgr.get(&info.session_id).unwrap_err();
        assert!(
            matches!(err, SessionError::Expired(_)),
            "expected Expired, got: {err}"
        );
        // Entry is gone: second access is NotFound, not Expired.
        let err = mgr.get(&info.session_id).unwrap_err();
        assert!(matches!(err, SessionError::NotFound(_)));
    }

    #[test]
    fn max_lifetime_expires_despite_activity() {
        let (_tmp, mgr) = test_manager(SessionConfig {
            idle_timeout_secs: 86400,
            max_lifetime_secs: 1,
            ..SessionConfig::default()
        });
        let (info, _) = mgr.create(create_req(None, HashMap::new())).unwrap();
        // Activity does not save it: lifetime is absolute.
        let _ = mgr.get(&info.session_id).unwrap();
        std::thread::sleep(std::time::Duration::from_secs(2));
        let err = mgr.touch(&info.session_id).unwrap_err();
        assert!(matches!(err, SessionError::Expired(_)));
    }

    #[test]
    fn list_filters_by_env_and_purges_expired() {
        let tmp = tempfile::TempDir::new().expect("temp dir");
        let fs = FilesystemBackend::new(
            crate::fs::FilesystemConfig::new(&[tmp.path().to_path_buf()]).expect("fs config"),
        );
        let mgr = SessionManager::new(
            test_env(),
            SessionConfig {
                idle_timeout_secs: 1,
                ..SessionConfig::default()
            },
            Some(fs),
        );
        let (live, _) = mgr.create(create_req(None, HashMap::new())).unwrap();
        std::thread::sleep(std::time::Duration::from_secs(2));
        // Live one expired too by now; create a fresh one after the sleep.
        // Creation purges the expired entry and reports it.
        let (fresh, purged) = mgr.create(create_req(None, HashMap::new())).unwrap();
        assert!(
            purged.contains(&live.session_id),
            "create must report the expired session it purged"
        );
        let (sessions, _) = mgr.list(&test_env());
        assert_eq!(sessions.len(), 1);
        assert_eq!(sessions[0].session_id, fresh.session_id);
        // The expired entry was purged, not listed.
        assert!(sessions.iter().all(|s| s.session_id != live.session_id));
        // Other environments see nothing.
        assert!(mgr.list(&EnvironmentId::new("other-env")).0.is_empty());
    }

    #[test]
    fn terminate_removes_session() {
        let (_tmp, mgr) = test_manager(SessionConfig::default());
        let (info, _) = mgr.create(create_req(None, HashMap::new())).unwrap();
        mgr.terminate(&info.session_id).unwrap();
        let err = mgr.get(&info.session_id).unwrap_err();
        assert!(matches!(err, SessionError::NotFound(_)));
    }

    #[test]
    fn terminate_unknown_is_not_found() {
        let (_tmp, mgr) = test_manager(SessionConfig::default());
        let err = mgr.terminate(&SessionId::new("sess-nope")).unwrap_err();
        assert!(matches!(err, SessionError::NotFound(_)));
    }

    #[test]
    fn max_sessions_bound_purges_expired_first() {
        let (_tmp, mgr) = test_manager(SessionConfig {
            idle_timeout_secs: 1,
            max_sessions: 2,
            ..SessionConfig::default()
        });
        let _a = mgr.create(create_req(None, HashMap::new())).unwrap();
        let _b = mgr.create(create_req(None, HashMap::new())).unwrap();
        // Full of live sessions: refused.
        let err = mgr.create(create_req(None, HashMap::new())).unwrap_err();
        assert!(matches!(err, SessionError::TooManySessions(_)));
        // After expiry, creation purges and succeeds.
        std::thread::sleep(std::time::Duration::from_secs(2));
        let c = mgr.create(create_req(None, HashMap::new()));
        assert!(c.is_ok());
    }

    #[test]
    fn environment_mismatch_rejected() {
        let (_tmp, mgr) = test_manager(SessionConfig::default());
        let err = mgr
            .create(CreateSessionRequest {
                environment_id: EnvironmentId::new("other-env"),
                working_directory: None,
                env_vars: HashMap::new(),
            })
            .unwrap_err();
        assert!(matches!(err, SessionError::EnvironmentMismatch(_)));
    }

    #[test]
    fn allocated_ids_are_unique_and_well_formed() {
        let mut seen = HashSet::new();
        for _ in 0..100 {
            let id = alloc_session_id().expect("alloc");
            assert!(id.as_str().starts_with("sess-"));
            assert_eq!(id.as_str().len(), "sess-".len() + 32);
            assert!(id
                .as_str()
                .chars()
                .skip("sess-".len())
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
            assert!(seen.insert(id.as_str().to_string()), "id collision");
        }
    }

    #[test]
    fn default_session_bounds() {
        let config = SessionConfig::default();
        assert_eq!(config.idle_timeout_secs, DEFAULT_SESSION_IDLE_TIMEOUT_SECS);
        assert_eq!(config.max_lifetime_secs, DEFAULT_SESSION_MAX_LIFETIME_SECS);
        assert_eq!(config.max_sessions, DEFAULT_MAX_SESSIONS);
        assert_eq!(
            config.max_processes_per_session,
            DEFAULT_MAX_PROCESSES_PER_SESSION
        );
    }
}
