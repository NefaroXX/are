//! Request dispatch and handler for the daemon.
//!
//! Handles `RpcRequest` variants and returns `RpcResponse` values.
//! Gate 3 handles `GetEnvironmentInfo`. Gate 4 adds `ReadFile`,
//! `ListDirectory`, and `GetFileMetadata`. Gate 5 adds `Execute`,
//! `ProcessStatus`, `TerminateProcess`, and `WaitProcess`. Gate 6 adds
//! `CreateSession`, `GetSession` (resume), `ListSessions`, and
//! `TerminateSession`, and binds every process operation to a live session.
//!
//! Session checks run BEFORE process-table lookups on every session-scoped
//! operation: an unknown session yields `SessionNotFound`, an expired one
//! `SessionExpired`. A live session with a mismatched process id yields
//! plain `NotFound` — indistinguishable from an unknown id (no oracle into
//! other sessions' processes).
//!
//! KNOWN LEAK (expiry oracle): `SessionNotFound` vs `SessionExpired` lets
//! any client confirm an id was once live. Gate 8 must return generic
//! `NotFound` to non-owners once `SessionInfo.owner` binds to the
//! client-cert identity; add a cross-client indistinguishability test then.
//! No behavior change today: owner binding does not exist yet.
//!
//! NO EXPIRY PATH SILENTLY ORPHANS LIVE CHILDREN: `require_live_session`
//! (the single choke point all session ops traverse) best-effort kills the
//! session's processes when the session check returns `Expired`, before
//! returning the error. `create`/`list` purge sweeps return purged ids up
//! here for the same kill. The handler checks, then trusts — managers stay
//! uncoupled.
//!
//! The handler is synchronous; async backends (filesystem, processes) are
//! driven via `tokio::task::block_in_place` + `block_on`, matching the
//! established Gate 4 pattern. This requires a multi-threaded Tokio
//! runtime (the daemon's `#[tokio::main]` default).

use std::sync::Arc;

use are_core::{
    CapabilitySet, EnvironmentId, GetEnvironmentInfoRequest, GetEnvironmentInfoResponse, Platform,
    RpcError, RpcRequest, RpcResponse, RpcResponsePayload, SessionId, SessionInfo,
};

use crate::fs::{FilesystemBackend, FsError};
use crate::process::{ProcessError, ProcessManager};
use crate::session::{SessionError, SessionManager};

/// Daemon state needed to handle requests.
pub struct DaemonState {
    /// The environment this daemon serves.
    pub environment_id: EnvironmentId,
    /// Machine hostname.
    pub machine_name: String,
    /// Daemon version string.
    pub daemon_version: String,
    /// Operations this environment advertises as available.
    ///
    /// This is NOT per-client authorization — all clients see the same set.
    /// Per-client capability enforcement arrives in Gate 8.
    pub advertised_capabilities: CapabilitySet,
    /// Platform type.
    pub platform: Platform,
    /// Filesystem backend (None for backward-compatible tests without FS).
    pub fs: Option<FilesystemBackend>,
    /// Process manager (None when process execution is not configured).
    ///
    /// The manager is shared across connections: the process table lives in
    /// daemon memory, so a client can disconnect and a new connection can
    /// still query processes by id. It does NOT survive daemon restarts.
    /// Every entry belongs to a session (Gate 6).
    pub proc: Option<Arc<ProcessManager>>,
    /// Session manager (None when sessions are not configured).
    ///
    /// Like the process table, sessions live in daemon memory and survive
    /// client disconnects but NOT daemon restarts. Every RPC is already a
    /// fresh TLS connection, so "resume across reconnect" needs no
    /// connection tracking — just this table, addressable by id.
    pub sessions: Option<Arc<SessionManager>>,
}

impl DaemonState {
    /// Create a new `DaemonState` with the given configuration.
    pub fn new(
        environment_id: EnvironmentId,
        machine_name: String,
        daemon_version: String,
        advertised_capabilities: CapabilitySet,
        platform: Platform,
    ) -> Self {
        Self {
            environment_id,
            machine_name,
            daemon_version,
            advertised_capabilities,
            platform,
            fs: None,
            proc: None,
            sessions: None,
        }
    }

    /// Create a new `DaemonState` with a filesystem backend.
    pub fn with_fs(
        environment_id: EnvironmentId,
        machine_name: String,
        daemon_version: String,
        advertised_capabilities: CapabilitySet,
        platform: Platform,
        fs: FilesystemBackend,
    ) -> Self {
        Self {
            environment_id,
            machine_name,
            daemon_version,
            advertised_capabilities,
            platform,
            fs: Some(fs),
            proc: None,
            sessions: None,
        }
    }

    /// Attach a process manager (builder style, mirrors `with_fs` usage).
    pub fn with_proc(mut self, proc: Arc<ProcessManager>) -> Self {
        self.proc = Some(proc);
        self
    }

    /// Attach a session manager (builder style, mirrors `with_proc` usage).
    pub fn with_sess(mut self, sessions: Arc<SessionManager>) -> Self {
        self.sessions = Some(sessions);
        self
    }

    /// Handle an RPC request and return a response.
    pub fn handle(&self, request: RpcRequest) -> RpcResponse {
        match request {
            RpcRequest::GetEnvironmentInfo(req) => {
                let result = self.handle_get_environment_info(req);
                RpcResponse {
                    result: result.map(RpcResponsePayload::GetEnvironmentInfo),
                }
            }
            RpcRequest::ReadFile(req) => {
                let result = self.handle_read_file(req);
                RpcResponse {
                    result: result.map(RpcResponsePayload::ReadFile),
                }
            }
            RpcRequest::ListDirectory(req) => {
                let result = self.handle_list_directory(req);
                RpcResponse {
                    result: result.map(RpcResponsePayload::ListDirectory),
                }
            }
            RpcRequest::GetFileMetadata(req) => {
                let result = self.handle_get_file_metadata(req);
                RpcResponse {
                    result: result.map(RpcResponsePayload::GetFileMetadata),
                }
            }
            RpcRequest::Execute(req) => {
                let result = self.handle_execute(req);
                RpcResponse {
                    result: result.map(RpcResponsePayload::Execute),
                }
            }
            RpcRequest::ProcessStatus(req) => {
                let result = self.handle_process_status(req);
                RpcResponse {
                    result: result.map(RpcResponsePayload::ProcessStatus),
                }
            }
            RpcRequest::TerminateProcess(req) => {
                let result = self.handle_terminate_process(req);
                RpcResponse {
                    result: result.map(RpcResponsePayload::TerminateProcess),
                }
            }
            RpcRequest::WaitProcess(req) => {
                let result = self.handle_wait_process(req);
                RpcResponse {
                    result: result.map(RpcResponsePayload::WaitProcess),
                }
            }
            RpcRequest::CreateSession(req) => {
                let result = self.handle_create_session(req);
                RpcResponse {
                    result: result.map(RpcResponsePayload::CreateSession),
                }
            }
            RpcRequest::GetSession(req) => {
                let result = self.handle_get_session(req);
                RpcResponse {
                    result: result.map(RpcResponsePayload::GetSession),
                }
            }
            RpcRequest::ListSessions(req) => {
                let result = self.handle_list_sessions(req);
                RpcResponse {
                    result: result.map(RpcResponsePayload::ListSessions),
                }
            }
            RpcRequest::TerminateSession(req) => {
                let result = self.handle_terminate_session(req);
                RpcResponse {
                    result: result.map(RpcResponsePayload::TerminateSession),
                }
            }
        }
    }

    fn handle_get_environment_info(
        &self,
        req: GetEnvironmentInfoRequest,
    ) -> Result<GetEnvironmentInfoResponse, RpcError> {
        // Validate that the requested environment matches this daemon's env.
        if req.environment_id != self.environment_id {
            return Err(RpcError::InvalidRequest(format!(
                "requested environment '{}' does not match daemon environment '{}'",
                req.environment_id, self.environment_id
            )));
        }

        Ok(GetEnvironmentInfoResponse {
            environment_id: self.environment_id.clone(),
            machine_name: self.machine_name.clone(),
            operating_system: std::env::consts::OS.to_string(),
            daemon_version: self.daemon_version.clone(),
            advertised_capabilities: self.advertised_capabilities.clone(),
            platform: self.platform.clone(),
        })
    }

    fn handle_read_file(
        &self,
        req: are_core::ReadFileRequest,
    ) -> Result<are_core::ReadFileResponse, RpcError> {
        if req.environment_id != self.environment_id {
            return Err(RpcError::InvalidRequest(format!(
                "requested environment '{}' does not match daemon environment '{}'",
                req.environment_id, self.environment_id
            )));
        }

        let fs = self
            .fs
            .as_ref()
            .ok_or_else(|| RpcError::InternalError("filesystem backend not configured".into()))?;

        let req_clone = req.clone();
        // Block on async FS operation within the sync handler.
        let (content, metadata) = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { fs.read_file(&req_clone.path).await })
        })
        .map_err(|e| fs_error_to_rpc(e, &req.path))?;

        Ok(are_core::ReadFileResponse { content, metadata })
    }

    fn handle_list_directory(
        &self,
        req: are_core::ListDirectoryRequest,
    ) -> Result<are_core::ListDirectoryResponse, RpcError> {
        if req.environment_id != self.environment_id {
            return Err(RpcError::InvalidRequest(format!(
                "requested environment '{}' does not match daemon environment '{}'",
                req.environment_id, self.environment_id
            )));
        }

        let fs = self
            .fs
            .as_ref()
            .ok_or_else(|| RpcError::InternalError("filesystem backend not configured".into()))?;

        let req_clone = req.clone();
        let entries = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { fs.list_directory(&req_clone.path).await })
        })
        .map_err(|e| fs_error_to_rpc(e, &req.path))?;

        Ok(are_core::ListDirectoryResponse { entries })
    }

    fn handle_get_file_metadata(
        &self,
        req: are_core::GetFileMetadataRequest,
    ) -> Result<are_core::GetFileMetadataResponse, RpcError> {
        if req.environment_id != self.environment_id {
            return Err(RpcError::InvalidRequest(format!(
                "requested environment '{}' does not match daemon environment '{}'",
                req.environment_id, self.environment_id
            )));
        }

        let fs = self
            .fs
            .as_ref()
            .ok_or_else(|| RpcError::InternalError("filesystem backend not configured".into()))?;

        let req_clone = req.clone();
        let metadata = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { fs.file_metadata(&req_clone.path).await })
        })
        .map_err(|e| fs_error_to_rpc(e, &req.path))?;

        Ok(are_core::GetFileMetadataResponse { metadata })
    }

    /// Require the process backend and check the environment binding first,
    /// mirroring the filesystem handlers.
    fn require_proc(
        &self,
        environment_id: &EnvironmentId,
    ) -> Result<Arc<ProcessManager>, RpcError> {
        if *environment_id != self.environment_id {
            return Err(RpcError::InvalidRequest(format!(
                "requested environment '{environment_id}' does not match daemon environment '{}'",
                self.environment_id
            )));
        }
        self.proc
            .clone()
            .ok_or_else(|| RpcError::InternalError("process backend not configured".into()))
    }

    fn handle_execute(
        &self,
        req: are_core::ExecuteRequest,
    ) -> Result<are_core::ExecuteResponse, RpcError> {
        let proc = self.require_proc(&req.environment_id)?;
        // Session liveness FIRST (touch bumps activity): unknown →
        // SessionNotFound, aged-out → SessionExpired. A live session whose
        // environment differs from the request is NotFound-adjacent — but
        // since sessions belong to exactly one environment, treat it as a
        // plain NotFound to avoid distinguishing "wrong env" from
        // "wrong session".
        let session = self.require_live_session(&req.session_id)?;
        if session.environment_id != req.environment_id {
            return Err(RpcError::NotFound(format!(
                "unknown session '{}'",
                req.session_id
            )));
        }
        let process_id = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async { proc.start(req, &session).await })
        })
        .map_err(process_error_to_rpc)?;
        Ok(are_core::ExecuteResponse { process_id })
    }

    fn handle_process_status(
        &self,
        req: are_core::ProcessStatusRequest,
    ) -> Result<are_core::ProcessStatusResponse, RpcError> {
        let proc = self.require_proc(&req.environment_id)?;
        let session = self.require_live_session(&req.session_id)?;
        if session.environment_id != req.environment_id {
            return Err(RpcError::NotFound(format!(
                "unknown process id '{}'",
                req.process_id
            )));
        }
        proc.status(&req).map_err(process_error_to_rpc)
    }

    fn handle_terminate_process(
        &self,
        req: are_core::TerminateProcessRequest,
    ) -> Result<are_core::TerminateProcessResponse, RpcError> {
        let proc = self.require_proc(&req.environment_id)?;
        let session = self.require_live_session(&req.session_id)?;
        if session.environment_id != req.environment_id {
            return Err(RpcError::NotFound(format!(
                "unknown process id '{}'",
                req.process_id
            )));
        }
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async { proc.terminate(req).await })
        })
        .map_err(process_error_to_rpc)
    }

    fn handle_wait_process(
        &self,
        req: are_core::WaitProcessRequest,
    ) -> Result<are_core::WaitProcessResponse, RpcError> {
        let proc = self.require_proc(&req.environment_id)?;
        let session = self.require_live_session(&req.session_id)?;
        if session.environment_id != req.environment_id {
            return Err(RpcError::NotFound(format!(
                "unknown process id '{}'",
                req.process_id
            )));
        }
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async { proc.wait(req).await })
        })
        .map_err(process_error_to_rpc)
    }

    /// Require the session backend and return the touched (live) session.
    ///
    /// Every session-scoped operation (execute/status/wait/terminate, plus
    /// get) proves liveness, so all of them bump `last_activity` here.
    /// Listing is the exception (read-only scan, no touch).
    ///
    /// Kill-on-expiry: when the session check reports `Expired`, this
    /// choke point best-effort kills that session's processes FIRST, then
    /// returns `Expired`. Without the kill, the just-removed session's live
    /// children would become unaddressable (all proc ops gate on a live
    /// session first) — a silent-orphan table-exhaustion path.
    fn require_live_session(&self, session_id: &SessionId) -> Result<SessionInfo, RpcError> {
        let sessions = self
            .sessions
            .clone()
            .ok_or_else(|| RpcError::InternalError("session backend not configured".into()))?;
        match sessions.touch(session_id) {
            Ok(info) => Ok(info),
            Err(crate::session::SessionError::Expired(msg)) => {
                self.kill_session_processes_best_effort(session_id);
                Err(RpcError::SessionExpired(msg))
            }
            Err(other) => Err(session_error_to_rpc(other)),
        }
    }

    /// Best-effort kill of a session's processes. Never fails: the managers
    /// stay uncoupled (handler-checks-then-trusts) and a missing proc
    /// backend simply means nothing to kill.
    fn kill_session_processes_best_effort(&self, session_id: &SessionId) {
        if let Some(proc) = self.proc.clone() {
            proc.kill_session_processes(&self.environment_id, session_id);
        }
    }

    /// Best-effort kill for every purged session id from a `create`/`list`
    /// expiry sweep. Without this, purged sessions' live children would be
    /// silently orphaned (unaddressable, and live entries never age out by
    /// retention).
    fn kill_purged_sessions_best_effort(&self, purged: &[SessionId]) {
        for id in purged {
            self.kill_session_processes_best_effort(id);
        }
    }

    fn handle_create_session(
        &self,
        req: are_core::CreateSessionRequest,
    ) -> Result<are_core::CreateSessionResponse, RpcError> {
        if req.environment_id != self.environment_id {
            return Err(RpcError::InvalidRequest(format!(
                "requested environment '{}' does not match daemon environment '{}'",
                req.environment_id, self.environment_id
            )));
        }
        let sessions = self
            .sessions
            .clone()
            .ok_or_else(|| RpcError::InternalError("session backend not configured".into()))?;
        let (session, purged) = sessions.create(req).map_err(session_error_to_rpc)?;
        // The pre-creation purge may have removed expired sessions with
        // live children: kill them best-effort so they never orphan.
        self.kill_purged_sessions_best_effort(&purged);
        Ok(are_core::CreateSessionResponse { session })
    }

    fn handle_get_session(
        &self,
        req: are_core::GetSessionRequest,
    ) -> Result<are_core::GetSessionResponse, RpcError> {
        if req.environment_id != self.environment_id {
            return Err(RpcError::InvalidRequest(format!(
                "requested environment '{}' does not match daemon environment '{}'",
                req.environment_id, self.environment_id
            )));
        }
        // `require_live_session` IS the resume operation here: bumps
        // activity, kills-on-expiry, and maps Expired/NotFound. (It touches
        // rather than plain-getting so expiry kills apply on this path too.)
        let session = self.require_live_session(&req.session_id)?;
        if session.environment_id != req.environment_id {
            return Err(RpcError::NotFound(format!(
                "unknown session '{}'",
                req.session_id
            )));
        }
        Ok(are_core::GetSessionResponse { session })
    }

    fn handle_list_sessions(
        &self,
        req: are_core::ListSessionsRequest,
    ) -> Result<are_core::ListSessionsResponse, RpcError> {
        if req.environment_id != self.environment_id {
            return Err(RpcError::InvalidRequest(format!(
                "requested environment '{}' does not match daemon environment '{}'",
                req.environment_id, self.environment_id
            )));
        }
        let sessions = self
            .sessions
            .clone()
            .ok_or_else(|| RpcError::InternalError("session backend not configured".into()))?;
        let (live, purged) = sessions.list(&req.environment_id);
        self.kill_purged_sessions_best_effort(&purged);
        Ok(are_core::ListSessionsResponse { sessions: live })
    }

    fn handle_terminate_session(
        &self,
        req: are_core::TerminateSessionRequest,
    ) -> Result<are_core::TerminateSessionResponse, RpcError> {
        if req.environment_id != self.environment_id {
            return Err(RpcError::InvalidRequest(format!(
                "requested environment '{}' does not match daemon environment '{}'",
                req.environment_id, self.environment_id
            )));
        }
        let sessions = self
            .sessions
            .clone()
            .ok_or_else(|| RpcError::InternalError("session backend not configured".into()))?;
        // Peek-live FIRST via the kill-on-expiry choke point. Live →
        // kill → remove → return the live-kill count. Expired → the kill
        // was already attempted inside `require_live_session`, so return
        // `Expired` (documented: kill attempted despite the error) instead
        // of masking the recovery path as success.
        let live = match self.require_live_session(&req.session_id) {
            Ok(info) => info,
            Err(RpcError::SessionExpired(msg)) => {
                return Err(RpcError::SessionExpired(format!(
                    "{msg} (session processes kill attempted despite expiry)"
                )));
            }
            Err(other) => return Err(other),
        };
        if live.environment_id != req.environment_id {
            return Err(RpcError::NotFound(format!(
                "unknown session '{}'",
                req.session_id
            )));
        }
        // Kill-then-remove: cascade to session processes best-effort FIRST
        // (direct children only — the inherited Gate 5 limitation; counts
        // live kills only), then drop the session record. A crash between
        // the two leaves either a live session with dead processes or
        // orphaned processes that fail closed on next access — both safe
        // directions.
        let terminated_processes = self
            .proc
            .clone()
            .map(|proc| proc.kill_session_processes(&self.environment_id, &req.session_id))
            .unwrap_or(0);
        sessions
            .terminate(&req.session_id)
            .map_err(session_error_to_rpc)?;
        Ok(are_core::TerminateSessionResponse {
            terminated_processes,
        })
    }
}

/// Map a session error to an RPC error, preserving the resume-relevant
/// distinction: unknown ids (`SessionNotFound`) vs aged-out sessions
/// (`SessionExpired`) vs malformed requests (`InvalidRequest`). Capacity
/// refusals (`TooManySessions`) map to the dedicated `CapacityExceeded`
/// category. NOTE: the `NotFound`/`Expired` split is a known expiry oracle
/// (see the module docs); Gate 8 must collapse it for non-owners.
fn session_error_to_rpc(err: SessionError) -> RpcError {
    match err {
        SessionError::InvalidRequest(msg) => RpcError::InvalidRequest(msg),
        SessionError::EnvironmentMismatch(msg) => RpcError::InvalidRequest(msg),
        SessionError::NotFound(msg) => RpcError::SessionNotFound(msg),
        SessionError::Expired(msg) => RpcError::SessionExpired(msg),
        SessionError::TooManySessions(msg) => RpcError::CapacityExceeded(msg),
        SessionError::Internal(msg) => RpcError::InternalError(msg),
    }
}

/// Map a process error to an RPC error, preserving the error category so
/// clients can distinguish policy rejection (`DeniedExecutable`), unknown
/// ids (`NotFound`), malformed requests (`InvalidRequest`), capacity
/// refusals (`CapacityExceeded`), and daemon failures (`InternalError`).
/// Fail-closed refusals (`PolicyDenied`) map onto `DeniedExecutable`.
fn process_error_to_rpc(err: ProcessError) -> RpcError {
    match err {
        ProcessError::InvalidRequest(msg) => RpcError::InvalidRequest(msg),
        ProcessError::EnvironmentMismatch(msg) => RpcError::InvalidRequest(msg),
        ProcessError::DeniedExecutable(msg) => RpcError::DeniedExecutable(msg),
        ProcessError::PolicyDenied(msg) => RpcError::DeniedExecutable(msg),
        ProcessError::TooManyProcesses(msg) => RpcError::CapacityExceeded(msg),
        ProcessError::NotFound(msg) => RpcError::NotFound(msg),
        ProcessError::Io(msg) => RpcError::InternalError(msg),
        ProcessError::Internal(msg) => RpcError::InternalError(msg),
    }
}

/// Map a filesystem error to an RPC error, preserving the error category.
fn fs_error_to_rpc(err: FsError, path: &str) -> RpcError {
    match &err {
        FsError::InvalidPath(msg) => RpcError::InvalidRequest(format!("{path}: {msg}")),
        FsError::FilesystemEscape(msg) => {
            RpcError::InternalError(format!("filesystem escape blocked: {msg}"))
        }
        FsError::NotFound(_) => RpcError::InternalError(format!("{path}: not found")),
        FsError::PermissionDenied(_) => {
            RpcError::InternalError(format!("{path}: permission denied"))
        }
        FsError::NotADirectory(_) => RpcError::InternalError(format!("{path}: not a directory")),
        FsError::IsADirectory(_) => RpcError::InternalError(format!("{path}: is a directory")),
        FsError::FileTooLarge { path, size, limit } => RpcError::InternalError(format!(
            "file too large: {path} is {size} bytes, limit is {limit} bytes"
        )),
        FsError::Io(msg) => RpcError::InternalError(format!("{path}: I/O error: {msg}")),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use are_core::Capability;

    use crate::fs::FilesystemConfig;
    use crate::process::{ProcessConfig, ProcessManager};

    fn test_state() -> DaemonState {
        let mut caps = CapabilitySet::default();
        caps.insert(Capability::FilesystemRead);
        caps.insert(Capability::ProcessExecute);

        DaemonState::new(
            EnvironmentId::new("test-env"),
            "test-host".into(),
            "0.1.0".into(),
            caps,
            Platform::Debian,
        )
    }

    #[test]
    fn handle_get_environment_info_matching_env() {
        let state = test_state();
        let req = RpcRequest::GetEnvironmentInfo(GetEnvironmentInfoRequest {
            environment_id: EnvironmentId::new("test-env"),
        });

        let resp = state.handle(req);
        match resp.result {
            Ok(RpcResponsePayload::GetEnvironmentInfo(info)) => {
                assert_eq!(info.environment_id.as_str(), "test-env");
                assert_eq!(info.machine_name, "test-host");
                assert_eq!(info.daemon_version, "0.1.0");
                assert_eq!(info.platform, Platform::Debian);
                assert!(info
                    .advertised_capabilities
                    .contains(&Capability::FilesystemRead));
                assert!(info
                    .advertised_capabilities
                    .contains(&Capability::ProcessExecute));
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[test]
    fn handle_get_environment_info_wrong_env() {
        let state = test_state();
        let req = RpcRequest::GetEnvironmentInfo(GetEnvironmentInfoRequest {
            environment_id: EnvironmentId::new("wrong-env"),
        });

        let resp = state.handle(req);
        assert!(resp.result.is_err());
        match resp.result {
            Err(RpcError::InvalidRequest(msg)) => {
                assert!(msg.contains("does not match"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn handle_read_file_without_fs_backend() {
        let state = test_state();
        let req = RpcRequest::ReadFile(are_core::ReadFileRequest {
            environment_id: EnvironmentId::new("test-env"),
            path: "test.txt".into(),
        });

        let resp = state.handle(req);
        assert!(resp.result.is_err());
        match resp.result {
            Err(RpcError::InternalError(msg)) => {
                assert!(msg.contains("filesystem backend not configured"));
            }
            other => panic!("expected InternalError, got {other:?}"),
        }
    }

    #[test]
    fn handle_list_directory_without_fs_backend() {
        let state = test_state();
        let req = RpcRequest::ListDirectory(are_core::ListDirectoryRequest {
            environment_id: EnvironmentId::new("test-env"),
            path: ".".into(),
        });

        let resp = state.handle(req);
        assert!(resp.result.is_err());
        match resp.result {
            Err(RpcError::InternalError(msg)) => {
                assert!(msg.contains("filesystem backend not configured"));
            }
            other => panic!("expected InternalError, got {other:?}"),
        }
    }

    #[test]
    fn handle_get_file_metadata_without_fs_backend() {
        let state = test_state();
        let req = RpcRequest::GetFileMetadata(are_core::GetFileMetadataRequest {
            environment_id: EnvironmentId::new("test-env"),
            path: "test.txt".into(),
        });

        let resp = state.handle(req);
        assert!(resp.result.is_err());
        match resp.result {
            Err(RpcError::InternalError(msg)) => {
                assert!(msg.contains("filesystem backend not configured"));
            }
            other => panic!("expected InternalError, got {other:?}"),
        }
    }

    #[test]
    fn handle_read_file_wrong_env() {
        let state = test_state();
        let req = RpcRequest::ReadFile(are_core::ReadFileRequest {
            environment_id: EnvironmentId::new("wrong-env"),
            path: "test.txt".into(),
        });

        let resp = state.handle(req);
        assert!(resp.result.is_err());
        match resp.result {
            Err(RpcError::InvalidRequest(msg)) => {
                assert!(msg.contains("does not match"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn handle_list_directory_wrong_env() {
        let state = test_state();
        let req = RpcRequest::ListDirectory(are_core::ListDirectoryRequest {
            environment_id: EnvironmentId::new("wrong-env"),
            path: ".".into(),
        });

        let resp = state.handle(req);
        assert!(resp.result.is_err());
        match resp.result {
            Err(RpcError::InvalidRequest(msg)) => {
                assert!(msg.contains("does not match"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn handle_get_file_metadata_wrong_env() {
        let state = test_state();
        let req = RpcRequest::GetFileMetadata(are_core::GetFileMetadataRequest {
            environment_id: EnvironmentId::new("wrong-env"),
            path: "test.txt".into(),
        });

        let resp = state.handle(req);
        assert!(resp.result.is_err());
        match resp.result {
            Err(RpcError::InvalidRequest(msg)) => {
                assert!(msg.contains("does not match"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    // ---- Gate 5: process dispatch (Gate 6: session-bound) ----

    /// Build a `DaemonState` wired with a filesystem backend rooted at a
    /// temp dir, an explicitly permissive process manager (tests opt in;
    /// the production default is fail-closed), and a session manager plus
    /// one live session for the process tests.
    fn proc_state() -> (tempfile::TempDir, DaemonState, are_core::SessionId) {
        let tmp = tempfile::TempDir::new().unwrap();
        let fs =
            FilesystemBackend::new(FilesystemConfig::new(&[tmp.path().to_path_buf()]).unwrap());
        let proc = Arc::new(ProcessManager::new(
            EnvironmentId::new("test-env"),
            ProcessConfig {
                permissive: true,
                ..ProcessConfig::default()
            },
            Some(fs.clone()),
        ));
        let mut caps = CapabilitySet::default();
        caps.insert(Capability::ProcessExecute);
        caps.insert(Capability::ProcessInspect);
        caps.insert(Capability::ProcessTerminate);
        let sessions = Arc::new(crate::session::SessionManager::new(
            EnvironmentId::new("test-env"),
            crate::session::SessionConfig::default(),
            Some(fs.clone()),
        ));
        let session_id = sessions
            .create(are_core::CreateSessionRequest {
                environment_id: EnvironmentId::new("test-env"),
                working_directory: None,
                env_vars: std::collections::HashMap::new(),
            })
            .unwrap()
            .0
            .session_id;
        let state = DaemonState::with_fs(
            EnvironmentId::new("test-env"),
            "test-host".into(),
            "0.1.0".into(),
            caps,
            Platform::Debian,
            fs,
        )
        .with_proc(proc)
        .with_sess(sessions);
        (tmp, state, session_id)
    }

    #[test]
    fn handle_execute_wrong_env_rejected_first() {
        let (_tmp, state, session_id) = proc_state();
        let req = RpcRequest::Execute(are_core::ExecuteRequest {
            environment_id: EnvironmentId::new("wrong-env"),
            session_id,
            program: "shutdown".into(),
            args: vec![],
            working_directory: ".".into(),
            env_vars: std::collections::HashMap::new(),
        });

        let resp = state.handle(req);
        match resp.result {
            Err(RpcError::InvalidRequest(msg)) => assert!(msg.contains("does not match")),
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    #[test]
    fn handle_execute_without_proc_backend() {
        let state = test_state();
        let req = RpcRequest::Execute(are_core::ExecuteRequest {
            environment_id: EnvironmentId::new("test-env"),
            session_id: are_core::SessionId::new("sess-1"),
            program: "cargo".into(),
            args: vec![],
            working_directory: ".".into(),
            env_vars: std::collections::HashMap::new(),
        });

        let resp = state.handle(req);
        match resp.result {
            Err(RpcError::InternalError(msg)) => {
                assert!(msg.contains("process backend not configured"));
            }
            other => panic!("expected InternalError, got {other:?}"),
        }
    }

    #[test]
    fn handle_process_status_without_proc_backend() {
        let state = test_state();
        let req = RpcRequest::ProcessStatus(are_core::ProcessStatusRequest {
            environment_id: EnvironmentId::new("test-env"),
            session_id: are_core::SessionId::new("sess-1"),
            process_id: are_core::ProcessId::new("proc-000001"),
        });

        let resp = state.handle(req);
        assert!(matches!(resp.result, Err(RpcError::InternalError(_))));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn handle_execute_denied_maps_to_denied_executable() {
        let (_tmp, state, session_id) = proc_state();
        let req = RpcRequest::Execute(are_core::ExecuteRequest {
            environment_id: EnvironmentId::new("test-env"),
            session_id,
            program: "shutdown".into(),
            args: vec![],
            working_directory: ".".into(),
            env_vars: std::collections::HashMap::new(),
        });

        let resp = state.handle(req);
        match resp.result {
            Err(RpcError::DeniedExecutable(msg)) => assert!(msg.contains("shutdown")),
            other => panic!("expected DeniedExecutable, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn handle_process_status_unknown_id_maps_to_not_found() {
        let (_tmp, state, session_id) = proc_state();
        let req = RpcRequest::ProcessStatus(are_core::ProcessStatusRequest {
            environment_id: EnvironmentId::new("test-env"),
            session_id,
            process_id: are_core::ProcessId::new("proc-999999"),
        });

        let resp = state.handle(req);
        assert!(matches!(resp.result, Err(RpcError::NotFound(_))));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn handle_wait_rejects_timeout_over_bound() {
        let (_tmp, state, session_id) = proc_state();
        let req = RpcRequest::WaitProcess(are_core::WaitProcessRequest {
            environment_id: EnvironmentId::new("test-env"),
            session_id,
            process_id: are_core::ProcessId::new("proc-999999"),
            timeout_secs: are_core::MAX_WAIT_TIMEOUT_SECS + 1,
        });

        let resp = state.handle(req);
        assert!(matches!(resp.result, Err(RpcError::InvalidRequest(_))));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn handle_wait_rejects_zero_timeout() {
        let (_tmp, state, session_id) = proc_state();
        let req = RpcRequest::WaitProcess(are_core::WaitProcessRequest {
            environment_id: EnvironmentId::new("test-env"),
            session_id,
            process_id: are_core::ProcessId::new("proc-999999"),
            timeout_secs: 0,
        });

        let resp = state.handle(req);
        assert!(matches!(resp.result, Err(RpcError::InvalidRequest(_))));
    }

    #[tokio::test(flavor = "multi_thread")]
    #[cfg(unix)]
    async fn handle_execute_wait_status_happy_path() {
        let (_tmp, state, session_id) = proc_state();
        if !std::path::Path::new("/bin/echo").exists() {
            return;
        }

        // Start.
        let req = RpcRequest::Execute(are_core::ExecuteRequest {
            environment_id: EnvironmentId::new("test-env"),
            session_id: session_id.clone(),
            program: "/bin/echo".into(),
            args: vec!["hello".into()],
            working_directory: ".".into(),
            env_vars: std::collections::HashMap::new(),
        });
        let resp = state.handle(req);
        let process_id = match resp.result {
            Ok(RpcResponsePayload::Execute(exec)) => exec.process_id,
            other => panic!("expected Execute response, got {other:?}"),
        };

        // Wait.
        let req = RpcRequest::WaitProcess(are_core::WaitProcessRequest {
            environment_id: EnvironmentId::new("test-env"),
            session_id: session_id.clone(),
            process_id: process_id.clone(),
            timeout_secs: 10,
        });
        let resp = state.handle(req);
        match resp.result {
            Ok(RpcResponsePayload::WaitProcess(wait)) => {
                assert_eq!(wait.stdout, b"hello\n");
                assert_eq!(wait.exit_code, Some(0));
                assert!(!wait.timed_out);
            }
            other => panic!("expected WaitProcess response, got {other:?}"),
        }

        // Status.
        let req = RpcRequest::ProcessStatus(are_core::ProcessStatusRequest {
            environment_id: EnvironmentId::new("test-env"),
            session_id,
            process_id,
        });
        let resp = state.handle(req);
        match resp.result {
            Ok(RpcResponsePayload::ProcessStatus(status)) => {
                assert_eq!(status.state, are_core::ProcessState::Exited { code: 0 });
            }
            other => panic!("expected ProcessStatus response, got {other:?}"),
        }
    }
}
