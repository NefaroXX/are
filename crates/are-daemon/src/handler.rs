//! Request dispatch and handler for the daemon.
//!
//! Handles `RpcRequest` variants and returns `RpcResponse` values.
//! Gate 3 handles `GetEnvironmentInfo`. Gate 4 adds `ReadFile`,
//! `ListDirectory`, and `GetFileMetadata`. Gate 5 adds `Execute`,
//! `ProcessStatus`, `TerminateProcess`, and `WaitProcess`. Gate 6 adds
//! `CreateSession`, `GetSession` (resume), `ListSessions`, and
//! `TerminateSession`, and binds every process operation to a live session.
//! Gate 7 adds `WriteFile`, `CreateDirectory`, `Rename`, and `DeleteFile`:
//! environment-scoped (no session), atomic writes, optimistic concurrency,
//! no recursive delete.
//!
//! Session checks run BEFORE process-table lookups on every session-scoped
//! operation: an unknown session yields `SessionNotFound`, an expired one
//! `SessionExpired`. A live session with a mismatched process id yields
//! plain `NotFound` — indistinguishable from an unknown id (no oracle into
//! other sessions' processes).
//!
//! Gate 8 adds caller identity + grants on top, without changing the legacy
//! path: `handle_legacy_test_only()` (no identity — TEST-ONLY legacy
//! dispatch, ownerless wildcard sessions, permissive grants; hidden from
//! production use) vs `handle_as()` (production path: the server passes
//! the mTLS-derived `Caller`). Ownership isolation is ALWAYS on for
//! `handle_as`: sessions are bound to the caller's fingerprint at
//! creation, cross-owner access misses with generic `SessionNotFound`
//! (expiry collapsed — the kill is still attempted), and listings are
//! owner-filtered. Grant enforcement is strict iff a grants table is
//! configured (`state.grants.is_some()`); without one every check passes
//! (legacy-permissive, loud WARN at startup).
//!
//! Filesystem grant checks run AFTER resolution: the handler resolves the
//! request path (same function the op uses), relativizes the canonical
//! result, and checks grants on that relative path — symlink escapes are
//! still rejected by the boundary first, and `..` still surfaces as an
//! escape error under authz (never remapped to `Forbidden`).
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
    grants_allow_exec, grants_allow_fs, grants_allow_inspect, grants_allow_terminate,
    CapabilitySet, EnvironmentId, FsGrantKind, GetEnvironmentInfoRequest,
    GetEnvironmentInfoResponse, Grant, Platform, RpcError, RpcRequest, RpcResponse,
    RpcResponsePayload, SessionId, SessionInfo,
};

use crate::auth::Caller;
use crate::fs::{FilesystemBackend, FsError};
use crate::grants::GrantsTable;
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
    /// Per-client enforcement is Gate 8 grants (`state.grants`): effective
    /// = advertised ∩ grants (see `docs/grants.md`).
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
    /// Capability grants table (Gate 8). `None` = legacy-permissive: every
    /// grant check passes (development only). `Some` = STRICT: unknown
    /// fingerprints get `GetEnvironmentInfo` only; known fingerprints get
    /// exactly their grants. Ownership isolation applies in BOTH modes.
    pub grants: Option<GrantsTable>,
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
            grants: None,
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
            grants: None,
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

    /// Attach a capability grants table (Gate 8 strict mode).
    pub fn with_grants(mut self, grants: GrantsTable) -> Self {
        self.grants = Some(grants);
        self
    }

    /// Handle an RPC request WITHOUT a caller identity.
    ///
    /// TEST-ONLY. Never call from production code: this is
    /// `handle_as(None, ...)` — the caller identity is absent, so under a
    /// STRICT grants table every non-`GetEnvironmentInfo` RPC is
    /// forbidden, and with no grants table configured EVERY authorization
    /// check passes (fail-open). Sessions created here are ownerless
    /// (wildcard — any caller may address them). Production dispatch MUST
    /// use [`DaemonState::handle_as`] with the mTLS-derived caller from
    /// `server.rs`.
    ///
    /// `#[cfg(test)]` cannot expose this to the integration tests in
    /// `crates/are-daemon/tests/` (they compile the library WITHOUT
    /// `cfg(test)`), so the hard gate is structural instead: a
    /// deliberately non-idiomatic name, `#[doc(hidden)]`, and a loud
    /// warning on every invocation.
    #[doc(hidden)]
    pub fn handle_legacy_test_only(&self, request: RpcRequest) -> RpcResponse {
        tracing::warn!(
            "handle_legacy_test_only invoked (TEST-ONLY dispatch): no caller identity — \
             ownerless sessions and permissive grants; never call from production code; \
             use handle_as with the mTLS caller"
        );
        self.handle_as(None, request)
    }

    /// Handle an RPC request AS an authenticated caller (`None` = the
    /// legacy/test path, see `handle_legacy_test_only` — never in
    /// production). This is the production dispatch: `server.rs` passes
    /// the fingerprint derived from the verified leaf client certificate.
    pub fn handle_as(&self, caller: Option<&Caller>, request: RpcRequest) -> RpcResponse {
        match request {
            RpcRequest::GetEnvironmentInfo(req) => {
                let result = self.handle_get_environment_info(caller, req);
                RpcResponse {
                    result: result.map(RpcResponsePayload::GetEnvironmentInfo),
                }
            }
            RpcRequest::ReadFile(req) => {
                let result = self.handle_read_file(caller, req);
                RpcResponse {
                    result: result.map(RpcResponsePayload::ReadFile),
                }
            }
            RpcRequest::ListDirectory(req) => {
                let result = self.handle_list_directory(caller, req);
                RpcResponse {
                    result: result.map(RpcResponsePayload::ListDirectory),
                }
            }
            RpcRequest::GetFileMetadata(req) => {
                let result = self.handle_get_file_metadata(caller, req);
                RpcResponse {
                    result: result.map(RpcResponsePayload::GetFileMetadata),
                }
            }
            RpcRequest::WriteFile(req) => {
                let result = self.handle_write_file(caller, req);
                RpcResponse {
                    result: result.map(RpcResponsePayload::WriteFile),
                }
            }
            RpcRequest::CreateDirectory(req) => {
                let result = self.handle_create_directory(caller, req);
                RpcResponse {
                    result: result.map(RpcResponsePayload::CreateDirectory),
                }
            }
            RpcRequest::Rename(req) => {
                let result = self.handle_rename(caller, req);
                RpcResponse {
                    result: result.map(RpcResponsePayload::Rename),
                }
            }
            RpcRequest::DeleteFile(req) => {
                let result = self.handle_delete_file(caller, req);
                RpcResponse {
                    result: result.map(RpcResponsePayload::DeleteFile),
                }
            }
            RpcRequest::Execute(req) => {
                let result = self.handle_execute(caller, req);
                RpcResponse {
                    result: result.map(RpcResponsePayload::Execute),
                }
            }
            RpcRequest::ProcessStatus(req) => {
                let result = self.handle_process_status(caller, req);
                RpcResponse {
                    result: result.map(RpcResponsePayload::ProcessStatus),
                }
            }
            RpcRequest::TerminateProcess(req) => {
                let result = self.handle_terminate_process(caller, req);
                RpcResponse {
                    result: result.map(RpcResponsePayload::TerminateProcess),
                }
            }
            RpcRequest::WaitProcess(req) => {
                let result = self.handle_wait_process(caller, req);
                RpcResponse {
                    result: result.map(RpcResponsePayload::WaitProcess),
                }
            }
            RpcRequest::CreateSession(req) => {
                let result = self.handle_create_session(caller, req);
                RpcResponse {
                    result: result.map(RpcResponsePayload::CreateSession),
                }
            }
            RpcRequest::GetSession(req) => {
                let result = self.handle_get_session(caller, req);
                RpcResponse {
                    result: result.map(RpcResponsePayload::GetSession),
                }
            }
            RpcRequest::ListSessions(req) => {
                let result = self.handle_list_sessions(caller, req);
                RpcResponse {
                    result: result.map(RpcResponsePayload::ListSessions),
                }
            }
            RpcRequest::TerminateSession(req) => {
                let result = self.handle_terminate_session(caller, req);
                RpcResponse {
                    result: result.map(RpcResponsePayload::TerminateSession),
                }
            }
        }
    }

    // ---- Gate 8: authorization helpers ----

    /// Effective grants for a caller: `None` = legacy-permissive (no grants
    /// file configured) → unrestricted. `Some` = strict lookup (unknown
    /// fingerprint, or the legacy path under a strict table → empty).
    fn effective_grants(&self, caller: Option<&Caller>) -> Option<&[Grant]> {
        let table = self.grants.as_ref()?;
        match caller {
            Some(c) => Some(table.grants_for(&c.fingerprint).unwrap_or_default()),
            None => Some(&[]),
        }
    }

    /// Strict-mode unknown-principal gate: unknown fingerprints (and the
    /// legacy path under a strict table) may ONLY call
    /// `GetEnvironmentInfo`. Permissive mode always passes. Session
    /// operations for KNOWN principals are governed by ownership, not by
    /// this gate (there are no session grants in the model).
    fn deny_unknown_principal(&self, caller: Option<&Caller>) -> Result<(), RpcError> {
        if self.grants.is_none() {
            return Ok(());
        }
        let known = caller.is_some_and(|c| {
            self.grants
                .as_ref()
                .is_some_and(|table| table.is_known(&c.fingerprint))
        });
        if known {
            Ok(())
        } else {
            Err(RpcError::Forbidden(
                "unknown principal: no grants for this client identity (GetEnvironmentInfo only)"
                    .into(),
            ))
        }
    }

    /// Filesystem grant check on an already-relativized path. Denials echo
    /// the RELATIVE path only — never canonical host paths.
    fn check_fs_grant(
        &self,
        caller: Option<&Caller>,
        kind: FsGrantKind,
        rel: &str,
    ) -> Result<(), RpcError> {
        let scope = match kind {
            FsGrantKind::Read => "filesystem.read",
            FsGrantKind::Write => "filesystem.write",
            FsGrantKind::List => "filesystem.list",
        };
        let Some(grants) = self.effective_grants(caller) else {
            log_authz_decision(caller, true, scope, &format!("permissive: '{rel}'"));
            return Ok(());
        };
        if grants_allow_fs(grants, kind, rel) {
            log_authz_decision(
                caller,
                true,
                scope,
                &format!("granted scope covers '{rel}'"),
            );
            return Ok(());
        }
        log_authz_decision(
            caller,
            false,
            scope,
            &format!("no {scope} grant covers '{rel}'"),
        );
        Err(RpcError::Forbidden(format!("{scope} denied for '{rel}'")))
    }

    /// Execute grant check (normalized basename match). The daemon's
    /// execution policy is checked separately, FIRST — `DeniedExecutable`
    /// means "nobody may run this", `Forbidden` means "you may not".
    fn check_exec_grant(&self, caller: Option<&Caller>, program: &str) -> Result<(), RpcError> {
        let Some(grants) = self.effective_grants(caller) else {
            log_authz_decision(
                caller,
                true,
                "process.execute",
                &format!("permissive: '{program}'"),
            );
            return Ok(());
        };
        let normalized = are_core::normalize_program_name(program);
        if grants_allow_exec(grants, program) {
            log_authz_decision(
                caller,
                true,
                "process.execute",
                &format!("allowlist covers '{normalized}'"),
            );
            return Ok(());
        }
        log_authz_decision(
            caller,
            false,
            "process.execute",
            &format!("'{normalized}' not in process.execute allowlist"),
        );
        Err(RpcError::Forbidden(format!(
            "process.execute denied for '{normalized}'"
        )))
    }

    /// Inspect grant check (gates `process_status`).
    fn check_inspect_grant(&self, caller: Option<&Caller>) -> Result<(), RpcError> {
        let Some(grants) = self.effective_grants(caller) else {
            log_authz_decision(caller, true, "process.inspect", "permissive");
            return Ok(());
        };
        if grants_allow_inspect(grants) {
            log_authz_decision(
                caller,
                true,
                "process.inspect",
                "process_inspect grant present",
            );
            return Ok(());
        }
        log_authz_decision(caller, false, "process.inspect", "no process_inspect grant");
        Err(RpcError::Forbidden("process.inspect denied".into()))
    }

    /// Terminate grant check (gates `terminate_process` AND `wait_process`).
    fn check_terminate_grant(&self, caller: Option<&Caller>) -> Result<(), RpcError> {
        let Some(grants) = self.effective_grants(caller) else {
            log_authz_decision(caller, true, "process.terminate", "permissive");
            return Ok(());
        };
        if grants_allow_terminate(grants) {
            log_authz_decision(
                caller,
                true,
                "process.terminate",
                "process_terminate grant present",
            );
            return Ok(());
        }
        log_authz_decision(
            caller,
            false,
            "process.terminate",
            "no process_terminate grant",
        );
        Err(RpcError::Forbidden("process.terminate denied".into()))
    }

    /// Resolve `path` with the same function the op uses (`follow_final`
    /// must match: `true` for read/write/metadata/list, `false` for
    /// rename/delete) and relativize the canonical result for the grant
    /// check. Resolve failures propagate EXACTLY as the op would report
    /// them (boundary escapes stay escapes — never remapped to
    /// `Forbidden`); a canonical path under no root is a defensive escape
    /// error (unreachable — resolution guarantees containment).
    ///
    /// RESIDUAL (documented in `docs/grants.md`): the op re-resolves after
    /// the check, so a concurrent host-side symlink swap between the two
    /// could move the target within the root but outside the granted
    /// scope. Clients cannot plant symlinks (no symlink-creation op), so
    /// this needs a confederate with host access — out of scope, same
    /// class as the existing documented TOCTOU windows.
    fn fs_rel_for_grant(
        &self,
        fs: &FilesystemBackend,
        path: &str,
        follow_final: bool,
    ) -> Result<String, RpcError> {
        let canonical = if follow_final {
            fs.resolve(path)
        } else {
            fs.resolve_no_follow(path)
        }
        .map_err(|e| fs_error_to_rpc(e, path))?;
        fs.relativize(&canonical).ok_or_else(|| {
            RpcError::InternalError(
                "filesystem escape blocked: path escapes allowed boundary".into(),
            )
        })
    }

    fn handle_get_environment_info(
        &self,
        caller: Option<&Caller>,
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
            // Open to ALL authenticated callers (even unknown principals
            // in strict mode): this is how a client learns its fingerprint
            // to request grants. No authorization check here by design.
            caller_fingerprint: caller.map(|c| c.fingerprint.clone()),
        })
    }

    fn handle_read_file(
        &self,
        caller: Option<&Caller>,
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
        self.deny_unknown_principal(caller)?;
        // Authorize AFTER resolution (relativized canonical path).
        let rel = self.fs_rel_for_grant(fs, &req.path, true)?;
        self.check_fs_grant(caller, FsGrantKind::Read, &rel)?;

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
        caller: Option<&Caller>,
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
        self.deny_unknown_principal(caller)?;
        let rel = self.fs_rel_for_grant(fs, &req.path, true)?;
        self.check_fs_grant(caller, FsGrantKind::List, &rel)?;

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
        caller: Option<&Caller>,
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
        self.deny_unknown_principal(caller)?;
        // Metadata carries the content hash: it is a read, gated by Read.
        let rel = self.fs_rel_for_grant(fs, &req.path, true)?;
        self.check_fs_grant(caller, FsGrantKind::Read, &rel)?;

        let req_clone = req.clone();
        let metadata = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { fs.file_metadata(&req_clone.path).await })
        })
        .map_err(|e| fs_error_to_rpc(e, &req.path))?;

        Ok(are_core::GetFileMetadataResponse { metadata })
    }

    /// Require the filesystem backend and check the environment binding
    /// first, mirroring the read-path handlers. File operations are
    /// ENVIRONMENT-scoped, not session-scoped (Gate 7 decision): files
    /// belong to the environment's allowed roots; sessions only carry
    /// working directories and process state. No `session_id` is taken.
    fn require_fs(
        &self,
        environment_id: &are_core::EnvironmentId,
    ) -> Result<&FilesystemBackend, RpcError> {
        if *environment_id != self.environment_id {
            return Err(RpcError::InvalidRequest(format!(
                "requested environment '{environment_id}' does not match daemon environment '{}'",
                self.environment_id
            )));
        }
        self.fs
            .as_ref()
            .ok_or_else(|| RpcError::InternalError("filesystem backend not configured".into()))
    }

    fn handle_write_file(
        &self,
        caller: Option<&Caller>,
        req: are_core::WriteFileRequest,
    ) -> Result<are_core::WriteFileResponse, RpcError> {
        // Domain validation first (empty path, malformed expected_hash).
        if let Err(e) = req.validate() {
            return Err(RpcError::InvalidRequest(e.to_string()));
        }
        let fs = self.require_fs(&req.environment_id)?;
        self.deny_unknown_principal(caller)?;
        let rel = self.fs_rel_for_grant(fs, &req.path, true)?;
        self.check_fs_grant(caller, FsGrantKind::Write, &rel)?;
        let req_clone = req.clone();
        let metadata = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async {
                fs.write_file(
                    &req_clone.path,
                    &req_clone.content,
                    req_clone.overwrite,
                    req_clone.expected_hash.as_deref(),
                )
                .await
            })
        })
        .map_err(|e| fs_error_to_rpc(e, &req.path))?;

        Ok(are_core::WriteFileResponse { metadata })
    }

    fn handle_create_directory(
        &self,
        caller: Option<&Caller>,
        req: are_core::CreateDirectoryRequest,
    ) -> Result<are_core::CreateDirectoryResponse, RpcError> {
        if let Err(e) = req.validate() {
            return Err(RpcError::InvalidRequest(e.to_string()));
        }
        let fs = self.require_fs(&req.environment_id)?;
        self.deny_unknown_principal(caller)?;
        // Creation targets usually do not exist: authorize the lexical
        // creation path (same rejection set as the op's own walk).
        let rel = fs
            .creation_rel(&req.path)
            .map_err(|e| fs_error_to_rpc(e, &req.path))?;
        self.check_fs_grant(caller, FsGrantKind::Write, &rel)?;
        let req_clone = req.clone();
        let metadata = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { fs.create_directory(&req_clone.path).await })
        })
        .map_err(|e| fs_error_to_rpc(e, &req.path))?;

        Ok(are_core::CreateDirectoryResponse { metadata })
    }

    fn handle_rename(
        &self,
        caller: Option<&Caller>,
        req: are_core::RenameRequest,
    ) -> Result<are_core::RenameResponse, RpcError> {
        if let Err(e) = req.validate() {
            return Err(RpcError::InvalidRequest(e.to_string()));
        }
        let fs = self.require_fs(&req.environment_id)?;
        self.deny_unknown_principal(caller)?;
        // Rename needs Write covering BOTH ends (no-follow, matching the op).
        let rel_src = self.fs_rel_for_grant(fs, &req.src, false)?;
        self.check_fs_grant(caller, FsGrantKind::Write, &rel_src)?;
        let rel_dst = self.fs_rel_for_grant(fs, &req.dst, false)?;
        self.check_fs_grant(caller, FsGrantKind::Write, &rel_dst)?;
        let req_clone = req.clone();
        let metadata = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { fs.rename_path(&req_clone.src, &req_clone.dst).await })
        })
        .map_err(|e| fs_error_to_rpc(e, &format!("{} -> {}", req.src, req.dst)))?;

        Ok(are_core::RenameResponse { metadata })
    }

    fn handle_delete_file(
        &self,
        caller: Option<&Caller>,
        req: are_core::DeleteRequest,
    ) -> Result<are_core::DeleteResponse, RpcError> {
        if let Err(e) = req.validate() {
            return Err(RpcError::InvalidRequest(e.to_string()));
        }
        let fs = self.require_fs(&req.environment_id)?;
        self.deny_unknown_principal(caller)?;
        // DELETE folds into the Write scope: no separate delete variant.
        let rel = self.fs_rel_for_grant(fs, &req.path, false)?;
        self.check_fs_grant(caller, FsGrantKind::Write, &rel)?;
        let req_clone = req.clone();
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current()
                .block_on(async { fs.delete_path(&req_clone.path).await })
        })
        .map_err(|e| fs_error_to_rpc(e, &req.path))?;

        Ok(are_core::DeleteResponse { deleted: true })
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
        caller: Option<&Caller>,
        req: are_core::ExecuteRequest,
    ) -> Result<are_core::ExecuteResponse, RpcError> {
        let proc = self.require_proc(&req.environment_id)?;
        // Session liveness FIRST (touch bumps activity): unknown →
        // SessionNotFound, aged-out → SessionExpired. A live session whose
        // environment differs from the request is NotFound-adjacent — but
        // since sessions belong to exactly one environment, treat it as a
        // plain NotFound to avoid distinguishing "wrong env" from
        // "wrong session".
        let session = self.require_live_session(caller, &req.session_id)?;
        if session.environment_id != req.environment_id {
            return Err(RpcError::NotFound(format!(
                "unknown session '{}'",
                req.session_id
            )));
        }
        self.deny_unknown_principal(caller)?;
        // Domain validation (was inside `start`; hoisted so malformed
        // requests stay `InvalidRequest` before any policy evaluation).
        if let Err(e) = req.validate() {
            return Err(RpcError::InvalidRequest(e.to_string()));
        }
        // Daemon-wide execution policy FIRST ("nobody may run this"),
        // then the caller's grants ("you may not").
        if let Err(e) = proc.config().check_policy(&req.program) {
            return Err(process_error_to_rpc(e));
        }
        self.check_exec_grant(caller, &req.program)?;
        let process_id = tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async { proc.start(req, &session).await })
        })
        .map_err(process_error_to_rpc)?;
        Ok(are_core::ExecuteResponse { process_id })
    }

    fn handle_process_status(
        &self,
        caller: Option<&Caller>,
        req: are_core::ProcessStatusRequest,
    ) -> Result<are_core::ProcessStatusResponse, RpcError> {
        let proc = self.require_proc(&req.environment_id)?;
        let session = self.require_live_session(caller, &req.session_id)?;
        if session.environment_id != req.environment_id {
            return Err(RpcError::NotFound(format!(
                "unknown process id '{}'",
                req.process_id
            )));
        }
        self.deny_unknown_principal(caller)?;
        self.check_inspect_grant(caller)?;
        proc.status(&req).map_err(process_error_to_rpc)
    }

    fn handle_terminate_process(
        &self,
        caller: Option<&Caller>,
        req: are_core::TerminateProcessRequest,
    ) -> Result<are_core::TerminateProcessResponse, RpcError> {
        let proc = self.require_proc(&req.environment_id)?;
        let session = self.require_live_session(caller, &req.session_id)?;
        if session.environment_id != req.environment_id {
            return Err(RpcError::NotFound(format!(
                "unknown process id '{}'",
                req.process_id
            )));
        }
        self.deny_unknown_principal(caller)?;
        self.check_terminate_grant(caller)?;
        tokio::task::block_in_place(|| {
            tokio::runtime::Handle::current().block_on(async { proc.terminate(req).await })
        })
        .map_err(process_error_to_rpc)
    }

    fn handle_wait_process(
        &self,
        caller: Option<&Caller>,
        req: are_core::WaitProcessRequest,
    ) -> Result<are_core::WaitProcessResponse, RpcError> {
        let proc = self.require_proc(&req.environment_id)?;
        let session = self.require_live_session(caller, &req.session_id)?;
        if session.environment_id != req.environment_id {
            return Err(RpcError::NotFound(format!(
                "unknown process id '{}'",
                req.process_id
            )));
        }
        self.deny_unknown_principal(caller)?;
        // Waiting observes terminal output: gated by Terminate, mirroring
        // the advertised-capability mapping.
        self.check_terminate_grant(caller)?;
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
    /// Ownership (Gate 8): the touch is owner-aware. Cross-owner access
    /// misses with `SessionNotFound` — including for expired entries (the
    /// expiry is collapsed, but the removal is still reported so the kill
    /// below is still attempted: non-owners never observe `Expired`).
    ///
    /// Kill-on-expiry: when the session check reports `Expired`, this
    /// choke point best-effort kills that session's processes FIRST, then
    /// returns `Expired`. Without the kill, the just-removed session's live
    /// children would become unaddressable (all proc ops gate on a live
    /// session first) — a silent-orphan table-exhaustion path.
    fn require_live_session(
        &self,
        caller: Option<&Caller>,
        session_id: &SessionId,
    ) -> Result<SessionInfo, RpcError> {
        let sessions = self
            .sessions
            .clone()
            .ok_or_else(|| RpcError::InternalError("session backend not configured".into()))?;
        let (result, purged) =
            sessions.touch_owned(session_id, caller.map(|c| c.fingerprint.as_str()));
        // Purged expired entries lose their processes either way — owner or
        // hidden-oracle path alike (kill attempted despite the error).
        self.kill_purged_sessions_best_effort(&purged);
        match result {
            Ok(info) => Ok(info),
            Err(crate::session::SessionError::Expired(msg)) => Err(RpcError::SessionExpired(msg)),
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
        caller: Option<&Caller>,
        req: are_core::CreateSessionRequest,
    ) -> Result<are_core::CreateSessionResponse, RpcError> {
        if req.environment_id != self.environment_id {
            return Err(RpcError::InvalidRequest(format!(
                "requested environment '{}' does not match daemon environment '{}'",
                req.environment_id, self.environment_id
            )));
        }
        self.deny_unknown_principal(caller)?;
        let sessions = self
            .sessions
            .clone()
            .ok_or_else(|| RpcError::InternalError("session backend not configured".into()))?;
        // Ownership isolation (ALWAYS on, both modes): bind the session to
        // the caller's fingerprint. The legacy path binds nothing
        // (ownerless wildcard, debug-logged by the manager).
        let owner = caller.map(|c| c.fingerprint.clone());
        let (session, purged) = sessions
            .create_owned(req, owner)
            .map_err(session_error_to_rpc)?;
        // The pre-creation purge may have removed expired sessions with
        // live children: kill them best-effort so they never orphan.
        self.kill_purged_sessions_best_effort(&purged);
        Ok(are_core::CreateSessionResponse { session })
    }

    fn handle_get_session(
        &self,
        caller: Option<&Caller>,
        req: are_core::GetSessionRequest,
    ) -> Result<are_core::GetSessionResponse, RpcError> {
        if req.environment_id != self.environment_id {
            return Err(RpcError::InvalidRequest(format!(
                "requested environment '{}' does not match daemon environment '{}'",
                req.environment_id, self.environment_id
            )));
        }
        self.deny_unknown_principal(caller)?;
        // `require_live_session` IS the resume operation here: bumps
        // activity, kills-on-expiry, and maps Expired/NotFound. (It touches
        // rather than plain-getting so expiry kills apply on this path too.)
        let session = self.require_live_session(caller, &req.session_id)?;
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
        caller: Option<&Caller>,
        req: are_core::ListSessionsRequest,
    ) -> Result<are_core::ListSessionsResponse, RpcError> {
        if req.environment_id != self.environment_id {
            return Err(RpcError::InvalidRequest(format!(
                "requested environment '{}' does not match daemon environment '{}'",
                req.environment_id, self.environment_id
            )));
        }
        self.deny_unknown_principal(caller)?;
        let sessions = self
            .sessions
            .clone()
            .ok_or_else(|| RpcError::InternalError("session backend not configured".into()))?;
        // Owner-filtered: a caller sees own sessions plus legacy ownerless
        // ones — never another principal's.
        let (live, purged) =
            sessions.list_owned(&req.environment_id, caller.map(|c| c.fingerprint.as_str()));
        self.kill_purged_sessions_best_effort(&purged);
        Ok(are_core::ListSessionsResponse { sessions: live })
    }

    fn handle_terminate_session(
        &self,
        caller: Option<&Caller>,
        req: are_core::TerminateSessionRequest,
    ) -> Result<are_core::TerminateSessionResponse, RpcError> {
        if req.environment_id != self.environment_id {
            return Err(RpcError::InvalidRequest(format!(
                "requested environment '{}' does not match daemon environment '{}'",
                req.environment_id, self.environment_id
            )));
        }
        self.deny_unknown_principal(caller)?;
        let sessions = self
            .sessions
            .clone()
            .ok_or_else(|| RpcError::InternalError("session backend not configured".into()))?;
        // Peek-live FIRST via the kill-on-expiry choke point. Live →
        // kill → remove → return the live-kill count. Expired → the kill
        // was already attempted inside `require_live_session`, so return
        // `Expired` (documented: kill attempted despite the error) instead
        // of masking the recovery path as success.
        let live = match self.require_live_session(caller, &req.session_id) {
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
        let (result, purged) =
            sessions.terminate_owned(&req.session_id, caller.map(|c| c.fingerprint.as_str()));
        // The touch above just proved liveness, so `purged` here only fires
        // on the touch→remove max-lifetime race — still kill it.
        self.kill_purged_sessions_best_effort(&purged);
        match result {
            Ok(()) => Ok(are_core::TerminateSessionResponse {
                terminated_processes,
            }),
            Err(crate::session::SessionError::Expired(msg)) => Err(RpcError::SessionExpired(
                format!("{msg} (session processes kill attempted despite expiry)"),
            )),
            Err(other) => Err(session_error_to_rpc(other)),
        }
    }
}

/// Server-side-only authorization forensics: one debug line per grant
/// decision. The detail carries the granted scope plus the relative path,
/// program, or denied reason. `debug!` output stays on the daemon host
/// (tracing) and is never rendered into a client-visible `RpcError` —
/// denials still use the same generic messages as before. Noisy under
/// unconstrained permissive mode by design: that is the fail-open signal.
fn log_authz_decision(caller: Option<&Caller>, allowed: bool, scope: &str, detail: &str) {
    let who = caller
        .map(|c| c.fingerprint.as_str())
        .unwrap_or("<no-identity>");
    if allowed {
        tracing::debug!("authz allow {scope} for {who}: {detail}");
    } else {
        tracing::debug!("authz deny {scope} for {who}: {detail}");
    }
}

/// Map a session error to an RPC error, preserving the resume-relevant
/// distinction: unknown ids (`SessionNotFound`) vs aged-out sessions
/// (`SessionExpired`) vs malformed requests (`InvalidRequest`). Capacity
/// refusals (`TooManySessions`) map to the dedicated `CapacityExceeded`
/// category. NOTE: the `NotFound`/`Expired` split reaches only owners and
/// legacy ownerless sessions — owner-aware access collapses it to
/// `NotFound` for non-owners (see `SessionManager::get_owned`).
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
        FsError::NotFound(_) => RpcError::NotFound(format!("{path}: not found")),
        FsError::Conflict(msg) => RpcError::Conflict(format!("{path}: {msg}")),
        FsError::PermissionDenied(_) => {
            RpcError::InternalError(format!("{path}: permission denied"))
        }
        FsError::NotADirectory(_) => RpcError::InternalError(format!("{path}: not a directory")),
        FsError::IsADirectory(_) => RpcError::InternalError(format!("{path}: is a directory")),
        // Oversized payloads/reads are REFUSED as InvalidRequest (the
        // client could have bounded the request) — not an internal fault.
        FsError::FileTooLarge { path, size, limit } => RpcError::InvalidRequest(format!(
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

        let resp = state.handle_legacy_test_only(req);
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

        let resp = state.handle_legacy_test_only(req);
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

        let resp = state.handle_legacy_test_only(req);
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

        let resp = state.handle_legacy_test_only(req);
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

        let resp = state.handle_legacy_test_only(req);
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

        let resp = state.handle_legacy_test_only(req);
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

        let resp = state.handle_legacy_test_only(req);
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

        let resp = state.handle_legacy_test_only(req);
        assert!(resp.result.is_err());
        match resp.result {
            Err(RpcError::InvalidRequest(msg)) => {
                assert!(msg.contains("does not match"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }

    // ---- Gate 7: file-write dispatch (environment-scoped, no session) ----

    /// Build a `DaemonState` wired with a filesystem backend rooted at a
    /// temp dir. File ops take no session: this state has none.
    fn fs_state() -> (tempfile::TempDir, DaemonState) {
        let tmp = tempfile::TempDir::new().unwrap();
        let fs =
            FilesystemBackend::new(FilesystemConfig::new(&[tmp.path().to_path_buf()]).unwrap());
        let mut caps = CapabilitySet::default();
        caps.insert(Capability::FilesystemRead);
        caps.insert(Capability::FilesystemList);
        caps.insert(Capability::FilesystemWrite);
        let state = DaemonState::with_fs(
            EnvironmentId::new("test-env"),
            "test-host".into(),
            "0.1.0".into(),
            caps,
            Platform::Debian,
            fs,
        );
        (tmp, state)
    }

    #[test]
    fn handle_write_ops_without_fs_backend() {
        let state = test_state();
        for req in [
            RpcRequest::WriteFile(are_core::WriteFileRequest {
                environment_id: EnvironmentId::new("test-env"),
                path: "a.txt".into(),
                content: b"x".to_vec(),
                overwrite: true,
                expected_hash: None,
            }),
            RpcRequest::CreateDirectory(are_core::CreateDirectoryRequest {
                environment_id: EnvironmentId::new("test-env"),
                path: "a".into(),
            }),
            RpcRequest::Rename(are_core::RenameRequest {
                environment_id: EnvironmentId::new("test-env"),
                src: "a".into(),
                dst: "b".into(),
            }),
            RpcRequest::DeleteFile(are_core::DeleteRequest {
                environment_id: EnvironmentId::new("test-env"),
                path: "a".into(),
            }),
        ] {
            let resp = state.handle_legacy_test_only(req);
            match resp.result {
                Err(RpcError::InternalError(msg)) => {
                    assert!(msg.contains("filesystem backend not configured"), "{msg}");
                }
                other => panic!("expected InternalError, got {other:?}"),
            }
        }
    }

    #[test]
    fn handle_write_ops_wrong_env_rejected_first() {
        let (_tmp, state) = fs_state();
        for req in [
            RpcRequest::WriteFile(are_core::WriteFileRequest {
                environment_id: EnvironmentId::new("wrong-env"),
                path: "a.txt".into(),
                content: b"x".to_vec(),
                overwrite: true,
                expected_hash: None,
            }),
            RpcRequest::CreateDirectory(are_core::CreateDirectoryRequest {
                environment_id: EnvironmentId::new("wrong-env"),
                path: "a".into(),
            }),
            RpcRequest::Rename(are_core::RenameRequest {
                environment_id: EnvironmentId::new("wrong-env"),
                src: "a".into(),
                dst: "b".into(),
            }),
            RpcRequest::DeleteFile(are_core::DeleteRequest {
                environment_id: EnvironmentId::new("wrong-env"),
                path: "a".into(),
            }),
        ] {
            let resp = state.handle_legacy_test_only(req);
            match resp.result {
                Err(RpcError::InvalidRequest(msg)) => assert!(msg.contains("does not match")),
                other => panic!("expected InvalidRequest, got {other:?}"),
            }
        }
    }

    #[test]
    fn handle_write_rejects_malformed_expected_hash() {
        let (_tmp, state) = fs_state();
        let req = RpcRequest::WriteFile(are_core::WriteFileRequest {
            environment_id: EnvironmentId::new("test-env"),
            path: "a.txt".into(),
            content: b"x".to_vec(),
            overwrite: true,
            expected_hash: Some("not-a-hash".into()),
        });
        let resp = state.handle_legacy_test_only(req);
        assert!(
            matches!(resp.result, Err(RpcError::InvalidRequest(_))),
            "malformed expected_hash must be InvalidRequest, got {:?}",
            resp.result
        );
    }

    #[test]
    fn handle_rename_rejects_src_eq_dst() {
        let (_tmp, state) = fs_state();
        let req = RpcRequest::Rename(are_core::RenameRequest {
            environment_id: EnvironmentId::new("test-env"),
            src: "a".into(),
            dst: "a".into(),
        });
        let resp = state.handle_legacy_test_only(req);
        assert!(
            matches!(resp.result, Err(RpcError::InvalidRequest(_))),
            "src==dst must be InvalidRequest, got {:?}",
            resp.result
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn handle_write_mkdir_rename_delete_happy_path() {
        let (_tmp, state) = fs_state();
        let env = EnvironmentId::new("test-env");

        // write
        let resp =
            state.handle_legacy_test_only(RpcRequest::WriteFile(are_core::WriteFileRequest {
                environment_id: env.clone(),
                path: "hello.txt".into(),
                content: b"hello".to_vec(),
                overwrite: true,
                expected_hash: None,
            }));
        let hash = match resp.result {
            Ok(RpcResponsePayload::WriteFile(w)) => {
                assert_eq!(w.metadata.size, 5);
                match w.metadata.hash {
                    Some(h) => h,
                    None => panic!("write must return a hash"),
                }
            }
            other => panic!("expected WriteFile response, got {other:?}"),
        };

        // stale-hash overwrite refuses with Conflict (RPC-level check).
        let resp =
            state.handle_legacy_test_only(RpcRequest::WriteFile(are_core::WriteFileRequest {
                environment_id: env.clone(),
                path: "hello.txt".into(),
                content: b"stale".to_vec(),
                overwrite: true,
                expected_hash: Some("d".repeat(64)),
            }));
        assert!(
            matches!(resp.result, Err(RpcError::Conflict(_))),
            "stale hash must be Conflict, got {:?}",
            resp.result
        );

        // fresh-hash overwrite succeeds.
        let resp =
            state.handle_legacy_test_only(RpcRequest::WriteFile(are_core::WriteFileRequest {
                environment_id: env.clone(),
                path: "hello.txt".into(),
                content: b"hello2".to_vec(),
                overwrite: true,
                expected_hash: Some(hash),
            }));
        assert!(
            matches!(resp.result, Ok(RpcResponsePayload::WriteFile(_))),
            "fresh hash must succeed, got {:?}",
            resp.result
        );

        // mkdir
        let resp = state.handle_legacy_test_only(RpcRequest::CreateDirectory(
            are_core::CreateDirectoryRequest {
                environment_id: env.clone(),
                path: "sub/dir".into(),
            },
        ));
        assert!(
            matches!(resp.result, Ok(RpcResponsePayload::CreateDirectory(_))),
            "got {:?}",
            resp.result
        );

        // rename
        let resp = state.handle_legacy_test_only(RpcRequest::Rename(are_core::RenameRequest {
            environment_id: env.clone(),
            src: "hello.txt".into(),
            dst: "sub/moved.txt".into(),
        }));
        assert!(
            matches!(resp.result, Ok(RpcResponsePayload::Rename(_))),
            "got {:?}",
            resp.result
        );

        // rename onto existing dst conflicts.
        let resp = state.handle_legacy_test_only(RpcRequest::Rename(are_core::RenameRequest {
            environment_id: env.clone(),
            src: "sub/moved.txt".into(),
            dst: "sub/dir".into(),
        }));
        assert!(
            matches!(resp.result, Err(RpcError::Conflict(_))),
            "got {:?}",
            resp.result
        );

        // delete non-empty dir conflicts.
        let resp = state.handle_legacy_test_only(RpcRequest::DeleteFile(are_core::DeleteRequest {
            environment_id: env.clone(),
            path: "sub".into(),
        }));
        assert!(
            matches!(resp.result, Err(RpcError::Conflict(_))),
            "got {:?}",
            resp.result
        );

        // delete file, then empty dirs, bottom-up.
        for p in ["sub/moved.txt", "sub/dir", "sub"] {
            let resp =
                state.handle_legacy_test_only(RpcRequest::DeleteFile(are_core::DeleteRequest {
                    environment_id: env.clone(),
                    path: p.into(),
                }));
            assert!(
                matches!(resp.result, Ok(RpcResponsePayload::DeleteFile(_))),
                "delete {p} must succeed, got {:?}",
                resp.result
            );
        }
    }

    // ---- FIX 4: fs error categories map to distinct RPC errors ----

    #[tokio::test(flavor = "multi_thread")]
    async fn handle_rename_missing_src_is_not_found() {
        let (_tmp, state) = fs_state();
        let resp = state.handle_legacy_test_only(RpcRequest::Rename(are_core::RenameRequest {
            environment_id: EnvironmentId::new("test-env"),
            src: "missing.txt".into(),
            dst: "other.txt".into(),
        }));
        assert!(
            matches!(resp.result, Err(RpcError::NotFound(_))),
            "missing rename src must be NotFound, got {:?}",
            resp.result
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn handle_write_missing_parent_is_not_found() {
        // Write under an absent parent chain (`missing-dir/` does not
        // exist): the path does NOT escape — its parent simply does not
        // exist. The backend's new `FsError::NotFound` must map through
        // `fs_error_to_rpc` to `RpcError::NotFound` (it already does;
        // this is the end-to-end guard) — never the misleading
        // "filesystem escape blocked" InternalError.
        let (_tmp, state) = fs_state();
        let resp =
            state.handle_legacy_test_only(RpcRequest::WriteFile(are_core::WriteFileRequest {
                environment_id: EnvironmentId::new("test-env"),
                path: "missing-dir/file.txt".into(),
                content: b"x".to_vec(),
                overwrite: true,
                expected_hash: None,
            }));
        assert!(
            matches!(resp.result, Err(RpcError::NotFound(_))),
            "missing parent must be RpcError::NotFound, got {:?}",
            resp.result
        );
    }

    // ---- FIX 2: non-NotFound canonicalize failures stay generic at the
    //       RPC boundary — no host paths may reach the client ----

    #[tokio::test(flavor = "multi_thread")]
    async fn handle_delete_under_file_error_leaks_no_host_root() {
        let (tmp, state) = fs_state();
        // `file.txt/child/x`: parent `file.txt` is a FILE, so the parent
        // canonicalize fails — ENOTDIR-as-Io on Linux (which previously
        // leaked the allowed ROOT host path), NotFound on Windows. Either
        // way the RPC error must NOT embed the root.
        std::fs::write(tmp.path().join("file.txt"), "x").unwrap();
        let root_str = tmp.path().to_string_lossy().to_string();
        let resp = state.handle_legacy_test_only(RpcRequest::DeleteFile(are_core::DeleteRequest {
            environment_id: EnvironmentId::new("test-env"),
            path: "file.txt/child/x".into(),
        }));
        match resp.result {
            Err(RpcError::InternalError(msg)) | Err(RpcError::NotFound(msg)) => {
                assert!(!msg.contains(&root_str), "leaked allowed root: {msg}");
                assert!(
                    !msg.contains(tmp.path().file_name().unwrap().to_string_lossy().as_ref()),
                    "leaked root component: {msg}"
                );
            }
            other => panic!("expected InternalError or NotFound, got {other:?}"),
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

        let resp = state.handle_legacy_test_only(req);
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

        let resp = state.handle_legacy_test_only(req);
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

        let resp = state.handle_legacy_test_only(req);
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

        let resp = state.handle_legacy_test_only(req);
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

        let resp = state.handle_legacy_test_only(req);
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

        let resp = state.handle_legacy_test_only(req);
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

        let resp = state.handle_legacy_test_only(req);
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
        let resp = state.handle_legacy_test_only(req);
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
        let resp = state.handle_legacy_test_only(req);
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
        let resp = state.handle_legacy_test_only(req);
        match resp.result {
            Ok(RpcResponsePayload::ProcessStatus(status)) => {
                assert_eq!(status.state, are_core::ProcessState::Exited { code: 0 });
            }
            other => panic!("expected ProcessStatus response, got {other:?}"),
        }
    }
}
