//! Gate 8 acceptance + adversarial tests: capability-based authorization.
//!
//! Acceptance mapping (PLAN.md Gate 8):
//!
//! - Two agents, one machine, different permissions: Agent A (read/write
//!   project + exec) vs Agent B (read logs only) —
//!   `agent_a_fullish_vs_agent_b_logs_only`, `exec_authorization`, and the
//!   wire test `wire_two_principals_end_to_end`.
//! - Default DENY: unknown principals get `GetEnvironmentInfo` only —
//!   `unknown_principal_gets_env_info_only` (+ wire angle).
//!
//! Adversarial table (STOP gate: attempt each, all must fail closed):
//!
//! | Attack                              | Test                                              | Must see       |
//! | ----------------------------------- | ------------------------------------------------- | -------------- |
//! | Session hijack (B uses A's session) | `hijack_cross_owner_ops_miss`                     | `SessionNotFound` |
//! | Expiry oracle (was id once live?)   | `expiry_oracle_collapsed_for_non_owner`           | never `Expired` for non-owners |
//! | Privilege escalation via A's session| `hijack_cross_owner_ops_miss` (exec/status/rm)    | `SessionNotFound` |
//! | Path escape under authz (`..`)      | `dotdot_still_escape_under_authz`                 | escape error, NOT `Forbidden` |
//! | Scope confusion (`logs` vs `logs2`) | `scope_edges_logs_vs_logs2`                       | `Forbidden`    |
//! | Whole-root (`""`) over/under-grant  | `scope_edges_logs_vs_logs2`                       | exact coverage |
//! | Empty `process_execute` allows all? | `exec_authorization`                              | `Forbidden`    |
//! | Rename across scopes                | `rename_needs_write_on_both_ends`                 | `Forbidden`    |
//! | Delete without Write                | `delete_folds_into_write`                         | `Forbidden`    |
//!
//! Dispatch-level tests go through `DaemonState::handle_as` (the same
//! envelope the wire uses); the final test runs the real mTLS wire with
//! two distinct client certificates proving end-to-end principal binding.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::sync::Arc;

use are_core::{
    CreateSessionRequest, EnvironmentId, GetSessionRequest, ListSessionsRequest, RpcRequest,
    RpcResponsePayload, TerminateSessionRequest,
};
use are_daemon::auth::Caller;
use are_daemon::fs::{FilesystemBackend, FilesystemConfig};
use are_daemon::grants::GrantsTable;
use are_daemon::handler::DaemonState;
use are_daemon::process::{ProcessConfig, ProcessManager};
use are_daemon::session::{SessionConfig, SessionManager};

const ENV: &str = "test-env";

fn fp_a() -> String {
    format!("blake3:{}", "a".repeat(64))
}

fn fp_b() -> String {
    format!("blake3:{}", "b".repeat(64))
}

fn fp_unknown() -> String {
    format!("blake3:{}", "c".repeat(64))
}

fn caller_a() -> Caller {
    Caller::new(fp_a())
}

fn caller_b() -> Caller {
    Caller::new(fp_b())
}

fn caller_unknown() -> Caller {
    Caller::new(fp_unknown())
}

fn env() -> EnvironmentId {
    EnvironmentId::new(ENV)
}

/// Fixture tree: `project/app.txt`, `logs/app.log`, `logs2/other.txt`.
fn plant_fixtures(root: &std::path::Path) {
    for dir in ["project", "logs", "logs2"] {
        std::fs::create_dir_all(root.join(dir)).unwrap();
    }
    std::fs::write(root.join("project/app.txt"), "app").unwrap();
    std::fs::write(root.join("logs/app.log"), "log").unwrap();
    std::fs::write(root.join("logs2/other.txt"), "other").unwrap();
}

/// Strict state: A is full-ish (read/list whole root, write project, exec
/// echo, inspect + terminate), B reads/lists logs only.
fn strict_state() -> (tempfile::TempDir, DaemonState) {
    let tmp = tempfile::TempDir::new().unwrap();
    plant_fixtures(tmp.path());
    strict_state_on(tmp)
}

fn strict_state_on(tmp: tempfile::TempDir) -> (tempfile::TempDir, DaemonState) {
    let fs = FilesystemBackend::new(FilesystemConfig::new(&[tmp.path().to_path_buf()]).unwrap());
    let mut allow = std::collections::HashSet::new();
    for name in ["echo", "true", "sleep", "git"] {
        allow.insert(name.to_string());
    }
    let proc = Arc::new(ProcessManager::new(
        env(),
        ProcessConfig {
            allowed_executables: Some(allow),
            ..ProcessConfig::default()
        },
        Some(fs.clone()),
    ));
    let sessions = Arc::new(SessionManager::new(
        env(),
        SessionConfig::default(),
        Some(fs.clone()),
    ));
    let table = GrantsTable::parse_json(&format!(
        r#"{{
            "principals": {{
                "{}": {{
                    "filesystem_read": [""],
                    "filesystem_write": ["project"],
                    "filesystem_list": [""],
                    "process_execute": ["echo", "sleep"],
                    "process_inspect": true,
                    "process_terminate": true
                }},
                "{}": {{
                    "filesystem_read": ["logs"],
                    "filesystem_list": ["logs"]
                }}
            }}
        }}"#,
        fp_a(),
        fp_b()
    ))
    .unwrap();
    let mut caps = are_core::CapabilitySet::default();
    for cap in [
        are_core::Capability::FilesystemRead,
        are_core::Capability::FilesystemWrite,
        are_core::Capability::FilesystemList,
        are_core::Capability::ProcessExecute,
        are_core::Capability::ProcessInspect,
        are_core::Capability::ProcessTerminate,
    ] {
        caps.insert(cap);
    }
    let state = DaemonState::with_fs(
        env(),
        "test-host".into(),
        "0.1.0".into(),
        caps,
        are_core::Platform::Debian,
        fs,
    )
    .with_proc(proc)
    .with_sess(sessions)
    .with_grants(table);
    (tmp, state)
}

fn create_session_as(state: &DaemonState, caller: &Caller) -> are_core::SessionInfo {
    let resp = state.handle_as(
        Some(caller),
        RpcRequest::CreateSession(CreateSessionRequest {
            environment_id: env(),
            working_directory: None,
            env_vars: HashMap::new(),
        }),
    );
    match resp.result {
        Ok(RpcResponsePayload::CreateSession(created)) => created.session,
        other => panic!("expected CreateSession response, got {other:?}"),
    }
}

fn read_as(state: &DaemonState, caller: &Caller, path: &str) -> Result<Vec<u8>, String> {
    let resp = state.handle_as(
        Some(caller),
        RpcRequest::ReadFile(are_core::ReadFileRequest {
            environment_id: env(),
            path: path.into(),
        }),
    );
    match resp.result {
        Ok(RpcResponsePayload::ReadFile(r)) => Ok(r.content),
        Err(e) => Err(format!("{e:?}::{e}")),
        other => panic!("unexpected response: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Acceptance: A (read/write project + exec) vs B (read logs only)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn agent_a_fullish_vs_agent_b_logs_only() {
    let (_tmp, state) = strict_state();
    let a = caller_a();
    let b = caller_b();

    // A writes + reads inside project/.
    let resp = state.handle_as(
        Some(&a),
        RpcRequest::WriteFile(are_core::WriteFileRequest {
            environment_id: env(),
            path: "project/new.txt".into(),
            content: b"new".to_vec(),
            overwrite: true,
            expected_hash: None,
        }),
    );
    assert!(
        matches!(resp.result, Ok(RpcResponsePayload::WriteFile(_))),
        "A write project must succeed, got {:?}",
        resp.result
    );
    assert_eq!(read_as(&state, &a, "project/new.txt").unwrap(), b"new");

    // A lists the whole root ("").
    let resp = state.handle_as(
        Some(&a),
        RpcRequest::ListDirectory(are_core::ListDirectoryRequest {
            environment_id: env(),
            path: ".".into(),
        }),
    );
    assert!(
        matches!(resp.result, Ok(RpcResponsePayload::ListDirectory(_))),
        "A list root must succeed, got {:?}",
        resp.result
    );

    // A reads logs too (whole-root read grant).
    assert_eq!(read_as(&state, &a, "logs/app.log").unwrap(), b"log");

    // B reads + lists logs/.
    assert_eq!(read_as(&state, &b, "logs/app.log").unwrap(), b"log");
    let resp = state.handle_as(
        Some(&b),
        RpcRequest::ListDirectory(are_core::ListDirectoryRequest {
            environment_id: env(),
            path: "logs".into(),
        }),
    );
    assert!(
        matches!(resp.result, Ok(RpcResponsePayload::ListDirectory(_))),
        "B list logs must succeed, got {:?}",
        resp.result
    );

    // B is denied outside logs/: read, write, list, metadata, delete.
    let err = read_as(&state, &b, "project/app.txt").unwrap_err();
    assert!(err.contains("Forbidden"), "B read project: {err}");
    assert!(
        err.contains("project/app.txt"),
        "denial echoes rel path: {err}"
    );

    let resp = state.handle_as(
        Some(&b),
        RpcRequest::WriteFile(are_core::WriteFileRequest {
            environment_id: env(),
            path: "logs/evil.txt".into(),
            content: b"x".to_vec(),
            overwrite: true,
            expected_hash: None,
        }),
    );
    assert!(
        matches!(&resp.result, Err(are_core::RpcError::Forbidden(_))),
        "B write (no write grant) must be Forbidden, got {:?}",
        resp.result
    );

    let resp = state.handle_as(
        Some(&b),
        RpcRequest::ListDirectory(are_core::ListDirectoryRequest {
            environment_id: env(),
            path: ".".into(),
        }),
    );
    assert!(
        matches!(&resp.result, Err(are_core::RpcError::Forbidden(_))),
        "B list root (uncovered rel \"\") must be Forbidden, got {:?}",
        resp.result
    );

    let resp = state.handle_as(
        Some(&b),
        RpcRequest::GetFileMetadata(are_core::GetFileMetadataRequest {
            environment_id: env(),
            path: "project/app.txt".into(),
        }),
    );
    assert!(
        matches!(&resp.result, Err(are_core::RpcError::Forbidden(_))),
        "B metadata project must be Forbidden, got {:?}",
        resp.result
    );

    // B metadata inside logs/ is allowed (metadata follows Read).
    let resp = state.handle_as(
        Some(&b),
        RpcRequest::GetFileMetadata(are_core::GetFileMetadataRequest {
            environment_id: env(),
            path: "logs/app.log".into(),
        }),
    );
    assert!(
        matches!(resp.result, Ok(RpcResponsePayload::GetFileMetadata(_))),
        "B metadata logs must succeed, got {:?}",
        resp.result
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn unknown_principal_gets_env_info_only() {
    let (_tmp, state) = strict_state();
    let u = caller_unknown();

    // GetEnvironmentInfo is open and echoes the caller's fingerprint.
    let resp = state.handle_as(
        Some(&u),
        RpcRequest::GetEnvironmentInfo(are_core::GetEnvironmentInfoRequest {
            environment_id: env(),
        }),
    );
    match resp.result {
        Ok(RpcResponsePayload::GetEnvironmentInfo(info)) => {
            assert_eq!(
                info.caller_fingerprint.as_deref(),
                Some(fp_unknown().as_str())
            );
        }
        other => panic!("env info must succeed for unknown, got {other:?}"),
    }

    // Everything else is Forbidden — sessions included.
    let err = read_as(&state, &u, "logs/app.log").unwrap_err();
    assert!(err.contains("Forbidden"), "unknown read: {err}");

    let resp = state.handle_as(
        Some(&u),
        RpcRequest::CreateSession(CreateSessionRequest {
            environment_id: env(),
            working_directory: None,
            env_vars: HashMap::new(),
        }),
    );
    assert!(
        matches!(&resp.result, Err(are_core::RpcError::Forbidden(msg)) if msg.contains("unknown principal")),
        "unknown create session must be Forbidden, got {:?}",
        resp.result
    );

    let resp = state.handle_as(
        Some(&u),
        RpcRequest::ListSessions(ListSessionsRequest {
            environment_id: env(),
        }),
    );
    assert!(
        matches!(&resp.result, Err(are_core::RpcError::Forbidden(_))),
        "unknown list sessions must be Forbidden, got {:?}",
        resp.result
    );

    // Legacy path (no identity) under a strict table is unknown too.
    let resp = state.handle_legacy_test_only(RpcRequest::ReadFile(are_core::ReadFileRequest {
        environment_id: env(),
        path: "logs/app.log".into(),
    }));
    assert!(
        matches!(&resp.result, Err(are_core::RpcError::Forbidden(_))),
        "legacy path under strict must be Forbidden, got {:?}",
        resp.result
    );
    // ...but env info stays open with no fingerprint.
    let resp = state.handle_legacy_test_only(RpcRequest::GetEnvironmentInfo(
        are_core::GetEnvironmentInfoRequest {
            environment_id: env(),
        },
    ));
    match resp.result {
        Ok(RpcResponsePayload::GetEnvironmentInfo(info)) => {
            assert_eq!(info.caller_fingerprint, None);
        }
        other => panic!("legacy env info must succeed, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Adversarial: session hijack + escalation via another principal's session
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn hijack_cross_owner_ops_miss() {
    let (_tmp, state) = strict_state();
    let a = caller_a();
    let b = caller_b();

    let sess_a = create_session_as(&state, &a);
    assert_eq!(sess_a.owner.as_deref(), Some(fp_a().as_str()));

    // B resumes A's session → SessionNotFound (not "owned by A").
    let resp = state.handle_as(
        Some(&b),
        RpcRequest::GetSession(GetSessionRequest {
            environment_id: env(),
            session_id: sess_a.session_id.clone(),
        }),
    );
    assert!(
        matches!(resp.result, Err(are_core::RpcError::SessionNotFound(_))),
        "cross-owner get must miss, got {:?}",
        resp.result
    );

    // B terminates A's session → SessionNotFound, and A's session survives.
    let resp = state.handle_as(
        Some(&b),
        RpcRequest::TerminateSession(TerminateSessionRequest {
            environment_id: env(),
            session_id: sess_a.session_id.clone(),
        }),
    );
    assert!(
        matches!(resp.result, Err(are_core::RpcError::SessionNotFound(_))),
        "cross-owner terminate must miss, got {:?}",
        resp.result
    );

    // B lists: A's session is invisible. A lists: only its own.
    let resp = state.handle_as(
        Some(&b),
        RpcRequest::ListSessions(ListSessionsRequest {
            environment_id: env(),
        }),
    );
    match resp.result {
        Ok(RpcResponsePayload::ListSessions(list)) => assert!(
            list.sessions.is_empty(),
            "B must see no sessions, saw {:?}",
            list.sessions
                .iter()
                .map(|s| &s.session_id)
                .collect::<Vec<_>>()
        ),
        other => panic!("B list must succeed, got {other:?}"),
    }
    let resp = state.handle_as(
        Some(&a),
        RpcRequest::ListSessions(ListSessionsRequest {
            environment_id: env(),
        }),
    );
    match resp.result {
        Ok(RpcResponsePayload::ListSessions(list)) => {
            assert_eq!(list.sessions.len(), 1);
            assert_eq!(list.sessions[0].session_id, sess_a.session_id);
        }
        other => panic!("A list must succeed, got {other:?}"),
    }

    // Escalation: B drives A's session for execute/status → SessionNotFound
    // (ownership is checked BEFORE grants — no grant oracle either).
    let resp = state.handle_as(
        Some(&b),
        RpcRequest::Execute(are_core::ExecuteRequest {
            environment_id: env(),
            session_id: sess_a.session_id.clone(),
            program: "echo".into(),
            args: vec![],
            working_directory: ".".into(),
            env_vars: HashMap::new(),
        }),
    );
    assert!(
        matches!(resp.result, Err(are_core::RpcError::SessionNotFound(_))),
        "cross-owner execute must miss, got {:?}",
        resp.result
    );

    let resp = state.handle_as(
        Some(&b),
        RpcRequest::ProcessStatus(are_core::ProcessStatusRequest {
            environment_id: env(),
            session_id: sess_a.session_id.clone(),
            process_id: are_core::ProcessId::new("proc-999999"),
        }),
    );
    assert!(
        matches!(resp.result, Err(are_core::RpcError::SessionNotFound(_))),
        "cross-owner status must miss, got {:?}",
        resp.result
    );

    // A still owns its session.
    let resp = state.handle_as(
        Some(&a),
        RpcRequest::GetSession(GetSessionRequest {
            environment_id: env(),
            session_id: sess_a.session_id,
        }),
    );
    assert!(
        matches!(resp.result, Ok(RpcResponsePayload::GetSession(_))),
        "owner access must survive the probes, got {:?}",
        resp.result
    );
}

// ---------------------------------------------------------------------------
// Adversarial: expiry oracle collapses for non-owners
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn expiry_oracle_collapsed_for_non_owner() {
    let tmp = tempfile::TempDir::new().unwrap();
    plant_fixtures(tmp.path());
    // Short idle timeout so expiry is observable without long sleeps.
    let fs = FilesystemBackend::new(FilesystemConfig::new(&[tmp.path().to_path_buf()]).unwrap());
    let proc = Arc::new(ProcessManager::new(
        env(),
        ProcessConfig {
            permissive: true,
            ..ProcessConfig::default()
        },
        Some(fs.clone()),
    ));
    let sessions = Arc::new(SessionManager::new(
        env(),
        SessionConfig {
            idle_timeout_secs: 1,
            ..SessionConfig::default()
        },
        Some(fs.clone()),
    ));
    let table = GrantsTable::parse_json(&format!(
        r#"{{"principals": {{"{}": {{"filesystem_read": [""]}}, "{}": {{"filesystem_read": [""]}}}}}}"#,
        fp_a(),
        fp_b()
    ))
    .unwrap();
    let state = DaemonState::with_fs(
        env(),
        "test-host".into(),
        "0.1.0".into(),
        are_core::CapabilitySet::default(),
        are_core::Platform::Debian,
        fs,
    )
    .with_proc(proc)
    .with_sess(Arc::clone(&sessions))
    .with_grants(table);
    let a = caller_a();
    let b = caller_b();

    // Non-owner probing an expired session: generic NotFound, never Expired.
    let sess = create_session_as(&state, &a);
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let resp = state.handle_as(
        Some(&b),
        RpcRequest::GetSession(GetSessionRequest {
            environment_id: env(),
            session_id: sess.session_id.clone(),
        }),
    );
    assert!(
        matches!(resp.result, Err(are_core::RpcError::SessionNotFound(_))),
        "non-owner must never see Expired, got {:?}",
        resp.result
    );

    // Owner of an expired session: precise Expired (recovery signal kept).
    let sess2 = create_session_as(&state, &a);
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let resp = state.handle_as(
        Some(&a),
        RpcRequest::GetSession(GetSessionRequest {
            environment_id: env(),
            session_id: sess2.session_id,
        }),
    );
    assert!(
        matches!(resp.result, Err(are_core::RpcError::SessionExpired(_))),
        "owner must see Expired, got {:?}",
        resp.result
    );
}

#[tokio::test(flavor = "multi_thread")]
#[cfg(unix)]
async fn hidden_expiry_still_kills_live_child() {
    if !std::path::Path::new("/bin/sleep").exists() {
        return;
    }
    let tmp = tempfile::TempDir::new().unwrap();
    plant_fixtures(tmp.path());
    let fs = FilesystemBackend::new(FilesystemConfig::new(&[tmp.path().to_path_buf()]).unwrap());
    let proc = Arc::new(ProcessManager::new(
        env(),
        ProcessConfig {
            permissive: true,
            ..ProcessConfig::default()
        },
        Some(fs.clone()),
    ));
    let sessions = Arc::new(SessionManager::new(
        env(),
        SessionConfig {
            idle_timeout_secs: 1,
            ..SessionConfig::default()
        },
        Some(fs),
    ));
    let table = GrantsTable::parse_json(&format!(
        r#"{{"principals": {{"{}": {{"filesystem_read": [""]}}, "{}": {{"filesystem_read": [""]}}}}}}"#,
        fp_a(),
        fp_b()
    ))
    .unwrap();
    let mut caps = are_core::CapabilitySet::default();
    caps.insert(are_core::Capability::ProcessExecute);
    let state = DaemonState::with_fs(
        env(),
        "test-host".into(),
        "0.1.0".into(),
        caps,
        are_core::Platform::Debian,
        FilesystemBackend::new(FilesystemConfig::new(&[tmp.path().to_path_buf()]).unwrap()),
    )
    .with_proc(Arc::clone(&proc))
    .with_sess(Arc::clone(&sessions))
    .with_grants(table);
    let a = caller_a();
    let b = caller_b();

    let sess = create_session_as(&state, &a);
    let resp = state.handle_as(
        Some(&a),
        RpcRequest::Execute(are_core::ExecuteRequest {
            environment_id: env(),
            session_id: sess.session_id.clone(),
            program: "/bin/sleep".into(),
            args: vec!["30".into()],
            working_directory: ".".into(),
            env_vars: HashMap::new(),
        }),
    );
    let pid = match resp.result {
        Ok(RpcResponsePayload::Execute(exec)) => exec.process_id,
        other => panic!("exec must succeed, got {other:?}"),
    };
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    // Non-owner touch: collapsed to NotFound (kill still attempted).
    let resp = state.handle_as(
        Some(&b),
        RpcRequest::GetSession(GetSessionRequest {
            environment_id: env(),
            session_id: sess.session_id.clone(),
        }),
    );
    assert!(
        matches!(resp.result, Err(are_core::RpcError::SessionNotFound(_))),
        "non-owner must see NotFound, got {:?}",
        resp.result
    );
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    let direct = proc
        .status(&are_core::ProcessStatusRequest {
            environment_id: env(),
            session_id: sess.session_id,
            process_id: pid,
        })
        .expect("manager-level status");
    assert_ne!(
        direct.state,
        are_core::ProcessState::Running,
        "hidden-expiry path must still kill the live child"
    );
}

// ---------------------------------------------------------------------------
// Adversarial: path escape still surfaces as escape under authz
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn dotdot_still_escape_under_authz() {
    let (_tmp, state) = strict_state();
    let b = caller_b();
    // B is a KNOWN principal: the `..` hits the resolve-time boundary
    // check first and must stay an escape error — never remapped to
    // Forbidden (which would blur the boundary/grant distinction).
    let resp = state.handle_as(
        Some(&b),
        RpcRequest::WriteFile(are_core::WriteFileRequest {
            environment_id: env(),
            path: "../escape.txt".into(),
            content: b"nope".to_vec(),
            overwrite: true,
            expected_hash: None,
        }),
    );
    match &resp.result {
        Err(are_core::RpcError::InternalError(msg)) => {
            assert!(msg.contains("filesystem escape blocked"), "got: {msg}");
        }
        Err(are_core::RpcError::InvalidRequest(_)) => {}
        other => panic!("traversal under authz must be escape-shaped, got {other:?}"),
    }
    let err = read_as(&state, &b, "../escape.txt").unwrap_err();
    assert!(
        !err.contains("Forbidden"),
        "escape must not be remapped to Forbidden: {err}"
    );
}

// ---------------------------------------------------------------------------
// Scope edges: logs vs logs2, "", empty programs
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn scope_edges_logs_vs_logs2_whole_root_empty_programs() {
    let (_tmp, state) = strict_state();
    let a = caller_a();
    let b = caller_b();

    // `logs` grant does NOT cover sibling-prefix `logs2/`.
    let err = read_as(&state, &b, "logs2/other.txt").unwrap_err();
    assert!(err.contains("Forbidden"), "logs2 must be denied: {err}");
    // A (whole-root read) reaches it.
    assert_eq!(read_as(&state, &a, "logs2/other.txt").unwrap(), b"other");

    // Empty `process_execute` set allows nothing: B has no execute grant.
    let sess_b = create_session_as(&state, &b);
    let resp = state.handle_as(
        Some(&b),
        RpcRequest::Execute(are_core::ExecuteRequest {
            environment_id: env(),
            session_id: sess_b.session_id,
            program: "echo".into(),
            args: vec![],
            working_directory: ".".into(),
            env_vars: HashMap::new(),
        }),
    );
    assert!(
        matches!(&resp.result, Err(are_core::RpcError::Forbidden(_))),
        "exec without grant must be Forbidden, got {:?}",
        resp.result
    );

    // B has no inspect/terminate grants either.
    let sess_a = create_session_as(&state, &a);
    for req in [
        RpcRequest::ProcessStatus(are_core::ProcessStatusRequest {
            environment_id: env(),
            session_id: sess_a.session_id.clone(),
            process_id: are_core::ProcessId::new("proc-1"),
        }),
        RpcRequest::TerminateProcess(are_core::TerminateProcessRequest {
            environment_id: env(),
            session_id: sess_a.session_id.clone(),
            process_id: are_core::ProcessId::new("proc-1"),
            force: false,
        }),
    ] {
        let resp = state.handle_as(Some(&b), req);
        // Ownership fires first (B doesn't own A's session) — still
        // SessionNotFound, proving no grant oracle precedes ownership.
        assert!(
            matches!(resp.result, Err(are_core::RpcError::SessionNotFound(_))),
            "cross-owner proc op must miss, got {:?}",
            resp.result
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn exec_authorization_policy_then_grants() {
    let (_tmp, state) = strict_state();
    let a = caller_a();
    let sess_a = create_session_as(&state, &a);

    // Daemon policy fires first: denied-for-everyone stays DeniedExecutable.
    let resp = state.handle_as(
        Some(&a),
        RpcRequest::Execute(are_core::ExecuteRequest {
            environment_id: env(),
            session_id: sess_a.session_id.clone(),
            program: "shutdown".into(),
            args: vec![],
            working_directory: ".".into(),
            env_vars: HashMap::new(),
        }),
    );
    assert!(
        matches!(&resp.result, Err(are_core::RpcError::DeniedExecutable(_))),
        "policy-denied program must stay DeniedExecutable, got {:?}",
        resp.result
    );

    // Policy-passing but ungranted program → Forbidden ("you may not").
    // (`git` is in the daemon allow-list but not in A's grants.)
    let resp = state.handle_as(
        Some(&a),
        RpcRequest::Execute(are_core::ExecuteRequest {
            environment_id: env(),
            session_id: sess_a.session_id.clone(),
            program: "git".into(),
            args: vec![],
            working_directory: ".".into(),
            env_vars: HashMap::new(),
        }),
    );
    assert!(
        matches!(&resp.result, Err(are_core::RpcError::Forbidden(msg)) if msg.contains("process.execute")),
        "ungranted program must be Forbidden, got {:?}",
        resp.result
    );

    // Malformed requests stay InvalidRequest (validation precedes grants).
    let resp = state.handle_as(
        Some(&a),
        RpcRequest::Execute(are_core::ExecuteRequest {
            environment_id: env(),
            session_id: sess_a.session_id,
            program: String::new(),
            args: vec![],
            working_directory: ".".into(),
            env_vars: HashMap::new(),
        }),
    );
    assert!(
        matches!(&resp.result, Err(are_core::RpcError::InvalidRequest(_))),
        "empty program must be InvalidRequest, got {:?}",
        resp.result
    );
}

#[tokio::test(flavor = "multi_thread")]
#[cfg(unix)]
async fn exec_allowed_path_spawns() {
    if !std::path::Path::new("/bin/echo").exists() {
        return;
    }
    let (_tmp, state) = strict_state();
    let a = caller_a();
    let sess_a = create_session_as(&state, &a);
    let resp = state.handle_as(
        Some(&a),
        RpcRequest::Execute(are_core::ExecuteRequest {
            environment_id: env(),
            session_id: sess_a.session_id.clone(),
            program: "/bin/echo".into(),
            args: vec!["hi".into()],
            working_directory: ".".into(),
            env_vars: HashMap::new(),
        }),
    );
    let pid = match resp.result {
        Ok(RpcResponsePayload::Execute(exec)) => exec.process_id,
        other => panic!("granted exec must spawn, got {other:?}"),
    };
    // Granted inspect + terminate follow the same principal.
    let resp = state.handle_as(
        Some(&a),
        RpcRequest::WaitProcess(are_core::WaitProcessRequest {
            environment_id: env(),
            session_id: sess_a.session_id,
            process_id: pid,
            timeout_secs: 10,
        }),
    );
    match resp.result {
        Ok(RpcResponsePayload::WaitProcess(wait)) => {
            assert_eq!(wait.exit_code, Some(0));
            assert_eq!(wait.stdout, b"hi\n");
        }
        other => panic!("granted wait must succeed, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Rename needs Write on BOTH ends; delete folds into Write
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn rename_needs_write_on_both_ends() {
    let tmp = tempfile::TempDir::new().unwrap();
    std::fs::create_dir_all(tmp.path().join("d1")).unwrap();
    std::fs::create_dir_all(tmp.path().join("d2")).unwrap();
    std::fs::write(tmp.path().join("d1/a.txt"), "a").unwrap();
    let fs = FilesystemBackend::new(FilesystemConfig::new(&[tmp.path().to_path_buf()]).unwrap());
    let sessions = Arc::new(SessionManager::new(
        env(),
        SessionConfig::default(),
        Some(fs.clone()),
    ));
    // R reads both dirs but writes only d1/.
    let table = GrantsTable::parse_json(&format!(
        r#"{{"principals": {{"{}": {{"filesystem_read": ["d1", "d2"], "filesystem_write": ["d1"], "filesystem_list": ["d1", "d2"]}}}}}}"#,
        fp_a()
    ))
    .unwrap();
    let state = DaemonState::with_fs(
        env(),
        "test-host".into(),
        "0.1.0".into(),
        are_core::CapabilitySet::default(),
        are_core::Platform::Debian,
        fs,
    )
    .with_sess(sessions)
    .with_grants(table);
    let r = caller_a();

    // dst outside the write scope → Forbidden, src untouched.
    let resp = state.handle_as(
        Some(&r),
        RpcRequest::Rename(are_core::RenameRequest {
            environment_id: env(),
            src: "d1/a.txt".into(),
            dst: "d2/b.txt".into(),
        }),
    );
    assert!(
        matches!(&resp.result, Err(are_core::RpcError::Forbidden(_))),
        "cross-scope rename must be Forbidden, got {:?}",
        resp.result
    );
    assert!(tmp.path().join("d1/a.txt").exists());

    // Both ends inside the write scope → allowed.
    let resp = state.handle_as(
        Some(&r),
        RpcRequest::Rename(are_core::RenameRequest {
            environment_id: env(),
            src: "d1/a.txt".into(),
            dst: "d1/b.txt".into(),
        }),
    );
    assert!(
        matches!(resp.result, Ok(RpcResponsePayload::Rename(_))),
        "same-scope rename must succeed, got {:?}",
        resp.result
    );
    assert!(tmp.path().join("d1/b.txt").exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn delete_folds_into_write() {
    let (_tmp, state) = strict_state();
    let a = caller_a();
    let b = caller_b();

    // B (read-only) cannot delete even inside its readable scope.
    let resp = state.handle_as(
        Some(&b),
        RpcRequest::DeleteFile(are_core::DeleteRequest {
            environment_id: env(),
            path: "logs/app.log".into(),
        }),
    );
    assert!(
        matches!(&resp.result, Err(are_core::RpcError::Forbidden(_))),
        "delete without Write must be Forbidden, got {:?}",
        resp.result
    );

    // A cannot delete outside its write scope either (read "" ≠ write).
    let resp = state.handle_as(
        Some(&a),
        RpcRequest::DeleteFile(are_core::DeleteRequest {
            environment_id: env(),
            path: "logs/app.log".into(),
        }),
    );
    assert!(
        matches!(&resp.result, Err(are_core::RpcError::Forbidden(_))),
        "delete outside write scope must be Forbidden, got {:?}",
        resp.result
    );

    // A deletes inside project/ (planted first via granted write).
    let resp = state.handle_as(
        Some(&a),
        RpcRequest::WriteFile(are_core::WriteFileRequest {
            environment_id: env(),
            path: "project/gone.txt".into(),
            content: b"x".to_vec(),
            overwrite: true,
            expected_hash: None,
        }),
    );
    assert!(matches!(resp.result, Ok(RpcResponsePayload::WriteFile(_))));
    let resp = state.handle_as(
        Some(&a),
        RpcRequest::DeleteFile(are_core::DeleteRequest {
            environment_id: env(),
            path: "project/gone.txt".into(),
        }),
    );
    assert!(
        matches!(resp.result, Ok(RpcResponsePayload::DeleteFile(_))),
        "delete inside write scope must succeed, got {:?}",
        resp.result
    );
}

// ---------------------------------------------------------------------------
// Permissive back-compat: no grants file → legacy behavior per principal,
// ownership still bound
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn permissive_mode_back_compat_with_ownership() {
    let tmp = tempfile::TempDir::new().unwrap();
    plant_fixtures(tmp.path());
    let fs = FilesystemBackend::new(FilesystemConfig::new(&[tmp.path().to_path_buf()]).unwrap());
    let proc = Arc::new(ProcessManager::new(
        env(),
        ProcessConfig {
            permissive: true,
            ..ProcessConfig::default()
        },
        Some(fs.clone()),
    ));
    let sessions = Arc::new(SessionManager::new(
        env(),
        SessionConfig::default(),
        Some(fs.clone()),
    ));
    let mut caps = are_core::CapabilitySet::default();
    caps.insert(are_core::Capability::FilesystemRead);
    caps.insert(are_core::Capability::FilesystemWrite);
    let state = DaemonState::with_fs(
        env(),
        "test-host".into(),
        "0.1.0".into(),
        caps,
        are_core::Platform::Debian,
        fs,
    )
    .with_proc(proc)
    .with_sess(sessions);
    assert!(state.grants.is_none(), "no grants = permissive");
    let a = caller_a();
    let b = caller_b();

    // Single-client flows work exactly as before Gate 8.
    let sess = create_session_as(&state, &a);
    assert_eq!(sess.owner.as_deref(), Some(fp_a().as_str()));
    let resp = state.handle_as(
        Some(&a),
        RpcRequest::GetSession(GetSessionRequest {
            environment_id: env(),
            session_id: sess.session_id.clone(),
        }),
    );
    assert!(matches!(resp.result, Ok(RpcResponsePayload::GetSession(_))));
    let resp = state.handle_as(
        Some(&a),
        RpcRequest::WriteFile(are_core::WriteFileRequest {
            environment_id: env(),
            path: "project/p.txt".into(),
            content: b"p".to_vec(),
            overwrite: true,
            expected_hash: None,
        }),
    );
    assert!(matches!(resp.result, Ok(RpcResponsePayload::WriteFile(_))));
    assert_eq!(read_as(&state, &a, "project/p.txt").unwrap(), b"p");

    // Ownership is ALWAYS on, even permissive: B cannot touch A's session.
    let resp = state.handle_as(
        Some(&b),
        RpcRequest::GetSession(GetSessionRequest {
            environment_id: env(),
            session_id: sess.session_id,
        }),
    );
    assert!(
        matches!(resp.result, Err(are_core::RpcError::SessionNotFound(_))),
        "cross-owner access is denied even in permissive mode, got {:?}",
        resp.result
    );
}

// ---------------------------------------------------------------------------
// Wire: two real mTLS client certificates → two distinct principals
// ---------------------------------------------------------------------------

/// Generate a CA certificate for testing.
fn make_ca(cn: &str) -> (rcgen::Certificate, rcgen::KeyPair) {
    let mut params = rcgen::CertificateParams::new(vec![cn.to_string()]).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    (cert, key_pair)
}

/// Generate a certificate signed by the given CA.
fn make_signed_cert(
    ca_cert: &rcgen::Certificate,
    ca_key: &rcgen::KeyPair,
    cn: &str,
) -> (
    rustls::pki_types::CertificateDer<'static>,
    rustls::pki_types::PrivateKeyDer<'static>,
) {
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let params = rcgen::CertificateParams::new(vec![cn.to_string()]).unwrap();
    let cert = params.signed_by(&key_pair, ca_cert, ca_key).unwrap();
    (
        cert.der().clone(),
        rustls::pki_types::PrivateKeyDer::try_from(key_pair.serialize_der()).unwrap(),
    )
}

/// Minimal wire client returning raw `RpcResponse`s (variant assertions).
struct WireClient {
    addr: std::net::SocketAddr,
    tls_config: Arc<rustls::ClientConfig>,
    server_name: rustls::pki_types::ServerName<'static>,
}

impl WireClient {
    fn new(
        addr: std::net::SocketAddr,
        client_certs: Vec<rustls::pki_types::CertificateDer<'static>>,
        client_key: rustls::pki_types::PrivateKeyDer<'static>,
        ca_cert: &rustls::pki_types::CertificateDer<'static>,
    ) -> Self {
        let tls_config =
            are_daemon::tls::build_client_config(client_certs, client_key, ca_cert, "localhost")
                .unwrap();
        let server_name = rustls::pki_types::ServerName::try_from("localhost".to_string()).unwrap();
        Self {
            addr,
            tls_config,
            server_name,
        }
    }

    async fn send(&self, request: are_core::RpcRequest) -> are_core::RpcResponse {
        use tokio::io;
        let tcp = tokio::net::TcpStream::connect(&self.addr).await.unwrap();
        let connector = tokio_rustls::TlsConnector::from(Arc::clone(&self.tls_config));
        let tls_stream = connector
            .connect(self.server_name.clone(), tcp)
            .await
            .unwrap();
        let (read_half, write_half) = io::split(tls_stream);
        let mut reader = io::BufReader::new(read_half);
        let mut writer = io::BufWriter::new(write_half);
        are_daemon::framing::write_message(&mut writer, &request)
            .await
            .unwrap();
        are_daemon::framing::read_message(&mut reader)
            .await
            .unwrap()
    }
}

/// Start a daemon whose accept loop derives the caller from the verified
/// leaf certificate — the same plumbing as production `server.rs`.
async fn start_daemon_with_callers(
    state: Arc<DaemonState>,
    server_cert: rustls::pki_types::CertificateDer<'static>,
    server_key: rustls::pki_types::PrivateKeyDer<'static>,
    ca_cert: &rustls::pki_types::CertificateDer<'static>,
) -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let ca_clone = ca_cert.clone();
    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((tcp, _peer)) => {
                            let acceptor_inner = tokio_rustls::TlsAcceptor::from(
                                are_daemon::tls::build_server_config(
                                    vec![server_cert.clone()],
                                    server_key.clone_key(),
                                    &ca_clone,
                                )
                                .unwrap(),
                            );
                            let state = Arc::clone(&state);
                            tokio::spawn(async move {
                                if let Ok(tls_stream) = acceptor_inner.accept(tcp).await {
                                    let caller = are_daemon::auth::caller_from_peer_certs(
                                        tls_stream.get_ref().1.peer_certificates(),
                                    );
                                    let Some(caller) = caller else { return };
                                    let (read_half, write_half) = tokio::io::split(tls_stream);
                                    let mut reader = tokio::io::BufReader::new(read_half);
                                    let mut writer = tokio::io::BufWriter::new(write_half);
                                    let request: are_core::RpcRequest =
                                        are_daemon::framing::read_message(&mut reader).await.unwrap();
                                    let response: are_core::RpcResponse =
                                        state.handle_as(Some(&caller), request);
                                    let _ = are_daemon::framing::write_message(&mut writer, &response).await;
                                }
                            });
                        }
                        Err(_) => break,
                    }
                }
                _ = tokio::time::sleep(std::time::Duration::from_secs(20)) => break,
            }
        }
    });
    (addr, handle)
}

#[tokio::test(flavor = "multi_thread")]
async fn wire_two_principals_end_to_end() {
    let tmp = tempfile::TempDir::new().unwrap();
    plant_fixtures(tmp.path());
    let fs = FilesystemBackend::new(FilesystemConfig::new(&[tmp.path().to_path_buf()]).unwrap());
    let sessions = Arc::new(SessionManager::new(
        env(),
        SessionConfig::default(),
        Some(fs.clone()),
    ));

    // PKI: one CA, server cert, and THREE client certs (A, B, stranger).
    let (ca_cert, ca_key) = make_ca("Test Root CA");
    let (server_cert, server_key) = make_signed_cert(&ca_cert, &ca_key, "localhost");
    let (client_a_cert, client_a_key) = make_signed_cert(&ca_cert, &ca_key, "agent-a");
    let (client_b_cert, client_b_key) = make_signed_cert(&ca_cert, &ca_key, "agent-b");
    let (client_c_cert, client_c_key) = make_signed_cert(&ca_cert, &ca_key, "stranger");
    let ca_der = ca_cert.der().clone();

    // Fingerprints the daemon will see (blake3 over leaf DER) — the same
    // strings `are fingerprint --cert` prints.
    let fp_wire_a = Caller::from_leaf_der(client_a_cert.as_ref()).fingerprint;
    let fp_wire_b = Caller::from_leaf_der(client_b_cert.as_ref()).fingerprint;
    let fp_wire_c = Caller::from_leaf_der(client_c_cert.as_ref()).fingerprint;
    assert_ne!(fp_wire_a, fp_wire_b);
    assert_ne!(fp_wire_a, fp_wire_c);

    let table = GrantsTable::parse_json(&format!(
        r#"{{
            "principals": {{
                "{fp_wire_a}": {{
                    "filesystem_read": [""],
                    "filesystem_write": ["project"],
                    "filesystem_list": [""]
                }},
                "{fp_wire_b}": {{
                    "filesystem_read": ["logs"],
                    "filesystem_list": ["logs"]
                }}
            }}
        }}"#
    ))
    .unwrap();
    let mut caps = are_core::CapabilitySet::default();
    caps.insert(are_core::Capability::FilesystemRead);
    caps.insert(are_core::Capability::FilesystemWrite);
    caps.insert(are_core::Capability::FilesystemList);
    let state = Arc::new(
        DaemonState::with_fs(
            env(),
            "test-host".into(),
            "0.1.0".into(),
            caps,
            are_core::Platform::Debian,
            fs,
        )
        .with_sess(sessions)
        .with_grants(table),
    );

    let (addr, _handle) = start_daemon_with_callers(state, server_cert, server_key, &ca_der).await;
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    let wire_a = WireClient::new(addr, vec![client_a_cert], client_a_key, &ca_der);
    let wire_b = WireClient::new(addr, vec![client_b_cert], client_b_key, &ca_der);
    let wire_c = WireClient::new(addr, vec![client_c_cert], client_c_key, &ca_der);

    // Identity: env info echoes each connection's own fingerprint.
    for (wire, expected) in [
        (&wire_a, &fp_wire_a),
        (&wire_b, &fp_wire_b),
        (&wire_c, &fp_wire_c),
    ] {
        let resp = wire
            .send(are_core::RpcRequest::GetEnvironmentInfo(
                are_core::GetEnvironmentInfoRequest {
                    environment_id: env(),
                },
            ))
            .await;
        match resp.result {
            Ok(RpcResponsePayload::GetEnvironmentInfo(info)) => {
                assert_eq!(info.caller_fingerprint.as_deref(), Some(expected.as_str()));
            }
            other => panic!("env info must succeed, got {other:?}"),
        }
    }

    // A writes project/, B's read of it is Forbidden on the wire.
    let resp = wire_a
        .send(are_core::RpcRequest::WriteFile(
            are_core::WriteFileRequest {
                environment_id: env(),
                path: "project/wire.txt".into(),
                content: b"wire".to_vec(),
                overwrite: true,
                expected_hash: None,
            },
        ))
        .await;
    assert!(
        matches!(resp.result, Ok(RpcResponsePayload::WriteFile(_))),
        "A write must succeed, got {:?}",
        resp.result
    );
    let resp = wire_b
        .send(are_core::RpcRequest::ReadFile(are_core::ReadFileRequest {
            environment_id: env(),
            path: "project/wire.txt".into(),
        }))
        .await;
    assert!(
        matches!(&resp.result, Err(are_core::RpcError::Forbidden(_))),
        "B read of project must be Forbidden, got {:?}",
        resp.result
    );
    // B reads logs fine.
    let resp = wire_b
        .send(are_core::RpcRequest::ReadFile(are_core::ReadFileRequest {
            environment_id: env(),
            path: "logs/app.log".into(),
        }))
        .await;
    assert!(
        matches!(resp.result, Ok(RpcResponsePayload::ReadFile(_))),
        "B read of logs must succeed, got {:?}",
        resp.result
    );

    // A creates a session; B's resume misses with SessionNotFound.
    let resp = wire_a
        .send(are_core::RpcRequest::CreateSession(CreateSessionRequest {
            environment_id: env(),
            working_directory: None,
            env_vars: HashMap::new(),
        }))
        .await;
    let session_id = match resp.result {
        Ok(RpcResponsePayload::CreateSession(created)) => {
            assert_eq!(created.session.owner.as_deref(), Some(fp_wire_a.as_str()));
            created.session.session_id
        }
        other => panic!("A create session must succeed, got {other:?}"),
    };
    let resp = wire_b
        .send(are_core::RpcRequest::GetSession(GetSessionRequest {
            environment_id: env(),
            session_id: session_id.clone(),
        }))
        .await;
    assert!(
        matches!(&resp.result, Err(are_core::RpcError::SessionNotFound(_))),
        "B resume of A's session must be SessionNotFound, got {:?}",
        resp.result
    );

    // Stranger reads nothing (strict unknown) but keeps env info.
    let resp = wire_c
        .send(are_core::RpcRequest::ReadFile(are_core::ReadFileRequest {
            environment_id: env(),
            path: "logs/app.log".into(),
        }))
        .await;
    assert!(
        matches!(&resp.result, Err(are_core::RpcError::Forbidden(msg)) if msg.contains("unknown principal")),
        "stranger read must be Forbidden, got {:?}",
        resp.result
    );
}
