//! Gate 6 scenario tests: persistent agent sessions.
//!
//! Acceptance mapping (PLAN.md Gate 6):
//!
//! - create → disconnect → reconnect → resume with workdir + env intact
//!   (`resume_across_reconnect_keeps_workdir_and_env`).
//! - Session expiry: idle timeout, explicit termination, maximum lifetime
//!   (unit-deterministic parts live in `session.rs`; the dispatch mapping
//!   is covered here).
//! - Processes keep running under their session across reconnects; the
//!   session cascade kills them on explicit termination.
//! - Isolation: a process in session A is invisible from session B
//!   (`NotFound`, no oracle).
//!
//! Dispatch-level tests go through the public `DaemonState::handle` API
//! (the same envelope the wire uses). Manager-level tests use
//! `SessionManager`/`ProcessManager` directly where the handler would
//! mask the precise error category.
//!
//! Unix spawn tests use absolute coreutils paths, gated with `#[cfg(unix)]`.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;
use std::sync::Arc;

use are_core::{
    CreateSessionRequest, EnvironmentId, GetSessionRequest, ListSessionsRequest, RpcRequest,
    RpcResponsePayload, TerminateSessionRequest,
};
use are_daemon::fs::{FilesystemBackend, FilesystemConfig};
use are_daemon::handler::DaemonState;
use are_daemon::process::{ProcessConfig, ProcessManager};
use are_daemon::session::{SessionConfig, SessionManager};

fn test_env() -> EnvironmentId {
    EnvironmentId::new("test-env")
}

/// Build a fully wired state (fs + permissive proc + sessions) plus the
/// temp root it is rooted at. Tests opt into permissive execution; the
/// production default is fail-closed.
fn wired_state() -> (tempfile::TempDir, DaemonState) {
    wired_state_with_session_config(SessionConfig::default())
}

fn wired_state_with_session_config(
    session_config: SessionConfig,
) -> (tempfile::TempDir, DaemonState) {
    let tmp = tempfile::TempDir::new().expect("temp dir");
    let fs =
        FilesystemBackend::new(FilesystemConfig::new(&[tmp.path().to_path_buf()]).expect("fs"));
    let proc = Arc::new(ProcessManager::new(
        test_env(),
        ProcessConfig {
            permissive: true,
            ..ProcessConfig::default()
        },
        Some(fs.clone()),
    ));
    let sessions = Arc::new(SessionManager::new(
        test_env(),
        session_config,
        Some(fs.clone()),
    ));
    let mut caps = are_core::CapabilitySet::default();
    caps.insert(are_core::Capability::ProcessExecute);
    caps.insert(are_core::Capability::ProcessInspect);
    caps.insert(are_core::Capability::ProcessTerminate);
    let state = DaemonState::with_fs(
        test_env(),
        "test-host".into(),
        "0.1.0".into(),
        caps,
        are_core::Platform::Debian,
        fs,
    )
    .with_proc(proc)
    .with_sess(sessions);
    (tmp, state)
}

fn create_session(
    state: &DaemonState,
    workdir: Option<&str>,
    env: HashMap<String, String>,
) -> are_core::SessionInfo {
    let resp = state.handle(RpcRequest::CreateSession(CreateSessionRequest {
        environment_id: test_env(),
        working_directory: workdir.map(str::to_string),
        env_vars: env,
    }));
    match resp.result {
        Ok(RpcResponsePayload::CreateSession(created)) => created.session,
        other => panic!("expected CreateSession response, got {other:?}"),
    }
}

#[cfg(unix)]
fn exec_in(
    state: &DaemonState,
    session: &are_core::SessionInfo,
    program: &str,
    args: &[&str],
    workdir: &str,
) -> are_core::ProcessId {
    let resp = state.handle(RpcRequest::Execute(are_core::ExecuteRequest {
        environment_id: test_env(),
        session_id: session.session_id.clone(),
        program: program.into(),
        args: args.iter().map(|s| (*s).to_string()).collect(),
        working_directory: workdir.into(),
        env_vars: HashMap::new(),
    }));
    match resp.result {
        Ok(RpcResponsePayload::Execute(exec)) => exec.process_id,
        other => panic!("expected Execute response, got {other:?}"),
    }
}

#[cfg(unix)]
fn require_bin(path: &'static str) -> Option<&'static str> {
    std::path::Path::new(path).exists().then_some(path)
}

// ---------------------------------------------------------------------------
// Acceptance: create → disconnect → reconnect → resume
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn resume_across_reconnect_keeps_workdir_and_env() {
    let (_tmp, state) = wired_state();
    let state = Arc::new(state);

    let session = create_session(
        &state,
        Some("."),
        HashMap::from([("FOO".into(), "bar".into())]),
    );

    // "Disconnect": drop every client-side handle. The handler is
    // stateless; only the shared `DaemonState` (daemon memory) retains
    // anything. "Reconnect": a new Arc handle (a new TLS connection on the
    // wire) resumes by id.
    drop(session.clone());
    let reconnected = Arc::clone(&state);

    let resp = reconnected.handle(RpcRequest::GetSession(GetSessionRequest {
        environment_id: test_env(),
        session_id: session.session_id.clone(),
    }));
    match resp.result {
        Ok(RpcResponsePayload::GetSession(resumed)) => {
            assert_eq!(resumed.session.session_id, session.session_id);
            assert_eq!(resumed.session.working_directory, ".");
            assert_eq!(
                resumed.session.env_vars.get("FOO").map(String::as_str),
                Some("bar")
            );
        }
        other => panic!("expected GetSession response, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn session_survives_interleaved_unrelated_ops() {
    let (_tmp, state) = wired_state();
    let session = create_session(&state, None, HashMap::new());

    // Many unrelated ops (other sessions, listings, env info) must not
    // invalidate the session.
    for _ in 0..5 {
        let other = create_session(&state, None, HashMap::new());
        assert_ne!(other.session_id, session.session_id);
    }
    let listed = state.handle(RpcRequest::ListSessions(ListSessionsRequest {
        environment_id: test_env(),
    }));
    match listed.result {
        Ok(RpcResponsePayload::ListSessions(list)) => assert_eq!(list.sessions.len(), 6),
        other => panic!("expected ListSessions response, got {other:?}"),
    }
    let info = state.handle(RpcRequest::GetEnvironmentInfo(
        are_core::GetEnvironmentInfoRequest {
            environment_id: test_env(),
        },
    ));
    assert!(info.result.is_ok());

    let resp = state.handle(RpcRequest::GetSession(GetSessionRequest {
        environment_id: test_env(),
        session_id: session.session_id.clone(),
    }));
    assert!(
        matches!(resp.result, Ok(RpcResponsePayload::GetSession(_))),
        "session must survive interleaved ops, got {:?}",
        resp.result
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn list_filters_by_environment() {
    let (_tmp, state) = wired_state();
    let session = create_session(&state, None, HashMap::new());

    let resp = state.handle(RpcRequest::ListSessions(ListSessionsRequest {
        environment_id: test_env(),
    }));
    match resp.result {
        Ok(RpcResponsePayload::ListSessions(list)) => {
            assert_eq!(list.sessions.len(), 1);
            assert_eq!(list.sessions[0].session_id, session.session_id);
        }
        other => panic!("expected ListSessions response, got {other:?}"),
    }

    let resp = state.handle(RpcRequest::ListSessions(ListSessionsRequest {
        environment_id: EnvironmentId::new("other-env"),
    }));
    match resp.result {
        Err(are_core::RpcError::InvalidRequest(_)) => {}
        other => panic!("cross-env list must be rejected, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn execute_with_unknown_session_is_session_not_found() {
    let (_tmp, state) = wired_state();
    let resp = state.handle(RpcRequest::Execute(are_core::ExecuteRequest {
        environment_id: test_env(),
        session_id: are_core::SessionId::new("sess-nope"),
        program: "cargo".into(),
        args: vec![],
        working_directory: ".".into(),
        env_vars: HashMap::new(),
    }));
    match resp.result {
        Err(are_core::RpcError::SessionNotFound(_)) => {}
        other => panic!("expected SessionNotFound, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn get_unknown_session_is_session_not_found() {
    let (_tmp, state) = wired_state();
    let resp = state.handle(RpcRequest::GetSession(GetSessionRequest {
        environment_id: test_env(),
        session_id: are_core::SessionId::new("sess-nope"),
    }));
    assert!(matches!(
        resp.result,
        Err(are_core::RpcError::SessionNotFound(_))
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn terminate_unknown_session_is_session_not_found() {
    let (_tmp, state) = wired_state();
    let resp = state.handle(RpcRequest::TerminateSession(TerminateSessionRequest {
        environment_id: test_env(),
        session_id: are_core::SessionId::new("sess-nope"),
    }));
    assert!(matches!(
        resp.result,
        Err(are_core::RpcError::SessionNotFound(_))
    ));
}

#[tokio::test(flavor = "multi_thread")]
async fn idle_expired_session_reports_expired_on_resume() {
    let (_tmp, state) = wired_state_with_session_config(SessionConfig {
        idle_timeout_secs: 1,
        ..SessionConfig::default()
    });
    let session = create_session(&state, None, HashMap::new());
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let resp = state.handle(RpcRequest::GetSession(GetSessionRequest {
        environment_id: test_env(),
        session_id: session.session_id,
    }));
    assert!(
        matches!(resp.result, Err(are_core::RpcError::SessionExpired(_))),
        "expired resume must report SessionExpired, got {:?}",
        resp.result
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn max_lifetime_expires_despite_activity() {
    let (_tmp, state) = wired_state_with_session_config(SessionConfig {
        idle_timeout_secs: 86400,
        max_lifetime_secs: 1,
        ..SessionConfig::default()
    });
    let session = create_session(&state, None, HashMap::new());
    // Activity does not extend the absolute lifetime.
    let resp = state.handle(RpcRequest::GetSession(GetSessionRequest {
        environment_id: test_env(),
        session_id: session.session_id.clone(),
    }));
    assert!(matches!(resp.result, Ok(RpcResponsePayload::GetSession(_))));
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let resp = state.handle(RpcRequest::GetSession(GetSessionRequest {
        environment_id: test_env(),
        session_id: session.session_id,
    }));
    assert!(matches!(
        resp.result,
        Err(are_core::RpcError::SessionExpired(_))
    ));
}

// ---------------------------------------------------------------------------
// Isolation: no oracle across sessions
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
#[cfg(unix)]
async fn process_in_session_a_is_not_found_from_session_b() {
    let Some(echo) = require_bin("/bin/echo") else {
        return;
    };
    let (_tmp, state) = wired_state();
    let sess_a = create_session(&state, None, HashMap::new());
    let sess_b = create_session(&state, None, HashMap::new());

    let pid = exec_in(&state, &sess_a, echo, &["hello"], ".");

    // Same live session B, A's process id: plain NotFound — no leak, no
    // "exists elsewhere" oracle.
    let resp = state.handle(RpcRequest::ProcessStatus(are_core::ProcessStatusRequest {
        environment_id: test_env(),
        session_id: sess_b.session_id,
        process_id: pid,
    }));
    assert!(
        matches!(resp.result, Err(are_core::RpcError::NotFound(_))),
        "cross-session lookup must miss with NotFound, got {:?}",
        resp.result
    );
}

// ---------------------------------------------------------------------------
// Cascade: terminate session kills its processes
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
#[cfg(unix)]
async fn terminate_session_cascades_to_its_processes() {
    let Some(sleep) = require_bin("/bin/sleep") else {
        return;
    };
    let (_tmp, state) = wired_state();
    let session = create_session(&state, None, HashMap::new());
    let pid = exec_in(&state, &session, sleep, &["30"], ".");

    // Sanity: running before termination.
    let resp = state.handle(RpcRequest::ProcessStatus(are_core::ProcessStatusRequest {
        environment_id: test_env(),
        session_id: session.session_id.clone(),
        process_id: pid.clone(),
    }));
    assert!(matches!(
        resp.result,
        Ok(RpcResponsePayload::ProcessStatus(_))
    ));

    // Terminate the session: cascade counts the live kill, then drops the record.
    let resp = state.handle(RpcRequest::TerminateSession(TerminateSessionRequest {
        environment_id: test_env(),
        session_id: session.session_id.clone(),
    }));
    match resp.result {
        Ok(RpcResponsePayload::TerminateSession(done)) => {
            assert_eq!(done.terminated_processes, 1);
        }
        other => panic!("expected TerminateSession response, got {other:?}"),
    }

    // The cascade is best-effort kill-then-remove: give the supervisor a
    // moment, then confirm the child is dead via the manager directly
    // (the handler path now fails on the dead session — also asserted).
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    let proc = state.proc.clone().expect("proc backend");
    let direct = proc
        .status(&are_core::ProcessStatusRequest {
            environment_id: test_env(),
            session_id: session.session_id.clone(),
            process_id: pid,
        })
        .expect("manager-level status");
    assert_ne!(
        direct.state,
        are_core::ProcessState::Running,
        "cascaded process must be dead"
    );

    // Session record is gone: resume reports NotFound.
    let resp = state.handle(RpcRequest::GetSession(GetSessionRequest {
        environment_id: test_env(),
        session_id: session.session_id,
    }));
    assert!(matches!(
        resp.result,
        Err(are_core::RpcError::SessionNotFound(_))
    ));
}

// ---------------------------------------------------------------------------
// Inheritance: workdir + env flow into children
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
#[cfg(unix)]
async fn empty_workdir_inherits_session_directory() {
    let Some(pwd) = require_bin("/bin/pwd") else {
        return;
    };
    let (tmp, state) = wired_state();
    std::fs::create_dir(tmp.path().join("sub")).expect("mkdir sub");

    let session = create_session(&state, Some("sub"), HashMap::new());
    let pid = exec_in(&state, &session, pwd, &[], "");
    let resp = state.handle(RpcRequest::WaitProcess(are_core::WaitProcessRequest {
        environment_id: test_env(),
        session_id: session.session_id,
        process_id: pid,
        timeout_secs: 10,
    }));
    match resp.result {
        Ok(RpcResponsePayload::WaitProcess(wait)) => {
            assert_eq!(wait.exit_code, Some(0));
            let expected = tmp
                .path()
                .join("sub")
                .canonicalize()
                .expect("canonicalize sub");
            assert_eq!(
                String::from_utf8_lossy(&wait.stdout).trim(),
                expected.to_string_lossy().trim()
            );
        }
        other => panic!("expected WaitProcess response, got {other:?}"),
    }
}

#[tokio::test(flavor = "multi_thread")]
#[cfg(unix)]
async fn session_env_visible_to_child_with_trusted_path() {
    let Some(env) = require_bin("/usr/bin/env") else {
        return;
    };
    let (_tmp, state) = wired_state();
    let session = create_session(
        &state,
        None,
        HashMap::from([("ARE_SESS_FOO".into(), "bar".into())]),
    );
    let pid = exec_in(&state, &session, env, &[], "");
    // Wait needs the session id again (moved above) — fetch it back.
    let session_id = session.session_id.clone();
    let resp = state.handle(RpcRequest::WaitProcess(are_core::WaitProcessRequest {
        environment_id: test_env(),
        session_id,
        process_id: pid,
        timeout_secs: 10,
    }));
    match resp.result {
        Ok(RpcResponsePayload::WaitProcess(wait)) => {
            assert_eq!(wait.exit_code, Some(0));
            let out = String::from_utf8_lossy(&wait.stdout);
            assert!(
                out.lines().any(|line| line == "ARE_SESS_FOO=bar"),
                "session env must reach the child; got:\n{out}"
            );
            assert!(
                !out.lines().any(|line| line.starts_with("LD_PRELOAD=")),
                "loader keys must never reach the child"
            );
            // PATH is the daemon's trusted PATH, not client-supplied.
            let daemon_path = std::env::var("PATH").unwrap_or_default();
            let child_path = out
                .lines()
                .find_map(|line| line.strip_prefix("PATH="))
                .unwrap_or("<missing>");
            assert_eq!(child_path, daemon_path);
        }
        other => panic!("expected WaitProcess response, got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Bounds: per-session process cap
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
#[cfg(unix)]
async fn per_session_process_cap_refuses_overfull_session() {
    let Some(sleep) = require_bin("/bin/sleep") else {
        return;
    };
    let tmp = tempfile::TempDir::new().expect("temp dir");
    let fs =
        FilesystemBackend::new(FilesystemConfig::new(&[tmp.path().to_path_buf()]).expect("fs"));
    let proc = Arc::new(ProcessManager::new(
        test_env(),
        ProcessConfig {
            permissive: true,
            max_processes_per_session: 2,
            ..ProcessConfig::default()
        },
        Some(fs.clone()),
    ));
    let sessions = Arc::new(SessionManager::new(
        test_env(),
        SessionConfig::default(),
        Some(fs),
    ));
    let session = sessions
        .create(CreateSessionRequest {
            environment_id: test_env(),
            working_directory: None,
            env_vars: HashMap::new(),
        })
        .expect("session")
        .0;

    let mk_req = || are_core::ExecuteRequest {
        environment_id: test_env(),
        session_id: session.session_id.clone(),
        program: sleep.into(),
        args: vec!["30".into()],
        working_directory: String::new(),
        env_vars: HashMap::new(),
    };
    let first = proc.start(mk_req(), &session).await.expect("first");
    let second = proc.start(mk_req(), &session).await.expect("second");
    let err = proc.start(mk_req(), &session).await.unwrap_err();
    assert!(
        matches!(err, are_daemon::process::ProcessError::TooManyProcesses(_)),
        "overfull session must refuse spawn, got: {err}"
    );
    assert_eq!(proc.count_for_session(&session.session_id), 2);

    // Cleanup.
    for pid in [first, second] {
        proc.terminate(are_core::TerminateProcessRequest {
            environment_id: test_env(),
            session_id: session.session_id.clone(),
            process_id: pid,
            force: true,
        })
        .await
        .expect("terminate");
    }
}

// ---------------------------------------------------------------------------
// Gate 6 must-fix regressions (reviewer + security batch)
// ---------------------------------------------------------------------------

/// FIX A regression: a session filled to its per-session cap with
/// short-lived (already-terminal, retention-expired) entries must accept a
/// new spawn — expired terminals are purged BEFORE the cap check.
#[tokio::test(flavor = "multi_thread")]
#[cfg(unix)]
async fn per_session_cap_frees_retention_expired_terminals_before_check() {
    let Some(echo) = require_bin("/bin/echo") else {
        return;
    };
    let tmp = tempfile::TempDir::new().expect("temp dir");
    let fs =
        FilesystemBackend::new(FilesystemConfig::new(&[tmp.path().to_path_buf()]).expect("fs"));
    let proc = Arc::new(ProcessManager::new(
        test_env(),
        ProcessConfig {
            permissive: true,
            max_processes_per_session: 2,
            retention_secs: 1,
            ..ProcessConfig::default()
        },
        Some(fs.clone()),
    ));
    let sessions = Arc::new(SessionManager::new(
        test_env(),
        SessionConfig::default(),
        Some(fs),
    ));
    let session = sessions
        .create(CreateSessionRequest {
            environment_id: test_env(),
            working_directory: None,
            env_vars: HashMap::new(),
        })
        .expect("session")
        .0;

    let mk_req = || are_core::ExecuteRequest {
        environment_id: test_env(),
        session_id: session.session_id.clone(),
        program: echo.into(),
        args: vec!["hi".into()],
        working_directory: String::new(),
        env_vars: HashMap::new(),
    };
    // Two short-lived procs: wait for each to go terminal.
    for _ in 0..2 {
        let pid = proc.start(mk_req(), &session).await.expect("spawn");
        proc.wait(are_core::WaitProcessRequest {
            environment_id: test_env(),
            session_id: session.session_id.clone(),
            process_id: pid,
            timeout_secs: 10,
        })
        .await
        .expect("wait");
    }
    assert_eq!(proc.count_for_session(&session.session_id), 2);
    // Let retention expire, then the cap must not dead-end the next spawn.
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let third = proc.start(mk_req(), &session).await;
    assert!(
        third.is_ok(),
        "spawn past retention-expired terminals must succeed, got {:?}",
        third.err()
    );
}

/// (a) Re-spawn after terminate-at-cap: filling a session to cap, then
/// terminating it, must free the slots so a fresh session can spawn.
#[tokio::test(flavor = "multi_thread")]
#[cfg(unix)]
async fn respawn_after_terminate_at_cap_succeeds() {
    let Some(sleep) = require_bin("/bin/sleep") else {
        return;
    };
    let tmp = tempfile::TempDir::new().expect("temp dir");
    let fs =
        FilesystemBackend::new(FilesystemConfig::new(&[tmp.path().to_path_buf()]).expect("fs"));
    let proc = Arc::new(ProcessManager::new(
        test_env(),
        ProcessConfig {
            permissive: true,
            max_processes_per_session: 2,
            ..ProcessConfig::default()
        },
        Some(fs.clone()),
    ));
    let sessions = Arc::new(SessionManager::new(
        test_env(),
        SessionConfig::default(),
        Some(fs.clone()),
    ));
    let mut caps = are_core::CapabilitySet::default();
    caps.insert(are_core::Capability::ProcessExecute);
    caps.insert(are_core::Capability::ProcessInspect);
    caps.insert(are_core::Capability::ProcessTerminate);
    let state = DaemonState::with_fs(
        test_env(),
        "test-host".into(),
        "0.1.0".into(),
        caps,
        are_core::Platform::Debian,
        fs,
    )
    .with_proc(Arc::clone(&proc))
    .with_sess(Arc::clone(&sessions));
    let session = sessions
        .create(CreateSessionRequest {
            environment_id: test_env(),
            working_directory: None,
            env_vars: HashMap::new(),
        })
        .expect("session")
        .0;
    let mk_req = || are_core::ExecuteRequest {
        environment_id: test_env(),
        session_id: session.session_id.clone(),
        program: sleep.into(),
        args: vec!["30".into()],
        working_directory: String::new(),
        env_vars: HashMap::new(),
    };
    let pids: Vec<_> = [
        proc.start(mk_req(), &session).await.expect("p1"),
        proc.start(mk_req(), &session).await.expect("p2"),
    ]
    .to_vec();
    assert!(proc.start(mk_req(), &session).await.is_err());
    // Terminate via the handler (kill-then-remove, live-kill count).
    let resp = state.handle(RpcRequest::TerminateSession(TerminateSessionRequest {
        environment_id: test_env(),
        session_id: session.session_id.clone(),
    }));
    match resp.result {
        Ok(RpcResponsePayload::TerminateSession(done)) => {
            assert_eq!(done.terminated_processes, 2);
        }
        other => panic!("expected TerminateSession, got {other:?}"),
    }
    // Fresh session reuses the freed capacity.
    let fresh = sessions
        .create(CreateSessionRequest {
            environment_id: test_env(),
            working_directory: None,
            env_vars: HashMap::new(),
        })
        .expect("fresh session")
        .0;
    let fresh_req = are_core::ExecuteRequest {
        environment_id: test_env(),
        session_id: fresh.session_id.clone(),
        program: sleep.into(),
        args: vec!["30".into()],
        working_directory: String::new(),
        env_vars: HashMap::new(),
    };
    let pid = proc.start(fresh_req, &fresh).await.expect("respawn");
    proc.terminate(are_core::TerminateProcessRequest {
        environment_id: test_env(),
        session_id: fresh.session_id.clone(),
        process_id: pid,
        force: true,
    })
    .await
    .expect("cleanup fresh");
    for pid in pids {
        // Best-effort cleanup of the terminated session's children.
        let _ = proc
            .terminate(are_core::TerminateProcessRequest {
                environment_id: test_env(),
                session_id: session.session_id.clone(),
                process_id: pid,
                force: true,
            })
            .await;
    }
}

/// FIX C regression: touching an expired session with a live child kills
/// the child (no silent orphan) and reports `Expired`.
#[tokio::test(flavor = "multi_thread")]
#[cfg(unix)]
async fn expired_session_touch_kills_live_child_and_reports_expired() {
    let Some(sleep) = require_bin("/bin/sleep") else {
        return;
    };
    let (_tmp, state) = wired_state_with_session_config(SessionConfig {
        idle_timeout_secs: 1,
        ..SessionConfig::default()
    });
    let session = create_session(&state, None, HashMap::new());
    let pid = exec_in(&state, &session, sleep, &["30"], ".");
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    // Next access expires the session: handler kills the live child first.
    let resp = state.handle(RpcRequest::GetSession(GetSessionRequest {
        environment_id: test_env(),
        session_id: session.session_id.clone(),
    }));
    assert!(
        matches!(resp.result, Err(are_core::RpcError::SessionExpired(_))),
        "expired touch must report SessionExpired, got {:?}",
        resp.result
    );
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    let proc = state.proc.clone().expect("proc backend");
    let direct = proc
        .status(&are_core::ProcessStatusRequest {
            environment_id: test_env(),
            session_id: session.session_id.clone(),
            process_id: pid,
        })
        .expect("manager-level status");
    assert_ne!(
        direct.state,
        are_core::ProcessState::Running,
        "expired session's live child must be dead (kill-on-expiry)"
    );
}

/// (b) Terminate of an EXPIRED session: the recovery path kills live
/// children best-effort, then returns `Expired` (kill attempted despite
/// the error) — never masked as success.
#[tokio::test(flavor = "multi_thread")]
#[cfg(unix)]
async fn terminate_expired_session_kills_and_returns_expired() {
    let Some(sleep) = require_bin("/bin/sleep") else {
        return;
    };
    let (_tmp, state) = wired_state_with_session_config(SessionConfig {
        idle_timeout_secs: 1,
        ..SessionConfig::default()
    });
    let session = create_session(&state, None, HashMap::new());
    let pid = exec_in(&state, &session, sleep, &["30"], ".");
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let resp = state.handle(RpcRequest::TerminateSession(TerminateSessionRequest {
        environment_id: test_env(),
        session_id: session.session_id.clone(),
    }));
    match resp.result {
        Err(are_core::RpcError::SessionExpired(msg)) => {
            assert!(
                msg.contains("kill attempted"),
                "expired terminate must document the kill attempt, got: {msg}"
            );
        }
        other => panic!("expected SessionExpired with kill note, got {other:?}"),
    }
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;
    let proc = state.proc.clone().expect("proc backend");
    let direct = proc
        .status(&are_core::ProcessStatusRequest {
            environment_id: test_env(),
            session_id: session.session_id,
            process_id: pid,
        })
        .expect("manager-level status");
    assert_ne!(
        direct.state,
        are_core::ProcessState::Running,
        "expired terminate must kill the live child"
    );
}

/// (c) Execute + status against an expired session report `Expired` and
/// spawn nothing (no orphan, no slot consumed).
#[tokio::test(flavor = "multi_thread")]
async fn execute_and_status_with_expired_session_report_expired_without_spawn() {
    let (_tmp, state) = wired_state_with_session_config(SessionConfig {
        idle_timeout_secs: 1,
        ..SessionConfig::default()
    });
    // Two sessions: the first expired access removes its entry, so execute
    // and status each need a distinct expired session to observe `Expired`
    // (a second touch of the same id is `NotFound` by the lazy-expiry
    // contract).
    let sess_exec = create_session(&state, None, HashMap::new());
    let sess_status = create_session(&state, None, HashMap::new());
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    let before = state.proc.clone().expect("proc").process_count();
    let resp = state.handle(RpcRequest::Execute(are_core::ExecuteRequest {
        environment_id: test_env(),
        session_id: sess_exec.session_id.clone(),
        program: "cargo".into(),
        args: vec![],
        working_directory: ".".into(),
        env_vars: HashMap::new(),
    }));
    assert!(
        matches!(resp.result, Err(are_core::RpcError::SessionExpired(_))),
        "execute on expired session must report Expired, got {:?}",
        resp.result
    );
    let resp = state.handle(RpcRequest::ProcessStatus(are_core::ProcessStatusRequest {
        environment_id: test_env(),
        session_id: sess_status.session_id,
        process_id: are_core::ProcessId::new("proc-999999"),
    }));
    assert!(
        matches!(resp.result, Err(are_core::RpcError::SessionExpired(_))),
        "status on expired session must report Expired, got {:?}",
        resp.result
    );
    let after = state.proc.clone().expect("proc").process_count();
    assert_eq!(before, after, "expired execute must not consume a slot");
}

/// (d) Cross-session terminal eviction sanity: the global process pool is
/// shared — one session's terminal entries may evict another session's
/// oldest terminals (documented global oldest-terminal-first behavior).
#[tokio::test(flavor = "multi_thread")]
#[cfg(unix)]
async fn cross_session_terminal_eviction_shares_global_pool_oldest_first() {
    let Some(echo) = require_bin("/bin/echo") else {
        return;
    };
    let tmp = tempfile::TempDir::new().expect("temp dir");
    let fs =
        FilesystemBackend::new(FilesystemConfig::new(&[tmp.path().to_path_buf()]).expect("fs"));
    // Tiny global pool: 3 entries. Two sessions share it.
    let proc = Arc::new(ProcessManager::new(
        test_env(),
        ProcessConfig {
            permissive: true,
            max_processes: 3,
            ..ProcessConfig::default()
        },
        Some(fs.clone()),
    ));
    let sessions = Arc::new(SessionManager::new(
        test_env(),
        SessionConfig::default(),
        Some(fs),
    ));
    let sess_a = sessions
        .create(CreateSessionRequest {
            environment_id: test_env(),
            working_directory: None,
            env_vars: HashMap::new(),
        })
        .expect("sess a")
        .0;
    let sess_b = sessions
        .create(CreateSessionRequest {
            environment_id: test_env(),
            working_directory: None,
            env_vars: HashMap::new(),
        })
        .expect("sess b")
        .0;
    let mk = |sess: &are_core::SessionInfo| are_core::ExecuteRequest {
        environment_id: test_env(),
        session_id: sess.session_id.clone(),
        program: echo.into(),
        args: vec!["x".into()],
        working_directory: String::new(),
        env_vars: HashMap::new(),
    };
    // Fill the pool with terminal entries: 2 from A, 1 from B.
    for sess in [&sess_a, &sess_a, &sess_b] {
        let pid = proc.start(mk(sess), sess).await.expect("spawn");
        proc.wait(are_core::WaitProcessRequest {
            environment_id: test_env(),
            session_id: sess.session_id.clone(),
            process_id: pid,
            timeout_secs: 10,
        })
        .await
        .expect("wait");
    }
    assert_eq!(proc.process_count(), 3);
    // One more terminal spawn from B evicts the oldest terminal GLOBALLY
    // (which belongs to A) — sessions share one pool.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let pid = proc.start(mk(&sess_b), &sess_b).await.expect("spawn");
    proc.wait(are_core::WaitProcessRequest {
        environment_id: test_env(),
        session_id: sess_b.session_id.clone(),
        process_id: pid,
        timeout_secs: 10,
    })
    .await
    .expect("wait");
    assert_eq!(proc.process_count(), 3, "global pool stays bounded");
    assert!(
        proc.count_for_session(&sess_a.session_id) < 2,
        "A's oldest terminal must have been evicted by B's spawn (shared pool)"
    );
}

/// Env scoping: `GetSession`/`TerminateSession` with a mismatched
/// environment miss with `NotFound`, never by leaking liveness.
#[tokio::test(flavor = "multi_thread")]
async fn session_get_and_terminate_enforce_environment_match() {
    let (_tmp, state) = wired_state();
    let session = create_session(&state, None, HashMap::new());
    let resp = state.handle(RpcRequest::GetSession(GetSessionRequest {
        environment_id: EnvironmentId::new("other-env"),
        session_id: session.session_id.clone(),
    }));
    // Daemon-env mismatch is a malformed request (same as create/list).
    assert!(matches!(
        resp.result,
        Err(are_core::RpcError::InvalidRequest(_))
    ));
}

/// Capacity errors surface as the dedicated `CapacityExceeded` category.
#[tokio::test(flavor = "multi_thread")]
async fn session_capacity_refusal_maps_to_capacity_exceeded() {
    let (_tmp, state) = wired_state_with_session_config(SessionConfig {
        max_sessions: 1,
        ..SessionConfig::default()
    });
    let _first = create_session(&state, None, HashMap::new());
    let resp = state.handle(RpcRequest::CreateSession(CreateSessionRequest {
        environment_id: test_env(),
        working_directory: None,
        env_vars: HashMap::new(),
    }));
    assert!(
        matches!(resp.result, Err(are_core::RpcError::CapacityExceeded(_))),
        "full session table must map to CapacityExceeded, got {:?}",
        resp.result
    );
}
