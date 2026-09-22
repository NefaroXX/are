//! Gate 5 scenario tests: secure structured process execution.
//!
//! Test-child strategy (documented choice): production code never invokes a
//! shell, so tests must spawn real programs without one. We use absolute
//! coreutils paths (`/bin/echo`, `/bin/sleep`, `/bin/cat`, `/bin/false`)
//! on Unix, gated with `#[cfg(unix)]`, skipping gracefully if a binary is
//! absent. Policy/boundary tests need no child at all and run on every
//! platform. Windows therefore always compiles; Unix CI runs the full set.
//!
//! Every test asserts through the public `ProcessManager` API only.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::collections::HashMap;

#[cfg(unix)]
use are_core::ProcessState;
use are_core::{
    EnvironmentId, ExecuteRequest, ProcessId, TerminateProcessRequest, WaitProcessRequest,
};
use are_daemon::fs::{FilesystemBackend, FilesystemConfig};
use are_daemon::process::{ProcessConfig, ProcessError, ProcessManager};

fn test_env() -> EnvironmentId {
    EnvironmentId::new("test-env")
}

/// Build a manager rooted at a fresh temp dir.
fn test_manager(
    max_output_bytes: usize,
    allowed: Option<Vec<String>>,
) -> (tempfile::TempDir, ProcessManager) {
    let tmp = tempfile::TempDir::new().expect("temp dir");
    let fs = FilesystemBackend::new(
        FilesystemConfig::new(&[tmp.path().to_path_buf()]).expect("fs config"),
    );
    let config = ProcessConfig {
        max_output_bytes,
        allowed_executables: allowed.map(|list| list.into_iter().collect()),
        ..ProcessConfig::default()
    };
    let mgr = ProcessManager::new(test_env(), config, Some(fs));
    (tmp, mgr)
}

fn exec_req(program: &str, args: &[&str], workdir: &str) -> ExecuteRequest {
    ExecuteRequest {
        environment_id: test_env(),
        program: program.into(),
        args: args.iter().map(|s| (*s).to_string()).collect(),
        working_directory: workdir.into(),
        env_vars: HashMap::new(),
    }
}

fn wait_req(process_id: ProcessId, timeout_secs: Option<u64>) -> WaitProcessRequest {
    WaitProcessRequest {
        environment_id: test_env(),
        process_id,
        timeout_secs,
    }
}

/// Unix helper binary path, or `None` to skip the test gracefully.
#[cfg(unix)]
fn require_bin(path: &'static str) -> Option<&'static str> {
    std::path::Path::new(path).exists().then_some(path)
}

// ---------------------------------------------------------------------------
// Policy tests (portable — rejected before any spawn)
// ---------------------------------------------------------------------------

#[test]
fn deny_list_rejects_shutdown_family() {
    let (_tmp, mgr) = test_manager(4096, None);
    for prog in [
        "shutdown",
        "reboot",
        "poweroff",
        "halt",
        "init",
        "/sbin/shutdown",
    ] {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let err = rt
            .block_on(mgr.start(exec_req(prog, &[], ".")))
            .unwrap_err();
        assert!(
            matches!(err, ProcessError::DeniedExecutable(_)),
            "{prog} must be denied, got: {err}"
        );
    }
}

#[test]
fn allow_list_rejects_unlisted_program() {
    let (_tmp, mgr) = test_manager(4096, Some(vec!["git".into()]));
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let err = rt
        .block_on(mgr.start(exec_req("cargo", &["--version"], ".")))
        .unwrap_err();
    assert!(
        matches!(err, ProcessError::DeniedExecutable(_)),
        "unlisted program must be denied, got: {err}"
    );
}

#[test]
fn program_with_shell_metachars_is_not_interpreted() {
    // If a shell were involved, `echo; id` would run `id`. Structured
    // execution treats the whole string as one program name → spawn fails.
    let (_tmp, mgr) = test_manager(4096, None);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let err = rt
        .block_on(mgr.start(exec_req("echo; id", &[], ".")))
        .unwrap_err();
    assert!(
        matches!(err, ProcessError::Internal(_)),
        "metachar program must fail to spawn, got: {err}"
    );
}

#[test]
fn traversal_and_absolute_workdirs_rejected() {
    let (_tmp, mgr) = test_manager(4096, None);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    for workdir in ["../..", "..", "/etc", "C:\\Windows"] {
        let err = rt
            .block_on(mgr.start(exec_req("cargo", &[], workdir)))
            .unwrap_err();
        assert!(
            matches!(err, ProcessError::InvalidRequest(_)),
            "workdir {workdir:?} must be rejected, got: {err}"
        );
    }
}

#[test]
fn workdir_must_be_an_existing_directory() {
    let (tmp, mgr) = test_manager(4096, None);
    std::fs::write(tmp.path().join("file.txt"), b"data").unwrap();
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    // A file is not a directory.
    let err = rt
        .block_on(mgr.start(exec_req("cargo", &[], "file.txt")))
        .unwrap_err();
    assert!(matches!(err, ProcessError::InvalidRequest(_)));
    // A missing directory is rejected too.
    let err = rt
        .block_on(mgr.start(exec_req("cargo", &[], "no-such-dir")))
        .unwrap_err();
    assert!(matches!(err, ProcessError::InvalidRequest(_)));
}

#[test]
fn invalid_env_var_key_rejected_before_spawn() {
    let (_tmp, mgr) = test_manager(4096, None);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut req = exec_req("cargo", &[], ".");
    req.env_vars.insert("A=B".into(), "v".into());
    let err = rt.block_on(mgr.start(req)).unwrap_err();
    assert!(matches!(err, ProcessError::InvalidRequest(_)));
}

#[test]
fn wrong_environment_id_rejected_before_spawn() {
    let (_tmp, mgr) = test_manager(4096, None);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    // Even a denied program reports the environment mismatch first.
    let mut req = exec_req("shutdown", &[], ".");
    req.environment_id = EnvironmentId::new("other-env");
    let err = rt.block_on(mgr.start(req)).unwrap_err();
    assert!(matches!(err, ProcessError::EnvironmentMismatch(_)));
}

#[test]
fn unknown_process_ids_are_not_found() {
    let (_tmp, mgr) = test_manager(4096, None);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let ghost = ProcessId::new("proc-999999");
    let err = rt
        .block_on(mgr.wait(wait_req(ghost.clone(), Some(1))))
        .unwrap_err();
    assert!(matches!(err, ProcessError::NotFound(_)));
    let err = rt
        .block_on(mgr.terminate(TerminateProcessRequest {
            environment_id: test_env(),
            process_id: ghost,
            force: false,
        }))
        .unwrap_err();
    assert!(matches!(err, ProcessError::NotFound(_)));
}

#[test]
fn wait_timeout_over_bound_rejected() {
    let (_tmp, mgr) = test_manager(4096, None);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let err = rt
        .block_on(mgr.wait(wait_req(
            ProcessId::new("proc-000001"),
            Some(are_core::MAX_WAIT_TIMEOUT_SECS + 1),
        )))
        .unwrap_err();
    assert!(matches!(err, ProcessError::InvalidRequest(_)));
}

#[test]
fn start_without_filesystem_backend_fails_closed() {
    let mgr = ProcessManager::new(test_env(), ProcessConfig::default(), None);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let err = rt
        .block_on(mgr.start(exec_req("cargo", &[], ".")))
        .unwrap_err();
    assert!(
        matches!(err, ProcessError::Internal(_)),
        "missing fs backend must fail closed, got: {err}"
    );
}

// ---------------------------------------------------------------------------
// Spawn tests (Unix coreutils, no shell)
// ---------------------------------------------------------------------------

#[tokio::test]
#[cfg(unix)]
async fn happy_path_start_wait_status() {
    let Some(echo) = require_bin("/bin/echo") else {
        return;
    };
    let (_tmp, mgr) = test_manager(1024 * 1024, None);

    let id = mgr
        .start(exec_req(echo, &["hello", "world"], "."))
        .await
        .expect("start");
    let resp = mgr
        .wait(wait_req(id.clone(), Some(10)))
        .await
        .expect("wait");
    assert_eq!(resp.stdout, b"hello world\n");
    assert!(resp.stderr.is_empty());
    assert_eq!(resp.exit_code, Some(0));
    assert!(!resp.timed_out);
    assert!(!resp.truncated);

    let status = mgr
        .status(&are_core::ProcessStatusRequest {
            environment_id: test_env(),
            process_id: id,
        })
        .expect("status");
    assert_eq!(status.state, ProcessState::Exited { code: 0 });
}

#[tokio::test]
#[cfg(unix)]
async fn shell_injection_args_stay_literal() {
    let Some(echo) = require_bin("/bin/echo") else {
        return;
    };
    let (tmp, mgr) = test_manager(1024 * 1024, None);

    // If these were interpreted by a shell, a file would be created and
    // command substitution would execute. Structured argv passes them
    // literally to /bin/echo.
    let evil = "hello; touch pwned-marker-1";
    let id = mgr
        .start(exec_req(
            echo,
            &[evil, "$(touch pwned-marker-2)", "`touch pwned-marker-3`"],
            ".",
        ))
        .await
        .expect("start");
    let resp = mgr.wait(wait_req(id, Some(10))).await.expect("wait");
    let out = String::from_utf8_lossy(&resp.stdout);
    assert!(out.contains(evil), "literal arg must be echoed: {out}");
    assert!(out.contains("$(touch pwned-marker-2)"));
    assert!(out.contains("`touch pwned-marker-3`"));
    for marker in ["pwned-marker-1", "pwned-marker-2", "pwned-marker-3"] {
        assert!(
            !tmp.path().join(marker).exists(),
            "side-effect file {marker} must NOT exist"
        );
    }
}

#[tokio::test]
#[cfg(unix)]
async fn large_output_is_truncated_and_bounded() {
    let Some(cat) = require_bin("/bin/cat") else {
        return;
    };
    let (tmp, mgr) = test_manager(4096, None);
    let big = vec![b'x'; 64 * 1024];
    std::fs::write(tmp.path().join("big.txt"), &big).unwrap();

    let id = mgr
        .start(exec_req(cat, &["big.txt"], "."))
        .await
        .expect("start");
    let resp = mgr.wait(wait_req(id, Some(15))).await.expect("wait");
    assert!(resp.truncated, "20 MiB-scale output must set truncated");
    assert!(
        resp.stdout.len() <= 4096,
        "stdout must be capped, got {} bytes",
        resp.stdout.len()
    );
    assert_eq!(resp.exit_code, Some(0));
}

#[tokio::test]
#[cfg(unix)]
async fn crash_reports_nonzero_exit() {
    let mgr_path = require_bin("/bin/false");
    let Some(prog) = mgr_path else {
        return;
    };
    let (_tmp, mgr) = test_manager(4096, None);

    let id = mgr.start(exec_req(prog, &[], ".")).await.expect("start");
    let resp = mgr.wait(wait_req(id, Some(10))).await.expect("wait");
    assert!(
        resp.exit_code.is_some_and(|c| c != 0),
        "crash must report non-zero exit, got {:?}",
        resp.exit_code
    );
    assert!(!resp.timed_out);
}

#[tokio::test]
#[cfg(unix)]
async fn wait_timeout_returns_snapshot_and_process_survives() {
    let Some(sleep) = require_bin("/bin/sleep") else {
        return;
    };
    let (_tmp, mgr) = test_manager(4096, None);

    let id = mgr
        .start(exec_req(sleep, &["30"], "."))
        .await
        .expect("start");
    let resp = mgr.wait(wait_req(id.clone(), Some(1))).await.expect("wait");
    assert!(resp.timed_out);
    assert_eq!(resp.exit_code, None);

    // Still running after the timed-out wait.
    let status = mgr
        .status(&are_core::ProcessStatusRequest {
            environment_id: test_env(),
            process_id: id.clone(),
        })
        .expect("status");
    assert_eq!(status.state, ProcessState::Running);

    // Cleanup.
    let term = mgr
        .terminate(TerminateProcessRequest {
            environment_id: test_env(),
            process_id: id.clone(),
            force: true,
        })
        .await
        .expect("terminate");
    assert!(term.terminated);
    let resp = mgr
        .wait(wait_req(id.clone(), Some(10)))
        .await
        .expect("wait");
    assert!(!resp.timed_out);
    let status = mgr
        .status(&are_core::ProcessStatusRequest {
            environment_id: test_env(),
            process_id: id,
        })
        .expect("final status");
    assert_ne!(status.state, ProcessState::Running);
}

#[tokio::test]
#[cfg(unix)]
async fn disconnect_reconnect_shared_table_then_terminate() {
    let Some(sleep) = require_bin("/bin/sleep") else {
        return;
    };
    // One manager shared across "connections" (Arc clones), simulating a
    // client that disconnects and reconnects: the process table persists.
    let (_tmp, mgr) = test_manager(4096, None);
    let mgr = std::sync::Arc::new(mgr);

    let id = mgr
        .start(exec_req(sleep, &["30"], "."))
        .await
        .expect("start");

    // "Reconnect": a different Arc handle queries the same table by id.
    let reconnected = std::sync::Arc::clone(&mgr);
    let status = reconnected
        .status(&are_core::ProcessStatusRequest {
            environment_id: test_env(),
            process_id: id.clone(),
        })
        .expect("status after reconnect");
    assert_eq!(status.state, ProcessState::Running);

    // Terminate through the reconnected handle.
    let term = reconnected
        .terminate(TerminateProcessRequest {
            environment_id: test_env(),
            process_id: id.clone(),
            force: false,
        })
        .await
        .expect("terminate");
    assert!(term.terminated);

    // Already-exited processes report terminated=false.
    let term2 = reconnected
        .terminate(TerminateProcessRequest {
            environment_id: test_env(),
            process_id: id.clone(),
            force: true,
        })
        .await
        .expect("second terminate");
    assert!(!term2.terminated);

    let status = reconnected
        .status(&are_core::ProcessStatusRequest {
            environment_id: test_env(),
            process_id: id,
        })
        .expect("final status");
    assert_ne!(status.state, ProcessState::Running);
}

#[tokio::test]
#[cfg(unix)]
async fn status_rejects_environment_mismatch() {
    let Some(echo) = require_bin("/bin/echo") else {
        return;
    };
    let (_tmp, mgr) = test_manager(4096, None);
    let id = mgr
        .start(exec_req(echo, &["hi"], "."))
        .await
        .expect("start");
    let err = mgr
        .status(&are_core::ProcessStatusRequest {
            environment_id: EnvironmentId::new("other-env"),
            process_id: id,
        })
        .unwrap_err();
    assert!(matches!(err, ProcessError::EnvironmentMismatch(_)));
}
