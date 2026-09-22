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

/// Build a manager rooted at a fresh temp dir, explicitly permissive
/// (tests opt in; the production default is fail-closed).
fn test_manager(
    max_output_bytes: usize,
    allowed: Option<Vec<String>>,
) -> (tempfile::TempDir, ProcessManager) {
    test_manager_full(max_output_bytes, allowed, None, None)
}

/// Build a manager with explicit table bounds. `max_processes` /
/// `retention_secs` default to the production defaults when `None`.
fn test_manager_full(
    max_output_bytes: usize,
    allowed: Option<Vec<String>>,
    max_processes: Option<usize>,
    retention_secs: Option<u64>,
) -> (tempfile::TempDir, ProcessManager) {
    let tmp = tempfile::TempDir::new().expect("temp dir");
    let fs = FilesystemBackend::new(
        FilesystemConfig::new(&[tmp.path().to_path_buf()]).expect("fs config"),
    );
    let mut config = ProcessConfig {
        max_output_bytes,
        allowed_executables: allowed.map(|list| list.into_iter().collect()),
        // Tests without an allow list opt into permissive mode explicitly;
        // the default (fail-closed) is covered by dedicated tests below.
        permissive: true,
        ..ProcessConfig::default()
    };
    if let Some(max) = max_processes {
        config.max_processes = max;
    }
    if let Some(retention) = retention_secs {
        config.retention_secs = retention;
    }
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

fn wait_req(process_id: ProcessId, timeout_secs: u64) -> WaitProcessRequest {
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
        .block_on(mgr.wait(wait_req(ghost.clone(), 1)))
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
            are_core::MAX_WAIT_TIMEOUT_SECS + 1,
        )))
        .unwrap_err();
    assert!(matches!(err, ProcessError::InvalidRequest(_)));
}

#[test]
fn wait_zero_timeout_rejected() {
    let (_tmp, mgr) = test_manager(4096, None);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let err = rt
        .block_on(mgr.wait(wait_req(ProcessId::new("proc-000001"), 0)))
        .unwrap_err();
    assert!(matches!(err, ProcessError::InvalidRequest(_)));
}

#[test]
fn default_config_is_fail_closed_at_spawn() {
    // No allow list + no permissive opt-in: even a valid spawn is refused
    // with PolicyDenied before any fs/spawn work happens.
    let tmp = tempfile::TempDir::new().expect("temp dir");
    let fs = FilesystemBackend::new(
        FilesystemConfig::new(&[tmp.path().to_path_buf()]).expect("fs config"),
    );
    let mgr = ProcessManager::new(test_env(), ProcessConfig::default(), Some(fs));
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let err = rt
        .block_on(mgr.start(exec_req("cargo", &[], ".")))
        .unwrap_err();
    assert!(
        matches!(err, ProcessError::PolicyDenied(_)),
        "fail-closed default must refuse spawn, got: {err}"
    );
}

#[test]
fn client_supplied_path_env_rejected() {
    let (_tmp, mgr) = test_manager(4096, None);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let mut req = exec_req("cargo", &[], ".");
    req.env_vars.insert("PATH".into(), "/tmp/evil".into());
    let err = rt.block_on(mgr.start(req)).unwrap_err();
    assert!(
        matches!(err, ProcessError::InvalidRequest(_)),
        "client PATH must be rejected, got: {err}"
    );
}

#[test]
fn deny_list_catches_exe_variants_without_spawn() {
    let (_tmp, mgr) = test_manager(4096, None);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    for prog in ["shutdown.exe", "SHUTDOWN", "Shutdown.ExE"] {
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
fn start_without_filesystem_backend_fails_closed() {
    // Permissive so the policy passes and the missing backend is what
    // fails the spawn.
    let mgr = ProcessManager::new(
        test_env(),
        ProcessConfig {
            permissive: true,
            ..ProcessConfig::default()
        },
        None,
    );
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
    let resp = mgr.wait(wait_req(id.clone(), 10)).await.expect("wait");
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
    let resp = mgr.wait(wait_req(id, 10)).await.expect("wait");
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
    let resp = mgr.wait(wait_req(id, 15)).await.expect("wait");
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
    let resp = mgr.wait(wait_req(id, 10)).await.expect("wait");
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
    let resp = mgr.wait(wait_req(id.clone(), 1)).await.expect("wait");
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
    let resp = mgr.wait(wait_req(id.clone(), 10)).await.expect("wait");
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

// ---------------------------------------------------------------------------
// Table-retention regression tests (FIX 1; Unix coreutils, no shell)
// ---------------------------------------------------------------------------

#[tokio::test]
#[cfg(unix)]
async fn process_table_bounded_evicts_oldest_terminal_first() {
    let (Some(echo), Some(sleep)) = (require_bin("/bin/echo"), require_bin("/bin/sleep")) else {
        return;
    };
    // Tiny table: 1 live slot + 2 terminal slots.
    let (_tmp, mgr) = test_manager_full(4096, None, Some(3), Some(3600));

    // One live process that must never be evicted.
    let live = mgr
        .start(exec_req(sleep, &["30"], "."))
        .await
        .expect("start live");

    // Fill the table with terminal entries.
    let mut terminal = Vec::new();
    for i in 0..3 {
        let id = mgr
            .start(exec_req(echo, &[&format!("msg-{i}")], "."))
            .await
            .expect("start echo");
        let resp = mgr.wait(wait_req(id.clone(), 10)).await.expect("wait");
        assert_eq!(resp.exit_code, Some(0));
        terminal.push(id);
    }

    // Bound holds despite 4 spawns into a 3-slot table.
    assert!(
        mgr.process_count() <= 3,
        "table must stay bounded, has {} entries",
        mgr.process_count()
    );
    // The oldest terminal entry was evicted; the live entry survived.
    let err = mgr
        .status(&are_core::ProcessStatusRequest {
            environment_id: test_env(),
            process_id: terminal[0].clone(),
        })
        .unwrap_err();
    assert!(
        matches!(err, ProcessError::NotFound(_)),
        "oldest terminal must be evicted, got: {err}"
    );
    let status = mgr
        .status(&are_core::ProcessStatusRequest {
            environment_id: test_env(),
            process_id: live.clone(),
        })
        .expect("live entry must survive eviction");
    assert_eq!(status.state, ProcessState::Running);
    // The newest terminal entry is still queryable.
    let newest = terminal.last().expect("terminal").clone();
    let status = mgr
        .status(&are_core::ProcessStatusRequest {
            environment_id: test_env(),
            process_id: newest,
        })
        .expect("newest terminal must be retained");
    assert_eq!(status.state, ProcessState::Exited { code: 0 });

    // Cleanup the live process.
    mgr.terminate(TerminateProcessRequest {
        environment_id: test_env(),
        process_id: live,
        force: true,
    })
    .await
    .expect("terminate");
}

#[tokio::test]
#[cfg(unix)]
async fn process_table_full_of_live_processes_rejects_spawn() {
    let Some(sleep) = require_bin("/bin/sleep") else {
        return;
    };
    let (_tmp, mgr) = test_manager_full(4096, None, Some(2), Some(3600));

    let first = mgr
        .start(exec_req(sleep, &["30"], "."))
        .await
        .expect("start first");
    let second = mgr
        .start(exec_req(sleep, &["30"], "."))
        .await
        .expect("start second");

    // Table full and everything live: refuse instead of evicting running work.
    let err = mgr.start(exec_req(sleep, &["1"], ".")).await.unwrap_err();
    assert!(
        matches!(err, ProcessError::TooManyProcesses(_)),
        "full live table must refuse spawn, got: {err}"
    );
    assert_eq!(mgr.process_count(), 2);

    for id in [first, second] {
        mgr.terminate(TerminateProcessRequest {
            environment_id: test_env(),
            process_id: id,
            force: true,
        })
        .await
        .expect("terminate");
    }
}

#[tokio::test]
#[cfg(unix)]
async fn expired_terminal_entries_evictable_by_retention() {
    let Some(echo) = require_bin("/bin/echo") else {
        return;
    };
    // Zero-second retention: terminal entries are immediately expirable.
    // (Spawns within the same second may still count as age 0, so this
    // test only asserts the bound + queryability, not eviction itself —
    // deterministic expiry is covered by unit tests with fabricated ages.)
    let (_tmp, mgr) = test_manager_full(4096, None, Some(4), Some(0));

    let mut ids = Vec::new();
    for i in 0..4 {
        let id = mgr
            .start(exec_req(echo, &[&format!("r-{i}")], "."))
            .await
            .expect("start echo");
        mgr.wait(wait_req(id.clone(), 10)).await.expect("wait");
        ids.push(id);
    }
    assert!(
        mgr.process_count() <= 4,
        "table must stay bounded, has {} entries",
        mgr.process_count()
    );
    // Spawning one more must succeed by evicting (all entries terminal).
    let extra = mgr
        .start(exec_req(echo, &["extra"], "."))
        .await
        .expect("spawn past retention must succeed via eviction");
    mgr.wait(wait_req(extra, 10)).await.expect("wait");
    assert!(
        mgr.process_count() <= 4,
        "table must stay bounded, has {} entries",
        mgr.process_count()
    );
}
