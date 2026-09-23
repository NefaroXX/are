//! Capability-based authorization grants (Gate 8).
//!
//! [`Grant`] is pure data: a scoped permission held by one principal
//! (identified daemon-side by the `blake3:<hex>` fingerprint of its client
//! certificate — see `are-daemon/src/auth.rs`). This crate stays dependency-
//! free: no crypto, no I/O, no x509 parsing. Normalization and matching are
//! total string functions, unit-tested here.
//!
//! # Scope model
//!
//! Filesystem grants carry env-relative prefix `root`s (`""` = the whole
//! allowed root). Matching is component-wise: `logs` covers `logs` and
//! `logs/a` but NOT `logs2/x`. DELETE folds into the Write scope — there is
//! deliberately no separate delete variant (Gate 8 decision).
//!
//! Process grants: `ProcessExecute` carries a set of allowed program names
//! (matched by normalized basename — see [`normalize_program_name`]);
//! `ProcessInspect` gates status/wait... no — status only; `wait` follows
//! the terminate mapping (see below). `ProcessTerminate` gates
//! terminate AND wait (waiting observes terminal output, so it shares the
//! terminate scope — mirrors the daemon's advertised-capability mapping).
//!
//! There are NO `service.*` / `system.package.*` variants: those futures are
//! out of scope and must fail loudly at grants-file load (unknown fields),
//! never parse as something else.
//!
//! # Preconditions
//!
//! [`root_covers`] assumes both inputs are normalized ([`normalize_grant_root`]
//! for roots; the daemon's `FilesystemBackend::relativize` output for paths).
//! The `grants_allow_*` helpers normalize program names on both sides, so
//! grant entries and request programs compare canonically regardless of
//! where they were written.

use serde::{Deserialize, Serialize};

use crate::CoreError;

/// A scoped authorization grant held by one principal.
///
/// Serialized adjacently-tagged (`{"type":"filesystem_read","data":{...}}`),
/// mirroring the `RpcResponsePayload` envelope style in `info.rs`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum Grant {
    /// Read files (and file metadata) under `root`.
    FilesystemRead {
        /// Env-relative prefix root; `""` = the whole allowed root.
        root: String,
    },
    /// Write/create/rename/delete under `root`. Delete folds in here.
    FilesystemWrite {
        /// Env-relative prefix root; `""` = the whole allowed root.
        root: String,
    },
    /// List directories under `root`.
    FilesystemList {
        /// Env-relative prefix root; `""` = the whole allowed root.
        root: String,
    },
    /// Execute programs whose normalized basename is in `programs`.
    ProcessExecute {
        /// Allowed program names (normalized at match time; an empty set
        /// allows nothing).
        programs: Vec<String>,
    },
    /// Query process status.
    ProcessInspect,
    /// Terminate processes AND wait on them.
    ProcessTerminate,
}

/// Which filesystem scope a check targets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsGrantKind {
    /// `read_file` / `get_file_metadata`.
    Read,
    /// `write_file` / `create_directory` / `rename` (both ends) / `delete`.
    Write,
    /// `list_directory`.
    List,
}

/// Normalize a raw grant root from the grants file into canonical form.
///
/// - Backslashes become `/` (Windows-authored configs).
/// - Leading slashes are stripped (`/logs` means `logs` — lenient, logged
///   daemon-side).
/// - `.` segments and empty segments (`a//b`) are dropped; `""` and `"."`
///   both normalize to `""` (the whole root).
/// - `..` segments are REJECTED (a grant root that climbs is meaningless —
///   fail closed at config load, never silently scope it).
pub fn normalize_grant_root(raw: &str) -> Result<String, CoreError> {
    let slashed = raw.replace('\\', "/");
    let mut parts = Vec::new();
    for comp in slashed.split('/') {
        match comp {
            "" | "." => {}
            ".." => {
                return Err(CoreError::InvalidGrant(format!(
                    "grant root climbs above its scope: {raw:?}"
                )));
            }
            c => parts.push(c),
        }
    }
    Ok(parts.join("/"))
}

/// Returns `true` when normalized `root` covers normalized env-relative
/// `rel`: exact match or a strict path-component prefix (`logs` covers
/// `logs/a` but NOT `logs2/x`). `""` covers everything.
pub fn root_covers(root: &str, rel: &str) -> bool {
    if root.is_empty() {
        return true;
    }
    if rel == root {
        return true;
    }
    rel.strip_prefix(root)
        .is_some_and(|rest| rest.starts_with('/'))
}

/// Normalize a program name for policy comparison: basename (split on both
/// `/` and `\` so Windows-style paths match on any host), ASCII-lowercased,
/// with a single trailing `.exe` stripped.
///
/// This is the single canonical normalization shared by the daemon's
/// execution policy and grant matching, so the two cannot drift: an allow
/// entry of `git` matches `git`, `git.exe`, `GIT`, and `/usr/bin/git`.
/// It is NOT a sandbox boundary (renamed copies bypass basename checks —
/// documented Gate 5 limitation, unchanged by Gate 8).
pub fn normalize_program_name(raw: &str) -> String {
    let base = raw.rsplit(['/', '\\']).next().unwrap_or(raw);
    let lower = base.to_ascii_lowercase();
    lower.strip_suffix(".exe").unwrap_or(&lower).to_string()
}

/// Returns `true` when `grants` authorize `kind` on normalized env-relative
/// `rel_path`.
pub fn grants_allow_fs(grants: &[Grant], kind: FsGrantKind, rel_path: &str) -> bool {
    grants.iter().any(|grant| match (grant, kind) {
        (Grant::FilesystemRead { root }, FsGrantKind::Read) => root_covers(root, rel_path),
        (Grant::FilesystemWrite { root }, FsGrantKind::Write) => root_covers(root, rel_path),
        (Grant::FilesystemList { root }, FsGrantKind::List) => root_covers(root, rel_path),
        _ => false,
    })
}

/// Returns `true` when `grants` authorize executing `program` (matched by
/// normalized basename against every `ProcessExecute` entry).
pub fn grants_allow_exec(grants: &[Grant], program: &str) -> bool {
    let want = normalize_program_name(program);
    if want.is_empty() {
        return false;
    }
    grants.iter().any(|grant| match grant {
        Grant::ProcessExecute { programs } => programs
            .iter()
            .any(|entry| normalize_program_name(entry) == want),
        _ => false,
    })
}

/// Returns `true` when `grants` contain `ProcessInspect`.
pub fn grants_allow_inspect(grants: &[Grant]) -> bool {
    grants
        .iter()
        .any(|grant| matches!(grant, Grant::ProcessInspect))
}

/// Returns `true` when `grants` contain `ProcessTerminate` (also gates
/// `wait`, which observes terminal output).
pub fn grants_allow_terminate(grants: &[Grant]) -> bool {
    grants
        .iter()
        .any(|grant| matches!(grant, Grant::ProcessTerminate))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn normalize_grant_root_cases() {
        assert_eq!(normalize_grant_root("").unwrap(), "");
        assert_eq!(normalize_grant_root(".").unwrap(), "");
        assert_eq!(normalize_grant_root("logs").unwrap(), "logs");
        assert_eq!(normalize_grant_root("/logs/").unwrap(), "logs");
        assert_eq!(normalize_grant_root("a\\b").unwrap(), "a/b");
        assert_eq!(normalize_grant_root("a//b").unwrap(), "a/b");
        assert_eq!(normalize_grant_root("./a/./b").unwrap(), "a/b");
        assert_eq!(normalize_grant_root("a/b/").unwrap(), "a/b");
    }

    #[test]
    fn normalize_grant_root_rejects_climb() {
        for bad in ["..", "a/../b", "a/..", "../logs", "logs/../../x"] {
            assert!(
                normalize_grant_root(bad).is_err(),
                "climbing root {bad:?} must be rejected"
            );
        }
    }

    #[test]
    fn root_covers_component_wise() {
        // "" covers everything, including itself.
        assert!(root_covers("", ""));
        assert!(root_covers("", "anything/at/all"));
        // Exact match.
        assert!(root_covers("logs", "logs"));
        // Strict component prefix.
        assert!(root_covers("logs", "logs/a"));
        assert!(root_covers("logs", "logs/a/b"));
        // Sibling-prefix is NOT covered (the `logs` vs `logs2` edge).
        assert!(!root_covers("logs", "logs2"));
        assert!(!root_covers("logs", "logs2/x"));
        assert!(!root_covers("logs", "log"));
        assert!(!root_covers("logs", "other"));
        assert!(!root_covers("logs", ""));
        // Nested roots.
        assert!(root_covers("a/b", "a/b/c"));
        assert!(!root_covers("a/b", "a/bc"));
        assert!(!root_covers("a/b", "a"));
    }

    #[test]
    fn normalize_program_name_cases() {
        assert_eq!(normalize_program_name("cargo"), "cargo");
        assert_eq!(normalize_program_name("Cargo"), "cargo");
        assert_eq!(normalize_program_name("git.exe"), "git");
        assert_eq!(normalize_program_name("GIT.EXE"), "git");
        assert_eq!(normalize_program_name("/usr/bin/cargo"), "cargo");
        assert_eq!(normalize_program_name("./shutdown"), "shutdown");
        assert_eq!(
            normalize_program_name("C:\\Windows\\System32\\cmd.exe"),
            "cmd"
        );
        assert_eq!(normalize_program_name("..\\reboot"), "reboot");
        assert_eq!(normalize_program_name(""), "");
    }

    fn sample_grants() -> Vec<Grant> {
        vec![
            Grant::FilesystemRead {
                root: "logs".into(),
            },
            Grant::FilesystemWrite {
                root: "project".into(),
            },
            Grant::FilesystemList {
                root: String::new(),
            },
            Grant::ProcessExecute {
                programs: vec!["cargo".into(), "Git".into()],
            },
            Grant::ProcessInspect,
        ]
    }

    #[test]
    fn grants_allow_fs_read_write_list() {
        let grants = sample_grants();
        // Read is scoped to logs/.
        assert!(grants_allow_fs(&grants, FsGrantKind::Read, "logs"));
        assert!(grants_allow_fs(&grants, FsGrantKind::Read, "logs/a.txt"));
        assert!(!grants_allow_fs(&grants, FsGrantKind::Read, "logs2/x"));
        assert!(!grants_allow_fs(&grants, FsGrantKind::Read, "project/a"));
        // Write is scoped to project/ (delete folds in — same scope).
        assert!(grants_allow_fs(&grants, FsGrantKind::Write, "project"));
        assert!(grants_allow_fs(&grants, FsGrantKind::Write, "project/a"));
        assert!(!grants_allow_fs(&grants, FsGrantKind::Write, "logs/a"));
        // List covers the whole root ("").
        assert!(grants_allow_fs(&grants, FsGrantKind::List, "logs"));
        assert!(grants_allow_fs(&grants, FsGrantKind::List, "project/deep"));
        assert!(grants_allow_fs(&grants, FsGrantKind::List, ""));
        // Kinds do not cross-authorize.
        assert!(!grants_allow_fs(&grants, FsGrantKind::Read, "project/a"));
        assert!(!grants_allow_fs(&grants, FsGrantKind::Write, "logs/a.txt"));
    }

    #[test]
    fn grants_allow_fs_empty_grants_deny() {
        let empty: Vec<Grant> = vec![];
        assert!(!grants_allow_fs(&empty, FsGrantKind::Read, "logs"));
        assert!(!grants_allow_fs(&empty, FsGrantKind::Write, ""));
        assert!(!grants_allow_fs(&empty, FsGrantKind::List, ""));
    }

    #[test]
    fn grants_allow_exec_matches_basename_case_insensitively() {
        let grants = sample_grants();
        assert!(grants_allow_exec(&grants, "cargo"));
        assert!(grants_allow_exec(&grants, "CARGO"));
        assert!(grants_allow_exec(&grants, "/usr/bin/cargo"));
        assert!(grants_allow_exec(&grants, "git.exe"));
        assert!(grants_allow_exec(&grants, "GIT"));
        assert!(!grants_allow_exec(&grants, "shutdown"));
        assert!(!grants_allow_exec(&grants, ""));
        assert!(!grants_allow_exec(&grants, "cargo-extra"));
    }

    #[test]
    fn grants_allow_exec_empty_programs_deny() {
        let grants = vec![Grant::ProcessExecute { programs: vec![] }];
        assert!(!grants_allow_exec(&grants, "cargo"));
        let empty: Vec<Grant> = vec![];
        assert!(!grants_allow_exec(&empty, "cargo"));
    }

    #[test]
    fn grants_allow_inspect_terminate() {
        let grants = sample_grants();
        assert!(grants_allow_inspect(&grants));
        assert!(!grants_allow_terminate(&grants));
        let full = vec![Grant::ProcessTerminate];
        assert!(!grants_allow_inspect(&full));
        assert!(grants_allow_terminate(&full));
        let empty: Vec<Grant> = vec![];
        assert!(!grants_allow_inspect(&empty));
        assert!(!grants_allow_terminate(&empty));
    }

    #[test]
    fn grant_serde_roundtrip() {
        let cases = vec![
            Grant::FilesystemRead {
                root: "logs".into(),
            },
            Grant::FilesystemWrite { root: "".into() },
            Grant::FilesystemList { root: "a/b".into() },
            Grant::ProcessExecute {
                programs: vec!["cargo".into()],
            },
            Grant::ProcessInspect,
            Grant::ProcessTerminate,
        ];
        for grant in cases {
            let json = serde_json::to_string(&grant).unwrap();
            let back: Grant = serde_json::from_str(&json).unwrap();
            assert_eq!(grant, back);
        }
        // Adjacently-tagged shape, mirroring RpcResponsePayload.
        let json = serde_json::to_string(&Grant::FilesystemRead {
            root: "logs".into(),
        })
        .unwrap();
        assert!(json.contains("filesystem_read"), "got: {json}");
        let json = serde_json::to_string(&Grant::ProcessInspect).unwrap();
        assert!(json.contains("process_inspect"), "got: {json}");
    }
}
