//! Grants-file configuration (Gate 8).
//!
//! `--grants-file` points at JSON of the form:
//!
//! ```json
//! {
//!   "principals": {
//!     "blake3:<64hex>": {
//!       "filesystem_read": ["logs"],
//!       "filesystem_write": ["project"],
//!       "filesystem_list": ["", "logs"],
//!       "process_execute": ["cargo", "git"]
//!     }
//!   }
//! }
//! ```
//!
//! Full schema, normalization rules, and examples live in
//! `docs/grants.md` (the normative schema doc).
//!
//! # Strictness contract
//!
//! - No grants file → legacy-permissive (loud WARN at startup, dev only).
//! - File present → STRICT: unknown fingerprints get `GetEnvironmentInfo`
//!   only; known fingerprints get exactly their grants (nothing more).
//! - Malformed file (bad JSON, unknown fields, climbing `..` roots, empty
//!   program entries, malformed fingerprint keys) → refuse to start. A
//!   typo'd capability must never silently narrow to "no access" or widen
//!   to "full access" — hence `deny_unknown_fields` plus validation, and a
//!   process exit (not a fallback) on any load error.
//!
//! There is deliberately no privilege/user field: `process.execute: user =
//! www-data` setuid-style scoping is DEFERRED (no privilege management in
//! Gate 8 — documented in `docs/grants.md`). Unknown fields such as a
//! future `run_as` are rejected today so they cannot be mistaken for
//! enforced scoping later.

use std::collections::HashMap;
use std::path::Path;

use are_core::{normalize_grant_root, normalize_program_name, Grant};

/// Raw per-principal grants as written in the JSON file.
///
/// Unknown fields are REJECTED (`deny_unknown_fields`): a misspelled scope
/// (`filesystem_red`) or a future capability (`service.restart`,
/// `run_as`, ...) must fail the load loudly, never parse as "no grant".
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPrincipalGrants {
    /// Env-relative read roots (`""` = whole root).
    #[serde(default)]
    filesystem_read: Vec<String>,
    /// Env-relative write roots (delete folds in).
    #[serde(default)]
    filesystem_write: Vec<String>,
    /// Env-relative list roots.
    #[serde(default)]
    filesystem_list: Vec<String>,
    /// Allowed program names (normalized basename match).
    #[serde(default)]
    process_execute: Vec<String>,
    /// Presence gates `process_status`.
    #[serde(default)]
    process_inspect: bool,
    /// Presence gates `terminate_process` and `wait_process`.
    #[serde(default)]
    process_terminate: bool,
}

/// Raw grants file envelope. Unknown top-level fields are rejected too.
#[derive(Debug, Clone, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGrantsFile {
    #[serde(default)]
    principals: HashMap<String, RawPrincipalGrants>,
}

/// Normalized, validated grants table: fingerprint → grants.
///
/// Roots are normalized ([`normalize_grant_root`]); program entries are
/// validated non-empty (normalization itself happens at match time on both
/// sides via [`are_core::normalize_program_name`], so entries and requests
/// compare canonically wherever they were written).
#[derive(Debug, Clone, Default)]
pub struct GrantsTable {
    principals: HashMap<String, Vec<Grant>>,
}

impl GrantsTable {
    /// Load and validate a grants file. Any problem is a `String` for
    /// human-facing startup errors — the daemon refuses to start.
    pub fn load_from_file(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("failed to read grants file {}: {e}", path.display()))?;
        Self::parse_json(&text).map_err(|e| format!("{}: {e}", path.display()))
    }

    /// Parse and validate grants JSON (file I/O separated for testability).
    pub fn parse_json(text: &str) -> Result<Self, String> {
        let raw: RawGrantsFile =
            serde_json::from_str(text).map_err(|e| format!("invalid grants JSON: {e}"))?;
        let mut principals = HashMap::with_capacity(raw.principals.len());
        for (fingerprint, grants) in raw.principals {
            validate_fingerprint(&fingerprint)?;
            let mut normalized = Vec::new();
            for root in grants.filesystem_read {
                let root = normalize_grant_root(&root).map_err(|e| {
                    format!("principal {fingerprint}: bad filesystem_read root: {e}")
                })?;
                normalized.push(Grant::FilesystemRead { root });
            }
            for root in grants.filesystem_write {
                let root = normalize_grant_root(&root).map_err(|e| {
                    format!("principal {fingerprint}: bad filesystem_write root: {e}")
                })?;
                normalized.push(Grant::FilesystemWrite { root });
            }
            for root in grants.filesystem_list {
                let root = normalize_grant_root(&root).map_err(|e| {
                    format!("principal {fingerprint}: bad filesystem_list root: {e}")
                })?;
                normalized.push(Grant::FilesystemList { root });
            }
            if !grants.process_execute.is_empty() {
                let mut programs = Vec::with_capacity(grants.process_execute.len());
                for entry in grants.process_execute {
                    if normalize_program_name(&entry).is_empty() {
                        return Err(format!(
                            "principal {fingerprint}: empty process_execute entry"
                        ));
                    }
                    programs.push(entry);
                }
                normalized.push(Grant::ProcessExecute { programs });
            }
            if grants.process_inspect {
                normalized.push(Grant::ProcessInspect);
            }
            if grants.process_terminate {
                normalized.push(Grant::ProcessTerminate);
            }
            principals.insert(fingerprint, normalized);
        }
        Ok(Self { principals })
    }

    /// Grants for a fingerprint, or `None` when the principal is unknown.
    pub fn grants_for(&self, fingerprint: &str) -> Option<&[Grant]> {
        self.principals.get(fingerprint).map(Vec::as_slice)
    }

    /// Whether the fingerprint has an entry (even an empty-grants one).
    pub fn is_known(&self, fingerprint: &str) -> bool {
        self.principals.contains_key(fingerprint)
    }

    /// Number of principals in the table.
    pub fn len(&self) -> usize {
        self.principals.len()
    }

    /// Whether the table holds no principals.
    pub fn is_empty(&self) -> bool {
        self.principals.is_empty()
    }
}

/// Fingerprint keys must look like fingerprints (`blake3:` + 64 hex).
/// A pasted CN, a truncated hash, or a typo would otherwise never match and
/// silently lock the principal out — refuse the file instead.
fn validate_fingerprint(fp: &str) -> Result<(), String> {
    let hex = fp.strip_prefix("blake3:").ok_or_else(|| {
        format!("malformed principal fingerprint {fp:?}: expected \"blake3:<64 hex>\"")
    })?;
    if hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(format!(
            "malformed principal fingerprint {fp:?}: expected \"blake3:<64 hex>\""
        ))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use are_core::{grants_allow_exec, grants_allow_fs, FsGrantKind};

    const FP_A: &str = "blake3:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const FP_B: &str = "blake3:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

    fn sample_json() -> String {
        format!(
            r#"{{
                "principals": {{
                    "{FP_A}": {{
                        "filesystem_read": ["logs", ".", "/project/"],
                        "filesystem_write": ["project"],
                        "filesystem_list": [""],
                        "process_execute": ["cargo", "Git"],
                        "process_inspect": true,
                        "process_terminate": true
                    }},
                    "{FP_B}": {{
                        "filesystem_read": ["logs"]
                    }}
                }}
            }}"#
        )
    }

    #[test]
    fn parse_valid_file_normalizes() {
        let table = GrantsTable::parse_json(&sample_json()).unwrap();
        assert_eq!(table.len(), 2);
        assert!(table.is_known(FP_A));
        assert!(table.is_known(FP_B));
        assert!(!table.is_known("blake3:cccc"));
        let a = table.grants_for(FP_A).unwrap();
        // "." and "/project/" normalize to "" and "project".
        assert!(grants_allow_fs(a, FsGrantKind::Read, "logs/x"));
        assert!(grants_allow_fs(a, FsGrantKind::Read, "anything"));
        assert!(grants_allow_fs(a, FsGrantKind::Write, "project/a"));
        assert!(grants_allow_fs(a, FsGrantKind::List, "logs"));
        assert!(grants_allow_exec(a, "cargo"));
        assert!(grants_allow_exec(a, "git.exe"));
        let b = table.grants_for(FP_B).unwrap();
        assert!(grants_allow_fs(b, FsGrantKind::Read, "logs/x"));
        assert!(!grants_allow_fs(b, FsGrantKind::Read, "project/x"));
        assert!(!grants_allow_exec(b, "cargo"));
    }

    #[test]
    fn parse_rejects_unknown_fields() {
        // Misspelled scope must not silently parse as "no grant".
        let bad = format!(r#"{{"principals": {{"{FP_A}": {{"filesystem_red": ["logs"]}}}}}}"#);
        assert!(GrantsTable::parse_json(&bad).is_err());
        // Future capabilities must not sneak in either.
        let bad = format!(r#"{{"principals": {{"{FP_A}": {{"service_restart": true}}}}}}"#);
        assert!(GrantsTable::parse_json(&bad).is_err());
        let bad = r#"{"principals": {}, "run_as": "www-data"}"#;
        assert!(GrantsTable::parse_json(bad).is_err());
    }

    #[test]
    fn parse_rejects_bad_roots_programs_fingerprints() {
        // Climbing root.
        let bad = format!(r#"{{"principals": {{"{FP_A}": {{"filesystem_read": [".."]}}}}}}"#);
        assert!(GrantsTable::parse_json(&bad).is_err());
        // Empty program entry.
        let bad = format!(r#"{{"principals": {{"{FP_A}": {{"process_execute": [""]}}}}}}"#);
        assert!(GrantsTable::parse_json(&bad).is_err());
        // Malformed fingerprint key.
        let bad = r#"{"principals": {"not-a-fingerprint": {}}}"#;
        assert!(GrantsTable::parse_json(bad).is_err());
        let bad = r#"{"principals": {"blake3:short": {}}}"#;
        assert!(GrantsTable::parse_json(bad).is_err());
        // Invalid JSON.
        assert!(GrantsTable::parse_json("{oops").is_err());
    }

    #[test]
    fn parse_empty_file_is_empty_table() {
        let table = GrantsTable::parse_json(r#"{"principals": {}}"#).unwrap();
        assert!(table.is_empty());
        let table = GrantsTable::parse_json(r#"{}"#).unwrap();
        assert!(table.is_empty());
    }

    #[test]
    fn load_missing_file_errors() {
        let err = GrantsTable::load_from_file(Path::new("/no/such/grants.json")).unwrap_err();
        assert!(err.contains("failed to read"), "got: {err}");
    }
}
