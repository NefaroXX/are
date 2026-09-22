//! Filesystem backend with strict path security enforcement.
//!
//! This module implements the core security layer for filesystem operations.
//! Every path is resolved against configured allowed roots, with comprehensive
//! protection against:
//!
//! - **Path traversal** (`../` attacks) — resolved via canonicalization + prefix check
//! - **Symlink traversal** — `std::fs::canonicalize` resolves symlinks; any symlink
//!   pointing outside the allowed root is rejected
//! - **Filesystem boundary escape** — canonical target must be a prefix of a canonical root
//! - **TOCTOU issues** — after resolve, operations execute on the canonical path directly
//!   without re-resolving
//!
//! # Design decisions (ADR-002)
//!
//! All paths are environment-relative, resolved against the daemon's configured
//! workspace root. Absolute host paths are rejected by default.
//!
//! # Gate 7: symlink follow/no-follow matrix
//!
//! POSIX-like, documented per operation:
//!
//! | Operation | Final-component symlink | Parent-component symlink |
//! |-----------|-------------------------|--------------------------|
//! | `read_file`, `file_metadata`, `list_directory` | FOLLOWED (then boundary-checked; escape → rejected) | FOLLOWED + checked |
//! | `write_file` | FOLLOWED (then boundary-checked). Writing through an in-root link writes the target; a link escaping the root is rejected. | FOLLOWED + checked (writing via an escaping dir-link is rejected) |
//! | `rename` (src and dst) | NOT followed: the LINK itself is renamed, the target is untouched. | FOLLOWED + checked |
//! | `delete` | NOT followed: the LINK itself is removed, the target is intact. `resolve()` (which follows) is NEVER used here — deleting via a canonicalized path would delete the TARGET. | FOLLOWED + checked |
//! | `create_directory` | N/A (created dirs are real). Intermediate components are verified prefix-by-prefix (see `ensure_dir_under_root`): an escaping symlink in the middle is rejected, never followed for creation. | VERIFIED per prefix |
//!
//! # Gate 7: hash policy
//!
//! Single-file ops (`read_file`, `write_file`, `file_metadata`, rename-dst
//! metadata) return a BLAKE3-256 hex content hash. `file_metadata` on a file
//! larger than `max_file_bytes` returns `hash: None` (metadata must not fail
//! just for being big; the content could not be bounded-read). `list_directory`
//! entries ALWAYS carry `hash: None` — hashing a listing is O(total bytes).
//!
//! # Gate 7: deliberate refusals
//!
//! - NO recursive delete, ever. Non-empty directories fail with `Conflict`
//!   and are left intact (agent-safety rule).
//! - `rename` onto an existing destination fails with `Conflict` (no silent
//!   overwrite).
//! - `write_file` with `overwrite: false` onto an existing file fails with
//!   `Conflict`; a stale `expected_hash` (or one given for a missing file)
//!   fails with `Conflict` whose message reveals nothing about the content.

use std::path::PathBuf;

use are_core::{DirectoryEntry, FileMetadata};
use tokio::fs;

/// Errors from filesystem operations.
#[derive(Debug, thiserror::Error)]
pub enum FsError {
    /// The path is empty, absolute, or otherwise invalid.
    #[error("invalid path: {0}")]
    InvalidPath(String),

    /// The resolved path escapes the allowed filesystem boundary.
    #[error("path escapes allowed boundary: {0}")]
    FilesystemEscape(String),

    /// The target does not exist.
    #[error("not found: {0}")]
    NotFound(String),

    /// Permission denied by the OS.
    #[error("permission denied: {0}")]
    PermissionDenied(String),

    /// Expected a directory but found a file.
    #[error("not a directory: {0}")]
    NotADirectory(String),

    /// Expected a file but found a directory.
    #[error("is a directory: {0}")]
    IsADirectory(String),

    /// File exceeds the configured size limit.
    #[error("file too large: {size} bytes exceeds limit {limit} bytes ({path})")]
    FileTooLarge {
        /// The path that was rejected.
        path: String,
        /// Actual file size in bytes.
        size: u64,
        /// Configured limit in bytes.
        limit: u64,
    },

    /// Well-formed request refused by current filesystem state: stale
    /// `expected_hash`, `overwrite: false` onto an existing file, rename
    /// onto an existing destination, `mkdir` where a file exists, or delete
    /// of a non-empty directory. Retry-identical will fail identically —
    /// re-read first.
    #[error("conflict: {0}")]
    Conflict(String),

    /// An I/O error occurred.
    #[error("I/O error: {0}")]
    Io(String),
}

impl From<std::io::Error> for FsError {
    fn from(e: std::io::Error) -> Self {
        match e.kind() {
            std::io::ErrorKind::NotFound => FsError::NotFound(e.to_string()),
            std::io::ErrorKind::PermissionDenied => FsError::PermissionDenied(e.to_string()),
            _ => FsError::Io(e.to_string()),
        }
    }
}

/// Filesystem configuration: defines the allowed roots for path resolution.
///
/// All roots must be canonicalized at construction time. The filesystem backend
/// will only serve files that resolve to a location under one of these roots.
#[derive(Debug, Clone)]
pub struct FilesystemConfig {
    /// Canonicalized allowed root directories. Must be non-empty.
    pub allowed_roots: Vec<PathBuf>,
    /// Maximum file size in bytes for `read_file`. Files exceeding this limit
    /// are rejected before loading into memory. Default: 16 MiB.
    pub max_file_bytes: usize,
}

/// Default maximum file size: 16 MiB (matches the framing layer limit).
const DEFAULT_MAX_FILE_BYTES: usize = 16 * 1024 * 1024;

impl FilesystemConfig {
    /// Create a new config, canonicalizing the given root paths.
    ///
    /// Uses the default 16 MiB file-size limit. Use `with_max_file_bytes` to
    /// override.
    ///
    /// # Errors
    ///
    /// Returns an error if no roots are provided, or if any root path cannot
    /// be canonicalized (e.g., does not exist).
    pub fn new(roots: &[PathBuf]) -> Result<Self, FsError> {
        Self::with_max_file_bytes(roots, DEFAULT_MAX_FILE_BYTES)
    }

    /// Create a new config with an explicit file-size limit.
    ///
    /// # Errors
    ///
    /// Returns an error if no roots are provided, or if any root path cannot
    /// be canonicalized (e.g., does not exist).
    pub fn with_max_file_bytes(roots: &[PathBuf], max_file_bytes: usize) -> Result<Self, FsError> {
        if roots.is_empty() {
            return Err(FsError::InvalidPath(
                "at least one allowed root must be configured".into(),
            ));
        }

        let mut canonical = Vec::with_capacity(roots.len());
        for root in roots {
            let c = std::fs::canonicalize(root).map_err(|e| {
                FsError::InvalidPath(format!(
                    "failed to canonicalize root '{}': {e}",
                    root.display()
                ))
            })?;
            canonical.push(c);
        }

        Ok(Self {
            allowed_roots: canonical,
            max_file_bytes,
        })
    }
}

/// Compute the BLAKE3-256 hex digest of in-memory bytes.
///
/// BLAKE3 was chosen over SHA-256 (sha2 crate) because it is faster
/// (tree mode, SIMD), pure-Rust with no assembly risk surface beyond its
/// audited core, and already a de-facto standard for content hashing
/// (used by Bazel-adjacent tooling, b3sum). `are-core` stays crypto-free:
/// it stores the digest as an opaque `String` and only shape-checks it.
pub fn hash_bytes(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

/// Reject empty paths, absolute paths (Unix `/`, Windows `\`, drive
/// letters), and NUL bytes. Shared by `resolve` and `resolve_no_follow`
/// so both primitives enforce the identical ADR-002 shape bar.
fn check_path_shape(path: &str) -> Result<(), FsError> {
    if path.is_empty() {
        return Err(FsError::InvalidPath("path must not be empty".into()));
    }
    if path.contains('\0') {
        return Err(FsError::InvalidPath("path must not contain NUL".into()));
    }
    if path.starts_with('/') || path.starts_with('\\') {
        return Err(FsError::InvalidPath(format!(
            "absolute path rejected: {path}"
        )));
    }
    // Windows drive letter check: "C:\..." or "C:/...".
    // Always compiled so that paths like "C:/secret" are rejected on all
    // platforms (the check is a harmless no-op on Unix since ':' never
    // appears in a relative path component there).
    {
        let bytes = path.as_bytes();
        if bytes.len() >= 2 && bytes[1] == b':' {
            return Err(FsError::InvalidPath(format!(
                "absolute path rejected: {path}"
            )));
        }
    }
    Ok(())
}

/// Filesystem backend with strict path security.
///
/// All operations go through `resolve()` to ensure paths stay within the
/// configured allowed roots. Symlinks are resolved and checked. TOCTOU is
/// mitigated by operating on the canonical path directly after resolution.
#[derive(Debug, Clone)]
pub struct FilesystemBackend {
    config: FilesystemConfig,
}

impl FilesystemBackend {
    /// Create a new filesystem backend with the given configuration.
    pub fn new(config: FilesystemConfig) -> Self {
        Self { config }
    }

    /// Resolve an environment-relative path to a canonical path within the
    /// allowed roots.
    ///
    /// # Security guarantees
    ///
    /// - Empty paths are rejected.
    /// - Absolute paths (starting with `/`, `\`, or a Windows drive letter) are
    ///   rejected per ADR-002.
    /// - `..` traversal is neutralized by canonicalization.
    /// - Symlinks that escape the root are rejected.
    /// - If the target does not exist, the parent directory is canonicalized
    ///   and checked, preventing TOCTOU on the leaf component.
    pub fn resolve(&self, path: &str) -> Result<PathBuf, FsError> {
        // 1-2. Shape checks (empty / absolute / drive letter / NUL).
        check_path_shape(path)?;

        // 3. Try to resolve against each allowed root.
        let candidate = PathBuf::from(path);

        for root in &self.config.allowed_roots {
            let joined = root.join(&candidate);

            // Attempt to canonicalize the joined path.
            match std::fs::canonicalize(&joined) {
                Ok(canonical) => {
                    // Verify the canonical path is under the root.
                    if canonical.starts_with(root) {
                        return Ok(canonical);
                    }
                    // Symlink or traversal escaped the root. The remote-facing
                    // error is generic: canonical paths must not reach
                    // clients. Full paths go only to server-side logs here.
                    tracing::debug!(
                        canonical = %canonical.display(),
                        root = %root.display(),
                        "path escapes root"
                    );
                    return Err(FsError::FilesystemEscape(
                        "path escapes allowed boundary".into(),
                    ));
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // Target doesn't exist — validate the parent directory instead.
                    // This prevents TOCTOU: we verify the parent is within the root,
                    // then join the leaf without canonicalizing it.
                    if let Some(parent) = joined.parent() {
                        match std::fs::canonicalize(parent) {
                            Ok(canonical_parent) => {
                                if canonical_parent.starts_with(root) {
                                    // Parent is safe. The leaf is just a name (no traversal).
                                    return Ok(canonical_parent.join(
                                        joined.file_name().ok_or_else(|| {
                                            FsError::InvalidPath(format!(
                                                "no file name in path: {path}"
                                            ))
                                        })?,
                                    ));
                                }
                                // Parent escaped — this shouldn't happen if the root is valid,
                                // but be defensive. Remote-facing error stays
                                // generic; paths go only to the log above.
                                tracing::debug!(
                                    canonical_parent = %canonical_parent.display(),
                                    root = %root.display(),
                                    "parent escapes root"
                                );
                                return Err(FsError::FilesystemEscape(
                                    "path escapes allowed boundary".into(),
                                ));
                            }
                            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                                // Parent doesn't exist either — try next root or fail.
                                continue;
                            }
                            // Non-NotFound canonicalize failure (permission,
                            // ENOTDIR, ...). The remote-facing error must
                            // never embed a path — not even the relative
                            // request — so it stays generic; the full detail
                            // goes to server-side logs only.
                            Err(e) => {
                                tracing::debug!(
                                    requested = %path,
                                    error = %e,
                                    "cannot canonicalize parent under any allowed root"
                                );
                                return Err(FsError::Io(
                                    "failed to resolve parent directory".into(),
                                ));
                            }
                        }
                    } else {
                        return Err(FsError::InvalidPath(format!(
                            "no parent directory in path: {path}"
                        )));
                    }
                }
                Err(e) => {
                    // Non-NotFound canonicalize failure (permission,
                    // ENOTDIR, ...). Generic remote-facing message — the
                    // requested path and OS detail are log-only.
                    tracing::debug!(
                        requested = %path,
                        error = %e,
                        "cannot resolve path under any allowed root"
                    );
                    return Err(FsError::Io("failed to resolve path".into()));
                }
            }
        }

        // Generic remote-facing message (no client path echo, no canonical
        // paths); the failing path is server-side log detail only.
        tracing::debug!(path = %path, "path does not resolve under any allowed root");
        Err(FsError::FilesystemEscape(
            "path escapes allowed boundary".into(),
        ))
    }

    /// Resolve a path WITHOUT following the final component.
    ///
    /// The parent chain is canonicalized (following parent symlinks) and
    /// boundary-checked; the leaf name is then joined WITHOUT canonicalizing
    /// it. Used by `rename` and `delete`, which must operate on a symlink
    /// LINK itself rather than its target (POSIX `rename`/`unlink` don't
    /// follow the final component; following it here would rename/delete
    /// the target — an escape when the link points outside the root).
    ///
    /// With multiple allowed roots the parent is accepted under the first
    /// root that canonicalizes inside its boundary. A parent missing under
    /// every root yields `NotFound` (not an escape: nothing resolved).
    pub fn resolve_no_follow(&self, path: &str) -> Result<PathBuf, FsError> {
        check_path_shape(path)?;

        let requested = PathBuf::from(path);
        let leaf = requested
            .file_name()
            .ok_or_else(|| FsError::InvalidPath(format!("no file name in path: {path}")))?;
        if leaf == "." || leaf == ".." {
            return Err(FsError::InvalidPath(format!(
                "invalid file name in path: {path}"
            )));
        }
        let parent = requested
            .parent()
            .map_or_else(|| PathBuf::from(""), std::path::Path::to_path_buf);

        let mut parent_missing_everywhere = false;
        for root in &self.config.allowed_roots {
            let joined_parent = if parent.as_os_str().is_empty() {
                root.clone()
            } else {
                root.join(&parent)
            };
            match std::fs::canonicalize(&joined_parent) {
                Ok(canonical_parent) => {
                    if canonical_parent.starts_with(root) {
                        return Ok(canonical_parent.join(leaf));
                    }
                    tracing::debug!(
                        canonical_parent = %canonical_parent.display(),
                        root = %root.display(),
                        "parent escapes root"
                    );
                    return Err(FsError::FilesystemEscape(
                        "path escapes allowed boundary".into(),
                    ));
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    parent_missing_everywhere = true;
                    continue;
                }
                Err(e) => {
                    // Non-NotFound canonicalize failure (permission,
                    // ENOTDIR, ...). The joined parent embeds the allowed
                    // ROOT — an absolute host path that must never reach a
                    // client. Generic message; detail is log-only.
                    tracing::debug!(
                        requested = %path,
                        error = %e,
                        "cannot canonicalize parent under any allowed root"
                    );
                    return Err(FsError::Io("failed to resolve parent directory".into()));
                }
            }
        }

        if parent_missing_everywhere {
            return Err(FsError::NotFound(format!("parent does not exist: {path}")));
        }
        tracing::debug!(path = %path, "path does not resolve under any allowed root");
        Err(FsError::FilesystemEscape(
            "path escapes allowed boundary".into(),
        ))
    }

    /// Ensure a directory (and all missing ancestors) exists under the
    /// primary allowed root, verifying each prefix.
    ///
    /// DANGER this defeats: `create_dir_all` follows symlinks in
    /// intermediate components, so a `link -> /outside` mid-path would
    /// create directories OUTSIDE the root. Instead we walk the requested
    /// relative components one by one: each existing prefix is
    /// canonicalized + boundary-checked (Gate 4 semantics); each missing
    /// prefix is created with `create_dir` on the already-verified parent
    /// (a just-created directory is real — no symlink possible — though a
    /// concurrent swap between our check and a later prefix remains a
    /// best-effort TOCTOU window, documented).
    ///
    /// An existing final directory is success (idempotent); an existing
    /// final FILE is `Conflict`. Multi-root configs create under the
    /// primary (first) root — documented, not ambiguous.
    fn ensure_dir_under_root(&self, path: &str) -> Result<PathBuf, FsError> {
        check_path_shape(path)?;

        let root = self
            .config
            .allowed_roots
            .first()
            .ok_or_else(|| FsError::InvalidPath("no allowed roots configured".into()))?;
        let requested = PathBuf::from(path);

        // Walk components; reject `.`/`..`/absolute prefixes explicitly
        // (canonicalization alone would normalize `a/../b` into `b`, which
        // is safe but surprising — fail closed on `..` in creation paths).
        let mut rel = PathBuf::new();
        for comp in requested.components() {
            use std::path::Component::{CurDir, Normal, ParentDir, Prefix, RootDir};
            match comp {
                Normal(c) => rel.push(c),
                CurDir => {}
                ParentDir | RootDir | Prefix(_) => {
                    return Err(FsError::InvalidPath(format!(
                        "invalid component in directory path: {path}"
                    )));
                }
            }
        }
        if rel.as_os_str().is_empty() {
            return Err(FsError::InvalidPath(format!(
                "no directory name in path: {path}"
            )));
        }

        // Walk prefixes: verify-or-create each level.
        let comps: Vec<std::ffi::OsString> = rel
            .components()
            .map(|c| c.as_os_str().to_os_string())
            .collect();
        let mut current = root.clone();
        for (i, comp) in comps.iter().enumerate() {
            let is_final = i + 1 == comps.len();
            current.push(comp);
            match std::fs::symlink_metadata(&current) {
                Ok(meta) => {
                    // Exists: canonicalize + boundary check (catches a
                    // symlink component pointing outside).
                    let canonical = std::fs::canonicalize(&current).map_err(FsError::from)?;
                    if !canonical.starts_with(root) {
                        tracing::debug!(
                            canonical = %canonical.display(),
                            root = %root.display(),
                            "mkdir prefix escapes root"
                        );
                        return Err(FsError::FilesystemEscape(
                            "path escapes allowed boundary".into(),
                        ));
                    }
                    if is_final {
                        if meta.file_type().is_symlink() {
                            // A final symlink is followed for the
                            // existence check: link-to-dir = existing dir
                            // (idempotent success); link-to-file or
                            // dangling = conflict (creation would replace
                            // the link — refuse, never overwrite links).
                            if !canonical.is_dir() {
                                return Err(FsError::Conflict(format!(
                                    "path exists and is not a directory: {path}"
                                )));
                            }
                        } else if !meta.is_dir() {
                            // Final component exists as a file.
                            return Err(FsError::Conflict(format!(
                                "path exists and is not a directory: {path}"
                            )));
                        }
                    } else if !canonical.is_dir() {
                        return Err(FsError::NotADirectory(format!(
                            "path component is not a directory: {path}"
                        )));
                    }
                    current = canonical;
                }
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    // Missing: create on the verified parent. `current`'s
                    // parent chain was verified above (root itself is
                    // canonical by construction).
                    std::fs::create_dir(&current).map_err(FsError::from)?;
                    // Re-canonicalize so the next prefix check sees the real
                    // path (also normalizes the just-created dir).
                    current = std::fs::canonicalize(&current).map_err(FsError::from)?;
                    if !current.starts_with(root) {
                        return Err(FsError::FilesystemEscape(
                            "path escapes allowed boundary".into(),
                        ));
                    }
                }
                Err(e) => return Err(FsError::from(e)),
            }
        }
        Ok(current)
    }

    /// Read a file from the environment.
    ///
    /// Returns the file contents and metadata. Files exceeding
    /// `config.max_file_bytes` are rejected before loading into memory.
    ///
    /// The file-size cap bounds daemon memory, not the wire: `Vec<u8>`
    /// serializes as a JSON array-of-numbers (~4x expansion), so even a
    /// capped file can serialize past the 16 MiB framing limit. The
    /// transport-layer response-size guard (`framing::write_message_sized`)
    /// is the backstop that converts such oversize responses into a clean
    /// `RpcError::InternalError`.
    pub async fn read_file(&self, path: &str) -> Result<(Vec<u8>, FileMetadata), FsError> {
        let canonical = self.resolve(path)?;

        // Check it's a file, not a directory.
        let meta = fs::metadata(&canonical).await?;
        if meta.is_dir() {
            return Err(FsError::IsADirectory(path.to_string()));
        }

        // Reject files that exceed the configured size limit to prevent
        // memory exhaustion from oversized reads.
        //
        // NOTE (FIX 11): this cap bounds memory, not the wire. `Vec<u8>`
        // serializes as a JSON array-of-numbers (~4x expansion), so a
        // capped file can still serialize past the 16 MiB framing limit.
        // The transport-layer guard (`framing::write_message_sized`)
        // converts such oversize responses into a clean RPC error.
        let size = meta.len();
        let limit = self.config.max_file_bytes as u64;
        if size > limit {
            return Err(FsError::FileTooLarge {
                path: path.to_string(),
                size,
                limit,
            });
        }

        let content = fs::read(&canonical).await?;
        let metadata = with_content_hash(make_metadata(&meta), &content);

        Ok((content, metadata))
    }

    /// List the contents of a directory.
    pub async fn list_directory(&self, path: &str) -> Result<Vec<DirectoryEntry>, FsError> {
        let canonical = self.resolve(path)?;

        // Check it's a directory.
        let meta = fs::metadata(&canonical).await?;
        if !meta.is_dir() {
            return Err(FsError::NotADirectory(path.to_string()));
        }

        let mut entries = Vec::new();
        let mut dir = fs::read_dir(&canonical).await?;

        while let Some(entry) = dir.next_entry().await? {
            let entry_meta = entry.metadata().await?;
            let name = entry.file_name().to_string_lossy().into_owned();

            // Build environment-relative path for the entry.
            let entry_rel = if path.is_empty() || path == "." {
                name.clone()
            } else {
                format!("{}/{}", path.trim_end_matches('/'), name)
            };

            entries.push(DirectoryEntry {
                name,
                path: entry_rel,
                metadata: make_metadata(&entry_meta),
            });
        }

        Ok(entries)
    }

    /// Get metadata about a file or directory.
    ///
    /// Regular files carry a content hash (read once, bounded by
    /// `max_file_bytes`). A file LARGER than the cap returns its size with
    /// `hash: None` — metadata must not fail just for being big. Directories
    /// always carry `hash: None`.
    pub async fn file_metadata(&self, path: &str) -> Result<FileMetadata, FsError> {
        let canonical = self.resolve(path)?;
        let meta = fs::metadata(&canonical).await?;
        if meta.is_file() {
            let limit = self.config.max_file_bytes as u64;
            if meta.len() <= limit {
                let content = fs::read(&canonical).await?;
                return Ok(with_content_hash(make_metadata(&meta), &content));
            }
            // Oversized: size without hash (documented above).
            return Ok(make_metadata(&meta));
        }
        Ok(make_metadata(&meta))
    }

    /// Write a file atomically with optimistic concurrency.
    ///
    /// Steps: (a) `resolve()` the path (missing-file parent logic; a final
    /// symlink is FOLLOWED — in-root targets are written, escaping ones are
    /// rejected); (b) refuse writing to an existing directory with
    /// `IsADirectory`; (c) `overwrite: false` + existing file → `Conflict`;
    /// (d) `expected_hash: Some(h)` → read current content (missing →
    /// `Conflict`; mismatch → `Conflict` with a message that reveals
    /// nothing about the content); (e) content length capped at
    /// `max_file_bytes` → `FileTooLarge`; (f) ATOMIC COMMIT: temp file
    /// `.are-tmp-<32hex>` (CSPRNG name, same directory so the rename stays
    /// on one filesystem) → `write_all` → file `sync_all` (fsync) →
    /// best-effort parent-dir `sync_all` (ignored on platforms that reject
    /// dir sync, e.g. Windows) → atomic `rename` temp→target. Any failure
    /// removes the temp file best-effort: no strays, original intact.
    ///
    /// Crash safety: readers always see the old or the new content, never a
    /// torn write — the target path is only ever replaced by an atomic
    /// rename of a fully-synced temp file.
    pub async fn write_file(
        &self,
        path: &str,
        content: &[u8],
        overwrite: bool,
        expected_hash: Option<&str>,
    ) -> Result<FileMetadata, FsError> {
        // (e) Bound the incoming payload first (cheap, before any I/O).
        let limit = self.config.max_file_bytes as u64;
        if content.len() as u64 > limit {
            return Err(FsError::FileTooLarge {
                path: path.to_string(),
                size: content.len() as u64,
                limit,
            });
        }

        // (a) Resolve (follows a final symlink; escapes rejected).
        let canonical = self.resolve(path)?;

        // (b) Refuse directory targets.
        match fs::symlink_metadata(&canonical).await {
            Ok(meta) if meta.is_dir() => {
                return Err(FsError::IsADirectory(path.to_string()));
            }
            Ok(meta) => {
                // Existing file. `canonical` is the fully-resolved real
                // path (resolve follows final symlinks), so `meta.len()` is
                // the file's size even when reached through a symlink.
                // (c) overwrite gate.
                if !overwrite {
                    return Err(FsError::Conflict(format!(
                        "file already exists (pass overwrite to replace): {path}"
                    )));
                }
                // (d) optimistic concurrency: compare current digest.
                if let Some(expected) = expected_hash {
                    // (m3) The daemon emits lowercase hex; a client may
                    // pass uppercase (`is_valid_hash` accepts both, per
                    // the shape doc). Normalize before comparing.
                    let expected = expected.to_ascii_lowercase();
                    // (FIX 1) Stat BEFORE reading: an on-disk file larger
                    // than the cap must be refused with `FileTooLarge`
                    // WITHOUT loading it into memory — the digest compare
                    // below would otherwise allocate the whole file,
                    // turning a size check into an O(file) memory risk.
                    let limit = self.config.max_file_bytes as u64;
                    if meta.len() > limit {
                        return Err(FsError::FileTooLarge {
                            path: path.to_string(),
                            size: meta.len(),
                            limit,
                        });
                    }
                    let current = fs::read(&canonical).await.map_err(|e| match e.kind() {
                        std::io::ErrorKind::NotFound => {
                            FsError::Conflict(format!("file changed since read: {path}"))
                        }
                        _ => FsError::from(e),
                    })?;
                    if hash_bytes(&current) != expected {
                        return Err(FsError::Conflict(format!(
                            "file changed since read: {path}"
                        )));
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Missing target: expected_hash cannot match nonexistent
                // content.
                if expected_hash.is_some() {
                    return Err(FsError::Conflict(format!(
                        "file changed since read: {path}"
                    )));
                }
            }
            Err(e) => return Err(FsError::from(e)),
        }

        // Parent dir must exist (no implicit mkdir — call create_directory).
        let parent = canonical
            .parent()
            .ok_or_else(|| FsError::InvalidPath(format!("no parent directory in path: {path}")))?;
        if fs::metadata(parent).await.is_err() {
            return Err(FsError::NotFound(format!(
                "parent directory does not exist: {path}"
            )));
        }

        // (f) Atomic commit via temp file in the SAME directory. The temp
        // name is 128-bit CSPRNG; `atomic_commit` owns bounded create_new
        // retries and cleanup (no strays on any failure). `no_replace` =
        // `!overwrite`: an `overwrite: false` write must never replace a
        // concurrently-created target at the rename step.
        self.atomic_commit(parent, &canonical, content, !overwrite)
            .await?;

        // Fresh metadata WITH the new content hash.
        let meta = fs::metadata(&canonical).await?;
        Ok(with_content_hash(make_metadata(&meta), content))
    }

    /// Commit helper: create temp → write → fsync file → best-effort fsync
    /// parent dir → atomic rename.
    ///
    /// Owns the temp name and cleanup: on ANY failure the temp file is
    /// removed best-effort (no strays) and the target is never touched.
    ///
    /// `no_replace` uses an atomic no-replace rename (`renameat2
    /// RENAME_NOREPLACE` on Linux, check-then-rename fallback elsewhere) so
    /// a `Conflict` fires instead of silently replacing an existing target.
    async fn atomic_commit(
        &self,
        parent: &std::path::Path,
        target: &std::path::Path,
        content: &[u8],
        no_replace: bool,
    ) -> Result<(), FsError> {
        // create_new: never clobber a concurrent writer's temp file. Names
        // are 128-bit CSPRNG, so a collision is astronomically unlikely —
        // but on `AlreadyExists` we RE-ROLL a fresh name (bounded) rather
        // than truncate, and NEVER delete the pre-existing file: a temp
        // name that collides is not ours to remove.
        const MAX_TEMP_NAME_ATTEMPTS: u32 = 8;
        let mut attempts = 0u32;
        let (mut tmp, tmp_path) = loop {
            attempts += 1;
            if attempts > MAX_TEMP_NAME_ATTEMPTS {
                return Err(FsError::Io(format!(
                    "failed to create temporary file: \
                     {MAX_TEMP_NAME_ATTEMPTS} name collisions"
                )));
            }
            let mut rand = [0u8; 16];
            getrandom::getrandom(&mut rand)
                .map_err(|e| FsError::Io(format!("failed to generate temp name: {e}")))?;
            let tmp_name: String = rand.iter().map(|b| format!("{b:02x}")).collect();
            let tmp_path = parent.join(format!(".are-tmp-{tmp_name}"));
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp_path)
                .await
            {
                Ok(file) => break (file, tmp_path),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(FsError::from(e)),
            }
        };

        // Write + durability, then the atomic rename. From here the temp
        // file is OURS (create_new succeeded), so cleanup is safe.
        use tokio::io::AsyncWriteExt as _;
        let write_and_rename = async {
            tmp.write_all(content).await?;
            tmp.sync_all().await?;
            drop(tmp);

            // Best-effort parent-dir fsync (durability of the rename
            // itself). Opening a directory is not supported on Windows —
            // ignore errors with a comment, not silence: this is
            // durability, not correctness (atomicity holds without it).
            if let Ok(dir) = fs::File::open(parent).await {
                let _ = dir.sync_all().await;
            }

            if no_replace {
                rename_noreplace(&tmp_path, target).await
            } else {
                fs::rename(&tmp_path, target).await.map_err(FsError::from)
            }
        }
        .await;

        if write_and_rename.is_err() {
            // Best-effort temp cleanup: no strays on ANY failure path.
            let _ = fs::remove_file(&tmp_path).await;
        }
        write_and_rename
    }

    /// Create a directory and all missing ancestors (`mkdir -p`).
    ///
    /// Idempotent for existing directories; `Conflict` when the final path
    /// exists as a file. Traversal and symlink-escape components are
    /// rejected by `ensure_dir_under_root`.
    pub async fn create_directory(&self, path: &str) -> Result<FileMetadata, FsError> {
        // `ensure_dir_under_root` is synchronous `std::fs` (a handful of
        // syscalls), matching the existing style of `resolve()` — also sync
        // `std::fs` called from async contexts. No `spawn_blocking`: this
        // method is reached via the handler's `block_in_place`, where
        // spawning blocking work would nest pools pointlessly.
        let canonical = self.ensure_dir_under_root(path)?;
        let meta = fs::metadata(&canonical).await?;
        Ok(make_metadata(&meta))
    }

    /// Rename (move) a file, symlink, or directory.
    ///
    /// No-follow on BOTH ends: the src LINK is renamed (target untouched),
    /// and dst existence is tested on the link itself. `src == dst` (after
    /// no-follow resolution) → `InvalidRequest`; existing dst → `Conflict`
    /// (no silent overwrite, enforced atomically via `rename_noreplace`);
    /// missing src → `NotFound`. Same-root renames are single-filesystem
    /// atomics; a cross-device error surfaces as `Io` (same root ⇒ same fs
    /// in practice).
    pub async fn rename_path(&self, src: &str, dst: &str) -> Result<FileMetadata, FsError> {
        let src_canon = self.resolve_no_follow(src)?;
        let dst_canon = self.resolve_no_follow(dst)?;
        if src_canon == dst_canon {
            return Err(FsError::InvalidPath(
                "src and dst resolve to the same path".into(),
            ));
        }
        match fs::symlink_metadata(&src_canon).await {
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(FsError::NotFound(format!("source not found: {src}")));
            }
            Err(e) => return Err(FsError::from(e)),
        }
        if fs::symlink_metadata(&dst_canon).await.is_ok() {
            return Err(FsError::Conflict(format!(
                "destination already exists: {dst}"
            )));
        }
        // Atomic no-replace commit: the friendly pre-check above covers the
        // common case; `rename_noreplace` closes the TOCTOU race between
        // the check and the rename (renameat2 RENAME_NOREPLACE on Linux).
        rename_noreplace(&src_canon, &dst_canon).await?;
        // Destination metadata, with hash for regular files.
        let meta = fs::metadata(&dst_canon).await?;
        if meta.is_file() {
            let limit = self.config.max_file_bytes as u64;
            if meta.len() <= limit {
                let content = fs::read(&dst_canon).await?;
                return Ok(with_content_hash(make_metadata(&meta), &content));
            }
        }
        Ok(make_metadata(&meta))
    }

    /// Delete a file, symlink, or EMPTY directory.
    ///
    /// No-follow on the leaf: symlinks are unlinked themselves (target
    /// intact). Non-empty directories → `Conflict`, contents intact — there
    /// is deliberately NO recursive delete (agent-safety rule). Missing
    /// targets → `NotFound`.
    pub async fn delete_path(&self, path: &str) -> Result<(), FsError> {
        let canonical = self.resolve_no_follow(path)?;
        let meta = fs::symlink_metadata(&canonical)
            .await
            .map_err(|e| match e.kind() {
                std::io::ErrorKind::NotFound => FsError::NotFound(format!("not found: {path}")),
                _ => FsError::from(e),
            })?;
        if meta.file_type().is_symlink() || meta.is_file() {
            fs::remove_file(&canonical).await.map_err(FsError::from)?;
            return Ok(());
        }
        if meta.is_dir() {
            // Refuse non-empty directories: check first so the error is
            // `Conflict`, not an OS error string.
            let mut dir = fs::read_dir(&canonical).await.map_err(FsError::from)?;
            if dir.next_entry().await.map_err(FsError::from)?.is_some() {
                return Err(FsError::Conflict(format!(
                    "directory not empty; recursive delete not supported: {path}"
                )));
            }
            fs::remove_dir(&canonical).await.map_err(FsError::from)?;
            return Ok(());
        }
        // Socket, fifo, device, or other non-file non-dir: refuse rather
        // than guess (fail closed on exotic types).
        Err(FsError::InvalidPath(format!(
            "unsupported file type: {path}"
        )))
    }

    /// Access the underlying configuration.
    pub fn config(&self) -> &FilesystemConfig {
        &self.config
    }
}

/// Convert OS metadata to our domain type, WITHOUT a content hash.
///
/// Used for `list_directory` entries (hashing a listing is O(total bytes))
/// and as the base for directory metadata. Single-file ops add the hash
/// via `with_content_hash`.
fn make_metadata(meta: &std::fs::Metadata) -> FileMetadata {
    FileMetadata {
        size: meta.len(),
        modified_at: meta.modified().ok(),
        is_dir: meta.is_dir(),
        is_file: meta.is_file(),
        hash: None,
    }
}

/// Attach a content hash to file metadata. Directories never carry one.
/// Atomically rename `src` to `dst`, refusing to replace an existing
/// destination (`Conflict`).
///
/// Linux: `renameat2(..., RENAME_NOREPLACE)` — the kernel refuses to
/// replace an existing destination in the very same atomic syscall, so
/// there is NO check-then-act window. The syscall is synchronous `libc`,
/// matching the module's existing style (`resolve()` already runs sync
/// `std::fs` from async contexts; daemon handlers run inside
/// `block_in_place`). Both paths are relative (already resolved under an
/// allowed root) and NUL-terminated via `CString`.
///
/// Non-Linux fallback: check-then-rename. The destination is tested with
/// `symlink_metadata` first, then renamed — a small TOCTOU window remains
/// (a concurrent creator could slip between the two calls and be silently
/// replaced). Documented; Gate 8 should add a portable lockfile or
/// platform-specific exclusive rename (e.g. macOS `renamex_np`).
///
/// `EEXIST` / `AlreadyExists` maps to `FsError::Conflict`, so the "no
/// silent overwrite" contract holds on every platform.
#[cfg(target_os = "linux")]
async fn rename_noreplace(src: &std::path::Path, dst: &std::path::Path) -> Result<(), FsError> {
    use std::os::unix::ffi::OsStrExt;
    let c_src = std::ffi::CString::new(src.as_os_str().as_bytes())
        .map_err(|e| FsError::Io(format!("source path is invalid: {e}")))?;
    let c_dst = std::ffi::CString::new(dst.as_os_str().as_bytes())
        .map_err(|e| FsError::Io(format!("destination path is invalid: {e}")))?;
    // SAFETY: both arguments are NUL-terminated CStrings derived from the
    // incoming relative OS paths; AT_FDCWD keeps the syscall scoped to the
    // daemon's working directory. renameat2 is a single atomic syscall with
    // no pointers that outlive the call.
    let rc = unsafe {
        libc::renameat2(
            libc::AT_FDCWD,
            c_src.as_ptr(),
            libc::AT_FDCWD,
            c_dst.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if rc == 0 {
        return Ok(());
    }
    let err = std::io::Error::last_os_error();
    if err.kind() == std::io::ErrorKind::AlreadyExists {
        return Err(FsError::Conflict("destination exists".into()));
    }
    Err(FsError::from(err))
}

/// Check-then-rename fallback for non-Linux (see the linux variant's doc
/// for the documented TOCTOU window).
#[cfg(not(target_os = "linux"))]
async fn rename_noreplace(src: &std::path::Path, dst: &std::path::Path) -> Result<(), FsError> {
    match fs::symlink_metadata(dst).await {
        Ok(_) => return Err(FsError::Conflict("destination exists".into())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(FsError::from(e)),
    }
    fs::rename(src, dst).await.map_err(FsError::from)
}

fn with_content_hash(mut meta: FileMetadata, content: &[u8]) -> FileMetadata {
    if meta.is_file {
        meta.hash = Some(hash_bytes(content));
    }
    meta
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use tempfile::TempDir;

    /// Helper: create a FilesystemBackend rooted at a temp directory.
    fn make_backend() -> (TempDir, FilesystemBackend) {
        let tmp = TempDir::new().expect("failed to create temp dir");
        let config =
            FilesystemConfig::new(&[tmp.path().to_path_buf()]).expect("failed to create config");
        (tmp, FilesystemBackend::new(config))
    }

    // ---- resolve() tests ----

    #[test]
    fn resolve_rejects_empty_path() {
        let (_tmp, backend) = make_backend();
        let result = backend.resolve("");
        assert!(matches!(result, Err(FsError::InvalidPath(_))));
    }

    #[test]
    fn resolve_rejects_absolute_unix_path() {
        let (_tmp, backend) = make_backend();
        let result = backend.resolve("/etc/passwd");
        assert!(matches!(result, Err(FsError::InvalidPath(_))));
    }

    #[test]
    fn resolve_rejects_absolute_backslash_path() {
        let (_tmp, backend) = make_backend();
        let result = backend.resolve("\\etc\\passwd");
        assert!(matches!(result, Err(FsError::InvalidPath(_))));
    }

    #[test]
    fn resolve_rejects_path_traversal() {
        let (tmp, backend) = make_backend();
        // Create a file inside the root.
        std::fs::write(tmp.path().join("safe.txt"), "safe").unwrap();
        // Try to escape with ../
        let result = backend.resolve("../etc/passwd");
        assert!(
            matches!(result, Err(FsError::FilesystemEscape(_))),
            "path traversal must be blocked, got: {result:?}"
        );
    }

    #[test]
    fn resolve_allows_valid_relative_path() {
        let (tmp, backend) = make_backend();
        std::fs::write(tmp.path().join("hello.txt"), "hello").unwrap();
        let result = backend.resolve("hello.txt");
        assert!(result.is_ok());
        assert!(result.unwrap().ends_with("hello.txt"));
    }

    #[test]
    fn resolve_allows_nested_path() {
        let (tmp, backend) = make_backend();
        std::fs::create_dir_all(tmp.path().join("src").join("lib")).unwrap();
        std::fs::write(tmp.path().join("src").join("lib").join("mod.rs"), "").unwrap();
        let result = backend.resolve("src/lib/mod.rs");
        assert!(result.is_ok());
    }

    #[test]
    fn resolve_rejects_symlink_outside_root() {
        let (_tmp, _backend) = make_backend();
        #[cfg(unix)]
        {
            let tmp = &_tmp;
            let backend = &_backend;
            let outside = TempDir::new().unwrap();
            let outside_file = outside.path().join("secret.txt");
            std::fs::write(&outside_file, "secret").unwrap();

            std::os::unix::fs::symlink(&outside_file, tmp.path().join("escape.txt")).unwrap();
            let result = backend.resolve("escape.txt");
            assert!(
                matches!(result, Err(FsError::FilesystemEscape(_))),
                "symlink escape must be blocked, got: {result:?}"
            );
        }
    }

    #[test]
    fn resolve_handles_missing_file_parent_exists() {
        let (_tmp, backend) = make_backend();
        // File doesn't exist, but parent (root) does.
        let result = backend.resolve("nonexistent.txt");
        assert!(result.is_ok());
        assert!(result.unwrap().ends_with("nonexistent.txt"));
    }

    #[test]
    fn resolve_handles_missing_nested_file() {
        let (tmp, backend) = make_backend();
        std::fs::create_dir(tmp.path().join("src")).unwrap();
        let result = backend.resolve("src/nonexistent.rs");
        assert!(result.is_ok());
        assert!(result.unwrap().ends_with("nonexistent.rs"));
    }

    // ---- read_file() tests ----

    #[tokio::test]
    async fn read_file_normal() {
        let (tmp, backend) = make_backend();
        std::fs::write(tmp.path().join("test.txt"), b"hello world").unwrap();

        let (content, meta) = backend.read_file("test.txt").await.unwrap();
        assert_eq!(content, b"hello world");
        assert!(meta.is_file);
        assert!(!meta.is_dir);
        assert_eq!(meta.size, 11);
    }

    #[tokio::test]
    async fn read_file_not_found() {
        let (_tmp, backend) = make_backend();
        let result = backend.read_file("nonexistent.txt").await;
        assert!(matches!(result, Err(FsError::NotFound(_))));
    }

    #[tokio::test]
    async fn read_file_is_directory() {
        let (tmp, backend) = make_backend();
        std::fs::create_dir(tmp.path().join("mydir")).unwrap();

        let result = backend.read_file("mydir").await;
        assert!(matches!(result, Err(FsError::IsADirectory(_))));
    }

    #[tokio::test]
    async fn read_file_permission_denied() {
        let (_tmp, _backend) = make_backend();
        // On Unix, create a file with no read permissions.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let backend = &_backend;
            let path = backend.config().allowed_roots[0].join("noperm.txt");
            std::fs::write(&path, b"secret").unwrap();
            let mut perms = std::fs::metadata(&path).unwrap().permissions();
            perms.set_mode(0o000);
            std::fs::set_permissions(&path, perms).unwrap();

            // Running as root (or another privileged user) bypasses file
            // mode bits, so the denial cannot trigger. Detect that and
            // skip rather than fail: the mapping itself is covered by the
            // non-privileged case and by handler-level tests.
            if std::fs::File::open(&path).is_ok() {
                eprintln!(
                    "SKIP read_file_permission_denied: process can still open mode-000 files (running as root?)"
                );
                let mut restore = std::fs::metadata(&path).unwrap().permissions();
                restore.set_mode(0o644);
                std::fs::set_permissions(&path, restore).unwrap();
                return;
            }

            let result = backend.read_file("noperm.txt").await;
            assert!(
                matches!(result, Err(FsError::PermissionDenied(_))),
                "expected PermissionDenied, got: {result:?}"
            );
        }
    }

    #[tokio::test]
    async fn read_file_rejects_too_large() {
        let tmp = tempfile::TempDir::new().unwrap();
        let config = FilesystemConfig::with_max_file_bytes(
            &[tmp.path().to_path_buf()],
            1024, // 1 KiB limit for testing
        )
        .unwrap();
        let backend = FilesystemBackend::new(config);

        // Write a file that exceeds the limit.
        let data = vec![0u8; 2048]; // 2 KiB > 1 KiB limit
        std::fs::write(tmp.path().join("big.bin"), &data).unwrap();

        let result = backend.read_file("big.bin").await;
        match result {
            Err(FsError::FileTooLarge { path, size, limit }) => {
                assert_eq!(path, "big.bin");
                assert_eq!(size, 2048);
                assert_eq!(limit, 1024);
            }
            other => panic!("expected FileTooLarge, got: {other:?}"),
        }
    }

    // ---- list_directory() tests ----

    #[tokio::test]
    async fn list_directory_normal() {
        let (tmp, backend) = make_backend();
        std::fs::write(tmp.path().join("a.txt"), b"a").unwrap();
        std::fs::write(tmp.path().join("b.txt"), b"bb").unwrap();
        std::fs::create_dir(tmp.path().join("subdir")).unwrap();

        let entries = backend.list_directory(".").await.unwrap();
        assert_eq!(entries.len(), 3);

        // Sort for deterministic check.
        let mut sorted = entries.clone();
        sorted.sort_by(|a, b| a.name.cmp(&b.name));

        assert_eq!(sorted[0].name, "a.txt");
        assert!(sorted[0].metadata.is_file);
        assert_eq!(sorted[0].metadata.size, 1);
        assert_eq!(sorted[1].name, "b.txt");
        assert!(sorted[1].metadata.is_file);
        assert_eq!(sorted[1].metadata.size, 2);
        assert_eq!(sorted[2].name, "subdir");
        assert!(sorted[2].metadata.is_dir);
    }

    #[tokio::test]
    async fn list_directory_not_found() {
        let (_tmp, backend) = make_backend();
        let result = backend.list_directory("nonexistent").await;
        assert!(matches!(result, Err(FsError::NotFound(_))));
    }

    #[tokio::test]
    async fn list_directory_not_a_directory() {
        let (tmp, backend) = make_backend();
        std::fs::write(tmp.path().join("file.txt"), b"data").unwrap();

        let result = backend.list_directory("file.txt").await;
        assert!(matches!(result, Err(FsError::NotADirectory(_))));
    }

    // ---- file_metadata() tests ----

    #[tokio::test]
    async fn file_metadata_normal_file() {
        let (tmp, backend) = make_backend();
        std::fs::write(tmp.path().join("meta.txt"), b"content").unwrap();

        let meta = backend.file_metadata("meta.txt").await.unwrap();
        assert!(meta.is_file);
        assert!(!meta.is_dir);
        assert_eq!(meta.size, 7);
    }

    #[tokio::test]
    async fn file_metadata_directory() {
        let (tmp, backend) = make_backend();
        std::fs::create_dir(tmp.path().join("mydir")).unwrap();

        let meta = backend.file_metadata("mydir").await.unwrap();
        assert!(meta.is_dir);
        assert!(!meta.is_file);
    }

    #[tokio::test]
    async fn file_metadata_not_found() {
        let (_tmp, backend) = make_backend();
        let result = backend.file_metadata("ghost.txt").await;
        assert!(matches!(result, Err(FsError::NotFound(_))));
    }

    // ---- escape tests ----

    #[tokio::test]
    async fn read_file_cannot_escape_via_symlink() {
        let (_tmp, _backend) = make_backend();
        #[cfg(unix)]
        {
            let tmp = &_tmp;
            let backend = &_backend;
            let outside = TempDir::new().unwrap();
            std::fs::write(outside.path().join("secret.txt"), b"secret").unwrap();

            std::os::unix::fs::symlink(
                outside.path().join("secret.txt"),
                tmp.path().join("link.txt"),
            )
            .unwrap();

            let result = backend.read_file("link.txt").await;
            assert!(
                matches!(result, Err(FsError::FilesystemEscape(_))),
                "symlink escape must be blocked, got: {result:?}"
            );
        }
    }

    #[tokio::test]
    async fn list_directory_cannot_escape_via_symlink() {
        let (_tmp, _backend) = make_backend();
        #[cfg(unix)]
        {
            let tmp = &_tmp;
            let backend = &_backend;
            let outside = TempDir::new().unwrap();

            std::os::unix::fs::symlink(outside.path(), tmp.path().join("escape")).unwrap();

            let result = backend.list_directory("escape").await;
            assert!(
                matches!(result, Err(FsError::FilesystemEscape(_))),
                "symlink escape must be blocked, got: {result:?}"
            );
        }
    }

    #[tokio::test]
    async fn nested_symlink_chain_resolves_and_blocks() {
        let (_tmp, _backend) = make_backend();
        #[cfg(unix)]
        {
            let tmp = &_tmp;
            let backend = &_backend;
            let outside = TempDir::new().unwrap();
            std::fs::write(outside.path().join("secret.txt"), b"secret").unwrap();

            // chain: root/link1 -> root/link2 -> outside/secret.txt
            std::os::unix::fs::symlink(outside.path().join("secret.txt"), tmp.path().join("link2"))
                .unwrap();
            std::os::unix::fs::symlink(tmp.path().join("link2"), tmp.path().join("link1")).unwrap();

            let result = backend.read_file("link1").await;
            assert!(
                matches!(result, Err(FsError::FilesystemEscape(_))),
                "nested symlink escape must be blocked, got: {result:?}"
            );
        }
    }

    // ---- Config tests ----

    #[test]
    fn config_rejects_empty_roots() {
        let result = FilesystemConfig::new(&[]);
        assert!(matches!(result, Err(FsError::InvalidPath(_))));
    }

    #[test]
    fn config_rejects_nonexistent_root() {
        let result = FilesystemConfig::new(&[PathBuf::from("/nonexistent/path/that/doesnt/exist")]);
        assert!(matches!(result, Err(FsError::InvalidPath(_))));
    }

    #[test]
    fn config_accepts_valid_root() {
        let tmp = TempDir::new().unwrap();
        let result = FilesystemConfig::new(&[tmp.path().to_path_buf()]);
        assert!(result.is_ok());
    }

    // ---- Gate 7: hash helper ----

    #[test]
    fn hash_bytes_is_stable_64_hex() {
        let h1 = hash_bytes(b"hello");
        let h2 = hash_bytes(b"hello");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
        assert!(h1.bytes().all(|b| b.is_ascii_hexdigit()));
        // Case matters: digest differs across inputs.
        assert_ne!(h1, hash_bytes(b"hello!"));
        // Empty input hashes fine (no panic on empty).
        assert_eq!(hash_bytes(b"").len(), 64);
    }

    // ---- Gate 7: read/metadata hash policy ----

    /// Assert no `.are-tmp-*` stray files exist directly under `dir`.
    fn assert_no_strays(dir: &std::path::Path) {
        let strays: Vec<_> = std::fs::read_dir(dir)
            .expect("read_dir")
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with(".are-tmp-"))
            .collect();
        assert!(
            strays.is_empty(),
            "stray temp files left behind: {strays:?}"
        );
    }

    #[tokio::test]
    async fn read_file_returns_content_hash() {
        let (tmp, backend) = make_backend();
        std::fs::write(tmp.path().join("h.txt"), b"hello").unwrap();

        let (content, meta) = backend.read_file("h.txt").await.unwrap();
        assert_eq!(content, b"hello");
        let hash = meta.hash.expect("read_file must return a hash");
        assert_eq!(hash, hash_bytes(b"hello"));
        assert_eq!(hash.len(), 64);
    }

    #[tokio::test]
    async fn file_metadata_returns_hash_for_files_none_for_dirs() {
        let (tmp, backend) = make_backend();
        std::fs::write(tmp.path().join("f.txt"), b"data").unwrap();
        std::fs::create_dir(tmp.path().join("d")).unwrap();

        let meta = backend.file_metadata("f.txt").await.unwrap();
        assert_eq!(meta.hash.as_deref(), Some(&hash_bytes(b"data")[..]));

        let meta = backend.file_metadata("d").await.unwrap();
        assert_eq!(meta.hash, None);
    }

    #[tokio::test]
    async fn file_metadata_oversized_file_returns_size_without_hash() {
        let tmp = tempfile::TempDir::new().unwrap();
        let config = FilesystemConfig::with_max_file_bytes(&[tmp.path().to_path_buf()], 4).unwrap();
        let backend = FilesystemBackend::new(config);
        std::fs::write(tmp.path().join("big.bin"), b"12345678").unwrap();

        // Must NOT fail: size is reported, hash is skipped (documented).
        let meta = backend.file_metadata("big.bin").await.unwrap();
        assert_eq!(meta.size, 8);
        assert_eq!(meta.hash, None);
    }

    #[tokio::test]
    async fn list_directory_entries_carry_no_hash() {
        let (tmp, backend) = make_backend();
        std::fs::write(tmp.path().join("a.txt"), b"a").unwrap();

        let entries = backend.list_directory(".").await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].metadata.hash, None);
    }

    // ---- Gate 7: write_file ----

    #[tokio::test]
    async fn write_new_file_read_back_hash_matches() {
        let (tmp, backend) = make_backend();
        let meta = backend
            .write_file("new.txt", b"content!", true, None)
            .await
            .unwrap();
        assert!(meta.is_file);
        assert_eq!(meta.size, 8);
        assert_eq!(meta.hash.as_deref(), Some(&hash_bytes(b"content!")[..]));

        let (content, read_meta) = backend.read_file("new.txt").await.unwrap();
        assert_eq!(content, b"content!");
        assert_eq!(read_meta.hash, meta.hash);
        assert_no_strays(tmp.path());
    }

    #[tokio::test]
    async fn write_overwrite_false_refuses_existing() {
        let (tmp, backend) = make_backend();
        backend
            .write_file("e.txt", b"v1", true, None)
            .await
            .unwrap();
        let err = backend
            .write_file("e.txt", b"v2", false, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, FsError::Conflict(_)),
            "overwrite=false on existing file must be Conflict, got: {err:?}"
        );
        // Original intact, no strays.
        let (content, _) = backend.read_file("e.txt").await.unwrap();
        assert_eq!(content, b"v1");
        assert_no_strays(tmp.path());
    }

    #[tokio::test]
    async fn write_overwrite_true_replaces() {
        let (tmp, backend) = make_backend();
        backend
            .write_file("e.txt", b"v1", true, None)
            .await
            .unwrap();
        let meta = backend
            .write_file("e.txt", b"v2-longer", true, None)
            .await
            .unwrap();
        assert_eq!(meta.hash.as_deref(), Some(&hash_bytes(b"v2-longer")[..]));
        let (content, _) = backend.read_file("e.txt").await.unwrap();
        assert_eq!(content, b"v2-longer");
        assert_no_strays(tmp.path());
    }

    #[tokio::test]
    async fn write_expected_hash_match_succeeds_mismatch_conflicts() {
        let (tmp, backend) = make_backend();
        backend
            .write_file("o.txt", b"one", true, None)
            .await
            .unwrap();
        let good = hash_bytes(b"one");

        // Matching hash proceeds.
        backend
            .write_file("o.txt", b"two", true, Some(&good))
            .await
            .unwrap();
        let (content, _) = backend.read_file("o.txt").await.unwrap();
        assert_eq!(content, b"two");

        // Stale hash refuses WITHOUT revealing content.
        let stale = hash_bytes(b"one");
        let err = backend
            .write_file("o.txt", b"three", true, Some(&stale))
            .await
            .unwrap_err();
        match &err {
            FsError::Conflict(msg) => {
                assert!(msg.contains("changed"), "got: {msg}");
                assert!(!msg.contains("two"), "conflict must not leak content");
            }
            other => panic!("expected Conflict, got: {other:?}"),
        }
        // Loser's write never landed; no strays.
        let (content, _) = backend.read_file("o.txt").await.unwrap();
        assert_eq!(content, b"two");
        assert_no_strays(tmp.path());
    }

    // ---- FIX 1: expected-hash compare stats BEFORE reading ----

    #[tokio::test]
    async fn write_expected_hash_stat_refuses_oversized_without_reading() {
        let tmp = TempDir::new().unwrap();
        let config = FilesystemConfig::with_max_file_bytes(&[tmp.path().to_path_buf()], 4).unwrap();
        let backend = FilesystemBackend::new(config);

        // Seed a 5-byte file ON DISK (over the 4-byte cap) so the
        // expected-hash compare path is reached with an oversized target.
        let big = tmp.path().join("big.txt");
        std::fs::write(&big, b"hello").unwrap();

        let err = backend
            .write_file("big.txt", b"new", true, Some(&hash_bytes(b"hello")))
            .await
            .unwrap_err();
        assert!(
            matches!(err, FsError::FileTooLarge { size: 5, .. }),
            "expected FileTooLarge (size 5), got: {err:?}"
        );
        // Refused BEFORE reading: the on-disk file is untouched and no
        // strays were left behind.
        assert_eq!(std::fs::read(&big).unwrap(), b"hello");
        assert_no_strays(tmp.path());
    }

    // ---- FIX 5 m3: expected-hash comparison is case-insensitive ----

    #[tokio::test]
    async fn write_expected_hash_accepts_uppercase() {
        let (tmp, backend) = make_backend();
        backend
            .write_file("u.txt", b"one", true, None)
            .await
            .unwrap();
        // `is_valid_hash` accepts uppercase hex; the daemon must normalize
        // before comparing (its own `hash_bytes` emits lowercase).
        let good = hash_bytes(b"one").to_uppercase();
        backend
            .write_file("u.txt", b"two", true, Some(&good))
            .await
            .unwrap();
        let (content, _) = backend.read_file("u.txt").await.unwrap();
        assert_eq!(content, b"two");
        assert_no_strays(tmp.path());
    }

    // ---- FIX 2: non-NotFound canonicalize failures stay generic ----

    #[tokio::test]
    async fn delete_under_file_error_leaks_no_host_root() {
        // Portable invariant (FIX 2): whichever error surfaces — NotFound
        // on Windows (ERROR_PATH_NOT_FOUND), ENOTDIR-as-Io on Linux — the
        // remote-facing message must never embed the allowed ROOT (an
        // absolute host path) or the requested path. The relative requested
        // path MAY appear (the client supplied it); the root must not.
        let (tmp, backend) = make_backend();
        std::fs::write(tmp.path().join("file.txt"), "x").unwrap();
        let root_str = tmp.path().to_string_lossy().to_string();
        let err = backend.delete_path("file.txt/child/x").await.unwrap_err();
        match err {
            FsError::NotFound(msg) | FsError::Io(msg) => {
                assert!(!msg.contains(&root_str), "leaked allowed root: {msg}");
            }
            other => panic!("expected NotFound or Io, got: {other:?}"),
        }
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn delete_under_file_parent_enotdir_maps_to_generic_io() {
        // Linux-specific deterministic trigger: parent `file.txt` is a FILE,
        // so canonicalize(root/file.txt/child) fails ENOTDIR — a NON-NotFound
        // error whose message previously embedded the absolute allowed ROOT
        // (via the joined-parent display in resolve_no_follow). Now it must
        // be a generic Io: no root, no path fragments at all.
        let (tmp, backend) = make_backend();
        std::fs::write(tmp.path().join("file.txt"), "x").unwrap();
        let root_str = tmp.path().to_string_lossy().to_string();
        let err = backend.delete_path("file.txt/child/x").await.unwrap_err();
        match err {
            FsError::Io(msg) => {
                assert!(!msg.contains(&root_str), "leaked allowed root: {msg}");
                assert!(!msg.contains("file.txt"), "leaked path fragment: {msg}");
            }
            other => panic!("expected Io (ENOTDIR), got: {other:?}"),
        }
    }

    // ---- FIX 3: rename_noreplace ----

    #[tokio::test]
    async fn rename_noreplace_dst_exists_conflicts() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        std::fs::write(&src, b"a").unwrap();
        std::fs::write(&dst, b"b").unwrap();

        let err = rename_noreplace(&src, &dst).await.unwrap_err();
        assert!(
            matches!(err, FsError::Conflict(_)),
            "expected Conflict, got: {err:?}"
        );
        // dst intact AND src not consumed (rename must not have happened).
        assert_eq!(std::fs::read(&dst).unwrap(), b"b");
        assert!(src.exists());
    }

    #[tokio::test]
    async fn rename_noreplace_dst_absent_succeeds() {
        let tmp = TempDir::new().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        std::fs::write(&src, b"a").unwrap();

        rename_noreplace(&src, &dst).await.unwrap();
        assert!(!src.exists());
        assert_eq!(std::fs::read(&dst).unwrap(), b"a");
    }

    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn rename_noreplace_concurrent_single_winner() {
        // 8 racing RENAME_NOREPLACE to one dst: the kernel must let exactly
        // one win; every other racer gets EEXIST/Conflict. This is the
        // TOCTOU-closure property the fallback (non-Linux) cannot offer.
        let tmp = TempDir::new().unwrap();
        let dst = tmp.path().join("dst");
        let mut handles = Vec::new();
        for i in 0..8u32 {
            let src = tmp.path().join(format!("src-{i}"));
            std::fs::write(&src, b"x").unwrap();
            let dst = dst.clone();
            handles.push(tokio::spawn(
                async move { rename_noreplace(&src, &dst).await },
            ));
        }
        let mut ok = 0u32;
        let mut conflicts = 0u32;
        for handle in handles {
            match handle.await.unwrap() {
                Ok(()) => ok += 1,
                Err(FsError::Conflict(_)) => conflicts += 1,
                Err(e) => panic!("unexpected error: {e:?}"),
            }
        }
        assert_eq!(ok, 1, "exactly one rename must win");
        assert_eq!(conflicts, 7, "all other racers must Conflict");
        assert_eq!(std::fs::read(&dst).unwrap(), b"x");
    }

    #[tokio::test]
    async fn write_expected_hash_on_missing_file_conflicts() {
        let (_tmp, backend) = make_backend();
        let err = backend
            .write_file("ghost.txt", b"x", true, Some(&"a".repeat(64)))
            .await
            .unwrap_err();
        assert!(
            matches!(err, FsError::Conflict(_)),
            "expected_hash on missing file must be Conflict, got: {err:?}"
        );
        // Nothing was created.
        assert!(matches!(
            backend.read_file("ghost.txt").await,
            Err(FsError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn write_to_existing_directory_refused() {
        let (_tmp, backend) = make_backend();
        std::fs::create_dir(_tmp.path().join("d")).unwrap();
        let err = backend.write_file("d", b"x", true, None).await.unwrap_err();
        assert!(matches!(err, FsError::IsADirectory(_)), "got: {err:?}");
    }

    #[tokio::test]
    async fn write_rejects_oversized_content() {
        let tmp = tempfile::TempDir::new().unwrap();
        let config = FilesystemConfig::with_max_file_bytes(&[tmp.path().to_path_buf()], 4).unwrap();
        let backend = FilesystemBackend::new(config);
        let err = backend
            .write_file("big.txt", b"12345", true, None)
            .await
            .unwrap_err();
        assert!(matches!(err, FsError::FileTooLarge { .. }), "got: {err:?}");
        assert_no_strays(tmp.path());
    }

    #[tokio::test]
    async fn write_rejects_traversal_and_missing_parent() {
        let (_tmp, backend) = make_backend();
        // Traversal out of the root.
        let err = backend
            .write_file("../evil.txt", b"x", true, None)
            .await
            .unwrap_err();
        assert!(matches!(err, FsError::FilesystemEscape(_)), "got: {err:?}");
        // Missing parent dir: no implicit mkdir.
        let err = backend
            .write_file("no/such/dir/f.txt", b"x", true, None)
            .await
            .unwrap_err();
        assert!(
            matches!(err, FsError::NotFound(_) | FsError::FilesystemEscape(_)),
            "missing parent must fail closed, got: {err:?}"
        );
    }

    // ---- Gate 7: create_directory ----

    #[tokio::test]
    async fn mkdir_nested_creates_all_idempotent() {
        let (tmp, backend) = make_backend();
        let meta = backend.create_directory("a/b/c").await.unwrap();
        assert!(meta.is_dir);
        assert_eq!(meta.hash, None);
        assert!(tmp.path().join("a/b/c").is_dir());

        // Idempotent: existing dir succeeds.
        let meta2 = backend.create_directory("a/b/c").await.unwrap();
        assert!(meta2.is_dir);
        // Partial prefix also idempotent.
        backend.create_directory("a").await.unwrap();
    }

    #[tokio::test]
    async fn mkdir_where_file_exists_conflicts() {
        let (tmp, backend) = make_backend();
        std::fs::write(tmp.path().join("f.txt"), b"x").unwrap();
        let err = backend.create_directory("f.txt").await.unwrap_err();
        assert!(matches!(err, FsError::Conflict(_)), "got: {err:?}");
        // Nested under a file also fails (NotADirectory on the component).
        let err = backend.create_directory("f.txt/sub").await.unwrap_err();
        assert!(
            matches!(err, FsError::Conflict(_) | FsError::NotADirectory(_)),
            "got: {err:?}"
        );
    }

    #[tokio::test]
    async fn mkdir_rejects_traversal() {
        let (_tmp, backend) = make_backend();
        let err = backend.create_directory("../x").await.unwrap_err();
        assert!(
            matches!(err, FsError::InvalidPath(_) | FsError::FilesystemEscape(_)),
            "got: {err:?}"
        );
        let err = backend.create_directory("a/../../x").await.unwrap_err();
        assert!(
            matches!(err, FsError::InvalidPath(_) | FsError::FilesystemEscape(_)),
            "got: {err:?}"
        );
    }

    #[tokio::test]
    async fn mkdir_through_symlink_outside_rejected() {
        let (_tmp, _backend) = make_backend();
        #[cfg(unix)]
        {
            let tmp = &_tmp;
            let backend = &_backend;
            let outside = TempDir::new().unwrap();
            std::os::unix::fs::symlink(outside.path(), tmp.path().join("link")).unwrap();

            // Creating THROUGH the escaping link must fail...
            let err = backend.create_directory("link/sub").await.unwrap_err();
            assert!(
                matches!(
                    err,
                    FsError::FilesystemEscape(_) | FsError::NotADirectory(_)
                ),
                "got: {err:?}"
            );
            // ...and nothing may appear outside the root.
            assert!(
                std::fs::read_dir(outside.path()).unwrap().next().is_none(),
                "outside root must stay untouched"
            );
        }
    }

    // ---- Gate 7: rename ----

    #[tokio::test]
    async fn rename_file_moves_with_hash() {
        let (tmp, backend) = make_backend();
        backend
            .write_file("src.txt", b"payload", true, None)
            .await
            .unwrap();
        let meta = backend.rename_path("src.txt", "dst.txt").await.unwrap();
        assert!(meta.is_file);
        assert_eq!(meta.hash.as_deref(), Some(&hash_bytes(b"payload")[..]));
        assert!(!tmp.path().join("src.txt").exists());
        let (content, _) = backend.read_file("dst.txt").await.unwrap();
        assert_eq!(content, b"payload");
    }

    #[tokio::test]
    async fn rename_dst_exists_conflicts_src_intact() {
        let (_tmp, backend) = make_backend();
        backend.write_file("a.txt", b"a", true, None).await.unwrap();
        backend.write_file("b.txt", b"b", true, None).await.unwrap();
        let err = backend.rename_path("a.txt", "b.txt").await.unwrap_err();
        assert!(matches!(err, FsError::Conflict(_)), "got: {err:?}");
        // Both files intact (no silent overwrite).
        let (ca, _) = backend.read_file("a.txt").await.unwrap();
        let (cb, _) = backend.read_file("b.txt").await.unwrap();
        assert_eq!((ca, cb), (b"a".to_vec(), b"b".to_vec()));
    }

    #[tokio::test]
    async fn rename_same_path_rejected() {
        let (_tmp, backend) = make_backend();
        backend.write_file("s.txt", b"s", true, None).await.unwrap();
        // Identical strings (also caught by request validation; the
        // backend defends in depth on canonical equality).
        let err = backend.rename_path("s.txt", "s.txt").await.unwrap_err();
        assert!(matches!(err, FsError::InvalidPath(_)), "got: {err:?}");
        // Equivalent via dot-component resolves identically.
        let err = backend.rename_path("s.txt", "./s.txt").await.unwrap_err();
        assert!(
            matches!(err, FsError::InvalidPath(_) | FsError::Conflict(_)),
            "got: {err:?}"
        );
    }

    #[tokio::test]
    async fn rename_missing_src_not_found() {
        let (_tmp, backend) = make_backend();
        let err = backend
            .rename_path("ghost.txt", "dst.txt")
            .await
            .unwrap_err();
        assert!(matches!(err, FsError::NotFound(_)), "got: {err:?}");
    }

    #[tokio::test]
    async fn rename_outside_rejected_both_ends() {
        let (_tmp, backend) = make_backend();
        backend
            .write_file("in.txt", b"in", true, None)
            .await
            .unwrap();
        // dst outside.
        let err = backend
            .rename_path("in.txt", "../out.txt")
            .await
            .unwrap_err();
        assert!(
            matches!(err, FsError::FilesystemEscape(_) | FsError::NotFound(_)),
            "got: {err:?}"
        );
        // src outside.
        let err = backend
            .rename_path("../outside.txt", "in2.txt")
            .await
            .unwrap_err();
        assert!(
            matches!(err, FsError::FilesystemEscape(_) | FsError::NotFound(_)),
            "got: {err:?}"
        );
        // Source still here.
        let (c, _) = backend.read_file("in.txt").await.unwrap();
        assert_eq!(c, b"in");
    }

    #[tokio::test]
    async fn rename_symlink_renames_link_target_untouched() {
        let (_tmp, _backend) = make_backend();
        #[cfg(unix)]
        {
            let tmp = &_tmp;
            let backend = &_backend;
            // In-root target with real content.
            std::fs::write(tmp.path().join("target.txt"), b"target").unwrap();
            std::os::unix::fs::symlink(tmp.path().join("target.txt"), tmp.path().join("link.txt"))
                .unwrap();

            backend.rename_path("link.txt", "link2.txt").await.unwrap();
            // Link moved...
            assert!(tmp.path().join("link2.txt").exists());
            assert!(!tmp.path().join("link.txt").exists());
            // ...as a link (target untouched, content intact).
            let meta = std::fs::symlink_metadata(tmp.path().join("link2.txt")).unwrap();
            assert!(meta.file_type().is_symlink());
            assert_eq!(
                std::fs::read(tmp.path().join("target.txt")).unwrap(),
                b"target"
            );
        }
    }

    // ---- Gate 7: delete ----

    #[tokio::test]
    async fn delete_file_ok() {
        let (tmp, backend) = make_backend();
        backend.write_file("d.txt", b"x", true, None).await.unwrap();
        backend.delete_path("d.txt").await.unwrap();
        assert!(!tmp.path().join("d.txt").exists());
    }

    #[tokio::test]
    async fn delete_empty_dir_ok_nonempty_conflicts_intact() {
        let (tmp, backend) = make_backend();
        backend.create_directory("empty").await.unwrap();
        backend.delete_path("empty").await.unwrap();
        assert!(!tmp.path().join("empty").exists());

        backend.create_directory("full").await.unwrap();
        backend
            .write_file("full/inner.txt", b"keep", true, None)
            .await
            .unwrap();
        let err = backend.delete_path("full").await.unwrap_err();
        assert!(matches!(err, FsError::Conflict(_)), "got: {err:?}");
        // Contents intact — NO recursive delete.
        let (c, _) = backend.read_file("full/inner.txt").await.unwrap();
        assert_eq!(c, b"keep");
    }

    #[tokio::test]
    async fn delete_missing_not_found() {
        let (_tmp, backend) = make_backend();
        let err = backend.delete_path("ghost.txt").await.unwrap_err();
        assert!(matches!(err, FsError::NotFound(_)), "got: {err:?}");
    }

    #[tokio::test]
    async fn delete_symlink_removes_link_target_intact() {
        let (_tmp, _backend) = make_backend();
        #[cfg(unix)]
        {
            let tmp = &_tmp;
            let backend = &_backend;
            // In-root target.
            std::fs::write(tmp.path().join("keep.txt"), b"keep").unwrap();
            std::os::unix::fs::symlink(tmp.path().join("keep.txt"), tmp.path().join("link.txt"))
                .unwrap();

            backend.delete_path("link.txt").await.unwrap();
            assert!(!tmp.path().join("link.txt").exists());
            // Target intact — the no-follow leaf delete unlinked only.
            assert_eq!(std::fs::read(tmp.path().join("keep.txt")).unwrap(), b"keep");
        }
    }

    #[tokio::test]
    async fn delete_symlink_to_outside_removes_link_only() {
        let (_tmp, _backend) = make_backend();
        #[cfg(unix)]
        {
            let tmp = &_tmp;
            let backend = &_backend;
            // Link pointing OUTSIDE the root: resolve() would follow it
            // (escape) — resolve_no_follow must unlink the link itself.
            let outside = TempDir::new().unwrap();
            std::fs::write(outside.path().join("secret.txt"), b"secret").unwrap();
            std::os::unix::fs::symlink(
                outside.path().join("secret.txt"),
                tmp.path().join("evil.txt"),
            )
            .unwrap();

            backend.delete_path("evil.txt").await.unwrap();
            assert!(!tmp.path().join("evil.txt").exists());
            // Outside target untouched.
            assert_eq!(
                std::fs::read(outside.path().join("secret.txt")).unwrap(),
                b"secret"
            );
        }
    }

    #[tokio::test]
    async fn delete_traversal_rejected() {
        let (_tmp, backend) = make_backend();
        let err = backend.delete_path("../x").await.unwrap_err();
        assert!(
            matches!(
                err,
                FsError::FilesystemEscape(_) | FsError::NotFound(_) | FsError::InvalidPath(_)
            ),
            "got: {err:?}"
        );
    }

    // ---- Gate 7: optimistic-concurrency end-to-end ----

    #[tokio::test]
    async fn stale_read_then_write_conflicts() {
        let (_tmp, backend) = make_backend();
        // Agent A reads (gets hash H1).
        backend
            .write_file("shared.txt", b"v1", true, None)
            .await
            .unwrap();
        let (_, read_meta) = backend.read_file("shared.txt").await.unwrap();
        let h1 = read_meta.hash.clone().expect("read must carry hash");

        // Human (or agent B) modifies the file out of band.
        backend
            .write_file("shared.txt", b"v2-human", true, None)
            .await
            .unwrap();

        // Agent A writes with the stale hash → Conflict.
        let err = backend
            .write_file("shared.txt", b"v3-stale", true, Some(&h1))
            .await
            .unwrap_err();
        assert!(matches!(err, FsError::Conflict(_)), "got: {err:?}");
        let (c, _) = backend.read_file("shared.txt").await.unwrap();
        assert_eq!(c, b"v2-human");
    }

    // ---- Gate 7: symlink-escape fixtures (Gate 4 style, write side) ----

    #[tokio::test]
    async fn write_via_symlink_dir_outside_rejected() {
        let (_tmp, _backend) = make_backend();
        #[cfg(unix)]
        {
            let tmp = &_tmp;
            let backend = &_backend;
            let outside = TempDir::new().unwrap();
            std::os::unix::fs::symlink(outside.path(), tmp.path().join("escape")).unwrap();

            // Writing THROUGH the escaping dir-link must fail...
            let err = backend
                .write_file("escape/evil.txt", b"x", true, None)
                .await
                .unwrap_err();
            assert!(
                matches!(err, FsError::FilesystemEscape(_) | FsError::NotFound(_)),
                "got: {err:?}"
            );
            // ...and nothing may appear outside.
            assert!(
                std::fs::read_dir(outside.path()).unwrap().next().is_none(),
                "outside root must stay untouched"
            );
        }
    }

    #[tokio::test]
    async fn write_to_direct_symlink_outside_rejected() {
        let (_tmp, _backend) = make_backend();
        #[cfg(unix)]
        {
            let tmp = &_tmp;
            let backend = &_backend;
            let outside = TempDir::new().unwrap();
            std::fs::write(outside.path().join("secret.txt"), b"secret").unwrap();
            std::os::unix::fs::symlink(
                outside.path().join("secret.txt"),
                tmp.path().join("direct.txt"),
            )
            .unwrap();

            // resolve() follows the link → outside → rejected.
            let err = backend
                .write_file("direct.txt", b"pwned", true, None)
                .await
                .unwrap_err();
            assert!(matches!(err, FsError::FilesystemEscape(_)), "got: {err:?}");
            assert_eq!(
                std::fs::read(outside.path().join("secret.txt")).unwrap(),
                b"secret"
            );
        }
    }

    #[tokio::test]
    async fn nested_symlink_chain_write_blocked() {
        let (_tmp, _backend) = make_backend();
        #[cfg(unix)]
        {
            let tmp = &_tmp;
            let backend = &_backend;
            let outside = TempDir::new().unwrap();
            std::fs::write(outside.path().join("secret.txt"), b"secret").unwrap();

            // chain: root/link1 -> root/link2 -> outside/secret.txt
            std::os::unix::fs::symlink(outside.path().join("secret.txt"), tmp.path().join("link2"))
                .unwrap();
            std::os::unix::fs::symlink(tmp.path().join("link2"), tmp.path().join("link1")).unwrap();

            let err = backend
                .write_file("link1", b"pwned", true, None)
                .await
                .unwrap_err();
            assert!(matches!(err, FsError::FilesystemEscape(_)), "got: {err:?}");
        }
    }
}
