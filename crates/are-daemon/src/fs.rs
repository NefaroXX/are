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
        // 1. Reject empty paths.
        if path.is_empty() {
            return Err(FsError::InvalidPath("path must not be empty".into()));
        }

        // 2. Reject absolute paths (Unix-style `/` or Windows drive letters `C:\`).
        if path.starts_with('/') || path.starts_with('\\') {
            return Err(FsError::InvalidPath(format!(
                "absolute path rejected: {path}"
            )));
        }
        // Windows drive letter check: "C:\..." or "C:/..."
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
                            Err(e) => {
                                return Err(FsError::Io(format!(
                                    "failed to canonicalize parent '{}': {e}",
                                    parent.display()
                                )));
                            }
                        }
                    } else {
                        return Err(FsError::InvalidPath(format!(
                            "no parent directory in path: {path}"
                        )));
                    }
                }
                Err(e) => {
                    return Err(FsError::Io(format!("failed to resolve path '{path}': {e}")));
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

    /// Read a file from the environment.
    ///
    /// Returns the file contents and metadata. Files exceeding
    /// `config.max_file_bytes` are rejected before loading into memory.
    ///
    /// The file-size cap ensures the serialized response stays within the
    /// framing layer's 16 MiB read limit (with serde overhead absorbed by
    /// the 4 GiB write guard).
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
        // This cap also implicitly bounds the serialized RPC response: the
        // file content plus serde overhead (headers, metadata) will stay
        // well under the framing layer's 4 GiB write-side guard, so no
        // additional check is needed in write_message.
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
        let metadata = make_metadata(&meta);

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
    pub async fn file_metadata(&self, path: &str) -> Result<FileMetadata, FsError> {
        let canonical = self.resolve(path)?;
        let meta = fs::metadata(&canonical).await?;
        Ok(make_metadata(&meta))
    }

    /// Access the underlying configuration.
    pub fn config(&self) -> &FilesystemConfig {
        &self.config
    }
}

/// Convert OS metadata to our domain type.
fn make_metadata(meta: &std::fs::Metadata) -> FileMetadata {
    FileMetadata {
        size: meta.len(),
        modified_at: meta.modified().ok(),
        is_dir: meta.is_dir(),
        is_file: meta.is_file(),
    }
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
}
