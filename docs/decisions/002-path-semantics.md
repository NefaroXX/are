# ADR-002: Path Semantics — Environment-Relative, Not Absolute Host Paths

## Status

**Accepted** (Gate 3.5, 2026-09-01)

## Context

Gate 4 introduces read-only filesystem access. The `ReadFileRequest` struct in `are-core/src/request.rs` has a `path: String` field. The current doc comment says "Absolute or workspace-relative path," but this is ambiguous and creates a security risk:

- If clients can pass arbitrary absolute host paths (e.g., `/etc/passwd`), the daemon becomes an open filesystem proxy — the exact opposite of ARE's environment isolation model.
- "Workspace-relative" is ambiguous: relative to the client's local working directory? Relative to the daemon's configured root? These resolve to different locations.
- There is no path validation, allowed-roots enforcement, or traversal prevention until Gate 4.

The path semantics must be decided before Gate 4 implementation begins, because the filesystem backend will enforce them on every request.

## Decision

**Paths in all future file APIs (Gate 4+) are environment-relative, resolved against the daemon's configured workspace root / allowed roots.**

Concretely:

1. **Environment-relative path:** A path within the environment's allowed root directory, as configured on the daemon. Example: `src/main.rs` resolves to `<workspace_root>/src/main.rs` on the remote machine.
2. **Absolute host paths are rejected by default.** A path starting with `/` (or a Windows drive letter) is treated as a path traversal attempt unless the absolute path falls within an explicitly configured allowed root and the request carries the required capability. This allowlist behavior is designed in Gate 4 and enforced there.
3. **No client-local workspace resolution.** The client's local working directory is irrelevant. The daemon resolves paths against its own configured root. A client at `/home/user/project` and a daemon with workspace root `/srv/env` see different filesystems — the daemon's is authoritative.

### `ReadFileRequest.path` doc update

The comment in `are-core/src/request.rs:64` must be corrected to:

```rust
/// Environment-relative path (resolved against allowed roots; absolute host paths rejected by default).
pub path: String,
```

This ADR records the intended semantics. The source comment fix is a code change tracked separately.

## Consequences

### What this enables

- Gate 4 can implement path validation with a clear contract: every path is environment-relative, resolved against configured roots, with `../` traversal blocked.
- Allowed-roots enforcement is the single chokepoint for filesystem access — easy to audit and test.

### What this blocks

- Gate 4 implementation cannot begin until allowed-roots enforcement exists. The path semantics decision is a prerequisite.
- Clients cannot access arbitrary host filesystem locations. This is intentional — it is the core security guarantee of ARE.

### Migration

- Existing `ReadFileRequest` uses in tests (e.g., `request.rs` tests with literal paths) will continue to work as long as the test daemon has those paths under its configured root.
- The doc comment fix (`request.rs:64`) is a code change and must be made by the code agent, not this docs session.

### Not decided (deferred to Gate 4)

- Exact allowed-roots configuration format (file, environment variable, daemon flag).
- Symlink traversal behavior (follow or block?).
- TOCTOU mitigation strategy.
- Write-path semantics (Gate 7) — likely the same environment-relative model, but that decision is separate.
