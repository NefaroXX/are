# ARE Testing Guide

**Gate 4 — Read-Only Filesystem**

This document covers automated tests, manual verification, and the required
Gate 4 filesystem security test scenarios.

---

## Automated Tests

### Run everything

```bash
cargo test --all-features
```

140 tests across 4 crates.

### Run individual crates

```bash
cargo test -p are-core          # domain models, IDs, capabilities, serialization
cargo test -p are-client        # client TLS, framing
cargo test -p are-daemon        # daemon handler, filesystem backend, session manager
```

### Run filesystem tests specifically

```bash
cargo test -p are-daemon fs
```

This runs the `fs.rs` unit tests: path resolution, allowed-root enforcement,
traversal/symlink/escape rejection, read_file, list_directory, file_metadata.

### Run Gate 3 mTLS security tests

```bash
cargo test -p are-daemon --test gate3_security -- --nocapture
```

7 integration tests:

| Test | What it checks |
|------|---------------|
| `test_valid_mtls_connect_and_get_info` | Happy path: valid certs, handshake succeeds, environment info returned |
| `test_invalid_client_certificate_rejected` | Client cert from wrong CA → rejected |
| `test_invalid_daemon_certificate_rejected` | Client trusts wrong CA → rejects daemon cert |
| `test_expired_credential_rejected` | Expired client cert → rejected |
| `test_unknown_credential_rejected` | Cert from rogue CA → rejected |
| `test_tls12_rejected` | TLS 1.2 client rejected by TLS 1.3-only server |
| `test_connection_without_authentication_rejected` | No client cert → rejected (mTLS required) |

### Formatting and linting

```bash
cargo fmt --check                    # formatting
cargo clippy --all-targets --all-features -- -D warnings   # lints
```

Both must pass before any commit. CI enforces these.

---

## Gate 4 Manual Filesystem Testing

The8 required test scenarios from PLAN.md §Gate 4 must be verified manually
against a running daemon. This section provides exact setup and commands.

### Setup: create the test workspace

```bash
# Create allowed root with test fixtures
mkdir -p /tmp/are-test/subdir
echo "hello world" > /tmp/are-test/file.txt
echo "nested content" > /tmp/are-test/subdir/nested.txt

# Symlink that escapes the root (Linux only)
ln -s /etc /tmp/are-test/link_outside

# Nested symlink chain (Linux only): link1 -> link2 -> outside/secret.txt
# (optional, for nested symlink test)
ln -s /etc/hostname /tmp/are-test/link2
ln -s link2 /tmp/are-test/link1
```

On Windows, skip symlink creation (see Windows notes below).

### Start the daemon

```bash
# Terminal 1: start daemon with file-based certs
./target/debug/ared listen \
  --port 9000 \
  --environment-id dev-vm \
  --cert certs/server.pem \
  --key certs/server.key \
  --ca certs/ca.pem \
  --allowed-root /tmp/are-test
```

### Run the client tests

Set a shell variable for the common flags:

```bash
ARE_CLIENT="./target/debug/are"
ARE_FLAGS="--addr 127.0.0.1:9000 --cert certs/client.pem --key certs/client.key --ca certs/ca.pem --env-id dev-vm"
```

### Scenario 1: Normal file — SHOULD SUCCEED

```bash
$ARE_CLIENT fs read $ARE_FLAGS file.txt
```

**Expected:** Prints `hello world` to stdout.

```bash
$ARE_CLIENT fs metadata $ARE_FLAGS file.txt
```

**Expected:** Size, is_file=true, is_dir=false.

### Scenario 2: Directory — SHOULD SUCCEED

```bash
$ARE_CLIENT fs list $ARE_FLAGS .
```

**Expected:** Lists `file.txt`, `subdir/`, and symlinks (if present) with sizes.

```bash
$ARE_CLIENT fs list $ARE_FLAGS subdir
```

**Expected:** Lists `nested.txt`.

```bash
$ARE_CLIENT fs metadata $ARE_FLAGS subdir
```

**Expected:** is_dir=true, is_file=false.

### Scenario 3: Missing file — SHOULD FAIL

```bash
$ARE_CLIENT fs read $ARE_FLAGS nonexistent.txt
```

**Expected:** `error: not found: nonexistent.txt` (or similar). Exit code non-zero.

```bash
$ARE_CLIENT fs metadata $ARE_FLAGS nonexistent.txt
```

**Expected:** Same not-found error.

### Scenario 4: Permission denied — SHOULD FAIL (Linux only)

```bash
# Create a file with no read permissions (run as non-root)
chmod 000 /tmp/are-test/file.txt
$ARE_CLIENT fs read $ARE_FLAGS file.txt
```

**Expected:** `error: permission denied: ...` Exit code non-zero.

```bash
# Restore permissions
chmod 644 /tmp/are-test/file.txt
```

### Scenario 5: Path traversal `../` — SHOULD FAIL

```bash
$ARE_CLIENT fs read $ARE_FLAGS ../etc/passwd
```

**Expected:** `error: path escapes allowed boundary: ...` (or `filesystem escape blocked`). Exit code non-zero.

```bash
$ARE_CLIENT fs read $ARE_FLAGS subdir/../../etc/passwd
```

**Expected:** Same escape error.

### Scenario 6: Absolute path `/etc/passwd` — SHOULD FAIL

```bash
$ARE_CLIENT fs read $ARE_FLAGS /etc/passwd
```

**Expected:** `error: invalid path: absolute path rejected: /etc/passwd`. Exit code non-zero.

### Scenario 7: Symlink outside root — SHOULD FAIL (Linux only)

```bash
$ARE_CLIENT fs read $ARE_FLAGS link_outside/passwd
```

**Expected:** `error: path escapes allowed boundary: ...`. Exit code non-zero.

```bash
$ARE_CLIENT fs list $ARE_FLAGS link_outside
```

**Expected:** Same escape error.

### Scenario 8: Nested symlink chain — SHOULD FAIL (Linux only)

```bash
$ARE_CLIENT fs read $ARE_FLAGS link1
```

**Expected:** `error: path escapes allowed boundary: ...`. The nested chain
(`link1 -> link2 -> /etc/hostname`) resolves outside the root. Exit code non-zero.

---

## Gate 3 Smoke Tests

These verify the mTLS connection works with file-based certs:

```bash
# Connection test
$ARE_CLIENT connect $ARE_FLAGS
# Expected: environment info printed

# Diagnostics
$ARE_CLIENT doctor $ARE_FLAGS
# Expected: "All checks passed."
```

---

## Windows Notes

- Backslash `\` paths are rejected as absolute (`\etc\passwd`).
- Drive-letter paths (`C:\...`) are rejected on all platforms.
- Symlink tests (scenarios 7, 8) require **Administrator** or **Developer Mode**
  enabled on Windows. Without it, `ln -s` fails or creates a file symlink that
  behaves differently.
- The `chmod 000` test (scenario 4) has no direct Windows equivalent. Skip it
  or use `icacls` to deny read access, but the daemon may not enforce it the
  same way.
- Use WSL for full-fidelity testing if on Windows.

---

## Test Summary

| # | Scenario | Expected | Linux | Windows |
|---|----------|----------|-------|---------|
| 1 | Normal file read | Success | Y | Y |
| 2 | Directory list/metadata | Success | Y | Y |
| 3 | Missing file | FAIL (not found) | Y | Y |
| 4 | Permission denied | FAIL (permission denied) | Y | partial |
| 5 | Path traversal `../` | FAIL (escape blocked) | Y | Y |
| 6 | Absolute path `/etc/passwd` | FAIL (absolute rejected) | Y | Y |
| 7 | Symlink outside root | FAIL (escape blocked) | Y | needs admin |
| 8 | Nested symlink chain | FAIL (escape blocked) | Y | needs admin |

---

## Further Reading

- [INSTALL.md](INSTALL.md) — Installation and first-run guide
- [architecture.md](architecture.md) — Trust boundaries and data flow
- [decisions/002-path-semantics.md](decisions/002-path-semantics.md) — ADR-002: environment-relative path contract
- [threat-model.md](threat-model.md) — Threat model
