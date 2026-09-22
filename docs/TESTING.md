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

The 8 required test scenarios from PLAN.md §Gate 4 must be verified manually
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

## Remote Testing (LXC / VM)

The loopback `127.0.0.1` tests above prove protocol, mTLS, and handler logic,
but they do **not** prove the deployment works on a real Debian host, LXC
container, or VM. PLAN.md's STOP after Gate 4 requires:

> Test against a real VM or LXC.
>
> Attempt deliberate filesystem escape attacks.

Do not proceed past Gate 4 until remote testing passes on a real Debian
filesystem.

### Why loopback first, why remote is still required

Iterate at layer 2 (loopback) first because it isolates protocol bugs from
network, firewall, and certificate-SAN variables, and it runs fully on the
Windows dev machine before a Linux target exists. It catches framing, mTLS,
and path-logic defects in minutes.

Remote testing is still required because loopback cannot exercise:

- **Real filesystem semantics** — allowed-root canonicalization on a real
  Debian FS, real permission bits (`chmod 000`, `root` vs non-root), real
  symlink follow behavior (scenarios 7–8), and filesystem boundary behavior
  for a root like `/home/projects`.
- **`/etc/os-release` platform detection** — the daemon reads it to report
  `Platform::Debian` / `Platform::Ubuntu` / `Platform::GenericLinux`.
- **Cert SAN matching** — the server certificate must carry a
  `subjectAltName` matching the remote IP/hostname, not just `localhost`.
  A `localhost`-only cert fails the TLS handshake against a remote IP.
- **Firewall / port reachability** — the container's port must actually be
  reachable from the client host.
- **`--address 0.0.0.0`** — the daemon binds `127.0.0.1` by default, which
  listens only on the container's loopback and is unreachable from other
  hosts.

### Three-layer test strategy

| Layer | What it proves | Cost |
|-------|----------------|------|
| 1. `cargo test` (unit + integration) | Path resolution, escape/symlink rejection, mTLS handshake logic | Seconds |
| 2. Loopback `127.0.0.1`, same machine | Full process pair (daemon + CLI), file-based mTLS certs, protocol framing | Minutes; runs on Windows dev |
| 3. Remote LXC / VM | Deployment: cert SAN, firewall, real Debian FS, symlinks, permissions, `/etc/os-release` | Slower; required by Gate 4 STOP |

---

### LXC on Proxmox — copy-paste steps

**Step 1 — Build the release binary (on the dev machine)**

```bash
cargo build --release -p are-daemon
# → target/release/ared
```

On a **Windows dev host**, `target/release/ared` is a Windows binary and
will not run in the container. Options:

- Build inside the container after copying the source
  (`cargo build --release -p are-daemon`; requires the Rust toolchain in the
  container), or
- Cross-compile with a Linux target **and** a working cross-linker:

  ```bash
  rustup target add x86_64-unknown-linux-gnu
  cargo build --release -p are-daemon --target x86_64-unknown-linux-gnu
  # → target/x86_64-unknown-linux-gnu/release/ared
  ```

**Step 2 — Copy the binary and certs into the container**

```bash
pct push <vmid> ./target/release/ared /usr/local/bin/ared
pct push <vmid> certs/server.pem /etc/are/server.pem
pct push <vmid> certs/server.key /etc/are/server.key
pct push <vmid> certs/ca.pem /etc/are/ca.pem
```

If the container has SSH instead:

```bash
scp target/release/ared certs/server.pem certs/server.key certs/ca.pem root@<container-ip>:
```

Secure the key inside the container:

```bash
pct exec <vmid> -- chmod 700 /etc/are/server.key
```

**Step 3 — Build the filesystem fixtures**

`--allowed-root` must exist and be canonicalizable before the daemon starts
(the daemon rejects a nonexistent root at startup). Recreate the Gate 4
fixtures, including the symlink escape chains:

```bash
pct exec <vmid> -- mkdir -p /home/projects/subdir
pct exec <vmid> -- sh -c 'echo hello > /home/projects/file.txt'
pct exec <vmid> -- sh -c 'echo nested > /home/projects/subdir/nested.txt'
pct exec <vmid> -- ln -s /etc /home/projects/link_outside
pct exec <vmid> -- ln -s /etc/hostname /home/projects/link2
pct exec <vmid> -- ln -s link2 /home/projects/link1
```

**Step 4 — Start the daemon inside the container**

```bash
pct exec <vmid> -- /usr/local/bin/ared listen \
  --address 0.0.0.0 \
  --port 9000 \
  --cert /etc/are/server.pem \
  --key /etc/are/server.key \
  --ca /etc/are/ca.pem \
  --allowed-root /home/projects \
  --environment-id dev-container
```

`--address 0.0.0.0` is required — the default `127.0.0.1` binds only the
container's loopback and is unreachable from the dev host. Foreground run is
fine for Gate 4 testing; a `systemd` service / on-boot setup is deferred to
Gate 12.

**Step 5 — Connect from the dev host**

```bash
./target/debug/are connect \
  --addr <container-ip>:9000 \
  --cert certs/client.pem \
  --key certs/client.key \
  --ca certs/ca.pem \
  --server-name <SAN> \
  --env-id dev-container
```

`--server-name` must match the server certificate's SAN (next section), and
`<container-ip>` must be the IP reachable from the dev host. Then **repeat all
8 Gate 4 scenarios from the Manual section against `<container-ip>:9000`
instead of `127.0.0.1`**, including deliberate escape attempts: every `../`
variant, absolute paths, symlinks to `/`, nested link chains, and any other
boundary-escape you can devise. Confirm expected failures (non-zero exit,
escape-rejected errors) on the real Debian filesystem.

---

### Generic VM (SSH) variant

Same three steps, replacing `pct exec` / `pct push` with `ssh` / `scp`, and
open the port on the VM's firewall:

```bash
ufw allow 9000/tcp        # ufw (Ubuntu/Debian)
# or
iptables -A INPUT -p tcp --dport 9000 -j ACCEPT
```

Confirm reachability from the dev host before testing:

```bash
nc -vz <vm-ip> 9000
```

---

### Cert SAN warning — regenerate the server cert

The certificates generated in [INSTALL.md](INSTALL.md) are SAN
`DNS:localhost,IP:127.0.0.1`. A `localhost`-only server cert **fails the TLS
handshake** against a remote IP. From the `certs/` directory, regenerate the
server cert with the container's actual IP and hostname:

```bash
openssl genrsa -out server.key 4096
openssl req -new -key server.key -out server.csr -subj "/CN=<hostname>"
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out server.pem -days 365 -sha256 -extensions v3_req \
  -extfile <(echo -e "[v3_req]\nsubjectAltName=IP:<container-ip>,DNS:<hostname>")
```

Re-copy the regenerated `server.pem` / `server.key` into `<container-ip>`'s
`/etc/are/`, restart the daemon, and pass
`--server-name <hostname-or-IP>` to the client. The CA and client certs do
not need regeneration.

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
