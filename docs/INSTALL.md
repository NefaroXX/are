# ARE Installation & First-Run Guide

**Gate 4 — Read-Only Filesystem**

---

## Prerequisites

| Requirement | Version | Notes |
|-------------|---------|-------|
| Rust | 1.78+ (stable) | `rustup default stable` |
| `rustup` | latest | [rustup.rs](https://rustup.rs/) |
| OS | Linux (primary) | Windows dev OK with WSL recommended |
| `cargo` | comes with rustup | |
| `openssl` | any recent | Only needed for manual cert generation |

Check your toolchain:

```bash
rustc --version   # must be >= 1.78
cargo --version
```

---

## Clone

```bash
git clone https://github.com/NefaroXX/are.git
cd are
```

---

## Build

Debug build (fast compile, slower runtime):

```bash
cargo build
```

Release build (slow compile, optimized runtime):

```bash
cargo build --release
```

### Output binaries

| Binary | Path (debug) | Path (release) | Purpose |
|--------|-------------|----------------|---------|
| `ared` | `target/debug/ared` | `target/release/ared` | Remote daemon |
| `are` | `target/debug/are` | `target/release/are` | CLI client |

---

## Generate mTLS Certificates (Production / Multi-Machine)

For real testing across machines (or when you need the `are` CLI to connect to
`ared` as separate processes), you need file-based certificates. The commands
below generate a self-signed CA, a server cert, and a client cert — all valid
for `localhost` / `127.0.0.1`.

```bash
# Create a working directory for certs
mkdir -p certs && cd certs

# --- CA ---
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 \
  -out ca.pem -subj "/CN=ARE Dev CA"

# --- Server cert (SAN: localhost + 127.0.0.1) ---
openssl genrsa -out server.key 4096
openssl req -new -key server.key -out server.csr -subj "/CN=localhost"
openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out server.pem -days 365 -sha256 \
  -extensions v3_req \
  -extfile <(echo -e "[v3_req]\nsubjectAltName=DNS:localhost,IP:127.0.0.1")

# --- Client cert ---
openssl genrsa -out client.key 4096
openssl req -new -key client.key -out client.csr -subj "/CN=are-client"
openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out client.pem -days 365 -sha256
```

After this you have six files in `certs/`:

```
ca.pem / ca.key
server.pem / server.key
client.pem / client.key
```

---

## Ephemeral Dev Mode (Quick Start, No Cert Files)

If you omit `--cert`, `--key`, and `--ca` on the daemon, `ared` generates
**ephemeral in-memory certificates** via `rcgen`. This is fine for local
`cargo test` and single-process development, but has a critical limitation:

> **The `are` CLI cannot connect to an ephemeral-daemon unless it trusts the
> same ephemeral CA.** Ephemeral certs are never written to disk, so there is
> no CA file to pass to the client. For separate-process testing, use
> file-based certs (above).

---

## Run the Daemon

### With file-based certs (recommended for real testing)

```bash
./target/debug/ared listen \
  --port 9000 \
  --address 127.0.0.1 \
  --environment-id dev-vm \
  --cert certs/server.pem \
  --key certs/server.key \
  --ca certs/ca.pem \
  --allowed-root /path/to/your/workspace
```

### With ephemeral certs (single-process dev only)

```bash
./target/debug/ared listen \
  --port 9000 \
  --allowed-root ./test-workspace
```

The daemon prints a warning that it is using ephemeral certs. It listens on
`127.0.0.1:9000` by default.

### Daemon flags reference

| Flag | Default | Description |
|------|---------|-------------|
| `--port` | `9000` | TCP port to listen on |
| `--address` | `127.0.0.1` | Bind address |
| `--environment-id` | `default` | Environment name this daemon serves |
| `--cert` | *(ephemeral)* | Path to server certificate PEM |
| `--key` | *(ephemeral)* | Path to server private key PEM |
| `--ca` | *(ephemeral)* | Path to CA certificate PEM (for client verification) |
| `--allowed-root` | cwd | Allowed root directory for filesystem operations |

---

## Quick Dev Shortcut (cargo run)

For rapid iteration during development, `cargo run` builds and starts in one
step. This uses ephemeral certs — fine for `cargo test`, not for separate
terminal client connections.

```bash
cargo run -p are-daemon -- listen \
  --port 9000 \
  --allowed-root ./test-workspace
```

---

## Connect with the CLI

### Verify connection (using file-based certs)

```bash
./target/debug/are connect \
  --addr 127.0.0.1:9000 \
  --cert certs/client.pem \
  --key certs/client.key \
  --ca certs/ca.pem \
  --env-id dev-vm
```

Expected output:

```
Environment: dev-vm
  Machine:   your-hostname
  OS:        linux
  Platform:  Debian
  Version:   0.1.0
  Capabilities:
    - filesystem.read
    - filesystem.list
```

### Run diagnostics

```bash
./target/debug/are doctor \
  --addr 127.0.0.1:9000 \
  --cert certs/client.pem \
  --key certs/client.key \
  --ca certs/ca.pem \
  --env-id dev-vm
```

Expected output:

```
ARE Doctor v0.1.0

  TLS configuration ... ok
  Daemon reachable ... ok

  Environment: dev-vm
  Machine:     your-hostname
  Platform:    Debian
  Version:     0.1.0
  Capabilities:
    - filesystem.read
    - filesystem.list

All checks passed.
```

### CLI flags reference (`are`)

| Flag | Default | Description |
|------|---------|-------------|
| `--addr` | `127.0.0.1:9000` | Server address (host:port) |
| `--cert` | *(required)* | Path to client certificate PEM |
| `--key` | *(required)* | Path to client private key PEM |
| `--ca` | *(required)* | Path to CA certificate PEM |
| `--server-name` | `localhost` | Server hostname for SNI |
| `--env-id` | `default` | Environment ID to query |

---

## Filesystem Operations (Gate 4)

Once connected, you can read files, list directories, and inspect metadata.
All paths are **environment-relative** — resolved against the daemon's
`--allowed-root`. See [TESTING.md](TESTING.md) for full test scenarios.

```bash
# Read a file
./target/debug/are fs read \
  --addr 127.0.0.1:9000 \
  --cert certs/client.pem \
  --key certs/client.key \
  --ca certs/ca.pem \
  --env-id dev-vm \
  file.txt

# List directory
./target/debug/are fs list \
  --addr 127.0.0.1:9000 \
  --cert certs/client.pem \
  --key certs/client.key \
  --ca certs/ca.pem \
  --env-id dev-vm \
  .

# Get file metadata
./target/debug/are fs metadata \
  --addr 127.0.0.1:9000 \
  --cert certs/client.pem \
  --key certs/client.key \
  --ca certs/ca.pem \
  --env-id dev-vm \
  file.txt
```

---

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `error: failed to configure TLS` | Cert/key/CA paths wrong or unreadable | Check file paths and permissions |
| `error: connection refused` | Daemon not running or wrong port | Start daemon, verify `--port` and `--addr` |
| TLS handshake error | Client cert not signed by daemon's CA, or wrong `--server-name` | Ensure both sides use the same CA; `--server-name` must match cert CN/SAN |
| `path escapes allowed boundary` | Attempted traversal or symlink escape | Expected for attack paths — see TESTING.md |
| `absolute path rejected` | Passed `/etc/passwd` or similar | Paths must be environment-relative (no leading `/`) |

---

## Next Steps

- [TESTING.md](TESTING.md) — Full testing guide for Gates 0–4
- [architecture.md](architecture.md) — Component and trust boundary overview
- [identity.md](identity.md) — Identity and mTLS design
- [PLAN.md](../PLAN.md) — Full 14-gate project plan
