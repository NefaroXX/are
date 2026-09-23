# ARE — Agent Remote Environment

> **Status: Gate 9 complete — Agent Integration Prototype (OpenCode-style adapter with Environment trait, session/process handles, 3 verified scenarios). STOP for review before Gate 10. Do not use.**

ARE is a secure, agent-oriented remote environment system that lets AI coding agents operate on remote Linux machines as if those machines are their primary execution environment.

This repo is currently **private** while the gated implementation proceeds. See `PLAN.md` for the full 14-gate plan (Gates 0–14, strict STOP gates). Gates 0–9 are complete and awaiting STOP review.

## Working Names

- `ared` — remote daemon
- `are` — CLI/client
- `are-protocol` — shared protocol types (if needed)

Name is provisional.

## Vision (from PLAN.md)

> An AI agent must never need to reason about whether a command, file operation, process, or workspace is local or remote. Once bound to an environment, every operation through that environment unambiguously occurs on the bound machine.

Targets: LXC containers, VMs, remote Linux servers (Debian/Ubuntu/Proxmox LXC), dev machines.

## Gates (summary)

0. Repository & Architecture Foundation ✓ complete
1. Environment Domain Model ✓ complete (transport-independent trait)
2. Security Model & Identity ✓ complete (design + types, mTLS design)
3. Minimal Secure Connection ✓ complete (TLS 1.3 mTLS + GetEnvironmentInfo)
3.5 Boundary Cleanup ✓ complete (implemented vs designed, ADR-001/002, advertised_capabilities, RpcResponse.id removed, TLS 1.2 test, env-relative paths, future API gated)
4. Read-Only Filesystem ✓ complete (env-relative, allowed roots, canonicalization + symlink/escape/TOCTOU, file_metadata, 16 MiB cap, advertised read+list)
5. Process Execution ✓ complete (structured, no shell, deny-wins + fail-closed allowlist, 8 MiB output caps, wait/terminate, CSPRNG ids)
6. Persistent Agent Sessions ✓ complete (create/resume/list/terminate, idle 3600s + lifetime 86400s expiry, session-bound procs, workdir inherit, session env, kill-on-expiry)
7. Filesystem Writes ✓ complete (atomic temp+fsync+rename, mkdir/rename/delete, blake3 content hashes, expected_hash conflicts, renameat2 NOREPLACE on Linux, typed NotFound/Conflict errors)
8. Capability-Based Authorization ✓ complete (blake3 cert-fingerprint principals, grants.json scopes, ownership isolation, Forbidden errors, --grants-file/--permissive-authz)
9. Agent Integration Prototype ← **we are here** ✓ complete (Environment trait, RemoteEnvironment, SessionHandle, ProcessHandle, 3 OpenCode scenarios verified on 192.168.0.13)
10. CLI & Usability
11. Reverse Connection (NAT/CGNAT)
12. Service Management
13. Package Management
14. Protocol Stabilization Review

**Do not proceed past a gate without explicit approval.** See `PLAN.md` §6 and Final Instruction.

## Development Rules

- Rust, Linux first
- No custom crypto — use audited libs
- Environment identity is explicit, no local fallback
- Security before convenience, least privilege default DENY

## Next Step

Gates 0–4 deliverables (complete, STOP gate):

```
are/
├── Cargo.toml (workspace with tokio + rustls 0.23 + tokio-rustls + rcgen + tempfile)
├── crates/are-core (85 tests; GetEnvironmentInfo + ReadFile/ListDirectory/GetFileMetadata + advertised_capabilities)
├── crates/are-daemon (fs.rs allowed roots + canonicalization + symlink/escape/TOCTOU + 16 MiB cap + handler.rs + 47 tests)
├── crates/are-client (read_file/list_directory/file_metadata via mTLS)
├── crates/are-cli (fs read/list/metadata + connect/doctor)
├── docs/{architecture.md,threat-model.md,identity.md,decisions/001,002}
└── tests/ gate3_security 7 tests
```

Gate 4 added: read_file, list_directory, file_metadata with env-relative paths (ADR-002), allowed roots canonicalization, path traversal/symlink/escape/absolute rejected, TOCTOU parent canonicalization, 16 MiB file cap, advertised_capabilities = read+list only (honest), 8/8 required test scenarios covered, 140 tests total.

CI: fmt + clippy -D warnings + tests (140 tests total) — `.github/workflows/ci.yml`

**STOP — do not start Gate 5 without explicit approval.** See `PLAN.md` §6 and STOP after Gate 4. Test against real VM/LXC and attempt deliberate filesystem escape attacks before proceeding.

## Quick Start (Gate 4)

```bash
# Build
cargo build

# Start daemon (ephemeral certs — dev mode only, single-process)
cargo run -p are-daemon -- listen --port 9000 --allowed-root ./test-workspace
```

For multi-process testing with the `are` CLI, generate file-based mTLS certs
(see [docs/INSTALL.md](docs/INSTALL.md)):

```bash
# Generate certs (one-time)
cd certs && openssl genrsa -out ca.key 4096 && openssl req -x509 -new -nodes -key ca.key -sha256 -days 365 -out ca.pem -subj "/CN=ARE Dev CA" && openssl genrsa -out server.key 4096 && openssl req -new -key server.key -out server.csr -subj "/CN=localhost" && openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out server.pem -days 365 -sha256 -extensions v3_req -extfile <(echo -e "[v3_req]\nsubjectAltName=DNS:localhost,IP:127.0.0.1") && openssl genrsa -out client.key 4096 && openssl req -new -key client.key -out client.csr -subj "/CN=are-client" && openssl x509 -req -in client.csr -CA ca.pem -CAkey ca.key -CAcreateserial -out client.pem -days 365 -sha256 && cd ..

# Start daemon with certs
./target/debug/ared listen --port 9000 --cert certs/server.pem --key certs/server.key --ca certs/ca.pem --allowed-root ./test-workspace

# Connect from another terminal
./target/debug/are connect --addr 127.0.0.1:9000 --cert certs/client.pem --key certs/client.key --ca certs/ca.pem
```

Full setup, all 8 filesystem security test scenarios, and troubleshooting:
- **[docs/INSTALL.md](docs/INSTALL.md)** — prerequisites, cert generation, daemon/CLI usage
- **[docs/TESTING.md](docs/TESTING.md)** — automated tests, manual verification, attack scenarios

---

Private repo. Contact owner for access.
