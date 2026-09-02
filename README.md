# ARE — Agent Remote Environment

> **Status: Gate 4 complete — read-only filesystem (env-relative paths, allowed roots, traversal/symlink/escape/TOCTOU enforced, 16 MiB cap, file_metadata). STOP for review before Gate 5. Do not use.**

ARE is a secure, agent-oriented remote environment system that lets AI coding agents operate on remote Linux machines as if those machines are their primary execution environment.

This repo is currently **private** while the gated implementation proceeds. See `PLAN.md` for the full 14-gate plan (Gates 0–14, strict STOP gates). Gates 0–4 are complete and awaiting STOP review.

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
4. Read-Only Filesystem ← **we are here** ✓ complete (env-relative, allowed roots, canonicalization + symlink/escape/TOCTOU, file_metadata, 16 MiB cap, advertised read+list)
4. Read-Only Filesystem
5. Process Execution (structured, no shell)
6. Persistent Agent Sessions
7. Filesystem Writes (atomic)
8. Capability-Based Authorization
9. Agent Integration Prototype (OpenCode)
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

---

Private repo. Contact owner for access.
