# ARE — Agent Remote Environment

> **Status: Gate 3.5 complete — boundary cleanup (implemented vs designed, advertised_capabilities, path semantics, wire protocol ADR, TLS 1.2 test, RpcResponse.id removed, future API gated). STOP for review before Gate 4. Do not use.**

ARE is a secure, agent-oriented remote environment system that lets AI coding agents operate on remote Linux machines as if those machines are their primary execution environment.

This repo is currently **private** while the gated implementation proceeds. See `PLAN.md` for the full 14-gate plan (Gates 0–14, strict STOP gates). Gates 0–3.5 are complete and awaiting STOP review.

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
3.5 Boundary Cleanup ← **we are here** ✓ complete (implemented vs designed, ADR-001/002, advertised_capabilities, RpcResponse.id removed, TLS 1.2 test, env-relative paths, future API gated)
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

Gates 0–3.5 deliverables (complete, STOP gate):

```
are/
├── Cargo.toml (workspace with tokio + rustls 0.23 + tokio-rustls + rcgen)
├── crates/are-core (76 tests; GetEnvironmentInfo + Rpc envelope (no id) + future types gated)
├── crates/are-daemon (tls.rs TLS 1.3-only + server.rs + framing.rs 16 MiB + handler.rs advertised_capabilities + 13 tests)
├── crates/are-client (tls.rs + connection.rs + framing.rs)
├── crates/are-cli (are connect + are doctor — advertised_capabilities)
├── docs/{architecture.md,threat-model.md,identity.md,decisions/001-wire-protocol-temporary.md,002-path-semantics.md}
└── tests/ gate3_security 7 tests (incl. TLS 1.2 rejected + no client cert)
```

Gate 3.5 added: docs implemented vs designed callouts, ADR-001 temporary wire protocol (NOT spec), ADR-002 env-relative path semantics, advertised_capabilities rename + docs, RpcResponse.id removed, TLS 1.2 rejection test, future WriteFile/Execute/Process* gated behind `feature=future` (not exported).

CI: fmt + clippy -D warnings + tests (97 tests total) — `.github/workflows/ci.yml`

**STOP — do not start Gate 4 without explicit approval.** See `PLAN.md` §6 and STOP after Gate 3.5.

---

Private repo. Contact owner for access.
