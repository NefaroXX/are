# ARE — Agent Remote Environment

> **Status: Gate 3 complete — minimal secure connection (TLS 1.3 mTLS + GetEnvironmentInfo). STOP for review before Gate 4. Do not use.**

ARE is a secure, agent-oriented remote environment system that lets AI coding agents operate on remote Linux machines as if those machines are their primary execution environment.

This repo is currently **private** while the gated implementation proceeds. See `PLAN.md` for the full 14-gate plan (Gates 0–14, strict STOP gates). Gates 0–3 are complete and awaiting STOP review.

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
3. Minimal Secure Connection ← **we are here** ✓ complete (TLS 1.3 mTLS + GetEnvironmentInfo over length-prefixed JSON)
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

Gates 0–3 deliverables (complete, STOP gate):

```
are/
├── Cargo.toml (workspace with tokio + rustls 0.23 + tokio-rustls + rcgen)
├── crates/are-core (info.rs GetEnvironmentInfo + Rpc envelope + 76 tests)
├── crates/are-daemon (tls.rs + server.rs + framing.rs + handler.rs + 13 tests)
├── crates/are-client (tls.rs + connection.rs + framing.rs + SecureClient)
├── crates/are-cli (are connect + are doctor)
├── docs/{architecture.md,threat-model.md,identity.md,decisions/}
└── tests/
```

Gate 3 added: TLS 1.3 mTLS (rustls), length-prefixed JSON framing (16 MiB limit), GetEnvironmentInfo RPC, ared listen + are connect/doctor, 6 security integration tests (5 failure modes must fail closed).

CI: fmt + clippy -D warnings + tests (96 tests total) — `.github/workflows/ci.yml`

**STOP — do not start Gate 4 without explicit approval.** See `PLAN.md` §6 and STOP after Gate 3.

---

Private repo. Contact owner for access.
