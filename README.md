# ARE — Agent Remote Environment

> **Status: Gate 2 complete — identity architecture design. STOP for review before Gate 3. Do not use.**

ARE is a secure, agent-oriented remote environment system that lets AI coding agents operate on remote Linux machines as if those machines are their primary execution environment.

This repo is currently **private** while the gated implementation proceeds. See `PLAN.md` for the full 14-gate plan (Gates 0–14, strict STOP gates). Gates 0–2 are complete and awaiting STOP review.

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
2. Security Model & Identity ← **we are here** ✓ complete (design + types, no crypto enforcement yet)
3. Minimal Secure Connection (TLS 1.3 + HTTP/2, mTLS, `GetEnvironmentInfo`)
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

Gates 0–2 deliverables (complete, STOP gate):

```
are/
├── Cargo.toml (workspace)
├── crates/are-core (Identity, EnrollmentCredential, TrustAnchor, RevocationReason + 70 domain tests)
├── docs/{architecture.md,threat-model.md,identity.md,decisions/}
└── tests/
```

Gate 2 added: identity types, enrollment design, revocation matrix, threat model update, identity architecture doc. No crypto deps yet — Gate 3 adds rustls/rcgen.

CI: fmt + clippy -D warnings + tests — `.github/workflows/ci.yml`

**STOP — do not start Gate 3 without explicit approval.** See `PLAN.md` §6 and STOP after Gate 2.

---

Private repo. Contact owner for access.
