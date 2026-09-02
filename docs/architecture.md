# ARE Architecture

**Gate 3.5 — 2026-09-01**

---

## Overview

Agent Remote Environment (ARE) provides a secure, agent-oriented abstraction for operating on remote Linux machines. The fundamental guarantee: once an agent is bound to an environment, every operation unambiguously occurs on the remote machine. There is no local fallback.

---

## Component Responsibilities

### `are-core`

Domain models, identifiers, and types shared by all other crates.

Contains:

- `EnvironmentId`, `SessionId`, `ProcessId`
- Request types, response types, error types
- Capability models

**Constraints (non-negotiable):**

```
NO networking
NO filesystem access
NO process execution
NO TLS implementation
```

`are-core` is a pure data/types crate. It depends on no other workspace crate and introduces no I/O.

### `are-client`

Remote environment client. Provides the transport-agnostic client API that agents and adapters call.

Contains:

- Transport abstraction (connection lifecycle)
- Session client logic
- Environment API surface

**Constraints:**

```
MUST NOT execute local shell commands
MUST NOT perform implicit local filesystem access
```

The client sends requests over the transport and receives responses. It never silently executes operations on the local machine.

### `are-daemon` (`ared`)

The remote daemon. Runs on the target Linux machine and is the trust anchor for that environment.

Contains:

- Request handling (inbound RPC/service)
- Authentication and authorization
- Session manager
- Process backend
- Filesystem backend

The daemon is the only component that touches the remote machine's OS. It enforces all security policy.

### `are-cli` (`are`)

The command-line interface for human operators.

Contains:

- Environment management commands
- Connection testing
- Daemon interaction
- Diagnostics

The CLI depends on `are-core` and `are-client`. It does not contain business logic — it delegates to the client.

---

## Trust Boundaries

### Agent vs. Client vs. Daemon

```
┌─────────────────────────────────────────────────┐
│  Agent / Adapter (untrusted — runs on user      │
│  machine, may be compromised)                   │
│                                                 │
│  Trust: none. Every operation must be explicitly│
│  authorized by the daemon.                      │
└──────────────────────┬──────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────┐
│  ARE Client (untrusted — runs on user machine,  │
│  transports requests to daemon)                 │
│                                                 │
│  Trust: none. No local fallback. No ambient     │
│  authority.                                     │
└──────────────────────┬──────────────────────────┘
                       │
                       │ TLS / mTLS
                       │ (transport boundary)
                       ▼
┌─────────────────────────────────────────────────┐
│  ared — Daemon (trust anchor on remote machine) │
│                                                 │
│  Trust: this component IS the security policy.  │
│  It authenticates the client, authorizes each   │
│  request, and enforces environment boundaries.  │
└──────────────────────┬──────────────────────────┘
                       │
                       ▼
               Remote Linux Machine
         (authoritative environment — no
          operations occur elsewhere)
```

### Transport Boundary

The boundary between client and daemon is TLS/mTLS. All data in transit is encrypted and mutually authenticated. No plaintext protocol exists.

### Environment Boundary

Each environment has a defined set of allowed roots (filesystem paths, capabilities). The daemon enforces these per-request. Compromising one environment does not grant access to another.

---

## Security / Identity (Gate 2 + Gate 3)

**Design document:** `docs/identity.md`

### Machine Identity

> **Status: IMPLEMENTED.** `MachineIdentity` and `TrustAnchor` types are implemented in `are-core`. Certificate generation and mTLS handshake are implemented in Gate 3.

Every daemon and client is **designed to possess** a machine identity consisting of a keypair, an X.509 certificate, and a stable machine identifier. Private keys never leave the host and are never serialized. Public-facing identity is expressed as:

```
MachineIdentity {
    id: "dev-vm",
    public_key_fingerprint: "sha256:<64 hex>",
    certificate_pem: "-----BEGIN CERTIFICATE-----..."
}
```

### Trust Model

> **Status: IMPLEMENTED (mTLS only).** TLS 1.3 mutual authentication is implemented in Gate 3 via rustls/webpki. Revocation, capability enforcement, and rotation are designed only.

- **Client ↔ Daemon:** Mutual TLS 1.3 (mTLS). Both sides present certificates and validate the peer.
- **Trust anchors:** `SelfSigned` (development only) or `CaSigned` (production).
- **No permanent shared secrets.** Every credential is revocable and time-limited.

### Enrollment

> **Status: DESIGNED only.** `EnrollmentCredential` struct exists in `are-core`, but no enrollment endpoint or issuance flow is implemented.

One-time enrollment credentials bootstrap new daemons. Properties: short-lived (< 1h), single-use, revocable, scoped to one environment + capability set. Enrollment credentials **never** become permanent machine credentials.

### Revocation

> **Status: DESIGNED only.** Gate 3 checks mTLS certificate validity + expiry via rustls/webpki. There is no CRL, no revocation list, and no runtime revocation check. The scenarios below describe intended future behavior.

Four revocation scenarios with documented detection → action → recovery:

| Scenario | Action | Status |
|----------|--------|--------|
| Client credential revoked | Reject requests, terminate sessions | DESIGNED |
| Daemon credential revoked | Deny connections, invalidate sessions | DESIGNED |
| Environment disabled | Terminate all sessions, deny new requests | DESIGNED |
| Session terminated | Terminate processes, preserve state | DESIGNED |

**See:** `docs/identity.md` §4 for full revocation matrix.

### Constraints

- **No crypto in `are-core`.** Identity types are pure data shapes. Cryptographic enforcement (rustls, rcgen) is implemented in Gate 3.
- **No custom cryptography.** Established libraries only (rustls, webpki, rcgen).

---

## Data Flow

```
Agent
  │
  │ (adapter calls environment API)
  ▼
ARE Client
  │
  │ (serializes request, sends over TLS)
  │
  ├──────── TLS / mTLS ─────────┐
  │                              │
  ▼                              ▼
┌──────────────────────────────────────┐
│  ared (daemon on remote Linux box)   │
│                                      │
│  1. Authenticate client (mTLS cert)  │
│  2. Authorize request (capabilities) │
│  3. Validate path / operation        │
│  4. Execute on remote OS             │
│  5. Return result                    │
└──────────────────────────────────────┘
  │
  ▼
Remote Linux Machine (authoritative)
```

**Key invariant:** The remote machine is authoritative. The client never falls back to local execution. If the remote is unreachable, the operation fails — it does not silently succeed locally.

---

## Crate Dependency Graph

```
are-cli (binary: are)
  ├── are-core
  └── are-client
        └── are-core

are-daemon (binary: ared)
  └── are-core
```

- `are-core` has zero workspace dependencies — standalone.
- `are-client` depends only on `are-core`.
- `are-daemon` depends only on `are-core` (does not depend on `are-client`).
- `are-cli` depends on both `are-core` and `are-client`.

This ensures `are-core` can be used independently by any future component (e.g., a relay in Gate 11, or an agent integration in Gate 9) without pulling in client or daemon logic.

---

## Workspace Layout

```
are/
├── Cargo.toml              (workspace root)
├── crates/
│   ├── are-core/           (domain models, no I/O)
│   ├── are-client/         (transport client, no local exec)
│   ├── are-daemon/         (remote daemon, trust anchor)
│   └── are-cli/            (CLI frontend)
├── docs/
│   ├── architecture.md     (this file)
│   ├── threat-model.md     (threat model)
│   └── decisions/          (ADR directory)
└── tests/                  (integration tests)
```

---

## Gate Reference

This architecture is the foundation (Gate 0). Future gates add capability incrementally:

| Gate | Scope | Status |
|------|-------|--------|
| 0 | Repository and architecture foundation | ✓ Complete |
| 1 | Environment domain model | ✓ Complete |
| 2 | Security model and identity design | ✓ Complete |
| 3 | Minimal secure connection (TLS 1.3 mTLS + GetEnvironmentInfo) | ✓ Complete (scoped: TLS 1.3 mTLS + GetEnvironmentInfo only; revocation/rotation/capability enforcement = designed) |
| 3.5 | Boundary cleanup (implemented vs designed, ADRs, advertised_capabilities, path semantics) | ✓ Complete |
| 4 | Read-only filesystem access | Pending |
| 5 | Process execution (structured, no shell) | Pending |
| 6 | Persistent agent sessions | Pending |
| 7 | Filesystem write operations | Pending |
| 8 | Capability-based authorization | Pending |
| 9 | Agent integration prototype | Pending |
| 10 | CLI and SSH-level usability | Pending |
| 11 | Reverse connection architecture | Pending |
| 12 | Service management | Pending |
| 13 | Package management | Pending |
| 14 | Protocol stabilization review | Pending |

**STOP gates** exist after every gate. No gate is started until the previous gate's deliverables are reviewed and approved.

**Gate 3 is minimal secure connection.** TLS 1.3 mTLS with length-prefixed JSON framing and GetEnvironmentInfo RPC. No filesystem or process operations yet. See `docs/identity.md` for trust model and `crates/are-daemon/tests/gate3_security.rs` for mTLS security tests.

---

## Design Rules (Summary)

1. **No custom cryptography.** Use audited libraries and OS primitives.
2. **Environment identity is explicit.** Every operation names its environment; never inferred from local working directory.
3. **No local fallback.** If bound to a remote environment, all operations occur remotely.
4. **Security before convenience.** No arbitrary remote execution without authentication and authorization.
5. **No premature protocol standardisation.** The protocol emerges from real usage (Gate 14).

See `PLAN.md` Sections 5 and 8 for full design rules and security principles.
