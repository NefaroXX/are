# ARE Threat Model

**Gate 3.5 — 2026-09-01**

---

## Status

This is the initial threat model, authored at Gate 0, updated through Gate 3. **Gate 3 implements TLS 1.3 mTLS and `GetEnvironmentInfo` RPC.** Revocation enforcement, credential rotation, capability-based authorization, and all other identity-layer enforcement remain **designed only** and are not enforced at runtime. This is an honest document — it states what is protected and what is not yet protected.

---

## Trust Boundaries

| Boundary | Description |
|----------|-------------|
| **Agent ↔ Client** | Agent runs on user machine, untrusted. Client transports requests. No trust relationship — every operation must be authorized by the daemon. |
| **Client ↔ Daemon** | Transport boundary. Protected by TLS/mTLS (Gate 3). Daemon authenticates client; client authenticates daemon. |
| **Daemon ↔ Remote OS** | Daemon IS the trust anchor on the remote machine. It enforces all policy against the OS. |
| **Environment ↔ Environment** | Each environment is isolated. Compromising environment A does not grant access to environment B. |

---

## Attacker Categories

### 1. Network Attacker

**Capability:** Observe, modify, or replay traffic between client and daemon on the network.

**Impact:** Eavesdropping on commands, file contents, credentials; man-in-the-middle attacks; command injection via modified requests.

**Expected protection:**

- TLS 1.3 encryption in transit — **Gate 3** (minimal secure connection)
- mTLS mutual authentication — **Gate 3**
- Certificate pinning or trust-on-first-use — **Gate 2** (identity design)

**Gate 0 status:** NOT YET MITIGATED. No transport exists. Traffic is non-existent.

---

### 2. Compromised Client

**Capability:** Attacker has stolen or compromised the client machine or its private keys.

**Impact:** Can send arbitrary requests to the daemon using the client's identity. Can attempt to access environments beyond authorized scope.

**Expected protection:**

- Capability-based authorization (least privilege) — **Gate 8**
- Short-lived enrollment credentials — **Gate 2** (identity design)
- Credential revocation — **Gate 2** (revocation strategy)
- Scoped permissions per environment — **Gate 8**

**Gate 0 status:** NOT YET MITIGATED. No auth or capability model exists.

---

### 3. Compromised Daemon

**Capability:** Attacker has root or privileged access on the remote machine where `ared` runs.

**Impact:** Full control of the remote environment. Can read/write all files, execute all processes, intercept all client traffic on that machine.

**Expected protection:**

- Daemon runs with minimal necessary privileges (not root where possible) — **Gate 0** (design principle, enforcement in Gate 12+)
- Audit logging of all daemon actions — **Section 10 of PLAN.md**
- Environment isolation (compromising daemon on machine A does not affect machine B) — inherent in architecture

**Gate 0 status:** DESIGN PRINCIPLE ONLY. No enforcement mechanism exists yet.

**Note:** A fully compromised daemon is out of scope for most threat models — the daemon IS the trust anchor on its machine. Mitigation is operational: monitoring, audit logs, and rapid credential rotation.

---

### 4. Compromised Controller (Future / Relay)

**Capability:** In the future (Gate 11), a relay/controller may sit between client and daemon for NAT traversal. An attacker who compromises the relay can observe and modify routing metadata.

**Impact:** Relay sees connection metadata, timing, and volume. May be able to replay or inject requests if end-to-end encryption is not enforced.

**Expected protection:**

- End-to-end encrypted sessions (relay sees routing metadata only) — **Gate 11**
- Machine authentication independent of relay — **Gate 11**
- Relay compromise does not grant daemon access — **Gate 11**

**Gate 0 status:** OUT OF SCOPE for Gate 0. Relay architecture not yet designed.

---

### 5. Malicious Agent

**Capability:** The AI agent itself is adversarial. It has legitimate access to an environment but attempts to exceed its authorization.

**Impact:** Read files outside allowed scope, execute unauthorized processes, escape environment boundaries.

**Expected protection:**

- Capability-based authorization (per-operation) — **Gate 8**
- Allowed roots / filesystem boundaries — **Gate 4** (read-only) and **Gate 7** (write)
- Executable allow/deny lists — **Gate 5** (process execution)
- Default DENY policy — **Gate 8**

**Gate 0 status:** NOT YET MITIGATED. No capability model exists.

---

### 6. Credential Theft

**Capability:** Attacker obtains client or daemon private keys, enrollment tokens, or session credentials through theft, phishing, or compromise of the machine storing them.

**Impact:** Attacker can authenticate as the stolen identity and perform all operations that identity is authorized for.

**Expected protection:**

- Short-lived enrollment credentials (single use, revocable) — **Gate 2**
- Credential rotation mechanism — **Gate 2** (revocation strategy)
- No permanent shared secrets — **Gate 2**
- Daemon credential revocation terminates sessions — **Gate 2** (documented)

**Gate 0 status:** DESIGN ONLY. No credential management implemented.

---

### 7. Replay Attacks

**Capability:** Attacker captures a valid request and replays it later.

**Impact:** Duplicate operations (file writes, process execution); potential for unintended state changes.

**Expected protection:**

- TLS session resumption prevents replay at transport layer — **Gate 3**
- Request nonces or timestamps — **Gate 2** (identity design, to be specified)
- Idempotent operation design where possible — future consideration

**Gate 0 status:** NOT YET MITIGATED. No transport exists.

---

### 8. Privilege Escalation

**Capability:** Attacker with limited environment access attempts to gain higher privileges (e.g., root, access to other environments).

**Impact:** Unauthorized access to other environments, the host OS, or other users' data.

**Expected protection:**

- Capability-based authorization (explicit grants only) — **Gate 8**
- Environment isolation (no ambient authority) — **Gate 8**
- Process execution runs as configured user, not root by default — **Gate 5**
- No automatic privilege escalation — **PLAN.md Section 7** (non-goal)

**Gate 0 status:** NOT YET MITIGATED.

---

### 9. Filesystem Escape

**Capability:** Attacker crafts requests to read/write files outside the configured allowed roots.

**Impact:** Access to system files, other users' data, credentials, or sensitive configuration.

**Expected protection:**

- Path validation with allowed roots — **Gate 4** (read-only)
- Symlink traversal prevention — **Gate 4**
- TOCTOU mitigation — **Gate 4**
- Path traversal prevention (e.g., `../` filtering) — **Gate 4**

**Gate 0 status:** NOT YET MITIGATED. No filesystem operations exist.

---

### 10. Process Escape

**Capability:** Attacker executes processes that escape the environment boundary (e.g., spawn shells, access host resources not in allowed scope).

**Impact:** Arbitrary code execution outside the environment; full host compromise.

**Expected protection:**

- Structured process execution (no arbitrary shell strings) — **Gate 5**
- Executable allow/deny lists — **Gate 5**
- Working directory constrained to allowed roots — **Gate 5**
- Process runs as configured user — **Gate 5**

**Gate 0 status:** NOT YET MITIGATED. No process execution exists.

---

## Assumptions

1. **The remote Linux machine's OS kernel is trusted.** If the kernel is compromised, all bets are off. This is standard for any remote execution system.

2. **`ared` runs with the privileges of its installing user.** It does not install as root unless explicitly configured. The daemon's privilege level is a deployment decision.

3. **The initial enrollment flow happens over a trusted channel.** The first time a client connects to a daemon, the enrollment credential is transmitted securely (e.g., out-of-band, manual copy). This is Gate 2 work.

4. **Clock synchronization is approximately correct.** Time-based credential validation requires reasonably accurate clocks on both client and daemon machines.

5. **TLS implementations are correct.** We rely on established Rust TLS libraries (rustls or similar) rather than implementing custom cryptography.

6. **Machine identities are per-machine, not per-environment.** One machine identity serves all environments on that machine. Environment-level authorization is via capabilities, not separate identities. (Added Gate 2)

7. **Enrollment credentials are bootstrap-only.** They never become permanent machine credentials. After enrollment, the daemon possesses its own keypair and certificate. (Added Gate 2)

---

## Gate 2 Threat Update

**Date:** 2026-09-01  
**Scope:** Identity architecture design. No crypto enforcement yet.

### Network Attacker (TLS)

| Aspect | Gate 0 | Gate 2 | Gate 3 (enforcement) |
|--------|--------|--------|---------------------|
| Traffic encryption | Not mitigated | Trust anchor model defined | TLS 1.3 encrypts all traffic |
| Traffic integrity | Not mitigated | mTLS designed | mTLS provides integrity |
| Replay protection | Not mitigated | Request nonces designed | TLS session resumption + nonces |

**Gate 2 contribution:** Defines trust anchor types (`SelfSigned` for dev, `CaSigned` for prod) and certificate format (X.509 PEM). Establishes that no plaintext protocol will ever exist.

### Machine Impersonation (mTLS)

| Aspect | Gate 0 | Gate 2 | Gate 3 (enforcement) |
|--------|--------|--------|---------------------|
| Daemon impersonation | Not mitigated | Client validates daemon cert (designed) | mTLS handshake enforces |
| Client impersonation | Not mitigated | Daemon validates client cert (designed) | mTLS handshake enforces |
| Enrollment token theft | Not designed | Single-use + short-lived (<1h) + revocable | Token consumed on first use |
| Stolen machine key | Not designed | Revocation + re-enrollment procedure | CRL / invalidation endpoint |

**Gate 2 contribution:** Enrollment credential design limits impersonation window to <1 hour with single use. Revocation matrix documented with detection → action → recovery for all four scenarios.

### Malicious Agent (Capability Auth)

| Aspect | Gate 0 | Gate 2 | Gate 8 (enforcement) |
|--------|--------|--------|---------------------|
| Exceed authorized ops | Not mitigated | Enrollment scoped to specific capabilities | Per-operation capability check |
| Cross-environment access | Not mitigated | Enrollment scoped to one environment | Environment isolation enforced |
| Process escape | Not mitigated | Executable allow/deny lists designed | Gate 5 enforcement |

**Gate 2 contribution:** Enrollment credentials are scoped to exactly one environment and a specific capability set. This scoping principle extends to machine credentials in Gate 8.

### Compromised Client (Revocation/Rotation)

| Aspect | Gate 0 | Gate 2 | Future Gates |
|--------|--------|--------|-------------|
| Stolen private key | No response | Revocation terminates sessions + rejects requests | CRL enforcement (Gate 3) |
| Credential rotation | Not designed | Re-enrollment flow: revoke → new keypair → new cert | Automated rotation (future) |
| Blast radius | Unbounded | One environment + limited capabilities per credential | Scoped permissions (Gate 8) |
| Detection | None | Revocation logged with reason (`Compromised`, `Administrative`, etc.) | Audit logging (future) |

**Gate 2 contribution:** Revocation reasons defined (`Compromised`, `Expired`, `Administrative`, `EnvironmentDisabled`). Rotation procedure documented: revoke old → generate new keypair → re-enroll → update config.

### Honest Assessment

Gate 2 designs the identity architecture. Gate 3 implements mTLS and GetEnvironmentInfo. Specifically:

- ✅ Identity types defined (`MachineIdentity`, `EnrollmentCredential`, `TrustAnchor`, `RevocationReason`)
- ✅ Trust model documented (mTLS, enrollment flow, revocation matrix)
- ✅ Threat model updated with Gate 2 analysis
- ✅ TLS 1.3 mTLS implemented (Gate 3) — client and daemon validate peer certificates via rustls/webpki
- ✅ `GetEnvironmentInfo` RPC implemented (Gate 3)
- ❌ No enrollment endpoint (designed only, no token issuance/validation)
- ❌ No revocation list implementation (designed only)
- ❌ No credential rotation (designed only)
- ❌ No capability enforcement (designed only, Gate 8)

**The identity design is sound.** Gate 3 provides transport-layer authentication and encryption. The revocation, rotation, and capability layers are designed but not yet enforced — an attacker who bypasses the identity layer faces no cryptographic barrier beyond mTLS cert validation.

---

## Out of Scope (Gate 0)
- Windows or macOS support
- GUI or web dashboard
- Multi-user collaboration
- Distributed filesystems
- Container orchestration / Kubernetes
- Automatic agent discovery
- Full terminal emulation
- SSH replacement
- Remote desktop
- NAT traversal / reverse connections (Gate 11)

These are explicitly excluded from the initial implementation per `PLAN.md` Section 7.

---

## Revocation Strategy

Revocation is designed at Gate 2 (see `docs/identity.md` for full architecture). Implementation of enforcement mechanisms is deferred to Gate 3.

**Designed mechanisms:**

| Scenario | Response |
|----------|----------|
| Client credential revoked | Daemon rejects all requests from that credential. Active sessions terminated. |
| Daemon credential revoked | Client cannot reconnect. Existing sessions invalidated on next operation. |
| Environment disabled | All sessions for that environment terminated. New requests denied. |
| Session terminated | All processes in session terminated. Working directory state preserved for reconnection (Gate 6). |

**Credential properties (designed, Gate 2):**

- Short-lived enrollment credentials (single use, time-limited, < 1h TTL)
- Machine credentials (long-lived keypair + certificate, rotatable via re-enrollment)
- No permanent shared secrets — enrollment tokens never become permanent credentials
- Revocation reasons: `Compromised`, `Expired`, `Administrative`, `EnvironmentDisabled`

**See:** `docs/identity.md` §4 Revocation for full revocation matrix and rotation procedure.

---

## Gate Summary

| Threat | Gate 0 | Gate 2 (design) | Enforcement Gate |
|--------|--------|-----------------|------------------|
| Network attacker | No | Trust anchor model, cert format defined | Gate 3 (TLS/mTLS) |
| Compromised client | No | Revocation matrix, rotation procedure, scoped enrollment | Gate 3 (CRL) + Gate 8 (capabilities) |
| Compromised daemon | Design principle only | Revocation + re-enrollment documented | Operational concern |
| Compromised controller | Out of scope | — | Gate 11 |
| Malicious agent | No | Enrollment scoped to one environment + capabilities | Gate 8 (capabilities) |
| Credential theft | No | Single-use short-lived tokens, revocation reasons defined | Gate 3 (CRL) |
| Replay attacks | No | Request nonces designed | Gate 3 (TLS) |
| Privilege escalation | No | — | Gate 5 (structured exec), Gate 8 (capabilities) |
| Filesystem escape | No | — | Gate 4 (path validation) |
| Process escape | No | — | Gate 5 (structured exec, allow lists) |

**Gate 0:** Architectural boundaries and threat landscape documented. No runtime security.

**Gate 2:** Identity architecture designed. Types implemented in `are-core`. Trust model, enrollment flow, and revocation matrix documented. **No cryptographic enforcement yet.**

**Gate 3:** TLS 1.3 mTLS implemented (certificate validation + expiry via rustls/webpki). `GetEnvironmentInfo` RPC operational over length-prefixed JSON framing. **Not implemented:** enrollment flow, revocation enforcement, credential rotation, capability-based authorization (all designed only).

**Honest assessment:** Gate 3 provides transport-layer security (encryption + mutual authentication). Identity types are implemented and tested. Revocation, rotation, and capability enforcement remain designed only — the identity layer beyond mTLS cert validation is not yet enforced at runtime.

---

## Security Principles Reference

From `PLAN.md` Section 8:

1. **Explicit Authority** — An agent must explicitly receive permission for each operation.
2. **Environment Isolation** — Every operation belongs to an explicit environment.
3. **Least Privilege** — Default policy is DENY. Capabilities are explicitly granted.
4. **No Ambient Authority** — Connecting successfully does not grant access to all environments, filesystems, or processes.
5. **Independent Machine Identity** — Compromising environment A does not compromise environment B.
6. **Explicit Dangerous Operations** — Delete, restart, remove, reboot must be separately authorized.
