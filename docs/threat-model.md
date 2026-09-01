# ARE Threat Model

**Gate 0 — 2026-09-01**

---

## Status

This is the initial threat model, authored at Gate 0. **No networking implementation exists yet.** Threats are identified and categorized; mitigations reference the gates where they will be implemented. This is an honest document — it states what is protected and what is not yet protected.

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

---

## Out of Scope (Gate 0)

- Custom encryption or key exchange algorithms
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

## Revocation Strategy (Placeholder)

Revocation is designed at Gate 2 but not implemented until credentials exist.

**Planned mechanisms:**

| Scenario | Response |
|----------|----------|
| Client credential revoked | Daemon rejects all requests from that credential. Active sessions terminated. |
| Daemon credential revoked | Client cannot reconnect. Existing sessions invalidated on next operation. |
| Environment disabled | All sessions for that environment terminated. New requests denied. |
| Session terminated | All processes in session terminated. Working directory state preserved for reconnection (Gate 6). |

**Credential properties (target):**

- Short-lived enrollment credentials (single use, time-limited)
- Machine credentials (long-lived but rotatable)
- No permanent shared secrets
- Revocation list or credential invalidation endpoint (mechanism TBD at Gate 2)

---

## Gate 0 Summary

| Threat | Mitigated at Gate 0? | Planned Gate |
|--------|-----------------------|--------------|
| Network attacker | No | Gate 3 (TLS/mTLS) |
| Compromised client | No | Gate 2 (revocation), Gate 8 (capabilities) |
| Compromised daemon | Design principle only | Operational concern |
| Compromised controller | Out of scope | Gate 11 |
| Malicious agent | No | Gate 8 (capabilities) |
| Credential theft | No | Gate 2 (short-lived creds, rotation) |
| Replay attacks | No | Gate 3 (TLS) |
| Privilege escalation | No | Gate 5 (structured exec), Gate 8 (capabilities) |
| Filesystem escape | No | Gate 4 (path validation) |
| Process escape | No | Gate 5 (structured exec, allow lists) |

**Honest assessment:** Gate 0 provides no runtime security. It establishes the architectural boundaries and documents the threat landscape so that subsequent gates implement mitigations with clear targets. The architecture ensures security is layered in, not bolted on.

---

## Security Principles Reference

From `PLAN.md` Section 8:

1. **Explicit Authority** — An agent must explicitly receive permission for each operation.
2. **Environment Isolation** — Every operation belongs to an explicit environment.
3. **Least Privilege** — Default policy is DENY. Capabilities are explicitly granted.
4. **No Ambient Authority** — Connecting successfully does not grant access to all environments, filesystems, or processes.
5. **Independent Machine Identity** — Compromising environment A does not compromise environment B.
6. **Explicit Dangerous Operations** — Delete, restart, remove, reboot must be separately authorized.
