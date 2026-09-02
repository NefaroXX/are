# ARE Identity Architecture

**Gate 3 — 2026-09-01**

---

## Status

This document defines the identity and trust model for ARE. It mixes **design** and **implementation** — the distinction matters and is marked explicitly below. Gate 3 implements TLS 1.3 mTLS (certificate validation + expiry via rustls/webpki) and the `GetEnvironmentInfo` RPC. Everything else described here — enrollment flow, revocation enforcement, credential rotation, capability-based authorization — is **designed only** and not enforced at runtime.

---

## 1. Machine Identity

> **Implementation status:** `MachineIdentity` and `TrustAnchor` types are **implemented** as pure data shapes in `are-core`. Cryptographic enforcement (certificate generation, TLS handshake, trust validation) is implemented in Gate 3 via rustls/webpki.

### What Constitutes Identity

Every ARE daemon and client is **designed to possess** a machine identity consisting of:

| Component | Description |
|-----------|-------------|
| **Keypair** | An asymmetric key pair (e.g. Ed25519 or ECDSA P-256). The private key **never** leaves the host and is **never** serialized or transmitted. |
| **Certificate** | An X.509 certificate binding the public key to a machine identifier. For development: self-signed. For production: CA-signed. |
| **Fingerprint** | A `sha256:<64 hex chars>` hash of the Subject Public Key Info (SPKI). Stable across certificate renewals if the key is reused. |
| **Machine ID** | A stable, human-readable identifier (e.g. hostname `dev-vm`). Lowercase alphanumeric + hyphens/underscores/dots, max 64 bytes. |

### Identity Types (implemented in `are-core`)

```rust
pub struct MachineIdentity {
    pub id: String,                           // stable machine identifier
    pub public_key_fingerprint: String,       // sha256:<64 hex chars>
    pub certificate_pem: String,              // X.509 PEM
}
```

**Key invariant:** Private key material is **never** stored in `MachineIdentity` or any serializable type. The private key lives in a file on the daemon host (e.g. `~/.config/ared/key.pem`) with restricted file permissions (0600).

### Certificate Generation

| Mode | Tool | Use Case |
|------|------|----------|
| Development | `rcgen` (self-signed) | Local testing, single-machine setups |
| Production | Internal CA or public CA | Multi-machine deployments, production trust |

Gate 2 does **not** add `rcgen` or `rustls` as dependencies. This is a design constraint — Gate 3 implements the actual certificate handling.

### Trust Anchors

```rust
pub enum TrustAnchor {
    SelfSigned,           // development only
    CaSigned(String),     // production: CA certificate PEM
}
```

The trust anchor determines how the peer's certificate chain is validated. Self-signed mode is explicitly flagged as development-only and must never appear in production configurations.

---

## 2. Trust Model

### mTLS (Mutual TLS)

The target authentication model is **mutual TLS 1.3**: both client and daemon present certificates, and both validate the peer's certificate against a trust anchor.

```
┌──────────────┐                      ┌──────────────┐
│    Client     │                      │    Daemon     │
│              │                      │              │
│  presents    │──── ClientHello ────▶│              │
│  cert + key  │                      │  presents    │
│              │◀── ServerHello + ────│  cert + key  │
│  validates   │    daemon cert       │  validates   │
│  daemon cert │◀═══ mTLS channel ═══▶│  client cert │
│              │                      │              │
└──────────────┘                      └──────────────┘
```

### Trust Boundaries

| Boundary | Protection | Gate |
|----------|-----------|------|
| **Agent ↔ Client** | None — agent is untrusted. Every operation explicitly authorized by daemon. | Gate 8 |
| **Client ↔ Daemon** | mTLS. Both sides authenticate. Encrypted transport. | Gate 3 |
| **Daemon ↔ Remote OS** | Daemon IS the trust anchor. Enforces all policy. | Gate 0 (design) |

### No Permanent Shared Secrets

ARE never uses:

- Pre-shared keys (PSK) as permanent credentials
- Static tokens that grant indefinite access
- Passwords or API keys as primary authentication
- Any credential that cannot be revoked

Every credential has a defined lifetime and revocation path.

---

## 3. Enrollment Design

> **Implementation status: DESIGNED — not implemented at runtime.** `EnrollmentCredential` struct exists in `are-core` as a data type, but no enrollment endpoint exists, no token issuance flow is wired, and no validation logic runs against a real token store.

### One-Time Enrollment Credential

When a new daemon is provisioned, it needs a way to obtain its initial identity. This is the **enrollment** process.

```
┌──────────────┐         ┌──────────────┐         ┌──────────────┐
│   Operator   │         │    Daemon    │         │   Validator  │
│  (provision) │         │  (new host)  │         │  (Gate 3+)   │
└──────┬───────┘         └──────┬───────┘         └──────┬───────┘
       │                        │                        │
       │  1. Generate enrollment│                        │
       │     token (short-lived)│                        │
       ├───────────────────────▶│                        │
       │                        │  2. Present token +   │
       │                        │     keypair proof     │
       │                        ├───────────────────────▶│
       │                        │                        │
       │                        │  3. Validate token,    │
       │                        │     issue certificate  │
       │                        │◀───────────────────────┤
       │                        │                        │
       │                        │  4. Daemon now has     │
       │                        │     permanent identity │
       │                        │     (own keypair+cert) │
       │                        │                        │
       │  5. Enrollment token   │                        │
       │     is consumed and    │                        │
       │     cannot be reused   │                        │
```

### Enrollment Credential Properties

| Property | Value | Rationale |
|----------|-------|-----------|
| **Lifetime** | < 1 hour (recommended) | Limits exposure window if token is intercepted |
| **Single-use** | Yes | Prevents replay after initial enrollment |
| **Revocable** | Yes | Operator can invalidate before expiry |
| **Scope** | One environment + capability set | Principle of least privilege |
| **Becomes permanent?** | **Never** | Enrollment is bootstrap only — the daemon generates its own keypair |

### Enrollment State Machine

```
  ┌─────────┐     presented      ┌───────────┐
  │ ISSUED  │──────────────────▶│ CONSUMED  │
  └─────────┘                   └───────────┘
       │                             │
       │ expired                     │ (terminal)
       ▼                             │
  ┌───────────┐                      │
  │ EXPIRED   │                      │
  └───────────┘                      │
                                     │
       revoked                       │
       ▼                             │
  ┌───────────┐                      │
  │ REVOKED   │                      │
  └───────────┘                      │
                                     │
                                     ▼
                              ┌───────────┐
                              │ TERMINAL  │
                              └───────────┘
```

### Enrollment Credential Type (implemented in `are-core`)

```rust
pub struct EnrollmentCredential {
    pub token: String,                    // opaque, high-entropy
    pub environment_id: EnvironmentId,    // scoped to one environment
    pub capabilities: CapabilitySet,      // granted capabilities
    pub expires_at: String,               // ISO 8601
    pub single_use: bool,                 // always true
    pub issued_at: String,                // ISO 8601, for audit
}
```

**Validation logic:**
- Empty token → rejected
- Expired (now >= expires_at) → rejected
- Single-use and already consumed → rejected

### Important: Enrollment Does NOT Issue the Machine Identity

The enrollment token authenticates the *enrollment event*, not the machine permanently. After enrollment:

1. The daemon generates its own keypair (never shared).
2. The validator issues a certificate bound to the daemon's public key.
3. The enrollment token is consumed and discarded.
4. The daemon's permanent identity is its own keypair + certificate.

This means compromising an enrollment token gives an attacker a one-time window, not persistent access.

---

## 4. Revocation

> **Implementation status: DESIGNED — not enforced at runtime.** Gate 3 checks mTLS certificate validity and expiry via rustls/webpki. There is no CRL, no revocation list, no runtime revocation check, and no credential rotation logic. The revocation scenarios below describe intended Gate 3+ behavior, not current behavior.

### Revocation Scenarios

| Scenario | Detection | Action | Recovery |
|----------|-----------|--------|----------|
| **Client credential revoked** | Daemon checks cert against revocation list on each request | Reject all requests from that credential. Terminate active sessions. | Client re-enrolls with new identity. |
| **Daemon credential revoked** | Client cannot establish new TLS connections | Client connection fails. Existing sessions invalidated on next operation. | Operator re-provisions daemon identity. |
| **Environment disabled** | Daemon checks environment status on each request | Terminate all sessions for that environment. Deny new requests. | Operator re-enables environment. |
| **Session terminated** | Explicit operator action or idle timeout | Terminate all processes in session. Preserve working directory state. | Client creates new session (Gate 6). |

### Revocation Reason Types (implemented in `are-core`)

```rust
pub enum RevocationReason {
    Compromised,          // private key stolen
    Expired,              // natural expiry
    Administrative,       // operator action
    EnvironmentDisabled,  // environment shut down
}
```

### Revocation Mechanisms (designed, Gate 3+)

| Mechanism | Scope | Implementation |
|-----------|-------|---------------|
| **Certificate Revocation List (CRL)** | Daemon → client | Daemon maintains list of revoked client cert serial numbers. Checked on mTLS handshake. |
| **OCSP stapling** | Future | Daemon staples OCSP response for its own cert. Client validates. |
| **Credential invalidation endpoint** | Client → daemon | API call to revoke a specific credential. Requires admin capability. |
| **Environment disable** | Daemon-internal | Daemon refuses all requests for disabled environments. |

### Credential Rotation

> **Implementation status: DESIGNED — not implemented.** No rotation logic exists.

Rotation is the **designed** preferred response to compromise — not just revocation:

1. Revoke old credential (with reason: `Compromised`).
2. Generate new keypair.
3. Obtain new certificate (via re-enrollment or CA).
4. Update daemon configuration.
5. All clients must re-establish connections with new trust material.

Gate 2 designs the rotation interface. Gate 3 implements TLS certificate validation only. Automated rotation is deferred to a future gate.

---

## 5. Threat Model Update (Gate 2)

### Network Attacker

| Aspect | Gate 0 Status | Gate 2 Design |
|--------|--------------|---------------|
| **Observe traffic** | Not mitigated | TLS 1.3 encryption (Gate 3) |
| **Modify traffic** | Not mitigated | mTLS provides integrity + authenticity (Gate 3) |
| **Replay requests** | Not mitigated | TLS session resumption + request nonces (Gate 3) |
| **Certificate pinning** | Not designed | Trust anchor model defined — self-signed (dev) or CA-signed (prod) |

**Gate 2 contribution:** Trust anchor model and certificate format defined. Actual TLS enforcement deferred to Gate 3.

### Machine Impersonation

| Aspect | Gate 0 Status | Gate 2 Design |
|--------|--------------|---------------|
| **Impersonate daemon** | Not mitigated | mTLS — client validates daemon certificate (Gate 3) |
| **Impersonate client** | Not mitigated | mTLS — daemon validates client certificate (Gate 3) |
| **Stolen enrollment token** | Not designed | Single-use, short-lived, revocable — limits window |
| **Stolen machine key** | Not designed | Revocation + re-enrollment (documented above) |

**Gate 2 contribution:** Enrollment credential design limits impersonation window. Revocation matrix defined.

### Malicious Agent

| Aspect | Gate 0 Status | Gate 2 Design |
|--------|--------------|---------------|
| **Exceed authorized operations** | Not mitigated | Capability-based authorization (Gate 8) |
| **Access other environments** | Not mitigated | Environment isolation + capability scoping (Gate 8) |
| **Execute unauthorized processes** | Not mitigated | Executable allow/deny lists (Gate 5) |

**Gate 2 contribution:** Enrollment credentials are scoped to one environment + specific capabilities. This principle extends to machine credentials in Gate 8.

### Compromised Client

| Aspect | Gate 0 Status | Gate 2 Design |
|--------|--------------|---------------|
| **Stolen private key** | Not mitigated | Revocation terminates sessions + rejects requests |
| **Credential rotation** | Not designed | Re-enrollment flow documented above |
| **Scoped permissions** | Not implemented | Capabilities per environment (Gate 8) |
| **Blast radius** | Unbounded | One environment + limited capabilities per credential |

**Gate 2 contribution:** Revocation matrix and rotation procedure documented. Credential scope limited by design.

---

## 6. Constraints

### What Gate 2 Does NOT Add

- **No crypto dependencies:** No `rustls`, `rcgen`, `ring`, or `webpki` in `are-core`. These arrive in Gate 3.
- **No enrollment endpoint:** The enrollment flow is designed, not implemented.
- **No certificate verification logic:** Design only.
- **No networking or filesystem access in `are-core`:** Identity types are pure data shapes.

### What Gate 2 DOES Add

- `identity.rs` module in `are-core` with `MachineIdentity`, `EnrollmentCredential`, `TrustAnchor`, `RevocationReason` types.
- Validation logic for enrollment credentials (expiry, single-use).
- Fingerprint format validation (`sha256:<64 hex>`).
- `IdentityError` variant in `CoreError`.
- This architecture document.
- Threat model updates.

### What Gate 3 Adds (in addition to Gate 2)

- `rustls`, `rcgen`, `webpki` dependencies for TLS 1.3 mTLS.
- Certificate generation (self-signed for dev, CA-signed for prod).
- mTLS handshake: both client and daemon present and validate certificates.
- Trust anchor validation via rustls/webpki (expiry + chain validation).
- `GetEnvironmentInfo` RPC over length-prefixed JSON framing.
- **Not yet implemented:** enrollment flow, revocation enforcement, credential rotation, capability-based authorization.

---

## 7. Future Gate References

| Gate | Scope | Relationship to Identity |
|------|-------|------------------------|
| **Gate 3** | Minimal secure connection (mTLS) | Implements TLS 1.3 mTLS, certificate handling, trust validation (complete: scoped to cert validation + GetEnvironmentInfo only; revocation/rotation/capability enforcement = designed) |
| **Gate 8** | Capability-based authorization | Extends identity with per-environment capability scoping |
| **Gate 11** | Reverse connection (relay) | Relay must not become trust anchor — end-to-end identity independent of relay |
| **Gate 14** | Protocol stabilization | Identity protocol elements reviewed for standardization |

---

## 8. File Permissions (Design)

| File | Permissions | Owner | Notes |
|------|-------------|-------|-------|
| `~/.config/ared/key.pem` | 0600 | daemon user | Private key. Never transmitted. |
| `~/.config/ared/cert.pem` | 0644 | daemon user | Certificate. Shared during mTLS handshake. |
| `~/.config/ared/ca.pem` | 0644 | daemon user | Trust anchor. Used to validate client certs. |
| `~/.config/are/credentials.json` | 0600 | client user | Client identity. Contains private key reference. |

**Gate 2 constraint:** File permission enforcement is not implemented yet. This is the target design for Gate 3.

---

## 9. Credential Lifecycle Summary

```
  Provisioning          Enrollment            Steady State           Revocation
  ─────────────         ──────────            ─────────────          ──────────
  Operator creates      One-time token        Machine identity       Operator revokes
  enrollment token ───▶ presented to    ───▶  (keypair + cert)  ───▶ credential
  (short-lived,         daemon, daemon        used for mTLS,         (reason logged,
   single-use)          generates keypair     capability auth)       sessions terminated)
```
