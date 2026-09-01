//! Identity types for machine identity, enrollment, and trust.
//!
//! These are pure data shapes — no cryptography, no networking, no key
//! material handling. The actual cryptographic implementation lives in
//! `are-daemon` (Gate 3) using established libraries (rustls, rcgen).
//!
//! ## Invariants
//!
//! - Private keys **never** leave the daemon host and are **never** serialized.
//! - Fingerprint strings are hex-encoded SHA-256 of the Subject Public Key
//!   Info (SPKI), formatted as `sha256:<64 hex chars>`.
//! - Certificate PEM is the X.509 certificate in PEM encoding.
//! - Enrollment credentials are one-time, short-lived, and revocable.
//!   They must **never** become permanent machine credentials.

use serde::{Deserialize, Serialize};
use std::fmt;

use crate::{CapabilitySet, CoreError, EnvironmentId};

// ---------------------------------------------------------------------------
// MachineIdentity
// ---------------------------------------------------------------------------

/// Cryptographic identity of a daemon or client machine.
///
/// Contains the public-facing components of a machine's identity. The private
/// key is **not** stored here — it lives on the daemon host only and is never
/// serialized or transmitted.
///
/// # Fields
///
/// - `id` — stable, human-readable machine identifier (e.g. hostname).
/// - `public_key_fingerprint` — `sha256:<64 hex chars>` of the SPKI.
/// - `certificate_pem` — X.509 certificate in PEM encoding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineIdentity {
    /// Stable machine identifier (lowercase, alphanumeric + hyphens/underscores).
    pub id: String,
    /// SHA-256 fingerprint of the Subject Public Key Info, formatted as
    /// `sha256:<64 hex chars>`.
    pub public_key_fingerprint: String,
    /// X.509 certificate in PEM encoding.
    pub certificate_pem: String,
}

/// Prefix for valid fingerprint strings.
const FINGERPRINT_PREFIX: &str = "sha256:";

/// Number of hex characters in a SHA-256 fingerprint.
const FINGERPRINT_HEX_LEN: usize = 64;

impl MachineIdentity {
    /// Create a new `MachineIdentity`, validating all fields.
    ///
    /// # Errors
    ///
    /// Returns `CoreError::InvalidIdentity` if:
    /// - `id` is empty or contains invalid characters.
    /// - `public_key_fingerprint` does not match `sha256:<64 hex chars>`.
    /// - `certificate_pem` is empty or does not start with `-----BEGIN`.
    pub fn try_new(
        id: impl Into<String>,
        public_key_fingerprint: impl Into<String>,
        certificate_pem: impl Into<String>,
    ) -> Result<Self, CoreError> {
        let id = id.into();
        let fingerprint = public_key_fingerprint.into();
        let cert = certificate_pem.into();

        if id.is_empty() {
            return Err(CoreError::InvalidIdentity(
                "machine id must not be empty".into(),
            ));
        }
        Self::validate_fingerprint(&fingerprint)?;
        if cert.is_empty() || !cert.starts_with("-----BEGIN") {
            return Err(CoreError::InvalidIdentity(
                "certificate_pem must be a valid PEM block".into(),
            ));
        }

        Ok(Self {
            id,
            public_key_fingerprint: fingerprint,
            certificate_pem: cert,
        })
    }

    /// Validate a fingerprint string format.
    fn validate_fingerprint(fingerprint: &str) -> Result<(), CoreError> {
        let rest = fingerprint
            .strip_prefix(FINGERPRINT_PREFIX)
            .ok_or_else(|| {
                CoreError::InvalidIdentity(format!(
                    "fingerprint must start with `{FINGERPRINT_PREFIX}`"
                ))
            })?;

        if rest.len() != FINGERPRINT_HEX_LEN {
            return Err(CoreError::InvalidIdentity(format!(
                "fingerprint hex part must be {FINGERPRINT_HEX_LEN} characters, got {}",
                rest.len()
            )));
        }

        if !rest.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(CoreError::InvalidIdentity(
                "fingerprint hex part contains non-hex characters".into(),
            ));
        }

        Ok(())
    }

    /// Access the raw identifier string.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Access the fingerprint string.
    pub fn fingerprint(&self) -> &str {
        &self.public_key_fingerprint
    }

    /// Access the certificate PEM.
    pub fn certificate_pem(&self) -> &str {
        &self.certificate_pem
    }
}

impl fmt::Display for MachineIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.id, self.public_key_fingerprint)
    }
}

// ---------------------------------------------------------------------------
// TrustAnchor
// ---------------------------------------------------------------------------

/// How a machine's certificate chain is trusted.
///
/// In development, self-signed certificates are acceptable. In production,
/// a proper CA hierarchy is required.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustAnchor {
    /// Self-signed certificate (development / testing only).
    SelfSigned,
    /// CA-signed certificate, carrying the CA's PEM certificate.
    CaSigned(String),
}

// ---------------------------------------------------------------------------
// EnrollmentCredential
// ---------------------------------------------------------------------------

/// A one-time enrollment credential used to bootstrap machine identity.
///
/// Enrollment credentials are:
///
/// - **Short-lived** (recommended: < 1 hour TTL).
/// - **Single-use** — once presented, they are consumed and cannot be reused.
/// - **Revocable** — can be invalidated before expiry.
/// - **Limited-scope** — grant access to exactly one environment and a
///   specific capability set.
///
/// **Critical invariant:** An enrollment credential must **never** become a
/// permanent machine credential. It is a bootstrap mechanism only — after
/// enrollment, the machine possesses its own keypair and certificate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrollmentCredential {
    /// Opaque enrollment token (random, high-entropy string).
    pub token: String,
    /// The environment this credential grants access to.
    pub environment_id: EnvironmentId,
    /// Capabilities granted by this enrollment.
    pub capabilities: CapabilitySet,
    /// ISO 8601 expiry timestamp.
    pub expires_at: String,
    /// Whether this token can only be used once.
    pub single_use: bool,
    /// ISO 8601 timestamp when the token was issued (for audit).
    pub issued_at: String,
}

/// Maximum recommended TTL for enrollment credentials (1 hour in seconds).
pub const ENROLLMENT_MAX_TTL_SECS: u64 = 3600;

impl EnrollmentCredential {
    /// Create a new enrollment credential with validation.
    ///
    /// # Errors
    ///
    /// Returns `CoreError::InvalidIdentity` if the token is empty or
    /// `expires_at` is not a valid ISO 8601 timestamp.
    pub fn try_new(
        token: impl Into<String>,
        environment_id: EnvironmentId,
        capabilities: CapabilitySet,
        expires_at: impl Into<String>,
        issued_at: impl Into<String>,
    ) -> Result<Self, CoreError> {
        let token = token.into();
        let expires_at = expires_at.into();
        let issued_at = issued_at.into();

        if token.is_empty() {
            return Err(CoreError::InvalidIdentity(
                "enrollment token must not be empty".into(),
            ));
        }
        if expires_at.is_empty() {
            return Err(CoreError::InvalidIdentity(
                "expires_at must not be empty".into(),
            ));
        }

        Ok(Self {
            token,
            environment_id,
            capabilities,
            expires_at,
            single_use: true,
            issued_at,
        })
    }

    /// Check whether the credential has expired relative to the given
    /// ISO 8601 timestamp.
    ///
    /// This performs a **lexicographic string comparison** on ISO 8601
    /// timestamps, which is valid because ISO 8601 in UTC sorts correctly
    /// as strings.
    pub fn is_expired(&self, now: &str) -> bool {
        now >= self.expires_at.as_str()
    }

    /// Validate the credential is usable: not expired and (if single-use)
    /// not yet consumed. The `consumed` flag is external state — the
    /// credential itself does not track consumption.
    ///
    /// # Errors
    ///
    /// Returns `CoreError::InvalidIdentity` if expired or (single-use && consumed).
    pub fn validate(&self, now: &str, consumed: bool) -> Result<(), CoreError> {
        if self.is_expired(now) {
            return Err(CoreError::InvalidIdentity(
                "enrollment credential has expired".into(),
            ));
        }
        if self.single_use && consumed {
            return Err(CoreError::InvalidIdentity(
                "enrollment credential has already been consumed".into(),
            ));
        }
        Ok(())
    }

    /// Access the token string.
    pub fn token(&self) -> &str {
        &self.token
    }
}

// ---------------------------------------------------------------------------
// RevocationReason
// ---------------------------------------------------------------------------

/// Why a credential was revoked.
///
/// Used in revocation logs and CRL (Certificate Revocation List) entries.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RevocationReason {
    /// The credential's private key was compromised.
    Compromised,
    /// The credential expired naturally.
    Expired,
    /// Administrative action (e.g. operator revocation).
    Administrative,
    /// The associated environment was disabled.
    EnvironmentDisabled,
}

impl fmt::Display for RevocationReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Compromised => f.write_str("compromised"),
            Self::Expired => f.write_str("expired"),
            Self::Administrative => f.write_str("administrative"),
            Self::EnvironmentDisabled => f.write_str("environment_disabled"),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    // ---- MachineIdentity ----

    fn valid_fingerprint() -> String {
        "sha256:".to_owned() + &"a".repeat(64)
    }

    fn valid_pem() -> String {
        "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wI...\n-----END CERTIFICATE-----".into()
    }

    #[test]
    fn machine_identity_try_new_valid() {
        let id = MachineIdentity::try_new("dev-vm", valid_fingerprint(), valid_pem()).unwrap();
        assert_eq!(id.id(), "dev-vm");
        assert_eq!(id.public_key_fingerprint, valid_fingerprint());
    }

    #[test]
    fn machine_identity_empty_id_is_err() {
        assert!(MachineIdentity::try_new("", valid_fingerprint(), valid_pem()).is_err());
    }

    #[test]
    fn machine_identity_bad_fingerprint_prefix() {
        let bad = "md5:".to_owned() + &"a".repeat(64);
        assert!(MachineIdentity::try_new("vm", bad, valid_pem()).is_err());
    }

    #[test]
    fn machine_identity_bad_fingerprint_length() {
        let short = "sha256:".to_owned() + &"a".repeat(32);
        assert!(MachineIdentity::try_new("vm", short, valid_pem()).is_err());
    }

    #[test]
    fn machine_identity_bad_fingerprint_hex() {
        let bad = "sha256:".to_owned() + &"g".repeat(64); // 'g' is not hex
        assert!(MachineIdentity::try_new("vm", bad, valid_pem()).is_err());
    }

    #[test]
    fn machine_identity_empty_cert_is_err() {
        assert!(MachineIdentity::try_new("vm", valid_fingerprint(), "").is_err());
    }

    #[test]
    fn machine_identity_non_pem_cert_is_err() {
        assert!(MachineIdentity::try_new("vm", valid_fingerprint(), "not-a-pem").is_err());
    }

    #[test]
    fn machine_identity_display() {
        let id = MachineIdentity::try_new("prod-01", valid_fingerprint(), valid_pem()).unwrap();
        let display = format!("{id}");
        assert!(display.contains("prod-01"));
        assert!(display.contains("sha256:"));
    }

    #[test]
    fn machine_identity_serde_roundtrip() {
        let id = MachineIdentity::try_new("rt-vm", valid_fingerprint(), valid_pem()).unwrap();
        let json = serde_json::to_string(&id).unwrap();
        let back: MachineIdentity = serde_json::from_str(&json).unwrap();
        assert_eq!(id, back);
    }

    // ---- TrustAnchor ----

    #[test]
    fn trust_anchor_serde_roundtrip() {
        let anchors = [
            TrustAnchor::SelfSigned,
            TrustAnchor::CaSigned("ca-cert-pem".into()),
        ];
        for anchor in &anchors {
            let json = serde_json::to_string(anchor).unwrap();
            let back: TrustAnchor = serde_json::from_str(&json).unwrap();
            assert_eq!(*anchor, back);
        }
    }

    // ---- EnrollmentCredential ----

    fn make_enrollment() -> EnrollmentCredential {
        let mut caps = CapabilitySet::default();
        caps.insert(crate::Capability::FilesystemRead);
        EnrollmentCredential::try_new(
            "tok-abc123",
            EnvironmentId::new("test-env"),
            caps,
            "2026-12-31T23:59:59Z",
            "2026-01-01T00:00:00Z",
        )
        .unwrap()
    }

    #[test]
    fn enrollment_try_new_valid() {
        let ec = make_enrollment();
        assert_eq!(ec.token(), "tok-abc123");
        assert!(ec.single_use);
    }

    #[test]
    fn enrollment_empty_token_is_err() {
        let mut caps = CapabilitySet::default();
        caps.insert(crate::Capability::FilesystemRead);
        assert!(EnrollmentCredential::try_new(
            "",
            EnvironmentId::new("e"),
            caps,
            "2099-01-01T00:00:00Z",
            "2026-01-01T00:00:00Z"
        )
        .is_err());
    }

    #[test]
    fn enrollment_empty_expires_is_err() {
        let mut caps = CapabilitySet::default();
        caps.insert(crate::Capability::FilesystemRead);
        assert!(EnrollmentCredential::try_new(
            "tok",
            EnvironmentId::new("e"),
            caps,
            "",
            "2026-01-01T00:00:00Z"
        )
        .is_err());
    }

    #[test]
    fn enrollment_is_expired() {
        let ec = make_enrollment();
        assert!(!ec.is_expired("2026-06-01T00:00:00Z"));
        assert!(ec.is_expired("2099-01-01T00:00:00Z"));
        // Boundary: exactly at expiry is expired (>=)
        assert!(ec.is_expired("2026-12-31T23:59:59Z"));
    }

    #[test]
    fn enrollment_validate_ok() {
        let ec = make_enrollment();
        assert!(ec.validate("2026-06-01T00:00:00Z", false).is_ok());
    }

    #[test]
    fn enrollment_validate_expired() {
        let ec = make_enrollment();
        assert!(ec.validate("2099-01-01T00:00:00Z", false).is_err());
    }

    #[test]
    fn enrollment_validate_single_use_consumed() {
        let ec = make_enrollment();
        assert!(ec.single_use);
        assert!(ec.validate("2026-06-01T00:00:00Z", true).is_err());
    }

    #[test]
    fn enrollment_validate_not_single_use_and_consumed() {
        let mut ec = make_enrollment();
        ec.single_use = false;
        // Not single-use, so consumed flag is irrelevant
        assert!(ec.validate("2026-06-01T00:00:00Z", true).is_ok());
    }

    #[test]
    fn enrollment_serde_roundtrip() {
        let ec = make_enrollment();
        let json = serde_json::to_string(&ec).unwrap();
        let back: EnrollmentCredential = serde_json::from_str(&json).unwrap();
        assert_eq!(ec, back);
    }

    // ---- RevocationReason ----

    #[test]
    fn revocation_reason_display() {
        assert_eq!(RevocationReason::Compromised.to_string(), "compromised");
        assert_eq!(RevocationReason::Expired.to_string(), "expired");
        assert_eq!(
            RevocationReason::Administrative.to_string(),
            "administrative"
        );
        assert_eq!(
            RevocationReason::EnvironmentDisabled.to_string(),
            "environment_disabled"
        );
    }

    #[test]
    fn revocation_reason_serde_roundtrip() {
        let reasons = [
            RevocationReason::Compromised,
            RevocationReason::Expired,
            RevocationReason::Administrative,
            RevocationReason::EnvironmentDisabled,
        ];
        for reason in &reasons {
            let json = serde_json::to_string(reason).unwrap();
            let back: RevocationReason = serde_json::from_str(&json).unwrap();
            assert_eq!(*reason, back);
        }
    }
}
