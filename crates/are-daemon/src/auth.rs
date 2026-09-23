//! Caller principal identity (Gate 8).
//!
//! A `Caller` is the daemon's view of "who is on this connection": the
//! `blake3:<64hex>` fingerprint of the DER bytes of the verified leaf
//! client certificate presented during the mTLS handshake.
//!
//! # Why fingerprint-only (no x509 parsing)
//!
//! The certificate has ALREADY been chain-verified by rustls
//! (`WebPkiClientVerifier` in `tls.rs`) before this code ever runs —
//! trust is established by the handshake, not by anything parsed here.
//! Parsing x509 (subject names, SANs, extensions) would add a parsing
//! dependency and a whole class of name-matching ambiguities (which field
//! is the identity? what if it is missing? how are collisions handled?)
//! for zero security benefit: the fingerprint binds the EXACT leaf key
//! material, is unambiguous, and rotates naturally (new cert = new
//! fingerprint = new grants entry). The daemon never needs to know "who"
//! a client claims to be — only that this exact credential holds these
//! grants.
//!
//! The fingerprint is an identifier, not a secret: it is safe to log and
//! to echo back in `GetEnvironmentInfoResponse.caller_fingerprint` (that
//! is how operators map `are fingerprint` output to grants-file keys).

/// An authenticated caller's identity for one connection.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Caller {
    /// `blake3:<64 lowercase hex>` over the leaf certificate DER bytes.
    pub fingerprint: String,
}

impl Caller {
    /// Build a caller from an already-computed fingerprint string.
    pub fn new(fingerprint: String) -> Self {
        Self { fingerprint }
    }

    /// Build a caller directly from leaf certificate DER bytes.
    pub fn from_leaf_der(der: &[u8]) -> Self {
        Self::new(fingerprint_der(der))
    }
}

/// Compute the `blake3:<hex>` fingerprint of DER bytes.
///
/// `blake3` is already a workspace dependency (content hashing); no new
/// crypto is introduced — this is a collision-resistant identifier, not
/// encryption, key exchange, or signatures (Rule 1 unaffected).
pub fn fingerprint_der(der: &[u8]) -> String {
    format!("blake3:{}", blake3::hash(der).to_hex())
}

/// Extract the caller from verified peer certificates (leaf first).
///
/// Returns `None` when no peer certificate is present. Under mTLS that is
/// unreachable (the handshake requires a client cert), so callers treat
/// `None` as fail-closed: log and drop the connection without dispatch.
pub fn caller_from_peer_certs(
    certs: Option<&[rustls::pki_types::CertificateDer<'_>]>,
) -> Option<Caller> {
    let leaf = certs?.first()?;
    Some(Caller::from_leaf_der(leaf.as_ref()))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn fingerprint_shape_is_blake3_prefixed_hex() {
        let fp = fingerprint_der(b"fake-der-bytes");
        assert!(fp.starts_with("blake3:"), "got: {fp}");
        let hex = fp.strip_prefix("blake3:").unwrap();
        assert_eq!(hex.len(), 64);
        assert!(hex.bytes().all(|b| b.is_ascii_hexdigit()));
        assert!(!hex.bytes().any(|b| b.is_ascii_uppercase()));
    }

    #[test]
    fn fingerprint_is_deterministic_and_sensitive() {
        let a = fingerprint_der(b"cert-a");
        assert_eq!(a, fingerprint_der(b"cert-a"));
        assert_ne!(a, fingerprint_der(b"cert-b"));
        assert_ne!(a, fingerprint_der(b""));
    }

    #[test]
    fn caller_from_peer_certs_needs_a_leaf() {
        assert!(caller_from_peer_certs(None).is_none());
        let empty: Vec<rustls::pki_types::CertificateDer<'static>> = vec![];
        assert!(caller_from_peer_certs(Some(&empty)).is_none());
        let leaf = rustls::pki_types::CertificateDer::from(vec![1u8, 2, 3]);
        let certs = [leaf];
        let caller = caller_from_peer_certs(Some(&certs)).unwrap();
        assert_eq!(caller.fingerprint, fingerprint_der(&[1u8, 2, 3]));
    }
}
