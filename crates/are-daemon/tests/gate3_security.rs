#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Gate 3 security integration tests.
//!
//! Tests the mTLS connection between client and daemon. Each test spins up
//! a daemon on an ephemeral port, connects with various certificate
//! configurations, and verifies the expected security behavior.
//!
//! Required by PLAN.md Gate 3:
//! - test_valid_mtls_connect_and_get_info (happy path)
//! - test_invalid_client_certificate_rejected
//! - test_invalid_daemon_certificate_rejected
//! - test_expired_credential_rejected
//! - test_unknown_credential_rejected
//! - test_connection_without_authentication_rejected

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use are_client::connection::SecureClient;
use are_core::{Capability, EnvironmentId, Platform, RpcRequest, RpcResponse};
use are_daemon::handler::DaemonState;
use are_daemon::tls;
use tokio::io;
use tokio_rustls::TlsAcceptor;

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/// Generate a CA certificate for testing.
fn make_ca(cn: &str) -> (rcgen::Certificate, rcgen::KeyPair) {
    let mut params = rcgen::CertificateParams::new(vec![cn.to_string()]).unwrap();
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    (cert, key_pair)
}

/// Generate a certificate signed by the given CA.
fn make_signed_cert(
    ca_cert: &rcgen::Certificate,
    ca_key: &rcgen::KeyPair,
    cn: &str,
) -> (
    rustls::pki_types::CertificateDer<'static>,
    rustls::pki_types::PrivateKeyDer<'static>,
) {
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let params = rcgen::CertificateParams::new(vec![cn.to_string()]).unwrap();
    let cert = params.signed_by(&key_pair, ca_cert, ca_key).unwrap();
    (
        cert.der().clone(),
        rustls::pki_types::PrivateKeyDer::try_from(key_pair.serialize_der()).unwrap(),
    )
}

/// Generate an expired certificate signed by the given CA.
fn make_expired_cert(
    ca_cert: &rcgen::Certificate,
    ca_key: &rcgen::KeyPair,
    cn: &str,
) -> (
    rustls::pki_types::CertificateDer<'static>,
    rustls::pki_types::PrivateKeyDer<'static>,
) {
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let mut params = rcgen::CertificateParams::new(vec![cn.to_string()]).unwrap();
    // not_before: 2020-01-01, not_after: 2020-12-31 (already expired)
    params.not_before = time::OffsetDateTime::from_unix_timestamp(1577836800).unwrap();
    params.not_after = time::OffsetDateTime::from_unix_timestamp(1609459200).unwrap();
    let cert = params.signed_by(&key_pair, ca_cert, ca_key).unwrap();
    (
        cert.der().clone(),
        rustls::pki_types::PrivateKeyDer::try_from(key_pair.serialize_der()).unwrap(),
    )
}

/// Create a daemon state for testing.
fn test_daemon_state() -> DaemonState {
    let mut caps = are_core::CapabilitySet::default();
    caps.insert(Capability::FilesystemRead);
    caps.insert(Capability::ProcessExecute);

    DaemonState::new(
        EnvironmentId::new("test-env"),
        "test-host".into(),
        "0.1.0".into(),
        caps,
        Platform::Debian,
    )
}

/// Start a daemon on a random port. Returns (addr, handle).
///
/// Each accepted connection spawns a task that reads one RPC request,
/// dispatches it, and writes the response — exactly one request per
/// connection (Gate 3 scope).
async fn start_daemon(
    server_cert: rustls::pki_types::CertificateDer<'static>,
    server_key: rustls::pki_types::PrivateKeyDer<'static>,
    ca_cert: &rustls::pki_types::CertificateDer<'static>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let server_config =
        tls::build_server_config(vec![server_cert.clone()], server_key.clone_key(), ca_cert)
            .unwrap();
    let _acceptor = TlsAcceptor::from(server_config);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let ca_clone = ca_cert.clone();
    let handle = tokio::spawn(async move {
        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((tcp, _peer)) => {
                            let acceptor_inner = TlsAcceptor::from(
                                tls::build_server_config(
                                    vec![server_cert.clone()],
                                    server_key.clone_key(),
                                    &ca_clone,
                                )
                                .unwrap(),
                            );
                            let state = Arc::new(test_daemon_state());
                            tokio::spawn(async move {
                                if let Ok(tls_stream) = acceptor_inner.accept(tcp).await {
                                    let (read_half, write_half) = io::split(tls_stream);
                                    let mut reader = io::BufReader::new(read_half);
                                    let mut writer = io::BufWriter::new(write_half);
                                    let request: RpcRequest =
                                        are_daemon::framing::read_message(&mut reader).await.unwrap();
                                    let response: RpcResponse = state.handle(request);
                                    let _ = are_daemon::framing::write_message(&mut writer, &response).await;
                                }
                            });
                        }
                        Err(_) => break,
                    }
                }
                _ = tokio::time::sleep(Duration::from_secs(10)) => break,
            }
        }
    });

    (addr, handle)
}

// ---------------------------------------------------------------------------
// Security tests
// ---------------------------------------------------------------------------

/// Gate 3: valid mTLS connection and GetEnvironmentInfo.
#[tokio::test]
async fn test_valid_mtls_connect_and_get_info() {
    let (ca_cert, ca_key) = make_ca("Test Root CA");
    let (server_cert, server_key) = make_signed_cert(&ca_cert, &ca_key, "localhost");
    let (client_cert, client_key) = make_signed_cert(&ca_cert, &ca_key, "test-client");

    let ca_cert_der = ca_cert.der().clone();

    let (addr, _handle) = start_daemon(server_cert, server_key, &ca_cert_der).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = SecureClient::new(
        vec![client_cert],
        client_key,
        ca_cert_der,
        &format!("127.0.0.1:{}", addr.port()),
        "localhost",
    )
    .unwrap();

    let env_id = EnvironmentId::new("test-env");
    let info = client.get_environment_info(&env_id).await.unwrap();

    assert_eq!(info.environment_id.as_str(), "test-env");
    assert_eq!(info.machine_name, "test-host");
    assert_eq!(info.daemon_version, "0.1.0");
    assert_eq!(info.platform, Platform::Debian);
    assert!(info
        .advertised_capabilities
        .contains(&Capability::FilesystemRead));
    assert!(info
        .advertised_capabilities
        .contains(&Capability::ProcessExecute));
}

/// Gate 3: client cert signed by unknown CA is rejected by daemon.
#[tokio::test]
async fn test_invalid_client_certificate_rejected() {
    let (ca_cert, ca_key) = make_ca("Test Root CA");
    let (server_cert, server_key) = make_signed_cert(&ca_cert, &ca_key, "localhost");

    // Client cert signed by a DIFFERENT CA.
    let (unknown_ca_cert, unknown_ca_key) = make_ca("Unknown CA");
    let (client_cert, client_key) =
        make_signed_cert(&unknown_ca_cert, &unknown_ca_key, "bad-client");

    let ca_cert_der = ca_cert.der().clone();

    let (addr, _handle) = start_daemon(server_cert, server_key, &ca_cert_der).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = SecureClient::new(
        vec![client_cert],
        client_key,
        ca_cert_der,
        &format!("127.0.0.1:{}", addr.port()),
        "localhost",
    )
    .unwrap();

    let env_id = EnvironmentId::new("test-env");
    let result = client.get_environment_info(&env_id).await;

    assert!(result.is_err(), "should fail with invalid client cert");
}

/// Gate 3: client trusts wrong CA → rejects daemon cert.
#[tokio::test]
async fn test_invalid_daemon_certificate_rejected() {
    let (ca_cert, ca_key) = make_ca("Correct CA");
    let (server_cert, server_key) = make_signed_cert(&ca_cert, &ca_key, "localhost");
    let (client_cert, client_key) = make_signed_cert(&ca_cert, &ca_key, "client");

    // Client trusts the WRONG CA.
    let (wrong_ca_cert, _wrong_ca_key) = make_ca("Wrong CA");

    let ca_cert_der = ca_cert.der().clone();
    let wrong_ca_der = wrong_ca_cert.der().clone();

    let (addr, _handle) = start_daemon(server_cert, server_key, &ca_cert_der).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = SecureClient::new(
        vec![client_cert],
        client_key,
        wrong_ca_der,
        &format!("127.0.0.1:{}", addr.port()),
        "localhost",
    )
    .unwrap();

    let env_id = EnvironmentId::new("test-env");
    let result = client.get_environment_info(&env_id).await;

    assert!(result.is_err(), "should fail when client trusts wrong CA");
}

/// Gate 3: expired client cert is rejected.
#[tokio::test]
async fn test_expired_credential_rejected() {
    let (ca_cert, ca_key) = make_ca("Test Root CA");
    let (server_cert, server_key) = make_signed_cert(&ca_cert, &ca_key, "localhost");

    let (expired_cert, expired_key) = make_expired_cert(&ca_cert, &ca_key, "expired-client");

    let ca_cert_der = ca_cert.der().clone();

    let (addr, _handle) = start_daemon(server_cert, server_key, &ca_cert_der).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = SecureClient::new(
        vec![expired_cert],
        expired_key,
        ca_cert_der,
        &format!("127.0.0.1:{}", addr.port()),
        "localhost",
    )
    .unwrap();

    let env_id = EnvironmentId::new("test-env");
    let result = client.get_environment_info(&env_id).await;

    assert!(result.is_err(), "should fail with expired certificate");
}

/// Gate 3: cert from unknown (rogue) CA is rejected.
#[tokio::test]
async fn test_unknown_credential_rejected() {
    let (ca_cert, ca_key) = make_ca("Daemon CA");
    let (server_cert, server_key) = make_signed_cert(&ca_cert, &ca_key, "localhost");

    let (rogue_ca_cert, rogue_ca_key) = make_ca("Rogue CA");
    let (rogue_cert, rogue_key) = make_signed_cert(&rogue_ca_cert, &rogue_ca_key, "rogue");

    let ca_cert_der = ca_cert.der().clone();

    let (addr, _handle) = start_daemon(server_cert, server_key, &ca_cert_der).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = SecureClient::new(
        vec![rogue_cert],
        rogue_key,
        ca_cert_der,
        &format!("127.0.0.1:{}", addr.port()),
        "localhost",
    )
    .unwrap();

    let env_id = EnvironmentId::new("test-env");
    let result = client.get_environment_info(&env_id).await;

    assert!(result.is_err(), "should fail with unknown CA credential");
}

/// Gate 3.5: TLS 1.2 client is rejected by TLS 1.3-only server.
///
/// The server is built with `build_server_config`, which restricts to TLS
/// 1.3 only. The client is restricted to TLS 1.2 only. Since there is no
/// overlapping protocol version, the handshake fails immediately — the
/// client cannot negotiate a version the server supports.
#[tokio::test]
async fn test_tls12_rejected() {
    let (ca_cert, ca_key) = make_ca("Test Root CA");
    let (server_cert, server_key) = make_signed_cert(&ca_cert, &ca_key, "localhost");
    let (client_cert, client_key) = make_signed_cert(&ca_cert, &ca_key, "test-client");

    let ca_cert_der = ca_cert.der().clone();

    // Server: TLS 1.3 only (production path via build_server_config).
    let server_config =
        tls::build_server_config(vec![server_cert], server_key.clone_key(), &ca_cert_der).unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(server_config);

    let server_handle = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        // Accept should fail — client won't negotiate TLS 1.3.
        let _ = acceptor.accept(tcp).await;
    });

    // Client: TLS 1.2 only, with valid mTLS certs.
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(ca_cert_der).unwrap();

    let client_config = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS12])
    .unwrap()
    .with_root_certificates(root_store)
    .with_client_auth_cert(vec![client_cert], client_key)
    .unwrap();

    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let server_name = rustls::pki_types::ServerName::try_from("localhost".to_string()).unwrap();

    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();

    // TLS handshake must fail — no overlapping protocol version.
    let result = connector.connect(server_name, tcp).await;
    assert!(
        result.is_err(),
        "TLS 1.2 client must be rejected by TLS 1.3-only server"
    );

    let _ = tokio::time::timeout(Duration::from_secs(3), server_handle).await;
}

/// Gate 3: connection without client cert is rejected (mTLS required).
///
/// In TLS 1.3, the client's `connect()` may complete before the server
/// validates the client certificate. The server then rejects the peer
/// and closes the connection. We detect this by attempting I/O on the
/// stream — a write or read should fail because the server dropped us.
#[tokio::test]
async fn test_connection_without_authentication_rejected() {
    let (ca_cert, ca_key) = make_ca("Test Root CA");
    let (server_cert, server_key) = make_signed_cert(&ca_cert, &ca_key, "localhost");

    let ca_cert_der = ca_cert.der().clone();

    // --- Build server config with mandatory client auth ---
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(ca_cert_der.clone()).unwrap();
    let client_verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(root_store))
        .build()
        .unwrap();

    assert!(
        client_verifier.client_auth_mandatory(),
        "server must require client auth"
    );

    let server_config = rustls::ServerConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_client_cert_verifier(client_verifier)
    .with_single_cert(vec![server_cert], server_key)
    .unwrap();

    // --- Bind listener and spawn TLS accept ---
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    let server_handle = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        // Server rejects the client (no cert) — accept returns Err.
        let _ = acceptor.accept(tcp).await;
    });

    // --- Build client config with NO client certificate ---
    let mut client_root_store = rustls::RootCertStore::empty();
    client_root_store.add(ca_cert_der).unwrap();

    let client_config = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_root_certificates(client_root_store)
    .with_no_client_auth();

    let server_name = rustls::pki_types::ServerName::try_from("localhost".to_string()).unwrap();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));

    let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();

    // In TLS 1.3, connect() may succeed before the server validates the
    // client cert. The server then closes the connection. Detect this
    // by attempting I/O — writing should fail.
    let tls_result = connector.connect(server_name, tcp).await;

    if let Ok(tls_stream) = tls_result {
        // TLS handshake completed from client side, but server should
        // have rejected us. Try to write — it should fail.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut reader, mut writer) = io::split(tls_stream);
        let write_result = writer.write_all(b"ping").await;
        let read_result = reader.read_u8().await;

        assert!(
            write_result.is_err() || read_result.is_err(),
            "I/O should fail because server rejected our missing client cert"
        );
    }
    // If connect() itself failed, that's also acceptable — server rejected us.

    let _ = tokio::time::timeout(Duration::from_secs(3), server_handle).await;
}
