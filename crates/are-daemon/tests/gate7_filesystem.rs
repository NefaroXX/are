#![allow(clippy::unwrap_used, clippy::expect_used)]

//! Gate 7 filesystem integration tests — real mTLS wire roundtrips.
//!
//! Unlike the handler-level tests, these exercise the full path: TCP →
//! TLS handshake → framing → `DaemonState::handle` → filesystem backend.
//! Each `WireClient::send` opens a fresh TLS connection (matching the
//! production client: one RPC per connection), and all connections share
//! ONE `Arc<DaemonState>` so a write on one connection is visible to a
//! read on the next — proving environment-scoped (not connection-scoped)
//! file state.
//!
//! Required by PLAN.md Gate 7 / reviewer fixes:
//! - write→read roundtrip with a matching content hash
//! - `overwrite: false` and stale-hash writes are refused (`Conflict`)
//! - FIX 4: missing rename source surfaces as `RpcError::NotFound` on the wire
//! - traversal writes are rejected (`InvalidRequest`)
//! - non-empty directory deletes are refused (`Conflict`), contents intact

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use are_client::connection::SecureClient;
use are_core::{
    Capability, CapabilitySet, CreateDirectoryRequest, DeleteRequest, EnvironmentId, Platform,
    ReadFileRequest, RenameRequest, RpcError, RpcRequest, RpcResponse, RpcResponsePayload,
    WriteFileRequest,
};
use are_daemon::fs::{FilesystemBackend, FilesystemConfig};
use are_daemon::handler::DaemonState;
use are_daemon::{framing, tls};
use tokio::io;
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, TlsConnector};

const ENV: &str = "test-env";
const HOST: &str = "test-host";
const VERSION: &str = "0.1.0";

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

fn env() -> EnvironmentId {
    EnvironmentId::new(ENV)
}

/// A `FilesystemBackend` rooted at `root` with read/list/write caps.
fn fs_wired_state(root: &Path) -> DaemonState {
    let fs = FilesystemBackend::new(FilesystemConfig::new(&[root.to_path_buf()]).unwrap());
    let mut caps = CapabilitySet::default();
    caps.insert(Capability::FilesystemRead);
    caps.insert(Capability::FilesystemList);
    caps.insert(Capability::FilesystemWrite);
    DaemonState::with_fs(
        env(),
        HOST.into(),
        VERSION.into(),
        caps,
        Platform::Debian,
        fs,
    )
}

/// Start a daemon on a random port. All accepted connections SHARE one
/// `Arc<DaemonState>` (built before the accept loop), so file state written
/// on one connection is visible to the next — unlike gate3's per-connection
/// throwaway state, which was fine there (stateless env-info RPCs).
async fn start_daemon(
    state: Arc<DaemonState>,
    server_cert: rustls::pki_types::CertificateDer<'static>,
    server_key: rustls::pki_types::PrivateKeyDer<'static>,
    ca_cert: &rustls::pki_types::CertificateDer<'static>,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
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
                            let state = Arc::clone(&state);
                            tokio::spawn(async move {
                                if let Ok(tls_stream) = acceptor_inner.accept(tcp).await {
                                    let (read_half, write_half) = io::split(tls_stream);
                                    let mut reader = io::BufReader::new(read_half);
                                    let mut writer = io::BufWriter::new(write_half);
                                    let request: RpcRequest =
                                        framing::read_message(&mut reader).await.unwrap();
                                    let response: RpcResponse = state.handle(request);
                                    let _ = framing::write_message(&mut writer, &response).await;
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

/// Minimal wire client: ONE fresh mTLS connection per `send`, returning the
/// raw `RpcResponse` so tests can assert on the exact `RpcError` variant
/// (SecureClient stringifies errors and loses the variant).
struct WireClient {
    addr: SocketAddr,
    tls_config: Arc<rustls::ClientConfig>,
    server_name: rustls::pki_types::ServerName<'static>,
}

impl WireClient {
    fn new(
        addr: SocketAddr,
        client_certs: Vec<rustls::pki_types::CertificateDer<'static>>,
        client_key: rustls::pki_types::PrivateKeyDer<'static>,
        ca_cert: &rustls::pki_types::CertificateDer<'static>,
    ) -> Self {
        let tls_config =
            tls::build_client_config(client_certs, client_key, ca_cert, "localhost").unwrap();
        let server_name = rustls::pki_types::ServerName::try_from("localhost".to_string()).unwrap();
        Self {
            addr,
            tls_config,
            server_name,
        }
    }

    async fn send(&self, request: RpcRequest) -> RpcResponse {
        let tcp = TcpStream::connect(&self.addr).await.unwrap();
        let connector = TlsConnector::from(Arc::clone(&self.tls_config));
        let tls_stream = connector
            .connect(self.server_name.clone(), tcp)
            .await
            .unwrap();
        let (read_half, write_half) = io::split(tls_stream);
        let mut reader = io::BufReader::new(read_half);
        let mut writer = io::BufWriter::new(write_half);
        framing::write_message(&mut writer, &request).await.unwrap();
        framing::read_message(&mut reader).await.unwrap()
    }
}

// ---------------------------------------------------------------------------
// Wire tests
// ---------------------------------------------------------------------------

/// One CA for the whole PKI: server cert (CN=localhost) and client cert
/// (CN=test-client) both signed by it, matching gate3's single-CA setup.
/// The daemon trusts the CA for client certs; clients trust it for the
/// server cert — a split-CA arrangement would fail handshakes on one side.
fn base_pki() -> (
    rustls::pki_types::CertificateDer<'static>, // ca_der
    rustls::pki_types::CertificateDer<'static>, // server_cert
    rustls::pki_types::PrivateKeyDer<'static>,  // server_key
    rustls::pki_types::CertificateDer<'static>, // client_cert
    rustls::pki_types::PrivateKeyDer<'static>,  // client_key
) {
    let (ca_cert, ca_key) = make_ca("Test Root CA");
    let (server_cert, server_key) = make_signed_cert(&ca_cert, &ca_key, "localhost");
    let (client_cert, client_key) = make_signed_cert(&ca_cert, &ca_key, "test-client");
    (
        ca_cert.der().clone(),
        server_cert,
        server_key,
        client_cert,
        client_key,
    )
}

/// Gate 7: write → read roundtrip over real mTLS with a matching hash,
/// exercised through the PUBLIC `SecureClient` API.
#[tokio::test(flavor = "multi_thread")]
async fn file_rpc_roundtrip_write_read_hash_matches() {
    let tmp = tempfile::TempDir::new().unwrap();
    let state = Arc::new(fs_wired_state(tmp.path()));
    let (ca_der, server_cert, server_key, client_cert, client_key) = base_pki();

    let (addr, _handle) = start_daemon(state, server_cert, server_key, &ca_der).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = SecureClient::new(
        vec![client_cert],
        client_key,
        ca_der,
        &format!("127.0.0.1:{}", addr.port()),
        "localhost",
    )
    .unwrap();

    let written = client
        .write_file(WriteFileRequest {
            environment_id: env(),
            path: "hello.txt".into(),
            content: b"wire hello".to_vec(),
            overwrite: true,
            expected_hash: None,
        })
        .await
        .unwrap();
    assert_eq!(written.metadata.size, 10);
    let hash = written.metadata.hash.expect("write must return a hash");

    let read = client
        .read_file(ReadFileRequest {
            environment_id: env(),
            path: "hello.txt".into(),
        })
        .await
        .unwrap();
    assert_eq!(read.content, b"wire hello");
    assert_eq!(read.metadata.hash, Some(hash), "roundtrip hash must match");
}

/// Gate 7: `overwrite: false` on an existing file → `Conflict` on the wire,
/// original content intact.
#[tokio::test(flavor = "multi_thread")]
async fn file_rpc_overwrite_false_refuses_existing() {
    let tmp = tempfile::TempDir::new().unwrap();
    let state = Arc::new(fs_wired_state(tmp.path()));
    let (ca_der, server_cert, server_key, client_cert, client_key) = base_pki();

    let (addr, _handle) = start_daemon(state, server_cert, server_key, &ca_der).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let wire = WireClient::new(addr, vec![client_cert], client_key, &ca_der);

    let resp = wire
        .send(RpcRequest::WriteFile(WriteFileRequest {
            environment_id: env(),
            path: "e.txt".into(),
            content: b"v1".to_vec(),
            overwrite: true,
            expected_hash: None,
        }))
        .await;
    assert!(matches!(resp.result, Ok(RpcResponsePayload::WriteFile(_))));

    let resp = wire
        .send(RpcRequest::WriteFile(WriteFileRequest {
            environment_id: env(),
            path: "e.txt".into(),
            content: b"v2".to_vec(),
            overwrite: false,
            expected_hash: None,
        }))
        .await;
    assert!(
        matches!(&resp.result, Err(RpcError::Conflict(_))),
        "overwrite=false must be Conflict, got {:?}",
        resp.result
    );

    // Original intact.
    let resp = wire
        .send(RpcRequest::ReadFile(ReadFileRequest {
            environment_id: env(),
            path: "e.txt".into(),
        }))
        .await;
    match resp.result {
        Ok(RpcResponsePayload::ReadFile(r)) => assert_eq!(r.content, b"v1"),
        other => panic!("expected ReadFile response, got {other:?}"),
    }
}

/// Gate 7: stale expected-hash write → `Conflict`, loser's content never
/// lands (verified over a SECOND independent connection).
#[tokio::test(flavor = "multi_thread")]
async fn file_rpc_stale_expected_hash_conflicts() {
    let tmp = tempfile::TempDir::new().unwrap();
    let state = Arc::new(fs_wired_state(tmp.path()));
    let (ca_der, server_cert, server_key, client_cert, client_key) = base_pki();

    let (addr, _handle) = start_daemon(state, server_cert, server_key, &ca_der).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let wire = WireClient::new(addr, vec![client_cert], client_key, &ca_der);

    wire.send(RpcRequest::WriteFile(WriteFileRequest {
        environment_id: env(),
        path: "o.txt".into(),
        content: b"one".to_vec(),
        overwrite: true,
        expected_hash: None,
    }))
    .await;

    // A valid 64-hex hash that cannot match the file's actual digest.
    let stale = "d".repeat(64);
    let resp = wire
        .send(RpcRequest::WriteFile(WriteFileRequest {
            environment_id: env(),
            path: "o.txt".into(),
            content: b"stale".to_vec(),
            overwrite: true,
            expected_hash: Some(stale),
        }))
        .await;
    assert!(
        matches!(&resp.result, Err(RpcError::Conflict(_))),
        "stale hash must be Conflict, got {:?}",
        resp.result
    );

    // Loser's write never landed — fresh connection, same shared state.
    let resp = wire
        .send(RpcRequest::ReadFile(ReadFileRequest {
            environment_id: env(),
            path: "o.txt".into(),
        }))
        .await;
    match resp.result {
        Ok(RpcResponsePayload::ReadFile(r)) => assert_eq!(r.content, b"one"),
        other => panic!("expected ReadFile response, got {other:?}"),
    }
}

/// FIX 4 wire proof: a rename with a missing source surfaces as
/// `RpcError::NotFound` (previously leaked as `InternalError`).
#[tokio::test(flavor = "multi_thread")]
async fn file_rpc_rename_missing_src_is_not_found() {
    let tmp = tempfile::TempDir::new().unwrap();
    let state = Arc::new(fs_wired_state(tmp.path()));
    let (ca_der, server_cert, server_key, client_cert, client_key) = base_pki();

    let (addr, _handle) = start_daemon(state, server_cert, server_key, &ca_der).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let wire = WireClient::new(addr, vec![client_cert], client_key, &ca_der);
    let resp = wire
        .send(RpcRequest::Rename(RenameRequest {
            environment_id: env(),
            src: "missing.txt".into(),
            dst: "other.txt".into(),
        }))
        .await;
    assert!(
        matches!(&resp.result, Err(RpcError::NotFound(_))),
        "missing rename src must be NotFound, got {:?}",
        resp.result
    );
}

/// Gate 7: traversal writes are rejected on the wire — the request never
/// lands, and nothing is created outside the root. `..` traversal hits the
/// resolve-time boundary check, which fails closed as `FilesystemEscape`
/// (mapped to `InternalError` — deliberately NOT remapped; per FIX 4 only
/// `NotFound`/`FileTooLarge` category changes were in scope).
#[tokio::test(flavor = "multi_thread")]
async fn file_rpc_traversal_write_rejected() {
    let tmp = tempfile::TempDir::new().unwrap();
    let state = Arc::new(fs_wired_state(tmp.path()));
    let (ca_der, server_cert, server_key, client_cert, client_key) = base_pki();

    let (addr, _handle) = start_daemon(state, server_cert, server_key, &ca_der).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let wire = WireClient::new(addr, vec![client_cert], client_key, &ca_der);
    let resp = wire
        .send(RpcRequest::WriteFile(WriteFileRequest {
            environment_id: env(),
            path: "../escape.txt".into(),
            content: b"nope".to_vec(),
            overwrite: true,
            expected_hash: None,
        }))
        .await;
    match &resp.result {
        // FilesystemEscape → InternalError ("filesystem escape blocked").
        // Also accept InvalidRequest (shape-level refusal) if a stricter
        // shape check is added later — both are fail-closed refusals.
        Err(RpcError::InternalError(msg)) => {
            assert!(msg.contains("filesystem escape blocked"), "got: {msg}");
        }
        Err(RpcError::InvalidRequest(_)) => {}
        other => panic!("traversal write must be refused, got {other:?}"),
    }
    // Nothing escaped into the tempdir's parent.
    assert!(!tmp.path().parent().unwrap().join("escape.txt").exists());
}

/// Gate 7: deleting a non-empty directory → `Conflict`, contents intact;
/// after removing the child, the dir deletes.
#[tokio::test(flavor = "multi_thread")]
async fn file_rpc_delete_nonempty_dir_conflicts_contents_intact() {
    let tmp = tempfile::TempDir::new().unwrap();
    let state = Arc::new(fs_wired_state(tmp.path()));
    let (ca_der, server_cert, server_key, client_cert, client_key) = base_pki();

    let (addr, _handle) = start_daemon(state, server_cert, server_key, &ca_der).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let wire = WireClient::new(addr, vec![client_cert], client_key, &ca_der);

    wire.send(RpcRequest::CreateDirectory(CreateDirectoryRequest {
        environment_id: env(),
        path: "sub".into(),
    }))
    .await;
    wire.send(RpcRequest::WriteFile(WriteFileRequest {
        environment_id: env(),
        path: "sub/child.txt".into(),
        content: b"child".to_vec(),
        overwrite: true,
        expected_hash: None,
    }))
    .await;

    // Non-empty dir refuses.
    let resp = wire
        .send(RpcRequest::DeleteFile(DeleteRequest {
            environment_id: env(),
            path: "sub".into(),
        }))
        .await;
    assert!(
        matches!(&resp.result, Err(RpcError::Conflict(_))),
        "non-empty dir delete must be Conflict, got {:?}",
        resp.result
    );

    // Child intact.
    let resp = wire
        .send(RpcRequest::ReadFile(ReadFileRequest {
            environment_id: env(),
            path: "sub/child.txt".into(),
        }))
        .await;
    match resp.result {
        Ok(RpcResponsePayload::ReadFile(r)) => assert_eq!(r.content, b"child"),
        other => panic!("expected ReadFile response, got {other:?}"),
    }

    // Child then dir delete cleanly.
    wire.send(RpcRequest::DeleteFile(DeleteRequest {
        environment_id: env(),
        path: "sub/child.txt".into(),
    }))
    .await;
    let resp = wire
        .send(RpcRequest::DeleteFile(DeleteRequest {
            environment_id: env(),
            path: "sub".into(),
        }))
        .await;
    assert!(
        matches!(&resp.result, Ok(RpcResponsePayload::DeleteFile(_))),
        "empty dir delete must succeed, got {:?}",
        resp.result
    );
}

/// Gate 7: rename → delete roundtrip across independent connections, with
/// the missing file surfacing as `NotFound` after deletion (FIX 4 wire
/// proof, second angle).
#[tokio::test(flavor = "multi_thread")]
async fn file_rpc_rename_then_delete_then_not_found() {
    let tmp = tempfile::TempDir::new().unwrap();
    let state = Arc::new(fs_wired_state(tmp.path()));
    let (ca_der, server_cert, server_key, client_cert, client_key) = base_pki();

    let (addr, _handle) = start_daemon(state, server_cert, server_key, &ca_der).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    let wire = WireClient::new(addr, vec![client_cert], client_key, &ca_der);

    wire.send(RpcRequest::WriteFile(WriteFileRequest {
        environment_id: env(),
        path: "a.txt".into(),
        content: b"x".to_vec(),
        overwrite: true,
        expected_hash: None,
    }))
    .await;

    // One connection renames...
    let resp = wire
        .send(RpcRequest::Rename(RenameRequest {
            environment_id: env(),
            src: "a.txt".into(),
            dst: "b.txt".into(),
        }))
        .await;
    assert!(
        matches!(&resp.result, Ok(RpcResponsePayload::Rename(_))),
        "rename must succeed, got {:?}",
        resp.result
    );

    // ...a SECOND connection deletes the renamed file (shared state)...
    let resp = wire
        .send(RpcRequest::DeleteFile(DeleteRequest {
            environment_id: env(),
            path: "b.txt".into(),
        }))
        .await;
    assert!(
        matches!(&resp.result, Ok(RpcResponsePayload::DeleteFile(_))),
        "delete must succeed, got {:?}",
        resp.result
    );

    // ...and a THIRD sees it as NotFound.
    let resp = wire
        .send(RpcRequest::ReadFile(ReadFileRequest {
            environment_id: env(),
            path: "b.txt".into(),
        }))
        .await;
    assert!(
        matches!(&resp.result, Err(RpcError::NotFound(_))),
        "deleted file must be NotFound, got {:?}",
        resp.result
    );
}
