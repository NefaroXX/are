//! TLS accept loop and per-connection handler.
//!
//! Listens on a TCP socket, accepts connections, performs TLS handshake
//! with mTLS, then reads/writes length-prefixed JSON messages.
//!
//! Each connection is spawned as an independent tokio task. For Gate 3,
//! each connection handles exactly one request and then closes — this is
//! the simplest model that proves mTLS works. Multiplexing and persistent
//! connections are deferred to later gates.

use std::net::SocketAddr;
use std::sync::Arc;

use are_core::{RpcError, RpcRequest, RpcResponse};
use tokio::io;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

use crate::framing::{self, FramingError, DEFAULT_MAX_PAYLOAD};
use crate::handler::DaemonState;

/// TLS server configuration and daemon state, shared across connections.
pub struct TlsServer {
    tls_acceptor: TlsAcceptor,
    state: Arc<DaemonState>,
}

impl TlsServer {
    /// Create a new TLS server.
    pub fn new(tls_acceptor: TlsAcceptor, state: DaemonState) -> Self {
        Self {
            tls_acceptor,
            state: Arc::new(state),
        }
    }

    /// Run the accept loop on the given address.
    ///
    /// Binds to `addr`, accepts connections, and spawns a handler task for
    /// each one. Runs until the process is terminated or the listener fails.
    ///
    /// # Errors
    ///
    /// Returns an error if the TCP listener cannot bind.
    pub async fn run(&self, addr: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(addr).await?;
        info!("ared listening on {addr}");

        loop {
            let (tcp_stream, peer_addr) = match listener.accept().await {
                Ok(conn) => conn,
                Err(e) => {
                    error!("accept error: {e}");
                    continue;
                }
            };

            let acceptor = self.tls_acceptor.clone();
            let state = Arc::clone(&self.state);

            tokio::spawn(async move {
                match acceptor.accept(tcp_stream).await {
                    Ok(tls_stream) => {
                        // Log peer certificate presence.
                        let has_client_cert = tls_stream
                            .get_ref()
                            .1
                            .peer_certificates()
                            .is_some_and(|certs| !certs.is_empty());
                        info!("TLS connection from {peer_addr}, client_cert={has_client_cert}");

                        if let Err(e) = handle_connection(tls_stream, state).await {
                            warn!("connection from {peer_addr} handler error: {e}");
                        }
                    }
                    Err(e) => {
                        warn!("TLS handshake failed from {peer_addr}: {e}");
                    }
                }
            });
        }
    }
}

/// Handle a single TLS connection: read one request, write one response.
///
/// Splits the TLS stream into independent read/write halves so we don't
/// need `Clone` on `TlsStream`.
async fn handle_connection(
    stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    state: Arc<DaemonState>,
) -> Result<(), Box<dyn std::error::Error>> {
    let (read_half, write_half) = io::split(stream);
    let mut reader = io::BufReader::new(read_half);
    let mut writer = io::BufWriter::new(write_half);

    let request: RpcRequest = framing::read_message(&mut reader).await.map_err(|e| {
        error!("failed to read request: {e}");
        e
    })?;

    let response: RpcResponse = state.handle(request);

    write_response(&mut writer, &response).await.map_err(|e| {
        error!("failed to write response: {e}");
        e
    })?;

    Ok(())
}

/// Build the small replacement error sent when a response is too large to
/// transmit. Always tiny (well under [`DEFAULT_MAX_PAYLOAD`]).
pub(crate) fn too_large_fallback(size: usize, max: usize) -> RpcResponse {
    RpcResponse {
        result: Err(RpcError::InternalError(format!(
            "response too large to transmit: {size} bytes exceeds {max}; narrow the command or read smaller ranges"
        ))),
    }
}

/// Send one `RpcResponse`, mapping an oversized payload to a small
/// [`RpcError::InternalError`] replacement instead of a doomed multi-MB
/// send. The replacement always fits, so oversized `ReadFile`/`WaitProcess`
/// responses surface as clean RPC errors — never as a client framing
/// failure. Only one fallback is attempted (no recursion): if the fallback
/// itself cannot be written its error is returned.
pub(crate) async fn write_response<W: io::AsyncWrite + Unpin>(
    writer: &mut W,
    response: &RpcResponse,
) -> Result<(), FramingError> {
    write_response_sized(writer, response, DEFAULT_MAX_PAYLOAD).await
}

/// [`write_response`] with an explicit limit. Production passes
/// [`DEFAULT_MAX_PAYLOAD`]; tests pass a tiny `max` (still larger than the
/// ~150-byte fallback) to exercise the mapping without megabytes.
pub(crate) async fn write_response_sized<W: io::AsyncWrite + Unpin>(
    writer: &mut W,
    response: &RpcResponse,
    max_payload: usize,
) -> Result<(), FramingError> {
    match framing::write_message_sized(writer, response, max_payload).await {
        Ok(()) => Ok(()),
        Err(FramingError::ResponseTooLarge { size, max }) => {
            error!("response ({size} bytes) exceeds transmit limit ({max}); sending compact error");
            let fallback = too_large_fallback(size, max);
            framing::write_message_sized(writer, &fallback, max_payload).await
        }
        Err(other) => Err(other),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use are_core::{RpcResponsePayload, WaitProcessResponse};

    fn duplex_pair() -> (
        io::BufWriter<tokio::io::DuplexStream>,
        io::BufReader<tokio::io::DuplexStream>,
    ) {
        let (writer, reader) = tokio::io::duplex(64 * 1024);
        (io::BufWriter::new(writer), io::BufReader::new(reader))
    }

    fn file_meta() -> are_core::FileMetadata {
        are_core::FileMetadata {
            size: 1024,
            modified_at: None,
            is_dir: false,
            is_file: true,
        }
    }

    fn oversized_read_file_response() -> RpcResponse {
        // 1 KiB of raw bytes serializes to ~4 KiB of JSON (array-of-numbers),
        // well over the 512-byte test limit but tiny in the test binary.
        RpcResponse {
            result: Ok(RpcResponsePayload::ReadFile(are_core::ReadFileResponse {
                content: vec![7u8; 1024],
                metadata: file_meta(),
            })),
        }
    }

    fn oversized_wait_response() -> RpcResponse {
        RpcResponse {
            result: Ok(RpcResponsePayload::WaitProcess(WaitProcessResponse {
                stdout: vec![8u8; 1024],
                stderr: vec![9u8; 512],
                exit_code: Some(0),
                timed_out: false,
                truncated: true,
            })),
        }
    }

    async fn assert_maps_to_clean_rpc_error(response: RpcResponse) {
        let (mut writer, mut reader) = duplex_pair();
        // 512 bytes fits the ~150-byte fallback but not the KiB-scale
        // oversized payloads above.
        write_response_sized(&mut writer, &response, 512)
            .await
            .unwrap();
        let got: RpcResponse = framing::read_message(&mut reader).await.unwrap();
        match got.result {
            Err(RpcError::InternalError(msg)) => {
                assert!(
                    msg.contains("response too large"),
                    "fallback must say 'response too large', got: {msg}"
                );
            }
            other => panic!("expected clean InternalError, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn oversized_read_file_maps_to_clean_rpc_error() {
        assert_maps_to_clean_rpc_error(oversized_read_file_response()).await;
    }

    #[tokio::test]
    async fn oversized_wait_process_maps_to_clean_rpc_error() {
        assert_maps_to_clean_rpc_error(oversized_wait_response()).await;
    }

    #[tokio::test]
    async fn small_response_passes_through_untouched() {
        let (mut writer, mut reader) = duplex_pair();
        let response = RpcResponse {
            result: Ok(RpcResponsePayload::ReadFile(are_core::ReadFileResponse {
                content: b"hi".to_vec(),
                metadata: file_meta(),
            })),
        };
        write_response_sized(&mut writer, &response, 512)
            .await
            .unwrap();
        let got: RpcResponse = framing::read_message(&mut reader).await.unwrap();
        match got.result {
            Ok(RpcResponsePayload::ReadFile(back)) => {
                assert_eq!(back.content, b"hi");
            }
            other => panic!("expected ReadFile passthrough, got {other:?}"),
        }
    }
}
