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

use are_core::{RpcRequest, RpcResponse};
use tokio::io;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

use crate::framing;
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

    framing::write_message(&mut writer, &response)
        .await
        .map_err(|e| {
            error!("failed to write response: {e}");
            e
        })?;

    Ok(())
}
