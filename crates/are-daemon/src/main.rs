//! # ared daemon binary
//!
//! Entry point for the `ared` daemon process.
//!
//! ## Usage
//!
//! ```bash
//! ared listen --port 9000 --cert server.pem --key server.key --ca ca.pem
//! ```
//!
//! If `--cert`, `--key`, and `--ca` are not provided, the daemon generates
//! ephemeral self-signed certificates for development/testing only. This
//! is NOT suitable for production — document in `docs/identity.md`.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use are_core::EnvironmentId;
use are_daemon::handler::DaemonState;
use are_daemon::tls;
use are_daemon::DaemonConfig;
use clap::{Parser, Subcommand};
use tokio_rustls::TlsAcceptor;
use tracing::info;

#[derive(Parser)]
#[command(name = "ared", about = "Agent Remote Environment daemon")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the daemon listener
    Listen {
        /// Port to listen on
        #[arg(long, default_value = "9000")]
        port: u16,

        /// Address to bind to
        #[arg(long, default_value = "127.0.0.1")]
        address: String,

        /// Environment ID this daemon serves
        #[arg(long, default_value = "default")]
        environment_id: String,

        /// Path to server certificate PEM file
        #[arg(long)]
        cert: Option<PathBuf>,

        /// Path to server private key PEM file
        #[arg(long)]
        key: Option<PathBuf>,

        /// Path to CA certificate PEM file (for client verification)
        #[arg(long)]
        ca: Option<PathBuf>,

        /// Allowed root directory for filesystem operations.
        /// Defaults to the current working directory if not specified.
        #[arg(long)]
        allowed_root: Option<PathBuf>,

        /// Comma-separated allow list of program basenames for process
        /// execution (e.g. `--allow-exec cargo,git,npm,node,python`).
        /// If omitted, the daemon is fail-closed and refuses every spawn;
        /// use `--permissive-exec` (development only) to allow any
        /// non-denied program. The deny list
        /// (shutdown/reboot/poweroff/halt/init, plus `.exe`/case variants)
        /// is always enforced.
        #[arg(long)]
        allow_exec: Option<String>,

        /// Development only: permit any non-denied program when no
        /// `--allow-exec` list is configured. The deny list still applies.
        /// NEVER use in production — any client could run arbitrary
        /// binaries. Logs a loud warning at startup and per spawn.
        #[arg(long)]
        permissive_exec: bool,

        /// Session idle timeout in seconds: a session untouched for longer
        /// is expired on next access (lazy expiry, no background reaper).
        #[arg(long, default_value = "3600")]
        session_idle_timeout: u64,

        /// Session maximum lifetime in seconds since creation, regardless
        /// of activity.
        #[arg(long, default_value = "86400")]
        session_max_lifetime: u64,

        /// Maximum live sessions. Creation past this bound purges expired
        /// entries first, then refuses with an error.
        #[arg(long, default_value = "64")]
        max_sessions: usize,

        /// Maximum processes per session (live + retained terminal).
        /// Copied into both the session and process configs (single source
        /// of truth is the daemon config). Default 32.
        #[arg(long, default_value = "32")]
        max_processes_per_session: usize,

        /// Path to a JSON capability-grants file (Gate 8). When present
        /// the daemon runs STRICT: unknown client fingerprints get
        /// `GetEnvironmentInfo` only, known ones get exactly their grants
        /// (see `docs/grants.md` for the schema). A malformed file refuses
        /// startup. At least one of `--grants-file` or
        /// `--permissive-authz` MUST be given: with neither, the daemon
        /// refuses to start.
        #[arg(long)]
        grants_file: Option<PathBuf>,

        /// Development only: run WITHOUT a grants table when no
        /// `--grants-file` is provided — every authenticated client may
        /// do anything (legacy-permissive, fail-open). NEVER use in
        /// production. Logs a loud warning at startup. If both flags are
        /// given, `--grants-file` wins and `--permissive-authz` is
        /// ignored (with a warning).
        #[arg(long)]
        permissive_authz: bool,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing subscriber.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Listen {
            port,
            address,
            environment_id,
            cert,
            key,
            ca,
            allowed_root,
            allow_exec,
            permissive_exec,
            session_idle_timeout,
            session_max_lifetime,
            max_sessions,
            max_processes_per_session,
            grants_file,
            permissive_authz,
        } => {
            // Gate 8 authentication mode: refuse to start unless the
            // operator explicitly picked STRICT (`--grants-file`) or the
            // development-only opt-out (`--permissive-authz`). Never
            // decide silently — fail closed (mirrors the allow/deny-exec
            // posture: no allow list and no opt-out means no daemon).
            if let Err(msg) = validate_authz_mode(grants_file.as_deref(), permissive_authz) {
                eprintln!("error: refusing to start: {msg}");
                std::process::exit(1);
            }

            let env_id = EnvironmentId::try_new(&environment_id)
                .map_err(|e| format!("invalid environment_id: {e}"))?;

            // Determine the allowed root: use provided path or fall back to cwd.
            let root = match allowed_root {
                Some(path) => {
                    if !path.exists() {
                        eprintln!(
                            "error: allowed-root path does not exist: {}",
                            path.display()
                        );
                        std::process::exit(1);
                    }
                    Some(path)
                }
                None => {
                    let cwd = std::env::current_dir()
                        .map_err(|e| format!("failed to get current directory: {e}"))?;
                    tracing::warn!(
                        "no --allowed-root specified, defaulting to current directory: {}",
                        cwd.display()
                    );
                    Some(cwd)
                }
            };

            let config = DaemonConfig {
                environment_id: env_id,
                port,
                max_sessions,
                max_processes_per_session: Some(max_processes_per_session),
                session_idle_timeout_secs: session_idle_timeout,
                session_max_lifetime_secs: session_max_lifetime,
                server_cert_path: cert.as_ref().map(|p| p.display().to_string()),
                server_key_path: key.as_ref().map(|p| p.display().to_string()),
                client_ca_path: ca.as_ref().map(|p| p.display().to_string()),
                allowed_root: root,
                allowed_executables: allow_exec.map(|s| {
                    s.split(',')
                        .map(str::trim)
                        .filter(|name| !name.is_empty())
                        .map(str::to_string)
                        .collect()
                }),
                permissive_exec,
                // Gate 8: a malformed grants file refuses startup (fail
                // closed — never fall back to permissive on a typo).
                grants: grants_file.map(
                    |path| match are_daemon::grants::GrantsTable::load_from_file(&path) {
                        Ok(table) => {
                            tracing::info!(
                                "loaded {} principal(s) from {}",
                                table.len(),
                                path.display()
                            );
                            if table.is_empty() {
                                tracing::warn!(
                                    "grants file has ZERO principals — running STRICT means \
                                     every client is unknown (GetEnvironmentInfo only)"
                                );
                            }
                            table
                        }
                        Err(e) => {
                            eprintln!("error: refusing to start: {e}");
                            std::process::exit(1);
                        }
                    },
                ),
            };

            if permissive_exec {
                tracing::warn!(
                    "--permissive-exec: DEVELOPMENT ONLY — any non-denied program may run"
                );
            }

            if permissive_authz {
                tracing::warn!(
                    "--permissive-authz: DEVELOPMENT ONLY — every authenticated client may do \
                     anything (legacy-permissive, no grants table)"
                );
            }

            if config.grants.is_some() && permissive_authz {
                tracing::warn!(
                    "--grants-file and --permissive-authz both given: the grants table wins, \
                     --permissive-authz is ignored"
                );
            }

            let state = are_daemon::build_daemon_state(&config);
            let tls_config = build_tls_config(&config, &state)?;

            let addr: SocketAddr = format!("{address}:{port}")
                .parse()
                .map_err(|e| format!("invalid address: {e}"))?;

            let acceptor = TlsAcceptor::from(tls_config);
            let server = are_daemon::server::TlsServer::new(acceptor, state);

            info!("ared starting on {addr}");
            server.run(addr).await?;
        }
    }

    Ok(())
}

/// Build TLS configuration from file paths or ephemeral test certs.
///
/// In production, `--cert`, `--key`, and `--ca` must be provided.
/// For development, ephemeral certs are generated via `rcgen`.
fn build_tls_config(
    config: &DaemonConfig,
    _state: &DaemonState,
) -> Result<Arc<rustls::ServerConfig>, Box<dyn std::error::Error>> {
    match (
        &config.server_cert_path,
        &config.server_key_path,
        &config.client_ca_path,
    ) {
        (Some(cert_path), Some(key_path), Some(ca_path)) => {
            // Production path: load from files.
            let cert_pem = std::fs::read_to_string(cert_path)
                .map_err(|e| format!("failed to read cert: {e}"))?;
            let key_pem = std::fs::read_to_string(key_path)
                .map_err(|e| format!("failed to read key: {e}"))?;
            let ca_pem =
                std::fs::read_to_string(ca_path).map_err(|e| format!("failed to read CA: {e}"))?;

            let server_certs: Vec<rustls::pki_types::CertificateDer<'static>> =
                rustls_pemfile::certs(&mut cert_pem.as_bytes())
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| format!("invalid cert PEM: {e}"))?;

            let server_key = rustls_pemfile::private_key(&mut key_pem.as_bytes())
                .map_err(|e| format!("invalid key PEM: {e}"))?
                .ok_or("no private key found in key PEM")?;

            let ca_cert = rustls_pemfile::certs(&mut ca_pem.as_bytes())
                .next()
                .ok_or("no CA certificate found")?
                .map_err(|e| format!("invalid CA PEM: {e}"))?;

            Ok(tls::build_server_config(
                server_certs,
                server_key,
                &ca_cert,
            )?)
        }
        _ => {
            // Development mode: generate ephemeral self-signed certs.
            info!("no cert/key/CA provided — generating ephemeral self-signed certificates (dev mode only)");
            generate_ephemeral_certs()
        }
    }
}

/// Generate ephemeral self-signed certificates for development.
///
/// Creates a CA, server cert, and client cert — all in memory, never
/// written to disk. The CA cert is used as both the server's trust root
/// (for client verification) and the client's trust root (for server
/// verification).
fn generate_ephemeral_certs() -> Result<Arc<rustls::ServerConfig>, Box<dyn std::error::Error>> {
    // Generate CA
    let mut ca_params = rcgen::CertificateParams::new(vec!["ARE Dev CA".to_string()])?;
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_key_pair = rcgen::KeyPair::generate()?;
    let ca_cert = ca_params.self_signed(&ca_key_pair)?;

    // Generate server cert signed by CA
    let server_key_pair = rcgen::KeyPair::generate()?;
    let server_params = rcgen::CertificateParams::new(vec!["localhost".to_string()])?;
    let server_cert = server_params.signed_by(&server_key_pair, &ca_cert, &ca_key_pair)?;
    let server_cert_der = server_cert.der().clone();
    let server_key_der =
        rustls::pki_types::PrivateKeyDer::try_from(server_key_pair.serialize_der())?;
    let ca_cert_der = ca_cert.der().clone();

    let config = tls::build_server_config(vec![server_cert_der], server_key_der, &ca_cert_der)?;
    Ok(config)
}

/// Gate 8 authentication-mode validation. The daemon must know WHY it is
/// authenticating before it accepts the first connection: either explicit
/// STRICT (`Some` grants file) or an explicit development-only opt-out
/// (`permissive_authz`). Neither → refuse to start. Never an implicit
/// decision.
fn validate_authz_mode(grants_file: Option<&Path>, permissive_authz: bool) -> Result<(), String> {
    if grants_file.is_none() && !permissive_authz {
        return Err(
            "neither --grants-file nor --permissive-authz given. Pass --grants-file <path> \
             to run STRICT, or --permissive-authz to run legacy-permissive (DEVELOPMENT ONLY \
             — every authenticated client may do anything; do not use in production)"
                .to_string(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use std::path::Path;

    #[test]
    fn authz_mode_neither_flag_refuses() {
        let err = match validate_authz_mode(None, false) {
            Err(e) => e,
            Ok(()) => panic!("expected refusal when neither flag is given"),
        };
        assert!(err.contains("--grants-file"), "message: {err}");
        assert!(err.contains("--permissive-authz"), "message: {err}");
    }

    #[test]
    fn authz_mode_grants_file_is_strict() {
        assert!(validate_authz_mode(Some(Path::new("grants.json")), false).is_ok());
    }

    #[test]
    fn authz_mode_permissive_is_explicit_opt_in() {
        assert!(validate_authz_mode(None, true).is_ok());
    }

    #[test]
    fn authz_mode_both_flags_is_ok_grants_wins() {
        assert!(validate_authz_mode(Some(Path::new("grants.json")), true).is_ok());
    }
}
