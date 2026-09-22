//! # are-cli
//!
//! The `are` command-line client for Agent Remote Environment.
//!
//! ## Subcommands
//!
//! - `connect` — Connect to a daemon and display environment info
//! - `doctor` — Run diagnostics to check daemon reachability and auth
//! - `env` — Environment management (stubs for later gates)

use std::path::PathBuf;

use are_client::connection::SecureClient;
use are_core::EnvironmentId;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "are", about = "Agent Remote Environment CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Connect to a daemon and display environment info
    Connect {
        /// Server address (host:port)
        #[arg(long, default_value = "127.0.0.1:9000")]
        addr: String,

        /// Path to client certificate PEM
        #[arg(long)]
        cert: PathBuf,

        /// Path to client private key PEM
        #[arg(long)]
        key: PathBuf,

        /// Path to CA certificate PEM (for server verification)
        #[arg(long)]
        ca: PathBuf,

        /// Server hostname for SNI (must match cert CN/SAN)
        #[arg(long, default_value = "localhost")]
        server_name: String,

        /// Environment ID to query
        #[arg(long, default_value = "default")]
        env_id: String,
    },

    /// Run diagnostics — check daemon reachability, auth, environment
    Doctor {
        /// Server address (host:port)
        #[arg(long, default_value = "127.0.0.1:9000")]
        addr: String,

        /// Path to client certificate PEM
        #[arg(long)]
        cert: PathBuf,

        /// Path to client private key PEM
        #[arg(long)]
        key: PathBuf,

        /// Path to CA certificate PEM
        #[arg(long)]
        ca: PathBuf,

        /// Server hostname for SNI
        #[arg(long, default_value = "localhost")]
        server_name: String,

        /// Environment ID to check
        #[arg(long, default_value = "default")]
        env_id: String,
    },

    /// Filesystem operations on a remote environment
    Fs {
        /// Subcommand: read, list, metadata
        #[command(subcommand)]
        action: FsAction,
    },

    /// Process operations on a remote environment
    Proc {
        /// Subcommand: run, status, wait, kill
        #[command(subcommand)]
        action: ProcAction,
    },

    /// Session operations on a remote environment (Gate 6: sessions are
    /// first-class — create once, resume across reconnects by id)
    Sess {
        /// Subcommand: create, show, list, rm
        #[command(subcommand)]
        action: SessAction,
    },

    /// Manage remote environments
    Env {
        /// Subcommand: list, add, remove
        #[command(subcommand)]
        action: EnvAction,
    },
}

#[derive(Subcommand)]
enum FsAction {
    /// Read a file from the remote environment
    Read {
        /// Server address (host:port)
        #[arg(long, default_value = "127.0.0.1:9000")]
        addr: String,

        /// Path to client certificate PEM
        #[arg(long)]
        cert: PathBuf,

        /// Path to client private key PEM
        #[arg(long)]
        key: PathBuf,

        /// Path to CA certificate PEM
        #[arg(long)]
        ca: PathBuf,

        /// Server hostname for SNI
        #[arg(long, default_value = "localhost")]
        server_name: String,

        /// Environment ID
        #[arg(long, default_value = "default")]
        env_id: String,

        /// Environment-relative path to read
        path: String,
    },

    /// List directory contents on the remote environment
    List {
        /// Server address (host:port)
        #[arg(long, default_value = "127.0.0.1:9000")]
        addr: String,

        /// Path to client certificate PEM
        #[arg(long)]
        cert: PathBuf,

        /// Path to client private key PEM
        #[arg(long)]
        key: PathBuf,

        /// Path to CA certificate PEM
        #[arg(long)]
        ca: PathBuf,

        /// Server hostname for SNI
        #[arg(long, default_value = "localhost")]
        server_name: String,

        /// Environment ID
        #[arg(long, default_value = "default")]
        env_id: String,

        /// Environment-relative path to list
        #[arg(default_value = ".")]
        path: String,
    },

    /// Get metadata about a file or directory
    Metadata {
        /// Server address (host:port)
        #[arg(long, default_value = "127.0.0.1:9000")]
        addr: String,

        /// Path to client certificate PEM
        #[arg(long)]
        cert: PathBuf,

        /// Path to client private key PEM
        #[arg(long)]
        key: PathBuf,

        /// Path to CA certificate PEM
        #[arg(long)]
        ca: PathBuf,

        /// Server hostname for SNI
        #[arg(long, default_value = "localhost")]
        server_name: String,

        /// Environment ID
        #[arg(long, default_value = "default")]
        env_id: String,

        /// Environment-relative path to inspect
        path: String,
    },

    /// Write (create or replace) a file in the remote environment.
    /// Content comes from exactly one of --content, --from-file, or stdin.
    Write {
        /// Server address (host:port)
        #[arg(long, default_value = "127.0.0.1:9000")]
        addr: String,

        /// Path to client certificate PEM
        #[arg(long)]
        cert: PathBuf,

        /// Path to client private key PEM
        #[arg(long)]
        key: PathBuf,

        /// Path to CA certificate PEM
        #[arg(long)]
        ca: PathBuf,

        /// Server hostname for SNI
        #[arg(long, default_value = "localhost")]
        server_name: String,

        /// Environment ID
        #[arg(long, default_value = "default")]
        env_id: String,

        /// Environment-relative destination path
        path: String,

        /// Inline content (mutually exclusive with --from-file; stdin
        /// when neither is given)
        #[arg(long, conflicts_with = "from_file")]
        content: Option<String>,

        /// Read content from a LOCAL file (explicit operator action: the
        /// CLI never reads local files implicitly — only this flag opts
        /// in to a local read for upload)
        #[arg(long, conflicts_with = "content")]
        from_file: Option<PathBuf>,

        /// Expected current content hash for optimistic concurrency
        /// (fails when the remote file changed since you read it)
        #[arg(long)]
        expect_hash: Option<String>,

        /// Refuse to overwrite an existing file
        #[arg(long)]
        no_overwrite: bool,
    },

    /// Create a directory (and missing ancestors) remotely
    Mkdir {
        /// Server address (host:port)
        #[arg(long, default_value = "127.0.0.1:9000")]
        addr: String,

        /// Path to client certificate PEM
        #[arg(long)]
        cert: PathBuf,

        /// Path to client private key PEM
        #[arg(long)]
        key: PathBuf,

        /// Path to CA certificate PEM
        #[arg(long)]
        ca: PathBuf,

        /// Server hostname for SNI
        #[arg(long, default_value = "localhost")]
        server_name: String,

        /// Environment ID
        #[arg(long, default_value = "default")]
        env_id: String,

        /// Environment-relative path to create
        path: String,
    },

    /// Rename (move) a remote file or directory
    Mv {
        /// Server address (host:port)
        #[arg(long, default_value = "127.0.0.1:9000")]
        addr: String,

        /// Path to client certificate PEM
        #[arg(long)]
        cert: PathBuf,

        /// Path to client private key PEM
        #[arg(long)]
        key: PathBuf,

        /// Path to CA certificate PEM
        #[arg(long)]
        ca: PathBuf,

        /// Server hostname for SNI
        #[arg(long, default_value = "localhost")]
        server_name: String,

        /// Environment ID
        #[arg(long, default_value = "default")]
        env_id: String,

        /// Environment-relative source path
        src: String,

        /// Environment-relative destination path (must not exist)
        dst: String,
    },

    /// Delete a remote file or EMPTY directory (never recursive)
    Rm {
        /// Server address (host:port)
        #[arg(long, default_value = "127.0.0.1:9000")]
        addr: String,

        /// Path to client certificate PEM
        #[arg(long)]
        cert: PathBuf,

        /// Path to client private key PEM
        #[arg(long)]
        key: PathBuf,

        /// Path to CA certificate PEM
        #[arg(long)]
        ca: PathBuf,

        /// Server hostname for SNI
        #[arg(long, default_value = "localhost")]
        server_name: String,

        /// Environment ID
        #[arg(long, default_value = "default")]
        env_id: String,

        /// Environment-relative path to delete
        path: String,
    },
}

#[derive(Subcommand)]
enum EnvAction {
    /// List configured environments
    List,
    /// Add an environment
    Add {
        /// Environment name
        name: String,
    },
    /// Remove an environment
    Remove {
        /// Environment name
        name: String,
    },
}

/// Shared TLS + addressing flags, flattened into each `proc` subcommand so
/// every command carries the standard `--addr/--cert/--key/--ca/
/// --server-name/--env-id/--session` set like the `fs` commands.
///
/// `--session` is REQUIRED (Gate 6): every process belongs to a session.
/// Create one first with `are sess create`.
#[derive(clap::Args)]
struct ProcConn {
    /// Server address (host:port)
    #[arg(long, default_value = "127.0.0.1:9000")]
    addr: String,

    /// Path to client certificate PEM
    #[arg(long)]
    cert: PathBuf,

    /// Path to client private key PEM
    #[arg(long)]
    key: PathBuf,

    /// Path to CA certificate PEM
    #[arg(long)]
    ca: PathBuf,

    /// Server hostname for SNI
    #[arg(long, default_value = "localhost")]
    server_name: String,

    /// Environment ID
    #[arg(long, default_value = "default")]
    env_id: String,

    /// Session ID (every process belongs to a session; see `are sess`)
    #[arg(long)]
    session: String,
}

/// Shared TLS + addressing flags for `sess` subcommands (no `--session`:
/// these commands create or name the session).
#[derive(clap::Args)]
struct SessConn {
    /// Server address (host:port)
    #[arg(long, default_value = "127.0.0.1:9000")]
    addr: String,

    /// Path to client certificate PEM
    #[arg(long)]
    cert: PathBuf,

    /// Path to client private key PEM
    #[arg(long)]
    key: PathBuf,

    /// Path to CA certificate PEM
    #[arg(long)]
    ca: PathBuf,

    /// Server hostname for SNI
    #[arg(long, default_value = "localhost")]
    server_name: String,

    /// Environment ID
    #[arg(long, default_value = "default")]
    env_id: String,
}

#[derive(Subcommand)]
enum SessAction {
    /// Create a persistent session (prints the session id)
    Create {
        #[command(flatten)]
        conn: SessConn,

        /// Environment-relative working directory (default ".")
        #[arg(long, default_value = ".")]
        workdir: String,

        /// Environment variable KEY=VAL (repeatable; PATH is rejected,
        /// LD_*/DYLD_* are stripped)
        #[arg(long)]
        env: Vec<String>,
    },

    /// Show (resume) a session by id
    Show {
        #[command(flatten)]
        conn: SessConn,

        /// Session ID
        id: String,
    },

    /// List live sessions in the environment
    List {
        #[command(flatten)]
        conn: SessConn,
    },

    /// Terminate a session, cascading to its processes
    Rm {
        #[command(flatten)]
        conn: SessConn,

        /// Session ID
        id: String,
    },
}

#[derive(Subcommand)]
enum ProcAction {
    /// Start a process in the remote environment (structured, no shell)
    Run {
        #[command(flatten)]
        conn: ProcConn,

        /// Program to execute (e.g. cargo, git)
        #[arg(long)]
        program: String,

        /// Argument to pass (repeatable)
        #[arg(long)]
        arg: Vec<String>,

        /// Environment-relative working directory. Empty ("") inherits
        /// the session's working directory (the default); a non-empty
        /// value resolves env-relative per ADR-002.
        #[arg(long, default_value = "")]
        workdir: String,

        /// Environment variable KEY=VAL (repeatable)
        #[arg(long)]
        env: Vec<String>,
    },

    /// Query the status of a process
    Status {
        #[command(flatten)]
        conn: ProcConn,

        /// Process ID
        id: String,
    },

    /// Wait for a process to exit, up to a timeout
    Wait {
        #[command(flatten)]
        conn: ProcConn,

        /// Process ID
        id: String,

        /// Timeout in seconds, 1..=3600 (daemon requires an explicit
        /// timeout; indefinite waits are rejected).
        #[arg(long, default_value = "30")]
        timeout: u64,
    },

    /// Terminate a process
    Kill {
        #[command(flatten)]
        conn: ProcConn,

        /// Process ID
        id: String,

        /// Force-kill (Gate 5: both paths are forceful — documented)
        #[arg(long)]
        force: bool,
    },
}

/// Parse an environment id or exit with an error.
fn parse_env_id(env_id: &str) -> EnvironmentId {
    match EnvironmentId::try_new(env_id) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("error: invalid environment_id: {e}");
            std::process::exit(1);
        }
    }
}

/// Parse a process id or exit with an error.
fn parse_process_id(id: &str) -> are_core::ProcessId {
    match are_core::ProcessId::try_new(id) {
        Ok(pid) => pid,
        Err(e) => {
            eprintln!("error: invalid process id: {e}");
            std::process::exit(1);
        }
    }
}

/// Parse a session id or exit with an error.
fn parse_session_id(id: &str) -> are_core::SessionId {
    match are_core::SessionId::try_new(id) {
        Ok(sid) => sid,
        Err(e) => {
            eprintln!("error: invalid session id: {e}");
            std::process::exit(1);
        }
    }
}

/// Build a TLS client or exit with an error.
fn make_client(conn: &ProcConn) -> SecureClient {
    match SecureClient::from_pem_files(
        &conn.cert,
        &conn.key,
        &conn.ca,
        &conn.addr,
        &conn.server_name,
    ) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: failed to configure TLS: {e}");
            std::process::exit(1);
        }
    }
}

/// Build a TLS client from session-command flags or exit with an error.
fn make_sess_client(conn: &SessConn) -> SecureClient {
    match SecureClient::from_pem_files(
        &conn.cert,
        &conn.key,
        &conn.ca,
        &conn.addr,
        &conn.server_name,
    ) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("error: failed to configure TLS: {e}");
            std::process::exit(1);
        }
    }
}

/// Maximum bytes the CLI will read from stdin / --content / --from-file
/// for `fs write`. Matches the daemon's 16 MiB file cap so oversized
/// payloads fail locally with a clean error instead of a framing failure.
const MAX_CLI_CONTENT_BYTES: u64 = 16 * 1024 * 1024;

/// Read stdin fully, capped at [`MAX_CLI_CONTENT_BYTES`] + 1 byte (the
/// extra byte detects overflow so we can reject with a clean error
/// instead of silently truncating).
fn read_stdin_capped() -> Vec<u8> {
    use std::io::Read as _;
    let mut buf = Vec::new();
    let limit = MAX_CLI_CONTENT_BYTES + 1;
    match std::io::stdin().take(limit).read_to_end(&mut buf) {
        Ok(_) => buf,
        Err(e) => {
            eprintln!("error: failed to read stdin: {e}");
            std::process::exit(1);
        }
    }
}

/// Parse KEY=VAL `--env` values or exit with an error.
fn parse_env_vars(env: &[String]) -> std::collections::HashMap<String, String> {
    let mut env_vars = std::collections::HashMap::new();
    for kv in env {
        match kv.split_once('=') {
            Some((k, v)) if !k.is_empty() => {
                env_vars.insert(k.to_string(), v.to_string());
            }
            _ => {
                eprintln!("error: invalid --env value {kv:?} (expected KEY=VAL)");
                std::process::exit(1);
            }
        }
    }
    env_vars
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();

    match cli.command {
        Commands::Connect {
            addr,
            cert,
            key,
            ca,
            server_name,
            env_id,
        } => {
            let env_id = match EnvironmentId::try_new(&env_id) {
                Ok(id) => id,
                Err(e) => {
                    eprintln!("error: invalid environment_id: {e}");
                    std::process::exit(1);
                }
            };

            let client = match SecureClient::from_pem_files(&cert, &key, &ca, &addr, &server_name) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("error: failed to configure TLS: {e}");
                    std::process::exit(1);
                }
            };

            match client.get_environment_info(&env_id).await {
                Ok(info) => {
                    println!("Environment: {}", info.environment_id);
                    println!("  Machine:   {}", info.machine_name);
                    println!("  OS:        {}", info.operating_system);
                    println!("  Platform:  {}", info.platform);
                    println!("  Version:   {}", info.daemon_version);
                    println!("  Capabilities:");
                    for cap in info.advertised_capabilities.iter() {
                        println!("    - {cap}");
                    }
                }
                Err(e) => {
                    eprintln!("error: {e}");
                    std::process::exit(1);
                }
            }
        }

        Commands::Doctor {
            addr,
            cert,
            key,
            ca,
            server_name,
            env_id,
        } => {
            let env_id = match EnvironmentId::try_new(&env_id) {
                Ok(id) => id,
                Err(e) => {
                    eprintln!("FAIL: invalid environment_id: {e}");
                    std::process::exit(1);
                }
            };

            println!("ARE Doctor v{}", env!("CARGO_PKG_VERSION"));
            println!();

            // Check 1: TLS configuration
            print!("  TLS configuration ... ");
            let client = match SecureClient::from_pem_files(&cert, &key, &ca, &addr, &server_name) {
                Ok(c) => c,
                Err(e) => {
                    println!("FAIL ({e})");
                    std::process::exit(1);
                }
            };
            println!("ok");

            // Check 2: Daemon reachable + mTLS handshake
            print!("  Daemon reachable ... ");
            match client.get_environment_info(&env_id).await {
                Ok(info) => {
                    println!("ok");
                    println!();
                    println!("  Environment: {}", info.environment_id);
                    println!("  Machine:     {}", info.machine_name);
                    println!("  Platform:    {}", info.platform);
                    println!("  Version:     {}", info.daemon_version);
                    println!("  Capabilities:");
                    for cap in info.advertised_capabilities.iter() {
                        println!("    - {cap}");
                    }
                    println!();
                    println!("All checks passed.");
                }
                Err(e) => {
                    println!("FAIL ({e})");
                    std::process::exit(1);
                }
            }
        }

        Commands::Fs { action } => match action {
            FsAction::Read {
                addr,
                cert,
                key,
                ca,
                server_name,
                env_id,
                path,
            } => {
                let env_id = match EnvironmentId::try_new(&env_id) {
                    Ok(id) => id,
                    Err(e) => {
                        eprintln!("error: invalid environment_id: {e}");
                        std::process::exit(1);
                    }
                };

                let client =
                    match SecureClient::from_pem_files(&cert, &key, &ca, &addr, &server_name) {
                        Ok(c) => c,
                        Err(e) => {
                            eprintln!("error: failed to configure TLS: {e}");
                            std::process::exit(1);
                        }
                    };

                let req = are_core::ReadFileRequest {
                    environment_id: env_id,
                    path,
                };

                match client.read_file(req).await {
                    Ok(resp) => {
                        // Write content to stdout.
                        if let Err(e) =
                            std::io::Write::write_all(&mut std::io::stdout(), &resp.content)
                        {
                            eprintln!("error: failed to write to stdout: {e}");
                            std::process::exit(1);
                        }
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        std::process::exit(1);
                    }
                }
            }

            FsAction::List {
                addr,
                cert,
                key,
                ca,
                server_name,
                env_id,
                path,
            } => {
                let env_id = match EnvironmentId::try_new(&env_id) {
                    Ok(id) => id,
                    Err(e) => {
                        eprintln!("error: invalid environment_id: {e}");
                        std::process::exit(1);
                    }
                };

                let client =
                    match SecureClient::from_pem_files(&cert, &key, &ca, &addr, &server_name) {
                        Ok(c) => c,
                        Err(e) => {
                            eprintln!("error: failed to configure TLS: {e}");
                            std::process::exit(1);
                        }
                    };

                let req = are_core::ListDirectoryRequest {
                    environment_id: env_id,
                    path,
                };

                match client.list_directory(req).await {
                    Ok(resp) => {
                        for entry in &resp.entries {
                            let kind = if entry.metadata.is_dir {
                                "d"
                            } else if entry.metadata.is_file {
                                "-"
                            } else {
                                "?"
                            };
                            println!("{} {:>8} {}", kind, entry.metadata.size, entry.path);
                        }
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        std::process::exit(1);
                    }
                }
            }

            FsAction::Metadata {
                addr,
                cert,
                key,
                ca,
                server_name,
                env_id,
                path,
            } => {
                let env_id = match EnvironmentId::try_new(&env_id) {
                    Ok(id) => id,
                    Err(e) => {
                        eprintln!("error: invalid environment_id: {e}");
                        std::process::exit(1);
                    }
                };

                let client =
                    match SecureClient::from_pem_files(&cert, &key, &ca, &addr, &server_name) {
                        Ok(c) => c,
                        Err(e) => {
                            eprintln!("error: failed to configure TLS: {e}");
                            std::process::exit(1);
                        }
                    };

                let req = are_core::GetFileMetadataRequest {
                    environment_id: env_id,
                    path,
                };

                match client.file_metadata(req).await {
                    Ok(resp) => {
                        println!("Size:     {} bytes", resp.metadata.size);
                        println!("Is file:  {}", resp.metadata.is_file);
                        println!("Is dir:   {}", resp.metadata.is_dir);
                        if let Some(modified) = resp.metadata.modified_at {
                            println!("Modified: {modified:?}");
                        }
                        if let Some(hash) = resp.metadata.hash {
                            println!("Hash:     blake3:{hash}");
                        }
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        std::process::exit(1);
                    }
                }
            }

            FsAction::Write {
                addr,
                cert,
                key,
                ca,
                server_name,
                env_id,
                path,
                content,
                from_file,
                expect_hash,
                no_overwrite,
            } => {
                let env_id = match EnvironmentId::try_new(&env_id) {
                    Ok(id) => id,
                    Err(e) => {
                        eprintln!("error: invalid environment_id: {e}");
                        std::process::exit(1);
                    }
                };

                // Exactly one content source: --content, --from-file, stdin.
                let bytes: Vec<u8> = match (content, from_file) {
                    (Some(text), None) => text.into_bytes(),
                    (None, Some(local)) => {
                        // Pre-stat BEFORE reading: an oversized --from-file
                        // must fail without loading it into memory (symmetric
                        // with the stdin `.take()` cap). A stat failure exits
                        // with a clean error too.
                        let size = match std::fs::metadata(&local) {
                            Ok(meta) => meta.len(),
                            Err(e) => {
                                eprintln!(
                                    "error: failed to stat --from-file {}: {e}",
                                    local.display()
                                );
                                std::process::exit(1);
                            }
                        };
                        if size > MAX_CLI_CONTENT_BYTES {
                            eprintln!(
                                "error: --from-file {} is {size} bytes, exceeds {}-byte cap",
                                local.display(),
                                MAX_CLI_CONTENT_BYTES
                            );
                            std::process::exit(1);
                        }
                        match std::fs::read(&local) {
                            Ok(data) => data,
                            Err(e) => {
                                eprintln!(
                                    "error: failed to read --from-file {}: {e}",
                                    local.display()
                                );
                                std::process::exit(1);
                            }
                        }
                    }
                    (None, None) => read_stdin_capped(),
                    // Unreachable: clap `conflicts_with` rejects both.
                    (Some(_), Some(_)) => {
                        eprintln!("error: --content and --from-file are mutually exclusive");
                        std::process::exit(1);
                    }
                };
                if bytes.len() as u64 > MAX_CLI_CONTENT_BYTES {
                    eprintln!(
                        "error: content is {} bytes, exceeds {}-byte cap",
                        bytes.len(),
                        MAX_CLI_CONTENT_BYTES
                    );
                    std::process::exit(1);
                }

                // (Gate 7 live-test fix) `are fs metadata` prints hashes as
                // `blake3:<64 lowercase hex>`, and `are fs write` prints the
                // result the same way. Accept that form verbatim (plus raw
                // and/or uppercase hex), normalize to lowercase 64-hex, and
                // send the normalized form to the daemon.
                let expect_hash = match &expect_hash {
                    Some(h) => match normalize_expect_hash(h) {
                        Some(normalized) => Some(normalized),
                        None => {
                            eprintln!("error: --expect-hash must be 64 hex chars");
                            std::process::exit(1);
                        }
                    },
                    None => None,
                };

                let client =
                    match SecureClient::from_pem_files(&cert, &key, &ca, &addr, &server_name) {
                        Ok(c) => c,
                        Err(e) => {
                            eprintln!("error: failed to configure TLS: {e}");
                            std::process::exit(1);
                        }
                    };

                let req = are_core::WriteFileRequest {
                    environment_id: env_id,
                    path,
                    content: bytes,
                    overwrite: !no_overwrite,
                    expected_hash: expect_hash,
                };

                match client.write_file(req).await {
                    Ok(resp) => {
                        println!("Wrote {} bytes", resp.metadata.size);
                        if let Some(hash) = resp.metadata.hash {
                            println!("Hash: blake3:{hash}");
                        }
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        std::process::exit(1);
                    }
                }
            }

            FsAction::Mkdir {
                addr,
                cert,
                key,
                ca,
                server_name,
                env_id,
                path,
            } => {
                let env_id = match EnvironmentId::try_new(&env_id) {
                    Ok(id) => id,
                    Err(e) => {
                        eprintln!("error: invalid environment_id: {e}");
                        std::process::exit(1);
                    }
                };

                let client =
                    match SecureClient::from_pem_files(&cert, &key, &ca, &addr, &server_name) {
                        Ok(c) => c,
                        Err(e) => {
                            eprintln!("error: failed to configure TLS: {e}");
                            std::process::exit(1);
                        }
                    };

                let req = are_core::CreateDirectoryRequest {
                    environment_id: env_id,
                    path,
                };

                match client.create_directory(req).await {
                    Ok(_) => println!("Created directory"),
                    Err(e) => {
                        eprintln!("error: {e}");
                        std::process::exit(1);
                    }
                }
            }

            FsAction::Mv {
                addr,
                cert,
                key,
                ca,
                server_name,
                env_id,
                src,
                dst,
            } => {
                let env_id = match EnvironmentId::try_new(&env_id) {
                    Ok(id) => id,
                    Err(e) => {
                        eprintln!("error: invalid environment_id: {e}");
                        std::process::exit(1);
                    }
                };

                let client =
                    match SecureClient::from_pem_files(&cert, &key, &ca, &addr, &server_name) {
                        Ok(c) => c,
                        Err(e) => {
                            eprintln!("error: failed to configure TLS: {e}");
                            std::process::exit(1);
                        }
                    };

                let req = are_core::RenameRequest {
                    environment_id: env_id,
                    src,
                    dst,
                };

                match client.rename(req).await {
                    Ok(resp) => {
                        println!("Renamed ({} bytes)", resp.metadata.size);
                        if let Some(hash) = resp.metadata.hash {
                            println!("Hash: blake3:{hash}");
                        }
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        std::process::exit(1);
                    }
                }
            }

            FsAction::Rm {
                addr,
                cert,
                key,
                ca,
                server_name,
                env_id,
                path,
            } => {
                let env_id = match EnvironmentId::try_new(&env_id) {
                    Ok(id) => id,
                    Err(e) => {
                        eprintln!("error: invalid environment_id: {e}");
                        std::process::exit(1);
                    }
                };

                let client =
                    match SecureClient::from_pem_files(&cert, &key, &ca, &addr, &server_name) {
                        Ok(c) => c,
                        Err(e) => {
                            eprintln!("error: failed to configure TLS: {e}");
                            std::process::exit(1);
                        }
                    };

                let req = are_core::DeleteRequest {
                    environment_id: env_id,
                    path,
                };

                match client.delete_file(req).await {
                    Ok(_) => println!("Deleted"),
                    Err(e) => {
                        eprintln!("error: {e}");
                        std::process::exit(1);
                    }
                }
            }
        },

        Commands::Proc { action } => match action {
            ProcAction::Run {
                conn,
                program,
                arg,
                workdir,
                env,
            } => {
                let env_id = parse_env_id(&conn.env_id);
                let session_id = parse_session_id(&conn.session);
                let client = make_client(&conn);

                let env_vars = parse_env_vars(&env);

                let req = are_core::ExecuteRequest {
                    environment_id: env_id,
                    session_id,
                    program,
                    args: arg,
                    working_directory: workdir,
                    env_vars,
                };

                match client.execute(req).await {
                    Ok(resp) => println!("{}", resp.process_id),
                    Err(e) => {
                        eprintln!("error: {e}");
                        std::process::exit(1);
                    }
                }
            }

            ProcAction::Status { conn, id } => {
                let env_id = parse_env_id(&conn.env_id);
                let session_id = parse_session_id(&conn.session);
                let process_id = parse_process_id(&id);
                let client = make_client(&conn);

                let req = are_core::ProcessStatusRequest {
                    environment_id: env_id,
                    session_id,
                    process_id,
                };

                match client.process_status(req).await {
                    Ok(resp) => println!("{:?}", resp.state),
                    Err(e) => {
                        eprintln!("error: {e}");
                        std::process::exit(1);
                    }
                }
            }

            ProcAction::Wait { conn, id, timeout } => {
                let env_id = parse_env_id(&conn.env_id);
                let session_id = parse_session_id(&conn.session);
                let process_id = parse_process_id(&id);
                let client = make_client(&conn);

                let req = are_core::WaitProcessRequest {
                    environment_id: env_id,
                    session_id,
                    process_id,
                    timeout_secs: timeout,
                };

                match client.wait_process(req).await {
                    Ok(resp) => {
                        println!("exit_code: {:?}", resp.exit_code);
                        println!("timed_out: {}", resp.timed_out);
                        println!("truncated: {}", resp.truncated);
                        if let Err(e) =
                            std::io::Write::write_all(&mut std::io::stdout(), &resp.stdout)
                        {
                            eprintln!("error: failed to write stdout: {e}");
                            std::process::exit(1);
                        }
                        if !resp.stderr.is_empty() {
                            eprintln!("--- stderr ---");
                            if let Err(e) =
                                std::io::Write::write_all(&mut std::io::stderr(), &resp.stderr)
                            {
                                eprintln!("error: failed to write stderr: {e}");
                                std::process::exit(1);
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        std::process::exit(1);
                    }
                }
            }

            ProcAction::Kill { conn, id, force } => {
                let env_id = parse_env_id(&conn.env_id);
                let session_id = parse_session_id(&conn.session);
                let process_id = parse_process_id(&id);
                let client = make_client(&conn);

                let req = are_core::TerminateProcessRequest {
                    environment_id: env_id,
                    session_id,
                    process_id,
                    force,
                };

                match client.terminate_process(req).await {
                    Ok(resp) => println!("terminated: {}", resp.terminated),
                    Err(e) => {
                        eprintln!("error: {e}");
                        std::process::exit(1);
                    }
                }
            }
        },

        Commands::Sess { action } => match action {
            SessAction::Create { conn, workdir, env } => {
                let env_id = parse_env_id(&conn.env_id);
                let client = make_sess_client(&conn);
                let env_vars = parse_env_vars(&env);

                let req = are_core::CreateSessionRequest {
                    environment_id: env_id,
                    working_directory: Some(workdir),
                    env_vars,
                };

                match client.create_session(req).await {
                    Ok(resp) => println!("{}", resp.session.session_id),
                    Err(e) => {
                        eprintln!("error: {e}");
                        std::process::exit(1);
                    }
                }
            }

            SessAction::Show { conn, id } => {
                let session_id = parse_session_id(&id);
                let environment_id = parse_env_id(&conn.env_id);
                let client = make_sess_client(&conn);

                let req = are_core::GetSessionRequest {
                    environment_id,
                    session_id,
                };

                match client.get_session(req).await {
                    Ok(resp) => {
                        let s = resp.session;
                        println!("session: {}", s.session_id);
                        println!("  environment: {}", s.environment_id);
                        println!("  workdir:     {}", s.working_directory);
                        println!("  created:     {}", s.created_at);
                        println!("  last-active: {}", s.last_activity);
                        println!("  env:");
                        let mut keys: Vec<&String> = s.env_vars.keys().collect();
                        keys.sort();
                        for k in keys {
                            println!("    {k}={}", s.env_vars[k]);
                        }
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        std::process::exit(1);
                    }
                }
            }

            SessAction::List { conn } => {
                let env_id = parse_env_id(&conn.env_id);
                let client = make_sess_client(&conn);

                let req = are_core::ListSessionsRequest {
                    environment_id: env_id,
                };

                match client.list_sessions(req).await {
                    Ok(resp) => {
                        for s in &resp.sessions {
                            println!(
                                "{}  workdir={}  env_vars={}  created={}  last-active={}",
                                s.session_id,
                                s.working_directory,
                                s.env_vars.len(),
                                s.created_at,
                                s.last_activity
                            );
                        }
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        std::process::exit(1);
                    }
                }
            }

            SessAction::Rm { conn, id } => {
                let session_id = parse_session_id(&id);
                let environment_id = parse_env_id(&conn.env_id);
                let client = make_sess_client(&conn);

                let req = are_core::TerminateSessionRequest {
                    environment_id,
                    session_id,
                };

                match client.terminate_session(req).await {
                    Ok(resp) => println!(
                        "terminated session ({} processes reaped)",
                        resp.terminated_processes
                    ),
                    Err(e) => {
                        eprintln!("error: {e}");
                        std::process::exit(1);
                    }
                }
            }
        },

        Commands::Env { action } => match action {
            EnvAction::List => println!("env list: no environments configured yet"),
            EnvAction::Add { name } => println!("env add: {name} (stub)"),
            EnvAction::Remove { name } => println!("env remove: {name} (stub)"),
        },
    }
}

/// Normalize a `--expect-hash` value before sending it to the daemon.
///
/// `are fs metadata`/`are fs write` print hashes as `blake3:<64 lowercase
/// hex>`; users copy that exact string back into `--expect-hash`. Strip the
/// optional `blake3:` prefix (exact lowercase; raw hex is accepted as-is),
/// lowercase the hex (the daemon emits and compares lowercase), then require
/// the canonical 64-hex shape. Returns `None` for anything that is not a
/// valid hash after normalization.
fn normalize_expect_hash(input: &str) -> Option<String> {
    let hex = input.strip_prefix("blake3:").unwrap_or(input);
    let hex = hex.to_ascii_lowercase();
    if are_core::is_valid_hash(&hex) {
        Some(hex)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::normalize_expect_hash;

    #[test]
    fn normalize_expect_hash_accepts_raw_lowercase_hex() {
        let hex = "a".repeat(64);
        assert_eq!(normalize_expect_hash(&hex).as_deref(), Some(hex.as_str()));
    }

    #[test]
    fn normalize_expect_hash_strips_blake3_prefix() {
        let hex = "a".repeat(64);
        let prefixed = format!("blake3:{hex}");
        assert_eq!(
            normalize_expect_hash(&prefixed).as_deref(),
            Some(hex.as_str())
        );
    }

    #[test]
    fn normalize_expect_hash_lowercases_uppercase_hex() {
        // Raw uppercase hex is accepted and normalized to lowercase.
        let expected = "a".repeat(64);
        assert_eq!(
            normalize_expect_hash(&"A".repeat(64)).as_deref(),
            Some(expected.as_str())
        );
        // Prefixed uppercase hex too.
        let upper = "B".repeat(64);
        let prefixed_upper = format!("blake3:{upper}");
        assert_eq!(
            normalize_expect_hash(&prefixed_upper).as_deref(),
            Some(upper.to_ascii_lowercase().as_str())
        );
    }

    #[test]
    fn normalize_expect_hash_rejects_invalid_shapes() {
        let bad = [
            String::new(),                        // empty
            "blake3:".to_string(),                // prefix, no hex
            "blake3:xyz".to_string(),             // prefix + short hex
            "a".repeat(63),                       // too short
            "a".repeat(65),                       // too long
            "g".repeat(64),                       // non-hex char
            format!("blake3:{}", "g".repeat(64)), // prefix + non-hex
            format!("BLAKE3:{}", "a".repeat(64)), // uppercase prefix not stripped
            format!("blake3:{}", "a".repeat(65)), // prefix + too long
        ];
        for input in bad {
            assert_eq!(normalize_expect_hash(&input), None, "input: {input:?}");
        }
    }
}
