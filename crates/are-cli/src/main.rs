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
                    }
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
