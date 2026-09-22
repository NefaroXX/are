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
/// --server-name/--env-id` set like the `fs` commands.
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

        /// Environment-relative working directory
        #[arg(long, default_value = ".")]
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
                let client = make_client(&conn);

                let mut env_vars = std::collections::HashMap::new();
                for kv in &env {
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

                let req = are_core::ExecuteRequest {
                    environment_id: env_id,
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
                let process_id = parse_process_id(&id);
                let client = make_client(&conn);

                let req = are_core::ProcessStatusRequest {
                    environment_id: env_id,
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
                let process_id = parse_process_id(&id);
                let client = make_client(&conn);

                let req = are_core::WaitProcessRequest {
                    environment_id: env_id,
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
                let process_id = parse_process_id(&id);
                let client = make_client(&conn);

                let req = are_core::TerminateProcessRequest {
                    environment_id: env_id,
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

        Commands::Env { action } => match action {
            EnvAction::List => println!("env list: no environments configured yet"),
            EnvAction::Add { name } => println!("env add: {name} (stub)"),
            EnvAction::Remove { name } => println!("env remove: {name} (stub)"),
        },
    }
}
