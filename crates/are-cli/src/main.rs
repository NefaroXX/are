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

    /// Manage remote environments
    Env {
        /// Subcommand: list, add, remove
        #[command(subcommand)]
        action: EnvAction,
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

        Commands::Env { action } => match action {
            EnvAction::List => println!("env list: no environments configured yet"),
            EnvAction::Add { name } => println!("env add: {name} (stub)"),
            EnvAction::Remove { name } => println!("env remove: {name} (stub)"),
        },
    }
}
