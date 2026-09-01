//! # are-cli
//!
//! The `are` command-line client for Agent Remote Environment.
//!
//! Subcommands (all placeholder stubs for Gate 0):
//!
//! - `env` — environment management
//! - `connect` — connection testing
//! - `doctor` — diagnostics

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "are", about = "Agent Remote Environment CLI")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Manage remote environments
    Env {
        /// Subcommand: list, add, remove
        #[command(subcommand)]
        action: EnvAction,
    },
    /// Test connection to a daemon
    Connect {
        /// Environment or host to connect to
        target: Option<String>,
    },
    /// Run diagnostics
    Doctor,
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

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Env { action } => match action {
            EnvAction::List => println!("env list: no environments configured yet"),
            EnvAction::Add { name } => println!("env add: {name} (stub)"),
            EnvAction::Remove { name } => println!("env remove: {name} (stub)"),
        },
        Commands::Connect { target } => {
            let t = target.unwrap_or_else(|| "<none>".into());
            println!("connect to {t}: stub — not implemented yet");
        }
        Commands::Doctor => println!("doctor: all checks pass (stub)"),
    }
}
