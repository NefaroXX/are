//! # are-cli (ared daemon binary)
//!
//! Entry point for the `ared` daemon process.

use are_core::EnvironmentId;
use are_daemon::{run, DaemonConfig};

fn main() {
    let config = DaemonConfig {
        environment_id: EnvironmentId::new("default"),
        port: 9000,
        max_sessions: 64,
    };

    if let Err(e) = run(config) {
        eprintln!("ared: error: {e}");
        std::process::exit(1);
    }
}
