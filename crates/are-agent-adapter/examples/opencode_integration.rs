//! Example: OpenCode-style agent integration with ARE.
//!
//! This demonstrates how an AI coding agent would use the ARE adapter
//! to perform coding tasks on a remote environment.

use are_agent_adapter::{
    Environment, ExecuteRequest, RemoteEnvironment, SessionConfig, AgentAdapterError,
};
use are_client::SecureClient;
use are_core::EnvironmentId;
use std::path::Path;
use tokio;

/// Example agent that fixes a Rust compile error on a remote environment.
async fn scenario_fix_rust_error(env: &RemoteEnvironment) -> Result<(), AgentAdapterError> {
    println!("=== Scenario 1: Fix Rust compile error ===");
    
    // Create a session for this task
    let session = env.create_session(SessionConfig {
        working_directory: "project".into(),
        env_vars: [("RUST_BACKTRACE".into(), "1".into())].into(),
    }).await?;
    
    println!("Created session: {}", session.session_id());
    
    // Read the failing source file
    let content = session.read_file("src/main.rs").await?;
    println!("Read main.rs ({} bytes)", content.len());
    let source = String::from_utf8_lossy(&content);
    println!("Source:\n{}", source);
    
    // Simulate fixing - in real usage, agent would analyze and modify
    let fixed = source.replace("fn main() {", "fn main() {\n    println!(\"Hello from remote!\");");
    
    // Write the fix
    let result = session.write_file("src/main.rs", fixed.as_bytes()).await?;
    println!("Wrote fix: {} bytes, hash: {}", result.bytes_written, result.content_hash);
    
    // Run cargo build to verify
    let proc = session.execute(ExecuteRequest {
        program: "cargo".into(),
        args: vec!["build".into()],
        working_directory: "project".into(),
        env_vars: std::collections::HashMap::new(),
        session_id: None,
    }).await?;
    
    println!("Started build process: {}", proc.process_id());
    
    // Wait for completion
    let output = proc.wait(120).await?;
    println!("Build exited: {:?}", output.exit_code);
    println!("Stdout: {}", output.stdout_str());
    println!("Stderr: {}", output.stderr_str());
    
    if output.success() {
        println!("✅ Build succeeded!");
    } else {
        println!("❌ Build failed");
    }
    
    Ok(())
}

/// Example agent that fixes a broken nginx configuration.
async fn scenario_fix_nginx(env: &RemoteEnvironment) -> Result<(), AgentAdapterError> {
    println!("\n=== Scenario 2: Fix broken nginx configuration ===");
    
    let session = env.create_session(SessionConfig {
        working_directory: "/etc/nginx".into(),
        env_vars: std::collections::HashMap::new(),
    }).await?;
    
    println!("Created session: {}", session.session_id());
    
    // Read nginx config
    let content = session.read_file("nginx.conf").await?;
    let config = String::from_utf8_lossy(&content);
    println!("Current nginx.conf:\n{}", config);
    
    // Fix: ensure proper upstream block
    let fixed = if !config.contains("upstream backend") {
        config.replace("http {", "http {\n    upstream backend {\n        server 127.0.0.1:8080;\n    }")
    } else {
        config.to_string()
    };
    
    // Write fixed config
    let result = session.write_file("nginx.conf", fixed.as_bytes()).await?;
    println!("Wrote fixed config: {} bytes", result.bytes_written);
    
    // Test nginx config
    let proc = session.execute(ExecuteRequest {
        program: "nginx".into(),
        args: vec!["-t".into()],
        working_directory: "/etc/nginx".into(),
        env_vars: std::collections::HashMap::new(),
        session_id: None,
    }).await?;
    
    let output = proc.wait(30).await?;
    println!("nginx -t exited: {:?}", output.exit_code);
    println!("Stdout: {}", output.stdout_str());
    println!("Stderr: {}", output.stderr_str());
    
    if output.success() {
        println!("✅ nginx config valid!");
    } else {
        println!("❌ nginx config still invalid");
    }
    
    Ok(())
}

/// Example agent that builds a website.
async fn scenario_build_website(env: &RemoteEnvironment) -> Result<(), AgentAdapterError> {
    println!("\n=== Scenario 3: Build a website ===");
    
    let session = env.create_session(SessionConfig {
        working_directory: "website".into(),
        env_vars: std::collections::HashMap::new(),
    }).await?;
    
    println!("Created session: {}", session.session_id());
    
    // List project structure
    let entries = session.list_directory(".").await?;
    println!("Project structure:");
    for e in &entries {
        println!("  {} ({})", e.name, if e.is_dir { "dir" } else { "file" });
    }
    
    // Check for package.json
    let has_package = entries.iter().any(|e| e.name == "package.json");
    if !has_package {
        println!("No package.json found, skipping npm install");
        return Ok(());
    }
    
    // Install dependencies
    let proc = session.execute(ExecuteRequest {
        program: "npm".into(),
        args: vec!["install".into()],
        working_directory: "website".into(),
        env_vars: std::collections::HashMap::new(),
        session_id: None,
    }).await?;
    
    let output = proc.wait(180).await?;
    println!("npm install exited: {:?}", output.exit_code);
    
    if !output.success() {
        println!("❌ npm install failed: {}", output.stderr_str());
        return Ok(());
    }
    
    // Run build
    let proc = session.execute(ExecuteRequest {
        program: "npm".into(),
        args: vec!["run".into(), "build".into()],
        working_directory: "website".into(),
        env_vars: std::collections::HashMap::new(),
        session_id: None,
    }).await?;
    
    let output = proc.wait(180).await?;
    println!("npm run build exited: {:?}", output.exit_code);
    println!("Stdout: {}", output.stdout_str());
    println!("Stderr: {}", output.stderr_str());
    
    if output.success() {
        println!("✅ Website built successfully!");
    } else {
        println!("❌ Build failed");
    }
    
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing (optional - requires tracing_subscriber feature)
    // tracing_subscriber::fmt::init();
    
    // Configuration - in real usage, these would come from config/env
    let client_cert = Path::new("C:/msys64/tmp/opencode/are-certs/client.pem");
    let client_key = Path::new("C:/msys64/tmp/opencode/are-certs/client.key");
    let ca_cert = Path::new("C:/msys64/tmp/opencode/are-certs/ca.pem");
    let server_addr = "192.168.0.13:9000";
    let server_name = "localhost";
    let env_id = EnvironmentId::new("dev-container");
    
    // Create secure client
    let client = SecureClient::from_pem_files(
        client_cert,
        client_key,
        ca_cert,
        server_addr,
        server_name,
    )?;
    
    // Connect to environment
    println!("Connecting to environment: {}", env_id);
    let env = RemoteEnvironment::connect(client, env_id).await?;
    println!("Connected! Capabilities: {:?}", env.capabilities());
    
    // Run scenarios
    scenario_fix_rust_error(&env).await?;
    scenario_fix_nginx(&env).await?;
    scenario_build_website(&env).await?;
    
    println!("\n=== All scenarios completed ===");
    Ok(())
}