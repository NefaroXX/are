//! Simple integration test for the agent adapter against a real ARE daemon.

use are_agent_adapter::{Environment, ExecuteRequest, RemoteEnvironment, SessionConfig};
use are_client::SecureClient;
use are_core::EnvironmentId;
use std::path::Path;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Setup
    let client_cert = Path::new("C:/msys64/tmp/opencode/are-certs/client.pem");
    let client_key = Path::new("C:/msys64/tmp/opencode/are-certs/client.key");
    let ca_cert = Path::new("C:/msys64/tmp/opencode/are-certs/ca.pem");
    let server_addr = "192.168.0.13:9000";
    let server_name = "localhost";
    let env_id = EnvironmentId::new("dev-container");
    
    println!("Creating secure client...");
    let client = SecureClient::from_pem_files(
        client_cert,
        client_key,
        ca_cert,
        server_addr,
        server_name,
    )?;
    
    println!("Connecting to environment {}...", env_id);
    let env = RemoteEnvironment::connect(client, env_id).await?;
    println!("Connected! Capabilities: {:?}", env.capabilities());
    
    // Test 1: Basic filesystem operations
    println!("\n=== Test 1: Filesystem operations ===");
    let session = env.create_session(SessionConfig::default()).await?;
    println!("Created session: {}", session.session_id());
    
    // Write a test file
    let content = b"Hello from agent adapter test!";
    let result = session.write_file("test-agent.txt", content).await?;
    println!("Wrote test file: {} bytes, hash: {}", result.bytes_written, result.content_hash);
    
    // Read it back
    let read_back = session.read_file("test-agent.txt").await?;
    println!("Read back: {}", String::from_utf8_lossy(&read_back));
    
    // List directory
    let entries = session.list_directory(".").await?;
    println!("Directory listing:");
    for e in entries {
        println!("  {} ({}, {} bytes)", e.name, if e.is_dir { "dir" } else { "file" }, e.size.unwrap_or(0));
    }
    
    // Test 2: Process execution
    println!("\n=== Test 2: Process execution ===");
    let proc = session.execute(ExecuteRequest {
        program: "echo".into(),
        args: vec!["hello from agent".into()],
        working_directory: ".".into(),
        env_vars: std::collections::HashMap::new(),
        session_id: None,
    }).await?;
    
    println!("Started process: {}", proc.process_id());
    let output = proc.wait(30).await?;
    println!("Exit code: {:?}", output.exit_code);
    println!("Stdout: {}", output.stdout_str());
    
    // Test 3: Long-running process with status check
    println!("\n=== Test 3: Long-running process ===");
    let proc = session.execute(ExecuteRequest {
        program: "sleep".into(),
        args: vec!["5".into()],
        working_directory: ".".into(),
        env_vars: std::collections::HashMap::new(),
        session_id: None,
    }).await?;
    
    println!("Started sleep process: {}", proc.process_id());
    
    // Check status immediately
    let status = proc.status().await?;
    println!("Immediate status: {:?}", status);
    
    // Wait for completion
    let output = proc.wait(30).await?;
    println!("Final output: exit={:?}, stdout={}", output.exit_code, output.stdout_str());
    
    // Clean up test file
    session.delete("test-agent.txt").await?;
    println!("\nCleaned up test file");
    
    println!("\n✅ All integration tests passed!");
    Ok(())
}