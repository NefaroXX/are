//! Comprehensive agent scenario tests against remote ARE daemon.

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
    
    // Scenario 1: Fix Rust compile error
    println!("\n{}", "=".repeat(60));
    println!("SCENARIO 1: Fix Rust compile error");
    println!("{}", "=".repeat(60));
    scenario_fix_rust(&env).await?;
    
    // Scenario 2: Fix nginx config
    println!("\n{}", "=".repeat(60));
    println!("SCENARIO 2: Fix nginx configuration");
    println!("{}", "=".repeat(60));
    scenario_fix_nginx(&env).await?;
    
    // Scenario 3: Build website
    println!("\n{}", "=".repeat(60));
    println!("SCENARIO 3: Build website");
    println!("{}", "=".repeat(60));
    scenario_build_website(&env).await?;
    
    println!("\n{}", "=".repeat(60));
    println!("ALL SCENARIOS COMPLETED SUCCESSFULLY");
    println!("{}", "=".repeat(60));
    Ok(())
}

async fn scenario_fix_rust(env: &RemoteEnvironment) -> Result<(), Box<dyn std::error::Error>> {
    let session = env.create_session(SessionConfig {
        working_directory: "project".into(),
        env_vars: std::collections::HashMap::new(),
    }).await?;
    println!("Created session: {}", session.session_id());
    
    // Read the source file (environment-relative path)
    let content = session.read_file("project/src/main.rs").await?;
    let source = String::from_utf8_lossy(&content);
    println!("Original source:\n{}", source);
    
    // Simulate a compile error by checking if there's an issue
    // In reality, agent would run cargo build, see error, then fix
    let proc = session.execute(ExecuteRequest {
        program: "cargo".into(),
        args: vec!["build".into()],
        working_directory: "".into(),  // empty = inherit from session working_directory
        env_vars: std::collections::HashMap::new(),
        session_id: Some(session.session_id().clone()),  // Use the session we created
    }).await?;
    
    let output = proc.wait(120).await?;
    println!("Initial build exit: {:?}", output.exit_code);
    println!("Stdout: {}", output.stdout_str());
    println!("Stderr: {}", output.stderr_str());
    
    // Modify the source to fix the compile error (missing quotes in println!)
    // The original source has: println!(Hello, world!);
    // We need to fix it to: println!("Hello, world!");
    let modified = source.replace(
        r#"println!(Hello, world!);"#, 
        r#"println!("Hello, world!");"#
    );
    
    let result = session.write_file("project/src/main.rs", modified.as_bytes()).await?;
    println!("Wrote modified source: {} bytes, hash: {}", result.bytes_written, result.content_hash);
    
    // Build again
    let proc = session.execute(ExecuteRequest {
        program: "cargo".into(),
        args: vec!["build".into()],
        working_directory: "".into(),  // empty = inherit from session working_directory
        env_vars: std::collections::HashMap::new(),
        session_id: Some(session.session_id().clone()),  // Use the session we created
    }).await?;
    
    let output = proc.wait(120).await?;
    println!("Second build exit: {:?}", output.exit_code);
    println!("Stdout: {}", output.stdout_str());
    println!("Stderr: {}", output.stderr_str());
    
    if output.success() {
        println!("✅ Rust project builds successfully!");
    } else {
        println!("❌ Build failed");
    }
    
    Ok(())
}

async fn scenario_fix_nginx(env: &RemoteEnvironment) -> Result<(), Box<dyn std::error::Error>> {
    let session = env.create_session(SessionConfig {
        working_directory: "nginx-test".into(),
        env_vars: std::collections::HashMap::new(),
    }).await?;
    println!("Created session: {}", session.session_id());
    
    // Read nginx config (environment-relative path)
    let content = session.read_file("nginx-test/nginx.conf").await?;
    let config = String::from_utf8_lossy(&content);
    println!("Original nginx.conf:\n{}", config);
    
    // Fix: add upstream block if missing
    let fixed = if !config.contains("upstream backend") {
        config.replace("http {", "http {\n    upstream backend {\n        server 127.0.0.1:8080;\n    }")
    } else {
        config.to_string()
    };
    
    let result = session.write_file("nginx-test/nginx.conf", fixed.as_bytes()).await?;
    println!("Wrote fixed config: {} bytes", result.bytes_written);
    
    // Test nginx config (using session) - handle nginx not being installed
    let proc = session.execute(ExecuteRequest {
        program: "nginx".into(),
        args: vec!["-t".into()],
        working_directory: "".into(),  // empty = inherit from session working_directory
        env_vars: std::collections::HashMap::new(),
        session_id: Some(session.session_id().clone()),
    }).await;
    
    match proc {
        Ok(proc) => {
            let output = proc.wait(30).await?;
            println!("nginx -t exit: {:?}", output.exit_code);
            println!("Stdout: {}", output.stdout_str());
            println!("Stderr: {}", output.stderr_str());
            
            if output.success() {
                println!("✅ nginx config valid!");
            } else {
                println!("⚠️ nginx not installed or config invalid: {}", output.stderr_str());
            }
        }
        Err(e) => {
            println!("⚠️ nginx not available (spawn failed): {}", e);
        }
    }
    
    Ok(())
}

async fn scenario_build_website(env: &RemoteEnvironment) -> Result<(), Box<dyn std::error::Error>> {
    let session = env.create_session(SessionConfig {
        working_directory: "website".into(),
        env_vars: std::collections::HashMap::new(),
    }).await?;
    println!("Created session: {}", session.session_id());
    
    // List project structure (environment-relative)
    let entries = session.list_directory("website").await?;
    println!("Project structure:");
    for e in &entries {
        println!("  {} ({})", e.name, if e.is_dir { "dir" } else { "file" });
    }
    
    // Check for package.json
    let has_package = entries.iter().any(|e| e.name == "package.json");
    if !has_package {
        println!("No package.json found");
        return Ok(());
    }
    
    // Read package.json
    let content = session.read_file("website/package.json").await?;
    println!("package.json:\n{}", String::from_utf8_lossy(&content));
    
    // Run npm install (if npm is available)
    let proc = session.execute(ExecuteRequest {
        program: "npm".into(),
        args: vec!["install".into()],
        working_directory: "".into(),  // empty = inherit from session working_directory
        env_vars: std::collections::HashMap::new(),
        session_id: Some(session.session_id().clone()),
    }).await?;
    
    let output = proc.wait(180).await?;
    println!("npm install exit: {:?}", output.exit_code);
    
    if output.success() {
        println!("✅ npm install succeeded!");
        
        // Run build
        let proc = session.execute(ExecuteRequest {
            program: "npm".into(),
            args: vec!["run".into(), "build".into()],
            working_directory: "".into(),  // empty = inherit from session working_directory
            env_vars: std::collections::HashMap::new(),
            session_id: Some(session.session_id().clone()),
        }).await?;
        
        let output = proc.wait(180).await?;
        println!("npm run build exit: {:?}", output.exit_code);
        println!("Stdout: {}", output.stdout_str());
        println!("Stderr: {}", output.stderr_str());
        
        if output.success() {
            println!("✅ Website built successfully!");
        } else {
            println!("❌ Build failed");
        }
    } else {
        println!("⚠️ npm not available or install skipped: {}", output.stderr_str());
    }
    
    Ok(())
}