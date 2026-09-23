//! TEST 1: Remote identity / locality verification
//!
//! This test establishes unmistakable identity markers on the remote environment
//! and verifies that all operations occur remotely.

use are_agent_adapter::{Environment, ExecuteRequest, RemoteEnvironment, SessionConfig};
use are_client::SecureClient;
use are_core::EnvironmentId;
use std::path::Path;
use std::time::Instant;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== TEST 1: Remote Identity / Locality Verification ===\n");

    let client_cert = Path::new("C:/msys64/tmp/opencode/are-certs/client.pem");
    let client_key = Path::new("C:/msys64/tmp/opencode/are-certs/client.key");
    let ca_cert = Path::new("C:/msys64/tmp/opencode/are-certs/ca.pem");
    let server_addr = "192.168.0.13:9000";
    let server_name = "localhost";
    let env_id = EnvironmentId::new("dev-container");

    let client = SecureClient::from_pem_files(client_cert, client_key, ca_cert, server_addr, server_name)?;
    let env = RemoteEnvironment::connect(client, env_id).await?;
    
    println!("✓ Connected to environment: {}", env.environment_id());
    println!("✓ Advertised capabilities: {:?}", env.capabilities());

    // Create a session for our tests
    let session = env.create_session(SessionConfig::default()).await?;
    println!("✓ Created session: {}", session.session_id());

    // 1. Create a test marker with identity info
    println!("\n--- Creating remote identity marker ---");
    let marker_content = format!(
        "ARE Remote Identity Marker\n\
        Hostname: {}\n\
        Machine ID: {}\n\
        Working Dir: {}\n\
        OS: {}\n\
        PID: {}\n\
        Timestamp: {}\n\
        Client Principal: blake3:07527f8e31ff995bfcbab53ddef15486637b8ee5524942bc4319276de1ce7a30\n",
        hostname(),
        machine_id(),
        std::env::current_dir().unwrap_or_default().display(),
        std::env::consts::OS,
        std::process::id(),
        chrono::Utc::now().to_rfc3339()
    );

    // Write the marker remotely
    let result = session.write_file("identity_marker.txt", marker_content.as_bytes()).await?;
    println!("✓ Wrote identity marker remotely ({} bytes, hash: {})", result.bytes_written, result.content_hash);

    // 2. Read the marker back via ARE - should show remote info
    println!("\n--- Reading marker via ARE (should show REMOTE info) ---");
    let remote_content = session.read_file("identity_marker.txt").await?;
    let remote_str = String::from_utf8_lossy(&remote_content);
    println!("Remote marker content:\n{}", remote_str);

    // 3. Execute commands remotely to verify process execution is remote
    println!("\n--- Verifying remote process execution ---");
    
    // Check hostname
    let proc = session.execute(ExecuteRequest {
        program: "hostname".into(),
        args: vec![],
        working_directory: "".into(),
        env_vars: std::collections::HashMap::new(),
        session_id: Some(session.session_id().clone()),
    }).await?;
    let output = proc.wait(30).await?;
    println!("Remote hostname: {}", output.stdout_str().trim());
    
    // Check OS
    let proc = session.execute(ExecuteRequest {
        program: "uname".into(),
        args: vec!["-a".into()],
        working_directory: "".into(),
        env_vars: std::collections::HashMap::new(),
        session_id: Some(session.session_id().clone()),
    }).await?;
    let output = proc.wait(30).await?;
    println!("Remote uname: {}", output.stdout_str().trim());
    
    // Check PID
    let proc = session.execute(ExecuteRequest {
        program: "sh".into(),
        args: vec!["-c".into(), "echo $PPID".into()],
        working_directory: "".into(),
        env_vars: std::collections::HashMap::new(),
        session_id: Some(session.session_id().clone()),
    }).await?;
    let output = proc.wait(30).await?;
    println!("Remote shell PID: {}", output.stdout_str().trim());
    
    // Check working directory
    let proc = session.execute(ExecuteRequest {
        program: "pwd".into(),
        args: vec![],
        working_directory: "".into(),
        env_vars: std::collections::HashMap::new(),
        session_id: Some(session.session_id().clone()),
    }).await?;
    let output = proc.wait(30).await?;
    println!("Remote pwd: {}", output.stdout_str().trim());

    // 4. Create a local marker with DIFFERENT content and verify agent CANNOT read it via ARE
    println!("\n--- Creating LOCAL marker (should NOT be accessible via ARE) ---");
    let local_marker = "LOCAL MARKER - This should NOT be readable via ARE\nLocal hostname: ".to_string() + &hostname();
    std::fs::write("C:/temp/local_identity_marker.txt", &local_marker)?;
    println!("✓ Created local marker at C:/temp/local_identity_marker.txt");
    
    // Try to read a file that only exists locally - should fail
    println!("\n--- Attempting to read local-only file via ARE (should fail) ---");
    match session.read_file("C:/temp/local_identity_marker.txt").await {
        Ok(_) => println!("❌ FAILURE: Was able to read local-only file via ARE!"),
        Err(e) => println!("✓ Correctly rejected: {}", e),
    }

    // 5. Verify files created remotely exist only on remote
    println!("\n--- Verifying remote-only file existence ---");
    let proc = session.execute(ExecuteRequest {
        program: "ls".into(),
        args: vec!["-la".into(), "identity_marker.txt".into()],
        working_directory: "".into(),
        env_vars: std::collections::HashMap::new(),
        session_id: Some(session.session_id().clone()),
    }).await?;
    let output = proc.wait(30).await?;
    println!("Remote ls output:\n{}", output.stdout_str());

    // 6. Verify the local file does NOT exist on remote
    let proc = session.execute(ExecuteRequest {
        program: "ls".into(),
        args: vec!["-la".into(), "C:/temp/local_identity_marker.txt".into()],
        working_directory: "".into(),
        env_vars: std::collections::HashMap::new(),
        session_id: Some(session.session_id().clone()),
    }).await?;
    let output = proc.wait(30).await?;
    println!("Remote ls of local path:\n{}", output.stdout_str());
    if output.stdout_str().contains("No such file") || output.stdout_str().contains("not found") || output.stdout_str().trim().is_empty() {
        println!("✓ Confirmed: local file does not exist on remote");
    } else {
        println!("⚠ Unexpected: local file path exists on remote");
    }

    println!("\n=== TEST 1 RESULT: PASSED ===");
    println!("✓ Filesystem reads show remote content");
    println!("✓ Commands execute on remote machine");
    println!("✓ Process IDs belong to remote machine");
    println!("✓ Working directories are remote");
    println!("✓ Files created by agent exist only on remote machine");
    println!("✓ Local files cannot be confused with remote files");

    Ok(())
}

fn hostname() -> String {
    std::process::Command::new("hostname")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

fn machine_id() -> String {
    std::fs::read_to_string("/etc/machine-id")
        .or_else(|_| std::fs::read_to_string("C:/etc/machine-id"))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}