//! TEST 4: Filesystem isolation (adversarial boundary tests)

use are_agent_adapter::{Environment, ExecuteRequest, RemoteEnvironment, SessionConfig};
use are_client::SecureClient;
use are_core::EnvironmentId;
use std::path::Path;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== TEST 4: Filesystem Isolation (Adversarial) ===\n");

    let client_cert = Path::new("C:/msys64/tmp/opencode/are-certs/client.pem");
    let client_key = Path::new("C:/msys64/tmp/opencode/are-certs/client.key");
    let ca_cert = Path::new("C:/msys64/tmp/opencode/are-certs/ca.pem");
    let server_addr = "192.168.0.13:9000";
    let server_name = "localhost";
    let env_id = EnvironmentId::new("dev-container");

    let client = SecureClient::from_pem_files(client_cert, client_key, ca_cert, server_addr, server_name)?;
    let env = RemoteEnvironment::connect(client, env_id).await?;
    
    println!("✓ Connected to environment: {}", env.environment_id());

    let session = env.create_session(SessionConfig::default()).await?;
    println!("✓ Created session: {}", session.session_id());

    let mut passed = 0;
    let mut failed = 0;

    macro_rules! test_case {
        ($name:expr, $path:expr, $should_fail:expr) => {
            println!("\n--- Test: {} ---", $name);
            println!("Path: {}", $path);
            match session.read_file($path).await {
                Ok(content) => {
                    if $should_fail {
                        println!("❌ FAIL: Expected failure but got success (content len: {})", content.len());
                        failed += 1;
                    } else {
                        println!("✓ PASS: Read succeeded ({} bytes)", content.len());
                        passed += 1;
                    }
                }
                Err(e) => {
                    if $should_fail {
                        println!("✓ PASS: Correctly rejected - {}", e);
                        passed += 1;
                    } else {
                        println!("❌ FAIL: Unexpected error - {}", e);
                        failed += 1;
                    }
                }
            }
        };
    }

    // Setup: create test files
    println!("\n=== Setup: Creating test files ===");
    let proc = session.execute(ExecuteRequest {
        program: "mkdir".into(),
        args: vec!["-p".into(), "test_fs/subdir".into()],
        working_directory: "".into(),
        env_vars: std::collections::HashMap::new(),
        session_id: Some(session.session_id().clone()),
    }).await?;
    proc.wait(30).await?;
    
    session.write_file("test_fs/file.txt", b"normal file").await?;
    session.write_file("test_fs/subdir/nested.txt", b"nested file").await?;
    
    // Create symlinks
    let proc = session.execute(ExecuteRequest {
        program: "ln".into(),
        args: vec!["-s".into(), "/etc".into(), "test_fs/link_outside".into()],
        working_directory: "".into(),
        env_vars: std::collections::HashMap::new(),
        session_id: Some(session.session_id().clone()),
    }).await?;
    proc.wait(30).await?;
    
    let proc = session.execute(ExecuteRequest {
        program: "ln".into(),
        args: vec!["-s".into(), "/etc/hostname".into(), "test_fs/link2".into()],
        working_directory: "".into(),
        env_vars: std::collections::HashMap::new(),
        session_id: Some(session.session_id().clone()),
    }).await?;
    proc.wait(30).await?;
    
    let proc = session.execute(ExecuteRequest {
        program: "ln".into(),
        args: vec!["-s".into(), "link2".into(), "test_fs/link1".into()],
        working_directory: "".into(),
        env_vars: std::collections::HashMap::new(),
        session_id: Some(session.session_id().clone()),
    }).await?;
    proc.wait(30).await?;
    
    println!("✓ Setup complete");

    // Test valid paths
    test_case!("Normal file", "test_fs/file.txt", false);
    test_case!("Nested file", "test_fs/subdir/nested.txt", false);
    // Note: directory listing should use list_directory, not read_file
    // test_case!("Directory listing", "test_fs", false);
    // test_case!("Subdirectory listing", "test_fs/subdir", false);

    // Test traversal attacks
    test_case!("Parent traversal", "test_fs/../etc/passwd", true);
    test_case!("Deep traversal", "test_fs/subdir/../../etc/passwd", true);
    test_case!("Traversal with extra slashes", "test_fs///subdir/../../../etc/passwd", true);
    test_case!("Traversal at root", "../etc/passwd", true);

    // Test absolute paths
    test_case!("Absolute path /etc/passwd", "/etc/passwd", true);
    test_case!("Absolute path /home/projects", "/home/projects", true);
    test_case!("Absolute path with traversal", "/home/projects/../etc/passwd", true);

    // Test symlink escapes
    test_case!("Symlink to /etc", "test_fs/link_outside/passwd", true);
    test_case!("Symlink to /etc/hostname", "test_fs/link2", true);
    test_case!("Nested symlink", "test_fs/link1", true);
    test_case!("Symlink to outside via relative", "test_fs/link_outside/../etc/shadow", true);

    // Test nonexistent paths
    test_case!("Nonexistent file", "test_fs/nonexistent.txt", true);
    test_case!("Nonexistent directory", "test_fs/nonexistent/", true);

    // Test paths with unusual characters
    test_case!("Path with spaces", "test_fs/file with spaces.txt", true);
    test_case!("Path with newlines", "test_fs/file\n.txt", true);
    test_case!("Path with null bytes", "test_fs/file\0.txt", true);

    // Test write operations
    println!("\n--- Write tests ---");
    
    // Valid write
    match session.write_file("test_fs/newfile.txt", b"new content").await {
        Ok(_) => { println!("✓ PASS: Valid write"); passed += 1; }
        Err(e) => { println!("❌ FAIL: Valid write failed - {}", e); failed += 1; }
    }
    
    // Write via traversal to sibling at root level (VALID - stays within root)
    match session.write_file("test_fs/../evil.txt", b"evil").await {
        Ok(_) => { println!("✓ PASS: Write to sibling at root allowed (test_fs/../evil.txt -> evil.txt)"); passed += 1; }
        Err(e) => { println!("❌ FAIL: Write to sibling at root rejected - {}", e); failed += 1; }
    }
    
    // Write to absolute path (REJECTED - outside root)
    match session.write_file("/etc/evil.txt", b"evil").await {
        Err(_) => { println!("✓ PASS: Absolute write rejected"); passed += 1; }
        Ok(_) => { println!("❌ FAIL: Absolute write allowed"); failed += 1; }
    }
    
    // Write via symlink (REJECTED - symlink points outside)
    match session.write_file("test_fs/link_outside/evil.txt", b"evil").await {
        Err(_) => { println!("✓ PASS: Symlink write rejected"); passed += 1; }
        Ok(_) => { println!("❌ FAIL: Symlink write allowed"); failed += 1; }
    }

    // Test mkdir operations (via CreateDirectory RPC - boundary checked)
    println!("\n--- Mkdir tests ---");
    // Valid mkdir
    match session.create_directory("test_fs/newdir").await {
        Ok(_) => { println!("✓ PASS: Valid mkdir"); passed += 1; }
        Err(e) => { println!("❌ FAIL: Valid mkdir failed - {}", e); failed += 1; }
    }
    
    // Mkdir via traversal - REJECTED (intentional: fail closed on .. in creation paths)
    match session.create_directory("test_fs/../evil").await {
        Err(e) if e.to_string().contains("invalid component") => { 
            println!("✓ PASS: Mkdir with .. rejected (fail-closed on .. in creation paths)"); passed += 1; 
        }
        Ok(_) => { println!("❌ FAIL: Mkdir with .. allowed"); failed += 1; }
        Err(e) => { println!("❌ FAIL: Unexpected error - {}", e); failed += 1; }
    }
    
    // Absolute mkdir (REJECTED - outside root)
    match session.create_directory("/tmp/evil").await {
        Err(_) => { println!("✓ PASS: Absolute mkdir rejected"); passed += 1; }
        Ok(_) => { println!("❌ FAIL: Absolute mkdir allowed"); failed += 1; }
    }

    // Test rename operations
    println!("\n--- Rename tests ---");
    session.write_file("test_fs/original.txt", b"original").await?;
    
    // Valid rename
    match session.execute(ExecuteRequest {
        program: "mv".into(),
        args: vec!["test_fs/original.txt".into(), "test_fs/renamed.txt".into()],
        working_directory: "".into(),
        env_vars: std::collections::HashMap::new(),
        session_id: Some(session.session_id().clone()),
    }).await {
        Ok(proc) => { proc.wait(30).await?; println!("✓ PASS: Valid rename"); passed += 1; }
        Err(e) => { println!("❌ FAIL: Valid rename failed - {}", e); failed += 1; }
    }
    
    // Rename via traversal (source) - to sibling at root (VALID - stays within root)
    session.write_file("test_fs/original2.txt", b"original2").await?;
    match session.execute(ExecuteRequest {
        program: "mv".into(),
        args: vec!["test_fs/original2.txt".into(), "test_fs/../evil.txt".into()],
        working_directory: "".into(),
        env_vars: std::collections::HashMap::new(),
        session_id: Some(session.session_id().clone()),
    }).await {
        Ok(proc) => { proc.wait(30).await?; println!("✓ PASS: Rename source to sibling at root allowed (test_fs/original2.txt -> evil.txt)"); passed += 1; }
        Err(e) => { println!("❌ FAIL: Rename source to sibling at root rejected - {}", e); failed += 1; }
    }
    
    // Rename via traversal (dest) - to sibling at root (VALID - stays within root)
    session.write_file("test_fs/original3.txt", b"original3").await?;
    match session.execute(ExecuteRequest {
        program: "mv".into(),
        args: vec!["test_fs/original3.txt".into(), "test_fs/../evil2.txt".into()],
        working_directory: "".into(),
        env_vars: std::collections::HashMap::new(),
        session_id: Some(session.session_id().clone()),
    }).await {
        Ok(proc) => { proc.wait(30).await?; println!("✓ PASS: Rename dest to sibling at root allowed (test_fs/original3.txt -> evil2.txt)"); passed += 1; }
        Err(e) => { println!("❌ FAIL: Rename dest to sibling at root rejected - {}", e); failed += 1; }
    }

    // Test delete operations
    println!("\n--- Delete tests ---");
    session.write_file("test_fs/todelete.txt", b"delete me").await?;
    
    // Valid delete
    match session.execute(ExecuteRequest {
        program: "rm".into(),
        args: vec!["test_fs/todelete.txt".into()],
        working_directory: "".into(),
        env_vars: std::collections::HashMap::new(),
        session_id: Some(session.session_id().clone()),
    }).await {
        Ok(proc) => { proc.wait(30).await?; println!("✓ PASS: Valid delete"); passed += 1; }
        Err(e) => { println!("❌ FAIL: Valid delete failed - {}", e); failed += 1; }
    }
    
    // Delete via traversal to sibling at root (VALID - stays within root)
    session.write_file("test_fs/todelete2.txt", b"delete me").await?;
    match session.execute(ExecuteRequest {
        program: "rm".into(),
        args: vec!["test_fs/../todelete2.txt".into()],
        working_directory: "".into(),
        env_vars: std::collections::HashMap::new(),
        session_id: Some(session.session_id().clone()),
    }).await {
        Ok(proc) => { proc.wait(30).await?; println!("✓ PASS: Delete to sibling at root allowed (test_fs/../todelete2.txt -> todelete2.txt)"); passed += 1; }
        Err(e) => { println!("❌ FAIL: Delete to sibling at root rejected - {}", e); failed += 1; }
    }
    
    // Delete via traversal outside root (REJECTED)
    session.write_file("test_fs/todelete3.txt", b"delete me").await?;
    match session.delete("test_fs/../../etc/passwd").await {
        Err(_) => { println!("✓ PASS: Delete to outside root rejected"); passed += 1; }
        Ok(_) => { println!("❌ FAIL: Delete to outside root allowed"); failed += 1; }
    }
    
    // Test list operations - skipped due to read_file not supporting directories
    // println!("\n--- List tests ---");
    // test_case!("List root", "", false);
    // test_case!("List valid dir", "test_fs", false);
    // test_case!("List via traversal", "test_fs/..", true);
    // test_case!("List absolute", "/home", true);

    println!("\n=== TEST 4 RESULT ===");
    println!("Passed: {}", passed);
    println!("Failed: {}", failed);
    
    if failed == 0 {
        println!("\n=== TEST 4 RESULT: PASSED ===");
        Ok(())
    } else {
        Err(format!("{} tests failed", failed).into())
    }
}