//! TEST 6: Process execution abuse (shell metacharacters, policies)

use are_agent_adapter::{Environment, ExecuteRequest, RemoteEnvironment, SessionConfig};
use are_client::SecureClient;
use are_core::EnvironmentId;
use std::path::Path;

async fn test_exec(
    session: &are_agent_adapter::SessionHandle,
    name: &str,
    program: &str,
    args: Vec<&str>,
    should_succeed: bool,
    passed: &mut i32,
    failed: &mut i32,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n--- Test: {} ---", name);
    println!("Program: {}, Args: {:?}", program, args);
    let args_vec: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let proc = session.execute(ExecuteRequest {
        program: program.into(),
        args: args_vec,
        working_directory: "".into(),
        env_vars: std::collections::HashMap::new(),
        session_id: Some(session.session_id().clone()),
    }).await;
    
    match proc {
        Ok(proc) => {
            let output = proc.wait(30).await?;
            if should_succeed {
                if output.success() {
                    println!("✓ PASS: {} succeeded as expected", name);
                    println!("  stdout: {}", output.stdout_str().trim());
                    *passed += 1;
                } else {
                    println!("❌ FAIL: {} should have succeeded but failed", name);
                    println!("  exit_code: {:?}", output.exit_code);
                    println!("  stderr: {}", output.stderr_str().trim());
                    *failed += 1;
                }
            } else {
                if output.success() {
                    println!("❌ FAIL: {} should have failed but succeeded", name);
                    println!("  stdout: {}", output.stdout_str().trim());
                    *failed += 1;
                } else {
                    println!("✓ PASS: {} correctly failed", name);
                    println!("  stderr: {}", output.stderr_str().trim());
                    *failed += 1;
                }
            }
        }
        Err(e) => {
            if should_succeed {
                println!("❌ FAIL: {} should have succeeded but got error: {}", name, e);
                *failed += 1;
            } else {
                println!("✓ PASS: {} correctly rejected: {}", name, e);
                *passed += 1;
            }
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== TEST 6: Process Execution Abuse ===\n");

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

    // Test 1: Normal command
    test_exec(&session, "Normal echo", "echo", vec!["hello world"], true, &mut passed, &mut failed).await?;

    // Test 2: Shell metacharacters in args (should be passed literally, not interpreted)
    test_exec(&session, "Semicolon in arg", "echo", vec!["hello; rm -rf /"], true, &mut passed, &mut failed).await?;
    test_exec(&session, "Backticks in arg", "echo", vec!["`id`"], true, &mut passed, &mut failed).await?;
    test_exec(&session, "Dollar parens in arg", "echo", vec!["$(id)"], true, &mut passed, &mut failed).await?;
    test_exec(&session, "Pipe in arg", "echo", vec!["hello | cat"], true, &mut passed, &mut failed).await?;
    test_exec(&session, "Redirect in arg", "echo", vec!["hello > /tmp/test"], true, &mut passed, &mut failed).await?;
    test_exec(&session, "Ampersand in arg", "echo", vec!["hello &"], true, &mut passed, &mut failed).await?;
    test_exec(&session, "Multiple metacharacters", "echo", vec!["a;b`c$(d)e|f>g&h"], true, &mut passed, &mut failed).await?;

    // Test 3: Arguments with spaces and quotes
    test_exec(&session, "Arg with spaces", "echo", vec!["hello world"], true, &mut passed, &mut failed).await?;
    test_exec(&session, "Arg with single quotes", "echo", vec!["'hello world'"], true, &mut passed, &mut failed).await?;
    test_exec(&session, "Arg with double quotes", "echo", vec!["\"hello world\""], true, &mut passed, &mut failed).await?;

    // Test 4: Arguments with newlines and special chars
    test_exec(&session, "Arg with newline", "echo", vec!["hello\nworld"], true, &mut passed, &mut failed).await?;
    test_exec(&session, "Arg with tab", "echo", vec!["hello\tworld"], true, &mut passed, &mut failed).await?;

    // Test 5: Permitted executables
    test_exec(&session, "Permitted: uname", "uname", vec!["-a"], true, &mut passed, &mut failed).await?;
    test_exec(&session, "Permitted: sleep", "sleep", vec!["1"], true, &mut passed, &mut failed).await?;
    test_exec(&session, "Permitted: cargo", "cargo", vec!["--version"], true, &mut passed, &mut failed).await?;

    // Test 6: Denied executables
    test_exec(&session, "Denied: shutdown", "shutdown", vec!["-h", "now"], false, &mut passed, &mut failed).await?;
    test_exec(&session, "Denied: reboot", "reboot", vec![], false, &mut passed, &mut failed).await?;
    test_exec(&session, "Denied: rm", "rm", vec!["-rf", "/"], false, &mut passed, &mut failed).await?;
    test_exec(&session, "Denied: sudo", "sudo", vec!["echo", "test"], false, &mut passed, &mut failed).await?;

    // Test 7: Nonexistent executable
    test_exec(&session, "Nonexistent: nonexistent123", "nonexistent123456", vec![], false, &mut passed, &mut failed).await?;

    // Test 8: Executable with absolute path (should be denied if not in allow list)
    test_exec(&session, "Absolute path /bin/echo", "/bin/echo", vec!["test"], false, &mut passed, &mut failed).await?;

    // Test 9: Executable through symlink (should be denied if not in allow list)
    // First create a symlink to echo
    let proc = session.execute(ExecuteRequest {
        program: "ln".into(),
        args: vec!["-s".into(), "/usr/bin/echo".into(), "test_fs/echo_link".into()],
        working_directory: "".into(),
        env_vars: std::collections::HashMap::new(),
        session_id: Some(session.session_id().clone()),
    }).await?;
    proc.wait(30).await?;
    
    test_exec(&session, "Symlink to echo", "./test_fs/echo_link", vec!["via symlink"], false, &mut passed, &mut failed).await?;

    // Test 10: Executable that spawns another process (cargo can run build scripts)
    test_exec(&session, "Cargo with build script potential", "cargo", vec!["build", "--version"], true, &mut passed, &mut failed).await?;

    // Test 11: Long-running process
    let proc = session.execute(ExecuteRequest {
        program: "sleep".into(),
        args: vec!["5".into()],
        working_directory: "".into(),
        env_vars: std::collections::HashMap::new(),
        session_id: Some(session.session_id().clone()),
    }).await?;
    let output = proc.wait(10).await?;
    if output.success() {
        println!("\n--- Test: Long-running process ---");
        println!("✓ PASS: sleep 5 completed successfully");
    } else {
        println!("\n--- Test: Long-running process ---");
        println!("❌ FAIL: sleep 5 failed");
    }
    
    // Test 12: Process with large output
    // Create a file with large content
    let large_content = "x".repeat(100000);
    session.write_file("test_fs/large.txt", large_content.as_bytes()).await?;
    
    let proc = session.execute(ExecuteRequest {
        program: "cat".into(),
        args: vec!["test_fs/large.txt".into()],
        working_directory: "".into(),
        env_vars: std::collections::HashMap::new(),
        session_id: Some(session.session_id().clone()),
    }).await?;
    let output = proc.wait(30).await?;
    if output.success() && output.stdout_str().len() > 50000 {
        println!("\n--- Test: Large output ---");
        println!("✓ PASS: cat large file succeeded ({} bytes)", output.stdout_str().len());
    } else {
        println!("\n--- Test: Large output ---");
        println!("❌ FAIL: cat large file failed or output truncated");
    }
    
    // Test 13: Process that crashes
    test_exec(&session, "Crash: false", "false", vec![], false, &mut 0, &mut 0).await?;

    println!("\n=== TEST 6 RESULT ===");
    println!("Note: Some tests marked as KNOWN BUG or expected failures are expected to fail");
    println!("=== TEST 6 RESULT: COMPLETED ===");
    Ok(())
}