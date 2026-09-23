//! TEST 5: Authorization / capabilities enforcement

use are_agent_adapter::{Environment, ExecuteRequest, RemoteEnvironment, SessionConfig, SessionHandle};
use are_client::SecureClient;
use are_core::EnvironmentId;
use std::path::Path;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== TEST 5: Authorization / Capabilities Enforcement ===\n");

    // Principal A (full access): blake3:07527f8e31ff995bfcbab53ddef15486637b8ee5524942bc4319276de1ce7a30
    let client_cert_a = Path::new("C:/msys64/tmp/opencode/are-certs/client.pem");
    let client_key_a = Path::new("C:/msys64/tmp/opencode/are-certs/client.key");
    
    // Principal B (logs only): blake3:ce3e4e730fb37b16a8fc39bbbfdb2fd0888616b22d1b1cceb56f7e05a7f78ad1
    let client_cert_b = Path::new("C:/msys64/tmp/opencode/are-certs/client-b.pem");
    let client_key_b = Path::new("C:/msys64/tmp/opencode/are-certs/client-b.key");
    
    // Principal C (unknown): blake3:6e0249dd4e09d0f5d811783b4fb8ef81b6fa2f3f148a4ee54d3804e9816123f1
    let client_cert_c = Path::new("C:/msys64/tmp/opencode/are-certs/client-c.pem");
    let client_key_c = Path::new("C:/msys64/tmp/opencode/are-certs/client-c.key");
    
    let ca_cert = Path::new("C:/msys64/tmp/opencode/are-certs/ca.pem");
    let server_addr = "192.168.0.13:9000";
    let server_name = "localhost";
    let env_id = EnvironmentId::new("dev-container");

    let mut all_passed = true;

    macro_rules! test_principal {
        ($name:expr, $cert:expr, $key:expr, $test_fn:expr) => {{
            println!("\n=== Testing Principal: {} ===", $name);
            let client = SecureClient::from_pem_files($cert, $key, ca_cert, server_addr, server_name)?;
            let env = RemoteEnvironment::connect(client, env_id.clone()).await?;
            let session = env.create_session(SessionConfig::default()).await?;
            println!("✓ Created session: {}", session.session_id());
            
            let result = $test_fn(session).await;
            match result {
                Ok(()) => println!("✓ {} tests passed", $name),
                Err(e) => { println!("❌ {} tests failed: {}", $name, e); all_passed = false; }
            }
        }}
    }

    // Test Principal A (full access)
    test_principal!("Principal A (full)", client_cert_a, client_key_a, |session: SessionHandle| async move {
        // Should be able to read anywhere
        session.read_file("test_fs/file.txt").await?;
        println!("✓ Can read test_fs/file.txt");
        
        session.read_file("logs/app.log").await?;
        println!("✓ Can read logs/app.log");
        
        // Should be able to write anywhere
        session.write_file("test_fs/principal_a_write.txt", b"from A").await?;
        println!("✓ Can write test_fs/principal_a_write.txt");
        
        session.write_file("logs/principal_a_log.txt", b"log from A").await?;
        println!("✓ Can write logs/principal_a_log.txt");
        
        // Should be able to list anywhere
        session.list_directory("test_fs").await?;
        println!("✓ Can list test_fs");
        
        session.list_directory("logs").await?;
        println!("✓ Can list logs");
        
        // Should be able to execute permitted programs
        let proc = session.execute(ExecuteRequest {
            program: "echo".into(),
            args: vec!["hello from A".into()],
            working_directory: "".into(),
            env_vars: std::collections::HashMap::new(),
            session_id: Some(session.session_id().clone()),
        }).await?;
        let output = proc.wait(30).await?;
        if output.stdout_str().contains("hello from A") {
            println!("✓ Can execute echo");
        } else {
            return Err::<(), Box<dyn std::error::Error>>("echo output mismatch".into());
        }
        
        let proc = session.execute(ExecuteRequest {
            program: "cargo".into(),
            args: vec!["--version".into()],
            working_directory: "".into(),
            env_vars: std::collections::HashMap::new(),
            session_id: Some(session.session_id().clone()),
        }).await?;
        let output = proc.wait(60).await?;
        if output.stdout_str().contains("cargo") {
            println!("✓ Can execute cargo");
        } else {
            return Err("cargo output mismatch".into());
        }
        
        Ok(())
    });

    // Test Principal B (logs only)
    test_principal!("Principal B (logs only)", client_cert_b, client_key_b, |session: SessionHandle| async move {
        // Should be able to read logs
        session.read_file("logs/app.log").await?;
        println!("✓ Can read logs/app.log");
        
        // Should be able to list logs
        session.list_directory("logs").await?;
        println!("✓ Can list logs");
        
        // Should NOT be able to read outside logs
        match session.read_file("test_fs/file.txt").await {
            Err(e) if e.to_string().contains("forbidden") || e.to_string().contains("denied") => {
                println!("✓ Correctly denied read test_fs/file.txt: {}", e);
            }
            Ok(_) => return Err::<(), Box<dyn std::error::Error>>("Should have been denied read access to test_fs/file.txt".into()),
            Err(e) => return Err(format!("Unexpected error: {}", e).into()),
        }
        
        // Should NOT be able to write anywhere
        match session.write_file("logs/principal_b_write.txt", b"from B").await {
            Err(e) if e.to_string().contains("forbidden") || e.to_string().contains("denied") => {
                println!("✓ Correctly denied write logs/principal_b_write.txt: {}", e);
            }
            Ok(_) => return Err::<(), Box<dyn std::error::Error>>("Should have been denied write access to logs".into()),
            Err(e) => return Err(format!("Unexpected error: {}", e).into()),
        }
        
        match session.write_file("test_fs/principal_b_write.txt", b"from B").await {
            Err(e) if e.to_string().contains("forbidden") || e.to_string().contains("denied") => {
                println!("✓ Correctly denied write test_fs/principal_b_write.txt: {}", e);
            }
            Ok(_) => return Err::<(), Box<dyn std::error::Error>>("Should have been denied write access to test_fs".into()),
            Err(e) => return Err(format!("Unexpected error: {}", e).into()),
        }
        
        // Should NOT be able to list outside logs
        match session.list_directory("test_fs").await {
            Err(e) if e.to_string().contains("forbidden") || e.to_string().contains("denied") => {
                println!("✓ Correctly denied list test_fs: {}", e);
            }
            Ok(_) => return Err::<(), Box<dyn std::error::Error>>("Should have been denied list access to test_fs".into()),
            Err(e) => return Err(format!("Unexpected error: {}", e).into()),
        }
        
        // Should NOT be able to execute
        match session.execute(ExecuteRequest {
            program: "echo".into(),
            args: vec!["hello from B".into()],
            working_directory: "".into(),
            env_vars: std::collections::HashMap::new(),
            session_id: None,
        }).await {
            Err(e) if e.to_string().contains("forbidden") || e.to_string().contains("denied") => {
                println!("✓ Correctly denied execute echo: {}", e);
            }
            Ok(proc) => {
                proc.wait(30).await?;
                return Err::<(), Box<dyn std::error::Error>>("Should have been denied execute access".into());
            }
            Err(e) => return Err(format!("Unexpected error: {}", e).into()),
        }
        
        Ok(())
    });

    // Test Principal C (unknown - no grants)
    println!("\n=== Testing Principal: Principal C (unknown) ===");
    let client_c = SecureClient::from_pem_files(client_cert_c, client_key_c, ca_cert, server_addr, server_name)?;
    let env_c = RemoteEnvironment::connect(client_c, env_id.clone()).await?;
    
    // Unknown principal CAN get environment info (only permitted operation)
    let info = env_c.client().get_environment_info(&env_id).await?;
    println!("✓ Unknown principal can get environment info");
    println!("  Capabilities advertised: {:?}", info.advertised_capabilities);
    
    // Should NOT be able to create session
    let temp_session = env_c.create_session(SessionConfig::default()).await;
    if temp_session.is_err() {
        println!("✓ Correctly denied session creation: {:?}", temp_session.err());
    } else {
        return Err::<(), Box<dyn std::error::Error>>("Should have been denied session creation".into());
    }
    
    // Should NOT be able to create session (any session operation)
    // The connection itself succeeds but operations are forbidden
    let session_c = env_c.create_session(SessionConfig::default()).await;
    if session_c.is_err() {
        println!("✓ Correctly denied session creation (second attempt)");
    } else {
        return Err::<(), Box<dyn std::error::Error>>("Should have been denied session creation".into());
    }
    
    println!("✓ Principal C (unknown) tests passed");

    println!("\n=== TEST 5 RESULT ===");
    if all_passed {
        println!("=== TEST 5 RESULT: PASSED ===");
        Ok(())
    } else {
        Err("Some authorization tests failed".into())
    }
}