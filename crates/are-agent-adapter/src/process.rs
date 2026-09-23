//! Process handle for interacting with remote processes.

use super::{AgentAdapterError};
use are_client::SecureClient;
use are_core::{
    EnvironmentId, ProcessId, ProcessState, ProcessStatusRequest, ProcessStatusResponse,
    TerminateProcessRequest, WaitProcessRequest, WaitProcessResponse,
};
use std::sync::Arc;
use tokio::time::{Duration, timeout};

/// Handle to a remote process.
///
/// Provides methods to wait for completion, check status, and terminate.
#[derive(Clone, Debug)]
pub struct ProcessHandle {
    client: Arc<SecureClient>,
    environment_id: EnvironmentId,
    process_id: ProcessId,
    session_id: Option<are_core::SessionId>,
}

impl ProcessHandle {
    /// Create a new process handle.
    pub fn new(
        client: SecureClient,
        environment_id: EnvironmentId,
        process_id: ProcessId,
        session_id: Option<are_core::SessionId>,
    ) -> Self {
        Self {
            client: Arc::new(client),
            environment_id,
            process_id,
            session_id,
        }
    }

    /// Get the process ID.
    pub fn process_id(&self) -> &ProcessId {
        &self.process_id
    }

    /// Get the environment ID.
    pub fn environment_id(&self) -> &EnvironmentId {
        &self.environment_id
    }

    /// Get the session ID (if any).
    pub fn session_id(&self) -> Option<&are_core::SessionId> {
        self.session_id.as_ref()
    }

    /// Wait for the process to exit, up to a timeout.
    ///
    /// Returns the process output (stdout, stderr, exit code).
    pub async fn wait(&self, timeout_secs: u64) -> Result<ProcessOutput, AgentAdapterError> {
        let req = WaitProcessRequest {
            environment_id: self.environment_id.clone(),
            session_id: self.session_id.clone().unwrap_or_else(|| are_core::SessionId::new("")),
            process_id: self.process_id.clone(),
            timeout_secs,
        };
        let resp = self.client.wait_process(req).await?;
        Ok(ProcessOutput::from(resp))
    }

    /// Wait for the process to exit with no timeout (infinite).
    pub async fn wait_infinite(&self) -> Result<ProcessOutput, AgentAdapterError> {
        self.wait(0).await // 0 = no timeout in daemon
    }

    /// Check the current status of the process.
    pub async fn status(&self) -> Result<ProcessStatus, AgentAdapterError> {
        let req = ProcessStatusRequest {
            environment_id: self.environment_id.clone(),
            session_id: self.session_id.clone().unwrap_or_else(|| are_core::SessionId::new("")),
            process_id: self.process_id.clone(),
        };
        let resp = self.client.process_status(req).await?;
        Ok(ProcessStatus::from(resp))
    }

    /// Terminate the process.
    pub async fn terminate(&self) -> Result<bool, AgentAdapterError> {
        let req = TerminateProcessRequest {
            environment_id: self.environment_id.clone(),
            session_id: self.session_id.clone().unwrap_or_else(|| are_core::SessionId::new("")),
            process_id: self.process_id.clone(),
            force: true,
        };
        let resp = self.client.terminate_process(req).await?;
        Ok(resp.terminated)
    }

    /// Wait for the process with a tokio timeout wrapper.
    ///
    /// This adds a client-side timeout on top of the server-side timeout.
    pub async fn wait_with_timeout(&self, client_timeout: Duration) -> Result<ProcessOutput, AgentAdapterError> {
        match timeout(client_timeout, self.wait(0)).await {
            Ok(result) => result,
            Err(_) => Err(AgentAdapterError::Timeout(format!(
                "client-side timeout waiting for process {}",
                self.process_id
            ))),
        }
    }
}

/// Process status snapshot.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum ProcessStatus {
    /// Process is currently running.
    Running,
    /// Process exited with a code.
    Exited { code: i32 },
    /// Process failed (killed by signal, spawn failed, daemon lost track).
    Failed { message: String },
}

impl From<ProcessStatusResponse> for ProcessStatus {
    fn from(resp: ProcessStatusResponse) -> Self {
        match resp.state {
            ProcessState::Running => ProcessStatus::Running,
            ProcessState::Exited { code } => ProcessStatus::Exited { code },
            ProcessState::Failed { message } => ProcessStatus::Failed { message },
        }
    }
}

/// Output from a completed process.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProcessOutput {
    /// Exit code (if exited normally).
    pub exit_code: Option<i32>,
    /// Captured stdout.
    pub stdout: Vec<u8>,
    /// Captured stderr.
    pub stderr: Vec<u8>,
    /// Whether the wait timed out.
    pub timed_out: bool,
    /// Whether output was truncated.
    pub truncated: bool,
}

impl From<WaitProcessResponse> for ProcessOutput {
    fn from(resp: WaitProcessResponse) -> Self {
        Self {
            exit_code: resp.exit_code,
            stdout: resp.stdout,
            stderr: resp.stderr,
            timed_out: resp.timed_out,
            truncated: resp.truncated,
        }
    }
}

impl ProcessOutput {
    /// Check if the process succeeded (exit code 0).
    pub fn success(&self) -> bool {
        self.exit_code == Some(0)
    }

    /// Get stdout as a string (lossy conversion).
    pub fn stdout_str(&self) -> String {
        String::from_utf8_lossy(&self.stdout).to_string()
    }

    /// Get stderr as a string (lossy conversion).
    pub fn stderr_str(&self) -> String {
        String::from_utf8_lossy(&self.stderr).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn process_output_success() {
        let out = ProcessOutput {
            exit_code: Some(0),
            stdout: b"hello".to_vec(),
            stderr: vec![],
            timed_out: false,
            truncated: false,
        };
        assert!(out.success());

        let out = ProcessOutput {
            exit_code: Some(1),
            stdout: vec![],
            stderr: vec![],
            timed_out: false,
            truncated: false,
        };
        assert!(!out.success());
    }
}