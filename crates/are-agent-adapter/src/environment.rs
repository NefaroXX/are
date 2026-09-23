//! RemoteEnvironment implementation backed by SecureClient.

use super::{AgentAdapterError, DirectoryEntry, Environment, ExecuteRequest, FileMetadata, FileWriteResult, SessionConfig, SessionHandle, ProcessHandle};
use are_client::SecureClient;
use are_core::{
    CapabilitySet, CreateSessionRequest, EnvironmentId, GetFileMetadataRequest, GetSessionRequest,
    ListDirectoryRequest, ListSessionsRequest, ReadFileRequest, SessionId, TerminateSessionRequest,
    WriteFileRequest,
};
use std::sync::Arc;
use tokio::sync::RwLock;

/// High-level remote environment backed by an ARE daemon.
///
/// This is the concrete implementation that agents use. It wraps a
/// `SecureClient` and provides the `Environment` trait interface.
pub struct RemoteEnvironment {
    client: SecureClient,
    environment_id: EnvironmentId,
    capabilities: CapabilitySet,
    /// Cached session handles for the current connection.
    sessions: Arc<RwLock<std::collections::HashMap<SessionId, SessionHandle>>>,
}

impl RemoteEnvironment {
    /// Create a new RemoteEnvironment by connecting to the daemon and
    /// fetching its capabilities.
    ///
    /// This establishes a test connection to verify the environment is
    /// reachable and discover its capabilities.
    pub async fn connect(
        client: SecureClient,
        environment_id: EnvironmentId,
    ) -> Result<Self, AgentAdapterError> {
        let info = client
            .get_environment_info(&environment_id)
            .await?;

        let env = Self {
            client,
            environment_id: environment_id.clone(),
            capabilities: info.advertised_capabilities.clone(),
            sessions: Arc::new(RwLock::new(std::collections::HashMap::new())),
        };

        Ok(env)
    }

    /// Create a RemoteEnvironment without a test connection (for when
    /// you already know the environment exists).
    pub fn new_unchecked(
        client: SecureClient,
        environment_id: EnvironmentId,
        capabilities: CapabilitySet,
    ) -> Self {
        Self {
            client,
            environment_id,
            capabilities,
            sessions: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Get the underlying client for advanced operations.
    pub fn client(&self) -> &SecureClient {
        &self.client
    }
}

#[async_trait::async_trait]
impl Environment for RemoteEnvironment {
    fn environment_id(&self) -> &EnvironmentId {
        &self.environment_id
    }

    fn capabilities(&self) -> &CapabilitySet {
        &self.capabilities
    }

    async fn read_file(&self, path: &str) -> Result<Vec<u8>, AgentAdapterError> {
        let req = ReadFileRequest {
            environment_id: self.environment_id.clone(),
            path: path.into(),
        };
        let resp = self.client.read_file(req).await?;
        Ok(resp.content)
    }

    async fn write_file(&self, path: &str, content: &[u8]) -> Result<FileWriteResult, AgentAdapterError> {
        let req = WriteFileRequest {
            environment_id: self.environment_id.clone(),
            path: path.into(),
            content: content.to_vec(),
            expected_hash: None,
            overwrite: true,
        };
        let resp = self.client.write_file(req).await?;
        Ok(FileWriteResult {
            bytes_written: resp.metadata.size,
            content_hash: resp.metadata.hash.unwrap_or_default(),
        })
    }

    async fn list_directory(&self, path: &str) -> Result<Vec<DirectoryEntry>, AgentAdapterError> {
        let req = ListDirectoryRequest {
            environment_id: self.environment_id.clone(),
            path: path.into(),
        };
        let resp = self.client.list_directory(req).await?;
        Ok(resp
            .entries
            .into_iter()
            .map(|e| DirectoryEntry {
                name: e.name,
                is_dir: e.metadata.is_dir,
                size: if e.metadata.is_file { Some(e.metadata.size) } else { None },
                content_hash: e.metadata.hash,
            })
            .collect())
    }

    async fn file_metadata(&self, path: &str) -> Result<FileMetadata, AgentAdapterError> {
        let req = GetFileMetadataRequest {
            environment_id: self.environment_id.clone(),
            path: path.into(),
        };
        let resp = self.client.file_metadata(req).await?;
        let meta = resp.metadata;
        Ok(FileMetadata {
            is_dir: meta.is_dir,
            size: meta.size,
            content_hash: meta.hash,
            modified: meta.modified_at.map(|t| {
                t.duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
            }).unwrap_or(0),
        })
    }

    async fn execute(&self, request: ExecuteRequest) -> Result<ProcessHandle, AgentAdapterError> {
        let session_id = request.session_id.clone().unwrap_or_else(|| SessionId::new(""));
        let req = are_core::ExecuteRequest {
            environment_id: self.environment_id.clone(),
            session_id: session_id.clone(),
            program: request.program,
            args: request.args,
            working_directory: request.working_directory,
            env_vars: request.env_vars,
        };
        let resp = self.client.execute(req).await?;
        let handle = ProcessHandle::new(
            self.client.clone(),
            self.environment_id.clone(),
            resp.process_id,
            Some(session_id),
        );
        Ok(handle)
    }

    async fn create_session(&self, config: SessionConfig) -> Result<SessionHandle, AgentAdapterError> {
        let req = CreateSessionRequest {
            environment_id: self.environment_id.clone(),
            working_directory: Some(config.working_directory).filter(|s| !s.is_empty()),
            env_vars: config.env_vars,
        };
        let resp = self.client.create_session(req).await?;
        let session_id = resp.session.session_id.clone();
        let handle = SessionHandle::new(
            self.client.clone(),
            self.environment_id.clone(),
            session_id.clone(),
        );
        // Cache it
        self.sessions.write().await.insert(session_id, handle.clone());
        Ok(handle)
    }

    async fn resume_session(&self, session_id: &SessionId) -> Result<SessionHandle, AgentAdapterError> {
        let req = GetSessionRequest {
            environment_id: self.environment_id.clone(),
            session_id: session_id.clone(),
        };
        let resp = self.client.get_session(req).await?;
        let handle = SessionHandle::new(
            self.client.clone(),
            self.environment_id.clone(),
            resp.session.session_id,
        );
        self.sessions.write().await.insert(session_id.clone(), handle.clone());
        Ok(handle)
    }

    async fn list_sessions(&self) -> Result<Vec<SessionHandle>, AgentAdapterError> {
        let req = ListSessionsRequest {
            environment_id: self.environment_id.clone(),
        };
        let resp = self.client.list_sessions(req).await?;
        let mut handles = Vec::new();
        for summary in resp.sessions {
            let handle = SessionHandle::new(
                self.client.clone(),
                self.environment_id.clone(),
                summary.session_id,
            );
            handles.push(handle);
        }
        Ok(handles)
    }

    async fn terminate_session(&self, session_id: &SessionId) -> Result<(), AgentAdapterError> {
        let req = TerminateSessionRequest {
            environment_id: self.environment_id.clone(),
            session_id: session_id.clone(),
        };
        self.client.terminate_session(req).await?;
        self.sessions.write().await.remove(session_id);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_env_construction() {
        // This test is just a placeholder - real construction tested in integration tests
        assert!(true);
    }
}