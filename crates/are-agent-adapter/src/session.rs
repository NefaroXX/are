//! Session handle for interacting with a specific session.

use super::{AgentAdapterError, DirectoryEntry, ExecuteRequest, FileMetadata, FileWriteResult, ProcessHandle};
use are_client::SecureClient;
use are_core::{
    CreateDirectoryRequest, DeleteRequest, EnvironmentId, GetFileMetadataRequest,
    ListDirectoryRequest, ReadFileRequest, RenameRequest, SessionId, WriteFileRequest,
};
use std::sync::Arc;

/// Handle to a specific session in an environment.
///
/// A session encapsulates:
/// - Working directory
/// - Environment variables
/// - Process tree
///
/// Operations on a session use the session's working directory and
/// environment by default.
#[derive(Clone, Debug)]
pub struct SessionHandle {
    client: Arc<SecureClient>,
    environment_id: EnvironmentId,
    session_id: SessionId,
}

impl SessionHandle {
    /// Create a new session handle.
    pub fn new(
        client: SecureClient,
        environment_id: EnvironmentId,
        session_id: SessionId,
    ) -> Self {
        Self {
            client: Arc::new(client),
            environment_id,
            session_id,
        }
    }

    /// Get the session ID.
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Get the environment ID.
    pub fn environment_id(&self) -> &EnvironmentId {
        &self.environment_id
    }

    /// Read a file relative to this session's working directory.
    pub async fn read_file(&self, path: &str) -> Result<Vec<u8>, AgentAdapterError> {
        let req = ReadFileRequest {
            environment_id: self.environment_id.clone(),
            path: path.into(),
        };
        let resp = self.client.read_file(req).await?;
        Ok(resp.content)
    }

    /// Write a file relative to this session's working directory.
    pub async fn write_file(&self, path: &str, content: &[u8]) -> Result<FileWriteResult, AgentAdapterError> {
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

    /// List a directory relative to this session's working directory.
    pub async fn list_directory(&self, path: &str) -> Result<Vec<DirectoryEntry>, AgentAdapterError> {
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

    /// Get metadata about a file or directory.
    pub async fn file_metadata(&self, path: &str) -> Result<FileMetadata, AgentAdapterError> {
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

    /// Create a directory (and missing ancestors).
    pub async fn create_directory(&self, path: &str) -> Result<(), AgentAdapterError> {
        let req = CreateDirectoryRequest {
            environment_id: self.environment_id.clone(),
            path: path.into(),
        };
        self.client.create_directory(req).await?;
        Ok(())
    }

    /// Rename (move) a file or directory.
    pub async fn rename(&self, src: &str, dst: &str) -> Result<(), AgentAdapterError> {
        let req = RenameRequest {
            environment_id: self.environment_id.clone(),
            src: src.into(),
            dst: dst.into(),
        };
        self.client.rename(req).await?;
        Ok(())
    }

    /// Delete a file or empty directory.
    pub async fn delete(&self, path: &str) -> Result<(), AgentAdapterError> {
        let req = DeleteRequest {
            environment_id: self.environment_id.clone(),
            path: path.into(),
        };
        self.client.delete_file(req).await?;
        Ok(())
    }

    /// Execute a program in this session.
    pub async fn execute(&self, request: ExecuteRequest) -> Result<ProcessHandle, AgentAdapterError> {
        let req = are_core::ExecuteRequest {
            environment_id: self.environment_id.clone(),
            session_id: self.session_id.clone(),
            program: request.program,
            args: request.args,
            working_directory: request.working_directory,
            env_vars: request.env_vars,
        };
        let resp = self.client.execute(req).await?;
        Ok(ProcessHandle::new(
            (*self.client).clone(),
            self.environment_id.clone(),
            resp.process_id,
            Some(self.session_id.clone()),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn session_handle_clone() {
        // Just verify it's Clone (can't easily construct without client)
        fn assert_clone<T: Clone>() {}
        assert_clone::<SessionHandle>();
    }
}