//! Request dispatch and handler for the daemon.
//!
//! Handles `RpcRequest` variants and returns `RpcResponse` values.
//! Gate 3 only handles `GetEnvironmentInfo` — all other request types
//! return `RpcError::UnknownRequestType`.

use are_core::{
    CapabilitySet, EnvironmentId, GetEnvironmentInfoRequest, GetEnvironmentInfoResponse, Platform,
    RpcError, RpcRequest, RpcResponse, RpcResponsePayload,
};

/// Daemon state needed to handle requests.
#[derive(Debug, Clone)]
pub struct DaemonState {
    /// The environment this daemon serves.
    pub environment_id: EnvironmentId,
    /// Machine hostname.
    pub machine_name: String,
    /// Daemon version string.
    pub daemon_version: String,
    /// Operations this environment advertises as available.
    ///
    /// This is NOT per-client authorization — all clients see the same set.
    /// Per-client capability enforcement arrives in Gate 8.
    pub advertised_capabilities: CapabilitySet,
    /// Platform type.
    pub platform: Platform,
}

impl DaemonState {
    /// Create a new `DaemonState` with the given configuration.
    pub fn new(
        environment_id: EnvironmentId,
        machine_name: String,
        daemon_version: String,
        advertised_capabilities: CapabilitySet,
        platform: Platform,
    ) -> Self {
        Self {
            environment_id,
            machine_name,
            daemon_version,
            advertised_capabilities,
            platform,
        }
    }

    /// Handle an RPC request and return a response.
    pub fn handle(&self, request: RpcRequest) -> RpcResponse {
        match request {
            RpcRequest::GetEnvironmentInfo(req) => {
                let result = self.handle_get_environment_info(req);
                RpcResponse {
                    result: result.map(RpcResponsePayload::GetEnvironmentInfo),
                }
            }
        }
    }

    fn handle_get_environment_info(
        &self,
        req: GetEnvironmentInfoRequest,
    ) -> Result<GetEnvironmentInfoResponse, RpcError> {
        // Validate that the requested environment matches this daemon's env.
        if req.environment_id != self.environment_id {
            return Err(RpcError::InvalidRequest(format!(
                "requested environment '{}' does not match daemon environment '{}'",
                req.environment_id, self.environment_id
            )));
        }

        Ok(GetEnvironmentInfoResponse {
            environment_id: self.environment_id.clone(),
            machine_name: self.machine_name.clone(),
            operating_system: std::env::consts::OS.to_string(),
            daemon_version: self.daemon_version.clone(),
            advertised_capabilities: self.advertised_capabilities.clone(),
            platform: self.platform.clone(),
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]

    use super::*;
    use are_core::Capability;

    fn test_state() -> DaemonState {
        let mut caps = CapabilitySet::default();
        caps.insert(Capability::FilesystemRead);
        caps.insert(Capability::ProcessExecute);

        DaemonState::new(
            EnvironmentId::new("test-env"),
            "test-host".into(),
            "0.1.0".into(),
            caps,
            Platform::Debian,
        )
    }

    #[test]
    fn handle_get_environment_info_matching_env() {
        let state = test_state();
        let req = RpcRequest::GetEnvironmentInfo(GetEnvironmentInfoRequest {
            environment_id: EnvironmentId::new("test-env"),
        });

        let resp = state.handle(req);
        match resp.result {
            Ok(RpcResponsePayload::GetEnvironmentInfo(info)) => {
                assert_eq!(info.environment_id.as_str(), "test-env");
                assert_eq!(info.machine_name, "test-host");
                assert_eq!(info.daemon_version, "0.1.0");
                assert_eq!(info.platform, Platform::Debian);
                assert!(info
                    .advertised_capabilities
                    .contains(&Capability::FilesystemRead));
                assert!(info
                    .advertised_capabilities
                    .contains(&Capability::ProcessExecute));
            }
            other => panic!("expected Ok, got {other:?}"),
        }
    }

    #[test]
    fn handle_get_environment_info_wrong_env() {
        let state = test_state();
        let req = RpcRequest::GetEnvironmentInfo(GetEnvironmentInfoRequest {
            environment_id: EnvironmentId::new("wrong-env"),
        });

        let resp = state.handle(req);
        assert!(resp.result.is_err());
        match resp.result {
            Err(RpcError::InvalidRequest(msg)) => {
                assert!(msg.contains("does not match"));
            }
            other => panic!("expected InvalidRequest, got {other:?}"),
        }
    }
}
