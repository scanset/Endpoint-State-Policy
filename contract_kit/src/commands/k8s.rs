//! Kubernetes command executor configuration
//!
//! Provides a whitelisted command executor for Kubernetes compliance scanning.

use execution_engine::strategies::SystemCommandExecutor;
use std::time::Duration;

/// Create command executor configured for Kubernetes scanning
///
/// Whitelist includes:
/// - kubectl: Kubernetes CLI (multiple paths for container compatibility)
///
/// Uses longer timeout (30s) since K8s API calls can be slower than local commands.
pub fn create_k8s_command_executor() -> SystemCommandExecutor {
    let mut executor = SystemCommandExecutor::with_timeout(Duration::from_secs(30));

    executor.allow_commands(&[
        "kubectl",                // Standard PATH lookup
        "/usr/local/bin/kubectl", // Common container location
        "/usr/bin/kubectl",       // Alternative location
    ]);

    executor
}
