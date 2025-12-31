//! RHEL 9 command executor configuration
//!
//! Provides a whitelisted command executor for RHEL 9 STIG compliance scanning.

use agent_core::strategies::SystemCommandExecutor;
use std::time::Duration;

/// Create command executor configured for RHEL 9 STIG scanning
///
/// Whitelist includes:
/// - rpm: Package management queries
/// - systemctl: Service status checks
/// - getenforce: SELinux enforcement mode
/// - sysctl: Kernel parameter queries
/// - auditctl: Audit rule inspection
/// - id: User identity information
/// - stat: File metadata queries
/// - getent: User/group database queries
pub fn create_rhel9_command_executor() -> SystemCommandExecutor {
    let mut executor = SystemCommandExecutor::with_timeout(Duration::from_secs(5));

    executor.allow_commands(&[
        "rpm",        // Package management
        "systemctl",  // Service status
        "getenforce", // SELinux status
        "auditctl",   // Audit rules
        "sysctl",     // Kernel parameters
        "id",         // User info
        "stat",       // File metadata
        "getent",     // User/group database
    ]);

    executor
}
