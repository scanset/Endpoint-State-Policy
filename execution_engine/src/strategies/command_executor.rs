//! Command execution with security controls for system state collection
#![allow(clippy::disallowed_methods)] // Security: This module provides controlled command execution via whitelist
use std::collections::HashSet;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Executes system commands with security controls and timeout enforcement
#[derive(Clone)]
pub struct SystemCommandExecutor {
    default_timeout: Duration,
    allowed_commands: HashSet<String>,
}

impl Default for SystemCommandExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemCommandExecutor {
    /// Create executor with empty whitelist - must be configured before use
    pub fn new() -> Self {
        Self {
            default_timeout: Duration::from_secs(5),
            allowed_commands: HashSet::new(),
        }
    }

    /// Create executor with custom timeout and empty whitelist
    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            default_timeout: timeout,
            allowed_commands: HashSet::new(),
        }
    }

    /// Add command to whitelist
    pub fn allow_command(&mut self, command: impl Into<String>) {
        self.allowed_commands.insert(command.into());
    }

    /// Add multiple commands to whitelist
    pub fn allow_commands(&mut self, commands: &[&str]) {
        for cmd in commands {
            self.allowed_commands.insert(cmd.to_string());
        }
    }

    /// Check if command is whitelisted
    pub fn is_allowed(&self, command: &str) -> bool {
        self.allowed_commands.contains(command)
    }

    /// Execute command with timeout and capture output
    pub fn execute(
        &self,
        program: &str,
        args: &[&str],
        timeout: Option<Duration>,
    ) -> Result<CommandOutput, CommandError> {
        // Validate program is whitelisted
        if !self.allowed_commands.contains(program) {
            return Err(CommandError::SecurityViolation {
                reason: format!("Command '{}' not in whitelist", program),
            });
        }

        let timeout_duration = timeout.unwrap_or(self.default_timeout);
        let start = Instant::now();

        // Build command with sanitized environment
        let mut cmd = Command::new(program);
        cmd.args(args)
            .env_clear() // Clear environment for security
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin") // Restricted PATH
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        // Spawn process
        let mut child = cmd.spawn().map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                CommandError::ProgramNotFound {
                    program: program.to_string(),
                }
            } else if e.kind() == std::io::ErrorKind::PermissionDenied {
                CommandError::PermissionDenied {
                    program: program.to_string(),
                }
            } else {
                CommandError::ExecutionFailed {
                    program: program.to_string(),
                    reason: e.to_string(),
                }
            }
        })?;

        // Wait with timeout
        let result =
            wait_timeout::ChildExt::wait_timeout(&mut child, timeout_duration).map_err(|e| {
                CommandError::ExecutionFailed {
                    program: program.to_string(),
                    reason: e.to_string(),
                }
            })?;

        match result {
            Some(status) => {
                // Process completed within timeout
                let output =
                    child
                        .wait_with_output()
                        .map_err(|e| CommandError::ExecutionFailed {
                            program: program.to_string(),
                            reason: e.to_string(),
                        })?;

                Ok(CommandOutput {
                    stdout: String::from_utf8_lossy(&output.stdout).to_string(),
                    stderr: String::from_utf8_lossy(&output.stderr).to_string(),
                    exit_code: status.code().unwrap_or(-1),
                    duration: start.elapsed(),
                })
            }
            None => {
                // Timeout - kill process
                let _ = child.kill();
                Err(CommandError::Timeout {
                    timeout_ms: timeout_duration.as_millis() as u64,
                })
            }
        }
    }
}

/// Command execution output
#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub duration: Duration,
}

/// Command execution errors
#[derive(Debug, thiserror::Error)]
pub enum CommandError {
    #[error("Program not found: {program}")]
    ProgramNotFound { program: String },

    #[error("Execution failed for '{program}': {reason}")]
    ExecutionFailed { program: String, reason: String },

    #[error("Command timed out after {timeout_ms}ms")]
    Timeout { timeout_ms: u64 },

    #[error("Permission denied: {program}")]
    PermissionDenied { program: String },

    #[error("Security violation: {reason}")]
    SecurityViolation { reason: String },
}

#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_whitelist() {
        let executor = SystemCommandExecutor::new();
        assert!(!executor.is_allowed("rpm"));
        assert!(!executor.is_allowed("ls"));
    }

    #[test]
    fn test_whitelist_management() {
        let mut executor = SystemCommandExecutor::new();

        executor.allow_command("rpm");
        assert!(executor.is_allowed("rpm"));
        assert!(!executor.is_allowed("systemctl"));

        executor.allow_commands(&["systemctl", "getenforce"]);
        assert!(executor.is_allowed("systemctl"));
        assert!(executor.is_allowed("getenforce"));
    }

    #[test]
    fn test_security_violation() {
        let executor = SystemCommandExecutor::new();
        let result = executor.execute("rm", &["-rf", "/"], None);

        match result {
            Err(CommandError::SecurityViolation { .. }) => {
                // Expected - command not whitelisted
            }
            _ => panic!("Expected SecurityViolation error"),
        }
    }
}
