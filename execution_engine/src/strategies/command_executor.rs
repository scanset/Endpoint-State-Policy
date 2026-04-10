//! Command execution with security controls for system state collection
#![allow(clippy::disallowed_methods)] // Security: This module provides controlled command execution via whitelist
use std::collections::{HashMap, HashSet};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Executes system commands with security controls and timeout enforcement
///
/// Environment handling:
///   - `env_clear()` wipes all inherited vars from the spawned process
///   - Only `PATH` (restricted) + explicitly configured vars reach the child
///   - Two injection modes:
///     - `set_env(key, value)` — static: value fixed at configuration time
///     - `set_env_from(child_var, source_var)` — dynamic: reads `source_var`
///       from the agent's environment on EVERY `execute()` call. Supports
///       credential rotation without agent restart.
#[derive(Clone)]
pub struct SystemCommandExecutor {
    default_timeout: Duration,
    allowed_commands: HashSet<String>,
    /// Static env vars injected as-is into every spawned process
    static_env: HashMap<String, String>,
    /// Dynamic env var mappings: child_var -> source_var_name.
    /// On each execute(), reads std::env::var(source_var) and injects
    /// as child_var. Silently skipped if source_var is not set.
    dynamic_env: HashMap<String, String>,
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
            static_env: HashMap::new(),
            dynamic_env: HashMap::new(),
        }
    }

    /// Create executor with custom timeout and empty whitelist
    pub fn with_timeout(timeout: Duration) -> Self {
        Self {
            default_timeout: timeout,
            allowed_commands: HashSet::new(),
            static_env: HashMap::new(),
            dynamic_env: HashMap::new(),
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

    /// Set a static environment variable injected into every spawned process.
    /// Value is fixed at configuration time.
    pub fn set_env(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.static_env.insert(key.into(), value.into());
    }

    /// Set multiple static environment variables at once
    pub fn set_envs(&mut self, vars: impl IntoIterator<Item = (String, String)>) {
        self.static_env.extend(vars);
    }

    /// Map a child process env var to a source env var name.
    /// On each `execute()`, reads `std::env::var(source_var)` and injects
    /// the result as `child_var` in the spawned process. If `source_var`
    /// is not set in the agent's environment, the mapping is silently skipped.
    ///
    /// This supports credential rotation: change the agent's env var and
    /// the next spawned process picks up the new value. No restart needed.
    ///
    /// Example:
    ///   executor.set_env_from("PGPASSWORD", "ESP_PG_PASS");
    ///   // Each psql call reads ESP_PG_PASS at that moment and passes it
    ///   // as PGPASSWORD to the child process.
    pub fn set_env_from(
        &mut self,
        child_var: impl Into<String>,
        source_var: impl Into<String>,
    ) {
        self.dynamic_env.insert(child_var.into(), source_var.into());
    }

    /// Resolve dynamic env mappings at call time.
    /// Returns a HashMap of child_var -> resolved_value for vars that exist.
    fn resolve_dynamic_env(&self) -> HashMap<String, String> {
        let mut resolved = HashMap::new();
        for (child_var, source_var) in &self.dynamic_env {
            if let Ok(val) = std::env::var(source_var) {
                resolved.insert(child_var.clone(), val);
            }
        }
        resolved
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

        // Resolve dynamic env vars from the agent's current environment
        let dynamic_resolved = self.resolve_dynamic_env();

        // Build command with sanitized environment
        let mut cmd = Command::new(program);
        cmd.args(args)
            .env_clear() // Clear environment for security
            .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin") // Restricted PATH
            .envs(&self.static_env) // Static vars (fixed at config time)
            .envs(&dynamic_resolved) // Dynamic vars (resolved just now)
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

    #[test]
    fn test_set_env_from_resolves_at_execute_time() {
        // Set a test env var
        std::env::set_var("TEST_ESP_SECRET", "resolved_value");

        let mut executor = SystemCommandExecutor::new();
        executor.allow_command("echo");
        executor.set_env_from("MY_SECRET", "TEST_ESP_SECRET");

        // Verify resolve_dynamic_env picks it up
        let resolved = executor.resolve_dynamic_env();
        assert_eq!(resolved.get("MY_SECRET").map(|s| s.as_str()), Some("resolved_value"));

        // Change the value — next resolve should see the new one
        std::env::set_var("TEST_ESP_SECRET", "rotated_value");
        let resolved = executor.resolve_dynamic_env();
        assert_eq!(resolved.get("MY_SECRET").map(|s| s.as_str()), Some("rotated_value"));

        // Clean up
        std::env::remove_var("TEST_ESP_SECRET");
    }

    #[test]
    fn test_set_env_from_skips_missing_var() {
        let mut executor = SystemCommandExecutor::new();
        executor.set_env_from("MY_SECRET", "NONEXISTENT_VAR_12345");

        let resolved = executor.resolve_dynamic_env();
        assert!(resolved.is_empty());
    }
}
