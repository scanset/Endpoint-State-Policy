//! Command execution with security controls for system state collection.
//!
//! `SystemCommandExecutor` handles the concerns that are independent of HOW
//! a command is dispatched:
//!   - whitelist enforcement (only pre-approved programs may run)
//!   - env-var resolution (static + dynamic, with credential rotation)
//!   - per-call timeout resolution
//!
//! The actual dispatch is delegated to an `Arc<dyn Channel>` backend. By
//! default that backend is `LocalChannel` (in-process spawn); agents can
//! construct an executor over any channel via `from_channel`.
//!
//! # Environment handling
//!
//!   - `env_clear()` semantics are preserved on the local backend — only
//!     `PATH` + explicitly configured vars reach the child.
//!   - Two injection modes survive unchanged:
//!     - `set_env(key, value)` — static: value fixed at configuration time.
//!     - `set_env_from(child_var, source_var)` — dynamic: reads `source_var`
//!       from the agent's environment on EVERY `execute()` call. Supports
//!       credential rotation without agent restart.
//!   - Resolution order when both are set for the same var: dynamic wins
//!     (dynamic is read fresh each call, static is a config-time baseline).
//!     `PATH` is the one exception — dynamic + static are stacked together
//!     to preserve original semantics.
//!
//! # Transport
//!
//!   - `new()` / `with_timeout()` — locally-backed (preserves original behavior).
//!   - `from_channel(Arc<dyn Channel>)` — dispatches over the given channel.

#![allow(clippy::disallowed_methods)] // Security: controlled execution via whitelist

use crate::strategies::channel::{ChannelError, LocalChannel, SharedChannel};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

/// Executes system commands with security controls and timeout enforcement.
///
/// Whitelist + env-var resolution are executor concerns. Transport (local
/// spawn, SSH, Bastion tunnel, SSM, WinRM, ...) is delegated to the
/// configured `Channel`.
#[derive(Clone)]
pub struct SystemCommandExecutor {
    default_timeout: Duration,
    allowed_commands: HashSet<String>,
    /// Static env vars injected as-is into every spawned process.
    static_env: HashMap<String, String>,
    /// Dynamic env var mappings: child_var -> source_var_name.
    /// On each execute() we read std::env::var(source_var) and inject as
    /// child_var. Silently skipped if source_var is not set.
    dynamic_env: HashMap<String, String>,
    /// Transport backend.
    channel: SharedChannel,
}

impl Default for SystemCommandExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemCommandExecutor {
    /// Create a locally-backed executor with empty whitelist.
    pub fn new() -> Self {
        Self::from_channel(Arc::new(LocalChannel::new()))
    }

    /// Create a locally-backed executor with a custom default timeout.
    pub fn with_timeout(timeout: Duration) -> Self {
        let mut e = Self::new();
        e.default_timeout = timeout;
        e
    }

    /// Create an executor over an arbitrary channel (SSH, Bastion tunnel,
    /// SSM, WinRM, ...). Whitelist and envs start empty and default timeout
    /// is 5s — configure with the usual setters before use.
    pub fn from_channel(channel: SharedChannel) -> Self {
        Self {
            default_timeout: Duration::from_secs(5),
            allowed_commands: HashSet::new(),
            static_env: HashMap::new(),
            dynamic_env: HashMap::new(),
            channel,
        }
    }

    /// Create an executor over an arbitrary channel with a custom default
    /// timeout. Preferred over `from_channel(..).default_timeout =` so callers
    /// can express the intended timeout at construction time — this is the
    /// one-shot equivalent of `with_timeout` for non-local transports.
    ///
    /// Whitelist and envs start empty; configure with the usual setters.
    pub fn from_channel_with_timeout(channel: SharedChannel, timeout: Duration) -> Self {
        let mut e = Self::from_channel(channel);
        e.default_timeout = timeout;
        e
    }

    /// Replace the underlying channel without rebuilding the whole executor.
    /// Whitelist, envs, and default timeout are preserved.
    pub fn with_channel(mut self, channel: SharedChannel) -> Self {
        self.channel = channel;
        self
    }

    /// Observe the current channel (e.g. to read `os_family()` for routing
    /// decisions, or to run `probe()` before a scan).
    pub fn channel(&self) -> &SharedChannel {
        &self.channel
    }

    /// Add command to whitelist.
    pub fn allow_command(&mut self, command: impl Into<String>) {
        self.allowed_commands.insert(command.into());
    }

    /// Add multiple commands to whitelist.
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

    /// Set multiple static environment variables at once.
    pub fn set_envs(&mut self, vars: impl IntoIterator<Item = (String, String)>) {
        self.static_env.extend(vars);
    }

    /// Map a child-process env var to a source env var read from the AGENT's
    /// environment on each `execute()` call. Supports credential rotation
    /// without agent restart. Silently skipped if the source var is not set.
    ///
    /// Example:
    ///   executor.set_env_from("PGPASSWORD", "ESP_PG_PASS");
    pub fn set_env_from(&mut self, child_var: impl Into<String>, source_var: impl Into<String>) {
        self.dynamic_env.insert(child_var.into(), source_var.into());
    }

    /// Check if command is whitelisted.
    pub fn is_allowed(&self, command: &str) -> bool {
        self.allowed_commands.contains(command)
    }

    /// Resolve the full env map for a single execute() call: static_env
    /// merged with dynamic_env freshly read from the agent's environment.
    ///
    /// Merge rules:
    ///   - For `PATH`: dynamic is prepended to static (both survive in the
    ///     final colon list). Preserves the original stacking behavior.
    ///   - For all other keys: dynamic overrides static.
    fn resolve_env(&self) -> HashMap<String, String> {
        let mut out = self.static_env.clone();

        // Read dynamic vars from the agent env.
        let mut dynamic: HashMap<String, String> = HashMap::new();
        for (child_var, source_var) in &self.dynamic_env {
            if let Ok(val) = std::env::var(source_var) {
                dynamic.insert(child_var.clone(), val);
            }
        }

        // PATH gets special stacking: dynamic:static (base is added by
        // LocalChannel at spawn time). Remote channels typically ignore
        // PATH from env — their target shell supplies its own.
        match (out.get("PATH").cloned(), dynamic.remove("PATH")) {
            (Some(static_path), Some(dynamic_path)) => {
                out.insert(
                    "PATH".to_string(),
                    format!("{}:{}", dynamic_path, static_path),
                );
            }
            (None, Some(dynamic_path)) => {
                out.insert("PATH".to_string(), dynamic_path);
            }
            _ => {} // static-only or none — leave `out` as-is.
        }

        // All other dynamic vars override static.
        for (k, v) in dynamic {
            out.insert(k, v);
        }

        out
    }

    /// Execute command with timeout and capture output via the configured
    /// channel.
    pub fn execute(
        &self,
        program: &str,
        args: &[&str],
        timeout: Option<Duration>,
    ) -> Result<CommandOutput, CommandError> {
        if !self.allowed_commands.contains(program) {
            return Err(CommandError::SecurityViolation {
                reason: format!("Command '{}' not in whitelist", program),
            });
        }

        let timeout_duration = timeout.unwrap_or(self.default_timeout);
        let env = self.resolve_env();

        self.channel
            .execute(program, args, &env, timeout_duration)
            .map_err(CommandError::from)
    }
}

/// Command execution output.
#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
    pub duration: Duration,
}

/// Errors returned by `SystemCommandExecutor::execute`.
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

    /// Transport-level failure surfaced from the underlying `Channel`
    /// (e.g. SSH auth failure, Bastion tunnel down, SSM API error).
    #[error(transparent)]
    Channel(ChannelError),
}

/// Hand-written to preserve backward compatibility for the three variants
/// whose shapes overlap exactly between `ChannelError` and `CommandError`
/// (`ProgramNotFound`, `PermissionDenied`, `Timeout`). Everything else flows
/// through as `CommandError::Channel(..)` — new code can match on that for
/// richer transport diagnostics.
impl From<ChannelError> for CommandError {
    fn from(e: ChannelError) -> Self {
        match e {
            ChannelError::ProgramNotFound { program } => CommandError::ProgramNotFound { program },
            ChannelError::PermissionDenied { program } => {
                CommandError::PermissionDenied { program }
            }
            ChannelError::Timeout { timeout_ms, .. } => CommandError::Timeout { timeout_ms },
            other => CommandError::Channel(other),
        }
    }
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
            Err(CommandError::SecurityViolation { .. }) => {}
            _ => panic!("Expected SecurityViolation error"),
        }
    }

    #[test]
    fn test_set_env_from_resolves_at_execute_time() {
        std::env::set_var("TEST_ESP_SECRET", "resolved_value");

        let mut executor = SystemCommandExecutor::new();
        executor.allow_command("echo");
        executor.set_env_from("MY_SECRET", "TEST_ESP_SECRET");

        let resolved = executor.resolve_env();
        assert_eq!(
            resolved.get("MY_SECRET").map(|s| s.as_str()),
            Some("resolved_value")
        );

        std::env::set_var("TEST_ESP_SECRET", "rotated_value");
        let resolved = executor.resolve_env();
        assert_eq!(
            resolved.get("MY_SECRET").map(|s| s.as_str()),
            Some("rotated_value")
        );

        std::env::remove_var("TEST_ESP_SECRET");
    }

    #[test]
    fn test_set_env_from_skips_missing_var() {
        let mut executor = SystemCommandExecutor::new();
        executor.set_env_from("MY_SECRET", "NONEXISTENT_VAR_12345");

        let resolved = executor.resolve_env();
        assert!(!resolved.contains_key("MY_SECRET"));
    }

    #[test]
    fn test_path_dynamic_stacks_on_static() {
        std::env::set_var("TEST_ESP_PATH_DYN", "/opt/dyn/bin");

        let mut executor = SystemCommandExecutor::new();
        executor.set_env("PATH", "/opt/static/bin");
        executor.set_env_from("PATH", "TEST_ESP_PATH_DYN");

        let resolved = executor.resolve_env();
        // Dynamic is prepended to static; LocalChannel will later prepend
        // its conservative base when spawning.
        assert_eq!(
            resolved.get("PATH").map(|s| s.as_str()),
            Some("/opt/dyn/bin:/opt/static/bin")
        );

        std::env::remove_var("TEST_ESP_PATH_DYN");
    }

    #[test]
    fn test_from_channel_preserves_empty_whitelist() {
        let ch: SharedChannel = Arc::new(LocalChannel::new());
        let executor = SystemCommandExecutor::from_channel(ch);
        assert!(!executor.is_allowed("anything"));
    }

    #[test]
    fn test_from_channel_with_timeout_sets_default_timeout() {
        let ch: SharedChannel = Arc::new(LocalChannel::new());
        let executor =
            SystemCommandExecutor::from_channel_with_timeout(ch, Duration::from_secs(42));
        assert_eq!(executor.default_timeout, Duration::from_secs(42));
        assert!(!executor.is_allowed("anything"));
    }
}
