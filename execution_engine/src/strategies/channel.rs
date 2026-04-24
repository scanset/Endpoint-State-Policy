//! Channel abstraction for command transport.
//!
//! A `Channel` is the pluggable backend that decides HOW a command is run —
//! locally via `std::process::Command`, remotely via SSH, via a cloud API
//! (AWS SSM, Azure Bastion tunnel), etc. `SystemCommandExecutor` holds an
//! `Arc<dyn Channel>` and delegates to it after whitelist + env resolution.
//!
//! The engine ships `LocalChannel` (zero-dep, preserves existing behavior).
//! Remote transports live in separate crates and are wired up by agent-layer
//! factories; the engine never depends on them.
//!
//! # Design invariants
//!
//! - Whitelist enforcement happens in `SystemCommandExecutor` before calling
//!   `Channel::execute`. Channel impls can trust that `program` is allowed.
//! - The `env` map passed to `execute` is already fully resolved — static +
//!   dynamic merged at call time (reading agent-side env vars for credential
//!   rotation). The channel decides HOW to propagate those vars to the target.
//! - PATH handling is channel-specific. `LocalChannel` prepends any caller
//!   PATH to a conservative base; remote channels should use the target
//!   shell's PATH unless they explicitly know how to inject one.

#![allow(clippy::disallowed_methods)] // Security: controlled execution via whitelist

use crate::strategies::command_executor::CommandOutput;
use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

// Re-export the v2.0.0 host-identity types so channel impls in external
// crates (e.g. `channels::az_bastion`) can `use
// execution_engine::strategies::channel::HostInfo` without needing a
// direct dep on `common`.
pub use common::results::{HostInfo, HostRef};

/// OS family the channel reaches. Lets the registry (or a scanner) refuse
/// to wire a Windows CTN to a Linux channel (or vice versa) at startup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OsFamily {
    Linux,
    Windows,
    MacOs,
    Other,
}

/// Transport-layer errors — failures to REACH or INTERACT with the target,
/// distinct from errors produced by running the command itself.
#[derive(Debug, thiserror::Error)]
pub enum ChannelError {
    #[error("Channel unreachable: {reason}")]
    Unreachable { reason: String },

    #[error("Authentication failed: {reason}")]
    AuthFailed { reason: String },

    #[error("Channel session failed: {reason}")]
    SessionFailed { reason: String },

    #[error("Transport error: {reason}")]
    Transport { reason: String },

    #[error("Command execution failed on channel '{channel}': {reason}")]
    ExecutionFailed { channel: String, reason: String },

    #[error("Command timed out after {timeout_ms}ms on channel '{channel}'")]
    Timeout { channel: String, timeout_ms: u64 },

    #[error("Program not found on target: {program}")]
    ProgramNotFound { program: String },

    #[error("Permission denied on target: {program}")]
    PermissionDenied { program: String },
}

/// Pluggable command-transport backend.
///
/// Implementors are responsible ONLY for running an already-authorized command
/// and returning its output. Whitelist enforcement and env-var resolution are
/// performed by `SystemCommandExecutor` before delegation.
pub trait Channel: Send + Sync {
    /// Stable kind identifier used by factories, e.g. "local", "ssh",
    /// "az_bastion_tunnel", "aws_ssm", "winrm".
    fn kind(&self) -> &'static str;

    /// OS family this channel reaches.
    fn os_family(&self) -> OsFamily;

    /// Cheap health probe — round-trip a trivial command to verify the
    /// channel is authenticated and reachable. Called before scans so
    /// credential / connectivity errors fail fast with a useful message.
    fn probe(&self) -> Result<(), ChannelError>;

    /// Execute a program with arguments under a resolved env map.
    ///
    /// `env` is pre-resolved by the caller (static + dynamic merged, with
    /// credential rotation applied). The channel decides how to propagate:
    ///   - `LocalChannel` uses `Command::env`
    ///   - `SshChannel` prefixes `VAR=val` on the remote command
    ///   - `AwsSsmChannel` bundles them into the SSM document body
    ///   - `WinRmChannel` emits `$env:VAR = "..."` before the program
    fn execute(
        &self,
        program: &str,
        args: &[&str],
        env: &HashMap<String, String>,
        timeout: Duration,
    ) -> Result<CommandOutput, ChannelError>;

    /// Identify the host this channel targets (v2.0.0).
    ///
    /// Produces the polymorphic `HostInfo` that goes into
    /// `ResultEnvelope.host`. Channel implementations own this because
    /// they carry the provider context needed to populate it - e.g.
    /// `AzBastionChannel` knows its `subscription_id` / `resource_group`,
    /// `AwsSsmChannel` knows its `account_id` / `region`.
    ///
    /// A default implementation is provided so existing channels keep
    /// compiling; it produces a minimal generic HostInfo based on
    /// `kind()` and `os_family()`. Transport implementations SHOULD
    /// override with provider-specific attrs.
    ///
    /// Called once per scan by the agent, typically in place of the
    /// legacy `HostInfo::from_system()`. MUST NOT mutate channel state
    /// or spawn long-running work - it should be as cheap as possible
    /// and idempotent.
    fn identify_host(&self) -> Result<HostInfo, ChannelError> {
        let os = os_family_label(self.os_family());
        let host_type = match self.os_family() {
            OsFamily::Linux => "linux.vm".to_string(),
            OsFamily::Windows => "windows.vm".to_string(),
            OsFamily::MacOs => "macos.vm".to_string(),
            OsFamily::Other => format!("{}.host", self.kind()),
        };

        // Minimal fallback: kind + os_family. Channels that know more
        // SHOULD override and return something richer.
        let host_id = format!("{}-unknown", self.kind());
        Ok(HostInfo::for_host_type(host_type, host_id)
            .with_os(os)
            .with_attr(
                "channel_kind",
                serde_json::Value::String(self.kind().to_string()),
            ))
    }
}

/// Map `OsFamily` to the short string used in `HostInfo.os`.
pub fn os_family_label(f: OsFamily) -> &'static str {
    match f {
        OsFamily::Linux => "linux",
        OsFamily::Windows => "windows",
        OsFamily::MacOs => "macos",
        OsFamily::Other => "other",
    }
}

/// Type alias for the shared-channel pattern — executors hold `SharedChannel`
/// so the same transport can be reused across many executors (connection
/// pooling for free).
pub type SharedChannel = Arc<dyn Channel>;

// ---------------------------------------------------------------------------
// LocalChannel — default, in-process implementation.
// ---------------------------------------------------------------------------

/// The default, in-process channel. Uses `std::process::Command` with
/// `env_clear()` + a conservative base PATH, mirroring the original
/// `SystemCommandExecutor` behavior exactly.
///
/// Constructed automatically by `SystemCommandExecutor::new()` /
/// `::with_timeout`, so all existing callers keep their behavior unchanged.
#[derive(Debug, Clone, Default)]
pub struct LocalChannel;

impl LocalChannel {
    pub fn new() -> Self {
        Self
    }
}

const LOCAL_BASE_PATH: &str = "/usr/bin:/bin:/usr/sbin:/sbin";
const LOCAL_KIND: &str = "local";

impl Channel for LocalChannel {
    fn kind(&self) -> &'static str {
        LOCAL_KIND
    }

    fn os_family(&self) -> OsFamily {
        if cfg!(target_os = "windows") {
            OsFamily::Windows
        } else if cfg!(target_os = "macos") {
            OsFamily::MacOs
        } else if cfg!(target_os = "linux") {
            OsFamily::Linux
        } else {
            OsFamily::Other
        }
    }

    fn probe(&self) -> Result<(), ChannelError> {
        // Local channel is always reachable — no-op.
        Ok(())
    }

    fn identify_host(&self) -> Result<HostInfo, ChannelError> {
        let hostname = hostname::get()
            .ok()
            .and_then(|s| s.into_string().ok())
            .unwrap_or_else(|| "unknown".to_string());

        let os_label = os_family_label(self.os_family());
        let host_type = match self.os_family() {
            OsFamily::Linux => "linux.vm",
            OsFamily::Windows => "windows.vm",
            OsFamily::MacOs => "macos.vm",
            OsFamily::Other => "unknown.vm",
        };

        // Prefer a stable machine-id when available:
        //   Linux: /etc/machine-id (systemd) or /var/lib/dbus/machine-id
        //   Windows/macOS: fall back to hashed hostname — platform-specific
        //   stable IDs can be layered in later without breaking the shape.
        let host_id = read_stable_machine_id()
            .unwrap_or_else(|| format!("host-{:x}", hash_hostname(&hostname)));

        let mut info = HostInfo::for_host_type(host_type, host_id)
            .with_hostname(&hostname)
            .with_os(os_label)
            .with_arch(std::env::consts::ARCH);

        // Opportunistic enrichment — any failure here is non-fatal, the
        // core `host_type` / `host_id` are enough.
        #[cfg(target_os = "linux")]
        {
            if let Ok(kernel) = std::fs::read_to_string("/proc/sys/kernel/osrelease") {
                info = info.with_attr(
                    "kernel",
                    serde_json::Value::String(kernel.trim().to_string()),
                );
            }
        }

        Ok(info)
    }

    fn execute(
        &self,
        program: &str,
        args: &[&str],
        env: &HashMap<String, String>,
        timeout: Duration,
    ) -> Result<CommandOutput, ChannelError> {
        let start = Instant::now();

        // Final PATH: caller-supplied PATH (if any) prepended to the
        // conservative base. The executor has already stacked dynamic over
        // static PATH when both were set, so a single value here is correct.
        let final_path = match env.get("PATH") {
            Some(p) => format!("{}:{}", p, LOCAL_BASE_PATH),
            None => LOCAL_BASE_PATH.to_string(),
        };

        let mut cmd = Command::new(program);
        cmd.args(args)
            .env_clear()
            .env("PATH", &final_path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        for (k, v) in env {
            if k != "PATH" {
                cmd.env(k, v);
            }
        }

        let mut child = cmd.spawn().map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => ChannelError::ProgramNotFound {
                program: program.to_string(),
            },
            std::io::ErrorKind::PermissionDenied => ChannelError::PermissionDenied {
                program: program.to_string(),
            },
            _ => ChannelError::ExecutionFailed {
                channel: LOCAL_KIND.to_string(),
                reason: e.to_string(),
            },
        })?;

        let result = wait_timeout::ChildExt::wait_timeout(&mut child, timeout).map_err(|e| {
            ChannelError::ExecutionFailed {
                channel: LOCAL_KIND.to_string(),
                reason: e.to_string(),
            }
        })?;

        match result {
            Some(status) => {
                let output =
                    child
                        .wait_with_output()
                        .map_err(|e| ChannelError::ExecutionFailed {
                            channel: LOCAL_KIND.to_string(),
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
                let _ = child.kill();
                Err(ChannelError::Timeout {
                    channel: LOCAL_KIND.to_string(),
                    timeout_ms: timeout.as_millis() as u64,
                })
            }
        }
    }
}

/// Try to read a stable machine identifier. Returns `None` on platforms
/// without one or if the file isn't readable (e.g. restricted container).
fn read_stable_machine_id() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        for path in ["/etc/machine-id", "/var/lib/dbus/machine-id"] {
            if let Ok(s) = std::fs::read_to_string(path) {
                let trimmed = s.trim();
                if !trimmed.is_empty() {
                    return Some(format!("linux-{}", trimmed));
                }
            }
        }
    }
    // Windows / macOS: platform-specific probes can land here later.
    None
}

/// Stable non-cryptographic hash used for host-id fallback when no
/// machine-id is available.
fn hash_hostname(s: &str) -> u64 {
    let mut h: u64 = 5381;
    for b in s.bytes() {
        h = h.wrapping_mul(33).wrapping_add(u64::from(b));
    }
    h
}

#[allow(clippy::unwrap_used, clippy::expect_used)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_channel_probe_ok() {
        let ch = LocalChannel::new();
        assert!(ch.probe().is_ok());
        assert_eq!(ch.kind(), "local");
    }

    #[test]
    fn local_channel_reports_os_family() {
        let ch = LocalChannel::new();
        let fam = ch.os_family();
        // Whichever platform we're on, it must resolve to one of these.
        assert!(matches!(
            fam,
            OsFamily::Linux | OsFamily::Windows | OsFamily::MacOs | OsFamily::Other
        ));
    }

    #[test]
    fn local_channel_identify_host_produces_vm_shape() {
        let ch = LocalChannel::new();
        let h = ch.identify_host().expect("identify_host must succeed");

        // host_type follows the dotted <provider>.<kind> convention.
        assert!(
            h.host_type.ends_with(".vm"),
            "unexpected host_type: {}",
            h.host_type
        );
        assert!(!h.host_id.is_empty());
        assert!(h.hostname.is_some());
        assert!(h.os.is_some());
        assert!(h.arch.is_some());
    }

    #[test]
    fn local_channel_host_id_stable_across_calls() {
        let ch = LocalChannel::new();
        let a = ch.identify_host().unwrap();
        let b = ch.identify_host().unwrap();
        assert_eq!(a.host_id, b.host_id);
        assert_eq!(a.host_type, b.host_type);
    }
}
