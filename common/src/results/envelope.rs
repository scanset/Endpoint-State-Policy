//! Execution envelope for ESP results
//!
//! The `ExecutionEnvelope` wraps all result types with metadata about WHO ran WHAT,
//! WHERE, and WHEN. It provides a consistent structure for both attestations
//! (network-safe) and full results (local storage).
//!
//! ## Structure
//!
//! ```text
//! ExecutionEnvelope
//! ├── result_id         - Unique identifier for this result set
//! ├── agent             - Agent that executed the scan
//! │   ├── id
//! │   ├── name
//! │   ├── version
//! │   └── agent_type
//! ├── host              - Host where scan executed
//! │   ├── hostname
//! │   ├── os
//! │   └── arch
//! ├── started_at        - When execution started
//! ├── completed_at      - When execution completed
//! ├── content_hash      - SHA-256 hash of content for verification
//! └── signature         - Optional cryptographic signature
//! ```
//!
//! ## Usage
//!
//! ```rust,ignore
//! use common::results::envelope::{ExecutionEnvelope, AgentInfo, HostInfo};
//!
//! let agent = AgentInfo::new("agent-001", "esp-scanner", "0.1.0", "cli");
//! let host = HostInfo::from_system();
//!
//! let envelope = ExecutionEnvelope::new("result-123", agent, host)
//!     .with_content_hash("sha256:abc123...");
//! ```

use serde::{Deserialize, Serialize};

// ============================================================================
// ExecutionEnvelope
// ============================================================================

/// Universal envelope for ESP execution results
///
/// Contains metadata about WHO ran WHAT, WHERE, and WHEN.
/// This wraps both attestations (network-safe) and full results (local).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionEnvelope {
    /// Unique identifier for this result set
    pub result_id: String,

    /// Agent that executed the scan
    pub agent: AgentInfo,

    /// Host where scan executed
    pub host: HostInfo,

    /// When execution started (ISO 8601)
    pub started_at: String,

    /// When execution completed (ISO 8601)
    pub completed_at: String,

    /// Hash of the content (for verification)
    pub content_hash: String,

    /// Cryptographic signature (populated by signing module)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureInfo>,
}

impl ExecutionEnvelope {
    /// Create a new execution envelope
    pub fn new(result_id: impl Into<String>, agent: AgentInfo, host: HostInfo) -> Self {
        let now = current_timestamp();
        Self {
            result_id: result_id.into(),
            agent,
            host,
            started_at: now.clone(),
            completed_at: now,
            content_hash: String::new(),
            signature: None,
        }
    }

    /// Set the start timestamp
    pub fn with_started_at(mut self, timestamp: impl Into<String>) -> Self {
        self.started_at = timestamp.into();
        self
    }

    /// Set the completion timestamp
    pub fn with_completed_at(mut self, timestamp: impl Into<String>) -> Self {
        self.completed_at = timestamp.into();
        self
    }

    /// Set the content hash
    pub fn with_content_hash(mut self, hash: impl Into<String>) -> Self {
        self.content_hash = hash.into();
        self
    }

    /// Add a signature to the envelope
    pub fn with_signature(mut self, signature: SignatureInfo) -> Self {
        self.signature = Some(signature);
        self
    }

    /// Check if the envelope has been signed
    pub fn is_signed(&self) -> bool {
        self.signature.is_some()
    }

    /// Generate a new unique result ID
    pub fn generate_result_id() -> String {
        use std::time::{SystemTime, UNIX_EPOCH};

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();

        format!("esp-result-{:x}", timestamp)
    }
}

impl Default for ExecutionEnvelope {
    fn default() -> Self {
        Self::new(
            Self::generate_result_id(),
            AgentInfo::default(),
            HostInfo::from_system(),
        )
    }
}

// ============================================================================
// AgentInfo
// ============================================================================

/// Information about the agent that executed the scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    /// Agent identifier (unique per deployment)
    pub id: String,

    /// Agent name
    pub name: String,

    /// Agent version
    pub version: String,

    /// Agent type (e.g., "cli", "daemon", "ci-agent", "controller")
    pub agent_type: String,
}

impl AgentInfo {
    /// Create new agent info
    pub fn new(
        id: impl Into<String>,
        name: impl Into<String>,
        version: impl Into<String>,
        agent_type: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            name: name.into(),
            version: version.into(),
            agent_type: agent_type.into(),
        }
    }

    /// Create agent info with default values
    pub fn with_defaults(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            name: "esp-agent".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            agent_type: "cli".to_string(),
        }
    }
}

impl Default for AgentInfo {
    fn default() -> Self {
        Self::with_defaults("unknown")
    }
}

// ============================================================================
// HostInfo
// ============================================================================

/// Information about the host where the scan executed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfo {
    /// Hostname
    pub hostname: String,

    /// Operating system
    pub os: String,

    /// Architecture
    pub arch: String,

    /// Fully qualified domain name (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fqdn: Option<String>,

    /// Asset identifier for CMDB correlation (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asset_id: Option<String>,
}

impl HostInfo {
    /// Create new host info
    pub fn new(
        hostname: impl Into<String>,
        os: impl Into<String>,
        arch: impl Into<String>,
    ) -> Self {
        Self {
            hostname: hostname.into(),
            os: os.into(),
            arch: arch.into(),
            fqdn: None,
            asset_id: None,
        }
    }

    /// Create host info from system information
    pub fn from_system() -> Self {
        let hostname = std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("COMPUTERNAME"))
            .unwrap_or_else(|_| "unknown".to_string());

        Self {
            hostname,
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            fqdn: None,
            asset_id: None,
        }
    }

    /// Set FQDN
    pub fn with_fqdn(mut self, fqdn: impl Into<String>) -> Self {
        self.fqdn = Some(fqdn.into());
        self
    }

    /// Set asset ID
    pub fn with_asset_id(mut self, asset_id: impl Into<String>) -> Self {
        self.asset_id = Some(asset_id.into());
        self
    }
}

impl Default for HostInfo {
    fn default() -> Self {
        Self::from_system()
    }
}

// ============================================================================
// SignatureInfo
// ============================================================================

/// Cryptographic signature information
///
/// Populated by the signing module after content is hashed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureInfo {
    /// Signing algorithm used (e.g., "tpm-ecdsa-p256", "ecdsa-p256", "ed25519")
    pub algorithm: String,

    /// Base64-encoded signature value
    pub value: String,

    /// Key identifier (for key lookup/verification)
    pub key_id: String,

    /// When the signature was created (ISO 8601)
    pub signed_at: String,
}

impl SignatureInfo {
    /// Create new signature info
    pub fn new(
        algorithm: impl Into<String>,
        value: impl Into<String>,
        key_id: impl Into<String>,
    ) -> Self {
        Self {
            algorithm: algorithm.into(),
            value: value.into(),
            key_id: key_id.into(),
            signed_at: current_timestamp(),
        }
    }

    /// Set signed timestamp
    pub fn with_signed_at(mut self, timestamp: impl Into<String>) -> Self {
        self.signed_at = timestamp.into();
        self
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Generate ISO 8601 timestamp
fn current_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    let secs = duration.as_secs();
    let days = secs / 86400;
    let remaining = secs % 86400;
    let hours = remaining / 3600;
    let minutes = (remaining % 3600) / 60;
    let seconds = remaining % 60;

    // Approximate date calculation
    let years = 1970 + (days / 365);
    let day_of_year = days % 365;
    let month = (day_of_year / 30) + 1;
    let day = (day_of_year % 30) + 1;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        years, month, day, hours, minutes, seconds
    )
}

// ============================================================================
// Tests
// ============================================================================
#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_execution_envelope_new() {
        let agent = AgentInfo::new("agent-1", "test-agent", "1.0.0", "cli");
        let host = HostInfo::new("testhost", "linux", "x86_64");

        let envelope = ExecutionEnvelope::new("result-123", agent, host);

        assert_eq!(envelope.result_id, "result-123");
        assert_eq!(envelope.agent.id, "agent-1");
        assert_eq!(envelope.host.hostname, "testhost");
        assert!(!envelope.is_signed());
    }

    #[test]
    fn test_execution_envelope_with_signature() {
        let agent = AgentInfo::default();
        let host = HostInfo::default();

        let signature = SignatureInfo::new("ecdsa-p256", "base64sig", "key-001");

        let envelope = ExecutionEnvelope::new("result-456", agent, host)
            .with_content_hash("sha256:abc123")
            .with_signature(signature);

        assert!(envelope.is_signed());
        assert_eq!(envelope.content_hash, "sha256:abc123");
        assert_eq!(envelope.signature.as_ref().unwrap().algorithm, "ecdsa-p256");
    }

    #[test]
    fn test_agent_info() {
        let agent = AgentInfo::new("agent-1", "esp-scanner", "0.1.0", "daemon");

        assert_eq!(agent.id, "agent-1");
        assert_eq!(agent.name, "esp-scanner");
        assert_eq!(agent.version, "0.1.0");
        assert_eq!(agent.agent_type, "daemon");
    }

    #[test]
    fn test_host_info_from_system() {
        let host = HostInfo::from_system();

        // These should be populated with system values
        assert!(!host.os.is_empty());
        assert!(!host.arch.is_empty());
    }

    #[test]
    fn test_host_info_with_optional_fields() {
        let host = HostInfo::new("server01", "linux", "x86_64")
            .with_fqdn("server01.example.com")
            .with_asset_id("ASSET-12345");

        assert_eq!(host.fqdn, Some("server01.example.com".to_string()));
        assert_eq!(host.asset_id, Some("ASSET-12345".to_string()));
    }

    #[test]
    fn test_signature_info() {
        let sig = SignatureInfo::new("tpm-ecdsa-p256", "base64value", "tpm:key:123");

        assert_eq!(sig.algorithm, "tpm-ecdsa-p256");
        assert_eq!(sig.value, "base64value");
        assert_eq!(sig.key_id, "tpm:key:123");
        assert!(!sig.signed_at.is_empty());
    }

    #[test]
    fn test_generate_result_id() {
        let id1 = ExecutionEnvelope::generate_result_id();
        let id2 = ExecutionEnvelope::generate_result_id();

        assert!(id1.starts_with("esp-result-"));
        assert!(id2.starts_with("esp-result-"));
        // IDs should be unique (very likely given nanosecond timestamps)
        assert_ne!(id1, id2);
    }

    #[test]
    fn test_serialization() {
        let agent = AgentInfo::new("agent-1", "test", "1.0.0", "cli");
        let host = HostInfo::new("host1", "linux", "x86_64");
        let envelope =
            ExecutionEnvelope::new("result-1", agent, host).with_content_hash("sha256:test");

        let json = serde_json::to_string(&envelope).unwrap();
        let parsed: ExecutionEnvelope = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.result_id, "result-1");
        assert_eq!(parsed.content_hash, "sha256:test");
    }
}
