//! Result envelope types
//!
//! The envelope wraps all result types with metadata about who ran what,
//! where, and when. Includes signature block for implementations to fill.

use serde::{Deserialize, Serialize};

/// Universal envelope for all ESP result types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResultEnvelope {
    /// Unique identifier for this result
    pub result_id: String,

    /// Schema version for this result format
    pub schema_version: String,

    /// Agent that executed the scan
    pub agent: AgentInfo,

    /// Host where scan executed
    pub host: HostInfo,

    /// When execution started (ISO 8601)
    pub started_at: String,

    /// When execution completed (ISO 8601)
    pub completed_at: String,

    /// SHA-256 hash of the result content (for integrity)
    pub content_hash: String,

    /// SHA-256 hash of collected evidence
    ///
    /// Present in all output modes. Allows verification that
    /// attestation matches full results.
    pub evidence_hash: String,

    /// Cryptographic signature (for implementations to fill)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureBlock>,
}

impl ResultEnvelope {
    /// Create a new result envelope
    pub fn new(agent: AgentInfo, host: HostInfo) -> Self {
        let now = current_timestamp();
        Self {
            result_id: generate_result_id(),
            schema_version: "1.0.0".to_string(),
            agent,
            host,
            started_at: now.clone(),
            completed_at: now,
            content_hash: String::new(),
            evidence_hash: String::new(),
            signature: None,
        }
    }

    /// Set the result ID
    pub fn with_result_id(mut self, id: impl Into<String>) -> Self {
        self.result_id = id.into();
        self
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

    /// Set the evidence hash
    pub fn with_evidence_hash(mut self, hash: impl Into<String>) -> Self {
        self.evidence_hash = hash.into();
        self
    }

    /// Add a signature
    pub fn with_signature(mut self, signature: SignatureBlock) -> Self {
        self.signature = Some(signature);
        self
    }

    /// Check if the envelope has been signed
    pub fn is_signed(&self) -> bool {
        self.signature.is_some()
    }

    /// Verify that evidence hash matches another envelope
    ///
    /// Used to verify attestation matches full results
    pub fn evidence_matches(&self, other: &ResultEnvelope) -> bool {
        !self.evidence_hash.is_empty()
            && !other.evidence_hash.is_empty()
            && self.evidence_hash == other.evidence_hash
    }
}

impl Default for ResultEnvelope {
    fn default() -> Self {
        Self::new(AgentInfo::default(), HostInfo::from_system())
    }
}

/// Cryptographic signature block
///
/// Intentionally implementation-agnostic. Implementations can use
/// TPM, HSM, software keys, or any other signing mechanism.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureBlock {
    /// Signing algorithm used
    ///
    /// Examples: "ecdsa-p256", "ed25519", "rsa-pss-sha256", "tpm-ecdsa-p256"
    pub algorithm: String,

    /// Key identifier for verification lookup
    ///
    /// Format is implementation-specific. Could be:
    /// - Key fingerprint
    /// - TPM handle
    /// - HSM key ID
    /// - Certificate subject
    pub key_id: String,

    /// Base64-encoded signature value
    pub value: String,

    /// When signature was created (ISO 8601)
    pub signed_at: String,

    /// Optional certificate chain (PEM or base64 DER)
    ///
    /// Used for certificate-based verification
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_chain: Option<Vec<String>>,
}

impl SignatureBlock {
    /// Create a new signature block
    pub fn new(
        algorithm: impl Into<String>,
        key_id: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        Self {
            algorithm: algorithm.into(),
            key_id: key_id.into(),
            value: value.into(),
            signed_at: current_timestamp(),
            certificate_chain: None,
        }
    }

    /// Set the signed timestamp
    pub fn with_signed_at(mut self, timestamp: impl Into<String>) -> Self {
        self.signed_at = timestamp.into();
        self
    }

    /// Add certificate chain
    pub fn with_certificate_chain(mut self, chain: Vec<String>) -> Self {
        self.certificate_chain = Some(chain);
        self
    }
}

/// Information about the agent that executed the scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    /// Agent identifier (unique per deployment)
    pub id: String,

    /// Agent name
    pub name: String,

    /// Agent version
    pub version: String,

    /// Agent type (e.g., "cli", "daemon", "controller")
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

    /// Create with default values
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

/// Information about the host where the scan executed
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostInfo {
    /// Host identifier
    pub id: String,

    /// Hostname
    pub hostname: String,

    /// Operating system
    pub os: String,

    /// Architecture
    pub arch: String,

    /// Fully qualified domain name (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fqdn: Option<String>,
}

impl HostInfo {
    /// Create new host info
    pub fn new(
        id: impl Into<String>,
        hostname: impl Into<String>,
        os: impl Into<String>,
        arch: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            hostname: hostname.into(),
            os: os.into(),
            arch: arch.into(),
            fqdn: None,
        }
    }

    /// Create from system information
    pub fn from_system() -> Self {
        let hostname = std::env::var("HOSTNAME")
            .or_else(|_| std::env::var("COMPUTERNAME"))
            .unwrap_or_else(|_| "unknown".to_string());

        // Generate a simple host ID from hostname
        let id = format!("host-{:x}", simple_hash(&hostname));

        Self {
            id,
            hostname,
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            fqdn: None,
        }
    }

    /// Set FQDN
    pub fn with_fqdn(mut self, fqdn: impl Into<String>) -> Self {
        self.fqdn = Some(fqdn.into());
        self
    }
}

impl Default for HostInfo {
    fn default() -> Self {
        Self::from_system()
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
    let month = (day_of_year / 30).min(11) + 1;
    let day = (day_of_year % 30) + 1;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        years, month, day, hours, minutes, seconds
    )
}

/// Generate a unique result ID
fn generate_result_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    format!("esp-result-{:x}", timestamp)
}

/// Simple hash for host ID generation (not cryptographic)
fn simple_hash(s: &str) -> u64 {
    let mut hash: u64 = 5381;
    for byte in s.bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(u64::from(byte));
    }
    hash
}

// ============================================================================
// Tests
// ============================================================================

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
    fn test_result_envelope_new() {
        let agent = AgentInfo::new("agent-1", "test-agent", "1.0.0", "cli");
        let host = HostInfo::new("host-1", "testhost", "linux", "x86_64");

        let envelope = ResultEnvelope::new(agent, host);

        assert!(envelope.result_id.starts_with("esp-result-"));
        assert_eq!(envelope.schema_version, "1.0.0");
        assert!(!envelope.is_signed());
    }

    #[test]
    fn test_signature_block() {
        let sig = SignatureBlock::new("ecdsa-p256", "key-123", "base64signature");

        assert_eq!(sig.algorithm, "ecdsa-p256");
        assert_eq!(sig.key_id, "key-123");
        assert!(!sig.signed_at.is_empty());
    }

    #[test]
    fn test_evidence_matches() {
        let agent = AgentInfo::default();
        let host = HostInfo::default();

        let envelope1 =
            ResultEnvelope::new(agent.clone(), host.clone()).with_evidence_hash("sha256:abc123");

        let envelope2 =
            ResultEnvelope::new(agent.clone(), host.clone()).with_evidence_hash("sha256:abc123");

        let envelope3 = ResultEnvelope::new(agent, host).with_evidence_hash("sha256:different");

        assert!(envelope1.evidence_matches(&envelope2));
        assert!(!envelope1.evidence_matches(&envelope3));
    }

    #[test]
    fn test_host_info_from_system() {
        let host = HostInfo::from_system();

        assert!(!host.id.is_empty());
        assert!(!host.os.is_empty());
        assert!(!host.arch.is_empty());
    }
}
