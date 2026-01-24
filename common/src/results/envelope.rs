//! Result envelope types
//!
//! The envelope wraps all result types with metadata about who ran what,
//! where, and when. Includes signature block for cryptographic signing
//! and identity status for PKI bootstrap tracking.
//!
//! ## Schema Reference
//!
//! Implements Sections 3.2-3.6 of ESP v1.1.0 Canonical Execution Schema.

use serde::{Deserialize, Serialize};

use super::identity_status::IdentityStatus;
use super::transparency::TransparencyProof;

// ============================================================================
// Constants
// ============================================================================

/// Current schema version
pub const SCHEMA_VERSION: &str = "1.1.0";

// ============================================================================
// ResultEnvelope
// ============================================================================

/// Universal envelope for all ESP result types
///
/// Contains metadata about the scan execution, cryptographic hashes for
/// integrity verification, optional signature, and identity status.
///
/// ## Schema Version
///
/// The `schema_version` field indicates which version of the ESP schema
/// this result conforms to. As of v1.1.0, the envelope includes:
/// - `identity_status` (required) - PKI bootstrap status
/// - `signature.transparency` (optional) - Certificate transparency proof
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

    /// Cryptographic signature (present when PKI identity available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<SignatureBlock>,

    /// Identity bootstrap status
    ///
    /// Indicates whether PKI identity was established and provides
    /// diagnostic information if bootstrap failed.
    pub identity_status: IdentityStatus,
}

impl ResultEnvelope {
    /// Create a new result envelope
    ///
    /// Creates an envelope with default identity status. Use `with_identity_status()`
    /// to set the actual status before building the final result.
    pub fn new(agent: AgentInfo, host: HostInfo) -> Self {
        let now = current_timestamp();
        Self {
            result_id: generate_result_id(),
            schema_version: SCHEMA_VERSION.to_string(),
            agent,
            host,
            started_at: now.clone(),
            completed_at: now,
            content_hash: String::new(),
            evidence_hash: String::new(),
            signature: None,
            identity_status: IdentityStatus::default(),
        }
    }

    /// Create a new result envelope with explicit identity status
    pub fn with_identity(
        agent: AgentInfo,
        host: HostInfo,
        identity_status: IdentityStatus,
    ) -> Self {
        let now = current_timestamp();
        Self {
            result_id: generate_result_id(),
            schema_version: SCHEMA_VERSION.to_string(),
            agent,
            host,
            started_at: now.clone(),
            completed_at: now,
            content_hash: String::new(),
            evidence_hash: String::new(),
            signature: None,
            identity_status,
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

    /// Set the identity status
    pub fn with_identity_status(mut self, identity_status: IdentityStatus) -> Self {
        self.identity_status = identity_status;
        self
    }

    /// Check if the envelope has been signed
    pub fn is_signed(&self) -> bool {
        self.signature.is_some()
    }

    /// Check if identity was successfully bootstrapped
    pub fn is_identity_bootstrapped(&self) -> bool {
        self.identity_status.is_bootstrapped()
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

// ============================================================================
// SignatureBlock
// ============================================================================

/// Cryptographic signature block
///
/// Contains a digital signature over the envelope's content_hash and
/// evidence_hash fields, along with the certificate chain and transparency
/// proof for PKI verification.
///
/// ## Signed Data
///
/// The signature covers `SHA256(content_hash || evidence_hash)` where
/// `||` denotes concatenation of the hash strings.
///
/// ## Verification Levels
///
/// - **Level 0** (Self-contained): Public key included; verifier trusts delivery channel
/// - **Level 1** (PKI): Certificate chain validated against trusted Root CA
/// - **Level 2** (PKI + Transparency): Chain validated AND transparency proof verified
///
/// ## Schema Reference
///
/// Implements Section 3.5 of ESP v1.1.0 Canonical Execution Schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureBlock {
    /// Unique identifier for the signer
    ///
    /// Format depends on identity source:
    /// - PKI: SAN URI from certificate (e.g., `scanset://prod/aws/account/123/workload/agent`)
    /// - Legacy TPM: `tpm:sha256:<fingerprint>`
    /// - Legacy Software: `software:sha256:<fingerprint>`
    pub signer_id: String,

    /// Type of signer
    ///
    /// Currently always `"agent"`. Reserved for future use:
    /// `"controller"`, `"assessor"`, `"witness"`
    pub signer_type: String,

    /// Signing algorithm identifier
    ///
    /// Values:
    /// - `"ecdsa-p256"` - ECDSA with NIST P-256 curve (standard)
    /// - `"tpm-ecdsa-p256"` - TPM-backed ECDSA (legacy)
    pub algorithm: String,

    /// Base64-encoded public key (DER format)
    ///
    /// Included for self-contained (Level 0) verification.
    pub public_key: String,

    /// Base64-encoded signature value (DER format)
    pub signature: String,

    /// Key identifier for external lookup
    ///
    /// Format depends on identity source:
    /// - PKI: `pki:cert:<certificate_serial>`
    /// - Legacy TPM: `tpm:ephemeral:<key_name>`
    /// - Legacy Software: `software:ephemeral:<uuid>`
    pub key_id: String,

    /// When signature was created (ISO 8601)
    ///
    /// Note: This timestamp is NOT part of the signed data.
    pub signed_at: String,

    /// Fields covered by this signature
    ///
    /// Standard value: `["content_hash", "evidence_hash"]`
    /// The signature is over `SHA256(content_hash || evidence_hash)`.
    pub covers: Vec<String>,

    /// X.509 certificate chain (PEM encoded)
    ///
    /// For PKI (Level 1+) verification. Chain order:
    /// - `[0]` = leaf (workload signing certificate)
    /// - `[1]` = intermediate CA (Workload CA)
    /// - `[2]` = intermediate CA (Trust System IA)
    /// - Root CA is typically in the verifier's trust store
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate_chain: Option<Vec<String>>,

    /// Transparency proof from certificate enrollment
    ///
    /// Provides cryptographic proof that the signing certificate was
    /// logged to the Trust System's append-only transparency log.
    /// Required for Level 2 verification.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transparency: Option<TransparencyProof>,
}

impl SignatureBlock {
    /// Create a new signature block (basic, without PKI)
    ///
    /// Use `with_pki()` for signatures with certificate chain and transparency proof.
    ///
    /// # Arguments
    ///
    /// * `signer_id` - Unique identifier for the signer
    /// * `algorithm` - Signing algorithm (e.g., "ecdsa-p256")
    /// * `public_key` - Base64-encoded public key
    /// * `signature` - Base64-encoded signature value
    /// * `key_id` - Key identifier for external lookup
    /// * `covers` - Fields covered by signature
    pub fn new(
        signer_id: impl Into<String>,
        algorithm: impl Into<String>,
        public_key: impl Into<String>,
        signature: impl Into<String>,
        key_id: impl Into<String>,
        covers: Vec<String>,
    ) -> Self {
        Self {
            signer_id: signer_id.into(),
            signer_type: "agent".to_string(),
            algorithm: algorithm.into(),
            public_key: public_key.into(),
            signature: signature.into(),
            key_id: key_id.into(),
            signed_at: current_timestamp(),
            covers,
            certificate_chain: None,
            transparency: None,
        }
    }

    /// Create a signature block with full PKI identity
    ///
    /// Includes certificate chain and transparency proof for Level 2 verification.
    ///
    /// # Arguments
    ///
    /// * `signer_id` - SAN URI from the workload certificate
    /// * `algorithm` - Signing algorithm (typically "ecdsa-p256")
    /// * `public_key` - Base64-encoded public key (DER format)
    /// * `signature` - Base64-encoded signature value (DER format)
    /// * `key_id` - Certificate serial (e.g., "pki:cert:1234567890abcdef")
    /// * `signed_at` - ISO 8601 timestamp when signature was created
    /// * `certificate_chain` - PEM-encoded certificate chain
    /// * `transparency` - Transparency proof from certificate enrollment
    #[allow(clippy::too_many_arguments)]
    pub fn with_pki(
        signer_id: impl Into<String>,
        algorithm: impl Into<String>,
        public_key: impl Into<String>,
        signature: impl Into<String>,
        key_id: impl Into<String>,
        signed_at: impl Into<String>,
        certificate_chain: Vec<String>,
        transparency: TransparencyProof,
    ) -> Self {
        Self {
            signer_id: signer_id.into(),
            signer_type: "agent".to_string(),
            algorithm: algorithm.into(),
            public_key: public_key.into(),
            signature: signature.into(),
            key_id: key_id.into(),
            signed_at: signed_at.into(),
            covers: Self::standard_covers(),
            certificate_chain: Some(certificate_chain),
            transparency: Some(transparency),
        }
    }

    /// Set the signed timestamp explicitly
    pub fn with_signed_at(mut self, timestamp: impl Into<String>) -> Self {
        self.signed_at = timestamp.into();
        self
    }

    /// Add certificate chain for PKI verification
    pub fn with_certificate_chain(mut self, chain: Vec<String>) -> Self {
        self.certificate_chain = Some(chain);
        self
    }

    /// Add transparency proof
    pub fn with_transparency(mut self, transparency: TransparencyProof) -> Self {
        self.transparency = Some(transparency);
        self
    }

    /// Create standard covers for envelope hash signing
    pub fn standard_covers() -> Vec<String> {
        vec!["content_hash".to_string(), "evidence_hash".to_string()]
    }

    /// Check if this signature has PKI identity (certificate chain)
    pub fn has_pki(&self) -> bool {
        self.certificate_chain.is_some()
    }

    /// Check if this signature has transparency proof
    pub fn has_transparency(&self) -> bool {
        self.transparency.is_some()
    }

    /// Check if this signature has full Level 2 verification support
    pub fn has_level2_support(&self) -> bool {
        self.has_pki() && self.has_transparency()
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

// ============================================================================
// HostInfo
// ============================================================================

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
        assert_eq!(envelope.schema_version, "1.1.0");
        assert!(!envelope.is_signed());
        assert!(!envelope.is_identity_bootstrapped());
    }

    #[test]
    fn test_result_envelope_with_identity() {
        let agent = AgentInfo::default();
        let host = HostInfo::default();
        let identity = IdentityStatus::success("scanset://test");

        let envelope = ResultEnvelope::with_identity(agent, host, identity);

        assert!(envelope.is_identity_bootstrapped());
        assert_eq!(envelope.identity_status.signer_id, "scanset://test");
    }

    #[test]
    fn test_result_envelope_with_identity_status() {
        let envelope = ResultEnvelope::default()
            .with_identity_status(IdentityStatus::success("scanset://test"));

        assert!(envelope.is_identity_bootstrapped());
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

    #[test]
    fn test_signature_block_new() {
        let sig = SignatureBlock::new(
            "tpm:sha256:abcd1234",
            "tpm-ecdsa-p256",
            "BASE64_PUBLIC_KEY",
            "BASE64_SIGNATURE",
            "tpm:ephemeral:ESP_EPHEMERAL_test",
            SignatureBlock::standard_covers(),
        );

        assert_eq!(sig.signer_id, "tpm:sha256:abcd1234");
        assert_eq!(sig.signer_type, "agent");
        assert_eq!(sig.algorithm, "tpm-ecdsa-p256");
        assert_eq!(sig.public_key, "BASE64_PUBLIC_KEY");
        assert_eq!(sig.signature, "BASE64_SIGNATURE");
        assert_eq!(sig.covers, vec!["content_hash", "evidence_hash"]);
        assert!(!sig.signed_at.is_empty());
        assert!(sig.certificate_chain.is_none());
        assert!(sig.transparency.is_none());
        assert!(!sig.has_pki());
        assert!(!sig.has_transparency());
        assert!(!sig.has_level2_support());
    }

    #[test]
    fn test_signature_block_with_pki() {
        let transparency = TransparencyProof::from_parts(
            47,
            100,
            "root_hash",
            vec!["h1".to_string(), "h2".to_string()],
        );

        let sig = SignatureBlock::with_pki(
            "scanset://prod/aws/account/123/workload/agent",
            "ecdsa-p256",
            "BASE64_PUBLIC_KEY",
            "BASE64_SIGNATURE",
            "pki:cert:1234567890abcdef",
            "2026-01-24T12:00:00Z",
            vec!["CERT1".to_string(), "CERT2".to_string()],
            transparency,
        );

        assert_eq!(
            sig.signer_id,
            "scanset://prod/aws/account/123/workload/agent"
        );
        assert_eq!(sig.algorithm, "ecdsa-p256");
        assert_eq!(sig.key_id, "pki:cert:1234567890abcdef");
        assert_eq!(sig.signed_at, "2026-01-24T12:00:00Z");
        assert!(sig.has_pki());
        assert!(sig.has_transparency());
        assert!(sig.has_level2_support());

        let chain = sig.certificate_chain.unwrap();
        assert_eq!(chain.len(), 2);

        let transparency = sig.transparency.unwrap();
        assert_eq!(transparency.log_index, 47);
    }

    #[test]
    fn test_signature_block_with_certificate_chain() {
        let sig = SignatureBlock::new(
            "software:sha256:efgh5678",
            "ecdsa-p256",
            "BASE64_PUBLIC_KEY",
            "BASE64_SIGNATURE",
            "software:ephemeral:test-uuid",
            SignatureBlock::standard_covers(),
        )
        .with_certificate_chain(vec!["CERT1".to_string(), "CERT2".to_string()]);

        assert!(sig.certificate_chain.is_some());
        assert_eq!(sig.certificate_chain.unwrap().len(), 2);
    }

    #[test]
    fn test_signature_block_with_transparency() {
        let transparency = TransparencyProof::from_parts(42, 50, "root", vec![]);

        let sig = SignatureBlock::new(
            "test",
            "ecdsa-p256",
            "key",
            "sig",
            "key_id",
            SignatureBlock::standard_covers(),
        )
        .with_transparency(transparency);

        assert!(sig.has_transparency());
        assert_eq!(sig.transparency.unwrap().log_index, 42);
    }

    #[test]
    fn test_envelope_serialization_with_identity_status() {
        let agent = AgentInfo::new("agent-1", "test", "1.0.0", "cli");
        let host = HostInfo::new("host-1", "testhost", "linux", "x86_64");
        let identity = IdentityStatus::success("scanset://test");

        let envelope = ResultEnvelope::with_identity(agent, host, identity)
            .with_content_hash("sha256:content")
            .with_evidence_hash("sha256:evidence");

        let json = serde_json::to_string_pretty(&envelope).unwrap();

        assert!(json.contains("\"schema_version\": \"1.1.0\""));
        assert!(json.contains("\"identity_status\":"));
        assert!(json.contains("\"bootstrapped\": true"));
        assert!(json.contains("\"signer_id\": \"scanset://test\""));

        // signature should be omitted when None
        assert!(!json.contains("\"signature\":"));

        let parsed: ResultEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.schema_version, "1.1.0");
        assert!(parsed.identity_status.is_bootstrapped());
    }

    #[test]
    fn test_envelope_serialization_with_failed_identity() {
        let envelope = ResultEnvelope::default().with_identity_status(IdentityStatus::failed(
            "unsigned:agent:test-host",
            "Connection refused",
            "BOOTSTRAP_CONNECTION_FAILED",
        ));

        let json = serde_json::to_string(&envelope).unwrap();

        assert!(json.contains("\"bootstrapped\":false"));
        assert!(json.contains("BOOTSTRAP_CONNECTION_FAILED"));

        let parsed: ResultEnvelope = serde_json::from_str(&json).unwrap();
        assert!(!parsed.identity_status.is_bootstrapped());
        assert!(parsed.identity_status.has_error());
    }

    #[test]
    fn test_signature_block_serialization_with_transparency() {
        let transparency = TransparencyProof::from_parts(
            47,
            100,
            "f6e5d4c3b2a1",
            vec!["abc123".to_string(), "def456".to_string()],
        );

        let sig = SignatureBlock::with_pki(
            "scanset://test",
            "ecdsa-p256",
            "pubkey",
            "signature",
            "pki:cert:abc",
            "2026-01-24T12:00:00Z",
            vec!["CERT".to_string()],
            transparency,
        );

        let json = serde_json::to_string_pretty(&sig).unwrap();

        assert!(json.contains("\"transparency\":"));
        assert!(json.contains("\"log_index\": 47"));
        assert!(json.contains("\"inclusion_proof\":"));
        assert!(json.contains("\"certificate_chain\":"));

        let parsed: SignatureBlock = serde_json::from_str(&json).unwrap();
        assert!(parsed.has_transparency());
        assert_eq!(parsed.transparency.unwrap().log_index, 47);
    }

    #[test]
    fn test_schema_version_constant() {
        assert_eq!(SCHEMA_VERSION, "1.1.0");
    }
}
