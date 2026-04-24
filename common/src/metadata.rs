//! Metadata block types for ESP policies
//!
//! The META block in ESP policies contains key-value pairs that describe
//! the policy's purpose, compliance mappings, and execution requirements.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// v1.0.0 required META fields
const V1_REQUIRED_FIELDS: &[&str] = &[
    "esp_id",
    "version",
    "dsl_schema_version",
    "platform",
    "criticality",
    "control_mapping",
    "title",
];

/// Valid criticality values
const VALID_CRITICALITY: &[&str] = &["critical", "high", "medium", "low", "info"];

/// A metadata block from an ESP policy file
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetaDataBlock {
    /// Key-value pairs from the META block
    pub fields: HashMap<String, String>,
}

impl MetaDataBlock {
    /// Create a new empty metadata block
    pub fn new() -> Self {
        Self {
            fields: HashMap::new(),
        }
    }

    /// Create from a HashMap
    pub fn from_fields(fields: HashMap<String, String>) -> Self {
        Self { fields }
    }

    /// Get a field value
    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields.get(key).map(|s| s.as_str())
    }

    /// Set a field value
    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.fields.insert(key.into(), value.into());
    }

    /// Check if a field exists
    pub fn has(&self, key: &str) -> bool {
        self.fields.contains_key(key)
    }

    /// Get the policy ID (esp_id)
    pub fn policy_id(&self) -> Option<&str> {
        self.get("esp_id")
    }

    /// Get the platform
    pub fn platform(&self) -> Option<&str> {
        self.get("platform")
    }

    /// Get the criticality
    pub fn criticality(&self) -> Option<&str> {
        self.get("criticality")
    }

    /// Get control mappings string
    pub fn control_mapping(&self) -> Option<&str> {
        self.get("control_mapping")
    }

    // === NEW v1.0.0 ACCESSORS ===

    /// Get the policy version/revision (v1.0.0 required)
    pub fn version(&self) -> Option<&str> {
        self.get("version")
    }

    /// Get the DSL schema version (v1.0.0 required)
    pub fn dsl_schema_version(&self) -> Option<&str> {
        self.get("dsl_schema_version")
    }

    /// Get the policy title (v1.0.0 required)
    pub fn title(&self) -> Option<&str> {
        self.get("title")
    }

    /// Get the agent type (v1.0.0 recommended)
    pub fn agent_type(&self) -> Option<&str> {
        self.get("agent_type")
    }

    // === LEGACY VALIDATION (unchanged) ===

    /// Check if all required fields are present (legacy)
    pub fn has_required_fields(&self) -> bool {
        self.has("esp_id")
            && self.has("platform")
            && self.has("criticality")
            && self.has("control_mapping")
    }

    /// Get list of missing required fields (legacy)
    pub fn missing_required_fields(&self) -> Vec<&'static str> {
        let required = ["esp_id", "platform", "criticality", "control_mapping"];
        required
            .iter()
            .filter(|&&field| !self.has(field))
            .copied()
            .collect()
    }

    // === v1.0.0 VALIDATION ===

    /// Validate all v1.0.0 required fields and constraints
    pub fn validate_v1(&self) -> Result<(), Vec<MetaValidationError>> {
        let mut errors = Vec::new();

        // Check required fields
        for &field in V1_REQUIRED_FIELDS {
            if self.get(field).is_none() {
                errors.push(MetaValidationError::MissingRequired(field.to_string()));
            }
        }

        // Validate criticality enum
        if let Some(crit) = self.criticality() {
            let crit_lower = crit.to_lowercase();
            if !VALID_CRITICALITY.contains(&crit_lower.as_str()) {
                errors.push(MetaValidationError::InvalidCriticality {
                    value: crit.to_string(),
                    valid: VALID_CRITICALITY.iter().map(|s| s.to_string()).collect(),
                });
            }
        }

        // Validate dsl_schema_version format (SemVer)
        if let Some(version) = self.dsl_schema_version() {
            if !is_valid_semver(version) {
                errors.push(MetaValidationError::InvalidDslVersion {
                    value: version.to_string(),
                    reason: "Must be valid SemVer (MAJOR.MINOR.PATCH)".to_string(),
                });
            }
        }

        // Validate control_mapping format
        if let Some(mapping) = self.control_mapping() {
            if let Err(reason) = validate_control_mapping_format(mapping) {
                errors.push(MetaValidationError::InvalidControlMapping {
                    value: mapping.to_string(),
                    reason,
                });
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Check if all v1.0.0 required fields are present (quick check)
    pub fn has_required_fields_v1(&self) -> bool {
        V1_REQUIRED_FIELDS.iter().all(|&field| self.has(field))
    }

    /// Get list of missing v1.0.0 required fields
    pub fn missing_required_fields_v1(&self) -> Vec<&'static str> {
        V1_REQUIRED_FIELDS
            .iter()
            .filter(|&&field| !self.has(field))
            .copied()
            .collect()
    }

    /// Build policy identity tuple for v1.0.0 (N-13)
    pub fn policy_identity(&self) -> Option<PolicyIdentity> {
        Some(PolicyIdentity {
            policy_id: self.policy_id()?.to_string(),
            policy_revision: self.version()?.to_string(),
            dsl_schema_version: self.dsl_schema_version()?.to_string(),
        })
    }
}

impl Default for MetaDataBlock {
    fn default() -> Self {
        Self::new()
    }
}

// === POLICY IDENTITY (N-13) ===

/// Policy identity tuple per N-13
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PolicyIdentity {
    pub policy_id: String,
    pub policy_revision: String,
    pub dsl_schema_version: String,
}

impl PolicyIdentity {
    /// Create a new policy identity
    pub fn new(policy_id: String, policy_revision: String, dsl_schema_version: String) -> Self {
        Self {
            policy_id,
            policy_revision,
            dsl_schema_version,
        }
    }
}

// === META VALIDATION ERRORS ===

/// META validation errors for v1.0.0
#[derive(Debug, Clone, PartialEq)]
pub enum MetaValidationError {
    /// Required field is missing
    MissingRequired(String),
    /// Criticality value is not valid
    InvalidCriticality { value: String, valid: Vec<String> },
    /// DSL schema version is not valid SemVer
    InvalidDslVersion { value: String, reason: String },
    /// Control mapping format is invalid
    InvalidControlMapping { value: String, reason: String },
}

impl std::fmt::Display for MetaValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingRequired(field) => {
                write!(f, "Missing required META field: {}", field)
            }
            Self::InvalidCriticality { value, valid } => {
                write!(
                    f,
                    "Invalid criticality '{}': must be one of {}",
                    value,
                    valid.join(", ")
                )
            }
            Self::InvalidDslVersion { value, reason } => {
                write!(f, "Invalid dsl_schema_version '{}': {}", value, reason)
            }
            Self::InvalidControlMapping { value, reason } => {
                write!(f, "Invalid control_mapping '{}': {}", value, reason)
            }
        }
    }
}

impl std::error::Error for MetaValidationError {}

// === HELPER FUNCTIONS ===

/// Validate SemVer format (MAJOR.MINOR.PATCH with optional pre-release/build)
fn is_valid_semver(version: &str) -> bool {
    // Handle empty string
    if version.is_empty() {
        return false;
    }

    // Split into at most 3 parts on '.'
    let parts: Vec<&str> = version.splitn(3, '.').collect();
    if parts.len() != 3 {
        return false;
    }

    let Some(major) = parts.first() else {
        return false;
    };
    let Some(minor) = parts.get(1) else {
        return false;
    };
    let Some(patch) = parts.get(2) else {
        return false;
    };

    // MAJOR and MINOR must be numeric
    if major.parse::<u32>().is_err() || minor.parse::<u32>().is_err() {
        return false;
    }

    // PATCH may have pre-release suffix (e.g., "0-alpha" or "0-rc.1")
    // or build metadata suffix (e.g., "0+build.123")
    // Pre-release comes before build metadata: "0-alpha+build"

    // First, strip build metadata (everything after '+')
    let without_build = patch.split('+').next().unwrap_or(patch);

    // Then, strip pre-release (everything after '-')
    let patch_base = without_build.split('-').next().unwrap_or(without_build);

    // The base patch version must be numeric
    !patch_base.is_empty() && patch_base.parse::<u32>().is_ok()
}

/// Validate control_mapping format: FRAMEWORK:CONTROL_ID (comma-separated for multiple)
fn validate_control_mapping_format(mapping: &str) -> Result<(), String> {
    for part in mapping.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if !part.contains(':') {
            return Err(format!(
                "Expected format FRAMEWORK:CONTROL_ID, got '{}'",
                part
            ));
        }
        let segments: Vec<&str> = part.splitn(2, ':').collect();

        // Use .get() to avoid indexing panics
        let framework = segments.first().copied().unwrap_or("");
        let control_id = segments.get(1).copied().unwrap_or("");

        if framework.is_empty() || control_id.is_empty() {
            return Err(format!("Invalid control mapping segment: '{}'", part));
        }
    }
    Ok(())
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
    fn test_metadata_new() {
        let meta = MetaDataBlock::new();
        assert!(meta.fields.is_empty());
    }

    #[test]
    fn test_metadata_set_get() {
        let mut meta = MetaDataBlock::new();
        meta.set("esp_id", "test-001");

        assert_eq!(meta.get("esp_id"), Some("test-001"));
        assert!(meta.has("esp_id"));
        assert!(!meta.has("nonexistent"));
    }

    #[test]
    fn test_metadata_helpers() {
        let mut fields = HashMap::new();
        fields.insert("esp_id".to_string(), "policy-001".to_string());
        fields.insert("platform".to_string(), "Kubernetes".to_string());
        fields.insert("criticality".to_string(), "high".to_string());
        fields.insert("control_mapping".to_string(), "CIS:1.1.1".to_string());

        let meta = MetaDataBlock::from_fields(fields);

        assert_eq!(meta.policy_id(), Some("policy-001"));
        assert_eq!(meta.platform(), Some("Kubernetes"));
        assert_eq!(meta.criticality(), Some("high"));
        assert!(meta.has_required_fields());
        assert!(meta.missing_required_fields().is_empty());
    }

    #[test]
    fn test_missing_required_fields() {
        let mut meta = MetaDataBlock::new();
        meta.set("esp_id", "test");

        assert!(!meta.has_required_fields());

        let missing = meta.missing_required_fields();
        assert!(missing.contains(&"platform"));
        assert!(missing.contains(&"criticality"));
        assert!(missing.contains(&"control_mapping"));
        assert!(!missing.contains(&"esp_id"));
    }

    // === v1.0.0 TESTS ===

    #[test]
    fn test_v1_accessors() {
        let mut meta = MetaDataBlock::new();
        meta.set("version", "1.2.3");
        meta.set("dsl_schema_version", "1.0.0");
        meta.set("title", "Test Policy");
        meta.set("agent_type", "linux_agent");

        assert_eq!(meta.version(), Some("1.2.3"));
        assert_eq!(meta.dsl_schema_version(), Some("1.0.0"));
        assert_eq!(meta.title(), Some("Test Policy"));
        assert_eq!(meta.agent_type(), Some("linux_agent"));
    }

    #[test]
    fn test_v1_validation_success() {
        let mut meta = MetaDataBlock::new();
        meta.set("esp_id", "policy-001");
        meta.set("version", "1.0.0");
        meta.set("dsl_schema_version", "1.0.0");
        meta.set("platform", "linux");
        meta.set("criticality", "high");
        meta.set("control_mapping", "NIST:AC-6");
        meta.set("title", "Test Policy");

        assert!(meta.validate_v1().is_ok());
        assert!(meta.has_required_fields_v1());
        assert!(meta.missing_required_fields_v1().is_empty());
    }

    #[test]
    fn test_v1_validation_missing_fields() {
        let mut meta = MetaDataBlock::new();
        meta.set("esp_id", "policy-001");
        // Missing: version, dsl_schema_version, platform, criticality, control_mapping, title

        let result = meta.validate_v1();
        assert!(result.is_err());

        let errors = result.unwrap_err();
        assert_eq!(errors.len(), 6); // 6 missing fields

        let missing = meta.missing_required_fields_v1();
        assert!(missing.contains(&"version"));
        assert!(missing.contains(&"dsl_schema_version"));
        assert!(missing.contains(&"title"));
    }

    #[test]
    fn test_v1_validation_invalid_criticality() {
        let mut meta = MetaDataBlock::new();
        meta.set("esp_id", "policy-001");
        meta.set("version", "1.0.0");
        meta.set("dsl_schema_version", "1.0.0");
        meta.set("platform", "linux");
        meta.set("criticality", "INVALID");
        meta.set("control_mapping", "NIST:AC-6");
        meta.set("title", "Test Policy");

        let result = meta.validate_v1();
        assert!(result.is_err());

        let errors = result.unwrap_err();
        assert!(errors
            .iter()
            .any(|e| matches!(e, MetaValidationError::InvalidCriticality { .. })));
    }

    #[test]
    fn test_v1_validation_invalid_dsl_version() {
        let mut meta = MetaDataBlock::new();
        meta.set("esp_id", "policy-001");
        meta.set("version", "1.0.0");
        meta.set("dsl_schema_version", "not-semver");
        meta.set("platform", "linux");
        meta.set("criticality", "high");
        meta.set("control_mapping", "NIST:AC-6");
        meta.set("title", "Test Policy");

        let result = meta.validate_v1();
        assert!(result.is_err());

        let errors = result.unwrap_err();
        assert!(errors
            .iter()
            .any(|e| matches!(e, MetaValidationError::InvalidDslVersion { .. })));
    }

    #[test]
    fn test_v1_validation_invalid_control_mapping() {
        let mut meta = MetaDataBlock::new();
        meta.set("esp_id", "policy-001");
        meta.set("version", "1.0.0");
        meta.set("dsl_schema_version", "1.0.0");
        meta.set("platform", "linux");
        meta.set("criticality", "high");
        meta.set("control_mapping", "invalid-no-colon");
        meta.set("title", "Test Policy");

        let result = meta.validate_v1();
        assert!(result.is_err());

        let errors = result.unwrap_err();
        assert!(errors
            .iter()
            .any(|e| matches!(e, MetaValidationError::InvalidControlMapping { .. })));
    }

    #[test]
    fn test_policy_identity() {
        let mut meta = MetaDataBlock::new();
        meta.set("esp_id", "policy-001");
        meta.set("version", "2.1.0");
        meta.set("dsl_schema_version", "1.0.0");

        let identity = meta.policy_identity();
        assert!(identity.is_some());

        let id = identity.unwrap();
        assert_eq!(id.policy_id, "policy-001");
        assert_eq!(id.policy_revision, "2.1.0");
        assert_eq!(id.dsl_schema_version, "1.0.0");
    }

    #[test]
    fn test_policy_identity_missing_fields() {
        let mut meta = MetaDataBlock::new();
        meta.set("esp_id", "policy-001");
        // Missing version and dsl_schema_version

        let identity = meta.policy_identity();
        assert!(identity.is_none());
    }

    #[test]
    fn test_semver_validation() {
        assert!(is_valid_semver("1.0.0"));
        assert!(is_valid_semver("0.1.0"));
        assert!(is_valid_semver("10.20.30"));
        assert!(is_valid_semver("1.0.0-alpha"));
        assert!(is_valid_semver("1.0.0-rc.1"));
        assert!(is_valid_semver("1.0.0+build.123"));
        assert!(is_valid_semver("1.0.0-alpha+build"));

        assert!(!is_valid_semver("1.0"));
        assert!(!is_valid_semver("1"));
        assert!(!is_valid_semver("1.0.0.0"));
        assert!(!is_valid_semver("v1.0.0"));
        assert!(!is_valid_semver("not-semver"));
        assert!(!is_valid_semver(""));
    }

    #[test]
    fn test_control_mapping_validation() {
        assert!(validate_control_mapping_format("NIST:AC-6").is_ok());
        assert!(validate_control_mapping_format("CIS:1.1.1").is_ok());
        assert!(validate_control_mapping_format("NIST:AC-6,CIS:1.1.1").is_ok());
        assert!(validate_control_mapping_format("DISA-STIG:SV-253284").is_ok());

        assert!(validate_control_mapping_format("invalid").is_err());
        assert!(validate_control_mapping_format(":no-framework").is_err());
        assert!(validate_control_mapping_format("no-control:").is_err());
    }

    #[test]
    fn test_criticality_case_insensitive() {
        let mut meta = MetaDataBlock::new();
        meta.set("esp_id", "policy-001");
        meta.set("version", "1.0.0");
        meta.set("dsl_schema_version", "1.0.0");
        meta.set("platform", "linux");
        meta.set("criticality", "HIGH"); // uppercase
        meta.set("control_mapping", "NIST:AC-6");
        meta.set("title", "Test Policy");

        assert!(meta.validate_v1().is_ok());
    }
}
