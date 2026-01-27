//! Policy identity for ESP attestations
//!
//! Provides a lightweight structure for identifying policies in attestations
//! without including CUI (Controlled Unclassified Information).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::common::{ControlMapping, Criticality};

// ============================================================================
// Known META field names (for extraction logic)
// ============================================================================

/// Fields that are parsed into typed struct fields (not put in metadata map)
pub const KNOWN_META_FIELDS: &[&str] = &[
    "esp_id",
    "platform",
    "criticality",
    "control_mapping",
    "version",
    "dsl_schema_version",
    "title",
    "description",
    "author",
    "tags",
];

// ============================================================================
// PolicyIdentity
// ============================================================================

/// Identity information for a policy in attestations
///
/// Contains the minimum information needed to identify a policy
/// and its compliance framework mappings without CUI.
///
/// ## Field Categories
///
/// - **Required**: `policy_id`, `platform`, `criticality`, `control_mappings`
/// - **Known Optional**: `version`, `dsl_schema_version`, `title`, `description`, `author`, `tags`
/// - **Extended**: Any other META fields captured in `metadata` HashMap
///
/// ## JSON Serialization
///
/// The `metadata` field uses `#[serde(flatten)]` so extended fields appear
/// at the same level as typed fields, enabling framework-agnostic output
/// that can be transformed to FedRAMP, CKLB, CMMC, etc.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyIdentity {
    // ========================================================================
    // Required fields (validated at parse time)
    // ========================================================================
    /// Policy identifier from META esp_id
    pub policy_id: String,

    /// Target platform from META
    pub platform: String,

    /// Criticality level from META
    pub criticality: Criticality,

    /// Control framework mappings
    pub control_mappings: Vec<ControlMapping>,

    // ========================================================================
    // Known optional fields (typed)
    // ========================================================================
    /// Policy version/revision
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    /// DSL schema version
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dsl_schema_version: Option<String>,

    /// Policy title
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,

    /// Policy description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Policy author
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,

    /// Policy tags
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,

    // ========================================================================
    // Extended metadata (catch-all for framework-specific fields)
    // ========================================================================
    /// Extended metadata fields not in the known list
    ///
    /// Examples: control_objective, assessment_method, implementation_status,
    /// responsible_role, control_origination, inherited_from, customer_responsibility
    #[serde(flatten, default, skip_serializing_if = "HashMap::is_empty")]
    pub metadata: HashMap<String, String>,
}

impl PolicyIdentity {
    /// Create a new policy identity with required fields only
    pub fn new(
        policy_id: impl Into<String>,
        platform: impl Into<String>,
        criticality: Criticality,
        control_mappings: Vec<ControlMapping>,
    ) -> Self {
        Self {
            policy_id: policy_id.into(),
            platform: platform.into(),
            criticality,
            control_mappings,
            version: None,
            dsl_schema_version: None,
            title: None,
            description: None,
            author: None,
            tags: Vec::new(),
            metadata: HashMap::new(),
        }
    }

    // ========================================================================
    // Builder methods for known optional fields
    // ========================================================================

    /// Set policy version
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Set DSL schema version
    pub fn with_dsl_schema_version(mut self, version: impl Into<String>) -> Self {
        self.dsl_schema_version = Some(version.into());
        self
    }

    /// Set policy title
    pub fn with_title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    /// Set policy description
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Set policy author
    pub fn with_author(mut self, author: impl Into<String>) -> Self {
        self.author = Some(author.into());
        self
    }

    /// Set policy tags
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    /// Add a single tag
    pub fn add_tag(mut self, tag: impl Into<String>) -> Self {
        self.tags.push(tag.into());
        self
    }

    // ========================================================================
    // Builder methods for extended metadata
    // ========================================================================

    /// Set extended metadata (replaces existing)
    pub fn with_metadata(mut self, metadata: HashMap<String, String>) -> Self {
        self.metadata = metadata;
        self
    }

    /// Add a single extended metadata field
    pub fn with_meta_field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }

    /// Add multiple extended metadata fields
    pub fn with_meta_fields<I, K, V>(mut self, fields: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        for (k, v) in fields {
            self.metadata.insert(k.into(), v.into());
        }
        self
    }

    // ========================================================================
    // Accessor methods
    // ========================================================================

    /// Get the primary control mapping (first one)
    pub fn primary_control(&self) -> Option<&ControlMapping> {
        self.control_mappings.first()
    }

    /// Get all framework names
    pub fn frameworks(&self) -> Vec<&str> {
        self.control_mappings
            .iter()
            .map(|m| m.framework.as_str())
            .collect()
    }

    /// Check if policy maps to a specific framework
    pub fn maps_to_framework(&self, framework: &str) -> bool {
        self.control_mappings
            .iter()
            .any(|m| m.framework.eq_ignore_ascii_case(framework))
    }

    /// Get control IDs for a specific framework
    pub fn controls_for_framework(&self, framework: &str) -> Vec<&str> {
        self.control_mappings
            .iter()
            .filter(|m| m.framework.eq_ignore_ascii_case(framework))
            .map(|m| m.control_id.as_str())
            .collect()
    }

    /// Get an extended metadata field by key
    pub fn get_meta(&self, key: &str) -> Option<&str> {
        self.metadata.get(key).map(|s| s.as_str())
    }

    /// Check if an extended metadata field exists
    pub fn has_meta(&self, key: &str) -> bool {
        self.metadata.contains_key(key)
    }

    /// Get all extended metadata keys
    pub fn meta_keys(&self) -> Vec<&str> {
        self.metadata.keys().map(|s| s.as_str()).collect()
    }
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
    fn test_policy_identity_new() {
        let mappings = vec![
            ControlMapping::new("NIST-800-53", "AC-6"),
            ControlMapping::new("CIS", "5.1.1"),
        ];

        let identity =
            PolicyIdentity::new("ssh-hardening-001", "linux", Criticality::High, mappings);

        assert_eq!(identity.policy_id, "ssh-hardening-001");
        assert_eq!(identity.platform, "linux");
        assert_eq!(identity.criticality, Criticality::High);
        assert_eq!(identity.control_mappings.len(), 2);
        assert!(identity.version.is_none());
        assert!(identity.title.is_none());
        assert!(identity.tags.is_empty());
        assert!(identity.metadata.is_empty());
    }

    #[test]
    fn test_policy_identity_with_known_optional_fields() {
        let identity = PolicyIdentity::new("test-policy", "linux", Criticality::Medium, vec![])
            .with_version("1.2.3")
            .with_dsl_schema_version("1.0.0")
            .with_title("Test Policy Title")
            .with_description("A test policy description")
            .with_author("security-team")
            .with_tags(vec!["test".to_string(), "baseline".to_string()]);

        assert_eq!(identity.version, Some("1.2.3".to_string()));
        assert_eq!(identity.dsl_schema_version, Some("1.0.0".to_string()));
        assert_eq!(identity.title, Some("Test Policy Title".to_string()));
        assert_eq!(
            identity.description,
            Some("A test policy description".to_string())
        );
        assert_eq!(identity.author, Some("security-team".to_string()));
        assert_eq!(identity.tags, vec!["test", "baseline"]);
    }

    #[test]
    fn test_policy_identity_with_extended_metadata() {
        let identity = PolicyIdentity::new("test-policy", "linux", Criticality::High, vec![])
            .with_meta_field("control_objective", "CM-6_obj.1")
            .with_meta_field("assessment_method", "TEST")
            .with_meta_field("implementation_status", "implemented");

        assert_eq!(identity.get_meta("control_objective"), Some("CM-6_obj.1"));
        assert_eq!(identity.get_meta("assessment_method"), Some("TEST"));
        assert_eq!(
            identity.get_meta("implementation_status"),
            Some("implemented")
        );
        assert!(identity.has_meta("control_objective"));
        assert!(!identity.has_meta("nonexistent"));
    }

    #[test]
    fn test_policy_identity_with_meta_fields_batch() {
        let fields = vec![
            ("responsible_role", "system-admin"),
            ("control_origination", "sp-system"),
            ("inherited_from", "AWS:us-east-1:infrastructure"),
        ];

        let identity = PolicyIdentity::new("test-policy", "linux", Criticality::High, vec![])
            .with_meta_fields(fields);

        assert_eq!(identity.get_meta("responsible_role"), Some("system-admin"));
        assert_eq!(identity.get_meta("control_origination"), Some("sp-system"));
        assert_eq!(identity.metadata.len(), 3);
    }

    #[test]
    fn test_primary_control() {
        let mappings = vec![
            ControlMapping::new("STIG", "V-242382"),
            ControlMapping::new("CIS", "1.1.1"),
        ];

        let identity = PolicyIdentity::new("test-policy", "linux", Criticality::Critical, mappings);

        let primary = identity.primary_control().unwrap();
        assert_eq!(primary.framework, "STIG");
        assert_eq!(primary.control_id, "V-242382");
    }

    #[test]
    fn test_frameworks() {
        let mappings = vec![
            ControlMapping::new("NIST-800-53", "AC-6"),
            ControlMapping::new("CIS", "5.1.1"),
            ControlMapping::new("STIG", "V-242382"),
        ];

        let identity = PolicyIdentity::new("test-policy", "linux", Criticality::High, mappings);

        let frameworks = identity.frameworks();
        assert_eq!(frameworks.len(), 3);
        assert!(frameworks.contains(&"NIST-800-53"));
        assert!(frameworks.contains(&"CIS"));
        assert!(frameworks.contains(&"STIG"));
    }

    #[test]
    fn test_maps_to_framework() {
        let mappings = vec![
            ControlMapping::new("NIST-800-53", "AC-6"),
            ControlMapping::new("CIS", "5.1.1"),
        ];

        let identity = PolicyIdentity::new("test-policy", "linux", Criticality::Medium, mappings);

        assert!(identity.maps_to_framework("NIST-800-53"));
        assert!(identity.maps_to_framework("nist-800-53")); // Case insensitive
        assert!(identity.maps_to_framework("CIS"));
        assert!(!identity.maps_to_framework("STIG"));
    }

    #[test]
    fn test_controls_for_framework() {
        let mappings = vec![
            ControlMapping::new("NIST-800-53", "AC-6"),
            ControlMapping::new("NIST-800-53", "AC-2"),
            ControlMapping::new("CIS", "5.1.1"),
        ];

        let identity = PolicyIdentity::new("test-policy", "linux", Criticality::High, mappings);

        let nist_controls = identity.controls_for_framework("NIST-800-53");
        assert_eq!(nist_controls.len(), 2);
        assert!(nist_controls.contains(&"AC-6"));
        assert!(nist_controls.contains(&"AC-2"));

        let cis_controls = identity.controls_for_framework("CIS");
        assert_eq!(cis_controls.len(), 1);
        assert!(cis_controls.contains(&"5.1.1"));
    }

    #[test]
    fn test_serialization_minimal() {
        let identity = PolicyIdentity::new(
            "test-policy",
            "linux",
            Criticality::High,
            vec![ControlMapping::new("CIS", "1.1.1")],
        );

        let json = serde_json::to_string(&identity).unwrap();

        // Should NOT contain optional fields when empty/None
        assert!(!json.contains("\"version\""));
        assert!(!json.contains("\"title\""));
        assert!(!json.contains("\"tags\""));

        // Should contain required fields
        assert!(json.contains("\"policy_id\":\"test-policy\""));
        assert!(json.contains("\"platform\":\"linux\""));
    }

    #[test]
    fn test_serialization_full() {
        let identity = PolicyIdentity::new(
            "test-policy",
            "linux",
            Criticality::High,
            vec![ControlMapping::new("NIST-800-53", "CM-6")],
        )
        .with_version("1.0.0")
        .with_title("Test Policy")
        .with_tags(vec!["baseline".to_string()])
        .with_meta_field("control_objective", "CM-6_obj.1")
        .with_meta_field("assessment_method", "TEST");

        let json = serde_json::to_string_pretty(&identity).unwrap();

        // Required fields
        assert!(json.contains("\"policy_id\": \"test-policy\""));
        assert!(json.contains("\"platform\": \"linux\""));

        // Known optional fields
        assert!(json.contains("\"version\": \"1.0.0\""));
        assert!(json.contains("\"title\": \"Test Policy\""));
        assert!(json.contains("\"tags\""));

        // Extended metadata (flattened - same level as other fields)
        assert!(json.contains("\"control_objective\": \"CM-6_obj.1\""));
        assert!(json.contains("\"assessment_method\": \"TEST\""));

        // Should NOT have a nested "metadata" key
        assert!(!json.contains("\"metadata\":"));
    }

    #[test]
    fn test_deserialization_with_extended_fields() {
        let json = r#"{
            "policy_id": "test-policy",
            "platform": "linux",
            "criticality": "high",
            "control_mappings": [{"framework": "CIS", "control_id": "1.1.1"}],
            "version": "1.0.0",
            "title": "Test Policy",
            "control_objective": "CM-6_obj.1",
            "assessment_method": "TEST",
            "custom_field": "custom_value"
        }"#;

        let identity: PolicyIdentity = serde_json::from_str(json).unwrap();

        // Required fields
        assert_eq!(identity.policy_id, "test-policy");
        assert_eq!(identity.platform, "linux");
        assert_eq!(identity.criticality, Criticality::High);

        // Known optional fields
        assert_eq!(identity.version, Some("1.0.0".to_string()));
        assert_eq!(identity.title, Some("Test Policy".to_string()));

        // Extended metadata (captured in HashMap)
        assert_eq!(identity.get_meta("control_objective"), Some("CM-6_obj.1"));
        assert_eq!(identity.get_meta("assessment_method"), Some("TEST"));
        assert_eq!(identity.get_meta("custom_field"), Some("custom_value"));
    }

    #[test]
    fn test_known_meta_fields_constant() {
        // Ensure the constant contains expected fields
        assert!(KNOWN_META_FIELDS.contains(&"esp_id"));
        assert!(KNOWN_META_FIELDS.contains(&"platform"));
        assert!(KNOWN_META_FIELDS.contains(&"criticality"));
        assert!(KNOWN_META_FIELDS.contains(&"control_mapping"));
        assert!(KNOWN_META_FIELDS.contains(&"version"));
        assert!(KNOWN_META_FIELDS.contains(&"title"));
        assert!(KNOWN_META_FIELDS.contains(&"tags"));
    }
}
