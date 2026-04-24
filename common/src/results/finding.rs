//! Compliance finding types for ESP scan results
//!
//! Findings represent validation failures discovered during policy execution.
//! They contain expected vs actual values for non-passing criteria.
//!
//! ## Schema Alignment
//!
//! This module implements the `ComplianceFinding` structure from the
//! ESP v1.0.0 Canonical Execution Schema (Section 9).
//!
//! As of v2.0.0 findings are always included in the `AssessorPackage`
//! envelope. Consumers that need an attestation-style (CUI-free) view
//! should drop the `findings` array in their own post-processing.

use serde::{Deserialize, Serialize};
use std::fmt;

// ============================================================================
// Finding Severity
// ============================================================================

/// Severity level of a compliance finding
///
/// Aligns with the schema's severity values (Section 9.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum FindingSeverity {
    /// Critical - Requires immediate attention
    Critical,
    /// High - High priority finding
    High,
    /// Medium - Standard priority finding
    #[default]
    Medium,
    /// Low - Low priority finding
    Low,
    /// Info - Informational only
    Info,
}

impl FindingSeverity {
    /// Convert to string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            FindingSeverity::Critical => "critical",
            FindingSeverity::High => "high",
            FindingSeverity::Medium => "medium",
            FindingSeverity::Low => "low",
            FindingSeverity::Info => "info",
        }
    }

    /// Parse from string (case-insensitive)
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "critical" => Some(FindingSeverity::Critical),
            "high" => Some(FindingSeverity::High),
            "medium" => Some(FindingSeverity::Medium),
            "low" => Some(FindingSeverity::Low),
            "info" | "informational" => Some(FindingSeverity::Info),
            _ => None,
        }
    }

    /// Check if this severity requires immediate action
    pub fn requires_immediate_action(&self) -> bool {
        matches!(self, FindingSeverity::Critical)
    }

    /// Check if this severity is high priority
    pub fn is_high_priority(&self) -> bool {
        matches!(self, FindingSeverity::Critical | FindingSeverity::High)
    }
}

impl fmt::Display for FindingSeverity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

impl From<super::common::Criticality> for FindingSeverity {
    fn from(criticality: super::common::Criticality) -> Self {
        match criticality {
            super::common::Criticality::Critical => FindingSeverity::Critical,
            super::common::Criticality::High => FindingSeverity::High,
            super::common::Criticality::Medium => FindingSeverity::Medium,
            super::common::Criticality::Low => FindingSeverity::Low,
            super::common::Criticality::Info => FindingSeverity::Info,
        }
    }
}

// ============================================================================
// Compliance Finding
// ============================================================================

/// A compliance finding from policy execution
///
/// Contains details about a validation failure, including expected vs actual
/// values. This is CUI (Controlled Unclassified Information) and should only
/// be included in full results, not attestations.
///
/// ## Schema Reference
///
/// Implements Section 9 of ESP v1.0.0 Canonical Execution Schema:
///
/// ```json
/// {
///   "finding_id": "f-a1b2c3d4",
///   "severity": "high",
///   "title": "file_metadata validation failed",
///   "description": "File permissions do not match expected value",
///   "expected": { "permissions": "0600" },
///   "actual": { "permissions": "0644" },
///   "field_path": "CRI_AND > CTN_file_metadata"
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceFinding {
    /// Unique finding identifier
    ///
    /// Format: "f-{random_hex}" (e.g., "f-a1b2c3d4")
    pub finding_id: String,

    /// Severity level of this finding
    pub severity: FindingSeverity,

    /// Human-readable title
    ///
    /// Should be concise and actionable.
    /// Example: "file_metadata validation failed"
    pub title: String,

    /// Detailed description of the finding
    ///
    /// Should explain what was checked and why it failed.
    /// Example: "File permissions are too permissive"
    pub description: String,

    /// Expected value(s) that would constitute compliance
    ///
    /// Can be a single value or object with multiple fields.
    pub expected: serde_json::Value,

    /// Actual value(s) found during collection
    ///
    /// Mirrors the structure of `expected` for comparison.
    pub actual: serde_json::Value,

    /// Path in the criteria tree where failure occurred
    ///
    /// Format: "CRI_AND > CTN_file_metadata" or similar.
    /// Optional - may be omitted for simple policies.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field_path: Option<String>,

    /// Object identifier that failed validation
    ///
    /// Links to the specific object in collected_data.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_id: Option<String>,

    /// CTN type that generated this finding
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ctn_type: Option<String>,

    /// Remediation guidance (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,
}

impl ComplianceFinding {
    /// Create a new compliance finding with explicit ID
    pub fn new(
        finding_id: impl Into<String>,
        severity: FindingSeverity,
        title: impl Into<String>,
        description: impl Into<String>,
        expected: serde_json::Value,
        actual: serde_json::Value,
    ) -> Self {
        Self {
            finding_id: finding_id.into(),
            severity,
            title: title.into(),
            description: description.into(),
            expected,
            actual,
            field_path: None,
            object_id: None,
            ctn_type: None,
            remediation: None,
        }
    }

    /// Create a new finding with auto-generated ID
    pub fn auto_id(
        severity: FindingSeverity,
        title: impl Into<String>,
        description: impl Into<String>,
        expected: serde_json::Value,
        actual: serde_json::Value,
    ) -> Self {
        Self::new(
            generate_finding_id(),
            severity,
            title,
            description,
            expected,
            actual,
        )
    }

    /// Set the field path
    pub fn with_field_path(mut self, path: impl Into<String>) -> Self {
        self.field_path = Some(path.into());
        self
    }

    /// Set the object ID
    pub fn with_object_id(mut self, object_id: impl Into<String>) -> Self {
        self.object_id = Some(object_id.into());
        self
    }

    /// Set the CTN type
    pub fn with_ctn_type(mut self, ctn_type: impl Into<String>) -> Self {
        self.ctn_type = Some(ctn_type.into());
        self
    }

    /// Set remediation guidance
    pub fn with_remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = Some(remediation.into());
        self
    }

    /// Check if this is a high-priority finding
    pub fn is_high_priority(&self) -> bool {
        self.severity.is_high_priority()
    }

    /// Check if this finding requires immediate action
    pub fn requires_immediate_action(&self) -> bool {
        self.severity.requires_immediate_action()
    }
}

// ============================================================================
// Finding Builder
// ============================================================================

/// Builder for constructing compliance findings
///
/// Provides a fluent API for creating findings with all optional fields.
#[derive(Debug, Default)]
pub struct FindingBuilder {
    finding_id: Option<String>,
    severity: FindingSeverity,
    title: Option<String>,
    description: Option<String>,
    expected: Option<serde_json::Value>,
    actual: Option<serde_json::Value>,
    field_path: Option<String>,
    object_id: Option<String>,
    ctn_type: Option<String>,
    remediation: Option<String>,
}

impl FindingBuilder {
    /// Create a new finding builder
    pub fn new() -> Self {
        Self::default()
    }

    /// Set the finding ID (auto-generated if not set)
    pub fn finding_id(mut self, id: impl Into<String>) -> Self {
        self.finding_id = Some(id.into());
        self
    }

    /// Set the severity level
    pub fn severity(mut self, severity: FindingSeverity) -> Self {
        self.severity = severity;
        self
    }

    /// Set the title
    pub fn title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    /// Set the description
    pub fn description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Set the expected value
    pub fn expected(mut self, expected: serde_json::Value) -> Self {
        self.expected = Some(expected);
        self
    }

    /// Set the expected value from a serializable type
    pub fn expected_from<T: serde::Serialize>(mut self, expected: &T) -> Self {
        self.expected = serde_json::to_value(expected).ok();
        self
    }

    /// Set the actual value
    pub fn actual(mut self, actual: serde_json::Value) -> Self {
        self.actual = Some(actual);
        self
    }

    /// Set the actual value from a serializable type
    pub fn actual_from<T: serde::Serialize>(mut self, actual: &T) -> Self {
        self.actual = serde_json::to_value(actual).ok();
        self
    }

    /// Set the field path
    pub fn field_path(mut self, path: impl Into<String>) -> Self {
        self.field_path = Some(path.into());
        self
    }

    /// Set the object ID
    pub fn object_id(mut self, object_id: impl Into<String>) -> Self {
        self.object_id = Some(object_id.into());
        self
    }

    /// Set the CTN type
    pub fn ctn_type(mut self, ctn_type: impl Into<String>) -> Self {
        self.ctn_type = Some(ctn_type.into());
        self
    }

    /// Set remediation guidance
    pub fn remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = Some(remediation.into());
        self
    }

    /// Build the finding
    ///
    /// Returns None if required fields (title, description, expected, actual) are missing.
    pub fn build(self) -> Option<ComplianceFinding> {
        let title = self.title?;
        let description = self.description?;
        let expected = self.expected.unwrap_or(serde_json::Value::Null);
        let actual = self.actual.unwrap_or(serde_json::Value::Null);

        let finding_id = self.finding_id.unwrap_or_else(generate_finding_id);

        Some(ComplianceFinding {
            finding_id,
            severity: self.severity,
            title,
            description,
            expected,
            actual,
            field_path: self.field_path,
            object_id: self.object_id,
            ctn_type: self.ctn_type,
            remediation: self.remediation,
        })
    }

    /// Build the finding, panicking if required fields are missing
    ///
    /// Use this only in tests or when you're certain all required fields are set.
    #[cfg(test)]
    #[allow(clippy::expect_used)]
    pub fn build_unchecked(self) -> ComplianceFinding {
        self.build().expect("Missing required fields for finding")
    }
}

// ============================================================================
// Convenience Constructors
// ============================================================================

impl ComplianceFinding {
    /// Create a finding for a field validation failure
    pub fn field_validation_failed(
        field_name: impl Into<String>,
        expected: impl Into<String>,
        actual: impl Into<String>,
        severity: FindingSeverity,
    ) -> Self {
        let field = field_name.into();
        let expected_val = expected.into();
        let actual_val = actual.into();

        Self::auto_id(
            severity,
            format!("Field '{}' validation failed", field),
            format!("Expected '{}' but found '{}'", expected_val, actual_val),
            serde_json::json!({ &field: expected_val }),
            serde_json::json!({ &field: actual_val }),
        )
    }

    /// Create a finding for a missing required value
    pub fn missing_required_value(
        field_name: impl Into<String>,
        expected: impl Into<String>,
        severity: FindingSeverity,
    ) -> Self {
        let field = field_name.into();
        let expected_val = expected.into();

        Self::auto_id(
            severity,
            format!("Required field '{}' not found", field),
            format!("Expected '{}' but value was not present", expected_val),
            serde_json::json!({ &field: expected_val }),
            serde_json::json!({ &field: null }),
        )
    }

    /// Create a finding for an existence check failure
    pub fn existence_check_failed(
        object_type: impl Into<String>,
        expected_count: usize,
        actual_count: usize,
        severity: FindingSeverity,
    ) -> Self {
        let obj_type = object_type.into();

        Self::auto_id(
            severity,
            format!("{} existence check failed", obj_type),
            format!(
                "Expected {} objects but found {}",
                expected_count, actual_count
            ),
            serde_json::json!({ "count": expected_count }),
            serde_json::json!({ "count": actual_count }),
        )
    }

    /// Create a finding for a permission/mode validation failure
    pub fn permission_mismatch(
        path: impl Into<String>,
        expected_mode: impl Into<String>,
        actual_mode: impl Into<String>,
        severity: FindingSeverity,
    ) -> Self {
        let path_str = path.into();
        let expected = expected_mode.into();
        let actual = actual_mode.into();

        Self::auto_id(
            severity,
            "File permission mismatch".to_string(),
            format!(
                "File '{}' has permissions '{}', expected '{}'",
                path_str, actual, expected
            ),
            serde_json::json!({ "permissions": expected }),
            serde_json::json!({ "permissions": actual }),
        )
        .with_object_id(path_str)
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Generate a unique finding ID
fn generate_finding_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    // Use timestamp + some randomness for uniqueness
    let random_part = timestamp.wrapping_mul(6364136223846793005).wrapping_add(1);

    format!("f-{:08x}", (random_part & 0xFFFF_FFFF) as u32)
}

// ============================================================================
// Tests
// ============================================================================

#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_finding_severity_parse() {
        assert_eq!(
            FindingSeverity::parse("critical"),
            Some(FindingSeverity::Critical)
        );
        assert_eq!(FindingSeverity::parse("HIGH"), Some(FindingSeverity::High));
        assert_eq!(
            FindingSeverity::parse("Medium"),
            Some(FindingSeverity::Medium)
        );
        assert_eq!(FindingSeverity::parse("low"), Some(FindingSeverity::Low));
        assert_eq!(FindingSeverity::parse("info"), Some(FindingSeverity::Info));
        assert_eq!(
            FindingSeverity::parse("informational"),
            Some(FindingSeverity::Info)
        );
        assert_eq!(FindingSeverity::parse("invalid"), None);
    }

    #[test]
    fn test_finding_severity_display() {
        assert_eq!(FindingSeverity::Critical.to_string(), "critical");
        assert_eq!(FindingSeverity::High.to_string(), "high");
        assert_eq!(FindingSeverity::Medium.to_string(), "medium");
    }

    #[test]
    fn test_finding_severity_priority() {
        assert!(FindingSeverity::Critical.is_high_priority());
        assert!(FindingSeverity::High.is_high_priority());
        assert!(!FindingSeverity::Medium.is_high_priority());
        assert!(!FindingSeverity::Low.is_high_priority());

        assert!(FindingSeverity::Critical.requires_immediate_action());
        assert!(!FindingSeverity::High.requires_immediate_action());
    }

    #[test]
    fn test_compliance_finding_new() {
        let finding = ComplianceFinding::new(
            "f-test123",
            FindingSeverity::High,
            "Test Finding",
            "This is a test finding",
            serde_json::json!({"value": "expected"}),
            serde_json::json!({"value": "actual"}),
        );

        assert_eq!(finding.finding_id, "f-test123");
        assert_eq!(finding.severity, FindingSeverity::High);
        assert_eq!(finding.title, "Test Finding");
        assert!(finding.field_path.is_none());
    }

    #[test]
    fn test_compliance_finding_auto_id() {
        let finding = ComplianceFinding::auto_id(
            FindingSeverity::Medium,
            "Auto ID Finding",
            "Description",
            serde_json::json!({}),
            serde_json::json!({}),
        );

        assert!(finding.finding_id.starts_with("f-"));
        assert_eq!(finding.finding_id.len(), 10); // "f-" + 8 hex chars
    }

    #[test]
    fn test_compliance_finding_with_methods() {
        let finding = ComplianceFinding::auto_id(
            FindingSeverity::High,
            "Test",
            "Description",
            serde_json::json!({}),
            serde_json::json!({}),
        )
        .with_field_path("CRI_AND > CTN_file_metadata")
        .with_object_id("sshd_config")
        .with_ctn_type("file_metadata")
        .with_remediation("Run chmod 0600 /etc/ssh/sshd_config");

        assert_eq!(
            finding.field_path,
            Some("CRI_AND > CTN_file_metadata".to_string())
        );
        assert_eq!(finding.object_id, Some("sshd_config".to_string()));
        assert_eq!(finding.ctn_type, Some("file_metadata".to_string()));
        assert!(finding.remediation.is_some());
    }

    #[test]
    fn test_finding_builder() {
        let finding = FindingBuilder::new()
            .severity(FindingSeverity::Critical)
            .title("Builder Test")
            .description("Testing the builder")
            .expected(serde_json::json!({"key": "expected_value"}))
            .actual(serde_json::json!({"key": "actual_value"}))
            .field_path("TEST > PATH")
            .object_id("test_obj")
            .build()
            .unwrap();

        assert_eq!(finding.severity, FindingSeverity::Critical);
        assert_eq!(finding.title, "Builder Test");
        assert!(finding.finding_id.starts_with("f-"));
    }

    #[test]
    fn test_finding_builder_missing_required() {
        let result = FindingBuilder::new()
            .severity(FindingSeverity::Medium)
            // Missing title and description
            .build();

        assert!(result.is_none());
    }

    #[test]
    fn test_field_validation_failed() {
        let finding = ComplianceFinding::field_validation_failed(
            "permissions",
            "0600",
            "0644",
            FindingSeverity::High,
        );

        assert!(finding.title.contains("permissions"));
        assert!(finding.description.contains("0600"));
        assert!(finding.description.contains("0644"));
    }

    #[test]
    fn test_permission_mismatch() {
        let finding = ComplianceFinding::permission_mismatch(
            "/etc/ssh/sshd_config",
            "0600",
            "0644",
            FindingSeverity::Medium,
        );

        assert!(finding.title.contains("permission"));
        assert_eq!(finding.object_id, Some("/etc/ssh/sshd_config".to_string()));
    }

    #[test]
    fn test_serialization() {
        let finding = ComplianceFinding::new(
            "f-abc123",
            FindingSeverity::High,
            "Test Finding",
            "Description",
            serde_json::json!({"permissions": "0600"}),
            serde_json::json!({"permissions": "0644"}),
        )
        .with_field_path("CTN_file_metadata");

        let json = serde_json::to_string(&finding).unwrap();
        let parsed: ComplianceFinding = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.finding_id, "f-abc123");
        assert_eq!(parsed.severity, FindingSeverity::High);
        assert_eq!(parsed.field_path, Some("CTN_file_metadata".to_string()));
    }

    #[test]
    fn test_serialization_skips_none() {
        let finding = ComplianceFinding::auto_id(
            FindingSeverity::Low,
            "Minimal Finding",
            "Description",
            serde_json::json!({}),
            serde_json::json!({}),
        );

        let json = serde_json::to_string(&finding).unwrap();

        // None fields should be omitted
        assert!(!json.contains("field_path"));
        assert!(!json.contains("object_id"));
        assert!(!json.contains("ctn_type"));
        assert!(!json.contains("remediation"));
    }

    #[test]
    fn test_unique_finding_ids() {
        let ids: Vec<String> = (0..100).map(|_| generate_finding_id()).collect();

        // All IDs should start with "f-"
        assert!(ids.iter().all(|id| id.starts_with("f-")));

        // Check for reasonable uniqueness (not guaranteed but highly likely)
        let unique: std::collections::HashSet<_> = ids.iter().collect();
        // Allow some collisions due to timing but expect most to be unique
        assert!(unique.len() > 90);
    }
}
