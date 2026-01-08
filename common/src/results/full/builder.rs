//! Builder for full scan results with evidence
//!
//! Constructs complete scan results including expected/actual values
//! and raw evidence data.
#[allow(unused_imports)]
use std::collections::HashMap;

use super::super::common::{
    ControlMapping, CriteriaCounts, Criticality, Outcome, PolicyOutcome, Weight,
};
use super::types::{
    ComplianceFinding, EspMetadata, Evidence, FindingSeverity, HostContext, PolicyResult,
    ScanResult, UserContext,
};
use crate::metadata::MetaDataBlock;

/// Builder for constructing full scan results
pub struct FullResultBuilder {
    scan_id: String,
    host: HostContext,
    user: UserContext,
    policy_results: Vec<PolicyResult>,
}

impl FullResultBuilder {
    /// Create a new result builder
    pub fn new(scan_id: impl Into<String>, host: HostContext, user: UserContext) -> Self {
        Self {
            scan_id: scan_id.into(),
            host,
            user,
            policy_results: Vec::new(),
        }
    }

    /// Create with system-detected host and user context
    pub fn new_from_system(scan_id: impl Into<String>) -> Self {
        Self::new(
            scan_id,
            HostContext::from_system(),
            UserContext::from_environment(),
        )
    }

    /// Add a policy result from execution
    pub fn add_policy(
        &mut self,
        metadata: &MetaDataBlock,
        outcome: Outcome,
        criteria_counts: CriteriaCounts,
        findings: Vec<ComplianceFinding>,
        evidence: Option<Evidence>,
    ) -> Result<(), FullResultBuildError> {
        let policy = build_policy_result(metadata, outcome, criteria_counts, findings, evidence)?;
        self.policy_results.push(policy);
        Ok(())
    }

    /// Add a pre-built policy result
    pub fn add_policy_result(&mut self, result: PolicyResult) {
        self.policy_results.push(result);
    }

    /// Build the final scan result
    pub fn build(self) -> ScanResult {
        let mut result = ScanResult::new(self.scan_id, self.host, self.user);

        for policy in self.policy_results {
            result.add_policy_result(policy);
        }

        result.finalize();
        result
    }
}

/// Build a policy result from metadata and execution results
pub fn build_policy_result(
    metadata: &MetaDataBlock,
    outcome: Outcome,
    criteria_counts: CriteriaCounts,
    findings: Vec<ComplianceFinding>,
    evidence: Option<Evidence>,
) -> Result<PolicyResult, FullResultBuildError> {
    // Extract required fields
    let policy_id = get_required_field(metadata, "esp_scan_id")?;
    let platform = get_required_field(metadata, "platform")?;
    let criticality_str = get_required_field(metadata, "criticality")?;

    // Parse criticality
    let criticality = Criticality::parse(&criticality_str)
        .ok_or_else(|| FullResultBuildError::InvalidCriticality(criticality_str.clone()))?;

    // Parse control mappings (required)
    let control_mapping_str = get_required_field(metadata, "control_mapping")?;
    let control_mappings = ControlMapping::parse_from_meta(&control_mapping_str)
        .map_err(|e| FullResultBuildError::InvalidControlMapping(e.to_string()))?;

    // Build ESP metadata
    let esp_metadata = EspMetadata::from_fields(&metadata.fields)
        .map_err(FullResultBuildError::MissingRequiredField)?;

    // Optional fields
    let policy_version = metadata.fields.get("esp_version").cloned();
    let weight = metadata
        .fields
        .get("weight")
        .and_then(|w| w.parse::<f32>().ok())
        .map(Weight::new)
        .unwrap_or_else(|| Weight::from(criticality));

    // Build policy outcome
    let mut policy_outcome = PolicyOutcome::new(
        policy_id,
        platform,
        outcome,
        criticality,
        control_mappings,
        criteria_counts,
    );
    policy_outcome = policy_outcome.with_weight(weight);
    if let Some(version) = policy_version {
        policy_outcome = policy_outcome.with_version(version);
    }

    // Build policy result
    let mut result = PolicyResult::from_outcome(policy_outcome, esp_metadata);
    result.findings = findings;
    result.evidence = evidence;

    Ok(result)
}

/// Build a finding from validation failure
pub fn build_finding(
    criticality: Criticality,
    title: impl Into<String>,
    description: impl Into<String>,
    expected: serde_json::Value,
    actual: serde_json::Value,
) -> ComplianceFinding {
    let severity = FindingSeverity::from(criticality);
    ComplianceFinding::auto_id(severity, title, description, expected, actual)
}

/// Get a required field from metadata
fn get_required_field(
    metadata: &MetaDataBlock,
    field_name: &str,
) -> Result<String, FullResultBuildError> {
    metadata
        .fields
        .get(field_name)
        .cloned()
        .ok_or_else(|| FullResultBuildError::MissingRequiredField(field_name.to_string()))
}

/// Errors that can occur when building full results
#[derive(Debug)]
pub enum FullResultBuildError {
    /// Required META field is missing
    MissingRequiredField(String),
    /// Invalid criticality value
    InvalidCriticality(String),
    /// Invalid control mapping
    InvalidControlMapping(String),
}

impl std::fmt::Display for FullResultBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FullResultBuildError::MissingRequiredField(field) => {
                write!(f, "Missing required META field: {}", field)
            }
            FullResultBuildError::InvalidCriticality(value) => {
                write!(
                    f,
                    "Invalid criticality '{}'. Expected: critical, high, medium, low, info",
                    value
                )
            }
            FullResultBuildError::InvalidControlMapping(e) => {
                write!(f, "Invalid control mapping: {}", e)
            }
        }
    }
}

impl std::error::Error for FullResultBuildError {}

#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_metadata() -> MetaDataBlock {
        let mut fields = HashMap::new();
        fields.insert("esp_scan_id".to_string(), "test-policy".to_string());
        fields.insert("platform".to_string(), "Linux".to_string());
        fields.insert("criticality".to_string(), "high".to_string());
        fields.insert("control_mapping".to_string(), "CIS:1.1.1".to_string());
        fields.insert("control_framework".to_string(), "CIS".to_string());
        fields.insert("control".to_string(), "1.1.1".to_string());
        fields.insert("tags".to_string(), "test".to_string());
        MetaDataBlock { fields }
    }

    #[test]
    fn test_build_policy_result() {
        let metadata = create_test_metadata();
        let criteria = CriteriaCounts::new(5, 4, 1, 0);

        let result = build_policy_result(&metadata, Outcome::Fail, criteria, vec![], None).unwrap();

        assert_eq!(result.policy_id(), "test-policy");
        assert!(!result.is_pass());
    }

    #[test]
    fn test_full_result_builder() {
        let host = HostContext::new("testhost", "Linux");
        let user = UserContext::new("testuser", "user");
        let mut builder = FullResultBuilder::new("scan-001", host, user);

        let metadata = create_test_metadata();
        builder
            .add_policy(
                &metadata,
                Outcome::Pass,
                CriteriaCounts::new(3, 3, 0, 0),
                vec![],
                None,
            )
            .unwrap();

        let result = builder.build();

        assert_eq!(result.scan_id, "scan-001");
        assert_eq!(result.policy_results.len(), 1);
        assert_eq!(result.summary.passed_count, 1);
    }

    #[test]
    fn test_build_finding() {
        let finding = build_finding(
            Criticality::High,
            "Permission mismatch",
            "File permissions do not match expected value",
            serde_json::json!("0600"),
            serde_json::json!("0644"),
        );

        assert_eq!(finding.severity, FindingSeverity::High);
        assert!(finding.title.contains("Permission"));
    }

    #[test]
    fn test_missing_required_field() {
        let mut metadata = create_test_metadata();
        metadata.fields.remove("criticality");

        let result = build_policy_result(
            &metadata,
            Outcome::Pass,
            CriteriaCounts::default(),
            vec![],
            None,
        );

        assert!(matches!(
            result,
            Err(FullResultBuildError::MissingRequiredField(_))
        ));
    }
}
