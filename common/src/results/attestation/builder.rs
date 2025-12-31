//! Attestation builder
//!
//! Constructs attestations from execution results. Validates required META fields
//! and transforms execution output into CUI-free attestation format.

use super::super::common::{
    ControlMapping, ControlMappingError, CriteriaCounts, Criticality, Outcome, Weight,
};
use super::hashing;
use super::types::{
    AttestationEnvelope, AttestationSummary, CheckAttestation, CriticalityBreakdown,
    ScanAttestation,
};
use crate::metadata::MetaDataBlock;

/// Builder for constructing scan attestations
pub struct AttestationBuilder {
    agent_id: String,
    agent_type: String,
    checks: Vec<CheckAttestation>,
}

impl AttestationBuilder {
    /// Create a new attestation builder
    pub fn new(agent_id: impl Into<String>, agent_type: impl Into<String>) -> Self {
        Self {
            agent_id: agent_id.into(),
            agent_type: agent_type.into(),
            checks: Vec::new(),
        }
    }

    /// Add a check attestation from execution results
    ///
    /// Validates required META fields and extracts attestation data.
    pub fn add_check(
        &mut self,
        metadata: &MetaDataBlock,
        outcome: Outcome,
        criteria_counts: CriteriaCounts,
    ) -> Result<(), AttestationBuildError> {
        let check = build_check_attestation(metadata, outcome, criteria_counts)?;
        self.checks.push(check);
        Ok(())
    }

    /// Add a pre-built check attestation
    pub fn add_check_attestation(&mut self, check: CheckAttestation) {
        self.checks.push(check);
    }

    /// Build the final scan attestation
    pub fn build(self) -> Result<ScanAttestation, AttestationBuildError> {
        // Build summary from checks
        let summary = build_summary(&self.checks);

        // Create content for hashing (summary + checks)
        let content = AttestationContent {
            summary: &summary,
            checks: &self.checks,
        };

        // Hash the content
        let content_hash = hashing::hash_content(&content)
            .map_err(|e| AttestationBuildError::HashingFailed(e.to_string()))?;

        // Generate attestation ID and timestamp
        let attestation_id = generate_attestation_id();
        let timestamp = generate_timestamp();

        // Build envelope
        let envelope = AttestationEnvelope::new(
            attestation_id,
            timestamp,
            self.agent_id,
            self.agent_type,
            content_hash,
        );

        Ok(ScanAttestation::new(envelope, summary, self.checks))
    }
}

/// Internal struct for hashing attestation content
#[derive(serde::Serialize)]
struct AttestationContent<'a> {
    summary: &'a AttestationSummary,
    checks: &'a [CheckAttestation],
}

/// Build a check attestation from metadata and outcome
pub fn build_check_attestation(
    metadata: &MetaDataBlock,
    outcome: Outcome,
    criteria_counts: CriteriaCounts,
) -> Result<CheckAttestation, AttestationBuildError> {
    // Extract and validate required fields
    let policy_id = get_required_field(metadata, "esp_scan_id")?;
    let platform = get_required_field(metadata, "platform")?;
    let criticality_str = get_required_field(metadata, "criticality")?;

    // Parse criticality
    let criticality = Criticality::parse(&criticality_str)
        .ok_or_else(|| AttestationBuildError::InvalidCriticality(criticality_str.clone()))?;

    // Parse control mappings (required)
    let control_mapping_str = get_required_field(metadata, "control_mapping")?;
    let control_mappings = ControlMapping::parse_from_meta(&control_mapping_str)
        .map_err(AttestationBuildError::ControlMappingError)?;

    // Optional: policy version
    let policy_version = metadata.fields.get("esp_version").cloned();

    // Optional: explicit weight (defaults to criticality)
    let weight = metadata
        .fields
        .get("weight")
        .and_then(|w| w.parse::<f32>().ok())
        .map(Weight::new)
        .unwrap_or_else(|| Weight::from(criticality));

    let mut check = CheckAttestation::new(
        policy_id,
        platform,
        outcome,
        criticality,
        control_mappings,
        criteria_counts,
    );

    // Use builder methods to set optional fields
    check = check.with_weight(weight.value());
    if let Some(version) = policy_version {
        check = check.with_version(version);
    }

    Ok(check)
}

/// Build summary statistics from check attestations
fn build_summary(checks: &[CheckAttestation]) -> AttestationSummary {
    let mut summary = AttestationSummary::default();
    let mut by_criticality = CriticalityBreakdown::default();
    let mut total_weight: f32 = 0.0;
    let mut passed_weight: f32 = 0.0;

    for check in checks {
        summary.total_checks += 1;

        match check.get_outcome() {
            Outcome::Pass => {
                summary.passed += 1;
                by_criticality.record(check.criticality(), true);
                passed_weight += check.weight_value();
            }
            Outcome::Fail => {
                summary.failed += 1;
                by_criticality.record(check.criticality(), false);
            }
            Outcome::Error => {
                summary.error += 1;
                // Errors don't contribute to criticality breakdown
            }
            Outcome::Unknown => {
                // Unknown checks don't affect counts
            }
        }

        total_weight += check.weight_value();
    }

    summary.by_criticality = by_criticality;
    summary.total_weight = total_weight;
    summary.passed_weight = passed_weight;

    summary
}

/// Get a required field from metadata
fn get_required_field(
    metadata: &MetaDataBlock,
    field_name: &str,
) -> Result<String, AttestationBuildError> {
    metadata
        .fields
        .get(field_name)
        .cloned()
        .ok_or_else(|| AttestationBuildError::MissingRequiredField(field_name.to_string()))
}

/// Generate a unique attestation ID
fn generate_attestation_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();

    // Simple format: att-{timestamp_hex}
    format!("att-{:x}", timestamp)
}

/// Generate ISO 8601 timestamp
fn generate_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    let secs = duration.as_secs();

    // Convert to approximate ISO 8601 without chrono dependency
    let days = secs / 86400;
    let remaining = secs % 86400;
    let hours = remaining / 3600;
    let minutes = (remaining % 3600) / 60;
    let seconds = remaining % 60;

    // Days since Unix epoch to approximate date
    let years = 1970 + (days / 365);
    let day_of_year = days % 365;
    let month = (day_of_year / 30) + 1;
    let day = (day_of_year % 30) + 1;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        years, month, day, hours, minutes, seconds
    )
}

/// Errors that can occur when building attestations
#[derive(Debug)]
pub enum AttestationBuildError {
    /// Required META field is missing
    MissingRequiredField(String),
    /// Invalid criticality value
    InvalidCriticality(String),
    /// Control mapping parsing error
    ControlMappingError(ControlMappingError),
    /// Content hashing failed
    HashingFailed(String),
}

impl std::fmt::Display for AttestationBuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AttestationBuildError::MissingRequiredField(field) => {
                write!(f, "Missing required META field: {}", field)
            }
            AttestationBuildError::InvalidCriticality(value) => {
                write!(
                    f,
                    "Invalid criticality value '{}'. Expected: critical, high, medium, low, info",
                    value
                )
            }
            AttestationBuildError::ControlMappingError(e) => {
                write!(f, "Control mapping error: {}", e)
            }
            AttestationBuildError::HashingFailed(e) => {
                write!(f, "Failed to hash attestation content: {}", e)
            }
        }
    }
}

impl std::error::Error for AttestationBuildError {}

impl From<ControlMappingError> for AttestationBuildError {
    fn from(err: ControlMappingError) -> Self {
        AttestationBuildError::ControlMappingError(err)
    }
}

/// Required META fields for attestation
pub const REQUIRED_META_FIELDS: &[&str] =
    &["esp_scan_id", "platform", "criticality", "control_mapping"];

/// Validate that metadata contains all required fields
pub fn validate_metadata(metadata: &MetaDataBlock) -> Result<(), Vec<String>> {
    let missing: Vec<String> = REQUIRED_META_FIELDS
        .iter()
        .filter(|&&field| !metadata.fields.contains_key(field))
        .map(|&s| s.to_string())
        .collect();

    if missing.is_empty() {
        Ok(())
    } else {
        Err(missing)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn create_test_metadata() -> MetaDataBlock {
        let mut fields = HashMap::new();
        fields.insert("esp_scan_id".to_string(), "test-policy-001".to_string());
        fields.insert("platform".to_string(), "Kubernetes".to_string());
        fields.insert("criticality".to_string(), "high".to_string());
        fields.insert(
            "control_mapping".to_string(),
            "NIST-800-53:AC-6,CIS:5.1.1".to_string(),
        );
        fields.insert("tags".to_string(), "rbac,security".to_string());

        MetaDataBlock { fields }
    }

    #[test]
    fn test_build_check_attestation() {
        let metadata = create_test_metadata();
        let criteria = CriteriaCounts::new(5, 5, 0, 0);

        let check = build_check_attestation(&metadata, Outcome::Pass, criteria).unwrap();

        assert_eq!(check.policy_id(), "test-policy-001");
        assert_eq!(check.platform(), "Kubernetes");
        assert_eq!(check.criticality(), Criticality::High);
        assert_eq!(check.get_outcome(), Outcome::Pass);
        assert_eq!(check.control_mappings().len(), 2);
        assert_eq!(check.weight_value(), 0.8); // High default
    }

    #[test]
    fn test_build_check_with_explicit_weight() {
        let mut metadata = create_test_metadata();
        metadata
            .fields
            .insert("weight".to_string(), "0.95".to_string());

        let criteria = CriteriaCounts::new(3, 3, 0, 0);
        let check = build_check_attestation(&metadata, Outcome::Pass, criteria).unwrap();

        assert_eq!(check.weight_value(), 0.95);
    }

    #[test]
    fn test_missing_required_field() {
        let mut metadata = create_test_metadata();
        metadata.fields.remove("criticality");

        let result = build_check_attestation(&metadata, Outcome::Pass, CriteriaCounts::default());

        assert!(matches!(
            result,
            Err(AttestationBuildError::MissingRequiredField(f)) if f == "criticality"
        ));
    }

    #[test]
    fn test_invalid_criticality() {
        let mut metadata = create_test_metadata();
        metadata
            .fields
            .insert("criticality".to_string(), "super-high".to_string());

        let result = build_check_attestation(&metadata, Outcome::Pass, CriteriaCounts::default());

        assert!(matches!(
            result,
            Err(AttestationBuildError::InvalidCriticality(_))
        ));
    }

    #[test]
    fn test_validate_metadata() {
        let metadata = create_test_metadata();
        assert!(validate_metadata(&metadata).is_ok());

        let mut incomplete = MetaDataBlock {
            fields: HashMap::new(),
        };
        incomplete
            .fields
            .insert("esp_scan_id".to_string(), "test".to_string());

        let result = validate_metadata(&incomplete);
        assert!(result.is_err());

        let missing = result.unwrap_err();
        assert!(missing.contains(&"platform".to_string()));
        assert!(missing.contains(&"criticality".to_string()));
        assert!(missing.contains(&"control_mapping".to_string()));
    }

    #[test]
    fn test_generate_attestation_id() {
        let id1 = generate_attestation_id();
        let id2 = generate_attestation_id();

        assert!(id1.starts_with("att-"));
        assert!(id2.starts_with("att-"));
    }
}
