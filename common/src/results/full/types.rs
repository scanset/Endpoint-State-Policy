//! # Full Result Types for Compliance Scanning
//!
//! Complete data structures for ESP compliance validation results.
//! Designed for serialization to JSON and integration with SIEM/SOAR tools.
//!
//! **WARNING: Contains CUI (Controlled Unclassified Information)**
//!
//! These types include actual system configuration values and should not be
//! transported over untrusted networks. Use attestation types for network transport.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use super::super::common::{ControlMapping, CriteriaCounts, Criticality, Outcome, PolicyOutcome};

// ============================================================================
// SCAN RESULT - Top Level (One per agent scan run)
// ============================================================================

/// Complete scan result for an agent scan run
///
/// Contains results for all policy files executed in a single scan run.
/// Host/user/timestamp metadata is stored once (not duplicated per policy).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// Unique identifier for this scan execution
    pub scan_id: String,

    /// Metadata about the scan execution environment
    pub metadata: ScanMetadata,

    /// Summary statistics across all policies
    pub summary: ScanSummary,

    /// Individual policy results (one per .esp file)
    pub policy_results: Vec<PolicyResult>,
}

impl ScanResult {
    /// Create a new scan result
    pub fn new(scan_id: impl Into<String>, host: HostContext, user: UserContext) -> Self {
        Self {
            scan_id: scan_id.into(),
            metadata: ScanMetadata::new(host, user),
            summary: ScanSummary::default(),
            policy_results: Vec::new(),
        }
    }

    /// Add a policy result
    pub fn add_policy_result(&mut self, result: PolicyResult) {
        self.policy_results.push(result);
    }

    /// Finalize the scan result (compute summary, set end time)
    pub fn finalize(&mut self) {
        self.metadata.timestamp.scan_end = current_timestamp();
        self.summary = ScanSummary::from_results(&self.policy_results);
    }

    /// Serialize to JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Serialize to compact JSON string
    pub fn to_json_compact(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Parse from JSON string
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }

    /// Check if scan was successful (no errors)
    pub fn is_successful(&self) -> bool {
        self.summary.error_count == 0
    }

    /// Get all findings across all policies
    pub fn all_findings(&self) -> Vec<&ComplianceFinding> {
        self.policy_results
            .iter()
            .flat_map(|r| r.findings.iter())
            .collect()
    }
}

// ============================================================================
// SCAN METADATA
// ============================================================================

/// Metadata about the scan execution environment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanMetadata {
    /// Host information where scan was executed
    pub host: HostContext,

    /// User context for scan execution
    pub user: UserContext,

    /// Scan execution timestamps
    pub timestamp: TimestampInfo,
}

impl ScanMetadata {
    /// Create new scan metadata
    pub fn new(host: HostContext, user: UserContext) -> Self {
        Self {
            host,
            user,
            timestamp: TimestampInfo::now(),
        }
    }
}

/// Host execution context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostContext {
    /// Hostname where scan executed
    pub hostname: String,

    /// Operating system information
    pub os_info: String,

    /// IP address of scanning host
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,

    /// Additional host identifiers for asset correlation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asset_id: Option<String>,
}

impl HostContext {
    /// Create host context from system information
    pub fn from_system() -> Self {
        Self {
            hostname: std::env::var("HOSTNAME")
                .or_else(|_| std::env::var("COMPUTERNAME"))
                .unwrap_or_else(|_| "unknown".to_string()),
            os_info: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
            ip_address: None,
            asset_id: None,
        }
    }

    /// Create with custom values
    pub fn new(hostname: impl Into<String>, os_info: impl Into<String>) -> Self {
        Self {
            hostname: hostname.into(),
            os_info: os_info.into(),
            ip_address: None,
            asset_id: None,
        }
    }

    /// Set IP address
    pub fn with_ip_address(mut self, ip: impl Into<String>) -> Self {
        self.ip_address = Some(ip.into());
        self
    }

    /// Set asset ID
    pub fn with_asset_id(mut self, asset_id: impl Into<String>) -> Self {
        self.asset_id = Some(asset_id.into());
        self
    }
}

impl Default for HostContext {
    fn default() -> Self {
        Self::from_system()
    }
}

/// User execution context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserContext {
    /// User account that executed the scan
    pub username: String,

    /// Execution privileges level
    pub privilege_level: String,

    /// Process information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_info: Option<String>,
}

impl UserContext {
    /// Create user context from environment
    pub fn from_environment() -> Self {
        let username = std::env::var("USER")
            .or_else(|_| std::env::var("USERNAME"))
            .unwrap_or_else(|_| "unknown".to_string());

        let privilege_level = if username == "root" {
            "root".to_string()
        } else if cfg!(unix) {
            match std::env::var("UID").or_else(|_| std::env::var("EUID")) {
                Ok(uid) if uid == "0" => "root".to_string(),
                _ => "user".to_string(),
            }
        } else if username.to_lowercase().contains("admin") {
            "admin".to_string()
        } else {
            "user".to_string()
        };

        Self {
            username,
            privilege_level,
            process_info: Some(format!("pid:{}", std::process::id())),
        }
    }

    /// Create with custom values
    pub fn new(username: impl Into<String>, privilege_level: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            privilege_level: privilege_level.into(),
            process_info: None,
        }
    }

    /// Set process information
    pub fn with_process_info(mut self, process_info: impl Into<String>) -> Self {
        self.process_info = Some(process_info.into());
        self
    }
}

impl Default for UserContext {
    fn default() -> Self {
        Self::from_environment()
    }
}

/// Timestamp information for scan execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimestampInfo {
    /// When scan execution started (ISO 8601 format)
    pub scan_start: String,

    /// When scan execution completed (ISO 8601 format)
    pub scan_end: String,

    /// Total execution duration in milliseconds
    pub duration_ms: u64,
}

impl TimestampInfo {
    /// Create with current timestamp
    pub fn now() -> Self {
        let now = current_timestamp();
        Self {
            scan_start: now.clone(),
            scan_end: now,
            duration_ms: 0,
        }
    }
}

impl Default for TimestampInfo {
    fn default() -> Self {
        Self::now()
    }
}

// ============================================================================
// SCAN SUMMARY
// ============================================================================

/// Summary statistics across all policies in a scan
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScanSummary {
    /// Total number of policies evaluated
    pub total_policies: u32,

    /// Number of policies that passed
    pub passed_count: u32,

    /// Number of policies that failed
    pub failed_count: u32,

    /// Number of policies with errors
    pub error_count: u32,

    /// Overall pass percentage
    pub pass_percentage: f32,

    /// Total weight of all policies
    pub total_weight: f32,

    /// Weight of passing policies
    pub passed_weight: f32,

    /// Posture score (weighted pass rate)
    pub posture_score: f32,
}

impl ScanSummary {
    /// Compute summary from policy results
    pub fn from_results(results: &[PolicyResult]) -> Self {
        let mut summary = Self::default();

        for result in results {
            summary.total_policies += 1;
            summary.total_weight += result.outcome.weight_value();

            match result.outcome.outcome {
                Outcome::Pass => {
                    summary.passed_count += 1;
                    summary.passed_weight += result.outcome.weight_value();
                }
                Outcome::Fail => {
                    summary.failed_count += 1;
                }
                Outcome::Error => {
                    summary.error_count += 1;
                }
                Outcome::Unknown => {
                    // Unknown doesn't count
                }
            }
        }

        // Calculate percentages
        if summary.total_policies > 0 {
            summary.pass_percentage =
                (summary.passed_count as f32 / summary.total_policies as f32) * 100.0;
        }

        if summary.total_weight > 0.0 {
            summary.posture_score = (summary.passed_weight / summary.total_weight) * 100.0;
        }

        summary
    }
}

// ============================================================================
// POLICY RESULT - One per .esp file (with CUI)
// ============================================================================

/// Result for a single policy file with full evidence
///
/// Extends PolicyOutcome with CUI data (findings and evidence).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResult {
    /// Core policy outcome data (CUI-free base)
    #[serde(flatten)]
    pub outcome: PolicyOutcome,

    /// ESP metadata from the policy file
    pub esp_metadata: EspMetadata,

    /// Detailed findings from validation (CUI)
    pub findings: Vec<ComplianceFinding>,

    /// Raw evidence data (CUI)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Evidence>,
}

impl PolicyResult {
    /// Create a new policy result
    pub fn new(
        policy_id: impl Into<String>,
        platform: impl Into<String>,
        outcome: Outcome,
        criticality: Criticality,
        control_mappings: Vec<ControlMapping>,
        criteria_counts: CriteriaCounts,
        esp_metadata: EspMetadata,
    ) -> Self {
        Self {
            outcome: PolicyOutcome::new(
                policy_id,
                platform,
                outcome,
                criticality,
                control_mappings,
                criteria_counts,
            ),
            esp_metadata,
            findings: Vec::new(),
            evidence: None,
        }
    }

    /// Create from an existing PolicyOutcome
    pub fn from_outcome(outcome: PolicyOutcome, esp_metadata: EspMetadata) -> Self {
        Self {
            outcome,
            esp_metadata,
            findings: Vec::new(),
            evidence: None,
        }
    }

    /// Add a finding
    pub fn add_finding(&mut self, finding: ComplianceFinding) {
        self.findings.push(finding);
    }

    /// Set evidence
    pub fn with_evidence(mut self, evidence: Evidence) -> Self {
        self.evidence = Some(evidence);
        self
    }

    /// Check if this policy passed
    pub fn is_pass(&self) -> bool {
        self.outcome.is_pass()
    }

    /// Get policy ID
    pub fn policy_id(&self) -> &str {
        &self.outcome.policy_id
    }
}

// ============================================================================
// ESP METADATA
// ============================================================================

/// Required fields from ESP META block for SIEM/SOAR output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EspMetadata {
    /// Unique identifier for this ESP scan definition
    pub esp_scan_id: String,

    /// Control framework being validated (e.g., "NIST", "CIS", "PCI-DSS")
    pub control_framework: String,

    /// Specific control identifier (e.g., "AC-2", "CIS-5.1.1")
    pub control: String,

    /// Target platform (e.g., "Windows", "Linux", "Kubernetes")
    pub platform: String,

    /// Criticality level (low, medium, high, critical)
    pub criticality: String,

    /// Tags for categorization and filtering
    pub tags: String,
}

impl EspMetadata {
    /// Create from metadata block fields
    pub fn from_fields(fields: &HashMap<String, String>) -> Result<Self, String> {
        Ok(Self {
            esp_scan_id: fields
                .get("esp_scan_id")
                .ok_or("Missing esp_scan_id")?
                .clone(),
            control_framework: fields
                .get("control_framework")
                .ok_or("Missing control_framework")?
                .clone(),
            control: fields.get("control").ok_or("Missing control")?.clone(),
            platform: fields.get("platform").ok_or("Missing platform")?.clone(),
            criticality: fields
                .get("criticality")
                .ok_or("Missing criticality")?
                .clone(),
            tags: fields.get("tags").cloned().unwrap_or_default(),
        })
    }

    /// Create with default values for testing
    pub fn default_test() -> Self {
        Self {
            esp_scan_id: "test-scan-001".to_string(),
            control_framework: "TEST".to_string(),
            control: "TEST-1".to_string(),
            platform: "Test".to_string(),
            criticality: "medium".to_string(),
            tags: "test".to_string(),
        }
    }
}

impl Default for EspMetadata {
    fn default() -> Self {
        Self::default_test()
    }
}

// ============================================================================
// FINDINGS (CUI)
// ============================================================================

/// Individual compliance violation or issue
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplianceFinding {
    /// Unique identifier for this finding
    pub finding_id: String,

    /// Severity level of the compliance violation
    pub severity: FindingSeverity,

    /// Human-readable title of the finding
    pub title: String,

    /// Detailed description of what was found
    pub description: String,

    /// Expected configuration value (CUI)
    pub expected: serde_json::Value,

    /// Actual configuration value found (CUI)
    pub actual: serde_json::Value,

    /// Remediation guidance
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remediation: Option<String>,

    /// Field path that failed validation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field_path: Option<String>,
}

impl ComplianceFinding {
    /// Create a new compliance finding
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
            remediation: None,
            field_path: None,
        }
    }

    /// Add remediation guidance
    pub fn with_remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = Some(remediation.into());
        self
    }

    /// Add field path context
    pub fn with_field_path(mut self, field_path: impl Into<String>) -> Self {
        self.field_path = Some(field_path.into());
        self
    }

    /// Create a finding with auto-generated ID
    pub fn auto_id(
        severity: FindingSeverity,
        title: impl Into<String>,
        description: impl Into<String>,
        expected: serde_json::Value,
        actual: serde_json::Value,
    ) -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let id = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        Self::new(
            format!("finding-{:x}", id),
            severity,
            title,
            description,
            expected,
            actual,
        )
    }
}

/// Severity levels for compliance findings
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum FindingSeverity {
    /// Critical compliance violation
    Critical,
    /// High priority compliance issue
    High,
    /// Medium priority compliance issue
    #[default]
    Medium,
    /// Low priority compliance issue
    Low,
    /// Informational finding
    Info,
}

impl From<Criticality> for FindingSeverity {
    fn from(criticality: Criticality) -> Self {
        match criticality {
            Criticality::Critical => FindingSeverity::Critical,
            Criticality::High => FindingSeverity::High,
            Criticality::Medium => FindingSeverity::Medium,
            Criticality::Low => FindingSeverity::Low,
            Criticality::Info => FindingSeverity::Info,
        }
    }
}

// ============================================================================
// EVIDENCE (CUI)
// ============================================================================

/// Raw evidence data collected during scan
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Evidence {
    /// Collected data keyed by object ID
    pub data: HashMap<String, serde_json::Value>,

    /// When evidence was collected
    pub collected_at: String,
}

impl Evidence {
    /// Create new evidence container
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
            collected_at: current_timestamp(),
        }
    }

    /// Add evidence data
    pub fn add_data(&mut self, key: impl Into<String>, value: serde_json::Value) {
        self.data.insert(key.into(), value);
    }

    /// Get evidence by key
    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        self.data.get(key)
    }
}

// ============================================================================
// RESULT GENERATION ERROR
// ============================================================================

/// Errors that can occur during result generation
#[derive(Debug, Clone)]
pub enum ResultGenerationError {
    /// Missing required metadata field
    MissingMetadata(String),
    /// Serialization error
    SerializationError(String),
    /// Invalid data
    InvalidData(String),
}

impl std::fmt::Display for ResultGenerationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResultGenerationError::MissingMetadata(field) => {
                write!(f, "Missing required metadata field: {}", field)
            }
            ResultGenerationError::SerializationError(e) => {
                write!(f, "Serialization error: {}", e)
            }
            ResultGenerationError::InvalidData(msg) => {
                write!(f, "Invalid data: {}", msg)
            }
        }
    }
}

impl std::error::Error for ResultGenerationError {}

// ============================================================================
// HELPER FUNCTIONS
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
// TESTS
// ============================================================================
#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scan_result_new() {
        let host = HostContext::new("testhost", "Linux x86_64");
        let user = UserContext::new("testuser", "user");

        let result = ScanResult::new("scan-001", host, user);

        assert_eq!(result.scan_id, "scan-001");
        assert!(result.policy_results.is_empty());
    }

    #[test]
    fn test_policy_result_new() {
        let esp = EspMetadata::default_test();
        let result = PolicyResult::new(
            "policy-1",
            "Linux",
            Outcome::Pass,
            Criticality::High,
            vec![],
            CriteriaCounts::default(),
            esp,
        );

        assert_eq!(result.policy_id(), "policy-1");
        assert!(result.is_pass());
    }

    #[test]
    fn test_scan_summary() {
        let esp = EspMetadata::default_test();
        let results = vec![
            PolicyResult::new(
                "p1",
                "Linux",
                Outcome::Pass,
                Criticality::High,
                vec![],
                CriteriaCounts::default(),
                esp.clone(),
            ),
            PolicyResult::new(
                "p2",
                "Linux",
                Outcome::Fail,
                Criticality::Critical,
                vec![],
                CriteriaCounts::default(),
                esp.clone(),
            ),
        ];

        let summary = ScanSummary::from_results(&results);

        assert_eq!(summary.total_policies, 2);
        assert_eq!(summary.passed_count, 1);
        assert_eq!(summary.failed_count, 1);
        assert_eq!(summary.pass_percentage, 50.0);
    }

    #[test]
    fn test_compliance_finding() {
        let finding = ComplianceFinding::new(
            "finding-1",
            FindingSeverity::High,
            "Test Finding",
            "Description",
            serde_json::json!("expected"),
            serde_json::json!("actual"),
        )
        .with_remediation("Fix it")
        .with_field_path("config.setting");

        assert_eq!(finding.finding_id, "finding-1");
        assert_eq!(finding.remediation, Some("Fix it".to_string()));
    }
}
