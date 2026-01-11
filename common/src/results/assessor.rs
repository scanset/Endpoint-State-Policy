//! Assessor Package Result Type
//!
//! The assessor package contains everything an assessor needs to verify
//! and reproduce compliance scan results. This includes:
//!
//! - Full evidence with collection methods (including exact commands)
//! - Policy identity and control mappings
//! - Detailed findings with remediation guidance
//! - Reproducibility information
//!
//! ## Hash Architecture
//!
//! The `evidence_hash` and `content_hash` are computed ONCE during execution
//! in `ExecutionEngine::execute()` and passed to the builder. The builder
//! does NOT compute hashes - it only accepts pre-computed values.
//!
//! This ensures hash consistency across all output formats (attestation,
//! full-results, assessor-evidence).
//!
//! ## Feature Flag
//!
//! This module requires the `assessor-evidence` feature, which implies `full-results`.
//! When enabled, `CollectionMethod` serialization includes:
//! - `command` - The exact command executed
//! - `inputs` - Input parameters used

use serde::{Deserialize, Serialize};

use super::common::Outcome;
use super::envelope::{AgentInfo, HostInfo, ResultEnvelope};
use super::error::ResultError;
use super::evidence::Evidence;
use super::finding::ComplianceFinding;
use super::identity::PolicyIdentity;
use super::summary::ExecutionSummary;

// ============================================================================
// Assessor Package
// ============================================================================

/// Complete assessor package with full evidence and reproducibility info
///
/// This is the most detailed output format, intended for assessors who need
/// to verify and potentially reproduce the compliance scan. Unlike `FullResult`,
/// this includes the exact commands and inputs used during collection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssessorPackage {
    /// Result envelope with metadata
    pub envelope: ResultEnvelope,

    /// Execution summary with pass/fail counts
    pub summary: ExecutionSummary,

    /// Individual policy results with full evidence
    pub policies: Vec<AssessorPolicyResult>,

    /// Package metadata
    pub package_info: PackageInfo,
}

impl AssessorPackage {
    /// Get the number of policies in this package
    pub fn policy_count(&self) -> usize {
        self.policies.len()
    }

    /// Check if all policies passed
    pub fn all_passed(&self) -> bool {
        self.summary.failed == 0 && self.summary.errors == 0
    }

    /// Get policies by outcome
    pub fn policies_by_outcome(&self, outcome: Outcome) -> Vec<&AssessorPolicyResult> {
        self.policies
            .iter()
            .filter(|p| p.outcome == outcome)
            .collect()
    }

    /// Get failed policies
    pub fn failed_policies(&self) -> Vec<&AssessorPolicyResult> {
        self.policies_by_outcome(Outcome::Fail)
    }
}

// ============================================================================
// Package Info
// ============================================================================

/// Metadata about the assessor package
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageInfo {
    /// Package format version
    pub format_version: String,

    /// When the package was generated
    pub generated_at: String,

    /// Purpose of this package
    pub purpose: String,

    /// Whether this package contains sensitive data
    pub contains_cui: bool,

    /// Distribution restrictions
    pub distribution: String,

    /// Notes for the assessor
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

impl Default for PackageInfo {
    fn default() -> Self {
        Self {
            format_version: "1.0.0".to_string(),
            generated_at: current_timestamp(),
            purpose: "Compliance assessment verification".to_string(),
            contains_cui: true,
            distribution: "Internal use only - contains CUI".to_string(),
            notes: None,
        }
    }
}

impl PackageInfo {
    /// Create with custom notes
    pub fn with_notes(mut self, notes: impl Into<String>) -> Self {
        self.notes = Some(notes.into());
        self
    }
}

// ============================================================================
// Assessor Policy Result
// ============================================================================

/// Single policy result with full assessor evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AssessorPolicyResult {
    /// Policy identity (ID, platform, criticality, control mappings)
    pub identity: PolicyIdentity,

    /// Overall outcome
    pub outcome: Outcome,

    /// Weight for posture scoring
    pub weight: f32,

    /// Compliance findings (empty if passed)
    pub findings: Vec<ComplianceFinding>,

    /// Full evidence with collection details
    pub evidence: Evidence,

    /// Reproducibility information
    pub reproducibility: ReproducibilityInfo,
}

impl AssessorPolicyResult {
    /// Create a new assessor policy result
    pub fn new(
        identity: PolicyIdentity,
        outcome: Outcome,
        weight: f32,
        findings: Vec<ComplianceFinding>,
        evidence: Evidence,
    ) -> Self {
        // Build reproducibility info from evidence
        let reproducibility = ReproducibilityInfo::from_evidence(&evidence);

        Self {
            identity,
            outcome,
            weight,
            findings,
            evidence,
            reproducibility,
        }
    }

    /// Check if this policy passed
    pub fn passed(&self) -> bool {
        self.outcome == Outcome::Pass
    }

    /// Get finding count
    pub fn finding_count(&self) -> usize {
        self.findings.len()
    }
}

// ============================================================================
// Reproducibility Info
// ============================================================================

/// Information to help assessors reproduce the scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReproducibilityInfo {
    /// Collection commands that can be re-run
    pub commands: Vec<CollectionCommand>,

    /// Environment requirements
    pub requirements: Vec<String>,

    /// Notes on reproduction
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

impl ReproducibilityInfo {
    /// Build reproducibility info from evidence
    pub fn from_evidence(evidence: &Evidence) -> Self {
        let commands: Vec<CollectionCommand> = evidence
            .collection_metadata
            .iter()
            .filter_map(|record| {
                record.method.as_ref().and_then(|method| {
                    // Only include if we have command details
                    method.command.as_ref().map(|cmd| CollectionCommand {
                        object_id: record.object_id.clone(),
                        method_type: method.method_type.to_string(),
                        command: cmd.clone(),
                        target: method.target.clone(),
                        inputs: method.inputs.clone(),
                    })
                })
            })
            .collect();

        // Determine requirements based on collection methods
        let mut requirements = Vec::new();
        let method_types: std::collections::HashSet<_> = evidence
            .collection_metadata
            .iter()
            .filter_map(|r| r.method.as_ref())
            .map(|m| m.method_type.to_string())
            .collect();

        if method_types.contains("file_read") || method_types.contains("file_stat") {
            requirements.push("File system access to target paths".to_string());
        }
        if method_types.contains("command") {
            requirements.push("Shell access with appropriate permissions".to_string());
        }
        if method_types.contains("api_call") {
            requirements.push("API access with valid credentials".to_string());
        }
        if method_types.contains("socket_inspection") {
            requirements.push("Read access to /proc/net/tcp or equivalent".to_string());
        }

        Self {
            commands,
            requirements,
            notes: None,
        }
    }

    /// Add a note
    pub fn with_notes(mut self, notes: impl Into<String>) -> Self {
        self.notes = Some(notes.into());
        self
    }
}

/// A collection command that can be reproduced
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionCommand {
    /// Object ID this command collected
    pub object_id: String,

    /// Type of collection method
    pub method_type: String,

    /// The exact command to run
    pub command: String,

    /// Target resource (file path, endpoint, etc.)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,

    /// Input parameters
    #[serde(skip_serializing_if = "std::collections::HashMap::is_empty", default)]
    pub inputs: std::collections::HashMap<String, String>,
}

// ============================================================================
// Assessor Package Builder
// ============================================================================

/// Builder for constructing AssessorPackage instances
///
/// ## Hash Handling
///
/// This builder requires pre-computed hashes from the execution engine.
/// It does NOT compute hashes itself - this ensures consistency across
/// all output formats.
///
/// ```rust,ignore
/// let builder = AssessorPackageBuilder::new(agent, host)
///     .with_content_hash(manifest.content_hash.clone())
///     .with_evidence_hash(manifest.evidence_hash.clone());
/// ```
pub struct AssessorPackageBuilder {
    agent: AgentInfo,
    host: HostInfo,
    policies: Vec<AssessorPolicyResult>,
    content_hash: Option<String>,
    evidence_hash: Option<String>,
    notes: Option<String>,
}

impl AssessorPackageBuilder {
    /// Create a new builder
    pub fn new(agent: AgentInfo, host: HostInfo) -> Self {
        Self {
            agent,
            host,
            policies: Vec::new(),
            content_hash: None,
            evidence_hash: None,
            notes: None,
        }
    }

    /// Add a policy result
    pub fn add_policy(&mut self, policy: AssessorPolicyResult) {
        self.policies.push(policy);
    }

    /// Set the content hash (pre-computed from ExecutionManifest)
    ///
    /// This hash is computed ONCE in the execution engine and must be
    /// passed through unchanged to ensure consistency.
    pub fn with_content_hash(mut self, hash: impl Into<String>) -> Self {
        self.content_hash = Some(hash.into());
        self
    }

    /// Set the evidence hash (pre-computed from ExecutionManifest)
    ///
    /// This hash is computed ONCE in the execution engine and must be
    /// passed through unchanged to ensure consistency.
    pub fn with_evidence_hash(mut self, hash: impl Into<String>) -> Self {
        self.evidence_hash = Some(hash.into());
        self
    }

    /// Add notes for the package
    pub fn with_notes(mut self, notes: impl Into<String>) -> Self {
        self.notes = Some(notes.into());
        self
    }

    /// Build the assessor package
    ///
    /// ## Errors
    ///
    /// Returns an error if:
    /// - No policies were added
    /// - `content_hash` or `evidence_hash` were not provided
    pub fn build(self) -> Result<AssessorPackage, ResultError> {
        if self.policies.is_empty() {
            return Err(ResultError::BuildError(
                "At least one policy result is required".to_string(),
            ));
        }

        // Require pre-computed hashes
        let content_hash = self.content_hash.ok_or_else(|| {
            ResultError::BuildError(
                "content_hash is required - must be pre-computed from ExecutionManifest"
                    .to_string(),
            )
        })?;

        let evidence_hash = self.evidence_hash.ok_or_else(|| {
            ResultError::BuildError(
                "evidence_hash is required - must be pre-computed from ExecutionManifest"
                    .to_string(),
            )
        })?;

        // Build summary
        let mut summary = ExecutionSummary::new();
        for policy in &self.policies {
            let passed = policy.outcome == Outcome::Pass;
            summary.record(passed, policy.identity.criticality, policy.weight);
        }

        // Build envelope with pre-computed hashes
        let envelope = ResultEnvelope::new(self.agent, self.host)
            .with_content_hash(content_hash)
            .with_evidence_hash(evidence_hash);

        // Build package info
        let mut package_info = PackageInfo::default();
        if let Some(notes) = self.notes {
            package_info = package_info.with_notes(notes);
        }

        Ok(AssessorPackage {
            envelope,
            summary,
            policies: self.policies,
            package_info,
        })
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

    let years = 1970 + (days / 365);
    let day_of_year = days % 365;
    let month = (day_of_year / 30).min(11) + 1;
    let day = (day_of_year % 30) + 1;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        years, month, day, hours, minutes, seconds
    )
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
    use crate::results::collection_method::{CollectionMethod, CollectionMethodType};
    use crate::results::evidence::CollectionRecord;
    use crate::results::ControlMapping;
    use crate::results::Criticality;

    fn create_test_evidence() -> Evidence {
        let mut evidence = Evidence::new();
        evidence.add_data("test_obj", serde_json::json!({"field": "value"}));

        let method = CollectionMethod::builder()
            .method_type(CollectionMethodType::Command)
            .description("Test command")
            .target("/etc/passwd")
            .command("cat /etc/passwd")
            .input("file", "/etc/passwd")
            .build();

        evidence.add_collection_record(
            CollectionRecord::new("test_obj", "file_content", "test_collector").with_method(method),
        );

        evidence
    }

    #[test]
    fn test_assessor_package_builder_with_hashes() {
        let agent = AgentInfo::with_defaults("test-agent");
        let host = HostInfo::from_system();
        let mut builder = AssessorPackageBuilder::new(agent, host)
            .with_content_hash("sha256:content123")
            .with_evidence_hash("sha256:evidence456");

        let identity = PolicyIdentity::new(
            "test-policy",
            "linux",
            Criticality::High,
            vec![ControlMapping::new("CIS", "1.1.1")],
        );

        let evidence = create_test_evidence();
        let policy = AssessorPolicyResult::new(identity, Outcome::Pass, 0.8, vec![], evidence);

        builder.add_policy(policy);
        let package = builder.build().unwrap();

        assert_eq!(package.policy_count(), 1);
        assert!(package.all_passed());
        // Verify hashes are preserved
        assert_eq!(package.envelope.content_hash, "sha256:content123");
        assert_eq!(package.envelope.evidence_hash, "sha256:evidence456");
    }

    #[test]
    fn test_assessor_package_builder_requires_hashes() {
        let agent = AgentInfo::with_defaults("test-agent");
        let host = HostInfo::from_system();
        let mut builder = AssessorPackageBuilder::new(agent, host);

        let identity = PolicyIdentity::new(
            "test-policy",
            "linux",
            Criticality::High,
            vec![ControlMapping::new("CIS", "1.1.1")],
        );

        let evidence = create_test_evidence();
        let policy = AssessorPolicyResult::new(identity, Outcome::Pass, 0.8, vec![], evidence);

        builder.add_policy(policy);

        // Should fail without hashes
        let result = builder.build();
        assert!(result.is_err());
    }

    #[test]
    fn test_reproducibility_info() {
        let evidence = create_test_evidence();
        let repro = ReproducibilityInfo::from_evidence(&evidence);

        assert_eq!(repro.commands.len(), 1);
        assert_eq!(repro.commands[0].command, "cat /etc/passwd");
        assert!(!repro.requirements.is_empty());
    }

    #[test]
    fn test_package_info_default() {
        let info = PackageInfo::default();
        assert!(info.contains_cui);
        assert_eq!(info.format_version, "1.0.0");
    }
}
