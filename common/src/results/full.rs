//! Full result types with complete evidence
//!
//! Full results contain actual system values and findings.
//! This is sensitive data - for local storage only.
//!
//! ## Feature
//!
//! This module requires the `full-results` feature.

use serde::{Deserialize, Serialize};

use super::common::{ControlMapping, Criticality, Outcome};
use super::envelope::{AgentInfo, HostInfo, ResultEnvelope};
use super::error::ResultError;
use super::evidence::Evidence;
use super::finding::ComplianceFinding;
use super::identity::PolicyIdentity;
use super::summary::ScanSummary;

/// Complete scan result with evidence
///
/// Contains full details including expected/actual values.
/// For local storage only - do not transmit over untrusted networks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FullResult {
    /// Envelope with metadata and signatures
    pub envelope: ResultEnvelope,

    /// Aggregate statistics
    pub summary: ScanSummary,

    /// Per-policy results with evidence
    pub policies: Vec<PolicyResult>,
}

impl FullResult {
    /// Create a new full result
    pub fn new(
        envelope: ResultEnvelope,
        summary: ScanSummary,
        policies: Vec<PolicyResult>,
    ) -> Self {
        Self {
            envelope,
            summary,
            policies,
        }
    }

    /// Get number of policies
    pub fn policy_count(&self) -> usize {
        self.policies.len()
    }

    /// Get all findings across all policies
    pub fn all_findings(&self) -> Vec<&ComplianceFinding> {
        self.policies
            .iter()
            .flat_map(|p| p.findings.iter())
            .collect()
    }

    /// Get passing policies
    pub fn passing_policies(&self) -> Vec<&PolicyResult> {
        self.policies
            .iter()
            .filter(|p| p.outcome.is_pass())
            .collect()
    }

    /// Get failing policies
    pub fn failing_policies(&self) -> Vec<&PolicyResult> {
        self.policies
            .iter()
            .filter(|p| p.outcome.is_fail())
            .collect()
    }

    /// Serialize to JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Serialize to compact JSON
    pub fn to_json_compact(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Parse from JSON
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

/// Single policy result with findings and evidence
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResult {
    /// Policy identity
    pub identity: PolicyIdentity,

    /// Check outcome
    pub outcome: Outcome,

    /// Weight for posture calculation
    pub weight: f32,

    /// Compliance findings (contains expected/actual values)
    pub findings: Vec<ComplianceFinding>,

    /// Collected evidence
    pub evidence: Evidence,
}

impl PolicyResult {
    /// Create a new policy result
    pub fn new(
        identity: PolicyIdentity,
        outcome: Outcome,
        weight: f32,
        findings: Vec<ComplianceFinding>,
        evidence: Evidence,
    ) -> Self {
        Self {
            identity,
            outcome,
            weight,
            findings,
            evidence,
        }
    }

    /// Create from policy details
    pub fn from_policy(
        policy_id: impl Into<String>,
        platform: impl Into<String>,
        criticality: Criticality,
        control_mappings: Vec<ControlMapping>,
        outcome: Outcome,
    ) -> Self {
        let identity = PolicyIdentity::new(policy_id, platform, criticality, control_mappings);
        let weight = criticality.default_weight();
        Self {
            identity,
            outcome,
            weight,
            findings: Vec::new(),
            evidence: Evidence::new(),
        }
    }

    /// Set weight
    pub fn with_weight(mut self, weight: f32) -> Self {
        self.weight = weight;
        self
    }

    /// Add finding
    pub fn add_finding(&mut self, finding: ComplianceFinding) {
        self.findings.push(finding);
    }

    /// Set findings
    pub fn with_findings(mut self, findings: Vec<ComplianceFinding>) -> Self {
        self.findings = findings;
        self
    }

    /// Set evidence
    pub fn with_evidence(mut self, evidence: Evidence) -> Self {
        self.evidence = evidence;
        self
    }

    /// Check if passed
    pub fn is_pass(&self) -> bool {
        self.outcome.is_pass()
    }

    /// Get policy ID
    pub fn policy_id(&self) -> &str {
        &self.identity.policy_id
    }

    /// Get criticality
    pub fn criticality(&self) -> Criticality {
        self.identity.criticality
    }

    /// Get finding count
    pub fn finding_count(&self) -> usize {
        self.findings.len()
    }
}

// ============================================================================
// Builder
// ============================================================================

/// Builder for constructing full results
pub struct FullResultBuilder {
    agent: AgentInfo,
    host: HostInfo,
    policies: Vec<PolicyResult>,
}

impl FullResultBuilder {
    /// Create a new builder
    pub fn new(agent: AgentInfo, host: HostInfo) -> Self {
        Self {
            agent,
            host,
            policies: Vec::new(),
        }
    }

    /// Add a policy result
    pub fn add_policy(&mut self, policy: PolicyResult) {
        self.policies.push(policy);
    }

    /// Add policy from details
    #[allow(clippy::too_many_arguments)]
    pub fn add_policy_result(
        &mut self,
        policy_id: impl Into<String>,
        platform: impl Into<String>,
        criticality: Criticality,
        control_mappings: Vec<ControlMapping>,
        outcome: Outcome,
        weight: f32,
        findings: Vec<ComplianceFinding>,
        evidence: Evidence,
    ) {
        let identity = PolicyIdentity::new(policy_id, platform, criticality, control_mappings);
        let policy = PolicyResult::new(identity, outcome, weight, findings, evidence);
        self.policies.push(policy);
    }

    /// Build the full result
    pub fn build(self) -> Result<FullResult, ResultError> {
        // Build summary from policies
        let mut summary = ScanSummary::new();
        for policy in &self.policies {
            let passed = policy.outcome.is_pass();
            summary.record(passed, policy.identity.criticality, policy.weight);
            if policy.outcome.is_error() {
                summary.record_error();
            }
        }

        // Compute evidence hash from all policy evidence
        let evidence_hash = compute_evidence_hash(&self.policies)?;

        // Build envelope
        let mut envelope = ResultEnvelope::new(self.agent, self.host);
        envelope = envelope.with_evidence_hash(evidence_hash);

        // Compute content hash
        let content_hash = compute_content_hash(&summary, &self.policies)?;
        envelope = envelope.with_content_hash(content_hash);

        Ok(FullResult::new(envelope, summary, self.policies))
    }
}

/// Compute evidence hash from all policies
fn compute_evidence_hash(policies: &[PolicyResult]) -> Result<String, ResultError> {
    use super::crypto::hash_content;

    // Collect all evidence data
    let evidence_data: Vec<_> = policies
        .iter()
        .map(|p| (&p.identity.policy_id, &p.evidence.data))
        .collect();

    hash_content(&evidence_data).map_err(|e| ResultError::HashingError(e.to_string()))
}

/// Compute content hash for full result
fn compute_content_hash(
    summary: &ScanSummary,
    policies: &[PolicyResult],
) -> Result<String, ResultError> {
    use super::crypto::hash_content;

    #[derive(serde::Serialize)]
    struct Content<'a> {
        summary: &'a ScanSummary,
        policies: &'a [PolicyResult],
    }

    let content = Content { summary, policies };
    hash_content(&content).map_err(|e| ResultError::HashingError(e.to_string()))
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
    use crate::results::finding::FindingSeverity;

    #[test]
    fn test_policy_result_new() {
        let identity = PolicyIdentity::new(
            "test-policy",
            "linux",
            Criticality::High,
            vec![ControlMapping::new("CIS", "5.1.1")],
        );

        let policy = PolicyResult::new(identity, Outcome::Fail, 0.8, vec![], Evidence::new());

        assert_eq!(policy.policy_id(), "test-policy");
        assert!(!policy.is_pass());
    }

    #[test]
    fn test_policy_result_with_findings() {
        let mut policy =
            PolicyResult::from_policy("test", "linux", Criticality::Medium, vec![], Outcome::Fail);

        policy.add_finding(ComplianceFinding::auto_id(
            FindingSeverity::Medium,
            "Test finding",
            "Description",
            serde_json::json!("expected"),
            serde_json::json!("actual"),
        ));

        assert_eq!(policy.finding_count(), 1);
    }

    #[test]
    fn test_full_result_builder() {
        let agent = AgentInfo::new("agent-1", "test", "1.0.0", "cli");
        let host = HostInfo::new("host-1", "testhost", "linux", "x86_64");

        let mut builder = FullResultBuilder::new(agent, host);

        builder.add_policy_result(
            "policy-1",
            "linux",
            Criticality::High,
            vec![ControlMapping::new("CIS", "1.1.1")],
            Outcome::Pass,
            0.8,
            vec![],
            Evidence::new(),
        );

        builder.add_policy_result(
            "policy-2",
            "linux",
            Criticality::Medium,
            vec![ControlMapping::new("CIS", "1.1.2")],
            Outcome::Fail,
            0.5,
            vec![ComplianceFinding::auto_id(
                FindingSeverity::Medium,
                "Failed check",
                "Description",
                serde_json::json!({}),
                serde_json::json!({}),
            )],
            Evidence::new(),
        );

        let result = builder.build().unwrap();

        assert_eq!(result.policy_count(), 2);
        assert_eq!(result.summary.passed, 1);
        assert_eq!(result.summary.failed, 1);
        assert_eq!(result.all_findings().len(), 1);
    }

    #[test]
    fn test_full_result_serialization() {
        let agent = AgentInfo::default();
        let host = HostInfo::default();

        let mut builder = FullResultBuilder::new(agent, host);
        builder.add_policy_result(
            "test",
            "linux",
            Criticality::Medium,
            vec![],
            Outcome::Pass,
            0.5,
            vec![],
            Evidence::new(),
        );

        let result = builder.build().unwrap();
        let json = result.to_json().unwrap();
        let parsed = FullResult::from_json(&json).unwrap();

        assert_eq!(parsed.policy_count(), 1);
    }
}
