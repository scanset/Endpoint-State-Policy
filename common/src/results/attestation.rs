//! Attestation types for CUI-free compliance results
//!
//! Attestations contain only metadata about compliance checks - no actual
//! system values. Safe for SaaS and network transport.
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
//! ## Feature
//!
//! This module requires the `attestation` feature (enabled by default).

use serde::{Deserialize, Serialize};

use super::common::{ControlMapping, Criticality, Outcome};
use super::envelope::{AgentInfo, HostInfo, ResultEnvelope};
use super::error::ResultError;
use super::identity::PolicyIdentity;
use super::summary::ScanSummary;

/// Complete attestation result for a scan
///
/// Contains per-policy pass/fail without any system values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationResult {
    /// Envelope with metadata and signatures
    pub envelope: ResultEnvelope,

    /// Aggregate statistics
    pub summary: ScanSummary,

    /// Per-policy attestations
    pub checks: Vec<CheckAttestation>,
}

impl AttestationResult {
    /// Create a new attestation result
    pub fn new(
        envelope: ResultEnvelope,
        summary: ScanSummary,
        checks: Vec<CheckAttestation>,
    ) -> Self {
        Self {
            envelope,
            summary,
            checks,
        }
    }

    /// Get number of checks
    pub fn check_count(&self) -> usize {
        self.checks.len()
    }

    /// Get passing checks
    pub fn passing_checks(&self) -> Vec<&CheckAttestation> {
        self.checks.iter().filter(|c| c.outcome.is_pass()).collect()
    }

    /// Get failing checks
    pub fn failing_checks(&self) -> Vec<&CheckAttestation> {
        self.checks.iter().filter(|c| c.outcome.is_fail()).collect()
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

/// Single policy check attestation
///
/// Contains outcome and identity without system values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckAttestation {
    /// Policy identity (id, platform, criticality, control_mappings)
    pub identity: PolicyIdentity,

    /// Check outcome
    pub outcome: Outcome,

    /// Weight for posture calculation
    pub weight: f32,
}

impl CheckAttestation {
    /// Create a new check attestation
    pub fn new(identity: PolicyIdentity, outcome: Outcome, weight: f32) -> Self {
        Self {
            identity,
            outcome,
            weight,
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
        Self::new(identity, outcome, weight)
    }

    /// Set explicit weight
    pub fn with_weight(mut self, weight: f32) -> Self {
        self.weight = weight;
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
}

// ============================================================================
// Builder
// ============================================================================

/// Builder for constructing attestation results
///
/// ## Hash Handling
///
/// This builder requires pre-computed hashes from the execution engine.
/// It does NOT compute hashes itself - this ensures consistency across
/// all output formats.
///
/// ```rust,ignore
/// let builder = AttestationBuilder::new(agent, host)
///     .with_content_hash(manifest.content_hash.clone())
///     .with_evidence_hash(manifest.evidence_hash.clone());
/// ```
pub struct AttestationBuilder {
    agent: AgentInfo,
    host: HostInfo,
    checks: Vec<CheckAttestation>,
    content_hash: Option<String>,
    evidence_hash: Option<String>,
}

impl AttestationBuilder {
    /// Create a new builder
    pub fn new(agent: AgentInfo, host: HostInfo) -> Self {
        Self {
            agent,
            host,
            checks: Vec::new(),
            content_hash: None,
            evidence_hash: None,
        }
    }

    /// Add a check attestation
    pub fn add_check(&mut self, check: CheckAttestation) {
        self.checks.push(check);
    }

    /// Add check from policy details
    pub fn add_policy_check(
        &mut self,
        policy_id: impl Into<String>,
        platform: impl Into<String>,
        criticality: Criticality,
        control_mappings: Vec<ControlMapping>,
        outcome: Outcome,
        weight: f32,
    ) {
        let identity = PolicyIdentity::new(policy_id, platform, criticality, control_mappings);
        let check = CheckAttestation::new(identity, outcome, weight);
        self.checks.push(check);
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

    /// Build the attestation result
    ///
    /// ## Errors
    ///
    /// Returns an error if `content_hash` or `evidence_hash` were not provided.
    /// These are required to ensure hash consistency across output formats.
    pub fn build(self) -> Result<AttestationResult, ResultError> {
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

        // Build summary from checks
        let mut summary = ScanSummary::new();
        for check in &self.checks {
            let passed = check.outcome.is_pass();
            summary.record(passed, check.identity.criticality, check.weight);
            if check.outcome.is_error() {
                summary.record_error();
            }
        }

        // Build envelope with pre-computed hashes
        let envelope = ResultEnvelope::new(self.agent, self.host)
            .with_content_hash(content_hash)
            .with_evidence_hash(evidence_hash);

        Ok(AttestationResult::new(envelope, summary, self.checks))
    }
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
    fn test_check_attestation_new() {
        let identity = PolicyIdentity::new(
            "test-policy",
            "linux",
            Criticality::High,
            vec![ControlMapping::new("CIS", "5.1.1")],
        );

        let check = CheckAttestation::new(identity, Outcome::Pass, 0.8);

        assert_eq!(check.policy_id(), "test-policy");
        assert!(check.is_pass());
        assert_eq!(check.weight, 0.8);
    }

    #[test]
    fn test_attestation_builder_with_hashes() {
        let agent = AgentInfo::new("agent-1", "test", "1.0.0", "cli");
        let host = HostInfo::new("host-1", "testhost", "linux", "x86_64");

        let mut builder = AttestationBuilder::new(agent, host)
            .with_content_hash("sha256:content123")
            .with_evidence_hash("sha256:evidence456");

        builder.add_policy_check(
            "policy-1",
            "linux",
            Criticality::High,
            vec![ControlMapping::new("CIS", "1.1.1")],
            Outcome::Pass,
            0.8,
        );

        builder.add_policy_check(
            "policy-2",
            "linux",
            Criticality::Medium,
            vec![ControlMapping::new("CIS", "1.1.2")],
            Outcome::Fail,
            0.5,
        );

        let result = builder.build().unwrap();

        assert_eq!(result.check_count(), 2);
        assert_eq!(result.summary.total_policies, 2);
        assert_eq!(result.summary.passed, 1);
        assert_eq!(result.summary.failed, 1);
        // Verify hashes are preserved
        assert_eq!(result.envelope.content_hash, "sha256:content123");
        assert_eq!(result.envelope.evidence_hash, "sha256:evidence456");
    }

    #[test]
    fn test_attestation_builder_requires_hashes() {
        let agent = AgentInfo::default();
        let host = HostInfo::default();

        let mut builder = AttestationBuilder::new(agent, host);
        builder.add_policy_check(
            "test",
            "linux",
            Criticality::Medium,
            vec![],
            Outcome::Pass,
            0.5,
        );

        // Should fail without hashes
        let result = builder.build();
        assert!(result.is_err());
    }

    #[test]
    fn test_attestation_serialization() {
        let agent = AgentInfo::default();
        let host = HostInfo::default();

        let mut builder = AttestationBuilder::new(agent, host)
            .with_content_hash("sha256:test")
            .with_evidence_hash("sha256:test");

        builder.add_policy_check(
            "test",
            "linux",
            Criticality::Medium,
            vec![],
            Outcome::Pass,
            0.5,
        );

        let result = builder.build().unwrap();
        let json = result.to_json().unwrap();
        let parsed = AttestationResult::from_json(&json).unwrap();

        assert_eq!(parsed.check_count(), 1);
    }
}
