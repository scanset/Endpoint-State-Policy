//! Attestation types for CUI-free compliance results
//!
//! Attestations contain only metadata about compliance checks - no actual
//! system values. Safe for SaaS and network transport.
//!
//! ## Hash Architecture
//!
//! The `replay_hash` is computed ONCE during execution
//! in `ExecutionEngine::execute()` and passed to the builder. The builder
//! does NOT compute the hash - it only accepts the pre-computed value.
//!
//! This ensures hash consistency across all output formats (attestation,
//! full-results, assessor-evidence). The replay hash captures intent +
//! contract + outcome rolled up through the CRI tree.
//!
//! ## Identity Status
//!
//! As of schema v1.2.0, all results include an `identity_status` field that
//! indicates whether PKI identity was established. This must be provided
//! when building attestations.
//!
//! ## Feature
//!
//! This module requires the `attestation` feature (enabled by default).

use serde::{Deserialize, Serialize};

use super::common::{ControlMapping, Criticality, Outcome};
use super::envelope::{AgentInfo, HostInfo, ResultEnvelope};
use super::error::ResultError;
use super::identity::PolicyIdentity;
use super::identity_status::IdentityStatus;
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

    /// Check if identity was bootstrapped
    pub fn is_identity_bootstrapped(&self) -> bool {
        self.envelope.identity_status.is_bootstrapped()
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
/// ## Required Fields
///
/// The builder requires the following fields to be set before building:
/// - `replay_hash` - Pre-computed from ExecutionManifest
/// - `identity_status` - PKI bootstrap status
///
/// ## Example
///
/// ```rust,ignore
/// let builder = AttestationBuilder::new(agent, host)
///     .with_replay_hash(manifest.replay_hash.clone())
///     .with_identity_status(identity_status);
///
/// builder.add_check(check);
/// let result = builder.build()?;
/// ```
pub struct AttestationBuilder {
    agent: AgentInfo,
    host: HostInfo,
    checks: Vec<CheckAttestation>,
    replay_hash: Option<String>,
    identity_status: Option<IdentityStatus>,
}

impl AttestationBuilder {
    /// Create a new builder
    pub fn new(agent: AgentInfo, host: HostInfo) -> Self {
        Self {
            agent,
            host,
            checks: Vec::new(),
            replay_hash: None,
            identity_status: None,
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

    /// Set the replay hash (pre-computed from ExecutionManifest)
    ///
    /// This hash is computed ONCE in the execution engine and must be
    /// passed through unchanged to ensure consistency.
    pub fn with_replay_hash(mut self, hash: impl Into<String>) -> Self {
        self.replay_hash = Some(hash.into());
        self
    }

    /// Set the identity status
    ///
    /// Indicates whether PKI identity was established during bootstrap.
    /// This is required for schema v1.2.0 compliance.
    pub fn with_identity_status(mut self, identity_status: IdentityStatus) -> Self {
        self.identity_status = Some(identity_status);
        self
    }

    /// Build the attestation result
    ///
    /// ## Errors
    ///
    /// Returns an error if any required field is not set:
    /// - `replay_hash`
    /// - `identity_status`
    pub fn build(self) -> Result<AttestationResult, ResultError> {
        // Require pre-computed replay hash
        let replay_hash = self.replay_hash.ok_or_else(|| {
            ResultError::BuildError(
                "replay_hash is required - must be pre-computed from ExecutionManifest".to_string(),
            )
        })?;

        // Require identity status
        let identity_status = self.identity_status.ok_or_else(|| {
            ResultError::BuildError("identity_status is required for schema v1.2.0".to_string())
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

        // Build envelope with pre-computed hash and identity status
        let envelope = ResultEnvelope::with_identity(self.agent, self.host, identity_status)
            .with_replay_hash(replay_hash);

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
    fn test_attestation_builder_with_all_required_fields() {
        let agent = AgentInfo::new("agent-1", "test", "1.0.0", "cli");
        let host = HostInfo::new("host-1", "testhost", "linux", "x86_64");
        let identity_status = IdentityStatus::success("scanset://test/workload");

        let mut builder = AttestationBuilder::new(agent, host)
            .with_replay_hash("sha256:replay123")
            .with_identity_status(identity_status);

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
        assert_eq!(result.envelope.replay_hash, "sha256:replay123");
        assert!(result.is_identity_bootstrapped());
        assert_eq!(
            result.envelope.identity_status.signer_id,
            "scanset://test/workload"
        );
    }

    #[test]
    fn test_attestation_builder_with_failed_identity() {
        let agent = AgentInfo::default();
        let host = HostInfo::default();
        let identity_status = IdentityStatus::failed(
            "unsigned:agent:test-host",
            "Connection refused",
            "BOOTSTRAP_CONNECTION_FAILED",
        );

        let mut builder = AttestationBuilder::new(agent, host)
            .with_replay_hash("sha256:replay")
            .with_identity_status(identity_status);

        builder.add_policy_check(
            "test",
            "linux",
            Criticality::Medium,
            vec![],
            Outcome::Pass,
            0.5,
        );

        let result = builder.build().unwrap();

        assert!(!result.is_identity_bootstrapped());
        assert!(result.envelope.identity_status.has_error());
        assert_eq!(
            result.envelope.identity_status.error_code(),
            Some("BOOTSTRAP_CONNECTION_FAILED")
        );
    }

    #[test]
    fn test_attestation_builder_requires_replay_hash() {
        let agent = AgentInfo::default();
        let host = HostInfo::default();

        let mut builder = AttestationBuilder::new(agent, host)
            // Missing replay_hash
            .with_identity_status(IdentityStatus::default());

        builder.add_policy_check(
            "test",
            "linux",
            Criticality::Medium,
            vec![],
            Outcome::Pass,
            0.5,
        );

        let result = builder.build();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("replay_hash is required"));
    }

    #[test]
    fn test_attestation_builder_requires_identity_status() {
        let agent = AgentInfo::default();
        let host = HostInfo::default();

        let mut builder = AttestationBuilder::new(agent, host).with_replay_hash("sha256:replay");
        // Missing identity_status

        builder.add_policy_check(
            "test",
            "linux",
            Criticality::Medium,
            vec![],
            Outcome::Pass,
            0.5,
        );

        let result = builder.build();
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("identity_status is required"));
    }

    #[test]
    fn test_attestation_serialization() {
        let agent = AgentInfo::default();
        let host = HostInfo::default();

        let mut builder = AttestationBuilder::new(agent, host)
            .with_replay_hash("sha256:test")
            .with_identity_status(IdentityStatus::success("scanset://test"));

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

        assert!(json.contains("\"identity_status\":"));
        assert!(json.contains("\"bootstrapped\": true"));

        let parsed = AttestationResult::from_json(&json).unwrap();

        assert_eq!(parsed.check_count(), 1);
        assert!(parsed.is_identity_bootstrapped());
    }
}
