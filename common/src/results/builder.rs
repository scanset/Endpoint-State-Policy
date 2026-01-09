//! Unified result builder interface
//!
//! Provides a single entry point for building results from ExecutionManifest.
//! The output type depends on the enabled feature.

use super::common::{ControlMapping, Criticality, Outcome};
use super::envelope::{AgentInfo, HostInfo};
use super::error::ResultError;
use super::identity::PolicyIdentity;

#[cfg(feature = "attestation")]
use super::attestation::{AttestationBuilder, AttestationResult, CheckAttestation};

#[cfg(feature = "full-results")]
use super::evidence::Evidence;
#[cfg(feature = "full-results")]
use super::finding::ComplianceFinding;
#[cfg(feature = "full-results")]
use super::full::{FullResult, FullResultBuilder, PolicyResult};

/// Unified result builder
///
/// Provides methods to build results based on enabled features.
pub struct ResultBuilder {
    agent: AgentInfo,
    host: HostInfo,
}

impl ResultBuilder {
    /// Create a new result builder
    pub fn new(agent: AgentInfo, host: HostInfo) -> Self {
        Self { agent, host }
    }

    /// Create with default agent and host from system
    pub fn from_system(agent_id: impl Into<String>) -> Self {
        Self {
            agent: AgentInfo::with_defaults(agent_id),
            host: HostInfo::from_system(),
        }
    }

    /// Build an attestation result
    #[cfg(feature = "attestation")]
    pub fn build_attestation(
        self,
        checks: Vec<CheckInput>,
        evidence_hash: Option<String>,
    ) -> Result<AttestationResult, ResultError> {
        let mut builder = AttestationBuilder::new(self.agent, self.host);

        for check in checks {
            let identity = PolicyIdentity::new(
                check.policy_id,
                check.platform,
                check.criticality,
                check.control_mappings,
            );
            let attestation = CheckAttestation::new(identity, check.outcome, check.weight);
            builder.add_check(attestation);
        }

        if let Some(hash) = evidence_hash {
            builder = builder.with_evidence_hash(hash);
        }

        builder.build()
    }

    /// Build a full result
    #[cfg(feature = "full-results")]
    pub fn build_full_result(self, policies: Vec<PolicyInput>) -> Result<FullResult, ResultError> {
        let mut builder = FullResultBuilder::new(self.agent, self.host);

        for policy in policies {
            let identity = PolicyIdentity::new(
                policy.policy_id,
                policy.platform,
                policy.criticality,
                policy.control_mappings,
            );
            let result = PolicyResult::new(
                identity,
                policy.outcome,
                policy.weight,
                policy.findings,
                policy.evidence,
            );
            builder.add_policy(result);
        }

        builder.build()
    }

    /// Build both attestation and full result
    ///
    /// Returns a tuple of (attestation, full_result) where the attestation's
    /// evidence_hash matches the full result's evidence.
    #[cfg(all(feature = "attestation", feature = "full-results"))]
    pub fn build_both(
        self,
        policies: Vec<PolicyInput>,
    ) -> Result<(AttestationResult, FullResult), ResultError> {
        // Build full result first to get evidence hash
        #[allow(unused_variables)]
        let full_builder = FullResultBuilder::new(self.agent.clone(), self.host.clone());
        let mut full_policies = Vec::with_capacity(policies.len());

        for policy in &policies {
            let identity = PolicyIdentity::new(
                policy.policy_id.clone(),
                policy.platform.clone(),
                policy.criticality,
                policy.control_mappings.clone(),
            );
            let result = PolicyResult::new(
                identity,
                policy.outcome,
                policy.weight,
                policy.findings.clone(),
                policy.evidence.clone(),
            );
            full_policies.push(result);
        }

        // Build full result
        let mut temp_builder = FullResultBuilder::new(self.agent.clone(), self.host.clone());
        for policy in full_policies.clone() {
            temp_builder.add_policy(policy);
        }
        let full_result = temp_builder.build()?;

        // Get evidence hash from full result
        let evidence_hash = full_result.envelope.evidence_hash.clone();

        // Build attestation with same evidence hash
        let mut att_builder = AttestationBuilder::new(self.agent, self.host);
        for policy in &policies {
            let identity = PolicyIdentity::new(
                policy.policy_id.clone(),
                policy.platform.clone(),
                policy.criticality,
                policy.control_mappings.clone(),
            );
            let check = CheckAttestation::new(identity, policy.outcome, policy.weight);
            att_builder.add_check(check);
        }
        let attestation = att_builder.with_evidence_hash(evidence_hash).build()?;

        Ok((attestation, full_result))
    }
}

/// Input for building a check attestation
#[cfg(feature = "attestation")]
#[derive(Debug, Clone)]
pub struct CheckInput {
    pub policy_id: String,
    pub platform: String,
    pub criticality: Criticality,
    pub control_mappings: Vec<ControlMapping>,
    pub outcome: Outcome,
    pub weight: f32,
}

#[cfg(feature = "attestation")]
impl CheckInput {
    /// Create a new check input
    pub fn new(
        policy_id: impl Into<String>,
        platform: impl Into<String>,
        criticality: Criticality,
        control_mappings: Vec<ControlMapping>,
        outcome: Outcome,
    ) -> Self {
        Self {
            policy_id: policy_id.into(),
            platform: platform.into(),
            criticality,
            control_mappings,
            outcome,
            weight: criticality.default_weight(),
        }
    }

    /// Set explicit weight
    pub fn with_weight(mut self, weight: f32) -> Self {
        self.weight = weight;
        self
    }
}

/// Input for building a policy result
#[cfg(feature = "full-results")]
#[derive(Debug, Clone)]
pub struct PolicyInput {
    pub policy_id: String,
    pub platform: String,
    pub criticality: Criticality,
    pub control_mappings: Vec<ControlMapping>,
    pub outcome: Outcome,
    pub weight: f32,
    pub findings: Vec<ComplianceFinding>,
    pub evidence: Evidence,
}

#[cfg(feature = "full-results")]
impl PolicyInput {
    /// Create a new policy input
    pub fn new(
        policy_id: impl Into<String>,
        platform: impl Into<String>,
        criticality: Criticality,
        control_mappings: Vec<ControlMapping>,
        outcome: Outcome,
    ) -> Self {
        Self {
            policy_id: policy_id.into(),
            platform: platform.into(),
            criticality,
            control_mappings,
            outcome,
            weight: criticality.default_weight(),
            findings: Vec::new(),
            evidence: Evidence::new(),
        }
    }

    /// Set explicit weight
    pub fn with_weight(mut self, weight: f32) -> Self {
        self.weight = weight;
        self
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

    #[cfg(feature = "attestation")]
    #[test]
    fn test_build_attestation() {
        let builder = ResultBuilder::from_system("test-agent");

        let checks = vec![
            CheckInput::new(
                "policy-1",
                "linux",
                Criticality::High,
                vec![ControlMapping::new("CIS", "1.1.1")],
                Outcome::Pass,
            ),
            CheckInput::new(
                "policy-2",
                "linux",
                Criticality::Medium,
                vec![ControlMapping::new("CIS", "1.1.2")],
                Outcome::Fail,
            ),
        ];

        let result = builder.build_attestation(checks, None).unwrap();

        assert_eq!(result.check_count(), 2);
        assert_eq!(result.summary.passed, 1);
        assert_eq!(result.summary.failed, 1);
    }

    #[cfg(feature = "full-results")]
    #[test]
    fn test_build_full_result() {
        let builder = ResultBuilder::from_system("test-agent");

        let policies = vec![PolicyInput::new(
            "policy-1",
            "linux",
            Criticality::High,
            vec![ControlMapping::new("CIS", "1.1.1")],
            Outcome::Pass,
        )];

        let result = builder.build_full_result(policies).unwrap();

        assert_eq!(result.policy_count(), 1);
        assert_eq!(result.summary.passed, 1);
    }

    #[cfg(all(feature = "attestation", feature = "full-results"))]
    #[test]
    fn test_build_both() {
        let builder = ResultBuilder::from_system("test-agent");

        let policies = vec![PolicyInput::new(
            "policy-1",
            "linux",
            Criticality::High,
            vec![ControlMapping::new("CIS", "1.1.1")],
            Outcome::Pass,
        )];

        let (attestation, full_result) = builder.build_both(policies).unwrap();

        // Evidence hashes should match
        assert_eq!(
            attestation.envelope.evidence_hash,
            full_result.envelope.evidence_hash
        );
    }
}
