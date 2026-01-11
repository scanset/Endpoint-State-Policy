//! Unified result builder interface
//!
//! Provides a single entry point for building results from ExecutionManifest.
//! The output type depends on the enabled feature.
//!
//! ## Hash Architecture
//!
//! All build methods require pre-computed `content_hash` and `evidence_hash`
//! from the ExecutionManifest. Hashes are computed ONCE during execution
//! and passed through to ensure consistency across all output formats.
//!
//! ```text
//! ExecutionManifest
//!     ├── content_hash  ──┬──► AttestationResult
//!     └── evidence_hash ──┼──► FullResult
//!                         └──► AssessorPackage
//! ```

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

#[cfg(feature = "assessor-evidence")]
use super::assessor::{AssessorPackage, AssessorPackageBuilder, AssessorPolicyResult};

/// Unified result builder
///
/// Provides methods to build results based on enabled features.
/// All methods require pre-computed hashes from the execution engine.
///
/// ## Example
///
/// ```rust,ignore
/// let builder = ResultBuilder::from_system("esp-agent");
///
/// // All build methods require pre-computed hashes
/// let attestation = builder.build_attestation(
///     checks,
///     manifest.content_hash.clone(),
///     manifest.evidence_hash.clone(),
/// )?;
/// ```
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
    ///
    /// ## Arguments
    ///
    /// * `checks` - The policy check results
    /// * `content_hash` - Pre-computed content hash from ExecutionManifest
    /// * `evidence_hash` - Pre-computed evidence hash from ExecutionManifest
    ///
    /// ## Example
    ///
    /// ```rust,ignore
    /// let attestation = builder.build_attestation(
    ///     checks,
    ///     scan_result.content_hash.clone(),
    ///     scan_result.evidence_hash.clone(),
    /// )?;
    /// ```
    #[cfg(feature = "attestation")]
    pub fn build_attestation(
        self,
        checks: Vec<CheckInput>,
        content_hash: String,
        evidence_hash: String,
    ) -> Result<AttestationResult, ResultError> {
        let mut builder = AttestationBuilder::new(self.agent, self.host)
            .with_content_hash(content_hash)
            .with_evidence_hash(evidence_hash);

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

        builder.build()
    }

    /// Build a full result
    ///
    /// ## Arguments
    ///
    /// * `policies` - The policy results with evidence
    /// * `content_hash` - Pre-computed content hash from ExecutionManifest
    /// * `evidence_hash` - Pre-computed evidence hash from ExecutionManifest
    ///
    /// ## Example
    ///
    /// ```rust,ignore
    /// let full_result = builder.build_full_result(
    ///     policies,
    ///     scan_result.content_hash.clone(),
    ///     scan_result.evidence_hash.clone(),
    /// )?;
    /// ```
    #[cfg(feature = "full-results")]
    pub fn build_full_result(
        self,
        policies: Vec<PolicyInput>,
        content_hash: String,
        evidence_hash: String,
    ) -> Result<FullResult, ResultError> {
        let mut builder = FullResultBuilder::new(self.agent, self.host)
            .with_content_hash(content_hash)
            .with_evidence_hash(evidence_hash);

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

    /// Build an assessor package
    ///
    /// ## Arguments
    ///
    /// * `policies` - The policy results with full evidence and collection details
    /// * `content_hash` - Pre-computed content hash from ExecutionManifest
    /// * `evidence_hash` - Pre-computed evidence hash from ExecutionManifest
    ///
    /// ## Example
    ///
    /// ```rust,ignore
    /// let assessor_package = builder.build_assessor_package(
    ///     policies,
    ///     scan_result.content_hash.clone(),
    ///     scan_result.evidence_hash.clone(),
    /// )?;
    /// ```
    #[cfg(feature = "assessor-evidence")]
    pub fn build_assessor_package(
        self,
        policies: Vec<AssessorInput>,
        content_hash: String,
        evidence_hash: String,
    ) -> Result<AssessorPackage, ResultError> {
        let mut builder = AssessorPackageBuilder::new(self.agent, self.host)
            .with_content_hash(content_hash)
            .with_evidence_hash(evidence_hash);

        for policy in policies {
            let identity = PolicyIdentity::new(
                policy.policy_id,
                policy.platform,
                policy.criticality,
                policy.control_mappings,
            );
            let result = AssessorPolicyResult::new(
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

    /// Build both attestation and full result with consistent hashes
    ///
    /// Returns a tuple of (attestation, full_result) where both have
    /// the same content_hash and evidence_hash.
    ///
    /// ## Arguments
    ///
    /// * `policies` - The policy results with evidence
    /// * `content_hash` - Pre-computed content hash from ExecutionManifest
    /// * `evidence_hash` - Pre-computed evidence hash from ExecutionManifest
    #[cfg(all(feature = "attestation", feature = "full-results"))]
    pub fn build_both(
        self,
        policies: Vec<PolicyInput>,
        content_hash: String,
        evidence_hash: String,
    ) -> Result<(AttestationResult, FullResult), ResultError> {
        // Build checks for attestation from policies
        let checks: Vec<CheckInput> = policies
            .iter()
            .map(|p| {
                CheckInput::new(
                    p.policy_id.clone(),
                    p.platform.clone(),
                    p.criticality,
                    p.control_mappings.clone(),
                    p.outcome,
                )
                .with_weight(p.weight)
            })
            .collect();

        // Build attestation with pre-computed hashes
        let attestation = {
            let mut builder = AttestationBuilder::new(self.agent.clone(), self.host.clone())
                .with_content_hash(content_hash.clone())
                .with_evidence_hash(evidence_hash.clone());

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
            builder.build()?
        };

        // Build full result with same pre-computed hashes
        let full_result = {
            let mut builder = FullResultBuilder::new(self.agent, self.host)
                .with_content_hash(content_hash)
                .with_evidence_hash(evidence_hash);

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
            builder.build()?
        };

        Ok((attestation, full_result))
    }

    /// Build all three output formats with consistent hashes
    ///
    /// Returns a tuple of (attestation, full_result, assessor_package) where all
    /// have the same content_hash and evidence_hash.
    ///
    /// ## Arguments
    ///
    /// * `policies` - The policy results with full evidence
    /// * `content_hash` - Pre-computed content hash from ExecutionManifest
    /// * `evidence_hash` - Pre-computed evidence hash from ExecutionManifest
    #[cfg(all(
        feature = "attestation",
        feature = "full-results",
        feature = "assessor-evidence"
    ))]
    pub fn build_all(
        self,
        policies: Vec<PolicyInput>,
        content_hash: String,
        evidence_hash: String,
    ) -> Result<(AttestationResult, FullResult, AssessorPackage), ResultError> {
        // Build checks for attestation
        let checks: Vec<CheckInput> = policies
            .iter()
            .map(|p| {
                CheckInput::new(
                    p.policy_id.clone(),
                    p.platform.clone(),
                    p.criticality,
                    p.control_mappings.clone(),
                    p.outcome,
                )
                .with_weight(p.weight)
            })
            .collect();

        // Build assessor inputs
        let assessor_inputs: Vec<AssessorInput> = policies
            .iter()
            .map(|p| {
                AssessorInput::new(
                    p.policy_id.clone(),
                    p.platform.clone(),
                    p.criticality,
                    p.control_mappings.clone(),
                    p.outcome,
                )
                .with_weight(p.weight)
                .with_findings(p.findings.clone())
                .with_evidence(p.evidence.clone())
            })
            .collect();

        // Build attestation
        let attestation = {
            let mut builder = AttestationBuilder::new(self.agent.clone(), self.host.clone())
                .with_content_hash(content_hash.clone())
                .with_evidence_hash(evidence_hash.clone());

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
            builder.build()?
        };

        // Build full result
        let full_result = {
            let mut builder = FullResultBuilder::new(self.agent.clone(), self.host.clone())
                .with_content_hash(content_hash.clone())
                .with_evidence_hash(evidence_hash.clone());

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
            builder.build()?
        };

        // Build assessor package
        let assessor_package = {
            let mut builder = AssessorPackageBuilder::new(self.agent, self.host)
                .with_content_hash(content_hash)
                .with_evidence_hash(evidence_hash);

            for policy in assessor_inputs {
                let identity = PolicyIdentity::new(
                    policy.policy_id,
                    policy.platform,
                    policy.criticality,
                    policy.control_mappings,
                );
                let result = AssessorPolicyResult::new(
                    identity,
                    policy.outcome,
                    policy.weight,
                    policy.findings,
                    policy.evidence,
                );
                builder.add_policy(result);
            }
            builder.build()?
        };

        Ok((attestation, full_result, assessor_package))
    }
}

// ============================================================================
// Input Types
// ============================================================================

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

/// Input for building a policy result (full results)
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

/// Input for building an assessor policy result
#[cfg(feature = "assessor-evidence")]
#[derive(Debug, Clone)]
pub struct AssessorInput {
    pub policy_id: String,
    pub platform: String,
    pub criticality: Criticality,
    pub control_mappings: Vec<ControlMapping>,
    pub outcome: Outcome,
    pub weight: f32,
    pub findings: Vec<ComplianceFinding>,
    pub evidence: Evidence,
}

#[cfg(feature = "assessor-evidence")]
impl AssessorInput {
    /// Create a new assessor input
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

        let result = builder
            .build_attestation(
                checks,
                "sha256:content123".to_string(),
                "sha256:evidence456".to_string(),
            )
            .unwrap();

        assert_eq!(result.check_count(), 2);
        assert_eq!(result.summary.passed, 1);
        assert_eq!(result.summary.failed, 1);
        assert_eq!(result.envelope.content_hash, "sha256:content123");
        assert_eq!(result.envelope.evidence_hash, "sha256:evidence456");
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

        let result = builder
            .build_full_result(
                policies,
                "sha256:content123".to_string(),
                "sha256:evidence456".to_string(),
            )
            .unwrap();

        assert_eq!(result.policy_count(), 1);
        assert_eq!(result.summary.passed, 1);
        assert_eq!(result.envelope.content_hash, "sha256:content123");
        assert_eq!(result.envelope.evidence_hash, "sha256:evidence456");
    }

    #[cfg(feature = "assessor-evidence")]
    #[test]
    fn test_build_assessor_package() {
        let builder = ResultBuilder::from_system("test-agent");

        let policies = vec![AssessorInput::new(
            "policy-1",
            "linux",
            Criticality::High,
            vec![ControlMapping::new("CIS", "1.1.1")],
            Outcome::Pass,
        )];

        let result = builder
            .build_assessor_package(
                policies,
                "sha256:content123".to_string(),
                "sha256:evidence456".to_string(),
            )
            .unwrap();

        assert_eq!(result.policy_count(), 1);
        assert!(result.all_passed());
        assert_eq!(result.envelope.content_hash, "sha256:content123");
        assert_eq!(result.envelope.evidence_hash, "sha256:evidence456");
    }

    #[cfg(all(feature = "attestation", feature = "full-results"))]
    #[test]
    fn test_build_both_has_same_hashes() {
        let builder = ResultBuilder::from_system("test-agent");

        let policies = vec![PolicyInput::new(
            "policy-1",
            "linux",
            Criticality::High,
            vec![ControlMapping::new("CIS", "1.1.1")],
            Outcome::Pass,
        )];

        let (attestation, full_result) = builder
            .build_both(
                policies,
                "sha256:content123".to_string(),
                "sha256:evidence456".to_string(),
            )
            .unwrap();

        // CRITICAL: Both must have same hashes
        assert_eq!(
            attestation.envelope.content_hash,
            full_result.envelope.content_hash
        );
        assert_eq!(
            attestation.envelope.evidence_hash,
            full_result.envelope.evidence_hash
        );
    }

    #[cfg(all(
        feature = "attestation",
        feature = "full-results",
        feature = "assessor-evidence"
    ))]
    #[test]
    fn test_build_all_has_same_hashes() {
        let builder = ResultBuilder::from_system("test-agent");

        let policies = vec![PolicyInput::new(
            "policy-1",
            "linux",
            Criticality::High,
            vec![ControlMapping::new("CIS", "1.1.1")],
            Outcome::Pass,
        )];

        let (attestation, full_result, assessor_package) = builder
            .build_all(
                policies,
                "sha256:content123".to_string(),
                "sha256:evidence456".to_string(),
            )
            .unwrap();

        // CRITICAL: All three must have same hashes
        assert_eq!(
            attestation.envelope.content_hash,
            full_result.envelope.content_hash
        );
        assert_eq!(
            attestation.envelope.evidence_hash,
            full_result.envelope.evidence_hash
        );
        assert_eq!(
            full_result.envelope.content_hash,
            assessor_package.envelope.content_hash
        );
        assert_eq!(
            full_result.envelope.evidence_hash,
            assessor_package.envelope.evidence_hash
        );
    }
}
