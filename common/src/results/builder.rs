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
//! ## Identity Status
//!
//! As of schema v1.1.0, all build methods require an `identity_status` parameter
//! that indicates whether PKI identity was established during bootstrap.
//!
//! ```text
//! ExecutionManifest
//!     ├── content_hash  ──┬──► AttestationResult
//!     ├── evidence_hash ──┼──► FullResult
//!     └── identity_status ┴──► AssessorPackage
//! ```

use std::collections::HashMap;

use super::common::{ControlMapping, Criticality, Outcome};
use super::envelope::{AgentInfo, HostInfo};
use super::error::ResultError;
use super::identity::PolicyIdentity;
use super::identity_status::IdentityStatus;

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

// ============================================================================
// Policy Metadata (shared across input types)
// ============================================================================

/// Extended policy metadata for building PolicyIdentity
///
/// Contains all the optional and extended fields from META block.
/// Used by `CheckInput`, `PolicyInput`, and `AssessorInput`.
#[derive(Debug, Clone, Default)]
pub struct PolicyMetadata {
    /// Policy version/revision
    pub version: Option<String>,
    /// DSL schema version
    pub dsl_schema_version: Option<String>,
    /// Policy title
    pub title: Option<String>,
    /// Policy description
    pub description: Option<String>,
    /// Policy author
    pub author: Option<String>,
    /// Policy tags
    pub tags: Vec<String>,
    /// Extended metadata (framework-specific fields)
    pub extended: HashMap<String, String>,
}

impl PolicyMetadata {
    /// Create empty metadata
    pub fn new() -> Self {
        Self::default()
    }

    /// Set version
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Set DSL schema version
    pub fn with_dsl_schema_version(mut self, version: impl Into<String>) -> Self {
        self.dsl_schema_version = Some(version.into());
        self
    }

    /// Set title
    pub fn with_title(mut self, title: impl Into<String>) -> Self {
        self.title = Some(title.into());
        self
    }

    /// Set description
    pub fn with_description(mut self, description: impl Into<String>) -> Self {
        self.description = Some(description.into());
        self
    }

    /// Set author
    pub fn with_author(mut self, author: impl Into<String>) -> Self {
        self.author = Some(author.into());
        self
    }

    /// Set tags
    pub fn with_tags(mut self, tags: Vec<String>) -> Self {
        self.tags = tags;
        self
    }

    /// Set extended metadata (replaces existing)
    pub fn with_extended(mut self, extended: HashMap<String, String>) -> Self {
        self.extended = extended;
        self
    }

    /// Add a single extended metadata field
    pub fn with_extended_field(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extended.insert(key.into(), value.into());
        self
    }

    /// Check if metadata has any content
    pub fn is_empty(&self) -> bool {
        self.version.is_none()
            && self.dsl_schema_version.is_none()
            && self.title.is_none()
            && self.description.is_none()
            && self.author.is_none()
            && self.tags.is_empty()
            && self.extended.is_empty()
    }

    /// Apply this metadata to a PolicyIdentity
    pub fn apply_to(self, mut identity: PolicyIdentity) -> PolicyIdentity {
        if let Some(v) = self.version {
            identity.version = Some(v);
        }
        if let Some(v) = self.dsl_schema_version {
            identity.dsl_schema_version = Some(v);
        }
        if let Some(v) = self.title {
            identity.title = Some(v);
        }
        if let Some(v) = self.description {
            identity.description = Some(v);
        }
        if let Some(v) = self.author {
            identity.author = Some(v);
        }
        if !self.tags.is_empty() {
            identity.tags = self.tags;
        }
        if !self.extended.is_empty() {
            identity.metadata = self.extended;
        }
        identity
    }
}

// ============================================================================
// Result Builder
// ============================================================================

/// Unified result builder
///
/// Provides methods to build results based on enabled features.
/// All methods require pre-computed hashes and identity status.
///
/// ## Example
///
/// ```rust,ignore
/// let builder = ResultBuilder::from_system("esp-agent");
/// let identity_status = IdentityStatus::success("scanset://prod/aws/...");
///
/// // All build methods require pre-computed hashes and identity status
/// let attestation = builder.build_attestation(
///     checks,
///     manifest.content_hash.clone(),
///     manifest.evidence_hash.clone(),
///     identity_status,
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
    /// * `identity_status` - PKI bootstrap status
    #[cfg(feature = "attestation")]
    pub fn build_attestation(
        self,
        checks: Vec<CheckInput>,
        content_hash: String,
        evidence_hash: String,
        identity_status: IdentityStatus,
    ) -> Result<AttestationResult, ResultError> {
        let mut builder = AttestationBuilder::new(self.agent, self.host)
            .with_content_hash(content_hash)
            .with_evidence_hash(evidence_hash)
            .with_identity_status(identity_status);

        for check in checks {
            let identity = check.to_policy_identity();
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
    /// * `identity_status` - PKI bootstrap status
    #[cfg(feature = "full-results")]
    pub fn build_full_result(
        self,
        policies: Vec<PolicyInput>,
        content_hash: String,
        evidence_hash: String,
        identity_status: IdentityStatus,
    ) -> Result<FullResult, ResultError> {
        let mut builder = FullResultBuilder::new(self.agent, self.host)
            .with_content_hash(content_hash)
            .with_evidence_hash(evidence_hash)
            .with_identity_status(identity_status);

        for policy in policies {
            let identity = policy.to_policy_identity();
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
    /// * `identity_status` - PKI bootstrap status
    #[cfg(feature = "assessor-evidence")]
    pub fn build_assessor_package(
        self,
        policies: Vec<AssessorInput>,
        content_hash: String,
        evidence_hash: String,
        identity_status: IdentityStatus,
    ) -> Result<AssessorPackage, ResultError> {
        let mut builder = AssessorPackageBuilder::new(self.agent, self.host)
            .with_content_hash(content_hash)
            .with_evidence_hash(evidence_hash)
            .with_identity_status(identity_status);

        for policy in policies {
            let identity = policy.to_policy_identity();
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
    /// the same content_hash, evidence_hash, and identity_status.
    #[cfg(all(feature = "attestation", feature = "full-results"))]
    pub fn build_both(
        self,
        policies: Vec<PolicyInput>,
        content_hash: String,
        evidence_hash: String,
        identity_status: IdentityStatus,
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
                .with_metadata(p.metadata.clone())
            })
            .collect();

        // Build attestation with pre-computed hashes and identity status
        let attestation = {
            let mut builder = AttestationBuilder::new(self.agent.clone(), self.host.clone())
                .with_content_hash(content_hash.clone())
                .with_evidence_hash(evidence_hash.clone())
                .with_identity_status(identity_status.clone());

            for check in checks {
                let identity = check.to_policy_identity();
                let attestation = CheckAttestation::new(identity, check.outcome, check.weight);
                builder.add_check(attestation);
            }
            builder.build()?
        };

        // Build full result with same pre-computed hashes and identity status
        let full_result = {
            let mut builder = FullResultBuilder::new(self.agent, self.host)
                .with_content_hash(content_hash)
                .with_evidence_hash(evidence_hash)
                .with_identity_status(identity_status);

            for policy in policies {
                let identity = policy.to_policy_identity();
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
    /// have the same content_hash, evidence_hash, and identity_status.
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
        identity_status: IdentityStatus,
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
                .with_metadata(p.metadata.clone())
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
                .with_metadata(p.metadata.clone())
                .with_findings(p.findings.clone())
                .with_evidence(p.evidence.clone())
            })
            .collect();

        // Build attestation
        let attestation = {
            let mut builder = AttestationBuilder::new(self.agent.clone(), self.host.clone())
                .with_content_hash(content_hash.clone())
                .with_evidence_hash(evidence_hash.clone())
                .with_identity_status(identity_status.clone());

            for check in checks {
                let identity = check.to_policy_identity();
                let attestation = CheckAttestation::new(identity, check.outcome, check.weight);
                builder.add_check(attestation);
            }
            builder.build()?
        };

        // Build full result
        let full_result = {
            let mut builder = FullResultBuilder::new(self.agent.clone(), self.host.clone())
                .with_content_hash(content_hash.clone())
                .with_evidence_hash(evidence_hash.clone())
                .with_identity_status(identity_status.clone());

            for policy in policies {
                let identity = policy.to_policy_identity();
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
                .with_evidence_hash(evidence_hash)
                .with_identity_status(identity_status);

            for policy in assessor_inputs {
                let identity = policy.to_policy_identity();
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
    pub metadata: PolicyMetadata,
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
            metadata: PolicyMetadata::default(),
        }
    }

    /// Set explicit weight
    pub fn with_weight(mut self, weight: f32) -> Self {
        self.weight = weight;
        self
    }

    /// Set policy metadata
    pub fn with_metadata(mut self, metadata: PolicyMetadata) -> Self {
        self.metadata = metadata;
        self
    }

    /// Convert to PolicyIdentity (borrows self, clones necessary data)
    pub fn to_policy_identity(&self) -> PolicyIdentity {
        let identity = PolicyIdentity::new(
            self.policy_id.clone(),
            self.platform.clone(),
            self.criticality,
            self.control_mappings.clone(),
        );
        self.metadata.clone().apply_to(identity)
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
    pub metadata: PolicyMetadata,
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
            metadata: PolicyMetadata::default(),
            findings: Vec::new(),
            evidence: Evidence::new(),
        }
    }

    /// Set explicit weight
    pub fn with_weight(mut self, weight: f32) -> Self {
        self.weight = weight;
        self
    }

    /// Set policy metadata
    pub fn with_metadata(mut self, metadata: PolicyMetadata) -> Self {
        self.metadata = metadata;
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

    /// Convert to PolicyIdentity (borrows self, clones necessary data)
    pub fn to_policy_identity(&self) -> PolicyIdentity {
        let identity = PolicyIdentity::new(
            self.policy_id.clone(),
            self.platform.clone(),
            self.criticality,
            self.control_mappings.clone(),
        );
        self.metadata.clone().apply_to(identity)
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
    pub metadata: PolicyMetadata,
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
            metadata: PolicyMetadata::default(),
            findings: Vec::new(),
            evidence: Evidence::new(),
        }
    }

    /// Set explicit weight
    pub fn with_weight(mut self, weight: f32) -> Self {
        self.weight = weight;
        self
    }

    /// Set policy metadata
    pub fn with_metadata(mut self, metadata: PolicyMetadata) -> Self {
        self.metadata = metadata;
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

    /// Convert to PolicyIdentity (borrows self, clones necessary data)
    pub fn to_policy_identity(&self) -> PolicyIdentity {
        let identity = PolicyIdentity::new(
            self.policy_id.clone(),
            self.platform.clone(),
            self.criticality,
            self.control_mappings.clone(),
        );
        self.metadata.clone().apply_to(identity)
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

    #[test]
    fn test_policy_metadata_builder() {
        let metadata = PolicyMetadata::new()
            .with_version("1.0.0")
            .with_title("Test Policy")
            .with_tags(vec!["baseline".to_string()])
            .with_extended_field("control_objective", "CM-6_obj.1");

        assert_eq!(metadata.version, Some("1.0.0".to_string()));
        assert_eq!(metadata.title, Some("Test Policy".to_string()));
        assert_eq!(metadata.tags, vec!["baseline"]);
        assert_eq!(
            metadata.extended.get("control_objective"),
            Some(&"CM-6_obj.1".to_string())
        );
    }

    #[test]
    fn test_policy_metadata_is_empty() {
        let empty = PolicyMetadata::new();
        assert!(empty.is_empty());

        let with_version = PolicyMetadata::new().with_version("1.0.0");
        assert!(!with_version.is_empty());

        let with_extended = PolicyMetadata::new().with_extended_field("key", "value");
        assert!(!with_extended.is_empty());
    }

    #[test]
    fn test_policy_metadata_apply_to() {
        let metadata = PolicyMetadata::new()
            .with_version("1.0.0")
            .with_title("Test Policy")
            .with_extended_field("assessment_method", "TEST");

        let identity = PolicyIdentity::new("policy-1", "linux", Criticality::High, vec![]);
        let updated = metadata.apply_to(identity);

        assert_eq!(updated.version, Some("1.0.0".to_string()));
        assert_eq!(updated.title, Some("Test Policy".to_string()));
        assert_eq!(updated.get_meta("assessment_method"), Some("TEST"));
    }

    #[cfg(feature = "attestation")]
    #[test]
    fn test_check_input_with_metadata() {
        let metadata = PolicyMetadata::new()
            .with_version("1.0.0")
            .with_extended_field("control_objective", "CM-6_obj.1");

        let check = CheckInput::new(
            "policy-1",
            "linux",
            Criticality::High,
            vec![ControlMapping::new("CIS", "1.1.1")],
            Outcome::Pass,
        )
        .with_metadata(metadata);

        let identity = check.to_policy_identity();

        assert_eq!(identity.policy_id, "policy-1");
        assert_eq!(identity.version, Some("1.0.0".to_string()));
        assert_eq!(identity.get_meta("control_objective"), Some("CM-6_obj.1"));
    }

    #[cfg(feature = "attestation")]
    #[test]
    fn test_build_attestation() {
        let builder = ResultBuilder::from_system("test-agent");
        let identity_status = IdentityStatus::success("scanset://test");

        let metadata = PolicyMetadata::new()
            .with_version("1.0.0")
            .with_title("Test Policy");

        let checks = vec![
            CheckInput::new(
                "policy-1",
                "linux",
                Criticality::High,
                vec![ControlMapping::new("CIS", "1.1.1")],
                Outcome::Pass,
            )
            .with_metadata(metadata.clone()),
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
                identity_status,
            )
            .unwrap();

        assert_eq!(result.check_count(), 2);
        assert_eq!(result.summary.passed, 1);
        assert_eq!(result.summary.failed, 1);
        assert_eq!(result.envelope.content_hash, "sha256:content123");
        assert_eq!(result.envelope.evidence_hash, "sha256:evidence456");
        assert!(result.is_identity_bootstrapped());
    }

    #[cfg(feature = "attestation")]
    #[test]
    fn test_build_attestation_with_failed_identity() {
        let builder = ResultBuilder::from_system("test-agent");
        let identity_status = IdentityStatus::failed(
            "unsigned:agent:test",
            "Connection refused",
            "BOOTSTRAP_CONNECTION_FAILED",
        );

        let checks = vec![CheckInput::new(
            "policy-1",
            "linux",
            Criticality::High,
            vec![],
            Outcome::Pass,
        )];

        let result = builder
            .build_attestation(
                checks,
                "sha256:content".to_string(),
                "sha256:evidence".to_string(),
                identity_status,
            )
            .unwrap();

        assert!(!result.is_identity_bootstrapped());
        assert!(result.envelope.identity_status.has_error());
    }

    #[cfg(feature = "full-results")]
    #[test]
    fn test_build_full_result() {
        let builder = ResultBuilder::from_system("test-agent");
        let identity_status = IdentityStatus::success("scanset://test");

        let metadata = PolicyMetadata::new()
            .with_version("1.0.0")
            .with_extended_field("implementation_status", "implemented");

        let policies = vec![PolicyInput::new(
            "policy-1",
            "linux",
            Criticality::High,
            vec![ControlMapping::new("CIS", "1.1.1")],
            Outcome::Pass,
        )
        .with_metadata(metadata)];

        let result = builder
            .build_full_result(
                policies,
                "sha256:content123".to_string(),
                "sha256:evidence456".to_string(),
                identity_status,
            )
            .unwrap();

        assert_eq!(result.policy_count(), 1);
        assert_eq!(result.summary.passed, 1);
        assert_eq!(result.envelope.content_hash, "sha256:content123");
        assert_eq!(result.envelope.evidence_hash, "sha256:evidence456");
        assert!(result.is_identity_bootstrapped());
    }

    #[cfg(feature = "assessor-evidence")]
    #[test]
    fn test_build_assessor_package() {
        let builder = ResultBuilder::from_system("test-agent");
        let identity_status = IdentityStatus::disabled("unsigned:agent:test");

        let metadata = PolicyMetadata::new()
            .with_version("1.0.0")
            .with_extended_field("responsible_role", "system-admin");

        let policies = vec![AssessorInput::new(
            "policy-1",
            "linux",
            Criticality::High,
            vec![ControlMapping::new("CIS", "1.1.1")],
            Outcome::Pass,
        )
        .with_metadata(metadata)];

        let result = builder
            .build_assessor_package(
                policies,
                "sha256:content123".to_string(),
                "sha256:evidence456".to_string(),
                identity_status,
            )
            .unwrap();

        assert_eq!(result.policy_count(), 1);
        assert!(result.all_passed());
        assert_eq!(result.envelope.content_hash, "sha256:content123");
        assert_eq!(result.envelope.evidence_hash, "sha256:evidence456");
        assert!(!result.is_identity_bootstrapped());
        assert!(result.envelope.identity_status.is_disabled());
    }

    #[cfg(all(feature = "attestation", feature = "full-results"))]
    #[test]
    fn test_build_both_has_same_hashes_and_identity() {
        let builder = ResultBuilder::from_system("test-agent");
        let identity_status = IdentityStatus::success("scanset://test");

        let metadata = PolicyMetadata::new().with_version("1.0.0");

        let policies = vec![PolicyInput::new(
            "policy-1",
            "linux",
            Criticality::High,
            vec![ControlMapping::new("CIS", "1.1.1")],
            Outcome::Pass,
        )
        .with_metadata(metadata)];

        let (attestation, full_result) = builder
            .build_both(
                policies,
                "sha256:content123".to_string(),
                "sha256:evidence456".to_string(),
                identity_status,
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
        // CRITICAL: Both must have same identity status
        assert_eq!(
            attestation.envelope.identity_status.signer_id,
            full_result.envelope.identity_status.signer_id
        );
        assert_eq!(
            attestation.envelope.identity_status.bootstrapped,
            full_result.envelope.identity_status.bootstrapped
        );
    }

    #[cfg(all(
        feature = "attestation",
        feature = "full-results",
        feature = "assessor-evidence"
    ))]
    #[test]
    fn test_build_all_has_same_hashes_and_identity() {
        let builder = ResultBuilder::from_system("test-agent");
        let identity_status = IdentityStatus::success("scanset://test");

        let metadata = PolicyMetadata::new()
            .with_version("1.0.0")
            .with_extended_field("assessment_method", "TEST");

        let policies = vec![PolicyInput::new(
            "policy-1",
            "linux",
            Criticality::High,
            vec![ControlMapping::new("CIS", "1.1.1")],
            Outcome::Pass,
        )
        .with_metadata(metadata)];

        let (attestation, full_result, assessor_package) = builder
            .build_all(
                policies,
                "sha256:content123".to_string(),
                "sha256:evidence456".to_string(),
                identity_status,
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
        // CRITICAL: All three must have same identity status
        assert_eq!(
            attestation.envelope.identity_status.signer_id,
            full_result.envelope.identity_status.signer_id
        );
        assert_eq!(
            full_result.envelope.identity_status.signer_id,
            assessor_package.envelope.identity_status.signer_id
        );
    }
}
