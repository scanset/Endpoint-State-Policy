//! Assessor package builder extensions
//!
//! This file provides the `AssessorInput` type and `build_assessor_package` method
//! to be added to the existing `builder.rs` file.
//!
//! Add these to your existing builder.rs:

// Add this import at the top of builder.rs:
// #[cfg(feature = "assessor-evidence")]
// use super::assessor::{AssessorPackage, AssessorPackageBuilder, AssessorPolicyResult};

// ============================================================================
// Add to ResultBuilder impl block
// ============================================================================

/*
    /// Build an assessor package
    #[cfg(feature = "assessor-evidence")]
    pub fn build_assessor_package(
        self,
        policies: Vec<AssessorInput>,
    ) -> Result<AssessorPackage, ResultError> {
        let mut builder = AssessorPackageBuilder::new(self.agent, self.host);

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
*/

// ============================================================================
// AssessorInput - Add after PolicyInput
// ============================================================================

use crate::results::common::{ControlMapping, Criticality, Outcome};
use crate::results::evidence::Evidence;
use crate::results::finding::ComplianceFinding;

/// Input for building an assessor policy result
///
/// Similar to `PolicyInput` but specifically for assessor packages.
/// When the `assessor-evidence` feature is enabled, the evidence's
/// CollectionMethod will include command and input details.
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
