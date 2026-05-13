//! Policy outcome - core evaluation data
//!
//! Per-policy result type carried inside `AssessorPackage.policies[]`.
//! Holds the policy's identity, pass/fail outcome, criteria counts, and
//! control mappings.

use serde::{Deserialize, Serialize};

use super::control::ControlMapping;
use super::counts::CriteriaCounts;
use super::criticality::{Criticality, Weight};
use super::outcome::Outcome;

/// Core policy evaluation result
///
/// Holds the policy's identity, pass/fail outcome, criteria counts, and
/// control mappings for one policy execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyOutcome {
    /// Policy identifier from META esp_scan_id
    pub policy_id: String,

    /// Policy version (if specified in META)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<String>,

    /// Target platform from META
    pub platform: String,

    /// Outcome of the policy evaluation
    pub outcome: Outcome,

    /// Criticality level from META
    pub criticality: Criticality,

    /// Weight for posture scoring (explicit or derived from criticality)
    pub weight: Weight,

    /// Control framework mappings (e.g., NIST-800-53:AC-6, CIS:5.1.1)
    pub control_mappings: Vec<ControlMapping>,

    /// Criteria pass/fail/error counts
    pub criteria_counts: CriteriaCounts,
}

impl PolicyOutcome {
    /// Create a new policy outcome
    pub fn new(
        policy_id: impl Into<String>,
        platform: impl Into<String>,
        outcome: Outcome,
        criticality: Criticality,
        control_mappings: Vec<ControlMapping>,
        criteria_counts: CriteriaCounts,
    ) -> Self {
        Self {
            policy_id: policy_id.into(),
            policy_version: None,
            platform: platform.into(),
            outcome,
            criticality,
            weight: Weight::from(criticality),
            control_mappings,
            criteria_counts,
        }
    }

    /// Set policy version
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.policy_version = Some(version.into());
        self
    }

    /// Set explicit weight (overrides criticality-derived weight)
    pub fn with_weight(mut self, weight: Weight) -> Self {
        self.weight = weight;
        self
    }

    /// Get the weight value
    pub fn weight_value(&self) -> f32 {
        self.weight.value()
    }

    /// Check if this policy passed
    pub fn is_pass(&self) -> bool {
        self.outcome.is_pass()
    }

    /// Check if this policy failed
    pub fn is_fail(&self) -> bool {
        self.outcome.is_fail()
    }

    /// Check if this policy had an error
    pub fn is_error(&self) -> bool {
        self.outcome.is_error()
    }
}

#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_outcome_new() {
        let outcome = PolicyOutcome::new(
            "test-policy",
            "Kubernetes",
            Outcome::Pass,
            Criticality::High,
            vec![],
            CriteriaCounts::new(5, 5, 0, 0),
        );

        assert_eq!(outcome.policy_id, "test-policy");
        assert_eq!(outcome.platform, "Kubernetes");
        assert!(outcome.is_pass());
        assert_eq!(outcome.weight_value(), 0.8); // High criticality default
    }

    #[test]
    fn test_policy_outcome_with_version() {
        let outcome = PolicyOutcome::new(
            "test-policy",
            "Linux",
            Outcome::Fail,
            Criticality::Critical,
            vec![],
            CriteriaCounts::default(),
        )
        .with_version("1.0.0");

        assert_eq!(outcome.policy_version, Some("1.0.0".to_string()));
    }

    #[test]
    fn test_policy_outcome_with_weight() {
        let outcome = PolicyOutcome::new(
            "test-policy",
            "Linux",
            Outcome::Pass,
            Criticality::Low,
            vec![],
            CriteriaCounts::default(),
        )
        .with_weight(Weight::new(0.95));

        assert_eq!(outcome.weight_value(), 0.95);
    }
}
