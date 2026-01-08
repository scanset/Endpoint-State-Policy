//! Attestation types for compliance scan results
//!
//! These types are designed for secure transport - no CUI (Controlled Unclassified Information)
//! is included. Only metadata about pass/fail status, not actual system values.
//!
//! ## Structure
//!
//! ```text
//! ScanAttestation
//! ├── envelope (mutable, excluded from signing)
//! │   ├── attestation_id
//! │   ├── timestamp
//! │   ├── agent_id
//! │   └── signature (future)
//! ├── summary (facts about the scan)
//! └── checks[] (one per policy)
//!     ├── policy_id
//!     ├── outcome
//!     ├── criticality
//!     └── control_mappings
//! ```

use serde::{Deserialize, Serialize};

use super::super::common::{
    ControlMapping, CriteriaCounts, Criticality, Outcome, PolicyOutcome, Weight,
};

/// Attestation for a single policy check
///
/// Contains only metadata - no evidence or actual values (CUI).
/// Wraps PolicyOutcome for the CUI-free attestation use case.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckAttestation {
    /// Core policy outcome data (CUI-free)
    #[serde(flatten)]
    pub outcome: PolicyOutcome,
}

impl CheckAttestation {
    /// Create a new check attestation
    pub fn new(
        policy_id: impl Into<String>,
        platform: impl Into<String>,
        outcome: Outcome,
        criticality: Criticality,
        control_mappings: Vec<ControlMapping>,
        criteria_counts: CriteriaCounts,
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
        }
    }

    /// Create from an existing PolicyOutcome
    pub fn from_outcome(outcome: PolicyOutcome) -> Self {
        Self { outcome }
    }

    /// Set explicit weight (overrides criticality default)
    pub fn with_weight(mut self, weight: f32) -> Self {
        self.outcome = self.outcome.with_weight(Weight::new(weight));
        self
    }

    /// Set policy version
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.outcome = self.outcome.with_version(version);
        self
    }

    /// Check if this attestation passed
    pub fn is_pass(&self) -> bool {
        self.outcome.is_pass()
    }

    /// Get the weight value
    pub fn weight_value(&self) -> f32 {
        self.outcome.weight_value()
    }

    // Convenience accessors to avoid .outcome.field everywhere
    /// Get policy ID
    pub fn policy_id(&self) -> &str {
        &self.outcome.policy_id
    }

    /// Get platform
    pub fn platform(&self) -> &str {
        &self.outcome.platform
    }

    /// Get outcome
    pub fn get_outcome(&self) -> Outcome {
        self.outcome.outcome
    }

    /// Get criticality
    pub fn criticality(&self) -> Criticality {
        self.outcome.criticality
    }

    /// Get control mappings
    pub fn control_mappings(&self) -> &[ControlMapping] {
        &self.outcome.control_mappings
    }

    /// Get criteria counts
    pub fn criteria_counts(&self) -> &CriteriaCounts {
        &self.outcome.criteria_counts
    }
}

/// Envelope containing mutable metadata excluded from content signing
///
/// These fields can change between attestation generations without
/// invalidating the signed content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationEnvelope {
    /// Unique identifier for this attestation
    pub attestation_id: String,

    /// ISO 8601 timestamp when attestation was created
    pub timestamp: String,

    /// Agent that performed the scan
    pub agent_id: String,

    /// Agent type (controller/daemon)
    pub agent_type: String,

    /// Hash of the attestation content (for verification)
    pub content_hash: String,

    /// Cryptographic signature (future - FIPS 140 compliant)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
}

impl AttestationEnvelope {
    /// Create a new envelope
    pub fn new(
        attestation_id: impl Into<String>,
        timestamp: impl Into<String>,
        agent_id: impl Into<String>,
        agent_type: impl Into<String>,
        content_hash: impl Into<String>,
    ) -> Self {
        Self {
            attestation_id: attestation_id.into(),
            timestamp: timestamp.into(),
            agent_id: agent_id.into(),
            agent_type: agent_type.into(),
            content_hash: content_hash.into(),
            signature: None,
        }
    }

    /// Add signature to envelope
    pub fn with_signature(mut self, signature: impl Into<String>) -> Self {
        self.signature = Some(signature.into());
        self
    }
}

/// Complete scan attestation containing all policy checks from an agent run
///
/// This is the primary output type for the attestation feature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanAttestation {
    /// Envelope with mutable metadata (excluded from signing)
    pub envelope: AttestationEnvelope,

    /// Summary statistics
    pub summary: AttestationSummary,

    /// Individual check attestations (one per policy)
    pub checks: Vec<CheckAttestation>,
}

impl ScanAttestation {
    /// Create a new scan attestation
    pub fn new(
        envelope: AttestationEnvelope,
        summary: AttestationSummary,
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

    /// Get all passing checks
    pub fn passing_checks(&self) -> Vec<&CheckAttestation> {
        self.checks.iter().filter(|c| c.is_pass()).collect()
    }

    /// Get all failing checks
    pub fn failing_checks(&self) -> Vec<&CheckAttestation> {
        self.checks
            .iter()
            .filter(|c| c.outcome.outcome.is_fail())
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

    /// Calculate posture score (weighted pass rate)
    pub fn posture_score(&self) -> f32 {
        if self.summary.total_weight == 0.0 {
            0.0
        } else {
            self.summary.passed_weight / self.summary.total_weight
        }
    }
}

/// Summary statistics for scan attestation
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AttestationSummary {
    /// Total number of policy checks
    pub total_checks: u32,

    /// Number of passing checks
    pub passed: u32,

    /// Number of failing checks
    pub failed: u32,

    /// Number of checks with errors
    pub error: u32,

    /// Breakdown by criticality level
    pub by_criticality: CriticalityBreakdown,

    /// Total weight of all checks
    pub total_weight: f32,

    /// Total weight of passing checks
    pub passed_weight: f32,
}

impl AttestationSummary {
    /// Calculate pass rate as percentage
    pub fn pass_rate(&self) -> f32 {
        if self.total_checks == 0 {
            0.0
        } else {
            (self.passed as f32 / self.total_checks as f32) * 100.0
        }
    }

    /// Calculate weighted pass rate (posture score)
    pub fn weighted_pass_rate(&self) -> f32 {
        if self.total_weight == 0.0 {
            0.0
        } else {
            (self.passed_weight / self.total_weight) * 100.0
        }
    }
}

/// Breakdown of results by criticality level
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CriticalityBreakdown {
    pub critical: CriticalityStats,
    pub high: CriticalityStats,
    pub medium: CriticalityStats,
    pub low: CriticalityStats,
    pub info: CriticalityStats,
}

impl CriticalityBreakdown {
    /// Record a result for a criticality level
    pub fn record(&mut self, criticality: Criticality, passed: bool) {
        let stats = match criticality {
            Criticality::Critical => &mut self.critical,
            Criticality::High => &mut self.high,
            Criticality::Medium => &mut self.medium,
            Criticality::Low => &mut self.low,
            Criticality::Info => &mut self.info,
        };

        stats.total += 1;
        if passed {
            stats.passed += 1;
        } else {
            stats.failed += 1;
        }
    }
}

/// Statistics for a single criticality level
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CriticalityStats {
    pub total: u32,
    pub passed: u32,
    pub failed: u32,
}

impl CriticalityStats {
    /// Calculate pass rate for this criticality level
    pub fn pass_rate(&self) -> f32 {
        if self.total == 0 {
            100.0
        } else {
            (self.passed as f32 / self.total as f32) * 100.0
        }
    }
}

#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_check_attestation_creation() {
        let check = CheckAttestation::new(
            "test-policy",
            "Kubernetes",
            Outcome::Pass,
            Criticality::High,
            vec![],
            CriteriaCounts::new(5, 5, 0, 0),
        );

        assert_eq!(check.policy_id(), "test-policy");
        assert_eq!(check.platform(), "Kubernetes");
        assert!(check.is_pass());
        assert_eq!(check.weight_value(), 0.8);
    }

    #[test]
    fn test_check_attestation_from_outcome() {
        let outcome = PolicyOutcome::new(
            "policy-1",
            "Linux",
            Outcome::Fail,
            Criticality::Critical,
            vec![],
            CriteriaCounts::default(),
        );

        let check = CheckAttestation::from_outcome(outcome);
        assert_eq!(check.policy_id(), "policy-1");
        assert!(!check.is_pass());
    }

    #[test]
    fn test_attestation_envelope() {
        let envelope = AttestationEnvelope::new(
            "att-123",
            "2024-01-01T00:00:00Z",
            "agent-1",
            "controller",
            "sha256:abc123",
        );

        assert_eq!(envelope.attestation_id, "att-123");
        assert_eq!(envelope.agent_id, "agent-1");
        assert!(envelope.signature.is_none());
    }

    #[test]
    fn test_scan_attestation() {
        let envelope = AttestationEnvelope::new(
            "att-456",
            "2024-01-01T00:00:00Z",
            "agent-1",
            "daemon",
            "sha256:def456",
        );

        let summary = AttestationSummary {
            total_checks: 2,
            passed: 1,
            failed: 1,
            ..Default::default()
        };

        let checks = vec![
            CheckAttestation::new(
                "policy-1",
                "Linux",
                Outcome::Pass,
                Criticality::High,
                vec![],
                CriteriaCounts::default(),
            ),
            CheckAttestation::new(
                "policy-2",
                "Linux",
                Outcome::Fail,
                Criticality::Medium,
                vec![],
                CriteriaCounts::default(),
            ),
        ];

        let attestation = ScanAttestation::new(envelope, summary, checks);

        assert_eq!(attestation.check_count(), 2);
        assert_eq!(attestation.passing_checks().len(), 1);
        assert_eq!(attestation.failing_checks().len(), 1);
    }

    #[test]
    fn test_criticality_breakdown() {
        let mut breakdown = CriticalityBreakdown::default();

        breakdown.record(Criticality::Critical, true);
        breakdown.record(Criticality::Critical, false);
        breakdown.record(Criticality::High, true);

        assert_eq!(breakdown.critical.total, 2);
        assert_eq!(breakdown.critical.passed, 1);
        assert_eq!(breakdown.critical.failed, 1);
        assert_eq!(breakdown.high.total, 1);
        assert_eq!(breakdown.high.passed, 1);
    }

    #[test]
    fn test_summary_pass_rate() {
        let summary = AttestationSummary {
            total_checks: 10,
            passed: 8,
            failed: 2,
            total_weight: 10.0,
            passed_weight: 7.5,
            ..Default::default()
        };

        assert_eq!(summary.pass_rate(), 80.0);
        assert_eq!(summary.weighted_pass_rate(), 75.0);
    }
}
