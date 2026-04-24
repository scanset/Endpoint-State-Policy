//! Execution summary for ESP scan results
//!
//! Provides aggregate statistics across all policies in a scan execution.
//! Used in both attestations and full results.
//!
//! ## Type Aliases
//!
//! - `ScanSummary` is an alias for `ExecutionSummary` for backward compatibility

use serde::{Deserialize, Serialize};

use super::common::{Criticality, Outcome};

// ============================================================================
// Type Aliases
// ============================================================================

/// Type alias for backward compatibility
///
/// `ScanSummary` is the same as `ExecutionSummary`.
pub type ScanSummary = ExecutionSummary;

// ============================================================================
// ExecutionSummary
// ============================================================================

/// Summary statistics for a scan execution
///
/// Aggregates pass/fail/error counts and calculates posture scores.
/// Also known as `ScanSummary` (type alias).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ExecutionSummary {
    /// Total number of policies evaluated
    pub total_policies: u32,

    /// Number of policies that passed
    pub passed: u32,

    /// Number of policies that failed
    pub failed: u32,

    /// Number of policies with errors
    pub errors: u32,

    /// Breakdown by criticality level
    pub by_criticality: CriticalityBreakdown,

    /// Total weight of all policies
    pub total_weight: f32,

    /// Weight of passing policies
    pub passed_weight: f32,

    /// Posture score (0.0 to 1.0)
    ///
    /// Calculated as: passed_weight / total_weight
    pub posture_score: f32,
}

impl ExecutionSummary {
    /// Create a new empty summary
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a policy result using pass/fail boolean
    ///
    /// This is the primary method used by result builders.
    ///
    /// # Arguments
    /// * `passed` - Whether the policy passed
    /// * `criticality` - Criticality level of the policy
    /// * `weight` - Weight for posture calculation
    pub fn record(&mut self, passed: bool, criticality: Criticality, weight: f32) {
        self.total_policies += 1;
        self.total_weight += weight;

        if passed {
            self.passed += 1;
            self.passed_weight += weight;
            self.by_criticality.record(criticality, true);
        } else {
            self.failed += 1;
            self.by_criticality.record(criticality, false);
        }

        // Update posture score
        self.update_posture_score();
    }

    /// Record a policy result using Outcome enum
    ///
    /// Alternative method that accepts an Outcome enum.
    pub fn record_outcome(&mut self, outcome: Outcome, criticality: Criticality, weight: f32) {
        self.total_policies += 1;
        self.total_weight += weight;

        match outcome {
            Outcome::Pass => {
                self.passed += 1;
                self.passed_weight += weight;
                self.by_criticality.record(criticality, true);
            }
            Outcome::Fail => {
                self.failed += 1;
                self.by_criticality.record(criticality, false);
            }
            Outcome::Error => {
                self.errors += 1;
                // Errors don't contribute to criticality breakdown
            }
            Outcome::Unknown => {
                // Unknown doesn't affect counts
            }
        }

        // Update posture score
        self.update_posture_score();
    }

    /// Record an error (increments error count without affecting pass/fail)
    ///
    /// Use this when a policy evaluation resulted in an error.
    /// The policy should already have been recorded via `record()`.
    pub fn record_error(&mut self) {
        self.errors += 1;
    }

    /// Recalculate the posture score
    fn update_posture_score(&mut self) {
        if self.total_weight > 0.0 {
            self.posture_score = self.passed_weight / self.total_weight;
        } else {
            self.posture_score = 0.0;
        }
    }

    /// Calculate pass rate as percentage (0-100)
    pub fn pass_rate(&self) -> f32 {
        if self.total_policies == 0 {
            0.0
        } else {
            (self.passed as f32 / self.total_policies as f32) * 100.0
        }
    }

    /// Calculate weighted pass rate as percentage (0-100)
    pub fn weighted_pass_rate(&self) -> f32 {
        self.posture_score * 100.0
    }

    /// Check if all policies passed (no failures or errors)
    pub fn all_passed(&self) -> bool {
        self.failed == 0 && self.errors == 0 && self.total_policies > 0
    }

    /// Check if there were any errors
    pub fn has_errors(&self) -> bool {
        self.errors > 0
    }

    /// Merge another summary into this one
    pub fn merge(&mut self, other: &ExecutionSummary) {
        self.total_policies += other.total_policies;
        self.passed += other.passed;
        self.failed += other.failed;
        self.errors += other.errors;
        self.total_weight += other.total_weight;
        self.passed_weight += other.passed_weight;
        self.by_criticality.merge(&other.by_criticality);
        self.update_posture_score();
    }
}

// ============================================================================
// CriticalityBreakdown
// ============================================================================

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
        let stats = self.stats_mut(criticality);
        stats.total += 1;
        if passed {
            stats.passed += 1;
        } else {
            stats.failed += 1;
        }
    }

    /// Get mutable stats for a criticality level
    fn stats_mut(&mut self, criticality: Criticality) -> &mut CriticalityStats {
        match criticality {
            Criticality::Critical => &mut self.critical,
            Criticality::High => &mut self.high,
            Criticality::Medium => &mut self.medium,
            Criticality::Low => &mut self.low,
            Criticality::Info => &mut self.info,
        }
    }

    /// Get stats for a criticality level
    pub fn stats(&self, criticality: Criticality) -> &CriticalityStats {
        match criticality {
            Criticality::Critical => &self.critical,
            Criticality::High => &self.high,
            Criticality::Medium => &self.medium,
            Criticality::Low => &self.low,
            Criticality::Info => &self.info,
        }
    }

    /// Merge another breakdown into this one
    pub fn merge(&mut self, other: &CriticalityBreakdown) {
        self.critical.merge(&other.critical);
        self.high.merge(&other.high);
        self.medium.merge(&other.medium);
        self.low.merge(&other.low);
        self.info.merge(&other.info);
    }
}

// ============================================================================
// CriticalityStats
// ============================================================================

/// Statistics for a single criticality level
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CriticalityStats {
    pub total: u32,
    pub passed: u32,
    pub failed: u32,
}

impl CriticalityStats {
    /// Calculate pass rate for this criticality level (0-100)
    pub fn pass_rate(&self) -> f32 {
        if self.total == 0 {
            100.0 // No checks at this level = 100% pass
        } else {
            (self.passed as f32 / self.total as f32) * 100.0
        }
    }

    /// Merge another stats into this one
    pub fn merge(&mut self, other: &CriticalityStats) {
        self.total += other.total;
        self.passed += other.passed;
        self.failed += other.failed;
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
    fn test_execution_summary_new() {
        let summary = ExecutionSummary::new();

        assert_eq!(summary.total_policies, 0);
        assert_eq!(summary.passed, 0);
        assert_eq!(summary.failed, 0);
        assert_eq!(summary.errors, 0);
        assert_eq!(summary.posture_score, 0.0);
    }

    #[test]
    fn test_execution_summary_record() {
        let mut summary = ExecutionSummary::new();

        summary.record(true, Criticality::High, 0.8);
        summary.record(true, Criticality::Medium, 0.5);
        summary.record(false, Criticality::Critical, 1.0);

        assert_eq!(summary.total_policies, 3);
        assert_eq!(summary.passed, 2);
        assert_eq!(summary.failed, 1);
        assert_eq!(summary.errors, 0);

        // Posture score: (0.8 + 0.5) / (0.8 + 0.5 + 1.0) = 1.3 / 2.3 ≈ 0.565
        assert!((summary.posture_score - 0.565).abs() < 0.01);
    }

    #[test]
    fn test_execution_summary_record_outcome() {
        let mut summary = ExecutionSummary::new();

        summary.record_outcome(Outcome::Pass, Criticality::High, 0.8);
        summary.record_outcome(Outcome::Pass, Criticality::Medium, 0.5);
        summary.record_outcome(Outcome::Fail, Criticality::Critical, 1.0);

        assert_eq!(summary.total_policies, 3);
        assert_eq!(summary.passed, 2);
        assert_eq!(summary.failed, 1);
    }

    #[test]
    fn test_execution_summary_record_error() {
        let mut summary = ExecutionSummary::new();

        summary.record(false, Criticality::High, 0.8);
        summary.record_error(); // Mark as error

        assert_eq!(summary.total_policies, 1);
        assert_eq!(summary.failed, 1);
        assert_eq!(summary.errors, 1);
    }

    #[test]
    fn test_execution_summary_pass_rate() {
        let mut summary = ExecutionSummary::new();

        summary.record(true, Criticality::High, 1.0);
        summary.record(true, Criticality::Medium, 1.0);
        summary.record(false, Criticality::Low, 1.0);
        summary.record(false, Criticality::Info, 1.0);

        assert_eq!(summary.pass_rate(), 50.0);
    }

    #[test]
    fn test_execution_summary_all_passed() {
        let mut summary = ExecutionSummary::new();

        summary.record(true, Criticality::High, 1.0);
        summary.record(true, Criticality::Medium, 1.0);

        assert!(summary.all_passed());

        summary.record(false, Criticality::Low, 1.0);
        assert!(!summary.all_passed());
    }

    #[test]
    fn test_criticality_breakdown() {
        let mut breakdown = CriticalityBreakdown::default();

        breakdown.record(Criticality::Critical, true);
        breakdown.record(Criticality::Critical, false);
        breakdown.record(Criticality::High, true);
        breakdown.record(Criticality::High, true);

        assert_eq!(breakdown.critical.total, 2);
        assert_eq!(breakdown.critical.passed, 1);
        assert_eq!(breakdown.critical.failed, 1);
        assert_eq!(breakdown.critical.pass_rate(), 50.0);

        assert_eq!(breakdown.high.total, 2);
        assert_eq!(breakdown.high.passed, 2);
        assert_eq!(breakdown.high.pass_rate(), 100.0);
    }

    #[test]
    fn test_criticality_stats_empty() {
        let stats = CriticalityStats::default();

        // Empty stats should return 100% pass rate
        assert_eq!(stats.pass_rate(), 100.0);
    }

    #[test]
    fn test_execution_summary_merge() {
        let mut summary1 = ExecutionSummary::new();
        summary1.record(true, Criticality::High, 1.0);
        summary1.record(false, Criticality::Medium, 0.5);

        let mut summary2 = ExecutionSummary::new();
        summary2.record(true, Criticality::Critical, 1.0);
        summary2.record_outcome(Outcome::Error, Criticality::Low, 0.2);

        summary1.merge(&summary2);

        assert_eq!(summary1.total_policies, 4);
        assert_eq!(summary1.passed, 2);
        assert_eq!(summary1.failed, 1);
        assert_eq!(summary1.errors, 1);
    }

    #[test]
    fn test_serialization() {
        let mut summary = ExecutionSummary::new();
        summary.record(true, Criticality::High, 0.8);
        summary.record(false, Criticality::Critical, 1.0);

        let json = serde_json::to_string(&summary).unwrap();
        let parsed: ExecutionSummary = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.total_policies, 2);
        assert_eq!(parsed.passed, 1);
        assert_eq!(parsed.failed, 1);
    }

    #[test]
    fn test_scan_summary_alias() {
        // Verify that ScanSummary is the same type as ExecutionSummary
        let summary: ScanSummary = ExecutionSummary::new();
        assert_eq!(summary.total_policies, 0);
    }
}
