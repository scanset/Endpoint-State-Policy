//! Count types for compliance check statistics
//!
//! Provides structured count types for criteria and result aggregation.

use serde::{Deserialize, Serialize};

/// Counts of criteria within a policy or check
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CriteriaCounts {
    /// Total number of criteria evaluated
    pub total: u32,
    /// Number of criteria that passed
    pub passed: u32,
    /// Number of criteria that failed
    pub failed: u32,
    /// Number of criteria that had errors
    pub error: u32,
}

impl CriteriaCounts {
    /// Create new criteria counts
    pub fn new(total: u32, passed: u32, failed: u32, error: u32) -> Self {
        Self {
            total,
            passed,
            failed,
            error,
        }
    }

    /// Check if all criteria passed (no failures or errors)
    pub fn all_passed(&self) -> bool {
        self.failed == 0 && self.error == 0
    }

    /// Check if there were any errors
    pub fn has_errors(&self) -> bool {
        self.error > 0
    }

    /// Check if there were any failures
    pub fn has_failures(&self) -> bool {
        self.failed > 0
    }

    /// Add another CriteriaCounts to this one
    pub fn add(&mut self, other: &CriteriaCounts) {
        self.total += other.total;
        self.passed += other.passed;
        self.failed += other.failed;
        self.error += other.error;
    }

    /// Calculate pass rate as a value between 0.0 and 1.0
    pub fn pass_rate(&self) -> f32 {
        if self.total == 0 {
            0.0
        } else {
            self.passed as f32 / self.total as f32
        }
    }
}

/// Result counts by outcome (simpler than CriteriaCounts)
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResultCounts {
    /// Total number of results
    pub total: u32,
    /// Number that passed
    pub passed: u32,
    /// Number that failed
    pub failed: u32,
}

impl ResultCounts {
    /// Create new result counts
    pub fn new(total: u32, passed: u32, failed: u32) -> Self {
        Self {
            total,
            passed,
            failed,
        }
    }

    /// Create from pass/fail only (total = passed + failed)
    pub fn from_pass_fail(passed: u32, failed: u32) -> Self {
        Self {
            total: passed + failed,
            passed,
            failed,
        }
    }

    /// Check if all results passed
    pub fn all_passed(&self) -> bool {
        self.failed == 0 && self.total > 0
    }

    /// Add another ResultCounts to this one
    pub fn add(&mut self, other: &ResultCounts) {
        self.total += other.total;
        self.passed += other.passed;
        self.failed += other.failed;
    }

    /// Increment passed count
    pub fn record_pass(&mut self) {
        self.total += 1;
        self.passed += 1;
    }

    /// Increment failed count
    pub fn record_fail(&mut self) {
        self.total += 1;
        self.failed += 1;
    }
}

#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_criteria_counts_new() {
        let counts = CriteriaCounts::new(10, 8, 1, 1);
        assert_eq!(counts.total, 10);
        assert_eq!(counts.passed, 8);
        assert_eq!(counts.failed, 1);
        assert_eq!(counts.error, 1);
    }

    #[test]
    fn test_criteria_counts_all_passed() {
        let passing = CriteriaCounts::new(10, 10, 0, 0);
        assert!(passing.all_passed());

        let with_failure = CriteriaCounts::new(10, 9, 1, 0);
        assert!(!with_failure.all_passed());

        let with_error = CriteriaCounts::new(10, 9, 0, 1);
        assert!(!with_error.all_passed());
    }

    #[test]
    fn test_criteria_counts_add() {
        let mut counts = CriteriaCounts::new(5, 4, 1, 0);
        counts.add(&CriteriaCounts::new(3, 2, 0, 1));

        assert_eq!(counts.total, 8);
        assert_eq!(counts.passed, 6);
        assert_eq!(counts.failed, 1);
        assert_eq!(counts.error, 1);
    }

    #[test]
    fn test_criteria_counts_pass_rate() {
        let counts = CriteriaCounts::new(10, 8, 2, 0);
        assert!((counts.pass_rate() - 0.8).abs() < f32::EPSILON);

        let empty = CriteriaCounts::default();
        assert_eq!(empty.pass_rate(), 0.0);
    }

    #[test]
    fn test_result_counts_from_pass_fail() {
        let counts = ResultCounts::from_pass_fail(7, 3);
        assert_eq!(counts.total, 10);
        assert_eq!(counts.passed, 7);
        assert_eq!(counts.failed, 3);
    }

    #[test]
    fn test_result_counts_record() {
        let mut counts = ResultCounts::default();
        counts.record_pass();
        counts.record_pass();
        counts.record_fail();

        assert_eq!(counts.total, 3);
        assert_eq!(counts.passed, 2);
        assert_eq!(counts.failed, 1);
    }

    #[test]
    fn test_serialization() {
        let counts = CriteriaCounts::new(10, 8, 1, 1);
        let json = serde_json::to_string(&counts).unwrap();
        let parsed: CriteriaCounts = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, counts);
    }
}
