//! Outcome types for compliance check results
//!
//! Defines the possible outcomes of a compliance check evaluation.
//! This replaces ComplianceStatus from the scanner crate.

use serde::{Deserialize, Serialize};

/// Outcome of a compliance check evaluation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Check passed - system is compliant
    Pass,
    /// Check failed - system is non-compliant
    Fail,
    /// Check encountered an error during evaluation
    Error,
    /// Check result is unknown (could not determine)
    #[default]
    Unknown,
}

impl Outcome {
    /// Negate the outcome (Pass <-> Fail, others unchanged)
    pub fn negate(self) -> Self {
        match self {
            Self::Pass => Self::Fail,
            Self::Fail => Self::Pass,
            Self::Error => Self::Error,
            Self::Unknown => Self::Unknown,
        }
    }

    /// Returns true if the evaluation completed successfully (Pass or Fail)
    /// Error and Unknown are not considered successful evaluations.
    pub fn is_successful(self) -> bool {
        matches!(self, Self::Pass | Self::Fail)
    }

    /// Returns true if the outcome represents a passing check
    pub fn is_pass(self) -> bool {
        matches!(self, Self::Pass)
    }

    /// Returns true if the outcome represents a failing check
    pub fn is_fail(self) -> bool {
        matches!(self, Self::Fail)
    }

    /// Returns true if the outcome represents an error
    pub fn is_error(self) -> bool {
        matches!(self, Self::Error)
    }

    /// Returns true if the outcome is unknown
    pub fn is_unknown(self) -> bool {
        matches!(self, Self::Unknown)
    }

    /// Convert to string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Outcome::Pass => "pass",
            Outcome::Fail => "fail",
            Outcome::Error => "error",
            Outcome::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for Outcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_outcome_negate() {
        assert_eq!(Outcome::Pass.negate(), Outcome::Fail);
        assert_eq!(Outcome::Fail.negate(), Outcome::Pass);
        assert_eq!(Outcome::Error.negate(), Outcome::Error);
        assert_eq!(Outcome::Unknown.negate(), Outcome::Unknown);
    }

    #[test]
    fn test_outcome_is_successful() {
        assert!(Outcome::Pass.is_successful());
        assert!(Outcome::Fail.is_successful());
        assert!(!Outcome::Error.is_successful());
        assert!(!Outcome::Unknown.is_successful());
    }

    #[test]
    fn test_outcome_predicates() {
        assert!(Outcome::Pass.is_pass());
        assert!(!Outcome::Pass.is_fail());

        assert!(Outcome::Fail.is_fail());
        assert!(!Outcome::Fail.is_pass());

        assert!(Outcome::Error.is_error());
        assert!(Outcome::Unknown.is_unknown());
    }

    #[test]
    fn test_outcome_display() {
        assert_eq!(Outcome::Pass.to_string(), "pass");
        assert_eq!(Outcome::Fail.to_string(), "fail");
        assert_eq!(Outcome::Error.to_string(), "error");
        assert_eq!(Outcome::Unknown.to_string(), "unknown");
    }

    #[test]
    fn test_outcome_serialization() {
        let json = serde_json::to_string(&Outcome::Pass).unwrap();
        assert_eq!(json, "\"pass\"");

        let parsed: Outcome = serde_json::from_str("\"fail\"").unwrap();
        assert_eq!(parsed, Outcome::Fail);

        let parsed: Outcome = serde_json::from_str("\"unknown\"").unwrap();
        assert_eq!(parsed, Outcome::Unknown);
    }

    #[test]
    fn test_outcome_default() {
        assert_eq!(Outcome::default(), Outcome::Unknown);
    }
}
