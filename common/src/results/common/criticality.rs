//! Criticality types for compliance checks
//!
//! Defines criticality levels and their default weights for posture scoring.

use serde::{Deserialize, Serialize};

/// Criticality level of a compliance check
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum Criticality {
    /// Critical - Immediate security impact, exploit potential
    Critical,
    /// High - Significant security gap
    High,
    /// Medium - Security weakness, compensating controls may exist
    #[default]
    Medium,
    /// Low - Minor issue, best practice
    Low,
    /// Info - Informational, no direct security impact
    Info,
}

impl Criticality {
    /// Get the default weight for this criticality level
    ///
    /// Weights are used for posture score calculations:
    /// `posture_score = sum(passed_weights) / sum(total_weights)`
    pub fn default_weight(&self) -> f32 {
        match self {
            Criticality::Critical => 1.0,
            Criticality::High => 0.8,
            Criticality::Medium => 0.5,
            Criticality::Low => 0.2,
            Criticality::Info => 0.1,
        }
    }

    /// Convert to string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Criticality::Critical => "critical",
            Criticality::High => "high",
            Criticality::Medium => "medium",
            Criticality::Low => "low",
            Criticality::Info => "info",
        }
    }

    /// Parse from string (case-insensitive)
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "critical" => Some(Criticality::Critical),
            "high" => Some(Criticality::High),
            "medium" => Some(Criticality::Medium),
            "low" => Some(Criticality::Low),
            "info" | "informational" => Some(Criticality::Info),
            _ => None,
        }
    }
}

impl std::fmt::Display for Criticality {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Weight value for a compliance check
///
/// Can be explicitly set or derived from criticality.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct Weight(f32);

impl Weight {
    /// Create a new weight value (clamped to 0.0 - 1.0)
    pub fn new(value: f32) -> Self {
        Weight(value.clamp(0.0, 1.0))
    }

    /// Create weight from criticality default
    pub fn from_criticality(criticality: Criticality) -> Self {
        Weight(criticality.default_weight())
    }

    /// Get the weight value
    pub fn value(&self) -> f32 {
        self.0
    }
}

impl Default for Weight {
    fn default() -> Self {
        Weight::from_criticality(Criticality::default())
    }
}

impl From<f32> for Weight {
    fn from(value: f32) -> Self {
        Weight::new(value)
    }
}

impl From<Criticality> for Weight {
    fn from(criticality: Criticality) -> Self {
        Weight::from_criticality(criticality)
    }
}

#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_criticality_weights() {
        assert_eq!(Criticality::Critical.default_weight(), 1.0);
        assert_eq!(Criticality::High.default_weight(), 0.8);
        assert_eq!(Criticality::Medium.default_weight(), 0.5);
        assert_eq!(Criticality::Low.default_weight(), 0.2);
        assert_eq!(Criticality::Info.default_weight(), 0.1);
    }

    #[test]
    fn test_criticality_from_str() {
        assert_eq!(Criticality::parse("critical"), Some(Criticality::Critical));
        assert_eq!(Criticality::parse("HIGH"), Some(Criticality::High));
        assert_eq!(Criticality::parse("Medium"), Some(Criticality::Medium));
        assert_eq!(Criticality::parse("info"), Some(Criticality::Info));
        assert_eq!(Criticality::parse("informational"), Some(Criticality::Info));
        assert_eq!(Criticality::parse("invalid"), None);
    }

    #[test]
    fn test_weight_clamping() {
        assert_eq!(Weight::new(1.5).value(), 1.0);
        assert_eq!(Weight::new(-0.5).value(), 0.0);
        assert_eq!(Weight::new(0.75).value(), 0.75);
    }

    #[test]
    fn test_criticality_serialization() {
        let json = serde_json::to_string(&Criticality::High).unwrap();
        assert_eq!(json, "\"high\"");

        let parsed: Criticality = serde_json::from_str("\"critical\"").unwrap();
        assert_eq!(parsed, Criticality::Critical);
    }
}
