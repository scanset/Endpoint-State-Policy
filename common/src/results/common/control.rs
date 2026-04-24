//! Control mapping types for compliance framework references
//!
//! Maps ESP policies to compliance framework controls (NIST 800-53, CIS, STIG, etc.)

use serde::{Deserialize, Serialize};

/// A mapping from an ESP policy to a compliance framework control
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ControlMapping {
    /// Framework identifier (e.g., "NIST-800-53", "CIS", "STIG", "CMMC")
    pub framework: String,

    /// Control identifier within the framework (e.g., "AC-6", "5.1.1", "V-242382")
    pub control_id: String,
}

impl ControlMapping {
    /// Create a new control mapping
    pub fn new(framework: impl Into<String>, control_id: impl Into<String>) -> Self {
        Self {
            framework: framework.into(),
            control_id: control_id.into(),
        }
    }

    /// Parse control mappings from comma-separated colon-paired META field
    ///
    /// Format: "FRAMEWORK:CONTROL_ID,FRAMEWORK:CONTROL_ID,..."
    ///
    /// Example:
    /// ```text
    /// control_mapping `NIST-800-53:AC-6,CIS:5.1.1,STIG:V-242382`
    /// ```
    ///
    /// Results in:
    /// - ControlMapping { framework: "NIST-800-53", control_id: "AC-6" }
    /// - ControlMapping { framework: "CIS", control_id: "5.1.1" }
    /// - ControlMapping { framework: "STIG", control_id: "V-242382" }
    pub fn parse_from_meta(
        control_mappings: &str,
    ) -> Result<Vec<ControlMapping>, ControlMappingError> {
        let trimmed = control_mappings.trim();

        if trimmed.is_empty() {
            return Err(ControlMappingError::EmptyMappings);
        }

        trimmed
            .split(',')
            .map(|pair| {
                let pair = pair.trim();
                if pair.is_empty() {
                    return Err(ControlMappingError::EmptyPair);
                }

                // Split on first colon only (control IDs might contain colons in theory)
                let mut parts = pair.splitn(2, ':');

                let framework = parts
                    .next()
                    .ok_or_else(|| ControlMappingError::InvalidFormat {
                        value: pair.to_string(),
                        reason: "Expected format FRAMEWORK:CONTROL_ID".to_string(),
                    })?
                    .trim();

                let control_id = parts
                    .next()
                    .ok_or_else(|| ControlMappingError::InvalidFormat {
                        value: pair.to_string(),
                        reason: "Expected format FRAMEWORK:CONTROL_ID".to_string(),
                    })?
                    .trim();

                if framework.is_empty() {
                    return Err(ControlMappingError::InvalidFormat {
                        value: pair.to_string(),
                        reason: "Framework cannot be empty".to_string(),
                    });
                }

                if control_id.is_empty() {
                    return Err(ControlMappingError::InvalidFormat {
                        value: pair.to_string(),
                        reason: "Control ID cannot be empty".to_string(),
                    });
                }

                Ok(ControlMapping::new(framework, control_id))
            })
            .collect()
    }

    /// Format as "FRAMEWORK:CONTROL_ID"
    pub fn as_string(&self) -> String {
        format!("{}:{}", self.framework, self.control_id)
    }

    /// Serialize a list of control mappings back to META format
    pub fn to_meta_format(mappings: &[ControlMapping]) -> String {
        mappings
            .iter()
            .map(|m| m.as_string())
            .collect::<Vec<_>>()
            .join(",")
    }
}

impl std::fmt::Display for ControlMapping {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.framework, self.control_id)
    }
}

/// Errors that can occur when parsing control mappings
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlMappingError {
    /// No mappings provided
    EmptyMappings,
    /// Empty pair in comma-separated list
    EmptyPair,
    /// Invalid format for a mapping pair
    InvalidFormat { value: String, reason: String },
}

impl std::fmt::Display for ControlMappingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ControlMappingError::EmptyMappings => {
                write!(f, "No control mappings specified in META block")
            }
            ControlMappingError::EmptyPair => {
                write!(f, "Empty control mapping pair in list")
            }
            ControlMappingError::InvalidFormat { value, reason } => {
                write!(f, "Invalid control mapping '{}': {}", value, reason)
            }
        }
    }
}

impl std::error::Error for ControlMappingError {}

#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_control_mapping_new() {
        let mapping = ControlMapping::new("NIST-800-53", "AC-6");
        assert_eq!(mapping.framework, "NIST-800-53");
        assert_eq!(mapping.control_id, "AC-6");
    }

    #[test]
    fn test_parse_single_mapping() {
        let mappings = ControlMapping::parse_from_meta("NIST-800-53:AC-6").unwrap();
        assert_eq!(mappings.len(), 1);
        assert_eq!(mappings[0].framework, "NIST-800-53");
        assert_eq!(mappings[0].control_id, "AC-6");
    }

    #[test]
    fn test_parse_multiple_mappings() {
        let mappings =
            ControlMapping::parse_from_meta("NIST-800-53:AC-6,CIS:5.1.1,STIG:V-242382").unwrap();

        assert_eq!(mappings.len(), 3);
        assert_eq!(mappings[0], ControlMapping::new("NIST-800-53", "AC-6"));
        assert_eq!(mappings[1], ControlMapping::new("CIS", "5.1.1"));
        assert_eq!(mappings[2], ControlMapping::new("STIG", "V-242382"));
    }

    #[test]
    fn test_parse_with_whitespace() {
        let mappings =
            ControlMapping::parse_from_meta("NIST-800-53:AC-6 , CIS:5.1.1 , STIG:V-242382")
                .unwrap();

        assert_eq!(mappings.len(), 3);
        assert_eq!(mappings[0].framework, "NIST-800-53");
        assert_eq!(mappings[0].control_id, "AC-6");
        assert_eq!(mappings[1].framework, "CIS");
    }

    #[test]
    fn test_parse_control_id_with_dots() {
        let mappings = ControlMapping::parse_from_meta("CIS:1.2.3.4").unwrap();
        assert_eq!(mappings[0].control_id, "1.2.3.4");
    }

    #[test]
    fn test_parse_empty() {
        let result = ControlMapping::parse_from_meta("");
        assert!(matches!(result, Err(ControlMappingError::EmptyMappings)));

        let result = ControlMapping::parse_from_meta("   ");
        assert!(matches!(result, Err(ControlMappingError::EmptyMappings)));
    }

    #[test]
    fn test_parse_missing_colon() {
        let result = ControlMapping::parse_from_meta("NIST-AC-6");
        assert!(matches!(
            result,
            Err(ControlMappingError::InvalidFormat { .. })
        ));
    }

    #[test]
    fn test_parse_empty_framework() {
        let result = ControlMapping::parse_from_meta(":AC-6");
        assert!(matches!(
            result,
            Err(ControlMappingError::InvalidFormat { .. })
        ));
    }

    #[test]
    fn test_parse_empty_control_id() {
        let result = ControlMapping::parse_from_meta("NIST:");
        assert!(matches!(
            result,
            Err(ControlMappingError::InvalidFormat { .. })
        ));
    }

    #[test]
    fn test_display() {
        let mapping = ControlMapping::new("STIG", "V-242382");
        assert_eq!(mapping.to_string(), "STIG:V-242382");
    }

    #[test]
    fn test_to_meta_format() {
        let mappings = vec![
            ControlMapping::new("NIST-800-53", "AC-6"),
            ControlMapping::new("CIS", "5.1.1"),
        ];
        let meta = ControlMapping::to_meta_format(&mappings);
        assert_eq!(meta, "NIST-800-53:AC-6,CIS:5.1.1");
    }

    #[test]
    fn test_serialization() {
        let mapping = ControlMapping::new("CIS", "5.1.1");
        let json = serde_json::to_string(&mapping).unwrap();
        assert!(json.contains("\"framework\":\"CIS\""));
        assert!(json.contains("\"control_id\":\"5.1.1\""));

        let parsed: ControlMapping = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, mapping);
    }

    #[test]
    fn test_roundtrip() {
        let original = "NIST-800-53:AC-6,CIS:5.1.1,STIG:V-242382";
        let mappings = ControlMapping::parse_from_meta(original).unwrap();
        let back = ControlMapping::to_meta_format(&mappings);
        assert_eq!(back, original);
    }
}
