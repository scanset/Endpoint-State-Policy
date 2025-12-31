//! # Behavior Hints Parsing
//!
//! Converts raw behavior strings into structured hints for collectors.
//! Behaviors follow the pattern: flag_name [parameter_value]*

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Structured behavior hints for collectors
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BehaviorHints {
    /// Simple flag-style behaviors (e.g., "recursive_scan", "include_hidden")
    pub flags: Vec<String>,

    /// Parameterized behaviors (e.g., "max_depth" -> "10")
    pub parameters: HashMap<String, String>,
}

impl BehaviorHints {
    /// Parse raw behavior values into structured hints
    ///
    /// # Parsing Rules
    /// - Identifiers with underscores are treated as flags
    /// - Identifiers followed by non-identifier values are parameters
    /// - Boolean values (true/false) are treated as parameter values
    /// - Numeric values are treated as parameter values
    pub fn parse(behavior_values: &[String]) -> Self {
        let mut flags = Vec::new();
        let mut parameters = HashMap::new();

        let mut i = 0;
        while i < behavior_values.len() {
            let current = &behavior_values[i];

            // Check if next value exists and could be a parameter
            if i + 1 < behavior_values.len() {
                let next = &behavior_values[i + 1];

                // If next value is NOT an identifier with underscores, it's a parameter
                if !Self::is_flag_like(next) {
                    parameters.insert(current.clone(), next.clone());
                    i += 2;
                    continue;
                }
            }

            // Otherwise, it's a flag
            flags.push(current.clone());
            i += 1;
        }

        Self { flags, parameters }
    }

    /// Check if value looks like a flag (contains underscore or is a single word)
    fn is_flag_like(value: &str) -> bool {
        // Flags typically have underscores or are single identifiers
        value.contains('_')
            || (value.chars().all(|c| c.is_alphabetic()) && !Self::is_boolean(value))
    }

    /// Check if value is a boolean literal
    fn is_boolean(value: &str) -> bool {
        matches!(value.to_lowercase().as_str(), "true" | "false")
    }

    /// Create empty behavior hints
    pub fn empty() -> Self {
        Self {
            flags: Vec::new(),
            parameters: HashMap::new(),
        }
    }

    /// Check if a specific flag is present
    pub fn has_flag(&self, flag: &str) -> bool {
        self.flags.iter().any(|f| f == flag)
    }

    /// Get a parameter value
    pub fn get_parameter(&self, key: &str) -> Option<&str> {
        self.parameters.get(key).map(|s| s.as_str())
    }

    /// Get a parameter as integer
    pub fn get_parameter_as_int(&self, key: &str) -> Option<i64> {
        self.get_parameter(key).and_then(|v| v.parse().ok())
    }

    /// Get a parameter as boolean
    pub fn get_parameter_as_bool(&self, key: &str) -> Option<bool> {
        self.get_parameter(key).and_then(|v| v.parse().ok())
    }

    /// Check if hints are empty
    pub fn is_empty(&self) -> bool {
        self.flags.is_empty() && self.parameters.is_empty()
    }

    /// Merge another set of hints into this one
    pub fn merge(&mut self, other: BehaviorHints) {
        self.flags.extend(other.flags);
        self.parameters.extend(other.parameters);
    }
}

/// Extract behavior hints from ExecutableObject
pub fn extract_behavior_hints(
    object: &crate::types::execution_context::ExecutableObject,
) -> BehaviorHints {
    use crate::types::execution_context::ExecutableObjectElement;

    for element in &object.elements {
        if let ExecutableObjectElement::Behavior { values } = element {
            return BehaviorHints::parse(values);
        }
    }

    BehaviorHints::empty()
}

/// Update DataCollector trait to receive behavior hints
///
/// Add this to your collector implementations:
///
/// ```ignore
/// fn collect_with_hints(
///     &self,
///     object: &ExecutableObject,
///     hints: &BehaviorHints,
/// ) -> Result<CollectedData, CollectionError> {
///     // Use hints to adjust collection behavior
///     if hints.has_flag("recursive_scan") {
///         if let Some(max_depth) = hints.get_parameter_as_int("max_depth") {
///             // Perform recursive scan with depth limit
///         }
///     }
///
///     // ... rest of collection logic
/// }
/// ```
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_simple_flags() {
        let hints = BehaviorHints::parse(&[
            "recursive_scan".to_string(),
            "include_hidden".to_string(),
            "compress_results".to_string(),
        ]);

        assert_eq!(hints.flags.len(), 3);
        assert!(hints.has_flag("recursive_scan"));
        assert!(hints.has_flag("include_hidden"));
        assert!(hints.has_flag("compress_results"));
        assert!(hints.parameters.is_empty());
    }

    #[test]
    fn test_parse_parameters() {
        let hints = BehaviorHints::parse(&[
            "max_depth".to_string(),
            "10".to_string(),
            "timeout".to_string(),
            "30".to_string(),
        ]);

        assert!(hints.flags.is_empty());
        assert_eq!(hints.parameters.len(), 2);
        assert_eq!(hints.get_parameter("max_depth"), Some("10"));
        assert_eq!(hints.get_parameter("timeout"), Some("30"));
    }

    #[test]
    fn test_parse_mixed() {
        let hints = BehaviorHints::parse(&[
            "recursive_scan".to_string(),
            "max_depth".to_string(),
            "10".to_string(),
            "include_hidden".to_string(),
            "compress_results".to_string(),
        ]);

        assert_eq!(hints.flags.len(), 3);
        assert_eq!(hints.parameters.len(), 1);
        assert!(hints.has_flag("recursive_scan"));
        assert!(hints.has_flag("include_hidden"));
        assert_eq!(hints.get_parameter("max_depth"), Some("10"));
    }

    #[test]
    fn test_parse_from_smoke_test() {
        // From smoke-test.ics: "behavior recursive_scan max_depth 10 include_hidden compress_results"
        let hints = BehaviorHints::parse(&[
            "recursive_scan".to_string(),
            "max_depth".to_string(),
            "10".to_string(),
            "include_hidden".to_string(),
            "compress_results".to_string(),
        ]);

        assert!(hints.has_flag("recursive_scan"));
        assert!(hints.has_flag("include_hidden"));
        assert!(hints.has_flag("compress_results"));
        assert_eq!(hints.get_parameter_as_int("max_depth"), Some(10));
    }

    #[test]
    fn test_parameter_type_conversion() {
        let hints = BehaviorHints::parse(&[
            "max_depth".to_string(),
            "10".to_string(),
            "enabled".to_string(),
            "true".to_string(),
        ]);

        assert_eq!(hints.get_parameter_as_int("max_depth"), Some(10));
        assert_eq!(hints.get_parameter_as_bool("enabled"), Some(true));
    }

    #[test]
    fn test_empty_hints() {
        let hints = BehaviorHints::empty();
        assert!(hints.is_empty());

        let hints = BehaviorHints::parse(&[]);
        assert!(hints.is_empty());
    }

    #[test]
    fn test_merge_hints() {
        // First hints: just a flag with a parameter
        let mut hints1 = BehaviorHints::parse(&[
            "recursive_scan".to_string(),
            "max_depth".to_string(),
            "5".to_string(),
        ]);

        // Second hints: another flag with a parameter
        let hints2 = BehaviorHints::parse(&[
            "include_hidden".to_string(),
            "timeout".to_string(),
            "30".to_string(),
        ]);

        hints1.merge(hints2);

        // After parsing:
        // hints1 should have: recursive_scan as param key with value "max_depth", and max_depth as param key with value "5"
        // OR: recursive_scan as flag, max_depth=5 as param
        // Let's check what we actually get:

        // Based on the parsing logic, "recursive_scan" followed by "max_depth"
        // Since max_depth has underscore (is_flag_like), recursive_scan becomes a flag
        // Then max_depth followed by "5" (not flag-like), becomes a parameter

        assert!(hints1.has_flag("recursive_scan"));
        assert!(hints1.has_flag("include_hidden"));
        assert_eq!(hints1.get_parameter("max_depth"), Some("5"));
        assert_eq!(hints1.get_parameter("timeout"), Some("30"));
    }
}
