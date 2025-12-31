//! # Module Version Matching
//!
//! Provides version compatibility checking for DataCollectors.
//! Ensures collectors can handle the requested module versions.
use crate::execution::ExecutionError;
use crate::strategies::CtnDataCollector;
use crate::types::execution_context::ExecutableObject;
use crate::types::ModuleField;
use common::{log_debug, log_info};
use std::cmp::Ordering;

/// Semantic version comparison result
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VersionCompatibility {
    /// Versions are compatible
    Compatible,
    /// Versions are incompatible
    Incompatible,
    /// Cannot determine compatibility (invalid version format)
    Unknown,
}

/// Parse and compare semantic versions
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

impl SemanticVersion {
    /// Parse version string (e.g., "2.1.0", "1.0", "3")
    pub fn parse(version_str: &str) -> Option<Self> {
        let parts: Vec<&str> = version_str.split('.').collect();

        match parts.len() {
            1 => {
                let major = parts[0].parse().ok()?;
                Some(Self {
                    major,
                    minor: 0,
                    patch: 0,
                })
            }
            2 => {
                let major = parts[0].parse().ok()?;
                let minor = parts[1].parse().ok()?;
                Some(Self {
                    major,
                    minor,
                    patch: 0,
                })
            }
            3 => {
                let major = parts[0].parse().ok()?;
                let minor = parts[1].parse().ok()?;
                let patch = parts[2].parse().ok()?;
                Some(Self {
                    major,
                    minor,
                    patch,
                })
            }
            _ => None,
        }
    }

    /// Check if this version is compatible with another version
    ///
    /// Compatibility rules (semver):
    /// - Major version must match
    /// - This version's minor must be >= requested minor
    /// - Patch version is ignored for compatibility
    pub fn is_compatible_with(&self, requested: &SemanticVersion) -> bool {
        // Major version must match
        if self.major != requested.major {
            return false;
        }

        // Minor version must be >= requested
        self.minor >= requested.minor
    }
}

impl PartialOrd for SemanticVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SemanticVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.major.cmp(&other.major) {
            Ordering::Equal => match self.minor.cmp(&other.minor) {
                Ordering::Equal => self.patch.cmp(&other.patch),
                other => other,
            },
            other => other,
        }
    }
}

/// Module specification with version requirements
#[derive(Debug, Clone)]
pub struct ModuleSpec {
    pub name: String,
    pub version: String,
}

impl ModuleSpec {
    pub fn new(name: String, version: String) -> Self {
        Self { name, version }
    }
}

/// Extension trait for DataCollector to support version matching
///
/// Add this to your DataCollector implementations:
///
/// ```ignore
/// impl DataCollector for MyCollector {
///     // ... existing methods ...
///
///     fn supports_module(&self, name: &str, version: &str) -> bool {
///         if name != "MyModule" {
///             return false;
///         }
///
///         // Parse versions
///         let requested = SemanticVersion::parse(version)?;
///         let supported = SemanticVersion::parse("2.1.0")?; // Your collector's version
///
///         supported.is_compatible_with(&requested)
///     }
/// }
/// ```
/// Update to StrategyRegistry to support version-aware collector lookup
pub struct VersionAwareCollectorRegistry;

impl VersionAwareCollectorRegistry {
    /// Get collector that supports the specified module and version
    ///
    /// This should be added to StrategyRegistry:
    ///
    /// ```ignore
    /// impl StrategyRegistry {
    ///     pub fn get_collector_for_module(
    ///         &self,
    ///         module_spec: &ModuleSpec,
    ///     ) -> Result<&dyn DataCollector, StrategyError> {
    ///         // Try to find a collector that supports this module and version
    ///         for (collector_type, collector) in &self.collectors {
    ///             if collector.supports_module(&module_spec.name, &module_spec.version) {
    ///                 return Ok(collector.as_ref());
    ///             }
    ///         }
    ///
    ///         Err(StrategyError::Configuration {
    ///             message: format!(
    ///                 "No collector found for module '{}' version '{}'",
    ///                 module_spec.name, module_spec.version
    ///             ),
    ///         })
    ///     }
    /// }
    /// ```
    pub fn example_usage() {
        // This is a template for updating StrategyRegistry
    }
}

/// Extract module specification from ExecutableObject
pub fn extract_module_spec(
    object: &crate::types::execution_context::ExecutableObject,
) -> Option<ModuleSpec> {
    use crate::types::execution_context::ExecutableObjectElement;

    let mut name = None;
    let mut version = None;

    for element in &object.elements {
        if let ExecutableObjectElement::Module { field, value } = element {
            match field {
                ModuleField::ModuleName => {
                    name = Some(value.clone());
                }
                ModuleField::ModuleVersion => {
                    version = Some(value.clone());
                }
                _ => {}
            }
        }
    }

    match (name, version) {
        (Some(n), Some(v)) => Some(ModuleSpec::new(n, v)),
        (Some(n), None) => Some(ModuleSpec::new(n, "1.0.0".to_string())), // Default version
        _ => None,
    }
}

/// Validate module compatibility before collection
pub fn validate_module_compatibility(
    collector: &dyn CtnDataCollector,
    object: &ExecutableObject,
) -> Result<(), ExecutionError> {
    // Extract module specs from object
    use crate::types::execution_context::ExecutableObjectElement;

    let mut module_specs: Vec<(ModuleField, String)> = Vec::new();
    for element in &object.elements {
        if let ExecutableObjectElement::Module { field, value } = element {
            module_specs.push((*field, value.clone()));
        }
    }

    if module_specs.is_empty() {
        return Ok(()); // No module requirements
    }

    for (field, value) in module_specs {
        log_debug!("Checking module requirement",
            "module_field" => format!("{:?}", field).as_str(),
            "module_value" => value,
            "collector_id" => collector.collector_id()
        );

        // For now, just log - module support not yet implemented in trait
        if matches!(field, ModuleField::ModuleVersion) {
            log_info!("Module version check skipped - trait support not implemented",
                "version" => value,
                "collector" => collector.collector_id()
            );
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_semantic_version_parsing() {
        let v = SemanticVersion::parse("2.1.0").unwrap();
        assert_eq!(v.major, 2);
        assert_eq!(v.minor, 1);
        assert_eq!(v.patch, 0);

        let v = SemanticVersion::parse("3.5").unwrap();
        assert_eq!(v.major, 3);
        assert_eq!(v.minor, 5);
        assert_eq!(v.patch, 0);

        let v = SemanticVersion::parse("1").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 0);
        assert_eq!(v.patch, 0);
    }

    #[test]
    fn test_version_compatibility() {
        let v2_1_0 = SemanticVersion::parse("2.1.0").unwrap();

        // Same major, equal minor - compatible
        let v2_1_5 = SemanticVersion::parse("2.1.5").unwrap();
        assert!(v2_1_0.is_compatible_with(&v2_1_5));

        // Same major, higher minor - compatible with lower request
        let v2_0_0 = SemanticVersion::parse("2.0.0").unwrap();
        assert!(v2_1_0.is_compatible_with(&v2_0_0));

        // Same major, lower minor - not compatible with higher request
        let v2_2_0 = SemanticVersion::parse("2.2.0").unwrap();
        assert!(!v2_1_0.is_compatible_with(&v2_2_0));

        // Different major - incompatible
        let v3_0_0 = SemanticVersion::parse("3.0.0").unwrap();
        assert!(!v2_1_0.is_compatible_with(&v3_0_0));
    }

    #[test]
    fn test_version_ordering() {
        let v1_0_0 = SemanticVersion::parse("1.0.0").unwrap();
        let v2_0_0 = SemanticVersion::parse("2.0.0").unwrap();
        let v2_1_0 = SemanticVersion::parse("2.1.0").unwrap();
        let v2_1_5 = SemanticVersion::parse("2.1.5").unwrap();

        assert!(v1_0_0 < v2_0_0);
        assert!(v2_0_0 < v2_1_0);
        assert!(v2_1_0 < v2_1_5);
    }

    #[test]
    fn test_invalid_version_parsing() {
        assert!(SemanticVersion::parse("invalid").is_none());
        assert!(SemanticVersion::parse("1.2.3.4").is_none());
        assert!(SemanticVersion::parse("a.b.c").is_none());
    }

    #[test]
    fn test_module_spec_creation() {
        let spec = ModuleSpec::new("PowerShell.Security".to_string(), "2.1.0".to_string());

        assert_eq!(spec.name, "PowerShell.Security");
        assert_eq!(spec.version, "2.1.0");
    }
}
