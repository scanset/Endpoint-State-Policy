//! Policy identity for ESP attestations
//!
//! Provides a lightweight structure for identifying policies in attestations
//! without including CUI (Controlled Unclassified Information).

use serde::{Deserialize, Serialize};

use super::common::{ControlMapping, Criticality};

// ============================================================================
// PolicyIdentity
// ============================================================================

/// Identity information for a policy in attestations
///
/// Contains the minimum information needed to identify a policy
/// and its compliance framework mappings without CUI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyIdentity {
    /// Policy identifier from META esp_scan_id
    pub policy_id: String,

    /// Policy version (optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    /// Target platform from META
    pub platform: String,

    /// Criticality level from META
    pub criticality: Criticality,

    /// Control framework mappings
    pub control_mappings: Vec<ControlMapping>,
}

impl PolicyIdentity {
    /// Create a new policy identity
    pub fn new(
        policy_id: impl Into<String>,
        platform: impl Into<String>,
        criticality: Criticality,
        control_mappings: Vec<ControlMapping>,
    ) -> Self {
        Self {
            policy_id: policy_id.into(),
            version: None,
            platform: platform.into(),
            criticality,
            control_mappings,
        }
    }

    /// Set policy version
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.version = Some(version.into());
        self
    }

    /// Get the primary control mapping (first one)
    pub fn primary_control(&self) -> Option<&ControlMapping> {
        self.control_mappings.first()
    }

    /// Get all framework names
    pub fn frameworks(&self) -> Vec<&str> {
        self.control_mappings
            .iter()
            .map(|m| m.framework.as_str())
            .collect()
    }

    /// Check if policy maps to a specific framework
    pub fn maps_to_framework(&self, framework: &str) -> bool {
        self.control_mappings
            .iter()
            .any(|m| m.framework.eq_ignore_ascii_case(framework))
    }

    /// Get control IDs for a specific framework
    pub fn controls_for_framework(&self, framework: &str) -> Vec<&str> {
        self.control_mappings
            .iter()
            .filter(|m| m.framework.eq_ignore_ascii_case(framework))
            .map(|m| m.control_id.as_str())
            .collect()
    }
}

// ============================================================================
// Tests
// ============================================================================
#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_identity_new() {
        let mappings = vec![
            ControlMapping::new("NIST-800-53", "AC-6"),
            ControlMapping::new("CIS", "5.1.1"),
        ];

        let identity =
            PolicyIdentity::new("ssh-hardening-001", "linux", Criticality::High, mappings);

        assert_eq!(identity.policy_id, "ssh-hardening-001");
        assert_eq!(identity.platform, "linux");
        assert_eq!(identity.criticality, Criticality::High);
        assert_eq!(identity.control_mappings.len(), 2);
        assert!(identity.version.is_none());
    }

    #[test]
    fn test_policy_identity_with_version() {
        let identity = PolicyIdentity::new("test-policy", "windows", Criticality::Medium, vec![])
            .with_version("1.2.3");

        assert_eq!(identity.version, Some("1.2.3".to_string()));
    }

    #[test]
    fn test_primary_control() {
        let mappings = vec![
            ControlMapping::new("STIG", "V-242382"),
            ControlMapping::new("CIS", "1.1.1"),
        ];

        let identity = PolicyIdentity::new("test-policy", "linux", Criticality::Critical, mappings);

        let primary = identity.primary_control().unwrap();
        assert_eq!(primary.framework, "STIG");
        assert_eq!(primary.control_id, "V-242382");
    }

    #[test]
    fn test_frameworks() {
        let mappings = vec![
            ControlMapping::new("NIST-800-53", "AC-6"),
            ControlMapping::new("CIS", "5.1.1"),
            ControlMapping::new("STIG", "V-242382"),
        ];

        let identity = PolicyIdentity::new("test-policy", "linux", Criticality::High, mappings);

        let frameworks = identity.frameworks();
        assert_eq!(frameworks.len(), 3);
        assert!(frameworks.contains(&"NIST-800-53"));
        assert!(frameworks.contains(&"CIS"));
        assert!(frameworks.contains(&"STIG"));
    }

    #[test]
    fn test_maps_to_framework() {
        let mappings = vec![
            ControlMapping::new("NIST-800-53", "AC-6"),
            ControlMapping::new("CIS", "5.1.1"),
        ];

        let identity = PolicyIdentity::new("test-policy", "linux", Criticality::Medium, mappings);

        assert!(identity.maps_to_framework("NIST-800-53"));
        assert!(identity.maps_to_framework("nist-800-53")); // Case insensitive
        assert!(identity.maps_to_framework("CIS"));
        assert!(!identity.maps_to_framework("STIG"));
    }

    #[test]
    fn test_controls_for_framework() {
        let mappings = vec![
            ControlMapping::new("NIST-800-53", "AC-6"),
            ControlMapping::new("NIST-800-53", "AC-2"),
            ControlMapping::new("CIS", "5.1.1"),
        ];

        let identity = PolicyIdentity::new("test-policy", "linux", Criticality::High, mappings);

        let nist_controls = identity.controls_for_framework("NIST-800-53");
        assert_eq!(nist_controls.len(), 2);
        assert!(nist_controls.contains(&"AC-6"));
        assert!(nist_controls.contains(&"AC-2"));

        let cis_controls = identity.controls_for_framework("CIS");
        assert_eq!(cis_controls.len(), 1);
        assert!(cis_controls.contains(&"5.1.1"));
    }

    #[test]
    fn test_serialization() {
        let identity = PolicyIdentity::new(
            "test-policy",
            "kubernetes",
            Criticality::Critical,
            vec![ControlMapping::new("CIS", "1.1.1")],
        )
        .with_version("2.0.0");

        let json = serde_json::to_string(&identity).unwrap();
        let parsed: PolicyIdentity = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.policy_id, "test-policy");
        assert_eq!(parsed.version, Some("2.0.0".to_string()));
        assert_eq!(parsed.criticality, Criticality::Critical);
    }
}
