//! Metadata block types for ESP policies
//!
//! The META block in ESP policies contains key-value pairs that describe
//! the policy's purpose, compliance mappings, and execution requirements.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// A metadata block from an ESP policy file
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetaDataBlock {
    /// Key-value pairs from the META block
    pub fields: HashMap<String, String>,
}

impl MetaDataBlock {
    /// Create a new empty metadata block
    pub fn new() -> Self {
        Self {
            fields: HashMap::new(),
        }
    }

    /// Create from a HashMap
    pub fn from_fields(fields: HashMap<String, String>) -> Self {
        Self { fields }
    }

    /// Get a field value
    pub fn get(&self, key: &str) -> Option<&str> {
        self.fields.get(key).map(|s| s.as_str())
    }

    /// Set a field value
    pub fn set(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.fields.insert(key.into(), value.into());
    }

    /// Check if a field exists
    pub fn has(&self, key: &str) -> bool {
        self.fields.contains_key(key)
    }

    /// Get the policy ID (esp_scan_id)
    pub fn policy_id(&self) -> Option<&str> {
        self.get("esp_scan_id")
    }

    /// Get the platform
    pub fn platform(&self) -> Option<&str> {
        self.get("platform")
    }

    /// Get the criticality
    pub fn criticality(&self) -> Option<&str> {
        self.get("criticality")
    }

    /// Get control mappings string
    pub fn control_mapping(&self) -> Option<&str> {
        self.get("control_mapping")
    }

    /// Check if all required fields are present
    pub fn has_required_fields(&self) -> bool {
        self.has("esp_scan_id")
            && self.has("platform")
            && self.has("criticality")
            && self.has("control_mapping")
    }

    /// Get list of missing required fields
    pub fn missing_required_fields(&self) -> Vec<&'static str> {
        let required = ["esp_scan_id", "platform", "criticality", "control_mapping"];
        required
            .iter()
            .filter(|&&field| !self.has(field))
            .copied()
            .collect()
    }
}

impl Default for MetaDataBlock {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metadata_new() {
        let meta = MetaDataBlock::new();
        assert!(meta.fields.is_empty());
    }

    #[test]
    fn test_metadata_set_get() {
        let mut meta = MetaDataBlock::new();
        meta.set("esp_scan_id", "test-001");

        assert_eq!(meta.get("esp_scan_id"), Some("test-001"));
        assert!(meta.has("esp_scan_id"));
        assert!(!meta.has("nonexistent"));
    }

    #[test]
    fn test_metadata_helpers() {
        let mut fields = HashMap::new();
        fields.insert("esp_scan_id".to_string(), "policy-001".to_string());
        fields.insert("platform".to_string(), "Kubernetes".to_string());
        fields.insert("criticality".to_string(), "high".to_string());
        fields.insert("control_mapping".to_string(), "CIS:1.1.1".to_string());

        let meta = MetaDataBlock::from_fields(fields);

        assert_eq!(meta.policy_id(), Some("policy-001"));
        assert_eq!(meta.platform(), Some("Kubernetes"));
        assert_eq!(meta.criticality(), Some("high"));
        assert!(meta.has_required_fields());
        assert!(meta.missing_required_fields().is_empty());
    }

    #[test]
    fn test_missing_required_fields() {
        let mut meta = MetaDataBlock::new();
        meta.set("esp_scan_id", "test");

        assert!(!meta.has_required_fields());

        let missing = meta.missing_required_fields();
        assert!(missing.contains(&"platform"));
        assert!(missing.contains(&"criticality"));
        assert!(missing.contains(&"control_mapping"));
        assert!(!missing.contains(&"esp_scan_id"));
    }
}
