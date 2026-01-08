//! Evidence types for ESP scan results
//!
//! Evidence contains the raw collected data from policy execution.
//! This is CUI (Controlled Unclassified Information) and should only
//! be included in full results, not attestations.
//!
//! ## Structure
//!
//! ```text
//! Evidence
//! ├── data                - Collected field values by object ID
//! ├── collection_metadata - Information about how data was collected
//! └── collected_at        - Timestamp when evidence was gathered
//! ```
//!
//! ## Attestation vs Full Results
//!
//! - **Attestations**: Include `evidence_hash` (SHA-256 of evidence), not actual data
//! - **Full Results**: Include complete `Evidence` structure with all collected values

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ============================================================================
// Evidence
// ============================================================================

/// Raw evidence data collected during scan execution
///
/// Contains the actual system configuration values gathered during collection.
/// This is CUI and should not be transmitted over untrusted networks.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Evidence {
    /// Collected data keyed by object ID
    ///
    /// Each value is a JSON object containing the collected fields
    /// for that object (e.g., service state, file permissions, etc.)
    pub data: HashMap<String, serde_json::Value>,

    /// Metadata about how evidence was collected
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub collection_metadata: Vec<CollectionRecord>,

    /// When evidence was collected (ISO 8601)
    pub collected_at: String,
}

impl Evidence {
    /// Create new evidence container
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
            collection_metadata: Vec::new(),
            collected_at: current_timestamp(),
        }
    }

    /// Add evidence data for an object
    pub fn add_data(&mut self, key: impl Into<String>, value: serde_json::Value) {
        self.data.insert(key.into(), value);
    }

    /// Add collection metadata record
    pub fn add_collection_record(&mut self, record: CollectionRecord) {
        self.collection_metadata.push(record);
    }

    /// Get evidence by key
    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        self.data.get(key)
    }

    /// Check if evidence contains a key
    pub fn contains(&self, key: &str) -> bool {
        self.data.contains_key(key)
    }

    /// Get number of evidence items
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if evidence is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Get all object IDs in evidence
    pub fn object_ids(&self) -> Vec<&String> {
        self.data.keys().collect()
    }

    /// Merge another evidence container into this one
    pub fn merge(&mut self, other: Evidence) {
        for (key, value) in other.data {
            self.data.insert(key, value);
        }
        self.collection_metadata.extend(other.collection_metadata);
    }

    /// Compute SHA-256 hash of evidence data
    ///
    /// Used for attestations to prove evidence existed without including it.
    pub fn compute_hash(&self) -> Result<String, super::crypto::HashingError> {
        super::crypto::hash_content(&self.data)
    }
}

// ============================================================================
// CollectionRecord
// ============================================================================

/// Metadata about a single collection operation
///
/// Records how data was collected for audit and debugging purposes.
/// This is included in full results but summarized in attestations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionRecord {
    /// Object ID that was collected
    pub object_id: String,

    /// CTN type (e.g., "service", "file_metadata", "registry")
    pub ctn_type: String,

    /// Collector that gathered the data
    pub collector_id: String,

    /// Collection mode used (e.g., "default", "query", "list")
    pub collection_mode: String,

    /// How long collection took in milliseconds
    pub duration_ms: u64,

    /// Number of fields collected
    pub field_count: usize,

    /// Whether collection produced any warnings
    pub has_warnings: bool,

    /// Warning messages (if any)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

impl CollectionRecord {
    /// Create a new collection record
    pub fn new(
        object_id: impl Into<String>,
        ctn_type: impl Into<String>,
        collector_id: impl Into<String>,
    ) -> Self {
        Self {
            object_id: object_id.into(),
            ctn_type: ctn_type.into(),
            collector_id: collector_id.into(),
            collection_mode: "default".to_string(),
            duration_ms: 0,
            field_count: 0,
            has_warnings: false,
            warnings: Vec::new(),
        }
    }

    /// Set collection mode
    pub fn with_mode(mut self, mode: impl Into<String>) -> Self {
        self.collection_mode = mode.into();
        self
    }

    /// Set duration
    pub fn with_duration_ms(mut self, duration_ms: u64) -> Self {
        self.duration_ms = duration_ms;
        self
    }

    /// Set field count
    pub fn with_field_count(mut self, count: usize) -> Self {
        self.field_count = count;
        self
    }

    /// Add warnings
    pub fn with_warnings(mut self, warnings: Vec<String>) -> Self {
        self.has_warnings = !warnings.is_empty();
        self.warnings = warnings;
        self
    }
}

// ============================================================================
// EvidenceSummary (for attestations)
// ============================================================================

/// Summary of evidence for attestations (CUI-free)
///
/// Provides metadata about collected evidence without actual values.
/// Safe for network transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceSummary {
    /// SHA-256 hash of the evidence data
    pub evidence_hash: String,

    /// Number of objects with collected evidence
    pub object_count: usize,

    /// Total number of fields collected
    pub total_fields: usize,

    /// Summary of collection operations
    pub collection_summary: Vec<CollectionSummary>,
}

impl EvidenceSummary {
    /// Create evidence summary from full evidence
    pub fn from_evidence(evidence: &Evidence) -> Result<Self, super::crypto::HashingError> {
        let evidence_hash = evidence.compute_hash()?;

        let total_fields: usize = evidence
            .data
            .values()
            .filter_map(|v| v.as_object())
            .map(|obj| obj.len())
            .sum();

        let collection_summary: Vec<CollectionSummary> = evidence
            .collection_metadata
            .iter()
            .map(CollectionSummary::from_record)
            .collect();

        Ok(Self {
            evidence_hash,
            object_count: evidence.data.len(),
            total_fields,
            collection_summary,
        })
    }
}

/// Summary of a collection operation (CUI-free)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectionSummary {
    /// Object ID that was collected
    pub object_id: String,

    /// CTN type
    pub ctn_type: String,

    /// Collector ID
    pub collector_id: String,

    /// Duration in milliseconds
    pub duration_ms: u64,

    /// Whether there were warnings
    pub has_warnings: bool,
}

impl CollectionSummary {
    /// Create from a full collection record
    pub fn from_record(record: &CollectionRecord) -> Self {
        Self {
            object_id: record.object_id.clone(),
            ctn_type: record.ctn_type.clone(),
            collector_id: record.collector_id.clone(),
            duration_ms: record.duration_ms,
            has_warnings: record.has_warnings,
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Generate ISO 8601 timestamp
fn current_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    let secs = duration.as_secs();
    let days = secs / 86400;
    let remaining = secs % 86400;
    let hours = remaining / 3600;
    let minutes = (remaining % 3600) / 60;
    let seconds = remaining % 60;

    let years = 1970 + (days / 365);
    let day_of_year = days % 365;
    let month = (day_of_year / 30) + 1;
    let day = (day_of_year % 30) + 1;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        years, month, day, hours, minutes, seconds
    )
}

// ============================================================================
// Tests
// ============================================================================
#[allow(clippy::unwrap_used)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_evidence_new() {
        let evidence = Evidence::new();

        assert!(evidence.is_empty());
        assert!(!evidence.collected_at.is_empty());
    }

    #[test]
    fn test_evidence_add_data() {
        let mut evidence = Evidence::new();

        evidence.add_data(
            "service_svc_obj",
            serde_json::json!({
                "exists": true,
                "state": "running",
                "start_type": "auto"
            }),
        );

        assert_eq!(evidence.len(), 1);
        assert!(evidence.contains("service_svc_obj"));

        let data = evidence.get("service_svc_obj").unwrap();
        assert_eq!(data["state"], "running");
    }

    #[test]
    fn test_evidence_merge() {
        let mut evidence1 = Evidence::new();
        evidence1.add_data("obj1", serde_json::json!({"field": "value1"}));

        let mut evidence2 = Evidence::new();
        evidence2.add_data("obj2", serde_json::json!({"field": "value2"}));

        evidence1.merge(evidence2);

        assert_eq!(evidence1.len(), 2);
        assert!(evidence1.contains("obj1"));
        assert!(evidence1.contains("obj2"));
    }

    #[test]
    fn test_evidence_compute_hash() {
        let mut evidence = Evidence::new();
        evidence.add_data("obj1", serde_json::json!({"field": "value"}));

        let hash = evidence.compute_hash().unwrap();

        // Hash should be deterministic
        let hash2 = evidence.compute_hash().unwrap();
        assert_eq!(hash, hash2);

        // Hash should be a hex string
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_collection_record() {
        let record = CollectionRecord::new("svc_obj", "service", "windows_service_collector")
            .with_mode("query")
            .with_duration_ms(45)
            .with_field_count(6)
            .with_warnings(vec!["Minor issue".to_string()]);

        assert_eq!(record.object_id, "svc_obj");
        assert_eq!(record.ctn_type, "service");
        assert_eq!(record.collector_id, "windows_service_collector");
        assert_eq!(record.collection_mode, "query");
        assert_eq!(record.duration_ms, 45);
        assert_eq!(record.field_count, 6);
        assert!(record.has_warnings);
        assert_eq!(record.warnings.len(), 1);
    }

    #[test]
    fn test_evidence_summary() {
        let mut evidence = Evidence::new();
        evidence.add_data(
            "obj1",
            serde_json::json!({
                "field1": "value1",
                "field2": "value2"
            }),
        );
        evidence.add_data(
            "obj2",
            serde_json::json!({
                "fieldA": "valueA"
            }),
        );

        evidence.add_collection_record(
            CollectionRecord::new("obj1", "service", "collector1").with_duration_ms(10),
        );
        evidence.add_collection_record(
            CollectionRecord::new("obj2", "file", "collector2").with_duration_ms(20),
        );

        let summary = EvidenceSummary::from_evidence(&evidence).unwrap();

        assert_eq!(summary.object_count, 2);
        assert_eq!(summary.total_fields, 3); // 2 + 1
        assert_eq!(summary.collection_summary.len(), 2);
        assert!(!summary.evidence_hash.is_empty());
    }

    #[test]
    fn test_serialization() {
        let mut evidence = Evidence::new();
        evidence.add_data("obj1", serde_json::json!({"state": "running"}));
        evidence.add_collection_record(CollectionRecord::new("obj1", "service", "collector"));

        let json = serde_json::to_string(&evidence).unwrap();
        let parsed: Evidence = serde_json::from_str(&json).unwrap();

        assert_eq!(parsed.len(), 1);
        assert!(parsed.contains("obj1"));
        assert_eq!(parsed.collection_metadata.len(), 1);
    }
}
