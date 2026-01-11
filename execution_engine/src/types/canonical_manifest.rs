//! Canonical Manifest Types
//!
//! These types define the canonical structures that are hashed ONCE during execution
//! and used by ALL output formats (attestation, full-results, assessor).
//!
//! ## Design Principles
//!
//! 1. **Deterministic**: Uses BTreeMap for sorted keys, ensuring identical JSON output
//! 2. **Format-independent**: Contains only the essential data, not presentation details
//! 3. **Computed once**: Hashes are computed in ExecutionEngine::execute(), not in output builders
//!
//! ## Crypto
//!
//! Uses `common::results::crypto` for FIPS 140-3 compliant hashing (Windows CNG / OpenSSL).

use common::results::crypto::{hash_content, sha256_hash};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ============================================================================
// Content Manifest - WHAT was evaluated
// ============================================================================

/// Canonical content manifest describing what was evaluated
///
/// This structure captures the policy identity and evaluation context.
/// It is hashed once and the hash is included in all output formats.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentManifest {
    /// Schema version for this manifest format
    pub schema_version: String,

    /// Policy identifier from ESP metadata
    pub policy_id: String,

    /// Policy version (if specified in metadata)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_version: Option<String>,

    /// Target platform (e.g., "windows", "linux", "kubernetes")
    pub platform: String,

    /// Criticality level as string for deterministic serialization
    pub criticality: String,

    /// Control mappings in deterministic order
    /// Format: ["FRAMEWORK:CONTROL_ID", ...]
    pub control_mappings: Vec<String>,

    /// Hash of the criteria tree structure
    pub criteria_structure_hash: String,

    /// Execution parameters that affect evaluation (sorted)
    #[serde(skip_serializing_if = "BTreeMap::is_empty", default)]
    pub parameters: BTreeMap<String, String>,
}

impl ContentManifest {
    /// Create a new content manifest
    pub fn new(policy_id: impl Into<String>, platform: impl Into<String>) -> Self {
        Self {
            schema_version: "1.0.0".to_string(),
            policy_id: policy_id.into(),
            policy_version: None,
            platform: platform.into(),
            criticality: "medium".to_string(),
            control_mappings: Vec::new(),
            criteria_structure_hash: String::new(),
            parameters: BTreeMap::new(),
        }
    }

    /// Set policy version
    pub fn with_version(mut self, version: impl Into<String>) -> Self {
        self.policy_version = Some(version.into());
        self
    }

    /// Set criticality
    pub fn with_criticality(mut self, criticality: impl Into<String>) -> Self {
        self.criticality = criticality.into();
        self
    }

    /// Set control mappings from vec (will be sorted)
    pub fn with_control_mappings(mut self, mut mappings: Vec<String>) -> Self {
        mappings.sort();
        self.control_mappings = mappings;
        self
    }

    /// Set criteria structure hash
    pub fn with_criteria_hash(mut self, hash: impl Into<String>) -> Self {
        self.criteria_structure_hash = hash.into();
        self
    }

    /// Add execution parameter
    pub fn add_parameter(&mut self, key: impl Into<String>, value: impl Into<String>) {
        self.parameters.insert(key.into(), value.into());
    }

    /// Compute the canonical hash of this manifest
    ///
    /// Uses FIPS 140-3 compliant SHA-256 via common::results::crypto
    pub fn compute_hash(&self) -> String {
        compute_manifest_hash(self)
    }
}

// ============================================================================
// Evidence Manifest - WHAT was observed
// ============================================================================

/// Canonical evidence manifest describing what was observed
///
/// This structure captures the collected evidence in a deterministic format.
/// It is hashed once and the hash is included in all output formats.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvidenceManifest {
    /// Schema version for this manifest format
    pub schema_version: String,

    /// Criterion results in deterministic order (sorted by criterion ID)
    pub criteria: BTreeMap<String, CriterionEvidence>,
}

impl EvidenceManifest {
    /// Create a new empty evidence manifest
    pub fn new() -> Self {
        Self {
            schema_version: "1.0.0".to_string(),
            criteria: BTreeMap::new(),
        }
    }

    /// Add criterion evidence
    pub fn add_criterion(&mut self, criterion_id: impl Into<String>, evidence: CriterionEvidence) {
        self.criteria.insert(criterion_id.into(), evidence);
    }

    /// Compute the canonical hash of this manifest
    ///
    /// Uses FIPS 140-3 compliant SHA-256 via common::results::crypto
    pub fn compute_hash(&self) -> String {
        compute_manifest_hash(self)
    }

    /// Check if manifest is empty
    pub fn is_empty(&self) -> bool {
        self.criteria.is_empty()
    }
}

impl Default for EvidenceManifest {
    fn default() -> Self {
        Self::new()
    }
}

/// Evidence for a single criterion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CriterionEvidence {
    /// CTN type (e.g., "file_metadata", "registry")
    pub ctn_type: String,

    /// Outcome as string for deterministic serialization
    pub outcome: String,

    /// Object evidence in deterministic order (sorted by object ID)
    pub objects: BTreeMap<String, ObjectEvidence>,
}

impl CriterionEvidence {
    /// Create new criterion evidence
    pub fn new(ctn_type: impl Into<String>, outcome: impl Into<String>) -> Self {
        Self {
            ctn_type: ctn_type.into(),
            outcome: outcome.into(),
            objects: BTreeMap::new(),
        }
    }

    /// Add object evidence
    pub fn add_object(&mut self, object_id: impl Into<String>, evidence: ObjectEvidence) {
        self.objects.insert(object_id.into(), evidence);
    }
}

/// Evidence for a single object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectEvidence {
    /// Collected field values in deterministic order (sorted by field name)
    pub fields: BTreeMap<String, serde_json::Value>,

    /// Collection method type (not the full command)
    pub collection_method: String,

    /// Whether collection succeeded
    pub collection_succeeded: bool,
}

impl ObjectEvidence {
    /// Create new object evidence
    pub fn new(collection_method: impl Into<String>) -> Self {
        Self {
            fields: BTreeMap::new(),
            collection_method: collection_method.into(),
            collection_succeeded: true,
        }
    }

    /// Add a field value
    pub fn add_field(&mut self, name: impl Into<String>, value: serde_json::Value) {
        self.fields.insert(name.into(), value);
    }

    /// Mark collection as failed
    pub fn with_failure(mut self) -> Self {
        self.collection_succeeded = false;
        self
    }
}

// ============================================================================
// Hash Computation - Uses existing FIPS-compliant crypto
// ============================================================================

/// Compute a deterministic SHA-256 hash of any serializable manifest
///
/// Uses the existing FIPS 140-3 compliant crypto from common::results::crypto.
/// Returns hash in format "sha256:<hex_digest>".
fn compute_manifest_hash<T: Serialize>(value: &T) -> String {
    match hash_content(value) {
        Ok(hex_hash) => format!("sha256:{}", hex_hash),
        Err(_) => "sha256:error-computing-hash".to_string(),
    }
}

/// Combine multiple hashes into a single hash (sorted for determinism)
///
/// Used when aggregating results from multiple policies.
pub fn combine_hashes<'a, I>(hashes: I) -> String
where
    I: Iterator<Item = &'a String>,
{
    let mut sorted: Vec<&String> = hashes.collect();
    sorted.sort();

    // Concatenate all hashes with separator
    let mut combined = Vec::new();
    for hash in sorted {
        combined.extend_from_slice(hash.as_bytes());
        combined.push(b'|');
    }

    match sha256_hash(&combined) {
        Ok(digest) => {
            let hex: String = digest.iter().map(|b| format!("{:02x}", b)).collect();
            format!("sha256:{}", hex)
        }
        Err(_) => "sha256:error-combining-hashes".to_string(),
    }
}

// ============================================================================
// Re-exports for convenience
// ============================================================================

pub use common::results::crypto::HashingError as ManifestHashError;

// ============================================================================
// Tests
// ============================================================================

#[allow(clippy::unwrap_used, clippy::expect_used)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_content_manifest_deterministic() {
        let mut manifest1 = ContentManifest::new("policy-1", "linux");
        manifest1.add_parameter("key1", "value1");
        manifest1.add_parameter("key2", "value2");

        let mut manifest2 = ContentManifest::new("policy-1", "linux");
        manifest2.add_parameter("key2", "value2");
        manifest2.add_parameter("key1", "value1");

        assert_eq!(manifest1.compute_hash(), manifest2.compute_hash());
    }

    #[test]
    fn test_evidence_manifest_deterministic() {
        let mut manifest1 = EvidenceManifest::new();
        let mut crit1 = CriterionEvidence::new("file_metadata", "Pass");
        let mut obj1 = ObjectEvidence::new("file_stat");
        obj1.add_field("exists", serde_json::json!(true));
        obj1.add_field("size", serde_json::json!(1024));
        crit1.add_object("obj-1", obj1);
        manifest1.add_criterion("crit-1", crit1);

        let mut manifest2 = EvidenceManifest::new();
        let mut crit2 = CriterionEvidence::new("file_metadata", "Pass");
        let mut obj2 = ObjectEvidence::new("file_stat");
        obj2.add_field("size", serde_json::json!(1024));
        obj2.add_field("exists", serde_json::json!(true));
        crit2.add_object("obj-1", obj2);
        manifest2.add_criterion("crit-1", crit2);

        assert_eq!(manifest1.compute_hash(), manifest2.compute_hash());
    }

    #[test]
    fn test_hash_format() {
        let manifest = ContentManifest::new("test", "linux");
        let hash = manifest.compute_hash();

        assert!(hash.starts_with("sha256:"));
        assert_eq!(hash.len(), 7 + 64); // "sha256:" + 64 hex chars
    }

    #[test]
    fn test_combine_hashes_deterministic() {
        let hash1 = "sha256:abc123".to_string();
        let hash2 = "sha256:def456".to_string();

        let combined1 = combine_hashes([&hash1, &hash2].into_iter());
        let combined2 = combine_hashes([&hash2, &hash1].into_iter());

        assert_eq!(combined1, combined2);
    }

    #[test]
    fn test_different_data_different_hash() {
        let manifest1 = ContentManifest::new("policy-1", "linux");
        let manifest2 = ContentManifest::new("policy-2", "linux");

        assert_ne!(manifest1.compute_hash(), manifest2.compute_hash());
    }
}
