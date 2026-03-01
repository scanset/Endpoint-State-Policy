//! Canonical Manifest Types — Replay Hash Architecture
//!
//! The `ReplayManifest` replaces the previous `ContentManifest` + `EvidenceManifest`
//! with a single hashable structure that captures the complete verification lifecycle.
//!
//! ## Three-Layer Design
//!
//! Each criterion (CTN) produces a hash from three layers:
//!
//! 1. **Intent** — What the policy author specified: STATE fields, operations,
//!    expected values, TEST specification, object identifiers. From the resolved AST.
//!
//! 2. **Contract** — How the system executed it: CTN type, collector ID, collection
//!    mode, validation field mappings (state_field → data_field). From the CtnContract.
//!
//! 3. **Outcome** — What happened: pass/fail per validated field, per criterion.
//!    Does NOT include actual collected values (those are volatile).
//!
//! ## Tree Rollup
//!
//! Criterion hashes are rolled up through the CRI tree structure:
//!
//! ```text
//! CRI AND
//! ├── CTN sysctl_parameter (node 3) → criterion_hash_3
//! ├── CTN file_content (node 1)     → criterion_hash_1
//! └── CRI OR (negated: false)
//!     ├── CTN tcp_listener (node 4) → criterion_hash_4
//!     └── CTN tcp_listener (node 5) → criterion_hash_5
//!     → or_block_hash = hash(OR | false | [hash_4, hash_5])
//! → replay_hash = hash(AND | false | [hash_1, hash_3, or_block_hash])
//! ```
//!
//! ## Stability Guarantee
//!
//! Same policy + same compliance posture = same `replay_hash`, always.
//! Volatile data (timestamps, counters, file contents that didn't change
//! compliance outcome) never enters the hash.
//!
//! ## Crypto
//!
//! Uses `common::results::crypto` for FIPS 140-3 compliant SHA-256.

use common::results::crypto::{hash_content, sha256_hash};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// ============================================================================
// Replay Manifest — Root structure
// ============================================================================

/// Canonical replay manifest for a single policy execution
///
/// Contains per-criterion replay entries and the tree structure used to
/// roll up individual criterion hashes into the final `replay_hash`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayManifest {
    /// Schema version for this manifest format
    pub schema_version: String,

    /// Policy identifier from ESP metadata
    pub policy_id: String,

    /// Target platform
    pub platform: String,

    /// Criticality level
    pub criticality: String,

    /// Control mappings in sorted order ("FRAMEWORK:CONTROL_ID")
    pub control_mappings: Vec<String>,

    /// Per-criterion replay data, keyed by ctn_node_id (BTreeMap for determinism)
    pub criteria: BTreeMap<String, CriterionReplay>,

    /// Tree structure for hash rollup
    pub tree_structure: ReplayTreeNode,
}

impl ReplayManifest {
    /// Create a new replay manifest
    pub fn new(
        policy_id: impl Into<String>,
        platform: impl Into<String>,
        criticality: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: "2.0.0".to_string(),
            policy_id: policy_id.into(),
            platform: platform.into(),
            criticality: criticality.into(),
            control_mappings: Vec::new(),
            criteria: BTreeMap::new(),
            tree_structure: ReplayTreeNode::Leaf {
                ctn_node_id: "0".to_string(),
            },
        }
    }

    /// Set control mappings (will be sorted)
    pub fn with_control_mappings(mut self, mut mappings: Vec<String>) -> Self {
        mappings.sort();
        self.control_mappings = mappings;
        self
    }

    /// Add a criterion replay entry
    pub fn add_criterion(&mut self, ctn_node_id: impl Into<String>, replay: CriterionReplay) {
        self.criteria.insert(ctn_node_id.into(), replay);
    }

    /// Set the tree structure for hash rollup
    pub fn set_tree_structure(&mut self, tree: ReplayTreeNode) {
        self.tree_structure = tree;
    }

    /// Compute the final replay_hash
    ///
    /// 1. Compute individual criterion hashes
    /// 2. Roll up through the tree structure
    /// 3. Combine with policy identity for the final hash
    pub fn compute_replay_hash(&self) -> String {
        // Step 1: Compute per-criterion hashes
        let criterion_hashes: BTreeMap<String, String> = self
            .criteria
            .iter()
            .map(|(id, replay)| (id.clone(), replay.compute_hash()))
            .collect();

        // Step 2: Roll up through tree
        let tree_hash = self.tree_structure.compute_hash(&criterion_hashes);

        // Step 3: Combine with policy identity
        let final_input = FinalHashInput {
            schema_version: &self.schema_version,
            policy_id: &self.policy_id,
            platform: &self.platform,
            criticality: &self.criticality,
            control_mappings: &self.control_mappings,
            tree_hash: &tree_hash,
        };

        compute_hash(&final_input)
    }

    /// Check if manifest has any criteria
    pub fn is_empty(&self) -> bool {
        self.criteria.is_empty()
    }
}

/// Input structure for final hash computation (borrows from manifest)
#[derive(Serialize)]
struct FinalHashInput<'a> {
    schema_version: &'a str,
    policy_id: &'a str,
    platform: &'a str,
    criticality: &'a str,
    control_mappings: &'a [String],
    tree_hash: &'a str,
}

// ============================================================================
// Tree Structure for Hash Rollup
// ============================================================================

/// Tree node for rolling up criterion hashes through CRI logical structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReplayTreeNode {
    /// Leaf: references a single criterion by ctn_node_id
    Leaf { ctn_node_id: String },

    /// Block: logical combination of children
    Block {
        logical_op: String, // "AND" or "OR"
        negate: bool,
        children: Vec<ReplayTreeNode>,
    },
}

impl ReplayTreeNode {
    /// Compute the hash for this tree node
    ///
    /// - Leaf: returns the pre-computed criterion hash
    /// - Block: hashes (logical_op | negate | sorted child hashes)
    pub fn compute_hash(&self, criterion_hashes: &BTreeMap<String, String>) -> String {
        match self {
            ReplayTreeNode::Leaf { ctn_node_id } => criterion_hashes
                .get(ctn_node_id)
                .cloned()
                .unwrap_or_else(|| "sha256:missing-criterion".to_string()),

            ReplayTreeNode::Block {
                logical_op,
                negate,
                children,
            } => {
                // Compute child hashes
                let mut child_hashes: Vec<String> = children
                    .iter()
                    .map(|child| child.compute_hash(criterion_hashes))
                    .collect();

                // Sort for determinism (AND/OR are commutative)
                child_hashes.sort();

                let block_input = BlockHashInput {
                    logical_op,
                    negate: *negate,
                    child_hashes: &child_hashes,
                };

                compute_hash(&block_input)
            }
        }
    }
}

/// Input structure for block hash computation
#[derive(Serialize)]
struct BlockHashInput<'a> {
    logical_op: &'a str,
    negate: bool,
    child_hashes: &'a [String],
}

// ============================================================================
// Criterion Replay — Per-CTN hashable data
// ============================================================================

/// Complete replay data for a single criterion (CTN execution)
///
/// Contains intent + contract + outcome layers. Hashed independently,
/// then rolled up through the tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CriterionReplay {
    /// Intent layer: what the policy author specified
    pub intent: ReplayIntent,

    /// Contract layer: how the system executed it
    pub contract: ReplayContract,

    /// Outcome layer: what happened (no actual values)
    pub outcome: ReplayOutcome,
}

impl CriterionReplay {
    /// Compute the hash for this criterion
    pub fn compute_hash(&self) -> String {
        compute_hash(self)
    }
}

// ============================================================================
// Intent Layer — From resolved AST
// ============================================================================

/// What the policy author specified
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayIntent {
    /// CTN type (e.g., "file_content", "sysctl_parameter", "tcp_listener")
    pub ctn_type: String,

    /// TEST specification
    pub test_spec: ReplayTestSpec,

    /// State definitions with expected values (sorted by state identifier)
    pub states: BTreeMap<String, ReplayStateIntent>,

    /// Object identifiers and their declared fields (sorted by identifier)
    pub objects: BTreeMap<String, ReplayObjectIntent>,
}

/// TEST specification from the criterion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayTestSpec {
    pub existence_check: String,
    pub item_check: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_operator: Option<String>,
}

/// State intent: fields with expected values and operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayStateIntent {
    /// Fields in this state (sorted by field name)
    pub fields: BTreeMap<String, ReplayFieldIntent>,

    /// Record checks in this state
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub record_checks: Vec<ReplayRecordCheckIntent>,
}

/// A single field's intent: what we expect and how we check it
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayFieldIntent {
    pub data_type: String,
    pub operation: String,
    pub expected_value: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_check: Option<String>,
}

/// Record check intent (for record datatype validation)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayRecordCheckIntent {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_type: Option<String>,
    pub content: ReplayRecordContentIntent,
}

/// Record content intent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReplayRecordContentIntent {
    /// Direct operation on entire record
    Direct {
        operation: String,
        expected_value: serde_json::Value,
    },
    /// Nested field validation (sorted by field path)
    Nested {
        fields: BTreeMap<String, ReplayRecordFieldIntent>,
    },
}

/// Individual record field intent
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayRecordFieldIntent {
    pub data_type: String,
    pub operation: String,
    pub expected_value: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_check: Option<String>,
}

/// Object intent: identifier and declared fields
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayObjectIntent {
    /// Object fields sorted by name → serialized value
    pub fields: BTreeMap<String, serde_json::Value>,
}

// ============================================================================
// Contract Layer — From CtnContract
// ============================================================================

/// How the system executed the verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayContract {
    /// CTN type
    pub ctn_type: String,

    /// Collector that gathered evidence
    pub collector_id: String,

    /// How evidence was collected (e.g., "metadata", "content", "command")
    pub collection_mode: String,

    /// How state fields map to collected data fields (sorted)
    pub validation_mappings: BTreeMap<String, String>,
}

// ============================================================================
// Outcome Layer — From execution results
// ============================================================================

/// What happened during execution (NO actual values)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayOutcome {
    /// Overall criterion status ("Pass", "Fail", "Error")
    pub status: String,

    /// Per-object validation outcomes (sorted by object_id)
    pub object_results: BTreeMap<String, ReplayObjectOutcome>,
}

/// Validation outcome for a single object
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayObjectOutcome {
    /// Whether this object's combined validation passed
    pub passed: bool,

    /// Per-field results (sorted by field_name)
    pub field_results: BTreeMap<String, ReplayFieldOutcome>,
}

/// Outcome for a single field validation (NO actual value)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayFieldOutcome {
    /// Operation that was applied
    pub operation: String,

    /// What was expected (from the STATE definition — deterministic)
    pub expected: serde_json::Value,

    /// Whether this field check passed
    pub passed: bool,
}

// ============================================================================
// Hash Computation — FIPS 140-3 compliant
// ============================================================================

/// Compute a deterministic SHA-256 hash of any serializable structure
///
/// Uses canonical JSON serialization (sorted keys via BTreeMap/serde)
/// followed by FIPS-compliant SHA-256.
/// Returns hash in format "sha256:<hex_digest>".
fn compute_hash<T: Serialize>(value: &T) -> String {
    match hash_content(value) {
        Ok(hex_hash) => format!("sha256:{}", hex_hash),
        Err(_) => "sha256:error-computing-hash".to_string(),
    }
}

/// Combine multiple replay hashes into a single hash (for multi-policy aggregation)
///
/// Sorts hashes before combining for determinism.
pub fn combine_hashes<'a, I>(hashes: I) -> String
where
    I: Iterator<Item = &'a String>,
{
    let mut sorted: Vec<&String> = hashes.collect();
    sorted.sort();

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
// Re-exports
// ============================================================================

pub use common::results::crypto::HashingError as ManifestHashError;

// ============================================================================
// Tests
// ============================================================================

#[allow(clippy::unwrap_used, clippy::expect_used)]
#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_field_intent(op: &str, expected: serde_json::Value) -> ReplayFieldIntent {
        ReplayFieldIntent {
            data_type: "boolean".to_string(),
            operation: op.to_string(),
            expected_value: expected,
            entity_check: None,
        }
    }

    fn make_test_criterion() -> CriterionReplay {
        let mut state_fields = BTreeMap::new();
        state_fields.insert(
            "listening".to_string(),
            make_test_field_intent("=", serde_json::json!(true)),
        );

        let mut states = BTreeMap::new();
        states.insert(
            "port_listening".to_string(),
            ReplayStateIntent {
                fields: state_fields,
                record_checks: Vec::new(),
            },
        );

        let mut obj_fields = BTreeMap::new();
        obj_fields.insert("port".to_string(), serde_json::json!(22));

        let mut objects = BTreeMap::new();
        objects.insert(
            "ssh_port".to_string(),
            ReplayObjectIntent { fields: obj_fields },
        );

        let mut field_results = BTreeMap::new();
        field_results.insert(
            "listening".to_string(),
            ReplayFieldOutcome {
                operation: "=".to_string(),
                expected: serde_json::json!(true),
                passed: true,
            },
        );

        let mut object_results = BTreeMap::new();
        object_results.insert(
            "ssh_port".to_string(),
            ReplayObjectOutcome {
                passed: true,
                field_results,
            },
        );

        let mut validation_mappings = BTreeMap::new();
        validation_mappings.insert("listening".to_string(), "listening".to_string());

        CriterionReplay {
            intent: ReplayIntent {
                ctn_type: "tcp_listener".to_string(),
                test_spec: ReplayTestSpec {
                    existence_check: "at_least_one".to_string(),
                    item_check: "all".to_string(),
                    state_operator: Some("AND".to_string()),
                },
                states,
                objects,
            },
            contract: ReplayContract {
                ctn_type: "tcp_listener".to_string(),
                collector_id: "tcp_listener_collector".to_string(),
                collection_mode: "metadata".to_string(),
                validation_mappings,
            },
            outcome: ReplayOutcome {
                status: "Pass".to_string(),
                object_results,
            },
        }
    }

    #[test]
    fn test_criterion_hash_deterministic() {
        let crit1 = make_test_criterion();
        let crit2 = make_test_criterion();
        assert_eq!(crit1.compute_hash(), crit2.compute_hash());
    }

    #[test]
    fn test_criterion_hash_changes_on_outcome_flip() {
        let crit1 = make_test_criterion();

        let mut crit2 = make_test_criterion();
        crit2.outcome.status = "Fail".to_string();
        crit2
            .outcome
            .object_results
            .get_mut("ssh_port")
            .unwrap()
            .passed = false;
        crit2
            .outcome
            .object_results
            .get_mut("ssh_port")
            .unwrap()
            .field_results
            .get_mut("listening")
            .unwrap()
            .passed = false;

        assert_ne!(crit1.compute_hash(), crit2.compute_hash());
    }

    #[test]
    fn test_criterion_hash_changes_on_intent_change() {
        let crit1 = make_test_criterion();

        let mut crit2 = make_test_criterion();
        // Change the expected value in the intent
        crit2
            .intent
            .states
            .get_mut("port_listening")
            .unwrap()
            .fields
            .get_mut("listening")
            .unwrap()
            .expected_value = serde_json::json!(false);

        assert_ne!(crit1.compute_hash(), crit2.compute_hash());
    }

    #[test]
    fn test_tree_leaf_returns_criterion_hash() {
        let crit = make_test_criterion();
        let hash = crit.compute_hash();

        let mut hashes = BTreeMap::new();
        hashes.insert("1".to_string(), hash.clone());

        let leaf = ReplayTreeNode::Leaf {
            ctn_node_id: "1".to_string(),
        };

        assert_eq!(leaf.compute_hash(&hashes), hash);
    }

    #[test]
    fn test_tree_block_deterministic_regardless_of_child_order() {
        let mut hashes = BTreeMap::new();
        hashes.insert("1".to_string(), "sha256:aaa".to_string());
        hashes.insert("2".to_string(), "sha256:bbb".to_string());

        let block1 = ReplayTreeNode::Block {
            logical_op: "AND".to_string(),
            negate: false,
            children: vec![
                ReplayTreeNode::Leaf {
                    ctn_node_id: "1".to_string(),
                },
                ReplayTreeNode::Leaf {
                    ctn_node_id: "2".to_string(),
                },
            ],
        };

        let block2 = ReplayTreeNode::Block {
            logical_op: "AND".to_string(),
            negate: false,
            children: vec![
                ReplayTreeNode::Leaf {
                    ctn_node_id: "2".to_string(),
                },
                ReplayTreeNode::Leaf {
                    ctn_node_id: "1".to_string(),
                },
            ],
        };

        assert_eq!(block1.compute_hash(&hashes), block2.compute_hash(&hashes));
    }

    #[test]
    fn test_tree_and_vs_or_different_hash() {
        let mut hashes = BTreeMap::new();
        hashes.insert("1".to_string(), "sha256:aaa".to_string());
        hashes.insert("2".to_string(), "sha256:bbb".to_string());

        let and_block = ReplayTreeNode::Block {
            logical_op: "AND".to_string(),
            negate: false,
            children: vec![
                ReplayTreeNode::Leaf {
                    ctn_node_id: "1".to_string(),
                },
                ReplayTreeNode::Leaf {
                    ctn_node_id: "2".to_string(),
                },
            ],
        };

        let or_block = ReplayTreeNode::Block {
            logical_op: "OR".to_string(),
            negate: false,
            children: vec![
                ReplayTreeNode::Leaf {
                    ctn_node_id: "1".to_string(),
                },
                ReplayTreeNode::Leaf {
                    ctn_node_id: "2".to_string(),
                },
            ],
        };

        assert_ne!(
            and_block.compute_hash(&hashes),
            or_block.compute_hash(&hashes)
        );
    }

    #[test]
    fn test_negation_changes_hash() {
        let mut hashes = BTreeMap::new();
        hashes.insert("1".to_string(), "sha256:aaa".to_string());

        let normal = ReplayTreeNode::Block {
            logical_op: "AND".to_string(),
            negate: false,
            children: vec![ReplayTreeNode::Leaf {
                ctn_node_id: "1".to_string(),
            }],
        };

        let negated = ReplayTreeNode::Block {
            logical_op: "AND".to_string(),
            negate: true,
            children: vec![ReplayTreeNode::Leaf {
                ctn_node_id: "1".to_string(),
            }],
        };

        assert_ne!(normal.compute_hash(&hashes), negated.compute_hash(&hashes));
    }

    #[test]
    fn test_full_replay_manifest_hash() {
        let mut manifest = ReplayManifest::new("ksi-svc-01", "linux", "high");
        manifest.control_mappings = vec!["NIST-800-53:CM-6".to_string()];

        manifest.add_criterion("1", make_test_criterion());
        manifest.set_tree_structure(ReplayTreeNode::Block {
            logical_op: "AND".to_string(),
            negate: false,
            children: vec![ReplayTreeNode::Leaf {
                ctn_node_id: "1".to_string(),
            }],
        });

        let hash = manifest.compute_replay_hash();
        assert!(hash.starts_with("sha256:"));
        assert_eq!(hash.len(), 7 + 64);

        // Idempotent
        assert_eq!(hash, manifest.compute_replay_hash());
    }

    #[test]
    fn test_different_policy_different_hash() {
        let make = |id: &str| {
            let mut m = ReplayManifest::new(id, "linux", "high");
            m.add_criterion("1", make_test_criterion());
            m.set_tree_structure(ReplayTreeNode::Leaf {
                ctn_node_id: "1".to_string(),
            });
            m
        };

        assert_ne!(
            make("policy-1").compute_replay_hash(),
            make("policy-2").compute_replay_hash()
        );
    }

    #[test]
    fn test_combine_hashes_deterministic() {
        let h1 = "sha256:abc123".to_string();
        let h2 = "sha256:def456".to_string();

        assert_eq!(
            combine_hashes([&h1, &h2].into_iter()),
            combine_hashes([&h2, &h1].into_iter())
        );
    }

    #[test]
    fn test_nested_tree_rollup() {
        let mut hashes = BTreeMap::new();
        hashes.insert("1".to_string(), "sha256:aaa".to_string());
        hashes.insert("2".to_string(), "sha256:bbb".to_string());
        hashes.insert("3".to_string(), "sha256:ccc".to_string());

        let nested = ReplayTreeNode::Block {
            logical_op: "AND".to_string(),
            negate: false,
            children: vec![
                ReplayTreeNode::Leaf {
                    ctn_node_id: "1".to_string(),
                },
                ReplayTreeNode::Block {
                    logical_op: "OR".to_string(),
                    negate: false,
                    children: vec![
                        ReplayTreeNode::Leaf {
                            ctn_node_id: "2".to_string(),
                        },
                        ReplayTreeNode::Leaf {
                            ctn_node_id: "3".to_string(),
                        },
                    ],
                },
            ],
        };

        let hash = nested.compute_hash(&hashes);
        assert!(hash.starts_with("sha256:"));

        // Idempotent
        assert_eq!(hash, nested.compute_hash(&hashes));

        // Different from flat AND
        let flat = ReplayTreeNode::Block {
            logical_op: "AND".to_string(),
            negate: false,
            children: vec![
                ReplayTreeNode::Leaf {
                    ctn_node_id: "1".to_string(),
                },
                ReplayTreeNode::Leaf {
                    ctn_node_id: "2".to_string(),
                },
                ReplayTreeNode::Leaf {
                    ctn_node_id: "3".to_string(),
                },
            ],
        };

        assert_ne!(hash, flat.compute_hash(&hashes));
    }
}
