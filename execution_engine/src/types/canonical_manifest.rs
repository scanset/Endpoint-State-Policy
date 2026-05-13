//! Canonical Manifest Types — Replay Hash Architecture
//!
//! The `ReplayManifest` captures the complete verification lifecycle of a
//! policy execution as a single hashable structure.
//!
//! ## Two Hash Schemes
//!
//! ### v1 (legacy, default for back-compat)
//!
//! Per-criterion hash bundles all OBJECTs together into a single
//! `CriterionReplay`. Tree rollup walks the CRI structure and produces one
//! `replay_hash` per policy execution. Used by every envelope produced
//! before engine v2.2.0; `compute_replay_hash()` continues to return this
//! shape so existing transparency-log entries stay verifiable.
//!
//! ### v2 (per-CTN-per-OBJECT primitive — engine v2.2.0+)
//!
//! Hierarchy:
//!
//! ```text
//! envelope_hash = SHA256(canonical(sorted_vec(policy_hashes)))
//! policy_hash   = SHA256(canonical({
//!                   policy_id, criticality, platform, schema_version,
//!                   control_mappings (sorted),
//!                   cri_tree_structure,
//!                   ctn_object_hashes (sorted vec),
//!                 }))
//! ctn_object_hash = SHA256(canonical(PerObjectReplay))   ← primitive
//! ```
//!
//! The leaf is per-CTN-per-OBJECT (`PerObjectReplay`). The OBJECT's
//! BTreeMap key (the object_id) is **stripped** — only the OBJECT's
//! fields enter the hash. This gives two desired properties:
//!
//! - **Asset-internal dedup**: many hosts running the same
//!   policy with the same OBJECT template + identical outcome → one hash.
//! - **Asset-list per-asset**: SET-expanded OBJECTs whose
//!   fields encode the asset reference (e.g. `resource_id`) naturally
//!   produce distinct hashes per asset.
//!
//! Per-asset attribution that doesn't collapse (which host the evidence
//! came from) lives in the envelope's `subject_assets`, never in the hash.
//!
//! ## Three-Layer Per-Criterion Design (used by both v1 and v2 leaves)
//!
//! 1. **Intent** — What the policy author specified: STATE fields,
//!    operations, expected values, TEST specification, object fields.
//!    From the resolved AST.
//! 2. **Contract** — How the system executed it: CTN type, collector ID,
//!    collection mode, validation field mappings.
//! 3. **Outcome** — What happened: pass/fail per validated field. Does
//!    NOT include actual collected values (those are volatile).
//!
//! ## Stability Guarantee
//!
//! Same policy + same compliance posture = same hash, always (within a
//! `replay_hash_version`). Volatile data (timestamps, counters, file
//! contents that didn't change compliance outcome) never enters the hash.
//! Cross-version comparison is meaningless and must be flagged explicitly
//! by callers (see `replay_hash_version` field).
//!
//! ## Crypto
//!
//! Uses `common::results::crypto` for FIPS 140-3 compliant SHA-256
//! (OpenSSL FIPS provider on Linux, BCrypt CNG on Windows).

use common::results::crypto::{hash_content, sha256_hash};
use common::results::SCHEMA_VERSION;
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

    /// Replay-hash schema version. `1` = legacy bundled-objects rollup
    /// (`compute_replay_hash` / `compute_replay_hash_v1`); `2` =
    /// per-CTN-per-OBJECT primitive with explicit envelope→policy→ctn
    /// hierarchy (`compute_replay_hash_v2`). Defaults to `1` for
    /// back-compat — manifests deserialized from older envelopes do not
    /// carry this field.
    #[serde(default = "default_replay_hash_version")]
    pub replay_hash_version: u8,

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

fn default_replay_hash_version() -> u8 {
    1
}

impl ReplayManifest {
    /// Create a new replay manifest
    pub fn new(
        policy_id: impl Into<String>,
        platform: impl Into<String>,
        criticality: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION.to_string(),
            replay_hash_version: default_replay_hash_version(),
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

    /// Set the replay-hash schema version. Pass `2` to opt into the v2
    /// per-CTN-per-OBJECT primitive when computing the rollup; the
    /// stored value also flows through serialization so downstream
    /// consumers can route comparisons correctly.
    pub fn with_replay_hash_version(mut self, version: u8) -> Self {
        self.replay_hash_version = version;
        self
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

    /// Compute the v1 replay_hash (legacy bundled-objects rollup).
    ///
    /// 1. Compute individual criterion hashes (one per CTN, all OBJECTs bundled)
    /// 2. Roll up through the CRI tree structure
    /// 3. Combine with policy identity for the final hash
    ///
    /// This is the hash carried on every envelope produced before engine
    /// v2.2.0. It stays callable forever so existing transparency-log
    /// entries remain verifiable. New code targeting per-asset drift
    /// detection should call `compute_replay_hash_v2` instead.
    pub fn compute_replay_hash(&self) -> String {
        self.compute_replay_hash_v1()
    }

    /// Explicit v1 alias — same output as `compute_replay_hash`.
    /// Prefer this name in new code so the version is unambiguous.
    pub fn compute_replay_hash_v1(&self) -> String {
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

    /// Compute the v2 policy_hash from per-CTN-per-OBJECT primitives.
    ///
    /// Hierarchy:
    /// ```text
    /// policy_hash = SHA256(canonical({
    ///   schema_version, policy_id, platform, criticality,
    ///   control_mappings (sorted),
    ///   cri_tree_structure,         ← preserves AND/OR/negate shape
    ///   ctn_object_hashes (sorted), ← all per-CTN-per-OBJECT leaves
    /// }))
    /// ```
    ///
    /// The leaves come from `CriterionReplay::all_per_object_hashes()`
    /// for every criterion in this manifest. The CRI tree structure is
    /// included as part of the policy intent so that re-shaping the
    /// AND/OR tree produces a new hash even if the leaves are unchanged.
    pub fn compute_replay_hash_v2(&self) -> String {
        // Collect every per-CTN-per-OBJECT hash from every criterion.
        // We flatten across criteria — the leaf hashes themselves
        // already encode their CTN type via PerObjectIntent.ctn_type, so
        // grouping by ctn_node_id is unnecessary. The CRI tree below
        // preserves the policy's logical shape.
        let mut leaf_hashes: Vec<String> = Vec::new();
        for criterion in self.criteria.values() {
            for hash in criterion.all_per_object_hashes().values() {
                leaf_hashes.push(hash.clone());
            }
        }
        leaf_hashes.sort();

        let policy_input = PolicyHashInputV2 {
            schema_version: &self.schema_version,
            policy_id: &self.policy_id,
            platform: &self.platform,
            criticality: &self.criticality,
            control_mappings: &self.control_mappings,
            cri_tree_structure: &self.tree_structure,
            ctn_object_hashes: &leaf_hashes,
        };

        compute_hash(&policy_input)
    }

    /// Dispatch to v1 or v2 based on `self.replay_hash_version`.
    /// Unknown versions fall back to v1 with the assumption that the
    /// caller's environment doesn't yet recognize the new shape.
    pub fn compute_replay_hash_versioned(&self) -> String {
        match self.replay_hash_version {
            2 => self.compute_replay_hash_v2(),
            _ => self.compute_replay_hash_v1(),
        }
    }

    /// Check if manifest has any criteria
    pub fn is_empty(&self) -> bool {
        self.criteria.is_empty()
    }
}

/// Input structure for v2 policy hash computation
#[derive(Serialize)]
struct PolicyHashInputV2<'a> {
    schema_version: &'a str,
    policy_id: &'a str,
    platform: &'a str,
    criticality: &'a str,
    control_mappings: &'a [String],
    cri_tree_structure: &'a ReplayTreeNode,
    ctn_object_hashes: &'a [String],
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
    /// Compute the v1 hash for this criterion (bundles all OBJECTs).
    ///
    /// Used by the v1 rollup. Two criteria with identical intent +
    /// contract + outcome (across ALL their OBJECTs) collapse to the
    /// same hash; criteria with even one OBJECT differing diverge.
    pub fn compute_hash(&self) -> String {
        compute_hash(self)
    }

    /// Compute the v2 per-CTN-per-OBJECT hash for a single OBJECT in
    /// this criterion. Returns `None` if `object_id` is not present in
    /// either the intent or outcome (this happens when the OBJECT was
    /// declared but never collected — e.g., dropped during SET filter
    /// application — and the caller should treat that as "no hash" not
    /// as a synthetic empty hash).
    ///
    /// The OBJECT's BTreeMap key (the object_id itself) is **stripped**
    /// from the hash input — only the OBJECT's *fields* enter the hash.
    /// This gives the dedup property: if two OBJECTs (in the same
    /// criterion or across criteria) have identical intent shape +
    /// identical OBJECT field values + identical outcome, they produce
    /// the same hash. The SET-expanded asset-internal case (same OBJECT template
    /// across many hosts) collapses; the SET-expanded asset-list case
    /// (per-asset OBJECT fields like `resource_id`) naturally produces
    /// distinct hashes per asset.
    pub fn compute_per_object_hash(&self, object_id: &str) -> Option<String> {
        let object_intent = self.intent.objects.get(object_id)?;
        let object_outcome = self.outcome.object_results.get(object_id)?;

        let per_object = PerObjectReplay {
            intent: PerObjectIntent {
                ctn_type: self.intent.ctn_type.clone(),
                test_spec: self.intent.test_spec.clone(),
                states: self.intent.states.clone(),
                object: object_intent.clone(),
            },
            contract: self.contract.clone(),
            outcome: PerObjectOutcome {
                passed: object_outcome.passed,
                field_results: object_outcome.field_results.clone(),
            },
        };

        Some(compute_hash(&per_object))
    }

    /// Compute the per-CTN-per-OBJECT hash for every OBJECT in this
    /// criterion. The map is keyed by object_id (so callers can
    /// attribute back to a specific OBJECT) and ordered deterministically.
    /// OBJECTs that produced no outcome (e.g., dropped by SET filtering)
    /// are silently omitted.
    pub fn all_per_object_hashes(&self) -> BTreeMap<String, String> {
        let mut out = BTreeMap::new();
        for object_id in self.outcome.object_results.keys() {
            if let Some(hash) = self.compute_per_object_hash(object_id) {
                out.insert(object_id.clone(), hash);
            }
        }
        out
    }
}

// ============================================================================
// v2 — CTN×OBJECT result entry (carried alongside scan results)
// ============================================================================

/// A single per-CTN-per-OBJECT hash result, surfaced from the engine
/// alongside the policy's outcome so callers (the prooflayer-2 ingest
/// path) can persist them to `evidence.ctn_results` for drift detection
/// AND for per-execution outcome aggregation (the ScanDetail "Policy
/// outcomes" headline tallies pass/fail/error from these rows rather
/// than rolling up to policy-level outcomes which mask "3 of 4 OBJECTs
/// passed under one policy").
///
/// Distinct from `PerObjectReplay` (which is the hash *input*): this is
/// the *output* — the computed hash with enough metadata to attribute it
/// back to a CTN type and OBJECT identifier in the source policy, plus
/// the per-OBJECT pass/fail verdict.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CtnObjectHash {
    /// CTN type (e.g., `az_storage_account`, `linux_sshd_config`).
    /// Matches `CriterionReplay.intent.ctn_type`.
    pub ctn_type: String,

    /// CTN node identifier within the policy's CRI tree. Lets callers
    /// disambiguate two CTN blocks of the same type within one policy.
    pub ctn_node_id: String,

    /// OBJECT identifier from the policy or SET expansion (e.g.
    /// `kv_tenant_a`, `storage_acct_aaa`). Used by callers to attribute
    /// per-asset drift back to a specific subject_asset.
    pub object_id: String,

    /// SHA-256 of the v2 per-CTN-per-OBJECT replay primitive.
    /// Format: `sha256:<hex>`.
    pub hash: String,

    /// Per-OBJECT verdict for this CTN execution. `true` means this
    /// specific OBJECT passed all of its STATE checks under this CTN;
    /// `false` means it failed (or errored — see note). Sourced from
    /// `ReplayObjectOutcome.passed`.
    ///
    /// Note: today the engine collapses pass/fail/error into a boolean
    /// at the OBJECT layer; collection failures bubble up as a
    /// policy-level error rather than per-OBJECT. When per-OBJECT error
    /// granularity lands, this field can widen to a tri-state enum
    /// (`PerObjectOutcome::{Pass, Fail, Error}`) without breaking the
    /// hash primitive — the hash already excludes outcome metadata.
    pub passed: bool,
}

impl ReplayManifest {
    /// Walk every criterion + every OBJECT and emit the v2 per-OBJECT
    /// hash list. One entry per (ctn_node_id, object_id) pair. Order is
    /// deterministic via the `BTreeMap` iteration on both the criteria
    /// map and the per-object outcome map.
    ///
    /// Used by callers that want to persist per-CTN-per-OBJECT drift
    /// signals AND per-execution outcome counts (the ScanDetail
    /// headline tallies pass/fail by walking these) without changing
    /// the wire envelope shape — they pull these out of the typed
    /// `ExecutionManifest` / `PolicyExecutionResult` before/after
    /// envelope serialization.
    pub fn all_ctn_object_hashes(&self) -> Vec<CtnObjectHash> {
        let mut out = Vec::new();
        for (ctn_node_id, criterion) in &self.criteria {
            for (object_id, hash) in criterion.all_per_object_hashes() {
                // Pull the per-OBJECT verdict from the outcome layer.
                // `all_per_object_hashes` already filtered to OBJECTs
                // that produced an outcome, so the lookup is total.
                let passed = criterion
                    .outcome
                    .object_results
                    .get(&object_id)
                    .map(|r| r.passed)
                    .unwrap_or(false);
                out.push(CtnObjectHash {
                    ctn_type: criterion.intent.ctn_type.clone(),
                    ctn_node_id: ctn_node_id.clone(),
                    object_id,
                    hash,
                    passed,
                });
            }
        }
        out
    }
}

// ============================================================================
// v2 Per-CTN-per-OBJECT Primitive
// ============================================================================

/// Hash input for a single OBJECT's execution under a single CTN.
///
/// This is the v2 leaf primitive. It deliberately **omits the
/// `object_id`** (the BTreeMap key in `CriterionReplay.intent.objects` /
/// `outcome.object_results`) so that two OBJECTs with identical intent +
/// outcome collapse to the same hash, regardless of how the policy
/// author named them. The OBJECT's *fields* (the query target) ARE
/// included via `PerObjectIntent.object.fields`, which means:
///
/// - **Shared template OBJECTs** (asset-internal, same `path` / `port` / etc.
///   across many hosts) → one hash, dedupes naturally
/// - **Asset-specific OBJECTs** (asset-list, distinct `resource_id` per
///   asset from SET expansion) → one hash per asset, no dedup
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerObjectReplay {
    pub intent: PerObjectIntent,
    pub contract: ReplayContract,
    pub outcome: PerObjectOutcome,
}

/// Intent for a single OBJECT — same shape as `ReplayIntent` but with
/// only the one OBJECT's intent (key stripped, fields preserved).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerObjectIntent {
    /// CTN type (e.g., "az_storage_account", "linux_sshd_config")
    pub ctn_type: String,

    /// TEST specification (existence check, item check, state operator)
    pub test_spec: ReplayTestSpec,

    /// STATE definitions with expected values (sorted by state identifier)
    pub states: BTreeMap<String, ReplayStateIntent>,

    /// The single OBJECT's declared fields (no identifier — that's the
    /// BTreeMap key in the parent CriterionReplay, deliberately omitted
    /// from the hash input to enable dedup).
    pub object: ReplayObjectIntent,
}

/// Outcome for a single OBJECT — overall pass/fail plus per-field
/// validation results (NO actual collected values).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerObjectOutcome {
    /// Whether this OBJECT's combined validation passed
    pub passed: bool,

    /// Per-field results (sorted by field_name)
    pub field_results: BTreeMap<String, ReplayFieldOutcome>,
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
/// Sorts hashes before combining for determinism. This is the v1
/// combiner — it uses byte-level concatenation with `|` separators,
/// which is fine for the legacy bundled-objects scheme but is NOT the
/// envelope rollup for v2. Use `compute_envelope_hash_v2` for v2.
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

/// Compute the v2 envelope hash from a set of v2 policy hashes.
///
/// `envelope_hash = SHA256(canonical(sorted_vec(policy_hashes)))`
///
/// Use this when an envelope carries multiple policy executions (the
/// inventory `scan_now` orchestrator path). For single-policy envelopes
/// the policy_hash and envelope_hash are computed independently — the
/// envelope_hash will still differ because it wraps the policy_hash in
/// a sorted single-element list.
///
/// Returns `"sha256:<hex>"`. Empty input is treated as a valid empty
/// envelope (a scan that produced zero policy results) and produces a
/// stable hash of the empty list.
pub fn compute_envelope_hash_v2<'a, I>(policy_hashes: I) -> String
where
    I: IntoIterator<Item = &'a String>,
{
    let mut sorted: Vec<String> = policy_hashes.into_iter().cloned().collect();
    sorted.sort();

    let envelope_input = EnvelopeHashInputV2 {
        policy_hashes: &sorted,
    };

    compute_hash(&envelope_input)
}

/// Input structure for v2 envelope hash computation
#[derive(Serialize)]
struct EnvelopeHashInputV2<'a> {
    policy_hashes: &'a [String],
}

// ============================================================================
// Re-exports
// ============================================================================

pub use common::results::crypto::HashingError as ManifestHashError;

// ============================================================================
// Tests
// ============================================================================

#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::useless_vec
)]
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

    // ========================================================================
    // v2 — Per-CTN-per-OBJECT primitive tests
    // ========================================================================

    /// Build a criterion with a single named OBJECT. The object_id is
    /// the BTreeMap key in `intent.objects` and `outcome.object_results`;
    /// `object_field_value` populates the OBJECT's `port` field so we
    /// can simulate asset-list (per-asset reference) vs asset-internal (shared
    /// template) shapes by varying it.
    fn make_criterion_with_object(
        object_id: &str,
        object_field_value: serde_json::Value,
        passed: bool,
    ) -> CriterionReplay {
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
        obj_fields.insert("port".to_string(), object_field_value);

        let mut objects = BTreeMap::new();
        objects.insert(
            object_id.to_string(),
            ReplayObjectIntent { fields: obj_fields },
        );

        let mut field_results = BTreeMap::new();
        field_results.insert(
            "listening".to_string(),
            ReplayFieldOutcome {
                operation: "=".to_string(),
                expected: serde_json::json!(true),
                passed,
            },
        );

        let mut object_results = BTreeMap::new();
        object_results.insert(
            object_id.to_string(),
            ReplayObjectOutcome {
                passed,
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
                status: if passed { "Pass" } else { "Fail" }.to_string(),
                object_results,
            },
        }
    }

    #[test]
    fn test_per_object_hash_returns_some_for_known_object() {
        let crit = make_criterion_with_object("obj_a", serde_json::json!(22), true);
        let hash = crit.compute_per_object_hash("obj_a");
        assert!(hash.is_some());
        assert!(hash.unwrap().starts_with("sha256:"));
    }

    #[test]
    fn test_per_object_hash_returns_none_for_unknown_object() {
        let crit = make_criterion_with_object("obj_a", serde_json::json!(22), true);
        assert!(crit.compute_per_object_hash("does_not_exist").is_none());
    }

    /// asset-internal dedup: two OBJECTs with different identifiers but
    /// identical OBJECT fields + identical outcome must hash to the
    /// same value. This is the "5 RHEL hosts running the same policy
    /// against /etc/sshd_config" property — they collapse to one hash.
    #[test]
    fn test_per_object_hash_dedup_when_fields_and_outcome_identical() {
        // Same OBJECT field value (port=22) → represents shared template
        let crit_a = make_criterion_with_object("rhel_host_1", serde_json::json!(22), true);
        let crit_b = make_criterion_with_object("rhel_host_2", serde_json::json!(22), true);

        let hash_a = crit_a.compute_per_object_hash("rhel_host_1").unwrap();
        let hash_b = crit_b.compute_per_object_hash("rhel_host_2").unwrap();

        assert_eq!(
            hash_a, hash_b,
            "asset-internal dedup violated: identical intent + outcome should produce identical hash"
        );
    }

    /// asset-list per-asset: two OBJECTs with different field values
    /// (different `resource_id` / `port` in our test stand-in) produce
    /// distinct hashes even when their outcomes match. This is correct
    /// — the asset reference is part of the assertion target.
    #[test]
    fn test_per_object_hash_distinct_when_fields_differ() {
        // Different OBJECT field values → represents per-asset reference
        let crit_a = make_criterion_with_object("storage_acct_a", serde_json::json!(22), true);
        let crit_b = make_criterion_with_object("storage_acct_b", serde_json::json!(443), true);

        let hash_a = crit_a.compute_per_object_hash("storage_acct_a").unwrap();
        let hash_b = crit_b.compute_per_object_hash("storage_acct_b").unwrap();

        assert_ne!(
            hash_a, hash_b,
            "asset-list per-asset violated: distinct OBJECT fields should produce distinct hashes"
        );
    }

    /// Outcome flip on a single OBJECT changes that OBJECT's hash.
    /// Distinct from asset-internal dedup test — here intent matches but outcome
    /// diverges.
    #[test]
    fn test_per_object_hash_changes_on_outcome_flip() {
        let crit_pass = make_criterion_with_object("obj_a", serde_json::json!(22), true);
        let crit_fail = make_criterion_with_object("obj_a", serde_json::json!(22), false);

        let hash_pass = crit_pass.compute_per_object_hash("obj_a").unwrap();
        let hash_fail = crit_fail.compute_per_object_hash("obj_a").unwrap();

        assert_ne!(hash_pass, hash_fail);
    }

    /// Intent change (expected_value flip in STATE) cascades through
    /// all per-object hashes — the assertion target itself differs.
    #[test]
    fn test_per_object_hash_changes_on_intent_change() {
        let crit_a = make_criterion_with_object("obj_a", serde_json::json!(22), true);
        let mut crit_b = make_criterion_with_object("obj_a", serde_json::json!(22), true);

        // Mutate the STATE expected_value
        crit_b
            .intent
            .states
            .get_mut("port_listening")
            .unwrap()
            .fields
            .get_mut("listening")
            .unwrap()
            .expected_value = serde_json::json!(false);

        let hash_a = crit_a.compute_per_object_hash("obj_a").unwrap();
        let hash_b = crit_b.compute_per_object_hash("obj_a").unwrap();

        assert_ne!(hash_a, hash_b);
    }

    /// `all_per_object_hashes` returns one hash per OBJECT, exercises
    /// the path that the v2 rollup walks. Simulates a SET-expanded CTN
    /// where the engine produces N independent OBJECT executions.
    #[test]
    fn test_all_per_object_hashes_one_per_object() {
        // Build a criterion with three OBJECTs (e.g., SET expansion)
        let mut crit = make_criterion_with_object("obj_aaa", serde_json::json!(22), true);

        // Add two more OBJECTs to both intent and outcome
        crit.intent.objects.insert(
            "obj_bbb".to_string(),
            ReplayObjectIntent {
                fields: {
                    let mut f = BTreeMap::new();
                    f.insert("port".to_string(), serde_json::json!(443));
                    f
                },
            },
        );
        crit.intent.objects.insert(
            "obj_ccc".to_string(),
            ReplayObjectIntent {
                fields: {
                    let mut f = BTreeMap::new();
                    f.insert("port".to_string(), serde_json::json!(8080));
                    f
                },
            },
        );

        let mut field_results_b = BTreeMap::new();
        field_results_b.insert(
            "listening".to_string(),
            ReplayFieldOutcome {
                operation: "=".to_string(),
                expected: serde_json::json!(true),
                passed: true,
            },
        );
        crit.outcome.object_results.insert(
            "obj_bbb".to_string(),
            ReplayObjectOutcome {
                passed: true,
                field_results: field_results_b,
            },
        );

        let mut field_results_c = BTreeMap::new();
        field_results_c.insert(
            "listening".to_string(),
            ReplayFieldOutcome {
                operation: "=".to_string(),
                expected: serde_json::json!(true),
                passed: false,
            },
        );
        crit.outcome.object_results.insert(
            "obj_ccc".to_string(),
            ReplayObjectOutcome {
                passed: false,
                field_results: field_results_c,
            },
        );

        let hashes = crit.all_per_object_hashes();
        assert_eq!(hashes.len(), 3);
        assert!(hashes.contains_key("obj_aaa"));
        assert!(hashes.contains_key("obj_bbb"));
        assert!(hashes.contains_key("obj_ccc"));

        // All three are distinct (different OBJECT fields + outcomes)
        let mut seen = std::collections::HashSet::new();
        for v in hashes.values() {
            assert!(seen.insert(v.clone()), "hash collision unexpected: {}", v);
        }
    }

    /// Outcome flip on one OBJECT only changes that OBJECT's hash —
    /// other OBJECTs in the same CTN are independent.
    #[test]
    fn test_per_object_hash_isolation() {
        let mut crit = make_criterion_with_object("obj_a", serde_json::json!(22), true);

        // Add a second OBJECT
        crit.intent.objects.insert(
            "obj_b".to_string(),
            ReplayObjectIntent {
                fields: {
                    let mut f = BTreeMap::new();
                    f.insert("port".to_string(), serde_json::json!(443));
                    f
                },
            },
        );
        let mut field_results_b = BTreeMap::new();
        field_results_b.insert(
            "listening".to_string(),
            ReplayFieldOutcome {
                operation: "=".to_string(),
                expected: serde_json::json!(true),
                passed: true,
            },
        );
        crit.outcome.object_results.insert(
            "obj_b".to_string(),
            ReplayObjectOutcome {
                passed: true,
                field_results: field_results_b,
            },
        );

        let baseline_a = crit.compute_per_object_hash("obj_a").unwrap();
        let baseline_b = crit.compute_per_object_hash("obj_b").unwrap();

        // Flip OBJECT B's outcome
        crit.outcome.object_results.get_mut("obj_b").unwrap().passed = false;
        crit.outcome
            .object_results
            .get_mut("obj_b")
            .unwrap()
            .field_results
            .get_mut("listening")
            .unwrap()
            .passed = false;

        let after_a = crit.compute_per_object_hash("obj_a").unwrap();
        let after_b = crit.compute_per_object_hash("obj_b").unwrap();

        assert_eq!(baseline_a, after_a, "OBJECT A hash must not change");
        assert_ne!(baseline_b, after_b, "OBJECT B hash must change");
    }

    // ========================================================================
    // v2 — ReplayManifest rollup tests
    // ========================================================================

    fn make_v2_manifest() -> ReplayManifest {
        let mut m = ReplayManifest::new("ksi-svc-01", "linux", "high")
            .with_replay_hash_version(2)
            .with_control_mappings(vec!["NIST-800-53:CM-6".to_string()]);
        m.add_criterion("1", make_test_criterion());
        m.set_tree_structure(ReplayTreeNode::Leaf {
            ctn_node_id: "1".to_string(),
        });
        m
    }

    #[test]
    fn test_replay_hash_v2_deterministic() {
        let m = make_v2_manifest();
        assert_eq!(m.compute_replay_hash_v2(), m.compute_replay_hash_v2());
    }

    #[test]
    fn test_replay_hash_v2_starts_with_sha256() {
        let m = make_v2_manifest();
        let h = m.compute_replay_hash_v2();
        assert!(h.starts_with("sha256:"));
        assert_eq!(h.len(), 7 + 64);
    }

    #[test]
    fn test_replay_hash_v1_and_v2_differ() {
        let m = make_v2_manifest();
        assert_ne!(m.compute_replay_hash_v1(), m.compute_replay_hash_v2());
    }

    #[test]
    fn test_versioned_dispatch_picks_v2_when_set() {
        let m = make_v2_manifest();
        assert_eq!(
            m.compute_replay_hash_versioned(),
            m.compute_replay_hash_v2()
        );
    }

    #[test]
    fn test_versioned_dispatch_picks_v1_by_default() {
        let mut m = ReplayManifest::new("ksi-svc-01", "linux", "high");
        m.add_criterion("1", make_test_criterion());
        m.set_tree_structure(ReplayTreeNode::Leaf {
            ctn_node_id: "1".to_string(),
        });
        // version was never set → defaults to 1
        assert_eq!(m.replay_hash_version, 1);
        assert_eq!(
            m.compute_replay_hash_versioned(),
            m.compute_replay_hash_v1()
        );
    }

    #[test]
    fn test_replay_hash_v2_changes_on_cri_tree_shape() {
        let mut m_leaf = make_v2_manifest();
        m_leaf.set_tree_structure(ReplayTreeNode::Leaf {
            ctn_node_id: "1".to_string(),
        });

        let mut m_block = make_v2_manifest();
        m_block.set_tree_structure(ReplayTreeNode::Block {
            logical_op: "AND".to_string(),
            negate: false,
            children: vec![ReplayTreeNode::Leaf {
                ctn_node_id: "1".to_string(),
            }],
        });

        // Same leaves but different CRI tree shape → different hash
        assert_ne!(
            m_leaf.compute_replay_hash_v2(),
            m_block.compute_replay_hash_v2()
        );
    }

    #[test]
    fn test_replay_hash_v2_changes_on_negation() {
        let mut m_normal = make_v2_manifest();
        m_normal.set_tree_structure(ReplayTreeNode::Block {
            logical_op: "AND".to_string(),
            negate: false,
            children: vec![ReplayTreeNode::Leaf {
                ctn_node_id: "1".to_string(),
            }],
        });

        let mut m_negated = make_v2_manifest();
        m_negated.set_tree_structure(ReplayTreeNode::Block {
            logical_op: "AND".to_string(),
            negate: true,
            children: vec![ReplayTreeNode::Leaf {
                ctn_node_id: "1".to_string(),
            }],
        });

        assert_ne!(
            m_normal.compute_replay_hash_v2(),
            m_negated.compute_replay_hash_v2()
        );
    }

    #[test]
    fn test_replay_hash_v2_changes_on_criticality() {
        let mut m_high = make_v2_manifest();
        m_high.criticality = "high".to_string();

        let mut m_low = make_v2_manifest();
        m_low.criticality = "low".to_string();

        assert_ne!(
            m_high.compute_replay_hash_v2(),
            m_low.compute_replay_hash_v2()
        );
    }

    #[test]
    fn test_replay_hash_v2_changes_on_policy_id() {
        let mut m_a = make_v2_manifest();
        m_a.policy_id = "policy-a".to_string();

        let mut m_b = make_v2_manifest();
        m_b.policy_id = "policy-b".to_string();

        assert_ne!(m_a.compute_replay_hash_v2(), m_b.compute_replay_hash_v2());
    }

    // ========================================================================
    // v2 — envelope hash tests
    // ========================================================================

    #[test]
    fn test_envelope_hash_v2_deterministic() {
        let h1 = "sha256:aaa".to_string();
        let h2 = "sha256:bbb".to_string();
        let hashes = vec![h1, h2];

        let e1 = compute_envelope_hash_v2(hashes.iter());
        let e2 = compute_envelope_hash_v2(hashes.iter());

        assert_eq!(e1, e2);
        assert!(e1.starts_with("sha256:"));
    }

    #[test]
    fn test_envelope_hash_v2_order_independent() {
        let h1 = "sha256:aaa".to_string();
        let h2 = "sha256:bbb".to_string();
        let h3 = "sha256:ccc".to_string();

        let asc = vec![h1.clone(), h2.clone(), h3.clone()];
        let desc = vec![h3.clone(), h2.clone(), h1.clone()];

        assert_eq!(
            compute_envelope_hash_v2(asc.iter()),
            compute_envelope_hash_v2(desc.iter())
        );
    }

    #[test]
    fn test_envelope_hash_v2_changes_on_member_change() {
        let baseline = vec!["sha256:aaa".to_string(), "sha256:bbb".to_string()];
        let mutated = vec!["sha256:aaa".to_string(), "sha256:ccc".to_string()];

        assert_ne!(
            compute_envelope_hash_v2(baseline.iter()),
            compute_envelope_hash_v2(mutated.iter())
        );
    }

    #[test]
    fn test_envelope_hash_v2_empty_is_stable() {
        let empty: Vec<String> = Vec::new();
        let h1 = compute_envelope_hash_v2(empty.iter());
        let h2 = compute_envelope_hash_v2(empty.iter());
        assert_eq!(h1, h2);
        assert!(h1.starts_with("sha256:"));
    }

    /// End-to-end: an envelope of two policy_hashes computed via v2
    /// produces a stable envelope_hash; reordering the underlying
    /// manifests doesn't change the result.
    #[test]
    fn test_envelope_hash_v2_end_to_end() {
        let mut m_a = make_v2_manifest();
        m_a.policy_id = "policy-a".to_string();
        let mut m_b = make_v2_manifest();
        m_b.policy_id = "policy-b".to_string();

        let policy_hashes = vec![m_a.compute_replay_hash_v2(), m_b.compute_replay_hash_v2()];
        let envelope = compute_envelope_hash_v2(policy_hashes.iter());

        let policy_hashes_reversed =
            vec![m_b.compute_replay_hash_v2(), m_a.compute_replay_hash_v2()];
        let envelope_reversed = compute_envelope_hash_v2(policy_hashes_reversed.iter());

        assert_eq!(envelope, envelope_reversed);
        assert!(envelope.starts_with("sha256:"));
    }

    /// Serialization round-trip: a manifest with `replay_hash_version=2`
    /// must serialize the field and deserialize it back. A manifest
    /// JSON without the field (legacy / pre-2.2.0 envelopes) must
    /// deserialize with version=1.
    #[test]
    fn test_replay_hash_version_serde_roundtrip() {
        let m_v2 = make_v2_manifest();
        let json = serde_json::to_string(&m_v2).unwrap();
        let parsed: ReplayManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.replay_hash_version, 2);
    }

    #[test]
    fn test_replay_hash_version_defaults_to_1_when_missing() {
        // Manifest JSON shaped like a pre-2.2.0 envelope (no
        // replay_hash_version field). Must deserialize with version=1.
        let json = r#"{
            "schema_version": "2.0.0",
            "policy_id": "legacy",
            "platform": "linux",
            "criticality": "medium",
            "control_mappings": [],
            "criteria": {},
            "tree_structure": { "Leaf": { "ctn_node_id": "0" } }
        }"#;
        let parsed: ReplayManifest = serde_json::from_str(json).unwrap();
        assert_eq!(parsed.replay_hash_version, 1);
    }
}
