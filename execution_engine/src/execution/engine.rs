//! # Execution Engine
//!
//! Orchestrates TEST-driven compliance validation with CTN contracts and tree traversal.
//!
//! ## Architecture
//!
//! The engine executes a single policy file and produces an `ExecutionManifest`.
//! The manifest contains all raw execution data needed to build any output format.
//!
//! ```text
//! ExecutionEngine::execute()
//!   └── ExecutionManifest (raw, complete, with replay hash)
//!         ├── Policy identity (id, platform, criticality, mappings)
//!         ├── Policy metadata (version, title, description, author, tags, extended)
//!         ├── Tree result (logical structure with pass/fail)
//!         ├── Collected data (with CollectionMethod)
//!         ├── Findings (validation failures)
//!         └── ReplayManifest → replay_hash (computed ONCE)
//!
//!         ↓ ResultBuilder (in common/results) transforms to ↓
//!
//!         └── AssessorPackage (uses manifest.replay_hash; carries
//!             observations + findings + reproducibility info)
//! ```
//!
//! ## Replay Hash
//!
//! The `replay_hash` replaces the previous `content_hash` + `evidence_hash`.
//! It captures the complete verification lifecycle in three layers:
//! - **Intent**: What STATEs were checked, with what operations and expected values
//! - **Contract**: How the system collected and validated (collector, field mappings)
//! - **Outcome**: Pass/fail per field (NO actual collected values)
//!
//! Criterion hashes are rolled up through the CRI tree structure (AND/OR/NOT)
//! to produce a single deterministic hash that is stable across runs when
//! compliance posture is unchanged.

use crate::execution::behavior::extract_behavior_hints;
use crate::execution::comparisons::{string, ComparisonExt};
use crate::execution::deferred_ops;
use crate::execution::filter_evaluation::FilterEvaluator;
use crate::strategies::CtnExecutionError;
use crate::strategies::{CollectedData, CtnContract, CtnExecutionResult, CtnStrategyRegistry};
use crate::types::canonical_manifest::{
    CriterionReplay, ReplayContract, ReplayFieldIntent, ReplayFieldOutcome, ReplayIntent,
    ReplayManifest, ReplayObjectIntent, ReplayObjectOutcome, ReplayOutcome,
    ReplayRecordCheckIntent, ReplayRecordContentIntent, ReplayRecordFieldIntent, ReplayStateIntent,
    ReplayTestSpec, ReplayTreeNode,
};
use crate::types::common::{LogicalOp, ResolvedValue};
use crate::types::execution_context::{
    ExecutableCriteriaTree, ExecutableCriterion, ExecutableObject, ExecutableObjectElement,
    ExecutableRecordContent, ExecutionContext,
};
use crate::types::manifest::{
    is_known_meta_field, CtnResult, ExecutionManifest, PolicyMetadataFields, TreeResult,
};
use common::ast::nodes::FilterAction;
use common::metadata::MetaDataBlock;
use common::results::builder::PolicyMetadata;
use common::results::common::PolicyOutcome;
use common::results::{
    ComplianceFinding, ControlMapping, CriteriaCounts, Criticality, FindingSeverity, Outcome,
};
use common::{log_debug, log_info};
use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Instant;

// ============================================================================
// Execution Engine
// ============================================================================

/// Main execution engine that orchestrates compliance scanning for a single policy
pub struct ExecutionEngine {
    context: ExecutionContext,
    registry: Arc<CtnStrategyRegistry>,
}

impl ExecutionEngine {
    /// Create with strategy registry
    pub fn new(context: ExecutionContext, registry: Arc<CtnStrategyRegistry>) -> Self {
        Self { context, registry }
    }

    /// Main execution entry point
    ///
    /// Executes the criteria tree for a single policy and produces an `ExecutionManifest`.
    /// The manifest contains all raw data needed to build any output format.
    ///
    /// ## Replay Hash
    ///
    /// This method computes `replay_hash` ONCE before returning.
    /// All output builders MUST use this hash directly - never recompute!
    pub fn execute(&mut self) -> Result<ExecutionManifest, ExecutionError> {
        let start_time = Instant::now();

        // Validate execution context before starting
        self.context
            .validate()
            .map_err(|e| ExecutionError::ExecutorFailed {
                ctn_type: "context_validation".to_string(),
                reason: e,
            })?;

        // Execute the criteria tree recursively
        let tree_result = self.execute_tree(&self.context.criteria_tree.clone())?;

        // Calculate statistics from tree
        let stats = tree_result.calculate_stats();

        // Convert tree results to findings
        let findings = self.tree_result_to_findings(&tree_result, vec![])?;

        // Collect all collected_data from tree into a single HashMap
        let collected_data = self.collect_all_data_from_tree(&tree_result);

        // Extract metadata block
        let meta_block =
            self.context
                .metadata
                .as_ref()
                .ok_or_else(|| ExecutionError::ExecutorFailed {
                    ctn_type: "metadata_extraction".to_string(),
                    reason: "Missing metadata in execution context".to_string(),
                })?;

        // Extract required fields from metadata
        let policy_id = meta_block
            .policy_id()
            .ok_or_else(|| ExecutionError::ExecutorFailed {
                ctn_type: "metadata_extraction".to_string(),
                reason: "Missing esp_id in metadata".to_string(),
            })?
            .to_string();

        let platform = meta_block
            .platform()
            .ok_or_else(|| ExecutionError::ExecutorFailed {
                ctn_type: "metadata_extraction".to_string(),
                reason: "Missing platform in metadata".to_string(),
            })?
            .to_string();

        let criticality_str =
            meta_block
                .criticality()
                .ok_or_else(|| ExecutionError::ExecutorFailed {
                    ctn_type: "metadata_extraction".to_string(),
                    reason: "Missing criticality in metadata".to_string(),
                })?;

        let criticality =
            Criticality::parse(criticality_str).ok_or_else(|| ExecutionError::ExecutorFailed {
                ctn_type: "metadata_extraction".to_string(),
                reason: format!("Invalid criticality: {}", criticality_str),
            })?;

        // Parse control mappings
        let control_mapping_str =
            meta_block
                .control_mapping()
                .ok_or_else(|| ExecutionError::ExecutorFailed {
                    ctn_type: "metadata_extraction".to_string(),
                    reason: "Missing control_mapping in metadata".to_string(),
                })?;

        let control_mappings =
            ControlMapping::parse_from_meta(control_mapping_str).map_err(|e| {
                ExecutionError::ExecutorFailed {
                    ctn_type: "metadata_extraction".to_string(),
                    reason: format!("Invalid control_mapping: {}", e),
                }
            })?;

        // ====================================================================
        // Extract policy metadata (optional + extended fields)
        // ====================================================================
        let policy_metadata = self.extract_policy_metadata(meta_block);

        // Build criteria counts
        let criteria_counts =
            CriteriaCounts::new(stats.total, stats.passed, stats.failed, stats.errors);

        let execution_duration = start_time.elapsed();

        // ====================================================================
        // BUILD REPLAY MANIFEST AND COMPUTE HASH (ONCE!)
        // ====================================================================
        // v2 per-CTN-per-OBJECT rollup. The v2 leaves are the same per-object
        // hashes persisted to `evidence.ctn_results`, which lets the on-demand
        // verifier recompute this policy hash from the stored leaves + a
        // reconstructed intent/tree without per-field outcome
        // (docs/verification/replay-hash-canonical-spec.md). The manifest stamps
        // `replay_hash_version = 2` so downstream consumers route correctly.
        let replay_manifest = self
            .build_replay_manifest(meta_block, &control_mappings, &tree_result)
            .with_replay_hash_version(2);

        // Compute replay hash ONCE - all output formats MUST use this directly
        let replay_hash = replay_manifest.compute_replay_hash_versioned();

        log_debug!(
            "Computed replay hash",
            "replay_hash" => &replay_hash
        );

        // Build the execution manifest
        Ok(ExecutionManifest {
            policy_id,
            platform,
            criticality,
            control_mappings,
            metadata: policy_metadata,
            tree_result,
            criteria_counts,
            tree_passed: stats.failed == 0 && stats.errors == 0,
            collected_data,
            findings,
            replay_manifest,
            replay_hash,
            executed_at: current_timestamp(),
            execution_duration_ms: execution_duration.as_millis() as u64,
        })
    }

    // ========================================================================
    // Metadata Extraction
    // ========================================================================

    /// Extract policy metadata from META block
    ///
    /// Separates known typed fields from extended metadata fields.
    /// Known fields: version, dsl_schema_version, title, description, author, tags
    /// Extended fields: everything else (control_objective, assessment_method, etc.)
    fn extract_policy_metadata(&self, meta_block: &MetaDataBlock) -> PolicyMetadataFields {
        let mut metadata = PolicyMetadataFields::new();

        // Extract known optional fields
        if let Some(version) = meta_block.version() {
            metadata = metadata.with_version(version);
        }

        if let Some(dsl_version) = meta_block.dsl_schema_version() {
            metadata = metadata.with_dsl_schema_version(dsl_version);
        }

        if let Some(title) = meta_block.title() {
            metadata = metadata.with_title(title);
        }

        if let Some(description) = meta_block.get("description") {
            metadata = metadata.with_description(description);
        }

        if let Some(author) = meta_block.get("author") {
            metadata = metadata.with_author(author);
        }

        // Parse tags (comma-separated)
        if let Some(tags_str) = meta_block.get("tags") {
            let tags: Vec<String> = tags_str
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if !tags.is_empty() {
                metadata = metadata.with_tags(tags);
            }
        }

        // Extract extended metadata (all fields not in the known list)
        for (key, value) in &meta_block.fields {
            if !is_known_meta_field(key) {
                metadata = metadata.with_extended_field(key.clone(), value.clone());
            }
        }

        metadata
    }

    // ========================================================================
    // Replay Manifest Building
    // ========================================================================

    /// Reconstruct the **intent + contract + tree-structure** layers of a
    /// policy's `ReplayManifest` from the RESOLVED context alone — no
    /// execution, no collectors. The outcome layer is a placeholder (empty
    /// per-criterion state results), because the on-demand verification path
    /// (`docs/verification/replay-hash-canonical-spec.md` §9) recomputes the
    /// policy hash from externally-supplied stored leaf hashes via
    /// `ReplayManifest::compute_replay_hash_v2_with_leaves`, and surfaces the
    /// per-object verdict from `evidence.ctn_results` separately.
    ///
    /// The synthesized `TreeResult` mirrors `execute_tree` exactly
    /// (`leaf`/`block`), so `build_replay_tree_structure` yields the identical
    /// `ReplayTreeNode` that a real run would — i.e. the v2 `cri_tree_structure`
    /// in the hash input is byte-identical.
    pub fn reconstruct_intent_manifest(&self) -> Result<ReplayManifest, ExecutionError> {
        let meta_block =
            self.context
                .metadata
                .as_ref()
                .ok_or_else(|| ExecutionError::ExecutorFailed {
                    ctn_type: "metadata_extraction".to_string(),
                    reason: "Missing metadata in execution context".to_string(),
                })?;

        let control_mapping_str =
            meta_block
                .control_mapping()
                .ok_or_else(|| ExecutionError::ExecutorFailed {
                    ctn_type: "metadata_extraction".to_string(),
                    reason: "Missing control_mapping in metadata".to_string(),
                })?;
        let control_mappings =
            ControlMapping::parse_from_meta(control_mapping_str).map_err(|e| {
                ExecutionError::ExecutorFailed {
                    ctn_type: "metadata_extraction".to_string(),
                    reason: format!("Invalid control_mapping: {}", e),
                }
            })?;

        let tree_result = Self::synth_tree_result(&self.context.criteria_tree);
        Ok(self.build_replay_manifest(meta_block, &control_mappings, &tree_result))
    }

    /// Synthesize a `TreeResult` mirroring the resolved criteria tree with
    /// empty execution results. Shape matches `execute_tree` so intent +
    /// contract + tree-structure reconstruct identically; the outcome layer is
    /// a placeholder and is not used by the leaf-based v2 recompute.
    fn synth_tree_result(tree: &ExecutableCriteriaTree) -> TreeResult {
        match tree {
            ExecutableCriteriaTree::Criterion(crit) => {
                let result = CtnExecutionResult::pass(
                    crit.criterion_type.clone(),
                    "intent-only reconstruction (no execution)".to_string(),
                );
                let ctn = CtnResult::new(crit.ctn_node_id, crit.criterion_type.clone(), result, 0);
                TreeResult::leaf(ctn)
            }
            ExecutableCriteriaTree::Block {
                logical_op,
                negate,
                children,
            } => {
                let child_results = children.iter().map(Self::synth_tree_result).collect();
                TreeResult::block(*logical_op, *negate, child_results)
            }
        }
    }

    /// Build the canonical replay manifest
    ///
    /// Walks the tree result to construct per-criterion replay entries
    /// (intent + contract + outcome) and the tree structure for hash rollup.
    /// Replaces the previous `build_content_manifest()` + `build_evidence_manifest()`.
    fn build_replay_manifest(
        &self,
        metadata: &MetaDataBlock,
        control_mappings: &[ControlMapping],
        tree_result: &TreeResult,
    ) -> ReplayManifest {
        let policy_id = metadata.policy_id().unwrap_or("unknown").to_string();
        let platform = metadata.platform().unwrap_or("unknown").to_string();
        let criticality = metadata.criticality().unwrap_or("medium").to_string();

        // Convert control mappings to sorted strings for determinism
        let mut mapping_strings: Vec<String> = control_mappings
            .iter()
            .map(|m| format!("{}:{}", m.framework, m.control_id))
            .collect();
        mapping_strings.sort();

        let mut manifest = ReplayManifest::new(&policy_id, &platform, &criticality)
            .with_control_mappings(mapping_strings);

        // Build per-criterion replay entries from the tree
        self.build_criterion_replays(tree_result, &mut manifest);

        // Build the tree structure for hash rollup
        let tree_structure = self.build_replay_tree_structure(tree_result);
        manifest.set_tree_structure(tree_structure);

        manifest
    }

    /// Recursively extract criterion replay entries from the tree result
    fn build_criterion_replays(&self, tree_result: &TreeResult, manifest: &mut ReplayManifest) {
        // Process CTN results at this level
        for ctn_result in &tree_result.ctn_results {
            let replay = self.build_single_criterion_replay(ctn_result);
            manifest.add_criterion(ctn_result.ctn_node_id.to_string(), replay);
        }

        // Recurse into children
        for child in &tree_result.child_results {
            self.build_criterion_replays(child, manifest);
        }
    }

    /// Build the three-layer replay entry for a single CTN result
    fn build_single_criterion_replay(&self, ctn_result: &CtnResult) -> CriterionReplay {
        let intent = self.build_replay_intent(ctn_result);
        let contract = self.build_replay_contract(ctn_result);
        let outcome = self.build_replay_outcome(ctn_result);

        CriterionReplay {
            intent,
            contract,
            outcome,
        }
    }

    /// Build the INTENT layer from the execution context's resolved AST
    ///
    /// Captures: ctn_type, TEST spec, STATE fields (name, data_type, operation,
    /// expected_value, entity_check), record checks, and OBJECT identifiers + fields.
    fn build_replay_intent(&self, ctn_result: &CtnResult) -> ReplayIntent {
        // Find the original criterion in the execution context by ctn_node_id
        let criterion = self
            .context
            .criteria_tree
            .get_all_criteria()
            .into_iter()
            .find(|c| c.ctn_node_id == ctn_result.ctn_node_id);

        match criterion {
            Some(crit) => {
                // TEST specification
                let test_spec = ReplayTestSpec {
                    existence_check: crit.test.existence_check.as_str().to_string(),
                    item_check: crit.test.item_check.as_str().to_string(),
                    state_operator: crit.test.state_operator.map(|op| op.as_str().to_string()),
                };

                // STATE definitions with expected values
                let mut states = BTreeMap::new();
                for state in &crit.states {
                    // Regular field intents
                    let mut fields = BTreeMap::new();
                    for field in &state.fields {
                        fields.insert(
                            field.name.clone(),
                            ReplayFieldIntent {
                                data_type: format!("{:?}", field.data_type),
                                operation: field.operation.as_str().to_string(),
                                expected_value: resolved_value_to_json(&field.value),
                                entity_check: field.entity_check.map(|ec| ec.as_str().to_string()),
                            },
                        );
                    }

                    // Record check intents
                    let record_checks: Vec<ReplayRecordCheckIntent> = state
                        .record_checks
                        .iter()
                        .map(|check| {
                            let content = match &check.content {
                                ExecutableRecordContent::Direct { operation, value } => {
                                    ReplayRecordContentIntent::Direct {
                                        operation: operation.as_str().to_string(),
                                        expected_value: resolved_value_to_json(value),
                                    }
                                }
                                ExecutableRecordContent::Nested { fields } => {
                                    let mut nested_fields = BTreeMap::new();
                                    for f in fields {
                                        nested_fields.insert(
                                            f.path.to_dot_notation(),
                                            ReplayRecordFieldIntent {
                                                data_type: format!("{:?}", f.data_type),
                                                operation: f.operation.as_str().to_string(),
                                                expected_value: resolved_value_to_json(&f.value),
                                                entity_check: f
                                                    .entity_check
                                                    .map(|ec| ec.as_str().to_string()),
                                            },
                                        );
                                    }
                                    ReplayRecordContentIntent::Nested {
                                        fields: nested_fields,
                                    }
                                }
                            };

                            ReplayRecordCheckIntent {
                                data_type: check.data_type.map(|dt| format!("{:?}", dt)),
                                content,
                            }
                        })
                        .collect();

                    states.insert(
                        state.identifier.clone(),
                        ReplayStateIntent {
                            fields,
                            record_checks,
                        },
                    );
                }

                // OBJECT identifiers and declared fields
                let mut objects = BTreeMap::new();
                for obj in &crit.objects {
                    let mut obj_fields = BTreeMap::new();
                    for elem in &obj.elements {
                        if let ExecutableObjectElement::Field { name, value, .. } = elem {
                            obj_fields.insert(name.clone(), resolved_value_to_json(value));
                        }
                    }
                    objects.insert(
                        obj.identifier.clone(),
                        ReplayObjectIntent { fields: obj_fields },
                    );
                }

                ReplayIntent {
                    ctn_type: crit.criterion_type.clone(),
                    test_spec,
                    states,
                    objects,
                }
            }
            None => {
                // Fallback if criterion not found in context (shouldn't happen)
                ReplayIntent {
                    ctn_type: ctn_result.criterion_type.clone(),
                    test_spec: ReplayTestSpec {
                        existence_check: "unknown".to_string(),
                        item_check: "unknown".to_string(),
                        state_operator: None,
                    },
                    states: BTreeMap::new(),
                    objects: BTreeMap::new(),
                }
            }
        }
    }

    /// Build the CONTRACT layer from the CtnContract registry
    ///
    /// Captures: ctn_type, collector_id, collection_mode, validation_mappings
    /// (state_field → data_field). These are execution provenance — they prove
    /// HOW the system interpreted the policy intent.
    fn build_replay_contract(&self, ctn_result: &CtnResult) -> ReplayContract {
        let contract_info = self
            .registry
            .get_ctn_contract(&ctn_result.criterion_type)
            .ok();

        // Source collector_id from the static registry, NOT from
        // `collected_data.values().next()`. The latter iterates a HashMap whose
        // order is nondeterministic across runs — for a CTN type served by
        // multiple collectors (or just to stabilize hashing in general), this
        // would cause `replay_hash` to flip between otherwise-identical runs,
        // violating the "same policy + same posture = same hash" guarantee.
        //
        // `get_collector_for_ctn` deterministically picks the registered
        // collector that declares support for this ctn_type. We fall back to
        // the runtime provenance path only if the registry lookup fails
        // (shouldn't happen in practice — we wouldn't have collected data at
        // all without a registered collector).
        let collector_id = self
            .registry
            .get_collector_for_ctn(&ctn_result.criterion_type)
            .map(|c| c.collector_id().to_string())
            .unwrap_or_else(|_| {
                ctn_result
                    .execution_result
                    .collected_data
                    .values()
                    .next()
                    .map(|d| d.metadata.collector_id.clone())
                    .unwrap_or_else(|| "unknown".to_string())
            });

        match contract_info {
            Some(contract) => {
                let collection_mode = format!("{:?}", contract.collection_strategy.collection_mode);

                // Build sorted validation mappings (BTreeMap)
                let validation_mappings: BTreeMap<String, String> = contract
                    .field_mappings
                    .validation_mappings
                    .state_to_data
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();

                ReplayContract {
                    ctn_type: ctn_result.criterion_type.clone(),
                    collector_id,
                    collection_mode,
                    validation_mappings,
                }
            }
            None => ReplayContract {
                ctn_type: ctn_result.criterion_type.clone(),
                collector_id,
                collection_mode: "unknown".to_string(),
                validation_mappings: BTreeMap::new(),
            },
        }
    }

    /// Build the OUTCOME layer from execution results
    ///
    /// Captures: overall status, per-object pass/fail, per-field pass/fail
    /// with operation and expected value. Does NOT include actual collected
    /// values — those are volatile and would destabilize the hash.
    fn build_replay_outcome(&self, ctn_result: &CtnResult) -> ReplayOutcome {
        let mut object_results = BTreeMap::new();

        for state_result in &ctn_result.execution_result.state_results {
            let mut field_results = BTreeMap::new();

            for field_result in &state_result.state_results {
                field_results.insert(
                    field_result.field_name.clone(),
                    ReplayFieldOutcome {
                        operation: field_result.operation.as_str().to_string(),
                        expected: resolved_value_to_json(&field_result.expected_value),
                        passed: field_result.passed,
                    },
                );
            }

            object_results.insert(
                state_result.object_id.clone(),
                ReplayObjectOutcome {
                    passed: state_result.combined_result,
                    field_results,
                },
            );
        }

        ReplayOutcome {
            status: format!("{:?}", ctn_result.status),
            object_results,
        }
    }

    /// Build the tree structure for hash rollup (mirrors CRI AND/OR/NOT)
    ///
    /// Produces a `ReplayTreeNode` that mirrors the CRI tree structure.
    /// Leaf nodes reference criterion hashes by ctn_node_id.
    /// Block nodes encode the logical operator and negation.
    fn build_replay_tree_structure(&self, tree_result: &TreeResult) -> ReplayTreeNode {
        // Leaf: single CTN result, no children
        if tree_result.child_results.is_empty() {
            if let [single] = tree_result.ctn_results.as_slice() {
                return ReplayTreeNode::Leaf {
                    ctn_node_id: single.ctn_node_id.to_string(),
                };
            }
        }

        // Collect all children (both leaf CTN results and nested blocks)
        let mut children: Vec<ReplayTreeNode> = Vec::new();

        for ctn_result in &tree_result.ctn_results {
            children.push(ReplayTreeNode::Leaf {
                ctn_node_id: ctn_result.ctn_node_id.to_string(),
            });
        }

        for child in &tree_result.child_results {
            children.push(self.build_replay_tree_structure(child));
        }

        let logical_op = tree_result
            .logical_op
            .map(|op| match op {
                LogicalOp::And => "AND",
                LogicalOp::Or => "OR",
            })
            .unwrap_or("AND")
            .to_string();

        ReplayTreeNode::Block {
            logical_op,
            negate: tree_result.negated,
            children,
        }
    }

    // ========================================================================
    // Data Collection
    // ========================================================================

    /// Collect all CollectedData from tree into a single HashMap
    ///
    /// Keys are formatted as "{ctn_type}_{object_id}" for uniqueness.
    fn collect_all_data_from_tree(
        &self,
        tree_result: &TreeResult,
    ) -> HashMap<String, CollectedData> {
        let mut all_data = HashMap::new();
        self.collect_data_recursive(tree_result, &mut all_data);
        all_data
    }

    /// Recursively collect data from tree
    fn collect_data_recursive(
        &self,
        tree_result: &TreeResult,
        all_data: &mut HashMap<String, CollectedData>,
    ) {
        // Collect from CTN results at this level
        for ctn_result in &tree_result.ctn_results {
            for (object_id, collected_data) in &ctn_result.execution_result.collected_data {
                let key = format!("{}_{}", ctn_result.criterion_type, object_id);
                all_data.insert(key, collected_data.clone());
            }
        }

        // Recurse into children
        for child in &tree_result.child_results {
            self.collect_data_recursive(child, all_data);
        }
    }

    // ========================================================================
    // Tree Execution
    // ========================================================================

    /// Recursive tree traversal with logical operator application
    fn execute_tree(
        &mut self,
        tree: &ExecutableCriteriaTree,
    ) -> Result<TreeResult, ExecutionError> {
        match tree {
            ExecutableCriteriaTree::Criterion(criterion) => {
                let start = Instant::now();

                // Clone the criterion so we can mutate it
                let mut mutable_criterion = criterion.clone();

                // Execute with mutable reference; on error, record a Fail rather than aborting
                let result = match self.execute_single_criterion(&mut mutable_criterion) {
                    Ok(r) => r,
                    Err(e) => CtnExecutionResult::fail(
                        criterion.criterion_type.clone(),
                        format!("Policy execution error: {}", e),
                    ),
                };

                let ctn_result = CtnResult::new(
                    criterion.ctn_node_id,
                    criterion.criterion_type.clone(),
                    result,
                    start.elapsed().as_millis() as u64,
                );

                Ok(TreeResult::leaf(ctn_result))
            }
            ExecutableCriteriaTree::Block {
                logical_op,
                negate,
                children,
            } => {
                let mut child_results = Vec::new();
                for child in children {
                    let child_result = self.execute_tree(child)?;
                    child_results.push(child_result);
                }

                Ok(TreeResult::block(*logical_op, *negate, child_results))
            }
        }
    }

    /// Execute a single criterion with timeout protection
    fn execute_single_criterion(
        &mut self,
        criterion: &mut ExecutableCriterion,
    ) -> Result<CtnExecutionResult, ExecutionError> {
        use std::time::Instant;

        // Ceiling on the wall-clock time a single CTN can spend in setup +
        // collection. Has to be high enough for agentless / cloud-control-
        // plane channels (`az vm run-command invoke`, `aws ssm send-command`,
        // bastion tunnel setup) where each per-OBJECT round-trip is 15–30s
        // dominated by ARM/AWS API overhead. A CTN with N OBJECTs accumulates
        // N round-trips, so a baseline policy with ~20 file_metadata
        // OBJECTs against an Azure VM can legitimately need 5+ minutes.
        // Agent-mode scans finish in subseconds and never touch this
        // ceiling; raising it doesn't slow them down. Override via env var
        // for operators tuning either direction.
        const CTN_TIMEOUT_DEFAULT_SECS: u64 = 600;
        let ctn_timeout_secs: u64 = std::env::var("ESP_CTN_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(CTN_TIMEOUT_DEFAULT_SECS);
        let start = Instant::now();

        log_debug!("Starting CTN execution",
            "ctn_type" => &criterion.criterion_type,
            "ctn_node_id" => criterion.ctn_node_id
        );

        // Get contract for this CTN type
        let contract = self
            .registry
            .get_ctn_contract(&criterion.criterion_type)
            .map_err(|e| ExecutionError::NoContractRegistered {
                ctn_type: criterion.criterion_type.clone(),
                reason: e.to_string(),
            })?;

        let contract_clone = Arc::clone(&contract);

        // Get collector for this CTN type
        let collector = self
            .registry
            .get_collector_for_ctn(&criterion.criterion_type)
            .map_err(|e| ExecutionError::NoCollectorRegistered {
                ctn_type: criterion.criterion_type.clone(),
                reason: e.to_string(),
            })?;

        // Check timeout after setup
        if start.elapsed().as_secs() > ctn_timeout_secs {
            return Err(ExecutionError::ExecutorFailed {
                ctn_type: criterion.criterion_type.clone(),
                reason: format!(
                    "CTN execution exceeded timeout of {}s during setup",
                    ctn_timeout_secs
                ),
            });
        }

        // Attempt batch collection if supported
        let mut collected_data =
            if collector.supports_batch_collection() && !criterion.objects.is_empty() {
                log_debug!("Attempting batch collection",
                    "ctn_type" => &criterion.criterion_type,
                    "object_count" => criterion.objects.len()
                );

                let object_refs: Vec<&ExecutableObject> = criterion.objects.iter().collect();
                match collector.collect_batch(object_refs, &contract) {
                    Ok(batch_data) => {
                        log_debug!("Batch collection successful",
                            "ctn_type" => &criterion.criterion_type,
                            "objects_collected" => batch_data.len()
                        );
                        batch_data
                    }
                    Err(e) => {
                        log_debug!("Batch collection failed, falling back to individual",
                            "ctn_type" => &criterion.criterion_type,
                            "error" => e
                        );
                        HashMap::new()
                    }
                }
            } else {
                HashMap::new()
            };

        // Individual collection for any objects not batch-collected
        for object in &criterion.objects {
            if !collected_data.contains_key(&object.identifier) {
                let data = self.collect_data_for_object(object, &contract)?;
                collected_data.insert(object.identifier.clone(), data);
            }
        }

        log_debug!("Data collection complete",
            "ctn_type" => &criterion.criterion_type,
            "objects_collected" => collected_data.len()
        );

        // Apply SET-level filters FIRST
        collected_data = self.apply_set_filters(collected_data, criterion)?;

        log_debug!("After SET filters",
            "ctn_type" => &criterion.criterion_type,
            "objects_remaining" => collected_data.len(),
            "expected_count" => criterion.expected_object_count()
        );

        // Apply object-level filters
        collected_data = self.apply_object_filters(collected_data, criterion, &contract)?;

        log_debug!("After object filters",
            "ctn_type" => &criterion.criterion_type,
            "objects_remaining" => collected_data.len(),
            "expected_count" => criterion.expected_object_count()
        );

        // Check timeout after collection and filtering
        if start.elapsed().as_secs() > ctn_timeout_secs {
            return Err(ExecutionError::ExecutorFailed {
                ctn_type: criterion.criterion_type.clone(),
                reason: format!(
                    "CTN execution exceeded timeout of {}s during collection",
                    ctn_timeout_secs
                ),
            });
        }

        // Get executor for this CTN type
        let executor = self
            .registry
            .get_executor_for_ctn(&criterion.criterion_type)
            .map_err(|e| ExecutionError::NoExecutorRegistered {
                ctn_type: criterion.criterion_type.clone(),
                reason: e.to_string(),
            })?;

        // Execute validation - pass ownership of collected_data
        // The executor will move it into CtnExecutionResult.collected_data
        let result = executor
            .execute_with_contract(criterion, collected_data, &contract_clone)
            .map_err(|e| ExecutionError::ExecutorFailed {
                ctn_type: criterion.criterion_type.clone(),
                reason: format!("Executor failed: {}", e),
            })?;

        log_debug!("CTN execution completed",
            "ctn_type" => &criterion.criterion_type,
            "status" => format!("{:?}", result.status),
            "execution_time_ms" => start.elapsed().as_millis()
        );

        Ok(result)
    }

    // ========================================================================
    // Findings Generation
    // ========================================================================

    /// Convert CTN execution result to compliance finding
    fn ctn_result_to_finding(
        &self,
        ctn_result: &CtnExecutionResult,
        field_path: Vec<String>,
    ) -> Result<ComplianceFinding, ExecutionError> {
        // Extract failed field information from state results
        let mut expected_values = serde_json::Map::new();
        let mut actual_values = serde_json::Map::new();

        for state_result in &ctn_result.state_results {
            for field_result in &state_result.state_results {
                if !field_result.passed {
                    // Add to expected/actual maps
                    let expected_str = format!("{:?}", field_result.expected_value);
                    let actual_str = format!("{:?}", field_result.actual_value);

                    expected_values.insert(
                        field_result.field_name.clone(),
                        serde_json::Value::String(expected_str),
                    );
                    actual_values.insert(
                        field_result.field_name.clone(),
                        serde_json::Value::String(actual_str),
                    );
                }
            }
        }

        // Fallback: existence-level failures (object not found) and executors
        // that decide their verdict outside the per-field comparison loop leave
        // both maps empty, which renders as `{}` / `{}` in the operator's
        // evidence — a content-free finding. Carry the CTN-level outcome so a
        // finding always says *why* it failed. (Findings are not part of the
        // replay manifest, so this does not affect any replay_hash.)
        if expected_values.is_empty() && actual_values.is_empty() {
            expected_values.insert(
                "result".to_string(),
                serde_json::Value::String("pass".to_string()),
            );
            actual_values.insert(
                "result".to_string(),
                serde_json::Value::String(format!(
                    "{:?}: {}",
                    ctn_result.status, ctn_result.message
                )),
            );
        }

        // Determine severity from CTN status
        let severity = match ctn_result.status {
            Outcome::Fail => FindingSeverity::High,
            Outcome::Error => FindingSeverity::Critical,
            _ => FindingSeverity::Medium,
        };

        // Build title and description
        let title = format!("{} validation failed", ctn_result.ctn_type);
        let description = ctn_result.message.clone();

        // Convert to JSON values
        let expected_json =
            serde_json::to_value(&expected_values).map_err(|e| ExecutionError::ExecutorFailed {
                ctn_type: ctn_result.ctn_type.clone(),
                reason: format!("Failed to serialize expected values: {}", e),
            })?;
        let actual_json =
            serde_json::to_value(&actual_values).map_err(|e| ExecutionError::ExecutorFailed {
                ctn_type: ctn_result.ctn_type.clone(),
                reason: format!("Failed to serialize actual values: {}", e),
            })?;

        // Truncate large values to prevent JSON bloat
        let expected_truncated = Self::truncate_large_values(&expected_json);
        let actual_truncated = Self::truncate_large_values(&actual_json);

        Ok(ComplianceFinding::auto_id(
            severity,
            title,
            description,
            expected_truncated,
            actual_truncated,
        )
        .with_field_path(field_path.join(" > ")))
    }

    /// Truncate large values in findings to prevent JSON bloat
    fn truncate_large_values(value: &serde_json::Value) -> serde_json::Value {
        const MAX_FIELD_LENGTH: usize = 200;

        match value {
            serde_json::Value::String(s) if s.len() > MAX_FIELD_LENGTH => {
                serde_json::Value::String(format!(
                    "{}... [truncated: {} total chars]",
                    &s[..MAX_FIELD_LENGTH],
                    s.len()
                ))
            }
            serde_json::Value::Object(map) => {
                let truncated: serde_json::Map<String, serde_json::Value> = map
                    .iter()
                    .map(|(k, v)| (k.clone(), Self::truncate_large_values(v)))
                    .collect();
                serde_json::Value::Object(truncated)
            }
            serde_json::Value::Array(arr) => {
                serde_json::Value::Array(arr.iter().map(Self::truncate_large_values).collect())
            }
            other => other.clone(),
        }
    }

    /// Collect data for a single object
    fn collect_data_for_object(
        &self,
        object: &ExecutableObject,
        contract: &Arc<CtnContract>,
    ) -> Result<CollectedData, ExecutionError> {
        let collector = self
            .registry
            .get_collector_for_ctn(&contract.ctn_type)
            .map_err(|e| ExecutionError::NoCollectorRegistered {
                ctn_type: contract.ctn_type.clone(),
                reason: e.to_string(),
            })?;

        // Extract behavior hints from the object
        let hints = extract_behavior_hints(object);

        // Call the new method with hints
        collector
            .collect_for_ctn_with_hints(object, contract, &hints)
            .map_err(|e| ExecutionError::DataCollectionFailed {
                object_id: object.identifier.clone(),
                reason: e.to_string(),
            })
    }

    // ========================================================================
    // Filter Evaluation
    // ========================================================================

    /// Apply object filters to collected data
    fn apply_object_filters(
        &self,
        mut collected: HashMap<String, CollectedData>,
        criterion: &mut ExecutableCriterion,
        contract: &CtnContract,
    ) -> Result<HashMap<String, CollectedData>, ExecutionError> {
        let mut to_remove = Vec::new();

        for (object_id, data) in &collected {
            let object = criterion
                .objects
                .iter()
                .find(|o| o.identifier == *object_id)
                .ok_or_else(|| ExecutionError::ObjectNotFoundInCriterion {
                    object_id: object_id.clone(),
                })?;

            let filters = object.get_filters();

            if !filters.is_empty() {
                log_debug!(
                    "Object has filters",
                    "object_id" => object_id,
                    "filter_count" => filters.len()
                );
            }

            for filter in filters {
                let passes = self.evaluate_filter_against_global_states(filter, data, contract)?;

                let should_remove = match filter.action {
                    FilterAction::Include => !passes,
                    FilterAction::Exclude => passes,
                };

                if should_remove {
                    to_remove.push(object_id.clone());
                    break;
                }
            }
        }

        // Remove filtered-out objects
        for object_id in &to_remove {
            collected.remove(object_id);
        }

        // Update active objects if any were filtered
        if !to_remove.is_empty() {
            let active_ids: HashSet<String> = collected.keys().cloned().collect();

            // Merge with existing active_object_ids if SET filters already applied
            match &criterion.active_object_ids {
                Some(existing) => {
                    // Intersection: only keep objects that passed both filters
                    let merged: HashSet<String> =
                        active_ids.intersection(existing).cloned().collect();
                    criterion.set_active_objects(merged);
                }
                None => {
                    criterion.set_active_objects(active_ids);
                }
            }

            log_debug!(
                "Updated active objects after object filters",
                "active_count" => criterion.expected_object_count()
            );
        }

        Ok(collected)
    }

    /// Evaluate filter against GLOBAL states (not CTN-local states)
    fn evaluate_filter_against_global_states(
        &self,
        filter: &crate::types::filter::ResolvedFilterSpec,
        data: &CollectedData,
        contract: &CtnContract,
    ) -> Result<bool, ExecutionError> {
        // AND logic: ALL state refs must match for filter to pass
        for state_ref in &filter.state_refs {
            // Look up in GLOBAL states, not local states
            let state = self.context.global_states.get(state_ref).ok_or_else(|| {
                ExecutionError::StateNotFound {
                    state_id: state_ref.clone(),
                }
            })?;

            // Convert ResolvedState to ExecutableState fields for evaluation
            for field in &state.resolved_fields {
                // Map state field name to data field name using contract
                let data_field_name = contract
                    .field_mappings
                    .validation_mappings
                    .state_to_data
                    .get(&field.name)
                    .unwrap_or(&field.name);

                // Get collected value for this field
                if let Some(collected_value) = data.get_field(data_field_name) {
                    let matches =
                        self.compare_for_filter(collected_value, &field.value, field.operation)?;

                    // Short-circuit: If any field fails, entire filter fails
                    if !matches {
                        return Ok(false);
                    }
                } else {
                    // Field not collected - treat as filter failure
                    return Ok(false);
                }
            }
        }

        // All states matched
        Ok(true)
    }

    /// Compare values for filter evaluation with full operation support
    fn compare_for_filter(
        &self,
        actual: &ResolvedValue,
        expected: &ResolvedValue,
        operation: crate::types::common::Operation,
    ) -> Result<bool, ExecutionError> {
        use crate::types::common::Operation;

        let result = match (actual, expected, operation) {
            // String operations
            (ResolvedValue::String(a), ResolvedValue::String(e), op) => {
                string::compare(a, e, op).map_err(|e| ExecutionError::ExecutorFailed {
                    ctn_type: "filter_evaluation".to_string(),
                    reason: format!("String comparison failed: {}", e),
                })?
            }

            // Integer operations
            (ResolvedValue::Integer(a), ResolvedValue::Integer(e), Operation::Equals) => a == e,
            (ResolvedValue::Integer(a), ResolvedValue::Integer(e), Operation::NotEqual) => a != e,
            (ResolvedValue::Integer(a), ResolvedValue::Integer(e), Operation::GreaterThan) => a > e,
            (ResolvedValue::Integer(a), ResolvedValue::Integer(e), Operation::LessThan) => a < e,
            (
                ResolvedValue::Integer(a),
                ResolvedValue::Integer(e),
                Operation::GreaterThanOrEqual,
            ) => a >= e,
            (ResolvedValue::Integer(a), ResolvedValue::Integer(e), Operation::LessThanOrEqual) => {
                a <= e
            }

            // Float operations
            (ResolvedValue::Float(a), ResolvedValue::Float(e), Operation::Equals) => a == e,
            (ResolvedValue::Float(a), ResolvedValue::Float(e), Operation::NotEqual) => a != e,
            (ResolvedValue::Float(a), ResolvedValue::Float(e), Operation::GreaterThan) => a > e,
            (ResolvedValue::Float(a), ResolvedValue::Float(e), Operation::LessThan) => a < e,
            (ResolvedValue::Float(a), ResolvedValue::Float(e), Operation::GreaterThanOrEqual) => {
                a >= e
            }
            (ResolvedValue::Float(a), ResolvedValue::Float(e), Operation::LessThanOrEqual) => {
                a <= e
            }

            // Boolean operations
            (ResolvedValue::Boolean(a), ResolvedValue::Boolean(e), Operation::Equals) => a == e,
            (ResolvedValue::Boolean(a), ResolvedValue::Boolean(e), Operation::NotEqual) => a != e,

            // Version comparisons
            (ResolvedValue::Version(_), ResolvedValue::Version(_), _) => actual
                .compare_with(expected, operation)
                .map_err(|e| ExecutionError::ExecutorFailed {
                    ctn_type: "filter_evaluation".to_string(),
                    reason: format!("Version comparison failed: {}", e),
                })?,

            // Collection operations
            (ResolvedValue::Collection(a), ResolvedValue::Collection(e), op) => {
                use crate::execution::comparisons::collection;
                collection::compare(a, e, op).map_err(|e| ExecutionError::ExecutorFailed {
                    ctn_type: "filter_evaluation".to_string(),
                    reason: format!("Collection comparison failed: {}", e),
                })?
            }

            // EVR string comparisons (RPM-style versions)
            (ResolvedValue::EvrString(a), ResolvedValue::EvrString(e), op) => {
                use crate::execution::comparisons::evr;
                evr::compare(a, e, op).map_err(|e| ExecutionError::ExecutorFailed {
                    ctn_type: "filter_evaluation".to_string(),
                    reason: format!("EVR comparison failed: {}", e),
                })?
            }

            // Binary operations
            (ResolvedValue::Binary(a), ResolvedValue::Binary(e), op) => {
                use crate::execution::comparisons::binary;
                binary::compare(a, e, op).map_err(|e| ExecutionError::ExecutorFailed {
                    ctn_type: "filter_evaluation".to_string(),
                    reason: format!("Binary comparison failed: {}", e),
                })?
            }

            // Type mismatch or unsupported operation
            _ => {
                return Err(ExecutionError::ExecutorFailed {
                    ctn_type: "filter_evaluation".to_string(),
                    reason: format!(
                        "Type mismatch in filter: actual={:?}, expected={:?}, operation={:?}",
                        actual, expected, operation
                    ),
                })
            }
        };

        Ok(result)
    }

    /// Execute deferred operations for this criterion
    #[allow(dead_code)]
    fn execute_deferred_operations_for_criterion(
        &mut self,
        _criterion: &ExecutableCriterion,
        collected_data: &HashMap<String, CollectedData>,
    ) -> Result<(), ExecutionError> {
        deferred_ops::execute_all_deferred_operations(
            &mut self.context,
            &self.registry,
            collected_data,
        )?;

        Ok(())
    }

    /// Convert tree result to findings with logical paths
    fn tree_result_to_findings(
        &self,
        tree_result: &TreeResult,
        current_path: Vec<String>,
    ) -> Result<Vec<ComplianceFinding>, ExecutionError> {
        let mut findings = Vec::new();

        // Add current level to path if it's a block
        let path = if let Some(logical_op) = tree_result.logical_op {
            let mut new_path = current_path.clone();
            let block_name = if tree_result.negated {
                format!("CRI_{}_NOT", logical_op_to_string(logical_op))
            } else {
                format!("CRI_{}", logical_op_to_string(logical_op))
            };
            new_path.push(block_name);
            new_path
        } else {
            current_path.clone()
        };

        // If this is a leaf node (has CTN results), process them
        if !tree_result.ctn_results.is_empty() {
            for ctn_result in &tree_result.ctn_results {
                if ctn_result.status != Outcome::Pass {
                    let mut finding_path = path.clone();
                    finding_path.push(format!("CTN_{}", ctn_result.criterion_type));

                    let finding =
                        self.ctn_result_to_finding(&ctn_result.execution_result, finding_path)?;
                    findings.push(finding);
                }
            }
        }

        // Recurse into child trees
        for child in &tree_result.child_results {
            let child_findings = self.tree_result_to_findings(child, path.clone())?;
            findings.extend(child_findings);
        }

        Ok(findings)
    }

    /// Apply SET-level filters to collected data
    fn apply_set_filters(
        &self,
        mut collected: HashMap<String, CollectedData>,
        criterion: &mut ExecutableCriterion,
    ) -> Result<HashMap<String, CollectedData>, ExecutionError> {
        // Early return if no SET filters
        if criterion.set_filters.is_empty() {
            return Ok(collected);
        }

        log_debug!(
            "Applying SET filters",
            "criterion_type" => &criterion.criterion_type,
            "set_filter_count" => criterion.set_filters.len(),
            "collected_count" => collected.len()
        );

        let mut to_remove = Vec::new();

        // Evaluate SET filter for each object that has one
        for (object_id, (set_id, filter)) in &criterion.set_filters {
            if let Some(data) = collected.get(object_id) {
                log_debug!(
                    "Evaluating SET filter",
                    "object_id" => object_id,
                    "set_id" => set_id,
                    "filter_action" => format!("{:?}", filter.action),
                    "state_ref_count" => filter.state_refs.len()
                );

                let passes = FilterEvaluator::evaluate_filter(filter, data, &self.context)
                    .map_err(|e| ExecutionError::FilterEvaluationFailed {
                        object_id: object_id.clone(),
                        reason: e.to_string(),
                    })?;

                let should_remove = match filter.action {
                    FilterAction::Include => !passes,
                    FilterAction::Exclude => passes,
                };

                if should_remove {
                    log_info!(
                        "SET filter excludes object",
                        "object_id" => object_id,
                        "set_id" => set_id,
                        "filter_action" => match filter.action {
                            FilterAction::Include => "include",
                            FilterAction::Exclude => "exclude",
                        },
                        "states_satisfied" => passes
                    );
                    to_remove.push(object_id.clone());
                }
            }
        }

        // Remove filtered-out objects
        for object_id in &to_remove {
            collected.remove(object_id);
        }

        // Update active objects tracking
        if !criterion.set_filters.is_empty() {
            let active_ids: HashSet<String> = collected.keys().cloned().collect();
            criterion.set_active_objects(active_ids);

            log_debug!(
                "Updated active objects after SET filters",
                "active_count" => criterion.expected_object_count()
            );
        }

        log_info!(
            "SET filter application complete",
            "original_count" => collected.len() + to_remove.len(),
            "filtered_out_count" => to_remove.len(),
            "remaining_count" => collected.len()
        );

        Ok(collected)
    }
}

// ============================================================================
// Legacy Result Type (for backwards compatibility)
// ============================================================================

/// Result from executing a single policy
///
/// **DEPRECATED**: Use `ExecutionManifest` directly. This type is provided
/// for backwards compatibility with existing code.
///
/// ## Replay Hash
///
/// The `replay_hash` field is carried through from the `ExecutionManifest`.
/// All output builders MUST use this directly.
#[derive(Debug, Clone)]
pub struct PolicyExecutionResult {
    /// Policy outcome
    pub outcome: PolicyOutcome,
    /// Criteria counts
    pub criteria_counts: CriteriaCounts,
    /// Findings
    pub findings: Vec<ComplianceFinding>,
    /// Evidence (if any)
    pub evidence: Option<common::results::Evidence>,
    /// Whether the tree passed
    pub tree_passed: bool,
    /// SHA-256 replay hash capturing intent + contract + outcome
    ///
    /// Replaces the previous `content_hash` + `evidence_hash`.
    /// Stable across runs when compliance posture is unchanged.
    pub replay_hash: String,
    /// Per-CTN-per-OBJECT v2 hash list. One entry per (ctn_node_id,
    /// object_id) pair the engine evaluated. Used by ingest-side
    /// callers to populate `evidence.ctn_results` and surface drift at
    /// the granularity of "which check on which asset flipped". Empty
    /// for envelopes built from policies that don't have any OBJECTs
    /// resolved at execution (rare).
    pub ctn_object_hashes: Vec<crate::types::CtnObjectHash>,
    /// Policy metadata (optional + extended fields)
    ///
    /// Contains version, title, description, author, tags, and any
    /// framework-specific extended fields from the META block.
    pub metadata: PolicyMetadata,
}

impl From<ExecutionManifest> for PolicyExecutionResult {
    fn from(manifest: ExecutionManifest) -> Self {
        // Build PolicyOutcome from manifest
        let outcome = PolicyOutcome::new(
            manifest.policy_id.clone(),
            manifest.platform.clone(),
            manifest.tree_result.status,
            manifest.criticality,
            manifest.control_mappings.clone(),
            manifest.criteria_counts,
        );

        // Build Evidence from collected_data
        let evidence = if manifest.collected_data.is_empty() {
            None
        } else {
            let mut evidence = common::results::Evidence::new();
            for (key, data) in &manifest.collected_data {
                evidence.add_data(key.clone(), data.fields_to_json());

                // Add collection record with method
                let record = common::results::CollectionRecord::new(
                    data.object_id.clone(),
                    data.ctn_type.clone(),
                    data.metadata.collector_id.clone(),
                )
                .with_mode(data.metadata.collection_mode.clone())
                .with_duration_ms(data.metadata.collection_duration.as_millis() as u64)
                .with_field_count(data.fields.len())
                .with_warnings(data.metadata.warnings.clone());

                // Add method if present
                let record = if let Some(ref method) = data.metadata.method {
                    record.with_method(method.clone())
                } else {
                    record
                };

                evidence.add_collection_record(record);
            }
            Some(evidence)
        };

        // Convert PolicyMetadataFields to PolicyMetadata
        let metadata = manifest.metadata.to_builder_metadata();

        // v2 per-CTN-per-OBJECT hash list, computed alongside the v1
        // bundled rollup. Cost is one extra walk over the criteria; the
        // SHA-256 work is identical whether v1 or v2 paths are queried.
        let ctn_object_hashes = manifest.replay_manifest.all_ctn_object_hashes();

        Self {
            outcome,
            criteria_counts: manifest.criteria_counts,
            findings: manifest.findings,
            evidence,
            tree_passed: manifest.tree_passed,
            // CRITICAL: Carry through the replay hash!
            replay_hash: manifest.replay_hash,
            ctn_object_hashes,
            // CRITICAL: Carry through the metadata!
            metadata,
        }
    }
}

impl PolicyExecutionResult {
    /// Check if the policy passed
    pub fn is_pass(&self) -> bool {
        self.tree_passed
    }

    /// Get the outcome
    pub fn outcome(&self) -> Outcome {
        self.outcome.outcome
    }

    /// Get policy ID
    pub fn policy_id(&self) -> &str {
        &self.outcome.policy_id
    }

    /// Check if replay hash is present
    pub fn has_valid_hash(&self) -> bool {
        !self.replay_hash.is_empty()
    }

    /// Check if metadata has any content
    pub fn has_metadata(&self) -> bool {
        !self.metadata.is_empty()
    }

    /// Get policy metadata
    pub fn metadata(&self) -> &PolicyMetadata {
        &self.metadata
    }
}

// ============================================================================
// Error Types
// ============================================================================

#[derive(Debug, thiserror::Error)]
pub enum ExecutionError {
    #[error("No contract registered for CTN type '{ctn_type}': {reason}")]
    NoContractRegistered { ctn_type: String, reason: String },

    #[error("Contract validation failed for '{ctn_type}': {errors:?}")]
    ContractValidationFailed {
        ctn_type: String,
        errors: Vec<String>,
    },

    #[error("No collector registered for CTN type '{ctn_type}': {reason}")]
    NoCollectorRegistered { ctn_type: String, reason: String },

    #[error("Data collection failed for object '{object_id}': {reason}")]
    DataCollectionFailed { object_id: String, reason: String },

    #[error("Deferred operation failed: {operation} - {reason}")]
    DeferredOperationFailed { operation: String, reason: String },

    #[error("State '{state_id}' not found")]
    StateNotFound { state_id: String },

    #[error("Executor failed for CTN type '{ctn_type}': {reason}")]
    ExecutorFailed { ctn_type: String, reason: String },

    #[error("No executor registered for CTN type '{ctn_type}': {reason}")]
    NoExecutorRegistered { ctn_type: String, reason: String },

    #[error("Filter evaluation failed for object '{object_id}': {reason}")]
    FilterEvaluationFailed { object_id: String, reason: String },

    #[error("Object '{object_id}' not found in criterion object list")]
    ObjectNotFoundInCriterion { object_id: String },
}

impl From<CtnExecutionError> for ExecutionError {
    fn from(err: CtnExecutionError) -> Self {
        ExecutionError::ExecutorFailed {
            ctn_type: "unknown".to_string(),
            reason: err.to_string(),
        }
    }
}

// ============================================================================
// Helper Functions
// ============================================================================

fn logical_op_to_string(op: LogicalOp) -> &'static str {
    match op {
        LogicalOp::And => "AND",
        LogicalOp::Or => "OR",
    }
}

/// Convert ResolvedValue to serde_json::Value
fn resolved_value_to_json(value: &ResolvedValue) -> serde_json::Value {
    match value {
        ResolvedValue::String(s) => serde_json::Value::String(s.clone()),
        ResolvedValue::Integer(i) => serde_json::Value::Number((*i).into()),
        ResolvedValue::Float(f) => serde_json::Number::from_f64(*f)
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null),
        ResolvedValue::Boolean(b) => serde_json::Value::Bool(*b),
        ResolvedValue::Collection(items) => {
            serde_json::Value::Array(items.iter().map(resolved_value_to_json).collect())
        }
        ResolvedValue::Version(v) => serde_json::Value::String(v.to_string()),
        ResolvedValue::Binary(bytes) => {
            // Encode binary as hex for JSON compatibility
            let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
            serde_json::Value::String(format!("hex:{}", hex))
        }
        ResolvedValue::EvrString(evr) => serde_json::Value::String(evr.to_string()),
        ResolvedValue::RecordData(record) => record.as_json_value().clone(),
    }
}

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
    let month = (day_of_year / 30).min(11) + 1;
    let day = (day_of_year % 30) + 1;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        years, month, day, hours, minutes, seconds
    )
}
