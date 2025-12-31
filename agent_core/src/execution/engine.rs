//! # Execution Engine
//!
//! Orchestrates TEST-driven compliance validation with CTN contracts and tree traversal.
//!
//! ## Architecture
//!
//! The engine executes a single policy file and produces a `PolicyResult`.
//! Multiple `PolicyResult`s are aggregated into a `ScanResult` by the agent.
//!
//! ```text
//! ExecutionEngine::execute()
//!   └── PolicyExecutionResult
//!         ├── PolicyOutcome (CUI-free core)
//!         ├── findings: Vec<ComplianceFinding> (CUI)
//!         └── evidence: Option<Evidence> (CUI)
//! ```

use crate::execution::behavior::extract_behavior_hints;
use crate::execution::comparisons::{string, ComparisonExt};
use crate::execution::deferred_ops;
use crate::execution::filter_evaluation::FilterEvaluator;
use crate::strategies::CtnExecutionError;
use crate::strategies::{CollectedData, CtnContract, CtnExecutionResult, CtnStrategyRegistry};
use crate::types::common::{LogicalOp, ResolvedValue};
use crate::types::criterion::CtnNodeId;
use crate::types::execution_context::{
    ExecutableCriteriaTree, ExecutableCriterion, ExecutableObject, ExecutionContext,
};
use common::ast::nodes::FilterAction;
use common::metadata::MetaDataBlock;
use common::results::{
    ComplianceFinding, ControlMapping, CriteriaCounts, Criticality, Evidence, FindingSeverity,
    Outcome, PolicyOutcome,
};
use common::{log_debug, log_info};
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;

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
    /// Executes the criteria tree for a single policy and produces a `PolicyExecutionResult`.
    /// The result contains CUI-free outcome data plus optional CUI (findings/evidence).
    pub fn execute(&mut self) -> Result<PolicyExecutionResult, ExecutionError> {
        // Validate execution context before starting
        self.context
            .validate()
            .map_err(|e| ExecutionError::ExecutorFailed {
                ctn_type: "context_validation".to_string(),
                reason: e,
            })?;

        // Execute the criteria tree recursively
        let tree_result = self.execute_tree(&self.context.criteria_tree.clone())?;

        // Calculate flat statistics from tree (for metrics/dashboards)
        let stats = tree_result.calculate_stats();

        // Convert tree results to findings (CUI)
        let findings = self.tree_result_to_findings(&tree_result, vec![])?;

        // Build evidence from collected data (CUI)
        let evidence = self.build_evidence(&tree_result);

        // Extract metadata and build policy outcome
        let metadata =
            self.context
                .metadata
                .as_ref()
                .ok_or_else(|| ExecutionError::ExecutorFailed {
                    ctn_type: "metadata_extraction".to_string(),
                    reason: "Missing metadata in execution context".to_string(),
                })?;

        let policy_outcome = self.build_policy_outcome(metadata, &tree_result, &stats)?;

        // Build criteria counts
        let criteria_counts =
            CriteriaCounts::new(stats.total, stats.passed, stats.failed, stats.errors);

        Ok(PolicyExecutionResult {
            outcome: policy_outcome,
            criteria_counts,
            findings,
            evidence,
            tree_passed: tree_result.status == Outcome::Pass,
        })
    }

    /// Build PolicyOutcome from metadata and execution results
    fn build_policy_outcome(
        &self,
        metadata: &MetaDataBlock,
        tree_result: &TreeResult,
        stats: &TreeStats,
    ) -> Result<PolicyOutcome, ExecutionError> {
        // Extract required fields
        let policy_id = metadata
            .policy_id()
            .ok_or_else(|| ExecutionError::ExecutorFailed {
                ctn_type: "metadata_extraction".to_string(),
                reason: "Missing esp_scan_id in metadata".to_string(),
            })?;

        let platform = metadata
            .platform()
            .ok_or_else(|| ExecutionError::ExecutorFailed {
                ctn_type: "metadata_extraction".to_string(),
                reason: "Missing platform in metadata".to_string(),
            })?;

        let criticality_str =
            metadata
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
            metadata
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

        // Determine outcome - use tree logic, not flat stats
        let outcome = tree_result.status;

        // Build criteria counts
        let criteria_counts =
            CriteriaCounts::new(stats.total, stats.passed, stats.failed, stats.errors);

        Ok(PolicyOutcome::new(
            policy_id,
            platform,
            outcome,
            criticality,
            control_mappings,
            criteria_counts,
        ))
    }

    /// Build evidence from tree execution (CUI)
    fn build_evidence(&self, _tree_result: &TreeResult) -> Option<Evidence> {
        // Evidence collection is optional - can be expanded to capture
        // raw collected data for audit purposes
        None
    }

    /// Recursive tree traversal with logical operator application
    fn execute_tree(
        &mut self,
        tree: &ExecutableCriteriaTree,
    ) -> Result<TreeResult, ExecutionError> {
        match tree {
            ExecutableCriteriaTree::Criterion(criterion) => {
                // Clone the criterion so we can mutate it
                let mut mutable_criterion = criterion.clone();

                // Execute with mutable reference
                let result = self.execute_single_criterion(&mut mutable_criterion)?;

                Ok(TreeResult {
                    status: result.status,
                    logical_op: None,
                    negated: false,
                    ctn_results: vec![CtnResult {
                        ctn_node_id: criterion.ctn_node_id,
                        criterion_type: criterion.criterion_type.clone(),
                        status: result.status,
                        execution_result: result,
                        execution_time_ms: 0,
                    }],
                    child_results: vec![],
                })
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

                let combined = self.apply_logical_op(&child_results, *logical_op);
                let final_status = if *negate { combined.negate() } else { combined };

                Ok(TreeResult {
                    status: final_status,
                    logical_op: Some(*logical_op),
                    negated: *negate,
                    ctn_results: vec![],
                    child_results,
                })
            }
        }
    }

    /// Apply logical operator to child tree results
    fn apply_logical_op(&self, children: &[TreeResult], op: LogicalOp) -> Outcome {
        if children.is_empty() {
            return Outcome::Error;
        }

        match op {
            LogicalOp::And => {
                // ALL children must pass
                if children.iter().all(|c| c.status == Outcome::Pass) {
                    Outcome::Pass
                } else if children.iter().any(|c| c.status == Outcome::Error) {
                    Outcome::Error
                } else {
                    Outcome::Fail
                }
            }
            LogicalOp::Or => {
                // ANY child passes = pass
                if children.iter().any(|c| c.status == Outcome::Pass) {
                    Outcome::Pass
                } else if children.iter().all(|c| c.status == Outcome::Error) {
                    Outcome::Error
                } else {
                    Outcome::Fail
                }
            }
        }
    }

    /// Execute a single criterion with timeout protection
    fn execute_single_criterion(
        &mut self,
        criterion: &mut ExecutableCriterion,
    ) -> Result<CtnExecutionResult, ExecutionError> {
        use std::time::Instant;

        const CTN_TIMEOUT_SECS: u64 = 30;
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
        if start.elapsed().as_secs() > CTN_TIMEOUT_SECS {
            return Err(ExecutionError::ExecutorFailed {
                ctn_type: criterion.criterion_type.clone(),
                reason: format!(
                    "CTN execution exceeded timeout of {}s during setup",
                    CTN_TIMEOUT_SECS
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
        if start.elapsed().as_secs() > CTN_TIMEOUT_SECS {
            return Err(ExecutionError::ExecutorFailed {
                ctn_type: criterion.criterion_type.clone(),
                reason: format!(
                    "CTN execution exceeded timeout of {}s during collection",
                    CTN_TIMEOUT_SECS
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

        // Execute validation
        let result = executor
            .execute_with_contract(criterion, &collected_data, &contract_clone)
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
// Result Types
// ============================================================================

/// Result from executing a single policy
///
/// This is the output of `ExecutionEngine::execute()` for one policy file.
/// Contains both CUI-free outcome data and optional CUI (findings/evidence).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PolicyExecutionResult {
    /// CUI-free policy outcome (safe for attestations)
    pub outcome: PolicyOutcome,

    /// Criteria counts (pass/fail/error)
    pub criteria_counts: CriteriaCounts,

    /// Detailed findings (CUI - contains expected/actual values)
    pub findings: Vec<ComplianceFinding>,

    /// Raw evidence data (CUI - contains collected system values)
    pub evidence: Option<Evidence>,

    /// Whether the tree logic resulted in pass (respects CRI AND/OR/NOT)
    pub tree_passed: bool,
}

impl PolicyExecutionResult {
    /// Check if the policy passed (using tree logic)
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
}

/// CTN execution result with tree context
#[derive(Debug, Clone)]
pub struct CtnResult {
    pub ctn_node_id: CtnNodeId,
    pub criterion_type: String,
    pub status: Outcome,
    pub execution_result: CtnExecutionResult,
    pub execution_time_ms: u64,
}

/// Tree traversal result (internal)
#[derive(Debug, Clone)]
struct TreeResult {
    pub status: Outcome,
    pub logical_op: Option<LogicalOp>,
    pub negated: bool,
    pub ctn_results: Vec<CtnResult>,
    pub child_results: Vec<TreeResult>,
}

impl TreeResult {
    fn calculate_stats(&self) -> TreeStats {
        let mut stats = TreeStats::default();
        for ctn in &self.ctn_results {
            stats.total += 1;
            match ctn.status {
                Outcome::Pass => stats.passed += 1,
                Outcome::Fail => stats.failed += 1,
                Outcome::Error => stats.errors += 1,
                _ => {}
            }
        }

        // Recurse into children
        for child in &self.child_results {
            let child_stats = child.calculate_stats();
            stats.total += child_stats.total;
            stats.passed += child_stats.passed;
            stats.failed += child_stats.failed;
            stats.errors += child_stats.errors;
        }

        stats
    }
}

#[derive(Debug, Default)]
struct TreeStats {
    total: u32,
    passed: u32,
    failed: u32,
    errors: u32,
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
