// src/strategies/traits.rs
//! CTN strategy traits for extensible compliance validation
//!
//! Defines the contract-based extension points for CTN data collection and execution.
//! All strategies operate within explicit CTN contracts that define field requirements,
//! mappings, and validation rules.

use crate::execution::behavior::BehaviorHints;
use crate::strategies::ctn_contract::CtnContract;
use crate::strategies::errors::{CollectionError, CtnExecutionError, ValidationReport};
use crate::types::common::ResolvedValue;
use crate::types::execution_context::{ExecutableCriterion, ExecutableObject};
use crate::types::{ExistenceCheck, ItemCheck, StateJoinOp};
use common::results::Outcome;
use std::collections::HashMap;
use std::time::{Duration, SystemTime};

// ============================================================================
// Data Collection Traits
// ============================================================================

/// CTN-specific data collector with contract validation
pub trait CtnDataCollector: Send + Sync {
    /// Collect data with explicit behavior hints (preferred method)
    ///
    /// This method receives pre-extracted behavior hints from the execution engine,
    /// allowing collectors to modify their behavior based on BEHAVIOR directives in
    /// the ICS object definition.
    ///
    /// # Arguments
    /// * `object` - The executable object containing target resource information
    /// * `ctn_contract` - The CTN contract defining collection requirements
    /// * `hints` - Parsed behavior hints from the object's BEHAVIOR element
    ///
    /// # Behavior Hints
    /// Common hints include:
    /// - Flags: `recursive_scan`, `include_hidden`, `fast_mode`, `list`, `query`
    /// - Parameters: `max_depth`, `timeout`, `batch_size`
    ///
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        ctn_contract: &CtnContract,
        hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError>;

    /// Get supported CTN types
    fn supported_ctn_types(&self) -> Vec<String>;

    /// Validate that collector can handle this CTN contract
    fn validate_ctn_compatibility(&self, ctn_contract: &CtnContract)
        -> Result<(), CollectionError>;

    /// Get collector identifier
    fn collector_id(&self) -> &str;

    /// Optional: Check if object exists without full collection
    fn object_exists(
        &self,
        object: &ExecutableObject,
        ctn_contract: &CtnContract,
    ) -> Result<bool, CollectionError> {
        // Default implementation: try collection and check for errors
        let hints = crate::execution::behavior::extract_behavior_hints(object);
        match self.collect_for_ctn_with_hints(object, ctn_contract, &hints) {
            Ok(data) => Ok(!data.fields.is_empty()),
            Err(CollectionError::ObjectNotFound { .. }) => Ok(false),
            Err(CollectionError::AccessDenied { .. }) => Ok(true),
            Err(e) => Err(e),
        }
    }

    /// Optional: Extract specific field from collected data
    fn extract_field(
        &self,
        data: &CollectedData,
        field_path: &str,
    ) -> Result<ResolvedValue, CollectionError> {
        data.get_field(field_path)
            .cloned()
            .ok_or_else(|| CollectionError::FieldExtractionFailed {
                field: field_path.to_string(),
            })
    }

    /// Optional: Get collection capabilities
    fn get_capabilities(&self) -> Vec<String> {
        Vec::new()
    }

    /// Optional: Get performance characteristics
    fn get_performance_profile(&self) -> CollectorPerformanceProfile {
        CollectorPerformanceProfile::default()
    }

    fn collect_batch(
        &self,
        objects: Vec<&ExecutableObject>,
        ctn_contract: &CtnContract,
    ) -> Result<HashMap<String, CollectedData>, CollectionError> {
        // Default implementation: individual collection with hints
        let mut results = HashMap::new();

        for object in objects {
            // Extract hints once per object
            let hints = crate::execution::behavior::extract_behavior_hints(object);
            let data = self.collect_for_ctn_with_hints(object, ctn_contract, &hints)?;
            results.insert(object.identifier.clone(), data);
        }

        Ok(results)
    }

    fn supports_batch_collection(&self) -> bool {
        false
    }
}

/// Performance profile for collectors
#[derive(Debug, Clone, Default)]
pub struct CollectorPerformanceProfile {
    pub typical_collection_time_ms: Option<u64>,
    pub memory_usage_mb: Option<u64>,
    pub supports_batch_collection: bool,
    pub requires_elevated_privileges: bool,
    pub network_dependent: bool,
}

// ============================================================================
// CTN Execution Traits
// ============================================================================

/// CTN-specific executor with explicit contract enforcement
pub trait CtnExecutor: Send + Sync {
    /// Execute with CTN contract validation and TEST specification processing
    ///
    /// Takes ownership of collected_data to avoid cloning. The data is moved
    /// into the CtnExecutionResult for downstream evidence generation.
    fn execute_with_contract(
        &self,
        criterion: &ExecutableCriterion,
        collected_data: HashMap<String, CollectedData>,
        ctn_contract: &CtnContract,
    ) -> Result<CtnExecutionResult, CtnExecutionError>;

    /// Get the CTN contract this executor implements
    fn get_ctn_contract(&self) -> CtnContract;

    /// Validate collected data meets CTN requirements
    fn validate_collected_data(
        &self,
        collected_data: &HashMap<String, CollectedData>,
        ctn_contract: &CtnContract,
    ) -> Result<(), CtnExecutionError>;

    /// Get supported CTN type
    fn ctn_type(&self) -> &str;

    /// Optional: Validate criterion before execution
    fn validate_criterion(
        &self,
        criterion: &ExecutableCriterion,
    ) -> Result<ValidationReport, CtnExecutionError> {
        let contract = self.get_ctn_contract();
        Ok(contract.validate_criterion(criterion))
    }

    /// Optional: Get executor capabilities
    fn get_executor_capabilities(&self) -> Vec<String> {
        Vec::new()
    }
}

// ============================================================================
// Data Structures
// ============================================================================

/// Collected data with CTN context and metadata
#[derive(Debug, Clone)]
pub struct CollectedData {
    /// Object identifier that was collected
    pub object_id: String,

    /// CTN type this data was collected for
    pub ctn_type: String,

    /// Collected field values mapped by field name
    pub fields: HashMap<String, ResolvedValue>,

    /// Collection metadata and diagnostics
    pub metadata: CollectionMetadata,
}

#[derive(Debug, Clone)]
pub struct CollectionMetadata {
    /// Collector that gathered this data
    pub collector_id: String,

    /// Collection mode used
    pub collection_mode: String,

    /// When collection occurred
    pub collected_at: SystemTime,

    /// How long collection took
    pub collection_duration: Duration,

    /// Platform-specific metadata
    pub platform_specific: Option<serde_json::Value>,

    /// Collection warnings or notes
    pub warnings: Vec<String>,
}

impl CollectedData {
    /// Create new collected data
    pub fn new(object_id: String, ctn_type: String, collector_id: String) -> Self {
        Self {
            object_id,
            ctn_type,
            fields: HashMap::new(),
            metadata: CollectionMetadata {
                collector_id,
                collection_mode: "default".to_string(),
                collected_at: SystemTime::now(),
                collection_duration: Duration::from_millis(0),
                platform_specific: None,
                warnings: Vec::new(),
            },
        }
    }

    /// Add a field to collected data
    pub fn add_field(&mut self, name: String, value: ResolvedValue) {
        self.fields.insert(name, value);
    }

    /// Get field value by name
    pub fn get_field(&self, name: &str) -> Option<&ResolvedValue> {
        self.fields.get(name)
    }

    /// Check if field exists
    pub fn has_field(&self, name: &str) -> bool {
        self.fields.contains_key(name)
    }

    /// Add collection warning
    pub fn add_warning(&mut self, warning: String) {
        self.metadata.warnings.push(warning);
    }

    /// Set collection duration
    pub fn set_duration(&mut self, duration: Duration) {
        self.metadata.collection_duration = duration;
    }

    /// Set collection mode
    pub fn set_collection_mode(&mut self, mode: String) {
        self.metadata.collection_mode = mode;
    }

    /// Get all field names
    pub fn field_names(&self) -> Vec<&String> {
        self.fields.keys().collect()
    }

    /// Check if collection has warnings
    pub fn has_warnings(&self) -> bool {
        !self.metadata.warnings.is_empty()
    }

    /// Convert to JSON value for evidence serialization
    pub fn to_json_value(&self) -> serde_json::Value {
        let fields: serde_json::Map<String, serde_json::Value> = self
            .fields
            .iter()
            .map(|(k, v)| (k.clone(), resolved_value_to_json(v)))
            .collect();

        serde_json::json!({
            "object_id": self.object_id,
            "ctn_type": self.ctn_type,
            "fields": fields,
            "metadata": {
                "collector_id": self.metadata.collector_id,
                "collection_mode": self.metadata.collection_mode,
                "collection_duration_ms": self.metadata.collection_duration.as_millis() as u64,
                "warnings": self.metadata.warnings,
            }
        })
    }

    /// Convert fields only to JSON (for evidence.data)
    pub fn fields_to_json(&self) -> serde_json::Value {
        let fields: serde_json::Map<String, serde_json::Value> = self
            .fields
            .iter()
            .map(|(k, v)| (k.clone(), resolved_value_to_json(v)))
            .collect();

        serde_json::Value::Object(fields)
    }
}

/// Convert ResolvedValue to serde_json::Value
fn resolved_value_to_json(value: &ResolvedValue) -> serde_json::Value {
    match value {
        ResolvedValue::String(s) => serde_json::Value::String(s.clone()),
        ResolvedValue::Integer(i) => serde_json::json!(i),
        ResolvedValue::Float(f) => serde_json::json!(f),
        ResolvedValue::Boolean(b) => serde_json::Value::Bool(*b),
        ResolvedValue::Version(v) => serde_json::Value::String(v.clone()),
        ResolvedValue::EvrString(e) => serde_json::Value::String(e.clone()),
        ResolvedValue::Collection(items) => {
            serde_json::Value::Array(items.iter().map(resolved_value_to_json).collect())
        }
        ResolvedValue::RecordData(record) => record.as_json_value().clone(),
        ResolvedValue::Binary(bytes) => {
            // Encode binary as base64 string
            use base64::Engine;
            let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
            serde_json::json!({
                "_type": "binary",
                "encoding": "base64",
                "data": encoded
            })
        }
    }
}

/// CTN execution result with full details
#[derive(Debug, Clone)]
pub struct CtnExecutionResult {
    /// CTN type that was executed
    pub ctn_type: String,

    /// Overall status (pass/fail/error)
    pub status: Outcome,

    /// Which phase of TEST evaluation produced the result
    pub test_phase: TestPhase,

    /// Existence check results (if applicable)
    pub existence_result: Option<ExistenceResult>,

    /// State validation results per object
    pub state_results: Vec<StateValidationResult>,

    /// Item check results (if applicable)
    pub item_check_result: Option<ItemCheckResult>,

    /// Human-readable result message
    pub message: String,

    /// Additional details as JSON
    pub details: serde_json::Value,

    /// Execution metadata
    pub execution_metadata: ExecutionMetadata,

    /// Collected data preserved for evidence generation
    ///
    /// This contains the full collected data from all objects,
    /// moved here to avoid cloning and enable downstream evidence
    /// generation for both attestations and full results.
    pub collected_data: HashMap<String, CollectedData>,
}

#[derive(Debug, Clone)]
pub struct ExecutionMetadata {
    pub execution_duration: Duration,
    pub objects_processed: usize,
    pub states_evaluated: usize,
    pub warnings: Vec<String>,
    pub debug_info: Option<serde_json::Value>,
}

/// TEST evaluation phase
#[derive(Debug, Clone, PartialEq)]
pub enum TestPhase {
    ExistenceCheck,
    StateValidation,
    ItemCheck,
    Complete,
}

/// Existence check evaluation result
#[derive(Debug, Clone)]
pub struct ExistenceResult {
    pub existence_check: ExistenceCheck,
    pub objects_expected: usize,
    pub objects_found: usize,
    pub passed: bool,
    pub message: String,
}

/// State validation result for a single object
#[derive(Debug, Clone)]
pub struct StateValidationResult {
    pub object_id: String,
    pub state_results: Vec<FieldValidationResult>,
    pub combined_result: bool,
    pub state_operator: Option<StateJoinOp>,
    pub message: String,
}

/// Individual field validation result
#[derive(Debug, Clone)]
pub struct FieldValidationResult {
    pub field_name: String,
    pub expected_value: ResolvedValue,
    pub actual_value: ResolvedValue,
    pub operation: crate::types::common::Operation,
    pub passed: bool,
    pub message: String,
}

/// Item check evaluation result
#[derive(Debug, Clone)]
pub struct ItemCheckResult {
    pub item_check: ItemCheck,
    pub objects_passing: usize,
    pub objects_total: usize,
    pub passed: bool,
    pub message: String,
}

impl CtnExecutionResult {
    /// Create a passing result
    pub fn pass(ctn_type: String, message: String) -> Self {
        Self {
            ctn_type,
            status: Outcome::Pass,
            test_phase: TestPhase::Complete,
            existence_result: None,
            state_results: Vec::new(),
            item_check_result: None,
            message,
            details: serde_json::json!({}),
            execution_metadata: ExecutionMetadata::default(),
            collected_data: HashMap::new(),
        }
    }

    /// Create a failing result
    pub fn fail(ctn_type: String, message: String) -> Self {
        Self {
            ctn_type,
            status: Outcome::Fail,
            test_phase: TestPhase::Complete,
            existence_result: None,
            state_results: Vec::new(),
            item_check_result: None,
            message,
            details: serde_json::json!({}),
            execution_metadata: ExecutionMetadata::default(),
            collected_data: HashMap::new(),
        }
    }

    /// Create an error result
    pub fn error(ctn_type: String, message: String) -> Self {
        Self {
            ctn_type,
            status: Outcome::Error,
            test_phase: TestPhase::Complete,
            existence_result: None,
            state_results: Vec::new(),
            item_check_result: None,
            message,
            details: serde_json::json!({}),
            execution_metadata: ExecutionMetadata::default(),
            collected_data: HashMap::new(),
        }
    }

    /// Add execution details
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = details;
        self
    }

    /// Set test phase
    pub fn with_test_phase(mut self, phase: TestPhase) -> Self {
        self.test_phase = phase;
        self
    }

    /// Add existence result
    pub fn with_existence_result(mut self, result: ExistenceResult) -> Self {
        self.existence_result = Some(result);
        self
    }

    /// Add state results
    pub fn with_state_results(mut self, results: Vec<StateValidationResult>) -> Self {
        self.state_results = results;
        self
    }

    /// Add item check result
    pub fn with_item_check_result(mut self, result: ItemCheckResult) -> Self {
        self.item_check_result = Some(result);
        self
    }

    /// Add collected data for evidence generation
    pub fn with_collected_data(mut self, data: HashMap<String, CollectedData>) -> Self {
        self.collected_data = data;
        self
    }

    /// Convert collected data to evidence-ready JSON
    ///
    /// Returns a map of object_id -> field values suitable for
    /// inclusion in Evidence.data
    pub fn collected_data_to_evidence(&self) -> HashMap<String, serde_json::Value> {
        self.collected_data
            .iter()
            .map(|(id, data)| (id.clone(), data.fields_to_json()))
            .collect()
    }

    /// Get collection metadata summary for attestations
    ///
    /// Returns metadata about collection without the actual field values,
    /// suitable for CUI-free attestations
    pub fn collection_metadata_summary(&self) -> Vec<CollectionMetadataSummary> {
        self.collected_data
            .values()
            .map(|data| CollectionMetadataSummary {
                object_id: data.object_id.clone(),
                ctn_type: data.ctn_type.clone(),
                collector_id: data.metadata.collector_id.clone(),
                collection_mode: data.metadata.collection_mode.clone(),
                collection_duration_ms: data.metadata.collection_duration.as_millis() as u64,
                field_count: data.fields.len(),
                has_warnings: !data.metadata.warnings.is_empty(),
            })
            .collect()
    }
}

/// Summary of collection metadata for attestations (CUI-free)
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CollectionMetadataSummary {
    pub object_id: String,
    pub ctn_type: String,
    pub collector_id: String,
    pub collection_mode: String,
    pub collection_duration_ms: u64,
    pub field_count: usize,
    pub has_warnings: bool,
}

impl Default for ExecutionMetadata {
    fn default() -> Self {
        Self {
            execution_duration: Duration::from_millis(0),
            objects_processed: 0,
            states_evaluated: 0,
            warnings: Vec::new(),
            debug_info: None,
        }
    }
}

// ============================================================================
// Helper Traits
// ============================================================================

/// Trait for TEST specification processing
pub trait TestProcessor {
    /// Evaluate existence check
    fn evaluate_existence_check(
        &self,
        existence_check: ExistenceCheck,
        objects_expected: usize,
        objects_found: usize,
    ) -> ExistenceResult;

    /// Evaluate item check
    fn evaluate_item_check(
        &self,
        item_check: ItemCheck,
        objects_passing: usize,
        objects_total: usize,
    ) -> ItemCheckResult;

    /// Apply state operator to combine state results
    fn apply_state_operator(
        &self,
        state_operator: Option<StateJoinOp>,
        state_results: &[bool],
    ) -> bool;
}

/// Default TEST processor implementation
pub struct DefaultTestProcessor;

impl TestProcessor for DefaultTestProcessor {
    fn evaluate_existence_check(
        &self,
        existence_check: ExistenceCheck,
        objects_expected: usize,
        objects_found: usize,
    ) -> ExistenceResult {
        let passed = crate::execution::helpers::evaluate_existence_check(
            existence_check,
            objects_found,
            objects_expected,
        );

        let message = if passed {
            format!(
                "Existence check '{}' passed: {} of {} objects found",
                existence_check.as_str(),
                objects_found,
                objects_expected
            )
        } else {
            format!(
                "Existence check '{}' failed: {} of {} objects found",
                existence_check.as_str(),
                objects_found,
                objects_expected
            )
        };

        ExistenceResult {
            existence_check,
            objects_expected,
            objects_found,
            passed,
            message,
        }
    }

    fn evaluate_item_check(
        &self,
        item_check: ItemCheck,
        objects_passing: usize,
        objects_total: usize,
    ) -> ItemCheckResult {
        let passed = crate::execution::helpers::evaluate_item_check(
            item_check,
            objects_passing,
            objects_total,
        );

        let message = if passed {
            format!(
                "Item check '{}' passed: {} of {} objects satisfied requirements",
                item_check.as_str(),
                objects_passing,
                objects_total
            )
        } else {
            format!(
                "Item check '{}' failed: {} of {} objects satisfied requirements",
                item_check.as_str(),
                objects_passing,
                objects_total
            )
        };

        ItemCheckResult {
            item_check,
            objects_passing,
            objects_total,
            passed,
            message,
        }
    }

    fn apply_state_operator(
        &self,
        state_operator: Option<StateJoinOp>,
        state_results: &[bool],
    ) -> bool {
        crate::execution::helpers::evaluate_state_operator(state_operator, state_results)
    }
}

// ============================================================================
// Extension Traits for Implementation Helpers
// ============================================================================

/// Extension trait for CTN contract validation
pub trait CtnContractValidator {
    fn validate_against_contract(&self, contract: &CtnContract) -> ValidationReport;
}

// Note: Implementations for ExecutableCriterion would go in the execution_context module
// This trait provides the interface that the strategies module expects
