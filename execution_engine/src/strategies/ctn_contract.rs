// src/strategies/ctn_contract.rs
//! CTN contract specifications and validation
//!
//! Defines complete contracts for CTN types including object requirements,
//! state requirements, field mappings, and collection strategies.

use crate::strategies::errors::{
    CtnContractError, ValidationErrorType, ValidationReport, ValidationWarningType,
};
use crate::types::common::{DataType, Operation};
use crate::types::execution_context::{ExecutableCriterion, ExecutableObject, ExecutableState};
use std::collections::{HashMap, HashSet};

/// Complete CTN contract specification
#[derive(Debug, Clone)]
pub struct CtnContract {
    pub ctn_type: String,
    pub object_requirements: ObjectRequirements,
    pub state_requirements: StateRequirements,
    pub field_mappings: CtnFieldMappings,
    pub collection_strategy: CollectionStrategy,
    pub metadata: CtnMetadata,
    pub supported_behaviors: Vec<SupportedBehavior>,
}

/// Metadata about the CTN contract
#[derive(Debug, Clone)]
pub struct CtnMetadata {
    pub description: String,
    pub version: String,
    pub author: Option<String>,
    pub compliance_frameworks: Vec<String>,
    pub platform_compatibility: Vec<String>,
    pub performance_notes: Option<String>,
}
/// Behavior supported by a CTN type
#[derive(Debug, Clone)]
pub struct SupportedBehavior {
    pub name: String,
    pub behavior_type: BehaviorType,
    pub parameters: Vec<BehaviorParameter>,
    pub description: String,
    pub example: String,
}

/// Type of behavior
#[derive(Debug, Clone, PartialEq)]
pub enum BehaviorType {
    Flag,      // Simple flag: recursive_scan, include_hidden
    Parameter, // Takes value: max_depth, timeout
}

/// Parameter specification for a behavior
#[derive(Debug, Clone)]
pub struct BehaviorParameter {
    pub name: String,
    pub data_type: DataType,
    pub required: bool,
    pub default_value: Option<String>,
    pub description: String,
}

/// Object field requirements for a CTN type
#[derive(Debug, Clone)]
pub struct ObjectRequirements {
    pub required_fields: Vec<ObjectFieldSpec>,
    pub optional_fields: Vec<ObjectFieldSpec>,
}

#[derive(Debug, Clone)]
pub struct ObjectFieldSpec {
    pub name: String,
    pub data_type: DataType,
    pub description: String,
    pub example_values: Vec<String>,
    pub validation_notes: Option<String>,
}

/// State field requirements for a CTN type
#[derive(Debug, Clone)]
pub struct StateRequirements {
    pub required_fields: Vec<StateFieldSpec>,
    pub optional_fields: Vec<StateFieldSpec>,
}

#[derive(Debug, Clone)]
pub struct StateFieldSpec {
    pub name: String,
    pub data_type: DataType,
    pub allowed_operations: Vec<Operation>,
    pub description: String,
    pub example_values: Vec<String>,
    pub validation_notes: Option<String>,
}

/// Field mappings for CTN data flow
#[derive(Debug, Clone)]
pub struct CtnFieldMappings {
    /// How object fields drive data collection
    pub collection_mappings: CollectionMappings,
    /// How collected data maps to state validation
    pub validation_mappings: ValidationMappings,
}

#[derive(Debug, Clone)]
pub struct CollectionMappings {
    /// object_field_name -> collection_parameter
    /// e.g., "path" -> "target_path", "key" -> "registry_key"
    pub object_to_collection: HashMap<String, String>,
    /// What data fields should be collected for this CTN
    pub required_data_fields: Vec<String>,
    /// Optional data fields that may be collected
    pub optional_data_fields: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ValidationMappings {
    /// state_field_name -> collected_data_field_name
    /// e.g., "permissions" -> "file_mode", "owner" -> "file_owner"
    pub state_to_data: HashMap<String, String>,
    /// Computed field mappings (derived from multiple collected fields)
    pub computed_mappings: HashMap<String, ComputedField>,
}

#[derive(Debug, Clone)]
pub struct ComputedField {
    pub name: String,
    pub source_fields: Vec<String>,
    pub computation: FieldComputation,
    pub description: String,
}

#[derive(Debug, Clone)]
pub enum FieldComputation {
    Concatenate {
        separator: String,
    },
    FormatString {
        template: String,
    },
    ConditionalValue {
        condition: String,
        true_value: String,
        false_value: String,
    },
    Custom {
        function_name: String,
    },
}

/// Collection strategy specification
#[derive(Debug, Clone)]
pub struct CollectionStrategy {
    pub collector_type: String,
    pub collection_mode: CollectionMode,
    pub required_capabilities: Vec<String>,
    pub performance_hints: PerformanceHints,
}

#[derive(Debug, Clone)]
pub enum CollectionMode {
    Metadata,       // Collect metadata only (permissions, size, etc.)
    Content,        // Collect content (file contents, registry values, etc.)
    Security,       // Collect security attributes (ACLs, contexts, etc.)
    Command,        // Execute system commands for data collection
    Status,         // Collect runtime status (service state, process info, etc.)
    Custom(String), // Custom collection mode
}

#[derive(Debug, Clone, Default)]
pub struct PerformanceHints {
    pub expected_collection_time_ms: Option<u64>,
    pub memory_usage_mb: Option<u64>,
    pub network_intensive: bool,
    pub cpu_intensive: bool,
    pub requires_elevated_privileges: bool,
}

// ============================================================================
// Implementation methods for CtnContract
// ============================================================================

impl CtnContract {
    pub fn new(ctn_type: String) -> Self {
        Self {
            ctn_type,
            object_requirements: ObjectRequirements::default(),
            state_requirements: StateRequirements::default(),
            field_mappings: CtnFieldMappings::default(),
            collection_strategy: CollectionStrategy::default(),
            metadata: CtnMetadata::default(),
            supported_behaviors: Vec::new(),
        }
    }

    /// Validate the entire contract for consistency
    pub fn validate(&self) -> Result<(), CtnContractError> {
        // Validate field mappings consistency
        self.field_mappings
            .validate_mappings(&self.state_requirements, &self.object_requirements)?;

        // Validate collection strategy
        self.collection_strategy.validate()?;

        // Validate required fields exist
        self.validate_required_fields()?;

        // Check for circular dependencies in computed fields
        self.validate_computed_field_dependencies()?;

        Ok(())
    }

    /// Validate a criterion against this contract
    pub fn validate_criterion(&self, criterion: &ExecutableCriterion) -> ValidationReport {
        let mut report = ValidationReport::new(self.ctn_type.clone());

        // Validate objects
        for object in &criterion.objects {
            self.validate_object_against_contract(object, &mut report);
        }

        // Validate states
        for state in &criterion.states {
            self.validate_state_against_contract(state, &mut report);
        }

        report
    }

    /// Get all required collection fields
    pub fn get_all_required_collection_fields(&self) -> Vec<String> {
        let mut fields = self
            .field_mappings
            .collection_mappings
            .required_data_fields
            .clone();

        // Add computed field dependencies
        for computed_field in self
            .field_mappings
            .validation_mappings
            .computed_mappings
            .values()
        {
            fields.extend(computed_field.source_fields.clone());
        }

        fields.sort();
        fields.dedup();
        fields
    }

    /// Check if field supports operation
    pub fn supports_operation(&self, state_field: &str, operation: &Operation) -> bool {
        self.state_requirements
            .get_field_spec(state_field)
            .map(|spec| spec.allowed_operations.contains(operation))
            .unwrap_or(false)
    }

    /// Get collection field for object field
    pub fn get_collection_field(&self, object_field: &str) -> Option<&str> {
        self.field_mappings.get_collection_field(object_field)
    }

    /// Get validation field for state field
    pub fn get_validation_field(&self, state_field: &str) -> Option<&str> {
        self.field_mappings.get_validation_field(state_field)
    }

    fn validate_required_fields(&self) -> Result<(), CtnContractError> {
        // Check that all required object fields have collection mappings
        for req_field in &self.object_requirements.required_fields {
            if !self
                .field_mappings
                .collection_mappings
                .object_to_collection
                .contains_key(&req_field.name)
            {
                return Err(CtnContractError::CollectionMappingError {
                    ctn_type: self.ctn_type.clone(),
                    reason: format!(
                        "Required object field '{}' has no collection mapping",
                        req_field.name
                    ),
                });
            }
        }

        // Check that all required state fields have validation mappings
        for req_field in &self.state_requirements.required_fields {
            let has_direct_mapping = self
                .field_mappings
                .validation_mappings
                .state_to_data
                .contains_key(&req_field.name);
            let has_computed_mapping = self
                .field_mappings
                .validation_mappings
                .computed_mappings
                .contains_key(&req_field.name);

            if !has_direct_mapping && !has_computed_mapping {
                return Err(CtnContractError::ValidationMappingError {
                    ctn_type: self.ctn_type.clone(),
                    reason: format!(
                        "Required state field '{}' has no validation mapping",
                        req_field.name
                    ),
                });
            }
        }

        Ok(())
    }

    fn validate_computed_field_dependencies(&self) -> Result<(), CtnContractError> {
        let computed_fields = &self.field_mappings.validation_mappings.computed_mappings;

        // Check for circular dependencies using DFS
        for field_name in computed_fields.keys() {
            let mut visited = HashSet::new();
            let mut path = Vec::new();

            if let Some(cycle) = self.detect_computed_field_cycle(
                field_name,
                &mut visited,
                &mut path,
                computed_fields,
            ) {
                return Err(CtnContractError::CircularComputedFieldDependency { cycle });
            }
        }

        Ok(())
    }

    fn detect_computed_field_cycle(
        &self,
        field_name: &str,
        visited: &mut HashSet<String>,
        path: &mut Vec<String>,
        computed_fields: &HashMap<String, ComputedField>,
    ) -> Option<Vec<String>> {
        if path.contains(&field_name.to_string()) {
            // Found cycle
            let Some(cycle_start) = path.iter().position(|f| f == field_name) else {
                // This should never happen since we only enter this branch
                // when path.contains(field_name), but handle gracefully
                return Some(vec![field_name.to_string()]);
            };
            let mut cycle = path
                .get(cycle_start..)
                .map(|s| s.to_vec())
                .unwrap_or_default();
            cycle.push(field_name.to_string());
            return Some(cycle);
        }

        if visited.contains(field_name) {
            return None; // Already processed, no cycle
        }

        visited.insert(field_name.to_string());
        path.push(field_name.to_string());

        if let Some(computed_field) = computed_fields.get(field_name) {
            for source_field in &computed_field.source_fields {
                if computed_fields.contains_key(source_field) {
                    if let Some(cycle) = self.detect_computed_field_cycle(
                        source_field,
                        visited,
                        path,
                        computed_fields,
                    ) {
                        return Some(cycle);
                    }
                }
            }
        }

        path.pop();
        None
    }

    fn validate_object_against_contract(
        &self,
        object: &ExecutableObject,
        report: &mut ValidationReport,
    ) {
        // Check required fields
        for req_field in &self.object_requirements.required_fields {
            if !object.has_field(&req_field.name) {
                report.add_error(
                    ValidationErrorType::MissingRequiredField,
                    format!(
                        "Object '{}' missing required field '{}'",
                        object.identifier, req_field.name
                    ),
                    Some(format!("CTN type '{}' requires this field", self.ctn_type)),
                );
            }
        }

        // Check field types
        for field in object.get_all_fields() {
            if let Some(spec) = self.object_requirements.get_field_spec(&field.name) {
                if !field.data_type.is_compatible_with(&spec.data_type) {
                    report.add_error(
                        ValidationErrorType::InvalidFieldType,
                        format!(
                            "Object '{}' field '{}' has incompatible type",
                            object.identifier, field.name
                        ),
                        Some(format!(
                            "Expected {:?}, got {:?}",
                            spec.data_type, field.data_type
                        )),
                    );
                }
            } else {
                report.add_warning(
                    ValidationWarningType::UnrecognizedField,
                    format!(
                        "Object '{}' has unrecognized field '{}'",
                        object.identifier, field.name
                    ),
                    Some("This field may be ignored during collection".to_string()),
                );
            }
        }
    }

    fn validate_state_against_contract(
        &self,
        state: &ExecutableState,
        report: &mut ValidationReport,
    ) {
        for field in &state.fields {
            if let Some(spec) = self.state_requirements.get_field_spec(&field.name) {
                // Check operation support
                if !spec.allowed_operations.contains(&field.operation) {
                    report.add_error(
                        ValidationErrorType::UnsupportedOperation,
                        format!(
                            "State '{}' field '{}' uses unsupported operation {:?}",
                            state.identifier, field.name, field.operation
                        ),
                        Some(format!("Allowed operations: {:?}", spec.allowed_operations)),
                    );
                }

                // Check data type compatibility
                if !field.data_type.is_compatible_with(&spec.data_type) {
                    report.add_error(
                        ValidationErrorType::InvalidFieldType,
                        format!(
                            "State '{}' field '{}' has incompatible type",
                            state.identifier, field.name
                        ),
                        Some(format!(
                            "Expected {:?}, got {:?}",
                            spec.data_type, field.data_type
                        )),
                    );
                }
            } else {
                report.add_warning(
                    ValidationWarningType::UnrecognizedField,
                    format!(
                        "State '{}' has unrecognized field '{}'",
                        state.identifier, field.name
                    ),
                    Some("This field may not be validated".to_string()),
                );
            }
        }
    }

    /// Add a supported behavior to this contract
    pub fn add_supported_behavior(&mut self, behavior: SupportedBehavior) {
        self.supported_behaviors.push(behavior);
    }

    /// Validate that behavior hints are supported by this contract
    pub fn validate_behavior_hints(
        &self,
        hints: &crate::execution::BehaviorHints,
    ) -> Result<(), CtnContractError> {
        // Validate flags
        for flag in &hints.flags {
            if !self.is_behavior_supported(flag) {
                return Err(CtnContractError::UnsupportedBehavior {
                    ctn_type: self.ctn_type.clone(),
                    behavior: flag.clone(),
                    supported_behaviors: self.get_supported_behavior_names(),
                });
            }
        }

        // Validate parameters - check if they belong to a declared behavior
        for param_name in hints.parameters.keys() {
            if !self.is_parameter_of_supported_behavior(param_name) {
                return Err(CtnContractError::UnsupportedBehavior {
                    ctn_type: self.ctn_type.clone(),
                    behavior: param_name.clone(),
                    supported_behaviors: self.get_supported_behavior_names(),
                });
            }
        }

        Ok(())
    }

    /// Check if parameter name belongs to any supported behavior
    fn is_parameter_of_supported_behavior(&self, param_name: &str) -> bool {
        self.supported_behaviors
            .iter()
            .any(|behavior| behavior.parameters.iter().any(|p| p.name == param_name))
    }

    /// Check if a behavior is supported
    fn is_behavior_supported(&self, behavior_name: &str) -> bool {
        self.supported_behaviors
            .iter()
            .any(|b| b.name == behavior_name)
    }

    /// Get list of supported behavior names
    fn get_supported_behavior_names(&self) -> Vec<String> {
        self.supported_behaviors
            .iter()
            .map(|b| b.name.clone())
            .collect()
    }
}

// ============================================================================
// Default implementations
// ============================================================================

impl Default for ObjectRequirements {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for StateRequirements {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for CtnFieldMappings {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for CollectionMappings {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for ValidationMappings {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Implementation methods for supporting structs
// ============================================================================

impl ObjectRequirements {
    pub fn new() -> Self {
        Self {
            required_fields: Vec::new(),
            optional_fields: Vec::new(),
        }
    }

    pub fn get_field_spec(&self, field_name: &str) -> Option<&ObjectFieldSpec> {
        self.required_fields
            .iter()
            .chain(self.optional_fields.iter())
            .find(|spec| spec.name == field_name)
    }

    pub fn is_field_required(&self, field_name: &str) -> bool {
        self.required_fields
            .iter()
            .any(|spec| spec.name == field_name)
    }

    pub fn add_required_field(&mut self, spec: ObjectFieldSpec) {
        self.required_fields.push(spec);
    }

    pub fn add_optional_field(&mut self, spec: ObjectFieldSpec) {
        self.optional_fields.push(spec);
    }
}

impl StateRequirements {
    pub fn new() -> Self {
        Self {
            required_fields: Vec::new(),
            optional_fields: Vec::new(),
        }
    }

    pub fn get_field_spec(&self, field_name: &str) -> Option<&StateFieldSpec> {
        self.required_fields
            .iter()
            .chain(self.optional_fields.iter())
            .find(|spec| spec.name == field_name)
    }

    pub fn is_field_required(&self, field_name: &str) -> bool {
        self.required_fields
            .iter()
            .any(|spec| spec.name == field_name)
    }

    pub fn add_required_field(&mut self, spec: StateFieldSpec) {
        self.required_fields.push(spec);
    }

    pub fn add_optional_field(&mut self, spec: StateFieldSpec) {
        self.optional_fields.push(spec);
    }
}

impl CtnFieldMappings {
    pub fn new() -> Self {
        Self {
            collection_mappings: CollectionMappings::new(),
            validation_mappings: ValidationMappings::new(),
        }
    }

    pub fn get_collection_field(&self, object_field: &str) -> Option<&str> {
        self.collection_mappings
            .object_to_collection
            .get(object_field)
            .map(|s| s.as_str())
    }

    pub fn get_validation_field(&self, state_field: &str) -> Option<&str> {
        self.validation_mappings
            .state_to_data
            .get(state_field)
            .map(|s| s.as_str())
    }

    pub fn validate_mappings(
        &self,
        state_requirements: &StateRequirements,
        object_requirements: &ObjectRequirements,
    ) -> Result<(), CtnContractError> {
        // Validate collection mappings reference valid object fields
        for object_field in self.collection_mappings.object_to_collection.keys() {
            if object_requirements.get_field_spec(object_field).is_none() {
                return Err(CtnContractError::FieldMappingError {
                    ctn_type: "unknown".to_string(),
                    reason: format!(
                        "Collection mapping references undefined object field '{}'",
                        object_field
                    ),
                });
            }
        }

        // Validate validation mappings reference valid state fields
        for state_field in self.validation_mappings.state_to_data.keys() {
            if state_requirements.get_field_spec(state_field).is_none() {
                return Err(CtnContractError::FieldMappingError {
                    ctn_type: "unknown".to_string(),
                    reason: format!(
                        "Validation mapping references undefined state field '{}'",
                        state_field
                    ),
                });
            }
        }

        Ok(())
    }
}

impl CollectionMappings {
    pub fn new() -> Self {
        Self {
            object_to_collection: HashMap::new(),
            required_data_fields: Vec::new(),
            optional_data_fields: Vec::new(),
        }
    }
}

impl ValidationMappings {
    pub fn new() -> Self {
        Self {
            state_to_data: HashMap::new(),
            computed_mappings: HashMap::new(),
        }
    }
}

impl CollectionStrategy {
    pub fn validate(&self) -> Result<(), CtnContractError> {
        if self.collector_type.is_empty() {
            return Err(CtnContractError::CollectionStrategyError {
                reason: "Collector type cannot be empty".to_string(),
            });
        }

        // Validate capabilities
        for capability in &self.required_capabilities {
            if capability.is_empty() {
                return Err(CtnContractError::CollectionStrategyError {
                    reason: "Capability name cannot be empty".to_string(),
                });
            }
        }

        Ok(())
    }
}

impl Default for CollectionStrategy {
    fn default() -> Self {
        Self {
            collector_type: "generic".to_string(),
            collection_mode: CollectionMode::Metadata,
            required_capabilities: Vec::new(),
            performance_hints: PerformanceHints::default(),
        }
    }
}

impl Default for CtnMetadata {
    fn default() -> Self {
        Self {
            description: "No description provided".to_string(),
            version: "1.0.0".to_string(),
            author: None,
            compliance_frameworks: Vec::new(),
            platform_compatibility: Vec::new(),
            performance_notes: None,
        }
    }
}

// ============================================================================
// Helper traits and implementations
// ============================================================================

/// Trait for objects that need to expose their fields for validation
pub trait FieldProvider {
    fn has_field(&self, field_name: &str) -> bool;
    fn get_all_fields(&self) -> Vec<FieldInfo>;
}

#[derive(Debug, Clone)]
pub struct FieldInfo {
    pub name: String,
    pub data_type: DataType,
}

// Note: These would need to be implemented for ExecutableObject and ExecutableState
// in the actual types module, but including the trait definition here for completeness

/// Data type compatibility checking
pub trait DataTypeCompatible {
    fn is_compatible_with(&self, other: &DataType) -> bool;
}

impl DataTypeCompatible for DataType {
    fn is_compatible_with(&self, other: &DataType) -> bool {
        // Basic compatibility - can be enhanced
        match (self, other) {
            (DataType::String, DataType::String) => true,
            (DataType::Int, DataType::Int) => true,
            (DataType::Float, DataType::Float) => true,
            (DataType::Boolean, DataType::Boolean) => true,
            (DataType::Binary, DataType::Binary) => true,
            (DataType::Version, DataType::Version) => true,
            (DataType::EvrString, DataType::EvrString) => true,
            (DataType::RecordData, DataType::RecordData) => true,
            // Allow some flexible conversions
            (DataType::Int, DataType::Float) => true,
            (DataType::Float, DataType::Int) => true,
            (DataType::String, DataType::Version) => true,
            (DataType::String, DataType::EvrString) => true,
            _ => false,
        }
    }
}
