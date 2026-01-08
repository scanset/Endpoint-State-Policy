//! Computed Values CTN Contract
//!
//! Special CTN type for validating computed variables from RUN operations.
//! This is for TESTING and DEVELOPMENT only - NOT for compliance scans.
//!
//! Use case: Validate that RUN operations produce expected results

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

/// Create contract for computed_values CTN type
///
/// This CTN validates computed variables (from RUN operations) instead of collected data.
/// It's designed for testing RUN operations, not for compliance scanning.
pub fn create_computed_values_contract() -> CtnContract {
    let mut contract = CtnContract::new("computed_values".to_string());

    // Object requirements - minimal, just needs an identifier
    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "type".to_string(),
            data_type: DataType::String,
            description: "Validation type marker".to_string(),
            example_values: vec!["test".to_string(), "validation".to_string()],
            validation_notes: Some("Informational only - not used for collection".to_string()),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "description".to_string(),
            data_type: DataType::String,
            description: "Description of what is being validated".to_string(),
            example_values: vec!["RUN operations test".to_string()],
            validation_notes: Some("Informational only".to_string()),
        });

    // State requirements - flexible to support any computed value type
    // String values
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "*".to_string(), // Wildcard - any field name accepted
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
                Operation::NotContains,
                Operation::StartsWith,
                Operation::EndsWith,
            ],
            description: "Any string variable".to_string(),
            example_values: vec!["Hello".to_string(), "test".to_string()],
            validation_notes: Some("Validates against resolved variables".to_string()),
        });

    // Integer values
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "*_int".to_string(),
            data_type: DataType::Int,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::GreaterThan,
                Operation::LessThan,
                Operation::GreaterThanOrEqual,
                Operation::LessThanOrEqual,
            ],
            description: "Any integer variable".to_string(),
            example_values: vec!["42".to_string(), "100".to_string()],
            validation_notes: Some("Validates against resolved variables".to_string()),
        });

    // Boolean values
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "*_bool".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Any boolean variable".to_string(),
            example_values: vec!["true".to_string(), "false".to_string()],
            validation_notes: Some("Validates against resolved variables".to_string()),
        });

    // Field mappings - Add a dummy required field to satisfy validation
    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["_validation_marker".to_string()];

    // Validation mappings are identity mappings (state field → variable name)
    // The executor will implement this by looking up variables directly

    // Collection strategy - no actual collection happens
    contract.collection_strategy = CollectionStrategy {
        collector_type: "computed_values".to_string(),
        collection_mode: CollectionMode::Metadata, // Closest match, but not really collecting
        required_capabilities: vec![],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(0),
            memory_usage_mb: Some(0),
            network_intensive: false,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract
}
