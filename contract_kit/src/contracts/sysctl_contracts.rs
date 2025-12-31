//! Sysctl kernel parameter CTN contract
//!
//! Validates kernel parameter values.

use agent_core::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use agent_core::types::common::{DataType, Operation};

pub fn create_sysctl_parameter_contract() -> CtnContract {
    let mut contract = CtnContract::new("sysctl_parameter".to_string());

    // Object requirements
    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "parameter_name".to_string(),
            data_type: DataType::String,
            description: "Kernel parameter name".to_string(),
            example_values: vec![
                "net.ipv4.ip_forward".to_string(),
                "kernel.randomize_va_space".to_string(),
            ],
            validation_notes: Some("Dot-notation parameter path".to_string()),
        });

    // State requirements
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "value".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Parameter value as string".to_string(),
            example_values: vec!["0".to_string(), "1".to_string(), "2".to_string()],
            validation_notes: Some("Compared as strings".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "value_int".to_string(),
            data_type: DataType::Int,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::GreaterThan,
                Operation::LessThan,
                Operation::GreaterThanOrEqual,
                Operation::LessThanOrEqual,
            ],
            description: "Parameter value as integer".to_string(),
            example_values: vec!["0".to_string(), "1".to_string(), "2".to_string()],
            validation_notes: Some("For numeric comparisons".to_string()),
        });

    // Field mappings
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("parameter_name".to_string(), "parameter_name".to_string());

    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["parameter_name".to_string()];

    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec!["value".to_string(), "value_int".to_string()];

    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("value".to_string(), "value".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("value_int".to_string(), "value_int".to_string());

    // Collection strategy
    contract.collection_strategy = CollectionStrategy {
        collector_type: "command".to_string(),
        collection_mode: CollectionMode::Command,
        required_capabilities: vec!["execute_sysctl".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(30),
            memory_usage_mb: Some(1),
            network_intensive: false,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract
}
