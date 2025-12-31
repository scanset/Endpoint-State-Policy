//! SELinux status CTN contract
//!
//! Validates SELinux enforcement mode.

use agent_core::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use agent_core::types::common::{DataType, Operation};

pub fn create_selinux_status_contract() -> CtnContract {
    let mut contract = CtnContract::new("selinux_status".to_string());

    // Object requirements - none needed, checking system-wide status
    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "check_type".to_string(),
            data_type: DataType::String,
            description: "Type of check (informational)".to_string(),
            example_values: vec!["enforcement".to_string()],
            validation_notes: Some("Optional field".to_string()),
        });

    // State requirements
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "mode".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "SELinux enforcement mode".to_string(),
            example_values: vec![
                "Enforcing".to_string(),
                "Permissive".to_string(),
                "Disabled".to_string(),
            ],
            validation_notes: Some("From getenforce command".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "enforcing".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether SELinux is in enforcing mode".to_string(),
            example_values: vec!["true".to_string(), "false".to_string()],
            validation_notes: Some("true if mode is Enforcing".to_string()),
        });

    // Field mappings
    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["mode".to_string(), "enforcing".to_string()];

    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("mode".to_string(), "mode".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("enforcing".to_string(), "enforcing".to_string());

    // Collection strategy
    contract.collection_strategy = CollectionStrategy {
        collector_type: "command".to_string(),
        collection_mode: CollectionMode::Command,
        required_capabilities: vec!["execute_getenforce".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(20),
            memory_usage_mb: Some(1),
            network_intensive: false,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract
}
