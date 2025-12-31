//! Systemd service CTN contract
//!
//! Validates systemd service status (active, enabled, loaded).

use agent_core::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use agent_core::types::common::{DataType, Operation};

pub fn create_systemd_service_contract() -> CtnContract {
    let mut contract = CtnContract::new("systemd_service".to_string());

    // Object requirements
    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "service_name".to_string(),
            data_type: DataType::String,
            description: "Systemd service unit name".to_string(),
            example_values: vec!["sshd.service".to_string(), "firewalld.service".to_string()],
            validation_notes: Some("Include .service suffix".to_string()),
        });

    // State requirements
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "active".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether service is active/running".to_string(),
            example_values: vec!["true".to_string(), "false".to_string()],
            validation_notes: Some("From 'systemctl is-active'".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "enabled".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether service is enabled at boot".to_string(),
            example_values: vec!["true".to_string(), "false".to_string()],
            validation_notes: Some("From 'systemctl is-enabled'".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "loaded".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether service unit is loaded".to_string(),
            example_values: vec!["true".to_string(), "false".to_string()],
            validation_notes: Some("From 'systemctl status'".to_string()),
        });

    // Field mappings
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("service_name".to_string(), "service_name".to_string());

    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["service_name".to_string()];

    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec![
        "active".to_string(),
        "enabled".to_string(),
        "loaded".to_string(),
    ];

    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("active".to_string(), "active".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("enabled".to_string(), "enabled".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("loaded".to_string(), "loaded".to_string());

    // Collection strategy
    contract.collection_strategy = CollectionStrategy {
        collector_type: "command".to_string(),
        collection_mode: CollectionMode::Command,
        required_capabilities: vec!["execute_systemctl".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(50),
            memory_usage_mb: Some(2),
            network_intensive: false,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract
}
