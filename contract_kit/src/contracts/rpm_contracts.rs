//! RPM package CTN contract
//!
//! Validates RPM package installation status and versions.

use agent_core::strategies::{
    BehaviorParameter, BehaviorType, CollectionMode, CollectionStrategy, CtnContract,
    ObjectFieldSpec, PerformanceHints, StateFieldSpec, SupportedBehavior,
};
use agent_core::types::common::{DataType, Operation};

/// Create contract for rpm_package CTN type
pub fn create_rpm_package_contract() -> CtnContract {
    let mut contract = CtnContract::new("rpm_package".to_string());

    // Object requirements
    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "package_name".to_string(),
            data_type: DataType::String,
            description: "RPM package name".to_string(),
            example_values: vec!["openssl".to_string(), "systemd".to_string()],
            validation_notes: Some("Package name without version".to_string()),
        });

    // State requirements
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "installed".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether package is installed".to_string(),
            example_values: vec!["true".to_string(), "false".to_string()],
            validation_notes: Some("Boolean value".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "version".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::GreaterThan,
                Operation::LessThan,
                Operation::GreaterThanOrEqual,
                Operation::LessThanOrEqual,
            ],
            description: "Package version".to_string(),
            example_values: vec!["3.0.7".to_string(), "1.2.3-4.el9".to_string()],
            validation_notes: Some("Version comparison as strings".to_string()),
        });

    // Field mappings
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("package_name".to_string(), "package_name".to_string());

    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["package_name".to_string(), "installed".to_string()];

    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec!["version".to_string()];

    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("installed".to_string(), "installed".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("version".to_string(), "version".to_string());

    // Collection strategy
    contract.collection_strategy = CollectionStrategy {
        collector_type: "command".to_string(),
        collection_mode: CollectionMode::Command,
        required_capabilities: vec!["execute_rpm".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(100),
            memory_usage_mb: Some(5),
            network_intensive: false,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract.add_supported_behavior(SupportedBehavior {
        name: "timeout".to_string(),
        behavior_type: BehaviorType::Parameter,
        parameters: vec![BehaviorParameter {
            name: "timeout".to_string(),
            data_type: DataType::Int,
            required: true,
            default_value: Some("5".to_string()),
            description: "Command timeout in seconds".to_string(),
        }],
        description: "Set command execution timeout".to_string(),
        example: "BEHAVIOR timeout 30".to_string(),
    });

    contract.add_supported_behavior(SupportedBehavior {
        name: "cache_results".to_string(),
        behavior_type: BehaviorType::Flag,
        parameters: vec![],
        description: "Cache command results for batch operations".to_string(),
        example: "BEHAVIOR cache_results".to_string(),
    });

    contract
}
