//! TCP Listener CTN contract
//!
//! Validates whether a TCP port is listening on the local system.
//! Used for runtime validation of network services.

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

/// Create contract for tcp_listener CTN type
///
/// Checks if a TCP port is listening on the local system by reading /proc/net/tcp.
pub fn create_tcp_listener_contract() -> CtnContract {
    let mut contract = CtnContract::new("tcp_listener".to_string());

    // Object requirements
    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "port".to_string(),
            data_type: DataType::Int,
            description: "TCP port number to check".to_string(),
            example_values: vec!["22".to_string(), "10255".to_string(), "8080".to_string()],
            validation_notes: Some("Port range 1-65535".to_string()),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "host".to_string(),
            data_type: DataType::String,
            description: "Bind address filter (default: any)".to_string(),
            example_values: vec![
                "0.0.0.0".to_string(),
                "127.0.0.1".to_string(),
                "any".to_string(),
            ],
            validation_notes: Some("Use 'any' or omit to match any bind address".to_string()),
        });

    // State requirements
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "listening".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether port is in LISTEN state".to_string(),
            example_values: vec!["true".to_string(), "false".to_string()],
            validation_notes: Some("true if any process is listening on the port".to_string()),
        });

    // Field mappings - object to collection
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("port".to_string(), "port".to_string());
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("host".to_string(), "host".to_string());

    // Required data fields from collection
    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["listening".to_string()];

    // Optional data fields
    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec!["local_address".to_string()];

    // State to data mappings for validation
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("listening".to_string(), "listening".to_string());

    // Collection strategy
    contract.collection_strategy = CollectionStrategy {
        collector_type: "tcp_listener".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["procfs_access".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(10),
            memory_usage_mb: Some(1),
            network_intensive: false,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract
}
