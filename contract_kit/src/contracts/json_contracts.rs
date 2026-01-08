//! JSON record CTN contract
//!
//! Validates structured JSON data with field path queries.

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_json_record_contract() -> CtnContract {
    let mut contract = CtnContract::new("json_record".to_string());

    // Object requirements
    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "path".to_string(),
            data_type: DataType::String,
            description: "Path to JSON file".to_string(),
            example_values: vec!["scanfiles/test_data.json".to_string()],
            validation_notes: Some("Must be valid JSON file".to_string()),
        });

    // State requirements - allow record checks
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "record".to_string(),
            data_type: DataType::RecordData,
            allowed_operations: vec![Operation::Equals],
            description: "Record validation with field paths".to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: Some("Use record checks for JSON validation".to_string()),
        });

    // Field mappings
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("path".to_string(), "file_path".to_string());

    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["json_data".to_string()];

    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("record".to_string(), "json_data".to_string());

    // Collection strategy
    contract.collection_strategy = CollectionStrategy {
        collector_type: "filesystem".to_string(),
        collection_mode: CollectionMode::Content,
        required_capabilities: vec!["file_access".to_string(), "json_parsing".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(100),
            memory_usage_mb: Some(10),
            network_intensive: false,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract
}
