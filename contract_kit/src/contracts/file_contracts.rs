//! # File System CTN Contracts
//!
//! Contracts for file metadata and content validation.

use execution_engine::strategies::{
    BehaviorParameter, BehaviorType, CollectionMode, CollectionStrategy, CtnContract,
    ObjectFieldSpec, PerformanceHints, StateFieldSpec, SupportedBehavior,
};
use execution_engine::types::common::{DataType, Operation};

/// Create contract for file_metadata CTN type
///
/// Fast metadata collection via stat() - permissions, owner, group, existence
pub fn create_file_metadata_contract() -> CtnContract {
    let mut contract = CtnContract::new("file_metadata".to_string());

    // Object requirements
    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "path".to_string(),
            data_type: DataType::String,
            description: "File system path (absolute or relative)".to_string(),
            example_values: vec!["/etc/sudoers".to_string(), "scanfiles/sudoers".to_string()],
            validation_notes: Some("Supports VAR resolution".to_string()),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "type".to_string(),
            data_type: DataType::String,
            description: "Resource type indicator".to_string(),
            example_values: vec!["file".to_string()],
            validation_notes: Some("Informational only".to_string()),
        });

    // State requirements
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "permissions".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "File permissions in octal format".to_string(),
            example_values: vec!["0440".to_string(), "0644".to_string()],
            validation_notes: Some("4-digit octal format (e.g., 0440)".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "owner".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "File owner (username or UID)".to_string(),
            example_values: vec!["root".to_string(), "0".to_string()],
            validation_notes: Some("Returns UID as string on Unix".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "group".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "File group (group name or GID)".to_string(),
            example_values: vec!["root".to_string(), "0".to_string()],
            validation_notes: Some("Returns GID as string on Unix".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "exists".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether file exists".to_string(),
            example_values: vec!["true".to_string(), "false".to_string()],
            validation_notes: Some("Boolean value".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "readable".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether file is readable by current process".to_string(),
            example_values: vec!["true".to_string(), "false".to_string()],
            validation_notes: Some("Tests read permission".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "size".to_string(),
            data_type: DataType::Int,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::GreaterThan,
                Operation::LessThan,
                Operation::GreaterThanOrEqual,
                Operation::LessThanOrEqual,
            ],
            description: "File size in bytes".to_string(),
            example_values: vec!["0".to_string(), "1024".to_string()],
            validation_notes: Some("Integer bytes".to_string()),
        });

    // Field mappings
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("path".to_string(), "target_path".to_string());

    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec![
        "file_mode".to_string(),
        "file_owner".to_string(),
        "file_group".to_string(),
        "exists".to_string(),
        "readable".to_string(),
        "file_size".to_string(),
    ];

    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("permissions".to_string(), "file_mode".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("owner".to_string(), "file_owner".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("group".to_string(), "file_group".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("exists".to_string(), "exists".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("readable".to_string(), "readable".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("size".to_string(), "file_size".to_string());

    // Collection strategy
    contract.collection_strategy = CollectionStrategy {
        collector_type: "filesystem".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec!["file_access".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(5),
            memory_usage_mb: Some(1),
            network_intensive: false,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract
}

/// Create contract for file_content CTN type
///
/// Full file content reading for string validation
pub fn create_file_content_contract() -> CtnContract {
    let mut contract = CtnContract::new("file_content".to_string());

    // Object requirements (same as metadata)
    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "path".to_string(),
            data_type: DataType::String,
            description: "File system path (absolute or relative)".to_string(),
            example_values: vec!["/etc/sudoers".to_string(), "scanfiles/sudoers".to_string()],
            validation_notes: Some("Supports VAR resolution".to_string()),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "type".to_string(),
            data_type: DataType::String,
            description: "Resource type indicator".to_string(),
            example_values: vec!["file".to_string()],
            validation_notes: Some("Informational only".to_string()),
        });

    // State requirements - content field with string operations
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "content".to_string(),
            data_type: DataType::String,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::Contains,
                Operation::NotContains,
                Operation::StartsWith,
                Operation::EndsWith,
                Operation::PatternMatch,
            ],
            description: "File content as UTF-8 string".to_string(),
            example_values: vec!["logfile=".to_string(), "NOPASSWD".to_string()],
            validation_notes: Some("Binary files will error or return as binary".to_string()),
        });

    // Field mappings
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("path".to_string(), "target_path".to_string());

    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["file_content".to_string()];

    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("content".to_string(), "file_content".to_string());

    // Collection strategy - more expensive
    contract.collection_strategy = CollectionStrategy {
        collector_type: "filesystem".to_string(),
        collection_mode: CollectionMode::Content,
        required_capabilities: vec!["file_access".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(50),
            memory_usage_mb: Some(10),
            network_intensive: false,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract.add_supported_behavior(SupportedBehavior {
        name: "recursive_scan".to_string(),
        behavior_type: BehaviorType::Flag,
        parameters: vec![BehaviorParameter {
            name: "max_depth".to_string(),
            data_type: DataType::Int,
            required: false,
            default_value: Some("3".to_string()),
            description: "Maximum directory depth for recursive scan".to_string(),
        }],
        description: "Recursively scan directories for matching files".to_string(),
        example: "BEHAVIOR recursive_scan max_depth 5".to_string(),
    });

    contract.add_supported_behavior(SupportedBehavior {
        name: "include_hidden".to_string(),
        behavior_type: BehaviorType::Flag,
        parameters: vec![],
        description: "Include hidden files (starting with .) in scan".to_string(),
        example: "BEHAVIOR include_hidden".to_string(),
    });

    contract.add_supported_behavior(SupportedBehavior {
        name: "binary_mode".to_string(),
        behavior_type: BehaviorType::Flag,
        parameters: vec![],
        description: "Collect binary files as base64-encoded data".to_string(),
        example: "BEHAVIOR binary_mode".to_string(),
    });

    contract.add_supported_behavior(SupportedBehavior {
        name: "follow_symlinks".to_string(),
        behavior_type: BehaviorType::Flag,
        parameters: vec![],
        description: "Follow symbolic links during collection".to_string(),
        example: "BEHAVIOR follow_symlinks".to_string(),
    });

    contract
}
