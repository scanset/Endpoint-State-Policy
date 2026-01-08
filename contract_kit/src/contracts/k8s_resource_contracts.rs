//! Kubernetes Resource CTN contract
//!
//! Validates Kubernetes API resources using kubectl.
//! Returns resource JSON as RecordData for record check validation.

use execution_engine::strategies::{
    CollectionMode, CollectionStrategy, CtnContract, ObjectFieldSpec, PerformanceHints,
    StateFieldSpec,
};
use execution_engine::types::common::{DataType, Operation};

/// Create contract for k8s_resource CTN type
///
/// Queries Kubernetes API via kubectl and returns resource as RecordData.
/// Supports Pod, Namespace, Service, Deployment, StatefulSet, DaemonSet.
pub fn create_k8s_resource_contract() -> CtnContract {
    let mut contract = CtnContract::new("k8s_resource".to_string());

    // Object requirements
    contract
        .object_requirements
        .add_required_field(ObjectFieldSpec {
            name: "kind".to_string(),
            data_type: DataType::String,
            description: "Kubernetes resource kind".to_string(),
            example_values: vec![
                "Pod".to_string(),
                "Namespace".to_string(),
                "Service".to_string(),
                "Deployment".to_string(),
                "StatefulSet".to_string(),
                "DaemonSet".to_string(),
            ],
            validation_notes: Some("Case-sensitive resource kind".to_string()),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "namespace".to_string(),
            data_type: DataType::String,
            description: "Namespace to query (omit for all or cluster-scoped)".to_string(),
            example_values: vec!["kube-system".to_string(), "default".to_string()],
            validation_notes: Some("Omit for cluster-scoped resources like Namespace".to_string()),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "name".to_string(),
            data_type: DataType::String,
            description: "Exact resource name".to_string(),
            example_values: vec![
                "kube-apiserver-control-plane".to_string(),
                "default".to_string(),
            ],
            validation_notes: Some("Mutually exclusive with name_prefix".to_string()),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "name_prefix".to_string(),
            data_type: DataType::String,
            description: "Resource name prefix filter".to_string(),
            example_values: vec![
                "kube-apiserver-".to_string(),
                "kube-controller-manager-".to_string(),
            ],
            validation_notes: Some("Filters results where name starts with prefix".to_string()),
        });

    contract
        .object_requirements
        .add_optional_field(ObjectFieldSpec {
            name: "label_selector".to_string(),
            data_type: DataType::String,
            description: "Kubernetes label selector".to_string(),
            example_values: vec![
                "component=kube-apiserver".to_string(),
                "app=nginx".to_string(),
            ],
            validation_notes: Some("Standard k8s label selector syntax".to_string()),
        });

    // State requirements
    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "record".to_string(),
            data_type: DataType::RecordData,
            allowed_operations: vec![Operation::Equals],
            description: "Record validation with field path queries".to_string(),
            example_values: vec!["See record_checks".to_string()],
            validation_notes: Some("Use record checks for JSON path validation".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "found".to_string(),
            data_type: DataType::Boolean,
            allowed_operations: vec![Operation::Equals, Operation::NotEqual],
            description: "Whether matching resource was found".to_string(),
            example_values: vec!["true".to_string(), "false".to_string()],
            validation_notes: Some("Check resource existence".to_string()),
        });

    contract
        .state_requirements
        .add_optional_field(StateFieldSpec {
            name: "count".to_string(),
            data_type: DataType::Int,
            allowed_operations: vec![
                Operation::Equals,
                Operation::NotEqual,
                Operation::GreaterThan,
                Operation::LessThan,
                Operation::GreaterThanOrEqual,
                Operation::LessThanOrEqual,
            ],
            description: "Number of matching resources".to_string(),
            example_values: vec!["0".to_string(), "1".to_string()],
            validation_notes: Some("Count before name_prefix filtering".to_string()),
        });

    // Field mappings - object to collection
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("kind".to_string(), "kind".to_string());
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("namespace".to_string(), "namespace".to_string());
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("name".to_string(), "name".to_string());
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("name_prefix".to_string(), "name_prefix".to_string());
    contract
        .field_mappings
        .collection_mappings
        .object_to_collection
        .insert("label_selector".to_string(), "label_selector".to_string());

    // Required data fields from collection
    contract
        .field_mappings
        .collection_mappings
        .required_data_fields = vec!["resource".to_string(), "found".to_string()];

    // Optional data fields
    contract
        .field_mappings
        .collection_mappings
        .optional_data_fields = vec!["count".to_string()];

    // State to data mappings for validation
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("record".to_string(), "resource".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("found".to_string(), "found".to_string());
    contract
        .field_mappings
        .validation_mappings
        .state_to_data
        .insert("count".to_string(), "count".to_string());

    // Collection strategy
    contract.collection_strategy = CollectionStrategy {
        collector_type: "k8s_resource".to_string(),
        collection_mode: CollectionMode::Content,
        required_capabilities: vec!["kubectl_access".to_string()],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(500),
            memory_usage_mb: Some(10),
            network_intensive: true,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };

    contract
}
