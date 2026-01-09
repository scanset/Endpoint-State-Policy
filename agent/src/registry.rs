//! Scanner Registry Setup
//!
//! Creates and configures the CTN strategy registry with all available
//! collectors and executors for the agent.

use contract_kit::execution_api::strategies::{CtnStrategyRegistry, StrategyError};
use contract_kit::{collectors, commands, contracts, executors};

/// Create a registry with all available strategies
///
/// Includes:
/// - File metadata validation (fast stat-based checks)
/// - File content validation (string operations)
/// - JSON record validation (structured data)
/// - TCP listener validation (port listening state)
/// - Kubernetes resource validation (K8s API objects)
/// - Computed values validation (derived/calculated values)
pub fn create_scanner_registry() -> Result<CtnStrategyRegistry, StrategyError> {
    let mut registry = CtnStrategyRegistry::new();

    // Register file system strategies
    let metadata_contract = contracts::create_file_metadata_contract();
    let content_contract = contracts::create_file_content_contract();
    let json_contract = contracts::create_json_record_contract();
    let computed_values_contract = contracts::create_computed_values_contract();

    registry.register_ctn_strategy(
        Box::new(collectors::FileSystemCollector::new()),
        Box::new(executors::FileMetadataExecutor::new(metadata_contract)),
    )?;

    registry.register_ctn_strategy(
        Box::new(collectors::FileSystemCollector::new()),
        Box::new(executors::FileContentExecutor::new(content_contract)),
    )?;

    registry.register_ctn_strategy(
        Box::new(collectors::ComputedValuesCollector::new()),
        Box::new(executors::ComputedValuesExecutor::new(
            computed_values_contract,
        )),
    )?;

    registry.register_ctn_strategy(
        Box::new(collectors::FileSystemCollector::new()),
        Box::new(executors::JsonRecordExecutor::new(json_contract)),
    )?;

    // Register TCP listener strategy
    let tcp_listener_contract = contracts::create_tcp_listener_contract();
    registry.register_ctn_strategy(
        Box::new(collectors::TcpListenerCollector::new()),
        Box::new(executors::TcpListenerExecutor::new(tcp_listener_contract)),
    )?;

    // Register Kubernetes resource strategy
    let k8s_executor = commands::create_k8s_command_executor();
    let k8s_collector =
        collectors::K8sResourceCollector::new("k8s-resource-collector", k8s_executor);
    let k8s_resource_contract = contracts::create_k8s_resource_contract();
    registry.register_ctn_strategy(
        Box::new(k8s_collector),
        Box::new(executors::K8sResourceExecutor::new(k8s_resource_contract)),
    )?;

    Ok(registry)
}
