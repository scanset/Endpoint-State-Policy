// src/strategies/registry.rs
//! CTN strategy registry for contract-based collector and executor management
//!
//! Provides centralized registration and lookup of CTN strategies with comprehensive
//! contract validation and compatibility checking.

use crate::strategies::ctn_contract::CtnContract;
use crate::strategies::errors::{StrategyError, ValidationReport};
use crate::strategies::traits::{CtnDataCollector, CtnExecutor};
use crate::strategies::validation::{CtnCompatibilityChecker, CtnContractValidator};
use crate::types::execution_context::ExecutableCriterion;
use std::collections::HashMap;
use std::sync::Arc;

/// CTN strategy registry with contract-based validation
pub struct CtnStrategyRegistry {
    /// CTN contracts define the complete specification for each CTN type
    contracts: HashMap<String, Arc<CtnContract>>,

    /// CTN-specific data collectors
    collectors: HashMap<String, Box<dyn CtnDataCollector>>,

    /// CTN-specific executors
    executors: HashMap<String, Box<dyn CtnExecutor>>,

    /// Registry metadata and statistics
    metadata: RegistryMetadata,
}

#[derive(Debug, Clone)]
pub struct RegistryMetadata {
    pub total_ctn_types: usize,
    pub creation_time: std::time::SystemTime,
    pub last_registration: Option<std::time::SystemTime>,
    pub validation_enabled: bool,
}

impl CtnStrategyRegistry {
    /// Create a new empty registry
    pub fn new() -> Self {
        Self {
            contracts: HashMap::new(),
            collectors: HashMap::new(),
            executors: HashMap::new(),
            metadata: RegistryMetadata {
                total_ctn_types: 0,
                creation_time: std::time::SystemTime::now(),
                last_registration: None,
                validation_enabled: true,
            },
        }
    }

    /// Create registry with validation disabled (for testing)
    pub fn new_unvalidated() -> Self {
        let mut registry = Self::new();
        registry.metadata.validation_enabled = false;
        registry
    }

    /// Register complete CTN strategy (contract + collector + executor)
    pub fn register_ctn_strategy(
        &mut self,
        collector: Box<dyn CtnDataCollector>,
        executor: Box<dyn CtnExecutor>,
    ) -> Result<(), StrategyError> {
        let contract = executor.get_ctn_contract();
        let ctn_type = contract.ctn_type.clone();

        // Check for duplicate registration
        if self.contracts.contains_key(&ctn_type) {
            return Err(StrategyError::DuplicateCtnType { ctn_type });
        }

        // Validate contract if validation enabled
        if self.metadata.validation_enabled {
            CtnContractValidator::validate_contract(&contract)
                .map_err(StrategyError::ContractError)?;
        }

        // Validate collector supports this CTN type
        if !collector.supported_ctn_types().contains(&ctn_type) {
            return Err(StrategyError::CollectorCtnMismatch {
                collector_id: collector.collector_id().to_string(),
                ctn_type: ctn_type.clone(),
            });
        }

        // Validate collector can handle contract requirements
        collector
            .validate_ctn_compatibility(&contract)
            .map_err(|e| StrategyError::RegistrationFailed {
                ctn_type: ctn_type.clone(),
                reason: format!("Collector validation failed: {}", e),
            })?;

        // Validate executor contract matches
        let executor_contract = executor.get_ctn_contract();
        if executor_contract.ctn_type != ctn_type {
            return Err(StrategyError::ExecutorContractMismatch {
                ctn_type: ctn_type.clone(),
            });
        }

        // Store all components
        let collector_id = collector.collector_id().to_string();
        self.contracts.insert(ctn_type.clone(), Arc::new(contract));
        self.collectors.insert(collector_id, collector);
        self.executors.insert(ctn_type.clone(), executor);

        // Update metadata
        self.metadata.total_ctn_types += 1;
        self.metadata.last_registration = Some(std::time::SystemTime::now());

        Ok(())
    }

    /// Register CTN strategy with custom validation
    pub fn register_ctn_strategy_with_validation<F>(
        &mut self,
        collector: Box<dyn CtnDataCollector>,
        executor: Box<dyn CtnExecutor>,
        custom_validator: F,
    ) -> Result<(), StrategyError>
    where
        F: FnOnce(&CtnContract) -> Result<(), String>,
    {
        let contract = executor.get_ctn_contract();

        // Run custom validation
        custom_validator(&contract).map_err(|reason| StrategyError::RegistrationFailed {
            ctn_type: contract.ctn_type.clone(),
            reason,
        })?;

        // Continue with normal registration
        self.register_ctn_strategy(collector, executor)
    }

    /// Get CTN contract by type
    pub fn get_ctn_contract(&self, ctn_type: &str) -> Result<Arc<CtnContract>, StrategyError> {
        self.contracts
            .get(ctn_type)
            .cloned()
            .ok_or_else(|| StrategyError::UnknownCtnType(ctn_type.to_string()))
    }

    /// Get collector for CTN type
    pub fn get_collector_for_ctn(
        &self,
        ctn_type: &str,
    ) -> Result<&dyn CtnDataCollector, StrategyError> {
        // Find collector by checking which one supports this CTN type
        for collector in self.collectors.values() {
            if collector
                .supported_ctn_types()
                .contains(&ctn_type.to_string())
            {
                return Ok(collector.as_ref());
            }
        }

        Err(StrategyError::UnknownCtnType(ctn_type.to_string()))
    }

    /// Get executor for CTN type
    pub fn get_executor_for_ctn(&self, ctn_type: &str) -> Result<&dyn CtnExecutor, StrategyError> {
        self.executors
            .get(ctn_type)
            .map(|e| e.as_ref())
            .ok_or_else(|| StrategyError::UnknownCtnType(ctn_type.to_string()))
    }

    /// Validate CTN criterion compatibility
    pub fn validate_ctn_criterion(
        &self,
        criterion: &ExecutableCriterion,
    ) -> Result<ValidationReport, StrategyError> {
        let contract = self.get_ctn_contract(&criterion.criterion_type)?;
        Ok(CtnContractValidator::validate_criterion_against_contract(
            criterion, &contract,
        ))
    }

    /// Check if CTN type is registered
    pub fn has_ctn_type(&self, ctn_type: &str) -> bool {
        self.contracts.contains_key(ctn_type)
    }

    /// List all registered CTN types
    pub fn list_ctn_types(&self) -> Vec<String> {
        self.contracts.keys().cloned().collect()
    }

    /// Get registry statistics
    pub fn get_statistics(&self) -> RegistryStatistics {
        RegistryStatistics {
            total_ctn_types: self.contracts.len(),
            total_collectors: self.collectors.len(),
            total_executors: self.executors.len(),
            contracts_with_computed_fields: self
                .contracts
                .values()
                .filter(|c| {
                    !c.field_mappings
                        .validation_mappings
                        .computed_mappings
                        .is_empty()
                })
                .count(),
            average_required_object_fields: self.calculate_average_required_object_fields(),
            average_required_state_fields: self.calculate_average_required_state_fields(),
            registry_health: self.assess_registry_health(),
        }
    }

    /// Get detailed contract information
    pub fn get_contract_details(&self, ctn_type: &str) -> Result<ContractDetails, StrategyError> {
        let contract = self.get_ctn_contract(ctn_type)?;
        let collector = self.get_collector_for_ctn(ctn_type)?;
        let executor = self.get_executor_for_ctn(ctn_type)?;

        Ok(ContractDetails {
            contract: contract.clone(),
            collector_id: collector.collector_id().to_string(),
            collector_capabilities: collector.get_capabilities(),
            executor_capabilities: executor.get_executor_capabilities(),
            performance_profile: collector.get_performance_profile(),
        })
    }

    /// Validate all contracts in registry
    pub fn validate_all_contracts(&self) -> Vec<ContractValidationResult> {
        let mut results = Vec::new();

        for (ctn_type, contract) in &self.contracts {
            let validation_result = match CtnContractValidator::validate_contract(contract) {
                Ok(()) => ContractValidationResult {
                    ctn_type: ctn_type.clone(),
                    is_valid: true,
                    errors: Vec::new(),
                    warnings: Vec::new(),
                },
                Err(error) => ContractValidationResult {
                    ctn_type: ctn_type.clone(),
                    is_valid: false,
                    errors: vec![error.to_string()],
                    warnings: Vec::new(),
                },
            };
            results.push(validation_result);
        }

        results
    }

    /// Find compatible CTN types for a given contract
    pub fn find_compatible_ctn_types(&self, target_contract: &CtnContract) -> Vec<String> {
        let mut compatible = Vec::new();

        for (ctn_type, contract) in &self.contracts {
            if CtnCompatibilityChecker::are_contracts_compatible(contract, target_contract)
                .unwrap_or(false)
            {
                compatible.push(ctn_type.clone());
            }
        }

        compatible
    }

    /// Remove CTN type registration
    pub fn unregister_ctn_type(&mut self, ctn_type: &str) -> Result<(), StrategyError> {
        if !self.contracts.contains_key(ctn_type) {
            return Err(StrategyError::UnknownCtnType(ctn_type.to_string()));
        }

        // Remove contract
        self.contracts.remove(ctn_type);

        // Remove executor
        self.executors.remove(ctn_type);

        // Remove collector (find by CTN type support)
        let collector_id = self.collectors.iter().find_map(|(id, collector)| {
            if collector
                .supported_ctn_types()
                .contains(&ctn_type.to_string())
            {
                Some(id.clone())
            } else {
                None
            }
        });

        if let Some(id) = collector_id {
            self.collectors.remove(&id);
        }

        // Update metadata
        self.metadata.total_ctn_types = self.metadata.total_ctn_types.saturating_sub(1);

        Ok(())
    }

    /// Clear all registrations
    pub fn clear(&mut self) {
        self.contracts.clear();
        self.collectors.clear();
        self.executors.clear();
        self.metadata.total_ctn_types = 0;
        self.metadata.last_registration = None;
    }

    /// Enable/disable validation
    pub fn set_validation_enabled(&mut self, enabled: bool) {
        self.metadata.validation_enabled = enabled;
    }

    // Private helper methods

    fn calculate_average_required_object_fields(&self) -> f64 {
        if self.contracts.is_empty() {
            return 0.0;
        }

        let total: usize = self
            .contracts
            .values()
            .map(|c| c.object_requirements.required_fields.len())
            .sum();

        total as f64 / self.contracts.len() as f64
    }

    fn calculate_average_required_state_fields(&self) -> f64 {
        if self.contracts.is_empty() {
            return 0.0;
        }

        let total: usize = self
            .contracts
            .values()
            .map(|c| c.state_requirements.required_fields.len())
            .sum();

        total as f64 / self.contracts.len() as f64
    }

    fn assess_registry_health(&self) -> RegistryHealth {
        if self.contracts.is_empty() {
            return RegistryHealth::Empty;
        }

        let has_validation_issues = self.validate_all_contracts().iter().any(|r| !r.is_valid);

        let collector_coverage = self.collectors.len() as f64 / self.contracts.len() as f64;
        let executor_coverage = self.executors.len() as f64 / self.contracts.len() as f64;

        if has_validation_issues {
            RegistryHealth::Unhealthy
        } else if collector_coverage < 1.0 || executor_coverage < 1.0 {
            RegistryHealth::Incomplete
        } else {
            RegistryHealth::Healthy
        }
    }
}

impl Default for CtnStrategyRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Supporting Data Structures
// ============================================================================

#[derive(Debug, Clone)]
pub struct RegistryStatistics {
    pub total_ctn_types: usize,
    pub total_collectors: usize,
    pub total_executors: usize,
    pub contracts_with_computed_fields: usize,
    pub average_required_object_fields: f64,
    pub average_required_state_fields: f64,
    pub registry_health: RegistryHealth,
}

#[derive(Debug, Clone)]
pub struct ContractDetails {
    pub contract: Arc<CtnContract>,
    pub collector_id: String,
    pub collector_capabilities: Vec<String>,
    pub executor_capabilities: Vec<String>,
    pub performance_profile: crate::strategies::traits::CollectorPerformanceProfile,
}

#[derive(Debug, Clone)]
pub struct ContractValidationResult {
    pub ctn_type: String,
    pub is_valid: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryHealth {
    Healthy,    // All contracts valid, full coverage
    Incomplete, // Valid contracts but missing collectors/executors
    Unhealthy,  // Contract validation issues
    Empty,      // No registrations
}

impl RegistryHealth {
    pub fn is_healthy(self) -> bool {
        matches!(self, Self::Healthy)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Incomplete => "incomplete",
            Self::Unhealthy => "unhealthy",
            Self::Empty => "empty",
        }
    }
}

// ============================================================================
// Specialized Registry Builders
// ============================================================================

/// Builder for creating registries with common CTN types
pub struct RegistryBuilder {
    registry: CtnStrategyRegistry,
    validation_enabled: bool,
}

impl RegistryBuilder {
    pub fn new() -> Self {
        Self {
            registry: CtnStrategyRegistry::new(),
            validation_enabled: true,
        }
    }

    pub fn with_validation(mut self, enabled: bool) -> Self {
        self.validation_enabled = enabled;
        self.registry.set_validation_enabled(enabled);
        self
    }

    pub fn add_ctn_strategy(
        mut self,
        collector: Box<dyn CtnDataCollector>,
        executor: Box<dyn CtnExecutor>,
    ) -> Result<Self, StrategyError> {
        self.registry.register_ctn_strategy(collector, executor)?;
        Ok(self)
    }

    pub fn build(self) -> CtnStrategyRegistry {
        self.registry
    }
}

impl Default for RegistryBuilder {
    fn default() -> Self {
        Self::new()
    }
}

// ============================================================================
// Registry Query Interface
// ============================================================================

/// Query interface for advanced registry searches
pub struct RegistryQuery<'a> {
    registry: &'a CtnStrategyRegistry,
}

impl<'a> RegistryQuery<'a> {
    pub fn new(registry: &'a CtnStrategyRegistry) -> Self {
        Self { registry }
    }

    /// Find CTN types that support specific object fields
    pub fn find_by_object_fields(&self, required_fields: &[String]) -> Vec<String> {
        self.registry
            .contracts
            .iter()
            .filter_map(|(ctn_type, contract)| {
                let has_all_fields = required_fields
                    .iter()
                    .all(|field| contract.object_requirements.get_field_spec(field).is_some());

                if has_all_fields {
                    Some(ctn_type.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Find CTN types that support specific state fields
    pub fn find_by_state_fields(&self, required_fields: &[String]) -> Vec<String> {
        self.registry
            .contracts
            .iter()
            .filter_map(|(ctn_type, contract)| {
                let has_all_fields = required_fields
                    .iter()
                    .all(|field| contract.state_requirements.get_field_spec(field).is_some());

                if has_all_fields {
                    Some(ctn_type.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Find CTN types with specific capabilities
    pub fn find_by_capabilities(&self, required_capabilities: &[String]) -> Vec<String> {
        self.registry
            .contracts
            .iter()
            .filter_map(|(ctn_type, contract)| {
                let has_all_capabilities = required_capabilities.iter().all(|cap| {
                    contract
                        .collection_strategy
                        .required_capabilities
                        .contains(cap)
                });

                if has_all_capabilities {
                    Some(ctn_type.clone())
                } else {
                    None
                }
            })
            .collect()
    }

    /// Find CTN types by performance characteristics
    pub fn find_by_performance(
        &self,
        max_time_ms: Option<u64>,
        requires_privileges: Option<bool>,
    ) -> Vec<String> {
        self.registry
            .contracts
            .iter()
            .filter_map(|(ctn_type, contract)| {
                let hints = &contract.collection_strategy.performance_hints;

                let time_ok = max_time_ms.is_none_or( |max| {
                    hints
                        .expected_collection_time_ms
                        .is_none_or( |time| time <= max)
                });

                let privileges_ok = requires_privileges.is_none_or( |required| {
                    hints.requires_elevated_privileges == required
                });

                if time_ok && privileges_ok {
                    Some(ctn_type.clone())
                } else {
                    None
                }
            })
            .collect()
    }
}
