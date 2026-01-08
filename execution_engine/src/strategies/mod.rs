// src/strategies/mod.rs
//! CTN strategy module for contract-based compliance validation
//!
//! This module provides the foundation for extensible compliance checking through
//! CTN (Criterion Type Node) contracts that define explicit field requirements,
//! mappings, and validation rules.
//!
//! # Architecture Overview
//!
//! The strategies module implements a contract-based approach where:
//! - **CTN Contracts** define what object/state fields are required
//! - **Data Collectors** gather platform-specific data according to contracts
//! - **Executors** perform compliance validation using collected data
//! - **Registry** manages and validates strategy registration
//!
//! # Key Components
//!
//! - [`CtnContract`] - Complete specification for CTN type requirements
//! - [`CtnDataCollector`] - Platform-specific data collection trait
//! - [`CtnExecutor`] - Compliance validation execution trait
//! - [`CtnStrategyRegistry`] - Central registry for strategy management
//!
//! # Example Usage
//!
//! ```

pub mod command_executor;
pub mod ctn_contract;
pub mod errors;
pub mod registry;
pub mod traits;
pub mod validation;

// Re-export core types for public API
pub use ctn_contract::{
    BehaviorParameter, BehaviorType, CollectionMappings, CollectionMode, CollectionStrategy,
    ComputedField, CtnContract, CtnFieldMappings, CtnMetadata, FieldComputation, ObjectFieldSpec,
    ObjectRequirements, PerformanceHints, StateFieldSpec, StateRequirements, SupportedBehavior,
    ValidationMappings,
};

pub use errors::{
    BehaviorValidationError, CollectionError, CtnContractError, CtnExecutionError, StrategyError,
    ValidationError, ValidationErrorType, ValidationReport, ValidationWarning,
    ValidationWarningType,
};

pub use registry::{
    ContractDetails, ContractValidationResult, CtnStrategyRegistry, RegistryBuilder,
    RegistryHealth, RegistryQuery, RegistryStatistics,
};

pub use traits::{
    CollectedData, CollectionMetadata, CollectorPerformanceProfile, CtnDataCollector,
    CtnExecutionResult, CtnExecutor, DefaultTestProcessor, ExecutionMetadata, ExistenceResult,
    FieldValidationResult, ItemCheckResult, StateValidationResult, TestPhase, TestProcessor,
};

pub use validation::{CtnCompatibilityChecker, CtnContractValidator};

pub use command_executor::{CommandError, CommandOutput, SystemCommandExecutor};

// ============================================================================
// Module-level convenience functions
// ============================================================================

/// Create a new CTN strategy registry with validation enabled
pub fn create_registry() -> CtnStrategyRegistry {
    CtnStrategyRegistry::new()
}

/// Create a registry builder for fluent configuration
pub fn registry_builder() -> RegistryBuilder {
    RegistryBuilder::new()
}

/// Validate a CTN contract for consistency
pub fn validate_contract(contract: &CtnContract) -> Result<(), CtnContractError> {
    CtnContractValidator::validate_contract(contract)
}

/// Create a validation report for a criterion against a contract
pub fn validate_criterion(
    criterion: &crate::types::execution_context::ExecutableCriterion,
    contract: &CtnContract,
) -> ValidationReport {
    CtnContractValidator::validate_criterion_against_contract(criterion, contract)
}
