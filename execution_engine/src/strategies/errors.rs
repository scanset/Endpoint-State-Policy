// src/strategies/errors.rs
//! Error types for CTN strategy module
//!
//! Comprehensive error handling for CTN contracts, collection, and execution

use crate::types::common::{DataType, Operation};

/// CTN contract validation and compatibility errors
#[derive(Debug, thiserror::Error)]
pub enum CtnContractError {
    #[error("Object field '{field}' required for CTN type '{ctn_type}' but not found in object '{object_id}'")]
    MissingRequiredObjectField {
        ctn_type: String,
        object_id: String,
        field: String,
    },

    #[error("State field '{field}' not supported by CTN type '{ctn_type}'")]
    UnsupportedStateField { ctn_type: String, field: String },

    #[error(
        "Operation '{operation:?}' not allowed for state field '{field}' in CTN type '{ctn_type}'"
    )]
    UnsupportedFieldOperation {
        ctn_type: String,
        field: String,
        operation: Operation,
    },

    #[error("Field type mismatch: field '{field}' expected {expected:?}, got {actual:?}")]
    FieldTypeMismatch {
        field: String,
        expected: DataType,
        actual: DataType,
    },

    #[error("Object field '{field}' has invalid type {actual:?} for CTN '{ctn_type}', expected {expected:?}")]
    ObjectFieldTypeMismatch {
        ctn_type: String,
        field: String,
        expected: DataType,
        actual: DataType,
    },

    #[error("State field '{field}' has invalid type {actual:?} for CTN '{ctn_type}', expected {expected:?}")]
    StateFieldTypeMismatch {
        ctn_type: String,
        field: String,
        expected: DataType,
        actual: DataType,
    },

    #[error("Field mapping error in CTN '{ctn_type}': {reason}")]
    FieldMappingError { ctn_type: String, reason: String },

    #[error("Collection mapping validation failed for CTN '{ctn_type}': {reason}")]
    CollectionMappingError { ctn_type: String, reason: String },

    #[error("Validation mapping validation failed for CTN '{ctn_type}': {reason}")]
    ValidationMappingError { ctn_type: String, reason: String },

    #[error("Computed field '{field}' error: {reason}")]
    ComputedFieldError { field: String, reason: String },

    #[error("Circular dependency detected in computed fields: {cycle:?}")]
    CircularComputedFieldDependency { cycle: Vec<String> },

    #[error("CTN contract validation failed for '{ctn_type}': {reason}")]
    ContractValidationFailed { ctn_type: String, reason: String },

    #[error("Collection strategy validation failed: {reason}")]
    CollectionStrategyError { reason: String },

    #[error("Required capability '{capability}' not satisfied by collection strategy")]
    MissingRequiredCapability { capability: String },

    #[error("Inconsistent field mappings: collection field '{collection_field}' maps to validation field '{validation_field}' but validation expects '{expected_field}'")]
    InconsistentFieldMappings {
        collection_field: String,
        validation_field: String,
        expected_field: String,
    },
    #[error("Behavior '{behavior}' not supported by CTN type '{ctn_type}'. Supported behaviors: {supported_behaviors:?}")]
    UnsupportedBehavior {
        ctn_type: String,
        behavior: String,
        supported_behaviors: Vec<String>,
    },
}

/// Strategy registry and management errors
#[derive(Debug, thiserror::Error)]
pub enum StrategyError {
    #[error("Unknown CTN type: {0}")]
    UnknownCtnType(String),

    #[error("Collector '{collector_id}' does not support CTN type '{ctn_type}'")]
    CollectorCtnMismatch {
        collector_id: String,
        ctn_type: String,
    },

    #[error("Executor for CTN type '{ctn_type}' does not match expected contract")]
    ExecutorContractMismatch { ctn_type: String },

    #[error("Collector not found: {0}")]
    CollectorNotFound(String),

    #[error("Executor not found for CTN type: {0}")]
    ExecutorNotFound(String),

    #[error("CTN contract error: {0}")]
    ContractError(#[from] CtnContractError),

    #[error("Strategy registration failed for CTN '{ctn_type}': {reason}")]
    RegistrationFailed { ctn_type: String, reason: String },

    #[error("CTN validation failed: {errors:?}")]
    CtnValidationFailed { errors: Vec<String> },

    #[error("Duplicate CTN type registration: {ctn_type}")]
    DuplicateCtnType { ctn_type: String },

    #[error("Registry is empty - no CTN strategies registered")]
    EmptyRegistry,

    #[error("Registry corruption detected: {reason}")]
    RegistryCorruption { reason: String },

    #[error("Strategy incompatibility: {reason}")]
    StrategyIncompatibility { reason: String },
}

/// Data collection errors
#[derive(Debug, thiserror::Error)]
pub enum CollectionError {
    #[error("Collection failed for object '{object_id}': {reason}")]
    CollectionFailed { object_id: String, reason: String },

    #[error("CTN contract validation failed: {reason}")]
    CtnContractValidation { reason: String },

    #[error("Required capability missing: {capability}")]
    MissingCapability { capability: String },

    #[error("Platform error: {message}")]
    PlatformError { message: String },

    #[error("Required collection field missing: {field}")]
    MissingCollectionField { field: String },

    #[error("Collection timeout for object '{object_id}' after {timeout_ms}ms")]
    CollectionTimeout { object_id: String, timeout_ms: u64 },

    #[error("Access denied for object '{object_id}': {reason}")]
    AccessDenied { object_id: String, reason: String },

    #[error("Object not found: {object_id}")]
    ObjectNotFound { object_id: String },

    #[error("Invalid object configuration for '{object_id}': {reason}")]
    InvalidObjectConfiguration { object_id: String, reason: String },

    #[error("Collection mode '{mode:?}' not supported by collector '{collector_id}'")]
    UnsupportedCollectionMode { collector_id: String, mode: String },

    #[error("CTN type '{ctn_type}' not supported by collector '{collector_id}'")]
    UnsupportedCtnType {
        ctn_type: String,
        collector_id: String,
    },

    #[error("Field extraction failed: field '{field}' not accessible in collected data")]
    FieldExtractionFailed { field: String },

    #[error("Data format error: {reason}")]
    DataFormatError { reason: String },

    #[error("Resource limit exceeded: {limit_type}")]
    ResourceLimitExceeded { limit_type: String },
}

/// CTN execution errors
#[derive(Debug, thiserror::Error)]
pub enum CtnExecutionError {
    #[error("Execution failed for CTN '{ctn_type}': {reason}")]
    ExecutionFailed { ctn_type: String, reason: String },

    #[error("Collected data validation failed: {reason}")]
    DataValidationFailed { reason: String },

    #[error("State validation failed for state '{state_id}': {reason}")]
    StateValidationFailed { state_id: String, reason: String },

    #[error("CTN contract violation: {reason}")]
    ContractViolation { reason: String },

    #[error("Required data field missing: {field}")]
    MissingDataField { field: String },

    #[error("Field computation failed for '{field}': {reason}")]
    FieldComputationFailed { field: String, reason: String },

    #[error("Test specification validation failed: {reason}")]
    TestSpecValidationFailed { reason: String },

    #[error("Object '{object_id}' failed state validation: {failed_fields:?}")]
    ObjectStateValidationFailed {
        object_id: String,
        failed_fields: Vec<String>,
    },

    #[error("Existence check failed: expected {expected} objects, found {found}")]
    ExistenceCheckFailed { expected: usize, found: usize },

    #[error("Item check failed: {passing} of {total} objects passed, but {item_check} requires different outcome")]
    ItemCheckFailed {
        item_check: String,
        passing: usize,
        total: usize,
    },

    #[error("State operator '{operator}' evaluation failed: {reason}")]
    StateOperatorFailed { operator: String, reason: String },

    #[error("No collected data available for validation")]
    NoCollectedData,

    #[error("Inconsistent execution state: {reason}")]
    InconsistentExecutionState { reason: String },

    #[error("Execution timeout after {timeout_ms}ms")]
    ExecutionTimeout { timeout_ms: u64 },
}

/// Validation report for CTN criterion compatibility
#[derive(Debug, Clone)]
pub struct ValidationReport {
    pub errors: Vec<ValidationError>,
    pub warnings: Vec<ValidationWarning>,
    pub ctn_type: String,
}

#[derive(Debug, Clone)]
pub struct ValidationError {
    pub error_type: ValidationErrorType,
    pub message: String,
    pub context: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ValidationWarning {
    pub warning_type: ValidationWarningType,
    pub message: String,
    pub suggestion: Option<String>,
}

#[derive(Debug, Clone)]
pub struct BehaviorValidationError {
    pub behavior_name: String,
    pub reason: String,
    pub supported_behaviors: Vec<String>,
}

#[derive(Debug, Clone)]
pub enum ValidationErrorType {
    MissingRequiredField,
    InvalidFieldType,
    UnsupportedOperation,
    FieldMappingError,
    ContractViolation,
}

#[derive(Debug, Clone)]
pub enum ValidationWarningType {
    UnrecognizedField,
    SuboptimalConfiguration,
    PerformanceImpact,
    DeprecatedUsage,
}

impl ValidationReport {
    pub fn new(ctn_type: String) -> Self {
        Self {
            errors: Vec::new(),
            warnings: Vec::new(),
            ctn_type,
        }
    }

    pub fn add_error(
        &mut self,
        error_type: ValidationErrorType,
        message: String,
        context: Option<String>,
    ) {
        self.errors.push(ValidationError {
            error_type,
            message,
            context,
        });
    }

    pub fn add_warning(
        &mut self,
        warning_type: ValidationWarningType,
        message: String,
        suggestion: Option<String>,
    ) {
        self.warnings.push(ValidationWarning {
            warning_type,
            message,
            suggestion,
        });
    }

    pub fn is_valid(&self) -> bool {
        self.errors.is_empty()
    }

    pub fn has_warnings(&self) -> bool {
        !self.warnings.is_empty()
    }

    pub fn error_count(&self) -> usize {
        self.errors.len()
    }

    pub fn warning_count(&self) -> usize {
        self.warnings.len()
    }
}

/// Convert strategy errors to execution errors
impl From<StrategyError> for CtnExecutionError {
    fn from(err: StrategyError) -> Self {
        match err {
            StrategyError::UnknownCtnType(ctn_type) => CtnExecutionError::ExecutionFailed {
                ctn_type,
                reason: "CTN type not registered".to_string(),
            },
            StrategyError::ContractError(contract_err) => CtnExecutionError::ContractViolation {
                reason: contract_err.to_string(),
            },
            StrategyError::CtnValidationFailed { errors } => CtnExecutionError::ExecutionFailed {
                ctn_type: "unknown".to_string(),
                reason: format!("Validation failed: {}", errors.join(", ")),
            },
            _ => CtnExecutionError::ExecutionFailed {
                ctn_type: "unknown".to_string(),
                reason: err.to_string(),
            },
        }
    }
}

/// Convert collection errors to execution errors
impl From<CollectionError> for CtnExecutionError {
    fn from(err: CollectionError) -> Self {
        match err {
            CollectionError::CollectionFailed { object_id, reason } => {
                CtnExecutionError::DataValidationFailed {
                    reason: format!("Collection failed for {}: {}", object_id, reason),
                }
            }
            CollectionError::MissingCollectionField { field } => {
                CtnExecutionError::MissingDataField { field }
            }
            CollectionError::AccessDenied { object_id, reason } => {
                CtnExecutionError::DataValidationFailed {
                    reason: format!("Access denied for {}: {}", object_id, reason),
                }
            }
            _ => CtnExecutionError::DataValidationFailed {
                reason: err.to_string(),
            },
        }
    }
}
