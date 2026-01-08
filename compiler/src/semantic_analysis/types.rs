//! Consolidated semantic analysis types - Updated with Global Logging and Compile-Time Security Limits
//!
//! This module provides all the shared types needed across semantic analysis modules
//! with proper integration to the global logging system and SSDF-compliant security boundaries.
use common::ast::nodes::{DataType, Operation, RuntimeOperationType, SetOperationType};
use common::config::constants::compile_time::semantic::*;
use common::log_error;
use common::logging::codes;
use common::utils::Span;
use thiserror::Error;

/// Result type for semantic analysis operations
pub type SemanticResult<T> = Result<T, SemanticError>;

/// Semantic error types with proper error code mapping and security-bounded messages
#[derive(Debug, Clone, Error)]
pub enum SemanticError {
    /// Type incompatibility error (E180)
    #[error("Type incompatibility: operation '{operation}' cannot be used with data type '{data_type}' on field '{field_name}' at {span}")]
    TypeIncompatibility {
        field_name: String,
        data_type: DataType,
        operation: Operation,
        span: Span,
    },

    /// Runtime operation type error (E181)
    #[error("Runtime operation '{operation_type}' type error for variable '{variable_name}': {reason} at {span}")]
    RuntimeOperationError {
        variable_name: String,
        operation_type: RuntimeOperationType,
        reason: String,
        span: Span,
    },

    /// SET constraint violation (E200)
    #[error("SET operation '{operation_type}' on set '{set_id}' violates constraints: {reason} at {span}")]
    SetConstraintViolation {
        set_id: String,
        operation_type: SetOperationType,
        reason: String,
        span: Span,
    },

    /// Circular dependency detected (E140)
    #[error("Circular dependency detected in {dependency_type}: {cycle_description} at {span}")]
    CircularDependency {
        dependency_type: String,
        cycle_description: String,
        cycle_path: Vec<String>,
        span: Span,
    },

    /// Internal validation error (E180)
    #[error("Internal semantic validation error: {message}")]
    InternalError { message: String },
}

impl SemanticError {
    /// Get the appropriate error code for this error type
    pub fn error_code(&self) -> codes::Code {
        match self {
            SemanticError::TypeIncompatibility { .. } => codes::semantic::TYPE_INCOMPATIBILITY,
            SemanticError::RuntimeOperationError { .. } => codes::semantic::RUNTIME_OPERATION_ERROR,
            SemanticError::SetConstraintViolation { .. } => {
                codes::semantic::SET_CONSTRAINT_VIOLATION
            }
            SemanticError::CircularDependency { .. } => codes::references::CIRCULAR_DEPENDENCY,
            SemanticError::InternalError { .. } => codes::semantic::TYPE_INCOMPATIBILITY,
        }
    }

    /// Get error type string for logging context
    pub fn error_type(&self) -> &'static str {
        match self {
            SemanticError::TypeIncompatibility { .. } => "TypeIncompatibility",
            SemanticError::RuntimeOperationError { .. } => "RuntimeOperationError",
            SemanticError::SetConstraintViolation { .. } => "SetConstraintViolation",
            SemanticError::CircularDependency { .. } => "CircularDependency",
            SemanticError::InternalError { .. } => "InternalError",
        }
    }

    /// Check if this error requires halting
    pub fn requires_halt(&self) -> bool {
        common::logging::codes::requires_halt(self.error_code().as_str())
    }

    /// Get error span if available
    pub fn span(&self) -> Option<Span> {
        match self {
            Self::TypeIncompatibility { span, .. }
            | Self::RuntimeOperationError { span, .. }
            | Self::SetConstraintViolation { span, .. }
            | Self::CircularDependency { span, .. } => Some(*span),
            Self::InternalError { .. } => None,
        }
    }

    /// Get error severity
    pub fn severity(&self) -> &'static str {
        common::logging::codes::get_severity(self.error_code().as_str()).as_str()
    }

    /// Check if error is recoverable
    pub fn is_recoverable(&self) -> bool {
        common::logging::codes::is_recoverable(self.error_code().as_str())
    }

    // Constructor methods with security-bounded message lengths

    /// Create type incompatibility error
    pub fn type_incompatibility(
        field_name: &str,
        data_type: DataType,
        operation: Operation,
        span: Span,
    ) -> Self {
        Self::TypeIncompatibility {
            field_name: Self::truncate_string(field_name),
            data_type,
            operation,
            span,
        }
    }

    /// Create runtime operation error with message length validation
    pub fn runtime_operation_error(
        variable_name: &str,
        operation_type: RuntimeOperationType,
        reason: &str,
        span: Span,
    ) -> Self {
        // SECURITY: Truncate excessively long error messages to prevent memory attacks
        let truncated_reason = Self::truncate_message(reason);

        Self::RuntimeOperationError {
            variable_name: Self::truncate_string(variable_name),
            operation_type,
            reason: truncated_reason,
            span,
        }
    }

    /// Create SET constraint violation error with message length validation
    pub fn set_constraint_violation(
        set_id: &str,
        operation_type: SetOperationType,
        reason: &str,
        span: Span,
    ) -> Self {
        // SECURITY: Truncate excessively long error messages to prevent memory attacks
        let truncated_reason = Self::truncate_message(reason);

        Self::SetConstraintViolation {
            set_id: Self::truncate_string(set_id),
            operation_type,
            reason: truncated_reason,
            span,
        }
    }

    /// Create circular dependency error with cycle path length validation
    pub fn circular_dependency(dependency_type: &str, cycle_path: Vec<String>, span: Span) -> Self {
        // SECURITY: Limit cycle path length to prevent DoS via deep cycle reporting
        let limited_cycle_path = if cycle_path.len() > MAX_CYCLE_PATH_LENGTH {
            let mut truncated = cycle_path
                .get(..MAX_CYCLE_PATH_LENGTH)
                .map(|s| s.to_vec())
                .unwrap_or_else(|| cycle_path.to_vec());
            truncated.push("... [truncated for security]".to_string());
            truncated
        } else {
            cycle_path
        };

        let cycle_description = if !limited_cycle_path.is_empty() {
            format!(
                "{} -> {}",
                limited_cycle_path.join(" -> "),
                limited_cycle_path.first().cloned().unwrap_or_default()
            )
        } else {
            "unknown cycle".to_string()
        };

        // SECURITY: Truncate cycle description if it's too long
        let truncated_description = Self::truncate_message(&cycle_description);

        Self::CircularDependency {
            dependency_type: Self::truncate_string(dependency_type),
            cycle_description: truncated_description,
            cycle_path: limited_cycle_path,
            span,
        }
    }

    /// Create internal error with message length validation
    pub fn internal_error(message: &str) -> Self {
        Self::InternalError {
            message: Self::truncate_message(message),
        }
    }

    /// Helper function to truncate strings to prevent excessive memory usage
    fn truncate_string(input: &str) -> String {
        if input.len() > 255 {
            format!("{}... [truncated]", &input[..252])
        } else {
            input.to_string()
        }
    }

    /// Helper function to truncate error messages to security-bounded length
    fn truncate_message(message: &str) -> String {
        if message.len() > MAX_ERROR_MESSAGE_LENGTH {
            format!(
                "{}... [truncated for security]",
                &message[..MAX_ERROR_MESSAGE_LENGTH - 30]
            )
        } else {
            message.to_string()
        }
    }

    /// Log this error using global logging macros
    pub fn log_error(&self) {
        match self.span() {
            Some(span) => {
                log_error!(self.error_code(), &self.to_string(),
                    span = span,
                    "error_type" => self.error_type(),
                    "severity" => self.severity(),
                    "recoverable" => self.is_recoverable());
            }
            None => {
                log_error!(self.error_code(), &self.to_string(),
                    "error_type" => self.error_type(),
                    "severity" => self.severity(),
                    "recoverable" => self.is_recoverable());
            }
        }

        // Add type-specific context
        match self {
            SemanticError::TypeIncompatibility {
                field_name,
                data_type,
                operation,
                ..
            } => {
                log_error!(self.error_code(), "Type incompatibility details",
                    "field_name" => field_name,
                    "data_type" => data_type.as_str(),
                    "operation" => operation.as_str());
            }
            SemanticError::RuntimeOperationError {
                variable_name,
                operation_type,
                ..
            } => {
                log_error!(self.error_code(), "Runtime operation error details",
                    "variable_name" => variable_name,
                    "operation_type" => operation_type.as_str());
            }
            SemanticError::SetConstraintViolation {
                set_id,
                operation_type,
                ..
            } => {
                log_error!(self.error_code(), "SET constraint violation details",
                    "set_id" => set_id,
                    "operation_type" => operation_type.as_str());
            }
            SemanticError::CircularDependency {
                dependency_type,
                cycle_path,
                ..
            } => {
                log_error!(self.error_code(), "Circular dependency details",
                    "dependency_type" => dependency_type,
                    "cycle_length" => cycle_path.len(),
                    "truncated" => cycle_path.iter().any(|p| p.contains("truncated")));
            }
            SemanticError::InternalError { .. } => {
                // No additional context for internal errors
            }
        }
    }
}

/// Input data for semantic analysis
#[derive(Debug)]
pub struct SemanticInput {
    pub ast: common::ast::nodes::EspFile,
    pub symbols: crate::symbols::SymbolDiscoveryResult,
    pub validation_result: crate::reference_resolution::ReferenceValidationResult,
}

impl SemanticInput {
    pub fn new(
        ast: common::ast::nodes::EspFile,
        symbols: crate::symbols::SymbolDiscoveryResult,
        validation_result: crate::reference_resolution::ReferenceValidationResult,
    ) -> Self {
        Self {
            ast,
            symbols,
            validation_result,
        }
    }

    /// Get total number of fields across all states for metrics
    pub fn total_field_count(&self) -> usize {
        let mut count = 0;

        // Count global state fields
        for state in &self.ast.definition.states {
            count += state.fields.len();
        }

        // Count criterion state fields recursively
        for criteria in &self.ast.definition.criteria {
            count += self.count_criteria_fields(criteria);
        }

        count
    }

    /// Recursively count fields in criteria
    fn count_criteria_fields(&self, criteria_node: &common::ast::nodes::CriteriaNode) -> usize {
        use common::ast::nodes::CriteriaContent;

        let mut count = 0;

        for content in &criteria_node.content {
            match content {
                CriteriaContent::Criteria(nested) => {
                    count += self.count_criteria_fields(nested);
                }
                CriteriaContent::Criterion(ctn) => {
                    for state in &ctn.local_states {
                        count += state.fields.len();
                    }
                }
            }
        }

        count
    }

    /// Get summary information for logging
    pub fn get_summary(&self) -> String {
        format!(
            "{} states, {} criteria, {} variables, {} runtime ops, {} sets, {} total fields",
            self.ast.definition.states.len(),
            self.ast.definition.criteria.len(),
            self.symbols.global_symbols.variables.len(),
            self.ast.definition.runtime_operations.len(),
            self.ast.definition.set_operations.len(),
            self.total_field_count()
        )
    }
}

/// Output data from semantic analysis with security-aware error handling
#[derive(Debug, Clone)]
pub struct SemanticOutput {
    pub errors: Vec<SemanticError>,
    pub is_successful: bool,
    pub error_limit_reached: bool,
}

impl SemanticOutput {
    pub fn new() -> Self {
        Self {
            errors: Vec::new(),
            is_successful: false,
            error_limit_reached: false,
        }
    }

    /// Create successful output with no errors
    pub fn success() -> Self {
        Self {
            errors: Vec::new(),
            is_successful: true,
            error_limit_reached: false,
        }
    }

    /// Create failed output with errors
    pub fn with_errors(errors: Vec<SemanticError>) -> Self {
        let is_successful = errors.is_empty();
        let error_limit_reached = errors.len() >= MAX_SEMANTIC_ERRORS;

        Self {
            errors,
            is_successful,
            error_limit_reached,
        }
    }

    /// Add an error to the output with security limit checking
    pub fn add_error(&mut self, error: SemanticError) {
        if self.errors.len() < MAX_SEMANTIC_ERRORS {
            self.errors.push(error);
            self.is_successful = false;

            if self.errors.len() >= MAX_SEMANTIC_ERRORS {
                self.error_limit_reached = true;
            }
        }
    }

    /// Check if any errors require halting
    pub fn has_halt_required_errors(&self) -> bool {
        self.errors.iter().any(|e| e.requires_halt())
    }

    /// Get error count by type
    pub fn error_count_by_type(&self, error_type: &str) -> usize {
        self.errors
            .iter()
            .filter(|e| e.error_type() == error_type)
            .count()
    }

    /// Get all critical errors
    pub fn critical_errors(&self) -> Vec<&SemanticError> {
        self.errors
            .iter()
            .filter(|e| e.severity() == "Critical")
            .collect()
    }

    /// Get simple summary string
    pub fn summary(&self) -> String {
        if self.is_successful {
            "Success".to_string()
        } else if self.error_limit_reached {
            format!("{} errors (limit reached)", self.errors.len())
        } else {
            format!("{} errors", self.errors.len())
        }
    }

    /// Check if error collection was truncated due to security limits
    pub fn is_truncated(&self) -> bool {
        self.error_limit_reached
    }
}

impl Default for SemanticOutput {
    fn default() -> Self {
        Self::new()
    }
}
