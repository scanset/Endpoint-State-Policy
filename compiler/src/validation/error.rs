//! Error types for Pass 6: Structural Validation with global logging integration

use common::logging::codes;
use common::utils::Span;
use thiserror::Error;

/// Result type for structural validation operations
pub type StructuralResult<T> = Result<T, StructuralError>;

/// Structural validation error types
#[derive(Debug, Clone, Error)]
pub enum StructuralError {
    /// Missing required definition components
    #[error("Missing required definition component: {component} at {span}")]
    MissingRequiredComponent { component: String, span: Span },

    /// Block ordering violation
    #[error("Block ordering violation in {block_type}: {violation} at {span}")]
    BlockOrderingViolation {
        block_type: String,
        violation: String,
        span: Span,
    },

    /// Implementation limit exceeded
    #[error("Implementation limit exceeded: {limit_type} has {actual_value}, maximum allowed is {limit_value}")]
    ImplementationLimitExceeded {
        limit_type: String,
        actual_value: usize,
        limit_value: usize,
    },

    /// Empty definition block
    #[error(
        "Empty definition block: definition must contain at least one criteria block at {span}"
    )]
    EmptyDefinition { span: Span },

    /// Empty criteria block
    #[error(
        "Empty criteria block: criteria must contain at least one CTN or nested CRI at {span}"
    )]
    EmptyCriteria { span: Span },

    /// Internal structural validation error
    #[error("Internal structural validation error: {message}")]
    InternalError { message: String },

    /// Structural complexity violation
    #[error("Structural complexity violation: {complexity_type} exceeds recommended threshold")]
    ComplexityViolation { complexity_type: String },

    /// Structural consistency violation
    #[error("Structural consistency violation: {inconsistency} detected at {span}")]
    ConsistencyViolation { inconsistency: String, span: Span },
}

impl StructuralError {
    /// Create missing required component error
    pub fn missing_required_component(component: &str, span: Span) -> Self {
        Self::MissingRequiredComponent {
            component: component.to_string(),
            span,
        }
    }

    /// Create block ordering violation error
    pub fn block_ordering_violation(block_type: &str, violation: &str, span: Span) -> Self {
        Self::BlockOrderingViolation {
            block_type: block_type.to_string(),
            violation: violation.to_string(),
            span,
        }
    }

    /// Create implementation limit exceeded error
    pub fn implementation_limit_exceeded(
        limit_type: &str,
        actual_value: usize,
        limit_value: usize,
    ) -> Self {
        Self::ImplementationLimitExceeded {
            limit_type: limit_type.to_string(),
            actual_value,
            limit_value,
        }
    }

    /// Create empty definition error
    pub fn empty_definition(span: Span) -> Self {
        Self::EmptyDefinition { span }
    }

    /// Create empty criteria error
    pub fn empty_criteria(span: Span) -> Self {
        Self::EmptyCriteria { span }
    }

    /// Create internal error
    pub fn internal_error(message: &str) -> Self {
        Self::InternalError {
            message: message.to_string(),
        }
    }

    /// Create complexity violation error
    pub fn complexity_violation(complexity_type: &str) -> Self {
        Self::ComplexityViolation {
            complexity_type: complexity_type.to_string(),
        }
    }

    /// Create consistency violation error
    pub fn consistency_violation(inconsistency: &str, span: Span) -> Self {
        Self::ConsistencyViolation {
            inconsistency: inconsistency.to_string(),
            span,
        }
    }

    /// Get error span if available
    pub fn span(&self) -> Option<Span> {
        match self {
            Self::MissingRequiredComponent { span, .. }
            | Self::BlockOrderingViolation { span, .. }
            | Self::EmptyDefinition { span }
            | Self::EmptyCriteria { span }
            | Self::ConsistencyViolation { span, .. } => Some(*span),
            Self::ImplementationLimitExceeded { .. }
            | Self::InternalError { .. }
            | Self::ComplexityViolation { .. } => None,
        }
    }

    /// Get appropriate error code for logging system
    pub fn error_code(&self) -> common::logging::codes::Code {
        match self {
            Self::MissingRequiredComponent { .. } => {
                codes::structural::INCOMPLETE_DEFINITION_STRUCTURE
            }
            Self::BlockOrderingViolation { .. } => codes::structural::INVALID_BLOCK_ORDERING,
            Self::ImplementationLimitExceeded { .. } => {
                codes::structural::IMPLEMENTATION_LIMIT_EXCEEDED
            }
            Self::EmptyDefinition { .. } => codes::structural::INCOMPLETE_DEFINITION_STRUCTURE,
            Self::EmptyCriteria { .. } => codes::structural::EMPTY_CRITERIA_BLOCK,
            Self::InternalError { .. } => codes::system::INTERNAL_ERROR,
            Self::ComplexityViolation { .. } => codes::structural::COMPLEXITY_VIOLATION,
            Self::ConsistencyViolation { .. } => codes::structural::CONSISTENCY_VIOLATION,
        }
    }

    /// Check if error requires halt
    pub fn requires_halt(&self) -> bool {
        match self {
            Self::InternalError { .. } => true,
            Self::ImplementationLimitExceeded { limit_type, .. } => {
                // Critical limits require halt
                matches!(
                    limit_type.as_str(),
                    "total_symbols" | "nesting_depth" | "string_literal_size"
                )
            }
            _ => false,
        }
    }

    /// Get error type for context
    pub fn error_type(&self) -> &'static str {
        match self {
            Self::MissingRequiredComponent { .. } => "MissingComponent",
            Self::BlockOrderingViolation { .. } => "BlockOrdering",
            Self::ImplementationLimitExceeded { .. } => "LimitExceeded",
            Self::EmptyDefinition { .. } => "EmptyDefinition",
            Self::EmptyCriteria { .. } => "EmptyCriteria",
            Self::InternalError { .. } => "InternalError",
            Self::ComplexityViolation { .. } => "ComplexityViolation",
            Self::ConsistencyViolation { .. } => "ConsistencyViolation",
        }
    }

    /// Get error severity level
    pub fn severity(&self) -> &'static str {
        match self {
            Self::InternalError { .. } => "Critical",
            Self::ImplementationLimitExceeded { limit_type, .. } => {
                if matches!(
                    limit_type.as_str(),
                    "total_symbols" | "nesting_depth" | "string_literal_size"
                ) {
                    "High"
                } else {
                    "Medium"
                }
            }
            Self::EmptyDefinition { .. } => "High",
            Self::MissingRequiredComponent { .. }
            | Self::BlockOrderingViolation { .. }
            | Self::ConsistencyViolation { .. } => "Medium",
            Self::EmptyCriteria { .. } | Self::ComplexityViolation { .. } => "Low",
        }
    }

    /// Get recommended action
    pub fn recommended_action(&self) -> &'static str {
        match self {
            Self::MissingRequiredComponent { .. } => {
                "Add missing required elements to complete the definition"
            }
            Self::BlockOrderingViolation { .. } => {
                "Reorder blocks according to ESP specification requirements"
            }
            Self::ImplementationLimitExceeded { .. } => {
                "Reduce complexity or increase implementation limits"
            }
            Self::EmptyDefinition { .. } => "Add at least one criteria block to the definition",
            Self::EmptyCriteria { .. } => "Add at least one CTN or nested CRI to criteria block",
            Self::InternalError { .. } => "Contact system administrator or file bug report",
            Self::ComplexityViolation { .. } => "Simplify structure to reduce complexity",
            Self::ConsistencyViolation { .. } => "Fix structural inconsistency",
        }
    }
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/// Check if any errors require halt
pub fn should_halt_on_errors(errors: &[StructuralError]) -> bool {
    errors.iter().any(|e| e.requires_halt())
}

/// Get error statistics for reporting
pub fn get_error_statistics(errors: &[StructuralError]) -> ErrorStatistics {
    let mut stats = ErrorStatistics::default();

    for error in errors {
        stats.total_count += 1;
        match error.severity() {
            "Critical" => stats.critical_count += 1,
            "High" => stats.high_count += 1,
            "Medium" => stats.medium_count += 1,
            "Low" => stats.low_count += 1,
            _ => {}
        }

        if error.requires_halt() {
            stats.halt_required_count += 1;
        }

        *stats
            .by_type
            .entry(error.error_type().to_string())
            .or_insert(0) += 1;
    }

    stats
}

/// Error statistics for reporting
#[derive(Debug, Default)]
pub struct ErrorStatistics {
    pub total_count: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub halt_required_count: usize,
    pub by_type: std::collections::HashMap<String, usize>,
}

impl ErrorStatistics {
    /// Generate a summary report
    pub fn summary(&self) -> String {
        format!(
            "Total: {}, Critical: {}, High: {}, Medium: {}, Low: {}, Halt Required: {}",
            self.total_count,
            self.critical_count,
            self.high_count,
            self.medium_count,
            self.low_count,
            self.halt_required_count
        )
    }
}
