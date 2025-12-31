//! Error types for Reference Validation
//!
//! Integrated with global logging system and compile-time security limits.

use common::logging::codes;
use common::utils::Span;
use thiserror::Error;

/// Result type for Reference Validation operations
pub type ValidationResult<T> = Result<T, ReferenceValidationError>;

/// SSDF-compliant error types for reference validation
#[derive(Debug, Clone, Error)]
pub enum ReferenceValidationError {
    /// Undefined reference error - most common validation error
    #[error("Undefined {symbol_type} reference '{target}' at {span}")]
    UndefinedReference {
        target: String,
        symbol_type: String,
        span: Span,
    },

    /// Circular dependency detected
    #[error("Circular dependency detected: {cycle_description} at {span}")]
    CircularDependency {
        cycle: Vec<String>,
        cycle_description: String,
        span: Span,
    },

    /// Security boundary violation - compile-time limits exceeded
    #[error("Security boundary violation: {violation_type} - {message}")]
    SecurityBoundaryViolation {
        violation_type: String,
        message: String,
        current_value: usize,
        limit_value: usize,
    },

    /// Invalid reference type detected
    #[error("Invalid reference type: expected {expected_type}, found {actual_type} for '{target}' at {span}")]
    InvalidReferenceType {
        target: String,
        expected_type: String,
        actual_type: String,
        span: Span,
    },

    /// Internal validation error (system issues)
    #[error("Internal validation error: {message}")]
    InternalValidationError { message: String },

    /// Symbol table inconsistency (Pass 3 integration issues)
    #[error("Symbol table inconsistency: {message}")]
    SymbolTableInconsistency { message: String },

    /// Reference depth limit exceeded (prevents infinite loops)
    #[error("Reference depth limit exceeded: {current_depth} > {max_depth} at {span}")]
    ReferenceDepthExceeded {
        current_depth: usize,
        max_depth: usize,
        span: Span,
    },
}

impl ReferenceValidationError {
    /// Create undefined reference error
    pub fn undefined_reference(target: &str, symbol_type: &str, span: Span) -> Self {
        Self::UndefinedReference {
            target: target.to_string(),
            symbol_type: symbol_type.to_string(),
            span,
        }
    }

    /// Create circular dependency error
    pub fn circular_dependency(cycle: Vec<String>, span: Span) -> Self {
        let cycle_description = format!(
            "{} -> {}",
            cycle.join(" -> "),
            cycle.first().unwrap_or(&"unknown".to_string())
        );
        Self::CircularDependency {
            cycle,
            cycle_description,
            span,
        }
    }

    /// Create security boundary violation error
    pub fn security_boundary_violation(
        violation_type: &str,
        message: &str,
        current_value: usize,
        limit_value: usize,
    ) -> Self {
        Self::SecurityBoundaryViolation {
            violation_type: violation_type.to_string(),
            message: message.to_string(),
            current_value,
            limit_value,
        }
    }

    /// Create invalid reference type error
    pub fn invalid_reference_type(
        target: &str,
        expected_type: &str,
        actual_type: &str,
        span: Span,
    ) -> Self {
        Self::InvalidReferenceType {
            target: target.to_string(),
            expected_type: expected_type.to_string(),
            actual_type: actual_type.to_string(),
            span,
        }
    }

    /// Create reference depth exceeded error
    pub fn reference_depth_exceeded(current_depth: usize, max_depth: usize, span: Span) -> Self {
        Self::ReferenceDepthExceeded {
            current_depth,
            max_depth,
            span,
        }
    }

    /// Create internal validation error
    pub fn internal_validation_error(message: &str) -> Self {
        Self::InternalValidationError {
            message: message.to_string(),
        }
    }

    /// Create symbol table inconsistency error
    pub fn symbol_table_inconsistency(message: &str) -> Self {
        Self::SymbolTableInconsistency {
            message: message.to_string(),
        }
    }

    /// Get the appropriate error code for global logging system
    pub fn error_code(&self) -> codes::Code {
        match self {
            Self::UndefinedReference { .. } => codes::references::UNDEFINED_REFERENCE,
            Self::CircularDependency { .. } => codes::references::CIRCULAR_DEPENDENCY,
            Self::SecurityBoundaryViolation { .. } => codes::system::INTERNAL_ERROR, // Fallback to system error
            Self::InvalidReferenceType { .. } => codes::references::UNDEFINED_REFERENCE, // Fallback to undefined reference
            Self::ReferenceDepthExceeded { .. } => codes::system::INTERNAL_ERROR, // Fallback to system error
            Self::InternalValidationError { .. } => codes::system::INTERNAL_ERROR,
            Self::SymbolTableInconsistency { .. } => {
                codes::symbols::SYMBOL_TABLE_CONSTRUCTION_ERROR
            }
        }
    }

    /// Get error severity level for SSDF compliance
    pub fn severity(&self) -> &'static str {
        match self {
            Self::SecurityBoundaryViolation { .. }
            | Self::ReferenceDepthExceeded { .. }
            | Self::InternalValidationError { .. }
            | Self::SymbolTableInconsistency { .. } => "Critical",

            Self::UndefinedReference { .. }
            | Self::CircularDependency { .. }
            | Self::InvalidReferenceType { .. } => "High",
        }
    }

    /// Check if error is recoverable (SSDF: PW.8.1 DoS Protection)
    pub fn is_recoverable(&self) -> bool {
        !matches!(self.severity(), "Critical")
    }

    /// Check if error requires halting processing (SSDF compliance)
    pub fn requires_halt(&self) -> bool {
        matches!(
            self,
            Self::SecurityBoundaryViolation { .. }
                | Self::ReferenceDepthExceeded { .. }
                | Self::InternalValidationError { .. }
                | Self::SymbolTableInconsistency { .. }
        )
    }

    /// Get the span associated with this error (if any)
    pub fn span(&self) -> Option<Span> {
        match self {
            Self::UndefinedReference { span, .. }
            | Self::CircularDependency { span, .. }
            | Self::InvalidReferenceType { span, .. }
            | Self::ReferenceDepthExceeded { span, .. } => Some(*span),

            Self::SecurityBoundaryViolation { .. }
            | Self::InternalValidationError { .. }
            | Self::SymbolTableInconsistency { .. } => None,
        }
    }

    /// Get affected target identifier (if any)
    pub fn affected_target(&self) -> Option<&str> {
        match self {
            Self::UndefinedReference { target, .. } | Self::InvalidReferenceType { target, .. } => {
                Some(target)
            }

            Self::CircularDependency { cycle, .. } => cycle.first().map(|s| s.as_str()),

            Self::SecurityBoundaryViolation { .. }
            | Self::ReferenceDepthExceeded { .. }
            | Self::InternalValidationError { .. }
            | Self::SymbolTableInconsistency { .. } => None,
        }
    }

    /// Get error context for debugging and audit logging (SSDF: PW.3.1)
    pub fn context(&self) -> &'static str {
        match self {
            Self::UndefinedReference { .. } => "reference_validation",
            Self::CircularDependency { .. } => "cycle_detection",
            Self::SecurityBoundaryViolation { .. } => "security_boundary_check",
            Self::InvalidReferenceType { .. } => "reference_type_validation",
            Self::ReferenceDepthExceeded { .. } => "depth_limit_enforcement",
            Self::InternalValidationError { .. } => "internal_error",
            Self::SymbolTableInconsistency { .. } => "symbol_table_validation",
        }
    }

    /// Get recommended action for resolving this error
    pub fn recommended_action(&self) -> &'static str {
        match self {
            Self::UndefinedReference { .. } => {
                "Check symbol declarations and ensure referenced symbols exist"
            }
            Self::CircularDependency { .. } => {
                "Break circular dependencies between variables or operations"
            }
            Self::SecurityBoundaryViolation { .. } => {
                "Reduce input size or complexity to stay within security limits"
            }
            Self::InvalidReferenceType { .. } => {
                "Check that reference types match symbol declarations"
            }
            Self::ReferenceDepthExceeded { .. } => {
                "Reduce reference chain depth to prevent infinite loops"
            }
            Self::InternalValidationError { .. } => "Report internal validation system bug",
            Self::SymbolTableInconsistency { .. } => {
                "Check Pass 3 symbol discovery output for completeness"
            }
        }
    }

    /// Get human-readable description for audit logging
    pub fn description(&self) -> &'static str {
        match self {
            Self::UndefinedReference { .. } => "Reference target not found in symbol tables",
            Self::CircularDependency { .. } => {
                "Circular dependency detected in variable initialization or operations"
            }
            Self::SecurityBoundaryViolation { .. } => "Compile-time security boundary exceeded",
            Self::InvalidReferenceType { .. } => {
                "Reference type doesn't match expected symbol type"
            }
            Self::ReferenceDepthExceeded { .. } => "Reference chain depth exceeds security limit",
            Self::InternalValidationError { .. } => "Internal validation system error",
            Self::SymbolTableInconsistency { .. } => {
                "Symbol table data inconsistency between passes"
            }
        }
    }

    /// Create error summary for reporting and audit logs
    pub fn summary(&self) -> String {
        match self {
            Self::UndefinedReference {
                target,
                symbol_type,
                ..
            } => {
                format!("Undefined {} reference: '{}'", symbol_type, target)
            }
            Self::CircularDependency { cycle, .. } => {
                format!("Circular dependency: {} symbols", cycle.len())
            }
            Self::SecurityBoundaryViolation {
                violation_type,
                current_value,
                limit_value,
                ..
            } => {
                format!(
                    "Security violation ({}): {} exceeds limit {}",
                    violation_type, current_value, limit_value
                )
            }
            Self::InvalidReferenceType {
                target,
                expected_type,
                actual_type,
                ..
            } => {
                format!(
                    "Type mismatch for '{}': expected {}, found {}",
                    target, expected_type, actual_type
                )
            }
            Self::ReferenceDepthExceeded {
                current_depth,
                max_depth,
                ..
            } => {
                format!("Depth exceeded: {} > {} limit", current_depth, max_depth)
            }
            Self::InternalValidationError { message } => {
                format!(
                    "Internal error: {}",
                    message.chars().take(50).collect::<String>()
                )
            }
            Self::SymbolTableInconsistency { message } => {
                format!(
                    "Symbol table issue: {}",
                    message.chars().take(50).collect::<String>()
                )
            }
        }
    }

    /// Check if this is a security-related error (SSDF compliance)
    pub fn is_security_related(&self) -> bool {
        matches!(
            self,
            Self::SecurityBoundaryViolation { .. } | Self::ReferenceDepthExceeded { .. }
        )
    }

    /// Get security violation details for audit logging
    pub fn security_details(&self) -> Option<(String, usize, usize)> {
        match self {
            Self::SecurityBoundaryViolation {
                violation_type,
                current_value,
                limit_value,
                ..
            } => Some((violation_type.clone(), *current_value, *limit_value)),
            Self::ReferenceDepthExceeded {
                current_depth,
                max_depth,
                ..
            } => Some(("reference_depth".to_string(), *current_depth, *max_depth)),
            _ => None,
        }
    }
}

/// Helper functions for error handling with global logging and SSDF compliance
/// Check if an error should halt the entire pipeline (SSDF: PW.8.1)
pub fn should_halt_pipeline(error: &ReferenceValidationError) -> bool {
    error.requires_halt()
}

/// Get validation context from error for audit logging (SSDF: PW.3.1)
pub fn get_error_context(error: &ReferenceValidationError) -> Vec<(&'static str, String)> {
    let mut context = vec![
        ("error_type", error.context().to_string()),
        ("severity", error.severity().to_string()),
        ("recoverable", error.is_recoverable().to_string()),
        ("security_related", error.is_security_related().to_string()),
    ];

    if let Some(target) = error.affected_target() {
        context.push(("affected_target", target.to_string()));
    }

    // Add specific context based on error type
    match error {
        ReferenceValidationError::CircularDependency { cycle, .. } => {
            context.push(("cycle_length", cycle.len().to_string()));
            context.push(("cycle_nodes", cycle.join(",")));
        }
        ReferenceValidationError::UndefinedReference { symbol_type, .. } => {
            context.push(("expected_symbol_type", symbol_type.clone()));
        }
        ReferenceValidationError::SecurityBoundaryViolation {
            violation_type,
            current_value,
            limit_value,
            ..
        } => {
            context.push(("violation_type", violation_type.clone()));
            context.push(("current_value", current_value.to_string()));
            context.push(("limit_value", limit_value.to_string()));
        }
        ReferenceValidationError::InvalidReferenceType {
            expected_type,
            actual_type,
            ..
        } => {
            context.push(("expected_type", expected_type.clone()));
            context.push(("actual_type", actual_type.clone()));
        }
        ReferenceValidationError::ReferenceDepthExceeded {
            current_depth,
            max_depth,
            ..
        } => {
            context.push(("current_depth", current_depth.to_string()));
            context.push(("max_depth", max_depth.to_string()));
        }
        _ => {}
    }

    context
}

/// Create error from undefined reference with automatic error code assignment
pub fn create_undefined_reference_error(
    target: &str,
    symbol_type: &str,
    span: Span,
) -> ReferenceValidationError {
    ReferenceValidationError::undefined_reference(target, symbol_type, span)
}

/// Create error from circular dependency with automatic error code assignment
pub fn create_circular_dependency_error(
    cycle: Vec<String>,
    span: Span,
) -> ReferenceValidationError {
    ReferenceValidationError::circular_dependency(cycle, span)
}

/// Create security boundary violation error with detailed information
pub fn create_security_violation_error(
    violation_type: &str,
    message: &str,
    current_value: usize,
    limit_value: usize,
) -> ReferenceValidationError {
    ReferenceValidationError::security_boundary_violation(
        violation_type,
        message,
        current_value,
        limit_value,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::utils::{Position, Span};

    #[test]
    fn test_undefined_reference_error() {
        let span = Span::new(Position::start(), Position::start());
        let error = ReferenceValidationError::undefined_reference("missing_var", "variable", span);

        assert_eq!(error.severity(), "High");
        assert!(error.is_recoverable());
        assert!(!error.requires_halt());
        assert_eq!(error.affected_target(), Some("missing_var"));
        assert_eq!(error.context(), "reference_validation");
        assert!(!error.is_security_related());
    }

    #[test]
    fn test_security_boundary_violation() {
        let error = ReferenceValidationError::security_boundary_violation(
            "max_relationships",
            "Too many relationships",
            1000,
            500,
        );

        assert_eq!(error.severity(), "Critical");
        assert!(!error.is_recoverable());
        assert!(error.requires_halt());
        assert!(error.is_security_related());
        assert_eq!(error.context(), "security_boundary_check");

        let details = error.security_details().unwrap();
        assert_eq!(details.0, "max_relationships");
        assert_eq!(details.1, 1000);
        assert_eq!(details.2, 500);
    }

    #[test]
    fn test_reference_depth_exceeded() {
        let span = Span::new(Position::start(), Position::start());
        let error = ReferenceValidationError::reference_depth_exceeded(100, 50, span);

        assert_eq!(error.severity(), "Critical");
        assert!(error.requires_halt());
        assert!(error.is_security_related());
        assert_eq!(error.context(), "depth_limit_enforcement");
    }

    #[test]
    fn test_invalid_reference_type() {
        let span = Span::new(Position::start(), Position::start());
        let error =
            ReferenceValidationError::invalid_reference_type("test_var", "variable", "state", span);

        assert_eq!(error.severity(), "High");
        assert!(error.is_recoverable());
        assert!(!error.is_security_related());
        assert_eq!(error.affected_target(), Some("test_var"));
    }

    #[test]
    fn test_error_code_assignment() {
        let span = Span::new(Position::start(), Position::start());

        let undefined_error =
            ReferenceValidationError::undefined_reference("test", "variable", span);
        assert_eq!(
            undefined_error.error_code(),
            codes::references::UNDEFINED_REFERENCE
        );

        let security_error =
            ReferenceValidationError::security_boundary_violation("test", "test", 100, 50);
        assert_eq!(security_error.error_code(), codes::system::INTERNAL_ERROR);
    }

    #[test]
    fn test_error_summaries() {
        let span = Span::new(Position::start(), Position::start());

        let undefined_error =
            ReferenceValidationError::undefined_reference("test_var", "variable", span);
        let summary = undefined_error.summary();
        assert!(summary.contains("Undefined variable reference"));
        assert!(summary.contains("test_var"));

        let security_error = ReferenceValidationError::security_boundary_violation(
            "relationships",
            "Too many",
            1000,
            500,
        );
        let security_summary = security_error.summary();
        assert!(security_summary.contains("Security violation"));
        assert!(security_summary.contains("1000 exceeds limit 500"));
    }

    #[test]
    fn test_helper_functions() {
        let span = Span::new(Position::start(), Position::start());

        let recoverable_error = create_undefined_reference_error("test", "variable", span);
        assert!(!should_halt_pipeline(&recoverable_error));

        let critical_error = create_security_violation_error("test", "test", 100, 50);
        assert!(should_halt_pipeline(&critical_error));
    }

    #[test]
    fn test_error_context_extraction() {
        let span = Span::new(Position::start(), Position::start());
        let error = ReferenceValidationError::undefined_reference("test_var", "variable", span);

        let context = get_error_context(&error);
        assert!(context.iter().any(|(k, _)| k == &"error_type"));
        assert!(context.iter().any(|(k, _)| k == &"severity"));
        assert!(context.iter().any(|(k, _)| k == &"security_related"));
        assert!(context
            .iter()
            .any(|(k, v)| k == &"expected_symbol_type" && v == "variable"));
    }
}
