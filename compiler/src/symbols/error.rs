//! Simplified Error types for Pass 3: Symbol Discovery

use common::ast::nodes::SetOperationType;
use common::logging::codes;
use common::utils::Span;
use std::fmt;

/// Result type for symbol discovery operations
pub type SymbolResult<T> = Result<T, SymbolDiscoveryError>;

/// Shadowing error details (boxed to reduce enum size)
#[derive(Debug, Clone)]
pub struct ShadowingDetails {
    pub identifier: String,
    pub local_type: String,
    pub global_type: String,
    pub ctn_type: String,
    pub local_span: Span,
    pub global_span: Span,
}

/// Basic error types for symbol discovery
#[derive(Debug, Clone)]
pub enum SymbolDiscoveryError {
    DuplicateSymbol {
        identifier: String,
        scope: String,
        first_span: Span,
        duplicate_span: Span,
    },

    Shadowing(Box<ShadowingDetails>),

    ReservedSymbolName {
        identifier: String,
        span: Span,
    },

    EmptySymbolBlock {
        symbol_type: String,
        identifier: String,
        span: Span,
    },

    MultipleCtnObjects {
        ctn_type: String,
        first_span: Span,
        duplicate_span: Span,
    },

    InvalidSetOperandCount {
        set_id: String,
        operation: String,
        expected: String,
        actual: usize,
        span: Span,
    },

    InternalSymbolError {
        message: String,
    },

    SymbolTableCorruption {
        message: String,
    },
}

impl fmt::Display for SymbolDiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateSymbol {
                identifier,
                scope,
                first_span,
                duplicate_span,
            } => write!(
                f,
                "Duplicate symbol '{}' in {} scope: first declared at {}, redeclared at {}",
                identifier, scope, first_span, duplicate_span
            ),
            Self::Shadowing(details) => write!(
                f,
                "Local {} '{}' in CTN '{}' shadows global {} declared at {}",
                details.local_type,
                details.identifier,
                details.ctn_type,
                details.global_type,
                details.global_span
            ),
            Self::ReservedSymbolName { identifier, span } => write!(
                f,
                "Reserved keyword '{}' cannot be used as symbol name at {}",
                identifier, span
            ),
            Self::EmptySymbolBlock {
                symbol_type,
                identifier,
                span,
            } => write!(
                f,
                "Empty {} block '{}' at {}: must contain at least one element",
                symbol_type, identifier, span
            ),
            Self::MultipleCtnObjects {
                ctn_type,
                first_span,
                duplicate_span,
            } => write!(
                f,
                "Multiple local objects in CTN '{}': first at {}, second at {}",
                ctn_type, first_span, duplicate_span
            ),
            Self::InvalidSetOperandCount {
                set_id,
                operation,
                expected,
                actual,
                span,
            } => write!(
                f,
                "Invalid operand count for SET '{}' operation '{}': expected {}, found {} at {}",
                set_id, operation, expected, actual, span
            ),
            Self::InternalSymbolError { message } => {
                write!(f, "Internal symbol discovery error: {}", message)
            }
            Self::SymbolTableCorruption { message } => {
                write!(f, "Symbol table corruption: {}", message)
            }
        }
    }
}

impl std::error::Error for SymbolDiscoveryError {}

impl SymbolDiscoveryError {
    /// Create a duplicate symbol error
    pub fn duplicate_symbol(
        identifier: &str,
        scope: &str,
        first_span: Span,
        duplicate_span: Span,
    ) -> Self {
        Self::DuplicateSymbol {
            identifier: identifier.to_string(),
            scope: scope.to_string(),
            first_span,
            duplicate_span,
        }
    }

    /// Create a shadowing error when local symbol shadows global (N-5)
    pub fn shadowing(
        identifier: &str,
        local_type: &str,
        global_type: &str,
        ctn_type: &str,
        local_span: Span,
        global_span: Span,
    ) -> Self {
        Self::Shadowing(Box::new(ShadowingDetails {
            identifier: identifier.to_string(),
            local_type: local_type.to_string(),
            global_type: global_type.to_string(),
            ctn_type: ctn_type.to_string(),
            local_span,
            global_span,
        }))
    }

    /// Create a reserved symbol name error
    pub fn reserved_symbol_name(identifier: &str, span: Span) -> Self {
        Self::ReservedSymbolName {
            identifier: identifier.to_string(),
            span,
        }
    }

    /// Create an empty symbol block error
    pub fn empty_symbol_block(symbol_type: &str, identifier: &str, span: Span) -> Self {
        Self::EmptySymbolBlock {
            symbol_type: symbol_type.to_string(),
            identifier: identifier.to_string(),
            span,
        }
    }

    /// Create a multiple CTN objects error
    pub fn multiple_ctn_objects(ctn_type: &str, first_span: Span, duplicate_span: Span) -> Self {
        Self::MultipleCtnObjects {
            ctn_type: ctn_type.to_string(),
            first_span,
            duplicate_span,
        }
    }

    /// Create an invalid SET operand count error
    pub fn invalid_set_operand_count(
        set_id: &str,
        operation: SetOperationType,
        actual: usize,
        span: Span,
    ) -> Self {
        let expected = match operation {
            SetOperationType::Union => "1 or more".to_string(),
            SetOperationType::Intersection => "2 or more".to_string(),
            SetOperationType::Complement => "exactly 2".to_string(),
        };

        Self::InvalidSetOperandCount {
            set_id: set_id.to_string(),
            operation: operation.as_str().to_string(),
            expected,
            actual,
            span,
        }
    }

    /// Create an internal symbol error
    pub fn internal_symbol_error(message: &str) -> Self {
        Self::InternalSymbolError {
            message: message.to_string(),
        }
    }

    /// Create a symbol table corruption error
    pub fn symbol_table_corruption(message: &str) -> Self {
        Self::SymbolTableCorruption {
            message: message.to_string(),
        }
    }

    /// Get span if available
    pub fn span(&self) -> Option<Span> {
        match self {
            Self::DuplicateSymbol { duplicate_span, .. } => Some(*duplicate_span),
            Self::Shadowing(details) => Some(details.local_span),
            Self::ReservedSymbolName { span, .. } => Some(*span),
            Self::EmptySymbolBlock { span, .. } => Some(*span),
            Self::MultipleCtnObjects { duplicate_span, .. } => Some(*duplicate_span),
            Self::InvalidSetOperandCount { span, .. } => Some(*span),
            Self::InternalSymbolError { .. } => None,
            Self::SymbolTableCorruption { .. } => None,
        }
    }

    /// Check if this error requires halting
    pub fn requires_halt(&self) -> bool {
        matches!(
            self,
            Self::InternalSymbolError { .. } | Self::SymbolTableCorruption { .. }
        )
    }

    /// Get error code for global logging system
    pub fn error_code(&self) -> codes::Code {
        match self {
            Self::DuplicateSymbol { .. } => codes::symbols::DUPLICATE_SYMBOL,
            Self::Shadowing(_) => codes::symbols::SYMBOL_SHADOWING,
            Self::ReservedSymbolName { .. } => codes::symbols::SYMBOL_DISCOVERY_ERROR,
            Self::EmptySymbolBlock { .. } => codes::symbols::SYMBOL_DISCOVERY_ERROR,
            Self::MultipleCtnObjects { .. } => codes::symbols::MULTIPLE_LOCAL_OBJECTS,
            Self::InvalidSetOperandCount { .. } => codes::symbols::SYMBOL_DISCOVERY_ERROR,
            Self::InternalSymbolError { .. } => codes::symbols::SYMBOL_TABLE_CONSTRUCTION_ERROR,
            Self::SymbolTableCorruption { .. } => codes::symbols::SYMBOL_TABLE_CONSTRUCTION_ERROR,
        }
    }
}
