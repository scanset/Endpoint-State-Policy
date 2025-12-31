//! Simplified Error types for Pass 3: Symbol Discovery

use common::ast::nodes::SetOperationType;
use common::utils::Span;

/// Result type for symbol discovery operations
pub type SymbolResult<T> = Result<T, SymbolDiscoveryError>;

/// Basic error types for symbol discovery
#[derive(Debug, Clone, thiserror::Error)]
pub enum SymbolDiscoveryError {
    #[error("Duplicate symbol '{identifier}' in {scope} scope: first declared at {first_span}, redeclared at {duplicate_span}")]
    DuplicateSymbol {
        identifier: String,
        scope: String,
        first_span: Span,
        duplicate_span: Span,
    },

    #[error("Reserved keyword '{identifier}' cannot be used as symbol name at {span}")]
    ReservedSymbolName { identifier: String, span: Span },

    #[error(
        "Empty {symbol_type} block '{identifier}' at {span}: must contain at least one element"
    )]
    EmptySymbolBlock {
        symbol_type: String,
        identifier: String,
        span: Span,
    },

    #[error("Multiple local objects in CTN '{ctn_type}': first at {first_span}, second at {duplicate_span}")]
    MultipleCtnObjects {
        ctn_type: String,
        first_span: Span,
        duplicate_span: Span,
    },

    #[error("Invalid operand count for SET '{set_id}' operation '{operation}': expected {expected}, found {actual} at {span}")]
    InvalidSetOperandCount {
        set_id: String,
        operation: String,
        expected: String,
        actual: usize,
        span: Span,
    },

    #[error("Internal symbol discovery error: {message}")]
    InternalSymbolError { message: String },

    #[error("Symbol table corruption: {message}")]
    SymbolTableCorruption { message: String },
}

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
    pub fn error_code(&self) -> common::logging::codes::Code {
        use common::logging::codes;
        match self {
            Self::DuplicateSymbol { .. } => codes::symbols::DUPLICATE_SYMBOL,
            Self::ReservedSymbolName { .. } => codes::symbols::SYMBOL_DISCOVERY_ERROR,
            Self::EmptySymbolBlock { .. } => codes::symbols::SYMBOL_DISCOVERY_ERROR,
            Self::MultipleCtnObjects { .. } => codes::symbols::MULTIPLE_LOCAL_OBJECTS,
            Self::InvalidSetOperandCount { .. } => codes::symbols::SYMBOL_DISCOVERY_ERROR,
            Self::InternalSymbolError { .. } => codes::symbols::SYMBOL_TABLE_CONSTRUCTION_ERROR,
            Self::SymbolTableCorruption { .. } => codes::symbols::SYMBOL_TABLE_CONSTRUCTION_ERROR,
        }
    }
}
