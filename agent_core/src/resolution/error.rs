use crate::types::common::DataType;
use crate::types::error::FieldResolutionError;

#[derive(Debug)]
pub enum ResolutionError {
    FieldResolutionError(FieldResolutionError),
    ContextError(String),
    InvalidState(String),

    // Add the missing InvalidInput variant that parser code expects
    InvalidInput {
        message: String,
    },

    UndefinedVariable {
        name: String,
        context: String,
    },
    UndefinedGlobalState {
        name: String,
        context: String,
    },
    UndefinedGlobalObject {
        name: String,
        context: String,
    },
    UndefinedSet {
        name: String,
        context: String,
    },
    TypeMismatch {
        expected: DataType,
        found: DataType,
        symbol: String,
    },
    CircularDependency {
        cycle: Vec<String>,
    },
    RuntimeOperationFailed {
        operation: String,
        reason: String,
    },
    FilterValidationFailed {
        filter_context: String,
        reason: String,
    },
    SetOperationFailed {
        set_id: String,
        reason: String,
    },
    LocalSymbolConflict {
        symbol: String,
        ctn_id: usize,
    },
    DependencyGraphCorrupted {
        details: String,
    },
    MemoizationError {
        key: String,
        reason: String,
    },
}

impl std::fmt::Display for ResolutionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolutionError::FieldResolutionError(fre) => {
                write!(f, "Field resolution error: {}", fre)
            }
            ResolutionError::ContextError(msg) => {
                write!(f, "Context error: {}", msg)
            }
            ResolutionError::InvalidState(msg) => {
                write!(f, "Invalid state: {}", msg)
            }
            ResolutionError::InvalidInput { message } => {
                write!(f, "Invalid input: {}", message)
            }
            ResolutionError::UndefinedVariable { name, context } => {
                write!(f, "Undefined variable '{}' in context: {}", name, context)
            }
            ResolutionError::UndefinedGlobalState { name, context } => {
                write!(
                    f,
                    "Undefined global state '{}' in context: {}",
                    name, context
                )
            }
            ResolutionError::UndefinedGlobalObject { name, context } => {
                write!(
                    f,
                    "Undefined global object '{}' in context: {}",
                    name, context
                )
            }
            ResolutionError::UndefinedSet { name, context } => {
                write!(f, "Undefined set '{}' in context: {}", name, context)
            }
            ResolutionError::TypeMismatch {
                expected,
                found,
                symbol,
            } => {
                write!(
                    f,
                    "Type mismatch in '{}': expected {:?}, found {:?}",
                    symbol, expected, found
                )
            }
            ResolutionError::CircularDependency { cycle } => {
                write!(f, "Circular dependency detected: {}", cycle.join(" -> "))
            }
            ResolutionError::RuntimeOperationFailed { operation, reason } => {
                write!(f, "Runtime operation '{}' failed: {}", operation, reason)
            }
            ResolutionError::FilterValidationFailed {
                filter_context,
                reason,
            } => {
                write!(
                    f,
                    "Filter validation failed in '{}': {}",
                    filter_context, reason
                )
            }
            ResolutionError::SetOperationFailed { set_id, reason } => {
                write!(f, "Set operation '{}' failed: {}", set_id, reason)
            }
            ResolutionError::LocalSymbolConflict { symbol, ctn_id } => {
                write!(f, "Local symbol conflict: '{}' in CTN {}", symbol, ctn_id)
            }
            ResolutionError::DependencyGraphCorrupted { details } => {
                write!(f, "Dependency graph corrupted: {}", details)
            }
            ResolutionError::MemoizationError { key, reason } => {
                write!(f, "Memoization error for '{}': {}", key, reason)
            }
        }
    }
}

impl std::error::Error for ResolutionError {}

impl From<FieldResolutionError> for ResolutionError {
    fn from(error: FieldResolutionError) -> Self {
        Self::FieldResolutionError(error)
    }
}

impl From<crate::types::common::RecordDataError> for ResolutionError {
    fn from(error: crate::types::common::RecordDataError) -> Self {
        Self::InvalidInput {
            message: format!("Record data error: {}", error),
        }
    }
}
