//! Error types for results module

use super::common::ControlMappingError;
use super::crypto::HashingError;

/// Errors that can occur during result generation
#[derive(Debug)]
pub enum ResultError {
    /// Required META field is missing
    MissingRequiredField(String),

    /// Invalid criticality value
    InvalidCriticality(String),

    /// Control mapping error
    ControlMappingError(ControlMappingError),

    /// Serialization error
    SerializationError(String),

    /// Hashing error
    HashingError(String),

    /// Builder error
    BuildError(String),
}

impl std::fmt::Display for ResultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResultError::MissingRequiredField(field) => {
                write!(f, "Missing required META field: {}", field)
            }
            ResultError::InvalidCriticality(value) => {
                write!(
                    f,
                    "Invalid criticality '{}'. Expected: critical, high, medium, low, info",
                    value
                )
            }
            ResultError::ControlMappingError(e) => {
                write!(f, "Control mapping error: {}", e)
            }
            ResultError::SerializationError(e) => {
                write!(f, "Serialization error: {}", e)
            }
            ResultError::HashingError(e) => {
                write!(f, "Hashing error: {}", e)
            }
            ResultError::BuildError(e) => {
                write!(f, "Build error: {}", e)
            }
        }
    }
}

impl std::error::Error for ResultError {}

impl From<ControlMappingError> for ResultError {
    fn from(err: ControlMappingError) -> Self {
        ResultError::ControlMappingError(err)
    }
}

impl From<serde_json::Error> for ResultError {
    fn from(err: serde_json::Error) -> Self {
        ResultError::SerializationError(err.to_string())
    }
}

impl From<HashingError> for ResultError {
    fn from(err: HashingError) -> Self {
        ResultError::HashingError(err.to_string())
    }
}

// Legacy error type alias for backwards compatibility
pub type ResultGenerationError = ResultError;
