// ============================================================================
// COMPILER TYPE RE-EXPORTS
// ============================================================================

// Re-export compiler types that scanner uses extensively
// These are the authoritative types from the compiler
pub use common::ast::nodes::{DataType, LogicalOp, Operation, Value};

// ============================================================================
// SCANNER-SPECIFIC VALUE TYPES
// ============================================================================

use serde::{Deserialize, Serialize};
use std::fmt;

/// Resolved value after variable substitution and computation
/// This is the scanner's runtime representation of values
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ResolvedValue {
    String(String),
    Integer(i64),
    Float(f64),
    Boolean(bool),
    Version(String),                // Semantic version string
    EvrString(String),              // EVR (Epoch-Version-Release) string
    Collection(Vec<ResolvedValue>), // Collection of values (for entity checks)
    RecordData(Box<RecordData>),    // Nested structured data
    Binary(Vec<u8>),                // Binary data
}

impl ResolvedValue {
    /// Check if this is a string value
    pub fn is_string(&self) -> bool {
        matches!(self, ResolvedValue::String(_))
    }

    /// Check if this is an integer value
    pub fn is_integer(&self) -> bool {
        matches!(self, ResolvedValue::Integer(_))
    }

    /// Check if this is a collection
    pub fn is_collection(&self) -> bool {
        matches!(self, ResolvedValue::Collection(_))
    }

    /// Get as string if possible
    pub fn as_string(&self) -> Option<&str> {
        match self {
            ResolvedValue::String(s) => Some(s),
            _ => None,
        }
    }

    /// Get as integer if possible
    pub fn as_integer(&self) -> Option<i64> {
        match self {
            ResolvedValue::Integer(i) => Some(*i),
            _ => None,
        }
    }

    /// Get as collection if possible
    pub fn as_collection(&self) -> Option<&[ResolvedValue]> {
        match self {
            ResolvedValue::Collection(vec) => Some(vec),
            _ => None,
        }
    }
}

impl fmt::Display for ResolvedValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResolvedValue::String(s) => write!(f, "\"{}\"", s),
            ResolvedValue::Integer(i) => write!(f, "{}", i),
            ResolvedValue::Float(fl) => write!(f, "{}", fl),
            ResolvedValue::Boolean(b) => write!(f, "{}", b),
            ResolvedValue::Version(v) => write!(f, "version({})", v),
            ResolvedValue::EvrString(e) => write!(f, "evr({})", e),
            ResolvedValue::Collection(items) => {
                write!(f, "[")?;
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", item)?;
                }
                write!(f, "]")
            }
            ResolvedValue::RecordData(record) => {
                write!(f, "record({} fields)", record.field_count())
            }
            ResolvedValue::Binary(bytes) => write!(f, "binary({} bytes)", bytes.len()),
        }
    }
}

// ============================================================================
// RECORD DATA - Nested structured data
// ============================================================================

/// Structured data container (like JSON object)
/// Used for PARAMETER blocks, SELECT blocks, and nested data
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecordData {
    pub(crate) data: serde_json::Value,
}

impl RecordData {
    /// Create from JSON value
    pub fn from_json_value(value: serde_json::Value) -> Self {
        Self { data: value }
    }

    /// Create from field pairs (key-value)
    pub fn from_field_pairs(fields: Vec<(String, serde_json::Value)>) -> Self {
        let mut map = serde_json::Map::new();
        for (key, value) in fields {
            map.insert(key, value);
        }
        Self {
            data: serde_json::Value::Object(map),
        }
    }

    /// Get field by simple path (e.g., "Config.Database.Host")
    pub fn get_field_by_path(&self, path: &str) -> Option<&serde_json::Value> {
        let parts: Vec<&str> = path.split('.').collect();
        let mut current = &self.data;

        for part in parts {
            match current {
                serde_json::Value::Object(map) => {
                    current = map.get(part)?;
                }
                _ => return None,
            }
        }

        Some(current)
    }

    /// Get as JSON value reference
    pub fn as_json_value(&self) -> &serde_json::Value {
        &self.data
    }

    /// Get field count (for display purposes)
    pub fn field_count(&self) -> usize {
        match &self.data {
            serde_json::Value::Object(map) => map.len(),
            _ => 0,
        }
    }

    /// Check if this record contains a field
    pub fn has_field(&self, field_name: &str) -> bool {
        match &self.data {
            serde_json::Value::Object(map) => map.contains_key(field_name),
            _ => false,
        }
    }

    /// Get all field names at top level
    pub fn field_names(&self) -> Vec<String> {
        match &self.data {
            serde_json::Value::Object(map) => map.keys().cloned().collect(),
            _ => Vec::new(),
        }
    }

    /// Extract a ResolvedValue from a field path
    pub fn extract_resolved_value(&self, path: &str) -> Result<ResolvedValue, String> {
        let value = self
            .get_field_by_path(path)
            .ok_or_else(|| format!("Field not found: {}", path))?;

        Self::json_to_resolved_value(value)
    }

    /// Convert serde_json::Value to ResolvedValue
    fn json_to_resolved_value(value: &serde_json::Value) -> Result<ResolvedValue, String> {
        match value {
            serde_json::Value::String(s) => Ok(ResolvedValue::String(s.clone())),
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Ok(ResolvedValue::Integer(i))
                } else if let Some(f) = n.as_f64() {
                    Ok(ResolvedValue::Float(f))
                } else {
                    Err("Invalid number format".to_string())
                }
            }
            serde_json::Value::Bool(b) => Ok(ResolvedValue::Boolean(*b)),
            serde_json::Value::Null => Err("Cannot convert null to ResolvedValue".to_string()),
            serde_json::Value::Array(arr) => {
                let resolved: Result<Vec<_>, _> =
                    arr.iter().map(Self::json_to_resolved_value).collect();
                Ok(ResolvedValue::Collection(resolved?))
            }
            serde_json::Value::Object(_) => Ok(ResolvedValue::RecordData(Box::new(
                RecordData::from_json_value(value.clone()),
            ))),
        }
    }

    pub fn from_string_pairs(fields: Vec<(String, String)>) -> Self {
        let json_fields: Vec<(String, serde_json::Value)> = fields
            .into_iter()
            .map(|(k, v)| {
                #[allow(clippy::unnecessary_lazy_evaluations)]
                let json_val =
                    serde_json::from_str(&v).unwrap_or_else(|_| serde_json::Value::String(v));
                (k, json_val)
            })
            .collect();
        Self::from_field_pairs(json_fields)
    }
}

// ============================================================================
// EXTENSION TRAITS - For compiler types used in scanner
// ============================================================================

/// Extension trait for compiler's Value type
pub trait ValueExt {
    fn has_variable_reference(&self) -> bool;
    fn get_variable_name(&self) -> Option<&str>;
    fn is_literal(&self) -> bool;
}

impl ValueExt for Value {
    fn has_variable_reference(&self) -> bool {
        matches!(self, Value::Variable(_))
    }

    fn get_variable_name(&self) -> Option<&str> {
        match self {
            Value::Variable(name) => Some(name),
            _ => None,
        }
    }

    fn is_literal(&self) -> bool {
        !self.has_variable_reference()
    }
}

/// Extension trait for DataType to add scanner-specific helpers
pub trait DataTypeExt {
    fn matches_resolved_value(&self, value: &ResolvedValue) -> bool;
    fn is_numeric(&self) -> bool;
    fn is_comparable(&self) -> bool;
    fn default_value(&self) -> ResolvedValue;

    // Display helper (since we can't implement Display for external type)
    fn as_display_string(&self) -> &'static str;

    // SDK validation methods (moved from resolution/validation.rs to avoid orphan rule)
    fn sdk_valid_operations(&self) -> Vec<Operation>;
    fn sdk_supports_operation(&self, operation: &Operation) -> bool;
}

impl DataTypeExt for DataType {
    fn matches_resolved_value(&self, value: &ResolvedValue) -> bool {
        matches!(
            (self, value),
            (DataType::String, ResolvedValue::String(_))
                | (DataType::Int, ResolvedValue::Integer(_))
                | (DataType::Float, ResolvedValue::Float(_))
                | (DataType::Boolean, ResolvedValue::Boolean(_))
                | (DataType::Version, ResolvedValue::Version(_))
                | (DataType::EvrString, ResolvedValue::EvrString(_))
                | (DataType::RecordData, ResolvedValue::RecordData(_))
                | (DataType::Binary, ResolvedValue::Binary(_))
        )
    }

    fn is_numeric(&self) -> bool {
        matches!(self, DataType::Int | DataType::Float)
    }

    fn is_comparable(&self) -> bool {
        matches!(
            self,
            DataType::Int
                | DataType::Float
                | DataType::String
                | DataType::Version
                | DataType::EvrString
        )
    }

    fn default_value(&self) -> ResolvedValue {
        match self {
            DataType::String => ResolvedValue::String(String::new()),
            DataType::Int => ResolvedValue::Integer(0),
            DataType::Float => ResolvedValue::Float(0.0),
            DataType::Boolean => ResolvedValue::Boolean(false),
            DataType::Version => ResolvedValue::Version("0.0.0".to_string()),
            DataType::EvrString => ResolvedValue::EvrString("0:0-0".to_string()),
            DataType::RecordData => ResolvedValue::RecordData(Box::new(
                RecordData::from_json_value(serde_json::json!({})),
            )),
            DataType::Binary => ResolvedValue::Binary(Vec::new()),
        }
    }

    fn as_display_string(&self) -> &'static str {
        match self {
            DataType::String => "string",
            DataType::Int => "int",
            DataType::Float => "float",
            DataType::Boolean => "boolean",
            DataType::Version => "version",
            DataType::EvrString => "evr_string",
            DataType::RecordData => "record_data",
            DataType::Binary => "binary",
        }
    }

    fn sdk_valid_operations(&self) -> Vec<Operation> {
        use Operation::*;
        match self {
            DataType::String => vec![
                Equals,
                NotEqual,
                Contains,
                NotContains,
                StartsWith,
                EndsWith,
                PatternMatch,
            ],
            DataType::Int | DataType::Float => vec![
                Equals,
                NotEqual,
                GreaterThan,
                LessThan,
                GreaterThanOrEqual,
                LessThanOrEqual,
            ],
            DataType::Boolean => vec![Equals, NotEqual],
            DataType::Version | DataType::EvrString => vec![
                Equals,
                NotEqual,
                GreaterThan,
                LessThan,
                GreaterThanOrEqual,
                LessThanOrEqual,
            ],
            DataType::Binary => vec![Equals, NotEqual],
            DataType::RecordData => vec![
                Equals,
                NotEqual, // RecordData might support additional operations like Contains
                         // for field-level searches, but start conservative
            ],
        }
    }

    fn sdk_supports_operation(&self, operation: &Operation) -> bool {
        self.sdk_valid_operations().contains(operation)
    }
}

/// Extension trait for Operation to add scanner-specific helpers
pub trait OperationExt {
    fn is_comparison(&self) -> bool;
    fn is_string_operation(&self) -> bool;
    fn requires_string_operands(&self) -> bool;
    fn requires_numeric_operands(&self) -> bool;

    // Display helper (since we can't implement Display for external type)
    fn as_display_string(&self) -> &'static str;
}

impl OperationExt for Operation {
    fn is_comparison(&self) -> bool {
        matches!(
            self,
            Operation::Equals
                | Operation::NotEqual
                | Operation::GreaterThan
                | Operation::LessThan
                | Operation::GreaterThanOrEqual
                | Operation::LessThanOrEqual
        )
    }

    fn is_string_operation(&self) -> bool {
        matches!(
            self,
            Operation::Contains
                | Operation::NotContains
                | Operation::StartsWith
                | Operation::EndsWith
                | Operation::NotStartsWith
                | Operation::NotEndsWith
                | Operation::PatternMatch
                | Operation::Matches
        )
    }

    fn requires_string_operands(&self) -> bool {
        self.is_string_operation()
    }

    fn requires_numeric_operands(&self) -> bool {
        matches!(
            self,
            Operation::GreaterThan
                | Operation::LessThan
                | Operation::GreaterThanOrEqual
                | Operation::LessThanOrEqual
        )
    }

    fn as_display_string(&self) -> &'static str {
        match self {
            Operation::Equals => "=",
            Operation::NotEqual => "!=",
            Operation::GreaterThan => ">",
            Operation::LessThan => "<",
            Operation::GreaterThanOrEqual => ">=",
            Operation::LessThanOrEqual => "<=",
            Operation::Contains => "contains",
            Operation::NotContains => "not_contains",
            // FIXED: Added missing Operation variants
            Operation::CaseInsensitiveEquals => "case_insensitive_equals",
            Operation::CaseInsensitiveNotEqual => "case_insensitive_not_equal",
            Operation::StartsWith => "starts",
            Operation::EndsWith => "ends",
            Operation::NotStartsWith => "not_starts",
            Operation::NotEndsWith => "not_ends",
            Operation::PatternMatch => "pattern_match",
            Operation::Matches => "matches",
            Operation::SubsetOf => "subset_of",
            Operation::SupersetOf => "superset_of",
        }
    }
}

// ============================================================================
// ERRORS
// ============================================================================

/// Errors that can occur during RecordData operations
#[derive(Debug, thiserror::Error)]
pub enum RecordDataError {
    #[error("Field not found: {0}")]
    FieldNotFound(String),

    #[error("Invalid field path: {0}")]
    InvalidFieldPath(String),

    #[error("Type mismatch: expected {expected}, found {found}")]
    TypeMismatch { expected: String, found: String },

    #[error("Invalid operation: {0}")]
    InvalidOperation(String),

    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
}
