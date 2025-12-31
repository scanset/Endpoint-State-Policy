//! # Record Data Traits
//!
//! This module defines the core abstractions for handling structured record data
//! in the ESP SDK. It provides format-agnostic interfaces that allow the SDK
//! to work with JSON, XML, SQL results, PowerShell objects, and other structured
//! data sources without being tied to any specific format.
//!
//! ## Design Principles
//!
//! - **Format Agnostic**: Core SDK logic works with any data format
//! - **Extensible**: Scanner implementers can add custom record types
//! - **Type Safe**: Consistent interfaces with compile-time guarantees
//! - **Performance**: Each format can optimize its access patterns
//!

use crate::types::common::ResolvedValue;
use crate::types::field_path_extensions::{FieldPathExt, PathComponent};
use crate::types::RecordData;
use common::ast::nodes::FieldPath;
use serde::{Deserialize, Serialize};

/// Core trait for reading structured record data in any format
///
/// This trait provides a unified interface for accessing field data regardless
/// of the underlying storage format (JSON, XML, SQL, etc.). All record types
/// in the ESP system must implement this trait.
pub trait RecordAccess: Send + Sync + std::fmt::Debug {
    /// Get a field value by path, returning None if the field doesn't exist
    ///
    /// # Arguments
    /// * `path` - The field path to retrieve (supports dot notation)
    ///
    /// # Returns
    /// * `Ok(Some(value))` - Field exists and was successfully retrieved
    /// * `Ok(None)` - Field does not exist
    /// * `Err(error)` - Error occurred during field access
    fn get_field(&self, path: &FieldPath) -> Result<Option<ResolvedValue>, RecordError>;

    /// Check if a field exists at the given path without retrieving the value
    fn has_field(&self, path: &FieldPath) -> bool;

    /// List all available field paths in this record
    ///
    /// For nested structures, this returns flattened dot-notation paths.
    /// Large records may implement pagination or lazy loading.
    fn list_fields(&self) -> Vec<FieldPath>;

    /// Get the total number of fields in this record
    ///
    /// For nested structures, this counts all leaf fields.
    fn field_count(&self) -> usize;

    /// Get a hint about the underlying data format
    ///
    /// Returns format identifiers like "json", "xml", "powershell", "sql", etc.
    /// This helps the execution engine choose appropriate processing strategies.
    fn format_hint(&self) -> Option<&str>;

    /// Get a human-readable description of this record for debugging
    fn record_description(&self) -> String {
        format!(
            "{} record with {} fields",
            self.format_hint().unwrap_or("unknown"),
            self.field_count()
        )
    }

    /// Validate that this record's structure is consistent
    ///
    /// Default implementation always returns Ok, but specific formats
    /// can override this to perform validation checks.
    fn validate_structure(&self) -> Result<(), RecordError> {
        Ok(())
    }
}

/// Extension trait for modifying record data
///
/// Not all record types support modification (e.g., SQL query results may be read-only).
/// This trait is optional and only implemented by mutable record types.
pub trait RecordAccessMut: RecordAccess {
    /// Set a field value at the given path
    ///
    /// Creates intermediate path components if they don't exist.
    fn set_field(&mut self, path: &FieldPath, value: ResolvedValue) -> Result<(), RecordError>;

    /// Remove a field at the given path, returning the previous value if it existed
    fn remove_field(&mut self, path: &FieldPath) -> Result<Option<ResolvedValue>, RecordError>;

    /// Clear all fields from this record
    fn clear(&mut self) -> Result<(), RecordError>;

    /// Merge another record into this one
    ///
    /// Conflicting fields are overwritten with values from the other record.
    fn merge(&mut self, other: &dyn RecordAccess) -> Result<(), RecordError> {
        for field_path in other.list_fields() {
            if let Ok(Some(value)) = other.get_field(&field_path) {
                self.set_field(&field_path, value)?;
            }
        }
        Ok(())
    }
}

/// Factory trait for creating record instances from raw data
///
/// Adapters parse format-specific data (JSON bytes, XML documents, etc.)
/// into record instances that implement RecordAccess.
pub trait RecordAdapter: Send + Sync + std::fmt::Debug {
    /// Parse raw data into a record instance
    ///
    /// # Arguments
    /// * `data` - Raw bytes in the format this adapter understands
    ///
    /// # Returns
    /// * `Ok(record)` - Successfully parsed record
    /// * `Err(error)` - Parse error with details
    fn parse(&self, data: &[u8]) -> Result<Box<dyn RecordAccess>, RecordError>;

    /// Check if this adapter supports the given format identifier
    fn supports_format(&self, format: &str) -> bool;

    /// Get the name of this adapter for registry management
    fn adapter_name(&self) -> &str;

    /// Get all format identifiers this adapter supports
    fn supported_formats(&self) -> Vec<&str>;

    /// Validate raw data before parsing (optional optimization)
    ///
    /// Returns true if the data appears to be in the correct format.
    /// This can be used for format detection or early validation.
    fn can_parse(&self, data: &[u8]) -> bool {
        // Default implementation attempts to parse and checks for success
        self.parse(data).is_ok()
    }
}

/// Comprehensive error types for record operations
#[derive(Debug, thiserror::Error)]
pub enum RecordError {
    /// Field does not exist at the specified path
    #[error("Field '{0}' not found")]
    FieldNotFound(String),

    /// Invalid field path syntax
    #[error("Invalid field path '{path}': {reason}")]
    InvalidPath { path: String, reason: String },

    /// Error parsing data into record format
    #[error("Parse error for format '{format}': {details}")]
    ParseError { format: String, details: String },

    /// Unsupported data format
    #[error("Unsupported format: {0}")]
    UnsupportedFormat(String),

    /// Error converting between value types
    #[error("Type conversion error: {details}")]
    TypeConversion { details: String },

    /// Record structure is invalid or corrupted
    #[error("Invalid record structure: {details}")]
    InvalidStructure { details: String },

    /// Operation not supported by this record type
    #[error("Operation '{operation}' not supported by {record_type}")]
    UnsupportedOperation {
        operation: String,
        record_type: String,
    },

    /// Access denied (e.g., read-only record)
    #[error("Access denied: {reason}")]
    AccessDenied { reason: String },

    /// Field value is too large or record exceeds limits
    #[error("Resource limit exceeded: {details}")]
    ResourceLimit { details: String },

    /// Wrapped error from underlying format-specific libraries
    #[error("Underlying format error: {0}")]
    FormatSpecific(Box<dyn std::error::Error + Send + Sync>),
}

impl RecordError {
    /// Create a field not found error
    pub fn field_not_found(field_path: &FieldPath) -> Self {
        Self::FieldNotFound(field_path.to_dot_notation())
    }

    /// Create an invalid path error
    pub fn invalid_path(path: &str, reason: &str) -> Self {
        Self::InvalidPath {
            path: path.to_string(),
            reason: reason.to_string(),
        }
    }

    /// Create a parse error
    pub fn parse_error(format: &str, details: &str) -> Self {
        Self::ParseError {
            format: format.to_string(),
            details: details.to_string(),
        }
    }

    /// Create a type conversion error
    pub fn type_conversion(details: &str) -> Self {
        Self::TypeConversion {
            details: details.to_string(),
        }
    }

    /// Create an unsupported operation error
    pub fn unsupported_operation(operation: &str, record_type: &str) -> Self {
        Self::UnsupportedOperation {
            operation: operation.to_string(),
            record_type: record_type.to_string(),
        }
    }

    /// Create an access denied error
    pub fn access_denied(reason: &str) -> Self {
        Self::AccessDenied {
            reason: reason.to_string(),
        }
    }

    /// Create a resource limit error
    pub fn resource_limit(details: &str) -> Self {
        Self::ResourceLimit {
            details: details.to_string(),
        }
    }

    /// Create an invalid structure error
    pub fn invalid_structure(details: &str) -> Self {
        Self::InvalidStructure {
            details: details.to_string(),
        }
    }
}

// ============================================================================
// JSON RECORD IMPLEMENTATION
// ============================================================================

/// JSON-based record implementation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRecord {
    data: serde_json::Value,
}

impl JsonRecord {
    /// Create a new JSON record from a serde_json::Value
    pub fn from_json_value(value: serde_json::Value) -> Self {
        Self { data: value }
    }

    /// Create a new JSON record from a JSON string
    pub fn from_json_str(json_str: &str) -> Result<Self, RecordError> {
        let value: serde_json::Value = serde_json::from_str(json_str)
            .map_err(|e| RecordError::parse_error("json", &e.to_string()))?;
        Ok(Self { data: value })
    }

    /// Get the underlying JSON value
    pub fn as_json_value(&self) -> &serde_json::Value {
        &self.data
    }

    /// Convert a serde_json::Value to ResolvedValue
    fn json_value_to_resolved(json_val: &serde_json::Value) -> Result<ResolvedValue, RecordError> {
        match json_val {
            serde_json::Value::String(s) => Ok(ResolvedValue::String(s.clone())),
            serde_json::Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    Ok(ResolvedValue::Integer(i))
                } else if let Some(f) = n.as_f64() {
                    Ok(ResolvedValue::Float(f))
                } else {
                    Err(RecordError::type_conversion("Invalid number format"))
                }
            }
            serde_json::Value::Bool(b) => Ok(ResolvedValue::Boolean(*b)),
            serde_json::Value::Null => Ok(ResolvedValue::String(String::new())),
            serde_json::Value::Array(arr) => {
                let items: Result<Vec<_>, _> =
                    arr.iter().map(Self::json_value_to_resolved).collect();
                Ok(ResolvedValue::Collection(items?))
            }
            serde_json::Value::Object(_) => {
                // For nested objects, wrap in RecordData
                use crate::types::common::RecordData;
                Ok(ResolvedValue::RecordData(Box::new(
                    RecordData::from_json_value(json_val.clone()),
                )))
            }
        }
    }

    /// Convert ResolvedValue to serde_json::Value
    fn resolved_to_json_value(resolved: &ResolvedValue) -> serde_json::Value {
        match resolved {
            ResolvedValue::String(s) => serde_json::Value::String(s.clone()),
            ResolvedValue::Integer(i) => serde_json::json!(i),
            ResolvedValue::Float(f) => serde_json::json!(f),
            ResolvedValue::Boolean(b) => serde_json::Value::Bool(*b),
            ResolvedValue::Version(v) => serde_json::Value::String(v.clone()),
            ResolvedValue::EvrString(e) => serde_json::Value::String(e.clone()),
            ResolvedValue::Collection(items) => {
                let json_items: Vec<serde_json::Value> =
                    items.iter().map(Self::resolved_to_json_value).collect();
                serde_json::Value::Array(json_items)
            }
            ResolvedValue::RecordData(record) => record.as_json_value().clone(),
            ResolvedValue::Binary(bytes) => {
                // Encode binary as base64 string
                serde_json::Value::String(base64::Engine::encode(
                    &base64::engine::general_purpose::STANDARD,
                    bytes,
                ))
            }
        }
    }
}

impl RecordAccess for JsonRecord {
    fn get_field(&self, path: &FieldPath) -> Result<Option<ResolvedValue>, RecordError> {
        let current = &self.data;

        // Navigate through path components
        let components = path.parse_components();
        for component in &components {
            match component {
                PathComponent::Field(field_name) => {
                    match current.get(field_name) {
                        Some(value) => value,
                        None => return Ok(None), // Field doesn't exist
                    }
                }
                PathComponent::Index(idx) => {
                    match current.get(idx) {
                        Some(value) => value,
                        None => return Ok(None), // Index out of bounds
                    }
                }
                PathComponent::Wildcard => {
                    // Wildcards require special handling - not supported in basic get_field
                    return Err(RecordError::invalid_path(
                        &path.to_dot_notation(),
                        "Wildcard paths not supported in get_field",
                    ));
                }
            };
        }

        // Convert final value to ResolvedValue
        let resolved = Self::json_value_to_resolved(current)?;
        Ok(Some(resolved))
    }

    fn has_field(&self, path: &FieldPath) -> bool {
        let current = &self.data;

        let components = path.parse_components();
        for component in &components {
            match component {
                PathComponent::Field(field_name) => match current.get(field_name) {
                    Some(value) => value,
                    None => return false,
                },
                PathComponent::Index(idx) => match current.get(idx) {
                    Some(value) => value,
                    None => return false,
                },
                PathComponent::Wildcard => return false, // Wildcards not supported here
            };
        }

        true
    }

    fn list_fields(&self) -> Vec<FieldPath> {
        let mut fields = Vec::new();
        Self::collect_field_paths(&self.data, &mut Vec::new(), &mut fields);
        fields
    }

    fn field_count(&self) -> usize {
        self.list_fields().len()
    }

    fn format_hint(&self) -> Option<&str> {
        Some("json")
    }
}

impl JsonRecord {
    /// Recursively collect all field paths from JSON structure
    fn collect_field_paths(
        value: &serde_json::Value,
        #[allow(clippy::ptr_arg)] current_path: &mut Vec<PathComponent>,
        result: &mut Vec<FieldPath>,
    ) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, val) in map {
                    let mut new_path = current_path.clone();
                    new_path.push(PathComponent::Field(key.clone()));

                    match val {
                        serde_json::Value::Object(_) | serde_json::Value::Array(_) => {
                            // Recurse into nested structures
                            Self::collect_field_paths(val, &mut new_path, result);
                        }
                        _ => {
                            // Leaf value - add to results
                            result.push(FieldPath {
                                components: new_path
                                    .iter()
                                    .map(|pc| pc.to_string_component())
                                    .collect(),
                            });
                        }
                    }
                }
            }
            serde_json::Value::Array(arr) => {
                for (idx, val) in arr.iter().enumerate() {
                    let mut new_path = current_path.clone();
                    new_path.push(PathComponent::Index(idx));

                    match val {
                        serde_json::Value::Object(_) | serde_json::Value::Array(_) => {
                            Self::collect_field_paths(val, &mut new_path, result);
                        }
                        _ => {
                            result.push(FieldPath {
                                components: new_path
                                    .iter()
                                    .map(|pc| pc.to_string_component())
                                    .collect(),
                            });
                        }
                    }
                }
            }
            _ => {
                // Leaf value at current path
                if !current_path.is_empty() {
                    result.push(FieldPath {
                        components: current_path
                            .iter()
                            .map(|pc| pc.to_string_component())
                            .collect(),
                    });
                }
            }
        }
    }
}

impl RecordAccessMut for JsonRecord {
    fn set_field(&mut self, path: &FieldPath, value: ResolvedValue) -> Result<(), RecordError> {
        if path.components.is_empty() {
            return Err(RecordError::invalid_path("", "Empty field path"));
        }

        let json_value = Self::resolved_to_json_value(&value);

        // Navigate or create path to the target field
        let mut current = &mut self.data;

        for (i, component) in path.components.iter().enumerate() {
            let is_last = i == path.components.len() - 1;

            if is_last {
                // Set the final field
                match current {
                    serde_json::Value::Object(map) => {
                        // Convert PathComponent to String for map key
                        let key = component.to_string();
                        map.insert(key, json_value);
                        return Ok(());
                    }
                    _ => {
                        return Err(RecordError::invalid_path(
                            &path.to_dot_notation(),
                            "Cannot set field on non-object value",
                        ));
                    }
                }
            } else {
                // Navigate or create intermediate path
                match current {
                    serde_json::Value::Object(map) => {
                        // Convert PathComponent to String for map key
                        let key = component.to_string();
                        current = map
                            .entry(key)
                            .or_insert_with(|| serde_json::Value::Object(serde_json::Map::new()));
                    }
                    _ => {
                        return Err(RecordError::invalid_path(
                            &path.to_dot_notation(),
                            "Cannot navigate through non-object value",
                        ));
                    }
                }
            }
        }

        Ok(())
    }

    fn remove_field(&mut self, path: &FieldPath) -> Result<Option<ResolvedValue>, RecordError> {
        if path.components.is_empty() {
            return Err(RecordError::invalid_path("", "Empty field path"));
        }

        // Navigate to the parent of the target field
        let mut current = &mut self.data;

        for component in &path.components[..path.components.len() - 1] {
            current = match current {
                serde_json::Value::Object(map) => {
                    // Convert PathComponent to String for map key
                    let key = component.to_string();
                    match map.get_mut(&key) {
                        Some(value) => value,
                        None => return Ok(None), // Parent doesn't exist
                    }
                }
                _ => return Ok(None), // Cannot navigate through non-object
            };
        }

        // Remove the final field
        let final_component = &path.components[path.components.len() - 1];
        match current {
            serde_json::Value::Object(map) => {
                // Convert PathComponent to String for map key
                let key = final_component.to_string();
                let removed_value = map.remove(&key);
                match removed_value {
                    Some(json_val) => {
                        let resolved_val = Self::json_value_to_resolved(&json_val)?;
                        Ok(Some(resolved_val))
                    }
                    None => Ok(None),
                }
            }
            _ => Ok(None),
        }
    }

    fn clear(&mut self) -> Result<(), RecordError> {
        self.data = serde_json::Value::Object(serde_json::Map::new());
        Ok(())
    }
}

/// Default JSON adapter for creating JsonRecord instances
#[derive(Debug)]
pub struct JsonRecordAdapter {
    name: String,
}

impl JsonRecordAdapter {
    pub fn new() -> Self {
        Self {
            name: "json".to_string(),
        }
    }
}

impl Default for JsonRecordAdapter {
    fn default() -> Self {
        Self::new()
    }
}

impl RecordAdapter for JsonRecordAdapter {
    fn parse(&self, data: &[u8]) -> Result<Box<dyn RecordAccess>, RecordError> {
        let json_str = std::str::from_utf8(data)
            .map_err(|e| RecordError::parse_error("json", &e.to_string()))?;

        let record = JsonRecord::from_json_str(json_str)?;
        Ok(Box::new(record))
    }

    fn supports_format(&self, format: &str) -> bool {
        matches!(format.to_lowercase().as_str(), "json" | "application/json")
    }

    fn adapter_name(&self) -> &str {
        &self.name
    }

    fn supported_formats(&self) -> Vec<&str> {
        vec!["json", "application/json"]
    }

    fn can_parse(&self, data: &[u8]) -> bool {
        if let Ok(json_str) = std::str::from_utf8(data) {
            serde_json::from_str::<serde_json::Value>(json_str).is_ok()
        } else {
            false
        }
    }
}

/// Extension trait for RecordData providing scanner-specific operations
pub trait RecordDataExt {
    /// Check if a field exists at the given path
    fn has_field(&self, path: &FieldPath) -> bool;

    /// Get nested field value
    fn get_nested_field(&self, path: &FieldPath) -> Option<&serde_json::Value>;
}

impl RecordDataExt for RecordData {
    fn has_field(&self, path: &FieldPath) -> bool {
        let components = path.parse_components();

        let mut current = &self.data;

        for component in &components {
            match component {
                PathComponent::Field(field_name) => {
                    if let Some(obj) = current.as_object() {
                        if let Some(value) = obj.get(field_name) {
                            current = value;
                        } else {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
                PathComponent::Index(idx) => {
                    if let Some(arr) = current.as_array() {
                        if let Some(value) = arr.get(*idx) {
                            current = value;
                        } else {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
                PathComponent::Wildcard => {
                    return true;
                }
            }
        }

        true
    }

    fn get_nested_field(&self, path: &FieldPath) -> Option<&serde_json::Value> {
        let components = path.parse_components();

        let mut current = &self.data;

        for component in &components {
            match component {
                PathComponent::Field(field_name) => {
                    current = current.get(field_name)?;
                }
                PathComponent::Index(idx) => {
                    current = current.get(*idx)?;
                }
                PathComponent::Wildcard => {
                    return None;
                }
            }
        }

        Some(current)
    }
}

/// Extension trait providing convenience methods for working with records
pub trait RecordAccessExt: RecordAccess {
    /// Get a field as a specific ResolvedValue variant
    fn get_string_field(&self, path: &FieldPath) -> Result<Option<String>, RecordError> {
        match self.get_field(path)? {
            Some(ResolvedValue::String(s)) => Ok(Some(s)),
            Some(_) => Err(RecordError::type_conversion("Field is not a string")),
            None => Ok(None),
        }
    }

    /// Get a field as an integer
    fn get_integer_field(&self, path: &FieldPath) -> Result<Option<i64>, RecordError> {
        match self.get_field(path)? {
            Some(ResolvedValue::Integer(i)) => Ok(Some(i)),
            Some(_) => Err(RecordError::type_conversion("Field is not an integer")),
            None => Ok(None),
        }
    }

    /// Get a field as a boolean
    fn get_boolean_field(&self, path: &FieldPath) -> Result<Option<bool>, RecordError> {
        match self.get_field(path)? {
            Some(ResolvedValue::Boolean(b)) => Ok(Some(b)),
            Some(_) => Err(RecordError::type_conversion("Field is not a boolean")),
            None => Ok(None),
        }
    }
}

/// Blanket implementation for all types that implement RecordAccess
impl<T: RecordAccess + ?Sized> RecordAccessExt for T {}
