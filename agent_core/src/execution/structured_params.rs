//! # Structured Parameter Parsing
//!
//! Handles parsing of nested parameter blocks into structured RecordData.
//! Supports JSON-like nested structures with reasonable depth limits.

use crate::types::common::{DataType, RecordData, RecordDataError};
use serde_json::{Map, Value as JsonValue};

/// Maximum nesting depth for parameters (prevent stack overflow)
const MAX_NESTING_DEPTH: usize = 10;

/// Parse parameter field pairs into structured RecordData
///
/// # Arguments
/// * `fields` - Vector of (key, value) string pairs
/// * `data_type` - Hint for the target data type
///
/// # Returns
/// * `RecordData` with properly nested structure
///
/// # Format
/// Supports dot notation for nesting:
/// ```ignore
/// [
///     ("Config.Database.Host", "localhost"),
///     ("Config.Database.Port", "5432"),
///     ("Config.Timeout", "30"),
/// ]
/// ```
///
/// Becomes:
/// ```json
/// {
///     "Config": {
///         "Database": {
///             "Host": "localhost",
///             "Port": "5432"
///         },
///         "Timeout": "30"
///     }
/// }
/// ```
pub fn parse_parameters(
    fields: &[(String, String)],
    _data_type: DataType,
) -> Result<RecordData, RecordDataError> {
    let mut root = Map::new();

    for (key, value) in fields {
        insert_nested_value(&mut root, key, value)?;
    }

    Ok(RecordData::from_json_value(JsonValue::Object(root)))
}

/// Insert a value at a nested path in the JSON structure
fn insert_nested_value(
    root: &mut Map<String, JsonValue>,
    path: &str,
    value: &str,
) -> Result<(), RecordDataError> {
    let parts: Vec<&str> = path.split('.').collect();

    if parts.len() > MAX_NESTING_DEPTH {
        return Err(RecordDataError::InvalidOperation(format!(
            "Parameter nesting depth {} exceeds maximum {}",
            parts.len(),
            MAX_NESTING_DEPTH
        )));
    }

    insert_at_path(root, &parts, value, 0)
}

/// Recursively insert value at the given path
fn insert_at_path(
    current: &mut Map<String, JsonValue>,
    path: &[&str],
    value: &str,
    depth: usize,
) -> Result<(), RecordDataError> {
    if depth > MAX_NESTING_DEPTH {
        return Err(RecordDataError::InvalidOperation(
            "Maximum nesting depth exceeded".to_string(),
        ));
    }

    if path.is_empty() {
        return Err(RecordDataError::InvalidOperation(
            "Empty path in parameter".to_string(),
        ));
    }

    let key = path[0];

    if path.len() == 1 {
        // Leaf node - insert the value
        current.insert(key.to_string(), parse_value(value));
    } else {
        // Intermediate node - ensure object exists and recurse
        let next_map = current
            .entry(key.to_string())
            .or_insert_with(|| JsonValue::Object(Map::new()));

        if let JsonValue::Object(map) = next_map {
            insert_at_path(map, &path[1..], value, depth + 1)?;
        } else {
            return Err(RecordDataError::InvalidOperation(format!(
                "Cannot create nested structure: '{}' is not an object",
                key
            )));
        }
    }

    Ok(())
}

/// Parse string value into appropriate JSON type
fn parse_value(value_str: &str) -> JsonValue {
    // Try parsing as different types
    if value_str.is_empty() {
        return JsonValue::String(String::new());
    }

    // Boolean
    if value_str == "true" {
        return JsonValue::Bool(true);
    }
    if value_str == "false" {
        return JsonValue::Bool(false);
    }

    // Null
    if value_str == "null" {
        return JsonValue::Null;
    }

    // Integer
    if let Ok(i) = value_str.parse::<i64>() {
        return JsonValue::Number(i.into());
    }

    // Float
    if let Ok(f) = value_str.parse::<f64>() {
        if let Some(num) = serde_json::Number::from_f64(f) {
            return JsonValue::Number(num);
        }
    }

    // Default to string
    JsonValue::String(value_str.to_string())
}

/// Validate parameter structure depth
pub fn validate_parameter_depth(fields: &[(String, String)]) -> Result<(), String> {
    for (key, _) in fields {
        let depth = key.split('.').count();
        if depth > MAX_NESTING_DEPTH {
            return Err(format!(
                "Parameter '{}' has depth {} which exceeds maximum {}",
                key, depth, MAX_NESTING_DEPTH
            ));
        }
    }
    Ok(())
}

/// Extract parameters from object elements during resolution
pub fn extract_parameter_fields(
    param_fields: &[(String, String)],
) -> Result<RecordData, RecordDataError> {
    parse_parameters(param_fields, DataType::RecordData)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_flat_parameters() {
        let fields = vec![
            ("Name".to_string(), "TestApp".to_string()),
            ("Version".to_string(), "1.0.0".to_string()),
        ];

        let record = parse_parameters(&fields, DataType::RecordData).unwrap();
        let json = record.as_json_value();

        assert_eq!(json["Name"], JsonValue::String("TestApp".to_string()));
        assert_eq!(json["Version"], JsonValue::String("1.0.0".to_string()));
    }

    #[test]
    fn test_nested_parameters() {
        let fields = vec![
            ("Config.Database.Host".to_string(), "localhost".to_string()),
            ("Config.Database.Port".to_string(), "5432".to_string()),
            ("Config.Timeout".to_string(), "30".to_string()),
        ];

        let record = parse_parameters(&fields, DataType::RecordData).unwrap();
        let json = record.as_json_value();

        assert_eq!(
            json["Config"]["Database"]["Host"],
            JsonValue::String("localhost".to_string())
        );
        assert_eq!(
            json["Config"]["Database"]["Port"],
            JsonValue::Number(5432.into())
        );
        assert_eq!(json["Config"]["Timeout"], JsonValue::Number(30.into()));
    }

    #[test]
    fn test_type_inference() {
        let fields = vec![
            ("StringVal".to_string(), "hello".to_string()),
            ("IntVal".to_string(), "42".to_string()),
            ("FloatVal".to_string(), "3.14".to_string()),
            ("BoolVal".to_string(), "true".to_string()),
        ];

        let record = parse_parameters(&fields, DataType::RecordData).unwrap();
        let json = record.as_json_value();

        assert!(matches!(json["StringVal"], JsonValue::String(_)));
        assert!(matches!(json["IntVal"], JsonValue::Number(_)));
        assert!(matches!(json["FloatVal"], JsonValue::Number(_)));
        assert_eq!(json["BoolVal"], JsonValue::Bool(true));
    }

    #[test]
    fn test_max_depth_validation() {
        let mut deep_key = String::new();
        for i in 0..15 {
            if i > 0 {
                deep_key.push('.');
            }
            deep_key.push_str(&format!("level{}", i));
        }

        let fields = vec![(deep_key, "value".to_string())];

        let result = parse_parameters(&fields, DataType::RecordData);
        assert!(result.is_err());
    }

    #[test]
    fn test_from_smoke_test() {
        // From smoke-test.esp complex_object parameters
        let fields = vec![
            ("CommandName".to_string(), "Get-SecurityAudit".to_string()),
            (
                "FilterScript".to_string(),
                "{$_.Severity -eq 'High'}".to_string(),
            ),
            ("MaxCount".to_string(), "100".to_string()),
            ("IncludeDetails".to_string(), "true".to_string()),
        ];

        let record = parse_parameters(&fields, DataType::RecordData).unwrap();
        let json = record.as_json_value();

        assert_eq!(
            json["CommandName"],
            JsonValue::String("Get-SecurityAudit".to_string())
        );
        assert_eq!(json["MaxCount"], JsonValue::Number(100.into()));
        assert_eq!(json["IncludeDetails"], JsonValue::Bool(true));
    }

    #[test]
    fn test_conflicting_paths() {
        // Test that we can't create both "Config" as string and "Config.Database" as object
        let fields = vec![
            ("Config".to_string(), "value".to_string()),
            ("Config.Database".to_string(), "localhost".to_string()),
        ];

        // First insertion creates Config as string, second should fail
        let result = parse_parameters(&fields, DataType::RecordData);
        assert!(result.is_err());
    }
}
