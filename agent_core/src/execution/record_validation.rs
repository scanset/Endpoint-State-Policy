//! Record check validation logic
//!
//! Handles validation of RecordData against record checks from states.

use crate::execution::comparisons::ComparisonExt;
use crate::types::common::{DataType, Operation, RecordData, ResolvedValue};
use crate::types::execution_context::{
    ExecutableRecordCheck, ExecutableRecordContent, ExecutableRecordField,
};
use crate::types::field_path_extensions::{FieldPathExt, PathComponent};
use crate::types::EntityCheck;

/// Result of validating a single record field or check
#[derive(Debug, Clone)]
pub struct RecordValidationResult {
    pub field_path: String,
    pub passed: bool,
    pub message: String,
    pub expected: Option<String>,
    pub actual: Option<String>,
}

/// Validate all record checks against collected record data
pub fn validate_record_checks(
    record_data: &RecordData,
    record_checks: &[ExecutableRecordCheck],
) -> Result<Vec<RecordValidationResult>, String> {
    let mut results = Vec::new();

    for check in record_checks {
        match &check.content {
            ExecutableRecordContent::Direct { operation, value } => {
                let result = validate_direct_record(record_data, *operation, value)?;
                results.push(result);
            }
            ExecutableRecordContent::Nested { fields } => {
                let field_results = validate_nested_fields(record_data, fields)?;
                results.extend(field_results);
            }
        }
    }

    Ok(results)
}

/// Validate entire record with direct operation
fn validate_direct_record(
    record_data: &RecordData,
    operation: Operation,
    expected: &ResolvedValue,
) -> Result<RecordValidationResult, String> {
    let actual = ResolvedValue::RecordData(Box::new(record_data.clone()));

    let passed = actual
        .compare_with(expected, operation)
        .map_err(|e| format!("Direct record comparison failed: {}", e))?;

    Ok(RecordValidationResult {
        field_path: "<record>".to_string(),
        passed,
        message: if passed {
            "Record validation passed".to_string()
        } else {
            format!("Record validation failed for operation {:?}", operation)
        },
        expected: Some(format!("{:?}", expected)),
        actual: Some("<record_data>".to_string()),
    })
}

/// Validate nested fields in record
fn validate_nested_fields(
    record_data: &RecordData,
    fields: &[ExecutableRecordField],
) -> Result<Vec<RecordValidationResult>, String> {
    let mut results = Vec::new();

    for field in fields {
        // Check if field path has wildcards
        if field.path.has_wildcards() {
            // Collection validation with entity check
            let collection_result = validate_field_collection(record_data, field)?;
            results.push(collection_result);
        } else {
            // Single value validation - but the value might still be an array!
            let single_result = validate_field_single(record_data, field)?;
            results.push(single_result);
        }
    }

    Ok(results)
}

// ============================================================================
// WILDCARD PATH EXPANSION
// ============================================================================

/// Expand a wildcard path against a JSON value, returning all matching values
///
/// For example, given path "spec.containers.*.image" and JSON:
/// ```json
/// {
///   "spec": {
///     "containers": [
///       {"image": "nginx:1.19"},
///       {"image": "envoy:1.20"}
///     ]
///   }
/// }
/// ```
/// Returns: ["nginx:1.19", "envoy:1.20"]
fn expand_wildcard_path<'a>(
    value: &'a serde_json::Value,
    components: &[PathComponent],
) -> Vec<&'a serde_json::Value> {
    if components.is_empty() {
        return vec![value];
    }

    let (current, rest) = (&components[0], &components[1..]);

    match current {
        PathComponent::Field(field_name) => {
            // Navigate to named field
            match value.get(field_name) {
                Some(child) => expand_wildcard_path(child, rest),
                None => Vec::new(),
            }
        }
        PathComponent::Index(idx) => {
            // Navigate to array index
            match value.get(*idx) {
                Some(child) => expand_wildcard_path(child, rest),
                None => Vec::new(),
            }
        }
        PathComponent::Wildcard => {
            // Expand across all array elements or object values
            let mut results = Vec::new();

            match value {
                serde_json::Value::Array(arr) => {
                    for item in arr {
                        results.extend(expand_wildcard_path(item, rest));
                    }
                }
                serde_json::Value::Object(map) => {
                    for (_key, child) in map {
                        results.extend(expand_wildcard_path(child, rest));
                    }
                }
                _ => {
                    // Wildcard on non-collection - return empty
                }
            }

            results
        }
    }
}

/// Validate a field with wildcard path (collection validation)
///
/// NOTE: The expanded values might themselves be arrays (e.g., spec.containers.*.command
/// where each container's command is an array of strings). In that case, we need to
/// flatten and iterate through those nested arrays.
fn validate_field_collection(
    record_data: &RecordData,
    field: &ExecutableRecordField,
) -> Result<RecordValidationResult, String> {
    // Parse field path into components
    let components = field.path.parse_components();

    // Expand wildcard path to get all matching values
    let json_values = expand_wildcard_path(record_data.as_json_value(), &components);

    if json_values.is_empty() {
        // No matches found - behavior depends on entity check
        let entity_check = field.entity_check.unwrap_or(EntityCheck::All);
        let passed = match entity_check {
            EntityCheck::None => true, // "none" passes when no items exist
            _ => false,                // Other checks fail when no items exist
        };

        return Ok(RecordValidationResult {
            field_path: field.path.to_dot_notation(),
            passed,
            message: format!(
                "No values matched wildcard path '{}' (entity check: {})",
                field.path.to_dot_notation(),
                entity_check.as_str()
            ),
            expected: Some(format!("{:?}", field.value)),
            actual: Some("no matching values".to_string()),
        });
    }

    // =========================================================================
    // FIX: Handle nested arrays for string operations
    // =========================================================================
    // If we're doing a string operation and the expanded values are arrays,
    // we need to flatten them and iterate through the elements.
    if is_string_operation(field.operation) {
        // Check if any of the expanded values are arrays
        let has_array_values = json_values.iter().any(|v| v.is_array());

        if has_array_values {
            return validate_collection_with_nested_arrays(field, &json_values);
        }
    }

    // Standard collection validation (no nested arrays)
    let mut comparison_results = Vec::new();
    let mut actual_values = Vec::new();

    for json_value in &json_values {
        // Convert JSON to ResolvedValue based on expected type
        let actual_value = json_to_resolved_value(json_value, field.data_type);

        let passed = match actual_value {
            Ok(ref actual) => {
                // Use ComparisonExt for consistent comparison logic
                actual
                    .compare_with(&field.value, field.operation)
                    .unwrap_or(false)
            }
            Err(_) => {
                // Type conversion failed - treat as non-match
                false
            }
        };

        comparison_results.push(passed);
        if let Ok(val) = actual_value {
            actual_values.push(val);
        }
    }

    // Apply entity check to aggregate results
    let entity_check = field.entity_check.unwrap_or(EntityCheck::All);
    let final_passed = apply_entity_check_to_collection(&comparison_results, entity_check);

    // Create detailed message
    let passing_count = comparison_results.iter().filter(|&&p| p).count();
    let total_count = comparison_results.len();

    let message = if final_passed {
        format!(
            "Collection validation passed ({}): {} of {} items matched (entity check: {})",
            field.path.to_dot_notation(),
            passing_count,
            total_count,
            entity_check.as_str()
        )
    } else {
        format!(
            "Collection validation failed ({}): {} of {} items matched (entity check: {} requires {})",
            field.path.to_dot_notation(),
            passing_count,
            total_count,
            entity_check.as_str(),
            match entity_check {
                EntityCheck::All => "all items",
                EntityCheck::AtLeastOne => "at least one item",
                EntityCheck::None => "no items",
                EntityCheck::OnlyOne => "exactly one item",
            }
        )
    };

    Ok(RecordValidationResult {
        field_path: field.path.to_dot_notation(),
        passed: final_passed,
        message,
        expected: Some(format!("{:?}", field.value)),
        actual: Some(format!(
            "{} values: {:?}",
            actual_values.len(),
            actual_values
        )),
    })
}

/// Validate a collection where expanded values may contain nested arrays
///
/// This handles paths like `spec.containers.*.command` where each container's
/// command is itself an array of strings.
fn validate_collection_with_nested_arrays(
    field: &ExecutableRecordField,
    json_values: &[&serde_json::Value],
) -> Result<RecordValidationResult, String> {
    use crate::execution::comparisons::string;

    // Get the expected value as a string
    let expected_str = match &field.value {
        ResolvedValue::String(s) => s.clone(),
        other => format_value(other),
    };

    // Flatten all arrays and collect scalar values
    let mut comparison_results = Vec::new();
    let mut actual_values = Vec::new();

    for json_value in json_values {
        match json_value {
            serde_json::Value::Array(arr) => {
                // Iterate through array elements
                for item in arr {
                    let actual_str = match item {
                        serde_json::Value::String(s) => s.clone(),
                        serde_json::Value::Number(n) => n.to_string(),
                        serde_json::Value::Bool(b) => b.to_string(),
                        _ => continue, // Skip non-scalar values
                    };

                    actual_values.push(actual_str.clone());

                    // Perform the string comparison
                    let passed = string::compare(&actual_str, &expected_str, field.operation)
                        .unwrap_or(false);

                    comparison_results.push(passed);
                }
            }
            // Handle scalar values directly
            serde_json::Value::String(s) => {
                actual_values.push(s.clone());
                let passed = string::compare(s, &expected_str, field.operation).unwrap_or(false);
                comparison_results.push(passed);
            }
            serde_json::Value::Number(n) => {
                let s = n.to_string();
                actual_values.push(s.clone());
                let passed = string::compare(&s, &expected_str, field.operation).unwrap_or(false);
                comparison_results.push(passed);
            }
            serde_json::Value::Bool(b) => {
                let s = b.to_string();
                actual_values.push(s.clone());
                let passed = string::compare(&s, &expected_str, field.operation).unwrap_or(false);
                comparison_results.push(passed);
            }
            _ => continue,
        }
    }

    if comparison_results.is_empty() {
        let entity_check = field.entity_check.unwrap_or(EntityCheck::All);
        let passed = matches!(entity_check, EntityCheck::None);

        return Ok(RecordValidationResult {
            field_path: field.path.to_dot_notation(),
            passed,
            message: format!(
                "Collection '{}' contains no scalar values to compare",
                field.path.to_dot_notation()
            ),
            expected: Some(format_value(&field.value)),
            actual: Some("empty or non-scalar collection".to_string()),
        });
    }

    // Apply entity check to aggregate results
    let entity_check = field.entity_check.unwrap_or(EntityCheck::AtLeastOne);
    let final_passed = apply_entity_check_to_collection(&comparison_results, entity_check);

    // Create detailed message
    let passing_count = comparison_results.iter().filter(|&&p| p).count();
    let total_count = comparison_results.len();

    let message = if final_passed {
        format!(
            "Collection validation passed ({}): {} of {} elements matched '{}' (entity check: {})",
            field.path.to_dot_notation(),
            passing_count,
            total_count,
            expected_str,
            entity_check.as_str()
        )
    } else {
        format!(
            "Collection validation failed ({}): {} of {} elements matched '{}' (entity check: {} requires {})",
            field.path.to_dot_notation(),
            passing_count,
            total_count,
            expected_str,
            entity_check.as_str(),
            match entity_check {
                EntityCheck::All => "all elements",
                EntityCheck::AtLeastOne => "at least one element",
                EntityCheck::None => "no elements",
                EntityCheck::OnlyOne => "exactly one element",
            }
        )
    };

    Ok(RecordValidationResult {
        field_path: field.path.to_dot_notation(),
        passed: final_passed,
        message,
        expected: Some(format_value(&field.value)),
        actual: Some(format!("[{} elements]", actual_values.len())),
    })
}

/// Validate a single field value
///
/// NOTE: Even though the path has no wildcards, the resolved value might still
/// be an array (e.g., spec.containers.0.command is an array of strings).
/// In that case, we need to iterate through the array elements.
fn validate_field_single(
    record_data: &RecordData,
    field: &ExecutableRecordField,
) -> Result<RecordValidationResult, String> {
    // Parse components to handle both dot notation and numeric indices
    let components = field.path.parse_components();

    // Use our path expansion (which handles indices) to get single value
    let json_values = expand_wildcard_path(record_data.as_json_value(), &components);

    let json_value = match json_values.first() {
        Some(v) => *v,
        None => {
            return Ok(RecordValidationResult {
                field_path: field.path.to_dot_notation(),
                passed: false,
                message: format!(
                    "Field '{}' not found in record",
                    field.path.to_dot_notation()
                ),
                expected: Some(format!("{:?}", field.value)),
                actual: None,
            });
        }
    };

    // =========================================================================
    // FIX: Handle array values for string operations
    // =========================================================================
    // If the JSON value is an array and we're doing a string operation,
    // iterate through the array elements and apply the entity check.
    if let serde_json::Value::Array(arr) = json_value {
        // Check if this is a string operation that should iterate over array elements
        if is_string_operation(field.operation) {
            return validate_array_with_string_operation(field, arr);
        }
    }

    // Convert to ResolvedValue
    let actual_value = json_to_resolved_value(json_value, field.data_type).map_err(|e| {
        format!(
            "Type conversion failed for field '{}': {}",
            field.path.to_dot_notation(),
            e
        )
    })?;

    // Use ComparisonExt for comparison
    let comparison_passed = actual_value
        .compare_with(&field.value, field.operation)
        .unwrap_or_else(|_e| {
            // If comparison trait fails, try direct comparison for simple types
            match (field.operation, &actual_value, &field.value) {
                (Operation::Equals, a, b) => a == b,
                (Operation::NotEqual, a, b) => a != b,
                (Operation::GreaterThan, ResolvedValue::Integer(a), ResolvedValue::Integer(b)) => {
                    a > b
                }
                (Operation::LessThan, ResolvedValue::Integer(a), ResolvedValue::Integer(b)) => {
                    a < b
                }
                (
                    Operation::GreaterThanOrEqual,
                    ResolvedValue::Integer(a),
                    ResolvedValue::Integer(b),
                ) => a >= b,
                (
                    Operation::LessThanOrEqual,
                    ResolvedValue::Integer(a),
                    ResolvedValue::Integer(b),
                ) => a <= b,
                _ => false,
            }
        });

    // Apply entity check if present (for single values)
    let final_passed = if let Some(entity_check) = field.entity_check {
        apply_entity_check(comparison_passed, entity_check)
    } else {
        comparison_passed
    };

    Ok(RecordValidationResult {
        field_path: field.path.to_dot_notation(),
        passed: final_passed,
        message: if final_passed {
            format!("Field '{}' validation passed", field.path.to_dot_notation())
        } else {
            format!(
                "Field '{}' validation failed: expected {} {:?} {}",
                field.path.to_dot_notation(),
                format_value(&field.value),
                field.operation,
                format_value(&actual_value)
            )
        },
        expected: Some(format_value(&field.value)),
        actual: Some(format_value(&actual_value)),
    })
}

// ============================================================================
// Array handling for string operations
// ============================================================================

/// Check if an operation is a string operation that should iterate over array elements
fn is_string_operation(operation: Operation) -> bool {
    matches!(
        operation,
        Operation::Contains
            | Operation::NotContains
            | Operation::StartsWith
            | Operation::NotStartsWith
            | Operation::EndsWith
            | Operation::NotEndsWith
            | Operation::PatternMatch
            | Operation::Matches
            | Operation::Equals
            | Operation::NotEqual
            | Operation::CaseInsensitiveEquals
            | Operation::CaseInsensitiveNotEqual
    )
}

/// Validate an array field with string operations
///
/// This handles the case where a path like `spec.containers.0.command` resolves
/// to an array of strings (command-line arguments), and we want to check if any
/// element in the array contains a specific value.
fn validate_array_with_string_operation(
    field: &ExecutableRecordField,
    arr: &[serde_json::Value],
) -> Result<RecordValidationResult, String> {
    use crate::execution::comparisons::string;

    // Get the expected value as a string
    let expected_str = match &field.value {
        ResolvedValue::String(s) => s.clone(),
        other => {
            // If expected is not a string, fall back to format representation
            format_value(other)
        }
    };

    // Check each element in the array
    let mut comparison_results = Vec::new();
    let mut actual_values = Vec::new();

    for item in arr {
        let actual_str = match item {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Number(n) => n.to_string(),
            serde_json::Value::Bool(b) => b.to_string(),
            _ => continue, // Skip non-scalar values
        };

        actual_values.push(actual_str.clone());

        // Perform the string comparison
        let passed = string::compare(&actual_str, &expected_str, field.operation).unwrap_or(false);

        comparison_results.push(passed);
    }

    if comparison_results.is_empty() {
        // No scalar values found in array
        let entity_check = field.entity_check.unwrap_or(EntityCheck::All);
        let passed = matches!(entity_check, EntityCheck::None);

        return Ok(RecordValidationResult {
            field_path: field.path.to_dot_notation(),
            passed,
            message: format!(
                "Array '{}' contains no scalar values to compare",
                field.path.to_dot_notation()
            ),
            expected: Some(format_value(&field.value)),
            actual: Some("empty or non-scalar array".to_string()),
        });
    }

    // Apply entity check to aggregate results
    let entity_check = field.entity_check.unwrap_or(EntityCheck::AtLeastOne);
    let final_passed = apply_entity_check_to_collection(&comparison_results, entity_check);

    // Create detailed message
    let passing_count = comparison_results.iter().filter(|&&p| p).count();
    let total_count = comparison_results.len();

    let message = if final_passed {
        format!(
            "Array validation passed ({}): {} of {} elements matched '{}' (entity check: {})",
            field.path.to_dot_notation(),
            passing_count,
            total_count,
            expected_str,
            entity_check.as_str()
        )
    } else {
        format!(
            "Array validation failed ({}): {} of {} elements matched '{}' (entity check: {} requires {})",
            field.path.to_dot_notation(),
            passing_count,
            total_count,
            expected_str,
            entity_check.as_str(),
            match entity_check {
                EntityCheck::All => "all elements",
                EntityCheck::AtLeastOne => "at least one element",
                EntityCheck::None => "no elements",
                EntityCheck::OnlyOne => "exactly one element",
            }
        )
    };

    Ok(RecordValidationResult {
        field_path: field.path.to_dot_notation(),
        passed: final_passed,
        message,
        expected: Some(format_value(&field.value)),
        actual: Some(format!("[{} elements]", actual_values.len())),
    })
}

/// Convert JSON value to ResolvedValue with type hint
fn json_to_resolved_value(
    json: &serde_json::Value,
    data_type: DataType,
) -> Result<ResolvedValue, String> {
    match (json, data_type) {
        // String conversion - also handle numbers/bools as strings if requested
        (serde_json::Value::String(s), DataType::String) => Ok(ResolvedValue::String(s.clone())),
        (serde_json::Value::Number(n), DataType::String) => {
            Ok(ResolvedValue::String(n.to_string()))
        }
        (serde_json::Value::Bool(b), DataType::String) => Ok(ResolvedValue::String(b.to_string())),

        // Integer conversion
        (serde_json::Value::Number(n), DataType::Int) => n
            .as_i64()
            .map(ResolvedValue::Integer)
            .ok_or_else(|| "Number is not a valid integer".to_string()),

        // Float conversion
        (serde_json::Value::Number(n), DataType::Float) => n
            .as_f64()
            .map(ResolvedValue::Float)
            .ok_or_else(|| "Number is not a valid float".to_string()),

        // Boolean conversion
        (serde_json::Value::Bool(b), DataType::Boolean) => Ok(ResolvedValue::Boolean(*b)),

        // Array to Collection
        (serde_json::Value::Array(items), _) => {
            let resolved_items: Result<Vec<_>, _> = items
                .iter()
                .map(|item| json_to_resolved_value(item, data_type))
                .collect();
            Ok(ResolvedValue::Collection(resolved_items?))
        }

        // Object to RecordData
        (serde_json::Value::Object(_), DataType::RecordData) => Ok(ResolvedValue::RecordData(
            Box::new(RecordData::from_json_value(json.clone())),
        )),

        // Auto-detect type if RecordData is requested but we have a primitive
        (serde_json::Value::String(s), DataType::RecordData) => {
            Ok(ResolvedValue::String(s.clone()))
        }
        (serde_json::Value::Number(n), DataType::RecordData) => {
            if let Some(i) = n.as_i64() {
                Ok(ResolvedValue::Integer(i))
            } else if let Some(f) = n.as_f64() {
                Ok(ResolvedValue::Float(f))
            } else {
                Err("Invalid number".to_string())
            }
        }
        (serde_json::Value::Bool(b), DataType::RecordData) => Ok(ResolvedValue::Boolean(*b)),

        // Null handling
        (serde_json::Value::Null, _) => Err("Cannot convert null to ResolvedValue".to_string()),

        // Type mismatch
        _ => Err(format!(
            "Cannot convert JSON type {:?} to {:?}",
            json, data_type
        )),
    }
}

/// Apply entity check to validation result (for single values)
fn apply_entity_check(passed: bool, entity_check: EntityCheck) -> bool {
    match entity_check {
        EntityCheck::All => passed,        // Must pass
        EntityCheck::AtLeastOne => passed, // Must pass
        EntityCheck::None => !passed,      // Must fail
        EntityCheck::OnlyOne => passed,    // Must pass (single value)
    }
}

/// Apply entity check to collection of boolean results
fn apply_entity_check_to_collection(results: &[bool], entity_check: EntityCheck) -> bool {
    match entity_check {
        EntityCheck::All => results.iter().all(|&r| r),
        EntityCheck::AtLeastOne => results.iter().any(|&r| r),
        EntityCheck::None => !results.iter().any(|&r| r),
        EntityCheck::OnlyOne => results.iter().filter(|&&r| r).count() == 1,
    }
}

/// Format a ResolvedValue for display
fn format_value(value: &ResolvedValue) -> String {
    match value {
        ResolvedValue::String(s) => format!("\"{}\"", s),
        ResolvedValue::Integer(i) => i.to_string(),
        ResolvedValue::Float(f) => f.to_string(),
        ResolvedValue::Boolean(b) => b.to_string(),
        ResolvedValue::Version(v) => format!("version({})", v),
        ResolvedValue::EvrString(e) => format!("evr({})", e),
        ResolvedValue::Binary(b) => format!("binary({} bytes)", b.len()),
        ResolvedValue::RecordData(_) => "<record>".to_string(),
        ResolvedValue::Collection(items) => format!("[{} items]", items.len()),
    }
}

// ============================================================================
// TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_json_to_resolved_value() {
        let json = serde_json::json!("test");
        let result = json_to_resolved_value(&json, DataType::String);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ResolvedValue::String("test".to_string()));
    }

    #[test]
    fn test_json_to_integer() {
        let json = serde_json::json!(42);
        let result = json_to_resolved_value(&json, DataType::Int);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ResolvedValue::Integer(42));
    }

    #[test]
    fn test_json_to_boolean() {
        let json = serde_json::json!(true);
        let result = json_to_resolved_value(&json, DataType::Boolean);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), ResolvedValue::Boolean(true));
    }

    #[test]
    fn test_entity_check_application() {
        assert!(apply_entity_check(true, EntityCheck::All));
        assert!(apply_entity_check(false, EntityCheck::None));
        assert!(!apply_entity_check(true, EntityCheck::None));
        assert!(apply_entity_check(true, EntityCheck::AtLeastOne));
    }

    #[test]
    fn test_entity_check_collection_all() {
        assert!(apply_entity_check_to_collection(
            &[true, true, true],
            EntityCheck::All
        ));
        assert!(!apply_entity_check_to_collection(
            &[true, false, true],
            EntityCheck::All
        ));
    }

    #[test]
    fn test_entity_check_collection_at_least_one() {
        assert!(apply_entity_check_to_collection(
            &[false, false, true],
            EntityCheck::AtLeastOne
        ));
        assert!(!apply_entity_check_to_collection(
            &[false, false, false],
            EntityCheck::AtLeastOne
        ));
    }

    #[test]
    fn test_entity_check_collection_none() {
        assert!(apply_entity_check_to_collection(
            &[false, false, false],
            EntityCheck::None
        ));
        assert!(!apply_entity_check_to_collection(
            &[true, false, false],
            EntityCheck::None
        ));
    }

    #[test]
    fn test_entity_check_collection_only_one() {
        assert!(apply_entity_check_to_collection(
            &[false, true, false],
            EntityCheck::OnlyOne
        ));
        assert!(!apply_entity_check_to_collection(
            &[true, true, false],
            EntityCheck::OnlyOne
        ));
        assert!(!apply_entity_check_to_collection(
            &[false, false, false],
            EntityCheck::OnlyOne
        ));
    }

    #[test]
    fn test_format_value() {
        assert_eq!(
            format_value(&ResolvedValue::String("test".to_string())),
            "\"test\""
        );
        assert_eq!(format_value(&ResolvedValue::Integer(42)), "42");
        assert_eq!(format_value(&ResolvedValue::Boolean(true)), "true");
    }

    // =========================================================================
    // WILDCARD EXPANSION TESTS
    // =========================================================================

    #[test]
    fn test_expand_simple_path() {
        let json = serde_json::json!({
            "metadata": {
                "name": "test-pod"
            }
        });

        let components = vec![
            PathComponent::Field("metadata".to_string()),
            PathComponent::Field("name".to_string()),
        ];

        let results = expand_wildcard_path(&json, &components);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], &serde_json::json!("test-pod"));
    }

    #[test]
    fn test_expand_wildcard_array() {
        let json = serde_json::json!({
            "spec": {
                "containers": [
                    {"name": "app", "image": "nginx:1.19"},
                    {"name": "sidecar", "image": "envoy:1.20"}
                ]
            }
        });

        let components = vec![
            PathComponent::Field("spec".to_string()),
            PathComponent::Field("containers".to_string()),
            PathComponent::Wildcard,
            PathComponent::Field("image".to_string()),
        ];

        let results = expand_wildcard_path(&json, &components);
        assert_eq!(results.len(), 2);
        assert_eq!(results[0], &serde_json::json!("nginx:1.19"));
        assert_eq!(results[1], &serde_json::json!("envoy:1.20"));
    }

    #[test]
    fn test_expand_index_path() {
        let json = serde_json::json!({
            "items": ["first", "second", "third"]
        });

        let components = vec![
            PathComponent::Field("items".to_string()),
            PathComponent::Index(1),
        ];

        let results = expand_wildcard_path(&json, &components);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0], &serde_json::json!("second"));
    }

    #[test]
    fn test_expand_nested_wildcard() {
        let json = serde_json::json!({
            "spec": {
                "containers": [
                    {
                        "name": "app",
                        "ports": [
                            {"containerPort": 8080},
                            {"containerPort": 8443}
                        ]
                    },
                    {
                        "name": "sidecar",
                        "ports": [
                            {"containerPort": 9090}
                        ]
                    }
                ]
            }
        });

        // spec.containers.*.ports.*.containerPort
        let components = vec![
            PathComponent::Field("spec".to_string()),
            PathComponent::Field("containers".to_string()),
            PathComponent::Wildcard,
            PathComponent::Field("ports".to_string()),
            PathComponent::Wildcard,
            PathComponent::Field("containerPort".to_string()),
        ];

        let results = expand_wildcard_path(&json, &components);
        assert_eq!(results.len(), 3);
        assert_eq!(results[0], &serde_json::json!(8080));
        assert_eq!(results[1], &serde_json::json!(8443));
        assert_eq!(results[2], &serde_json::json!(9090));
    }

    #[test]
    fn test_expand_missing_path() {
        let json = serde_json::json!({
            "metadata": {
                "name": "test"
            }
        });

        let components = vec![
            PathComponent::Field("spec".to_string()),
            PathComponent::Field("missing".to_string()),
        ];

        let results = expand_wildcard_path(&json, &components);
        assert!(results.is_empty());
    }

    #[test]
    fn test_expand_wildcard_on_object() {
        let json = serde_json::json!({
            "labels": {
                "app": "nginx",
                "env": "prod",
                "version": "1.0"
            }
        });

        // labels.* - should return all label values
        let components = vec![
            PathComponent::Field("labels".to_string()),
            PathComponent::Wildcard,
        ];

        let results = expand_wildcard_path(&json, &components);
        assert_eq!(results.len(), 3);
        // Note: object iteration order may vary, so just check count
    }

    // =========================================================================
    // Array field validation tests
    // =========================================================================

    #[test]
    fn test_array_field_contains() {
        // Simulates spec.containers.0.command which is an array of strings
        let json = serde_json::json!({
            "spec": {
                "containers": [
                    {
                        "name": "kube-apiserver",
                        "command": [
                            "kube-apiserver",
                            "--authorization-mode=Node,RBAC",
                            "--enable-admission-plugins=NodeRestriction",
                            "--tls-cert-file=/etc/kubernetes/pki/apiserver.crt"
                        ]
                    }
                ]
            }
        });

        let components = vec![
            PathComponent::Field("spec".to_string()),
            PathComponent::Field("containers".to_string()),
            PathComponent::Index(0),
            PathComponent::Field("command".to_string()),
        ];

        let results = expand_wildcard_path(&json, &components);
        assert_eq!(results.len(), 1);

        // The result should be an array
        assert!(results[0].is_array());
        let arr = results[0].as_array().unwrap();
        assert_eq!(arr.len(), 4);

        // Check that the array contains the expected value
        let contains_rbac = arr.iter().any(|v| {
            v.as_str()
                .map(|s| s.contains("--authorization-mode=Node,RBAC"))
                .unwrap_or(false)
        });
        assert!(
            contains_rbac,
            "Array should contain --authorization-mode=Node,RBAC"
        );
    }

    #[test]
    fn test_wildcard_command_array() {
        // Simulates spec.containers.*.command which returns arrays
        let json = serde_json::json!({
            "spec": {
                "containers": [
                    {
                        "name": "kube-apiserver",
                        "command": [
                            "kube-apiserver",
                            "--authorization-mode=Node,RBAC",
                            "--tls-cert-file=/etc/kubernetes/pki/apiserver.crt"
                        ]
                    }
                ]
            }
        });

        let components = vec![
            PathComponent::Field("spec".to_string()),
            PathComponent::Field("containers".to_string()),
            PathComponent::Wildcard,
            PathComponent::Field("command".to_string()),
        ];

        let results = expand_wildcard_path(&json, &components);
        assert_eq!(results.len(), 1);

        // The result should be an array (the command array)
        assert!(results[0].is_array());
        let arr = results[0].as_array().unwrap();
        assert_eq!(arr.len(), 3);
    }

    #[test]
    fn test_is_string_operation() {
        assert!(is_string_operation(Operation::Contains));
        assert!(is_string_operation(Operation::NotContains));
        assert!(is_string_operation(Operation::StartsWith));
        assert!(is_string_operation(Operation::Equals));
        assert!(!is_string_operation(Operation::GreaterThan));
        assert!(!is_string_operation(Operation::LessThan));
    }
}
