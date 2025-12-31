//! # Deferred Operation Execution
//!
//! Handles scan-time operations that require collected data.

use crate::execution::engine::ExecutionError;
use crate::strategies::{CollectedData, CtnStrategyRegistry};
use crate::types::common::{DataType, ResolvedValue};
use crate::types::execution_context::ExecutionContext;
use crate::types::resolution_context::DeferredOperation;
use crate::types::RuntimeOperationType;
use common::ast::nodes::RunParameter;
use regex::Regex;
use std::collections::HashMap;

/// Execute all deferred operations in sequence
pub fn execute_all_deferred_operations(
    context: &mut ExecutionContext,
    _registry: &CtnStrategyRegistry,
    collected_data: &HashMap<String, CollectedData>,
) -> Result<(), ExecutionError> {
    let operations = context.deferred_operations.clone();

    for operation in operations.iter() {
        execute_single_operation(operation, context, collected_data)?;
    }

    Ok(())
}

/// Execute a single deferred operation
fn execute_single_operation(
    operation: &DeferredOperation,
    context: &mut ExecutionContext,
    collected_data: &HashMap<String, CollectedData>,
) -> Result<(), ExecutionError> {
    // Access operation_type through .operation field
    match operation.operation.operation_type {
        RuntimeOperationType::Extract => execute_extract(operation, context, collected_data),
        RuntimeOperationType::Unique => execute_unique(operation, context),
        RuntimeOperationType::Merge => execute_merge(operation, context),
        RuntimeOperationType::End => execute_end(operation, context),
        RuntimeOperationType::Split => execute_split(operation, context),
        RuntimeOperationType::Substring => execute_substring(operation, context),
        RuntimeOperationType::RegexCapture => execute_regex_capture(operation, context),
        RuntimeOperationType::Count => execute_count(operation, context),
        _ => Err(ExecutionError::DeferredOperationFailed {
            operation: format!("{:?}", operation.operation.operation_type),
            reason: "Not a scan-time operation".to_string(),
        }),
    }
}

fn execute_extract(
    operation: &DeferredOperation,
    context: &mut ExecutionContext,
    collected_data: &HashMap<String, CollectedData>,
) -> Result<(), ExecutionError> {
    // Extract object_id from ObjectExtraction parameter
    let object_id = operation.operation.extract_object_id().ok_or_else(|| {
        ExecutionError::DeferredOperationFailed {
            operation: "EXTRACT".to_string(),
            reason: "Missing ObjectExtraction parameter".to_string(),
        }
    })?;

    let data =
        collected_data
            .get(&object_id)
            .ok_or_else(|| ExecutionError::DataCollectionFailed {
                object_id: object_id.clone(),
                reason: "Object not in collected data".to_string(),
            })?;

    // Access parameters through .operation field
    let field_name = extract_field_name_from_parameters(&operation.operation.parameters)?;

    let field_value = data.get_field(&field_name).cloned().ok_or_else(|| {
        ExecutionError::DeferredOperationFailed {
            operation: "EXTRACT".to_string(),
            reason: format!("Field '{}' not found in collected data", field_name),
        }
    })?;

    update_target_variable(context, &operation.target_variable, field_value)?;
    Ok(())
}

fn execute_unique(
    operation: &DeferredOperation,
    context: &mut ExecutionContext,
) -> Result<(), ExecutionError> {
    let source_var_name = get_source_variable_name(operation)?;

    let source_value = context
        .global_variables
        .get(&source_var_name)
        .ok_or_else(|| ExecutionError::DeferredOperationFailed {
            operation: "UNIQUE".to_string(),
            reason: format!("Source variable '{}' not found", source_var_name),
        })?;

    let collection = match &source_value.value {
        ResolvedValue::Collection(items) => items.clone(),
        _ => {
            return Err(ExecutionError::DeferredOperationFailed {
                operation: "UNIQUE".to_string(),
                reason: format!("Variable '{}' is not a collection", source_var_name),
            })
        }
    };

    let unique_items = deduplicate_collection(collection);
    update_target_variable(
        context,
        &operation.target_variable,
        ResolvedValue::Collection(unique_items),
    )?;
    Ok(())
}

fn execute_merge(
    operation: &DeferredOperation,
    context: &mut ExecutionContext,
) -> Result<(), ExecutionError> {
    let source_var_names = get_all_source_variable_names(operation)?;

    if source_var_names.is_empty() {
        return Err(ExecutionError::DeferredOperationFailed {
            operation: "MERGE".to_string(),
            reason: "No source variables specified".to_string(),
        });
    }

    let mut all_items = Vec::new();

    for var_name in source_var_names {
        let var = context.global_variables.get(&var_name).ok_or_else(|| {
            ExecutionError::DeferredOperationFailed {
                operation: "MERGE".to_string(),
                reason: format!("Source variable '{}' not found", var_name),
            }
        })?;

        match &var.value {
            ResolvedValue::Collection(items) => all_items.extend(items.clone()),
            _ => {
                return Err(ExecutionError::DeferredOperationFailed {
                    operation: "MERGE".to_string(),
                    reason: format!("Variable '{}' is not a collection", var_name),
                })
            }
        }
    }

    update_target_variable(
        context,
        &operation.target_variable,
        ResolvedValue::Collection(all_items),
    )?;
    Ok(())
}

fn execute_end(
    operation: &DeferredOperation,
    context: &mut ExecutionContext,
) -> Result<(), ExecutionError> {
    let source_var_name = get_source_variable_name(operation)?;

    let source_value = context
        .global_variables
        .get(&source_var_name)
        .ok_or_else(|| ExecutionError::DeferredOperationFailed {
            operation: "END".to_string(),
            reason: format!("Source variable '{}' not found", source_var_name),
        })?;

    update_target_variable(
        context,
        &operation.target_variable,
        source_value.value.clone(),
    )?;
    Ok(())
}

/// Execute SPLIT operation - split string by delimiter into collection
fn execute_split(
    operation: &DeferredOperation,
    context: &mut ExecutionContext,
) -> Result<(), ExecutionError> {
    // 1. Get source variable name (the string to split)
    let source_var_name = get_source_variable_name(operation)?;

    // 2. Get delimiter from parameters (access through .operation field)
    let delimiter = extract_delimiter_from_parameters(&operation.operation.parameters)?;

    // 3. Get source variable value
    let source_value = context
        .global_variables
        .get(&source_var_name)
        .ok_or_else(|| ExecutionError::DeferredOperationFailed {
            operation: "SPLIT".to_string(),
            reason: format!("Source variable '{}' not found", source_var_name),
        })?;

    // 4. Extract string value
    let source_string = match &source_value.value {
        ResolvedValue::String(s) => s.clone(),
        _ => {
            return Err(ExecutionError::DeferredOperationFailed {
                operation: "SPLIT".to_string(),
                reason: format!(
                    "Variable '{}' is not a string (type: {:?})",
                    source_var_name, source_value.data_type
                ),
            })
        }
    };

    // 5. Perform split operation
    let parts: Vec<ResolvedValue> = source_string
        .split(&delimiter)
        .map(|s| ResolvedValue::String(s.to_string()))
        .collect();

    // 6. Update target variable as Collection
    update_target_variable(
        context,
        &operation.target_variable,
        ResolvedValue::Collection(parts),
    )?;

    Ok(())
}

/// Execute REGEX_CAPTURE operation - extract matched groups
fn execute_regex_capture(
    operation: &DeferredOperation,
    context: &mut ExecutionContext,
) -> Result<(), ExecutionError> {
    // 1. Get source variable name
    let source_var_name = get_source_variable_name(operation)?;

    // 2. Extract pattern from parameters (access through .operation field)
    let pattern = extract_pattern_from_parameters(&operation.operation.parameters)?;

    // 3. Get source variable value
    let source_value = context
        .global_variables
        .get(&source_var_name)
        .ok_or_else(|| ExecutionError::DeferredOperationFailed {
            operation: "REGEX_CAPTURE".to_string(),
            reason: format!("Source variable '{}' not found", source_var_name),
        })?;

    // 4. Extract string value
    let source_string = match &source_value.value {
        ResolvedValue::String(s) => s.clone(),
        _ => {
            return Err(ExecutionError::DeferredOperationFailed {
                operation: "REGEX_CAPTURE".to_string(),
                reason: format!(
                    "Variable '{}' is not a string (type: {:?})",
                    source_var_name, source_value.data_type
                ),
            })
        }
    };

    // 5. Compile regex and capture
    let regex = Regex::new(&pattern).map_err(|e| ExecutionError::DeferredOperationFailed {
        operation: "REGEX_CAPTURE".to_string(),
        reason: format!("Invalid regex pattern '{}': {}", pattern, e),
    })?;

    // 6. Capture all groups
    let captures: Vec<ResolvedValue> = if let Some(caps) = regex.captures(&source_string) {
        caps.iter()
            .skip(1) // Skip capture group 0 (full match)
            .filter_map(|cap| cap.map(|m| ResolvedValue::String(m.as_str().to_string())))
            .collect()
    } else {
        Vec::new()
    };

    // 7. Update target variable as Collection
    update_target_variable(
        context,
        &operation.target_variable,
        ResolvedValue::Collection(captures),
    )?;

    Ok(())
}

/// Execute COUNT operation - count items in collection
fn execute_count(
    operation: &DeferredOperation,
    context: &mut ExecutionContext,
) -> Result<(), ExecutionError> {
    // 1. Get source variable name
    let source_var_name = get_source_variable_name(operation)?;

    // 2. Get source variable value
    let source_value = context
        .global_variables
        .get(&source_var_name)
        .ok_or_else(|| ExecutionError::DeferredOperationFailed {
            operation: "COUNT".to_string(),
            reason: format!("Source variable '{}' not found", source_var_name),
        })?;

    // 3. Count based on type
    let count = match &source_value.value {
        ResolvedValue::Collection(items) => items.len() as i64,
        ResolvedValue::String(s) => {
            // Empty string counts as 0, non-empty as 1
            if s.is_empty() {
                0
            } else {
                1
            }
        }
        // Any other single value counts as 1
        _ => 1,
    };

    // 4. Update target variable with count
    update_target_variable(
        context,
        &operation.target_variable,
        ResolvedValue::Integer(count),
    )?;

    Ok(())
}

/// Helper: Update target variable in context
fn update_target_variable(
    context: &mut ExecutionContext,
    target_name: &str,
    value: ResolvedValue,
) -> Result<(), ExecutionError> {
    use crate::types::variable::ResolvedVariable;

    // Infer data type from resolved value
    let data_type = match &value {
        ResolvedValue::String(_) => DataType::String,
        ResolvedValue::Integer(_) => DataType::Int,
        ResolvedValue::Float(_) => DataType::Float,
        ResolvedValue::Boolean(_) => DataType::Boolean,
        ResolvedValue::Version(_) => DataType::Version,
        ResolvedValue::EvrString(_) => DataType::EvrString,
        ResolvedValue::Collection(_) => DataType::String, // Collection type doesn't exist in DataType
        ResolvedValue::RecordData(_) => DataType::RecordData,
        ResolvedValue::Binary(_) => DataType::Binary,
    };

    let resolved_var = ResolvedVariable::new(target_name.to_string(), data_type, value);

    context
        .global_variables
        .insert(target_name.to_string(), resolved_var);

    Ok(())
}

/// Helper: Get source variable name from first Variable parameter
fn get_source_variable_name(operation: &DeferredOperation) -> Result<String, ExecutionError> {
    for param in &operation.operation.parameters {
        if let RunParameter::Variable(var_name) = param {
            return Ok(var_name.clone());
        }
    }

    Err(ExecutionError::DeferredOperationFailed {
        operation: format!("{:?}", operation.operation.operation_type),
        reason: "No source variable parameter found".to_string(),
    })
}

/// Helper: Get all Variable parameter names
fn get_all_source_variable_names(
    operation: &DeferredOperation,
) -> Result<Vec<String>, ExecutionError> {
    let mut var_names = Vec::new();

    for param in &operation.operation.parameters {
        if let RunParameter::Variable(var_name) = param {
            var_names.push(var_name.clone());
        }
    }

    if var_names.is_empty() {
        Err(ExecutionError::DeferredOperationFailed {
            operation: format!("{:?}", operation.operation.operation_type),
            reason: "No variable parameters found".to_string(),
        })
    } else {
        Ok(var_names)
    }
}

/// Helper: Extract field name from ObjectExtraction parameter
fn extract_field_name_from_parameters(
    parameters: &[RunParameter],
) -> Result<String, ExecutionError> {
    for param in parameters {
        if let RunParameter::ObjectExtraction { field, .. } = param {
            return Ok(field.clone());
        }
    }

    Err(ExecutionError::DeferredOperationFailed {
        operation: "EXTRACT".to_string(),
        reason: "No ObjectExtraction parameter with field found".to_string(),
    })
}

/// Helper: Extract delimiter from Delimiter parameter
fn extract_delimiter_from_parameters(
    parameters: &[RunParameter],
) -> Result<String, ExecutionError> {
    for param in parameters {
        if let RunParameter::Delimiter(delimiter) = param {
            return Ok(delimiter.clone());
        }
    }

    Err(ExecutionError::DeferredOperationFailed {
        operation: "SPLIT".to_string(),
        reason: "No Delimiter parameter found".to_string(),
    })
}

/// Helper: Extract substring parameters (start, length)
fn extract_substring_params(parameters: &[RunParameter]) -> Result<(i64, i64), ExecutionError> {
    let mut start: Option<i64> = None;
    let mut length: Option<i64> = None;

    for param in parameters {
        match param {
            RunParameter::StartPosition(pos) => {
                start = Some(*pos);
            }
            RunParameter::Length(len) => {
                length = Some(*len);
            }
            _ => {}
        }
    }

    match (start, length) {
        (Some(s), Some(l)) => Ok((s, l)),
        _ => Err(ExecutionError::DeferredOperationFailed {
            operation: "SUBSTRING".to_string(),
            reason: "Missing StartPosition or Length parameters".to_string(),
        }),
    }
}

/// Execute SUBSTRING operation - extract substring from source
fn execute_substring(
    operation: &DeferredOperation,
    context: &mut ExecutionContext,
) -> Result<(), ExecutionError> {
    // 1. Get source variable name
    let source_var_name = get_source_variable_name(operation)?;

    // 2. Extract start position and length (access through .operation field)
    let (start, length) = extract_substring_params(&operation.operation.parameters)?;

    // 3. Get source variable value
    let source_value = context
        .global_variables
        .get(&source_var_name)
        .ok_or_else(|| ExecutionError::DeferredOperationFailed {
            operation: "SUBSTRING".to_string(),
            reason: format!("Source variable '{}' not found", source_var_name),
        })?;

    // 4. Extract string value
    let source_string = match &source_value.value {
        ResolvedValue::String(s) => s.clone(),
        _ => {
            return Err(ExecutionError::DeferredOperationFailed {
                operation: "SUBSTRING".to_string(),
                reason: format!(
                    "Variable '{}' is not a string (type: {:?})",
                    source_var_name, source_value.data_type
                ),
            })
        }
    };

    // 5. Perform substring extraction with UTF-8 awareness and negative index support
    let chars: Vec<char> = source_string.chars().collect();
    let total_len = chars.len() as i64;

    // Handle negative start (from end of string)
    let actual_start = if start < 0 {
        // Negative index: -1 means last char, -2 means second-to-last, etc.
        (total_len + start).max(0) as usize
    } else {
        // Positive index: normal start position
        start.min(total_len) as usize
    };

    // Bounds check: if start exceeds length, return empty string
    let substring = if actual_start >= chars.len() {
        String::new()
    } else {
        // Calculate how many characters we can actually extract
        let remaining = chars.len() - actual_start;
        // Take the minimum of requested length and remaining chars
        let actual_length = length.min(remaining as i64).max(0) as usize;
        // Extract characters (UTF-8 safe)
        chars
            .iter()
            .skip(actual_start)
            .take(actual_length)
            .collect()
    };

    // 6. Update target variable
    update_target_variable(
        context,
        &operation.target_variable,
        ResolvedValue::String(substring),
    )?;

    Ok(())
}

/// Helper: Extract regex pattern from Pattern parameter
fn extract_pattern_from_parameters(parameters: &[RunParameter]) -> Result<String, ExecutionError> {
    for param in parameters {
        if let RunParameter::Pattern(pattern) = param {
            return Ok(pattern.clone());
        }
    }

    Err(ExecutionError::DeferredOperationFailed {
        operation: "REGEX_CAPTURE".to_string(),
        reason: "No Pattern parameter found".to_string(),
    })
}

/// Helper: Deduplicate collection maintaining order
fn deduplicate_collection(items: Vec<ResolvedValue>) -> Vec<ResolvedValue> {
    let mut seen = std::collections::HashSet::new();
    let mut unique_items = Vec::new();

    for item in items {
        // Use debug representation as key for deduplication
        let key = format!("{:?}", item);
        if seen.insert(key) {
            unique_items.push(item);
        }
    }

    unique_items
}

/// Execute a deferred operation in isolation (public API for execution engine)
pub fn execute_deferred_operation(
    operation: &DeferredOperation,
    collected_data: &HashMap<String, CollectedData>,
    context: &mut ExecutionContext,
) -> Result<(), ExecutionError> {
    execute_single_operation(operation, context, collected_data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::resolution_context::ResolutionContext;
    use crate::types::variable::ResolvedVariable;

    fn create_empty_test_context() -> ExecutionContext {
        let res_context = ResolutionContext::new(vec![], vec![], vec![], vec![], vec![], vec![]);
        ExecutionContext::from_resolution_context(&res_context).expect("Failed to create context")
    }

    fn create_test_context_with_collection(var_name: &str, items: Vec<&str>) -> ExecutionContext {
        let mut res_context =
            ResolutionContext::new(vec![], vec![], vec![], vec![], vec![], vec![]);

        let collection_items: Vec<ResolvedValue> = items
            .into_iter()
            .map(|s| ResolvedValue::String(s.to_string()))
            .collect();

        res_context.resolved_variables.insert(
            var_name.to_string(),
            ResolvedVariable::new(
                var_name.to_string(),
                DataType::String, // Collection uses String as base type
                ResolvedValue::Collection(collection_items),
            ),
        );

        ExecutionContext::from_resolution_context(&res_context).expect("Failed to create context")
    }

    #[test]
    fn test_count_collection() {
        use crate::types::runtime_operation::RuntimeOperation;

        let mut context =
            create_test_context_with_collection("fruits", vec!["apple", "banana", "cherry"]);

        let operation = DeferredOperation {
            target_variable: "fruit_count".to_string(),
            operation: RuntimeOperation::new(
                "fruit_count".to_string(),
                RuntimeOperationType::Count,
                vec![RunParameter::Variable("fruits".to_string())],
            ),
            dependencies: vec![],
        };

        execute_count(&operation, &mut context).expect("Count should succeed");

        let result = context
            .global_variables
            .get("fruit_count")
            .expect("Target variable should exist");
        assert_eq!(result.value, ResolvedValue::Integer(3));
    }

    #[test]
    fn test_count_empty_collection() {
        use crate::types::runtime_operation::RuntimeOperation;

        let mut context = create_test_context_with_collection("empty", vec![]);

        let operation = DeferredOperation {
            target_variable: "count".to_string(),
            operation: RuntimeOperation::new(
                "count".to_string(),
                RuntimeOperationType::Count,
                vec![RunParameter::Variable("empty".to_string())],
            ),
            dependencies: vec![],
        };

        execute_count(&operation, &mut context).expect("Count should succeed");

        let result = context.global_variables.get("count").unwrap();
        assert_eq!(result.value, ResolvedValue::Integer(0));
    }

    #[test]
    fn test_count_single_item_collection() {
        use crate::types::runtime_operation::RuntimeOperation;

        let mut context = create_test_context_with_collection("single", vec!["only_one"]);

        let operation = DeferredOperation {
            target_variable: "count".to_string(),
            operation: RuntimeOperation::new(
                "count".to_string(),
                RuntimeOperationType::Count,
                vec![RunParameter::Variable("single".to_string())],
            ),
            dependencies: vec![],
        };

        execute_count(&operation, &mut context).expect("Count should succeed");

        let result = context.global_variables.get("count").unwrap();
        assert_eq!(result.value, ResolvedValue::Integer(1));
    }

    #[test]
    fn test_count_large_collection() {
        use crate::types::runtime_operation::RuntimeOperation;

        let items: Vec<&str> = (0..100).map(|_| "item").collect();
        let mut context = create_test_context_with_collection("large", items);

        let operation = DeferredOperation {
            target_variable: "count".to_string(),
            operation: RuntimeOperation::new(
                "count".to_string(),
                RuntimeOperationType::Count,
                vec![RunParameter::Variable("large".to_string())],
            ),
            dependencies: vec![],
        };

        execute_count(&operation, &mut context).expect("Count should succeed");

        let result = context.global_variables.get("count").unwrap();
        assert_eq!(result.value, ResolvedValue::Integer(100));
    }

    #[test]
    fn test_count_non_collection_string() {
        use crate::types::runtime_operation::RuntimeOperation;

        let mut res_context =
            ResolutionContext::new(vec![], vec![], vec![], vec![], vec![], vec![]);

        res_context.resolved_variables.insert(
            "text".to_string(),
            ResolvedVariable::new(
                "text".to_string(),
                DataType::String,
                ResolvedValue::String("hello".to_string()),
            ),
        );

        let mut context = ExecutionContext::from_resolution_context(&res_context)
            .expect("Failed to create context");

        let operation = DeferredOperation {
            target_variable: "count".to_string(),
            operation: RuntimeOperation::new(
                "count".to_string(),
                RuntimeOperationType::Count,
                vec![RunParameter::Variable("text".to_string())],
            ),
            dependencies: vec![],
        };

        execute_count(&operation, &mut context).expect("Count should succeed");

        let result = context.global_variables.get("count").unwrap();
        // Non-empty string counts as 1
        assert_eq!(result.value, ResolvedValue::Integer(1));
    }

    #[test]
    fn test_count_non_collection_empty_string() {
        use crate::types::runtime_operation::RuntimeOperation;

        let mut res_context =
            ResolutionContext::new(vec![], vec![], vec![], vec![], vec![], vec![]);

        res_context.resolved_variables.insert(
            "empty".to_string(),
            ResolvedVariable::new(
                "empty".to_string(),
                DataType::String,
                ResolvedValue::String("".to_string()),
            ),
        );

        let mut context = ExecutionContext::from_resolution_context(&res_context)
            .expect("Failed to create context");

        let operation = DeferredOperation {
            target_variable: "count".to_string(),
            operation: RuntimeOperation::new(
                "count".to_string(),
                RuntimeOperationType::Count,
                vec![RunParameter::Variable("empty".to_string())],
            ),
            dependencies: vec![],
        };

        execute_count(&operation, &mut context).expect("Count should succeed");

        let result = context.global_variables.get("count").unwrap();
        // Empty string counts as 0
        assert_eq!(result.value, ResolvedValue::Integer(0));
    }

    #[test]
    fn test_count_non_collection_integer() {
        use crate::types::runtime_operation::RuntimeOperation;

        let mut res_context =
            ResolutionContext::new(vec![], vec![], vec![], vec![], vec![], vec![]);

        res_context.resolved_variables.insert(
            "num".to_string(),
            ResolvedVariable::new("num".to_string(), DataType::Int, ResolvedValue::Integer(42)),
        );

        let mut context = ExecutionContext::from_resolution_context(&res_context)
            .expect("Failed to create context");

        let operation = DeferredOperation {
            target_variable: "count".to_string(),
            operation: RuntimeOperation::new(
                "count".to_string(),
                RuntimeOperationType::Count,
                vec![RunParameter::Variable("num".to_string())],
            ),
            dependencies: vec![],
        };

        execute_count(&operation, &mut context).expect("Count should succeed");

        let result = context.global_variables.get("count").unwrap();
        // Single integer counts as 1
        assert_eq!(result.value, ResolvedValue::Integer(1));
    }

    #[test]
    fn test_count_missing_source_variable() {
        use crate::types::runtime_operation::RuntimeOperation;

        let mut context = create_empty_test_context();

        let operation = DeferredOperation {
            target_variable: "count".to_string(),
            operation: RuntimeOperation::new(
                "count".to_string(),
                RuntimeOperationType::Count,
                vec![RunParameter::Variable("nonexistent".to_string())],
            ),
            dependencies: vec![],
        };

        let result = execute_count(&operation, &mut context);
        assert!(result.is_err());

        if let Err(ExecutionError::DeferredOperationFailed { operation, reason }) = result {
            assert_eq!(operation, "COUNT");
            assert!(reason.contains("not found"));
        } else {
            panic!("Expected DeferredOperationFailed error");
        }
    }

    #[test]
    fn test_count_after_split() {
        use crate::types::runtime_operation::RuntimeOperation;

        // Practical use case: count items after splitting
        let mut context =
            create_test_context_with_collection("parts", vec!["a", "b", "c", "d", "e"]);

        let operation = DeferredOperation {
            target_variable: "part_count".to_string(),
            operation: RuntimeOperation::new(
                "part_count".to_string(),
                RuntimeOperationType::Count,
                vec![RunParameter::Variable("parts".to_string())],
            ),
            dependencies: vec![],
        };

        execute_count(&operation, &mut context).expect("Count should succeed");

        let result = context.global_variables.get("part_count").unwrap();
        assert_eq!(result.value, ResolvedValue::Integer(5));
    }
}
