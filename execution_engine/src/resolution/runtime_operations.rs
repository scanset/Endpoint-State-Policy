//! Runtime operation execution for ICS RUN blocks
//! Handles literal-only operations as Phase 1 implementation

use crate::resolution::error::ResolutionError;
use crate::types::common::{ResolvedValue, Value};
use crate::types::runtime_operation::RunParameterExt;
use crate::types::runtime_operation::{RunParameter, RuntimeOperation, RuntimeOperationType};
use crate::types::variable::ResolvedVariable;
use common::log_error;
use common::logging::codes;
use regex::Regex;
use std::collections::HashMap;

/// Execute a runtime operation with literal-only parameters
pub fn execute_runtime_operation(
    operation: &RuntimeOperation,
    resolved_variables: &HashMap<String, ResolvedVariable>,
) -> Result<ResolvedValue, ResolutionError> {
    match operation.operation_type {
        RuntimeOperationType::Concat => execute_concat(operation, resolved_variables),
        RuntimeOperationType::Arithmetic => execute_arithmetic(operation, resolved_variables),
        RuntimeOperationType::Split => execute_split(operation, resolved_variables),
        RuntimeOperationType::Substring => execute_substring(operation, resolved_variables),
        RuntimeOperationType::RegexCapture => execute_regex_capture(operation, resolved_variables),
        RuntimeOperationType::Count => execute_count(operation, resolved_variables),
        RuntimeOperationType::Extract => execute_extract(operation, resolved_variables),
        RuntimeOperationType::Unique => execute_unique(operation, resolved_variables),
        RuntimeOperationType::Merge => execute_merge(operation, resolved_variables),
        RuntimeOperationType::End => execute_end(operation, resolved_variables),
    }
}

fn execute_arithmetic(
    operation: &RuntimeOperation,
    resolved_variables: &HashMap<String, ResolvedVariable>,
) -> Result<ResolvedValue, ResolutionError> {
    let mut current_value: f64 = 0.0;
    let mut has_initial_value = false;

    for (param_index, parameter) in operation.parameters.iter().enumerate() {
        match parameter {
            RunParameter::Literal(_) | RunParameter::Variable(_) => {
                if !has_initial_value {
                    let numeric_value = get_numeric_value_from_parameter(
                        parameter,
                        resolved_variables,
                        &operation.target_variable,
                        param_index,
                    )?;
                    current_value = numeric_value;
                    has_initial_value = true;
                }
            }
            RunParameter::ArithmeticOp(operator, operand) => {
                let operand_value = extract_operand_value(
                    operand,
                    resolved_variables,
                    &operation.target_variable,
                    param_index,
                )?;
                current_value = apply_arithmetic_operation(
                    *operator,
                    current_value,
                    operand_value,
                    &operation.target_variable,
                )?;
            }
            _ => {
                return Err(ResolutionError::RuntimeOperationFailed {
                    operation: operation.target_variable.clone(),
                    reason: format!(
                        "ARITHMETIC operation does not support parameter type: {}",
                        parameter.parameter_type_name()
                    ),
                });
            }
        }
    }

    if !has_initial_value {
        return Err(ResolutionError::RuntimeOperationFailed {
            operation: operation.target_variable.clone(),
            reason: "ARITHMETIC operation requires at least one numeric value".to_string(),
        });
    }

    let result = if current_value.fract() == 0.0 && current_value.is_finite() {
        ResolvedValue::Integer(current_value as i64)
    } else {
        ResolvedValue::Float(current_value)
    };

    Ok(result)
}

fn apply_arithmetic_operation(
    operator: crate::types::runtime_operation::ArithmeticOperator,
    current: f64,
    operand: f64,
    operation_name: &str,
) -> Result<f64, ResolutionError> {
    use crate::types::runtime_operation::ArithmeticOperator;

    match operator {
        ArithmeticOperator::Add => Ok(current + operand),
        ArithmeticOperator::Subtract => Ok(current - operand),
        ArithmeticOperator::Multiply => Ok(current * operand),
        ArithmeticOperator::Divide => {
            if operand == 0.0 {
                Err(ResolutionError::RuntimeOperationFailed {
                    operation: operation_name.to_string(),
                    reason: "Division by zero".to_string(),
                })
            } else {
                Ok(current / operand)
            }
        }
        ArithmeticOperator::Modulus => {
            if operand == 0.0 {
                Err(ResolutionError::RuntimeOperationFailed {
                    operation: operation_name.to_string(),
                    reason: "Modulus by zero".to_string(),
                })
            } else {
                Ok(current % operand)
            }
        }
    }
}

fn extract_operand_value(
    operand: &Value,
    resolved_variables: &HashMap<String, ResolvedVariable>,
    operation_name: &str,
    param_index: usize,
) -> Result<f64, ResolutionError> {
    match operand {
        Value::Integer(i) => Ok(*i as f64),
        Value::Float(f) => Ok(*f),
        Value::String(s) => s
            .parse::<f64>()
            .map_err(|_| ResolutionError::RuntimeOperationFailed {
                operation: operation_name.to_string(),
                reason: format!("Cannot parse '{}' as number", s),
            }),
        Value::Variable(var_name) => {
            if let Some(resolved_var) = resolved_variables.get(var_name) {
                get_numeric_value_from_resolved(
                    &resolved_var.value,
                    var_name,
                    operation_name,
                    param_index,
                )
            } else {
                Err(ResolutionError::UndefinedVariable {
                    name: var_name.clone(),
                    context: format!("ARITHMETIC operand at parameter {}", param_index),
                })
            }
        }
        _ => Err(ResolutionError::RuntimeOperationFailed {
            operation: operation_name.to_string(),
            reason: "Unsupported operand type".to_string(),
        }),
    }
}

// Placeholder implementations for each operation type
fn execute_concat(
    operation: &RuntimeOperation,
    resolved_variables: &HashMap<String, ResolvedVariable>,
) -> Result<ResolvedValue, ResolutionError> {
    let mut result = String::new();

    for (param_index, parameter) in operation.parameters.iter().enumerate() {
        let string_value = match parameter {
            RunParameter::Literal(value) => {
                // Convert literal value to string based on type
                match value {
                    crate::types::common::Value::String(s) => s.clone(),
                    crate::types::common::Value::Integer(i) => i.to_string(),
                    crate::types::common::Value::Float(f) => f.to_string(),
                    crate::types::common::Value::Boolean(b) => b.to_string(),
                    crate::types::common::Value::Variable(var_name) => {
                        // Resolve variable reference
                        if let Some(resolved_var) = resolved_variables.get(var_name) {
                            match &resolved_var.value {
                                ResolvedValue::String(s) => s.clone(),
                                ResolvedValue::Integer(i) => i.to_string(),
                                ResolvedValue::Float(f) => f.to_string(),
                                ResolvedValue::Boolean(b) => b.to_string(),
                                ResolvedValue::Version(v) => v.clone(),
                                ResolvedValue::EvrString(e) => e.clone(),
                                _ => {
                                    return Err(ResolutionError::RuntimeOperationFailed {
                                        operation: operation.target_variable.clone(),
                                        reason: format!("Cannot convert variable '{}' type to string for concatenation", var_name),
                                    });
                                }
                            }
                        } else {
                            return Err(ResolutionError::UndefinedVariable {
                                name: var_name.clone(),
                                context: format!("CONCAT operation parameter {}", param_index),
                            });
                        }
                    }
                }
            }
            RunParameter::Variable(var_name) => {
                // Direct variable reference
                if let Some(resolved_var) = resolved_variables.get(var_name) {
                    match &resolved_var.value {
                        ResolvedValue::String(s) => s.clone(),
                        ResolvedValue::Integer(i) => i.to_string(),
                        ResolvedValue::Float(f) => f.to_string(),
                        ResolvedValue::Boolean(b) => b.to_string(),
                        ResolvedValue::Version(v) => v.clone(),
                        ResolvedValue::EvrString(e) => e.clone(),
                        _ => {
                            return Err(ResolutionError::RuntimeOperationFailed {
                                operation: operation.target_variable.clone(),
                                reason: format!(
                                    "Cannot convert variable '{}' type to string for concatenation",
                                    var_name
                                ),
                            });
                        }
                    }
                } else {
                    return Err(ResolutionError::UndefinedVariable {
                        name: var_name.clone(),
                        context: format!("CONCAT operation parameter {}", param_index),
                    });
                }
            }
            _ => {
                return Err(ResolutionError::RuntimeOperationFailed {
                    operation: operation.target_variable.clone(),
                    reason: format!(
                        "CONCAT operation does not support parameter type: {:?}",
                        parameter.parameter_type_name()
                    ),
                });
            }
        };

        result.push_str(&string_value);
    }

    Ok(ResolvedValue::String(result))
}

// Helper function to extract numeric values from parameters
fn get_numeric_value_from_parameter(
    parameter: &RunParameter,
    resolved_variables: &HashMap<String, ResolvedVariable>,
    operation_name: &str,
    param_index: usize,
) -> Result<f64, ResolutionError> {
    match parameter {
        RunParameter::Literal(value) => match value {
            crate::types::common::Value::Integer(i) => Ok(*i as f64),
            crate::types::common::Value::Float(f) => Ok(*f),
            crate::types::common::Value::String(s) => {
                s.parse::<f64>()
                    .map_err(|_| ResolutionError::RuntimeOperationFailed {
                        operation: operation_name.to_string(),
                        reason: format!(
                            "Cannot parse string '{}' as number at parameter {}",
                            s, param_index
                        ),
                    })
            }
            crate::types::common::Value::Variable(var_name) => {
                if let Some(resolved_var) = resolved_variables.get(var_name) {
                    get_numeric_value_from_resolved(
                        &resolved_var.value,
                        var_name,
                        operation_name,
                        param_index,
                    )
                } else {
                    Err(ResolutionError::UndefinedVariable {
                        name: var_name.clone(),
                        context: format!("ARITHMETIC operation parameter {}", param_index),
                    })
                }
            }
            _ => Err(ResolutionError::RuntimeOperationFailed {
                operation: operation_name.to_string(),
                reason: format!(
                    "Cannot convert literal value to number at parameter {}",
                    param_index
                ),
            }),
        },
        RunParameter::Variable(var_name) => {
            if let Some(resolved_var) = resolved_variables.get(var_name) {
                get_numeric_value_from_resolved(
                    &resolved_var.value,
                    var_name,
                    operation_name,
                    param_index,
                )
            } else {
                Err(ResolutionError::UndefinedVariable {
                    name: var_name.clone(),
                    context: format!("ARITHMETIC operation parameter {}", param_index),
                })
            }
        }
        _ => Err(ResolutionError::RuntimeOperationFailed {
            operation: operation_name.to_string(),
            reason: format!(
                "Cannot extract numeric value from parameter type {} at parameter {}",
                parameter.parameter_type_name(),
                param_index
            ),
        }),
    }
}

// Helper to convert ResolvedValue to numeric
fn get_numeric_value_from_resolved(
    resolved_value: &ResolvedValue,
    var_name: &str,
    operation_name: &str,
    param_index: usize,
) -> Result<f64, ResolutionError> {
    match resolved_value {
        ResolvedValue::Integer(i) => Ok(*i as f64),
        ResolvedValue::Float(f) => Ok(*f),
        ResolvedValue::String(s) => {
            s.parse::<f64>()
                .map_err(|_| ResolutionError::RuntimeOperationFailed {
                    operation: operation_name.to_string(),
                    reason: format!(
                        "Cannot parse variable '{}' value '{}' as number at parameter {}",
                        var_name, s, param_index
                    ),
                })
        }
        _ => Err(ResolutionError::RuntimeOperationFailed {
            operation: operation_name.to_string(),
            reason: format!(
                "Variable '{}' type cannot be converted to number at parameter {}",
                var_name, param_index
            ),
        }),
    }
}

fn execute_split(
    operation: &RuntimeOperation,
    resolved_variables: &HashMap<String, ResolvedVariable>,
) -> Result<ResolvedValue, ResolutionError> {
    // Find the input string and delimiter
    let mut input_string: Option<String> = None;
    let mut delimiter: Option<String> = None;

    for parameter in &operation.parameters {
        match parameter {
            RunParameter::Variable(var_name) => {
                if let Some(resolved_var) = resolved_variables.get(var_name) {
                    match &resolved_var.value {
                        ResolvedValue::String(s) => input_string = Some(s.clone()),
                        _ => {
                            return Err(ResolutionError::RuntimeOperationFailed {
                                operation: operation.target_variable.clone(),
                                reason: format!(
                                    "Variable '{}' is not a string for SPLIT operation",
                                    var_name
                                ),
                            })
                        }
                    }
                } else {
                    return Err(ResolutionError::UndefinedVariable {
                        name: var_name.clone(),
                        context: "SPLIT operation".to_string(),
                    });
                }
            }
            RunParameter::Literal(crate::types::common::Value::String(s))
                if input_string.is_none() =>
            {
                input_string = Some(s.clone());
            }
            RunParameter::Literal(crate::types::common::Value::String(_)) => {}
            RunParameter::Literal(_) => {}
            RunParameter::Delimiter(delim) => {
                delimiter = Some(delim.clone());
            }
            RunParameter::Character(_) => {
                // Character parameter is ignored for SPLIT operation
            }
            _ => {} // Ignore other parameter types
        }
    }

    // Validate we have required parameters
    let input = input_string.ok_or_else(|| ResolutionError::RuntimeOperationFailed {
        operation: operation.target_variable.clone(),
        reason: "SPLIT operation missing input string".to_string(),
    })?;

    let delim = delimiter.ok_or_else(|| ResolutionError::RuntimeOperationFailed {
        operation: operation.target_variable.clone(),
        reason: "SPLIT operation missing delimiter".to_string(),
    })?;

    // Perform the split operation
    let parts: Vec<&str> = input.split(&delim).collect();

    // Convert to Collection of strings
    let collection: Vec<ResolvedValue> = parts
        .iter()
        .map(|s| ResolvedValue::String(s.to_string()))
        .collect();

    Ok(ResolvedValue::Collection(collection))
}

fn execute_substring(
    operation: &RuntimeOperation,
    resolved_variables: &HashMap<String, ResolvedVariable>,
) -> Result<ResolvedValue, ResolutionError> {
    let mut input_string: Option<String> = None;
    let mut start_pos: Option<i64> = None;
    let mut length: Option<i64> = None;

    for parameter in &operation.parameters {
        match parameter {
            RunParameter::Variable(var_name) => {
                if let Some(resolved_var) = resolved_variables.get(var_name) {
                    match &resolved_var.value {
                        ResolvedValue::String(s) => input_string = Some(s.clone()),
                        _ => {
                            return Err(ResolutionError::RuntimeOperationFailed {
                                operation: operation.target_variable.clone(),
                                reason: format!(
                                    "Variable '{}' is not a string for SUBSTRING operation",
                                    var_name
                                ),
                            })
                        }
                    }
                } else {
                    return Err(ResolutionError::UndefinedVariable {
                        name: var_name.clone(),
                        context: "SUBSTRING operation".to_string(),
                    });
                }
            }
            RunParameter::Literal(crate::types::common::Value::String(s))
                if input_string.is_none() =>
            {
                input_string = Some(s.clone());
            }
            RunParameter::Literal(crate::types::common::Value::String(_)) => {}
            RunParameter::Literal(_) => {}
            RunParameter::StartPosition(start) => {
                start_pos = Some(*start);
            }
            RunParameter::Length(len) => {
                length = Some(*len);
            }
            _ => {} // Ignore other parameter types
        }
    }

    let input = input_string.ok_or_else(|| ResolutionError::RuntimeOperationFailed {
        operation: operation.target_variable.clone(),
        reason: "SUBSTRING operation requires a string input".to_string(),
    })?;

    let start = start_pos.ok_or_else(|| ResolutionError::RuntimeOperationFailed {
        operation: operation.target_variable.clone(),
        reason: "SUBSTRING operation requires a start position".to_string(),
    })? as usize;

    let len = length.ok_or_else(|| ResolutionError::RuntimeOperationFailed {
        operation: operation.target_variable.clone(),
        reason: "SUBSTRING operation requires a length parameter".to_string(),
    })? as usize;

    // Perform substring operation with bounds checking
    let result = if start >= input.len() {
        String::new()
    } else {
        let end = std::cmp::min(start + len, input.len());
        input.chars().skip(start).take(end - start).collect()
    };

    Ok(ResolvedValue::String(result))
}
fn execute_count(
    operation: &RuntimeOperation,
    resolved_variables: &HashMap<String, ResolvedVariable>,
) -> Result<ResolvedValue, ResolutionError> {
    // COUNT operation counts characters in a string (literal-only implementation)
    for parameter in &operation.parameters {
        match parameter {
            RunParameter::Variable(var_name) => {
                if let Some(resolved_var) = resolved_variables.get(var_name) {
                    let count = match &resolved_var.value {
                        ResolvedValue::Collection(items) => items.len() as i64,
                        ResolvedValue::String(s) => s.len() as i64,
                        ResolvedValue::Integer(i) => i.to_string().len() as i64,
                        ResolvedValue::Float(f) => f.to_string().len() as i64,
                        ResolvedValue::Boolean(b) => b.to_string().len() as i64,
                        ResolvedValue::Version(v) => v.len() as i64,
                        ResolvedValue::EvrString(e) => e.len() as i64,
                        ResolvedValue::RecordData(_) => 1,
                        ResolvedValue::Binary(b) => b.len() as i64,
                    };

                    return Ok(ResolvedValue::Integer(count));
                } else {
                    return Err(ResolutionError::UndefinedVariable {
                        name: var_name.clone(),
                        context: "COUNT operation".to_string(),
                    });
                }
            }
            RunParameter::Literal(value) => {
                let count = match value {
                    crate::types::common::Value::String(s) => s.len() as i64,
                    crate::types::common::Value::Integer(i) => i.to_string().len() as i64,
                    crate::types::common::Value::Float(f) => f.to_string().len() as i64,
                    crate::types::common::Value::Boolean(b) => b.to_string().len() as i64,
                    _ => {
                        return Err(ResolutionError::RuntimeOperationFailed {
                            operation: operation.target_variable.clone(),
                            reason: "Cannot count elements in this literal type".to_string(),
                        })
                    }
                };

                return Ok(ResolvedValue::Integer(count));
            }
            _ => {} // Continue to next parameter
        }
    }

    Err(ResolutionError::RuntimeOperationFailed {
        operation: operation.target_variable.clone(),
        reason: "COUNT operation requires at least one countable parameter".to_string(),
    })
}

fn execute_regex_capture(
    operation: &RuntimeOperation,
    resolved_variables: &HashMap<String, ResolvedVariable>,
) -> Result<ResolvedValue, ResolutionError> {
    let mut input_string: Option<String> = None;
    let mut pattern: Option<String> = None;

    for parameter in &operation.parameters {
        match parameter {
            RunParameter::Variable(var_name) => {
                if let Some(resolved_var) = resolved_variables.get(var_name) {
                    match &resolved_var.value {
                        ResolvedValue::String(s) => input_string = Some(s.clone()),
                        ResolvedValue::Integer(i) => input_string = Some(i.to_string()),
                        ResolvedValue::Float(f) => input_string = Some(f.to_string()),
                        ResolvedValue::Boolean(b) => input_string = Some(b.to_string()),
                        ResolvedValue::Version(v) => input_string = Some(v.clone()),
                        ResolvedValue::EvrString(e) => input_string = Some(e.clone()),
                        _ => return Err(ResolutionError::RuntimeOperationFailed {
                            operation: operation.target_variable.clone(),
                            reason: format!("Variable '{}' type cannot be converted to string for REGEX_CAPTURE", var_name),
                        }),
                    }
                } else {
                    return Err(ResolutionError::UndefinedVariable {
                        name: var_name.clone(),
                        context: "REGEX_CAPTURE operation".to_string(),
                    });
                }
            }
            RunParameter::Literal(crate::types::common::Value::String(s))
                if input_string.is_none() =>
            {
                input_string = Some(s.clone());
            }
            RunParameter::Literal(crate::types::common::Value::String(_)) => {}
            RunParameter::Literal(_) => {}
            RunParameter::Pattern(pat) => {
                pattern = Some(pat.clone());
            }
            _ => {} // Ignore other parameter types
        }
    }

    let input = input_string.ok_or_else(|| ResolutionError::RuntimeOperationFailed {
        operation: operation.target_variable.clone(),
        reason: "REGEX_CAPTURE operation requires a string input".to_string(),
    })?;

    let regex_pattern = pattern.ok_or_else(|| ResolutionError::RuntimeOperationFailed {
        operation: operation.target_variable.clone(),
        reason: "REGEX_CAPTURE operation requires a pattern parameter".to_string(),
    })?;

    // Compile regex with proper error handling
    let regex = Regex::new(&regex_pattern).map_err(|regex_error| {
        log_error!(
            codes::file_processing::INVALID_EXTENSION,
            &format!("Invalid regex pattern '{}': {}", regex_pattern, regex_error),
            "target_variable" => operation.target_variable.as_str(),
            "pattern" => regex_pattern.as_str(),
            "regex_error" => regex_error.to_string().as_str()
        );
        ResolutionError::RuntimeOperationFailed {
            operation: operation.target_variable.clone(),
            reason: format!("Invalid regex pattern '{}': {}", regex_pattern, regex_error),
        }
    })?;

    // Perform regex capture
    let result = if let Some(captures) = regex.captures(&input) {
        if captures.len() > 1 {
            // Return first capture group if capture groups exist
            // This handles patterns like `([a-zA-Z]+)_([0-9]+)` returning the first group
            captures
                .get(1)
                .map(|m| m.as_str().to_string())
                .unwrap_or_else(String::new)
        } else {
            // Return full match if no capture groups
            captures
                .get(0)
                .map(|m| m.as_str().to_string())
                .unwrap_or_else(String::new)
        }
    } else {
        // No match found
        String::new()
    };

    Ok(ResolvedValue::String(result))
}

fn execute_extract(
    operation: &RuntimeOperation,
    resolved_variables: &HashMap<String, ResolvedVariable>,
) -> Result<ResolvedValue, ResolutionError> {
    // Find the ObjectExtraction parameter
    for parameter in &operation.parameters {
        if let RunParameter::ObjectExtraction { object_id, field } = parameter {
            // Look for the object in resolved variables (from global objects)
            if let Some(resolved_var) = resolved_variables.get(object_id) {
                match &resolved_var.value {
                    ResolvedValue::RecordData(record_data) => {
                        // Extract field from record data using dot notation
                        let field_path = [field.clone()];
                        // TODO: WE dont use json anymore. Fix RUN oeprations
                        match record_data.get_field_by_path(&field_path.join(".")) {
                            Some(json_value) => {
                                // Convert JSON value to ResolvedValue
                                let result = match json_value {
                                    serde_json::Value::String(s) => {
                                        ResolvedValue::String(s.clone())
                                    }
                                    serde_json::Value::Number(n) => {
                                        if let Some(i) = n.as_i64() {
                                            ResolvedValue::Integer(i)
                                        } else if let Some(f) = n.as_f64() {
                                            ResolvedValue::Float(f)
                                        } else {
                                            return Err(ResolutionError::RuntimeOperationFailed {
                                                operation: operation.target_variable.clone(),
                                                reason: format!("Cannot convert number field '{}' to supported type", field),
                                            });
                                        }
                                    }
                                    serde_json::Value::Bool(b) => ResolvedValue::Boolean(*b),
                                    serde_json::Value::Null => ResolvedValue::String(String::new()),
                                    _ => {
                                        return Err(ResolutionError::RuntimeOperationFailed {
                                            operation: operation.target_variable.clone(),
                                            reason: format!(
                                                "Field '{}' contains unsupported JSON type",
                                                field
                                            ),
                                        });
                                    }
                                };

                                return Ok(result);
                            }
                            None => {
                                return Err(ResolutionError::RuntimeOperationFailed {
                                    operation: operation.target_variable.clone(),
                                    reason: format!(
                                        "Field '{}' not found in object '{}'",
                                        field, object_id
                                    ),
                                });
                            }
                        }
                    }
                    ResolvedValue::String(s) => {
                        // If the object resolved to a string, treat field name as property
                        // This is a simple fallback for non-record objects
                        if field == "value" || field == "content" {
                            return Ok(ResolvedValue::String(s.clone()));
                        } else {
                            return Err(ResolutionError::RuntimeOperationFailed {
                                operation: operation.target_variable.clone(),
                                reason: format!(
                                    "Cannot extract field '{}' from string object '{}'",
                                    field, object_id
                                ),
                            });
                        }
                    }
                    _ => {
                        return Err(ResolutionError::RuntimeOperationFailed {
                            operation: operation.target_variable.clone(),
                            reason: format!(
                                "Object '{}' is not a record or extractable type",
                                object_id
                            ),
                        });
                    }
                }
            } else {
                return Err(ResolutionError::UndefinedVariable {
                    name: object_id.clone(),
                    context: ("EXTRACT operation object reference".to_string()),
                });
            }
        }
    }

    Err(ResolutionError::RuntimeOperationFailed {
        operation: operation.target_variable.clone(),
        reason: "EXTRACT operation requires an ObjectExtraction parameter".to_string(),
    })
}

/// Execute UNIQUE operation - remove duplicates from a collection
fn execute_unique(
    operation: &RuntimeOperation,
    resolved_variables: &HashMap<String, ResolvedVariable>,
) -> Result<ResolvedValue, ResolutionError> {
    // Get source variable name from parameters
    let source_var_name = extract_source_variable(operation)?;

    // Get the collection from the resolved variable
    let collection = get_collection_from_variable(
        &source_var_name,
        resolved_variables,
        &operation.target_variable,
    )?;

    // Deduplicate using HashMap with Debug format as key
    let mut seen = HashMap::new();
    let mut unique_items = Vec::new();

    for (index, item) in collection.into_iter().enumerate() {
        let key = format!("{:?}", item);
        if let std::collections::hash_map::Entry::Vacant(e) = seen.entry(key) {
            e.insert(index);
            unique_items.push(item);
        }
    }

    Ok(ResolvedValue::Collection(unique_items))
}

/// Execute MERGE operation - combine multiple collections
fn execute_merge(
    operation: &RuntimeOperation,
    resolved_variables: &HashMap<String, ResolvedVariable>,
) -> Result<ResolvedValue, ResolutionError> {
    // Get ALL variable names from parameters
    let var_names = extract_all_variables(operation)?;

    if var_names.is_empty() {
        return Err(ResolutionError::RuntimeOperationFailed {
            operation: operation.target_variable.clone(),
            reason: "MERGE requires at least one variable".to_string(),
        });
    }

    // Collect all items from all collections
    let mut merged_items = Vec::new();

    for var_name in var_names {
        let collection = get_collection_from_variable(
            &var_name,
            resolved_variables,
            &operation.target_variable,
        )?;

        let _item_count = collection.len();

        merged_items.extend(collection);
    }

    Ok(ResolvedValue::Collection(merged_items))
}

/// Execute END operation - get last element of a collection or string
fn execute_end(
    operation: &RuntimeOperation,
    resolved_variables: &HashMap<String, ResolvedVariable>,
) -> Result<ResolvedValue, ResolutionError> {
    // Get source variable name from parameters
    let source_var_name = extract_source_variable(operation)?;

    // Get resolved variable
    let resolved_var = resolved_variables.get(&source_var_name).ok_or_else(|| {
        ResolutionError::UndefinedVariable {
            name: source_var_name.clone(),
            context: "END operation".to_string(),
        }
    })?;

    // Handle different types
    let result = match &resolved_var.value {
        ResolvedValue::Collection(items) => {
            // Return last item or empty string if collection is empty
            if let Some(last) = items.last() {
                last.clone()
            } else {
                ResolvedValue::String(String::new())
            }
        }
        ResolvedValue::String(s) => {
            // For strings, return last character
            if let Some(last_char) = s.chars().last() {
                ResolvedValue::String(last_char.to_string())
            } else {
                ResolvedValue::String(String::new())
            }
        }
        other => {
            // For other types, return the value itself
            other.clone()
        }
    };

    Ok(result)
}

// ============================================================================
// Helper Functions
// ============================================================================

/// Extract single source variable name from parameters
fn extract_source_variable(operation: &RuntimeOperation) -> Result<String, ResolutionError> {
    for param in &operation.parameters {
        if let RunParameter::Variable(name) = param {
            return Ok(name.clone());
        }
    }

    Err(ResolutionError::RuntimeOperationFailed {
        operation: operation.target_variable.clone(),
        reason: "No source variable found in parameters".to_string(),
    })
}

/// Extract ALL variable names from parameters (for MERGE)
fn extract_all_variables(operation: &RuntimeOperation) -> Result<Vec<String>, ResolutionError> {
    let names: Vec<String> = operation
        .parameters
        .iter()
        .filter_map(|param| {
            if let RunParameter::Variable(name) = param {
                Some(name.clone())
            } else {
                None
            }
        })
        .collect();

    if names.is_empty() {
        Err(ResolutionError::RuntimeOperationFailed {
            operation: operation.target_variable.clone(),
            reason: "No variables found in parameters".to_string(),
        })
    } else {
        Ok(names)
    }
}

/// Get collection from a resolved variable with validation
fn get_collection_from_variable(
    var_name: &str,
    resolved_variables: &HashMap<String, ResolvedVariable>,
    operation_name: &str,
) -> Result<Vec<ResolvedValue>, ResolutionError> {
    let resolved_var =
        resolved_variables
            .get(var_name)
            .ok_or_else(|| ResolutionError::UndefinedVariable {
                name: var_name.to_string(),
                context: format!("{} operation", operation_name),
            })?;

    match &resolved_var.value {
        ResolvedValue::Collection(items) => Ok(items.clone()),
        _ => Err(ResolutionError::RuntimeOperationFailed {
            operation: operation_name.to_string(),
            reason: format!(
                "Variable '{}' is not a collection (found: {:?})",
                var_name,
                std::mem::discriminant(&resolved_var.value)
            ),
        }),
    }
}
