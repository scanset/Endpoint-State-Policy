//! Type Compatibility Matrix Validation - Updated with Global Logging
//!
//! Enforces the EBNF type compatibility matrix for field operations
//! with clean global logging integration.

use super::types::{SemanticError, SemanticInput};
use common::ast::nodes::{DataType, Operation};
use common::utils::Span;
use common::{log_debug, log_error, log_info};

/// Validate type compatibility for all field operations in the AST
pub fn validate_type_compatibility(
    input: &SemanticInput,
) -> Result<Vec<SemanticError>, SemanticError> {
    log_debug!("Starting type compatibility validation");

    let mut errors = Vec::new();
    let mut field_count = 0;

    // Validate global states
    for state in &input.ast.definition.states {
        log_debug!("Validating global state",
            "state_id" => state.id.as_str(),
            "field_count" => state.fields.len());

        for field in &state.fields {
            field_count += 1;

            match validate_field_operation(
                &field.name,
                field.data_type,
                field.operation,
                field.span.unwrap_or_else(Span::dummy),
            ) {
                Ok(()) => {
                    log_debug!("Field validation passed",
                        "field" => field.name.as_str(),
                        "type" => field.data_type.as_str(),
                        "operation" => field.operation.as_str());
                }
                Err(error) => {
                    log_error!(error.error_code(), "Field validation failed",
                        span = field.span.unwrap_or_else(Span::dummy),
                        "field" => field.name.as_str(),
                        "type" => field.data_type.as_str(),
                        "operation" => field.operation.as_str());
                    errors.push(error);
                }
            }
        }
    }

    // Validate criterion states (recursive)
    for criteria in &input.ast.definition.criteria {
        let criteria_errors = validate_criteria_states(criteria, &mut field_count);
        errors.extend(criteria_errors);
    }

    // Log completion summary
    let success_count = field_count - errors.len();

    if errors.is_empty() {
        log_info!("Type compatibility validation completed successfully",
            "total_fields" => field_count,
            "all_passed" => true);
    } else {
        log_info!("Type compatibility validation completed with errors",
            "total_fields" => field_count,
            "passed_fields" => success_count,
            "failed_fields" => errors.len());
    }

    Ok(errors)
}

/// Recursively validate states in criteria
fn validate_criteria_states(
    criteria_node: &common::ast::nodes::CriteriaNode,
    field_count: &mut usize,
) -> Vec<SemanticError> {
    use common::ast::nodes::CriteriaContent;

    let mut errors = Vec::new();

    log_debug!("Validating criteria node",
        "content_items" => criteria_node.content.len(),
        "logical_op" => format!("{:?}", criteria_node.logical_op));

    for content in &criteria_node.content {
        match content {
            CriteriaContent::Criteria(nested_criteria) => {
                let nested_errors = validate_criteria_states(nested_criteria, field_count);
                errors.extend(nested_errors);
            }
            CriteriaContent::Criterion(ctn) => {
                log_debug!("Validating criterion",
                    "type" => ctn.criterion_type.as_str(),
                    "local_states" => ctn.local_states.len());

                // Validate local states in container
                for state in &ctn.local_states {
                    for field in &state.fields {
                        *field_count += 1;

                        match validate_field_operation(
                            &field.name,
                            field.data_type,
                            field.operation,
                            field.span.unwrap_or_else(Span::dummy),
                        ) {
                            Ok(()) => {
                                log_debug!("Local field validation passed",
                                    "field" => field.name.as_str(),
                                    "criterion" => ctn.criterion_type.as_str(),
                                    "type" => field.data_type.as_str(),
                                    "operation" => field.operation.as_str());
                            }
                            Err(error) => {
                                log_error!(error.error_code(), "Local field validation failed",
                                    span = field.span.unwrap_or_else(Span::dummy),
                                    "field" => field.name.as_str(),
                                    "criterion" => ctn.criterion_type.as_str(),
                                    "type" => field.data_type.as_str(),
                                    "operation" => field.operation.as_str());
                                errors.push(error);
                            }
                        }
                    }
                }
            }
        }
    }

    errors
}

/// Validate a single field operation against the type compatibility matrix
fn validate_field_operation(
    field_name: &str,
    data_type: DataType,
    operation: Operation,
    span: Span,
) -> Result<(), SemanticError> {
    log_debug!("Checking field compatibility",
        "field" => field_name,
        "type" => data_type.as_str(),
        "operation" => operation.as_str());

    if !is_operation_compatible(data_type, operation) {
        log_debug!("Incompatibility detected",
            "type" => data_type.as_str(),
            "operation" => operation.as_str(),
            "supported_ops" => get_supported_operations_string(data_type));

        return Err(SemanticError::type_incompatibility(
            field_name, data_type, operation, span,
        ));
    }

    Ok(())
}

/// Check if operation is compatible with data type according to EBNF matrix
fn is_operation_compatible(data_type: DataType, operation: Operation) -> bool {
    use DataType::*;
    use Operation::*;

    match data_type {
        String => matches!(
            operation,
            Equals
                | NotEqual
                | GreaterThan
                | LessThan
                | GreaterThanOrEqual
                | LessThanOrEqual
                | CaseInsensitiveEquals
                | CaseInsensitiveNotEqual
                | Contains
                | StartsWith
                | EndsWith
                | NotContains
                | NotStartsWith
                | NotEndsWith
                | PatternMatch
                | Matches
                | SubsetOf
                | SupersetOf
        ),
        Int | Float => matches!(
            operation,
            Equals
                | NotEqual
                | GreaterThan
                | LessThan
                | GreaterThanOrEqual
                | LessThanOrEqual
                | SubsetOf
                | SupersetOf
        ),
        Boolean => matches!(operation, Equals | NotEqual),
        Binary => matches!(operation, Equals | NotEqual | Contains),
        RecordData => matches!(operation, Equals | NotEqual),
        Version | EvrString => matches!(
            operation,
            Equals | NotEqual | GreaterThan | LessThan | GreaterThanOrEqual | LessThanOrEqual
        ),
    }
}

/// Get supported operations for a data type as a formatted string
fn get_supported_operations_string(data_type: DataType) -> String {
    use DataType::*;

    let operations = match data_type {
        String => vec![
            "equals",
            "not_equal",
            "greater_than",
            "less_than",
            "greater_than_or_equal",
            "less_than_or_equal",
            "case_insensitive_equals",
            "case_insensitive_not_equal",
            "contains",
            "starts_with",
            "ends_with",
            "not_contains",
            "not_starts_with",
            "not_ends_with",
            "pattern_match",
            "matches",
            "subset_of",
            "superset_of",
        ],
        Int | Float => vec![
            "equals",
            "not_equal",
            "greater_than",
            "less_than",
            "greater_than_or_equal",
            "less_than_or_equal",
            "subset_of",
            "superset_of",
        ],
        Boolean => vec!["equals", "not_equal"],
        Binary => vec!["equals", "not_equal", "contains"],
        RecordData => vec!["equals", "not_equal"],
        Version | EvrString => vec![
            "equals",
            "not_equal",
            "greater_than",
            "less_than",
            "greater_than_or_equal",
            "less_than_or_equal",
        ],
    };

    operations.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_operation_compatible() {
        // String type should support equals operation
        assert!(is_operation_compatible(DataType::String, Operation::Equals));

        // Boolean type should not support contains operation
        assert!(!is_operation_compatible(
            DataType::Boolean,
            Operation::Contains
        ));

        // Int type should support greater than operation
        assert!(is_operation_compatible(
            DataType::Int,
            Operation::GreaterThan
        ));
    }

    #[test]
    fn test_get_supported_operations_string() {
        let string_ops = get_supported_operations_string(DataType::String);
        assert!(string_ops.contains("equals"));
        assert!(string_ops.contains("contains"));

        let boolean_ops = get_supported_operations_string(DataType::Boolean);
        assert!(boolean_ops.contains("equals"));
        assert!(!boolean_ops.contains("contains"));
    }
}
