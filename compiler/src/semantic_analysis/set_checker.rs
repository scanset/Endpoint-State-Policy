//! SET Constraint Validation - Updated with Global Logging and Compile-Time Security Limits
//!
//! Enforces EBNF SET operation constraints with SSDF-compliant security boundaries.

use super::types::{SemanticError, SemanticInput};
use common::ast::nodes::SetOperationType;
use common::config::constants::compile_time::semantic::*;
use common::logging::codes;
use common::utils::Span;
use common::{log_debug, log_error, log_info};

/// Validate all SET operations in the AST with security limits
pub fn validate_set_constraints(
    input: &SemanticInput,
) -> Result<Vec<SemanticError>, SemanticError> {
    let operation_count = input.ast.definition.set_operations.len();

    log_debug!("Starting SET constraints validation",
        "operation_count" => operation_count,
        "max_operands_limit" => MAX_SET_OPERATION_OPERANDS,
        "max_filter_refs_limit" => MAX_FILTER_STATE_REFERENCES);

    let mut errors = Vec::new();

    // Validate each SET operation
    for (index, set_op) in input.ast.definition.set_operations.iter().enumerate() {
        log_debug!("Validating SET operation",
            "index" => index + 1,
            "total" => operation_count,
            "operation" => set_op.operation.as_str(),
            "set_id" => set_op.set_id.as_str(),
            "operands" => set_op.operands.len(),
            "has_filter" => set_op.filter.is_some());

        match validate_set_operation(set_op, input) {
            Ok(()) => {
                log_debug!("SET operation validation passed",
                    "operation" => set_op.operation.as_str(),
                    "set_id" => set_op.set_id.as_str());
            }
            Err(error) => {
                log_error!(error.error_code(), "SET operation validation failed",
                    span = set_op.span.unwrap_or_else(Span::dummy),
                    "operation" => set_op.operation.as_str(),
                    "set_id" => set_op.set_id.as_str(),
                    "error" => error.to_string());
                errors.push(error);

                // SECURITY: Limit error collection to prevent DoS
                if errors.len() >= MAX_SEMANTIC_ERRORS {
                    log_info!("SET validation error limit reached",
                        "max_errors" => MAX_SEMANTIC_ERRORS,
                        "stopping_validation" => true);
                    break;
                }
            }
        }
    }

    // Log completion summary
    let success_count = operation_count - errors.len();

    if errors.is_empty() {
        log_info!("SET constraints validation completed successfully",
            "total_operations" => operation_count);
    } else {
        log_info!("SET constraints validation completed with errors",
            "total_operations" => operation_count,
            "successful_operations" => success_count,
            "failed_operations" => errors.len(),
            "error_limit_reached" => errors.len() >= MAX_SEMANTIC_ERRORS);
    }

    Ok(errors)
}

/// Validate a single SET operation with security boundaries
fn validate_set_operation(
    set_op: &common::ast::nodes::SetOperation,
    input: &SemanticInput,
) -> Result<(), SemanticError> {
    let span = set_op.span.unwrap_or_else(Span::dummy);
    let set_id = &set_op.set_id;
    let operation_type = set_op.operation;
    let operand_count = set_op.operands.len();

    log_debug!("Analyzing SET operation",
        "set_id" => set_id,
        "operation" => operation_type.as_str(),
        "operands" => operand_count,
        "has_filter" => set_op.filter.is_some());

    // SECURITY: Enforce maximum operand count to prevent DoS attacks
    if operand_count > MAX_SET_OPERATION_OPERANDS {
        return Err(SemanticError::set_constraint_violation(
            set_id,
            operation_type,
            &format!(
                "Operand count {} exceeds security limit of {}",
                operand_count, MAX_SET_OPERATION_OPERANDS
            ),
            span,
        ));
    }

    // Validate operand count constraints (semantic validation)
    validate_operand_count_semantic(set_id, operation_type, operand_count, span)?;

    // Validate filter state references (if present)
    if let Some(filter) = &set_op.filter {
        log_debug!("Validating filter references",
            "state_ref_count" => filter.state_refs.len());

        validate_filter_references(set_id, filter, input, span)?;

        log_debug!("Filter validation completed successfully");
    } else {
        log_debug!("No filter present - skipping filter validation");
    }

    log_debug!("SET operation passed all semantic checks",
        "set_id" => set_id);

    Ok(())
}

/// Validate SET operand count constraints (semantic validation)
fn validate_operand_count_semantic(
    set_id: &str,
    operation_type: SetOperationType,
    operand_count: usize,
    span: Span,
) -> Result<(), SemanticError> {
    let (is_valid, expected_desc) = match operation_type {
        SetOperationType::Union => (operand_count >= 1, "1 or more"),
        SetOperationType::Intersection => (operand_count >= 2, "2 or more"),
        SetOperationType::Complement => (operand_count == 2, "exactly 2"),
    };

    log_debug!("Checking operand count constraint",
        "operation" => operation_type.as_str(),
        "found" => operand_count,
        "expected" => expected_desc,
        "valid" => is_valid);

    if !is_valid {
        let error_msg = format!(
            "operand count constraint violation: {} operation requires {} operands, found {}",
            operation_type.as_str(),
            expected_desc,
            operand_count
        );

        return Err(SemanticError::set_constraint_violation(
            set_id,
            operation_type,
            &error_msg,
            span,
        ));
    }

    log_debug!("Operand count validation passed",
        "operation" => operation_type.as_str(),
        "operands" => operand_count);

    Ok(())
}

/// Validate that filter references point to global states with security limits
fn validate_filter_references(
    set_id: &str,
    filter: &common::ast::nodes::FilterSpec,
    input: &SemanticInput,
    span: Span,
) -> Result<(), SemanticError> {
    let reference_count = filter.state_refs.len();

    log_debug!("Validating filter state references",
        "set_id" => set_id,
        "reference_count" => reference_count);

    // SECURITY: Enforce maximum filter reference count to prevent DoS attacks
    if reference_count > MAX_FILTER_STATE_REFERENCES {
        return Err(SemanticError::set_constraint_violation(
            set_id,
            SetOperationType::Union, // Default for filter error
            &format!(
                "Filter reference count {} exceeds security limit of {}",
                reference_count, MAX_FILTER_STATE_REFERENCES
            ),
            span,
        ));
    }

    for (index, state_ref) in filter.state_refs.iter().enumerate() {
        let state_id = &state_ref.state_id;

        log_debug!("Checking filter reference",
            "index" => index + 1,
            "state_id" => state_id);

        // Check if state exists in global scope
        if !input.symbols.global_symbols.states.contains_key(state_id) {
            let error_msg = format!("filter references undefined global state '{}'", state_id);

            log_error!(codes::symbols::SYMBOL_SCOPE_VALIDATION_ERROR,
                "Filter reference validation failed",
                "state_id" => state_id,
                "error" => "state not found in global scope");

            return Err(SemanticError::set_constraint_violation(
                set_id,
                SetOperationType::Union, // Default for filter error
                &error_msg,
                span,
            ));
        } else {
            log_debug!("Filter reference validated",
                "state_id" => state_id,
                "status" => "found in global scope");
        }
    }

    log_debug!("All filter references validated successfully",
        "reference_count" => reference_count);

    Ok(())
}
