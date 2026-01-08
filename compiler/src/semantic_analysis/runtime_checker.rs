//! Runtime Operations Validation - Updated with Global Logging and Compile-Time Security Limits
//!
//! Validates runtime operations for parameter compatibility, type safety,
//! and semantic correctness with SSDF-compliant security boundaries.

use super::types::{SemanticError, SemanticInput};
use common::ast::nodes::{DataType, RunParameter, RuntimeOperation, RuntimeOperationType, Value};
use common::config::constants::compile_time::semantic::*;
use common::logging::codes;
use common::utils::Span;
use common::{log_debug, log_error, log_info, log_success};
use std::collections::HashMap;

/// Main validation function for runtime operations with security limits
pub fn validate_runtime_operations(
    input: &SemanticInput,
) -> Result<Vec<SemanticError>, SemanticError> {
    let operation_count = input.ast.definition.runtime_operations.len();

    log_info!("Starting runtime operations validation",
        "operation_count" => operation_count,
        "max_parameters_limit" => MAX_RUNTIME_OPERATION_PARAMETERS);

    let mut errors = Vec::new();

    // Early exit for empty operations
    if operation_count == 0 {
        log_info!("No runtime operations found - validation complete");
        return Ok(errors);
    }

    // Create operation validator
    let validator = RuntimeOperationValidator::new(input);

    // Validate each runtime operation
    for (index, runtime_op) in input.ast.definition.runtime_operations.iter().enumerate() {
        log_debug!("Validating runtime operation",
            "index" => index + 1,
            "total" => operation_count,
            "operation_type" => runtime_op.operation_type.as_str(),
            "target_variable" => runtime_op.target_variable.as_str(),
            "parameter_count" => runtime_op.parameters.len());

        match validator.validate_operation(runtime_op) {
            Ok(()) => {
                log_debug!("Runtime operation validation passed",
                    "operation" => runtime_op.operation_type.as_str(),
                    "target" => runtime_op.target_variable.as_str());
            }
            Err(error) => {
                log_error!(error.error_code(), "Runtime operation validation failed",
                    span = error.span().unwrap_or_else(Span::dummy),
                    "operation" => runtime_op.operation_type.as_str(),
                    "target" => runtime_op.target_variable.as_str(),
                    "error" => error.to_string());
                errors.push(error);

                // SECURITY: Limit error collection to prevent DoS
                if errors.len() >= MAX_SEMANTIC_ERRORS {
                    log_info!("Runtime operation error limit reached",
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
        log_success!(codes::success::RUNTIME_VALIDATION_COMPLETE,
            "All runtime operations validated successfully",
            "total_operations" => operation_count);
    } else {
        log_info!("Runtime validation completed with errors",
            "total_operations" => operation_count,
            "successful_operations" => success_count,
            "failed_operations" => errors.len(),
            "error_limit_reached" => errors.len() >= MAX_SEMANTIC_ERRORS);
    }

    Ok(errors)
}

/// Runtime operation validator with comprehensive analysis capabilities and security boundaries
struct RuntimeOperationValidator {
    symbol_cache: HashMap<String, DataType>,
}

impl RuntimeOperationValidator {
    fn new(input: &SemanticInput) -> Self {
        // Pre-populate symbol cache for faster lookups
        let mut symbol_cache = HashMap::new();
        for (name, var_symbol) in &input.symbols.global_symbols.variables {
            symbol_cache.insert(name.clone(), var_symbol.data_type);
        }

        log_debug!("Symbol cache initialized", "variable_count" => symbol_cache.len());

        Self { symbol_cache }
    }

    fn validate_operation(&self, runtime_op: &RuntimeOperation) -> Result<(), SemanticError> {
        let span = runtime_op.span.unwrap_or_else(Span::dummy);
        let operation_type = runtime_op.operation_type;
        let variable_name = &runtime_op.target_variable;

        log_debug!("Analyzing runtime operation",
            "operation" => operation_type.as_str(),
            "variable" => variable_name,
            "parameters" => runtime_op.parameters.len());

        // Validate target variable exists
        if !self.symbol_cache.contains_key(variable_name) {
            return Err(SemanticError::runtime_operation_error(
                variable_name,
                operation_type,
                &format!(
                    "Target variable '{}' not found in symbol table",
                    variable_name
                ),
                span,
            ));
        }

        // Validate parameter count requirements (including security limits)
        self.validate_parameter_count(operation_type, runtime_op.parameters.len(), span)?;

        // Analyze parameters for type compatibility
        let parameter_analysis = self.analyze_parameters(&runtime_op.parameters, span)?;

        // Validate operation-specific constraints
        self.validate_operation_constraints(
            operation_type,
            variable_name,
            &parameter_analysis,
            span,
        )?;

        Ok(())
    }

    fn analyze_parameters(
        &self,
        parameters: &[RunParameter],
        span: Span,
    ) -> Result<Vec<ParameterInfo>, SemanticError> {
        let mut analysis = Vec::new();

        log_debug!("Analyzing parameters", "count" => parameters.len());

        for (index, param) in parameters.iter().enumerate() {
            let param_info = self.analyze_single_parameter(param, index + 1, span)?;
            analysis.push(param_info);
        }

        Ok(analysis)
    }

    fn analyze_single_parameter(
        &self,
        param: &RunParameter,
        param_number: usize,
        span: Span,
    ) -> Result<ParameterInfo, SemanticError> {
        log_debug!("Analyzing parameter", "number" => param_number);

        match param {
            RunParameter::Variable(var_name) => {
                if let Some(&data_type) = self.symbol_cache.get(var_name) {
                    Ok(ParameterInfo {
                        inferred_type: Some(data_type),
                    })
                } else {
                    Err(SemanticError::runtime_operation_error(
                        var_name,
                        RuntimeOperationType::Extract, // Default for parameter error
                        &format!("Variable '{}' referenced in parameter not found", var_name),
                        span,
                    ))
                }
            }
            RunParameter::Literal(value) => {
                let inferred_type = self.infer_literal_type(value);
                Ok(ParameterInfo {
                    inferred_type: Some(inferred_type),
                })
            }
            RunParameter::ObjectExtraction { .. } => {
                // Object extraction parameters - assume string result type
                Ok(ParameterInfo {
                    inferred_type: Some(DataType::String),
                })
            }
            RunParameter::Pattern(_) => Ok(ParameterInfo {
                inferred_type: Some(DataType::String),
            }),
            RunParameter::Delimiter(_) => Ok(ParameterInfo {
                inferred_type: Some(DataType::String),
            }),
            RunParameter::Character(_) => Ok(ParameterInfo {
                inferred_type: Some(DataType::String),
            }),
            RunParameter::StartPosition(_) => Ok(ParameterInfo {
                inferred_type: Some(DataType::Int),
            }),
            RunParameter::Length(_) => Ok(ParameterInfo {
                inferred_type: Some(DataType::Int),
            }),
            RunParameter::ArithmeticOp(_, value) => {
                let value_type = self.infer_literal_type(value);
                if matches!(value_type, DataType::Int | DataType::Float) {
                    Ok(ParameterInfo {
                        inferred_type: Some(value_type),
                    })
                } else {
                    Err(SemanticError::runtime_operation_error(
                        "arithmetic_parameter",
                        RuntimeOperationType::Arithmetic,
                        &format!(
                            "Arithmetic operation requires numeric value, found {:?}",
                            value_type
                        ),
                        span,
                    ))
                }
            }
        }
    }

    fn infer_literal_type(&self, literal: &Value) -> DataType {
        match literal {
            Value::String(_) => DataType::String,
            Value::Integer(_) => DataType::Int,
            Value::Float(_) => DataType::Float,
            Value::Boolean(_) => DataType::Boolean,
            Value::Variable(var_name) => {
                // Look up the variable's type
                self.symbol_cache
                    .get(var_name)
                    .copied()
                    .unwrap_or(DataType::String)
            }
        }
    }

    fn validate_parameter_count(
        &self,
        operation_type: RuntimeOperationType,
        param_count: usize,
        span: Span,
    ) -> Result<(), SemanticError> {
        // SECURITY: Enforce maximum parameter count to prevent DoS attacks
        if param_count > MAX_RUNTIME_OPERATION_PARAMETERS {
            return Err(SemanticError::runtime_operation_error(
                "parameter_count",
                operation_type,
                &format!(
                    "Parameter count {} exceeds security limit of {}",
                    param_count, MAX_RUNTIME_OPERATION_PARAMETERS
                ),
                span,
            ));
        }

        let (min_params, max_params) = self.get_parameter_count_requirements(operation_type);

        if param_count < min_params {
            let error_msg = format!(
                "{} operation requires at least {} parameters, found {}",
                operation_type.as_str(),
                min_params,
                param_count
            );
            return Err(SemanticError::runtime_operation_error(
                "parameter_count",
                operation_type,
                &error_msg,
                span,
            ));
        }

        if let Some(max) = max_params {
            if param_count > max {
                let error_msg = format!(
                    "{} operation accepts at most {} parameters, found {}",
                    operation_type.as_str(),
                    max,
                    param_count
                );
                return Err(SemanticError::runtime_operation_error(
                    "parameter_count",
                    operation_type,
                    &error_msg,
                    span,
                ));
            }
        }

        Ok(())
    }

    fn get_parameter_count_requirements(
        &self,
        operation_type: RuntimeOperationType,
    ) -> (usize, Option<usize>) {
        match operation_type {
            RuntimeOperationType::Concat => (1, None),
            RuntimeOperationType::Split => (2, Some(3)),
            RuntimeOperationType::Substring => (2, Some(3)),
            RuntimeOperationType::RegexCapture => (2, Some(3)),
            RuntimeOperationType::Arithmetic => (2, None),
            RuntimeOperationType::Count => (1, Some(1)),
            RuntimeOperationType::Unique => (1, Some(1)),
            RuntimeOperationType::Merge => (2, None),
            RuntimeOperationType::Extract => (1, None),
            RuntimeOperationType::End => (0, Some(1)),
        }
    }

    fn validate_operation_constraints(
        &self,
        operation_type: RuntimeOperationType,
        variable_name: &str,
        parameter_analysis: &[ParameterInfo],
        span: Span,
    ) -> Result<(), SemanticError> {
        log_debug!("Validating operation constraints",
            "operation" => operation_type.as_str(),
            "parameter_count" => parameter_analysis.len());

        match operation_type {
            RuntimeOperationType::Concat => {
                self.validate_concat_constraints(variable_name, parameter_analysis, span)
            }
            RuntimeOperationType::Split | RuntimeOperationType::Substring => self
                .validate_string_operation_constraints(
                    variable_name,
                    operation_type,
                    parameter_analysis,
                    span,
                ),
            RuntimeOperationType::RegexCapture => {
                self.validate_regex_constraints(variable_name, parameter_analysis, span)
            }
            RuntimeOperationType::Arithmetic => {
                self.validate_arithmetic_constraints(variable_name, parameter_analysis, span)
            }
            RuntimeOperationType::Count | RuntimeOperationType::Unique => {
                self.validate_collection_constraints(variable_name, parameter_analysis, span)
            }
            RuntimeOperationType::Merge => {
                self.validate_merge_constraints(variable_name, parameter_analysis, span)
            }
            RuntimeOperationType::Extract => {
                self.validate_extract_constraints(variable_name, parameter_analysis, span)
            }
            RuntimeOperationType::End => {
                // END operation has no constraints
                Ok(())
            }
        }
    }

    fn validate_concat_constraints(
        &self,
        variable_name: &str,
        parameter_analysis: &[ParameterInfo],
        span: Span,
    ) -> Result<(), SemanticError> {
        // CONCAT requires all parameters to be string-compatible
        for (index, param_info) in parameter_analysis.iter().enumerate() {
            if let Some(param_type) = param_info.inferred_type {
                if param_type != DataType::String {
                    return Err(SemanticError::runtime_operation_error(
                        variable_name,
                        RuntimeOperationType::Concat,
                        &format!(
                            "CONCAT requires string parameters, found {} at position {}",
                            param_type.as_str(),
                            index + 1
                        ),
                        span,
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate_string_operation_constraints(
        &self,
        variable_name: &str,
        operation_type: RuntimeOperationType,
        parameter_analysis: &[ParameterInfo],
        span: Span,
    ) -> Result<(), SemanticError> {
        // String operations require first parameter to be string
        if let Some(first_param) = parameter_analysis.first() {
            if let Some(first_type) = first_param.inferred_type {
                if first_type != DataType::String {
                    return Err(SemanticError::runtime_operation_error(
                        variable_name,
                        operation_type,
                        &format!(
                            "{} requires string input, found {}",
                            operation_type.as_str(),
                            first_type.as_str()
                        ),
                        span,
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate_regex_constraints(
        &self,
        variable_name: &str,
        parameter_analysis: &[ParameterInfo],
        span: Span,
    ) -> Result<(), SemanticError> {
        // REGEX_CAPTURE requires string input and pattern
        if parameter_analysis.len() >= 2 {
            if let Some(first_param) = parameter_analysis.first() {
                if let Some(input_type) = first_param.inferred_type {
                    if input_type != DataType::String {
                        return Err(SemanticError::runtime_operation_error(
                            variable_name,
                            RuntimeOperationType::RegexCapture,
                            &format!(
                                "REGEX_CAPTURE requires string input, found {}",
                                input_type.as_str()
                            ),
                            span,
                        ));
                    }
                }
            }

            // Pattern parameter should be string
            if let Some(second_param) = parameter_analysis.get(1) {
                if let Some(pattern_type) = second_param.inferred_type {
                    if pattern_type != DataType::String {
                        return Err(SemanticError::runtime_operation_error(
                            variable_name,
                            RuntimeOperationType::RegexCapture,
                            &format!(
                                "REGEX_CAPTURE requires string pattern, found {}",
                                pattern_type.as_str()
                            ),
                            span,
                        ));
                    }
                }
            }
        }
        Ok(())
    }
    fn validate_arithmetic_constraints(
        &self,
        variable_name: &str,
        parameter_analysis: &[ParameterInfo],
        span: Span,
    ) -> Result<(), SemanticError> {
        // ARITHMETIC requires numeric parameters
        for (index, param_info) in parameter_analysis.iter().enumerate() {
            if let Some(param_type) = param_info.inferred_type {
                if !matches!(param_type, DataType::Int | DataType::Float) {
                    return Err(SemanticError::runtime_operation_error(
                        variable_name,
                        RuntimeOperationType::Arithmetic,
                        &format!(
                            "ARITHMETIC requires numeric parameters, found {} at position {}",
                            param_type.as_str(),
                            index + 1
                        ),
                        span,
                    ));
                }
            }
        }
        Ok(())
    }

    fn validate_collection_constraints(
        &self,
        _variable_name: &str,
        _parameter_analysis: &[ParameterInfo],
        _span: Span,
    ) -> Result<(), SemanticError> {
        // Collection operations have flexible requirements
        Ok(())
    }

    fn validate_merge_constraints(
        &self,
        variable_name: &str,
        parameter_analysis: &[ParameterInfo],
        span: Span,
    ) -> Result<(), SemanticError> {
        if parameter_analysis.len() < 2 {
            return Err(SemanticError::runtime_operation_error(
                variable_name,
                RuntimeOperationType::Merge,
                "MERGE operation requires at least two parameters",
                span,
            ));
        }

        // Check that all parameters have compatible types
        if let Some(first_param) = parameter_analysis.first() {
            if let Some(first_type) = first_param.inferred_type {
                for (index, param_info) in parameter_analysis
                    .get(1..)
                    .unwrap_or(&[])
                    .iter()
                    .enumerate()
                {
                    if let Some(param_type) = param_info.inferred_type {
                        if param_type != first_type {
                            return Err(SemanticError::runtime_operation_error(
                            variable_name,
                            RuntimeOperationType::Merge,
                            &format!(
                                "MERGE requires compatible types, cannot merge {} with {} at position {}",
                                first_type.as_str(),
                                param_type.as_str(),
                                index + 2
                            ),
                            span,
                        ));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    fn validate_extract_constraints(
        &self,
        _variable_name: &str,
        _parameter_analysis: &[ParameterInfo],
        _span: Span,
    ) -> Result<(), SemanticError> {
        // EXTRACT operations require object schema knowledge - basic validation only
        Ok(())
    }
}

/// Parameter analysis information
#[derive(Debug, Clone)]
struct ParameterInfo {
    inferred_type: Option<DataType>,
}
