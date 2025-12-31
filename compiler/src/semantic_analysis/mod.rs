//! Pass 5: Semantic Analysis Module - Updated with Global Logging and Compile-Time Constants
//!
//! Clean implementation using global logging macros and compile-time security boundaries.
//! Focuses on core business logic with SSDF-compliant security limits.

pub mod cycle_analyzer;
pub mod runtime_checker;
pub mod set_checker;
pub mod type_checker;
pub mod types;

// Re-export main types
use crate::{reference_resolution::ReferenceValidationResult, symbols::SymbolDiscoveryResult};
use common::ast::nodes::EspFile;
use common::config::constants::compile_time::semantic::*;
use common::logging::codes;
use common::{log_debug, log_error, log_info, log_success};
pub use types::{SemanticError, SemanticInput, SemanticOutput, SemanticResult};

/// Module version
pub const VERSION: &str = "1.0.0";

/// Pass number
pub const PASS_NUMBER: u8 = 5;

/// Semantic analyzer with global logging integration and compile-time security boundaries
pub struct SemanticAnalyzer;

impl SemanticAnalyzer {
    /// Main semantic analysis function with comprehensive validation and security limits
    pub fn analyze_semantics(
        ast: EspFile,
        symbols: SymbolDiscoveryResult,
        validation_result: ReferenceValidationResult,
    ) -> SemanticResult<SemanticOutput> {
        log_info!("Starting Pass 5: Semantic Analysis",
            "states" => ast.definition.states.len(),
            "criteria" => ast.definition.criteria.len(),
            "variables" => symbols.global_symbols.variables.len(),
            "runtime_ops" => ast.definition.runtime_operations.len(),
            "set_ops" => ast.definition.set_operations.len(),
            "max_errors_limit" => MAX_SEMANTIC_ERRORS
        );

        let input = SemanticInput::new(ast, symbols, validation_result);
        let mut output = SemanticOutput::new();
        let start_time = std::time::Instant::now();
        let mut error_collection_stopped = false;

        // Step 1: Type compatibility validation
        log_debug!("Step 1: Validating type compatibility matrix");
        match type_checker::validate_type_compatibility(&input) {
            Ok(type_errors) => {
                // SECURITY: Limit error collection to prevent DoS
                let limited_errors: Vec<_> = type_errors
                    .into_iter()
                    .take(MAX_SEMANTIC_ERRORS - output.errors.len())
                    .collect();

                if limited_errors.len() + output.errors.len() >= MAX_SEMANTIC_ERRORS {
                    error_collection_stopped = true;
                    log_error!(codes::semantic::TYPE_INCOMPATIBILITY,
                        "Error collection limit reached during type validation",
                        "max_errors" => MAX_SEMANTIC_ERRORS,
                        "current_errors" => output.errors.len());
                }

                if limited_errors.is_empty() {
                    log_debug!("Type compatibility validation passed");
                } else {
                    log_info!("Type compatibility validation found errors",
                        "error_count" => limited_errors.len());
                }

                output.errors.extend(limited_errors);
            }
            Err(error) => {
                log_error!(codes::semantic::TYPE_INCOMPATIBILITY,
                    "Type compatibility validation failed",
                    "error" => error.to_string());
                return Err(error);
            }
        }

        // Early exit if error limit reached
        if error_collection_stopped {
            log_error!(codes::semantic::TYPE_INCOMPATIBILITY,
                "Semantic analysis stopped due to error limit",
                "limit" => MAX_SEMANTIC_ERRORS);
            output.is_successful = false;
            return Ok(output);
        }

        // Step 2: Runtime operation validation
        log_debug!("Step 2: Validating runtime operations");
        match runtime_checker::validate_runtime_operations(&input) {
            Ok(runtime_errors) => {
                // SECURITY: Limit error collection to prevent DoS
                let remaining_capacity = MAX_SEMANTIC_ERRORS - output.errors.len();
                let limited_errors: Vec<_> = runtime_errors
                    .into_iter()
                    .take(remaining_capacity)
                    .collect();

                if limited_errors.len() >= remaining_capacity {
                    error_collection_stopped = true;
                    log_error!(codes::semantic::RUNTIME_OPERATION_ERROR,
                        "Error collection limit reached during runtime validation",
                        "max_errors" => MAX_SEMANTIC_ERRORS,
                        "current_errors" => output.errors.len());
                }

                if limited_errors.is_empty() {
                    log_debug!("Runtime operations validation passed");
                } else {
                    log_info!("Runtime operations validation found errors",
                        "error_count" => limited_errors.len());
                }

                output.errors.extend(limited_errors);
            }
            Err(error) => {
                log_error!(codes::semantic::RUNTIME_OPERATION_ERROR,
                    "Runtime operations validation failed",
                    "error" => error.to_string());
                return Err(error);
            }
        }

        // Early exit if error limit reached
        if error_collection_stopped {
            log_error!(codes::semantic::RUNTIME_OPERATION_ERROR,
                "Semantic analysis stopped due to error limit",
                "limit" => MAX_SEMANTIC_ERRORS);
            output.is_successful = false;
            return Ok(output);
        }

        // Step 3: SET constraint validation
        log_debug!("Step 3: Validating SET constraints");
        match set_checker::validate_set_constraints(&input) {
            Ok(set_errors) => {
                // SECURITY: Limit error collection to prevent DoS
                let remaining_capacity = MAX_SEMANTIC_ERRORS - output.errors.len();
                let limited_errors: Vec<_> =
                    set_errors.into_iter().take(remaining_capacity).collect();

                if limited_errors.len() >= remaining_capacity {
                    error_collection_stopped = true;
                    log_error!(codes::semantic::SET_CONSTRAINT_VIOLATION,
                        "Error collection limit reached during SET validation",
                        "max_errors" => MAX_SEMANTIC_ERRORS,
                        "current_errors" => output.errors.len());
                }

                if limited_errors.is_empty() {
                    log_debug!("SET constraints validation passed");
                } else {
                    log_info!("SET constraints validation found errors",
                        "error_count" => limited_errors.len());
                }

                output.errors.extend(limited_errors);
            }
            Err(error) => {
                log_error!(codes::semantic::SET_CONSTRAINT_VIOLATION,
                    "SET constraints validation failed",
                    "error" => error.to_string());
                return Err(error);
            }
        }

        // Early exit if error limit reached
        if error_collection_stopped {
            log_error!(codes::semantic::SET_CONSTRAINT_VIOLATION,
                "Semantic analysis stopped due to error limit",
                "limit" => MAX_SEMANTIC_ERRORS);
            output.is_successful = false;
            return Ok(output);
        }

        // Step 4: Dependency cycle detection
        log_debug!("Step 4: Analyzing dependency cycles");
        match cycle_analyzer::analyze_dependency_cycles(&input) {
            Ok(cycle_errors) => {
                // SECURITY: Limit error collection to prevent DoS
                let remaining_capacity = MAX_SEMANTIC_ERRORS - output.errors.len();
                let limited_errors: Vec<_> =
                    cycle_errors.into_iter().take(remaining_capacity).collect();

                if limited_errors.len() >= remaining_capacity {
                    log_error!(codes::references::CIRCULAR_DEPENDENCY,
                        "Error collection limit reached during cycle analysis",
                        "max_errors" => MAX_SEMANTIC_ERRORS,
                        "current_errors" => output.errors.len());
                }

                if limited_errors.is_empty() {
                    log_debug!("Dependency cycle analysis passed");
                } else {
                    log_info!("Dependency cycle analysis found errors",
                        "error_count" => limited_errors.len());
                }

                output.errors.extend(limited_errors);
            }
            Err(error) => {
                log_error!(codes::references::CIRCULAR_DEPENDENCY,
                    "Dependency cycle analysis failed",
                    "error" => error.to_string());
                return Err(error);
            }
        }

        // Calculate final results
        let total_errors = output.errors.len();
        let is_successful = total_errors == 0;
        let analysis_duration = start_time.elapsed();

        output.is_successful = is_successful;

        // Log completion
        if is_successful {
            log_success!(codes::success::SEMANTIC_ANALYSIS_COMPLETE,
                "Semantic analysis completed successfully",
                "duration_ms" => format!("{:.2}", analysis_duration.as_secs_f64() * 1000.0),
                "steps_completed" => 4,
                "total_errors" => total_errors
            );
        } else {
            let completion_message = if error_collection_stopped {
                "Semantic analysis completed with error limit reached"
            } else {
                "Semantic analysis completed with errors"
            };

            log_info!(completion_message,
                "total_errors" => total_errors,
                "error_limit" => MAX_SEMANTIC_ERRORS,
                "limit_reached" => error_collection_stopped,
                "duration_ms" => format!("{:.2}", analysis_duration.as_secs_f64() * 1000.0),
                "steps_completed" => 4
            );
        }

        Ok(output)
    }

    /// Quick validation for simple use cases
    pub fn quick_validate(
        ast: EspFile,
        symbols: SymbolDiscoveryResult,
        validation_result: ReferenceValidationResult,
    ) -> bool {
        match Self::analyze_semantics(ast, symbols, validation_result) {
            Ok(output) => {
                log_debug!("Quick validation result", "success" => output.is_successful);
                output.is_successful
            }
            Err(error) => {
                log_error!(error.error_code(), "Quick validation failed",
                    "error" => error.to_string());
                false
            }
        }
    }
}

// ============================================================================
// CONVENIENCE FUNCTIONS
// ============================================================================

/// Main semantic analysis function with global logging
pub fn analyze_semantics(
    ast: EspFile,
    symbols: SymbolDiscoveryResult,
    validation_result: ReferenceValidationResult,
) -> SemanticResult<SemanticOutput> {
    SemanticAnalyzer::analyze_semantics(ast, symbols, validation_result)
}

/// Quick validation with global logging
pub fn quick_validate(
    ast: EspFile,
    symbols: SymbolDiscoveryResult,
    validation_result: ReferenceValidationResult,
) -> bool {
    SemanticAnalyzer::quick_validate(ast, symbols, validation_result)
}

// ============================================================================
// INTEGRATION UTILITIES
// ============================================================================

/// Initialize semantic analysis logging with security boundary validation
pub fn init_semantic_analysis_logging() -> Result<(), String> {
    let test_codes = [
        codes::semantic::TYPE_INCOMPATIBILITY,
        codes::semantic::RUNTIME_OPERATION_ERROR,
        codes::semantic::SET_CONSTRAINT_VIOLATION,
        codes::references::CIRCULAR_DEPENDENCY,
    ];

    for code in &test_codes {
        let description = common::logging::codes::get_description(code.as_str());
        if description == "Unknown error" {
            return Err(format!(
                "Semantic analysis error code {} not properly configured",
                code.as_str()
            ));
        }
    }

    log_debug!("Semantic analysis logging validation completed",
        "max_errors" => MAX_SEMANTIC_ERRORS,
        "max_parameters" => MAX_RUNTIME_OPERATION_PARAMETERS,
        "max_operands" => MAX_SET_OPERATION_OPERANDS,
        "max_message_length" => MAX_ERROR_MESSAGE_LENGTH);

    Ok(())
}
