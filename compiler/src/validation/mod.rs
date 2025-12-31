//! Pass 6: Structural Validation Module for ESP Parser
//!
//! This module provides the final validation pass that ensures architectural compliance
//! and implementation limits using global logging integration.

pub mod error;
pub mod limits;
pub mod ordering;
pub mod requirements;
pub mod types;

// Re-export main types
use crate::{
    reference_resolution::ReferenceValidationResult, semantic_analysis::SemanticOutput,
    symbols::SymbolDiscoveryResult,
};
pub use common::ast::nodes::EspFile;
use common::logging::codes;
use common::{log_debug, log_error, log_info, log_success};
pub use error::{StructuralError, StructuralResult};
use std::time::Instant;
pub use types::{StructuralValidationInput, StructuralValidationResult};

/// Module version
pub const VERSION: &str = "1.0.0";

/// Pass number
pub const PASS_NUMBER: u8 = 6;

/// Structural validation metrics
#[derive(Debug, Clone, Default)]
pub struct StructuralValidationMetrics {
    pub total_duration_ms: f64,
    pub requirements_check_duration_ms: f64,
    pub ordering_check_duration_ms: f64,
    pub limits_check_duration_ms: f64,
    pub total_checks_performed: usize,
    pub errors_detected: usize,
}

impl StructuralValidationMetrics {
    /// Calculate validation throughput
    pub fn validations_per_second(&self) -> f64 {
        if self.total_duration_ms > 0.0 {
            (self.total_checks_performed as f64) / (self.total_duration_ms / 1000.0)
        } else {
            0.0
        }
    }
}

/// Main structural validation function with global logging
pub fn validate_structure_and_limits(
    ast: EspFile,
    symbols: SymbolDiscoveryResult,
    references: ReferenceValidationResult,
    semantics: SemanticOutput,
) -> StructuralResult<StructuralValidationResult> {
    let start_time = Instant::now();
    let mut metrics = StructuralValidationMetrics::default();

    // Log start of structural validation
    log_info!("Starting Pass 6: Structural Validation",
        "symbols" => symbols.total_symbol_count(),
        "criteria_blocks" => ast.definition.criteria.len()
    );

    let input = StructuralValidationInput::new(ast, symbols, references, semantics);
    let mut errors = Vec::new();

    // Validate minimum definition requirements
    log_debug!("Validating minimum definition requirements");
    let req_start = Instant::now();

    match requirements::validate_minimum_requirements(&input) {
        Ok(_) => {
            log_success!(
                codes::success::COMPLETENESS_CHECK_PASSED,
                "Minimum definition requirements validation passed"
            );
        }
        Err(req_errors) => {
            log_error!(codes::structural::INCOMPLETE_DEFINITION_STRUCTURE,
                "Minimum requirements validation failed",
                "errors" => req_errors.len()
            );

            // Log each requirement error with context - FIXED STRING BORROWING
            for req_error in &req_errors {
                let error_message = req_error.to_string();
                if let Some(span) = req_error.span() {
                    log_error!(req_error.error_code(), &error_message,
                        span = span,
                        "error_type" => req_error.error_type(),
                        "severity" => req_error.severity()
                    );
                } else {
                    log_error!(req_error.error_code(), &error_message,
                        "error_type" => req_error.error_type(),
                        "severity" => req_error.severity()
                    );
                }
            }

            errors.extend(req_errors);
        }
    }

    metrics.requirements_check_duration_ms = req_start.elapsed().as_secs_f64() * 1000.0;
    metrics.total_checks_performed += 1;

    // Validate block ordering constraints
    log_debug!("Validating block ordering constraints");
    let order_start = Instant::now();

    match ordering::validate_block_ordering(&input) {
        Ok(_) => {
            log_success!(
                codes::success::BLOCK_ORDERING_PASSED,
                "Block ordering validation passed"
            );
        }
        Err(order_errors) => {
            log_error!(codes::structural::INVALID_BLOCK_ORDERING,
                "Block ordering validation failed",
                "errors" => order_errors.len()
            );

            // Log each ordering error with context - FIXED STRING BORROWING
            for order_error in &order_errors {
                let error_message = order_error.to_string();
                if let Some(span) = order_error.span() {
                    log_error!(order_error.error_code(), &error_message,
                        span = span,
                        "error_type" => order_error.error_type(),
                        "severity" => order_error.severity()
                    );
                } else {
                    log_error!(order_error.error_code(), &error_message,
                        "error_type" => order_error.error_type(),
                        "severity" => order_error.severity()
                    );
                }
            }

            errors.extend(order_errors);
        }
    }

    metrics.ordering_check_duration_ms = order_start.elapsed().as_secs_f64() * 1000.0;
    metrics.total_checks_performed += 1;

    // Check implementation limits
    log_debug!("Checking implementation limits");
    let limits_start = Instant::now();

    let limits_status = limits::check_implementation_limits(&input);

    if let Some(limit_errors) = &limits_status.violations {
        log_error!(codes::structural::IMPLEMENTATION_LIMIT_EXCEEDED,
            "Implementation limits exceeded",
            "violations" => limit_errors.len()
        );

        errors.extend(limit_errors.iter().cloned());
    } else {
        log_success!(codes::success::LIMITS_CHECK_PASSED,
            "Implementation limits validation passed",
            "symbols_within_bounds" => limits_status.symbol_counts.total
        );
    }

    metrics.limits_check_duration_ms = limits_start.elapsed().as_secs_f64() * 1000.0;
    metrics.total_checks_performed += 1;

    // Calculate final metrics
    metrics.total_duration_ms = start_time.elapsed().as_secs_f64() * 1000.0;
    metrics.errors_detected = errors.len();

    let is_valid = errors.is_empty();

    // Log performance metrics
    log_info!("Structural validation performance",
        "total_duration_ms" => metrics.total_duration_ms,
        "requirements_duration_ms" => metrics.requirements_check_duration_ms,
        "ordering_duration_ms" => metrics.ordering_check_duration_ms,
        "limits_duration_ms" => metrics.limits_check_duration_ms,
        "validations_per_second" => metrics.validations_per_second(),
        "total_checks" => metrics.total_checks_performed,
        "errors_detected" => metrics.errors_detected
    );

    // Create comprehensive result
    let result = if is_valid {
        StructuralValidationResult::success(
            input.symbols.total_symbol_count(),
            calculate_max_nesting_depth(&input.ast),
            limits_status,
        )
    } else {
        StructuralValidationResult::with_errors(
            errors,
            input.symbols.total_symbol_count(),
            calculate_max_nesting_depth(&input.ast),
            limits_status,
        )
    };

    // Log final results
    if result.is_valid {
        log_success!(codes::success::STRUCTURAL_VALIDATION_COMPLETE,
            "Pass 6 completed successfully",
            "symbols" => result.total_symbols,
            "max_depth" => result.max_nesting_depth,
            "duration_ms" => metrics.total_duration_ms
        );
    } else {
        log_error!(codes::structural::MULTIPLE_STRUCTURAL_ERRORS,
            "Pass 6 completed with errors",
            "structural_errors" => result.error_count(),
            "symbols_analyzed" => result.total_symbols
        );

        // Log error statistics
        let error_stats = error::get_error_statistics(&result.errors);
        log_info!("Error breakdown",
            "critical" => error_stats.critical_count,
            "high" => error_stats.high_count,
            "medium" => error_stats.medium_count,
            "low" => error_stats.low_count
        );

        // Check if halt is required
        if error::should_halt_on_errors(&result.errors) {
            log_error!(
                codes::system::INTERNAL_ERROR,
                "Critical structural errors detected - immediate halt recommended"
            );
        }
    }

    // Log comprehensive summary
    log_info!("Structural validation summary",
        "symbols" => result.total_symbols,
        "max_nesting_depth" => result.max_nesting_depth,
        "error_count" => result.error_count(),
        "is_valid" => result.is_valid,
        "complexity_score" => result.limits_status.complexity_metrics.complexity_score,
        "within_limits" => result.limits_status.within_limits,
        "total_duration_ms" => metrics.total_duration_ms,
        "validations_per_second" => metrics.validations_per_second(),
        "variables_count" => result.limits_status.symbol_counts.variables,
        "states_count" => result.limits_status.symbol_counts.states,
        "objects_count" => result.limits_status.symbol_counts.objects,
        "sets_count" => result.limits_status.symbol_counts.sets,
        "criteria_count" => result.limits_status.symbol_counts.criteria,
        "symbol_density" => result.limits_status.symbol_counts.symbol_density(),
        "global_symbol_percentage" => result.limits_status.symbol_counts.global_symbol_percentage()
    );

    Ok(result)
}

/// Calculate maximum nesting depth in the AST
fn calculate_max_nesting_depth(ast: &EspFile) -> usize {
    let mut max_depth = 0;

    // Check criteria nesting depth
    for criterion in &ast.definition.criteria {
        let depth = calculate_criteria_depth(criterion, 1);
        max_depth = max_depth.max(depth);
    }

    max_depth
}

/// Calculate depth of nested criteria
fn calculate_criteria_depth(
    criteria: &common::ast::nodes::CriteriaNode,
    current_depth: usize,
) -> usize {
    let mut max_depth = current_depth;

    for content in &criteria.content {
        match content {
            common::ast::nodes::CriteriaContent::Criteria(nested) => {
                let nested_depth = calculate_criteria_depth(nested, current_depth + 1);
                max_depth = max_depth.max(nested_depth);
            }
            common::ast::nodes::CriteriaContent::Criterion(_) => {
                // CTN blocks don't add nesting depth
            }
        }
    }

    max_depth
}

/// Initialize structural validation logging system
pub fn init_structural_validation_logging() -> Result<(), String> {
    let test_codes = [
        codes::structural::INVALID_BLOCK_ORDERING,
        codes::structural::INCOMPLETE_DEFINITION_STRUCTURE,
        codes::structural::IMPLEMENTATION_LIMIT_EXCEEDED,
        codes::structural::EMPTY_CRITERIA_BLOCK,
        codes::structural::COMPLEXITY_VIOLATION,
        codes::structural::CONSISTENCY_VIOLATION,
        codes::structural::MULTIPLE_STRUCTURAL_ERRORS,
    ];

    for code in &test_codes {
        let description = common::logging::codes::get_description(code.as_str());
        if description == "Unknown error" {
            return Err(format!(
                "Structural validation error code {} not properly configured",
                code.as_str()
            ));
        }
    }

    log_debug!("Structural validation logging validation completed");
    Ok(())
}

/// Quick validation for simple use cases
pub fn validate_structure_quick(
    ast: EspFile,
    symbols: SymbolDiscoveryResult,
    references: ReferenceValidationResult,
    semantics: SemanticOutput,
) -> bool {
    match validate_structure_and_limits(ast, symbols, references, semantics) {
        Ok(result) => result.is_valid,
        Err(_) => false,
    }
}
