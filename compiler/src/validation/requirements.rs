//! Minimum valid definition requirements validation with global logging

use super::{error::StructuralError, types::StructuralValidationInput};
use common::ast::nodes;
use common::utils::Span;
use common::{log_debug, log_error, log_info, log_success};
use std::time::Instant;

/// Requirements validation metrics
#[derive(Debug, Clone, Default)]
pub struct RequirementsValidationMetrics {
    pub total_duration_ms: f64,
    pub definitions_checked: usize,
    pub criteria_blocks_validated: usize,
    pub ctn_blocks_analyzed: usize,
    pub test_specifications_verified: usize,
    pub requirement_violations_found: usize,
}

impl RequirementsValidationMetrics {
    /// Calculate throughput
    pub fn validations_per_second(&self) -> f64 {
        let total_validations = self.definitions_checked
            + self.criteria_blocks_validated
            + self.ctn_blocks_analyzed
            + self.test_specifications_verified;

        if self.total_duration_ms > 0.0 {
            (total_validations as f64) / (self.total_duration_ms / 1000.0)
        } else {
            0.0
        }
    }
}

/// Validate minimum definition requirements from EBNF spec
pub fn validate_minimum_requirements(
    input: &StructuralValidationInput,
) -> Result<RequirementsValidationMetrics, Vec<StructuralError>> {
    let start_time = Instant::now();
    let mut metrics = RequirementsValidationMetrics::default();
    let mut errors = Vec::new();

    log_info!("Starting minimum requirements validation",
        "criteria_blocks" => input.ast.definition.criteria.len()
    );

    // Phase 1: Must contain at least one CRI block
    log_debug!("Phase 1: Validating definition completeness");
    validate_definition_completeness(input, &mut errors, &mut metrics);

    // Phase 2: Each CRI must contain at least one CTN or nested CRI
    log_debug!("Phase 2: Validating criteria block content");
    validate_criteria_content(input, &mut errors, &mut metrics);

    // Phase 3: Each CTN must have a TEST specification
    log_debug!("Phase 3: Validating TEST specifications");
    validate_test_specifications(input, &mut errors, &mut metrics);

    // Calculate final metrics
    metrics.total_duration_ms = start_time.elapsed().as_secs_f64() * 1000.0;
    metrics.requirement_violations_found = errors.len();

    // Log validation results
    if errors.is_empty() {
        log_success!(
            common::logging::codes::success::REQUIREMENTS_CHECK_PASSED,
            "Minimum requirements validation passed",
            "total_validations" => metrics.definitions_checked + metrics.criteria_blocks_validated + metrics.ctn_blocks_analyzed + metrics.test_specifications_verified,
            "duration_ms" => metrics.total_duration_ms,
            "validations_per_second" => metrics.validations_per_second()
        );
        Ok(metrics)
    } else {
        log_error!(
            common::logging::codes::structural::INCOMPLETE_DEFINITION_STRUCTURE,
            "Minimum requirements validation failed",
            "violations" => errors.len(),
            "duration_ms" => metrics.total_duration_ms
        );

        // Log detailed error breakdown
        log_requirements_error_breakdown(&errors);

        Err(errors)
    }
}

/// Phase 1: Validate definition completeness
fn validate_definition_completeness(
    input: &StructuralValidationInput,
    errors: &mut Vec<StructuralError>,
    metrics: &mut RequirementsValidationMetrics,
) {
    log_debug!("Checking definition completeness",
        "criteria_blocks" => input.ast.definition.criteria.len()
    );

    // 1. Must contain at least one CRI block
    if input.ast.definition.criteria.is_empty() {
        let span = input.ast.definition.span.unwrap_or_else(Span::dummy);
        let error = StructuralError::empty_definition(span);

        log_error!(error.error_code(), "Definition completeness violation",
            span = span,
            "expected_minimum" => 1,
            "actual_count" => 0,
            "validation_type" => "criteria_block_presence"
        );

        errors.push(error);
    } else {
        log_debug!("Definition completeness check passed",
            "criteria_blocks_found" => input.ast.definition.criteria.len()
        );
    }

    metrics.definitions_checked += 1;
}

/// Phase 2: Validate criteria block content
fn validate_criteria_content(
    input: &StructuralValidationInput,
    errors: &mut Vec<StructuralError>,
    metrics: &mut RequirementsValidationMetrics,
) {
    // 2. Each CRI must contain at least one CTN or nested CRI
    for (i, criteria) in input.ast.definition.criteria.iter().enumerate() {
        log_debug!("Validating criteria block content",
            "block_index" => i + 1,
            "content_items" => criteria.content.len()
        );

        if criteria.content.is_empty() {
            let span = criteria.span.unwrap_or_else(Span::dummy);
            let error = StructuralError::empty_criteria(span);

            log_error!(error.error_code(), "Criteria content violation",
                span = span,
                "criteria_block_index" => i + 1,
                "expected_minimum_content" => 1,
                "actual_content_count" => 0,
                "validation_type" => "criteria_content_presence"
            );

            errors.push(error);
        } else {
            log_debug!("Criteria block content validation passed",
                "block_index" => i + 1,
                "items_found" => criteria.content.len()
            );

            // Log content breakdown for analysis
            let mut ctn_count = 0;
            let mut nested_criteria_count = 0;

            for content in &criteria.content {
                match content {
                    nodes::CriteriaContent::Criterion(_) => ctn_count += 1,
                    nodes::CriteriaContent::Criteria(_) => nested_criteria_count += 1,
                }
            }

            log_debug!("Criteria block analysis",
                "criteria_block_index" => i + 1,
                "ctn_count" => ctn_count,
                "nested_criteria_count" => nested_criteria_count,
                "total_content" => criteria.content.len()
            );
        }

        metrics.criteria_blocks_validated += 1;
    }
}

/// Phase 3: Validate TEST specifications
fn validate_test_specifications(
    input: &StructuralValidationInput,
    errors: &mut Vec<StructuralError>,
    metrics: &mut RequirementsValidationMetrics,
) {
    // 3. Each CTN must have a TEST specification
    for (i, criteria) in input.ast.definition.criteria.iter().enumerate() {
        log_debug!("Validating TEST specifications in criteria block", "block_index" => i + 1);

        validate_criteria_test_requirements(criteria, errors, metrics, i + 1);
    }
}

/// Recursively validate test requirements in criteria
fn validate_criteria_test_requirements(
    criteria: &nodes::CriteriaNode,
    _errors: &mut Vec<StructuralError>,
    metrics: &mut RequirementsValidationMetrics,
    criteria_index: usize,
) {
    for (j, content) in criteria.content.iter().enumerate() {
        match content {
            nodes::CriteriaContent::Criteria(nested_criteria) => {
                log_debug!("Validating nested criteria TEST requirements",
                    "parent_index" => criteria_index,
                    "nested_index" => j + 1
                );
                validate_criteria_test_requirements(
                    nested_criteria,
                    _errors,
                    metrics,
                    criteria_index,
                );
            }
            nodes::CriteriaContent::Criterion(ctn) => {
                log_debug!("Validating CTN TEST specification",
                    "criteria_index" => criteria_index,
                    "ctn_index" => j + 1
                );

                // TEST specification is required - this should always be present
                // due to parser constraints, but verify for completeness
                let test_spec = &ctn.test;

                log_debug!("CTN TEST analysis",
                    "criteria_index" => criteria_index,
                    "ctn_index" => j + 1,
                    "existence_check" => format!("{:?}", test_spec.existence_check),
                    "item_check" => format!("{:?}", test_spec.item_check),
                    "validation_type" => "test_specification_analysis"
                );

                // The parser ensures TEST is always present, so no validation error needed
                // This is more of a structural analysis for completeness

                metrics.ctn_blocks_analyzed += 1;
                metrics.test_specifications_verified += 1;
            }
        }
    }
}

/// Log detailed error breakdown for requirements validation
fn log_requirements_error_breakdown(errors: &[StructuralError]) {
    let mut error_types = std::collections::HashMap::new();
    let mut error_severity_counts = std::collections::HashMap::new();

    for error in errors {
        *error_types.entry(error.error_type()).or_insert(0) += 1;
        *error_severity_counts.entry(error.severity()).or_insert(0) += 1;
    }

    log_info!("Requirements validation error analysis",
        "total_errors" => errors.len(),
        "missing_component_errors" => error_types.get("MissingComponent").unwrap_or(&0),
        "empty_definition_errors" => error_types.get("EmptyDefinition").unwrap_or(&0),
        "empty_criteria_errors" => error_types.get("EmptyCriteria").unwrap_or(&0),
        "critical_severity_count" => error_severity_counts.get("Critical").unwrap_or(&0),
        "high_severity_count" => error_severity_counts.get("High").unwrap_or(&0),
        "medium_severity_count" => error_severity_counts.get("Medium").unwrap_or(&0),
        "low_severity_count" => error_severity_counts.get("Low").unwrap_or(&0)
    );

    // Log specific insights
    if errors
        .iter()
        .any(|e| matches!(e, StructuralError::EmptyDefinition { .. }))
    {
        log_info!("Critical issue: Empty definition detected - no criteria blocks present");
    }

    if errors
        .iter()
        .any(|e| matches!(e, StructuralError::EmptyCriteria { .. }))
    {
        let empty_criteria_count = errors
            .iter()
            .filter(|e| matches!(e, StructuralError::EmptyCriteria { .. }))
            .count();

        log_info!("Structure issue: Empty criteria blocks detected",
            "empty_criteria_count" => empty_criteria_count
        );
    }
}

// ============================================================================
// ANALYSIS UTILITIES
// ============================================================================

/// Analyze requirements validation results
pub fn analyze_requirements_results(
    metrics: &RequirementsValidationMetrics,
) -> RequirementsAnalysis {
    let total_validations = metrics.definitions_checked
        + metrics.criteria_blocks_validated
        + metrics.ctn_blocks_analyzed
        + metrics.test_specifications_verified;

    RequirementsAnalysis {
        total_validations_performed: total_validations,
        definitions_checked: metrics.definitions_checked,
        criteria_blocks_validated: metrics.criteria_blocks_validated,
        ctn_blocks_analyzed: metrics.ctn_blocks_analyzed,
        test_specifications_verified: metrics.test_specifications_verified,
        violations_found: metrics.requirement_violations_found,
        validation_duration_ms: metrics.total_duration_ms,
        throughput_validations_per_second: metrics.validations_per_second(),
        validation_efficiency: if metrics.requirement_violations_found > 0 {
            total_validations as f64 / metrics.requirement_violations_found as f64
        } else {
            f64::INFINITY
        },
        is_efficient: metrics.validations_per_second() > 500.0,
        has_violations: metrics.requirement_violations_found > 0,
        completeness_score: calculate_completeness_score(metrics),
    }
}

/// Calculate completeness score based on validation results
fn calculate_completeness_score(metrics: &RequirementsValidationMetrics) -> f64 {
    let total_validations = metrics.definitions_checked
        + metrics.criteria_blocks_validated
        + metrics.ctn_blocks_analyzed
        + metrics.test_specifications_verified;

    if total_validations == 0 {
        return 0.0;
    }

    let success_rate =
        1.0 - (metrics.requirement_violations_found as f64 / total_validations as f64);
    (success_rate * 100.0).clamp(0.0, 100.0)
}

/// Requirements validation analysis results
#[derive(Debug, Clone)]
pub struct RequirementsAnalysis {
    pub total_validations_performed: usize,
    pub definitions_checked: usize,
    pub criteria_blocks_validated: usize,
    pub ctn_blocks_analyzed: usize,
    pub test_specifications_verified: usize,
    pub violations_found: usize,
    pub validation_duration_ms: f64,
    pub throughput_validations_per_second: f64,
    pub validation_efficiency: f64,
    pub is_efficient: bool,
    pub has_violations: bool,
    pub completeness_score: f64,
}

impl RequirementsAnalysis {
    /// Get analysis summary
    pub fn summary(&self) -> String {
        format!(
            "Requirements: {} validations, {} violations, {:.1}/100 completeness, {:.1} validations/sec",
            self.total_validations_performed,
            self.violations_found,
            self.completeness_score,
            self.throughput_validations_per_second
        )
    }

    /// Check if analysis indicates good structural quality
    pub fn is_good_quality(&self) -> bool {
        !self.has_violations && self.completeness_score >= 90.0 && self.is_efficient
    }
}
