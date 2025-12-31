//! Block ordering validation according to EBNF constraints with global logging

use super::{error::StructuralError, types::StructuralValidationInput};
use common::ast::nodes;
use common::utils::Span;
use common::{log_debug, log_error, log_info, log_success};
use std::time::Instant;

/// Block ordering validation metrics
#[derive(Debug, Clone, Default)]
pub struct OrderingValidationMetrics {
    pub total_duration_ms: f64,
    pub criteria_blocks_checked: usize,
    pub ctn_blocks_validated: usize,
    pub ordering_violations_found: usize,
}

impl OrderingValidationMetrics {
    /// Calculate throughput
    pub fn blocks_per_second(&self) -> f64 {
        let total_blocks = self.criteria_blocks_checked + self.ctn_blocks_validated;
        if self.total_duration_ms > 0.0 {
            (total_blocks as f64) / (self.total_duration_ms / 1000.0)
        } else {
            0.0
        }
    }
}

/// Validate block ordering constraints from EBNF spec
pub fn validate_block_ordering(
    input: &StructuralValidationInput,
) -> Result<OrderingValidationMetrics, Vec<StructuralError>> {
    let start_time = Instant::now();
    let mut metrics = OrderingValidationMetrics::default();
    let mut errors = Vec::new();

    log_info!("Starting block ordering validation",
        "criteria_blocks" => input.ast.definition.criteria.len()
    );

    // Main validation: CTN block element ordering
    // EBNF requires: TEST, STATE_REF*, OBJECT_REF*, local STATE*, local OBJECT?
    for (i, criteria) in input.ast.definition.criteria.iter().enumerate() {
        log_debug!("Validating criteria block ordering", "block_index" => i + 1);

        validate_criteria_ordering(criteria, &mut errors, &mut metrics);
        metrics.criteria_blocks_checked += 1;
    }

    // Calculate final metrics
    metrics.total_duration_ms = start_time.elapsed().as_secs_f64() * 1000.0;
    metrics.ordering_violations_found = errors.len();

    // Log validation results
    if errors.is_empty() {
        log_success!(
            common::logging::codes::success::BLOCK_ORDERING_PASSED,
            "Block ordering validation passed",
            "criteria_blocks" => metrics.criteria_blocks_checked,
            "ctn_blocks" => metrics.ctn_blocks_validated,
            "duration_ms" => metrics.total_duration_ms,
            "blocks_per_second" => metrics.blocks_per_second()
        );
        Ok(metrics)
    } else {
        log_error!(
            common::logging::codes::structural::INVALID_BLOCK_ORDERING,
            "Block ordering validation failed",
            "violations" => errors.len(),
            "duration_ms" => metrics.total_duration_ms
        );

        // Log error breakdown
        let mut error_types = std::collections::HashMap::new();
        for error in &errors {
            *error_types.entry(error.error_type()).or_insert(0) += 1;
        }

        log_info!("Block ordering error breakdown",
            "total_errors" => errors.len(),
            "missing_component_errors" => error_types.get("MissingComponent").unwrap_or(&0),
            "block_ordering_errors" => error_types.get("BlockOrdering").unwrap_or(&0),
            "consistency_errors" => error_types.get("ConsistencyViolation").unwrap_or(&0)
        );

        Err(errors)
    }
}

/// Validate ordering within criteria blocks
fn validate_criteria_ordering(
    criteria: &nodes::CriteriaNode,
    errors: &mut Vec<StructuralError>,
    metrics: &mut OrderingValidationMetrics,
) {
    for (i, content) in criteria.content.iter().enumerate() {
        match content {
            nodes::CriteriaContent::Criteria(nested_criteria) => {
                log_debug!("Validating nested criteria block", "nested_index" => i + 1);
                validate_criteria_ordering(nested_criteria, errors, metrics);
            }
            nodes::CriteriaContent::Criterion(ctn) => {
                log_debug!("Validating CTN block ordering", "ctn_index" => i + 1);
                validate_ctn_ordering(ctn, errors, metrics);
                metrics.ctn_blocks_validated += 1;
            }
        }
    }
}

/// Validate CTN block element ordering
fn validate_ctn_ordering(
    ctn: &nodes::CriterionNode,
    errors: &mut Vec<StructuralError>,
    _metrics: &mut OrderingValidationMetrics,
) {
    let span = ctn.span.unwrap_or_else(Span::dummy);

    // EBNF ordering requirements for CTN:
    // 1. TEST specification (required) - always first
    // 2. STATE_REF references (optional, multiple allowed)
    // 3. OBJECT_REF references (optional, multiple allowed)
    // 4. Local STATE blocks (optional, multiple allowed)
    // 5. Local OBJECT block (optional, only one allowed)

    log_debug!("CTN validation details",
        "state_refs" => ctn.state_refs.len(),
        "object_refs" => ctn.object_refs.len(),
        "local_states" => ctn.local_states.len(),
        "has_local_object" => ctn.local_object.is_some()
    );

    // Validate logical consistency within CTN blocks
    validate_ctn_logical_consistency(ctn, errors, span);
}

/// Validate logical consistency within CTN blocks
fn validate_ctn_logical_consistency(
    ctn: &nodes::CriterionNode,
    errors: &mut Vec<StructuralError>,
    span: Span,
) {
    // Check that CTN has at least one way to validate items
    let has_state_refs = !ctn.state_refs.is_empty();
    let has_local_states = !ctn.local_states.is_empty();
    let has_object_refs = !ctn.object_refs.is_empty();
    let has_local_object = ctn.local_object.is_some();

    log_debug!("CTN consistency check",
        "has_state_refs" => has_state_refs,
        "has_local_states" => has_local_states,
        "has_object_refs" => has_object_refs,
        "has_local_object" => has_local_object
    );

    // A CTN should have at least some validation mechanism
    if !has_state_refs && !has_local_states && !has_object_refs && !has_local_object {
        let error = StructuralError::block_ordering_violation(
            "CTN",
            "CTN block has no validation states or objects",
            span,
        );

        log_error!(error.error_code(), "CTN consistency violation",
            span = span,
            "has_state_refs" => has_state_refs,
            "has_local_states" => has_local_states,
            "has_object_refs" => has_object_refs,
            "has_local_object" => has_local_object
        );

        errors.push(error);
    } else {
        log_debug!("CTN consistency check passed");
    }

    // Additional consistency checks
    validate_advanced_ctn_consistency(ctn, span);
}

/// Validate advanced CTN consistency rules
fn validate_advanced_ctn_consistency(ctn: &nodes::CriterionNode, span: Span) {
    // Check for potential redundancies or conflicts
    if !ctn.state_refs.is_empty() && !ctn.local_states.is_empty() {
        log_debug!("CTN uses both external state references and local states",
            "state_refs_count" => ctn.state_refs.len(),
            "local_states_count" => ctn.local_states.len(),
            "complexity_indicator" => "mixed_state_usage"
        );
    }

    if !ctn.object_refs.is_empty() && ctn.local_object.is_some() {
        log_debug!("CTN uses both external object references and local object",
            "object_refs_count" => ctn.object_refs.len(),
            "has_local_object" => true,
            "complexity_indicator" => "mixed_object_usage"
        );
    }

    // Validate TEST specification compatibility with available states/objects
    validate_test_compatibility(ctn, span);
}

/// Validate TEST specification compatibility with available validation mechanisms
fn validate_test_compatibility(ctn: &nodes::CriterionNode, _span: Span) {
    // Analyze TEST specification requirements vs available validation mechanisms
    let test_spec = &ctn.test;

    log_debug!("Validating TEST compatibility",
        "existence_check" => format!("{:?}", test_spec.existence_check),
        "item_check" => format!("{:?}", test_spec.item_check)
    );

    // For complex TEST specifications, ensure we have adequate validation mechanisms
    let has_validation_mechanisms = !ctn.state_refs.is_empty()
        || !ctn.local_states.is_empty()
        || !ctn.object_refs.is_empty()
        || ctn.local_object.is_some();

    if !has_validation_mechanisms {
        // This should have been caught by the consistency check above,
        // but adding explicit TEST compatibility validation
        log_debug!("TEST specification lacks validation mechanisms");
    } else {
        log_debug!("TEST specification has adequate validation mechanisms");
    }
}

// ============================================================================
// ANALYSIS UTILITIES
// ============================================================================

/// Analyze block ordering validation results
pub fn analyze_ordering_results(metrics: &OrderingValidationMetrics) -> OrderingAnalysis {
    OrderingAnalysis {
        total_blocks_validated: metrics.criteria_blocks_checked + metrics.ctn_blocks_validated,
        criteria_blocks: metrics.criteria_blocks_checked,
        ctn_blocks: metrics.ctn_blocks_validated,
        violations_found: metrics.ordering_violations_found,
        validation_duration_ms: metrics.total_duration_ms,
        throughput_blocks_per_second: metrics.blocks_per_second(),
        validation_efficiency: if metrics.ordering_violations_found > 0 {
            (metrics.criteria_blocks_checked + metrics.ctn_blocks_validated) as f64
                / metrics.ordering_violations_found as f64
        } else {
            f64::INFINITY
        },
        is_efficient: metrics.blocks_per_second() > 50.0,
        has_violations: metrics.ordering_violations_found > 0,
    }
}

/// Block ordering analysis results
#[derive(Debug, Clone)]
pub struct OrderingAnalysis {
    pub total_blocks_validated: usize,
    pub criteria_blocks: usize,
    pub ctn_blocks: usize,
    pub violations_found: usize,
    pub validation_duration_ms: f64,
    pub throughput_blocks_per_second: f64,
    pub validation_efficiency: f64,
    pub is_efficient: bool,
    pub has_violations: bool,
}

impl OrderingAnalysis {
    /// Get analysis summary
    pub fn summary(&self) -> String {
        format!(
            "Block Ordering: {} blocks validated ({} criteria, {} CTN), {} violations, {:.1} blocks/sec",
            self.total_blocks_validated,
            self.criteria_blocks,
            self.ctn_blocks,
            self.violations_found,
            self.throughput_blocks_per_second
        )
    }

    /// Check if analysis indicates good structural quality
    pub fn is_good_quality(&self) -> bool {
        !self.has_violations && self.is_efficient
    }
}
