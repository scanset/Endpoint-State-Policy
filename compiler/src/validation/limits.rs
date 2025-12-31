//! Implementation limits checking with global logging integration

use super::{error::StructuralError, types::StructuralValidationInput};
use common::ast::nodes;
use common::config::compile_time::{
    lexical::{MAX_IDENTIFIER_LENGTH, MAX_STRING_SIZE as MAX_STRING_LITERAL_SIZE},
    structural::*,
};
use common::{log_debug, log_error, log_info, log_success, log_warning};
use std::time::Instant;

/// Status of implementation limits checking
#[derive(Debug, Clone)]
pub struct LimitsStatus {
    /// Whether all limits are within bounds
    pub within_limits: bool,
    /// Limit violations found (if any)
    pub violations: Option<Vec<StructuralError>>,
    /// Symbol count breakdown
    pub symbol_counts: SymbolCounts,
    /// Complexity metrics
    pub complexity_metrics: ComplexityMetrics,
    /// Total processing duration
    pub processing_duration_ms: f64,
}

impl LimitsStatus {
    /// Create new limits status
    pub fn new() -> Self {
        Self {
            within_limits: true,
            violations: None,
            symbol_counts: SymbolCounts::new(),
            complexity_metrics: ComplexityMetrics::new(),
            processing_duration_ms: 0.0,
        }
    }

    /// Mark as having violations
    pub fn with_violations(mut self, violations: Vec<StructuralError>) -> Self {
        self.within_limits = false;
        self.violations = Some(violations);
        self
    }

    /// Add processing duration
    pub fn with_duration(mut self, duration_ms: f64) -> Self {
        self.processing_duration_ms = duration_ms;
        self
    }

    /// Generate summary
    pub fn generate_summary(&self) -> String {
        format!(
            "Implementation Limits Status: {} - {} symbols, depth {}, duration {:.2}ms",
            if self.within_limits {
                "PASSED"
            } else {
                "FAILED"
            },
            self.symbol_counts.total,
            self.complexity_metrics.max_nesting_depth,
            self.processing_duration_ms
        )
    }
}

impl Default for LimitsStatus {
    fn default() -> Self {
        Self::new()
    }
}

/// Symbol count breakdown
#[derive(Debug, Clone, Default)]
pub struct SymbolCounts {
    pub variables: usize,
    pub states: usize,
    pub objects: usize,
    pub sets: usize,
    pub criteria: usize,
    pub total: usize,
    pub local_symbols: usize,
    pub global_symbols: usize,
}

impl SymbolCounts {
    pub fn new() -> Self {
        Self::default()
    }

    /// Calculate symbol density (symbols per criteria block)
    pub fn symbol_density(&self) -> f64 {
        if self.criteria > 0 {
            self.total as f64 / self.criteria as f64
        } else {
            0.0
        }
    }

    /// Calculate global symbol percentage
    pub fn global_symbol_percentage(&self) -> f64 {
        if self.total > 0 {
            (self.global_symbols as f64 / self.total as f64) * 100.0
        } else {
            0.0
        }
    }
}

/// Complexity metrics
#[derive(Debug, Clone, Default)]
pub struct ComplexityMetrics {
    pub max_nesting_depth: usize,
    pub max_identifier_length: usize,
    pub max_string_literal_size: usize,
    pub criteria_block_count: usize,
    pub complexity_score: f64,
}

impl ComplexityMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    /// Calculate overall complexity score (0-100)
    pub fn calculate_complexity_score(&mut self, symbol_counts: &SymbolCounts) {
        let mut score = 0.0;

        // Nesting complexity (0-30 points)
        let nesting_factor = (self.max_nesting_depth as f64 / MAX_NESTING_DEPTH as f64).min(1.0);
        score += nesting_factor * 30.0;

        // Symbol complexity (0-25 points)
        let symbol_factor =
            (symbol_counts.total as f64 / MAX_SYMBOLS_PER_DEFINITION as f64).min(1.0);
        score += symbol_factor * 25.0;

        // Criteria complexity (0-20 points)
        let criteria_factor = (symbol_counts.criteria as f64 / MAX_CRITERIA_BLOCKS as f64).min(1.0);
        score += criteria_factor * 20.0;

        // Identifier complexity (0-15 points)
        let identifier_factor =
            (self.max_identifier_length as f64 / MAX_IDENTIFIER_LENGTH as f64).min(1.0);
        score += identifier_factor * 15.0;

        // String complexity (0-10 points)
        let string_factor =
            (self.max_string_literal_size as f64 / MAX_STRING_LITERAL_SIZE as f64).min(1.0);
        score += string_factor * 10.0;

        self.complexity_score = score;
    }
}

/// Check implementation limits with global logging
pub fn check_implementation_limits(input: &StructuralValidationInput) -> LimitsStatus {
    let start_time = Instant::now();

    log_info!("Starting implementation limits checking",
        "total_symbols" => input.symbols.total_symbol_count(),
        "criteria_blocks" => input.ast.definition.criteria.len()
    );

    let mut violations = Vec::new();
    let mut symbol_counts = SymbolCounts::new();
    let mut complexity_metrics = ComplexityMetrics::new();

    // Phase 1: Symbol Counting
    count_symbols(input, &mut symbol_counts);

    // Phase 2: Complexity Analysis
    analyze_complexity(input, &mut complexity_metrics, &symbol_counts);

    // Phase 3: Limit Validation
    validate_limits(&symbol_counts, &complexity_metrics, &mut violations);

    // Check SET operation limits
    check_set_operation_limits(&input.ast, &mut violations);

    let duration_ms = start_time.elapsed().as_secs_f64() * 1000.0;

    let mut status = LimitsStatus {
        within_limits: violations.is_empty(),
        violations: None,
        symbol_counts,
        complexity_metrics,
        processing_duration_ms: duration_ms,
    };

    if !violations.is_empty() {
        log_error!(
            common::logging::codes::structural::IMPLEMENTATION_LIMIT_EXCEEDED,
            "Implementation limits validation failed",
            "violations" => violations.len(),
            "duration_ms" => duration_ms
        );

        // Log each violation - FIXED STRING BORROWING
        for violation in &violations {
            let error_message = violation.to_string();
            if let Some(span) = violation.span() {
                log_error!(violation.error_code(), &error_message,
                    span = span,
                    "error_type" => violation.error_type(),
                    "severity" => violation.severity()
                );
            } else {
                log_error!(violation.error_code(), &error_message,
                    "error_type" => violation.error_type(),
                    "severity" => violation.severity()
                );
            }
        }

        status = status.with_violations(violations);
    } else {
        log_success!(
            common::logging::codes::success::LIMITS_CHECK_PASSED,
            "Implementation limits validation passed",
            "symbols_analyzed" => status.symbol_counts.total,
            "duration_ms" => duration_ms,
            "complexity_score" => status.complexity_metrics.complexity_score
        );
    }

    // Log summary
    log_info!("Implementation limits summary",
        "total_symbols" => status.symbol_counts.total,
        "variables" => status.symbol_counts.variables,
        "states" => status.symbol_counts.states,
        "objects" => status.symbol_counts.objects,
        "sets" => status.symbol_counts.sets,
        "criteria" => status.symbol_counts.criteria,
        "max_nesting_depth" => status.complexity_metrics.max_nesting_depth,
        "complexity_score" => status.complexity_metrics.complexity_score,
        "within_limits" => status.within_limits,
        "symbol_density" => status.symbol_counts.symbol_density(),
        "global_percentage" => status.symbol_counts.global_symbol_percentage()
    );

    status
}

/// Count symbols with logging
fn count_symbols(input: &StructuralValidationInput, symbol_counts: &mut SymbolCounts) {
    // Global symbols
    symbol_counts.variables = input.symbols.global_symbols.variables.len();
    symbol_counts.states = input.symbols.global_symbols.states.len();
    symbol_counts.objects = input.symbols.global_symbols.objects.len();
    symbol_counts.sets = input.symbols.global_symbols.sets.len();
    symbol_counts.global_symbols =
        symbol_counts.variables + symbol_counts.states + symbol_counts.objects + symbol_counts.sets;

    // Criteria and local symbols
    symbol_counts.criteria = input.ast.definition.criteria.len();

    // Count local symbols across all scopes
    for scope in &input.symbols.local_symbol_tables {
        symbol_counts.local_symbols +=
            scope.states.len() + if scope.object.is_some() { 1 } else { 0 };
    }

    symbol_counts.total = input.symbols.total_symbol_count();

    log_debug!("Symbol counting completed",
        "total" => symbol_counts.total,
        "global" => symbol_counts.global_symbols,
        "local" => symbol_counts.local_symbols
    );
}

/// Analyze complexity metrics
fn analyze_complexity(
    input: &StructuralValidationInput,
    complexity_metrics: &mut ComplexityMetrics,
    symbol_counts: &SymbolCounts,
) {
    complexity_metrics.criteria_block_count = symbol_counts.criteria;
    complexity_metrics.max_nesting_depth = calculate_nesting_depth(&input.ast);
    complexity_metrics.max_identifier_length = find_max_identifier_length(&input.ast);
    complexity_metrics.max_string_literal_size = find_max_string_literal_size(&input.ast);

    // Calculate overall complexity score
    complexity_metrics.calculate_complexity_score(symbol_counts);

    log_debug!("Complexity analysis completed",
        "max_depth" => complexity_metrics.max_nesting_depth,
        "complexity_score" => complexity_metrics.complexity_score
    );

    // Log complexity warnings
    if complexity_metrics.complexity_score > 75.0 {
        log_warning!("High structural complexity detected",
            "complexity_score" => complexity_metrics.complexity_score,
            "max_nesting_depth" => complexity_metrics.max_nesting_depth
        );
    }
}

/// Validate all limits with specific error reporting
fn validate_limits(
    symbol_counts: &SymbolCounts,
    complexity_metrics: &ComplexityMetrics,
    violations: &mut Vec<StructuralError>,
) {
    // Check symbol count limits
    if symbol_counts.total > MAX_SYMBOLS_PER_DEFINITION {
        violations.push(StructuralError::implementation_limit_exceeded(
            "total_symbols",
            symbol_counts.total,
            MAX_SYMBOLS_PER_DEFINITION,
        ));
    }

    if symbol_counts.variables > MAX_VARIABLES_PER_DEFINITION {
        violations.push(StructuralError::implementation_limit_exceeded(
            "variables",
            symbol_counts.variables,
            MAX_VARIABLES_PER_DEFINITION,
        ));
    }

    if symbol_counts.states > MAX_STATES_PER_DEFINITION {
        violations.push(StructuralError::implementation_limit_exceeded(
            "states",
            symbol_counts.states,
            MAX_STATES_PER_DEFINITION,
        ));
    }

    if symbol_counts.objects > MAX_OBJECTS_PER_DEFINITION {
        violations.push(StructuralError::implementation_limit_exceeded(
            "objects",
            symbol_counts.objects,
            MAX_OBJECTS_PER_DEFINITION,
        ));
    }

    if symbol_counts.criteria > MAX_CRITERIA_BLOCKS {
        violations.push(StructuralError::implementation_limit_exceeded(
            "criteria_blocks",
            symbol_counts.criteria,
            MAX_CRITERIA_BLOCKS,
        ));
    }

    // Check complexity limits
    if complexity_metrics.max_nesting_depth > MAX_NESTING_DEPTH {
        violations.push(StructuralError::implementation_limit_exceeded(
            "nesting_depth",
            complexity_metrics.max_nesting_depth,
            MAX_NESTING_DEPTH,
        ));
    }

    if complexity_metrics.max_identifier_length > MAX_IDENTIFIER_LENGTH {
        violations.push(StructuralError::implementation_limit_exceeded(
            "identifier_length",
            complexity_metrics.max_identifier_length,
            MAX_IDENTIFIER_LENGTH,
        ));
    }

    if complexity_metrics.max_string_literal_size > MAX_STRING_LITERAL_SIZE {
        violations.push(StructuralError::implementation_limit_exceeded(
            "string_literal_size",
            complexity_metrics.max_string_literal_size,
            MAX_STRING_LITERAL_SIZE,
        ));
    }

    log_debug!("Limit validation completed", "violations" => violations.len());
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Calculate maximum nesting depth in AST
fn calculate_nesting_depth(ast: &nodes::EspFile) -> usize {
    let mut max_depth = 0;

    for criteria in &ast.definition.criteria {
        let depth = calculate_criteria_depth(criteria, 1);
        max_depth = max_depth.max(depth);
    }

    max_depth
}

/// Calculate criteria nesting depth recursively
fn calculate_criteria_depth(criteria: &nodes::CriteriaNode, current_depth: usize) -> usize {
    let mut max_depth = current_depth;

    for content in &criteria.content {
        match content {
            nodes::CriteriaContent::Criteria(nested) => {
                let nested_depth = calculate_criteria_depth(nested, current_depth + 1);
                max_depth = max_depth.max(nested_depth);
            }
            nodes::CriteriaContent::Criterion(_) => {
                // CTN blocks don't add to nesting depth
            }
        }
    }

    max_depth
}

/// Find maximum identifier length in AST
fn find_max_identifier_length(ast: &nodes::EspFile) -> usize {
    let mut max_length = 0;

    // Check variable names
    for var in &ast.definition.variables {
        max_length = max_length.max(var.name.len());
    }

    // Check state names
    for state in &ast.definition.states {
        max_length = max_length.max(state.id.len());
        for field in &state.fields {
            max_length = max_length.max(field.name.len());
        }
    }

    // Check object names
    for obj in &ast.definition.objects {
        max_length = max_length.max(obj.id.len());
    }

    // Check set names
    for set in &ast.definition.set_operations {
        max_length = max_length.max(set.set_id.len());
    }

    max_length
}

/// Find maximum string literal size in AST
fn find_max_string_literal_size(ast: &nodes::EspFile) -> usize {
    let mut max_size = 0;

    // Check metadata strings
    if let Some(metadata) = &ast.metadata {
        for field in &metadata.fields {
            max_size = max_size.max(field.value.len());
        }
    }

    // Check variable initial values
    for var in &ast.definition.variables {
        if let Some(nodes::Value::String(s)) = &var.initial_value {
            max_size = max_size.max(s.len());
        }
    }

    // Check state field values
    for state in &ast.definition.states {
        for field in &state.fields {
            if let nodes::Value::String(s) = &field.value {
                max_size = max_size.max(s.len());
            }
        }
    }

    max_size
}

/// Check SET operation specific limits
fn check_set_operation_limits(ast: &nodes::EspFile, violations: &mut Vec<StructuralError>) {
    for set_op in &ast.definition.set_operations {
        if set_op.operands.len() > MAX_SET_OPERANDS {
            violations.push(StructuralError::implementation_limit_exceeded(
                "set_operands",
                set_op.operands.len(),
                MAX_SET_OPERANDS,
            ));
        }
    }
}
