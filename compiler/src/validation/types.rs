//! Types for Pass 6: Structural Validation - Simplified

use super::{error::StructuralError, limits::LimitsStatus};
use crate::{
    reference_resolution::ReferenceValidationResult, semantic_analysis::SemanticOutput,
    symbols::SymbolDiscoveryResult,
};
use common::ast::nodes::EspFile;

/// Input for Pass 6: Structural Validation
#[derive(Debug, Clone)]
pub struct StructuralValidationInput {
    /// The AST to validate (from Pass 2)
    pub ast: EspFile,
    /// Symbol table from Pass 3
    pub symbols: SymbolDiscoveryResult,
    /// Reference validation results from Pass 4
    pub references: ReferenceValidationResult,
    /// Semantic analysis results from Pass 5
    pub semantics: SemanticOutput,
}

impl StructuralValidationInput {
    /// Create new structural validation input
    pub fn new(
        ast: EspFile,
        symbols: SymbolDiscoveryResult,
        references: ReferenceValidationResult,
        semantics: SemanticOutput,
    ) -> Self {
        Self {
            ast,
            symbols,
            references,
            semantics,
        }
    }
}

/// Output from Pass 6: Structural Validation
#[derive(Debug, Clone)]
pub struct StructuralValidationResult {
    /// Whether structural validation passed
    pub is_valid: bool,
    /// Structural errors found
    pub errors: Vec<StructuralError>,
    /// Implementation limits status
    pub limits_status: LimitsStatus,
    /// Total symbol count across all passes
    pub total_symbols: usize,
    /// Maximum nesting depth found
    pub max_nesting_depth: usize,
}

impl StructuralValidationResult {
    /// Create new structural validation result
    pub fn new() -> Self {
        Self {
            is_valid: false,
            errors: Vec::new(),
            limits_status: LimitsStatus::new(),
            total_symbols: 0,
            max_nesting_depth: 0,
        }
    }

    /// Create successful result
    pub fn success(
        total_symbols: usize,
        max_nesting_depth: usize,
        limits_status: LimitsStatus,
    ) -> Self {
        Self {
            is_valid: true,
            errors: Vec::new(),
            limits_status,
            total_symbols,
            max_nesting_depth,
        }
    }

    /// Create failed result with errors
    pub fn with_errors(
        errors: Vec<StructuralError>,
        total_symbols: usize,
        max_nesting_depth: usize,
        limits_status: LimitsStatus,
    ) -> Self {
        Self {
            is_valid: false,
            errors,
            limits_status,
            total_symbols,
            max_nesting_depth,
        }
    }

    /// Add error to result
    pub fn add_error(&mut self, error: StructuralError) {
        self.errors.push(error);
        self.is_valid = false;
    }

    /// Get error count
    pub fn error_count(&self) -> usize {
        self.errors.len()
    }

    /// Check if any errors require halting
    pub fn has_critical_errors(&self) -> bool {
        self.errors.iter().any(|e| e.requires_halt())
    }

    /// Get errors by severity
    pub fn errors_by_severity(&self, severity: &str) -> Vec<&StructuralError> {
        self.errors
            .iter()
            .filter(|e| e.severity() == severity)
            .collect()
    }

    /// Generate summary
    pub fn summary(&self) -> String {
        format!(
            "Structural Validation: {} symbols, depth {}, {} errors, valid: {}",
            self.total_symbols,
            self.max_nesting_depth,
            self.error_count(),
            self.is_valid
        )
    }

    /// Check if validation is successful with good quality metrics
    pub fn is_high_quality(&self) -> bool {
        self.is_valid
            && self.limits_status.within_limits
            && self.limits_status.complexity_metrics.complexity_score < 50.0
    }

    /// Get validation score (0-100)
    pub fn validation_score(&self) -> f64 {
        if !self.is_valid {
            return 0.0;
        }

        let mut score: f64 = 100.0;

        // Deduct for complexity
        if self.limits_status.complexity_metrics.complexity_score > 75.0 {
            score -= 20.0;
        } else if self.limits_status.complexity_metrics.complexity_score > 50.0 {
            score -= 10.0;
        }

        // Deduct for high nesting
        if self.max_nesting_depth > 7 {
            score -= 15.0;
        } else if self.max_nesting_depth > 5 {
            score -= 5.0;
        }

        // Deduct for many symbols (might indicate complexity)
        if self.total_symbols > 1000 {
            score -= 10.0;
        } else if self.total_symbols > 500 {
            score -= 5.0;
        }

        score.max(0.0)
    }
}

impl Default for StructuralValidationResult {
    fn default() -> Self {
        Self::new()
    }
}

/// Type alias for structural validation result
pub type StructuralResult<T> = Result<T, StructuralError>;
