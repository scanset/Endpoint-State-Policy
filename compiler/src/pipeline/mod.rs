mod error;
mod info;
pub mod output; // This was missing from your original mod.rs
mod result;
mod stats;
mod validation;

// Re-export public types
pub use error::PipelineError;
pub use info::{get_pipeline_info, PipelineInfo};
pub use output::PipelineOutput; // Export the output module
pub use result::PipelineResult;
pub use stats::{get_pipeline_stats, PipelineStats};
pub use validation::validate_pipeline;

use common::config::runtime::ReferenceValidationPreferences;
use common::logging;
use std::path::PathBuf;
use std::time::Instant;

/// Process a single file through the complete pipeline (file -> lexical -> syntax -> symbols -> references -> semantics -> validation)
pub fn process_file(file_path: &str) -> Result<PipelineResult, PipelineError> {
    let start_time = Instant::now();

    // Set up file context for global logging
    logging::with_file_context(PathBuf::from(file_path), 0, || {
        common::log_info!("Starting complete ESP file processing pipeline", "file" => file_path);

        // Stage 1: File processing
        let file_result = crate::file_processor::process_file(file_path)?;

        // Stage 2: Lexical analysis
        let tokens = crate::lexical::tokenize_file_result(file_result.clone())?;

        // Create analyzer to get metrics
        let mut analyzer = crate::lexical::create_analyzer();
        let _ = analyzer.tokenize_file_result(file_result.clone())?; // Re-tokenize to get metrics
        let lexical_metrics = analyzer.metrics().clone();

        // Stage 3: Syntax analysis
        let ast = crate::syntax::parse_esp_file(tokens.clone())?;

        // Stage 4: Symbol discovery
        let symbol_discovery_result = crate::symbols::discover_symbols_from_ast(ast.clone())?;

        // Stage 5: Reference validation with SSDF-compliant preferences
        let reference_preferences = ReferenceValidationPreferences::default();
        let reference_validation_result =
            crate::reference_resolution::validate_references_and_basic_dependencies(
                symbol_discovery_result.clone(),
                &reference_preferences,
            )?;

        // Stage 6: Semantic analysis
        let semantic_analysis_result = crate::semantic_analysis::analyze_semantics(
            ast.clone(),
            symbol_discovery_result.clone(),
            reference_validation_result.clone(),
        )?;

        // Stage 7: Structural validation
        let structural_validation_result = crate::validation::validate_structure_and_limits(
            ast.clone(),
            symbol_discovery_result.clone(),
            reference_validation_result.clone(),
            semantic_analysis_result.clone(),
        )?;

        let total_duration = start_time.elapsed();
        let result = PipelineResult::new(
            ast,
            file_result.metadata,
            lexical_metrics,
            symbol_discovery_result,
            reference_validation_result,
            semantic_analysis_result,
            structural_validation_result,
            tokens.len(),
            total_duration,
        );

        result.log_success(file_path);

        Ok(result)
    })
}

/// Process a single file with custom reference validation preferences
pub fn process_file_with_preferences(
    file_path: &str,
    reference_preferences: &ReferenceValidationPreferences,
) -> Result<PipelineResult, PipelineError> {
    let start_time = Instant::now();

    // Set up file context for global logging
    logging::with_file_context(PathBuf::from(file_path), 0, || {
        common::log_info!("Starting complete ESP file processing pipeline with custom preferences",
            "file" => file_path,
            "cycle_detection_enabled" => reference_preferences.enable_cycle_detection,
            "log_validation_details" => reference_preferences.log_validation_details
        );

        // Stages 1-4: Same as process_file
        let file_result = crate::file_processor::process_file(file_path)?;
        let tokens = crate::lexical::tokenize_file_result(file_result.clone())?;
        let mut analyzer = crate::lexical::create_analyzer();
        let _ = analyzer.tokenize_file_result(file_result.clone())?;
        let lexical_metrics = analyzer.metrics().clone();
        let ast = crate::syntax::parse_esp_file(tokens.clone())?;
        let symbol_discovery_result = crate::symbols::discover_symbols_from_ast(ast.clone())?;

        // Stage 5: Reference validation with custom preferences
        common::log_info!("Stage 5: Reference validation with custom preferences");
        let reference_validation_result =
            crate::reference_resolution::validate_references_and_basic_dependencies(
                symbol_discovery_result.clone(),
                reference_preferences,
            )?;

        // Stages 6-7: Same as process_file
        let semantic_analysis_result = crate::semantic_analysis::analyze_semantics(
            ast.clone(),
            symbol_discovery_result.clone(),
            reference_validation_result.clone(),
        )?;

        let structural_validation_result = crate::validation::validate_structure_and_limits(
            ast.clone(),
            symbol_discovery_result.clone(),
            reference_validation_result.clone(),
            semantic_analysis_result.clone(),
        )?;

        let total_duration = start_time.elapsed();

        let result = PipelineResult::new(
            ast,
            file_result.metadata,
            lexical_metrics,
            symbol_discovery_result,
            reference_validation_result,
            semantic_analysis_result,
            structural_validation_result,
            tokens.len(),
            total_duration,
        );

        Ok(result)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_pipeline() {
        let _ = common::logging::init_global_logging();
        let result = validate_pipeline();
        assert!(result.is_ok());
    }
}
