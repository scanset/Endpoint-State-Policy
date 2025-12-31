/// Validate that the pipeline is properly configured
pub fn validate_pipeline() -> Result<(), String> {
    common::log_debug!("Validating complete pipeline configuration");

    // Validate file processor integration
    crate::file_processor::init_file_processor_logging()?;

    // Validate lexical analyzer integration
    crate::lexical::init_lexical_analysis_logging()?;

    // Validate syntax analyzer integration
    crate::syntax::init_syntax_logging()?;

    // Validate symbol discovery integration
    crate::symbols::init_symbol_discovery_logging()?;

    // Validate reference resolution integration
    crate::reference_resolution::init_reference_validation()
        .map_err(|e| format!("Reference validation initialization failed: {}", e))?;

    // Validate semantic analysis integration
    crate::semantic_analysis::init_semantic_analysis_logging()?;

    // Validate structural validation integration
    crate::validation::init_structural_validation_logging()?;

    // Validate grammar integration
    crate::syntax::validate_grammar_integration()?;

    common::log_success!(
        common::logging::codes::success::SYSTEM_INITIALIZATION_COMPLETED,
        "Complete pipeline validation succeeded",
        "stages_validated" => 7,
        "file_processing" => true,
        "lexical_analysis" => true,
        "syntax_analysis" => true,
        "symbol_discovery" => true,
        "reference_validation" => true,
        "semantic_analysis" => true,
        "structural_validation" => true
    );

    Ok(())
}
