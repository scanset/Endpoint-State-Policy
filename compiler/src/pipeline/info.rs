/// Information about pipeline capabilities
#[derive(Debug, Clone)]
pub struct PipelineInfo {
    pub pipeline_stages: usize,
    pub supports_file_processing: bool,
    pub supports_lexical_analysis: bool,
    pub supports_syntax_analysis: bool,
    pub supports_symbol_discovery: bool,
    pub supports_reference_validation: bool,
    pub supports_semantic_analysis: bool,
    pub supports_structural_validation: bool,
    pub max_file_size: usize,
    pub supported_extensions: Vec<String>,
    pub global_logging_enabled: bool,
    pub error_collection_enabled: bool,
    pub cargo_style_output: bool,
    pub ssdf_compliant: bool,
}

impl PipelineInfo {
    pub fn report(&self) -> String {
        format!(
            "ESP Processing Pipeline:\n\
             - Pipeline Stages: {}\n\
             - File Processing: {}\n\
             - Lexical Analysis: {}\n\
             - Syntax Analysis: {}\n\
             - Symbol Discovery: {}\n\
             - Reference Validation: {}\n\
             - Semantic Analysis: {}\n\
             - Structural Validation: {}\n\
             - Max File Size: {} MB\n\
             - Supported Extensions: {}\n\
             - Global Logging: {}\n\
             - Error Collection: {}\n\
             - Cargo-style Output: {}\n\
             - SSDF Compliant: {}",
            self.pipeline_stages,
            self.supports_file_processing,
            self.supports_lexical_analysis,
            self.supports_syntax_analysis,
            self.supports_symbol_discovery,
            self.supports_reference_validation,
            self.supports_semantic_analysis,
            self.supports_structural_validation,
            self.max_file_size / (1024 * 1024),
            self.supported_extensions.join(", "),
            self.global_logging_enabled,
            self.error_collection_enabled,
            self.cargo_style_output,
            self.ssdf_compliant
        )
    }

    pub fn summary(&self) -> String {
        let compliance = if self.ssdf_compliant {
            " (SSDF compliant)"
        } else {
            ""
        };
        format!(
            "{}-stage ESP compiler supporting {} extensions with global logging{}",
            self.pipeline_stages,
            self.supported_extensions.join(", "),
            compliance
        )
    }
}

/// Get pipeline capabilities information
pub fn get_pipeline_info() -> PipelineInfo {
    PipelineInfo {
        pipeline_stages: 7,
        supports_file_processing: true,
        supports_lexical_analysis: true,
        supports_syntax_analysis: true,
        supports_symbol_discovery: true,
        supports_reference_validation: true,
        supports_semantic_analysis: true,
        supports_structural_validation: true,
        max_file_size: 50 * 1024 * 1024, // 50MB default
        supported_extensions: vec!["esp".to_string()],
        global_logging_enabled: true,
        error_collection_enabled: true,
        cargo_style_output: true,
        ssdf_compliant: true,
    }
}
