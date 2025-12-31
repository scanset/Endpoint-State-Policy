use crate::lexical::LexicalMetrics;
use crate::reference_resolution::ReferenceValidationResult;
use crate::semantic_analysis::SemanticOutput;
use crate::symbols::SymbolDiscoveryResult;
use crate::validation::StructuralValidationResult;
use common::ast::nodes::EspFile;
use std::time::Duration;

/// Complete pipeline result containing all processing stages
#[derive(Debug)]
pub struct PipelineResult {
    pub ast: EspFile,
    pub file_metadata: crate::file_processor::FileMetadata,
    pub lexical_metrics: LexicalMetrics,
    pub symbol_discovery_result: SymbolDiscoveryResult,
    pub reference_validation_result: ReferenceValidationResult,
    pub semantic_analysis_result: SemanticOutput,
    pub structural_validation_result: StructuralValidationResult,
    pub token_count: usize,
    pub processing_duration: Duration,
}

impl PipelineResult {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ast: EspFile,
        file_metadata: crate::file_processor::FileMetadata,
        lexical_metrics: LexicalMetrics,
        symbol_discovery_result: SymbolDiscoveryResult,
        reference_validation_result: ReferenceValidationResult,
        semantic_analysis_result: SemanticOutput,
        structural_validation_result: StructuralValidationResult,
        token_count: usize,
        processing_duration: Duration,
    ) -> Self {
        Self {
            ast,
            file_metadata,
            lexical_metrics,
            symbol_discovery_result,
            reference_validation_result,
            semantic_analysis_result,
            structural_validation_result,
            token_count,
            processing_duration,
        }
    }

    pub fn log_success(&self, file_path: &str) {
        common::log_success!(
            common::logging::codes::success::AST_CONSTRUCTION_COMPLETE,
            "Complete ESP file processing pipeline succeeded",
            "file" => file_path,
            "duration_ms" => format!("{:.2}", self.processing_duration.as_secs_f64() * 1000.0),
            "processing_rate_bytes_per_sec" => format!("{:.0}",
                self.file_metadata.size as f64 / self.processing_duration.as_secs_f64()),
            "processing_rate_tokens_per_sec" => format!("{:.0}",
                self.token_count as f64 / self.processing_duration.as_secs_f64())
        );
    }
}
