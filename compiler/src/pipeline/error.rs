use crate::file_processor::FileProcessorError;
use crate::lexical::LexerError;
use crate::reference_resolution::ReferenceValidationError;
use crate::semantic_analysis::SemanticError;
use crate::symbols::SymbolDiscoveryError;
use crate::syntax::SyntaxError;
use crate::validation::StructuralError;

/// Pipeline processing errors
#[derive(Debug, thiserror::Error)]
pub enum PipelineError {
    #[error("File processing failed: {0}")]
    FileProcessing(#[from] FileProcessorError),

    #[error("Lexical analysis failed: {0}")]
    LexicalAnalysis(#[from] LexerError),

    #[error("Syntax analysis failed: {0}")]
    SyntaxAnalysis(#[from] SyntaxError),

    #[error("Symbol discovery failed: {0}")]
    SymbolDiscovery(#[from] SymbolDiscoveryError),

    #[error("Reference validation failed: {0}")]
    ReferenceValidation(#[from] ReferenceValidationError),

    #[error("Semantic analysis failed: {0}")]
    SemanticAnalysis(#[from] SemanticError),

    #[error("Structural validation failed: {0}")]
    StructuralValidation(#[from] StructuralError),

    #[error("Pipeline error: {message}")]
    Pipeline { message: String },
}

impl PipelineError {
    pub fn new(message: &str) -> Self {
        Self::Pipeline {
            message: message.to_string(),
        }
    }
}
