// Internal modules
pub mod batch;
pub mod config;
pub mod file_processor;
pub mod grammar;
pub mod lexical;
#[macro_use]
pub mod pipeline;
pub mod reference_resolution;
pub mod semantic_analysis;
pub mod symbols;
pub mod syntax;
pub mod tokens;
pub mod validation;

// Re-export key types for library consumers
pub use batch::{BatchConfig, BatchError, BatchResults};
pub use pipeline::{PipelineError, PipelineResult};

// Re-export pipeline output for FFI consumers
pub use pipeline::output::PipelineOutput;
