//! Output generation module
//!
//! Provides builders for different output formats:
//! - Full results with evidence
//! - Attestations (CUI-free)
//! - Summary (minimal)
//! - Assessor package (full reproducibility)

mod assessor;
mod attestation;
mod full;
mod summary;

pub use assessor::build_assessor_package;
pub use attestation::build_attestation;
pub use full::build_full_result;
pub use summary::build_summary;

use crate::config::OutputFormat;
use contract_kit::execution_api::ScanResult;

/// Build output in the specified format
pub fn build_output(
    scan_results: &[ScanResult],
    format: OutputFormat,
) -> Result<String, OutputError> {
    let json = match format {
        OutputFormat::Full => {
            let result = build_full_result(scan_results)?;
            serde_json::to_string_pretty(&result)
                .map_err(|e| OutputError::Serialization(e.to_string()))?
        }
        OutputFormat::Attestation => {
            let result = build_attestation(scan_results)?;
            serde_json::to_string_pretty(&result)
                .map_err(|e| OutputError::Serialization(e.to_string()))?
        }
        OutputFormat::Summary => {
            let result = build_summary(scan_results);
            serde_json::to_string_pretty(&result)
                .map_err(|e| OutputError::Serialization(e.to_string()))?
        }
        OutputFormat::Assessor => {
            let result = build_assessor_package(scan_results)?;
            serde_json::to_string_pretty(&result)
                .map_err(|e| OutputError::Serialization(e.to_string()))?
        }
    };
    Ok(json)
}

/// Errors that can occur during output generation
#[derive(Debug)]
pub enum OutputError {
    /// Failed to build result
    Build(String),
    /// Failed to serialize result
    Serialization(String),
}

impl std::fmt::Display for OutputError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputError::Build(msg) => write!(f, "Failed to build output: {}", msg),
            OutputError::Serialization(msg) => write!(f, "Failed to serialize output: {}", msg),
        }
    }
}

impl std::error::Error for OutputError {}

impl From<common::results::ResultError> for OutputError {
    fn from(e: common::results::ResultError) -> Self {
        OutputError::Build(e.to_string())
    }
}
