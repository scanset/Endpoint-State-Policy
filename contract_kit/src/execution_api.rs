//! # Agent Core API
//!
//! High-level API for executing ESP compliance scans.
//!
//! This module abstracts all the complexity of `compiler`, `execution_engine`, and `common`
//! into simple functions. Users only need to:
//! 1. Create a `CtnStrategyRegistry` with their scanner implementations
//! 2. Call `scan_file()` or `scan_ast()`
//!
//! ## Example
//!
//! ```ignore
//! use contract_kit::execution_engine_api::{scan_file, ScanError};
//! use contract_kit::execution_engine_api::{CtnStrategyRegistry, CtnStrategy};
//! use std::sync::Arc;
//!
//! fn main() -> Result<(), ScanError> {
//!     // Create your registry with scanner implementations
//!     let registry = Arc::new(create_my_registry()?);
//!
//!     // Scan a file - that's it!
//!     let result = scan_file("policy.esp", registry)?;
//!
//!     // Check results
//!     if result.tree_passed {
//!         println!("Compliance check passed!");
//!     } else {
//!         for finding in &result.findings {
//!             println!("Finding: {}", finding.title);
//!         }
//!     }
//!
//!     Ok(())
//! }
//! ```

use std::path::Path;
use std::sync::Arc;

// ============================================================================
// Internal imports - users don't need to know about these
// ============================================================================

use compiler::pipeline;
use execution_engine::conversion::convert_ast_to_scanner_types;
use execution_engine::execution::ExecutionEngine;
use execution_engine::resolution::engine::ResolutionEngine;
use execution_engine::types::ResolutionContext;

// ============================================================================
// Re-exports - types users need for registry creation and result handling
// ============================================================================

// Strategy registry types
pub use execution_engine::strategies::{
    CollectedData, CollectionError, CollectorPerformanceProfile, CtnDataCollector,
    CtnStrategyRegistry, StrategyError,
};

// Re-export the full strategies module for registry creation
pub use execution_engine::strategies;

// AST types (for scan_ast)
pub use common::ast::nodes::EspFile;

// Metadata
pub use common::metadata::MetaDataBlock;

// Execution result (legacy type for backwards compatibility)
pub use execution_engine::execution::engine::PolicyExecutionResult as ScanResult;

// New manifest type for advanced usage
pub use execution_engine::types::ExecutionManifest;

// Logging utilities (optional, for users who want logging)
pub use common::logging;
pub use common::{log_debug, log_error, log_info, log_success};

// ============================================================================
// Error Type
// ============================================================================

/// Error type for scan operations
#[derive(Debug)]
pub enum ScanError {
    /// File I/O error
    IoError(std::io::Error),
    /// ESP compilation failed
    CompilationFailed(String),
    /// AST conversion failed
    ConversionFailed(String),
    /// Resolution phase failed
    ResolutionFailed(String),
    /// Scan execution failed
    ExecutionFailed(String),
    /// Registry error
    RegistryError(String),
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::IoError(e) => write!(f, "I/O error: {}", e),
            Self::CompilationFailed(msg) => write!(f, "Compilation failed: {}", msg),
            Self::ConversionFailed(msg) => write!(f, "AST conversion failed: {}", msg),
            Self::ResolutionFailed(msg) => write!(f, "Resolution failed: {}", msg),
            Self::ExecutionFailed(msg) => write!(f, "Execution failed: {}", msg),
            Self::RegistryError(msg) => write!(f, "Registry error: {}", msg),
        }
    }
}

impl std::error::Error for ScanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::IoError(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for ScanError {
    fn from(err: std::io::Error) -> Self {
        Self::IoError(err)
    }
}

impl From<execution_engine::strategies::StrategyError> for ScanError {
    fn from(err: execution_engine::strategies::StrategyError) -> Self {
        Self::RegistryError(err.to_string())
    }
}

impl From<execution_engine::conversion::ConversionError> for ScanError {
    fn from(err: execution_engine::conversion::ConversionError) -> Self {
        Self::ConversionFailed(err.to_string())
    }
}

// ============================================================================
// Public API Functions
// ============================================================================

/// Scan an ESP file and return the result.
///
/// This is the main entry point for file-based scanning. It handles:
/// - Compiling the ESP file
/// - Converting the AST to execution types
/// - Resolving references
/// - Executing the scan with the provided registry
///
/// # Arguments
/// * `path` - Path to the ESP file
/// * `registry` - Strategy registry with scanner implementations
///
/// # Returns
/// * `Ok(ScanResult)` - The scan completed (check `tree_passed` for compliance status)
/// * `Err(ScanError)` - The scan could not be completed
///
/// # Example
/// ```ignore
/// let registry = Arc::new(create_registry()?);
/// let result = scan_file("policy.esp", registry)?;
/// println!("Passed: {}", result.tree_passed);
/// ```
pub fn scan_file<P: AsRef<Path>>(
    path: P,
    registry: Arc<CtnStrategyRegistry>,
) -> Result<ScanResult, ScanError> {
    let path_str = path.as_ref().display().to_string();

    // Phase 1: Compile
    let pipeline_result = pipeline::process_file(&path_str)
        .map_err(|e| ScanError::CompilationFailed(e.to_string()))?;

    // Phase 2-4: Execute using the AST
    scan_ast(&pipeline_result.ast, registry)
}

/// Scan an ESP file and return the raw execution manifest.
///
/// This is the advanced entry point that returns the full `ExecutionManifest`
/// instead of the legacy `ScanResult`. Use this when you need access to all
/// execution data for custom output formatting.
///
/// # Arguments
/// * `path` - Path to the ESP file
/// * `registry` - Strategy registry with scanner implementations
///
/// # Returns
/// * `Ok(ExecutionManifest)` - The complete execution data
/// * `Err(ScanError)` - The scan could not be completed
pub fn scan_file_manifest<P: AsRef<Path>>(
    path: P,
    registry: Arc<CtnStrategyRegistry>,
) -> Result<ExecutionManifest, ScanError> {
    let path_str = path.as_ref().display().to_string();

    // Phase 1: Compile
    let pipeline_result = pipeline::process_file(&path_str)
        .map_err(|e| ScanError::CompilationFailed(e.to_string()))?;

    // Phase 2-4: Execute using the AST
    scan_ast_manifest(&pipeline_result.ast, registry)
}

/// Scan a pre-compiled ESP AST and return the result.
///
/// Use this when you already have a compiled AST (e.g., from a gRPC service
/// or cached compilation). This skips the compilation phase.
///
/// # Arguments
/// * `ast` - The compiled ESP AST
/// * `registry` - Strategy registry with scanner implementations
///
/// # Returns
/// * `Ok(ScanResult)` - The scan completed (check `tree_passed` for compliance status)
/// * `Err(ScanError)` - The scan could not be completed
///
/// # Example
/// ```ignore
/// // AST received from orchestrator
/// let ast: EspFile = serde_json::from_slice(&response.ast_json)?;
/// let result = scan_ast(&ast, registry)?;
/// ```
pub fn scan_ast(
    ast: &EspFile,
    registry: Arc<CtnStrategyRegistry>,
) -> Result<ScanResult, ScanError> {
    // Get the manifest and convert to legacy result type
    let manifest = scan_ast_manifest(ast, registry)?;
    Ok(manifest.into())
}

/// Scan a pre-compiled ESP AST and return the raw execution manifest.
///
/// This is the advanced entry point that returns the full `ExecutionManifest`.
/// Use this when you need access to all execution data for custom output formatting.
///
/// # Arguments
/// * `ast` - The compiled ESP AST
/// * `registry` - Strategy registry with scanner implementations
///
/// # Returns
/// * `Ok(ExecutionManifest)` - The complete execution data
/// * `Err(ScanError)` - The scan could not be completed
pub fn scan_ast_manifest(
    ast: &EspFile,
    registry: Arc<CtnStrategyRegistry>,
) -> Result<ExecutionManifest, ScanError> {
    // Phase 2: Convert AST to scanner types
    let (variables, states, objects, runtime_operations, sets, criteria_root, metadata) =
        convert_ast_to_scanner_types(ast)?;

    // Phase 3: Build resolution context and resolve
    let mut resolution_context = ResolutionContext::from_ast_with_criteria_root(
        variables,
        states,
        objects,
        runtime_operations,
        sets,
        criteria_root,
        metadata,
    );

    let mut resolution_engine = ResolutionEngine::new();
    let execution_context = resolution_engine
        .resolve_context(&mut resolution_context)
        .map_err(|e| ScanError::ResolutionFailed(e.to_string()))?;

    // Phase 4: Execute scan
    let mut engine = ExecutionEngine::new(execution_context, registry);
    let manifest = engine
        .execute()
        .map_err(|e| ScanError::ExecutionFailed(e.to_string()))?;

    Ok(manifest)
}

/// Scan an ESP file with logging enabled.
///
/// Same as `scan_file` but logs progress using the global logging system.
/// Call `logging::init_global_logging()` before using this.
///
/// # Arguments
/// * `path` - Path to the ESP file
/// * `registry` - Strategy registry with scanner implementations
///
/// # Returns
/// * `Ok(ScanResult)` - The scan completed
/// * `Err(ScanError)` - The scan could not be completed
pub fn scan_file_with_logging<P: AsRef<Path>>(
    path: P,
    registry: Arc<CtnStrategyRegistry>,
) -> Result<ScanResult, ScanError> {
    let path_str = path.as_ref().display().to_string();

    log_info!("Scanning ESP file", "path" => &path_str);

    // Phase 1: Compile
    log_info!("Phase 1: Compiling ESP file");
    let pipeline_result = pipeline::process_file(&path_str).map_err(|e| {
        log_error!(
            common::logging::codes::file_processing::FILE_NOT_FOUND,
            "ESP compilation failed",
            "error" => e.to_string()
        );
        ScanError::CompilationFailed(e.to_string())
    })?;

    log_success!(
        common::logging::codes::success::FILE_PROCESSING_SUCCESS,
        "ESP compilation successful"
    );

    // Phase 2: Convert
    log_info!("Phase 2: Converting AST");
    let (variables, states, objects, runtime_operations, sets, criteria_root, metadata) =
        convert_ast_to_scanner_types(&pipeline_result.ast).map_err(|e| {
            log_error!(
                common::logging::codes::system::INTERNAL_ERROR,
                "AST conversion failed",
                "error" => e.to_string()
            );
            ScanError::ConversionFailed(e.to_string())
        })?;

    // Phase 3: Resolve
    log_info!("Phase 3: Resolving references");
    let mut resolution_context = ResolutionContext::from_ast_with_criteria_root(
        variables,
        states,
        objects,
        runtime_operations,
        sets,
        criteria_root,
        metadata,
    );

    let mut resolution_engine = ResolutionEngine::new();
    let execution_context = resolution_engine
        .resolve_context(&mut resolution_context)
        .map_err(|e| {
            log_error!(
                common::logging::codes::system::INTERNAL_ERROR,
                "Resolution failed",
                "error" => e.to_string()
            );
            ScanError::ResolutionFailed(e.to_string())
        })?;

    log_success!(
        common::logging::codes::success::SEMANTIC_ANALYSIS_COMPLETE,
        "Resolution complete",
        "criteria_count" => execution_context.count_criteria()
    );

    // Phase 4: Execute
    log_info!("Phase 4: Executing compliance scan");
    let mut engine = ExecutionEngine::new(execution_context, registry);
    let manifest = engine.execute().map_err(|e| {
        log_error!(
            common::logging::codes::system::INTERNAL_ERROR,
            "Scan execution failed",
            "error" => e.to_string()
        );
        ScanError::ExecutionFailed(e.to_string())
    })?;

    // Convert to legacy result for logging and return
    let result: ScanResult = manifest.into();

    if result.tree_passed {
        log_success!(
            common::logging::codes::success::STRUCTURAL_VALIDATION_COMPLETE,
            "Compliance scan passed",
            "criteria" => result.criteria_counts.total,
            "passed" => result.criteria_counts.passed
        );
    } else {
        log_error!(
            common::logging::codes::structural::INCOMPLETE_DEFINITION_STRUCTURE,
            "Compliance scan failed",
            "failed_criteria" => result.criteria_counts.failed,
            "findings" => result.findings.len()
        );
    }

    Ok(result)
}

/// Extract metadata from a compiled AST.
///
/// Useful for getting policy information without running a full scan.
///
/// # Arguments
/// * `ast` - The compiled ESP AST
///
/// # Returns
/// The metadata block from the policy
pub fn extract_metadata(ast: &EspFile) -> MetaDataBlock {
    if let Some(meta) = &ast.metadata {
        let mut fields = std::collections::HashMap::new();
        for field in &meta.fields {
            fields.insert(field.name.clone(), field.value.clone());
        }
        MetaDataBlock { fields }
    } else {
        MetaDataBlock::default()
    }
}

/// Compile an ESP file without executing it.
///
/// Useful for validation or extracting metadata.
///
/// # Arguments
/// * `path` - Path to the ESP file
///
/// # Returns
/// * `Ok(EspFile)` - The compiled AST
/// * `Err(ScanError)` - Compilation failed
pub fn compile_file<P: AsRef<Path>>(path: P) -> Result<EspFile, ScanError> {
    let path_str = path.as_ref().display().to_string();
    let pipeline_result = pipeline::process_file(&path_str)
        .map_err(|e| ScanError::CompilationFailed(e.to_string()))?;
    Ok(pipeline_result.ast)
}

// ============================================================================
// Helper Functions for Result Handling
// ============================================================================

/// Check if a scan result indicates compliance.
#[inline]
pub fn is_compliant(result: &ScanResult) -> bool {
    result.tree_passed
}

/// Get the pass rate as a percentage (0.0 - 100.0).
#[inline]
pub fn pass_rate(result: &ScanResult) -> f64 {
    if result.criteria_counts.total == 0 {
        0.0
    } else {
        (result.criteria_counts.passed as f64 / result.criteria_counts.total as f64) * 100.0
    }
}

/// Format a scan result as a human-readable summary string.
pub fn format_summary(result: &ScanResult) -> String {
    let status = if result.tree_passed {
        "COMPLIANT"
    } else {
        "NON-COMPLIANT"
    };

    format!(
        "Status: {} | Criteria: {}/{} passed ({:.1}%) | Findings: {}",
        status,
        result.criteria_counts.passed,
        result.criteria_counts.total,
        pass_rate(result),
        result.findings.len()
    )
}

/// Format a scan result as a detailed report.
pub fn format_report(result: &ScanResult) -> String {
    let mut report = String::new();

    let status = if result.tree_passed {
        "COMPLIANT"
    } else {
        "NON-COMPLIANT"
    };

    report.push_str("=== Scan Results ===\n");
    report.push_str(&format!("Status: {}\n", status));
    report.push_str(&format!(
        "Total Criteria: {}\n",
        result.criteria_counts.total
    ));
    report.push_str(&format!("Passed: {}\n", result.criteria_counts.passed));
    report.push_str(&format!("Failed: {}\n", result.criteria_counts.failed));
    report.push_str(&format!("Errors: {}\n", result.criteria_counts.error));
    report.push_str(&format!("Pass Rate: {:.1}%\n", pass_rate(result)));
    report.push_str(&format!("Findings: {}\n", result.findings.len()));

    if !result.findings.is_empty() {
        report.push_str("\n=== Findings ===\n");
        for finding in &result.findings {
            report.push_str(&format!(
                "[{:?}] {}: {}\n",
                finding.severity, finding.finding_id, finding.title
            ));
            if !finding.description.is_empty() {
                report.push_str(&format!("    {}\n", finding.description));
            }
        }
    }

    report
}
