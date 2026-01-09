//! Configuration types for the ESP agent
//!
//! Defines the configuration structures used throughout the agent.

use std::path::PathBuf;

/// Output format for scan results
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Summary only (minimal JSON)
    Summary,
    /// Full results with findings and evidence
    Full,
    /// Attestation format (CUI-free)
    Attestation,
    /// Assessor package with full reproducibility info
    Assessor,
}

impl OutputFormat {
    /// Get the default output filename for this format
    pub fn default_filename(&self) -> &'static str {
        match self {
            OutputFormat::Summary => "summary.json",
            OutputFormat::Full => "results.json",
            OutputFormat::Attestation => "attestation.json",
            OutputFormat::Assessor => "assessor_package.json",
        }
    }
}

impl std::fmt::Display for OutputFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OutputFormat::Summary => write!(f, "summary"),
            OutputFormat::Full => write!(f, "full"),
            OutputFormat::Attestation => write!(f, "attestation"),
            OutputFormat::Assessor => write!(f, "assessor"),
        }
    }
}

/// Configuration for a scan run
#[derive(Debug, Clone)]
pub struct ScanConfig {
    /// Input path (file or directory)
    pub input_path: PathBuf,

    /// Output file path (optional, uses default based on format)
    pub output_file: Option<String>,

    /// Output format
    pub output_format: OutputFormat,

    /// Suppress progress output
    pub quiet: bool,
}

impl ScanConfig {
    /// Get the output file path, using default if not specified
    pub fn output_path(&self) -> &str {
        self.output_file
            .as_deref()
            .unwrap_or_else(|| self.output_format.default_filename())
    }
}

/// Result of a scan run
#[derive(Debug)]
pub struct ScanSummary {
    /// Total files scanned
    pub total_files: usize,

    /// Policies that passed
    pub passed: usize,

    /// Policies that failed
    pub failed: usize,

    /// Files that had errors
    pub errors: usize,

    /// Total scan duration
    #[allow(dead_code)]
    pub duration: std::time::Duration,
}

impl ScanSummary {
    /// Create a new scan summary
    pub fn new(total_files: usize) -> Self {
        Self {
            total_files,
            passed: 0,
            failed: 0,
            errors: 0,
            duration: std::time::Duration::ZERO,
        }
    }

    /// Get the exit code based on results
    pub fn exit_code(&self) -> i32 {
        if self.errors > 0 {
            2
        } else if self.failed > 0 {
            1
        } else {
            0
        }
    }
}
