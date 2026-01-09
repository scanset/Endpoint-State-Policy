//! Core scanning logic
//!
//! Handles the execution of ESP scans and result collection.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use contract_kit::execution_api::{
    log_error, log_info, log_success, logging, scan_file_with_logging, CtnStrategyRegistry,
    ScanResult, StrategyError,
};

use crate::config::{OutputFormat, ScanConfig, ScanSummary};
use crate::output;
use crate::registry;

/// Run a scan with the given configuration
pub fn run_scan(config: &ScanConfig, esp_files: &[PathBuf]) -> Result<i32, ScanError> {
    let start = Instant::now();

    log_info!("Starting unified scan", "file_count" => esp_files.len());
    if !config.quiet {
        println!("Scanning {} ESP file(s)...\n", esp_files.len());
    }

    // Create registry once for all scans
    let registry = Arc::new(create_registry()?);

    if !config.quiet {
        let stats = registry.get_statistics();
        log_info!(
            "Registry initialized",
            "strategies" => stats.total_ctn_types,
            "healthy" => stats.registry_health.is_healthy()
        );
    }

    // Execute scans and collect results
    let (scan_results, summary) = execute_scans(esp_files, &registry, config.quiet)?;

    let duration = start.elapsed();

    // Print summary
    if !config.quiet {
        print_summary(&summary, duration, config.output_format);
    }

    // Build and save output
    if !scan_results.is_empty() {
        save_output(&scan_results, config)?;
    }

    if !config.quiet {
        println!("[OK] Results saved to: {}", config.output_path());
    }

    log_success!(
        logging::codes::success::FILE_PROCESSING_SUCCESS,
        "Scan completed",
        "total" => summary.total_files,
        "passed" => summary.passed,
        "failed" => summary.failed,
        "errors" => summary.errors
    );

    Ok(summary.exit_code())
}

/// Execute scans on all ESP files
fn execute_scans(
    esp_files: &[PathBuf],
    registry: &Arc<CtnStrategyRegistry>,
    quiet: bool,
) -> Result<(Vec<ScanResult>, ScanSummary), ScanError> {
    let mut scan_results: Vec<ScanResult> = Vec::new();
    let mut summary = ScanSummary::new(esp_files.len());

    for (index, esp_file) in esp_files.iter().enumerate() {
        let file_num = index + 1;

        if !quiet {
            println!("[{}/{}] {}", file_num, esp_files.len(), esp_file.display());
        }
        logging::set_file_context(esp_file.clone(), file_num);

        match scan_file_with_logging(esp_file, registry.clone()) {
            Ok(scan_result) => {
                if scan_result.tree_passed {
                    summary.passed += 1;
                    if !quiet {
                        println!(
                            "  ✓ PASSED ({}/{} criteria)\n",
                            scan_result.criteria_counts.passed, scan_result.criteria_counts.total
                        );
                    }
                } else {
                    summary.failed += 1;
                    if !quiet {
                        println!("  ✗ FAILED ({} findings)\n", scan_result.findings.len());
                        for finding in &scan_result.findings {
                            println!("    - {}: {}", finding.finding_id, finding.title);
                        }
                        println!();
                    }
                }
                scan_results.push(scan_result);
            }
            Err(e) => {
                summary.errors += 1;
                if !quiet {
                    println!("  ✗ ERROR: {}\n", e);
                }
                log_error!(
                    logging::codes::system::INTERNAL_ERROR,
                    "Scan failed",
                    "file" => esp_file.display().to_string(),
                    "error" => e.to_string()
                );
            }
        }

        logging::clear_file_context();
    }

    Ok((scan_results, summary))
}

/// Create the strategy registry
fn create_registry() -> Result<CtnStrategyRegistry, ScanError> {
    registry::create_scanner_registry().map_err(|e| {
        log_error!(
            logging::codes::system::INTERNAL_ERROR,
            "Failed to create scanner registry",
            "error" => e.to_string()
        );
        ScanError::Registry(e)
    })
}

/// Save output to file
fn save_output(scan_results: &[ScanResult], config: &ScanConfig) -> Result<(), ScanError> {
    let json =
        output::build_output(scan_results, config.output_format).map_err(ScanError::Output)?;

    std::fs::write(config.output_path(), &json)
        .map_err(|e| ScanError::WriteFile(config.output_path().to_string(), e))?;

    Ok(())
}

/// Print scan summary to console
fn print_summary(summary: &ScanSummary, duration: std::time::Duration, format: OutputFormat) {
    println!("═══════════════════════════════════════");
    println!("Scan Summary");
    println!("═══════════════════════════════════════");
    println!("  Total:     {}", summary.total_files);
    println!("  Passed:    {}", summary.passed);
    println!("  Failed:    {}", summary.failed);
    println!("  Errors:    {}", summary.errors);
    println!("  Duration:  {:.2}s", duration.as_secs_f64());
    println!("  Format:    {}", format);
    println!("═══════════════════════════════════════\n");
}

/// Errors that can occur during scanning
#[derive(Debug)]
pub enum ScanError {
    /// Failed to create registry
    Registry(StrategyError),
    /// Failed to generate output
    Output(output::OutputError),
    /// Failed to write output file
    WriteFile(String, std::io::Error),
}

impl std::fmt::Display for ScanError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ScanError::Registry(e) => write!(f, "Registry creation failed: {}", e),
            ScanError::Output(e) => write!(f, "Output generation failed: {}", e),
            ScanError::WriteFile(path, e) => write!(f, "Failed to write {}: {}", path, e),
        }
    }
}

impl std::error::Error for ScanError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ScanError::Registry(e) => Some(e),
            ScanError::Output(e) => Some(e),
            ScanError::WriteFile(_, e) => Some(e),
        }
    }
}
