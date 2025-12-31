//! # ESP Scanner CLI
//!
//! Compliance scanning for ESP (Endpoint State Policy) files.

use contract_kit::agent_core_api::{
    // Result helpers
    format_report,
    log_error,
    log_info,
    log_success,
    // Logging
    logging,
    // Scan functions
    scan_file_with_logging,
    // Result type
    ScanResult,
    // Types for error handling
    StrategyError,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

mod registry;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    logging::init_global_logging()?;
    log_info!("ESP Scanner starting");

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        print_usage(&args[0]);
        std::process::exit(1);
    }

    if args[1] == "--help" || args[1] == "-h" {
        print_help(&args[0]);
        return Ok(());
    }

    let input_path = Path::new(&args[1]);

    if input_path.is_file() {
        scan_single_file(input_path)?;
    } else if input_path.is_dir() {
        scan_directory(input_path)?;
    } else {
        eprintln!("Error: Input must be an ESP file or directory");
        eprintln!("  Path: {}", input_path.display());
        std::process::exit(1);
    }

    logging::print_cargo_style_summary();
    Ok(())
}

fn print_usage(program_name: &str) {
    eprintln!("Usage: {} <file.esp|directory>", program_name);
    eprintln!("       {} --help", program_name);
}

fn print_help(program_name: &str) {
    println!("ESP Scanner v{}", env!("CARGO_PKG_VERSION"));
    println!("Compliance scanning for ESP (Endpoint State Policy) files\n");
    println!("USAGE:");
    println!("    {} <file.esp>       Scan single ESP file", program_name);
    println!(
        "    {} <directory>      Scan all ESP files in directory",
        program_name
    );
    println!(
        "    {} --help           Show this help message\n",
        program_name
    );

    println!("EXAMPLES:");
    println!("    {} policy.esp", program_name);
    println!("    {} /etc/esp/policies/", program_name);
}

fn scan_single_file(file_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let start = Instant::now();
    let _file_path_str = file_path.display().to_string();

    logging::set_file_context(file_path.to_path_buf(), 1);

    // Create registry
    let registry = Arc::new(
        registry::create_scanner_registry().map_err(|e: StrategyError| {
            log_error!(
                logging::codes::system::INTERNAL_ERROR,
                "Failed to create scanner registry",
                "error" => e.to_string()
            );
            format!("Registry creation failed: {}", e)
        })?,
    );

    let stats = registry.get_statistics();
    log_info!(
        "Registry initialized",
        "strategies" => stats.total_ctn_types,
        "healthy" => stats.registry_health.is_healthy()
    );

    // Scan file using agent_core_api
    let scan_result = scan_file_with_logging(file_path, registry)?;

    let duration = start.elapsed();

    // Report results
    print_scan_results(&scan_result, duration);

    // Save results to JSON
    let json = serde_json::to_string_pretty(&scan_result)?;
    std::fs::write("scan_result.json", &json)?;
    println!("\n[OK] Results saved to: scan_result.json");

    logging::clear_file_context();

    if !scan_result.tree_passed {
        std::process::exit(1);
    }

    Ok(())
}

fn print_scan_results(scan_result: &ScanResult, duration: std::time::Duration) {
    println!("\n{}", format_report(scan_result));
    println!("Duration: {:.2}s", duration.as_secs_f64());
}

fn scan_directory(dir_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let start = Instant::now();
    log_info!("Starting batch directory scan", "path" => dir_path.display().to_string());

    let esp_files = discover_esp_files(dir_path)?;
    if esp_files.is_empty() {
        println!("No ESP files found in directory: {}", dir_path.display());
        return Ok(());
    }

    log_info!("Discovered ESP files", "count" => esp_files.len(), "directory" => dir_path.display().to_string());
    println!("Scanning {} ESP files...", esp_files.len());

    // Create registry once for all scans
    let registry = Arc::new(
        registry::create_scanner_registry().map_err(|e: StrategyError| {
            log_error!(
                logging::codes::system::INTERNAL_ERROR,
                "Failed to create scanner registry",
                "error" => e.to_string()
            );
            format!("Registry creation failed: {}", e)
        })?,
    );

    let mut successful_scans = 0;
    let mut failed_scans = 0;
    let mut compliant_scans = 0;
    let mut non_compliant_scans = 0;
    let mut all_results = Vec::new();

    for (file_id, esp_file) in esp_files.iter().enumerate() {
        let file_id = file_id + 1;
        println!(
            "\n[{}/{}] Scanning: {}",
            file_id,
            esp_files.len(),
            esp_file.display()
        );
        logging::set_file_context(esp_file.clone(), file_id);

        match scan_file_with_logging(esp_file, registry.clone()) {
            Ok(scan_result) => {
                successful_scans += 1;
                if scan_result.tree_passed {
                    compliant_scans += 1;
                    println!(
                        "  ✓ COMPLIANT ({} criteria)",
                        scan_result.criteria_counts.total
                    );
                } else {
                    non_compliant_scans += 1;
                    println!(
                        "  ✗ NON-COMPLIANT ({} findings)",
                        scan_result.findings.len()
                    );
                }
                all_results.push(scan_result);
            }
            Err(e) => {
                failed_scans += 1;
                println!("  ✗ FAILED: {}", e);
                log_error!(
                    logging::codes::system::INTERNAL_ERROR,
                    "File scan failed",
                    "file" => esp_file.display().to_string(),
                    "error" => e.to_string()
                );
            }
        }

        logging::clear_file_context();
    }

    let duration = start.elapsed();

    println!("\n=== Batch Scan Summary ===");
    println!("Directory: {}", dir_path.display());
    println!("Files Scanned: {}", esp_files.len());
    println!("Successful: {}", successful_scans);
    println!("Failed: {}", failed_scans);
    println!("Compliant: {}", compliant_scans);
    println!("Non-Compliant: {}", non_compliant_scans);
    println!("Duration: {:.2}s", duration.as_secs_f64());

    let json = serde_json::to_string_pretty(&all_results)?;
    std::fs::write("batch_results.json", &json)?;
    println!("\n[OK] Results saved to: batch_results.json");

    log_success!(
        logging::codes::success::FILE_PROCESSING_SUCCESS,
        "Batch scan completed",
        "total_files" => esp_files.len(),
        "successful" => successful_scans,
        "compliant" => compliant_scans,
        "duration_ms" => duration.as_millis()
    );

    if failed_scans > 0 || non_compliant_scans > 0 {
        std::process::exit(1);
    }

    Ok(())
}

fn discover_esp_files(dir_path: &Path) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let mut esp_files = Vec::new();
    for entry in std::fs::read_dir(dir_path)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            if let Some(extension) = path.extension() {
                if extension == "esp" {
                    esp_files.push(path);
                }
            }
        }
    }
    esp_files.sort();
    Ok(esp_files)
}
