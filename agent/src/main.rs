//! # ESP Compliance Agent
//!
//! Compliance scanning agent using ESP (Endpoint State Policy) files.
//! Uses contract_kit for collectors, executors, and the high-level execution API.

use contract_kit::execution_api::{
    format_report, log_error, log_info, log_success, logging, scan_file_with_logging,
    CtnStrategyRegistry, ScanResult, StrategyError,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

mod registry;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    logging::init_global_logging()?;
    log_info!("ESP Compliance Agent starting");

    let args: Vec<String> = std::env::args().collect();
    let program_name = args.first().map(|s| s.as_str()).unwrap_or("esp-agent");

    // Parse arguments
    let mut input_path: Option<&str> = None;
    let mut output_file: Option<&str> = None;
    let mut quiet = false;

    let mut i = 1;
    while i < args.len() {
        match args.get(i).map(|s| s.as_str()) {
            Some("--help" | "-h") => {
                print_help(program_name);
                return Ok(());
            }
            Some("--quiet" | "-q") => {
                quiet = true;
            }
            Some("--output" | "-o") => {
                i += 1;
                output_file = args.get(i).map(|s| s.as_str());
                if output_file.is_none() {
                    eprintln!("Error: --output requires a filename");
                    std::process::exit(2);
                }
            }
            Some(arg) if !arg.starts_with('-') => {
                input_path = Some(arg);
            }
            Some(arg) => {
                eprintln!("Unknown option: {}", arg);
                print_usage(program_name);
                std::process::exit(2);
            }
            None => break,
        }
        i += 1;
    }

    let input_path = match input_path {
        Some(p) => Path::new(p),
        None => {
            print_usage(program_name);
            std::process::exit(2);
        }
    };

    if !input_path.exists() {
        eprintln!("Error: Path not found: {}", input_path.display());
        std::process::exit(2);
    }

    let exit_code = if input_path.is_file() {
        scan_single_file(input_path, output_file, quiet)?
    } else if input_path.is_dir() {
        scan_directory(input_path, output_file, quiet)?
    } else {
        eprintln!("Error: Invalid path: {}", input_path.display());
        std::process::exit(2);
    };

    if !quiet {
        logging::print_cargo_style_summary();
    }

    std::process::exit(exit_code);
}

fn print_usage(program_name: &str) {
    eprintln!("Usage: {} [OPTIONS] <file.esp|directory>", program_name);
    eprintln!("       {} --help", program_name);
}

fn print_help(program_name: &str) {
    println!("ESP Compliance Agent v{}", env!("CARGO_PKG_VERSION"));
    println!("Compliance scanning using ESP policy files\n");
    println!("USAGE:");
    println!(
        "    {} [OPTIONS] <file.esp>       Scan single ESP file",
        program_name
    );
    println!(
        "    {} [OPTIONS] <directory>      Scan all ESP files in directory",
        program_name
    );
    println!(
        "    {} --help                     Show this help message\n",
        program_name
    );
    println!("OPTIONS:");
    println!("    -h, --help              Show this help message");
    println!("    -q, --quiet             Suppress progress output");
    println!("    -o, --output <file>     Write results to specified file (JSON)");
    println!();
    println!("EXIT CODES:");
    println!("    0    All policies passed");
    println!("    1    One or more policies failed");
    println!("    2    Execution error");
    println!();
    println!("EXAMPLES:");
    println!("    {} policy.esp", program_name);
    println!("    {} --output results.json policy.esp", program_name);
    println!("    {} --quiet /path/to/policies/", program_name);
}

fn scan_single_file(
    file_path: &Path,
    output_file: Option<&str>,
    quiet: bool,
) -> Result<i32, Box<dyn std::error::Error>> {
    let start = Instant::now();

    log_info!("Scanning ESP file", "path" => file_path.display().to_string());
    logging::set_file_context(file_path.to_path_buf(), 1);

    // Create registry
    let registry = Arc::new(create_registry()?);

    if !quiet {
        let stats = registry.get_statistics();
        log_info!(
            "Registry initialized",
            "strategies" => stats.total_ctn_types,
            "healthy" => stats.registry_health.is_healthy()
        );
    }

    // Scan file
    let scan_result = scan_file_with_logging(file_path, registry)?;

    let duration = start.elapsed();

    // Report results
    if !quiet {
        print_scan_results(&scan_result, duration);
    }

    // Save results if output file specified
    let output_path = output_file.unwrap_or("scan_result.json");
    let json = serde_json::to_string_pretty(&scan_result)?;
    std::fs::write(output_path, &json)?;

    if !quiet {
        println!("\n[OK] Results saved to: {}", output_path);
    }

    logging::clear_file_context();

    if scan_result.tree_passed {
        Ok(0)
    } else {
        Ok(1)
    }
}

fn scan_directory(
    dir_path: &Path,
    output_file: Option<&str>,
    quiet: bool,
) -> Result<i32, Box<dyn std::error::Error>> {
    let start = Instant::now();

    log_info!("Starting batch directory scan", "path" => dir_path.display().to_string());

    let esp_files = discover_esp_files(dir_path)?;
    if esp_files.is_empty() {
        if !quiet {
            println!("No ESP files found in directory: {}", dir_path.display());
        }
        return Ok(0);
    }

    log_info!("Discovered ESP files", "count" => esp_files.len());
    if !quiet {
        println!("Scanning {} ESP files...\n", esp_files.len());
    }

    // Create registry once for all scans
    let registry = Arc::new(create_registry()?);

    let mut passed = 0;
    let mut failed = 0;
    let mut errors = 0;
    let mut all_results: Vec<serde_json::Value> = Vec::new();

    for (index, esp_file) in esp_files.iter().enumerate() {
        let file_num = index + 1;

        if !quiet {
            println!("[{}/{}] {}", file_num, esp_files.len(), esp_file.display());
        }
        logging::set_file_context(esp_file.clone(), file_num);

        match scan_file_with_logging(esp_file, registry.clone()) {
            Ok(scan_result) => {
                if scan_result.tree_passed {
                    passed += 1;
                    if !quiet {
                        println!(
                            "  ✓ PASSED ({}/{} criteria)\n",
                            scan_result.criteria_counts.passed, scan_result.criteria_counts.total
                        );
                    }
                } else {
                    failed += 1;
                    if !quiet {
                        println!("  ✗ FAILED ({} findings)\n", scan_result.findings.len());
                        for finding in &scan_result.findings {
                            println!("    - {}: {}", finding.finding_id, finding.title);
                        }
                        println!();
                    }
                }

                all_results.push(serde_json::to_value(&scan_result)?);
            }
            Err(e) => {
                errors += 1;
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

    let duration = start.elapsed();

    // Print summary
    if !quiet {
        println!("═══════════════════════════════════════");
        println!("Batch Scan Summary");
        println!("═══════════════════════════════════════");
        println!("  Directory: {}", dir_path.display());
        println!("  Total:     {}", esp_files.len());
        println!("  Passed:    {}", passed);
        println!("  Failed:    {}", failed);
        println!("  Errors:    {}", errors);
        println!("  Duration:  {:.2}s", duration.as_secs_f64());
        println!("═══════════════════════════════════════\n");
    }

    // Save results
    let output_path = output_file.unwrap_or("batch_results.json");
    let json = serde_json::to_string_pretty(&all_results)?;
    std::fs::write(output_path, &json)?;

    if !quiet {
        println!("[OK] Results saved to: {}", output_path);
    }

    log_success!(
        logging::codes::success::FILE_PROCESSING_SUCCESS,
        "Batch scan completed",
        "total" => esp_files.len(),
        "passed" => passed,
        "failed" => failed,
        "errors" => errors
    );

    if errors > 0 {
        Ok(2)
    } else if failed > 0 {
        Ok(1)
    } else {
        Ok(0)
    }
}

fn create_registry() -> Result<CtnStrategyRegistry, Box<dyn std::error::Error>> {
    registry::create_scanner_registry().map_err(|e: StrategyError| {
        log_error!(
            logging::codes::system::INTERNAL_ERROR,
            "Failed to create scanner registry",
            "error" => e.to_string()
        );
        Box::<dyn std::error::Error>::from(format!("Registry creation failed: {}", e))
    })
}

fn discover_esp_files(dir_path: &Path) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let mut esp_files = Vec::new();

    for entry in std::fs::read_dir(dir_path)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() {
            if let Some(ext) = path.extension() {
                if ext == "esp" {
                    esp_files.push(path);
                }
            }
        }
    }

    esp_files.sort();
    Ok(esp_files)
}

fn print_scan_results(scan_result: &ScanResult, duration: std::time::Duration) {
    println!("\n{}", format_report(scan_result));
    println!("Duration: {:.2}s", duration.as_secs_f64());
}
