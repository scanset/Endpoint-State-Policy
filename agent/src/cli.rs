//! Command-line interface parsing
//!
//! Handles argument parsing, validation, and help text generation.

use std::path::PathBuf;

use crate::config::{OutputFormat, ScanConfig};

/// CLI parsing result
pub enum CliResult {
    /// Run scan with this configuration
    Run(ScanConfig),
    /// Show help and exit
    Help,
    /// Error with message
    Error(String),
}

/// Parse command-line arguments
pub fn parse_args(args: &[String]) -> CliResult {
    let program_name = args.first().map(|s| s.as_str()).unwrap_or("esp-agent");

    let mut input_path: Option<&str> = None;
    let mut output_file: Option<String> = None;
    let mut quiet = false;
    let mut output_format = OutputFormat::Full;

    let mut i = 1;
    while i < args.len() {
        match args.get(i).map(|s| s.as_str()) {
            Some("--help" | "-h") => {
                return CliResult::Help;
            }
            Some("--quiet" | "-q") => {
                quiet = true;
            }
            Some("--output" | "-o") => {
                i += 1;
                match args.get(i) {
                    Some(val) => output_file = Some(val.clone()),
                    None => return CliResult::Error("--output requires a filename".to_string()),
                }
            }
            Some("--format" | "-f") => {
                i += 1;
                match args.get(i).map(|s| s.as_str()) {
                    Some("full") => output_format = OutputFormat::Full,
                    Some("summary") => output_format = OutputFormat::Summary,
                    Some("attestation") => output_format = OutputFormat::Attestation,
                    Some("assessor") => output_format = OutputFormat::Assessor,
                    Some(other) => {
                        return CliResult::Error(format!(
                            "Unknown format '{}'. Use: full, summary, attestation, assessor",
                            other
                        ));
                    }
                    None => return CliResult::Error("--format requires a value".to_string()),
                }
            }
            Some(arg) if !arg.starts_with('-') => {
                input_path = Some(arg);
            }
            Some(arg) => {
                return CliResult::Error(format!("Unknown option: {}", arg));
            }
            None => break,
        }
        i += 1;
    }

    // Validate input path
    let input_path = match input_path {
        Some(p) => PathBuf::from(p),
        None => {
            return CliResult::Error(format!(
                "Missing input path\nUsage: {} [OPTIONS] <file.esp|directory>",
                program_name
            ));
        }
    };

    if !input_path.exists() {
        return CliResult::Error(format!("Path not found: {}", input_path.display()));
    }

    CliResult::Run(ScanConfig {
        input_path,
        output_file,
        output_format,
        quiet,
    })
}

/// Print usage information
#[allow(dead_code)]
pub fn print_usage(program_name: &str) {
    eprintln!("Usage: {} [OPTIONS] <file.esp|directory>", program_name);
    eprintln!("       {} --help", program_name);
}

/// Print full help text
pub fn print_help(program_name: &str) {
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
    println!("    -h, --help                  Show this help message");
    println!("    -q, --quiet                 Suppress progress output");
    println!("    -o, --output <file>         Write results to specified file (JSON)");
    println!("    -f, --format <format>       Output format: full (default), summary, attestation, assessor");
    println!();

    println!("OUTPUT FORMATS:");
    println!("    full          Complete results with findings and evidence (default)");
    println!("    summary       Minimal output with pass/fail counts only");
    println!("    attestation   CUI-free format safe for network transport");
    println!("    assessor      Full package with reproducibility info for assessors");
    println!();

    println!("OUTPUT STRUCTURE:");
    println!("    All formats produce a single envelope containing all scanned policies.");
    println!("    The envelope includes agent info, host info, and aggregated results.");
    println!();

    println!("EXIT CODES:");
    println!("    0    All policies passed");
    println!("    1    One or more policies failed");
    println!("    2    Execution error");
    println!();

    println!("EXAMPLES:");
    println!("    {} policy.esp", program_name);
    println!("    {} --output results.json policy.esp", program_name);
    println!(
        "    {} --format attestation -o attestation.json policy.esp",
        program_name
    );
    println!("    {} --quiet /path/to/policies/", program_name);
}
