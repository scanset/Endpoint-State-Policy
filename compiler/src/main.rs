use common::logging;
use compiler::{batch, pipeline};
use std::env;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize global logging system
    logging::init_global_logging()?;

    // Validate pipeline configuration
    pipeline::validate_pipeline()?;

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: {} <input.esp|directory> [options]", args[0]);
        eprintln!("       {} --help", args[0]);
        std::process::exit(1);
    }

    if args[1] == "--help" {
        print_help(&args[0]);
        return Ok(());
    }

    let input_path = Path::new(&args[1]);

    // Parse additional options
    let batch_config = parse_batch_options(&args[2..]);

    if input_path.is_file() {
        // Single file processing
        process_single_file(&args[1])?;
    } else if input_path.is_dir() {
        // Batch directory processing
        process_directory_batch(input_path, &batch_config)?;
    } else {
        eprintln!("Error: Input must be a file (.esp) or directory");
        eprintln!("  File: {}", input_path.display());
        std::process::exit(1);
    }

    Ok(())
}

fn print_help(program_name: &str) {
    println!("ESP Compiler v{}", env!("CARGO_PKG_VERSION"));
    println!("Complete ESP Compilation pipeline with batch processing");
    println!();
    println!("USAGE:");
    println!(
        "    {} <input.esp>                    # Process single file",
        program_name
    );
    println!(
        "    {} <directory> [options]          # Process directory",
        program_name
    );
    println!();
    println!("ARGUMENTS:");
    println!("    <input.esp>    Path to the ESP file to process");
    println!("    <directory>    Path to directory containing ESP files");
    println!();
    println!("OPTIONS:");
    println!("    --help              Show this help message");
    println!("    --sequential        Force sequential processing (no parallelism)");
    println!("    --parallel          Force parallel processing (default)");
    println!("    --threads N         Set maximum number of threads (default: auto)");
    println!("    --no-recursive      Don't search subdirectories");
    println!("    --max-files N       Limit maximum files to process");
    println!("    --fail-fast         Stop on first error");
    println!("    --quiet             Suppress progress reporting");
    println!();
    println!("SINGLE FILE OUTPUT:");
    println!("    Success: Detailed processing metrics, AST structure, symbol information");
    println!("    Failure: Comprehensive error information with recommendations");
    println!();
    println!("BATCH PROCESSING OUTPUT:");
    println!("    Cargo-style error reporting grouped by file");
    println!("    Processing summary with success/failure statistics");
    println!("    Performance metrics and throughput information");
    println!();
    println!("EXAMPLES:");
    println!(
        "    {} example.esp                     # Single file",
        program_name
    );
    println!(
        "    {} /path/to/esp-files/             # All files in directory",
        program_name
    );
    println!(
        "    {} configs/ --threads 4            # 4 threads max",
        program_name
    );
    println!(
        "    {} tests/ --sequential --fail-fast # Sequential with early exit",
        program_name
    );
    println!(
        "    {} large-dir/ --max-files 100      # Limit file count",
        program_name
    );
    println!();

    // Print pipeline capabilities
    let pipeline_info = pipeline::get_pipeline_info();
    println!("PIPELINE CAPABILITIES:");
    for line in pipeline_info.report().lines() {
        println!("    {}", line);
    }
    println!();

    // Print batch capabilities
    let batch_info = batch::get_batch_info();
    println!("BATCH PROCESSING CAPABILITIES:");
    println!(
        "    Max recommended threads: {}",
        batch_info.max_recommended_threads
    );
    println!(
        "    Recursive discovery: {}",
        batch_info.supports_recursive_discovery
    );
    println!(
        "    Parallel processing: {}",
        batch_info.supports_parallel_processing
    );
    println!(
        "    Progress reporting: {}",
        batch_info.supports_progress_reporting
    );
    println!("    Fail-fast mode: {}", batch_info.supports_fail_fast);
    println!(
        "    Supported extensions: {}",
        batch_info.supported_file_extensions.join(", ")
    );
}

fn parse_batch_options(args: &[String]) -> batch::BatchConfig {
    let mut config = batch::BatchConfig::default();

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--sequential" => {
                config.max_threads = 1;
            }
            "--parallel" => {
                // Keep default parallel setting
            }
            "--threads" => {
                if i + 1 < args.len() {
                    if let Ok(threads) = args[i + 1].parse::<usize>() {
                        config.max_threads = threads.clamp(1, 32); // Reasonable bounds
                        i += 1; // Skip the number argument
                    } else {
                        eprintln!(
                            "Warning: Invalid thread count '{}', using default",
                            args[i + 1]
                        );
                        i += 1;
                    }
                } else {
                    eprintln!("Warning: --threads requires a number");
                }
            }
            "--no-recursive" => {
                config.recursive = false;
            }
            "--max-files" => {
                if i + 1 < args.len() {
                    if let Ok(max_files) = args[i + 1].parse::<usize>() {
                        config.max_files = Some(max_files);
                        i += 1; // Skip the number argument
                    } else {
                        eprintln!("Warning: Invalid max files '{}', ignoring", args[i + 1]);
                        i += 1;
                    }
                } else {
                    eprintln!("Warning: --max-files requires a number");
                }
            }
            "--fail-fast" => {
                config.fail_fast = true;
            }
            "--quiet" => {
                config.progress_reporting = false;
            }
            _ => {
                eprintln!("Warning: Unknown option '{}'", args[i]);
            }
        }
        i += 1;
    }

    config
}

fn process_single_file(file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Processing file: {}", file_path);

    // Process through complete 7-stage pipeline
    match pipeline::process_file(file_path) {
        Ok(_) => {
            println!("\nSUCCESS: Complete parsing and validation successful");

            // Print cargo-style summary (if any errors were collected during processing)
            logging::print_cargo_style_summary();
        }
        Err(error) => {
            eprintln!("\nFAILED: {}", error);
            print_detailed_error(&error);

            // Print cargo-style error summary
            logging::print_cargo_style_summary();
            std::process::exit(1);
        }
    }

    Ok(())
}

fn process_directory_batch(
    dir_path: &Path,
    config: &batch::BatchConfig,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Starting batch processing: {}", dir_path.display());
    println!(
        "Configuration: {} threads, recursive={}, fail_fast={}",
        config.max_threads, config.recursive, config.fail_fast
    );

    if let Some(max_files) = config.max_files {
        println!("File limit: {} files maximum", max_files);
    }

    match batch::process_directory_with_config(dir_path, config) {
        Ok(results) => {
            println!("\nBatch processing completed!");
            print_batch_results(&results);

            // Print detailed cargo-style error report
            logging::print_cargo_style_summary();

            // Exit with error code if any files failed
            if results.failure_count() > 0 {
                std::process::exit(1);
            }
        }
        Err(error) => {
            eprintln!("Batch processing failed: {}", error);

            // Still print any collected errors
            logging::print_cargo_style_summary();
            std::process::exit(1);
        }
    }

    Ok(())
}

fn print_batch_results(results: &batch::BatchResults) {
    println!("Batch Processing Summary:");
    println!("  Files discovered: {}", results.files_discovered);
    println!("  Files processed: {}", results.files_processed);
    println!(
        "  Successful: {} ({:.1}%)",
        results.success_count(),
        results.success_rate() * 100.0
    );
    println!("  Failed: {}", results.failure_count());
    println!(
        "  Total time: {:.2}s",
        results.processing_duration.as_secs_f64()
    );

    if results.files_processed > 0 {
        let avg_time = results.processing_duration.as_secs_f64() / results.files_processed as f64;
        println!("  Average time per file: {:.2}s", avg_time);
    }

    // Performance metrics
    if !results.successful_files.is_empty() {
        let total_bytes: u64 = results
            .successful_files
            .iter()
            .map(|(_, result)| result.file_metadata.size)
            .sum();

        let total_tokens: usize = results
            .successful_files
            .iter()
            .map(|(_, result)| result.token_count)
            .sum();

        if results.processing_duration.as_secs_f64() > 0.0 {
            let bytes_per_sec = total_bytes as f64 / results.processing_duration.as_secs_f64();
            let tokens_per_sec = total_tokens as f64 / results.processing_duration.as_secs_f64();

            println!(
                "  Processing rate: {:.0} bytes/sec, {:.0} tokens/sec",
                bytes_per_sec, tokens_per_sec
            );
        }
    }

    // Show failed files summary
    if results.failure_count() > 0 {
        println!("\nFailed Files:");
        for (file_path, error) in &results.failed_files {
            println!("  {}: {}", file_path.display(), get_error_summary(error));
        }
    }

    // Show successful files if not too many
    if results.success_count() > 0 && results.success_count() <= 10 {
        println!("\nSuccessful Files:");
        for (file_path, result) in &results.successful_files {
            println!(
                "  {}: {} tokens, {} symbols",
                file_path.display(),
                result.token_count,
                result.symbol_discovery_result.total_symbol_count()
            );
        }
    } else if results.success_count() > 10 {
        println!(
            "\n{} files processed successfully (showing first 5):",
            results.success_count()
        );
        for (file_path, result) in results.successful_files.iter().take(5) {
            println!(
                "  {}: {} tokens, {} symbols",
                file_path.display(),
                result.token_count,
                result.symbol_discovery_result.total_symbol_count()
            );
        }
        println!("  ... and {} more", results.success_count() - 5);
    }
}

fn get_error_summary(error: &pipeline::PipelineError) -> String {
    match error {
        pipeline::PipelineError::FileProcessing(_) => "File processing error".to_string(),
        pipeline::PipelineError::LexicalAnalysis(_) => "Lexical analysis error".to_string(),
        pipeline::PipelineError::SyntaxAnalysis(_) => "Syntax analysis error".to_string(),
        pipeline::PipelineError::SymbolDiscovery(_) => "Symbol discovery error".to_string(),
        pipeline::PipelineError::ReferenceValidation(_) => "Reference validation error".to_string(),
        pipeline::PipelineError::SemanticAnalysis(_) => "Semantic analysis error".to_string(),
        pipeline::PipelineError::StructuralValidation(_) => {
            "Structural validation error".to_string()
        }
        pipeline::PipelineError::Pipeline { .. } => "Pipeline error".to_string(),
    }
}

fn print_detailed_error(error: &pipeline::PipelineError) {
    match error {
        pipeline::PipelineError::FileProcessing(ref file_err) => {
            eprintln!("File processing stage failed:");
            eprintln!("  {}", file_err);
        }
        pipeline::PipelineError::LexicalAnalysis(ref lex_err) => {
            eprintln!("Lexical analysis stage failed:");
            eprintln!("  {}", lex_err);
        }
        pipeline::PipelineError::SyntaxAnalysis(ref syntax_err) => {
            eprintln!("Syntax analysis stage failed:");
            eprintln!("  {}", syntax_err);
        }
        pipeline::PipelineError::SymbolDiscovery(ref symbol_err) => {
            eprintln!("Symbol discovery stage failed:");
            eprintln!("  {}", symbol_err);
        }
        pipeline::PipelineError::ReferenceValidation(ref ref_err) => {
            eprintln!("Reference validation stage failed:");
            eprintln!("  {}", ref_err);
        }
        pipeline::PipelineError::SemanticAnalysis(ref semantic_err) => {
            eprintln!("Semantic analysis stage failed:");
            eprintln!("  {}", semantic_err);
        }
        pipeline::PipelineError::StructuralValidation(ref structural_err) => {
            eprintln!("Structural validation stage failed:");
            eprintln!("  {}", structural_err);
        }
        pipeline::PipelineError::Pipeline { message } => {
            eprintln!("Pipeline error: {}", message);
        }
    }
}
