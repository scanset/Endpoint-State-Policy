// build.rs - Complete TOML-driven constant generation + Windows import library
use std::env;
use std::fs;
use std::path::Path;

#[derive(serde::Deserialize)]
struct CompileTimeConfig {
    file_processing: FileProcessingLimits,
    lexical: LexicalLimits,
    syntax: SyntaxLimits,
    symbols: SymbolLimits,
    references: ReferenceLimits,
    semantic: SemanticLimits,
    structural: StructuralLimits,
    batch_processing: BatchProcessingLimits,
    security: SecurityLimits,
    logging: LoggingLimits,
}

#[derive(serde::Deserialize)]
struct FileProcessingLimits {
    max_file_size: u64,
    large_file_threshold: u64,
    max_line_count_for_analysis: usize,
    performance_log_buffer_size: usize,
}

#[derive(serde::Deserialize)]
struct LexicalLimits {
    max_string_size: usize,
    max_identifier_length: usize,
    max_comment_length: usize,
    max_token_count: usize,
    metrics_buffer_size: usize,
    max_string_nesting_depth: u32,
}

#[derive(serde::Deserialize)]
struct SyntaxLimits {
    max_parse_depth: usize,
    max_error_history: usize,
    max_context_stack_depth: usize,
    max_recovery_scan_tokens: usize,
    max_lookahead_tokens: usize,
}

#[derive(serde::Deserialize)]
struct SymbolLimits {
    max_global_symbols: usize,
    max_local_symbols_per_ctn: usize,
    max_symbol_relationships: usize,
    max_symbol_identifier_length: usize,
    max_symbol_context_depth: usize,
    max_elements_per_symbol: usize,
    max_ctn_scopes: usize,
}

#[derive(serde::Deserialize)]
struct ReferenceLimits {
    max_reference_depth: usize,
    max_references_per_symbol: usize,
    max_reported_cycles: usize,
    max_cycle_length: usize,
    max_dependency_nodes: usize,
    max_relationships_per_pass: usize,
}

#[derive(serde::Deserialize)]
struct SemanticLimits {
    max_semantic_errors: usize,
    max_runtime_operation_parameters: usize,
    max_set_operation_operands: usize,
    max_error_message_length: usize,
    max_cycle_path_length: usize,
    max_filter_state_references: usize,
}

#[derive(serde::Deserialize)]
struct StructuralLimits {
    max_symbols_per_definition: usize,
    max_nesting_depth: usize,
    max_criteria_blocks: usize,
    max_set_operands: usize,
    max_variables_per_definition: usize,
    max_states_per_definition: usize,
    max_objects_per_definition: usize,
}

#[derive(serde::Deserialize)]
struct BatchProcessingLimits {
    max_worker_threads: usize,
    max_files_per_batch: usize,
    max_batch_memory: u64,
}

#[derive(serde::Deserialize)]
struct SecurityLimits {
    memory_alert_threshold: u64,
    max_processing_time_seconds: u64,
    audit_log_buffer_size: usize,
    max_concurrent_operations: usize,
}

#[derive(serde::Deserialize)]
struct LoggingLimits {
    max_error_collection: usize,
    log_buffer_size: usize,
    max_log_message_length: usize,
    max_log_events_per_file: usize,
    max_concurrent_log_operations: usize,
    security_min_log_level: u8,
    audit_log_retention_buffer: usize,
}

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=ESP_BUILD_PROFILE");
    println!("cargo:rerun-if-env-changed=ESP_CONFIG_DIR");

    // Windows DLL import library generation
    configure_windows_dll_build();

    let profile = env::var("ESP_BUILD_PROFILE").unwrap_or_else(|_| "development".to_string());
    let config_dir = env::var("ESP_CONFIG_DIR").unwrap_or_else(|_| "config".to_string());

    // Find workspace root (parent of esp_compiler directory)
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").unwrap();
    let workspace_root = Path::new(&manifest_dir)
        .parent()
        .expect("Could not find workspace root (parent directory)");

    // Build config path relative to workspace root
    let config_path = workspace_root
        .join(&config_dir)
        .join(format!("{}.toml", profile));

    println!("cargo:rerun-if-changed={}", config_path.display());

    if !config_path.exists() {
        panic!(
            "Configuration file not found: {}\nWorkspace root: {}\nLooking for: {}/{}/{}.toml",
            config_path.display(),
            workspace_root.display(),
            workspace_root.display(),
            config_dir,
            profile
        );
    }

    let config_content = fs::read_to_string(&config_path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", config_path.display(), e));

    let config: CompileTimeConfig = toml::from_str(&config_content)
        .unwrap_or_else(|e| panic!("Invalid TOML in {}: {}", config_path.display(), e));

    validate_security_constraints(&config, &profile);
    generate_constants(&config, &profile);

    println!(
        "cargo:warning=Generated constants from {}",
        config_path.display()
    );
}

fn configure_windows_dll_build() {
    let target = env::var("TARGET").unwrap_or_default();

    // For Windows MinGW targets, ensure import library is generated
    // This is for building esp_compiler as a cdylib (shared library) for FFI
    if target.contains("windows-gnu") {
        println!("cargo:rustc-cdylib-link-arg=-Wl,--out-implib,libesp_compiler.dll.a");
        println!(
            "cargo:warning=Configuring Windows DLL to generate import library (libesp_compiler.dll.a)"
        );
    }
}

fn validate_security_constraints(config: &CompileTimeConfig, profile: &str) {
    const ABSOLUTE_MAX_FILE_SIZE: u64 = 1_000_000_000;
    const ABSOLUTE_MAX_MEMORY: u64 = 10_000_000_000;
    const ABSOLUTE_MAX_PROCESSING_TIME: u64 = 3600;

    if config.file_processing.max_file_size > ABSOLUTE_MAX_FILE_SIZE {
        panic!("SECURITY: max_file_size exceeds absolute maximum");
    }

    if config.batch_processing.max_batch_memory > ABSOLUTE_MAX_MEMORY {
        panic!("SECURITY: max_batch_memory exceeds absolute maximum");
    }

    if config.security.max_processing_time_seconds > ABSOLUTE_MAX_PROCESSING_TIME {
        panic!("SECURITY: max_processing_time_seconds exceeds absolute maximum");
    }

    if config.logging.security_min_log_level > 2 {
        panic!("SECURITY: security_min_log_level too high (max: 2)");
    }

    if profile == "production" {
        if config.file_processing.max_file_size > 50_000_000 {
            panic!("PRODUCTION: max_file_size too high for production");
        }
        if config.security.max_processing_time_seconds > 600 {
            panic!("PRODUCTION: max_processing_time_seconds too high for production");
        }
    }
}

fn generate_constants(config: &CompileTimeConfig, profile: &str) {
    let out_dir = env::var("OUT_DIR").unwrap();
    let output_path = Path::new(&out_dir).join("constants.rs");

    let constants_code = format!(
        r#"
// Generated compile-time constants from TOML configuration
// Profile: {}
// DO NOT EDIT - Generated by build.rs

pub mod compile_time {{
    pub mod file_processing {{
        pub const MAX_FILE_SIZE: u64 = {};
        pub const LARGE_FILE_THRESHOLD: u64 = {};
        pub const MAX_LINE_COUNT_FOR_ANALYSIS: usize = {};
        pub const PERFORMANCE_LOG_BUFFER_SIZE: usize = {};
    }}

    pub mod lexical {{
        pub const MAX_STRING_SIZE: usize = {};
        pub const MAX_IDENTIFIER_LENGTH: usize = {};
        pub const MAX_COMMENT_LENGTH: usize = {};
        pub const MAX_TOKEN_COUNT: usize = {};
        pub const METRICS_BUFFER_SIZE: usize = {};
        pub const MAX_STRING_NESTING_DEPTH: u32 = {};
    }}

    pub mod syntax {{
        pub const MAX_PARSE_DEPTH: usize = {};
        pub const MAX_ERROR_HISTORY: usize = {};
        pub const MAX_CONTEXT_STACK_DEPTH: usize = {};
        pub const MAX_RECOVERY_SCAN_TOKENS: usize = {};
        pub const MAX_LOOKAHEAD_TOKENS: usize = {};
    }}

    pub mod symbols {{
        pub const MAX_GLOBAL_SYMBOLS: usize = {};
        pub const MAX_LOCAL_SYMBOLS_PER_CTN: usize = {};
        pub const MAX_SYMBOL_RELATIONSHIPS: usize = {};
        pub const MAX_SYMBOL_IDENTIFIER_LENGTH: usize = {};
        pub const MAX_SYMBOL_CONTEXT_DEPTH: usize = {};
        pub const MAX_ELEMENTS_PER_SYMBOL: usize = {};
        pub const MAX_CTN_SCOPES: usize = {};
    }}

    pub mod references {{
        pub const MAX_REFERENCE_DEPTH: usize = {};
        pub const MAX_REFERENCES_PER_SYMBOL: usize = {};
        pub const MAX_REPORTED_CYCLES: usize = {};
        pub const MAX_CYCLE_LENGTH: usize = {};
        pub const MAX_DEPENDENCY_NODES: usize = {};
        pub const MAX_RELATIONSHIPS_PER_PASS: usize = {};
    }}

    pub mod semantic {{
        pub const MAX_SEMANTIC_ERRORS: usize = {};
        pub const MAX_RUNTIME_OPERATION_PARAMETERS: usize = {};
        pub const MAX_SET_OPERATION_OPERANDS: usize = {};
        pub const MAX_ERROR_MESSAGE_LENGTH: usize = {};
        pub const MAX_CYCLE_PATH_LENGTH: usize = {};
        pub const MAX_FILTER_STATE_REFERENCES: usize = {};
    }}

    pub mod structural {{
        pub const MAX_SYMBOLS_PER_DEFINITION: usize = {};
        pub const MAX_NESTING_DEPTH: usize = {};
        pub const MAX_CRITERIA_BLOCKS: usize = {};
        pub const MAX_SET_OPERANDS: usize = {};
        pub const MAX_VARIABLES_PER_DEFINITION: usize = {};
        pub const MAX_STATES_PER_DEFINITION: usize = {};
        pub const MAX_OBJECTS_PER_DEFINITION: usize = {};
    }}

    pub mod batch_processing {{
        pub const MAX_WORKER_THREADS: usize = {};
        pub const MAX_FILES_PER_BATCH: usize = {};
        pub const MAX_BATCH_MEMORY: u64 = {};
    }}

    pub mod security {{
        pub const MEMORY_ALERT_THRESHOLD: u64 = {};
        pub const MAX_PROCESSING_TIME_SECONDS: u64 = {};
        pub const AUDIT_LOG_BUFFER_SIZE: usize = {};
        pub const MAX_CONCURRENT_OPERATIONS: usize = {};
    }}

    pub mod logging {{
        pub const MAX_ERROR_COLLECTION: usize = {};
        pub const LOG_BUFFER_SIZE: usize = {};
        pub const MAX_LOG_MESSAGE_LENGTH: usize = {};
        pub const MAX_LOG_EVENTS_PER_FILE: usize = {};
        pub const MAX_CONCURRENT_LOG_OPERATIONS: usize = {};
        pub const SECURITY_MIN_LOG_LEVEL: u8 = {};
        pub const AUDIT_LOG_RETENTION_BUFFER: usize = {};
    }}
}}
"#,
        profile,
        // File Processing
        config.file_processing.max_file_size,
        config.file_processing.large_file_threshold,
        config.file_processing.max_line_count_for_analysis,
        config.file_processing.performance_log_buffer_size,
        // Lexical
        config.lexical.max_string_size,
        config.lexical.max_identifier_length,
        config.lexical.max_comment_length,
        config.lexical.max_token_count,
        config.lexical.metrics_buffer_size,
        config.lexical.max_string_nesting_depth,
        // Syntax
        config.syntax.max_parse_depth,
        config.syntax.max_error_history,
        config.syntax.max_context_stack_depth,
        config.syntax.max_recovery_scan_tokens,
        config.syntax.max_lookahead_tokens,
        // Symbols
        config.symbols.max_global_symbols,
        config.symbols.max_local_symbols_per_ctn,
        config.symbols.max_symbol_relationships,
        config.symbols.max_symbol_identifier_length,
        config.symbols.max_symbol_context_depth,
        config.symbols.max_elements_per_symbol,
        config.symbols.max_ctn_scopes,
        // References
        config.references.max_reference_depth,
        config.references.max_references_per_symbol,
        config.references.max_reported_cycles,
        config.references.max_cycle_length,
        config.references.max_dependency_nodes,
        config.references.max_relationships_per_pass,
        // Semantic
        config.semantic.max_semantic_errors,
        config.semantic.max_runtime_operation_parameters,
        config.semantic.max_set_operation_operands,
        config.semantic.max_error_message_length,
        config.semantic.max_cycle_path_length,
        config.semantic.max_filter_state_references,
        // Structural
        config.structural.max_symbols_per_definition,
        config.structural.max_nesting_depth,
        config.structural.max_criteria_blocks,
        config.structural.max_set_operands,
        config.structural.max_variables_per_definition,
        config.structural.max_states_per_definition,
        config.structural.max_objects_per_definition,
        // Batch Processing
        config.batch_processing.max_worker_threads,
        config.batch_processing.max_files_per_batch,
        config.batch_processing.max_batch_memory,
        // Security
        config.security.memory_alert_threshold,
        config.security.max_processing_time_seconds,
        config.security.audit_log_buffer_size,
        config.security.max_concurrent_operations,
        // Logging
        config.logging.max_error_collection,
        config.logging.log_buffer_size,
        config.logging.max_log_message_length,
        config.logging.max_log_events_per_file,
        config.logging.max_concurrent_log_operations,
        config.logging.security_min_log_level,
        config.logging.audit_log_retention_buffer,
    );

    fs::write(output_path, constants_code).unwrap();
}
