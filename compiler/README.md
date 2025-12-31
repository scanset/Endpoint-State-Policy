# ESP Compiler

A robust, security-focused compiler for the ESP (Endpoint State Policy) language - a platform-agnostic intermediate language for compliance checking and validation logic.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
- [Module Reference](#module-reference)
- [Configuration](#configuration)
- [API Reference](#api-reference)
- [Examples](#examples)

## Overview

The ESP Compiler is a multi-pass compiler that transforms ESP source files through seven distinct processing stages, providing comprehensive validation and error reporting with SSDF (Secure Software Development Framework) compliance.

### Key Features

- **7-Stage Multi-Pass Architecture**: Complete validation from file reading to structural analysis
- **SSDF Compliant**: Security boundaries enforced at compile-time
- **Global Logging System**: Thread-safe, file-aware logging with structured error codes
- **Batch Processing**: Parallel file processing with cargo-style output
- **Compile-Time Configuration**: Security limits baked into the binary via TOML profiles
- **Runtime Preferences**: User-configurable behavior within security bounds

### Compliance & Standards

| SSDF Practice | Implementation |
|---------------|----------------|
| **PW.7.1** (Input Validation) | Compile-time limits, UTF-8 validation, type checking |
| **PW.8.1** (DoS Protection) | Resource limits, timeout enforcement, bounded allocations |
| **PW.3.1** (Audit Logging) | Mandatory audit logs, retention buffers |
| **RV.1** (Monitoring) | Resource monitoring, alert thresholds, metrics collection |

## Architecture

The ESP Compiler follows a systematic multi-pass architecture:

```
┌─────────────────────────────────────────────────────────────┐
│                    ESP Source File (.esp)                   │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ Pass 1: File Processing                                     │
│  • UTF-8 validation, size limits, encoding verification     │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ Pass 2: Lexical Analysis                                    │
│  • Token stream generation, string literals, comments       │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ Pass 3: Syntax Analysis                                     │
│  • Grammar validation, AST construction                     │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ Pass 4: Symbol Discovery                                    │
│  • Global/local symbol tables, relationship tracking        │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ Pass 5: Reference Resolution                                │
│  • Cross-reference validation, circular dependency detection│
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ Pass 6: Semantic Analysis                                   │
│  • Type checking, runtime ops, SET constraints, cycles      │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ Pass 7: Structural Validation                               │
│  • Requirements check, block ordering, implementation limits│
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│              Validated AST + Symbol Tables                  │
└─────────────────────────────────────────────────────────────┘
```

## Installation

### As a Library Dependency

```toml
[dependencies]
compiler = { path = "../compiler" }
```

### As a Standalone Binary

```bash
git clone https://github.com/anthropics/esp
cd esp
cargo build --release
```

The compiled binary will be at `target/release/compiler`.

## Usage

### Command Line Interface

#### Process a Single File

```bash
compiler example.esp
```

Output includes processing success/failure, detailed metrics, and cargo-style error reporting.

#### Batch Process a Directory

```bash
# Process all .esp files in directory
compiler /path/to/esp-files/

# With custom options
compiler configs/ --threads 4 --fail-fast

# Sequential processing
compiler tests/ --sequential

# Limit file count
compiler large-dir/ --max-files 100

# Non-recursive
compiler directory/ --no-recursive
```

#### Command Line Options

| Option | Description |
|--------|-------------|
| `--help` | Show help message |
| `--sequential` | Force sequential processing |
| `--parallel` | Force parallel processing (default) |
| `--threads N` | Set maximum threads (default: auto) |
| `--no-recursive` | Don't search subdirectories |
| `--max-files N` | Limit files to process |
| `--fail-fast` | Stop on first error |
| `--quiet` | Suppress progress reporting |

### Library API

#### Basic Usage

```rust
use compiler::pipeline;
use common::logging;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging system
    logging::init_global_logging()?;

    // Process a single file
    let result = pipeline::process_file("example.esp")?;

    println!("Tokens: {}", result.token_count);
    println!("Symbols: {}", result.symbol_discovery_result.total_symbol_count());
    println!("Duration: {:.2}ms", result.processing_duration.as_secs_f64() * 1000.0);

    Ok(())
}
```

#### Batch Processing

```rust
use compiler::batch::{self, BatchConfig};
use common::logging;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    logging::init_global_logging()?;

    let config = BatchConfig {
        max_threads: 4,
        recursive: true,
        fail_fast: false,
        progress_reporting: true,
        max_files: None,
    };

    let results = batch::process_directory_with_config(
        Path::new("/path/to/files"),
        &config
    )?;

    println!("Success: {}/{}", results.success_count(), results.files_processed);

    // Print cargo-style error summary
    logging::print_cargo_style_summary();

    Ok(())
}
```

#### Per-Pass Processing

```rust
use compiler::{file_processor, lexical, syntax, symbols};

// Pass 1: File Processing
let file_result = file_processor::process_file("example.esp")?;

// Pass 2: Lexical Analysis
let tokens = lexical::tokenize_file_result(file_result)?;

// Pass 3: Syntax Analysis
let ast = syntax::parse_esp_file(tokens)?;

// Pass 4: Symbol Discovery
let symbols = symbols::discover_symbols_from_ast(ast)?;

// ... continue with remaining passes
```

## Module Reference

### `file_processor`

File I/O with security validation: UTF-8 encoding, size limits, permission checking.

```rust
use compiler::file_processor;

let result = file_processor::process_file("example.esp")?;
println!("Size: {} bytes", result.metadata.size);

// Compile-time limits
let max_size = file_processor::get_max_file_size();
```

---

### `lexical`

Tokenizes ESP source code with security limits on string size, token count, and nesting depth.

```rust
use compiler::lexical;

let tokens = lexical::tokenize_file_result(file_result)?;
let analyzer = lexical::create_analyzer();
```

---

### `tokens`

Token types and stream management with lookahead, filtering, and checkpoint/restore.

```rust
use compiler::tokens::{Token, TokenStream, StringLiteral};

// Token classification
let class = token.classify();

// Stream navigation
let next = stream.peek()?;
stream.advance();
```

---

### `grammar`

Grammar definitions, reserved keywords, and systematic AST builders.

```rust
use compiler::grammar::{is_reserved_keyword, Keyword};

if is_reserved_keyword("DEF") {
    // Handle reserved keyword
}
```

---

### `syntax`

Token stream to AST transformation with span-accurate error reporting.

```rust
use compiler::syntax;

let ast = syntax::parse_esp_file(tokens)?;
syntax::validate_grammar_integration()?;
```

---

### `symbols`

Symbol discovery with configurable analysis modes.

```rust
use compiler::symbols;

// Standard discovery
let result = symbols::discover_symbols_from_ast(ast)?;

// Analysis modes
let detailed = symbols::discover_symbols_detailed(ast)?;   // Full analysis
let strict = symbols::discover_symbols_strict(ast)?;       // With naming validation
let minimal = symbols::discover_symbols_minimal(ast)?;     // Performance-optimized
```

---

### `reference_resolution`

Cross-reference validation and circular dependency detection.

```rust
use compiler::reference_resolution;
use common::config::runtime::ReferenceValidationPreferences;

let prefs = ReferenceValidationPreferences::default();
let result = reference_resolution::validate_references_and_basic_dependencies(
    symbols, &prefs
)?;
```

---

### `semantic_analysis`

Type compatibility, runtime operation validation, SET constraints, and cycle analysis.

```rust
use compiler::semantic_analysis;

let result = semantic_analysis::analyze_semantics(ast, symbols, refs)?;

// Quick validation
let is_valid = semantic_analysis::quick_validate(ast, symbols, refs);
```

---

### `validation`

Final structural validation: requirements, block ordering, implementation limits.

```rust
use compiler::validation;

let result = validation::validate_structure_and_limits(
    ast, symbols, refs, semantics
)?;

println!("Valid: {}", result.is_valid);
println!("Max nesting: {}", result.max_nesting_depth);
```

---

### `pipeline`

Orchestrates the complete 7-stage processing pipeline.

```rust
use compiler::pipeline;

// Full pipeline
let result = pipeline::process_file("example.esp")?;

// With custom preferences
let result = pipeline::process_file_with_preferences("example.esp", &prefs)?;

// Validate system initialization
pipeline::validate_pipeline()?;
```

---

### `batch`

Parallel/sequential batch processing with progress reporting.

```rust
use compiler::batch::{self, BatchConfig};

let config = BatchConfig {
    max_threads: 4,
    recursive: true,
    fail_fast: false,
    progress_reporting: true,
    max_files: Some(100),
};

let results = batch::process_directory_with_config(dir, &config)?;
```

## Configuration

### Build-Time Configuration (Security Boundaries)

Security limits are loaded from TOML files at compile time and baked into the binary.

#### Directory Structure

```
workspace/
├── config/
│   ├── development.toml
│   ├── testing.toml
│   └── production.toml
└── compiler/
    └── Cargo.toml
```

#### Build Environment Variables

```bash
# Select configuration profile
export ESP_BUILD_PROFILE=development  # or testing, production

# Custom config directory
export ESP_CONFIG_DIR=config
```

#### Example: `development.toml`

```toml
[file_processing]
max_file_size = 10485760              # 10MB
large_file_threshold = 1048576        # 1MB
max_line_count_for_analysis = 100000

[lexical]
max_string_size = 1048576             # 1MB
max_identifier_length = 255
max_token_count = 1000000

[syntax]
max_parse_depth = 100
max_error_history = 50

[symbols]
max_global_symbols = 50000
max_local_symbols_per_ctn = 1000
max_symbol_relationships = 100000

[references]
max_reference_depth = 50
max_references_per_symbol = 10000
max_dependency_nodes = 100000

[semantic]
max_semantic_errors = 1000
max_set_operation_operands = 1000

[structural]
max_symbols_per_definition = 10000
max_nesting_depth = 10
max_criteria_blocks = 1000

[batch_processing]
max_worker_threads = 8
max_files_per_batch = 1000

[security]
memory_alert_threshold = 500000000    # 500MB
max_processing_time_seconds = 300     # 5 minutes

[logging]
log_buffer_size = 10000
security_min_log_level = 1            # Warning minimum
```

#### Security Constraints

The build script enforces absolute maximum values:

| Constraint | Maximum |
|------------|---------|
| `max_file_size` | 1GB |
| `max_batch_memory` | 10GB |
| `max_processing_time_seconds` | 3600 (1 hour) |

Production builds have stricter limits (50MB files, 10 minute timeout).

### Runtime Configuration (User Preferences)

Runtime preferences customize behavior within security boundaries via environment variables.

```bash
# File Processor
ESP_REQUIRE_ESP_EXTENSION=true
ESP_ENABLE_PERFORMANCE_LOGGING=true

# Symbol Discovery
ESP_SYMBOLS_DETAILED_RELATIONSHIPS=true
ESP_SYMBOLS_VALIDATE_NAMING=false

# Reference Validation
ESP_REFERENCES_ENABLE_CYCLE_DETECTION=true
ESP_REFERENCES_CONTINUE_AFTER_CYCLES=true

# Logging
ESP_LOGGING_MIN_LEVEL=info
ESP_LOGGING_CARGO_STYLE=true
```

See [common/config](../common/config/README.md) for complete environment variable reference.

## API Reference

### Result Types

#### PipelineResult

```rust
pub struct PipelineResult {
    pub ast: EspFile,
    pub file_metadata: FileMetadata,
    pub lexical_metrics: LexicalMetrics,
    pub symbol_discovery_result: SymbolDiscoveryResult,
    pub reference_validation_result: ReferenceValidationResult,
    pub semantic_analysis_result: SemanticOutput,
    pub structural_validation_result: StructuralValidationResult,
    pub token_count: usize,
    pub processing_duration: Duration,
}
```

#### BatchResults

```rust
pub struct BatchResults {
    pub files_discovered: usize,
    pub files_processed: usize,
    pub successful_files: Vec<(PathBuf, PipelineResult)>,
    pub failed_files: Vec<(PathBuf, PipelineError)>,
    pub processing_duration: Duration,
}

impl BatchResults {
    pub fn success_count(&self) -> usize;
    pub fn failure_count(&self) -> usize;
    pub fn success_rate(&self) -> f64;
}
```

#### SymbolDiscoveryResult

```rust
pub struct SymbolDiscoveryResult {
    pub global_symbols: GlobalSymbolTable,
    pub local_symbol_tables: HashMap<CtnNodeId, LocalSymbolTable>,
}

impl SymbolDiscoveryResult {
    pub fn total_symbol_count(&self) -> usize;
    pub fn relationship_count(&self) -> usize;
}
```

### Error Types

All pipeline errors implement `std::error::Error` and provide:
- Error code via `error_code()` method
- Span information where available
- Recommended actions via logging metadata

```rust
match pipeline::process_file("example.esp") {
    Ok(result) => { /* success */ }
    Err(PipelineError::LexicalAnalysis(e)) => {
        eprintln!("Lexical error: {}", e);
    }
    Err(PipelineError::SyntaxAnalysis(e)) => {
        eprintln!("Syntax error: {}", e);
    }
    Err(e) => {
        eprintln!("Error: {}", e);
    }
}
```

## Examples

### Example 1: Complete File Validation

```rust
use compiler::pipeline;
use common::logging;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    logging::init_global_logging()?;

    match pipeline::process_file("policy.esp") {
        Ok(result) => {
            println!("✓ Validation successful");
            println!("  Tokens: {}", result.token_count);
            println!("  Symbols: {}", result.symbol_discovery_result.total_symbol_count());
            println!("  Duration: {:.2}ms",
                result.processing_duration.as_secs_f64() * 1000.0);
        }
        Err(error) => {
            eprintln!("✗ Validation failed: {}", error);
            logging::print_cargo_style_summary();
            std::process::exit(1);
        }
    }

    Ok(())
}
```

### Example 2: Batch Processing with Metrics

```rust
use compiler::batch::{self, BatchConfig};
use common::logging;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    logging::init_global_logging()?;

    let config = BatchConfig {
        max_threads: 4,
        recursive: true,
        fail_fast: false,
        progress_reporting: true,
        max_files: None,
    };

    let results = batch::process_directory_with_config(
        Path::new("./policies"),
        &config
    )?;

    // Summary
    println!("Files: {}/{} successful ({:.1}%)",
        results.success_count(),
        results.files_processed,
        results.success_rate() * 100.0
    );

    // Performance
    if !results.successful_files.is_empty() {
        let total_tokens: usize = results.successful_files
            .iter()
            .map(|(_, r)| r.token_count)
            .sum();

        let tokens_per_sec = total_tokens as f64
            / results.processing_duration.as_secs_f64();

        println!("Throughput: {:.0} tokens/sec", tokens_per_sec);
    }

    // Errors
    if results.failure_count() > 0 {
        println!("\nFailed files:");
        for (path, error) in &results.failed_files {
            println!("  {}: {}", path.display(), error);
        }
    }

    logging::print_cargo_style_summary();

    Ok(())
}
```

### Example 3: Custom Analysis Pipeline

```rust
use compiler::{
    file_processor, lexical, syntax, symbols,
    reference_resolution, semantic_analysis, validation
};
use common::config::runtime::{SymbolPreferences, ReferenceValidationPreferences};
use common::logging;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    logging::init_global_logging()?;

    // Pass 1-3: Standard processing
    let file_result = file_processor::process_file("example.esp")?;
    let tokens = lexical::tokenize_file_result(file_result)?;
    let ast = syntax::parse_esp_file(tokens)?;

    // Pass 4: Detailed symbol discovery
    let symbol_prefs = SymbolPreferences {
        detailed_relationships: true,
        track_cross_references: true,
        validate_naming_conventions: true,
        ..Default::default()
    };
    let symbols = symbols::discover_symbols_from_ast_with_preferences(
        ast.clone(), symbol_prefs
    )?;

    println!("Symbols: {}", symbols.total_symbol_count());
    println!("Relationships: {}", symbols.relationship_count());

    // Pass 5: Reference validation with cycle detection
    let ref_prefs = ReferenceValidationPreferences {
        enable_cycle_detection: true,
        include_cycle_descriptions: true,
        ..Default::default()
    };
    let refs = reference_resolution::validate_references_and_basic_dependencies(
        symbols.clone(), &ref_prefs
    )?;

    if !refs.cycles.is_empty() {
        println!("Warning: {} circular dependencies", refs.cycles.len());
    }

    // Pass 6-7: Semantic and structural validation
    let semantics = semantic_analysis::analyze_semantics(
        ast.clone(), symbols.clone(), refs.clone()
    )?;

    let structural = validation::validate_structure_and_limits(
        ast, symbols, refs, semantics
    )?;

    if structural.is_valid {
        println!("✓ All validations passed");
    } else {
        println!("✗ {} structural errors", structural.error_count());
    }

    Ok(())
}
```

## Related Documentation

- [common crate](../common/README.md) - Shared types (AST, logging, config, results)
- [EBNF Grammar](../docs/EBNF.md) - Complete ESP language specification
- [agent_core](../agent_core/README.md) - Execution engine for compiled policies

## License

See repository root for license information.
