# ESP Compiler

A robust, security-focused compiler for the ESP (Endpoint State Policy) language - a platform-agnostic intermediate language for compliance checking and validation logic.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Module Reference](#module-reference)
- [Installation](#installation)
- [Usage](#usage)
- [Configuration](#configuration)
- [Logging System](#logging-system)
- [Security Features](#security-features)
- [API Documentation](#api-documentation)
- [Examples](#examples)
- [Contributing](#contributing)

## Overview

The ESP Compiler is a multi-pass compiler that transforms ESP source files through seven distinct processing stages, providing comprehensive validation and error reporting with SSDF (Secure Software Development Framework) compliance.

### Key Features

- **7-Stage Multi-Pass Architecture**: Complete validation from file reading to structural analysis
- **SSDF Compliant**: Security boundaries enforced at compile-time
- **Global Logging System**: Thread-safe, file-aware logging with structured error codes
- **Batch Processing**: Parallel file processing with cargo-style output
- **Compile-Time Configuration**: Security limits baked into the binary
- **Runtime Preferences**: User-configurable behavior within security bounds
- **FFI Support**: Windows DLL generation for cross-language integration

### Compliance & Standards

- **SSDF PW.7.1**: Input Validation with compile-time limits
- **SSDF PW.8.1**: DoS Protection through resource boundaries
- **SSDF PW.3.1**: Audit Logging with mandatory retention
- **SSDF RV.1**: Resource monitoring and alerting

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
│  • UTF-8 validation                                         │
│  • Size limits enforcement                                  │
│  • Encoding verification                                    │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ Pass 2: Lexical Analysis (Tokenization)                    │
│  • String literal extraction                                │
│  • Token stream generation                                  │
│  • Comment handling                                         │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ Pass 3: Syntax Analysis (AST Construction)                 │
│  • Grammar validation                                       │
│  • AST building                                             │
│  • Block structure verification                             │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ Pass 4: Symbol Discovery                                   │
│  • Global symbol table                                      │
│  • Local scope management                                   │
│  • Symbol relationship tracking                             │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ Pass 5: Reference Resolution                                │
│  • Cross-reference validation                               │
│  • Circular dependency detection                            │
│  • Scope verification                                       │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ Pass 6: Semantic Analysis                                   │
│  • Type compatibility checking                              │
│  • Runtime operation validation                             │
│  • SET constraint enforcement                               │
│  • Dependency cycle analysis                                │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│ Pass 7: Structural Validation                               │
│  • Minimum requirements check                               │
│  • Block ordering validation                                │
│  • Implementation limits verification                       │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│              Validated AST + Symbol Tables                  │
└─────────────────────────────────────────────────────────────┘
```

## Module Reference

### Core Modules

#### `file_processor`
Handles file I/O with security validation.

**Key Functions:**
- `process_file(path)` - Process a single file
- `create_processor()` - Create processor with defaults
- `get_max_file_size()` - Get compile-time file size limit

**Security Features:**
- UTF-8 encoding validation
- File size limits (compile-time enforced)
- Permission checking
- Extension validation

---

#### `lexical`
Tokenizes ESP source code into a structured token stream.

**Key Functions:**
- `tokenize_file_result(file)` - Tokenize file content
- `create_analyzer()` - Create lexical analyzer

**Features:**
- String literal handling (backtick, raw, multiline)
- Comment extraction
- Token classification
- Metrics collection

**Security Limits:**
- Max string size: 1MB
- Max identifier length: 255 characters
- Max token count: 1,000,000
- Max comment length: 10,000 characters

---

#### `syntax`
Transforms token streams into Abstract Syntax Trees (AST).

**Key Functions:**
- `parse_esp_file(tokens)` - Parse token stream into AST
- `validate_grammar_integration()` - Validate builder coverage

**Features:**
- Grammar builders for all ESP constructs
- Span-accurate error reporting
- Recursive descent parsing
- Error recovery

**Security Limits:**
- Max parse depth: 100 levels
- Max error history: 50 entries
- Max lookahead: 10 tokens

---

#### `symbols`
Discovers and tracks symbol definitions and relationships.

**Key Functions:**
- `discover_symbols_from_ast(ast)` - Standard symbol discovery
- `discover_symbols_detailed(ast)` - Detailed analysis mode
- `discover_symbols_strict(ast)` - Strict validation mode
- `discover_symbols_minimal(ast)` - Performance-optimized mode

**Features:**
- Global symbol table management
- Local scope handling (CTN-level)
- Symbol relationship tracking
- Configurable analysis preferences

**Security Limits:**
- Max global symbols: 50,000
- Max local symbols per CTN: 1,000
- Max symbol relationships: 100,000

---

#### `reference_resolution`
Validates cross-references and detects circular dependencies.

**Key Functions:**
- `validate_references_and_basic_dependencies(symbols, prefs)` - Full validation

**Features:**
- STATE_REF validation
- OBJECT_REF validation
- SET_REF validation
- VAR reference resolution
- Circular dependency detection

**Security Limits:**
- Max reference depth: 50 levels
- Max references per symbol: 10,000
- Max dependency nodes: 100,000

---

#### `semantic_analysis`
Enforces type compatibility and semantic rules.

**Key Functions:**
- `analyze_semantics(ast, symbols, refs)` - Complete semantic analysis
- `quick_validate(ast, symbols, refs)` - Fast validation check

**Validation Steps:**
1. Type compatibility matrix enforcement
2. Runtime operation validation
3. SET constraint checking
4. Dependency cycle analysis

**Security Limits:**
- Max semantic errors: 1,000
- Max SET operands: 1,000
- Max filter references: 1,000
- Max cycle path length: 100

---

#### `validation` (Structural)
Final architectural compliance and limits verification.

**Key Functions:**
- `validate_structure_and_limits(ast, symbols, refs, semantics)` - Full validation

**Validation Steps:**
1. Minimum requirements (DEF must have CRI, CRI must have CTN)
2. Block ordering (CTN element sequence)
3. Implementation limits

**Security Limits:**
- Max symbols per definition: 10,000
- Max nesting depth: 10 levels
- Max criteria blocks: 1,000

---

#### `pipeline`
Orchestrates the complete 7-stage processing pipeline.

**Key Functions:**
- `process_file(path)` - Process single file through all stages
- `process_file_with_preferences(path, prefs)` - Custom preferences
- `validate_pipeline()` - Validate system initialization

**Output:**
- `PipelineResult` - Complete processing results with metrics
- `PipelineOutput` - AST + symbols for serialization

---

#### `batch`
Parallel file processing with cargo-style reporting.

**Key Functions:**
- `process_directory_with_config(dir, config)` - Batch processing

**Features:**
- Parallel or sequential processing
- File discovery with recursion
- Progress reporting
- Error aggregation
- Performance metrics

**Configuration:**
- Max worker threads (compile-time)
- Max files per batch (compile-time)
- Fail-fast mode
- Recursive directory scanning

---

#### `logging`
Global, thread-safe logging system with structured error codes.

**Key Components:**
- `codes` - Error code registry with metadata
- `events` - Log event structure (Error, Warning, Info, Debug)
- `service` - Logging backends (Console, Memory, Structured)
- `collector` - File-aware error collection
- `macros` - Type-safe logging macros

**Initialization:**
```rust
use esp_compiler::logging;

logging::init_global_logging()?;
```

---

#### `grammar`
AST node definitions and grammar builders.

**Components:**
- `ast::nodes` - Complete AST node types
- `keywords` - Reserved keyword definitions
- `builders` - Systematic grammar builders

**Builder Modules:**
- `atomic` - Foundation builders (no dependencies)
- `helpers` - Parsing utilities
- `expressions` - Expression builders
- `blocks` - Block-level builders

---

#### `tokens`
Token type system and stream management.

**Key Types:**
- `Token` - Complete token enumeration
- `TokenStream` - Efficient token navigation
- `StringLiteral` - ESP string literal variants

**Features:**
- Lookahead support
- Token filtering (significant/insignificant)
- Span tracking
- Checkpoint/restore

---

#### `utils`
Shared utilities for span tracking and source mapping.

**Key Types:**
- `Span` - Source location tracking
- `Position` - Line/column/offset
- `SourceMap` - Line start indexing
- `Spanned<T>` - Value with location

---

#### `config`
Compile-time constants and runtime preferences.

**Modules:**
- `constants::compile_time` - Generated from TOML (immutable)
- `runtime` - User preferences (validated at runtime)

---

## Installation

### As a Library Dependency

Add to your `Cargo.toml`:

```toml
[dependencies]
esp_compiler = { path = "../esp_compiler" }
```

Or from a git repository:

```toml
[dependencies]
esp_compiler = { git = "https://github.com/your-org/esp_compiler", branch = "main" }
```

### As a Standalone Binary

Clone and build:

```bash
git clone https://github.com/your-org/esp_compiler.git
cd esp_compiler
cargo build --release
```

The compiled binary will be at `target/release/esp_compiler`.

## Usage

### Command Line Interface

#### Process a Single File

```bash
esp_compiler example.esp
```

Output includes:
- Processing success/failure
- Detailed metrics (tokens, symbols, duration)
- Cargo-style error reporting

#### Batch Process a Directory

```bash
# Process all .esp files in directory
esp_compiler /path/to/esp-files/

# With custom options
esp_compiler configs/ --threads 4 --fail-fast

# Sequential processing
esp_compiler tests/ --sequential

# Limit file count
esp_compiler large-dir/ --max-files 100

# Non-recursive
esp_compiler directory/ --no-recursive
```

#### Command Line Options

| Option | Description |
|--------|-------------|
| `--help` | Show help message |
| `--sequential` | Force sequential processing (no parallelism) |
| `--parallel` | Force parallel processing (default) |
| `--threads N` | Set maximum threads (default: auto) |
| `--no-recursive` | Don't search subdirectories |
| `--max-files N` | Limit files to process |
| `--fail-fast` | Stop on first error |
| `--quiet` | Suppress progress reporting |

### Library API

#### Basic Usage

```rust
use esp_compiler::pipeline;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging system
    esp_compiler::logging::init_global_logging()?;

    // Process a single file
    let result = pipeline::process_file("example.esp")?;

    println!("Tokens: {}", result.token_count);
    println!("Symbols: {}", result.symbol_discovery_result.total_symbol_count());
    println!("Duration: {:.2}ms", result.processing_duration.as_secs_f64() * 1000.0);

    Ok(())
}
```

#### Custom Preferences

```rust
use esp_compiler::pipeline;
use esp_compiler::config::runtime::ReferenceValidationPreferences;

let mut prefs = ReferenceValidationPreferences::default();
prefs.enable_cycle_detection = true;
prefs.log_validation_details = true;

let result = pipeline::process_file_with_preferences("example.esp", &prefs)?;
```

#### Batch Processing

```rust
use esp_compiler::batch::{self, BatchConfig};
use std::path::Path;

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
```

#### Per-Pass Processing

```rust
use esp_compiler::{file_processor, lexical, syntax, symbols};

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

## Configuration

### Compile-Time Configuration (Security Boundaries)

Configuration is loaded from TOML files at compile time and baked into the binary. This ensures security limits cannot be bypassed at runtime.

#### Configuration Files

Place TOML files in your workspace `config/` directory:

```
workspace/
├── config/
│   ├── development.toml
│   ├── testing.toml
│   └── production.toml
└── esp_compiler/
    └── Cargo.toml
```

#### Environment Variables

Set during build to select configuration:

```bash
# Select configuration profile
export ESP_BUILD_PROFILE=development  # or testing, production

# Custom config directory
export ESP_CONFIG_DIR=config
```

#### Example Configuration: `development.toml`

```toml
[file_processing]
max_file_size = 10485760              # 10MB
large_file_threshold = 1048576        # 1MB
max_line_count_for_analysis = 100000
performance_log_buffer_size = 1000

[lexical]
max_string_size = 1048576             # 1MB
max_identifier_length = 255
max_comment_length = 10000
max_token_count = 1000000
metrics_buffer_size = 1000
max_string_nesting_depth = 100

[syntax]
max_parse_depth = 100
max_error_history = 50
max_context_stack_depth = 20
max_recovery_scan_tokens = 1000
max_lookahead_tokens = 10

[symbols]
max_global_symbols = 50000
max_local_symbols_per_ctn = 1000
max_symbol_relationships = 100000
max_symbol_identifier_length = 255
max_symbol_context_depth = 50
max_elements_per_symbol = 10000
max_ctn_scopes = 1000

[references]
max_reference_depth = 50
max_references_per_symbol = 10000
max_reported_cycles = 10
max_cycle_length = 100
max_dependency_nodes = 100000
max_relationships_per_pass = 1000000

[semantic]
max_semantic_errors = 1000
max_runtime_operation_parameters = 100
max_set_operation_operands = 1000
max_error_message_length = 10000
max_cycle_path_length = 100
max_filter_state_references = 1000

[structural]
max_symbols_per_definition = 10000
max_nesting_depth = 10
max_criteria_blocks = 1000
max_set_operands = 100
max_variables_per_definition = 1000
max_states_per_definition = 500
max_objects_per_definition = 200

[batch_processing]
max_worker_threads = 8
max_files_per_batch = 1000
max_batch_memory = 1000000000         # 1GB

[security]
memory_alert_threshold = 500000000    # 500MB
max_processing_time_seconds = 300     # 5 minutes
audit_log_buffer_size = 10000
max_concurrent_operations = 100

[logging]
max_error_collection = 1000
log_buffer_size = 10000
max_log_message_length = 10000
max_log_events_per_file = 1000
max_concurrent_log_operations = 100
security_min_log_level = 1            # Warning level minimum
audit_log_retention_buffer = 50000
```

#### Security Constraints

The build script enforces absolute maximum values:

| Constraint | Maximum Value |
|------------|---------------|
| `max_file_size` | 1GB |
| `max_batch_memory` | 10GB |
| `max_processing_time_seconds` | 3600 (1 hour) |
| `security_min_log_level` | 2 (Info) |

Production builds have additional limits:
- `max_file_size`: 50MB
- `max_processing_time_seconds`: 600 (10 minutes)

### Runtime Configuration (User Preferences)

Runtime preferences allow users to customize behavior within security boundaries.

#### Environment Variables (`.env`)

Create a `.env` file (see `.env.example`):

```bash
# Compile-Time (build)
ESP_BUILD_PROFILE=development
ESP_CONFIG_DIR=config

# Runtime: File Processor
ESP_REQUIRE_ESP_EXTENSION=true
ESP_ENABLE_PERFORMANCE_LOGGING=true
ESP_LOG_NON_ESP_PROCESSING=false
ESP_INCLUDE_COMPLEXITY_METRICS=true

# Runtime: Lexical Analysis
ESP_LEXICAL_DETAILED_METRICS=true
ESP_LEXICAL_INCLUDE_ALL_TOKENS=false
ESP_LEXICAL_LOG_STRING_STATS=false
ESP_LEXICAL_TRACK_OPERATORS=false
ESP_LEXICAL_INCLUDE_POSITIONS=true

# Runtime: Symbol Discovery
ESP_SYMBOLS_DETAILED_RELATIONSHIPS=true
ESP_SYMBOLS_TRACK_CROSS_REFS=false
ESP_SYMBOLS_VALIDATE_NAMING=false
ESP_SYMBOLS_INCLUDE_USAGE_METRICS=true
ESP_SYMBOLS_LOG_RELATIONSHIP_WARNINGS=true
ESP_SYMBOLS_ANALYZE_DEPENDENCY_CHAINS=false

# Runtime: Reference Validation
ESP_REFERENCES_ENABLE_CYCLE_DETECTION=true
ESP_REFERENCES_LOG_VALIDATION_DETAILS=false
ESP_REFERENCES_INCLUDE_CYCLE_DESCRIPTIONS=true
ESP_REFERENCES_CONTINUE_AFTER_CYCLES=true
ESP_REFERENCES_VALIDATE_TYPES=true

# Runtime: Semantic Analysis
ESP_SEMANTIC_COMPREHENSIVE_TYPE_CHECKING=true
ESP_SEMANTIC_VALIDATE_RUNTIME_CONSTRAINTS=true
ESP_SEMANTIC_CHECK_SET_SEMANTICS=true
ESP_SEMANTIC_ANALYZE_CYCLES=true
ESP_SEMANTIC_DETAILED_ERROR_CONTEXT=true

# Runtime: Structural Validation
ESP_STRUCTURAL_ADVANCED_CONSISTENCY_CHECKS=true
ESP_STRUCTURAL_LOG_DETAILED_METRICS=false
ESP_STRUCTURAL_INCLUDE_COMPLEXITY_BREAKDOWN=true
ESP_STRUCTURAL_VALIDATE_RECOMMENDATIONS=false
ESP_STRUCTURAL_ANALYZE_QUALITY_PATTERNS=false

# Runtime: Logging Preferences
ESP_LOGGING_USE_STRUCTURED=false
ESP_LOGGING_ENABLE_CONSOLE=true
ESP_LOGGING_MIN_LEVEL=info
ESP_LOGGING_LOG_PERFORMANCE=true
ESP_LOGGING_LOG_SECURITY=true
ESP_LOGGING_CARGO_STYLE=true
ESP_LOGGING_INCLUDE_FILE_CONTEXT=true
```

#### Programmatic Configuration

```rust
use esp_compiler::config::runtime::*;

// File Processor Preferences
let file_prefs = FileProcessorPreferences {
    require_esp_extension: false,
    enable_performance_logging: true,
    log_non_esp_processing: true,
    include_complexity_metrics: false,
};

// Symbol Discovery Preferences
let symbol_prefs = SymbolPreferences {
    detailed_relationships: true,
    track_cross_references: true,
    validate_naming_conventions: true,
    include_usage_metrics: true,
    log_relationship_warnings: true,
    analyze_dependency_chains: true,
};

// Reference Validation Preferences
let ref_prefs = ReferenceValidationPreferences {
    enable_cycle_detection: true,
    log_validation_details: false,
    include_cycle_descriptions: true,
    continue_after_cycles: true,
    validate_types: true,
};

// Logging Preferences
let log_prefs = LoggingPreferences {
    use_structured_logging: false,
    enable_console_logging: true,
    min_log_level: LogLevel::Info,
    log_performance_events: true,
    log_security_metrics: true,
    enable_cargo_style_output: true,
    include_file_context: true,
};
```

## Logging System

### Overview

The ESP Compiler uses a global, thread-safe logging system with structured error codes and file-aware context tracking.

### Initialization

```rust
use esp_compiler::logging;

// Initialize global logging (call once at startup)
logging::init_global_logging()?;
```

### Logging Macros

#### Error Logging

```rust
use esp_compiler::{log_error, logging::codes};

// Simple error
log_error!(codes::lexical::INVALID_CHARACTER, "Invalid character encountered");

// Error with span
log_error!(codes::syntax::UNEXPECTED_TOKEN, "Unexpected token",
    span = token_span
);

// Error with context
log_error!(codes::file_processing::FILE_TOO_LARGE, "File exceeds maximum size",
    "file" => file_path,
    "size" => file_size,
    "limit" => max_size
);

// Error with span and context
log_error!(codes::semantic::TYPE_INCOMPATIBILITY, "Type mismatch",
    span = field_span,
    "field" => field_name,
    "type" => data_type,
    "operation" => operation
);
```

#### Success Logging

```rust
use esp_compiler::{log_success, logging::codes};

log_success!(codes::success::TOKENIZATION_COMPLETE, "Tokenization completed",
    "tokens" => token_count,
    "duration_ms" => duration.as_secs_f64() * 1000.0
);
```

#### Info Logging

```rust
use esp_compiler::log_info;

log_info!("Processing file", "path" => file_path);

log_info!("Symbol discovery complete",
    "global_symbols" => global_count,
    "local_symbols" => local_count
);
```

#### Warning Logging

```rust
use esp_compiler::log_warning;

log_warning!("Deprecated feature used",
    "feature" => feature_name,
    "replacement" => replacement_name
);
```

#### Debug Logging

```rust
use esp_compiler::log_debug;

log_debug!("Parsing state definition", "state_id" => state_id);

log_debug!("Type checking field",
    "field" => field_name,
    "type" => data_type,
    "operation" => operation
);
```

### Error Code Registry

Error codes follow a structured format:

| Prefix | Category | Range |
|--------|----------|-------|
| `E001-E009` | System | System-level errors |
| `E005-E019` | File Processing | File I/O errors |
| `E020-E039` | Lexical | Tokenization errors |
| `E040-E059` | Syntax | Parsing errors |
| `E060-E079` | Symbols | Symbol discovery errors |
| `E080-E099` | References | Reference validation errors |
| `E100-E119` | Semantic | Semantic analysis errors |
| `E120-E139` | Structural | Structural validation errors |
| `I001-I099` | Success | Success codes |
| `W001-W099` | Warning | Warning codes |

### Error Code Examples

#### System Errors (E001-E004)
```rust
codes::system::INTERNAL_ERROR              // E001
codes::system::CONFIGURATION_ERROR         // E002
codes::system::INITIALIZATION_FAILURE      // E003
codes::system::RESOURCE_EXHAUSTED          // E004
```

#### File Processing Errors (E005-E019)
```rust
codes::file_processing::FILE_NOT_FOUND     // E005
codes::file_processing::FILE_TOO_LARGE     // E006
codes::file_processing::EMPTY_FILE         // E007
codes::file_processing::INVALID_EXTENSION  // E008
codes::file_processing::PERMISSION_DENIED  // E009
codes::file_processing::INVALID_ENCODING   // E010
codes::file_processing::IO_ERROR           // E011
codes::file_processing::INVALID_PATH       // E019
```

#### Lexical Errors (E020-E039)
```rust
codes::lexical::INVALID_CHARACTER          // E020
codes::lexical::UNTERMINATED_STRING        // E021
codes::lexical::INVALID_ESCAPE_SEQUENCE    // E022
codes::lexical::INVALID_NUMBER             // E023
codes::lexical::NUMBER_OVERFLOW            // E024
codes::lexical::RESERVED_KEYWORD           // E025
codes::lexical::IDENTIFIER_TOO_LONG        // E026
codes::lexical::STRING_TOO_LONG            // E027
codes::lexical::TOKEN_LIMIT_EXCEEDED       // E028
```

#### Syntax Errors (E040-E059)
```rust
codes::syntax::MISSING_EOF                 // E040
codes::syntax::EMPTY_TOKEN_STREAM          // E041
codes::syntax::UNEXPECTED_TOKEN            // E050
codes::syntax::GRAMMAR_VIOLATION           // E043
codes::syntax::UNMATCHED_BLOCK_DELIMITER   // E044
codes::syntax::MAX_RECURSION_DEPTH         // E087
codes::syntax::INTERNAL_PARSER_ERROR       // E086
```

#### Symbol Errors (E060-E079)
```rust
codes::symbols::DUPLICATE_SYMBOL           // E060
codes::symbols::SYMBOL_DISCOVERY_ERROR     // E061
codes::symbols::SYMBOL_TABLE_CONSTRUCTION_ERROR  // E062
codes::symbols::MULTIPLE_LOCAL_OBJECTS     // E063
codes::symbols::SYMBOL_SCOPE_VALIDATION_ERROR    // E064
```

#### Reference Errors (E080-E099)
```rust
codes::references::UNDEFINED_REFERENCE     // E080
codes::references::SCOPE_VIOLATION         // E081
codes::references::CIRCULAR_DEPENDENCY     // E082
codes::references::INVALID_REFERENCE_TYPE  // E083
```

#### Semantic Errors (E100-E119)
```rust
codes::semantic::TYPE_INCOMPATIBILITY      // E100
codes::semantic::RUNTIME_OPERATION_ERROR   // E101
codes::semantic::SET_CONSTRAINT_VIOLATION  // E102
codes::semantic::INVALID_OPERATION         // E103
```

#### Structural Errors (E120-E139)
```rust
codes::structural::INVALID_BLOCK_ORDERING           // E120
codes::structural::INCOMPLETE_DEFINITION_STRUCTURE  // E121
codes::structural::IMPLEMENTATION_LIMIT_EXCEEDED    // E122
codes::structural::EMPTY_CRITERIA_BLOCK             // E123
codes::structural::COMPLEXITY_VIOLATION             // E124
codes::structural::CONSISTENCY_VIOLATION            // E125
codes::structural::MULTIPLE_STRUCTURAL_ERRORS       // E126
```

#### Success Codes (I001-I099)
```rust
codes::success::SYSTEM_INITIALIZATION_COMPLETED  // I001
codes::success::FILE_PROCESSING_SUCCESS          // I006
codes::success::TOKENIZATION_COMPLETE            // I020
codes::success::AST_CONSTRUCTION_COMPLETE        // I040
codes::success::SYMBOL_DISCOVERY_COMPLETE        // I060
codes::success::REFERENCE_VALIDATION_COMPLETE    // I080
codes::success::SEMANTIC_ANALYSIS_COMPLETE       // I100
codes::success::STRUCTURAL_VALIDATION_COMPLETE   // I120
```

### Error Metadata

Each error code has associated metadata:

```rust
use esp_compiler::logging::codes;

let code = codes::lexical::INVALID_CHARACTER;

// Get error properties
let severity = codes::get_severity(code.as_str());      // "High"
let category = codes::get_category(code.as_str());      // "Lexical"
let description = codes::get_description(code.as_str()); // Full description
let action = codes::get_action(code.as_str());          // Recommended action

// Check error properties
let is_recoverable = codes::is_recoverable(code.as_str());  // true/false
let requires_halt = codes::requires_halt(code.as_str());    // true/false
```

### File-Aware Context

The logging system automatically tracks file context for batch processing:

```rust
use esp_compiler::logging;
use std::path::PathBuf;

// Set file context (automatically done by pipeline)
logging::set_file_context(PathBuf::from("example.esp"), 0);

// All logging within this context includes file information
log_error!(codes::syntax::UNEXPECTED_TOKEN, "Parse error");
// Output: [ERROR] E050 - Parse error (file: example.esp)

// Clear context when done
logging::clear_file_context();

// Or use with_file_context for automatic cleanup
logging::with_file_context(PathBuf::from("test.esp"), 1, || {
    log_info!("Processing file");
    // ... processing code ...
});
```

### Cargo-Style Error Reporting

For batch processing, get a cargo-style error summary:

```rust
use esp_compiler::logging;

// After processing multiple files
logging::print_cargo_style_summary();
```

Output format:
```
error[E050]: Unexpected token
  --> example1.esp:15:23
   |
15 |     STATE invalid syntax
   |                  ^^^^^^
   |
   = help: Expected identifier, found keyword

error[E080]: Undefined reference
  --> example2.esp:42:15
   |
42 |     STATE_REF missing_state
   |               ^^^^^^^^^^^^^
   |
   = help: State 'missing_state' not found in global scope

Error Summary:
  Files processed: 10
  Files with errors: 2
  Total errors: 3
  Total warnings: 5
```

### Performance Logging

Convenience macros for performance metrics:

```rust
use esp_compiler::{log_performance, logging::codes};
use std::time::Instant;

let start = Instant::now();
// ... processing ...
let duration = start.elapsed();

log_performance!(codes::success::TOKENIZATION_COMPLETE,
    "Tokenization completed",
    duration = duration,
    "tokens" => token_count,
    "bytes_per_sec" => bytes_per_sec
);
```

## Security Features

### Compile-Time Security Boundaries

All security limits are enforced at compile time and baked into the binary:

1. **DoS Prevention**
   - File size limits
   - Token count limits
   - Symbol count limits
   - Error collection limits
   - String literal size limits
   - Recursion depth limits

2. **Resource Management**
   - Memory allocation boundaries
   - Buffer size limits
   - Concurrent operation limits
   - Processing time limits

3. **Audit Logging**
   - Mandatory security event logging
   - Audit trail retention buffers
   - Minimum log level enforcement
   - Tamper-resistant logging

### Runtime Security Features

1. **Input Validation**
   - UTF-8 encoding verification
   - Path traversal prevention
   - Extension validation
   - Size limit enforcement

2. **Memory Safety**
   - Rust's memory safety guarantees
   - No unsafe code in core modules
   - Bounded buffer allocations
   - Stack overflow prevention

3. **Error Handling**
   - Comprehensive error recovery
   - Detailed error reporting
   - No panic-based failures
   - Graceful degradation

### SSDF Compliance Matrix

| SSDF Practice | Implementation |
|---------------|----------------|
| **PW.7.1** (Input Validation) | Compile-time limits, UTF-8 validation, type checking |
| **PW.8.1** (DoS Protection) | Resource limits, timeout enforcement, rate limiting |
| **PW.3.1** (Audit Logging) | Mandatory audit logs, retention buffers, tamper resistance |
| **RV.1** (Monitoring) | Resource monitoring, alert thresholds, metrics collection |

## API Documentation

### Pipeline API

#### Single File Processing

```rust
pub fn process_file(file_path: &str)
    -> Result<PipelineResult, PipelineError>
```

Process a single ESP file through all 7 pipeline stages.

**Returns:** `PipelineResult` containing:
- AST
- File metadata
- Lexical metrics
- Symbol discovery results
- Reference validation results
- Semantic analysis results
- Structural validation results
- Token count
- Processing duration

#### Batch Processing

```rust
pub fn process_directory_with_config(
    dir_path: &Path,
    config: &BatchConfig
) -> Result<BatchResults, BatchError>
```

Process multiple ESP files in a directory.

**Configuration:**
```rust
pub struct BatchConfig {
    pub max_threads: usize,
    pub recursive: bool,
    pub fail_fast: bool,
    pub progress_reporting: bool,
    pub max_files: Option<usize>,
}
```

**Returns:** `BatchResults` containing:
- Files discovered
- Files processed
- Successful files (with results)
- Failed files (with errors)
- Processing duration
- Performance metrics

### Module-Specific APIs

#### File Processor

```rust
// Process file with defaults
pub fn process_file(file_path: &str)
    -> Result<FileProcessingResult, FileProcessorError>

// Get compile-time limits
pub fn get_max_file_size() -> u64
pub fn get_large_file_threshold() -> u64

// Custom processor
pub fn create_custom_processor(
    require_esp_extension: bool,
    enable_performance_logging: bool
) -> FileProcessor
```

#### Lexical Analysis

```rust
// Tokenize file result
pub fn tokenize_file_result(file_result: FileProcessingResult)
    -> Result<TokenStream, LexerError>

// Create analyzer
pub fn create_analyzer() -> LexicalAnalyzer

// Get metrics
impl LexicalAnalyzer {
    pub fn metrics(&self) -> &LexicalMetrics;
}
```

#### Symbol Discovery

```rust
// Standard discovery
pub fn discover_symbols_from_ast(ast: EspFile)
    -> Result<SymbolDiscoveryResult, SymbolDiscoveryError>

// Detailed analysis
pub fn discover_symbols_detailed(ast: EspFile)
    -> Result<SymbolDiscoveryResult, SymbolDiscoveryError>

// Strict validation
pub fn discover_symbols_strict(ast: EspFile)
    -> Result<SymbolDiscoveryResult, SymbolDiscoveryError>

// Performance-optimized
pub fn discover_symbols_minimal(ast: EspFile)
    -> Result<SymbolDiscoveryResult, SymbolDiscoveryError>

// Custom preferences
pub fn discover_symbols_from_ast_with_preferences(
    ast: EspFile,
    preferences: SymbolPreferences
) -> Result<SymbolDiscoveryResult, SymbolDiscoveryError>
```

#### Reference Validation

```rust
pub fn validate_references_and_basic_dependencies(
    symbols: SymbolDiscoveryResult,
    preferences: &ReferenceValidationPreferences
) -> Result<ReferenceValidationResult, ReferenceValidationError>
```

#### Semantic Analysis

```rust
pub fn analyze_semantics(
    ast: EspFile,
    symbols: SymbolDiscoveryResult,
    validation_result: ReferenceValidationResult
) -> Result<SemanticOutput, SemanticError>

pub fn quick_validate(
    ast: EspFile,
    symbols: SymbolDiscoveryResult,
    validation_result: ReferenceValidationResult
) -> bool
```

#### Structural Validation

```rust
pub fn validate_structure_and_limits(
    ast: EspFile,
    symbols: SymbolDiscoveryResult,
    references: ReferenceValidationResult,
    semantics: SemanticOutput
) -> Result<StructuralValidationResult, StructuralError>
```

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

#### SymbolDiscoveryResult

```rust
pub struct SymbolDiscoveryResult {
    pub global_symbols: GlobalSymbolTable,
    pub local_symbol_tables: HashMap<CtnNodeId, LocalSymbolTable>,
    // ... relationship tracking ...

    pub fn total_symbol_count(&self) -> usize;
    pub fn relationship_count(&self) -> usize;
}
```

#### ReferenceValidationResult

```rust
pub struct ReferenceValidationResult {
    pub is_valid: bool,
    pub undefined_references: Vec<UndefinedReference>,
    pub scope_violations: Vec<ScopeViolation>,
    pub cycles: Vec<Vec<String>>,
    // ... detailed results ...
}
```

#### SemanticOutput

```rust
pub struct SemanticOutput {
    pub is_successful: bool,
    pub errors: Vec<SemanticError>,
    // ... validation results ...
}
```

#### StructuralValidationResult

```rust
pub struct StructuralValidationResult {
    pub is_valid: bool,
    pub errors: Vec<StructuralError>,
    pub limits_status: LimitsStatus,
    pub total_symbols: usize,
    pub max_nesting_depth: usize,
}
```

## Examples

### Example 1: Basic File Processing

```rust
use esp_compiler::logging;
use esp_compiler::pipeline;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    logging::init_global_logging()?;

    // Process file
    match pipeline::process_file("example.esp") {
        Ok(result) => {
            println!("✓ Processing successful");
            println!("  Tokens: {}", result.token_count);
            println!("  Symbols: {}", result.symbol_discovery_result.total_symbol_count());
            println!("  Duration: {:.2}ms",
                result.processing_duration.as_secs_f64() * 1000.0);
        }
        Err(error) => {
            eprintln!("✗ Processing failed: {}", error);
            logging::print_cargo_style_summary();
            std::process::exit(1);
        }
    }

    Ok(())
}
```

### Example 2: Batch Processing with Custom Config

```rust
use esp_compiler::{batch, logging};
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    logging::init_global_logging()?;

    let config = batch::BatchConfig {
        max_threads: 4,
        recursive: true,
        fail_fast: false,
        progress_reporting: true,
        max_files: Some(100),
    };

    let results = batch::process_directory_with_config(
        Path::new("./esp_files"),
        &config
    )?;

    println!("Batch Processing Results:");
    println!("  Files discovered: {}", results.files_discovered);
    println!("  Files processed: {}", results.files_processed);
    println!("  Success rate: {:.1}%", results.success_rate() * 100.0);

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

### Example 3: Per-Stage Processing with Custom Preferences

```rust
use esp_compiler::{
    file_processor, lexical, syntax, symbols,
    reference_resolution, semantic_analysis, validation,
    config::runtime::*,
    logging
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    logging::init_global_logging()?;

    // Pass 1: File Processing
    let file_result = file_processor::process_file("example.esp")?;
    println!("✓ File processed: {} bytes", file_result.metadata.size);

    // Pass 2: Lexical Analysis
    let tokens = lexical::tokenize_file_result(file_result)?;
    println!("✓ Tokenization complete: {} tokens", tokens.len());

    // Pass 3: Syntax Analysis
    let ast = syntax::parse_esp_file(tokens)?;
    println!("✓ AST constructed");

    // Pass 4: Symbol Discovery (detailed mode)
    let symbols = symbols::discover_symbols_detailed(ast.clone())?;
    println!("✓ Symbol discovery: {} symbols", symbols.total_symbol_count());

    // Pass 5: Reference Validation (custom preferences)
    let mut ref_prefs = ReferenceValidationPreferences::default();
    ref_prefs.enable_cycle_detection = true;
    ref_prefs.include_cycle_descriptions = true;

    let references = reference_resolution::validate_references_and_basic_dependencies(
        symbols.clone(),
        &ref_prefs
    )?;
    println!("✓ Reference validation complete");

    if !references.cycles.is_empty() {
        println!("  Warning: {} circular dependencies detected", references.cycles.len());
    }

    // Pass 6: Semantic Analysis
    let semantics = semantic_analysis::analyze_semantics(
        ast.clone(),
        symbols.clone(),
        references.clone()
    )?;
    println!("✓ Semantic analysis complete");

    if !semantics.is_successful {
        println!("  {} semantic errors found", semantics.errors.len());
    }

    // Pass 7: Structural Validation
    let structural = validation::validate_structure_and_limits(
        ast,
        symbols,
        references,
        semantics
    )?;

    if structural.is_valid {
        println!("✓ Structural validation passed");
        println!("\nValidation complete: All checks passed");
    } else {
        println!("✗ Structural validation failed: {} errors",
            structural.error_count());
    }

    Ok(())
}
```

### Example 4: Error Handling and Reporting

```rust
use esp_compiler::{pipeline, logging};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    logging::init_global_logging()?;

    let files = vec!["file1.esp", "file2.esp", "file3.esp"];

    for file in files {
        match pipeline::process_file(file) {
            Ok(result) => {
                println!("✓ {}: Success ({} tokens)",
                    file, result.token_count);
            }
            Err(error) => {
                eprintln!("✗ {}: {}", file, error);

                // Get error details
                match error {
                    pipeline::PipelineError::LexicalAnalysis(ref lex_err) => {
                        eprintln!("  Lexical error at stage 2");
                    }
                    pipeline::PipelineError::SyntaxAnalysis(ref syn_err) => {
                        eprintln!("  Syntax error at stage 3");
                    }
                    pipeline::PipelineError::SemanticAnalysis(ref sem_err) => {
                        eprintln!("  Semantic error at stage 6");
                    }
                    _ => {
                        eprintln!("  Error: {}", error);
                    }
                }
            }
        }
    }

    // Print comprehensive error summary
    logging::print_cargo_style_summary();

    // Get system diagnostics
    let diagnostics = logging::get_system_diagnostics();
    println!("\n{}", diagnostics);

    Ok(())
}
```

### Example 5: Custom Logging

```rust
use esp_compiler::{log_error, log_success, log_info, logging};

fn custom_processing() -> Result<(), Box<dyn std::error::Error>> {
    logging::init_global_logging()?;

    log_info!("Starting custom processing");

    // Simulate processing stages
    let stages = vec!["validation", "transformation", "optimization"];

    for (i, stage) in stages.iter().enumerate() {
        log_info!("Processing stage",
            "stage" => stage,
            "index" => i + 1,
            "total" => stages.len()
        );

        // Simulate stage processing
        if stage == &"transformation" {
            log_error!(
                logging::codes::semantic::TYPE_INCOMPATIBILITY,
                "Type mismatch detected",
                "expected" => "string",
                "found" => "int",
                "field" => "user_id"
            );
            return Err("Processing failed".into());
        }
    }

    log_success!(
        logging::codes::success::SEMANTIC_ANALYSIS_COMPLETE,
        "Custom processing completed successfully",
        "stages_completed" => stages.len()
    );

    Ok(())
}
```

## Contributing

### Development Setup

1. Clone the repository:
```bash
git clone https://github.com/your-org/esp_compiler.git
cd esp_compiler
```

2. Create configuration files:
```bash
mkdir -p config
cp config/development.toml.example config/development.toml
```

3. Set environment variables:
```bash
export ESP_BUILD_PROFILE=development
export ESP_CONFIG_DIR=config
```

4. Build and test:
```bash
cargo build
cargo test
```

### Running Tests

```bash
# All tests
cargo test

# Specific module
cargo test file_processor

# Integration tests
cargo test --test '*'

# With logging output
cargo test -- --nocapture
```

### Code Style

- Follow Rust standard formatting (`rustfmt`)
- Use `clippy` for linting
- Document public APIs
- Include unit tests for new features
- Add integration tests for major features

### Security Guidelines

- Never bypass compile-time security limits
- Validate all external inputs
- Use safe Rust (avoid `unsafe` blocks)
- Document security implications
- Follow SSDF practices

### Pull Request Process

1. Create a feature branch
2. Implement changes with tests
3. Update documentation
4. Run full test suite
5. Submit PR with description
6. Address review feedback

## License

[Add your license here]

## Support

- **Issues**: [GitHub Issues](https://github.com/your-org/esp_compiler/issues)
- **Documentation**: [Full API Docs](https://docs.rs/esp_compiler)
- **Examples**: See `examples/` directory

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and release notes.
