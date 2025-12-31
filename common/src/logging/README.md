# Logging Module

Thread-safe global logging with cargo-style error reporting, structured error codes, and batch file processing support.

This module provides a comprehensive logging system for the ESP compiler and scanner, featuring categorized error codes with metadata, file-aware batch processing, and multiple output formats.

## Quick Start

```rust
use common::logging;
use common::{log_error, log_info, log_success};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize global logging
    logging::init_global_logging()?;

    // Log messages
    log_info!("Starting processing");
    log_success!(logging::codes::success::FILE_PROCESSING_SUCCESS, "File processed");
    log_error!(logging::codes::lexical::INVALID_CHARACTER, "Unexpected character",
        "char" => '€',
        "position" => 42
    );

    // Print cargo-style summary
    logging::print_cargo_style_summary();

    Ok(())
}
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Global State                            │
│  ┌─────────────────┐  ┌──────────────────┐                 │
│  │ LoggingService  │  │  ErrorCollector  │                 │
│  │   (OnceLock)    │  │    (OnceLock)    │                 │
│  └────────┬────────┘  └────────┬─────────┘                 │
│           │                    │                            │
│           ▼                    ▼                            │
│  ┌─────────────────┐  ┌──────────────────┐                 │
│  │  Logger Trait   │  │ File Events Map  │                 │
│  │ (Console/JSON)  │  │  (BTreeMap)      │                 │
│  └─────────────────┘  └──────────────────┘                 │
└─────────────────────────────────────────────────────────────┘
           ▲                    ▲
           │                    │
    ┌──────┴──────┐      ┌──────┴──────┐
    │   Macros    │      │ File Context │
    │ log_error!  │      │ (thread-local)│
    │ log_info!   │      └──────────────┘
    └─────────────┘
```

### Components

| Component | Description |
|-----------|-------------|
| `LoggingService` | Main service that routes events to configured loggers |
| `ErrorCollector` | Aggregates events by file for batch processing summaries |
| `FileProcessingContext` | Thread-local context for file-aware logging |
| `LogEvent` | Core event structure with code, message, span, and context |
| `Code` | Typed wrapper for error/success codes with metadata lookup |

## Error Codes

All errors use typed `Code` constants with associated metadata. Codes are organized by category:

### Code Categories

| Module | Prefix | Description |
|--------|--------|-------------|
| `system` | `ERR0xx` | Critical system errors (internal, memory, init) |
| `file_processing` | `E0xx` | File I/O errors (not found, permissions, encoding) |
| `lexical` | `E02x` | Tokenization errors (invalid chars, unterminated strings) |
| `syntax` | `E04x` | Parse errors (grammar, unexpected tokens) |
| `symbols` | `E05x`, `E08x`, `E09x` | Symbol table errors (duplicates, scope) |
| `references` | `E1xx` | Reference errors (undefined, circular) |
| `semantic` | `E18x`, `E2xx` | Type and constraint errors |
| `structural` | `E23x`, `E24x` | Block structure errors |
| `consumer` | `C0xx` | Library integration errors |
| `transformation` | `T0xx` | FFI transformation errors |
| `success` | `I0xx` | Success/info codes |

### Code Metadata

Each code includes metadata for classification and user guidance:

```rust
use common::logging::codes;

let code = codes::lexical::INVALID_CHARACTER;  // E020

// Access metadata
codes::get_severity("E020");      // Severity::Medium
codes::get_category("E020");      // "Lexical"
codes::get_description("E020");   // "Invalid character in input"
codes::get_action("E020");        // "Remove or escape the character"
codes::is_recoverable("E020");    // true
codes::requires_halt("E020");     // false
```

### Severity Levels

| Level | Description |
|-------|-------------|
| `Critical` | Requires immediate halt, unrecoverable |
| `High` | Serious error, may be recoverable |
| `Medium` | Standard error, usually recoverable |
| `Low` | Minor issue, always recoverable |

## Logging Macros

All macros accept `Display` types for context values automatically.

### `log_error!`

```rust
use common::log_error;
use common::logging::codes;

// Basic error
log_error!(codes::file_processing::FILE_NOT_FOUND, "File not found");

// With context (accepts any Display type)
log_error!(codes::lexical::INVALID_CHARACTER, "Invalid character",
    "char" => invalid_char,
    "line" => line_number,
    "column" => col
);

// With span information
log_error!(codes::syntax::UNEXPECTED_TOKEN, "Unexpected token",
    span = token.span
);
```

### `log_success!`

```rust
use common::log_success;
use common::logging::codes;

log_success!(codes::success::FILE_PROCESSING_SUCCESS, "Compilation complete");

log_success!(codes::success::TOKENIZATION_COMPLETE, "Tokenization finished",
    "tokens" => token_count,
    "duration_ms" => elapsed.as_millis()
);
```

### `log_info!`

```rust
use common::log_info;

log_info!("Starting batch processing");

log_info!("Processing file",
    "path" => file_path.display(),
    "size" => file_size
);
```

### `log_warning!` and `log_debug!`

```rust
use common::{log_warning, log_debug};

log_warning!("Deprecated syntax detected",
    "feature" => "old_keyword"
);

log_debug!("Parser state",
    "stack_depth" => stack.len(),
    "current_token" => format!("{:?}", token)
);
```

### Convenience Macros

```rust
use common::{log_performance, log_file_metrics};
use common::logging::codes;

// Performance timing
log_performance!(codes::success::FILE_PROCESSING_SUCCESS, "File processed",
    duration = elapsed,
    "tokens" => count
);

// File metrics
log_file_metrics!(codes::success::FILE_PROCESSING_SUCCESS, "Parse complete",
    file = "input.esp",
    size = 1024,
    lines = 42
);
```

## File Context

For batch file processing, set file context to associate logs with specific files:

```rust
use common::logging;
use std::path::PathBuf;

// Process multiple files
for (id, file) in files.iter().enumerate() {
    // Set context for this file
    logging::set_file_context(file.clone(), id);

    // All logs now associated with this file
    process_file(file)?;

    // Clear when done
    logging::clear_file_context();
}

// Or use the RAII helper
logging::with_file_context(file_path, file_id, || {
    // Logs here are associated with file_path
    process_file()?;
    Ok(())
});
```

## Error Collector

The `ErrorCollector` aggregates events by file for cargo-style reporting:

```rust
use common::logging;

// After processing files...
let summary = logging::get_processing_summary();
println!("Files: {}", summary.total_files);
println!("Errors: {}", summary.total_errors);
println!("Warnings: {}", summary.total_warnings);
println!("Success rate: {:.1}%", summary.success_rate() * 100.0);

// Print cargo-style error output
logging::print_cargo_style_summary();
```

### Cargo-Style Output

```
Checking input.esp...
error[E020]: Invalid character '€'
 --> input.esp:10:5
  = severity: Medium, category: Lexical
  = help: Remove or escape the invalid character

warning[W000]: Deprecated syntax
 --> input.esp:15:1

Total errors: 1
Total warnings: 1
```

### Querying Collected Events

```rust
use common::logging;
use std::path::Path;

// Get events for a specific file
let errors = logging::get_file_errors(Path::new("input.esp"));

// Check if file has errors
if collector.file_has_errors(path) {
    // Handle error case
}

// Get all critical errors across all files
let critical = collector.get_critical_errors();
```

## Logger Types

### ConsoleLogger

Human-readable output to stdout/stderr:

```rust
use common::logging::service::ConsoleLogger;
use common::logging::LogLevel;

let logger = ConsoleLogger::new(LogLevel::Info);
```

### StructuredLogger

JSON output for tooling integration:

```rust
use common::logging::service::StructuredLogger;

let logger = StructuredLogger::new(LogLevel::Debug);
```

Output:
```json
{
  "timestamp": 1704067200,
  "level": "ERROR",
  "code": "E020",
  "message": "Invalid character",
  "category": "Lexical",
  "severity": "Medium",
  "error_metadata": {
    "recoverable": true,
    "requires_halt": false,
    "description": "Invalid character in input",
    "recommended_action": "Remove or escape the character"
  },
  "span": { "start_line": 10, "start_column": 5 },
  "context": { "char": "€" }
}
```

### MemoryLogger

Captures events for testing:

```rust
use common::logging::service::{MemoryLogger, create_test_logger};
use std::sync::Arc;

let logger = create_test_logger();

// After running code...
assert_eq!(logger.event_count(), 3);
assert!(logger.has_error_with_code(codes::lexical::INVALID_CHARACTER));

let errors = logger.get_errors();
let summary = logger.get_summary();
```

### MultiLogger

Log to multiple destinations:

```rust
use common::logging::service::MultiLogger;
use common::logging::LogLevel;

let multi = MultiLogger::new(LogLevel::Debug)
    .with_console(LogLevel::Info)
    .with_structured_console(LogLevel::Debug)
    .with_file("compile.log", LogLevel::Debug, true)?;

let (multi, memory) = multi.with_memory();  // Also capture in memory
```

## Configuration

Logging behavior is controlled by compile-time security constants and runtime preferences.

### Compile-Time Constants

Security-critical limits enforced at compile time:

| Constant | Description |
|----------|-------------|
| `LOG_BUFFER_SIZE` | Maximum total events in collector |
| `MAX_LOG_EVENTS_PER_FILE` | Maximum events per file |
| `MAX_LOG_MESSAGE_LENGTH` | Maximum message length |
| `SECURITY_MIN_LOG_LEVEL` | Minimum level for security events |
| `AUDIT_LOG_RETENTION_BUFFER` | Audit event retention size |

### Runtime Preferences

User-configurable options (within security bounds):

```rust
use common::logging::config;
use common::config::runtime::LoggingPreferences;

// Check current settings
let min_level = config::get_min_log_level();
let use_json = config::use_structured_logging();

// Development vs production presets
let dev_prefs = config::get_development_preferences();
let prod_prefs = config::get_production_preferences();
```

> **See also**: [Configuration Module](../config/README.md) for full configuration system documentation.

### Security Enforcement

Certain logging behaviors cannot be disabled:

- Security metrics are always logged
- Audit events are always captured
- Critical errors always reach stderr

```rust
use common::logging::config;

// These always return true - security requirement
assert!(config::log_security_metrics());
assert!(config::log_audit_events());
```

## Diagnostics

```rust
use common::logging;

// Get system diagnostics
let diagnostics = logging::get_system_diagnostics();
println!("{}", diagnostics);
```

Output:
```
=== Logging System Diagnostics ===
Initialized: true
Capacity: 42/10000 (0.4%)
Files processed: 5
Total errors: 3
Total warnings: 7

Logging Configuration:
=== Security Constants (Compile-time) ===
- Log buffer size: 10000
- Max events per file: 1000
...
```

## Module Structure

```
logging/
├── mod.rs          # Global state, initialization, file context management
├── codes.rs        # Error code constants and metadata registry
├── events.rs       # LogEvent structure and formatting
├── macros.rs       # log_error!, log_success!, log_info!, etc.
├── service.rs      # Logger trait and implementations
├── collector.rs    # ErrorCollector for batch processing
└── config.rs       # Configuration access (compile-time + runtime)
```
