# ESP v1.0.0 — Logging System

**Version:** 1.0.0
**Status:** Normative
**Last Updated:** 2026-01-09

---

> **v2.0.0 cross-reference.** Event model, error-code taxonomy,
> severity classification, file-aware logging, and audit-event
> non-suppressibility in this document are **unchanged** in v2.0.0.
>
> Two v2.0.0-adjacent notes:
>
> - Log events that reference collection activity may now carry an
>   `observation_uuid` field linking the log line to the entry in
>   `ResultEnvelope.observations[]`. This is additive — consumers that
>   ignore the field continue to function.
> - Channel-level events (connect / tunnel ready / channel close) from
>   transports like Azure Bastion SHOULD include `channel_kind` and
>   (where applicable) `target_resource_id` so log correlation against
>   the envelope's `host.attrs` works without a join table.
>
> Neither is a breaking change. Existing v1.x log consumers continue to
> parse v2.0.0 logs without modification.
>
> **v2.1.0 / v2.2.0 / v2.2.1** add no further logging refinements.
> The event model, codes, and severity rules in this document remain
> normative for the current crate version (`2.2.1`).

---

## 1. Overview

This document specifies the logging system for ESP v1.0.0, defining the event model, error classification, output formats, and integration patterns for the compiler, scanner, and consumer applications.

### 1.1 Core Principle

> Every significant operation is observable, every error is classifiable, and every event is attributable.

The logging system provides:

| Capability | Description |
|------------|-------------|
| **Typed error codes** | Every error has a unique code with metadata |
| **Severity classification** | Errors are categorized by impact and recoverability |
| **File-aware logging** | Events are attributed to source files in batch processing |
| **Multiple output formats** | Human-readable and structured JSON output |
| **Security enforcement** | Audit events cannot be suppressed |

### 1.2 Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           LOGGING SYSTEM                                    │
│                                                                             │
│  ┌─────────────────┐  ┌──────────────────┐  ┌─────────────────────────┐    │
│  │  LoggingService │  │  ErrorCollector  │  │   File Context          │    │
│  │   (OnceLock)    │  │    (OnceLock)    │  │   (thread-local)        │    │
│  └────────┬────────┘  └────────┬─────────┘  └───────────┬─────────────┘    │
│           │                    │                        │                   │
│           ▼                    ▼                        ▼                   │
│  ┌─────────────────┐  ┌──────────────────┐  ┌─────────────────────────┐    │
│  │  Logger Trait   │  │ File Events Map  │  │ FileProcessingContext   │    │
│  │ (impl: Console, │  │   (BTreeMap)     │  │ (path, id, start_time)  │    │
│  │  Structured,    │  │                  │  │                         │    │
│  │  Memory, File)  │  │                  │  │                         │    │
│  └─────────────────┘  └──────────────────┘  └─────────────────────────┘    │
│           ▲                    ▲                        ▲                   │
│           │                    │                        │                   │
│    ┌──────┴──────┐      ┌──────┴──────┐          ┌──────┴──────┐           │
│    │   Macros    │      │  Collector  │          │ set_file_   │           │
│    │ log_error!  │      │  Functions  │          │   context() │           │
│    │ log_info!   │      │             │          │             │           │
│    │ log_success!│      │             │          │             │           │
│    └─────────────┘      └─────────────┘          └─────────────┘           │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 1.3 SSDF Alignment

| SSDF Practice | Implementation |
|---------------|----------------|
| **PW.3.1** (Audit Logging) | `SECURITY_MIN_LOG_LEVEL`, mandatory audit events |
| **PW.8.1** (DoS Protection) | `LOG_BUFFER_SIZE`, `MAX_LOG_EVENTS_PER_FILE` limits |
| **RV.1** (Monitoring) | Structured output, event categorization |

---

## 2. Event Model

### 2.1 LogEvent Structure

Every log event contains:

| Field | Type | Description |
|-------|------|-------------|
| `timestamp` | `SystemTime` | Event creation time |
| `level` | `LogLevel` | Severity level (Error, Warning, Info, Debug) |
| `code` | `Code` | Typed error/success code |
| `message` | `String` | Human-readable message |
| `span` | `Option<Span>` | Source location (line, column) |
| `context` | `HashMap<String, String>` | Additional key-value metadata |

### 2.2 Log Levels

| Level | Numeric | Description | Use Case |
|-------|---------|-------------|----------|
| `Error` | 0 | Operation failed | Compilation errors, validation failures |
| `Warning` | 1 | Potential issue | Deprecated syntax, recoverable issues |
| `Info` | 2 | Informational | Progress, success messages |
| `Debug` | 3 | Diagnostic | Development tracing |

Log levels are ordered by severity. A minimum level setting of `Warning` will log `Error` and `Warning` events but suppress `Info` and `Debug`.

### 2.3 Event Classification

Events are classified by their error code metadata:

| Property | Description |
|----------|-------------|
| `severity` | Critical, High, Medium, Low |
| `category` | Functional area (FileProcessing, Lexical, etc.) |
| `recoverable` | Whether processing can continue |
| `requires_halt` | Whether immediate termination is required |
| `description` | Human-readable explanation |
| `recommended_action` | Guidance for resolution |

---

## 3. Error Code System

### 3.1 Code Structure

Error codes use a typed wrapper for compile-time safety:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Code(&'static str);

impl Code {
    pub const fn new(code: &'static str) -> Self;
    pub fn as_str(&self) -> &'static str;
}
```

### 3.2 Code Categories

| Module | Prefix | Description |
|--------|--------|-------------|
| `system` | `ERR0xx` | Critical system errors |
| `file_processing` | `E00x` | File I/O errors |
| `lexical` | `E02x` | Tokenization errors |
| `syntax` | `E04x`, `E05x`, `E08x` | Parse errors |
| `symbols` | `E05x`, `E08x`, `E09x` | Symbol table errors |
| `references` | `E1xx` | Reference resolution errors |
| `semantic` | `E18x`, `E2xx` | Type and constraint errors |
| `structural` | `E23x`, `E24x` | Block structure errors |
| `consumer` | `C0xx` | Library integration errors |
| `transformation` | `T0xx` | FFI transformation errors |
| `success` | `I0xx` | Success/info codes |

### 3.3 Severity Levels

| Severity | Description | Behavior |
|----------|-------------|----------|
| `Critical` | Unrecoverable system failure | Requires immediate halt |
| `High` | Serious error | May be recoverable with intervention |
| `Medium` | Standard error | Usually recoverable |
| `Low` | Minor issue | Always recoverable |

### 3.4 Code Lookup Functions

```rust
// Get metadata for any code
get_severity(code: &str) -> Severity
get_category(code: &str) -> &'static str
get_description(code: &str) -> &'static str
get_action(code: &str) -> &'static str
is_recoverable(code: &str) -> bool
requires_halt(code: &str) -> bool
```

See **Appendix A** for the complete error code registry.

---

## 4. Output Formats

### 4.1 Format Selection

Output format is controlled by the `ESP_LOGGING_USE_STRUCTURED` environment variable:

| Value | Output Format | Use Case |
|-------|---------------|----------|
| `false` (default) | JSON (human-oriented) | Development, debugging |
| `true` | JSON (machine-oriented) | SIEM integration, tooling |

### 4.2 Standard JSON Format (ESP_LOGGING_USE_STRUCTURED=false)

When structured logging is disabled, events are formatted as human-readable JSON:

```json
{
  "timestamp": 1704067200,
  "level": "ERROR",
  "code": "E020",
  "message": "Invalid character '€' in source",
  "category": "Lexical",
  "severity": "Medium"
}
```

#### Standard JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "ESP Log Event (Standard)",
  "type": "object",
  "required": ["timestamp", "level", "code", "message", "category", "severity"],
  "properties": {
    "timestamp": {
      "type": "integer",
      "description": "Unix timestamp in seconds"
    },
    "level": {
      "type": "string",
      "enum": ["ERROR", "WARN", "INFO", "DEBUG"]
    },
    "code": {
      "type": "string",
      "pattern": "^(ERR|E|W|I|D|C|T)[0-9]{2,3}$"
    },
    "message": {
      "type": "string"
    },
    "category": {
      "type": "string"
    },
    "severity": {
      "type": "string",
      "enum": ["Critical", "High", "Medium", "Low"]
    },
    "span": {
      "type": "object",
      "properties": {
        "start_line": { "type": "integer" },
        "start_column": { "type": "integer" },
        "end_line": { "type": "integer" },
        "end_column": { "type": "integer" }
      }
    },
    "context": {
      "type": "object",
      "additionalProperties": { "type": "string" }
    }
  }
}
```

### 4.3 Structured JSON Format (ESP_LOGGING_USE_STRUCTURED=true)

When structured logging is enabled, events include full error metadata:

```json
{
  "timestamp": 1704067200,
  "level": "ERROR",
  "code": "E020",
  "message": "Invalid character '€' in source",
  "category": "Lexical",
  "severity": "Medium",
  "error_metadata": {
    "recoverable": true,
    "requires_halt": false,
    "description": "Invalid character found in source text",
    "recommended_action": "Remove or escape invalid characters"
  },
  "span": {
    "start_line": 10,
    "start_column": 5,
    "end_line": 10,
    "end_column": 6
  },
  "context": {
    "char": "€",
    "file": "input.esp",
    "file_id": "1"
  }
}
```

#### Structured JSON Schema

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "ESP Log Event (Structured)",
  "type": "object",
  "required": ["timestamp", "level", "code", "message", "category", "severity"],
  "properties": {
    "timestamp": {
      "type": "integer",
      "description": "Unix timestamp in seconds"
    },
    "level": {
      "type": "string",
      "enum": ["ERROR", "WARN", "INFO", "DEBUG"]
    },
    "code": {
      "type": "string",
      "pattern": "^(ERR|E|W|I|D|C|T)[0-9]{2,3}$"
    },
    "message": {
      "type": "string"
    },
    "category": {
      "type": "string"
    },
    "severity": {
      "type": "string",
      "enum": ["Critical", "High", "Medium", "Low"]
    },
    "error_metadata": {
      "type": "object",
      "description": "Present only for error-level events",
      "properties": {
        "recoverable": { "type": "boolean" },
        "requires_halt": { "type": "boolean" },
        "description": { "type": "string" },
        "recommended_action": { "type": "string" }
      },
      "required": ["recoverable", "requires_halt", "description", "recommended_action"]
    },
    "span": {
      "type": "object",
      "properties": {
        "start_line": { "type": "integer", "minimum": 1 },
        "start_column": { "type": "integer", "minimum": 1 },
        "end_line": { "type": "integer", "minimum": 1 },
        "end_column": { "type": "integer", "minimum": 1 }
      },
      "required": ["start_line", "start_column", "end_line", "end_column"]
    },
    "context": {
      "type": "object",
      "additionalProperties": { "type": "string" },
      "description": "Application-specific key-value pairs"
    }
  }
}
```

### 4.4 Cargo-Style Text Format

When `ESP_LOGGING_CARGO_STYLE=true` (default), the error collector produces cargo-style output:

```
Checking input.esp...
error[E020]: Invalid character '€' in source
 --> input.esp:10:5
  = severity: Medium, category: Lexical
  = char: €
  = help: Remove or escape invalid characters

warning[W000]: Deprecated syntax detected
 --> input.esp:15:1
  = feature: old_keyword

Total errors: 1
Total warnings: 1
```

---

## 5. Configuration

The logging system uses compile-time constants for security boundaries and runtime preferences for user customization.

### 5.1 Compile-Time Constants

These values are baked into the binary and cannot be modified at runtime:

| Constant | Default | Description |
|----------|---------|-------------|
| `LOG_BUFFER_SIZE` | 10,000 | Maximum total events in collector |
| `MAX_LOG_EVENTS_PER_FILE` | 1,000 | Maximum events per source file |
| `MAX_LOG_MESSAGE_LENGTH` | 10,000 | Maximum message length |
| `SECURITY_MIN_LOG_LEVEL` | 1 (Warning) | Minimum level for security events |
| `AUDIT_LOG_RETENTION_BUFFER` | 50,000 | Audit event retention size |
| `MAX_CONCURRENT_LOG_OPERATIONS` | 100 | Maximum concurrent log operations |

### 5.2 Runtime Preferences

These settings are configurable via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `ESP_LOGGING_USE_STRUCTURED` | `false` | Enable structured JSON output |
| `ESP_LOGGING_ENABLE_CONSOLE` | `false` | Enable console output |
| `ESP_LOGGING_MIN_LEVEL` | `info` | Minimum log level |
| `ESP_LOGGING_LOG_PERFORMANCE` | `true` | Log performance events |
| `ESP_LOGGING_LOG_SECURITY` | `true` | Log security metrics (always enforced) |
| `ESP_LOGGING_CARGO_STYLE` | `true` | Use cargo-style error output |
| `ESP_LOGGING_INCLUDE_FILE_CONTEXT` | `true` | Include file context in messages |

### 5.3 Log Level Configuration

The `ESP_LOGGING_MIN_LEVEL` variable accepts:

| Value | Aliases | Events Logged |
|-------|---------|---------------|
| `error` | `0` | Error only |
| `warning` | `warn`, `1` | Error, Warning |
| `info` | `2` | Error, Warning, Info |
| `debug` | `3` | All events |

### 5.4 Security Enforcement

Certain logging behaviors cannot be disabled:

| Behavior | Enforcement |
|----------|-------------|
| Security events logged | `SECURITY_MIN_LOG_LEVEL` compile-time constant |
| Audit events captured | Always enabled regardless of preferences |
| Critical errors to stderr | Always written regardless of configuration |

```rust
// These always return true - security requirement
assert!(config::log_security_metrics());
assert!(config::log_audit_events());
```

### 5.5 Configuration Access

```rust
use common::logging::config;

// Compile-time constants
let buffer_size = config::get_error_buffer_size();
let max_per_file = config::get_max_log_events_per_file();

// Runtime preferences
let min_level = config::get_min_log_level();
let use_json = config::use_structured_logging();
let use_console = config::use_console_logging();

// Configuration summary for diagnostics
let summary = config::get_config_summary();
```

---

## 6. Logger Implementations

### 6.1 Logger Trait

All loggers implement the `Logger` trait:

```rust
pub trait Logger: Send + Sync {
    fn log(&self, event: &LogEvent);
}
```

### 6.2 Available Implementations

| Logger | Description | Use Case |
|--------|-------------|----------|
| `ConsoleLogger` | Human-readable to stdout/stderr | Development |
| `StructuredLogger` | JSON to stdout/stderr | Production, SIEM |
| `MemoryLogger` | Captures events in memory | Testing |
| `FileLogger` | Writes to file | Persistent logging |
| `MultiLogger` | Routes to multiple destinations | Complex deployments |

### 6.3 LoggingService

The `LoggingService` wraps a logger with level filtering:

```rust
pub struct LoggingService {
    logger: Arc<dyn Logger>,
    min_level: LogLevel,
}

impl LoggingService {
    pub fn new(logger: Arc<dyn Logger>, min_level: LogLevel) -> Self;
    pub fn with_config() -> Self;  // Uses runtime configuration
    pub fn log_event(&self, event: LogEvent);
    pub fn should_log(&self, level: LogLevel) -> bool;
}
```

---

## 7. Error Collector

### 7.1 Purpose

The `ErrorCollector` aggregates events by source file for batch processing, enabling cargo-style error reporting.

### 7.2 Structure

```rust
pub struct ErrorCollector {
    file_events: Mutex<BTreeMap<PathBuf, Vec<LogEvent>>>,
    file_contexts: Mutex<BTreeMap<PathBuf, FileProcessingContext>>,
    processing_start: Instant,
}
```

### 7.3 File Processing Context

```rust
pub struct FileProcessingContext {
    pub file_path: PathBuf,
    pub file_id: usize,
    pub start_time: Instant,
}
```

### 7.4 Processing Summary

```rust
pub struct ProcessingSummary {
    pub total_files: usize,
    pub successful_files: usize,
    pub failed_files: usize,
    pub files_with_warnings: usize,
    pub total_errors: usize,
    pub total_warnings: usize,
    pub total_processing_time: Duration,
    pub average_file_time: Duration,
}
```

### 7.5 Capacity Management

The collector respects compile-time limits:

| Limit | Behavior When Exceeded |
|-------|------------------------|
| `LOG_BUFFER_SIZE` | Oldest events removed |
| `MAX_LOG_EVENTS_PER_FILE` | Summary event added, new events dropped |
| `AUDIT_LOG_RETENTION_BUFFER` | Audit events truncated to limit |

---

## 8. Implementation Patterns

### 8.1 Initialization Pattern

Every application using the logging system MUST initialize it before use:

```rust
use common::logging;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize global logging system
    logging::init_global_logging()?;

    // Application logic...

    // Print summary at end
    logging::print_cargo_style_summary();

    Ok(())
}
```

### 8.2 Compiler Pipeline Pattern

For the compiler pipeline with file context:

```rust
use common::logging;
use common::{log_error, log_info, log_success};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize global logging system
    logging::init_global_logging()?;

    // Validate pipeline configuration
    pipeline::validate_pipeline()?;

    let input_path = Path::new(&args[1]);

    if input_path.is_file() {
        process_single_file(&args[1])?;
    } else if input_path.is_dir() {
        process_directory_batch(input_path, &config)?;
    }

    Ok(())
}

fn process_single_file(file_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("Processing file: {}", file_path);

    match pipeline::process_file(file_path) {
        Ok(_) => {
            println!("\nSUCCESS: Complete parsing and validation successful");
            logging::print_cargo_style_summary();
        }
        Err(error) => {
            eprintln!("\nFAILED: {}", error);
            logging::print_cargo_style_summary();
            std::process::exit(1);
        }
    }

    Ok(())
}
```

### 8.3 Batch Processing Pattern

For processing multiple files with file context tracking:

```rust
use common::logging;
use std::path::PathBuf;

fn process_batch(files: &[PathBuf]) -> Result<(), Error> {
    for (id, file) in files.iter().enumerate() {
        // Set context for this file
        logging::set_file_context(file.clone(), id);

        // All logs now associated with this file
        match process_file(file) {
            Ok(_) => {
                log_success!(
                    logging::codes::success::FILE_PROCESSING_SUCCESS,
                    "File processed successfully"
                );
            }
            Err(e) => {
                log_error!(
                    logging::codes::file_processing::IO_ERROR,
                    "Processing failed",
                    "error" => e.to_string()
                );
            }
        }

        // Clear when done with file
        logging::clear_file_context();
    }

    // Print aggregated results
    logging::print_cargo_style_summary();

    Ok(())
}
```

### 8.4 Scanner/Agent Pattern

For runtime scanning with operational logging:

```rust
use common::logging;
use common::{log_error, log_info, log_success};

fn run_scan(config: &ScanConfig, esp_files: &[PathBuf]) -> Result<i32, ScanError> {
    log_info!("Starting unified scan", "file_count" => esp_files.len());

    let registry = Arc::new(create_registry()?);

    let stats = registry.get_statistics();
    log_info!(
        "Registry initialized",
        "strategies" => stats.total_ctn_types,
        "healthy" => stats.registry_health.is_healthy()
    );

    let (scan_results, summary) = execute_scans(esp_files, &registry)?;

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
```

### 8.5 Consumer Library Pattern

For libraries integrating with the logging system:

```rust
use common::logging::{self, codes};
use common::{log_error, log_info};

pub fn initialize_consumer() -> Result<(), ConsumerError> {
    // Check if logging is already initialized
    if !logging::is_initialized() {
        // Initialize with consumer-specific configuration
        logging::init_global_logging()
            .map_err(|e| ConsumerError::InitFailed(e))?;
    }

    log_info!("Consumer library initialized");
    Ok(())
}

pub fn process_data(data: &[u8]) -> Result<Output, ConsumerError> {
    if data.is_empty() {
        log_error!(
            codes::consumer::CONSUMER_DATA_VALIDATION_ERROR,
            "Empty data provided"
        );
        return Err(ConsumerError::EmptyData);
    }

    // Process...
    Ok(output)
}
```

### 8.6 Testing Pattern

For unit tests that need to capture log events:

```rust
use common::logging::service::{MemoryLogger, LoggingService, create_test_logger};
use common::logging::codes;
use std::sync::Arc;

#[test]
fn test_error_logging() {
    let logger = create_test_logger();
    let service = LoggingService::new(logger.clone(), LogLevel::Debug);

    // Run code that logs
    service.log_error(codes::lexical::INVALID_CHARACTER, "Test error");

    // Verify logging behavior
    assert_eq!(logger.event_count(), 1);
    assert!(logger.has_error_with_code(codes::lexical::INVALID_CHARACTER));

    let errors = logger.get_errors();
    assert_eq!(errors[0].message, "Test error");

    let summary = logger.get_summary();
    assert_eq!(summary.error_count, 1);
}
```

---

## 9. Logging Macros

### 9.1 Error Logging

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

// With span and context
log_error!(codes::syntax::GRAMMAR_VIOLATION, "Grammar error",
    span = node.span,
    "expected" => "identifier",
    "found" => token_type
);
```

### 9.2 Success Logging

```rust
use common::log_success;
use common::logging::codes;

// Basic success
log_success!(codes::success::FILE_PROCESSING_SUCCESS, "Compilation complete");

// With context
log_success!(codes::success::TOKENIZATION_COMPLETE, "Tokenization finished",
    "tokens" => token_count,
    "duration_ms" => elapsed.as_millis()
);
```

### 9.3 Info Logging

```rust
use common::log_info;

// Basic info
log_info!("Starting batch processing");

// With context
log_info!("Processing file",
    "path" => file_path.display(),
    "size" => file_size
);
```

### 9.4 Warning and Debug Logging

```rust
use common::{log_warning, log_debug};

// Warning
log_warning!("Deprecated syntax detected",
    "feature" => "old_keyword"
);

// Debug (only logged if level permits)
log_debug!("Parser state",
    "stack_depth" => stack.len(),
    "current_token" => format!("{:?}", token)
);
```

### 9.5 Convenience Macros

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

// Classified error (automatically adds severity metadata)
log_classified_error!(codes::system::INTERNAL_ERROR, "Critical system failure");
```

---

## 10. Global State Management

### 10.1 Global Logging State

The logging system uses `OnceLock` for thread-safe global state:

```rust
static GLOBAL_LOGGER: OnceLock<Arc<LoggingService>> = OnceLock::new();
static GLOBAL_ERROR_COLLECTOR: OnceLock<Arc<ErrorCollector>> = OnceLock::new();
```

### 10.2 Initialization

```rust
/// Initialize global logging system
pub fn init_global_logging() -> Result<(), String>;

/// Initialize with custom service (for testing)
pub fn init_global_logging_with_service(service: Arc<LoggingService>) -> Result<(), String>;

/// Check if initialized
pub fn is_initialized() -> bool;
```

### 10.3 File Context (Thread-Local)

```rust
thread_local! {
    static FILE_CONTEXT: RefCell<Option<FileProcessingContext>> = const {RefCell::new(None)};
}

/// Set file context for current thread
pub fn set_file_context(file_path: PathBuf, file_id: usize);

/// Clear file context for current thread
pub fn clear_file_context();

/// Execute function with file context
pub fn with_file_context<F, R>(file_path: PathBuf, file_id: usize, f: F) -> R
where
    F: FnOnce() -> R;
```

### 10.4 Safe Fallback Logging

For critical errors when logging may not be initialized:

```rust
/// Safe error logging (won't panic if uninitialized)
pub fn safe_log_error(code: Code, message: &str);

/// Safe critical error logging (always writes to stderr)
pub fn safe_log_critical(code: Code, message: &str);
```

---

## 11. Diagnostics

### 11.1 System Diagnostics

```rust
use common::logging;

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
- Max message length: 10000
- Security min level: 1
- Audit buffer size: 50000
- Max concurrent ops: 100
=== User Preferences (Runtime) ===
- Min log level: Info
- Structured logging: false
- Console logging: true
- Performance events: true
- Security metrics: true (always enabled)
- Audit events: true (always enabled)
- Cargo-style output: true
- Include file context: true
```

### 11.2 Processing Summary

```rust
let summary = logging::get_processing_summary();
println!("Files: {}", summary.total_files);
println!("Errors: {}", summary.total_errors);
println!("Warnings: {}", summary.total_warnings);
println!("Success rate: {:.1}%", summary.success_rate() * 100.0);
```

### 11.3 Resource Usage

```rust
let usage = collector.get_resource_usage();
println!("{}", usage.get_summary());
// Output: Collector Usage: 4.2% capacity (420/10000 events), 0.21MB memory, 5 files
```

---

## 12. Relationship to Configuration System

This specification implements the logging configuration described in the ESP Configuration System specification.

### 12.1 Configuration Reference

| Configuration Aspect | Source Document |
|---------------------|-----------------|
| Compile-time constants | Configuration System §4.10 |
| Runtime preferences | Configuration System §5.7, §5.8 |
| Security enforcement | Configuration System §6 |
| Build profile selection | Configuration System §3 |

### 12.2 Security Invariants

The following invariants are maintained:

| Invariant | Enforcement |
|-----------|-------------|
| Security logging cannot be disabled | `SECURITY_MIN_LOG_LEVEL` compile-time |
| Audit trail always maintained | `log_audit_events()` always returns `true` |
| Critical errors always visible | Written to stderr regardless of config |

---

## 13. Module Structure

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

---

## Appendix A: Error Code Registry

### A.1 System Errors (ERR0xx)

| Code | Severity | Recoverable | Description |
|------|----------|-------------|-------------|
| `ERR001` | Critical | No | Critical internal system error |
| `ERR002` | Critical | No | System initialization failure |
| `ERR003` | Critical | No | Memory allocation failure |

### A.2 File Processing Errors (E00x)

| Code | Severity | Recoverable | Description |
|------|----------|-------------|-------------|
| `E005` | Medium | No | File not found at specified path |
| `E006` | Low | Yes | File does not have .esp extension |
| `E007` | Medium | No | File exceeds maximum size limit |
| `E008` | Medium | No | File is empty when content expected |
| `E009` | Medium | No | Permission denied accessing file |
| `E010` | Medium | No | Invalid UTF-8 encoding in file |
| `E011` | Medium | No | I/O error during file operation |
| `E012` | Medium | No | Invalid file path provided |

### A.3 Lexical Analysis Errors (E02x)

| Code | Severity | Recoverable | Description |
|------|----------|-------------|-------------|
| `E020` | Medium | Yes | Invalid character found in source text |
| `E021` | Medium | Yes | String literal not properly terminated |
| `E022` | Low | Yes | Number format is invalid |
| `E023` | Low | Yes | Identifier exceeds maximum allowed length |
| `E024` | Medium | Yes | String literal exceeds maximum size limit |
| `E025` | Low | Yes | Reserved keyword used as identifier |
| `E026` | Medium | No | Comment exceeds maximum allowed length |
| `E027` | High | No | File contains too many tokens |
| `E028` | Medium | No | String literal nesting exceeds maximum depth |

### A.4 Syntax Analysis Errors (E04x, E05x, E08x)

| Code | Severity | Recoverable | Description |
|------|----------|-------------|-------------|
| `E040` | Medium | Yes | Missing EOF token in token stream |
| `E041` | Medium | Yes | Empty token stream |
| `E042` | High | Yes | Unmatched block delimiter |
| `E043` | High | Yes | Grammar violation during parsing |
| `E044` | Medium | Yes | Semantic error during syntax analysis |
| `E050` | Medium | Yes | Unexpected token during parsing |
| `E086` | Critical | No | Internal parser error |
| `E087` | High | No | Maximum recursion depth exceeded |

### A.5 Symbol Discovery Errors (E05x, E08x, E09x)

| Code | Severity | Recoverable | Description |
|------|----------|-------------|-------------|
| `E051` | Medium | Yes | Symbol discovery error during analysis |
| `E081` | Medium | Yes | Symbol table construction error |
| `E090` | Medium | Yes | Duplicate symbol identifier within same scope |
| `E091` | Medium | Yes | Local symbol shadows global symbol |
| `E094` | Medium | Yes | Multiple local objects in same CTN scope |
| `E095` | Medium | Yes | Symbol scope validation error |

### A.6 Reference Resolution Errors (E1xx)

| Code | Severity | Recoverable | Description |
|------|----------|-------------|-------------|
| `E110` | High | No | Undefined reference target |
| `E140` | High | Yes | Circular variable dependency detected |

### A.7 Semantic Analysis Errors (E18x, E2xx)

| Code | Severity | Recoverable | Description |
|------|----------|-------------|-------------|
| `E180` | Medium | Yes | Operation not compatible with data type |
| `E181` | Medium | Yes | Runtime operation type error |
| `E200` | High | Yes | SET operation operand count violation |

### A.8 Structural Validation Errors (E23x, E24x)

| Code | Severity | Recoverable | Description |
|------|----------|-------------|-------------|
| `E230` | Medium | Yes | Invalid block ordering in ESP structure |
| `E240` | High | Yes | Incomplete definition structure |
| `E241` | High | Yes | Implementation limit exceeded |
| `E242` | Medium | Yes | Empty criteria block detected |
| `E243` | Low | Yes | Structural complexity violation |
| `E244` | Medium | Yes | Structural consistency violation |
| `E245` | High | Yes | Multiple structural errors detected |
| `E246` | High | Yes | Missing META block |
| `E247` | Medium | Yes | META block validation error |

### A.9 Consumer Integration Errors (C0xx)

| Code | Severity | Recoverable | Description |
|------|----------|-------------|-------------|
| `C001` | Medium | Yes | Consumer application initialization failure |
| `C002` | Medium | Yes | Consumer configuration error |
| `C003` | Medium | Yes | Consumer shutdown error |
| `C010` | High | Yes | Consumer pipeline integration error |
| `C011` | High | Yes | Consumer pass failure |
| `C012` | Medium | Yes | Consumer state mismatch |
| `C020` | Medium | Yes | Consumer data validation error |
| `C021` | Medium | Yes | Consumer format error |
| `C022` | Medium | Yes | Consumer encoding error |
| `C030` | High | Yes | Consumer memory error |
| `C031` | Medium | Yes | Consumer timeout error |
| `C032` | Medium | Yes | Consumer capacity error |
| `C040` | Medium | Yes | Consumer I/O error |
| `C041` | Medium | Yes | Consumer network error |
| `C042` | Medium | Yes | Consumer permission error |

### A.10 FFI Transformation Errors (T0xx)

| Code | Severity | Recoverable | Description |
|------|----------|-------------|-------------|
| `T001` | High | No | Complete FFI transformation failed |
| `T002` | Medium | Yes | AST to FFI structure mapping failed |
| `T003` | Medium | Yes | Execution context building failed |
| `T004` | High | Yes | Dependency analysis failed |
| `T005` | Medium | Yes | Variable processing failed |
| `T006` | Medium | Yes | Set resolution failed |
| `T007` | High | No | Cross-reference validation failed |
| `T008` | Medium | Yes | FFI schema validation failed |
| `T009` | Medium | No | JSON serialization failed |
| `T010` | Critical | No | Memory management error |
| `T011` | Low | Yes | Metadata extraction failed |
| `T012` | High | Yes | Execution order generation failed |
| `T013` | Medium | Yes | Scope mapping failed |
| `T014` | Medium | Yes | Partial transformation completed with errors |
| `T015` | Critical | No | FFI boundary crossing error |

### A.11 Success Codes (I0xx)

| Code | Category | Description |
|------|----------|-------------|
| `I001` | General | Operation completed successfully |
| `I004` | System | System initialization completed |
| `I005` | System | System cleanup completed |
| `I006` | FileProcessing | File processing completed successfully |
| `I007` | FileProcessing | File validation passed |
| `I020` | Lexical | Tokenization complete |
| `I021` | Lexical | Lexical validation passed |
| `I040` | Syntax | AST construction complete |
| `I041` | Syntax | Syntax validation passed |
| `I050` | Symbols | Symbol discovery complete |
| `I051` | Symbols | Symbol validation passed |
| `I060` | References | Reference resolution complete |
| `I061` | References | Dependency analysis complete |
| `I070` | Semantic | Semantic analysis complete |
| `I071` | Semantic | Type checking passed |
| `I072` | Semantic | Runtime validation complete |
| `I073` | Semantic | SET validation passed |
| `I080` | Structural | Structural validation complete |
| `I081` | Structural | Completeness check passed |
| `I082` | Structural | Block ordering passed |
| `I083` | Structural | Limits check passed |
| `I084` | Structural | Requirements check passed |
| `I085` | Structural | Metadata validation passed |
| `I090` | Transformation | FFI transformation completed |
| `I091` | Transformation | AST mapping completed |
| `I092` | Transformation | Dependency analysis completed |
| `I093` | Transformation | Variable resolution completed |
| `I094` | Transformation | Set resolution completed |
| `I095` | Transformation | Execution context building completed |

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-01-09 | Initial specification |
