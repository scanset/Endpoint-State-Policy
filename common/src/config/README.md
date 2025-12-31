# Configuration Module

Compile-time security constants and runtime user preferences for the ESP compiler and scanner.

This module separates configuration into two distinct layers:
- **Compile-time constants**: Security-critical limits that cannot be changed at runtime
- **Runtime preferences**: User experience settings configurable via environment variables

## Security Model

Security-critical limits are enforced at compile time to prevent:
- Denial of Service (DoS) attacks via resource exhaustion
- Memory exhaustion attacks
- Algorithmic complexity attacks
- Stack overflow via deep recursion

These limits reference NIST SSDF (Secure Software Development Framework) practices:
- **PW.7.1**: Input Validation
- **PW.8.1**: DoS Protection
- **PW.3.1**: Audit Logging
- **RV.1**: Monitoring

Runtime preferences allow users to customize behavior without compromising security boundaries.

## Compile-Time Constants

Access via `common::config::compile_time`:

```rust
use common::config::compile_time;

// Check limits at compile time
const _: () = assert!(compile_time::lexical::MAX_STRING_SIZE <= 10_000_000);

// Use in runtime checks
if file_size > compile_time::file_processing::MAX_FILE_SIZE {
    return Err("File too large");
}
```

### File Processing

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_FILE_SIZE` | 10 MB | Maximum file size for processing |
| `LARGE_FILE_THRESHOLD` | 1 MB | Threshold for "large file" optimizations |
| `MAX_LINE_COUNT_FOR_ANALYSIS` | 100,000 | Maximum lines for complexity analysis |

### Lexical Analysis

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_STRING_SIZE` | 1 MB | Maximum string literal size |
| `MAX_IDENTIFIER_LENGTH` | 255 | Maximum identifier length |
| `MAX_COMMENT_LENGTH` | 10,000 | Maximum comment length |
| `MAX_TOKEN_COUNT` | 1,000,000 | Maximum tokens per file |
| `MAX_STRING_NESTING_DEPTH` | 100 | Maximum nested string depth |

### Syntax Analysis

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_PARSE_DEPTH` | 100 | Maximum parser recursion depth |
| `MAX_ERROR_HISTORY` | 50 | Maximum errors in recovery buffer |
| `MAX_CONTEXT_STACK_DEPTH` | 20 | Maximum context stack for errors |
| `MAX_RECOVERY_SCAN_TOKENS` | 1,000 | Maximum tokens for error recovery |
| `MAX_LOOKAHEAD_TOKENS` | 10 | Token lookahead limit |

### Symbol Table

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_GLOBAL_SYMBOLS` | 50,000 | Maximum global symbols |
| `MAX_LOCAL_SYMBOLS_PER_CTN` | 1,000 | Maximum local symbols per CTN |
| `MAX_SYMBOL_RELATIONSHIPS` | 100,000 | Maximum symbol relationships |
| `MAX_ELEMENTS_PER_SYMBOL` | 10,000 | Maximum elements per symbol |
| `MAX_CTN_SCOPES` | 1,000 | Maximum CTN scopes |

### Reference Resolution

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_REFERENCE_DEPTH` | 50 | Maximum reference chain depth |
| `MAX_REFERENCES_PER_SYMBOL` | 10,000 | Maximum references per symbol |
| `MAX_CYCLE_LENGTH` | 100 | Maximum cycle length to analyze |
| `MAX_DEPENDENCY_NODES` | 100,000 | Maximum dependency graph nodes |

### Semantic Analysis

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_SEMANTIC_ERRORS` | 1,000 | Maximum semantic errors to collect |
| `MAX_RUNTIME_OPERATION_PARAMETERS` | 100 | Maximum RUN parameters |
| `MAX_SET_OPERATION_OPERANDS` | 1,000 | Maximum SET operands |
| `MAX_FILTER_STATE_REFERENCES` | 1,000 | Maximum filter state refs |

### Structural Validation

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_SYMBOLS_PER_DEFINITION` | 10,000 | Maximum symbols per DEF |
| `MAX_NESTING_DEPTH` | 10 | Maximum block nesting depth |
| `MAX_CRITERIA_BLOCKS` | 1,000 | Maximum CRI blocks |
| `MAX_VARIABLES_PER_DEFINITION` | 1,000 | Maximum variables per DEF |
| `MAX_STATES_PER_DEFINITION` | 500 | Maximum states per DEF |
| `MAX_OBJECTS_PER_DEFINITION` | 200 | Maximum objects per DEF |

### Batch Processing

| Constant | Value | Description |
|----------|-------|-------------|
| `MAX_WORKER_THREADS` | 8 | Maximum worker threads |
| `MAX_FILES_PER_BATCH` | 1,000 | Maximum files per batch |
| `MAX_BATCH_MEMORY` | 1 GB | Maximum batch memory |

### Security & Logging

| Constant | Value | Description |
|----------|-------|-------------|
| `MEMORY_ALERT_THRESHOLD` | 500 MB | Memory usage alert threshold |
| `MAX_PROCESSING_TIME_SECONDS` | 300 | Maximum processing time (5 min) |
| `MAX_CONCURRENT_OPERATIONS` | 100 | Maximum concurrent operations |
| `LOG_BUFFER_SIZE` | 10,000 | Log buffer size |
| `MAX_LOG_EVENTS_PER_FILE` | 1,000 | Maximum log events per file |
| `SECURITY_MIN_LOG_LEVEL` | 1 | Minimum security log level (Warning) |
| `AUDIT_LOG_RETENTION_BUFFER` | 50,000 | Audit log retention size |

## Runtime Preferences

Runtime preferences are configured via environment variables and can be customized per-execution.

### Environment Variables

All environment variables use the `ESP_` prefix.

#### File Processing

| Variable | Default | Description |
|----------|---------|-------------|
| `ESP_REQUIRE_ESP_EXTENSION` | `false` | Require .esp file extension |
| `ESP_ENABLE_PERFORMANCE_LOGGING` | `true` | Enable performance metrics |
| `ESP_LOG_NON_ESP_PROCESSING` | `false` | Log non-ESP file processing |
| `ESP_INCLUDE_COMPLEXITY_METRICS` | `true` | Include complexity scores |

#### Lexical Analysis

| Variable | Default | Description |
|----------|---------|-------------|
| `ESP_LEXICAL_DETAILED_METRICS` | `true` | Collect detailed token metrics |
| `ESP_LEXICAL_INCLUDE_ALL_TOKENS` | `false` | Include whitespace in counts |
| `ESP_LEXICAL_LOG_STRING_STATS` | `false` | Log string length statistics |
| `ESP_LEXICAL_TRACK_OPERATORS` | `false` | Track operator patterns |
| `ESP_LEXICAL_INCLUDE_POSITIONS` | `true` | Include positions in errors |

#### Symbol Table

| Variable | Default | Description |
|----------|---------|-------------|
| `ESP_SYMBOLS_DETAILED_RELATIONSHIPS` | `true` | Detailed relationship info |
| `ESP_SYMBOLS_TRACK_CROSS_REFS` | `false` | Track cross-references |
| `ESP_SYMBOLS_VALIDATE_NAMING` | `false` | Validate naming conventions |
| `ESP_SYMBOLS_INCLUDE_USAGE_METRICS` | `true` | Include usage metrics |
| `ESP_SYMBOLS_LOG_RELATIONSHIP_WARNINGS` | `true` | Log relationship warnings |
| `ESP_SYMBOLS_ANALYZE_DEPENDENCY_CHAINS` | `true` | Analyze dependency chains |

#### Reference Validation

| Variable | Default | Description |
|----------|---------|-------------|
| `ESP_REFERENCES_ENABLE_CYCLE_DETECTION` | `true` | Enable cycle detection |
| `ESP_REFERENCES_LOG_VALIDATION_DETAILS` | `false` | Log validation details |
| `ESP_REFERENCES_INCLUDE_CYCLE_DESCRIPTIONS` | `true` | Include cycle descriptions |
| `ESP_REFERENCES_CONTINUE_AFTER_CYCLES` | `false` | Continue after finding cycles |
| `ESP_REFERENCES_VALIDATE_TYPES` | `true` | Validate reference types |

#### Semantic Analysis

| Variable | Default | Description |
|----------|---------|-------------|
| `ESP_SEMANTIC_COMPREHENSIVE_TYPE_CHECKING` | `true` | Comprehensive type checks |
| `ESP_SEMANTIC_VALIDATE_RUNTIME_CONSTRAINTS` | `true` | Validate RUN constraints |
| `ESP_SEMANTIC_CHECK_SET_SEMANTICS` | `true` | Check SET semantics |
| `ESP_SEMANTIC_ANALYZE_CYCLES` | `true` | Analyze cycles |
| `ESP_SEMANTIC_DETAILED_ERROR_CONTEXT` | `true` | Detailed error context |

#### Structural Validation

| Variable | Default | Description |
|----------|---------|-------------|
| `ESP_STRUCTURAL_ADVANCED_CONSISTENCY_CHECKS` | `true` | Advanced consistency checks |
| `ESP_STRUCTURAL_LOG_DETAILED_METRICS` | `false` | Log detailed metrics |
| `ESP_STRUCTURAL_INCLUDE_COMPLEXITY_BREAKDOWN` | `true` | Complexity breakdown |
| `ESP_STRUCTURAL_VALIDATE_RECOMMENDATIONS` | `true` | Validate recommendations |
| `ESP_STRUCTURAL_ANALYZE_QUALITY_PATTERNS` | `true` | Analyze quality patterns |

#### Logging

| Variable | Default | Description |
|----------|---------|-------------|
| `ESP_LOGGING_USE_STRUCTURED` | `false` | Use JSON structured logging |
| `ESP_LOGGING_ENABLE_CONSOLE` | `false` | Enable console output |
| `ESP_LOGGING_MIN_LEVEL` | `info` | Minimum log level |
| `ESP_LOGGING_LOG_PERFORMANCE` | `true` | Log performance events |
| `ESP_LOGGING_LOG_SECURITY` | `true` | Log security metrics |
| `ESP_LOGGING_CARGO_STYLE` | `true` | Cargo-style error output |
| `ESP_LOGGING_INCLUDE_FILE_CONTEXT` | `true` | Include file context |

### Log Levels

The `ESP_LOGGING_MIN_LEVEL` variable accepts:

| Value | Aliases |
|-------|---------|
| `error` | `0` |
| `warning` | `warn`, `1` |
| `info` | `2` |
| `debug` | `3` |

## Usage

### Accessing Compile-Time Constants

```rust
use common::config::compile_time::*;

fn validate_file_size(size: u64) -> Result<(), &'static str> {
    if size > file_processing::MAX_FILE_SIZE {
        return Err("File exceeds maximum size limit");
    }
    if size > file_processing::LARGE_FILE_THRESHOLD {
        println!("Processing large file...");
    }
    Ok(())
}

fn check_token_count(count: usize) -> bool {
    count <= lexical::MAX_TOKEN_COUNT
}
```

### Accessing Runtime Preferences

```rust
use common::config::runtime::{RuntimeConfig, LoggingPreferences};

// Load from environment
let config = RuntimeConfig::default();

// Check preferences
if config.logging.use_structured_logging {
    // Use JSON output
}

if config.references.enable_cycle_detection {
    // Run cycle detection
}
```

### Combining Both Layers

```rust
use common::config::{compile_time, runtime::RuntimeConfig};

fn process_tokens(tokens: &[Token], config: &RuntimeConfig) -> Result<(), Error> {
    // Security check (compile-time constant)
    if tokens.len() > compile_time::lexical::MAX_TOKEN_COUNT {
        return Err(Error::TooManyTokens);
    }

    // User preference (runtime)
    if config.lexical.collect_detailed_metrics {
        collect_metrics(tokens);
    }

    Ok(())
}
```

### Environment Variable Configuration

```bash
# Development configuration
export ESP_LOGGING_MIN_LEVEL=debug
export ESP_LOGGING_CARGO_STYLE=true
export ESP_LEXICAL_DETAILED_METRICS=true

# Production configuration
export ESP_LOGGING_MIN_LEVEL=info
export ESP_LOGGING_USE_STRUCTURED=true
export ESP_LOGGING_CARGO_STYLE=false
```

## Module Structure

```
config/
├── mod.rs          # Module exports
├── constants.rs    # Compile-time security constants
└── runtime.rs      # Runtime preferences with env var support
```

## Related Modules

- [Logging Module](../logging/README.md) - Uses configuration for log levels and output format
