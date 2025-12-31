# Config Directory

Compile-time configuration profiles for the ESP compiler.

## Overview

This directory contains TOML configuration files that define security limits and resource boundaries for the ESP compiler. These values are baked into the binary at compile time, ensuring security limits cannot be bypassed at runtime.

## How It Works

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│ development.toml│     │  build.rs       │     │  constants.rs   │
│ testing.toml    │────▶│  (compiler)     │────▶│  (generated)    │
│ production.toml │     │                 │     │                 │
└─────────────────┘     └─────────────────┘     └─────────────────┘
        │                                               │
        │  ESP_BUILD_PROFILE=production                 │
        └───────────────────────────────────────────────┘
                                                        │
                                                        ▼
                                              Compile-time constants
                                              in final binary
```

## Profiles

| Profile | Purpose | Limits |
|---------|---------|--------|
| `development` | Local development and debugging | Relaxed limits, verbose logging |
| `testing` | CI/CD and automated testing | Moderate limits, enhanced error collection |
| `production` | Production deployment | Strict limits, security-optimized |

## Usage

### Selecting a Profile

Set the `ESP_BUILD_PROFILE` environment variable before building:

```bash
# Development (default)
export ESP_BUILD_PROFILE=development
cargo build

# Testing
export ESP_BUILD_PROFILE=testing
cargo build

# Production
export ESP_BUILD_PROFILE=production
cargo build --release
```

### Custom Config Directory

```bash
export ESP_CONFIG_DIR=my_config
cargo build
```

## Profile Comparison

### File Processing

| Setting | Development | Testing | Production |
|---------|-------------|---------|------------|
| `max_file_size` | 100 MB | 10 MB | 1 MB |
| `large_file_threshold` | 5 MB | 512 KB | 1 MB |
| `max_line_count_for_analysis` | 500,000 | 50,000 | 100,000 |

### Lexical Analysis

| Setting | Development | Testing | Production |
|---------|-------------|---------|------------|
| `max_string_size` | 2 MB | 512 KB | 1 MB |
| `max_identifier_length` | 512 | 256 | 255 |
| `max_token_count` | 5,000,000 | 500,000 | 1,000,000 |

### Syntax Parsing

| Setting | Development | Testing | Production |
|---------|-------------|---------|------------|
| `max_parse_depth` | 200 | 50 | 100 |
| `max_error_history` | 100 | 75 | 50 |
| `max_lookahead_tokens` | 20 | 15 | 10 |

### Symbol Management

| Setting | Development | Testing | Production |
|---------|-------------|---------|------------|
| `max_global_symbols` | 100,000 | 25,000 | 50,000 |
| `max_local_symbols_per_ctn` | 5,000 | 2,000 | 1,000 |
| `max_symbol_relationships` | 500,000 | 200,000 | 100,000 |

### Security

| Setting | Development | Testing | Production |
|---------|-------------|---------|------------|
| `memory_alert_threshold` | 1 GB | 250 MB | 500 MB |
| `max_processing_time_seconds` | 1800 (30 min) | 120 (2 min) | 300 (5 min) |
| `max_concurrent_operations` | 200 | 50 | 100 |

### Batch Processing

| Setting | Development | Testing | Production |
|---------|-------------|---------|------------|
| `max_worker_threads` | 16 | 4 | 8 |
| `max_files_per_batch` | 5,000 | 500 | 1,000 |
| `max_batch_memory` | 2 GB | 500 MB | 1 GB |

## Configuration Sections

### `[file_processing]`

Controls file I/O limits:
- `max_file_size` - Maximum ESP file size in bytes
- `large_file_threshold` - Threshold for "large file" optimizations
- `max_line_count_for_analysis` - Line limit for complexity analysis

### `[lexical]`

Controls tokenization limits:
- `max_string_size` - Maximum string literal size
- `max_identifier_length` - Maximum identifier length
- `max_token_count` - Maximum tokens per file
- `max_string_nesting_depth` - Maximum nested string depth

### `[syntax]`

Controls parsing limits:
- `max_parse_depth` - Maximum AST depth
- `max_error_history` - Errors to retain for recovery
- `max_lookahead_tokens` - Parser lookahead buffer

### `[symbols]`

Controls symbol table limits:
- `max_global_symbols` - Global symbol table capacity
- `max_local_symbols_per_ctn` - Per-CTN local symbols
- `max_symbol_relationships` - Total relationship tracking

### `[references]`

Controls reference resolution:
- `max_reference_depth` - Maximum reference chain depth
- `max_cycle_length` - Maximum cycle detection length
- `max_dependency_nodes` - Dependency graph size

### `[semantic]`

Controls semantic analysis:
- `max_semantic_errors` - Error collection limit
- `max_set_operation_operands` - SET operand count
- `max_runtime_operation_parameters` - RUN parameter count

### `[structural]`

Controls structural validation:
- `max_nesting_depth` - CRI block nesting depth
- `max_criteria_blocks` - Total CRI blocks per definition
- `max_symbols_per_definition` - Symbols per DEF block

### `[batch_processing]`

Controls parallel processing:
- `max_worker_threads` - Thread pool size
- `max_files_per_batch` - Files per batch operation
- `max_batch_memory` - Memory limit for batch processing

### `[security]`

Controls security boundaries:
- `memory_alert_threshold` - Memory warning threshold
- `max_processing_time_seconds` - Processing timeout
- `max_concurrent_operations` - Concurrency limit
- `audit_log_buffer_size` - Audit log capacity

### `[logging]`

Controls logging system:
- `log_buffer_size` - Log buffer capacity
- `max_error_collection` - Errors to collect per file
- `security_min_log_level` - Minimum log level (SSDF requirement)
- `audit_log_retention_buffer` - Audit trail size

## SSDF Compliance

All profiles maintain SSDF (Secure Software Development Framework) compliance:

| Practice | Implementation |
|----------|----------------|
| **PW.7.1** (Input Validation) | File size, token count, nesting depth limits |
| **PW.8.1** (DoS Protection) | Memory thresholds, timeouts, concurrency limits |
| **PW.3.1** (Audit Logging) | `security_min_log_level`, `audit_log_retention_buffer` |
| **RV.1** (Monitoring) | `memory_alert_threshold`, processing time limits |

## Build Script Validation

The compiler's `build.rs` enforces absolute maximum values:

```rust
// Absolute limits (cannot be exceeded in any profile)
const ABSOLUTE_MAX_FILE_SIZE: u64 = 1_000_000_000;      // 1GB
const ABSOLUTE_MAX_MEMORY: u64 = 10_000_000_000;        // 10GB
const ABSOLUTE_MAX_PROCESSING_TIME: u64 = 3600;         // 1 hour

// Production-specific limits
if profile == "production" {
    assert!(max_file_size <= 50_000_000);               // 50MB
    assert!(max_processing_time_seconds <= 600);        // 10 minutes
}
```

## Adding a New Profile

1. Create `config/my_profile.toml` with all required sections
2. Build with `ESP_BUILD_PROFILE=my_profile cargo build`
3. Ensure values stay within absolute limits enforced by `build.rs`

## Related Documentation

- [compiler README](../compiler/README.md) - Build system details
- [common/config README](../common/config/README.md) - Runtime preferences
