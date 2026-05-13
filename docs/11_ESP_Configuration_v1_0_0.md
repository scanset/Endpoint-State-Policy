# ESP v1.0.0 — Configuration System

**Version:** 1.0.0
**Status:** Normative
**Last Updated:** 2026-01-09

---

## 1. Overview

This document specifies the configuration system for ESP v1.0.0, defining the two-layer architecture that separates security-critical boundaries from user experience preferences.

### 1.1 Core Principle

> Security boundaries are immutable at runtime. User preferences are flexible.

ESP configuration is split into two distinct layers:

| Layer | Purpose | Modifiable At |
|-------|---------|---------------|
| **Compile-Time Constants** | Security boundaries, resource limits | Build time only |
| **Runtime Preferences** | User experience, logging, analysis options | Execution time |

### 1.2 Design Goals

| Goal | Implementation |
|------|----------------|
| **Security by default** | Conservative limits baked into binary |
| **DoS protection** | Resource exhaustion boundaries enforced |
| **Auditability** | Configuration source traceable via build info |
| **Flexibility** | Runtime preferences for operational tuning |
| **SSDF compliance** | Alignment with secure development practices |

---

## 2. Two-Layer Architecture

### 2.1 Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         BUILD TIME                                          │
│                                                                             │
│  ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────────┐   │
│  │  Profile TOML   │────▶│    build.rs     │────▶│   constants.rs      │   │
│  │  (selected by   │     │  (validation +  │     │   (generated code)  │   │
│  │   env var)      │     │   generation)   │     │                     │   │
│  └─────────────────┘     └─────────────────┘     └──────────┬──────────┘   │
│                                                              │              │
│         ESP_BUILD_PROFILE=production                         │              │
│         ESP_CONFIG_DIR=/path/to/profiles                     │              │
│                                                              ▼              │
│                                                   ┌─────────────────────┐   │
│                                                   │   Final Binary      │   │
│                                                   │   (constants baked) │   │
│                                                   └─────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────────┐
│                         RUNTIME                                             │
│                                                                             │
│  ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────────┐   │
│  │  Environment    │────▶│  RuntimeConfig  │────▶│   Application       │   │
│  │  Variables      │     │  (preferences)  │     │   Behavior          │   │
│  │  ESP_*          │     │                 │     │                     │   │
│  └─────────────────┘     └─────────────────┘     └─────────────────────┘   │
│                                                                             │
│         ESP_LOGGING_MIN_LEVEL=debug                                         │
│         ESP_SYMBOLS_DETAILED_RELATIONSHIPS=true                             │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Security Guarantee

Compile-time constants cannot be modified at runtime. This ensures:

- Security boundaries cannot be bypassed by configuration changes
- DoS protection limits are enforced regardless of runtime environment
- Audit logging minimums cannot be disabled
- Resource limits are predictable and verifiable

---

## 3. Build Profiles

### 3.1 Profile Selection

Profiles are selected at build time via environment variables:

| Variable | Purpose | Default |
|----------|---------|---------|
| `ESP_BUILD_PROFILE` | Selects the profile name | `development` |
| `ESP_CONFIG_DIR` | Path to profile directory | Implementation-defined |

```bash
# Select production profile
export ESP_BUILD_PROFILE=production
cargo build --release

# Use custom profile directory
export ESP_CONFIG_DIR=/path/to/my/profiles
export ESP_BUILD_PROFILE=custom
cargo build
```

### 3.2 Premade Profiles

ESP provides three premade profiles optimized for different use cases:

| Profile | Purpose | Characteristics |
|---------|---------|-----------------|
| **development** | Local development and debugging | Relaxed limits, verbose logging, extended timeouts |
| **testing** | CI/CD and automated testing | Moderate limits, enhanced error collection, faster timeouts |
| **production** | Production deployment | Conservative limits, security-optimized, strict boundaries |

### 3.3 Profile Requirements

All profiles MUST define values for every configuration category. The build system validates that:

1. All required sections are present
2. Values are within absolute maximum bounds
3. Security-critical minimums are maintained
4. Type constraints are satisfied

### 3.4 Custom Profiles

Consumers MAY create custom profiles by:

1. Creating a TOML file with all required sections
2. Setting `ESP_CONFIG_DIR` to the directory containing the profile
3. Setting `ESP_BUILD_PROFILE` to the profile name (filename without `.toml`)

Custom profiles MUST NOT exceed absolute maximum values enforced by the build system.

### 3.5 Consumer Guidance

When building ESP or dependent crates:

| Scenario | Recommendation |
|----------|----------------|
| Local development | Use `development` profile (default) |
| CI/CD pipelines | Set `ESP_BUILD_PROFILE=testing` |
| Production builds | Set `ESP_BUILD_PROFILE=production` explicitly |
| Custom requirements | Create custom profile, set `ESP_CONFIG_DIR` |

**Important:** Consumers SHOULD explicitly set `ESP_BUILD_PROFILE` for production builds rather than relying on defaults.

---

## 4. Compile-Time Constants

Compile-time constants define security boundaries that cannot be modified at runtime. All constants are organized into categories aligned with compiler pipeline stages.

### 4.1 File Processing

Controls file I/O boundaries to prevent resource exhaustion during file loading.

| Constant | Purpose | SSDF Practice |
|----------|---------|---------------|
| `MAX_FILE_SIZE` | Maximum ESP file size allowed | PW.7.1, PW.8.1 |
| `LARGE_FILE_THRESHOLD` | Threshold for large file optimizations | Performance |
| `MAX_LINE_COUNT_FOR_ANALYSIS` | Maximum lines for complexity analysis | PW.8.1 |
| `PERFORMANCE_LOG_BUFFER_SIZE` | Buffer size for performance metrics | Resource |

### 4.2 Lexical Analysis

Controls tokenization limits to prevent DoS via malformed input.

| Constant | Purpose | SSDF Practice |
|----------|---------|---------------|
| `MAX_STRING_SIZE` | Maximum string literal size | PW.7.1, PW.8.1 |
| `MAX_IDENTIFIER_LENGTH` | Maximum identifier length | PW.7.1 |
| `MAX_COMMENT_LENGTH` | Maximum comment length | PW.8.1 |
| `MAX_TOKEN_COUNT` | Maximum tokens per file | PW.8.1 |
| `METRICS_BUFFER_SIZE` | Buffer for lexical metrics | Resource |
| `MAX_STRING_NESTING_DEPTH` | Maximum nested string depth | PW.8.1 |

### 4.3 Syntax Analysis

Controls parser limits to prevent stack overflow and algorithmic complexity attacks.

| Constant | Purpose | SSDF Practice |
|----------|---------|---------------|
| `MAX_PARSE_DEPTH` | Maximum parser recursion depth | PW.8.1 |
| `MAX_ERROR_HISTORY` | Error history buffer size | Resource |
| `MAX_CONTEXT_STACK_DEPTH` | Context stack for error reporting | Resource |
| `MAX_RECOVERY_SCAN_TOKENS` | Tokens examined during error recovery | Performance |
| `MAX_LOOKAHEAD_TOKENS` | Parser lookahead buffer size | Performance |

### 4.4 Symbol Management

Controls symbol table limits to prevent memory exhaustion.

| Constant | Purpose | SSDF Practice |
|----------|---------|---------------|
| `MAX_GLOBAL_SYMBOLS` | Maximum global symbol count | PW.8.1 |
| `MAX_LOCAL_SYMBOLS_PER_CTN` | Maximum local symbols per CTN scope | PW.8.1 |
| `MAX_SYMBOL_RELATIONSHIPS` | Maximum relationship tracking | PW.8.1 |
| `MAX_SYMBOL_IDENTIFIER_LENGTH` | Maximum symbol identifier length | PW.7.1 |
| `MAX_SYMBOL_CONTEXT_DEPTH` | Context depth for symbol collection | Resource |
| `MAX_ELEMENTS_PER_SYMBOL` | Maximum elements (states/objects) per symbol | PW.8.1 |
| `MAX_CTN_SCOPES` | Maximum CTN scopes allowed | Resource |

### 4.5 Reference Resolution

Controls reference validation to prevent infinite loops and graph explosion.

| Constant | Purpose | SSDF Practice |
|----------|---------|---------------|
| `MAX_REFERENCE_DEPTH` | Maximum reference chain depth | PW.8.1 |
| `MAX_REFERENCES_PER_SYMBOL` | Maximum references per symbol | PW.8.1 |
| `MAX_REPORTED_CYCLES` | Maximum cycles to report | Resource |
| `MAX_CYCLE_LENGTH` | Maximum cycle length to analyze | PW.8.1 |
| `MAX_DEPENDENCY_NODES` | Maximum dependency graph nodes | PW.8.1 |
| `MAX_RELATIONSHIPS_PER_PASS` | Maximum relationships per validation pass | PW.8.1 |

### 4.6 Semantic Analysis

Controls semantic validation limits.

| Constant | Purpose | SSDF Practice |
|----------|---------|---------------|
| `MAX_SEMANTIC_ERRORS` | Maximum semantic errors to collect | PW.8.1 |
| `MAX_RUNTIME_OPERATION_PARAMETERS` | Maximum RUN operation parameters | PW.7.1, PW.8.1 |
| `MAX_SET_OPERATION_OPERANDS` | Maximum SET operation operands | PW.8.1 |
| `MAX_ERROR_MESSAGE_LENGTH` | Maximum error message length | PW.8.1 |
| `MAX_CYCLE_PATH_LENGTH` | Maximum cycle path length to report | PW.8.1 |
| `MAX_FILTER_STATE_REFERENCES` | Maximum filter state references | PW.8.1 |

### 4.7 Structural Validation

Controls structural analysis limits.

| Constant | Purpose | SSDF Practice |
|----------|---------|---------------|
| `MAX_SYMBOLS_PER_DEFINITION` | Maximum symbols per DEF block | PW.8.1 |
| `MAX_NESTING_DEPTH` | Maximum block nesting depth | PW.8.1 |
| `MAX_CRITERIA_BLOCKS` | Maximum CRI blocks per definition | PW.8.1 |
| `MAX_SET_OPERANDS` | Maximum SET operands (structural) | PW.8.1 |
| `MAX_VARIABLES_PER_DEFINITION` | Maximum variables per DEF | PW.8.1 |
| `MAX_STATES_PER_DEFINITION` | Maximum states per DEF | PW.8.1 |
| `MAX_OBJECTS_PER_DEFINITION` | Maximum objects per DEF | PW.8.1 |

### 4.8 Batch Processing

Controls parallel processing limits.

| Constant | Purpose | SSDF Practice |
|----------|---------|---------------|
| `MAX_WORKER_THREADS` | Maximum worker thread count | Resource |
| `MAX_FILES_PER_BATCH` | Maximum files per batch operation | PW.8.1 |
| `MAX_BATCH_MEMORY` | Maximum memory for batch processing | Resource |

### 4.9 Security

Controls security monitoring and enforcement.

| Constant | Purpose | SSDF Practice |
|----------|---------|---------------|
| `MEMORY_ALERT_THRESHOLD` | Memory usage warning threshold | RV.1 |
| `MAX_PROCESSING_TIME_SECONDS` | Maximum processing time per file | PW.8.1 |
| `AUDIT_LOG_BUFFER_SIZE` | Audit log buffer capacity | PW.3.1 |
| `MAX_CONCURRENT_OPERATIONS` | Maximum concurrent operations | PW.8.1 |

### 4.10 Logging

Controls logging system limits.

| Constant | Purpose | SSDF Practice |
|----------|---------|---------------|
| `MAX_ERROR_COLLECTION` | Maximum errors to collect per file | PW.8.1 |
| `LOG_BUFFER_SIZE` | Log buffer capacity | PW.8.1 |
| `MAX_LOG_MESSAGE_LENGTH` | Maximum log message length | PW.8.1 |
| `MAX_LOG_EVENTS_PER_FILE` | Maximum log events per file | PW.8.1 |
| `MAX_CONCURRENT_LOG_OPERATIONS` | Maximum concurrent log operations | Resource |
| `SECURITY_MIN_LOG_LEVEL` | Minimum log level for security events | PW.3.1 |
| `AUDIT_LOG_RETENTION_BUFFER` | Audit log retention size | PW.3.1 |

---

## 5. Runtime Preferences

Runtime preferences are configured via environment variables and can be customized per execution without rebuilding. All environment variables use the `ESP_` prefix.

### 5.1 File Processing Preferences

| Variable | Default | Description |
|----------|---------|-------------|
| `ESP_REQUIRE_ESP_EXTENSION` | `false` | Require `.esp` file extension |
| `ESP_ENABLE_PERFORMANCE_LOGGING` | `true` | Enable performance metrics collection |
| `ESP_LOG_NON_ESP_PROCESSING` | `false` | Log processing of non-ESP files |
| `ESP_INCLUDE_COMPLEXITY_METRICS` | `true` | Include complexity scores in output |

### 5.2 Lexical Preferences

| Variable | Default | Description |
|----------|---------|-------------|
| `ESP_LEXICAL_DETAILED_METRICS` | `true` | Collect detailed token metrics |
| `ESP_LEXICAL_INCLUDE_ALL_TOKENS` | `false` | Include whitespace/comments in counts |
| `ESP_LEXICAL_LOG_STRING_STATS` | `false` | Log string length statistics |
| `ESP_LEXICAL_TRACK_OPERATORS` | `false` | Track operator usage patterns |
| `ESP_LEXICAL_INCLUDE_POSITIONS` | `true` | Include positions in error messages |

### 5.3 Symbol Preferences

| Variable | Default | Description |
|----------|---------|-------------|
| `ESP_SYMBOLS_DETAILED_RELATIONSHIPS` | `true` | Collect detailed relationship info |
| `ESP_SYMBOLS_TRACK_CROSS_REFS` | `false` | Track cross-reference statistics |
| `ESP_SYMBOLS_VALIDATE_NAMING` | `false` | Validate naming conventions |
| `ESP_SYMBOLS_INCLUDE_USAGE_METRICS` | `true` | Include usage metrics in output |
| `ESP_SYMBOLS_LOG_RELATIONSHIP_WARNINGS` | `true` | Log relationship addition warnings |
| `ESP_SYMBOLS_ANALYZE_DEPENDENCY_CHAINS` | `true` | Analyze dependency chains |

### 5.4 Reference Validation Preferences

| Variable | Default | Description |
|----------|---------|-------------|
| `ESP_REFERENCES_ENABLE_CYCLE_DETECTION` | `true` | Enable cycle detection |
| `ESP_REFERENCES_LOG_VALIDATION_DETAILS` | `false` | Log detailed validation steps |
| `ESP_REFERENCES_INCLUDE_CYCLE_DESCRIPTIONS` | `true` | Include cycle descriptions in output |
| `ESP_REFERENCES_CONTINUE_AFTER_CYCLES` | `false` | Continue validation after finding cycles |
| `ESP_REFERENCES_VALIDATE_TYPES` | `true` | Validate reference type consistency |

### 5.5 Semantic Preferences

| Variable | Default | Description |
|----------|---------|-------------|
| `ESP_SEMANTIC_COMPREHENSIVE_TYPE_CHECKING` | `true` | Enable comprehensive type checking |
| `ESP_SEMANTIC_VALIDATE_RUNTIME_CONSTRAINTS` | `true` | Validate runtime operation constraints |
| `ESP_SEMANTIC_CHECK_SET_SEMANTICS` | `true` | Check SET operation semantics |
| `ESP_SEMANTIC_ANALYZE_CYCLES` | `true` | Analyze dependency cycles |
| `ESP_SEMANTIC_DETAILED_ERROR_CONTEXT` | `true` | Include detailed error context |

### 5.6 Structural Preferences

| Variable | Default | Description |
|----------|---------|-------------|
| `ESP_STRUCTURAL_ADVANCED_CONSISTENCY_CHECKS` | `true` | Enable advanced consistency checks |
| `ESP_STRUCTURAL_LOG_DETAILED_METRICS` | `false` | Log detailed structural metrics |
| `ESP_STRUCTURAL_INCLUDE_COMPLEXITY_BREAKDOWN` | `true` | Include complexity breakdown |
| `ESP_STRUCTURAL_VALIDATE_RECOMMENDATIONS` | `false` | Validate structural recommendations |
| `ESP_STRUCTURAL_ANALYZE_QUALITY_PATTERNS` | `false` | Analyze structural quality patterns |

### 5.7 Logging Preferences

| Variable | Default | Description |
|----------|---------|-------------|
| `ESP_LOGGING_USE_STRUCTURED` | `false` | Use JSON structured logging |
| `ESP_LOGGING_ENABLE_CONSOLE` | `false` | Enable console output |
| `ESP_LOGGING_MIN_LEVEL` | `info` | Minimum log level (see 5.9) |
| `ESP_LOGGING_LOG_PERFORMANCE` | `true` | Log performance events |
| `ESP_LOGGING_LOG_SECURITY` | `true` | Log security metrics |
| `ESP_LOGGING_CARGO_STYLE` | `true` | Use cargo-style error output |
| `ESP_LOGGING_INCLUDE_FILE_CONTEXT` | `true` | Include file context in messages |

### 5.8 Execution Engine Preferences

| Variable | Default | Description |
|----------|---------|-------------|
| `ESP_CTN_TIMEOUT_SECS` | `600` | Per-criterion collection timeout (seconds). Bounds the wall-clock time `execute_single_criterion` will wait for setup + collection + filtering before failing the criterion. The 600s default suits agentless and cloud-control-plane channels where per-OBJECT round-trips can carry 15–30s of cloud API overhead. Set to a smaller value (e.g. `30`) for agent-mode-only deployments where every collection is a local subprocess. Parsed as `u64`; falls back to the default on parse failure or absence. Introduced in v2.2.1. |

### 5.9 Log Levels

The `ESP_LOGGING_MIN_LEVEL` variable accepts:

| Value | Aliases | Numeric |
|-------|---------|---------|
| `error` | `ERROR` | `0` |
| `warning` | `warn`, `WARN`, `WARNING` | `1` |
| `info` | `INFO` | `2` |
| `debug` | `DEBUG` | `3` |

**Note:** Security events are always logged regardless of this setting. The compile-time constant `SECURITY_MIN_LOG_LEVEL` enforces a minimum that cannot be overridden.

---

## 6. SSDF Alignment

The configuration system aligns with NIST Secure Software Development Framework practices:

### 6.1 Practice Mapping

| SSDF Practice | Description | Configuration Implementation |
|---------------|-------------|------------------------------|
| **PW.7.1** | Input Validation | File size limits, identifier length limits, parameter count limits |
| **PW.8.1** | DoS Protection | Token limits, nesting depth, timeout enforcement, memory boundaries |
| **PW.3.1** | Audit Logging | `SECURITY_MIN_LOG_LEVEL`, `AUDIT_LOG_RETENTION_BUFFER` |
| **RV.1** | Monitoring | `MEMORY_ALERT_THRESHOLD`, processing time limits |

### 6.2 Security Invariants

The following invariants are maintained across all profiles:

| Invariant | Enforcement |
|-----------|-------------|
| Security logging cannot be disabled | `SECURITY_MIN_LOG_LEVEL` is compile-time |
| Audit trail is always maintained | `AUDIT_LOG_RETENTION_BUFFER` minimum enforced |
| Resource limits are always active | All limits are compile-time constants |
| Timeouts cannot be infinite | `MAX_PROCESSING_TIME_SECONDS` has absolute maximum |

---

## 7. Build System Integration

### 7.1 Build Script Validation

The build system (`build.rs`) performs validation before generating constants:

1. **Profile existence** — Selected profile file must exist
2. **Section completeness** — All required sections must be present
3. **Value bounds** — Values must be within absolute maximums
4. **Type correctness** — Values must match expected types
5. **Security minimums** — Security-critical values must meet minimums

### 7.2 Absolute Maximums

The build system enforces absolute maximum values that no profile can exceed:

| Category | Absolute Maximum | Purpose |
|----------|------------------|---------|
| File size | 1 GB | Prevent extreme memory allocation |
| Memory threshold | 10 GB | Prevent system exhaustion |
| Processing time | 1 hour | Prevent infinite processing |
| Token count | 10 million | Prevent token explosion |

### 7.3 Generated Output

The build system generates a `constants.rs` file containing:

```rust
pub mod compile_time {
    pub mod file_processing {
        pub const MAX_FILE_SIZE: u64 = /* from profile */;
        // ...
    }
    pub mod lexical {
        pub const MAX_STRING_SIZE: usize = /* from profile */;
        // ...
    }
    // ... all categories
}
```

### 7.4 Build Information

Build metadata is available at runtime:

| Function | Returns |
|----------|---------|
| `build_info::profile()` | Name of selected profile |
| `build_info::config_dir()` | Path to configuration directory |
| `build_info::source_info()` | Full path to source TOML |

---

## 8. Usage Patterns

### 8.1 Accessing Compile-Time Constants

```rust
use common::config::compile_time;

fn validate_file(size: u64) -> Result<(), Error> {
    if size > compile_time::file_processing::MAX_FILE_SIZE {
        return Err(Error::FileTooLarge);
    }
    Ok(())
}

fn check_tokens(count: usize) -> bool {
    count <= compile_time::lexical::MAX_TOKEN_COUNT
}
```

### 8.2 Accessing Runtime Preferences

```rust
use common::config::runtime::RuntimeConfig;

fn process(config: &RuntimeConfig) {
    if config.logging.use_structured_logging {
        // Use JSON output
    }

    if config.references.enable_cycle_detection {
        // Perform cycle detection
    }
}
```

### 8.3 Combining Both Layers

```rust
use common::config::{compile_time, runtime::RuntimeConfig};

fn analyze(tokens: &[Token], prefs: &RuntimeConfig) -> Result<(), Error> {
    // Security boundary (compile-time)
    if tokens.len() > compile_time::lexical::MAX_TOKEN_COUNT {
        return Err(Error::TooManyTokens);
    }

    // User preference (runtime)
    if prefs.lexical.collect_detailed_metrics {
        collect_metrics(tokens);
    }

    Ok(())
}
```

### 8.4 Environment Configuration Examples

```bash
# Development environment
export ESP_BUILD_PROFILE=development
export ESP_LOGGING_MIN_LEVEL=debug
export ESP_LOGGING_CARGO_STYLE=true

# CI/CD environment
export ESP_BUILD_PROFILE=testing
export ESP_LOGGING_USE_STRUCTURED=true
export ESP_REFERENCES_LOG_VALIDATION_DETAILS=true

# Production environment
export ESP_BUILD_PROFILE=production
export ESP_LOGGING_MIN_LEVEL=warning
export ESP_LOGGING_USE_STRUCTURED=true
```

---

## 9. Relationship to Trust Model

This specification implements the configuration trust boundaries defined in the ESP Trust Model (Section 6, N-21).

### 9.1 Trust Model Reference

The Trust Model establishes that:

> ESP configuration is split into two layers with different trust levels... Security boundaries cannot be relaxed at runtime.

### 9.2 Implementation Mapping

| Trust Model Requirement | Configuration Implementation |
|-------------------------|------------------------------|
| Security-critical limits at compile time | `compile_time` module constants |
| Cannot be changed at runtime | Constants baked into binary |
| Operational tuning within bounds | `runtime` module preferences |
| Cannot exceed compile-time limits | Preferences don't affect limits |

---

## 10. Validation Rules

### 10.1 Profile Validation

| Rule | Enforcement |
|------|-------------|
| All sections present | Build fails if section missing |
| All values within bounds | Build fails if value exceeds maximum |
| Security minimums met | Build fails if below minimum |
| Types correct | Build fails on type mismatch |

### 10.2 Runtime Validation

| Rule | Enforcement |
|------|-------------|
| Invalid env var values | Fall back to default |
| Log level below security minimum | Security minimum prevails |
| Unknown env var | Ignored |

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-01-09 | Initial specification |
