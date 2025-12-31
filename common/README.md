# Common Crate

Shared types and utilities for the ESP (Endpoint State Policy) compiler and scanner ecosystem.

This crate provides the foundational types used across the ESP toolchain: AST nodes, source location tracking, logging infrastructure, configuration management, result types, and metadata handling.

## Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                         common                                   │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌──────────┐           │
│  │   ast   │  │  utils  │  │ logging │  │  config  │           │
│  │         │  │         │  │         │  │          │           │
│  │ EspFile │  │ Position│  │ LogEvent│  │ compile_ │           │
│  │ State   │  │ Span    │  │ Code    │  │ time     │           │
│  │ Object  │  │ Spanned │  │ macros  │  │ runtime  │           │
│  │ Criteria│  │ SourceMap│ │ Collector│ │          │           │
│  └─────────┘  └─────────┘  └─────────┘  └──────────┘           │
│                                                                  │
│  ┌──────────┐  ┌──────────┐                                     │
│  │ results  │  │ metadata │                                     │
│  │          │  │          │                                     │
│  │Attestation│ │MetaData  │                                     │
│  │FullResult│  │Block     │                                     │
│  └──────────┘  └──────────┘                                     │
└─────────────────────────────────────────────────────────────────┘
```

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
common = { path = "../common" }

# With full results support
common = { path = "../common", features = ["full-results"] }
```

## Quick Start

```rust
use common::{
    // AST types
    EspFile, DataType, Operation, Value,
    // Location tracking
    Position, Span, SourceMap,
    // Logging
    log_error, log_info, log_success,
    logging::{self, codes},
    // Metadata
    metadata::MetaDataBlock,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize logging
    logging::init_global_logging()?;

    // Parse and work with AST
    let ast: EspFile = parse_file("policy.esp")?;

    // Access metadata
    if let Some(meta) = &ast.metadata {
        println!("Policy: {}", meta.policy_id().unwrap_or("unknown"));
    }

    // Log events
    log_info!("Processing policy", "file" => "policy.esp");

    Ok(())
}
```

## Modules

### ast

Abstract Syntax Tree types corresponding to the ESP EBNF grammar.

```rust
use common::ast::{EspFile, StateDefinition, ObjectDefinition, CriteriaNode};

// Root node contains metadata + definition
let file: EspFile = parse(source)?;

// Access components
for state in &file.definition.states {
    println!("State: {}", state.id);
}
```

Key types: `EspFile`, `DefinitionNode`, `StateDefinition`, `ObjectDefinition`, `CriteriaNode`, `CriterionNode`, `DataType`, `Operation`, `Value`

📄 [Full documentation](ast/README.md)

---

### utils

Source location tracking for error reporting.

```rust
use common::{Position, Span, SourceMap};

// Track positions in source
let pos = Position::new(42, 3, 10);  // offset, line, column

// Create spans for ranges
let span = Span::new(start_pos, end_pos);

// Format errors with context
let map = SourceMap::new(source);
println!("{}", map.format_error(&span, "syntax error"));
```

Key types: `Position`, `Span`, `Spanned<T>`, `SourceMap`

📄 [Full documentation](utils/README.md)

---

### logging

Thread-safe global logging with cargo-style error reporting.

```rust
use common::{log_error, log_info, log_success};
use common::logging::{self, codes};

// Initialize once
logging::init_global_logging()?;

// Log with typed error codes
log_error!(codes::lexical::INVALID_CHARACTER, "Unexpected character",
    "char" => '€',
    "line" => 42
);

log_success!(codes::success::FILE_PROCESSING_SUCCESS, "Done");

// Cargo-style summary
logging::print_cargo_style_summary();
```

Key types: `LogEvent`, `Code`, `ErrorCollector`, `LoggingService`

📄 [Full documentation](logging/README.md)

---

### config

Compile-time security constants and runtime preferences.

```rust
use common::config::{compile_time, runtime::RuntimeConfig};

// Security limits (compile-time enforced)
if tokens.len() > compile_time::lexical::MAX_TOKEN_COUNT {
    return Err("Too many tokens");
}

// User preferences (runtime, from env vars)
let config = RuntimeConfig::default();
if config.logging.use_structured_logging {
    // Use JSON output
}
```

Key types: `compile_time::*` constants, `RuntimeConfig`, `LoggingPreferences`

📄 [Full documentation](config/README.md)

---

### results

Feature-gated scan result types for secure output handling.

```rust
use common::results::{AttestationBuilder, Outcome, CriteriaCounts};

// Build attestation (safe for network transport)
let mut builder = AttestationBuilder::new("agent-001", "scanner");
builder.add_check(&metadata, Outcome::Pass, counts)?;
let attestation = builder.build()?;
```

Features:
- `attestation` (default) - Network-safe output without system details
- `full-results` - Complete evidence for local storage

Key types: `ScanAttestation`, `CheckAttestation`, `Outcome`, `Criticality`

📄 [Full documentation](results/README.md)

---

### metadata

Metadata block handling for ESP policies.

```rust
use common::metadata::MetaDataBlock;

// Access policy metadata
let meta = MetaDataBlock::from_fields(fields);

// Required fields for attestations
assert!(meta.has_required_fields());
println!("Policy: {}", meta.policy_id().unwrap());
println!("Platform: {}", meta.platform().unwrap());
println!("Criticality: {}", meta.criticality().unwrap());

// Check for missing fields
for field in meta.missing_required_fields() {
    eprintln!("Missing: {}", field);
}
```

Required fields for scanner attestations:

| Field | Description | Example |
|-------|-------------|---------|
| `esp_scan_id` | Unique policy identifier | `tcp-ports-check` |
| `platform` | Target platform | `linux`, `Kubernetes` |
| `criticality` | Severity level | `critical`, `high`, `medium`, `low` |
| `control_mapping` | Compliance framework mappings | `CIS:2.1,NIST-800-53:CM-7` |

---

## Re-exports

The crate re-exports common types at the root level for convenience:

```rust
// These are equivalent:
use common::EspFile;
use common::ast::nodes::EspFile;

// Location types
use common::{Position, Span, SourceMap, Spanned};
use common::utils::{Position, Span, SourceMap, Spanned};
```

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `attestation` | ✅ | Network-safe result types |
| `full-results` | ❌ | Complete results with evidence |

Enable features in `Cargo.toml`:

```toml
# Both modes
common = { path = "../common", features = ["full-results"] }
```

## Crate Structure

```
common/
├── Cargo.toml
├── src/
│   ├── lib.rs          # Crate root, re-exports
│   ├── ast/
│   │   ├── mod.rs
│   │   └── nodes.rs    # All AST node types
│   ├── utils/
│   │   ├── mod.rs
│   │   └── span.rs     # Position, Span, SourceMap
│   ├── logging/
│   │   ├── mod.rs      # Global state, initialization
│   │   ├── codes.rs    # Error code registry
│   │   ├── events.rs   # LogEvent structure
│   │   ├── macros.rs   # log_error!, log_info!, etc.
│   │   ├── service.rs  # Logger implementations
│   │   ├── collector.rs # Batch error collection
│   │   └── config.rs   # Logging configuration
│   ├── config/
│   │   ├── mod.rs
│   │   ├── constants.rs # Compile-time limits
│   │   └── runtime.rs   # Runtime preferences
│   ├── results/
│   │   ├── mod.rs       # Feature-gated exports
│   │   ├── common/      # Shared types
│   │   ├── attestation/ # Network-safe output
│   │   └── full/        # Complete results
│   └── metadata.rs      # MetaDataBlock
└── README.md
```

## Related Crates

| Crate | Description |
|-------|-------------|
| `compiler` | ESP parser that produces AST |
| `agent_core` | Execution engine that consumes AST |
| `contract_kit` | Scanner library with collectors and executors |

## License

See repository root for license information.
