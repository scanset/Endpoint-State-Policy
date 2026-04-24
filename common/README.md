# Common Crate

Shared types and utilities for the ESP (Endpoint State Policy) compiler and scanner ecosystem.

This crate provides the foundational types used across the ESP toolchain: AST nodes, source location tracking, logging infrastructure, configuration management, result types, metadata handling, and FIPS 140-3 compliant cryptography.

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
│  ┌───────────────────────────────────┐  ┌──────────┐            │
│  │            results                │  │ metadata │            │
│  │                                   │  │          │            │
│  │ AssessorPackage │ Observation     │  │MetaData  │            │
│  │ Evidence        │ Finding         │  │Block     │            │
│  │ Envelope        │ crypto          │  │          │            │
│  │ CollectionMethod│ IdentityStatus  │  │          │            │
│  └───────────────────────────────────┘  └──────────┘            │
└─────────────────────────────────────────────────────────────────┘
```

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
common = { path = "../common" }
```

As of v2.0.0 there are no Cargo feature gates on the `results` module — the
`AssessorPackage` envelope is the only output shape and is always compiled in.


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
    // Cryptography
    results::{hash_content, verify_hash},
    // Collection traceability
    results::CollectionMethod,
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

    // Hash content for integrity verification
    let hash = hash_content(&ast)?;
    println!("Content hash: {}", hash);

    // Document collection method for traceability
    let method = CollectionMethod::file_read("/etc/passwd")
        .with_description("Read file permissions");

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

📄 [Full documentation: ESP Logging System Specification](../docs/ESP-Logging-System-v1.0.0.md)

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

📄 [Full documentation: ESP Configuration System Specification](../docs/ESP-Configuration-System-v1.0.0.md)

---

### results

Scan result types. As of v2.0.0 the crate emits exactly one output shape:
`AssessorPackage`. The previous `attestation` / `full-results` /
`assessor-evidence` feature matrix has been removed — the assessor shape
is already a superset of the others.

#### Architecture

```
ExecutionManifest (from execution_engine)
    │
    ▼ ResultBuilder::build_assessor_package
    │
    ▼
AssessorPackage
    ├── envelope (ResultEnvelope)
    │   ├── host              (polymorphic HostInfo)
    │   ├── observations[]    (first-class evidence)
    │   ├── identity_status   (PKI bootstrap status)
    │   └── signature         (certificate_chain + transparency)
    ├── summary
    └── policies[]
        ├── identity
        ├── outcome
        ├── weight
        ├── findings[]
        └── observation_refs[]
```

#### Usage

```rust
use common::results::{
    ResultBuilder, AssessorInput, Criticality, Outcome, IdentityStatus,
};

let builder = ResultBuilder::from_system("esp-agent");
let identity_status = IdentityStatus::disabled("unsigned:agent:host-abc");

let policies = vec![
    AssessorInput::new("policy-1", "linux", Criticality::High, vec![], Outcome::Pass)
        .with_findings(findings)
        .with_evidence(evidence),
];

let package = builder.build_assessor_package(
    policies,
    manifest.replay_hash,
    identity_status,
)?;
```

Key types: `Outcome`, `Criticality`, `Weight`, `CriteriaCounts`, `ResultCounts`,
`ControlMapping`, `PolicyIdentity`, `ResultEnvelope`, `Evidence`, `Observation`,
`CollectionMethod`, `ComplianceFinding`, `IdentityStatus`, `ResultBuilder`,
`AssessorInput`, `AssessorPackage`, `AssessorPolicyResult`, `CollectionCommand`,
`ReproducibilityInfo`.

---

### results::CollectionMethod

Assessor-grade evidence traceability for documenting how data was collected.

```rust
use common::results::CollectionMethod;

// Command execution
let method = CollectionMethod::command("rpm", "-qa openssl")
    .with_description("Query RPM database for package");

// API call
let method = CollectionMethod::api("/api/v1/pods", "kube-system")
    .with_description("Kubernetes API query");

// Direct file read
let method = CollectionMethod::file_read("/etc/passwd")
    .with_description("Read file metadata");

// Computed/derived value (no system collection)
let method = CollectionMethod::computed()
    .with_description("Value computed from RUN operation");
```

**Method Types:**

| Method | Constructor | Use Case |
|--------|-------------|----------|
| `Command` | `CollectionMethod::command(cmd, target)` | System command execution (`stat`, `rpm`, `kubectl`) |
| `Api` | `CollectionMethod::api(endpoint, resource)` | REST/gRPC API calls |
| `FileRead` | `CollectionMethod::file_read(path)` | Direct file access, `/proc/*` reads |
| `Computed` | `CollectionMethod::computed()` | Derived/calculated values, RUN operation outputs |

**Builder Methods:**

| Method | Description |
|--------|-------------|
| `with_description(desc)` | Add human-readable description of collection |

**Integration with CollectedData:**

```rust
use common::results::CollectionMethod;
use execution_engine::strategies::CollectedData;

let mut data = CollectedData::new(
    object.identifier.clone(),
    "file_metadata".to_string(),
    "file_collector".to_string(),
);

// Document how evidence was gathered
let method = CollectionMethod::command("stat", &path)
    .with_description("File metadata via stat command");
data.set_method(method);

// Check if method is recorded
if data.has_method() {
    // Method available for assessor reporting
}
```

---

### results::crypto

**FIPS 140-3 compliant** cryptographic hashing with platform-native backends.

```rust
use common::results::{hash_content, sha256_hash, hex_encode};

// Hash serializable content (canonical JSON + SHA-256)
let hash = hash_content(&my_struct)?;

// Hash raw bytes
let digest = sha256_hash(b"hello world")?;

// Encode/decode hex strings
let hex_string = hex_encode(&bytes);
let bytes = hex_decode(&hex_string)?;
```

| Platform | Backend | Certification |
|----------|---------|---------------|
| **Windows** | Windows CNG (BCrypt) | FIPS 140-3 certified (built into Windows 10/11/Server 2016+) |
| **Linux/Unix** | OpenSSL FIPS provider | FIPS 140-3 certified |

The crypto module is **always available** regardless of feature flags and automatically selects the appropriate backend at compile time. This enables cross-compilation to Windows without bundling OpenSSL.

Key types: `HashingError`

Key functions: `hash_content()`, `sha256_hash()`, `hex_encode()`, `hex_decode()`

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
| `platform` | Target platform | `linux`, `Kubernetes`, `Windows` |
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

// Results types (always available)
use common::results::{Outcome, Criticality, CollectionMethod, Evidence};

// Crypto functions
use common::results::{hash_content, sha256_hash, hex_encode, hex_decode};
```

## Feature Flags

None. As of v2.0.0 the `results` module has no Cargo features — the
`AssessorPackage` envelope is the only output shape and is always compiled in.
See `CHANGELOG [2.0.0]` for the rationale behind removing the previous
`attestation` / `full-results` / `assessor-evidence` matrix.

## Platform Support

| Platform | Cryptography | Notes |
|----------|--------------|-------|
| Linux | OpenSSL | Requires OpenSSL development libraries |
| macOS | OpenSSL | Requires OpenSSL (via Homebrew or similar) |
| Windows | CNG (BCrypt) | Built-in, no external dependencies |

Cross-compilation from Linux to Windows is supported without needing OpenSSL for Windows.

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
│   │   ├── mod.rs               # Re-exports (unconditional)
│   │   ├── error.rs             # ResultError type
│   │   ├── common/              # Shared types (Outcome, Criticality, etc.)
│   │   ├── collection_method.rs # CollectionMethod for traceability
│   │   ├── envelope.rs          # ResultEnvelope, AgentInfo, HostInfo
│   │   ├── evidence.rs          # Evidence, CollectionRecord
│   │   ├── finding.rs           # ComplianceFinding, FindingBuilder
│   │   ├── identity.rs          # PolicyIdentity
│   │   ├── identity_status.rs   # IdentityStatus (PKI bootstrap state)
│   │   ├── observation.rs       # Observation, ObservationRef (v2.0.0)
│   │   ├── summary.rs           # ScanSummary, ExecutionSummary
│   │   ├── transparency.rs      # TransparencyProof, InclusionProof
│   │   ├── builder.rs           # ResultBuilder + AssessorInput
│   │   ├── assessor.rs          # AssessorPackage + AssessorPackageBuilder
│   │   └── crypto/              # FIPS 140-3 compliant hashing
│   │       ├── mod.rs           # Platform-agnostic interface
│   │       ├── canonical.rs     # Canonical JSON serialization
│   │       ├── openssl.rs       # Linux/Unix backend
│   │       └── windows.rs       # Windows CNG backend
│   └── metadata.rs              # MetaDataBlock
└── README.md
```

## Related Crates

| Crate | Description |
|-------|-------------|
| `compiler` | ESP parser that produces AST |
| `execution_engine` | Execution engine with CTN strategies |

## License

See repository root for license information.
