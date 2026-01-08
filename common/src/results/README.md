# Common Crate

Shared types and utilities for the ESP (Endpoint State Policy) compiler and scanner ecosystem.

This crate provides foundational types used across the ESP toolchain: AST nodes, source location tracking, logging infrastructure, configuration management, result types, metadata handling, and FIPS 140-3 compliant cryptography.

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
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                       │
│  │ results  │  │ metadata │  │  crypto  │                       │
│  │          │  │          │  │          │                       │
│  │Attestation│ │MetaData  │  │ SHA-256  │                       │
│  │FullResult│  │Block     │  │ FIPS 140 │                       │
│  │ Envelope │  │          │  │          │                       │
│  └──────────┘  └──────────┘  └──────────┘                       │
└─────────────────────────────────────────────────────────────────┘
```

## Installation

```toml
[dependencies]
common = { path = "../common" }

# With full results support
common = { path = "../common", features = ["full-results"] }
```

---

## Modules

### ast

Abstract Syntax Tree types corresponding to the ESP EBNF grammar.

```rust
use common::ast::{EspFile, StateDefinition, ObjectDefinition, CriteriaNode};

let file: EspFile = parse(source)?;

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

let pos = Position::new(42, 3, 10);  // offset, line, column
let span = Span::new(start_pos, end_pos);
let map = SourceMap::new(source);
println!("{}", map.format_error(&span, "syntax error"));
```

Key types: `Position`, `Span`, `Spanned<T>`, `SourceMap`

---

### logging

Thread-safe global logging with cargo-style error reporting.

```rust
use common::{log_error, log_info, log_success};
use common::logging::{self, codes};

logging::init_global_logging()?;

log_error!(codes::lexical::INVALID_CHARACTER, "Unexpected character",
    "char" => '€',
    "line" => 42
);

logging::print_cargo_style_summary();
```

Key types: `LogEvent`, `Code`, `ErrorCollector`, `LoggingService`

---

### config

Compile-time security constants and runtime preferences.

```rust
use common::config::{compile_time, runtime::RuntimeConfig};

if tokens.len() > compile_time::lexical::MAX_TOKEN_COUNT {
    return Err("Too many tokens");
}

let config = RuntimeConfig::default();
```

Key types: `compile_time::*` constants, `RuntimeConfig`, `LoggingPreferences`

---

### metadata

Metadata block handling for ESP policies.

```rust
use common::metadata::MetaDataBlock;

let meta = MetaDataBlock::from_fields(fields);
println!("Policy: {}", meta.policy_id().unwrap());
println!("Platform: {}", meta.platform().unwrap());

for field in meta.missing_required_fields() {
    eprintln!("Missing: {}", field);
}
```

Required META fields for attestations:

| Field | Description | Example |
|-------|-------------|---------|
| `esp_scan_id` | Unique policy identifier | `tcp-ports-check` |
| `platform` | Target platform | `linux`, `kubernetes` |
| `criticality` | Severity level | `critical`, `high`, `medium`, `low`, `info` |
| `control_mapping` | Framework mappings | `CIS:2.1,NIST-800-53:CM-7` |

---

### results

Feature-gated scan result types for secure output handling.

#### Security Model

| Mode | Contains CUI | Network Safe | Use Case |
|------|--------------|--------------|----------|
| Attestations | No | Yes | Transport to compliance servers |
| Full Results | Yes | No | Local audit trails, debugging |

#### Common Types (always available)

| Type | Description |
|------|-------------|
| `Outcome` | `Pass`, `Fail`, `Error`, `Unknown` |
| `Criticality` | `Critical`, `High`, `Medium`, `Low`, `Info` |
| `Weight` | Posture scoring weight (0.0 - 1.0) |
| `CriteriaCounts` | Pass/fail/error counts |
| `ControlMapping` | Framework reference (e.g., `NIST-800-53:AC-6`) |
| `PolicyOutcome` | Core policy evaluation data |
| `ExecutionEnvelope` | Wrapper with agent/host/timestamp metadata |
| `ExecutionSummary` | Aggregate statistics with posture score |
| `Evidence` | Raw collected data container |
| `PolicyIdentity` | CUI-free policy identification |

#### Envelope Types

The `ExecutionEnvelope` provides metadata about WHO ran WHAT, WHERE, and WHEN:

```rust
use common::results::{ExecutionEnvelope, AgentInfo, HostInfo};

let agent = AgentInfo::new("agent-001", "esp-scanner", "0.1.0", "cli");
let host = HostInfo::from_system();  // Auto-detects hostname, OS, arch

let envelope = ExecutionEnvelope::new("result-123", agent, host)
    .with_content_hash("sha256:abc123...");
```

**HostInfo fields:**
- `hostname` - System hostname
- `os` - Operating system
- `arch` - CPU architecture
- `fqdn` - Fully qualified domain name (optional)
- `asset_id` - CMDB asset identifier (optional)

**AgentInfo fields:**
- `id` - Agent instance identifier
- `name` - Agent name
- `version` - Agent version
- `agent_type` - Type: `cli`, `daemon`, `controller`

#### Attestations (default feature)

```rust
use common::results::{AttestationBuilder, Outcome, CriteriaCounts};

let mut builder = AttestationBuilder::new("agent-001", "controller");
builder.add_check(&metadata, Outcome::Pass, counts)?;
let attestation = builder.build()?;
let json = attestation.to_json()?;
```

#### Full Results (opt-in feature)

```rust
use common::results::full::{FullResultBuilder, HostContext, UserContext};

let host = HostContext::from_system();
let user = UserContext::from_environment();
let mut builder = FullResultBuilder::new("scan-001", host, user);

builder.add_policy(&metadata, outcome, counts, findings, evidence)?;
let result = builder.build();
```

#### Criticality Weights

| Criticality | Default Weight |
|-------------|----------------|
| Critical | 1.0 |
| High | 0.8 |
| Medium | 0.5 |
| Low | 0.2 |
| Info | 0.1 |

---

### results::crypto

**FIPS 140-3 compliant** cryptographic hashing with platform-native backends.

```rust
use common::results::{hash_content, sha256_hash, verify_hash};

// Hash serializable content (canonical JSON + SHA-256)
let hash = hash_content(&my_struct)?;

// Hash raw bytes
let digest = sha256_hash(b"hello world")?;

// Verify content against expected hash
let valid = verify_hash(&my_struct, &expected_hash)?;
```

| Platform | Backend | Notes |
|----------|---------|-------|
| Windows | CNG (BCrypt) | Built into Windows 10/11/Server 2016+ |
| Linux/Unix | OpenSSL | Requires FIPS-validated installation |

The crypto module is **always available** regardless of feature flags.

---

## Feature Flags

| Feature | Default | Description |
|---------|---------|-------------|
| `attestation` | ✅ | Network-safe result types |
| `full-results` | ❌ | Complete results with evidence |

```toml
# Both modes
common = { path = "../common", features = ["full-results"] }
```

---

## Platform Support

| Platform | Cryptography | Notes |
|----------|--------------|-------|
| Linux | OpenSSL | Requires OpenSSL development libraries |
| macOS | OpenSSL | Requires OpenSSL via Homebrew |
| Windows | CNG (BCrypt) | Built-in, no external dependencies |

Cross-compilation from Linux to Windows is supported without needing OpenSSL for Windows.

---

## Crate Structure

```
common/
├── src/
│   ├── lib.rs
│   ├── ast/
│   │   └── nodes.rs
│   ├── utils/
│   │   └── span.rs
│   ├── logging/
│   │   ├── codes.rs
│   │   ├── events.rs
│   │   ├── macros.rs
│   │   ├── service.rs
│   │   └── collector.rs
│   ├── config/
│   │   ├── constants.rs
│   │   └── runtime.rs
│   ├── results/
│   │   ├── error.rs
│   │   ├── envelope.rs
│   │   ├── evidence.rs
│   │   ├── identity.rs
│   │   ├── summary.rs
│   │   ├── crypto/
│   │   │   ├── canonical.rs
│   │   │   ├── openssl.rs
│   │   │   └── windows.rs
│   │   ├── common/
│   │   │   ├── outcome.rs
│   │   │   ├── criticality.rs
│   │   │   ├── counts.rs
│   │   │   ├── control.rs
│   │   │   └── policy_outcome.rs
│   │   ├── attestation/
│   │   │   ├── types.rs
│   │   │   ├── builder.rs
│   │   │   └── hashing.rs
│   │   └── full/
│   │       ├── types.rs
│   │       └── builder.rs
│   └── metadata.rs
└── README.md
```

---

## Related Crates

| Crate | Description |
|-------|-------------|
| `compiler` | ESP parser that produces AST |
| `execution_engine` | Resolution and execution framework |
| `contract_kit` | Scanner library with collectors and executors |
| `agent` | Reference CLI scanner |
