# Contract Kit

Reference implementation library for ESP (Endpoint State Policy) compliance scanning.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Module Reference](#module-reference)
- [Usage](#usage)
- [Creating a Scanner](#creating-a-scanner)
- [Extending with Custom CTN Types](#extending-with-custom-ctn-types)
- [Related Documentation](#related-documentation)

## Overview

Contract Kit (`contract_kit`) demonstrates how to build scanners using `agent_core`. It provides:

- **Reference Implementations**: Working collectors and executors for common CTN types
- **High-Level API**: Simplified `agent_core_api` for scan execution
- **CTN Contracts**: Interface specifications for each CTN type
- **Platform Commands**: Secure command execution with whitelisting

This crate serves as both a usable library and a template for building custom scanners.

### Relationship to Other Crates

```
┌─────────────────────────────────────────────────────────────┐
│                      Your Scanner                           │
│  (uses contract_kit or implements agent_core directly)      │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                     contract_kit                            │
│  • Reference collectors/executors                           │
│  • agent_core_api (high-level interface)                    │
│  • Example contracts and commands                           │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                      agent_core                             │
│  • Resolution engine                                        │
│  • Execution engine                                         │
│  • Strategy framework (traits, registry)                    │
└────────────────────────────┬────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                       compiler                              │
│  • ESP parsing and validation                               │
│  • AST generation                                           │
└─────────────────────────────────────────────────────────────┘
```

## Architecture

### Component Flow

```
ESP File (.esp)
      │
      ▼
┌─────────────────┐
│  agent_core_api │  scan_file() / scan_ast()
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│    Registry     │  Maps CTN types → collector/executor pairs
└────────┬────────┘
         │
    ┌────┴────┐
    ▼         ▼
┌───────┐ ┌───────┐
│Collect│ │Execute│
│ data  │→│validat│
└───────┘ └───────┘
    │         │
    └────┬────┘
         ▼
   ScanResult
```

### Contract-Based Design

Each CTN type has three components:

| Component | Purpose | Location |
|-----------|---------|----------|
| **Contract** | Interface specification (required fields, operations) | `contracts/` |
| **Collector** | Gathers data from the system | `collectors/` |
| **Executor** | Validates collected data against states | `executors/` |

## Module Reference

### `agent_core_api`

High-level API that abstracts compiler, agent_core, and common into simple functions.

```rust
use contract_kit::agent_core_api::{scan_file, scan_ast, ScanError};

// Scan a file
let result = scan_file("policy.esp", registry)?;

// Scan pre-compiled AST
let result = scan_ast(&ast, registry)?;

// With logging
let result = scan_file_with_logging("policy.esp", registry)?;

// Helper functions
if is_compliant(&result) {
    println!("{}", format_summary(&result));
}
```

**Key Functions:**

| Function | Description |
|----------|-------------|
| `scan_file(path, registry)` | Compile and scan an ESP file |
| `scan_ast(ast, registry)` | Scan a pre-compiled AST |
| `scan_file_with_logging(path, registry)` | Scan with progress logging |
| `compile_file(path)` | Compile without executing |
| `extract_metadata(ast)` | Get policy metadata |
| `is_compliant(result)` | Check pass/fail |
| `pass_rate(result)` | Get percentage (0-100) |
| `format_summary(result)` | One-line summary |
| `format_report(result)` | Detailed report |

---

### `contracts`

CTN contract definitions specifying interface requirements.

```rust
use contract_kit::contracts::create_file_metadata_contract;

let contract = create_file_metadata_contract();
// contract.object_requirements - required/optional object fields
// contract.state_requirements - supported state fields and operations
// contract.field_mappings - ESP names → collected data names
```

See `contracts/` for reference implementations.

---

### `collectors`

Data collection implementations.

```rust
use contract_kit::collectors::{FileSystemCollector, CommandCollector};

// File system collector (metadata, content, JSON)
let fs_collector = FileSystemCollector::new();

// Command-based collector (with whitelisted executor)
let cmd_collector = CommandCollector::new("my-collector", command_executor);
```

**Reference Collectors:**

| Collector | Data Sources |
|-----------|--------------|
| `FileSystemCollector` | File metadata, content, JSON |
| `CommandCollector` | System commands (rpm, systemctl, etc.) |
| `ComputedValuesCollector` | Pass-through for RUN results |

See `collectors/` for additional implementations.

---

### `executors`

Validation logic implementations.

```rust
use contract_kit::executors::FileMetadataExecutor;

let executor = FileMetadataExecutor::new(contract);
```

**Reference Executors:**

| Executor | Validates |
|----------|-----------|
| `FileMetadataExecutor` | Permissions, owner, group, size |
| `FileContentExecutor` | String operations on file content |
| `JsonRecordExecutor` | Structured JSON with field paths |
| `RpmPackageExecutor` | Package installation and versions |
| `SystemdServiceExecutor` | Service active/enabled status |
| `SysctlParameterExecutor` | Kernel parameters |
| `SelinuxStatusExecutor` | SELinux enforcement mode |

See `executors/` for additional implementations.

---

### `commands`

Platform-specific command whitelists.

```rust
use contract_kit::commands::create_rhel9_command_executor;

let executor = create_rhel9_command_executor();
// Whitelisted: rpm, systemctl, sysctl, getenforce, etc.
```

**Security Features:**
- Whitelist-only command execution
- Timeout enforcement
- No shell expansion
- Cleared environment variables

## Usage

### Basic Scan

```rust
use contract_kit::agent_core_api::{
    scan_file, CtnStrategyRegistry, ScanError,
};
use std::sync::Arc;

fn main() -> Result<(), ScanError> {
    // Create registry with your strategies
    let registry = Arc::new(create_my_registry()?);

    // Scan
    let result = scan_file("policy.esp", registry)?;

    // Check result
    if result.tree_passed {
        println!("Compliance check passed!");
    } else {
        println!("Failed: {} findings", result.findings.len());
        for finding in &result.findings {
            println!("  - {}: {}", finding.finding_id, finding.title);
        }
    }

    Ok(())
}
```

### Building a Registry

```rust
use contract_kit::agent_core_api::CtnStrategyRegistry;
use contract_kit::collectors::FileSystemCollector;
use contract_kit::executors::FileMetadataExecutor;
use contract_kit::contracts::create_file_metadata_contract;

fn create_my_registry() -> Result<CtnStrategyRegistry, ScanError> {
    let mut registry = CtnStrategyRegistry::new();

    // Register file_metadata CTN type
    let contract = create_file_metadata_contract();
    registry.register_ctn_strategy(
        Box::new(FileSystemCollector::new()),
        Box::new(FileMetadataExecutor::new(contract)),
    )?;

    // Register additional CTN types...

    Ok(registry)
}
```

### Using Pre-compiled AST

```rust
use contract_kit::agent_core_api::{scan_ast, compile_file};

// Compile once
let ast = compile_file("policy.esp")?;

// Scan multiple times (e.g., on different hosts)
let result = scan_ast(&ast, registry.clone())?;
```

## Creating a Scanner

To build a scanner using contract_kit:

1. **Add dependency:**
   ```toml
   [dependencies]
   contract_kit = { path = "../contract_kit" }
   ```

2. **Create registry with needed CTN types:**
   ```rust
   use contract_kit::agent_core_api::CtnStrategyRegistry;
   use contract_kit::collectors::*;
   use contract_kit::executors::*;
   use contract_kit::contracts::*;

   fn create_registry() -> CtnStrategyRegistry {
       let mut registry = CtnStrategyRegistry::new();

       // Add strategies for your target CTN types
       // ...

       registry
   }
   ```

3. **Scan policies:**
   ```rust
   use contract_kit::agent_core_api::scan_file;

   let result = scan_file("policy.esp", Arc::new(registry))?;
   ```

## Extending with Custom CTN Types

To add a new CTN type:

### 1. Define Contract

```rust
// my_contracts.rs
use agent_core::strategies::{CtnContract, ObjectFieldSpec, StateFieldSpec};

pub fn create_my_ctn_contract() -> CtnContract {
    let mut contract = CtnContract::new("my_ctn_type".to_string());

    // Required object fields
    contract.object_requirements.add_required_field(ObjectFieldSpec {
        name: "target".to_string(),
        data_type: DataType::String,
        description: "Target to check".to_string(),
        ..Default::default()
    });

    // Supported state fields
    contract.state_requirements.add_optional_field(StateFieldSpec {
        name: "status".to_string(),
        data_type: DataType::String,
        allowed_operations: vec![Operation::Equals, Operation::NotEqual],
        ..Default::default()
    });

    contract
}
```

### 2. Implement Collector

```rust
// my_collector.rs
use agent_core::strategies::{CtnDataCollector, CollectedData, CollectionError};

pub struct MyCollector;

impl CtnDataCollector for MyCollector {
    fn collector_id(&self) -> &str { "my-collector" }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["my_ctn_type".to_string()]
    }

    fn collect(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
    ) -> Result<CollectedData, CollectionError> {
        // Gather data from system
        let mut data = CollectedData::new(object.id.clone());
        data.set_field("status", ResolvedValue::String("active".into()));
        Ok(data)
    }
}
```

### 3. Implement Executor

```rust
// my_executor.rs
use agent_core::strategies::{CtnExecutor, CtnExecutionResult, CtnExecutionError};

pub struct MyExecutor {
    contract: CtnContract,
}

impl CtnExecutor for MyExecutor {
    fn executor_id(&self) -> &str { "my-executor" }

    fn ctn_type(&self) -> &str { "my_ctn_type" }

    fn execute_with_contract(
        &self,
        criterion: &ExecutableCriterion,
        collected_data: &HashMap<String, CollectedData>,
        contract: &CtnContract,
    ) -> Result<CtnExecutionResult, CtnExecutionError> {
        // Validate collected data against states
        // Use helpers from agent_core::execution
        todo!()
    }
}
```

### 4. Register Strategy

```rust
registry.register_ctn_strategy(
    Box::new(MyCollector),
    Box::new(MyExecutor::new(create_my_ctn_contract())),
)?;
```

See the existing implementations in `collectors/` and `executors/` for complete examples.

## Related Documentation

- [agent_core](../agent_core/README.md) - Core execution framework
- [compiler](../compiler/README.md) - ESP parsing and validation
- [common](../common/README.md) - Shared types (AST, logging, results)
- [EBNF Grammar](../docs/EBNF.md) - ESP language specification
- [Scanner Development Guide](./Scanner_Development_Guide.md) - Detailed extension guide

## License

See repository root for license information.
