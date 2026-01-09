# Contract Development Guide

A complete guide for implementing custom compliance scanners using the ESP framework.

---

## Table of Contents

1. [Overview](#overview)
2. [Quick Start: Hello CTN](#quick-start-hello-ctn)
3. [Architecture](#architecture)
4. [Getting Started](#getting-started)
5. [Creating a CTN Contract](#creating-a-ctn-contract)
6. [Implementing a Collector](#implementing-a-collector)
7. [Implementing an Executor](#implementing-an-executor)
8. [Registering Your Contract](#registering-your-contract)
9. [Command Execution](#command-execution)
10. [Advanced Features](#advanced-features)
11. [Testing](#testing)
12. [Best Practices](#best-practices)

---

## Overview

The ESP framework provides the infrastructure for building compliance scanners. The framework handles:

- ESP parsing and validation (`compiler`)
- Resolution and execution orchestration (`execution_engine`)
- Result generation and reporting (`common/results`)

**You implement:**

- **CTN Contracts** — Define what your scanner validates
- **Collectors** — Gather data from the system
- **Executors** — Validate collected data against ESP states

### Threat Model for Scanner Authors

ESP protects against several classes of threats. Understanding these helps you write secure scanners:

| Threat | ESP Protection | Your Responsibility |
|--------|----------------|---------------------|
| Resource exhaustion | Timeout enforcement, batch limits | Set appropriate timeouts on all I/O |
| Shell injection | No shell execution, whitelist-only commands | Use `SystemCommandExecutor`, never spawn shells |
| Sensitive evidence leakage | Attestation mode strips CUI | Avoid over-collection, respect contract scope |
| Non-deterministic results | Contract validation, typed values | Return consistent typed values |
| Privilege escalation | Capability declarations | Declare `requires_elevated_privileges` accurately |
| Environment variable leakage | Sandboxed execution | Explicitly declare required env vars |

### Result Modes and Scanner Design

ESP supports two result modes that affect how you design collectors:

- **Attestation mode** (default): Only policy outcomes are transmitted. Collected evidence stays local. Design collectors to gather what's needed for validation without storing sensitive data in results.

- **Full results mode**: Expected/actual values included for audit. If your scanner collects sensitive fields (passwords, keys, PII), document this clearly and consider filtering before adding to `CollectedData`.

---

## What is a CTN?

A **CTN (Criterion Type Node)** is the fundamental unit of compliance checking in ESP. Each CTN type represents a specific kind of resource you want to validate — files, packages, services, kernel parameters, etc. When you write `CTN file_metadata` in an ESP policy, you're invoking a registered CTN type that knows how to collect and validate file metadata. Creating a new scanner means defining a new CTN type with its contract (what fields it accepts), collector (how to gather data), and executor (how to validate against expected states).

---

## Quick Start: Hello CTN

Here's a minimal working example — a scanner that checks if a file exists:

```rust
// contracts/hello.rs
use execution_engine::strategies::{
    CtnContract, ObjectFieldSpec, StateFieldSpec,
    CollectionMode, CollectionStrategy, PerformanceHints,
};
use execution_engine::types::common::{DataType, Operation};

pub fn create_hello_contract() -> CtnContract {
    let mut contract = CtnContract::new("hello_file".to_string());

    // One required object field
    contract.object_requirements.add_required_field(ObjectFieldSpec {
        name: "path".to_string(),
        data_type: DataType::String,
        description: "File path to check".to_string(),
        example_values: vec!["/etc/passwd".to_string()],
        validation_notes: None,
    });

    // One state field
    contract.state_requirements.add_optional_field(StateFieldSpec {
        name: "exists".to_string(),
        data_type: DataType::Boolean,
        allowed_operations: vec![Operation::Equals],
        description: "Whether file exists".to_string(),
        example_values: vec!["true".to_string()],
        validation_notes: None,
    });

    // Field mappings
    contract.field_mappings.collection_mappings.required_data_fields =
        vec!["exists".to_string()];
    contract.field_mappings.validation_mappings.state_to_data
        .insert("exists".to_string(), "exists".to_string());

    // Collection strategy
    contract.collection_strategy = CollectionStrategy {
        collector_type: "filesystem".to_string(),
        collection_mode: CollectionMode::Metadata,
        required_capabilities: vec![],
        performance_hints: PerformanceHints::default(),
    };

    contract
}
```

```rust
// collectors/hello.rs
use execution_engine::execution::BehaviorHints;
use execution_engine::strategies::{CollectedData, CollectionError, CtnContract, CtnDataCollector};
use execution_engine::types::common::ResolvedValue;
use execution_engine::types::execution_context::ExecutableObject;
use std::path::Path;

pub struct HelloCollector;

impl CtnDataCollector for HelloCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        _contract: &CtnContract,
        _hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        // Extract path from object
        let path = object.get_field_value("path")
            .and_then(|v| v.as_string())
            .ok_or_else(|| CollectionError::InvalidObjectConfiguration {
                object_id: object.identifier.clone(),
                reason: "Missing 'path' field".to_string(),
            })?;

        let mut data = CollectedData::new(
            object.identifier.clone(),
            "hello_file".to_string(),
            "hello_collector".to_string(),
        );

        // Check if file exists
        let exists = Path::new(&path).exists();
        data.add_field("exists".to_string(), ResolvedValue::Boolean(exists));

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["hello_file".to_string()]
    }

    fn collector_id(&self) -> &str { "hello_collector" }

    fn validate_ctn_compatibility(&self, contract: &CtnContract) -> Result<(), CollectionError> {
        if contract.ctn_type != "hello_file" {
            return Err(CollectionError::CtnContractValidation {
                reason: format!("Expected 'hello_file', got '{}'", contract.ctn_type),
            });
        }
        Ok(())
    }

    fn supports_batch_collection(&self) -> bool { false }
}
```

```rust
// executors/hello.rs
use execution_engine::execution::{evaluate_existence_check, evaluate_item_check, evaluate_state_operator};
use execution_engine::strategies::{
    CollectedData, CtnContract, CtnExecutionError, CtnExecutionResult, CtnExecutor,
    FieldValidationResult, StateValidationResult, TestPhase,
};
use execution_engine::types::common::{Operation, ResolvedValue};
use execution_engine::types::execution_context::ExecutableCriterion;
use common::results::Outcome;
use std::collections::HashMap;

pub struct HelloExecutor { contract: CtnContract }

impl HelloExecutor {
    pub fn new(contract: CtnContract) -> Self { Self { contract } }
}

impl CtnExecutor for HelloExecutor {
    fn execute_with_contract(
        &self,
        criterion: &ExecutableCriterion,
        collected_data: HashMap<String, CollectedData>,
        _contract: &CtnContract,
    ) -> Result<CtnExecutionResult, CtnExecutionError> {
        let test = &criterion.test;

        // Existence check
        let expected = criterion.expected_object_count();
        let found = collected_data.len();
        if !evaluate_existence_check(test.existence_check, found, expected) {
            return Ok(CtnExecutionResult::fail(
                "hello_file".to_string(),
                format!("Expected {} objects, found {}", expected, found),
            ).with_collected_data(collected_data));
        }

        // State validation
        let mut state_results = Vec::new();
        for (id, data) in &collected_data {
            let actual = data.get_field("exists").cloned()
                .unwrap_or(ResolvedValue::Boolean(false));

            let expected_val = criterion.states.first()
                .and_then(|s| s.fields.first())
                .map(|f| f.value.clone())
                .unwrap_or(ResolvedValue::Boolean(true));

            let passed = actual == expected_val;

            state_results.push(StateValidationResult {
                object_id: id.clone(),
                state_results: vec![FieldValidationResult {
                    field_name: "exists".to_string(),
                    expected_value: expected_val,
                    actual_value: actual,
                    operation: Operation::Equals,
                    passed,
                    message: if passed { "Passed" } else { "Failed" }.to_string(),
                }],
                combined_result: passed,
                state_operator: test.state_operator,
                message: format!("{}: {}", id, if passed { "passed" } else { "failed" }),
            });
        }

        let passing = state_results.iter().filter(|r| r.combined_result).count();
        let item_passed = evaluate_item_check(test.item_check, passing, state_results.len());

        Ok(CtnExecutionResult {
            ctn_type: "hello_file".to_string(),
            status: if item_passed { Outcome::Pass } else { Outcome::Fail },
            test_phase: TestPhase::Complete,
            state_results,
            message: format!("{}/{} passed", passing, collected_data.len()),
            collected_data,
            ..Default::default()
        })
    }

    fn get_ctn_contract(&self) -> CtnContract { self.contract.clone() }
    fn ctn_type(&self) -> &str { "hello_file" }

    fn validate_collected_data(
        &self, _: &HashMap<String, CollectedData>, _: &CtnContract,
    ) -> Result<(), CtnExecutionError> { Ok(()) }
}
```

**Register and run:**

```rust
let mut registry = CtnStrategyRegistry::new();
let contract = create_hello_contract();
registry.register_ctn_strategy(
    Box::new(HelloCollector),
    Box::new(HelloExecutor::new(contract)),
)?;

let result = scan_file("policy.esp", Arc::new(registry))?;
```

---

## Architecture

### Component Hierarchy

```
┌─────────────────────────────────────────────────────────────┐
│                    ESP Policy (.esp file)                   │
└────────────────────────────┬────────────────────────────────┘
                             │ compiler
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                      Validated AST                          │
└────────────────────────────┬────────────────────────────────┘
                             │ execution_engine
                             ▼
┌─────────────────────────────────────────────────────────────┐
│                  CtnStrategyRegistry                        │
│           Maps CTN types → (Collector, Executor)            │
└────────────────────────────┬────────────────────────────────┘
                             │
              ┌──────────────┴──────────────┐
              ▼                              ▼
┌──────────────────────┐      ┌──────────────────────┐
│     Collector        │      │      Executor        │
│    (Your Code)       │      │    (Your Code)       │
└──────────┬───────────┘      └──────────┬───────────┘
           │                              │
           │ Gathers data                 │ Validates data
           ▼                              ▼
┌──────────────────────┐      ┌──────────────────────┐
│   CollectedData      │─────▶│  CtnExecutionResult  │
└──────────────────────┘      └──────────────────────┘
```

### Three-Component Pattern

Every CTN type requires exactly three components:

| Component | Location | Purpose |
|-----------|----------|---------|
| **Contract** | `contracts/` | Interface specification |
| **Collector** | `collectors/` | Data gathering |
| **Executor** | `executors/` | Validation logic |

### Collector vs Executor Responsibilities

| Concern | Collector | Executor |
|---------|-----------|----------|
| Gather evidence from system | ✅ | ❌ |
| Validate data against states | ❌ | ✅ |
| Enforce I/O timeouts | ✅ | ✅ (for internal ops) |
| Respect contract field limits | ✅ | ✅ |
| Handle behavior hints | ✅ (modify collection) | ✅ (validate only) |
| Return typed values | ✅ | N/A |

**Capability Safety Rules:**

- Collectors must not collect more than the contract requires
- Executors must not perform additional collection
- The contract defines what is allowed — enforce this boundary

### Naming Conventions

Follow these conventions for ecosystem consistency:

| Element | Convention | Example |
|---------|------------|---------|
| CTN type names | `snake_case` | `rpm_package`, `file_metadata` |
| Object field names | `snake_case`, policy-facing | `package_name`, `file_path` |
| State field names | `snake_case`, policy-facing | `installed`, `permissions` |
| Collected data fields | `snake_case`, internal | `pkg_version`, `file_mode` |
| Object IDs | Stable unique identifiers | `sudoers_file`, `openssl_pkg` |

---

## Getting Started

### Project Structure

```
your_scanner/
├── Cargo.toml
└── src/
    ├── lib.rs                    # Registry creation
    ├── main.rs                   # CLI (optional)
    ├── registry.rs               # Strategy registration
    ├── contracts/
    │   ├── mod.rs
    │   └── your_contract.rs
    ├── collectors/
    │   ├── mod.rs
    │   └── your_collector.rs
    ├── executors/
    │   ├── mod.rs
    │   └── your_executor.rs
    └── commands/                 # Optional: command configs
        ├── mod.rs
        └── platform_config.rs
```

### Dependencies

```toml
[dependencies]
execution_engine = { path = "../execution_engine" }
compiler = { path = "../compiler" }
common = { path = "../common" }
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
```

Or use `contract_kit` for the high-level API:

```toml
[dependencies]
contract_kit = { path = "../contract_kit" }
common = { path = "../common" }
serde_json = "1.0"
```

---

## Creating a CTN Contract

A contract defines the interface for your scanner: required fields, supported operations, and behaviors.

### Contract Template

```rust
use execution_engine::strategies::{
    CtnContract, ObjectFieldSpec, StateFieldSpec,
    CollectionStrategy, CollectionMode, PerformanceHints,
    SupportedBehavior, BehaviorType, BehaviorParameter,
};
use common::ast::{DataType, Operation};

pub fn create_your_ctn_contract() -> CtnContract {
    let mut contract = CtnContract::new("your_ctn_type".to_string());

    // 1. Object requirements
    add_object_requirements(&mut contract);

    // 2. State requirements
    add_state_requirements(&mut contract);

    // 3. Field mappings
    configure_field_mappings(&mut contract);

    // 4. Collection strategy
    set_collection_strategy(&mut contract);

    // 5. Behaviors (optional)
    add_behaviors(&mut contract);

    contract
}
```

### Object Requirements

Define fields required in OBJECT blocks:

```rust
fn add_object_requirements(contract: &mut CtnContract) {
    // Required field
    contract.object_requirements.add_required_field(ObjectFieldSpec {
        name: "resource_id".to_string(),
        data_type: DataType::String,
        description: "Unique identifier".to_string(),
        example_values: vec!["web-server-01".to_string()],
        validation_notes: Some("Must be unique".to_string()),
    });

    // Optional field
    contract.object_requirements.add_optional_field(ObjectFieldSpec {
        name: "description".to_string(),
        data_type: DataType::String,
        description: "Human-readable description".to_string(),
        example_values: vec!["Primary server".to_string()],
        validation_notes: None,
    });
}
```

### State Requirements

Define fields that can be validated in STATE blocks:

```rust
fn add_state_requirements(contract: &mut CtnContract) {
    // String field with operations
    contract.state_requirements.add_optional_field(StateFieldSpec {
        name: "status".to_string(),
        data_type: DataType::String,
        allowed_operations: vec![
            Operation::Equals,
            Operation::NotEqual,
            Operation::Contains,
            Operation::PatternMatch,
        ],
        description: "Resource status".to_string(),
        example_values: vec!["running".to_string(), "stopped".to_string()],
        validation_notes: None,
    });

    // Integer field with comparisons
    contract.state_requirements.add_optional_field(StateFieldSpec {
        name: "cpu_usage".to_string(),
        data_type: DataType::Int,
        allowed_operations: vec![
            Operation::Equals,
            Operation::GreaterThan,
            Operation::LessThan,
            Operation::GreaterThanOrEqual,
            Operation::LessThanOrEqual,
        ],
        description: "CPU usage percentage".to_string(),
        example_values: vec!["50".to_string()],
        validation_notes: Some("0-100".to_string()),
    });

    // Boolean field
    contract.state_requirements.add_optional_field(StateFieldSpec {
        name: "secure".to_string(),
        data_type: DataType::Boolean,
        allowed_operations: vec![Operation::Equals, Operation::NotEqual],
        description: "Security status".to_string(),
        example_values: vec!["true".to_string()],
        validation_notes: None,
    });
}
```

### Field Mappings

Map ESP names to internal data names:

```rust
fn configure_field_mappings(contract: &mut CtnContract) {
    // Object field → collector parameter
    contract.field_mappings.collection_mappings.object_to_collection
        .insert("resource_id".to_string(), "internal_id".to_string());

    // Required data fields from collector
    contract.field_mappings.collection_mappings.required_data_fields = vec![
        "status".to_string(),
        "cpu_usage".to_string(),
    ];

    // State field → collected data field
    contract.field_mappings.validation_mappings.state_to_data
        .insert("status".to_string(), "status".to_string());
    contract.field_mappings.validation_mappings.state_to_data
        .insert("cpu_usage".to_string(), "cpu_usage".to_string());
}
```

### Behaviors

Define optional behaviors that modify collection:

```rust
fn add_behaviors(contract: &mut CtnContract) {
    // Flag behavior
    contract.add_supported_behavior(SupportedBehavior {
        name: "include_metrics".to_string(),
        behavior_type: BehaviorType::Flag,
        parameters: vec![],
        description: "Include detailed metrics".to_string(),
        example: "behavior include_metrics".to_string(),
    });

    // Parameter behavior
    contract.add_supported_behavior(SupportedBehavior {
        name: "timeout".to_string(),
        behavior_type: BehaviorType::Parameter,
        parameters: vec![BehaviorParameter {
            name: "timeout".to_string(),
            data_type: DataType::Int,
            required: true,
            default_value: Some("30".to_string()),
            description: "Timeout in seconds".to_string(),
        }],
        description: "Set request timeout".to_string(),
        example: "behavior timeout 60".to_string(),
    });
}
```

### Collection Strategy

Specify how data should be collected:

```rust
fn set_collection_strategy(contract: &mut CtnContract) {
    contract.collection_strategy = CollectionStrategy {
        collector_type: "filesystem".to_string(),
        collection_mode: CollectionMode::Content,
        required_capabilities: vec![
            "file_read".to_string(),
        ],
        performance_hints: PerformanceHints {
            expected_collection_time_ms: Some(50),
            memory_usage_mb: Some(10),
            network_intensive: false,
            cpu_intensive: false,
            requires_elevated_privileges: false,
        },
    };
}
```

**Collection Modes:**

| Mode | Use Case |
|------|----------|
| `Metadata` | File stats, permissions, ownership |
| `Content` | File contents, configuration parsing |
| `Command` | System commands (rpm, systemctl) |
| `Security` | ACLs, SELinux contexts |
| `Status` | Service state, process info |
| `Custom(String)` | Custom collection mode |

---

## Implementing a Collector

A collector gathers data from the system.

### Collector Template

```rust
use execution_engine::strategies::{
    CtnDataCollector, CtnContract, CollectedData, CollectionError,
};
use execution_engine::execution::BehaviorHints;
use execution_engine::types::execution_context::{ExecutableObject, ExecutableObjectElement};
use common::ast::ResolvedValue;
use std::collections::HashMap;

pub struct YourCollector {
    id: String,
}

impl YourCollector {
    pub fn new() -> Self {
        Self {
            id: "your_collector".to_string(),
        }
    }

    fn extract_field(
        &self,
        object: &ExecutableObject,
        field_name: &str,
    ) -> Result<String, CollectionError> {
        for element in &object.elements {
            if let ExecutableObjectElement::Field { name, value, .. } = element {
                if name == field_name {
                    match value {
                        ResolvedValue::String(s) => return Ok(s.clone()),
                        ResolvedValue::Integer(i) => return Ok(i.to_string()),
                        ResolvedValue::Boolean(b) => return Ok(b.to_string()),
                        _ => {}
                    }
                }
            }
        }
        Err(CollectionError::InvalidObjectConfiguration {
            object_id: object.identifier.clone(),
            reason: format!("Missing field '{}'", field_name),
        })
    }
}

impl CtnDataCollector for YourCollector {
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError> {
        // Validate hints against contract
        contract.validate_behavior_hints(hints).map_err(|e| {
            CollectionError::CtnContractValidation { reason: e.to_string() }
        })?;

        // Extract required object fields
        let resource_id = self.extract_field(object, "resource_id")?;

        // Check behavior flags and parameters
        let include_metrics = hints.has_flag("include_metrics");
        let timeout = hints.get_parameter_as_int("timeout").unwrap_or(30);

        // Create collected data
        let mut data = CollectedData::new(
            object.identifier.clone(),
            "your_ctn_type".to_string(),
            self.id.clone(),
        );

        // Add collected fields
        data.add_field("status".to_string(), ResolvedValue::String("running".to_string()));
        data.add_field("cpu_usage".to_string(), ResolvedValue::Integer(45));
        data.add_field("secure".to_string(), ResolvedValue::Boolean(true));

        // Conditionally add based on behavior
        if include_metrics {
            data.add_field("memory_mb".to_string(), ResolvedValue::Integer(2048));
            data.add_field("uptime_secs".to_string(), ResolvedValue::Integer(86400));
        }

        Ok(data)
    }

    fn supported_ctn_types(&self) -> Vec<String> {
        vec!["your_ctn_type".to_string()]
    }

    fn collector_id(&self) -> &str {
        &self.id
    }

    fn supports_batch_collection(&self) -> bool {
        false
    }

    fn validate_ctn_compatibility(
        &self,
        contract: &CtnContract,
    ) -> Result<(), CollectionError> {
        if !self.supported_ctn_types().contains(&contract.ctn_type) {
            return Err(CollectionError::CtnContractValidation {
                reason: format!("CTN type '{}' not supported", contract.ctn_type),
            });
        }
        Ok(())
    }
}
```

### Error Types and Semantics

Choose the correct error type — it affects TEST evaluation:

```rust
// Object cannot be located (e.g., file doesn't exist, package not installed)
// This CONTRIBUTES TO existence check evaluation
Err(CollectionError::ObjectNotFound { object_id })

// Object exists but cannot be accessed (e.g., permission denied)
// This is DISTINCT from "not found" — avoids false "nonexistent" results
Err(CollectionError::AccessDenied { object_id, reason })

// Collection operation failed (e.g., timeout, parse error)
Err(CollectionError::CollectionFailed { object_id, reason })

// Object configuration is invalid (e.g., missing required field)
Err(CollectionError::InvalidObjectConfiguration { object_id, reason })

// CTN type not supported by this collector
Err(CollectionError::UnsupportedCtnType { ctn_type, collector_id })
```

**When to use which:**

| Situation | Error Type | Effect on TEST |
|-----------|------------|----------------|
| File doesn't exist | `ObjectNotFound` | Counted as missing for existence check |
| Permission denied reading file | `AccessDenied` | Error state, object exists but inaccessible |
| Package not in RPM database | `ObjectNotFound` | Counted as missing |
| JSON parse failure | `CollectionFailed` | Error state |
| Missing `path` field in OBJECT | `InvalidObjectConfiguration` | Configuration error |

---

## Implementing an Executor

An executor validates collected data against STATE requirements.

### Executor Template

```rust
use execution_engine::strategies::{
    CtnExecutor, CtnContract, CtnExecutionResult, CtnExecutionError,
    CollectedData, FieldValidationResult, StateValidationResult, TestPhase,
};
use execution_engine::execution::{
    evaluate_existence_check, evaluate_item_check, evaluate_state_operator,
    comparisons::string,
};
use execution_engine::types::execution_context::ExecutableCriterion;
use common::ast::{Operation, ResolvedValue};
use common::results::Outcome;
use std::collections::HashMap;

pub struct YourExecutor {
    contract: CtnContract,
}

impl YourExecutor {
    pub fn new(contract: CtnContract) -> Self {
        Self { contract }
    }

    fn compare_values(
        &self,
        expected: &ResolvedValue,
        actual: &ResolvedValue,
        operation: Operation,
    ) -> bool {
        match (expected, actual, operation) {
            // String: use string::compare for all string operations
            (ResolvedValue::String(exp), ResolvedValue::String(act), op) => {
                string::compare(act, exp, op).unwrap_or(false)
            }

            // Integer comparisons
            (ResolvedValue::Integer(exp), ResolvedValue::Integer(act), Operation::Equals) => act == exp,
            (ResolvedValue::Integer(exp), ResolvedValue::Integer(act), Operation::NotEqual) => act != exp,
            (ResolvedValue::Integer(exp), ResolvedValue::Integer(act), Operation::GreaterThan) => act > exp,
            (ResolvedValue::Integer(exp), ResolvedValue::Integer(act), Operation::LessThan) => act < exp,
            (ResolvedValue::Integer(exp), ResolvedValue::Integer(act), Operation::GreaterThanOrEqual) => act >= exp,
            (ResolvedValue::Integer(exp), ResolvedValue::Integer(act), Operation::LessThanOrEqual) => act <= exp,

            // Boolean comparisons
            (ResolvedValue::Boolean(exp), ResolvedValue::Boolean(act), Operation::Equals) => act == exp,
            (ResolvedValue::Boolean(exp), ResolvedValue::Boolean(act), Operation::NotEqual) => act != exp,

            // Type mismatch or unsupported operation
            _ => false,
        }
    }
}

impl CtnExecutor for YourExecutor {
    fn execute_with_contract(
        &self,
        criterion: &ExecutableCriterion,
        collected_data: HashMap<String, CollectedData>,
        _contract: &CtnContract,
    ) -> Result<CtnExecutionResult, CtnExecutionError> {
        let test_spec = &criterion.test;

        // Phase 1: Existence check
        let expected = criterion.expected_object_count();
        let found = collected_data.len();

        let existence_passed = evaluate_existence_check(
            test_spec.existence_check,
            found,
            expected,
        );

        if !existence_passed {
            return Ok(CtnExecutionResult::fail(
                criterion.criterion_type.clone(),
                format!("Existence check failed: expected {}, found {}", expected, found),
            ).with_collected_data(collected_data));
        }

        // Phase 2: State validation
        let mut state_results = Vec::new();

        for (object_id, data) in &collected_data {
            let mut field_results = Vec::new();

            for state in &criterion.states {
                for field in &state.fields {
                    let data_field = self.contract.field_mappings
                        .validation_mappings.state_to_data
                        .get(&field.name)
                        .cloned()
                        .unwrap_or_else(|| field.name.clone());

                    let actual = data.get_field(&data_field)
                        .cloned()
                        .unwrap_or(ResolvedValue::String("".to_string()));

                    let passed = self.compare_values(&field.value, &actual, field.operation);

                    field_results.push(FieldValidationResult {
                        field_name: field.name.clone(),
                        expected_value: field.value.clone(),
                        actual_value: actual,
                        operation: field.operation,
                        passed,
                        message: if passed { "Passed".to_string() } else { "Failed".to_string() },
                    });
                }
            }

            let bools: Vec<bool> = field_results.iter().map(|r| r.passed).collect();
            let combined = evaluate_state_operator(test_spec.state_operator, &bools);

            state_results.push(StateValidationResult {
                object_id: object_id.clone(),
                state_results: field_results,
                combined_result: combined,
                state_operator: test_spec.state_operator,
                message: format!("{}: {}", object_id, if combined { "passed" } else { "failed" }),
            });
        }

        // Phase 3: Item check
        let passing = state_results.iter().filter(|r| r.combined_result).count();
        let item_passed = evaluate_item_check(test_spec.item_check, passing, state_results.len());

        // Final result
        let status = if existence_passed && item_passed {
            Outcome::Pass
        } else {
            Outcome::Fail
        };

        Ok(CtnExecutionResult {
            ctn_type: criterion.criterion_type.clone(),
            status,
            test_phase: TestPhase::Complete,
            state_results,
            message: format!("{} of {} objects compliant", passing, state_results.len()),
            collected_data,
            ..Default::default()
        })
    }

    fn get_ctn_contract(&self) -> CtnContract {
        self.contract.clone()
    }

    fn ctn_type(&self) -> &str {
        "your_ctn_type"
    }

    fn validate_collected_data(
        &self,
        _collected_data: &HashMap<String, CollectedData>,
        _contract: &CtnContract,
    ) -> Result<(), CtnExecutionError> {
        Ok(())
    }
}
```

### String Operations

Always use `string::compare()` for string operations:

```rust
use execution_engine::execution::comparisons::string;

let passed = string::compare(actual, expected, operation).unwrap_or(false);
```

**Supported Operations:**

| Operation | Description |
|-----------|-------------|
| `Operation::Equals` | Exact match |
| `Operation::NotEqual` | Not equal |
| `Operation::Contains` | Contains substring |
| `Operation::NotContains` | Does not contain |
| `Operation::StartsWith` | Starts with prefix |
| `Operation::EndsWith` | Ends with suffix |
| `Operation::NotStartsWith` | Does not start with |
| `Operation::NotEndsWith` | Does not end with |
| `Operation::CaseInsensitiveEquals` | Case-insensitive match (`ieq`) |
| `Operation::CaseInsensitiveNotEquals` | Case-insensitive not equal (`ine`) |
| `Operation::PatternMatch` | Regex pattern matching |
| `Operation::Matches` | Regex (alias for PatternMatch) |

### Version Comparisons

For semantic version comparisons:

```rust
use execution_engine::execution::comparisons::version;

// Compares using semver rules: 2.10.0 > 2.9.0
let passed = version::compare(actual, expected, operation).unwrap_or(false);
```

### EVR String Comparisons

For RPM-style epoch:version-release comparisons:

```rust
use execution_engine::execution::comparisons::evr;

// Compares epoch:version-release format (e.g., "2:1.8.0-1.el9")
let passed = evr::compare(actual, expected, operation).unwrap_or(false);
```

---

## Registering Your Scanner

### Using contract_kit (Recommended)

```rust
use contract_kit::execution_api::strategies::{CtnStrategyRegistry, StrategyError};

pub fn create_registry() -> Result<CtnStrategyRegistry, StrategyError> {
    let mut registry = CtnStrategyRegistry::new();

    let contract = create_your_ctn_contract();
    registry.register_ctn_strategy(
        Box::new(YourCollector::new()),
        Box::new(YourExecutor::new(contract)),
    )?;

    Ok(registry)
}
```

### Scanning

```rust
use contract_kit::execution_api::{scan_file, format_report};
use std::sync::Arc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let registry = Arc::new(create_registry()?);
    let result = scan_file("policy.esp", registry)?;

    println!("{}", format_report(&result));

    if !result.tree_passed {
        std::process::exit(1);
    }

    Ok(())
}
```

---

## Command Execution

Command-based collectors require careful handling of execution environment, output parsing, and type conversion.

### The Command Sandbox

Commands run in an **isolated sandbox** with these constraints:

| Constraint | Description |
|------------|-------------|
| **No inherited environment** | Parent process env vars are NOT available |
| **Whitelisted commands only** | Only explicitly allowed commands can execute |
| **No shell expansion** | No globbing, pipes, or shell features |
| **Timeout enforced** | Commands killed after timeout |
| **Restricted PATH** | Only standard system paths |

**Critical**: If your command needs environment variables, you must **explicitly provide them**.

### SystemCommandExecutor

```rust
use execution_engine::strategies::SystemCommandExecutor;
use std::time::Duration;

// Create executor with default timeout
let mut executor = SystemCommandExecutor::with_timeout(Duration::from_secs(5));

// REQUIRED: Whitelist allowed commands
executor.allow_commands(&[
    "cat",
    "stat",
    "/usr/bin/stat",  // Absolute paths also work
]);

// Execute command
let output = executor.execute(
    "stat",
    &["-c", "%a", "/etc/passwd"],
    Some(Duration::from_secs(10)),  // Per-command timeout override
)?;

if output.exit_code == 0 {
    let permissions = output.stdout.trim();
    // permissions = "644"
}
```

### Environment Variables

Commands do **NOT** inherit environment variables. You must explicitly set any required variables:

```rust
// WRONG: Assumes $HOME is available
let output = executor.execute("kubectl", &["config", "view"], None)?;
// kubectl will fail - no KUBECONFIG or HOME available!

// RIGHT: Explicitly provide required environment
// Option 1: Read and pass specific env vars
if let Ok(kubeconfig) = std::env::var("KUBECONFIG") {
    // Pass via command args if supported
    let output = executor.execute(
        "kubectl",
        &["--kubeconfig", &kubeconfig, "get", "pods", "-o", "json"],
        None,
    )?;
}

// Option 2: Use file paths directly
let kubeconfig_path = std::env::var("KUBECONFIG")
    .unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_default();
        format!("{}/.kube/config", home)
    });

if std::path::Path::new(&kubeconfig_path).exists() {
    let output = executor.execute(
        "kubectl",
        &["--kubeconfig", &kubeconfig_path, "get", "pods"],
        None,
    )?;
}
```

### Understanding Command Output

Before implementing a collector, you must understand the **exact output format** of the command you're using. Document this in your CTN type reference.

#### Example: `/proc/net/tcp` for TCP Listeners

**Raw output:**
```
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345
   1: 0100007F:0035 00000000:0000 0A 00000000:00000000 00:00000000 00000000   101        0 23456
```

**Field breakdown:**

| Field | Format | Example | Meaning |
|-------|--------|---------|---------|
| `local_address` | `IP:PORT` (hex) | `00000000:0016` | `0.0.0.0:22` |
| `st` | Hex state | `0A` | `10` = LISTEN |

**Conversion required:**
```rust
// Port: hex to decimal
let port_hex = "0016";
let port = u16::from_str_radix(port_hex, 16)?;  // 22

// IP: hex bytes in reverse order
let ip_hex = "0100007F";  // 127.0.0.1 stored as 7F 00 00 01
let bytes = hex_to_bytes(ip_hex)?;
let ip = format!("{}.{}.{}.{}", bytes[3], bytes[2], bytes[1], bytes[0]);
// ip = "127.0.0.1"

// State: 0A (10) = TCP_LISTEN
let is_listening = state_hex == "0A";
```

#### Example: `stat` for File Metadata

**Command:** `stat -c '%a %U %G %s' /etc/passwd`

**Output:** `644 root root 2845`

**Field mapping:**

| Format | Output | Type | Notes |
|--------|--------|------|-------|
| `%a` | `644` | String | Octal permissions |
| `%U` | `root` | String | Owner name |
| `%G` | `root` | String | Group name |
| `%s` | `2845` | Integer | Size in bytes |

```rust
let output = executor.execute("stat", &["-c", "%a %U %G %s", path], None)?;
let parts: Vec<&str> = output.stdout.trim().split_whitespace().collect();

// SAFE: Use .get() instead of direct indexing
let permissions = parts.get(0).map(|s| s.to_string());
let owner = parts.get(1).map(|s| s.to_string());
let group = parts.get(2).map(|s| s.to_string());
let size = parts.get(3).and_then(|s| s.parse::<i64>().ok());
```

#### Example: `kubectl get` for Kubernetes Resources

**Command:** `kubectl get pod -n kube-system -l component=kube-apiserver -o json`

**Output structure:**
```json
{
  "apiVersion": "v1",
  "kind": "PodList",
  "items": [
    {
      "metadata": { "name": "kube-apiserver-control-plane", "namespace": "kube-system" },
      "spec": {
        "containers": [{
          "name": "kube-apiserver",
          "command": ["kube-apiserver", "--authorization-mode=Node,RBAC", "..."]
        }]
      },
      "status": { "phase": "Running" }
    }
  ]
}
```

**Parsing:**
```rust
let output = executor.execute("kubectl", &["get", "pod", "-o", "json"], None)?;
let json: serde_json::Value = serde_json::from_str(&output.stdout)?;

// Handle both list and single resource responses
let items = if let Some(items) = json.get("items").and_then(|i| i.as_array()) {
    items.clone()
} else if json.get("metadata").is_some() {
    vec![json.clone()]  // Single resource
} else {
    vec![]
};

let count = items.len();
let found = !items.is_empty();
```

### Type Conversion Rules

The executor expects specific types. Document what type your collector returns:

| Source Data | ResolvedValue | Notes |
|-------------|---------------|-------|
| `"644"` (permissions) | `String` | Keep as string for pattern matching |
| `"2845"` (file size) | `Integer` | Parse to i64 for numeric comparisons |
| `"true"` / `"false"` | `Boolean` | Parse to bool |
| `"1.2.3"` (version) | `String` | Use version comparator |
| JSON object | `RecordData` | For record check validation |

```rust
// Permissions - keep as string
data.add_field("permissions".to_string(),
    ResolvedValue::String("0644".to_string()));

// Size - parse to integer for comparisons like `size int > 1000`
data.add_field("size".to_string(),
    ResolvedValue::Integer(file_size));

// Boolean - parse the string
let is_enabled = value == "1" || value.eq_ignore_ascii_case("true");
data.add_field("enabled".to_string(),
    ResolvedValue::Boolean(is_enabled));
```

### Safe Output Parsing

**Always use `.get()` instead of direct indexing:**

```rust
// WRONG: Will panic if output is malformed
let parts: Vec<&str> = output.split(':').collect();
let port = parts[1];  // PANIC if no ':'

// RIGHT: Safe access with Option
let parts: Vec<&str> = output.split(':').collect();
let port = parts.get(1).ok_or_else(|| CollectionError::CollectionFailed {
    object_id: object_id.clone(),
    reason: "Malformed output: missing port field".to_string(),
})?;
```

### Documenting Command Output

Every CTN type that uses commands should document:

1. **Command format** - Exact command and arguments
2. **Expected output** - Sample output with field positions
3. **Field mappings** - How output maps to collected data fields
4. **Type conversions** - What type each field becomes
5. **Error conditions** - What output indicates errors

See `contract_kit/docs/` for CTN type reference documentation examples.

### Platform Command Configuration

```rust
use execution_engine::strategies::SystemCommandExecutor;
use std::time::Duration;

/// Create command executor for Linux filesystem operations
pub fn create_linux_fs_executor() -> SystemCommandExecutor {
    let mut executor = SystemCommandExecutor::with_timeout(Duration::from_secs(5));

    executor.allow_commands(&[
        "stat",        // File metadata
        "cat",         // File content
        "ls",          // Directory listing
        "readlink",    // Symlink resolution
    ]);

    executor
}

/// Create command executor for Kubernetes operations
pub fn create_k8s_executor() -> SystemCommandExecutor {
    let mut executor = SystemCommandExecutor::with_timeout(Duration::from_secs(30));

    executor.allow_commands(&[
        "kubectl",
        "/usr/local/bin/kubectl",
        "/usr/bin/kubectl",
    ]);

    executor
}
```

---

## Advanced Features

### Batch Collection

Optimize by collecting multiple objects in one operation:

```rust
impl CtnDataCollector for YourCollector {
    fn supports_batch_collection(&self) -> bool {
        true
    }

    fn collect_batch(
        &self,
        objects: Vec<&ExecutableObject>,
        contract: &CtnContract,
    ) -> Result<HashMap<String, CollectedData>, CollectionError> {
        // Single API call for all objects
        let ids: Vec<String> = objects.iter()
            .filter_map(|o| self.extract_field(o, "resource_id").ok())
            .collect();

        let bulk_data = self.fetch_bulk(&ids)?;

        let mut results = HashMap::new();
        for object in objects {
            let id = self.extract_field(object, "resource_id")?;
            if let Some(item) = bulk_data.get(&id) {
                results.insert(object.identifier.clone(), item.clone());
            }
        }

        Ok(results)
    }
}
```

### Record Validation

For structured JSON/record data validation:

```rust
use execution_engine::execution::record_validation::{validate_record_checks, RecordValidationResult};
use common::ast::RecordData;

// In your executor, handle record checks
for state in &criterion.states {
    if !state.record_checks.is_empty() {
        // Get RecordData from collected data
        let record_data = match data.get_field("json_data") {
            Some(ResolvedValue::RecordData(rd)) => rd,
            _ => {
                return Err(CtnExecutionError::DataValidationFailed {
                    reason: "Expected RecordData for record checks".to_string(),
                });
            }
        };

        // Validate all record checks
        let results = validate_record_checks(record_data, &state.record_checks)
            .map_err(|e| CtnExecutionError::ExecutionFailed {
                ctn_type: criterion.criterion_type.clone(),
                reason: format!("Record validation failed: {}", e),
            })?;

        // Process results
        for result in results {
            field_results.push(FieldValidationResult {
                field_name: result.field_path.clone(),
                expected_value: result.expected.clone(),
                actual_value: result.actual.clone(),
                operation: result.operation,
                passed: result.passed,
                message: result.message.clone(),
            });
        }
    }
}
```

**Record check features:**

- Nested field access: `settings.security.enabled`
- Array index: `items.0.name` (specific element)
- Array wildcard: `users.*.role` (check all elements)
- Entity checks: `all`, `at_least_one`, `none`, `only_one`

### Filter Support

Filters are evaluated by the execution engine before collection. Your collector receives only filtered objects:

```rust
// The execution engine handles FILTER blocks automatically
// Your collector doesn't need special filter logic

// In ESP:
// SET critical_files union
//     OBJECT_REF file1
//     OBJECT_REF file2
//     FILTER include
//         STATE_REF is_large
//     FILTER_END
// SET_END

// Your collector receives only objects that passed the filter
```

### SET Operations

SET operations are expanded by the resolution engine. Your collector sees individual objects:

```rust
// In ESP:
// SET security_packages union
//     OBJECT_REF pkg1
//     OBJECT_REF pkg2
// SET_END
//
// CTN rpm_package
//     TEST all all
//     STATE_REF installed
//     OBJECT
//         SET_REF security_packages
//     OBJECT_END
// CTN_END

// Your collector receives pkg1 and pkg2 as separate collection requests
```

---

## Testing

### Unit Tests

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_collector() {
        let collector = YourCollector::new();
        assert_eq!(collector.collector_id(), "your_collector");
    }

    #[test]
    fn test_contract() {
        let contract = create_your_ctn_contract();
        assert_eq!(contract.ctn_type, "your_ctn_type");
    }

    #[test]
    fn test_comparison() {
        let contract = create_your_ctn_contract();
        let executor = YourExecutor::new(contract);

        let expected = ResolvedValue::String("running".to_string());
        let actual = ResolvedValue::String("running".to_string());

        assert!(executor.compare_values(&expected, &actual, Operation::Equals));
    }
}
```

### Integration Test

```rust
#[test]
fn test_full_scan() -> Result<(), Box<dyn std::error::Error>> {
    let registry = Arc::new(create_registry()?);
    let result = scan_file("test_policy.esp", registry)?;

    assert!(result.tree_passed);
    Ok(())
}
```

---

## Troubleshooting

### Common Issues

**ObjectNotFound vs AccessDenied confusion**

This is the most common bug in new collectors. Using the wrong error type breaks TEST evaluation:

```rust
// WRONG: File exists but we can't read it
if let Err(e) = fs::read(&path) {
    return Err(CollectionError::ObjectNotFound { object_id });  // BUG!
}

// RIGHT: Distinguish between "doesn't exist" and "can't access"
match fs::metadata(&path) {
    Ok(_) => {
        // File exists, try to read
        match fs::read(&path) {
            Ok(content) => { /* ... */ }
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
                return Err(CollectionError::AccessDenied {
                    object_id,
                    reason: "Permission denied".to_string(),
                });
            }
            Err(e) => {
                return Err(CollectionError::CollectionFailed {
                    object_id,
                    reason: e.to_string(),
                });
            }
        }
    }
    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
        return Err(CollectionError::ObjectNotFound { object_id });
    }
    Err(e) => {
        return Err(CollectionError::CollectionFailed {
            object_id,
            reason: e.to_string(),
        });
    }
}
```

**Command fails due to missing environment variable**

```rust
// WRONG: Assumes env vars are inherited
let output = executor.execute("my-tool", &["--config"], None)?;

// RIGHT: Explicitly handle required env vars
let config_path = std::env::var("MY_TOOL_CONFIG")
    .unwrap_or_else(|_| "/etc/my-tool/config.yaml".to_string());

let output = executor.execute("my-tool", &["--config", &config_path], None)?;
```

**"Field not found" errors**

The executor can't find a field in collected data.

```rust
// Problem: ESP uses "permissions", collector provides "file_mode"

// Solution: Add field mapping in contract
contract.field_mappings.validation_mappings.state_to_data
    .insert("permissions".to_string(), "file_mode".to_string());
```

**Type mismatch in comparisons**

Comparisons fail due to type differences.

```rust
// Problem: Comparing String to Integer
(ResolvedValue::String(_), ResolvedValue::Integer(_), _) => false

// Solution: Ensure collector returns correct types
// If ESP expects `size int > 1000`, collector must return Integer
data.add_field("size".to_string(), ResolvedValue::Integer(file_size));
// NOT: ResolvedValue::String(file_size.to_string())
```

**Pattern matching fails**

Regex patterns don't match expected content.

```rust
// Problem: Manual string matching
if actual.contains(expected) { ... }  // Wrong for patterns

// Solution: Use string::compare for all string operations
match string::compare(actual, expected, Operation::PatternMatch) {
    Ok(result) => result,
    Err(e) => {
        eprintln!("Pattern error: {}", e);
        false
    }
}
```

### Debug Logging

Enable debug logging to trace execution:

```bash
ESP_LOGGING_MIN_LEVEL=debug cargo run -- policy.esp
```

Add logging in your collector:

```rust
use common::logging::{log_debug, log_info, log_error};

fn collect_for_ctn_with_hints(...) -> Result<CollectedData, CollectionError> {
    log_debug!("Collecting for object: {}", object.identifier);
    log_info!("Behavior hints: {:?}", hints);

    // ... collection logic

    log_debug!("Collected {} fields", data.field_count());
    Ok(data)
}
```

---

## Best Practices

### Contract Design

✅ **Do:**
- Provide clear field descriptions and examples
- Document edge cases in validation notes
- Define behaviors for optional features
- Use `snake_case` for all field names

❌ **Don't:**
- Add unnecessary required fields
- Use vague descriptions
- Expose internal names in ESP-facing fields
- Create contracts with no state fields

### Collector Implementation

✅ **Do:**
- Handle errors with specific types (`ObjectNotFound` vs `AccessDenied`)
- Validate behavior hints against contract before using them
- Implement batch collection when beneficial (command-based, API-based)
- Set timeouts on all I/O operations
- Return typed values matching contract expectations
- Use `.get()` for safe array/slice access
- Explicitly handle required environment variables

❌ **Don't:**
- Silently ignore errors
- Make API/command calls without timeout
- Collect more than contract specifies
- Perform validation logic (that's the executor's job)
- Use direct indexing (`parts[0]`) on parsed output
- Assume environment variables are inherited

### Executor Implementation

✅ **Do:**
- Use `string::compare()` for ALL string operations
- Use framework helper functions (`evaluate_existence_check`, `evaluate_item_check`, `evaluate_state_operator`)
- Apply field mappings from contract
- Provide detailed failure messages
- Include collected_data in results

❌ **Don't:**
- Implement custom string comparison logic
- Skip field mapping lookups
- Return generic error messages
- Perform data collection (that's the collector's job)

### Security

✅ **Do:**
- Use `SystemCommandExecutor` with explicit whitelists
- Clear environment variables (done automatically)
- Declare `requires_elevated_privileges` accurately
- Document sensitive fields in contract
- Explicitly provide only needed env vars to commands

❌ **Don't:**
- Spawn shell processes
- Use string interpolation in commands
- Execute commands not in whitelist
- Collect more data than needed for validation
- Pass sensitive env vars unnecessarily

### CTN Type Documentation

✅ **Do:**
- Document exact command format and arguments
- Show sample output with field positions
- Specify type conversions (string → int, etc.)
- List error conditions and their output
- Note platform-specific behavior

---

## Checklist

### Contract
- [ ] CTN type name is unique and uses `snake_case`
- [ ] Required/optional object fields defined with clear descriptions
- [ ] State fields have allowed operations listed
- [ ] Field mappings configured (collection and validation)
- [ ] Behaviors documented with examples
- [ ] Collection strategy includes accurate performance hints

### Collector
- [ ] Implements `CtnDataCollector` trait
- [ ] Validates behavior hints against contract
- [ ] Handles all error cases with appropriate error types
- [ ] Returns mapped field names matching contract
- [ ] Returns all fields listed in contract's `required_data_fields`
- [ ] Does not exceed contract's collection scope
- [ ] Sets timeouts on I/O operations
- [ ] Uses safe indexing (`.get()`) for parsed output
- [ ] Explicitly handles required environment variables

### Executor
- [ ] Implements `CtnExecutor` trait
- [ ] Uses `string::compare()` for string operations
- [ ] Uses framework helpers for TEST evaluation
- [ ] Applies field mappings from contract
- [ ] Does not perform additional collection
- [ ] Includes collected_data in results

### Integration
- [ ] Registered in registry with matching collector/executor
- [ ] End-to-end test passing
- [ ] Example ESP file provided

### Documentation
- [ ] CTN type reference document created
- [ ] Command output format documented
- [ ] Type conversions documented
- [ ] Error conditions documented

---

## Reference Implementations

See `contract_kit/src/` for complete examples:

| Type | Contract | Collector | Executor |
|------|----------|-----------|----------|
| `file_metadata` | `contracts/file_metadata.rs` | `collectors/file_metadata.rs` | `executors/file_metadata.rs` |
| `file_content` | `contracts/file_content.rs` | `collectors/file_content.rs` | `executors/file_content.rs` |
| `json_record` | `contracts/json_record.rs` | `collectors/json_record.rs` | `executors/json_record.rs` |
| `tcp_listener` | `contracts/tcp_listener.rs` | `collectors/tcp_listener.rs` | `executors/tcp_listener.rs` |
| `k8s_resource` | `contracts/k8s_resource.rs` | `collectors/k8s_resource.rs` | `executors/k8s_resource.rs` |
| `computed_values` | `contracts/computed_values.rs` | `collectors/computed_values.rs` | `executors/computed_values.rs` |

See `contract_kit/docs/` for CTN type reference documentation.

---

## Summary

To create a new CTN type:

1. **Define Contract** — Object requirements, state requirements, field mappings, behaviors
2. **Implement Collector** — Gather data, handle behaviors, return `CollectedData`
3. **Implement Executor** — Three-phase validation (existence → state → item)
4. **Register Strategy** — Pair collector + executor in registry
5. **Document** — Create CTN type reference with command output formats
6. **Test** — Unit tests, integration tests, example ESP file

**Key Principles:**

- Contracts define the interface between ESP and your code
- Collectors gather data without validation logic
- Executors validate data without collection logic
- Field mappings decouple ESP names from internal names
- Always use `string::compare()` for string operations
- Command execution requires explicit whitelisting and timeouts
- Commands run in a sandbox — no inherited environment variables
- Document command output formats and type conversions
- Use safe indexing (`.get()`) when parsing output
