# Scanner Development Guide

A complete guide for implementing custom compliance scanners using the ESP framework.

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [Getting Started](#getting-started)
4. [Creating a CTN Contract](#creating-a-ctn-contract)
5. [Implementing a Collector](#implementing-a-collector)
6. [Implementing an Executor](#implementing-an-executor)
7. [Registering Your Scanner](#registering-your-scanner)
8. [Advanced Features](#advanced-features)
9. [Testing](#testing)
10. [Best Practices](#best-practices)

---

## Overview

The ESP framework provides the infrastructure for building compliance scanners. The framework handles:

- ESP parsing and validation (`compiler`)
- Resolution and execution orchestration (`agent_core`)
- Result generation and reporting (`common/results`)

**You implement:**

- **CTN Contracts** — Define what your scanner validates
- **Collectors** — Gather data from the system
- **Executors** — Validate collected data against ESP states

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
                             │ agent_core
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
agent_core = { path = "../agent_core" }
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
use agent_core::strategies::{
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

---

## Implementing a Collector

A collector gathers data from the system.

### Collector Template

```rust
use agent_core::strategies::{
    CtnDataCollector, CtnContract, CollectedData, CollectionError,
};
use agent_core::execution::BehaviorHints;
use agent_core::types::execution_context::ExecutableObject;
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
        // Extract field from object elements
        for element in &object.elements {
            if let ExecutableObjectElement::Field { name, value, .. } = element {
                if name == field_name {
                    if let ResolvedValue::String(s) = value {
                        return Ok(s.clone());
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
        // Validate hints
        contract.validate_behavior_hints(hints).map_err(|e| {
            CollectionError::CtnContractValidation { reason: e.to_string() }
        })?;

        // Extract object fields
        let resource_id = self.extract_field(object, "resource_id")?;

        // Check behaviors
        let include_metrics = hints.has_flag("include_metrics");
        let timeout = hints.get_parameter_as_int("timeout").unwrap_or(30);

        // Collect data
        let mut data = CollectedData::new(
            object.identifier.clone(),
            "your_ctn_type".to_string(),
            self.id.clone(),
        );

        // Add fields
        data.add_field("status".to_string(), ResolvedValue::String("running".to_string()));
        data.add_field("cpu_usage".to_string(), ResolvedValue::Integer(45));

        if include_metrics {
            data.add_field("memory_mb".to_string(), ResolvedValue::Integer(2048));
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
}
```

### Error Types

```rust
// Object not found (triggers existence check)
Err(CollectionError::ObjectNotFound { object_id })

// Access denied
Err(CollectionError::AccessDenied { object_id, reason })

// General failure
Err(CollectionError::CollectionFailed { object_id, reason })

// Invalid configuration
Err(CollectionError::InvalidObjectConfiguration { object_id, reason })
```

---

## Implementing an Executor

An executor validates collected data against STATE requirements.

### Executor Template

```rust
use agent_core::strategies::{
    CtnExecutor, CtnContract, CtnExecutionResult, CtnExecutionError,
    CollectedData, ComplianceStatus, FieldValidationResult,
    StateValidationResult, TestPhase,
};
use agent_core::execution::{
    evaluate_existence_check, evaluate_item_check, evaluate_state_operator,
    comparisons::string,
};
use agent_core::types::execution_context::ExecutableCriterion;
use common::ast::{Operation, ResolvedValue};
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
            // String: use string::compare for all operations
            (ResolvedValue::String(exp), ResolvedValue::String(act), op) => {
                string::compare(act, exp, op).unwrap_or(false)
            }

            // Integer comparisons
            (ResolvedValue::Integer(exp), ResolvedValue::Integer(act), Operation::Equals) => {
                act == exp
            }
            (ResolvedValue::Integer(exp), ResolvedValue::Integer(act), Operation::GreaterThan) => {
                act > exp
            }
            (ResolvedValue::Integer(exp), ResolvedValue::Integer(act), Operation::LessThan) => {
                act < exp
            }

            // Boolean
            (ResolvedValue::Boolean(exp), ResolvedValue::Boolean(act), Operation::Equals) => {
                act == exp
            }

            _ => false,
        }
    }
}

impl CtnExecutor for YourExecutor {
    fn execute_with_contract(
        &self,
        criterion: &ExecutableCriterion,
        collected_data: &HashMap<String, CollectedData>,
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
            ));
        }

        // Phase 2: State validation
        let mut state_results = Vec::new();

        for (object_id, data) in collected_data {
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
            ComplianceStatus::Pass
        } else {
            ComplianceStatus::Fail
        };

        Ok(CtnExecutionResult {
            ctn_type: criterion.criterion_type.clone(),
            status,
            test_phase: TestPhase::Complete,
            state_results,
            message: format!("{} of {} objects compliant", passing, state_results.len()),
            ..Default::default()
        })
    }

    fn get_ctn_contract(&self) -> CtnContract {
        self.contract.clone()
    }

    fn ctn_type(&self) -> &str {
        "your_ctn_type"
    }
}
```

### String Operations

Always use `string::compare()` for string operations:

```rust
use agent_core::execution::comparisons::string;

// Handles: equals, not_equal, contains, not_contains,
// starts_with, ends_with, pattern_match, case_insensitive_equals
let passed = string::compare(actual, expected, operation).unwrap_or(false);
```

---

## Registering Your Scanner

### Using contract_kit (Recommended)

```rust
use contract_kit::agent_core_api::strategies::{CtnStrategyRegistry, StrategyError};

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

### Using agent_core Directly

```rust
use agent_core::strategies::{CtnStrategyRegistry, StrategyError};

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
use contract_kit::agent_core_api::{scan_file, format_report};
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

### Command Execution

For command-based collectors:

```rust
use agent_core::strategies::SystemCommandExecutor;
use std::time::Duration;

let mut executor = SystemCommandExecutor::with_timeout(Duration::from_secs(5));
executor.allow_commands(&["rpm", "systemctl", "sysctl"]);

let output = executor.execute("rpm", &["-q", "openssl"], None)?;
println!("stdout: {}", output.stdout);
```

### Record Validation

For structured JSON data:

```rust
use agent_core::execution::record_validation::validate_record_checks;

let validation_results = validate_record_checks(
    record_data,
    &state.record_checks,
)?;
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

## Best Practices

### Contract Design

✅ **Do:**
- Provide clear field descriptions and examples
- Document edge cases in validation notes
- Define behaviors for optional features

❌ **Don't:**
- Add unnecessary required fields
- Use vague descriptions
- Expose internal names in ESP fields

### Collector Implementation

✅ **Do:**
- Handle errors with specific types (`ObjectNotFound` vs `AccessDenied`)
- Validate behavior hints against contract
- Implement batch collection when beneficial

❌ **Don't:**
- Silently ignore errors
- Make API calls without timeout
- Collect more than contract specifies

### Executor Implementation

✅ **Do:**
- Use `string::compare()` for ALL string operations
- Use helper functions for TEST evaluation
- Provide detailed failure messages

❌ **Don't:**
- Implement custom string comparison logic
- Skip field mapping lookups
- Return generic error messages

---

## Checklist

### Contract
- [ ] CTN type name is unique
- [ ] Required/optional object fields defined
- [ ] State fields have allowed operations
- [ ] Field mappings configured
- [ ] Behaviors documented

### Collector
- [ ] Implements `CtnDataCollector`
- [ ] Validates behavior hints
- [ ] Handles all error cases
- [ ] Returns mapped field names

### Executor
- [ ] Implements `CtnExecutor`
- [ ] Uses `string::compare()` for strings
- [ ] Uses helper functions for TEST
- [ ] Applies field mappings

### Integration
- [ ] Registered in registry
- [ ] End-to-end test passing
- [ ] Example ESP file provided

---

## Reference Implementations

See `contract_kit/src/` for complete examples:

| Type | Contract | Collector | Executor |
|------|----------|-----------|----------|
| File metadata | `contracts/file_metadata.rs` | `collectors/filesystem.rs` | `executors/file_metadata.rs` |
| File content | `contracts/file_content.rs` | `collectors/filesystem.rs` | `executors/file_content.rs` |
| JSON record | `contracts/json_record.rs` | `collectors/filesystem.rs` | `executors/json_record.rs` |
| RPM package | `contracts/rpm_package.rs` | `collectors/command.rs` | `executors/rpm_package.rs` |
| Systemd service | `contracts/systemd_service.rs` | `collectors/command.rs` | `executors/systemd_service.rs` |
