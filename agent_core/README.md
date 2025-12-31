# ESP Scanner Base

**Endpoint State Policy Scanner Base Library**

A Rust-based compliance validation framework for executing platform-agnostic security and compliance checks defined in the ESP (Endpoint State Policy) language.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Core Concepts](#core-concepts)
- [Module Reference](#module-reference)
- [Getting Started](#getting-started)
- [Usage Guide](#usage-guide)
- [Execution Pipeline](#execution-pipeline)
- [Contract-Based Strategy System](#contract-based-strategy-system)
- [Advanced Features](#advanced-features)
- [Error Handling](#error-handling)
- [Testing](#testing)
- [Performance Considerations](#performance-considerations)
- [Logging and Debugging](#logging-and-debugging)
- [Contributing](#contributing)
- [Architecture Decisions](#architecture-decisions)
- [Glossary](#glossary)

---

## Overview

**ESP Scanner Base** (`esp_scanner_base`) is a runtime execution framework for ESP compliance definitions. It consumes parsed ESP definitions from the `esp_compiler`, resolves all variable dependencies and references, executes platform-specific data collection, and validates system state against compliance requirements.

### Purpose

ESP is a **platform-agnostic intermediate language** for expressing compliance rules. The scanner base provides:

- **Resolution Engine**: Transforms unresolved ESP definitions into executable contexts
- **Strategy Registry**: Contract-based system for pluggable CTN (Criterion Type Node) implementations
- **Execution Engine**: Orchestrates data collection and compliance validation
- **Result Generation**: Produces SIEM-compatible compliance findings

### Key Features

- ✅ **Multi-phase resolution** with dependency analysis and topological ordering
- ✅ **Contract-driven validation** ensuring ESP definitions match platform capabilities
- ✅ **Hierarchical criteria evaluation** preserving CRI block AND/OR/NOT semantics
- ✅ **Security-first design** with command whitelisting and timeout enforcement
- ✅ **Extensible architecture** supporting custom CTN types and collectors
- ✅ **Comprehensive error handling** with context-rich validation reports

---

## Architecture

### High-Level Pipeline

```
ESP Source Code
    ↓
[esp_compiler]
    ↓
AST (Abstract Syntax Tree)
    ↓
[Resolution Phase]
    ↓
ExecutionContext (fully resolved, ordered)
    ↓
[Execution Phase]
    ↓
CtnResults (pass/fail per criterion)
    ↓
[Results Generation]
    ↓
ScanResult (SIEM-compatible JSON)
```

### Three-Layer Architecture

1. **Types Layer** (`types/`)
   - Declaration types (input from compiler)
   - Resolved types (output from resolution)
   - Execution types (runtime structures)

2. **Resolution Layer** (`resolution/`)
   - Variable dependency analysis and ordering
   - Reference resolution and substitution
   - SET expansion and filter validation

3. **Execution Layer** (`execution/`)
   - Contract-based data collection
   - State validation and comparison
   - TEST specification evaluation

4. **Strategy Layer** (`strategies/`)
   - CTN contract specifications
   - Collector/Executor trait definitions
   - Registry and validation system

5. **Results Layer** (`results/`)
   - Compliance finding generation
   - SIEM output formatting
   - Scan metadata management

---

## Core Concepts

### ESP Language Fundamentals

ESP definitions consist of:

- **Variables** (`VAR`) - Values that can be referenced throughout the definition
- **States** (`STATE`) - Validation rules describing expected system state
- **Objects** (`OBJECT`) - Data collection specifications
- **Sets** (`SET`) - Collections of objects with set algebra operations
- **Criteria** (`CRI`/`CTN`) - Test specifications combining objects and states
- **Runtime Operations** (`RUN`) - Data transformations and computations

### Scoping Model

- **Global Scope**: Definition-level declarations referenceable everywhere
- **Local Scope**: CTN-level declarations usable only within that CTN
- **Reference Keywords**: `STATE_REF`, `OBJECT_REF`, `SET_REF`, `VAR`

### Resolution vs Execution

**Resolution Phase**:
- Builds dependency graphs (DAGs)
- Orders variables topologically
- Substitutes variable references with concrete values
- Expands SET_REF into object references
- Validates all references and types
- Produces `ExecutionContext`

**Execution Phase**:
- Looks up collectors/executors via registry
- Collects data per CTN contract
- Applies filters to collected data
- Validates states against collected data
- Evaluates TEST specifications
- Produces `ScanResult`

---

## Module Reference

### `types/` - Type Definitions

Central type system defining all scanner data structures.

#### Key Types

**Declaration Types** (input from compiler):
- `VariableDeclaration` - Variable with optional initial value
- `StateDeclaration` - State with entity checks and field operations
- `ObjectDeclaration` - Object with elements (fields, modules, parameters)
- `RuntimeOperation` - RUN block with operation type and parameters
- `SetOperation` - SET block with set algebra operations
- `CriterionDeclaration` - CTN with test specification and references

**Resolved Types** (output from resolution):
- `ResolvedVariable` - Variable with concrete value
- `ResolvedState` - State with all VAR refs substituted
- `ResolvedObject` - Object with all VAR refs substituted
- `ResolvedSetOperation` - Set with expanded operands

**Execution Types** (runtime structures):
- `ExecutableCriterion` - CTN ready to execute
- `ExecutableObject` - Object ready for collection
- `ExecutableState` - State ready for validation
- `ExecutionContext` - Complete resolved definition

**Hierarchical Types**:
- `CriteriaTree` - Recursive tree structure for CRI/CTN nesting
- `CriteriaRoot` - Forest of criteria trees with root logical operator

#### Sub-modules

- `common.rs` - Core types (`DataType`, `Value`, `ResolvedValue`, `Operation`, `LogicalOp`)
- `variable.rs` - Variable declarations and resolution
- `state.rs` - State declarations with field operations
- `object.rs` - Object declarations with elements
- `filter.rs` - Filter specifications and evaluation
- `set.rs` - Set operations and operands
- `runtime_operation.rs` - RUN blocks and parameters
- `criteria.rs` - Criteria tree structures
- `criterion.rs` - Individual CTN declarations
- `execution_context.rs` - Complete execution context
- `resolution_context.rs` - Resolution phase context
- `record_traits.rs` - Record validation traits
- `field_path_extensions.rs` - Field path parsing with wildcards

---

### `resolution/` - Resolution Engine

Transforms unresolved declarations into executable contexts through multi-phase processing.

#### Key Modules

**`dag.rs` - Dependency Analysis**
- Builds directed acyclic graphs for variable dependencies
- Detects circular dependencies
- Provides topological ordering for resolution

**`field_resolver.rs` - Field Resolution**
- Substitutes variable references with concrete values
- Validates type compatibility
- Provides context-aware error messages

**`set_operations.rs` - Set Algebra**
- Implements union, intersection, complement operations
- Handles nested SET_REF expansion
- Validates set operand types

**`set_expansion.rs` - SET_REF Expansion**
- Expands SET_REF into concrete object references
- Handles recursive SET_REF with circular dependency detection
- Operates at declaration level before execution

**`runtime_operations.rs` - RUN Block Resolution**
- Identifies immediate vs deferred operations
- Resolves variable dependencies in parameters
- Executes immediate transformations

**`engine.rs` - Resolution Orchestration**
- Coordinates multi-phase resolution process
- Manages memoization for performance
- Builds ExecutionContext from ResolutionContext

#### Resolution Flow

```
1. DAG Construction
   - Collect all symbol declarations
   - Build dependency edges
   - Detect cycles

2. Variable Resolution
   - Topological sort by dependencies
   - Resolve in dependency order
   - Literal values → ResolvedVariables
   - Variable references → ResolvedVariables

3. State/Object Resolution
   - Substitute VAR refs with ResolvedVariables
   - Validate field types
   - Create ResolvedStates/ResolvedObjects

4. SET Expansion
   - Expand SET_REF recursively
   - Apply filters (deferred to execution)
   - Validate no circular references

5. Filter Validation
   - Ensure filter state references exist
   - Validate filter actions

6. Context Creation
   - Build ExecutionContext
   - Organize criteria tree hierarchy
   - Prepare for execution
```

---

### `strategies/` - Contract-Based Strategy System

Pluggable framework for CTN type implementations with contract-driven validation.

#### Key Modules

**`ctn_contract.rs` - Contract Specifications**

Defines explicit requirements for each CTN type:

```rust
pub struct CtnContract {
    pub ctn_type: String,
    pub metadata: CtnMetadata,
    pub object_requirements: ObjectRequirements,
    pub state_requirements: StateRequirements,
    pub field_mappings: CtnFieldMappings,
    pub supported_behaviors: Vec<SupportedBehavior>,
    pub performance_hints: PerformanceHints,
}
```

**Object Requirements**:
- Required fields (e.g., `path` for file CTN)
- Optional fields
- Field types and validation rules
- Module specifications

**State Requirements**:
- Supported state fields (e.g., `size`, `permissions`)
- Allowed operations per field (e.g., `>=` for size, `=` for owner)
- Entity check support
- Record check support

**Field Mappings**:
- Collection mappings: ESP field → platform field
- Validation mappings: collected field → state field
- Computed fields: derived from collected data

**`traits.rs` - Core Traits**

**CtnDataCollector**:
```rust
pub trait CtnDataCollector: Send + Sync {
    fn collector_id(&self) -> &str;
    fn supported_ctn_types(&self) -> Vec<String>;
    fn collect(&self, object: &ExecutableObject, contract: &CtnContract)
        -> Result<CollectedData, CollectionError>;
    fn supports_batch_collection(&self) -> bool { false }
    fn collect_batch(&self, objects: Vec<&ExecutableObject>, contract: &CtnContract)
        -> Result<HashMap<String, CollectedData>, CollectionError>;
}
```

**CtnExecutor**:
```rust
pub trait CtnExecutor: Send + Sync {
    fn executor_id(&self) -> &str;
    fn ctn_type(&self) -> &str;
    fn execute_with_contract(
        &self,
        criterion: &ExecutableCriterion,
        collected_data: &HashMap<String, CollectedData>,
        contract: &CtnContract,
    ) -> Result<CtnExecutionResult, CtnExecutionError>;
}
```

**TestProcessor**:
- Default TEST specification evaluation logic
- Existence check evaluation
- Item check evaluation
- State operator combination

**`registry.rs` - Strategy Registry**

Central registry managing CTN types, contracts, collectors, and executors:

```rust
let mut registry = CtnStrategyRegistry::new();

// Register a CTN type with its contract
registry.register_ctn_type(
    "file",
    file_contract,
    Arc::new(FileCollector::new()),
    Arc::new(FileExecutor::new()),
)?;

// Validate registration consistency
registry.validate_all_registrations()?;

// Runtime lookup
let collector = registry.get_collector_for_ctn("file")?;
let executor = registry.get_executor_for_ctn("file")?;
let contract = registry.get_ctn_contract("file")?;
```

**`validation.rs` - Contract Validation**

Validates ESP definitions against CTN contracts:

```rust
pub struct CtnContractValidator;

impl CtnContractValidator {
    // Validate contract self-consistency
    pub fn validate_contract(contract: &CtnContract) -> Result<(), CtnContractError>;

    // Validate criterion against contract
    pub fn validate_criterion_against_contract(
        criterion: &ExecutableCriterion,
        contract: &CtnContract,
    ) -> ValidationReport;
}
```

**Validation Checks**:
- Required object fields present
- State fields supported by CTN type
- Operations valid for field types
- Behaviors supported
- Field type compatibility

**`command_executor.rs` - System Command Execution**

Security-controlled command execution:

```rust
let mut executor = SystemCommandExecutor::new();
executor.allow_commands(&["rpm", "systemctl", "getenforce"]);

let output = executor.execute("rpm", &["-qa", "package"], Some(Duration::from_secs(5)))?;
```

**Security Features**:
- Whitelist-based command filtering
- Cleared environment variables
- Restricted PATH
- Timeout enforcement
- Error categorization

**`errors.rs` - Strategy Error Types**

Comprehensive error types:
- `CtnContractError` - Contract validation failures
- `StrategyError` - Registry and management errors
- `CollectionError` - Data collection failures
- `CtnExecutionError` - Execution failures
- `ValidationReport` - Detailed validation results

---

### `execution/` - Execution Engine

Orchestrates compliance validation through contract-based collection and execution.

#### Key Modules

**`engine.rs` - Execution Orchestration**

Main execution engine:

```rust
pub struct ExecutionEngine {
    context: ExecutionContext,
    registry: Arc<CtnStrategyRegistry>,
}

impl ExecutionEngine {
    pub fn execute(&mut self) -> Result<ScanResult, ExecutionError> {
        // 1. Validate execution context
        // 2. Execute criteria tree recursively
        // 3. Convert results to findings
        // 4. Generate scan result
    }

    fn execute_tree(&mut self, tree: &ExecutableCriteriaTree)
        -> Result<TreeResult, ExecutionError>;

    fn execute_criterion(&mut self, criterion: &ExecutableCriterion)
        -> Result<CtnExecutionResult, ExecutionError>;
}
```

**Execution Flow**:
1. Validate execution context
2. Traverse criteria tree recursively
3. For each CTN:
   - Lookup contract, collector, executor
   - Collect data for all objects (batch or individual)
   - Apply SET-level filters
   - Apply object-level filters
   - Execute validation with executor
   - Evaluate TEST specification
4. Combine results per CRI logical operators
5. Generate compliance findings
6. Produce scan result

**`comparisons.rs` - Value Comparison**

Type-aware comparison operations:

**String Comparisons**:
- `ieq` / `ine` - Case-insensitive equality
- `contains` / `not_contains` - Substring matching
- `starts` / `not_starts` - Prefix matching
- `ends` / `not_ends` - Suffix matching
- `pattern_match` / `matches` - Regex matching

**Binary Comparisons**:
- `=`, `!=`, `>`, `<`, `>=`, `<=` - Standard comparisons

**Collection Comparisons**:
- `subset_of` / `superset_of` - Set membership

**EVR Comparisons**:
- Epoch-Version-Release comparison for RPM packages

```rust
use esp_scanner_base::execution::comparisons::ComparisonExt;

let actual = ResolvedValue::String("hello world".to_string());
let expected = ResolvedValue::String("hello".to_string());

let result = actual.compare_with(&expected, Operation::Contains)?;
// result = true
```

**`filter_evaluation.rs` - Filter Processing**

Applies FILTER specifications to collected data:

```rust
pub struct FilterEvaluator;

impl FilterEvaluator {
    pub fn evaluate_filter(
        filter: &ResolvedFilterSpec,
        collected_data: &CollectedData,
        context: &ExecutionContext,
    ) -> Result<bool, FilterEvaluationError>;
}
```

**Filter Semantics**:
- **Include filter**: Retain only objects that satisfy states
- **Exclude filter**: Retain only objects that DO NOT satisfy states

**`helpers.rs` - TEST Evaluation**

Helper functions for TEST specification evaluation:

```rust
// Evaluate existence check
pub fn evaluate_existence_check(
    check: ExistenceCheck,
    objects_found: usize,
    objects_expected: usize,
) -> bool;

// Evaluate item check
pub fn evaluate_item_check(
    check: ItemCheck,
    items_passing: usize,
    items_total: usize,
) -> bool;

// Evaluate state operator
pub fn evaluate_state_operator(
    operator: Option<StateJoinOp>,
    state_results: &[bool],
) -> bool;

// Evaluate entity check
pub fn evaluate_entity_check(
    check: Option<EntityCheck>,
    entity_results: &[bool],
) -> bool;
```

**`record_validation.rs` - Record Checks**

Validates nested record structures:

```rust
pub fn validate_record_checks(
    record_checks: &[ExecutableRecordCheck],
    collected_data: &CollectedData,
) -> RecordValidationResult;
```

**`behavior.rs` - Behavior Hints**

Parses behavior specifications for collectors:

```rust
pub struct BehaviorHints {
    pub flags: Vec<String>,
    pub parameters: HashMap<String, String>,
}

// Parse: "recursive_scan max_depth 10 include_hidden"
let hints = BehaviorHints::parse(&behavior_values);

if hints.has_flag("recursive_scan") {
    if let Some(depth) = hints.get_parameter_as_int("max_depth") {
        // Use depth limit
    }
}
```

**`module_version.rs` - Module Compatibility**

Semantic version matching for modules:

```rust
pub struct SemanticVersion {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

let collector_version = SemanticVersion::parse("2.1.0")?;
let requested_version = SemanticVersion::parse("2.0.0")?;

if collector_version.is_compatible_with(&requested_version) {
    // Compatible: major matches, minor >= requested
}
```

**`entity_check.rs` - Entity Check Support**

Utilities for handling entity-level checks:

```rust
pub struct EntityCheckAnalyzer;

impl EntityCheckAnalyzer {
    // Find fields requiring entity-level collection
    pub fn get_entity_check_fields(
        criterion: &ExecutableCriterion
    ) -> HashMap<String, EntityCheck>;

    // Check if field needs entity collection
    pub fn field_needs_entity_collection(
        criterion: &ExecutableCriterion,
        field_name: &str,
    ) -> bool;
}
```

**`deferred_ops.rs` - Deferred Operations**

Handles runtime operations that depend on collected data:

- Identifies operations requiring collected object data
- Schedules execution after data collection
- Resolves EXTRACT operations from collected fields

**`structured_params.rs` - Parameter Parsing**

Parses nested parameter structures:

```rust
// Input: [("Config.Database.Host", "localhost")]
// Output: { "Config": { "Database": { "Host": "localhost" } } }

pub fn parse_parameters(
    fields: &[(String, String)],
    data_type: DataType,
) -> Result<RecordData, RecordDataError>;
```

---

### `results/` - Result Generation

Converts execution results into SIEM-compatible compliance findings.

#### Key Types

**`ScanResult`** - Complete scan output:
```rust
pub struct ScanResult {
    pub scan_id: String,
    pub esp_metadata: EspMetadata,
    pub host: HostContext,
    pub user_context: UserContext,
    pub results: ComplianceResults,
    pub timestamps: ScanTimestamps,
}
```

**`ComplianceFinding`** - Individual violation:
```rust
pub struct ComplianceFinding {
    pub id: String,
    pub severity: FindingSeverity,
    pub title: String,
    pub description: String,
    pub expected: serde_json::Value,
    pub actual: serde_json::Value,
    pub field_path: Option<String>,
    pub remediation: Option<String>,
}
```

**`ResultGenerator`** - Finding generation:
```rust
impl ResultGenerator {
    pub fn generate_findings(
        ctn_results: &[CtnResult],
        scan_result: &mut ScanResult,
    ) -> Result<(), ResultGenerationError>;

    pub fn build_compliance_results(
        ctn_results: &[CtnResult],
        findings: Vec<ComplianceFinding>,
    ) -> ComplianceResults;
}
```

**Severity Mapping**:
- `ComplianceStatus::Pass` → `FindingSeverity::Info`
- `ComplianceStatus::Fail` → `FindingSeverity::High`
- `ComplianceStatus::Error` → `FindingSeverity::Critical`
- `ComplianceStatus::Unknown` → `FindingSeverity::Medium`

---

## Getting Started

### Prerequisites

- **Rust** 1.70 or later
- **esp_compiler** workspace dependency
- Platform-specific dependencies (for collectors)

### Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
esp_scanner_base = { path = "../esp_scanner_base" }
esp_compiler = { path = "../esp_compiler" }

# Core dependencies
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
thiserror = "1.0"
```

---

## Usage Guide

### Creating a Custom CTN Type

See the comprehensive example in the full documentation showing how to:
1. Define a contract
2. Implement the collector
3. Implement the executor
4. Register with the registry

---

## Execution Pipeline

### Complete Flow

The execution pipeline consists of multiple phases:

1. **Parsing** (esp_compiler) - Syntax and semantic validation
2. **Resolution** (scanner) - Dependency resolution and variable substitution
3. **Execution** (scanner) - Data collection and validation
4. **Results** (scanner) - Finding generation and SIEM output

Each phase has specific responsibilities and error handling.

---

## Contract-Based Strategy System

The strategy system separates **specification** (contracts) from **implementation** (collectors/executors), enabling:
- Compile-time validation
- Platform portability
- Pluggable implementations
- Clear capability declarations

---

## Advanced Features

### Entity Checks

Validate multiple values for a single field with `entity_check` qualifier.

### Record Checks

Validate nested data structures with `record` blocks.

### Deferred Operations

Execute runtime operations after data collection with EXTRACT.

### Batch Collection

Optimize performance by collecting multiple objects in one operation.

### Module Version Matching

Ensure collector compatibility with semantic versioning.

### Security Controls

Execute system commands with whitelisting and timeout enforcement.

### Structured Parameters

Parse nested parameter blocks with dot notation.

---

## Error Handling

The scanner uses a hierarchical error system with context-rich error messages:

- `ResolutionError` - Resolution phase failures
- `ExecutionError` - Execution phase failures
- `StrategyError` - Registry and contract errors
- `CollectionError` - Data collection failures
- `CtnExecutionError` - Validation failures

All errors implement `std::error::Error` and provide detailed context.

---

## Testing

### Unit Testing

Test individual components in isolation:

```rust
#[test]
fn test_variable_resolution() {
    let context = /* build test context */;
    let engine = ResolutionEngine::new(context);
    let result = engine.resolve();
    assert!(result.is_ok());
}
```

### Integration Testing

Test end-to-end execution flow with real contracts and implementations.

---

## Performance Considerations

- Use batch collection when available
- Apply filters early in the pipeline
- Enable memoization for repeated resolutions
- Pool collectors/executors across CTNs

---

## Logging and Debugging

The scanner integrates with `esp_compiler` logging system:

```rust
use esp_compiler::{log_debug, log_info, log_error};

log_debug!("Starting resolution", "var_count" => vars.len());
```

Enable with:
```bash
RUST_LOG=debug cargo run
```

---

## Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Write tests
4. Submit a pull request

---

## Architecture Decisions

### Contract-Based Design

Separates platform-agnostic specifications from platform-specific implementations.

### Multi-Phase Resolution

Supports forward references and detects circular dependencies through DAG analysis.

### Hierarchical Criteria Trees

Preserves CRI block logical operators for accurate compliance calculation.

---

## Glossary

- **AST**: Abstract Syntax Tree from compiler
- **CRI**: Criteria block with logical operator
- **CTN**: Criterion Type Node (individual test)
- **DAG**: Directed Acyclic Graph for dependencies
- **ESP**: Endpoint State Policy language
- **SIEM**: Security Information and Event Management

---

## License

Licensed under workspace license terms.

---

## Support

- GitHub Issues: [Create an issue](https://github.com/CurtisSlone/Endpoint-State-Policy/issues)
- Documentation: [Full docs](https://github.com/CurtisSlone/Endpoint-State-Policy)

**Last Updated**: November 2025
**Version**: 0.1.0
