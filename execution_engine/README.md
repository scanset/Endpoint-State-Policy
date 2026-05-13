# Execution Engine

Runtime execution framework for ESP (Endpoint State Policy) compliance validation.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Core Concepts](#core-concepts)
- [Module Reference](#module-reference)
- [Usage](#usage)
- [Execution Pipeline](#execution-pipeline)
- [Strategy System](#strategy-system)
- [Error Handling](#error-handling)
- [Glossary](#glossary)

## Overview

The Execution Engine (`execution_engine`) consumes parsed ESP definitions from the `compiler`, resolves all dependencies and references, executes platform-specific data collection, and validates system state against compliance requirements.

### Key Features

- **AST Conversion**: Transform compiler output to execution types
- **Multi-phase Resolution**: Dependency analysis with topological ordering
- **Contract-driven Validation**: ESP definitions validated against platform capabilities
- **Hierarchical Criteria Evaluation**: Preserves CRI block AND/OR/NOT semantics
- **Extensible Architecture**: Pluggable CTN types and collectors

### Related Crates

| Crate | Relationship |
|-------|--------------|
| `compiler` | Provides AST input via `conversion` module |
| `common` | Shared types (AST nodes, results, logging) |

## Architecture

### High-Level Pipeline

```
ESP Source (.esp)
       │
       ▼
┌─────────────────┐
│    compiler     │  Parsing, validation, AST generation
└─────────────────┘
       │
       ▼
┌─────────────────┐
│   conversion    │  AST → Execution types
└─────────────────┘
       │
       ▼
┌─────────────────┐
│   resolution    │  Variable substitution, SET expansion
└─────────────────┘
       │
       ▼
┌─────────────────┐
│   execution     │  Data collection, state validation
└─────────────────┘
       │
       ▼
   CtnResults (pass/fail per criterion)
```

### Module Layers

```
┌─────────────────────────────────────────────────────────────┐
│                      execution_engine                       │
├─────────────────────────────────────────────────────────────┤
│  conversion   │  AST → scanner types bridge                 │
├───────────────┼─────────────────────────────────────────────┤
│  types        │  Declaration, resolved, and execution types │
├───────────────┼─────────────────────────────────────────────┤
│  resolution   │  DAG analysis, variable/SET resolution      │
├───────────────┼─────────────────────────────────────────────┤
│  strategies   │  CTN contracts, collectors, executors       │
├───────────────┼─────────────────────────────────────────────┤
│  execution    │  Engine, comparisons, filter evaluation     │
└───────────────┴─────────────────────────────────────────────┘
```

## Core Concepts

### ESP Language Fundamentals

| Element | Keyword | Description |
|---------|---------|-------------|
| Variables | `VAR` | Referenceable values |
| States | `STATE` | Validation rules (expected system state) |
| Objects | `OBJECT` | Data collection specifications |
| Sets | `SET` | Object collections with set algebra |
| Criteria | `CRI` | Logical grouping (AND/OR) |
| Criterion | `CTN` | Individual test combining object + state |
| Runtime Ops | `RUN` | Data transformations |

📄 See [ESP Overview](../docs/01_ESP_Overview_v1_0_0.md) for complete language introduction.

### Scoping Model

- **Global Scope**: Definition-level declarations (VAR, STATE, OBJECT, SET)
- **Local Scope**: CTN-level declarations (only within that CTN)
- **References**: `STATE_REF`, `OBJECT_REF`, `SET_REF`, `VAR`

📄 See [ESP Symbol Resolution](../docs/05_ESP_Symbol_Resolution_v1_0_0.md) for scoping rules.

### Resolution vs Execution

| Phase | Input | Output | Purpose |
|-------|-------|--------|---------|
| Resolution | Declarations | ExecutionContext | Substitute variables, expand SETs, order dependencies |
| Execution | ExecutionContext | CtnResults | Collect data, validate states, evaluate TEST specs |

## Module Reference

### `conversion`

**Entry point** for transforming compiler AST to execution types.

```rust
use execution_engine::conversion::convert_ast_to_scanner_types;

let ast = compiler::pipeline::process_file("policy.esp")?.ast;

let (variables, states, objects, runtime_ops, sets, criteria, metadata) =
    convert_ast_to_scanner_types(&ast)?;
```

---

### `types`

Type definitions for all scanner data structures.

**Declaration Types** (from compiler):
- `VariableDeclaration`, `StateDeclaration`, `ObjectDeclaration`
- `RuntimeOperation`, `SetOperation`, `CriterionDeclaration`

**Resolved Types** (after resolution):
- `ResolvedVariable`, `ResolvedState`, `ResolvedObject`
- `ResolvedSetOperation`

**Execution Types** (runtime):
- `ExecutableCriterion`, `ExecutableObject`, `ExecutableState`
- `ExecutionContext`, `CriteriaTree`, `CriteriaRoot`

```rust
use execution_engine::types::{
    ExecutionContext, ExecutableCriterion, ResolvedValue, DataType
};
```

📄 See [ESP Type System](../docs/04_ESP_Type_System_v1_0_0.md) for type definitions.

---

### `resolution`

Transforms declarations into executable context through multi-phase processing.

**Key Components:**
- `dag` - Dependency graph construction and cycle detection
- `field_resolver` - Variable reference substitution
- `set_operations` - Union, intersection, complement
- `set_expansion` - SET_REF → concrete object references
- `runtime_operations` - RUN block resolution

```rust
use execution_engine::resolution::ResolutionEngine;

let context = ResolutionContext::new(variables, states, objects, ...);
let engine = ResolutionEngine::new(context);
let exec_context = engine.resolve()?;
```

**Resolution Flow:**
1. Build dependency DAG
2. Topologically sort variables
3. Substitute variable references
4. Expand SET_REF recursively
5. Validate filters
6. Produce `ExecutionContext`

📄 See [ESP Symbol Resolution](../docs/05_ESP_Symbol_Resolution_v1_0_0.md) for resolution rules.

---

### `strategies`

Contract-based system for CTN type implementations.

**Key Types:**
- `CtnContract` - Requirements for a CTN type (fields, operations, behaviors)
- `CtnDataCollector` - Platform-specific data collection trait
- `CtnExecutor` - Compliance validation trait
- `CtnStrategyRegistry` - Central registry for strategies

```rust
use execution_engine::strategies::{
    CtnStrategyRegistry, CtnContract, CtnDataCollector, CtnExecutor,
    CollectedData, StrategyError
};

let mut registry = CtnStrategyRegistry::new();
registry.register_ctn_strategy(
    Box::new(MyCollector::new()),
    Box::new(MyExecutor::new(contract)),
)?;
```

**Traits:**

```rust
pub trait CtnDataCollector: Send + Sync {
    fn collector_id(&self) -> &str;
    fn supported_ctn_types(&self) -> Vec<String>;
    fn collect_for_ctn_with_hints(
        &self,
        object: &ExecutableObject,
        contract: &CtnContract,
        hints: &BehaviorHints,
    ) -> Result<CollectedData, CollectionError>;
}

pub trait CtnExecutor: Send + Sync {
    fn ctn_type(&self) -> &str;
    fn get_ctn_contract(&self) -> CtnContract;
    fn execute_with_contract(
        &self,
        criterion: &ExecutableCriterion,
        collected_data: HashMap<String, CollectedData>,
        contract: &CtnContract,
    ) -> Result<CtnExecutionResult, CtnExecutionError>;
}
```

📄 See [ESP Trust Model](../docs/10_ESP_Trust_Model_v1_2_0.md) for security boundaries.

---

### `execution`

Orchestrates compliance validation.

**Key Components:**
- `engine` - Main execution orchestration
- `comparisons` - Type-aware value comparisons
- `filter_evaluation` - FILTER specification processing
- `helpers` - TEST specification evaluation
- `record_validation` - Nested record structure validation

```rust
use execution_engine::execution::{ExecutionEngine, ExecutionError};

let engine = ExecutionEngine::new(exec_context, registry);
let results = engine.execute()?;
```

**Comparison Operations:**

| Category | Operations |
|----------|------------|
| Equality | `=`, `!=`, `ieq`, `ine` |
| Ordering | `>`, `<`, `>=`, `<=` |
| String | `contains`, `starts`, `ends`, `not_contains`, `not_starts`, `not_ends` |
| Pattern | `pattern_match`, `matches` |
| Set | `subset_of`, `superset_of` |

```rust
use execution_engine::execution::comparisons::ComparisonExt;

let result = actual_value.compare_with(&expected_value, Operation::Contains)?;
```

📄 See [ESP Evaluation Semantics](../docs/06_ESP_Evaluation_Semantics_v1_0_0.md) for evaluation rules.

## Usage

### Basic Pipeline

```rust
use execution_engine::conversion::convert_ast_to_scanner_types;
use execution_engine::resolution::ResolutionEngine;
use execution_engine::execution::ExecutionEngine;
use execution_engine::types::ResolutionContext;

// 1. Compile ESP file
let pipeline_result = compiler::pipeline::process_file("policy.esp")?;

// 2. Convert AST to scanner types
let (vars, states, objects, run_ops, sets, criteria, metadata) =
    convert_ast_to_scanner_types(&pipeline_result.ast)?;

// 3. Resolve dependencies
let resolution_ctx = ResolutionContext::new(vars, states, objects, run_ops, sets, criteria);
let engine = ResolutionEngine::new(resolution_ctx);
let exec_context = engine.resolve()?;

// 4. Execute with registry
let mut exec_engine = ExecutionEngine::new(exec_context, registry);
let results = exec_engine.execute()?;
```

### Inline CTN Execution (Discovery / Inventory)

For **asset discovery and inventory enumeration**, where there's no
audit-meaningful policy to attest about, the `inline` module skips the
`.esp` → compiler → resolution → execution pipeline and dispatches
directly to a registered CTN strategy:

```rust
use execution_engine::inline::InlineRequestBuilder;

let result = InlineRequestBuilder::new("az_resource_list")
    .field_string("subscription_id", "00000000-0000-0000-0000-000000000000")
    .execute(&registry)?;

// result.data is CollectedData — the caller wraps it in its own
// envelope and signs it as discovery evidence.
```

What's skipped relative to the basic pipeline: `.esp` lexing/parsing,
META validation, policy compilation, the criterion evaluation tree,
and findings/outcome calculation. Use this **only** when the
credential's grants define the scope and there is no pass/fail
assertion to make. For evidence-gathering scans (asset-list /
asset-internal policy assertions with pass/fail outcomes, control
mappings, and audit context), continue to use the file-based pipeline
above — that's what produces a complete `AssessorPackage`.

Public API: [`inline::InlineRequest`](src/inline.rs),
[`inline::InlineRequestBuilder`](src/inline.rs),
[`inline::execute_inline`](src/inline.rs),
[`inline::InlineResult`](src/inline.rs). Introduced post-v2.2.0.

## Execution Pipeline

### Phase Details

#### 1. Conversion Phase

Transforms compiler AST nodes to scanner declaration types:
- `ast::VariableDeclaration` → `types::VariableDeclaration`
- `ast::StateDefinition` → `types::StateDeclaration`
- `ast::ObjectDefinition` → `types::ObjectDeclaration`
- `ast::CriteriaNode` → `types::CriteriaTree`

#### 2. Resolution Phase

```
Declarations
     │
     ▼
┌─────────────────┐
│  DAG Analysis   │  Build dependency graph, detect cycles
└─────────────────┘
     │
     ▼
┌─────────────────┐
│ Variable Order  │  Topological sort by dependencies
└─────────────────┘
     │
     ▼
┌─────────────────┐
│  Substitution   │  Replace VAR refs with concrete values
└─────────────────┘
     │
     ▼
┌─────────────────┐
│  SET Expansion  │  Expand SET_REF to object lists
└─────────────────┘
     │
     ▼
ExecutionContext
```

#### 3. Execution Phase

```
ExecutionContext
     │
     ▼
┌─────────────────┐
│ Registry Lookup │  Get collector/executor for CTN type
└─────────────────┘
     │
     ▼
┌─────────────────┐
│ Data Collection │  Gather system state per object
└─────────────────┘
     │
     ▼
┌─────────────────┐
│ Filter Apply    │  Include/exclude based on filter states
└─────────────────┘
     │
     ▼
┌─────────────────┐
│ State Validate  │  Compare collected vs expected
└─────────────────┘
     │
     ▼
┌─────────────────┐
│ TEST Evaluate   │  Apply existence/item checks
└─────────────────┘
     │
     ▼
CtnResults
```

## Strategy System

The strategy system separates **specification** (contracts) from **implementation** (collectors/executors):

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  CtnContract │────▶│  Collector   │────▶│   Executor   │
│              │     │              │     │              │
│ - ctn_type   │     │ - collect()  │     │ - execute()  │
│ - fields     │     │ - batch()    │     │ - validate() │
│ - operations │     └──────────────┘     └──────────────┘
│ - behaviors  │              │                   │
└──────────────┘              │                   │
       │                      ▼                   ▼
       │              ┌──────────────┐     ┌──────────────┐
       └─────────────▶│  Registry    │◀────│              │
                      │              │     │              │
                      │ - lookup()   │     │              │
                      │ - validate() │     │              │
                      └──────────────┘     └──────────────┘
```

### Implementing a Strategy

For implementing custom CTN types with collectors and executors, see the Contract Development Guide in external scanner implementations.

## Error Handling

Hierarchical error types with context:

| Error Type | Phase | Description |
|------------|-------|-------------|
| `ConversionError` | Conversion | AST transformation failures |
| `ResolutionError` | Resolution | Dependency/reference failures |
| `ExecutionError` | Execution | Collection/validation failures |
| `StrategyError` | Registry | Contract/registration failures |
| `CollectionError` | Collection | Data gathering failures |
| `CtnExecutionError` | Validation | State comparison failures |

```rust
match engine.execute() {
    Ok(results) => { /* process results */ }
    Err(ExecutionError::Collection { ctn_type, source }) => {
        eprintln!("Collection failed for {}: {}", ctn_type, source);
    }
    Err(e) => eprintln!("Execution error: {}", e),
}
```

📄 See [ESP Error Model](../docs/08_ESP_Error_Model_v1_0_0.md) for error codes and handling.

## Results

Scan results and compliance findings are handled by the `common` crate's results module:

- **Attestations**: Network-safe output (pass/fail metadata only)
- **Full Results**: Complete evidence for local storage
- **Assessor Packages**: Full results with collection commands for reproducibility

📄 See [ESP Canonical Schema](../docs/09_ESP_Canonical_Schema_v1_0_0.md) for output format specification.

## Glossary

| Term | Definition |
|------|------------|
| **AST** | Abstract Syntax Tree from compiler |
| **CRI** | Criteria block with logical operator (AND/OR) |
| **CTN** | Criterion Type Node (individual test specification) |
| **DAG** | Directed Acyclic Graph for dependency ordering |
| **ESP** | Endpoint State Policy language |
| **TEST** | Specification defining existence/item checks |

## Related Documentation

### ESP Language Specification

| Document | Description |
|----------|-------------|
| [ESP Overview](../docs/01_ESP_Overview_v1_0_0.md) | Language introduction and concepts |
| [Lexical Rules](../docs/02_ESP_Lexical_Rules_v1_0_0.md) | Token definitions and lexical structure |
| [Grammar EBNF](../docs/03_ESP_Grammar_EBNF_v2_1_0.md) | Complete grammar specification |
| [Type System](../docs/04_ESP_Type_System_v1_0_0.md) | Data types and type compatibility |
| [Symbol Resolution](../docs/05_ESP_Symbol_Resolution_v1_0_0.md) | Symbol tables and reference resolution |
| [Evaluation Semantics](../docs/06_ESP_Evaluation_Semantics_v1_0_0.md) | Runtime evaluation rules |
| [Meta Requirements](../docs/07_ESP_Meta_Requirements_v1_0_0.md) | Structural requirements |
| [Error Model](../docs/08_ESP_Error_Model_v1_0_0.md) | Error codes and handling |
| [Canonical Schema](../docs/09_ESP_Canonical_Schema_v1_0_0.md) | Output format specification |
| [Trust Model](../docs/10_ESP_Trust_Model_v1_2_0.md) | Security boundaries and trust |
| [Configuration](../docs/11_ESP_Configuration_v1_0_0.md) | Build and runtime configuration |
| [Logging](../docs/12_ESP_Logging_v1_0_0.md) | Logging system specification |

### Related Crates

| Crate | Description |
|-------|-------------|
| [compiler](../compiler/README.md) | ESP parsing and AST generation |
| [common](../common/README.md) | Shared types (AST, logging, config, results) |

## License

See repository root for license information.
