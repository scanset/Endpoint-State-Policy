# AST Module

Abstract Syntax Tree types for the ESP (Endpoint State Policy) language.

This module defines all AST node types corresponding to the [ESP EBNF grammar](../../docs/EBNF.md). These nodes represent the parsed structure of ESP files and are used throughout the compiler pipeline and by scanner implementations.

## Overview

The AST represents an ESP file as a tree of typed nodes:

```
EspFile
├── MetadataBlock (optional)
│   └── MetadataField[]
└── DefinitionNode
    ├── VariableDeclaration[]
    ├── StateDefinition[]        (global)
    ├── ObjectDefinition[]       (global)
    ├── RuntimeOperation[]       (RUN blocks)
    ├── SetOperation[]           (SET blocks)
    └── CriteriaNode[]           (CRI blocks)
        └── CriteriaContent[]
            ├── CriteriaNode     (nested CRI)
            └── CriterionNode    (CTN blocks)
                ├── TestSpecification
                ├── StateRef[]
                ├── ObjectRef[]
                ├── StateDefinition[]  (local)
                └── ObjectDefinition   (local, optional)
```

## Design Principles

- **EBNF Compliant**: Every grammar rule has a corresponding AST node
- **Span Tracking**: All nodes have `Option<Span>` for error reporting
- **Serde Compatible**: Full serialization support for FFI and tooling
- **Parser Ready**: Structures that the parser can directly populate

## Core Types

### File Structure

```rust
use common::ast::{EspFile, MetadataBlock, DefinitionNode};

// Root node
let file: EspFile = parse_file(source)?;

// Access metadata
if let Some(meta) = &file.metadata {
    for field in &meta.fields {
        println!("{}: {}", field.name, field.value);
    }
}

// Access definition
let def = &file.definition;
println!("Variables: {}", def.variables.len());
println!("States: {}", def.states.len());
println!("Criteria: {}", def.criteria.len());
```

### Data Types

ESP supports these data types for state fields and variables:

```rust
use common::ast::DataType;

let dt = DataType::parse("string").unwrap();
assert_eq!(dt.as_str(), "string");
```

| Type | Description |
|------|-------------|
| `String` | Text values |
| `Int` | 64-bit signed integer |
| `Float` | IEEE 754 double precision |
| `Boolean` | `true` or `false` |
| `Binary` | Binary data |
| `RecordData` | Structured record data |
| `Version` | Semantic version strings |
| `EvrString` | Epoch-Version-Release strings |

### Operations

Operations for state field comparisons:

```rust
use common::ast::Operation;

let op = Operation::parse("contains").unwrap();
assert_eq!(op.as_str(), "contains");
```

| Category | Operations |
|----------|------------|
| Comparison | `=`, `!=`, `>`, `<`, `>=`, `<=` |
| String | `ieq`, `ine`, `contains`, `starts`, `ends` |
| Negated String | `not_contains`, `not_starts`, `not_ends` |
| Pattern | `pattern_match`, `matches` |
| Set | `subset_of`, `superset_of` |

### Logical Operators

```rust
use common::ast::LogicalOp;

let op = LogicalOp::parse("AND").unwrap();  // Case-sensitive
assert_eq!(op.as_str(), "AND");
```

| Operator | Description |
|----------|-------------|
| `AND` | All children must pass |
| `OR` | At least one child must pass |

### Values

Values can be literals or variable references:

```rust
use common::ast::Value;

// Literal values
let string_val = Value::String("hello".to_string());
let int_val = Value::Integer(42);
let float_val = Value::Float(3.14);
let bool_val = Value::Boolean(true);

// Variable reference
let var_ref = Value::Variable("my_var".to_string());
```

## Block Types

### Variable Declaration (VAR)

```rust
use common::ast::VariableDeclaration;

// VAR config_path string `/etc/app.conf`
let var = VariableDeclaration {
    name: "config_path".to_string(),
    data_type: DataType::String,
    initial_value: Some(Value::String("/etc/app.conf".to_string())),
    span: None,
};
```

### State Definition (STATE)

States define conditions to check:

```rust
use common::ast::{StateDefinition, StateField};

// STATE permission_check
//     mode int = 0600
// STATE_END
let state = StateDefinition {
    id: "permission_check".to_string(),
    fields: vec![
        StateField {
            name: "mode".to_string(),
            data_type: DataType::Int,
            operation: Operation::Equals,
            value: Value::Integer(0o600),
            entity_check: None,
            span: None,
        }
    ],
    record_checks: vec![],
    is_global: true,
    span: None,
};
```

### Object Definition (OBJECT)

Objects define what to collect:

```rust
use common::ast::{ObjectDefinition, ObjectElement};

// OBJECT config_file
//     path `/etc/app.conf`
// OBJECT_END
let object = ObjectDefinition {
    id: "config_file".to_string(),
    elements: vec![
        ObjectElement::Field(ObjectField {
            name: "path".to_string(),
            value: Value::String("/etc/app.conf".to_string()),
            span: None,
        })
    ],
    is_global: true,
    span: None,
};
```

### Runtime Operation (RUN)

Runtime operations perform computations:

```rust
use common::ast::{RuntimeOperation, RuntimeOperationType, RunParameter};

// RUN result_var concat
//     VAR prefix
//     VAR suffix
// RUN_END
let run_op = RuntimeOperation {
    target_variable: "result_var".to_string(),
    operation_type: RuntimeOperationType::Concat,
    parameters: vec![
        RunParameter::Variable("prefix".to_string()),
        RunParameter::Variable("suffix".to_string()),
    ],
    span: None,
};
```

Runtime operation types:

| Type | Description |
|------|-------------|
| `Concat` | Concatenate strings |
| `Split` | Split string by delimiter |
| `Substring` | Extract substring |
| `Replace` | Replace pattern |
| `Arithmetic` | Mathematical operations |
| `Extract` | Extract field from object |
| `RegexCapture` | Capture regex groups |
| `Count` | Count occurrences |

### Set Operation (SET)

Set operations combine collections:

```rust
use common::ast::{SetOperation, SetOperationType, SetOperand};

// SET all_files union
//     SET_REF config_files
//     SET_REF log_files
// SET_END
let set_op = SetOperation {
    set_id: "all_files".to_string(),
    operation: SetOperationType::Union,
    operands: vec![
        SetOperand::SetRef("config_files".to_string()),
        SetOperand::SetRef("log_files".to_string()),
    ],
    filter: None,
    span: None,
};
```

| Type | Operands | Description |
|------|----------|-------------|
| `Union` | 1+ | Combine all items |
| `Intersection` | 2+ | Items in all sets |
| `Complement` | 2 | Items in first but not second |

### Criteria Block (CRI)

Criteria blocks define logical groupings:

```rust
use common::ast::{CriteriaNode, CriteriaContent, LogicalOp};

// CRI AND
//     CTN ...
//     CTN ...
// CRI_END
let criteria = CriteriaNode {
    logical_op: LogicalOp::And,
    negate: false,
    content: vec![
        CriteriaContent::Criterion(Box::new(criterion1)),
        CriteriaContent::Criterion(Box::new(criterion2)),
    ],
    span: None,
};
```

### Criterion Block (CTN)

Criterion blocks define individual checks:

```rust
use common::ast::{CriterionNode, TestSpecification, ExistenceCheck, ItemCheck};

// CTN file_permissions
//     TEST all all
//     STATE_REF permission_check
//     OBJECT_REF config_file
// CTN_END
let criterion = CriterionNode {
    criterion_type: "file_permissions".to_string(),
    test: TestSpecification {
        existence_check: ExistenceCheck::All,
        item_check: ItemCheck::All,
        state_operator: None,
        entity_check: None,
        span: None,
    },
    state_refs: vec![StateRef { state_id: "permission_check".to_string(), span: None }],
    object_refs: vec![ObjectRef { object_id: "config_file".to_string(), span: None }],
    local_states: vec![],
    local_object: None,
    span: None,
};
```

### Test Specification

Defines how items are checked:

| Existence Check | Description |
|-----------------|-------------|
| `any` | At least one item exists |
| `all` | All expected items exist |
| `none` | No items should exist |
| `at_least_one` | One or more items match |
| `only_one` | Exactly one item matches |

| Item Check | Description |
|------------|-------------|
| `all` | All items must pass state |
| `any` | At least one item passes |
| `none` | No items should pass |
| `at_least_one` | One or more pass |
| `only_one` | Exactly one passes |

## Scoping Rules

ESP has two scopes:

### Global Scope (Definition Level)

- Variables (`VAR`) - always global, referenceable everywhere
- States (`STATE` in DEF) - referenceable via `STATE_REF`
- Objects (`OBJECT` in DEF) - referenceable via `OBJECT_REF`
- Sets (`SET`) - referenceable via `SET_REF`

### Local Scope (CTN Level)

- States (`STATE` in CTN) - only visible within that CTN
- Objects (`OBJECT` in CTN) - only visible within that CTN

```rust
// Check if a state is global
if state.is_global {
    // Can be referenced from any CTN
} else {
    // Local to containing CTN only
}
```

## References

Reference nodes link to global symbols:

```rust
use common::ast::{StateRef, ObjectRef, SetRef};

// STATE_REF permission_check
let state_ref = StateRef {
    state_id: "permission_check".to_string(),
    span: None,
};

// OBJECT_REF config_file
let object_ref = ObjectRef {
    object_id: "config_file".to_string(),
    span: None,
};

// SET_REF all_files
let set_ref = SetRef {
    set_id: "all_files".to_string(),
    span: None,
};
```

## Serialization

All AST types implement `Serialize` and `Deserialize`:

```rust
use common::ast::EspFile;

// Serialize to JSON
let json = serde_json::to_string_pretty(&ast)?;

// Deserialize from JSON
let ast: EspFile = serde_json::from_str(&json)?;
```

Note: `Span` fields are skipped during serialization (`#[serde(skip)]`).

## Span Tracking

All nodes include optional span information for error reporting:

```rust
use common::utils::Span;

if let Some(span) = &node.span {
    println!("Error at {}:{}", span.start().line, span.start().column);
}
```

## Module Structure

```
ast/
├── mod.rs      # Re-exports all node types
└── nodes.rs    # Complete AST node definitions
```

## Related Documentation

- [EBNF Grammar](../../docs/EBNF.md) - Complete grammar specification
- [Compiler Module](../../compiler/README.md) - Parser that produces AST
- [agent_core Conversion](../../agent_core/src/conversion/README.md) - AST to execution types
