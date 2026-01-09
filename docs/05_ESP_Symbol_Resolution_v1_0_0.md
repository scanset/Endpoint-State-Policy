# ESP v1.0.0 — Symbol Resolution

**Version:** 1.0.0
**Status:** Normative
**Last Updated:** 2026-01-08

---

## 1. Overview

This document specifies the symbol resolution rules for ESP v1.0.0, including namespace organization, scoping rules, duplicate detection, shadowing prevention, and reference resolution.

---

## 2. Symbol Categories

### 2.1 Symbol Types

ESP defines five symbol types that can be declared:

| Symbol Type | Keyword | Scope | Referenceable Via |
|-------------|---------|-------|-------------------|
| Variable | `VAR` | Global | `VAR` |
| State | `STATE` | Global or Local | `STATE_REF` (global only) |
| Object | `OBJECT` | Global or Local | `OBJECT_REF` (global only) |
| Set | `SET` | Global | `SET_REF` |
| Runtime Operation | `RUN` | Global | `VAR` (target variable) |

### 2.2 Declaration Syntax

```ebnf
(* Global declarations - in DEF block *)
variable_declaration ::= "VAR" space identifier space data_type (space value)? statement_end
definition_state     ::= "STATE" space identifier statement_end state_content "STATE_END" statement_end
definition_object    ::= "OBJECT" space identifier statement_end object_content "OBJECT_END" statement_end
set_block            ::= "SET" space identifier space set_operation statement_end set_content "SET_END" statement_end
run_block            ::= "RUN" space identifier space operation_type statement_end run_content "RUN_END" statement_end

(* Local declarations - in CTN block *)
ctn_state            ::= "STATE" space identifier statement_end state_content "STATE_END" statement_end
ctn_object           ::= "OBJECT" space identifier statement_end object_content "OBJECT_END" statement_end
```

---

## 3. Scopes

### 3.1 Global Scope

The **global scope** encompasses all symbols declared at the DEF level:

- Variables (`VAR`)
- Definition-level States (`STATE`)
- Definition-level Objects (`OBJECT`)
- Sets (`SET`)
- Runtime Operations (`RUN` target variables)

Global symbols are accessible throughout the entire policy via reference keywords.

### 3.2 Local Scope

Each CTN block creates a **local scope** that can contain:

- Local States (`STATE`) — up to implementation limit
- Local Object (`OBJECT`) — maximum ONE per CTN

Local symbols are:
- Accessible only within their declaring CTN
- NOT referenceable via `STATE_REF` or `OBJECT_REF`
- Evaluated inline with the CTN

### 3.3 Scope Hierarchy

```
DEF (Global Scope)
├── VAR declarations
├── STATE declarations (global)
├── OBJECT declarations (global)
├── SET declarations
├── RUN declarations
└── CRI
    └── CTN (Local Scope A)
        ├── STATE declarations (local to A)
        └── OBJECT declaration (local to A, max 1)
    └── CTN (Local Scope B)
        ├── STATE declarations (local to B)
        └── OBJECT declaration (local to B, max 1)
```

---

## 4. Namespace Rules

### 4.1 Unified Global Namespace (N-4)

All global symbols share a **single unified namespace**. An identifier MUST be unique across all global symbol types.

**Constraint:** Within global scope, no two symbols may have the same identifier, regardless of symbol type.

| Declaration 1 | Declaration 2 | Result |
|---------------|---------------|--------|
| `VAR foo` | `STATE foo` | ✗ Error |
| `STATE foo` | `OBJECT foo` | ✗ Error |
| `SET foo` | `VAR foo` | ✗ Error |
| `RUN foo` | `STATE foo` | ✗ Error |
| `STATE foo` | `STATE bar` | ✓ Allowed |

### 4.2 Unified Local Namespace

Within each CTN, local symbols share a **unified local namespace**. An identifier MUST be unique across local STATE and local OBJECT within the same CTN.

| Declaration 1 | Declaration 2 | Same CTN | Result |
|---------------|---------------|----------|--------|
| Local `STATE foo` | Local `OBJECT foo` | Yes | ✗ Error |
| Local `STATE foo` | Local `STATE foo` | Yes | ✗ Error |
| Local `STATE foo` | Local `STATE foo` | No | ✓ Allowed |

### 4.3 Cross-CTN Isolation

Different CTN blocks have **independent local scopes**. The same identifier MAY be used in different CTNs.

```esp
CRI AND
    CTN file_content
        STATE check           # Local to file_content CTN
            content string contains `secure`
        STATE_END
    CTN_END

    CTN registry
        STATE check           # Local to registry CTN - ALLOWED (different scope)
            value_data string = `enabled`
        STATE_END
    CTN_END
CRI_END
```

---

## 5. Duplicate Detection (N-3)

### 5.1 Rule

Duplicate identifiers within the same scope MUST be a validation error. There is no "last wins" or "first wins" behavior.

### 5.2 Detection Points

| Scope | Duplicates Detected Across |
|-------|---------------------------|
| Global | VAR, STATE, OBJECT, SET, RUN |
| Local (per CTN) | Local STATE, Local OBJECT |

### 5.3 Error

```
DuplicateSymbol {
    identifier: String,
    scope: String,           // "global" or "CTN(criterion_type)"
    first_span: Span,
    duplicate_span: Span,
}
```

### 5.4 Examples

**Error: Global duplicate**
```esp
DEF
    STATE secure_perms
        permissions string = `0600`
    STATE_END

    STATE secure_perms        # Error: duplicate 'secure_perms' in global scope
        permissions string = `0644`
    STATE_END
DEF_END
```

**Error: Global cross-type duplicate**
```esp
DEF
    VAR config string `/etc/app.conf`

    STATE config              # Error: 'config' already declared as VAR
        content string contains `debug=false`
    STATE_END
DEF_END
```

**Error: Local duplicate**
```esp
CTN file_content
    TEST all all
    STATE check
        size int > 0
    STATE_END
    STATE check               # Error: duplicate 'check' in CTN(file_content)
        permissions string = `0644`
    STATE_END
CTN_END
```

---

## 6. Shadowing Prevention (N-5)

### 6.1 Rule

Local symbols MUST NOT shadow global symbols. A local STATE or OBJECT with the same identifier as any global symbol is forbidden.

### 6.2 Rationale

Shadowing prevention ensures unambiguous symbol resolution and prevents confusion about which symbol is being referenced.

### 6.3 Scope of Check

Local symbols are checked against ALL global symbol types:

| Local Symbol | Shadows Global | Result |
|--------------|----------------|--------|
| Local `STATE foo` | Global `STATE foo` | ✗ Error |
| Local `STATE foo` | Global `OBJECT foo` | ✗ Error |
| Local `STATE foo` | Global `VAR foo` | ✗ Error |
| Local `STATE foo` | Global `SET foo` | ✗ Error |
| Local `STATE foo` | Global `RUN foo` | ✗ Error |
| Local `OBJECT bar` | Global `STATE bar` | ✗ Error |

### 6.4 Error

```
Shadowing {
    identifier: String,
    local_type: String,      // "state" or "object"
    global_type: String,     // "variable", "state", "object", "set", "runtime_operation"
    ctn_type: String,        // CTN criterion type
    local_span: Span,
    global_span: Span,
}
```

### 6.5 Example

```esp
DEF
    STATE secure_settings
        PermitRootLogin string = `no`
    STATE_END

    CRI AND
        CTN file_content
            TEST all all
            # Error: Local 'secure_settings' shadows global STATE
            STATE secure_settings
                content string contains `secure`
            STATE_END
        CTN_END
    CRI_END
DEF_END
```

---

## 7. Reference Resolution (N-6)

### 7.1 Reference Keywords

| Keyword | Resolves To | Scope |
|---------|-------------|-------|
| `STATE_REF` | Global STATE | Global only |
| `OBJECT_REF` | Global OBJECT | Global only |
| `SET_REF` | Global SET | Global only |
| `VAR` | Global VAR or RUN target | Global only |

### 7.2 Resolution Rules

1. All references MUST resolve to exactly one symbol
2. References resolve to **global scope only**
3. Local symbols are NOT referenceable
4. Undefined references MUST be a validation error
5. Forward references ARE allowed (order-independent resolution)

### 7.3 Resolution Timing

Reference resolution occurs during the validation phase, after symbol discovery:

```
Parse → Symbol Discovery → Reference Resolution → Semantic Analysis
```

### 7.4 Forward References

Symbols may be referenced before their declaration. Resolution is order-independent.

```esp
DEF
    CRI AND
        CTN file_content
            TEST all all
            STATE_REF secure_settings    # Forward reference - OK
            OBJECT_REF ssh_config        # Forward reference - OK
        CTN_END
    CRI_END

    STATE secure_settings                # Declared after reference
        content string contains `secure`
    STATE_END

    OBJECT ssh_config                    # Declared after reference
        path `/etc/ssh/sshd_config`
    OBJECT_END
DEF_END
```

### 7.5 Resolution Errors

| Error | Condition |
|-------|-----------|
| Undefined reference | Referenced symbol does not exist |
| Wrong reference type | Using `STATE_REF` for an OBJECT |
| Ambiguous reference | Should not occur with unified namespace |

---

## 8. Local Object Constraints

### 8.1 Single Object Rule

Each CTN block MAY contain at most ONE local OBJECT declaration.

### 8.2 Rationale

A CTN evaluates a single criterion type against objects. Multiple local objects would create ambiguity about which object to evaluate.

### 8.3 Error

```
MultipleCtnObjects {
    ctn_type: String,
    first_span: Span,
    duplicate_span: Span,
}
```

### 8.4 Example

```esp
CTN file_content
    TEST all all
    OBJECT config_file
        path `/etc/app.conf`
    OBJECT_END
    OBJECT log_file           # Error: Multiple local objects in CTN
        path `/var/log/app.log`
    OBJECT_END
CTN_END
```

### 8.5 Alternative: Use Global Objects

For multiple objects, declare them globally and reference:

```esp
DEF
    OBJECT config_file
        path `/etc/app.conf`
    OBJECT_END

    OBJECT log_file
        path `/var/log/app.log`
    OBJECT_END

    SET app_files union
        OBJECT_REF config_file
        OBJECT_REF log_file
    SET_END

    CRI AND
        CTN file_content
            TEST all all
            STATE_REF file_check
            OBJECT
                SET_REF app_files     # Reference set of objects
            OBJECT_END
        CTN_END
    CRI_END
DEF_END
```

---

## 9. Symbol Table Structure

### 9.1 Global Symbol Table

The global symbol table maintains separate collections by symbol type:

```
GlobalSymbolTable
├── variables: Map<String, VariableSymbol>
├── states: Map<String, StateSymbol>
├── objects: Map<String, ObjectSymbol>
├── sets: Map<String, SetSymbol>
└── runtime_operations: Map<String, RuntimeOperationSymbol>
```

Despite separate storage, duplicate detection spans ALL collections.

### 9.2 Local Symbol Tables

Each CTN has its own local symbol table:

```
LocalSymbolTable
├── ctn_node_id: CtnNodeId
├── ctn_type: String
├── states: Map<String, LocalStateSymbol>
└── object: Option<LocalObjectSymbol>      // Max 1
```

### 9.3 Symbol Relationships

The symbol table tracks relationships between symbols:

| Relationship Type | Description |
|-------------------|-------------|
| `VariableInitialization` | VAR initialized from another VAR |
| `VariableUsage` | RUN operation using VAR |
| `ObjectFieldExtraction` | OBJ reference in RUN |
| `StateReference` | STATE_REF usage |
| `ObjectReference` | OBJECT_REF usage |
| `SetReference` | SET_REF usage |
| `FilterDependency` | FILTER referencing STATE |
| `RunOperationInput` | RUN parameter dependency |
| `RunOperationTarget` | RUN target variable |

---

## 10. Validation Order

### 10.1 Symbol Discovery Phase

1. Traverse AST in document order
2. Register global symbols (VAR, STATE, OBJECT, SET, RUN)
3. For each CTN:
   - Create local symbol table
   - Register local symbols with shadowing check
   - Validate single-object constraint
4. Check global duplicates
5. Build relationship graph

### 10.2 Reference Resolution Phase

1. Traverse all references (STATE_REF, OBJECT_REF, SET_REF, VAR)
2. Resolve each to global symbol table
3. Report undefined references
4. Validate reference type matches symbol type

---

## 11. Implementation Limits

| Limit | Recommended Value |
|-------|-------------------|
| Global symbols | 10,000 |
| Local symbols per CTN | 100 |
| CTN scopes | 1,000 |
| Symbol identifier length | 255 characters |
| Symbol relationships | 100,000 |

---

## 12. Summary Tables

### 12.1 Scope Visibility

| Symbol | Declared In | Visible In | Referenceable |
|--------|-------------|------------|---------------|
| Global VAR | DEF | Entire policy | Yes (`VAR`) |
| Global STATE | DEF | Entire policy | Yes (`STATE_REF`) |
| Global OBJECT | DEF | Entire policy | Yes (`OBJECT_REF`) |
| Global SET | DEF | Entire policy | Yes (`SET_REF`) |
| Global RUN | DEF | Entire policy | Yes (`VAR` target) |
| Local STATE | CTN | Declaring CTN only | No |
| Local OBJECT | CTN | Declaring CTN only | No |

### 12.2 Duplicate/Shadowing Rules

| Scenario | Allowed |
|----------|---------|
| Same identifier, same global type | ✗ Duplicate |
| Same identifier, different global types | ✗ Duplicate |
| Same identifier, same CTN, local types | ✗ Duplicate |
| Same identifier, different CTNs | ✓ Allowed |
| Local identifier matches global | ✗ Shadowing |

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-01-08 | Initial v1.0.0 specification |
