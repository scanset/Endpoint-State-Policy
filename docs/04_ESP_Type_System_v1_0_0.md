# ESP v1.0.0 — Type System

**Version:** 1.0.0
**Status:** Normative
**Last Updated:** 2026-01-08

---

> **v2.0.0 cross-reference.** The **policy-language** type system defined
> here (string / int / float / boolean / binary / timestamp / duration /
> path / identifier / record) is **unchanged** in v2.0.0. Strict typing
> and no-implicit-conversion rules continue to apply.
>
> v2.0.0 adds one new type at the **output-envelope** layer only:
> `Value` — an untyped JSON value used in two specific places:
> `HostInfo.attrs: map<string, Value>` (provider-specific host
> attributes like `subscription_id`, `region`, `account_id`) and
> `Observation.body: Value` (the collected payload). Neither is
> accessible from ESP source — policies cannot construct or inspect
> `Value`. It is purely a wire-shape concern for producers and
> consumers of `ResultEnvelope`.
>
> See `docs/09_ESP_Canonical_Schema_v2_1_1.md` §3.4 (HostInfo) and §4
> (Observation) for the envelope-level type rules.
>
> **v2.1.0 / v2.2.0 / v2.2.1** add no further DSL-language type
> changes. v2.1.0 adds one wire-shape field (`replay_hash_version: u8`
> on `ResultEnvelope`) but no policy-language consumer can construct
> or inspect it.

---

## 1. Overview

This document specifies the ESP type system, including data types, type compatibility rules, and operation legality. ESP v1.0.0 employs strict typing with no implicit conversions.

---

## 2. Data Types

### 2.1 Primitive Types

| Type | Description | Size/Precision |
|------|-------------|----------------|
| `string` | UTF-8 text | Variable length |
| `int` | Signed integer | 64-bit (−2⁶³ to 2⁶³−1) |
| `float` | Floating-point | IEEE 754 double (64-bit) |
| `boolean` | Boolean value | `true` or `false` |

### 2.2 Specialized Types

| Type | Description | Format |
|------|-------------|--------|
| `binary` | Raw byte sequence | Opaque bytes |
| `record_data` | Structured nested data | JSON-like structure |
| `version` | Semantic version | [SemVer 2.0.0] |
| `evr_string` | RPM version | `[epoch:]version[-release]` |

### 2.3 Type Syntax

```ebnf
data_type ::= "string" | "int" | "float" | "boolean"
            | "binary" | "record_data" | "version" | "evr_string"
```

Data type names are **case-sensitive** and parsed as identifiers.

---

## 3. Literal Representations

### 3.1 String Literals

| Form | Syntax | Escape Processing |
|------|--------|-------------------|
| Backtick | `` `content` `` | Yes |
| Raw | `` r`content` `` | No |
| Multiline | `` ```content``` `` | Yes |
| Raw Multiline | `` r```content``` `` | No |
| Empty | ``` `` ``` | N/A |

**Escape sequences (backtick strings):**
- ``` `` ``` → literal backtick

### 3.2 Integer Literals

```ebnf
integer_value ::= "-"? [0-9]+
```

**Range:** −9,223,372,036,854,775,808 to 9,223,372,036,854,775,807

**Examples:**
```
0
-1
42
9223372036854775807
```

Overflow at parse time is an error.

### 3.3 Float Literals

```ebnf
float_value ::= "-"? [0-9]+ "." [0-9]+
```

**Precision:** IEEE 754 double precision (64-bit)

**Examples:**
```
0.0
-3.14159
1.0
```

### 3.4 Boolean Literals

```ebnf
boolean_value ::= "true" | "false"
```

---

## 4. Type Compatibility

### 4.1 Strict Typing (N-7)

ESP v1.0.0 enforces strict type compatibility:

- Operations MUST be performed on compatible types
- No implicit type coercion is performed
- Type mismatches MUST be validation errors

### 4.2 Compatibility Matrix

| Left Type | Right Type | Compatible |
|-----------|------------|------------|
| `string` | `string` | ✓ |
| `int` | `int` | ✓ |
| `float` | `float` | ✓ |
| `boolean` | `boolean` | ✓ |
| `binary` | `binary` | ✓ |
| `record_data` | `record_data` | ✓ |
| `version` | `version` | ✓ |
| `evr_string` | `evr_string` | ✓ |
| `string` | `version` | ✓ |
| `string` | `evr_string` | ✓ |
| `int` | `float` | ✗ |
| `float` | `int` | ✗ |
| All other combinations | | ✗ |

**Key constraint:** `int` and `float` are NOT interchangeable. This is a deliberate v1.0.0 strictness requirement.

### 4.3 String-Representable Types

The following types are string-representable:

- `version` — Can be compared with `string` values
- `evr_string` — Can be compared with `string` values

This allows version literals to be written as strings:
```esp
package_version version >= `1.2.0`
```

---

## 5. Operations

### 5.1 Operation Categories

| Category | Operators |
|----------|-----------|
| Comparison | `=`, `!=`, `>`, `<`, `>=`, `<=` |
| String | `ieq`, `ine`, `contains`, `starts`, `ends`, `not_contains`, `not_starts`, `not_ends` |
| Pattern | `pattern_match`, `matches` |
| Set | `subset_of`, `superset_of` |
| Arithmetic | `+`, `-`, `*`, `/`, `%` |

### 5.2 Operation Legality by Type

| Operation | string | int | float | boolean | binary | record_data | version | evr_string |
|-----------|--------|-----|-------|---------|--------|-------------|---------|------------|
| `=` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `!=` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `>` | ✓¹ | ✓ | ✓ | ✗ | ✗ | ✗ | ✓² | ✓³ |
| `<` | ✓¹ | ✓ | ✓ | ✗ | ✗ | ✗ | ✓² | ✓³ |
| `>=` | ✓¹ | ✓ | ✓ | ✗ | ✗ | ✗ | ✓² | ✓³ |
| `<=` | ✓¹ | ✓ | ✓ | ✗ | ✗ | ✗ | ✓² | ✓³ |
| `ieq` | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| `ine` | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| `contains` | ✓ | ✗ | ✗ | ✗ | ✓⁴ | ✗ | ✗ | ✗ |
| `starts` | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| `ends` | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| `not_contains` | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| `not_starts` | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| `not_ends` | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| `pattern_match` | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| `matches` | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| `subset_of` | ✓⁵ | ✓⁵ | ✓⁵ | ✓⁵ | ✗ | ✗ | ✗ | ✗ |
| `superset_of` | ✓⁵ | ✓⁵ | ✓⁵ | ✓⁵ | ✗ | ✗ | ✗ | ✗ |

**Notes:**
1. Lexicographic (byte-wise) comparison
2. Semantic version comparison per [SemVer 2.0.0]
3. RPM EVR comparison per `rpmvercmp` algorithm
4. Byte sequence search
5. Requires collection context from SET operation

### 5.3 Arithmetic Operations

Arithmetic operations are used in RUN blocks:

| Operation | Symbol | Operand Types | Result Type |
|-----------|--------|---------------|-------------|
| Addition | `+` | `int`, `float` | Same as operand |
| Subtraction | `-` | `int`, `float` | Same as operand |
| Multiplication | `*` | `int`, `float` | Same as operand |
| Division | `/` | `int`, `float` | Same as operand |
| Modulus | `%` | `int`, `float` | Same as operand |

**Constraints:**
- Both operands MUST be the same type
- Division by zero is a runtime error
- Integer overflow behavior is implementation-defined

---

## 6. Version Comparison Semantics

### 6.1 SemVer (version type)

The `version` type follows [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

**Format:**
```
MAJOR.MINOR.PATCH[-PRERELEASE][+BUILD]
```

**Comparison rules:**
1. Compare MAJOR, MINOR, PATCH numerically (left to right)
2. Pre-release versions have lower precedence than normal versions
3. Pre-release identifiers compared lexically (numeric identifiers compared numerically)
4. Build metadata is ignored in comparisons

**Examples:**
```
1.0.0 < 1.0.1 < 1.1.0 < 2.0.0
1.0.0-alpha < 1.0.0-beta < 1.0.0
1.0.0-alpha.1 < 1.0.0-alpha.2
1.0.0+build1 = 1.0.0+build2
```

### 6.2 EVR (evr_string type)

The `evr_string` type follows RPM epoch:version-release format.

**Format:**
```
[EPOCH:]VERSION[-RELEASE]
```

**Components:**
- **EPOCH** — Numeric, defaults to 0 if omitted
- **VERSION** — Alphanumeric segments
- **RELEASE** — Alphanumeric segments (optional)

**Comparison rules:**
1. EPOCH takes absolute precedence (compared numerically)
2. VERSION compared using RPM `rpmvercmp` algorithm
3. RELEASE compared using RPM `rpmvercmp` algorithm

**RPM segment comparison:**
- Split into alphanumeric segments
- Numeric segments compared numerically
- Alphabetic segments compared lexically
- Numeric segments sort higher than alphabetic

**Examples:**
```
0:1.0.0-1 < 0:1.0.0-2
0:1.0.0-1 < 0:1.0.1-1
1:0.0.1-1 > 0:99.99.99-99
1.0.0-1 = 0:1.0.0-1
1.0 < 1.0.1
1.0a < 1.0b
1.0.1 > 1.0.1a
```

---

## 7. Record Data Type

### 7.1 Structure

The `record_data` type represents structured nested data (JSON-like):

- Objects with string keys
- Arrays with ordered elements
- Nested structures

### 7.2 Field Path Access

Record fields are accessed using dot notation:

```ebnf
field_path ::= path_component ("." path_component)*
path_component ::= identifier | index | wildcard
index ::= [0-9]+
wildcard ::= "*"
```

**Examples:**
```
settings.security.enabled
users.0.name
users.*.role
config.database.hosts.0
```

### 7.3 Wildcard Semantics

The wildcard `*` matches all elements at that level:

- `users.*.name` — All `name` fields in `users` array
- `config.*.enabled` — All `enabled` fields in `config` object

Wildcard results produce collections for entity checks.

---

## 8. Type Validation

### 8.1 Validation Timing

Type validation MUST occur at compile time (validation phase), not runtime.

### 8.2 Validation Errors

| Error | Condition |
|-------|-----------|
| Type mismatch | Operation applied to incompatible types |
| Invalid operation | Operation not legal for declared type |
| Undefined type | Unknown type identifier |

### 8.3 Examples

**Valid:**
```esp
STATE size_check
    size int > 1024
STATE_END
```

**Invalid (type mismatch):**
```esp
STATE invalid_check
    size int > `1024`    # Error: comparing int to string
STATE_END
```

**Invalid (operation not legal):**
```esp
STATE invalid_check
    enabled boolean > true    # Error: > not valid for boolean
STATE_END
```

---

## 9. RUN Operation Type Rules

### 9.1 Operation Input/Output Types

| Operation | Input Type | Output Type |
|-----------|------------|-------------|
| `CONCAT` | string | string |
| `SPLIT` | string | string[] |
| `SUBSTRING` | string | string |
| `REGEX_CAPTURE` | string | string |
| `ARITHMETIC` | int or float | Same as input |
| `COUNT` | collection | int |
| `UNIQUE` | collection | Same element type |
| `MERGE` | collections | Same element type |
| `EXTRACT` | object | Field type |
| `END` | string | string |

### 9.2 Type Inference

RUN operations infer result type from input:

```esp
VAR count int 0

RUN item_count COUNT
    OBJ my_set items
RUN_END
# item_count is int

VAR multiplied float 1.0

RUN computed ARITHMETIC
    VAR multiplied
    * 2.5
RUN_END
# computed is float (same as input)
```

---

## 10. Variable Type Declarations

### 10.1 Syntax

```ebnf
variable_declaration ::= "VAR" space identifier space data_type
                         (space direct_value)? statement_end
```

### 10.2 Type Enforcement

- Variable type is fixed at declaration
- Initial value (if present) MUST match declared type
- All references to variable MUST be type-compatible

**Example:**
```esp
VAR threshold int 1024
VAR config_path string `/etc/app/config`
VAR ratio float 0.75
VAR enabled boolean true
```

---

## Appendix A: Type Summary

| Type | Equality | Ordering | String Ops | Pattern Ops | Set Ops | Arithmetic |
|------|----------|----------|------------|-------------|---------|------------|
| `string` | ✓ | ✓¹ | ✓ | ✓ | ✓² | ✗ |
| `int` | ✓ | ✓ | ✗ | ✗ | ✓² | ✓ |
| `float` | ✓ | ✓ | ✗ | ✗ | ✓² | ✓ |
| `boolean` | ✓ | ✗ | ✗ | ✗ | ✓² | ✗ |
| `binary` | ✓ | ✗ | ✓³ | ✗ | ✗ | ✗ |
| `record_data` | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ |
| `version` | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ |
| `evr_string` | ✓ | ✓ | ✗ | ✗ | ✗ | ✗ |

¹ Lexicographic
² Collection context required
³ `contains` only (byte search)

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-01-08 | Initial v1.0.0 specification |
