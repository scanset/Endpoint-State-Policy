# CTN Type Reference: `computed_values`

## Overview

Special CTN type for validating computed variables from RUN operations. This is designed for **testing and development only**, not for compliance scans.

**Platform:** All
**Use Case:** Validate that RUN operations produce expected results

---

## Object Fields (Input)

| Field | Type | Required | Description | Example |
|-------|------|----------|-------------|---------|
| `type` | string | No | Validation type marker (informational only) | `test`, `validation` |
| `description` | string | No | Description of what is being validated | `RUN operations test` |

### Notes

- Object fields are informational only
- No actual data collection occurs
- Validation happens against resolved variables from RUN operations

---

## Collected Data Fields (Output)

This CTN type does not collect data from the system. The collector returns an empty `CollectedData` structure.

| Field | Type | Description |
|-------|------|-------------|
| (none) | - | No fields collected |

**Notes:**
- The executor validates against `ExecutionContext.global_variables`
- Variables are populated by RUN operations earlier in the policy

---

## State Fields (Validation)

State fields use wildcard matching - any field name is accepted and validated against the corresponding variable.

### String Variables

| Field Pattern | Type | Operations | Description |
|---------------|------|------------|-------------|
| `*` (any name) | string | `=`, `!=`, `contains`, `not_contains`, `starts`, `ends` | Any string variable |

### Integer Variables

| Field Pattern | Type | Operations | Description |
|---------------|------|------------|-------------|
| `*_int` | int | `=`, `!=`, `>`, `<`, `>=`, `<=` | Any integer variable |

### Boolean Variables

| Field Pattern | Type | Operations | Description |
|---------------|------|------------|-------------|
| `*_bool` | boolean | `=`, `!=` | Any boolean variable |

---

## Collection Strategy

| Property | Value |
|----------|-------|
| Collector Type | `computed_values` |
| Collection Mode | Metadata (pass-through) |
| Required Capabilities | None |
| Expected Collection Time | 0ms |
| Memory Usage | 0MB |
| Network Intensive | No |
| CPU Intensive | No |
| Requires Elevated Privileges | No |

---

## ESP Examples

### Validate RUN operation result

```esp
VAR greeting string

RUN concat
    INPUT `Hello, `
    INPUT `World!`
    OUTPUT greeting
RUN_END

OBJECT validation_check
    type `test`
    description `Validate concat RUN operation`
OBJECT_END

STATE expected_result
    greeting string = `Hello, World!`
STATE_END

CTN computed_values
    TEST at_least_one all
    STATE_REF expected_result
    OBJECT_REF validation_check
CTN_END
```

### Validate integer computation

```esp
VAR result int

RUN add
    INPUT `40`
    INPUT `2`
    OUTPUT result
RUN_END

OBJECT math_check
    type `test`
OBJECT_END

STATE correct_sum
    result int = `42`
STATE_END

CTN computed_values
    TEST at_least_one all
    STATE_REF correct_sum
    OBJECT_REF math_check
CTN_END
```

### Validate boolean flag

```esp
VAR is_valid boolean

RUN validate_input
    INPUT some_data
    OUTPUT is_valid
RUN_END

OBJECT flag_check
    type `validation`
OBJECT_END

STATE must_be_valid
    is_valid boolean = true
STATE_END

CTN computed_values
    TEST at_least_one all
    STATE_REF must_be_valid
    OBJECT_REF flag_check
CTN_END
```

### String contains check

```esp
VAR output_message string

RUN generate_report
    INPUT config_data
    OUTPUT output_message
RUN_END

OBJECT report_check
    description `Verify report contains required section`
OBJECT_END

STATE has_required_section
    output_message string contains `COMPLIANCE SUMMARY`
STATE_END

CTN computed_values
    TEST at_least_one all
    STATE_REF has_required_section
    OBJECT_REF report_check
CTN_END
```

---

## Implementation Status

> **⚠️ STUB IMPLEMENTATION**
>
> The current executor is a stub that always passes. Full implementation requires:
> - Access to `ExecutionContext.global_variables`
> - Variable lookup by name from STATE field names
> - Type-aware comparison logic

---

## Error Conditions

| Condition | Error Type | Effect on TEST |
|-----------|------------|----------------|
| Variable not found | `MissingVariable` | Validation failure |
| Type mismatch | `TypeMismatch` | Validation failure |
| Invalid operation for type | `InvalidOperation` | Configuration error |

---

## Platform Notes

- Works identically on all platforms
- No system access required
- Pure in-memory variable validation

---

## Security Considerations

- No elevated privileges required
- No system data accessed
- Safe for testing and development

---

## Related CTN Types

| CTN Type | Relationship |
|----------|--------------|
| All CTN types | Can use computed values from RUN operations |

---

## Design Notes

### Why a separate CTN type?

1. **Separation of concerns** - Computed values validation is fundamentally different from system state validation
2. **No collection overhead** - Skip the collection phase entirely
3. **Clear intent** - Policies explicitly show what is being tested
4. **Testing support** - Enables unit testing of RUN operations

### Variable Resolution Flow

```
RUN operation → global_variables → computed_values executor → validation
```

The executor looks up STATE field names directly in `global_variables` rather than using collected data.
