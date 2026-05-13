# ESP v1.0.0 — Evaluation Semantics

**Version:** 1.0.0
**Status:** Normative
**Last Updated:** 2026-01-08

---

> **v2.0.0 cross-reference.** Outcome semantics (`Pass` / `Fail` /
> `Error`), TEST specification, and CRI AND/OR short-circuit rules in
> this document are **unchanged** in v2.0.0. What changes is how the
> **evidence** backing an outcome is carried on the wire:
>
> - v1.x: `PolicyResult.evidence` embedded the collected data inline,
>   duplicated across every policy that consumed it.
> - v2.0.0: evidence lives once in `ResultEnvelope.observations[]`.
>   `PolicyResult.observation_refs[]` cites the observations that
>   produced the outcome by uuid. A single file read cited by ten
>   policies appears once in `observations[]`, ten times in
>   `observation_refs[]`.
>
> This is a wire-shape refactor, not a semantic change: the set of
> facts that determined the outcome is identical; only their
> representation in the envelope differs. See
> `docs/09_ESP_Canonical_Schema_v2_1_1.md` §5 and §7 for the
> `PolicyResult` / `Observation` binding rules.
>
> **v2.1.0** extends the *resolution* phase only: `SET_REF` is now an
> accepted CTN content operand (the resolution step expands it to the
> underlying `OBJECT_REF` list before evaluation). Evaluation
> semantics — outcome rules, TEST specification, CRI short-circuiting
> — are unchanged.
>
> **v2.2.0** introduces an opt-in v2 replay-hash scheme that hashes
> `(intent, contract, outcome)` per **(criterion, OBJECT)** pair
> rather than per criterion. This is a hashing change, not an
> evaluation-semantics change — the same set of facts is hashed at a
> finer granularity. See Trust Model §0 for trust implications.

---

## 1. Overview

This document specifies the evaluation semantics for ESP v1.0.0, including outcome types, STATE evaluation, TEST specification, and CRI (criteria) logic.

---

## 2. Outcome Types

### 2.1 Evaluation Outcomes

Every evaluation produces one of three outcomes:

| Outcome | Description |
|---------|-------------|
| `Pass` | Compliance check succeeded — system is compliant |
| `Fail` | Compliance check found non-compliance |
| `Error` | Compliance check could not complete (system issue) |

### 2.2 Outcome Semantics

- **Pass** — All required conditions were met
- **Fail** — One or more conditions were not met, but evaluation completed
- **Error** — Evaluation could not complete (e.g., permission denied, timeout, unreachable)

### 2.3 Fail vs Error Distinction

| Situation | Outcome | Rationale |
|-----------|---------|-----------|
| Field not present in collected data | Fail | Data collected successfully, field missing |
| Field value doesn't match expected | Fail | Data collected, validation failed |
| Collector couldn't run (permission denied) | Error | System issue prevented evaluation |
| Collector timeout | Error | System issue prevented evaluation |
| Target system unreachable | Error | System issue prevented evaluation |

---

## 3. STATE Evaluation (N-10)

### 3.1 State Field Evaluation

Each STATE field evaluates to a boolean result by comparing collected data against the expected value using the specified operation.

```esp
STATE secure_file
    permissions string = `0600`    # Field 1
    owner string = `root`          # Field 2
STATE_END
```

### 3.2 Multiple Fields (Implicit AND)

When a STATE contains multiple fields, they combine using **implicit AND**:

```
STATE result = Field1 AND Field2 AND ... AND FieldN
```

All fields MUST pass for the STATE to pass.

### 3.3 Missing Field Behavior

If a field specified in STATE is not present in collected data:

| Situation | Outcome |
|-----------|---------|
| Field missing from collected record | **Fail** |
| Record path doesn't exist | **Fail** |
| Collection failed entirely | **Error** |

### 3.4 Multiple STATEs in CTN

When a CTN references multiple STATEs, they combine using the `state_operator` (default: AND):

```esp
CTN file_metadata
    TEST all all AND              # state_operator = AND
    STATE_REF state_a
    STATE_REF state_b
CTN_END
# Result: state_a AND state_b
```

```esp
CTN file_metadata
    TEST all all OR               # state_operator = OR
    STATE_REF state_a
    STATE_REF state_b
CTN_END
# Result: state_a OR state_b
```

### 3.5 State Operators

| Operator | Semantics |
|----------|-----------|
| `AND` | All states must pass for object to pass |
| `OR` | Any state passing means object passes |
| `ONE` | Exactly one state must pass |

---

## 4. TEST Specification (N-11)

### 4.1 TEST Syntax

```ebnf
test_spec ::= "TEST" space existence_check space item_check (space state_operator)?
```

**Components:**
- `existence_check` — How many objects must exist
- `item_check` — How many existing objects must pass validation
- `state_operator` — How multiple states combine (default: AND)

### 4.2 Existence Check

The existence check determines requirements for object presence:

| Check | Passes When |
|-------|-------------|
| `all` | All expected objects exist (found == expected) |
| `any` | Always passes — no existence constraint |
| `none` | No objects exist (found == 0) |
| `at_least_one` | One or more objects exist (found >= 1) |
| `only_one` | Exactly one object exists (found == 1) |

**Expected objects** = resolved candidate objects after reference expansion and filtering.

### 4.3 Item Check

The item check determines how many existing objects must pass state validation:

| Check | Passes When |
|-------|-------------|
| `all` | All existing objects pass state validation |
| `at_least_one` | At least one existing object passes |
| `only_one` | Exactly one existing object passes |
| `none_satisfy` | No existing objects pass (all fail) |

### 4.4 Evaluation Flow

```
1. Resolve object references (OBJECT_REF, SET_REF, inline)
2. Apply filters (SET-level, then object-level)
3. Evaluate existence_check against resolved count
4. If existence passes: evaluate item_check against state validation
5. Combine results for final CTN outcome
```

### 4.5 TEST Examples

**All files must exist and all must pass:**
```esp
TEST all all
```

**At least one file must exist, all existing must pass:**
```esp
TEST at_least_one all
```

**Files may or may not exist, but if any exist, at least one must pass:**
```esp
TEST any at_least_one
```

**No files should exist (absence check):**
```esp
TEST none all
```

**Exactly one file must exist and it must pass:**
```esp
TEST only_one all
```

---

## 5. CRI Logic (N-12)

### 5.1 CRI Block Structure

```ebnf
cri_block ::= "CRI" space logical_op (space negate_flag)? statement_end
              cri_content
              "CRI_END" statement_end
```

### 5.2 Logical Operators

| Operator | Semantics |
|----------|-----------|
| `AND` | All children must pass |
| `OR` | Any child passing is sufficient |

### 5.3 No Short-Circuiting

All children are **always evaluated**, regardless of intermediate results. This ensures:
- Complete reporting of all failures
- Consistent execution time
- Full evidence collection

### 5.4 CRI AND Evaluation

**Precedence (evaluated in order):**
1. If ALL children are `Pass` → `Pass`
2. If ANY child is `Error` → `Error`
3. Otherwise → `Fail`

**Truth Table:**

| Children | Result |
|----------|--------|
| [Pass, Pass, Pass] | Pass |
| [Pass, Fail, Pass] | Fail |
| [Pass, Error, Pass] | Error |
| [Fail, Fail, Fail] | Fail |
| [Error, Fail, Fail] | Error |
| [Error, Error, Error] | Error |

### 5.5 CRI OR Evaluation

**Precedence (evaluated in order):**
1. If ANY child is `Pass` → `Pass` (Pass-dominant)
2. If ALL children are `Error` → `Error`
3. Otherwise → `Fail`

**Truth Table:**

| Children | Result |
|----------|--------|
| [Fail, Fail, Pass] | Pass |
| [Error, Fail, Pass] | Pass |
| [Error, Error, Pass] | Pass |
| [Fail, Fail, Fail] | Fail |
| [Error, Fail, Fail] | Fail |
| [Error, Error, Error] | Error |

### 5.6 Negate Flag

The `negate` flag inverts the **entire block result** after evaluation:

```esp
CRI AND true    # negate = true
    CTN ...     # evaluates to Pass
CRI_END
# Final result: Fail (negated)
```

**Negation rules:**
- `Pass` → `Fail`
- `Fail` → `Pass`
- `Error` → `Error` (unchanged)

### 5.7 Nested CRI Blocks

CRI blocks can be nested to create complex logic:

```esp
CRI AND
    CRI OR
        CTN check_a ...
        CTN check_b ...
    CRI_END
    CTN check_c ...
CRI_END
# Result: (check_a OR check_b) AND check_c
```

---

## 6. Object Evaluation

### 6.1 Single Object

For a single object, evaluation proceeds:
1. Collect data for object
2. Apply filters (if any)
3. Evaluate all referenced STATEs against collected data
4. Combine STATE results using state_operator

### 6.2 Multiple Objects

For multiple objects (via SET or multiple OBJECT_REFs):
1. Collect data for each object
2. Apply SET-level filters
3. Apply object-level filters
4. Evaluate each object against STATEs
5. Apply existence_check to object count
6. Apply item_check to validation results

### 6.3 Filter Evaluation

Filters modify the set of objects before validation:

| Action | Behavior |
|--------|----------|
| `include` | Keep only objects that match filter states |
| `exclude` | Remove objects that match filter states |

Filter states use AND logic — all state conditions must match.

---

## 7. Evaluation Order

### 7.1 Tree Traversal

The criteria tree is evaluated **depth-first**:

```
CRI AND
├── CTN a        # Evaluated 1st
├── CRI OR
│   ├── CTN b    # Evaluated 2nd
│   └── CTN c    # Evaluated 3rd
└── CTN d        # Evaluated 4th
```

### 7.2 CTN Execution Order

Within a CTN:
1. Resolve objects and states
2. Collect data (batch if supported, then individual)
3. Apply SET-level filters
4. Apply object-level filters
5. Execute state validation
6. Determine CTN outcome

---

## 8. Error Handling

### 8.1 Error Propagation

Errors propagate through the tree according to CRI logic:
- CRI AND: Any Error → Error (unless all Pass)
- CRI OR: All Errors → Error (Pass overrides Error)

### 8.2 Partial Evaluation

Even when errors occur:
- All children are still evaluated (no short-circuit)
- All findings are collected
- All evidence is gathered

### 8.3 Error Recovery

Errors at one CTN do not prevent evaluation of siblings:

```esp
CRI AND
    CTN a    # Error (permission denied)
    CTN b    # Still evaluated, returns Pass
    CTN c    # Still evaluated, returns Fail
CRI_END
# Result: Error (due to CTN a)
# But CTN b and c findings are still recorded
```

---

## 9. Determinism

### 9.1 Deterministic Evaluation

Given the same policy and system state, evaluation MUST produce the same result:
- Same outcome (Pass/Fail/Error)
- Same findings
- Same evidence

### 9.2 Order Independence

While tree traversal follows document order, the logical result is independent of:
- Declaration order within DEF
- Reference order within CTN
- Child order within CRI (associative operations)

---

## 10. Summary Tables

### 10.1 Existence Check Summary

| Check | found=0 | found=1 | found=N | found<expected |
|-------|---------|---------|---------|----------------|
| `all` | Fail* | Pass** | Pass** | Fail |
| `any` | Pass | Pass | Pass | Pass |
| `none` | Pass | Fail | Fail | Fail |
| `at_least_one` | Fail | Pass | Pass | Pass |
| `only_one` | Fail | Pass | Fail | Fail |

\* Pass if expected=0
\** Only if found==expected

### 10.2 CRI Logic Summary

| Operator | Pass Condition | Error Condition |
|----------|----------------|-----------------|
| `AND` | All children Pass | Any child Error (when not all Pass) |
| `OR` | Any child Pass | All children Error |

### 10.3 Negation Summary

| Original | Negated |
|----------|---------|
| Pass | Fail |
| Fail | Pass |
| Error | Error |

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-01-08 | Initial v1.0.0 specification |
