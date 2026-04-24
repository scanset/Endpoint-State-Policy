# ESP v1.0.0 — Error Model

**Version:** 1.0.0
**Status:** Normative
**Last Updated:** 2026-01-08

---

## 1. Overview

This document specifies the error model for ESP v1.0.0, including error categories, severity levels, error codes, and the mapping between errors and evaluation outcomes.

---

## 2. Error Categories (N-19)

ESP defines three error categories based on when errors occur:

| Category | When | Result |
|----------|------|--------|
| **ParseError** | Tokenization or grammar fails | Compilation fails |
| **ValidationError** | Symbol, reference, type, or structural checks fail | Compilation fails |
| **EvaluationError** | Runtime collection or execution fails | `Outcome::Error` |

### 2.1 ParseError

Errors during lexical analysis or syntax parsing. The policy cannot be compiled.

**Causes:**
- Invalid characters in source
- Unterminated string literals
- Grammar violations
- Unmatched block delimiters

**Code ranges:** E020-E028 (Lexical), E040-E050, E086-E087 (Syntax)

### 2.2 ValidationError

Errors during semantic analysis after successful parsing. The policy cannot be compiled.

**Causes:**
- Duplicate symbol declarations
- Undefined references
- Type mismatches
- Shadowing violations
- Missing required META fields
- Structural constraint violations

**Code ranges:** E051-E095 (Symbols), E110-E140 (References), E180-E200 (Semantic), E230-E247 (Structural)

### 2.3 EvaluationError

Errors during runtime execution. The policy compiles but evaluation cannot complete.

**Causes:**
- Data collection failures (permission denied, timeout)
- Object not found
- Execution timeout
- Platform errors

**Result:** CTN produces `Outcome::Error` instead of Pass/Fail.

---

## 3. Error Code Ranges

| Range | Category | Description |
|-------|----------|-------------|
| `ERR001-ERR003` | System | Critical system errors |
| `E005-E012` | FileProcessing | File access and encoding |
| `E020-E028` | Lexical | Tokenization errors |
| `E040-E050` | Syntax | Grammar and parsing errors |
| `E051-E095` | Symbols | Symbol discovery and scoping |
| `E086-E087` | Syntax | Parser internal errors |
| `E110-E140` | References | Reference resolution |
| `E180-E200` | Semantic | Type checking and operations |
| `E230-E247` | Structural | Block structure and META validation |
| `C001-C042` | Consumer | Integration errors |
| `T001-T015` | Transformation | FFI and IR transformation |
| `I001-I095` | Success | Informational success codes |

---

## 4. Severity Levels

Each error has a severity level affecting handling behavior:

| Severity | Description | Typical Handling |
|----------|-------------|------------------|
| **Critical** | System failure, cannot continue | Immediate halt |
| **High** | Significant error, compilation fails | Halt after phase |
| **Medium** | Recoverable error, may continue | Collect and report |
| **Low** | Minor issue, informational | Log and continue |

### 4.1 Error Metadata

Each error code has associated metadata:

```
ErrorMetadata {
    code: &str,
    category: &str,
    severity: Severity,
    recoverable: bool,
    requires_halt: bool,
    description: &str,
    recommended_action: &str,
}
```

| Field | Description |
|-------|-------------|
| `recoverable` | Whether compilation can continue after this error |
| `requires_halt` | Whether to stop processing immediately |

---

## 5. Key Compiler Errors

### 5.1 Lexical Errors (E020-E028)

| Code | Error | Description |
|------|-------|-------------|
| E020 | InvalidCharacter | Invalid character in source text |
| E021 | UnterminatedString | String literal not closed |
| E022 | InvalidNumber | Malformed number literal |
| E023 | IdentifierTooLong | Identifier exceeds 255 characters |
| E024 | StringTooLarge | String exceeds size limit |
| E025 | ReservedKeyword | Reserved keyword used as identifier |

### 5.2 Syntax Errors (E040-E050)

| Code | Error | Description |
|------|-------|-------------|
| E040 | MissingEof | Missing EOF token |
| E041 | EmptyTokenStream | No tokens to parse |
| E042 | UnmatchedDelimiter | Block start without end |
| E043 | GrammarViolation | EBNF grammar violation |
| E050 | UnexpectedToken | Unexpected token during parsing |

### 5.3 Symbol Errors (E051-E095)

| Code | Error | Description |
|------|-------|-------------|
| E051 | SymbolDiscoveryError | General symbol discovery failure |
| E081 | SymbolTableConstructionError | Symbol table build failure |
| E090 | DuplicateSymbol | Duplicate identifier in same scope |
| E091 | SymbolShadowing | Local symbol shadows global symbol |
| E094 | MultipleCtnObjects | More than one local OBJECT in CTN |
| E095 | SymbolScopeValidationError | Scope boundary violation |

### 5.4 Reference Errors (E110-E140)

| Code | Error | Description |
|------|-------|-------------|
| E110 | UndefinedReference | Reference target not found |
| E140 | CircularDependency | Circular variable dependency |

### 5.5 Semantic Errors (E180-E200)

| Code | Error | Description |
|------|-------|-------------|
| E180 | TypeIncompatibility | Operation incompatible with type |
| E181 | RuntimeOperationError | RUN operation parameter mismatch |
| E200 | SetConstraintViolation | SET operand count violation |

### 5.6 Structural Errors (E230-E247)

| Code | Error | Description |
|------|-------|-------------|
| E230 | InvalidBlockOrdering | Blocks in wrong order |
| E240 | IncompleteDefinition | Missing required elements |
| E241 | ImplementationLimitExceeded | Complexity limit exceeded |
| E242 | EmptyCriteriaBlock | CRI block has no children |
| E246 | MissingMetadata | META block required but absent |
| E247 | MetadataValidationError | META field invalid or missing |

---

## 6. Runtime Errors

Runtime errors occur during policy evaluation and do not have logging codes. They result in `Outcome::Error` for the affected CTN.

### 6.1 Execution Errors

| Error | Description |
|-------|-------------|
| NoContractRegistered | CTN type has no registered contract |
| NoCollectorRegistered | CTN type has no data collector |
| NoExecutorRegistered | CTN type has no executor |
| DataCollectionFailed | Collector could not gather data |
| ExecutorFailed | Executor encountered an error |
| FilterEvaluationFailed | Filter evaluation error |
| StateNotFound | Referenced state not in context |

### 6.2 Collection Errors

| Error | Description |
|-------|-------------|
| CollectionFailed | General collection failure |
| CollectionTimeout | Collection exceeded time limit |
| AccessDenied | Permission denied accessing object |
| ObjectNotFound | Target object does not exist |
| MissingCollectionField | Required field not collected |

### 6.3 CTN Execution Errors

| Error | Description |
|-------|-------------|
| ExecutionFailed | General execution failure |
| DataValidationFailed | Collected data invalid |
| StateValidationFailed | State check could not complete |
| ContractViolation | CTN contract requirements not met |
| ExistenceCheckFailed | Object count mismatch |
| ItemCheckFailed | Item check could not determine result |
| ExecutionTimeout | Execution exceeded time limit |

---

## 7. Error to Outcome Mapping

| Error Category | Compilation | Evaluation Outcome |
|----------------|-------------|-------------------|
| ParseError | Fails | N/A (no policy) |
| ValidationError | Fails | N/A (no policy) |
| EvaluationError | Succeeds | `Outcome::Error` |

### 7.1 Error Propagation in CRI

When a CTN produces `Outcome::Error`:

| CRI Type | Error Handling |
|----------|----------------|
| CRI AND | Any Error (when not all Pass) → Error |
| CRI OR | All Errors → Error; Pass overrides Error |

See [06-evaluation-semantics.md](06-evaluation-semantics.md) for complete CRI logic.

---

## 8. Error Reporting

### 8.1 Error Structure

Errors include contextual information:

| Field | Description |
|-------|-------------|
| `code` | Error code (e.g., E090) |
| `message` | Human-readable description |
| `span` | Source location (if applicable) |
| `severity` | Critical/High/Medium/Low |
| `recommended_action` | Suggested fix |

### 8.2 Span Information

For errors with source location:

```
Span {
    start: Position { offset, line, column },
    end: Position { offset, line, column },
}
```

### 8.3 Example Error Output

```
E090 [Medium] Duplicate symbol 'config' in global scope
  --> policy.esp:15:5
   |
15 |     STATE config
   |     ^^^^^^^^^^^^
   |
   = first declared at policy.esp:8:5
   = help: Use unique identifiers within each scope
```

---

## 9. Summary

| Category | Code Range | Compilation | Outcome |
|----------|------------|-------------|---------|
| ParseError | E020-E050 | Fails | N/A |
| ValidationError | E051-E247 | Fails | N/A |
| EvaluationError | (runtime) | Succeeds | Error |

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-01-08 | Initial v1.0.0 specification |
