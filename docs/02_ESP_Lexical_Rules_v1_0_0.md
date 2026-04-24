# ESP v1.0.0 — Lexical Rules Specification

**Version:** 1.0.0
**Status:** Normative
**Last Updated:** 2026-01-08

---

## 1. Overview

This document specifies the lexical rules for the Endpoint State Policy (ESP) language. These rules govern how source text is tokenized before parsing.

### 1.1 Standards Alignment

- **Character encoding:** UTF-8 (RFC 3629)
- **Keywords:** Case-sensitive per ISO 14977 EBNF conventions
- **Numeric literals:** IEEE 754 for floating-point, two's complement for integers

---

## 2. Source Text Encoding

### 2.1 Character Set

| Property | Specification |
|----------|---------------|
| Encoding | UTF-8 (no BOM) |
| Line endings | LF (preferred), CRLF (accepted) |
| Identifiers | ASCII only: `[a-zA-Z0-9_]` |
| String content | ASCII printable `[0x20-0x7E]` plus whitespace |
| Non-ASCII | Parser error |

### 2.2 File Constraints

| Constraint | Recommended Limit |
|------------|-------------------|
| File size | 10 MB |
| Line length | 4,096 characters |
| Nesting depth | 10 levels |

---

## 3. Token Categories

ESP tokens are classified into the following categories:

1. **Keywords** — Reserved structural words
2. **Operators** — Comparison, string, pattern, set, and arithmetic operators
3. **Literals** — String, integer, float, and boolean values
4. **Identifiers** — User-defined names and data type names
5. **Punctuation** — Structural characters (`.`)
6. **Whitespace** — Spaces, tabs, newlines
7. **Comments** — Line comments starting with `#`

---

## 4. Keywords

All keywords are **case-sensitive**. Keywords are reserved and MUST NOT be used as identifiers.

### 4.1 Block Structure Keywords (UPPERCASE)

| Keyword | Description |
|---------|-------------|
| `META` | Metadata block start |
| `META_END` | Metadata block end |
| `DEF` | Definition block start |
| `DEF_END` | Definition block end |
| `CRI` | Criteria block start |
| `CRI_END` | Criteria block end |
| `CTN` | Criterion block start |
| `CTN_END` | Criterion block end |
| `STATE` | State definition start |
| `STATE_END` | State definition end |
| `OBJECT` | Object definition start |
| `OBJECT_END` | Object definition end |
| `RUN` | Runtime operation start |
| `RUN_END` | Runtime operation end |
| `FILTER` | Filter block start |
| `FILTER_END` | Filter block end |
| `SET` | Set operation start |
| `SET_END` | Set operation end |
| `TEST` | Test specification |

### 4.2 Block Terminators (lowercase)

| Keyword | Description |
|---------|-------------|
| `parameters` | Parameters block start |
| `parameters_end` | Parameters block end |
| `select` | Select block start |
| `select_end` | Select block end |
| `record` | Record check start |
| `record_end` | Record check end |

### 4.3 Reference Keywords (UPPERCASE)

| Keyword | Description |
|---------|-------------|
| `VAR` | Variable reference |
| `STATE_REF` | State reference |
| `OBJECT_REF` | Object reference |
| `SET_REF` | Set reference |
| `OBJ` | Object field extraction (in RUN) |

### 4.4 Logical Operators (UPPERCASE)

| Keyword | Description |
|---------|-------------|
| `AND` | Logical AND |
| `OR` | Logical OR |
| `ONE` | Exactly one (state join) |

### 4.5 Runtime Operations (UPPERCASE)

| Keyword | Description |
|---------|-------------|
| `CONCAT` | String concatenation |
| `SPLIT` | String splitting |
| `SUBSTRING` | Substring extraction |
| `REGEX_CAPTURE` | Regex capture groups |
| `ARITHMETIC` | Arithmetic operations |
| `COUNT` | Collection counting |
| `UNIQUE` | Unique elements |
| `END` | End marker operation |
| `MERGE` | Collection merge |
| `EXTRACT` | Field extraction |

### 4.6 Module Fields (lowercase with underscore)

| Keyword | Description |
|---------|-------------|
| `module_name` | Module name field |
| `verb` | PowerShell verb |
| `noun` | PowerShell noun |
| `module_id` | Module identifier |
| `module_version` | Module version |

### 4.7 Filter Actions (lowercase)

| Keyword | Description |
|---------|-------------|
| `include` | Include matching items |
| `exclude` | Exclude matching items |

### 4.8 Set Operations (lowercase)

| Keyword | Description |
|---------|-------------|
| `union` | Set union (1+ operands) |
| `intersection` | Set intersection (2+ operands) |
| `complement` | Set complement (exactly 2 operands) |

### 4.9 Test Components (lowercase)

**Existence Checks:**
| Keyword | Description |
|---------|-------------|
| `any` | Any items exist |
| `all` | All items exist |
| `none` | No items exist |
| `at_least_one` | At least one item exists |
| `only_one` | Exactly one item exists |

**Item Checks:**
| Keyword | Description |
|---------|-------------|
| `all` | All items satisfy |
| `at_least_one` | At least one satisfies |
| `only_one` | Exactly one satisfies |
| `none_satisfy` | No items satisfy |

### 4.10 Other Keywords

| Keyword | Description |
|---------|-------------|
| `behavior` | Object behavior specification |

---

## 5. Operators

Operators are tokenized as dedicated symbol tokens, NOT as keywords or identifiers.

### 5.1 Comparison Operators

| Operator | Token | Description |
|----------|-------|-------------|
| `=` | `Equals` | Equality |
| `!=` | `NotEquals` | Inequality |
| `>` | `GreaterThan` | Greater than |
| `<` | `LessThan` | Less than |
| `>=` | `GreaterThanOrEqual` | Greater than or equal |
| `<=` | `LessThanOrEqual` | Less than or equal |

### 5.2 String Operators

| Operator | Token | Description |
|----------|-------|-------------|
| `ieq` | `CaseInsensitiveEquals` | Case-insensitive equality |
| `ine` | `CaseInsensitiveNotEquals` | Case-insensitive inequality |
| `contains` | `Contains` | Substring containment |
| `starts` | `StartsWith` | Prefix match |
| `ends` | `EndsWith` | Suffix match |
| `not_contains` | `NotContains` | No substring |
| `not_starts` | `NotStartsWith` | No prefix match |
| `not_ends` | `NotEndsWith` | No suffix match |

### 5.3 Pattern Operators

| Operator | Token | Description |
|----------|-------|-------------|
| `pattern_match` | `PatternMatch` | Glob pattern match |
| `matches` | `Matches` | Regex match |

### 5.4 Set Operators

| Operator | Token | Description |
|----------|-------|-------------|
| `subset_of` | `SubsetOf` | Subset relationship |
| `superset_of` | `SupersetOf` | Superset relationship |

### 5.5 Arithmetic Operators

| Operator | Token | Description |
|----------|-------|-------------|
| `+` | `Plus` | Addition |
| `-` | `Minus` | Subtraction |
| `*` | `Multiply` | Multiplication |
| `/` | `Divide` | Division |
| `%` | `Modulus` | Modulo |

---

## 6. Identifiers

### 6.1 Identifier Syntax

```ebnf
identifier ::= [a-zA-Z_][a-zA-Z0-9_]*
```

**Constraints:**
- Maximum length: 255 characters
- Case-sensitive
- MUST NOT be a reserved keyword
- MUST NOT start with a digit

### 6.2 Data Type Identifiers

The following are parsed as identifiers (NOT keywords) and have semantic meaning based on grammatical context:

| Identifier | Description |
|------------|-------------|
| `string` | String data type |
| `int` | 64-bit signed integer |
| `float` | IEEE 754 double precision |
| `boolean` | Boolean (true/false) |
| `binary` | Binary data |
| `record_data` | Structured record data |
| `version` | Version string |
| `evr_string` | Epoch:Version-Release string |

### 6.3 Context-Sensitive Identifiers

The following are parsed as identifiers and have semantic meaning only in specific contexts (e.g., within RUN blocks):

| Identifier | Context | Description |
|------------|---------|-------------|
| `literal` | RUN parameter | Literal value |
| `pattern` | RUN parameter | Pattern string |
| `delimiter` | RUN parameter | Delimiter string |
| `character` | RUN parameter | Character value |
| `start` | RUN parameter | Start position |
| `length` | RUN parameter | Length value |
| `field` | Record check | Field path prefix |

---

## 7. Literals

### 7.1 String Literals

**Backtick String:**
```ebnf
backtick_string ::= "`" ([^`] | "``")* "`"
```
- `\`\`` inside backticks = literal backtick
- `\`\`` alone = empty string

**Raw String:**
```ebnf
raw_string ::= "r`" ([^`] | "``")* "`"
```
- No escape sequence processing

**Multiline String:**
```ebnf
multiline_string ::= "```" ([^`] | "`" [^`] | "``" [^`])* "```"
```

**Raw Multiline String:**
```ebnf
raw_multiline ::= "r```" ([^`] | "`" [^`] | "``" [^`])* "```"
```

### 7.2 Numeric Literals

**Integer:**
```ebnf
integer_value ::= "-"? [0-9]+
```
- Range: −9,223,372,036,854,775,808 to 9,223,372,036,854,775,807 (64-bit signed)
- Overflow at parse time is an error

**Float:**
```ebnf
float_value ::= "-"? [0-9]+ "." [0-9]+
```
- IEEE 754 double precision (64-bit)

### 7.3 Boolean Literals

```ebnf
boolean_value ::= "true" | "false"
```

---

## 8. Whitespace and Comments

### 8.1 Whitespace

| Token | Description |
|-------|-------------|
| Space | Single space character (`0x20`) |
| Tab | Tab character (`0x09`) |
| Newline | LF (`0x0A`) or CRLF (`0x0D 0x0A`) |

### 8.2 Comments

```ebnf
comment ::= "#" [^\n]* newline
```

- Comments extend from `#` to end of line
- Comments are ignored during parsing
- Comments MAY appear on their own line or after a statement

### 8.3 Statement Termination

```ebnf
statement_end ::= space? comment? newline
```

---

## 9. META Block Fields (v1.0.0)

### 9.1 Required Fields

The following META fields are **REQUIRED** for v1.0.0 compliance:

| Field | Type | Description |
|-------|------|-------------|
| `esp_id` | string | Unique policy identifier |
| `version` | string | Policy revision (SemVer format) |
| `dsl_schema_version` | string | DSL schema version (SemVer: MAJOR.MINOR.PATCH) |
| `platform` | string | Target platform |
| `criticality` | enum | Policy criticality level |
| `control_mapping` | string | Compliance control mapping |
| `title` | string | Human-readable policy title |

### 9.2 Criticality Values

The `criticality` field MUST be one of (case-insensitive):

- `critical`
- `high`
- `medium`
- `low`
- `info`

### 9.3 Control Mapping Format

The `control_mapping` field MUST follow the format:

```
FRAMEWORK:CONTROL_ID[,FRAMEWORK:CONTROL_ID]*
```

**Examples:**
- `NIST:AC-6`
- `CIS:1.1.1`
- `NIST:AC-6,CIS:1.1.1,DISA-STIG:SV-253284`

### 9.4 DSL Schema Version Format

The `dsl_schema_version` field MUST be valid SemVer:

```
MAJOR.MINOR.PATCH[-prerelease][+build]
```

**Examples:**
- `1.0.0`
- `1.0.0-alpha`
- `1.0.0-rc.1`
- `1.0.0+build.123`

### 9.5 Recommended Fields

| Field | Type | Description |
|-------|------|-------------|
| `agent_type` | string | Target agent type |
| `author` | string | Policy author |
| `description` | string | Policy description |

### 9.6 Policy Identity Tuple

For v1.0.0, policies are uniquely identified by the tuple:

```
(esp_id, version, dsl_schema_version)
```

This tuple MUST be unique across all policies in a policy set.

---

## 10. Tokenization Algorithm

### 10.1 Token Classification

```
1. If char is '#', consume comment to end of line → Comment token
2. If char is '`', parse string literal → StringLiteral token
3. If char is digit or '-' followed by digit, parse number → Integer or Float token
4. If char is letter or '_', parse word:
   a. If word is reserved keyword → Keyword token
   b. If word is operator word (ieq, contains, etc.) → Operator token
   c. If word is "true" or "false" → Boolean token
   d. Otherwise → Identifier token
5. If char sequence is operator symbol (=, !=, etc.) → Operator token
6. If char is '.', → Dot token
7. If char is whitespace → Space/Tab/Newline token
8. Otherwise → Error
```

### 10.2 Operator Precedence in Tokenization

When tokenizing, longer operator sequences take precedence:

- `!=` is tokenized as `NotEquals`, not `!` + `=`
- `>=` is tokenized as `GreaterThanOrEqual`, not `>` + `=`
- `<=` is tokenized as `LessThanOrEqual`, not `<` + `=`

---

## 11. Error Handling

### 11.1 Lexical Errors

| Error | Description |
|-------|-------------|
| Invalid character | Non-ASCII character in source |
| Unterminated string | String literal missing closing backtick |
| Integer overflow | Integer literal exceeds 64-bit range |
| Invalid escape | Unknown escape sequence in string |
| Invalid identifier | Identifier starting with digit |

### 11.2 Error Recovery

The lexer SHOULD attempt to recover from errors by:

1. Skipping invalid characters until valid token boundary
2. Reporting error with source location (line, column)
3. Continuing tokenization to find additional errors

---

## Appendix A: Complete Keyword List

```
AND, ARITHMETIC, behavior, complement, CONCAT, COUNT, CRI, CRI_END, CTN,
CTN_END, DEF, DEF_END, END, exclude, EXTRACT, FILTER, FILTER_END, include,
intersection, MERGE, META, META_END, module_id, module_name, module_version,
noun, OBJ, OBJECT, OBJECT_END, OBJECT_REF, ONE, OR, parameters,
parameters_end, record, record_end, REGEX_CAPTURE, RUN, RUN_END, select,
select_end, SET, SET_END, SET_REF, SPLIT, STATE, STATE_END, STATE_REF,
SUBSTRING, TEST, UNIQUE, union, VAR, verb

Test components: all, any, at_least_one, none, none_satisfy, only_one
```

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-01-08 | Initial v1.0.0 specification with META field requirements |
