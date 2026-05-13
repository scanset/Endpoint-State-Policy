# ESP v2.1.0 — EBNF Grammar Specification

**Version:** 2.1.0
**Status:** Normative (v1.0.0 baseline + v2.1.0 extensions)
**Last Updated:** 2026-04-28
**Standards:** ISO 14977 EBNF with extensions

> **What's new in v2.1.0:** `SET_REF` is now a first-class CTN content
> operand (see `ctn_content` in §7). The rest of the grammar is
> unchanged from v1.0.0.

---

## Notation

```
Based on ISO 14977 EBNF with extensions:

::=         Definition
|           Alternation (choice)
?           Zero or one (optional)
*           Zero or more
+           One or more
[abc]       Character class (any of a, b, c)
[^abc]      Negated class (anything except a, b, c)
[a-z]       Character range
"text"      Literal (case-sensitive)
``          Empty string
(* ... *)   Comment
```

---

## 1. File Structure

```ebnf
(* Root production - an ESP file *)
esp_file ::= metadata? definition

(* Comments can appear anywhere whitespace is allowed *)
comment ::= "#" [^\n]* newline
```

---

## 2. Metadata Block (v1.0.0 Enhanced)

```ebnf
(* META block contains policy metadata *)
metadata ::= "META" statement_end
             metadata_field*
             "META_END" statement_end

(* Individual metadata field *)
metadata_field ::= metadata_key space metadata_value statement_end

(* Metadata keys - v1.0.0 required and optional *)
metadata_key ::= required_metadata_key | optional_metadata_key | identifier

(* v1.0.0 REQUIRED metadata keys *)
required_metadata_key ::= "esp_id"
                        | "version"
                        | "dsl_schema_version"
                        | "platform"
                        | "criticality"
                        | "control_mapping"
                        | "title"

(* v1.0.0 RECOMMENDED metadata keys *)
optional_metadata_key ::= "agent_type"
                        | "author"
                        | "description"

(* Metadata values *)
metadata_value ::= backtick_string | integer_value | float_value | boolean_value

(* v1.0.0 Criticality enumeration - case-insensitive *)
criticality_value ::= "critical" | "high" | "medium" | "low" | "info"

(* v1.0.0 DSL schema version - SemVer format *)
dsl_schema_version_value ::= semver

(* SemVer format per Semantic Versioning 2.0.0 *)
semver ::= major "." minor "." patch ("-" prerelease)? ("+" build_metadata)?
major ::= [0-9]+
minor ::= [0-9]+
patch ::= [0-9]+
prerelease ::= prerelease_id ("." prerelease_id)*
prerelease_id ::= [a-zA-Z0-9-]+
build_metadata ::= build_id ("." build_id)*
build_id ::= [a-zA-Z0-9]+

(* v1.0.0 Control mapping format *)
control_mapping_value ::= control_mapping_entry ("," control_mapping_entry)*
control_mapping_entry ::= framework ":" control_id
framework ::= [A-Z][A-Z0-9-]*
control_id ::= [a-zA-Z0-9.-]+

(* v1.0.0 Policy Identity Tuple - uniquely identifies a policy *)
(* Conceptual: (esp_id, version, dsl_schema_version) *)
```

---

## 3. Definition Block

```ebnf
(* DEF block contains all policy definitions *)
definition ::= "DEF" statement_end
               definition_content
               "DEF_END" statement_end

(* Definition content - elements followed by criteria *)
definition_content ::= definition_element* criteria+

(* Elements that can appear in definition *)
definition_element ::= variable_declaration
                     | definition_state
                     | definition_object
                     | run_block
                     | set_block
                     | comment
```

---

## 4. Variables

```ebnf
(* Variable declaration with type and optional initial value *)
variable_declaration ::= "VAR" space identifier space data_type
                         (space direct_value)? statement_end
```

---

## 5. States

```ebnf
(* Definition-level state: referenceable via STATE_REF *)
definition_state ::= "STATE" space state_identifier statement_end
                     state_content
                     "STATE_END" statement_end

(* CTN-level state: local, not referenceable from outside CTN *)
ctn_state ::= "STATE" space state_identifier statement_end
              state_content
              "STATE_END" statement_end

(* State content: fields and/or record checks *)
state_content ::= (state_field | record_check)+

(* State field with type, operation, value, and optional entity check *)
state_field ::= field_name space data_type space operation space value_spec
                (space entity_check)? statement_end

(* Record check for structured data validation *)
record_check ::= "record" (space data_type)? statement_end
                 record_content
                 "record_end" statement_end

(* Record content: direct operation or nested fields *)
record_content ::= direct_operation | record_field+

(* Direct operation on entire record *)
direct_operation ::= operation space value_spec statement_end

(* Nested field within record *)
record_field ::= "field" space field_path space data_type space operation
                 space value_spec (space entity_check)? statement_end

(* Field path for nested access *)
field_path ::= path_component ("." path_component)*
path_component ::= identifier | index | wildcard
index ::= [0-9]+
wildcard ::= "*"

(* State identifier *)
state_identifier ::= identifier
```

---

## 6. Objects

```ebnf
(* Definition-level object: referenceable via OBJECT_REF *)
definition_object ::= "OBJECT" space object_identifier statement_end
                      object_content
                      "OBJECT_END" statement_end

(* CTN-level object: local, not referenceable from outside CTN *)
ctn_object ::= "OBJECT" space object_identifier statement_end
               object_content
               "OBJECT_END" statement_end

(* Object content: one or more elements *)
object_content ::= object_element+

(* Object element types *)
object_element ::= object_field
                 | module_element
                 | parameter_block
                 | select_block
                 | behavior_spec
                 | filter_block
                 | set_reference
                 | record_check
                 | inline_set

(* Simple object field *)
object_field ::= field_name space field_value statement_end
field_value ::= backtick_string | variable_reference | identifier

(* Module specification for PowerShell, etc. *)
module_element ::= module_field space backtick_string statement_end
module_field ::= "module_name" | "verb" | "noun" | "module_id" | "module_version"

(* Parameters block *)
parameter_block ::= "parameters" space data_type statement_end
                    parameter_field*
                    "parameters_end" statement_end
parameter_field ::= field_name space field_value statement_end

(* Select block *)
select_block ::= "select" space data_type statement_end
                 select_field*
                 "select_end" statement_end
select_field ::= field_name space field_value statement_end

(* Behavior specification *)
behavior_spec ::= "behavior" space behavior_value+ statement_end
behavior_value ::= identifier | integer_value | boolean_value

(* Object identifier *)
object_identifier ::= identifier
```

---

## 7. Criteria and Criterion (CTN)

```ebnf
(* Criteria block with logical operator *)
criteria ::= "CRI" space logical_operator (space negate_flag)? statement_end
             criteria_content
             "CRI_END" statement_end

(* Logical operators for criteria *)
logical_operator ::= "AND" | "OR"

(* Negate flag *)
negate_flag ::= "true"

(* Criteria content: nested criteria or criterion blocks *)
criteria_content ::= (criteria | criterion)+

(* Criterion (CTN) block *)
criterion ::= "CTN" space criterion_type statement_end
              ctn_content
              "CTN_END" statement_end

(* Criterion type identifier *)
criterion_type ::= identifier

(* CTN content: elements MUST appear in this order *)
ctn_content ::= test_spec
                state_reference*
                object_reference*
                set_reference*
                ctn_state*
                ctn_object?

(* Test specification *)
test_spec ::= "TEST" space existence_check space item_check
              (space state_operator)? statement_end

(* Existence check options *)
existence_check ::= "all" | "any" | "none" | "at_least_one" | "only_one"

(* Item check options *)
item_check ::= "all" | "at_least_one" | "only_one" | "none_satisfy"

(* State operator for combining multiple states *)
state_operator ::= "AND" | "OR" | "ONE"

(* State reference *)
state_reference ::= "STATE_REF" space state_identifier statement_end

(* Object reference *)
object_reference ::= "OBJECT_REF" space object_identifier statement_end
```

---

## 8. SET Operations

```ebnf
(* SET block for set operations *)
set_block ::= "SET" space set_identifier space set_operation statement_end
              set_content
              "SET_END" statement_end

(* Set operation types with operand constraints *)
set_operation ::= "union"        (* 1+ operands *)
                | "intersection" (* 2+ operands *)
                | "complement"   (* exactly 2 operands *)

(* Set content: operands and optional filter *)
set_content ::= set_operand+ filter_block?

(* Set operand types *)
set_operand ::= (object_reference | set_reference | inline_object
                | filtered_object_ref) statement_end

(* Inline object within SET *)
inline_object ::= "OBJECT" space object_identifier? statement_end
                  object_content
                  "OBJECT_END"

(* Inline SET within object *)
inline_set ::= "SET" space set_identifier space set_operation statement_end
               set_content
               "SET_END" statement_end

(* Set reference *)
set_reference ::= "SET_REF" space set_identifier

(* Filtered object reference *)
filtered_object_ref ::= "OBJECT_REF" space object_identifier statement_end
                        filter_block

(* Set identifier *)
set_identifier ::= identifier
```

---

## 9. FILTER Block

```ebnf
(* Filter block for filtering items *)
filter_block ::= "FILTER" space filter_action? statement_end
                 state_reference+
                 "FILTER_END" statement_end

(* Filter action *)
filter_action ::= "include" | "exclude"
```

---

## 10. RUN Operations (Runtime)

```ebnf
(* RUN block for runtime operations *)
run_block ::= "RUN" space target_variable space operation_type statement_end
              run_parameter+
              "RUN_END" statement_end

(* Target variable for result *)
target_variable ::= identifier

(* Operation types *)
operation_type ::= "CONCAT" | "SPLIT" | "SUBSTRING" | "REGEX_CAPTURE"
                 | "ARITHMETIC" | "COUNT" | "UNIQUE" | "MERGE" | "EXTRACT" | "END"

(* Run parameters *)
run_parameter ::= (literal_param | variable_param | object_param
                 | pattern_param | delimiter_param | character_param
                 | position_param | arithmetic_op) statement_end

(* Parameter types *)
literal_param ::= "literal" space (backtick_string | integer_value)
variable_param ::= "VAR" space identifier
object_param ::= "OBJ" space object_identifier space field_name
pattern_param ::= "pattern" space backtick_string
delimiter_param ::= "delimiter" space backtick_string
character_param ::= "character" space backtick_string
position_param ::= ("start" | "length") space integer_value
arithmetic_op ::= ("+" | "-" | "*" | "/" | "%") space (integer_value | float_value)
```

---

## 11. Values and Types

```ebnf
(* Value specification *)
value_spec ::= direct_value | variable_reference

(* Direct value literals *)
direct_value ::= backtick_string | raw_string | multiline_string | raw_multiline
               | integer_value | float_value | boolean_value

(* Variable reference *)
variable_reference ::= "VAR" space identifier

(* Data types - parsed as identifiers *)
data_type ::= "string" | "int" | "float" | "boolean" | "binary"
            | "record_data" | "version" | "evr_string"

(* Operations *)
operation ::= comparison_op | string_op | set_op | pattern_op

(* Comparison operators *)
comparison_op ::= "=" | "!=" | ">" | "<" | ">=" | "<="

(* String operators *)
string_op ::= "ieq" | "ine" | "contains" | "starts" | "ends"
            | "not_contains" | "not_starts" | "not_ends"

(* Set operators *)
set_op ::= "subset_of" | "superset_of"

(* Pattern operators *)
pattern_op ::= "pattern_match" | "matches"

(* Entity check for state fields *)
entity_check ::= "all" | "at_least_one" | "none" | "only_one"
```

---

## 12. Tokens

```ebnf
(* Identifier: letter or underscore followed by alphanumeric or underscore *)
identifier ::= [a-zA-Z_][a-zA-Z0-9_]*

(* Field name alias *)
field_name ::= identifier

(* Integer literal: optional minus, digits *)
integer_value ::= "-"? [0-9]+

(* Float literal: optional minus, digits, dot, digits *)
float_value ::= "-"? [0-9]+ "." [0-9]+

(* Boolean literal *)
boolean_value ::= "true" | "false"

(* String literals *)
backtick_string ::= "`" ([^`] | "``")* "`"
raw_string ::= "r`" ([^`] | "``")* "`"
multiline_string ::= "```" ([^`] | "`" [^`] | "``" [^`])* "```"
raw_multiline ::= "r```" ([^`] | "`" [^`] | "``" [^`])* "```"

(* Whitespace *)
space ::= " "+
newline ::= "\n" | "\r\n"
statement_end ::= space? comment? newline

(* Comment *)
comment ::= "#" [^\n]*
```

---

## 13. Type Compatibility Matrix

### 13.1 Operations by Data Type

| Operation | string | int | float | boolean | binary | record | version | evr_string |
|-----------|--------|-----|-------|---------|--------|--------|---------|------------|
| `=` `!=` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `>` `<` `>=` `<=` | ✓¹ | ✓ | ✓ | ✗ | ✗ | ✗ | ✓² | ✓² |
| `ieq` `ine` | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| `contains` | ✓ | ✗ | ✗ | ✗ | ✓³ | ✗ | ✗ | ✗ |
| `starts` `ends` | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| `not_contains` `not_starts` `not_ends` | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| `pattern_match` `matches` | ✓ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ |
| `subset_of` `superset_of` | ✓⁴ | ✓⁴ | ✓⁴ | ✓⁴ | ✗ | ✗ | ✗ | ✗ |

¹ Lexicographic comparison
² Semantic version comparison (evr_string uses epoch:version-release)
³ Binary contains performs byte sequence search
⁴ Requires collection from SET operation

### 13.2 Type Strictness (N-7)

**Int and Float are NOT interchangeable:**
- Operations on Int require Int operands
- Operations on Float require Float operands
- No implicit type coercion is performed

### 13.3 RUN Operation Types

| Operation | Input | Output |
|-----------|-------|--------|
| `CONCAT` | string | string |
| `SPLIT` | string | string[] |
| `SUBSTRING` | string | string |
| `REGEX_CAPTURE` | string | string |
| `ARITHMETIC` | int, float | same type |
| `COUNT` | collection | int |
| `UNIQUE` | collection | same type |
| `MERGE` | collections | same type |
| `EXTRACT` | object | field type |
| `END` | string | string |

---

## 14. Scoping Rules

### 14.1 Global Scope (DEF Level)

Symbols declared at DEF level are **global** and can be referenced:
- `STATE` → via `STATE_REF`
- `OBJECT` → via `OBJECT_REF`
- `SET` → via `SET_REF`
- `VAR` → via `VAR` reference
- `RUN` target variables → via `VAR` reference

### 14.2 Local Scope (CTN Level)

Symbols declared within a CTN are **local**:
- `STATE` → NOT referenceable outside the CTN
- `OBJECT` → NOT referenceable outside the CTN

### 14.3 Duplicate Detection (N-3)

Within a scope, identifiers MUST be unique across all symbol types:
- Global `STATE foo` and global `OBJECT foo` → **Error**
- Local `STATE bar` (CTN A) and local `STATE bar` (CTN B) → **Allowed** (different scopes)

### 14.4 Shadowing Prevention (N-5)

Local symbols MUST NOT shadow global symbols:
- Global `STATE config` exists
- Local `STATE config` in any CTN → **Error** (shadows global)

---

## 15. Implementation Limits

| Constraint | Recommended Limit |
|------------|-------------------|
| Symbols per definition | 10,000 |
| String literal size | 1 MB |
| Nesting depth | 10 levels |
| Identifier length | 255 characters |
| Line length | 4,096 characters |
| File size | 10 MB |
| SET operands | 100 |
| CTN per CRI | 1,000 |

---

## 16. v1.0.0 Compliance Example

```esp
META
    esp_id `policy-ssh-hardening-001`
    version `2.1.0`
    dsl_schema_version `1.0.0`
    platform `linux`
    criticality `high`
    control_mapping `NIST:AC-6,CIS:5.2.1`
    title `SSH Server Hardening Policy`
    agent_type `linux_agent`
    author `security-team`
    description `Ensures SSH server is configured securely`
META_END

DEF
    # Global variable
    VAR config_path string `/etc/ssh/sshd_config`
    VAR max_auth_tries int 4

    # Runtime computation
    RUN auth_limit ARITHMETIC
        VAR max_auth_tries
        - 1
    RUN_END

    # Global state (referenceable)
    STATE secure_settings
        PermitRootLogin string = `no`
        PasswordAuthentication string = `no`
        MaxAuthTries int <= VAR auth_limit
    STATE_END

    # Global object (referenceable)
    OBJECT ssh_config
        path `/etc/ssh`
        filename `sshd_config`
        behavior recurse false
    OBJECT_END

    # Set operation
    SET config_files union
        OBJECT_REF ssh_config
        FILTER include
            STATE_REF secure_settings
        FILTER_END
    SET_END

    # Criteria
    CRI AND
        CTN file_content
            TEST all all AND
            STATE_REF secure_settings
            OBJECT_REF ssh_config
        CTN_END

        CTN file_permissions
            TEST all all
            # Local state (not referenceable outside this CTN)
            STATE permission_check
                mode int = 600
                owner string = `root`
            STATE_END
            OBJECT_REF ssh_config
        CTN_END
    CRI_END
DEF_END
```

---

## Appendix A: Grammar Summary

```
esp_file        → metadata? definition
metadata        → META metadata_field* META_END
definition      → DEF definition_content DEF_END
definition_content → definition_element* criteria+
criteria        → CRI logical_operator negate_flag? criteria_content CRI_END
criterion       → CTN criterion_type ctn_content CTN_END
```

---

## Appendix B: v1.0.0 Normative Requirements

| ID | Requirement |
|----|-------------|
| N-1 | Source files MUST be valid UTF-8 |
| N-2 | All keywords are case-sensitive |
| N-3 | Identifiers MUST be unique within scope |
| N-4 | Global symbols referenceable via *_REF |
| N-5 | Local symbols MUST NOT shadow global |
| N-6 | CTN content MUST follow ordering |
| N-7 | Int and Float are NOT interchangeable |
| N-13 | Policy identity = (esp_id, version, dsl_schema_version) |
| N-16 | META MUST include all required v1.0.0 fields |

---

## Revision History

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2026-01-08 | Initial v1.0.0 specification |
| | | - Added required META fields |
| | | - Formalized Policy Identity tuple |
| | | - Added scoping and shadowing rules |
| | | - Added type strictness (N-7) |
