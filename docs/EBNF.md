# ESP (Endpoint State Policy) — EBNF Grammar

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

## File Encoding

- **Encoding**: UTF-8 (no BOM)
- **Line endings**: LF preferred, CRLF accepted
- **Identifiers**: ASCII only `[a-zA-Z0-9_]`
- **String literals**: ASCII printable `[0x20-0x7E]` plus whitespace
- **Non-ASCII**: Parser error

---

## Lexical Rules

### Case Sensitivity

All elements are case-sensitive.

| Element | Case | Examples |
|---------|------|----------|
| Keywords | UPPERCASE | `DEF`, `STATE`, `CTN`, `CRI` |
| Identifiers | Sensitive | `my_var` ≠ `My_Var` |
| Operators | lowercase | `contains`, `ieq`, `starts` |
| Symbols | — | `=`, `!=`, `>=` |

### Reserved Keywords

**Structure:** `DEF`, `VAR`, `STATE`, `OBJECT`, `CTN`, `CRI`, `SET`, `RUN`, `TEST`, `FILTER`, `META`, `parameters`, `select`, `record`, `behavior`

**End markers:** `DEF_END`, `STATE_END`, `OBJECT_END`, `CTN_END`, `CRI_END`, `SET_END`, `RUN_END`, `FILTER_END`, `META_END`, `parameters_end`, `select_end`, `record_end`

**References:** `STATE_REF`, `OBJECT_REF`, `SET_REF`, `VAR`, `OBJ`

**Module fields:** `module_name`, `verb`, `noun`, `module_id`, `module_version`

**Logical/State operators:** `AND`, `OR`, `ONE`

**RUN operations:** `CONCAT`, `SPLIT`, `SUBSTRING`, `REGEX_CAPTURE`, `ARITHMETIC`, `COUNT`, `UNIQUE`, `END`, `MERGE`, `EXTRACT`

**SET operations:** `union`, `intersection`, `complement`

**Filter actions:** `include`, `exclude`

**Existence checks:** `all`, `any`, `none`, `at_least_one`, `only_one`

**Item checks:** `all`, `at_least_one`, `only_one`, `none_satisfy`

**Context-sensitive identifiers** (not keywords, semantic meaning in context):
`literal`, `pattern`, `delimiter`, `character`, `start`, `length`, `field`

**Data type identifiers** (not keywords, parsed as identifiers):
`string`, `int`, `float`, `boolean`, `binary`, `record_data`, `version`, `evr_string`

**Comparison operators:** `=`, `!=`, `>`, `<`, `>=`, `<=`

**String operators:** `ieq`, `ine`, `contains`, `starts`, `ends`, `not_contains`, `not_starts`, `not_ends`

**Pattern operators:** `pattern_match`, `matches`

**Set operators:** `subset_of`, `superset_of`

**Arithmetic operators:** `+`, `-`, `*`, `/`, `%`

### Numeric Limits

| Type | Range |
|------|-------|
| `int` | 64-bit signed: −9,223,372,036,854,775,808 to 9,223,372,036,854,775,807 |
| `float` | IEEE 754 double precision (64-bit) |

Overflow at parse time is an error.

---

## Grammar

### File Structure

```ebnf
esp_file ::= metadata? definition

comment ::= "#" [^\n]* newline
```

### Metadata Block

```ebnf
metadata ::= "META" statement_end
             metadata_field*
             "META_END" statement_end

metadata_field ::= identifier space field_value statement_end

field_value ::= backtick_string | integer_value | float_value | boolean_value
```

### Definition Block

```ebnf
definition ::= "DEF" statement_end
               definition_content
               "DEF_END" statement_end

definition_content ::= definition_element* criteria+

definition_element ::= variable_declaration
                     | definition_state
                     | definition_object
                     | run_block
                     | set_block
                     | comment
```

### Variables

```ebnf
variable_declaration ::= "VAR" space identifier space data_type
                         (space direct_value)? statement_end
```

### States

```ebnf
(* Definition-level: referenceable via STATE_REF *)
definition_state ::= "STATE" space identifier statement_end
                     state_content
                     "STATE_END" statement_end

(* CTN-level: local, not referenceable *)
ctn_state ::= "STATE" space identifier statement_end
              state_content
              "STATE_END" statement_end

state_content ::= (state_field | record_check)+

state_field ::= identifier space data_type space operation space value_spec statement_end

(* Record checks for structured data validation *)
record_check ::= "record" (space data_type)? statement_end
                 record_content
                 "record_end" statement_end

record_content ::= direct_operation | record_field+

direct_operation ::= operation space value_spec statement_end

record_field ::= "field" space field_path space data_type space operation
                 space value_spec (space entity_check)? statement_end

(* Note: "field" is a context-sensitive identifier, not a keyword *)

field_path ::= path_component ("." path_component)*

path_component ::= identifier | index | wildcard

index ::= [0-9]+

wildcard ::= "*"
```

### Objects

```ebnf
(* Definition-level: referenceable via OBJECT_REF *)
definition_object ::= "OBJECT" space identifier statement_end
                      object_content
                      "OBJECT_END" statement_end

(* CTN-level: local, not referenceable *)
ctn_object ::= "OBJECT" space identifier statement_end
               object_content
               "OBJECT_END" statement_end

object_content ::= object_element+

object_element ::= object_field
                 | module_element
                 | parameter_block
                 | select_block
                 | behavior_spec
                 | filter_block
                 | set_reference

(* Simple field *)
object_field ::= identifier space field_value statement_end

field_value ::= backtick_string | variable_reference | identifier

(* Module specification for PowerShell, etc. *)
module_element ::= module_field space backtick_string statement_end

module_field ::= "module_name" | "verb" | "noun" | "module_id" | "module_version"

(* Parameters block *)
parameter_block ::= "parameters" space data_type statement_end
                    parameter_field*
                    "parameters_end" statement_end

parameter_field ::= identifier space field_value statement_end

(* Select block *)
select_block ::= "select" space data_type statement_end
                 select_field*
                 "select_end" statement_end

select_field ::= identifier space field_value statement_end

(* Behavior specification *)
behavior_spec ::= "behavior" space behavior_value+ statement_end

behavior_value ::= identifier | integer_value | boolean_value
```

### Criteria and CTN

```ebnf
criteria ::= "CRI" space logical_operator (space negate_flag)? statement_end
             criteria_content
             "CRI_END" statement_end

logical_operator ::= "AND" | "OR"

negate_flag ::= "true"

criteria_content ::= (criteria | criterion)+

criterion ::= "CTN" space criterion_type statement_end
              ctn_content
              "CTN_END" statement_end

criterion_type ::= identifier  (* CTN type: file_content, rpm_package, etc. *)

(* CTN elements must appear in this order *)
ctn_content ::= test_spec
                state_reference*
                object_reference*
                ctn_state*
                ctn_object?

test_spec ::= "TEST" space existence_check space item_check
              (space state_operator)? statement_end

existence_check ::= "all" | "any" | "none" | "at_least_one" | "only_one"

item_check ::= "all" | "at_least_one" | "only_one" | "none_satisfy"

state_operator ::= "AND" | "OR" | "ONE"

state_reference ::= "STATE_REF" space identifier statement_end

object_reference ::= "OBJECT_REF" space identifier statement_end
```

### SET Operations

```ebnf
set_block ::= "SET" space identifier space set_operation statement_end
              set_content
              "SET_END" statement_end

set_operation ::= "union"        (* 1+ operands *)
                | "intersection" (* 2+ operands *)
                | "complement"   (* exactly 2 operands *)

set_content ::= set_operand+ filter_block?

set_operand ::= (object_reference | set_reference | inline_object) statement_end

inline_object ::= "OBJECT" space identifier? statement_end
                  object_content
                  "OBJECT_END"

set_reference ::= "SET_REF" space identifier
```

### FILTER

```ebnf
filter_block ::= "FILTER" space filter_action? statement_end
                 state_reference+
                 "FILTER_END" statement_end

filter_action ::= "include" | "exclude"
```

### RUN Operations

```ebnf
run_block ::= "RUN" space identifier space operation_type statement_end
              run_parameter+
              "RUN_END" statement_end

operation_type ::= "CONCAT" | "SPLIT" | "SUBSTRING" | "REGEX_CAPTURE"
                 | "ARITHMETIC" | "COUNT" | "UNIQUE" | "MERGE" | "EXTRACT" | "END"

run_parameter ::= (literal_param | variable_param | object_param
                 | pattern_param | delimiter_param | character_param
                 | position_param | arithmetic_op) statement_end

literal_param ::= "literal" space (backtick_string | integer_value)

variable_param ::= "VAR" space identifier

object_param ::= "OBJ" space identifier space identifier

pattern_param ::= "pattern" space backtick_string

delimiter_param ::= "delimiter" space backtick_string

character_param ::= "character" space backtick_string

position_param ::= ("start" | "length") space integer_value

arithmetic_op ::= ("+" | "-" | "*" | "/" | "%") space (integer_value | float_value)
```

### Values and Types

```ebnf
value_spec ::= direct_value | variable_reference

direct_value ::= backtick_string | raw_string | multiline_string | raw_multiline
               | integer_value | float_value | boolean_value

variable_reference ::= "VAR" space identifier

data_type ::= "string" | "int" | "float" | "boolean" | "binary"
            | "record_data" | "version" | "evr_string"

operation ::= comparison_op | string_op | set_op | pattern_op

comparison_op ::= "=" | "!=" | ">" | "<" | ">=" | "<="

string_op ::= "ieq" | "ine" | "contains" | "starts" | "ends"
            | "not_contains" | "not_starts" | "not_ends"

set_op ::= "subset_of" | "superset_of"

pattern_op ::= "pattern_match" | "matches"

entity_check ::= "all" | "at_least_one" | "none" | "only_one"
```

### Tokens

```ebnf
identifier ::= [a-zA-Z_][a-zA-Z0-9_]*

integer_value ::= "-"? [0-9]+

float_value ::= "-"? [0-9]+ "." [0-9]+

boolean_value ::= "true" | "false"

(* String literals *)
backtick_string ::= "`" ([^`] | "``")* "`"
(* `` inside backticks = literal backtick *)
(* `` alone = empty string *)

(* Raw strings - no escape processing *)
raw_string ::= "r`" ([^`] | "``")* "`"

(* Multiline strings *)
multiline_string ::= "```" ([^`] | "`" [^`] | "``" [^`])* "```"

raw_multiline ::= "r```" ([^`] | "`" [^`] | "``" [^`])* "```"

(* Whitespace *)
space ::= " "+

newline ::= "\n" | "\r\n"

statement_end ::= space? comment? newline

comment ::= "#" [^\n]*
```

---

## Type Compatibility

### Operations by Data Type

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

### RUN Operation Types

| Operation | Input | Output |
|-----------|-------|--------|
| `CONCAT` | string | string |
| `SPLIT` | string | string[] |
| `SUBSTRING` | string | string |
| `REGEX_CAPTURE` | string | string |
| `ARITHMETIC` | int, float | same |
| `COUNT` | collection | int |
| `UNIQUE` | collection | same |
| `MERGE` | collections | same |
| `EXTRACT` | object | field type |
| `END` | string | string |

---

## Implementation Limits

| Constraint | Recommended |
|------------|-------------|
| Symbols per definition | 10,000 |
| String literal size | 1 MB |
| Nesting depth | 10 levels |
| Identifier length | 255 chars |
| Line length | 4,096 chars |
| File size | 10 MB |
| SET operands | 100 |
| CTN per CRI | 1,000 |

---

## Example

```esp
META
    version `1.0.0`
    esp_version `1.0`
    author `security-team`
    control_framework `NIST-800-53`
    control `CM-6`
    platform `linux`
    severity `high`
META_END

DEF
    # Variables
    VAR config_path string `/etc/ssh/sshd_config`
    VAR threshold int 1024

    # Runtime operation
    RUN computed_limit ARITHMETIC
        VAR threshold
        * 2
    RUN_END

    # Global state (referenceable)
    STATE secure_settings
        content string not_contains `PermitRootLogin yes`
        content string contains `PasswordAuthentication no`
    STATE_END

    STATE size_check
        size int > VAR threshold
    STATE_END

    # Global object with select block
    OBJECT ssh_config
        path `/etc/ssh`
        filename `sshd_config`
        behavior recurse false

        select record
            content text
            owner uid
            permissions mode
        select_end
    OBJECT_END

    # Object with parameters (PowerShell example)
    OBJECT ps_process
        module_name `Microsoft.PowerShell.Management`
        verb `Get`
        noun `Process`

        parameters string
            Name `sshd`
            ErrorAction `SilentlyContinue`
        parameters_end
    OBJECT_END

    # JSON object with record check
    OBJECT config_json
        path `/etc/app`
        filename `config.json`
    OBJECT_END

    STATE json_valid
        record
            field settings.security.enabled boolean = true
            field users.*.role string = `admin` at_least_one
        record_end
    STATE_END

    # Set operation
    SET critical_files union
        OBJECT_REF ssh_config
        OBJECT_REF config_json
        FILTER include
            STATE_REF size_check
        FILTER_END
    SET_END

    # Criteria
    CRI AND
        CTN file_content
            TEST all all AND
            STATE_REF secure_settings
            OBJECT_REF ssh_config
        CTN_END

        CTN json_record
            TEST all all
            STATE_REF json_valid
            OBJECT_REF config_json
        CTN_END

        # Nested criteria
        CRI OR
            CTN file_metadata
                TEST any all
                STATE_REF size_check
                OBJECT
                    SET_REF critical_files
                OBJECT_END
            CTN_END
        CRI_END
    CRI_END
DEF_END
```
