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

**Structure:** `DEF`, `VAR`, `STATE`, `OBJECT`, `CTN`, `CRI`, `SET`, `RUN`, `TEST`, `FILTER`, `META`, `parameters`, `select`, `record`

**End markers:** `DEF_END`, `STATE_END`, `OBJECT_END`, `CTN_END`, `CRI_END`, `SET_END`, `RUN_END`, `FILTER_END`, `META_END`, `parameters_end`, `select_end`, `record_end`

**References:** `STATE_REF`, `OBJECT_REF`, `SET_REF`, `VAR`, `OBJ`

**Operators:** `AND`, `OR`, `ONE`, `=`, `!=`, `>`, `<`, `>=`, `<=`, `ieq`, `ine`, `contains`, `starts`, `ends`, `not_contains`, `not_starts`, `not_ends`, `subset_of`, `superset_of`, `pattern_match`, `matches`, `+`, `-`, `*`, `/`, `%`

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

state_content ::= state_field+

state_field ::= identifier space data_type space operation space value_spec statement_end

(* Record fields for structured data *)
record_check ::= "record" space data_type? statement_end
                 record_field+
                 "record_end" statement_end

record_field ::= "field" space field_path space data_type space operation
                 space value_spec (space entity_check)? statement_end

field_path ::= identifier ("." identifier)*
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
                 | parameter_block
                 | select_block
                 | behavior_spec
                 | filter_block
                 | set_reference

object_field ::= identifier space field_value statement_end

parameter_block ::= "parameters" space data_type statement_end
                    (identifier space field_value statement_end)*
                    "parameters_end" statement_end

select_block ::= "select" space data_type statement_end
                 (identifier space field_value statement_end)*
                 "select_end" statement_end

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

criterion ::= "CTN" space identifier statement_end
              ctn_content
              "CTN_END" statement_end

(* CTN elements must appear in this order *)
ctn_content ::= test_spec
                state_reference*
                object_reference*
                ctn_state*
                ctn_object?

test_spec ::= "TEST" space existence_check space item_check
              (space state_operator)? statement_end

existence_check ::= "all" | "any" | "none" | "at_least_one" | "only_one"

item_check ::= "all" | "any" | "none" | "at_least_one" | "only_one" | "none_satisfy"

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
                 | "ARITHMETIC" | "COUNT" | "UNIQUE" | "MERGE" | "EXTRACT"

run_parameter ::= (literal_param | variable_param | object_param
                 | pattern_param | delimiter_param | position_param
                 | arithmetic_op) statement_end

literal_param ::= "literal" space (backtick_string | integer_value)
variable_param ::= "VAR" space identifier
object_param ::= "OBJ" space identifier space identifier
pattern_param ::= "pattern" space backtick_string
delimiter_param ::= "delimiter" space backtick_string
position_param ::= ("start" | "length") space integer_value
arithmetic_op ::= ("+" | "-" | "*" | "/" | "%") space integer_value
```

### Values and Types

```ebnf
value_spec ::= direct_value | variable_reference

direct_value ::= backtick_string | integer_value | float_value | boolean_value

variable_reference ::= "VAR" space identifier

data_type ::= "string" | "int" | "float" | "boolean" | "binary"
            | "record" | "version" | "evr_string"

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

backtick_string ::= "`" ([^`] | "``")* "`"
(* `` inside backticks = literal backtick *)
(* `` alone = empty string *)

space ::= " "+

newline ::= "\n" | "\r\n"

statement_end ::= space? comment? newline
```

---

## Type Compatibility

### Operations by Data Type

| Operation | string | int | float | boolean | version |
|-----------|--------|-----|-------|---------|---------|
| `=` `!=` | ✓ | ✓ | ✓ | ✓ | ✓ |
| `>` `<` `>=` `<=` | ✓¹ | ✓ | ✓ | ✗ | ✓² |
| `ieq` `ine` | ✓ | ✗ | ✗ | ✗ | ✗ |
| `contains` `starts` `ends` | ✓ | ✗ | ✗ | ✗ | ✗ |
| `not_contains` `not_starts` `not_ends` | ✓ | ✗ | ✗ | ✗ | ✗ |
| `pattern_match` `matches` | ✓ | ✗ | ✗ | ✗ | ✗ |
| `subset_of` `superset_of` | ✓³ | ✓³ | ✓³ | ✓³ | ✗ |

¹ Lexicographic comparison
² Semantic version comparison
³ Requires collection from SET operation

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
    control_framework `NIST-800-53`
    control `CM-6`
META_END

DEF
    VAR config_path string `/etc/ssh/sshd_config`

    STATE secure_settings
        content string not_contains `PermitRootLogin yes`
        content string contains `PasswordAuthentication no`
    STATE_END

    OBJECT ssh_config
        path VAR config_path

        select record
            content text
            owner uid
        select_end
    OBJECT_END

    CRI AND
        CTN file_content
            TEST all all AND
            STATE_REF secure_settings
            OBJECT_REF ssh_config
        CTN_END
    CRI_END
DEF_END
```
