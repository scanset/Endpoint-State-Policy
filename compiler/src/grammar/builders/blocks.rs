//! Block builders for structured AST node parsing
//!
//! These functions parse fixed-structure EBNF sequences without alternatives.
//! They follow predictable patterns and delegate to atomic/expression builders for choices.
//!
//! FIXED: Removed circular dependencies by moving parse_filter_spec to expressions.rs
//! FIXED: parse_record_check now correctly distinguishes 'field' keyword from data types

use crate::grammar::builders::atomic::Parser;
use crate::grammar::builders::{atomic::*, expressions::*, helpers::*};
use crate::grammar::keywords::Keyword;
use crate::tokens::Token;
use common::ast::nodes::*;

// ============================================================================
// HELPER: Check if an identifier is a data type
// ============================================================================

/// Check if an identifier represents a data type
/// This prevents 'field' from being incorrectly parsed as a data type
fn is_data_type_name(name: &str) -> bool {
    matches!(
        name,
        "string"
            | "int"
            | "float"
            | "boolean"
            | "binary"
            | "record_data"
            | "version"
            | "evr_string"
    )
}

// ============================================================================
// ESP FILE PARSING
// ============================================================================

/// Parse esp_file ::= metadata? definition
pub fn parse_esp_file(parser: &mut dyn Parser) -> Result<EspFile, String> {
    let metadata = if matches!(parser.current_token(), Some(Token::Keyword(Keyword::Meta))) {
        Some(parse_metadata_block(parser)?)
    } else {
        None
    };

    let definition = parse_definition(parser)?;

    Ok(EspFile {
        metadata,
        definition,
        span: Some(parser.current_span()),
    })
}

/// Parse definition ::= "DEF" statement_end definition_content "DEF_END" statement_end
pub fn parse_definition(parser: &mut dyn Parser) -> Result<DefinitionNode, String> {
    parser.expect_keyword(Keyword::Def)?;

    let mut variables = Vec::new();
    let mut states = Vec::new();
    let mut objects = Vec::new();
    let mut runtime_operations = Vec::new();
    let mut set_operations = Vec::new();
    let mut criteria = Vec::new();

    // Parse definition content until DEF_END
    loop {
        match parser.current_token() {
            Some(Token::Keyword(Keyword::DefEnd)) => {
                parser.advance();
                break;
            }
            Some(Token::Keyword(Keyword::Var)) => {
                variables.push(parse_variable_declaration(parser)?);
            }
            Some(Token::Keyword(Keyword::State)) => {
                let mut state = parse_state_definition(parser)?;
                state.is_global = true; // Definition-level states are global
                states.push(state);
            }
            Some(Token::Keyword(Keyword::Object)) => {
                let mut object = parse_object_definition(parser)?;
                object.is_global = true; // Definition-level objects are global
                objects.push(object);
            }
            Some(Token::Keyword(Keyword::Run)) => {
                runtime_operations.push(parse_runtime_operation(parser)?);
            }
            Some(Token::Keyword(Keyword::Set)) => {
                set_operations.push(parse_set_operation(parser)?);
            }
            Some(Token::Keyword(Keyword::Cri)) => {
                criteria.push(parse_criteria_node(parser)?);
            }
            None => return Err("Expected DEF_END, reached end of input".to_string()),
            _ => {
                return Err(format!(
                    "Unexpected token in definition: {:?}",
                    parser.current_token()
                ))
            }
        }
    }

    // Validate EBNF constraint: must have at least one criteria
    if criteria.is_empty() {
        return Err("Definition must contain at least one criteria block".to_string());
    }

    Ok(DefinitionNode {
        variables,
        states,
        objects,
        runtime_operations,
        set_operations,
        criteria,
        span: Some(parser.current_span()),
    })
}

// ============================================================================
// METADATA PARSING
// ============================================================================

/// Parse metadata ::= "META" statement_end metadata_content "META_END" statement_end
pub fn parse_metadata_block(parser: &mut dyn Parser) -> Result<MetadataBlock, String> {
    parser.expect_keyword(Keyword::Meta)?;

    let mut fields = Vec::new();

    // Parse metadata fields until META_END
    loop {
        match parser.current_token() {
            Some(Token::Keyword(Keyword::MetaEnd)) => {
                parser.advance();
                break;
            }
            Some(Token::Identifier(_)) => {
                fields.push(parse_metadata_field(parser)?);
            }
            None => return Err("Expected META_END, reached end of input".to_string()),
            _ => return Err("Expected metadata field or META_END".to_string()),
        }
    }

    Ok(MetadataBlock {
        fields,
        span: Some(parser.current_span()),
    })
}

/// Parse metadata_field ::= field_name space field_value statement_end
pub fn parse_metadata_field(parser: &mut dyn Parser) -> Result<MetadataField, String> {
    let name = parser.expect_identifier()?;
    let value_obj = parse_value(parser)?;

    // Convert value to string for metadata storage
    let value = match value_obj {
        Value::String(s) => s,
        Value::Integer(i) => i.to_string(),
        Value::Float(f) => f.to_string(),
        Value::Boolean(b) => b.to_string(),
        Value::Variable(var) => format!("VAR {}", var),
    };

    Ok(MetadataField {
        name,
        value,
        span: Some(parser.current_span()),
    })
}

// ============================================================================
// VARIABLE PARSING
// ============================================================================

/// Parse variable_declaration ::= "VAR" space variable_name space data_type (space initial_value)? statement_end
pub fn parse_variable_declaration(parser: &mut dyn Parser) -> Result<VariableDeclaration, String> {
    parser.expect_keyword(Keyword::Var)?;
    let name = parser.expect_identifier()?;
    let data_type = parse_data_type(parser)?;

    // Check for optional initial value
    let initial_value = match parser.current_token() {
        // If we see another keyword or end of input, no initial value
        Some(Token::Keyword(_)) | None => None,
        // Otherwise, parse the value
        _ => Some(parse_value(parser)?),
    };

    Ok(VariableDeclaration {
        name,
        data_type,
        initial_value,
        span: Some(parser.current_span()),
    })
}

// ============================================================================
// STATE PARSING
// ============================================================================

/// Parse state_definition ::= "STATE" space state_identifier statement_end state_content "STATE_END" statement_end
pub fn parse_state_definition(parser: &mut dyn Parser) -> Result<StateDefinition, String> {
    parser.expect_keyword(Keyword::State)?;
    let id = parser.expect_identifier()?;

    let mut fields = Vec::new();
    let mut record_checks = Vec::new();

    // Parse state content until STATE_END
    loop {
        match parser.current_token() {
            Some(Token::Keyword(Keyword::StateEnd)) => {
                parser.advance();
                break;
            }
            Some(Token::Keyword(Keyword::Record)) => {
                record_checks.push(parse_record_check(parser)?);
            }
            Some(Token::Identifier(_)) => {
                fields.push(parse_state_field(parser)?);
            }
            None => return Err("Expected STATE_END, reached end of input".to_string()),
            _ => return Err("Expected state field, record check, or STATE_END".to_string()),
        }
    }

    Ok(StateDefinition {
        id,
        fields,
        record_checks,
        is_global: false, // Will be set by caller if needed
        span: Some(parser.current_span()),
    })
}

/// Parse state_field ::= field_name space data_type space operation space value_spec (space entity_check)? statement_end
pub fn parse_state_field(parser: &mut dyn Parser) -> Result<StateField, String> {
    let name = parser.expect_identifier()?;
    let data_type = parse_data_type(parser)?;
    let operation = parse_operation(parser)?;
    let value = parse_value(parser)?;
    let entity_check = parse_optional_entity_check(parser)?;

    Ok(StateField {
        name,
        data_type,
        operation,
        value,
        entity_check,
        span: Some(parser.current_span()),
    })
}

// ============================================================================
// RECORD PARSING - FIXED
// ============================================================================

/// Parse record_check ::= "record" space data_type? statement_end record_content "record_end" statement_end
///
/// FIXED: Now correctly distinguishes between:
/// - Optional data type identifier (string, int, etc.)
/// - 'field' keyword for nested field operations
/// - Direct operation symbols (=, contains, etc.)
pub fn parse_record_check(parser: &mut dyn Parser) -> Result<RecordCheck, String> {
    parser.expect_keyword(Keyword::Record)?;

    // FIXED: Check for optional data type - but ONLY if it's actually a data type,
    // not 'field' or other context-sensitive identifiers
    let data_type = match parser.current_token() {
        Some(Token::Identifier(name)) if is_data_type_name(name) => Some(parse_data_type(parser)?),
        _ => None,
    };

    let content = parse_record_content(parser)?;

    expect_block_end(parser, Keyword::RecordEnd)?;

    Ok(RecordCheck {
        data_type,
        content,
        span: Some(parser.current_span()),
    })
}

/// Parse record_field ::= "field" space field_path space data_type space operation space value_spec (space entity_check)? statement_end
pub fn parse_record_field(parser: &mut dyn Parser) -> Result<RecordField, String> {
    // Expect "field" identifier
    match parser.current_token() {
        Some(Token::Identifier(name)) if name == "field" => {
            parser.advance();
        }
        _ => return Err("Expected 'field' keyword".to_string()),
    }

    let path = parse_field_path(parser)?;
    let data_type = parse_data_type(parser)?;
    let operation = parse_operation(parser)?;
    let value = parse_value(parser)?;
    let entity_check = parse_optional_entity_check(parser)?;

    Ok(RecordField {
        path,
        data_type,
        operation,
        value,
        entity_check,
        span: Some(parser.current_span()),
    })
}

// ============================================================================
// OBJECT PARSING
// ============================================================================

/// Parse object_definition ::= "OBJECT" space object_identifier statement_end object_content "OBJECT_END" statement_end
pub fn parse_object_definition(parser: &mut dyn Parser) -> Result<ObjectDefinition, String> {
    parser.expect_keyword(Keyword::Object)?;
    let id = parser.expect_identifier()?;

    let mut elements = Vec::new();

    // Parse object elements until OBJECT_END
    loop {
        match parser.current_token() {
            Some(Token::Keyword(Keyword::ObjectEnd)) => {
                parser.advance();
                break;
            }
            None => return Err("Expected OBJECT_END, reached end of input".to_string()),
            _ => {
                elements.push(parse_object_element(parser)?);
            }
        }
    }

    Ok(ObjectDefinition {
        id,
        elements,
        is_global: false, // Will be set by caller if needed
        span: Some(parser.current_span()),
    })
}

// ============================================================================
// RUNTIME OPERATION PARSING
// ============================================================================

/// Parse runtime_operation ::= "RUN" space variable_name space operation_type statement_end run_parameters "RUN_END" statement_end
pub fn parse_runtime_operation(parser: &mut dyn Parser) -> Result<RuntimeOperation, String> {
    parser.expect_keyword(Keyword::Run)?;
    let target_variable = parser.expect_identifier()?;
    let operation_type = parse_runtime_operation_type(parser)?;

    let mut parameters = Vec::new();

    // Parse run parameters until RUN_END
    loop {
        match parser.current_token() {
            Some(Token::Keyword(Keyword::RunEnd)) => {
                parser.advance();
                break;
            }
            None => return Err("Expected RUN_END, reached end of input".to_string()),
            _ => {
                parameters.push(parse_run_parameter(parser)?);
            }
        }
    }

    Ok(RuntimeOperation {
        target_variable,
        operation_type,
        parameters,
        span: Some(parser.current_span()),
    })
}

// ============================================================================
// SET OPERATION PARSING
// ============================================================================

/// Parse set_operation ::= "SET" space set_identifier space set_operation statement_end set_content "SET_END" statement_end
pub fn parse_set_operation(parser: &mut dyn Parser) -> Result<SetOperation, String> {
    parser.expect_keyword(Keyword::Set)?;
    let set_id = parser.expect_identifier()?;
    let operation = parse_set_operation_type(parser)?;

    let mut operands = Vec::new();
    let mut filter = None;

    // Parse set content until SET_END
    loop {
        match parser.current_token() {
            Some(Token::Keyword(Keyword::SetEnd)) => {
                parser.advance();
                break;
            }
            Some(Token::Keyword(Keyword::Filter)) => {
                // FIXED: Use filter_spec from expressions module
                filter = Some(parse_filter_spec(parser)?);
                // Filter typically ends the operand list
            }
            None => return Err("Expected SET_END, reached end of input".to_string()),
            _ => {
                operands.push(parse_set_operand(parser)?);
            }
        }
    }

    // Validate set operation constraints
    operation
        .validate_operand_count(operands.len())
        .map_err(|e| format!("Set operation validation failed: {}", e))?;

    Ok(SetOperation {
        set_id,
        operation,
        operands,
        filter,
        span: Some(parser.current_span()),
    })
}

// ============================================================================
// CRITERIA PARSING
// ============================================================================

/// Parse criteria ::= "CRI" space logical_operator space? negate_flag? statement_end criteria_content "CRI_END" statement_end
pub fn parse_criteria_node(parser: &mut dyn Parser) -> Result<CriteriaNode, String> {
    parser.expect_keyword(Keyword::Cri)?;
    let logical_op = parse_logical_op(parser)?;

    // Check for optional negate flag
    let negate = parse_optional_boolean(parser, false)?;

    let mut content = Vec::new();

    // Parse criteria content until CRI_END
    loop {
        match parser.current_token() {
            Some(Token::Keyword(Keyword::CriEnd)) => {
                parser.advance();
                break;
            }
            Some(Token::Keyword(Keyword::Cri | Keyword::Ctn)) => {
                content.push(parse_criteria_content(parser)?);
            }
            None => return Err("Expected CRI_END, reached end of input".to_string()),
            _ => return Err("Expected CRI or CTN block".to_string()),
        }
    }

    // Validate EBNF constraint: must have at least one content element
    if content.is_empty() {
        return Err("Criteria must contain at least one CTN or nested CRI".to_string());
    }

    Ok(CriteriaNode {
        logical_op,
        negate,
        content,
        span: Some(parser.current_span()),
    })
}

// ============================================================================
// CRITERION PARSING
// ============================================================================

/// Parse criterion ::= "CTN" space criterion_type statement_end ctn_content "CTN_END" statement_end
pub fn parse_criterion_node(parser: &mut dyn Parser) -> Result<CriterionNode, String> {
    parser.expect_keyword(Keyword::Ctn)?;
    let criterion_type = parser.expect_identifier()?;

    // Parse required test specification
    let test = parse_test_specification(parser)?;

    let mut state_refs = Vec::new();
    let mut object_refs = Vec::new();
    let mut set_refs: Vec<SetRef> = Vec::new();
    let mut local_states = Vec::new();
    let mut local_object = None;

    // Parse CTN content until CTN_END (following EBNF order)
    loop {
        match parser.current_token() {
            Some(Token::Keyword(Keyword::CtnEnd)) => {
                parser.advance();
                break;
            }
            Some(Token::Keyword(Keyword::StateRef)) => {
                parser.advance(); // consume STATE_REF
                let state_id = parser.expect_identifier()?;
                state_refs.push(StateRef {
                    state_id,
                    span: Some(parser.current_span()),
                });
            }
            Some(Token::Keyword(Keyword::ObjectRef)) => {
                parser.advance(); // consume OBJECT_REF
                let object_id = parser.expect_identifier()?;
                object_refs.push(ObjectRef {
                    object_id,
                    span: Some(parser.current_span()),
                });
            }
            Some(Token::Keyword(Keyword::SetRef)) => {
                parser.advance(); // consume SET_REF
                let set_id = parser.expect_identifier()?;
                set_refs.push(SetRef {
                    set_id,
                    span: Some(parser.current_span()),
                });
            }
            Some(Token::Keyword(Keyword::State)) => {
                let mut state = parse_state_definition(parser)?;
                state.is_global = false; // CTN-level states are local
                local_states.push(state);
            }
            Some(Token::Keyword(Keyword::Object)) => {
                if local_object.is_some() {
                    return Err("CTN can only contain one local object".to_string());
                }
                let mut object = parse_object_definition(parser)?;
                object.is_global = false; // CTN-level objects are local
                local_object = Some(object);
            }
            None => return Err("Expected CTN_END, reached end of input".to_string()),
            _ => return Err("Unexpected token in CTN content".to_string()),
        }
    }

    Ok(CriterionNode {
        criterion_type,
        test,
        state_refs,
        object_refs,
        set_refs,
        local_states,
        local_object,
        span: Some(parser.current_span()),
    })
}

// ============================================================================
// TEST SPECIFICATION PARSING
// ============================================================================

/// Parse test_specification ::= "TEST" space existence_check space item_check (space state_operator)? statement_end
pub fn parse_test_specification(parser: &mut dyn Parser) -> Result<TestSpecification, String> {
    parser.expect_keyword(Keyword::Test)?;
    let existence_check = parse_existence_check(parser)?;
    let item_check = parse_item_check(parser)?;

    // Check for optional state operator
    let state_operator = match parser.current_token() {
        Some(Token::Keyword(Keyword::And | Keyword::Or | Keyword::One)) => {
            Some(parse_state_operator(parser)?)
        }
        _ => None,
    };

    // Check for optional entity check
    let entity_check = parse_optional_entity_check(parser)?;

    Ok(TestSpecification {
        existence_check,
        item_check,
        state_operator,
        entity_check,
        span: Some(parser.current_span()),
    })
}
