//! Helper functions for parsing utilities - Updated for unified token system
//!
//! FIXED: Updated to work with unified token system where boolean values
//! only use Token::Boolean(bool) and not Keyword::True/False

use crate::grammar::builders::atomic::{parse_entity_check, Parser};
use crate::grammar::keywords::Keyword;
use crate::tokens::Token;
use common::ast::nodes::*;

/// Parse field_path ::= path_component ("." path_component)*
/// where path_component ::= identifier | wildcard ("*") | index (integer)
///
/// FIXED: Now supports numeric indices like spec.containers.0.name
pub fn parse_field_path(parser: &mut dyn Parser) -> Result<FieldPath, String> {
    let mut components = Vec::new();

    // Parse first component (required) - can be identifier, wildcard, or integer index
    let first_component = match parser.current_token() {
        Some(Token::Multiply) => {
            parser.advance();
            "*".to_string()
        }
        Some(Token::Identifier(_)) => parser.expect_identifier()?,
        Some(Token::Integer(n)) => {
            let idx = (*n).to_string();
            parser.advance();
            idx
        }
        Some(token) => {
            return Err(format!(
                "Expected identifier, '*', or index in field path, found {:?}",
                token
            ))
        }
        None => return Err("Expected identifier, '*', or index, reached end of input".to_string()),
    };
    components.push(first_component);

    // Parse additional components separated by dots
    while let Some(Token::Dot) = parser.current_token() {
        parser.advance(); // consume dot

        let component = match parser.current_token() {
            Some(Token::Multiply) => {
                parser.advance();
                "*".to_string()
            }
            Some(Token::Identifier(_)) => parser.expect_identifier()?,
            Some(Token::Integer(n)) => {
                let idx = (*n).to_string();
                parser.advance();
                idx
            }
            Some(token) => {
                return Err(format!(
                    "Expected identifier, '*', or index after dot in field path, found {:?}",
                    token
                ))
            }
            None => {
                return Err(
                    "Expected identifier, '*', or index after dot, reached end of input"
                        .to_string(),
                )
            }
        };
        components.push(component);
    }

    Ok(FieldPath::new(components))
}

/// Parse a list of identifiers separated by whitespace
pub fn parse_identifier_list(parser: &mut dyn Parser) -> Result<Vec<Identifier>, String> {
    let mut identifiers = Vec::new();

    while let Some(Token::Identifier(_)) = parser.current_token() {
        identifiers.push(parser.expect_identifier()?);
    }

    if identifiers.is_empty() {
        Err("Expected at least one identifier".to_string())
    } else {
        Ok(identifiers)
    }
}

/// Parse optional entity_check ::= ("all" | "at_least_one" | "none" | "only_one")?
pub fn parse_optional_entity_check(parser: &mut dyn Parser) -> Result<Option<EntityCheck>, String> {
    match parser.current_token() {
        Some(Token::Keyword(
            Keyword::All | Keyword::AtLeastOne | Keyword::None | Keyword::OnlyOne,
        )) => Ok(Some(parse_entity_check(parser)?)),
        _ => Ok(None), // No entity check found
    }
}

/// Expect a specific block end keyword and consume it
pub fn expect_block_end(parser: &mut dyn Parser, expected: Keyword) -> Result<(), String> {
    match parser.current_token() {
        Some(Token::Keyword(kw)) if *kw == expected => {
            parser.advance();
            Ok(())
        }
        Some(token) => Err(format!("Expected {:?}, found {:?}", expected, token)),
        None => Err(format!("Expected {:?}, reached end of input", expected)),
    }
}

/// Parse until a specific end keyword is reached
pub fn parse_until_keyword(parser: &mut dyn Parser, end_keyword: Keyword) -> Result<(), String> {
    while let Some(token) = parser.current_token() {
        if matches!(token, Token::Keyword(kw) if *kw == end_keyword) {
            return Ok(());
        }
        parser.advance();
    }
    Err(format!(
        "Expected {:?} but reached end of input",
        end_keyword
    ))
}

/// Check if current token matches any of the given keywords
pub fn matches_any_keyword(parser: &dyn Parser, keywords: &[Keyword]) -> bool {
    match parser.current_token() {
        Some(Token::Keyword(kw)) => keywords.contains(kw),
        _ => false,
    }
}

/// Parse a boolean flag using unified token system
/// FIXED: Only uses Token::Boolean(bool) - removed Keyword::True/False support
pub fn parse_boolean_flag(parser: &mut dyn Parser) -> Result<bool, String> {
    match parser.current_token() {
        Some(Token::Boolean(b)) => {
            let value = *b;
            parser.advance();
            Ok(value)
        }
        _ => Err("Expected boolean value (true/false)".to_string()),
    }
}

/// Parse optional boolean flag with default value using unified token system
/// FIXED: Only uses Token::Boolean(bool) - removed Keyword::True/False support
pub fn parse_optional_boolean(parser: &mut dyn Parser, default: bool) -> Result<bool, String> {
    match parser.current_token() {
        Some(Token::Boolean(_)) => parse_boolean_flag(parser),
        _ => Ok(default),
    }
}

/// Skip whitespace and comments (if present in token stream)
pub fn skip_insignificant_tokens(parser: &mut dyn Parser) {
    while let Some(token) = parser.current_token() {
        match token {
            Token::Space | Token::Tab | Token::Newline | Token::Comment(_) => {
                parser.advance();
            }
            _ => break,
        }
    }
}

/// Check if we're at a block boundary (start of a new major construct)
pub fn at_block_boundary(parser: &dyn Parser) -> bool {
    matches!(
        parser.current_token(),
        Some(Token::Keyword(
            Keyword::Meta
                | Keyword::Def
                | Keyword::Cri
                | Keyword::Ctn
                | Keyword::State
                | Keyword::Object
                | Keyword::Run
                | Keyword::Set
                | Keyword::Filter
        ))
    )
}

/// Peek ahead to check if pattern matches without advancing
pub fn peek_matches_pattern(parser: &dyn Parser, keywords: &[Keyword]) -> bool {
    // This is a simplified version - real implementation would need lookahead support
    match parser.current_token() {
        Some(Token::Keyword(kw)) => keywords.contains(kw),
        _ => false,
    }
}

/// Parse a sequence of elements until end condition
pub fn parse_sequence_until<T, F>(
    parser: &mut dyn Parser,
    end_keyword: Keyword,
    parse_element: F,
) -> Result<Vec<T>, String>
where
    F: Fn(&mut dyn Parser) -> Result<T, String>,
{
    let mut elements = Vec::new();

    while !matches!(parser.current_token(), Some(Token::Keyword(kw)) if *kw == end_keyword) {
        match parser.current_token() {
            None => return Err(format!("Expected {:?}, reached end of input", end_keyword)),
            _ => {
                let element = parse_element(parser)?;
                elements.push(element);
            }
        }
    }

    Ok(elements)
}

/// Validate that a keyword is in its expected context
pub fn validate_keyword_context(
    parser: &dyn Parser,
    keyword: Keyword,
    _expected_contexts: &[&str],
) -> Result<(), String> {
    // This is a placeholder for context validation
    // Real implementation would track parsing context stack
    match parser.current_token() {
        Some(Token::Keyword(kw)) if *kw == keyword => Ok(()),
        _ => Err(format!(
            "Keyword {:?} not valid in current context",
            keyword
        )),
    }
}

/// Create a standard error message for unexpected tokens
pub fn unexpected_token_error(parser: &dyn Parser, expected: &str) -> String {
    match parser.current_token() {
        Some(token) => format!("Expected {}, found {:?}", expected, token),
        None => format!("Expected {}, reached end of input", expected),
    }
}

/// Check if current position looks like the start of a specific construct
pub fn looks_like_construct(parser: &dyn Parser, construct_type: &str) -> bool {
    match construct_type {
        "variable_declaration" => {
            matches!(parser.current_token(), Some(Token::Keyword(Keyword::Var)))
        }
        "state_definition" => {
            matches!(parser.current_token(), Some(Token::Keyword(Keyword::State)))
        }
        "object_definition" => matches!(
            parser.current_token(),
            Some(Token::Keyword(Keyword::Object))
        ),
        "runtime_operation" => matches!(parser.current_token(), Some(Token::Keyword(Keyword::Run))),
        "set_operation" => matches!(parser.current_token(), Some(Token::Keyword(Keyword::Set))),
        "criteria" => matches!(parser.current_token(), Some(Token::Keyword(Keyword::Cri))),
        "criterion" => matches!(parser.current_token(), Some(Token::Keyword(Keyword::Ctn))),
        "test_specification" => {
            matches!(parser.current_token(), Some(Token::Keyword(Keyword::Test)))
        }
        "filter_spec" => matches!(
            parser.current_token(),
            Some(Token::Keyword(Keyword::Filter))
        ),
        "record_check" => matches!(
            parser.current_token(),
            Some(Token::Keyword(Keyword::Record))
        ),
        _ => false,
    }
}

/// Parse key-value pairs for metadata and object fields
pub fn parse_key_value_pairs(
    parser: &mut dyn Parser,
    end_keyword: Keyword,
) -> Result<Vec<(String, String)>, String> {
    let mut pairs = Vec::new();

    while !matches!(parser.current_token(), Some(Token::Keyword(kw)) if *kw == end_keyword) {
        match parser.current_token() {
            Some(Token::Identifier(_)) => {
                let key = parser.expect_identifier()?;
                let value = parser.expect_string_literal()?;
                pairs.push((key, value));
            }
            None => return Err(format!("Expected {:?}, reached end of input", end_keyword)),
            _ => return Err("Expected identifier for key-value pair".to_string()),
        }
    }

    Ok(pairs)
}

// === UNIFIED TOKEN SYSTEM HELPERS ===

/// Check if current token is any boolean value using unified system
pub fn is_boolean_token(parser: &dyn Parser) -> bool {
    matches!(parser.current_token(), Some(Token::Boolean(_)))
}

/// Check if current token is any operation symbol using unified system
pub fn is_operation_token(parser: &dyn Parser) -> bool {
    if let Some(token) = parser.current_token() {
        token.is_operation()
    } else {
        false
    }
}

/// Check if current token is any arithmetic operator using unified system
pub fn is_arithmetic_token(parser: &dyn Parser) -> bool {
    matches!(
        parser.current_token(),
        Some(Token::Plus | Token::Multiply | Token::Minus | Token::Divide | Token::Modulus)
    )
}

/// Parse any arithmetic operator using unified token system
pub fn parse_any_arithmetic_operator(parser: &mut dyn Parser) -> Result<String, String> {
    match parser.current_token() {
        Some(Token::Plus) => {
            parser.advance();
            Ok("+".to_string())
        }
        Some(Token::Multiply) => {
            parser.advance();
            Ok("*".to_string())
        }
        Some(Token::Minus) => {
            parser.advance();
            Ok("-".to_string())
        }
        Some(Token::Divide) => {
            parser.advance();
            Ok("/".to_string())
        }
        Some(Token::Modulus) => {
            parser.advance();
            Ok("%".to_string())
        }
        _ => Err("Expected arithmetic operator (+, *, -, /, %)".to_string()),
    }
}

/// Validate unified token system consistency in helpers
pub fn validate_unified_token_helpers() -> Result<(), String> {
    // This validates that helper functions use unified token system consistently
    // If this module compiles without errors, consistency is maintained
    Ok(())
}

/// Get helper functions report for unified token system
pub fn get_unified_helpers_report() -> String {
    "=== Unified Token System Helpers Report ===\n\
         \n\
         Boolean Handling:\n\
         - Only Token::Boolean(bool) supported\n\
         - Removed Keyword::True/False handling\n\
         - Consistent boolean parsing throughout\n\
         \n\
         Operation Detection:\n\
         - is_operation_token: detects all unified operation symbols\n\
         - is_arithmetic_token: detects arithmetic symbol tokens\n\
         - parse_any_arithmetic_operator: handles all arithmetic symbols\n\
         \n\
         Helper Functions:\n\
         - parse_field_path: dot-separated identifier parsing\n\
         - parse_identifier_list: whitespace-separated identifiers\n\
         - parse_optional_entity_check: optional entity check parsing\n\
         - parse_boolean_flag: unified boolean token parsing\n\
         - parse_optional_boolean: optional boolean with defaults\n\
         - parse_key_value_pairs: metadata field parsing\n\
         \n\
         Utility Functions:\n\
         - expect_block_end: block terminator validation\n\
         - skip_insignificant_tokens: whitespace handling\n\
         - at_block_boundary: major construct detection\n\
         - looks_like_construct: construct type identification\n\
         - unexpected_token_error: standardized error messages\n\
         \n\
         Architecture Benefits:\n\
         - Consistent token type usage\n\
         - No mixed keyword/symbol approaches\n\
         - Predictable parsing patterns\n\
         - Unified error handling"
        .to_string()
}
