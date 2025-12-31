//! Updated token system with dedicated symbol tokens for systematic parsing
//!
//! This implements Option A: Pure Symbol Token Approach with no context sensitivity.
//! All operators are dedicated symbol tokens, data types are identifiers.
use crate::grammar::keywords::Keyword;
use common::log_debug;
use serde::{Deserialize, Serialize};
use std::fmt;

/// String literal variants for ESP
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum StringLiteral {
    /// Backtick string (`content`) - processes escape sequences
    Backtick(String),
    /// Raw string (r`content`) - no escape processing
    Raw(String),
    /// Multiline string (```content```) - processes escape sequences
    Multiline(String),
    /// Raw multiline string (r```content```) - no escape processing
    RawMultiline(String),
    /// Empty string (``)
    Empty,
}

impl StringLiteral {
    /// Get the actual content regardless of variant
    pub fn content(&self) -> &str {
        match self {
            Self::Backtick(s) | Self::Raw(s) | Self::Multiline(s) | Self::RawMultiline(s) => s,
            Self::Empty => "",
        }
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        matches!(self, Self::Empty) || self.content().is_empty()
    }

    /// Convert back to ESP source representation
    pub fn to_esp_string(&self) -> String {
        match self {
            Self::Backtick(s) => format!("`{}`", s),
            Self::Raw(s) => format!("r`{}`", s),
            Self::Multiline(s) => format!("```{}```", s),
            Self::RawMultiline(s) => format!("r```{}```", s),
            Self::Empty => "``".to_string(),
        }
    }
}

/// Systematic token system with dedicated symbol tokens
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Token {
    // === STRUCTURAL KEYWORDS ONLY ===
    /// Block structure and control flow keywords
    Keyword(Keyword),

    // === DEDICATED SYMBOL TOKENS FOR ALL OPERATORS ===

    // Comparison operators
    Equals,             // =
    NotEquals,          // !=
    GreaterThan,        // >
    LessThan,           // <
    GreaterThanOrEqual, // >=
    LessThanOrEqual,    // <=

    // String operators
    CaseInsensitiveEquals,    // ieq
    CaseInsensitiveNotEquals, // ine
    Contains,                 // contains
    StartsWith,               // starts
    EndsWith,                 // ends
    NotContains,              // not_contains
    NotStartsWith,            // not_starts
    NotEndsWith,              // not_ends

    // Pattern operators
    PatternMatch, // pattern_match
    Matches,      // matches

    // Set operators
    SubsetOf,   // subset_of
    SupersetOf, // superset_of

    // Arithmetic operators
    Plus,     // +
    Minus,    // -
    Multiply, // *
    Divide,   // /
    Modulus,  // %

    // === LITERALS ===
    /// String literal (all forms)
    StringLiteral(StringLiteral),
    /// Integer literal (64-bit signed)
    Integer(i64),
    /// Float literal (IEEE 754 double precision)
    Float(f64),
    /// Boolean literal
    Boolean(bool),

    // === IDENTIFIERS (INCLUDING DATA TYPES) ===
    /// All user-defined names AND data type names
    /// Parser determines semantic meaning based on grammatical context
    Identifier(String),

    // === PUNCTUATION ===
    /// Dot character for field paths
    Dot,

    // === WHITESPACE AND STRUCTURE ===
    /// Single space character
    Space,
    /// Tab character
    Tab,
    /// Newline character
    Newline,
    /// Comment (# to end of line)
    Comment(String),
    /// End of file marker
    Eof,
}

impl Token {
    /// Create token from keyword
    pub fn from_keyword(keyword: Keyword) -> Self {
        Self::Keyword(keyword)
    }

    /// Create token from string literal
    pub fn from_string_literal(literal: StringLiteral) -> Self {
        Self::StringLiteral(literal)
    }

    /// Create token from identifier
    pub fn from_identifier(name: String) -> Self {
        Self::Identifier(name)
    }

    /// Check if this token is a comparison operator
    pub fn is_comparison_operator(&self) -> bool {
        matches!(
            self,
            Self::Equals
                | Self::NotEquals
                | Self::GreaterThan
                | Self::LessThan
                | Self::GreaterThanOrEqual
                | Self::LessThanOrEqual
        )
    }

    /// Check if this token is a string operator
    pub fn is_string_operator(&self) -> bool {
        matches!(
            self,
            Self::CaseInsensitiveEquals
                | Self::CaseInsensitiveNotEquals
                | Self::Contains
                | Self::StartsWith
                | Self::EndsWith
                | Self::NotContains
                | Self::NotStartsWith
                | Self::NotEndsWith
        )
    }

    /// Check if this token is a pattern operator
    pub fn is_pattern_operator(&self) -> bool {
        matches!(self, Self::PatternMatch | Self::Matches)
    }

    /// Check if this token is a set operator
    pub fn is_set_operator(&self) -> bool {
        matches!(self, Self::SubsetOf | Self::SupersetOf)
    }

    /// Check if this token is an arithmetic operator
    pub fn is_arithmetic_operator(&self) -> bool {
        matches!(
            self,
            Self::Plus | Self::Minus | Self::Multiply | Self::Divide | Self::Modulus
        )
    }

    /// Check if this token is any operation symbol
    pub fn is_operation(&self) -> bool {
        self.is_comparison_operator()
            || self.is_string_operator()
            || self.is_pattern_operator()
            || self.is_set_operator()
    }

    /// Check if this token is a literal value
    pub fn is_literal(&self) -> bool {
        matches!(
            self,
            Self::StringLiteral(_) | Self::Integer(_) | Self::Float(_) | Self::Boolean(_)
        )
    }

    /// Check if this token is an identifier
    pub fn is_identifier(&self) -> bool {
        matches!(self, Self::Identifier(_))
    }

    /// Check if this token is a specific identifier
    pub fn is_identifier_with_name(&self, name: &str) -> bool {
        matches!(self, Self::Identifier(id) if id == name)
    }

    /// Check if this token is a data type identifier
    pub fn is_data_type_identifier(&self) -> bool {
        match self {
            Self::Identifier(name) => matches!(
                name.as_str(),
                "string"
                    | "int"
                    | "float"
                    | "boolean"
                    | "binary"
                    | "record_data"
                    | "version"
                    | "evr_string"
            ),
            _ => false,
        }
    }

    /// Check if this token is a context-sensitive identifier
    pub fn is_context_sensitive_identifier(&self) -> bool {
        match self {
            Self::Identifier(name) => matches!(
                name.as_str(),
                "literal" | "pattern" | "delimiter" | "character" | "start" | "length" | "field"
            ),
            _ => false,
        }
    }

    /// Check if this token is whitespace
    pub fn is_whitespace(&self) -> bool {
        matches!(self, Self::Space | Self::Tab | Self::Newline)
    }

    /// Check if this token should be ignored during parsing
    pub fn is_ignorable(&self) -> bool {
        matches!(
            self,
            Self::Space | Self::Tab | Self::Newline | Self::Comment(_)
        )
    }

    pub fn is_significant(&self) -> bool {
        let result = !self.is_ignorable();

        // Debug EOF token significance
        if matches!(self, Self::Eof) {
            log_debug!("EOF token significance determination",
                "is_significant" => result
            );
        }

        result
    }

    /// Get keyword if this token is a keyword
    pub fn as_keyword(&self) -> Option<Keyword> {
        match self {
            Self::Keyword(kw) => Some(*kw),
            _ => None,
        }
    }

    /// Get identifier if this token is an identifier
    pub fn as_identifier(&self) -> Option<&str> {
        match self {
            Self::Identifier(name) => Some(name),
            _ => None,
        }
    }

    /// Check if this token matches a specific keyword
    pub fn is_keyword(&self, keyword: Keyword) -> bool {
        matches!(self, Self::Keyword(kw) if *kw == keyword)
    }

    /// Get the token as it should appear in ESP source
    pub fn as_esp_string(&self) -> String {
        match self {
            // Keywords
            Self::Keyword(kw) => kw.as_str().to_string(),

            // Comparison operators
            Self::Equals => "=".to_string(),
            Self::NotEquals => "!=".to_string(),
            Self::GreaterThan => ">".to_string(),
            Self::LessThan => "<".to_string(),
            Self::GreaterThanOrEqual => ">=".to_string(),
            Self::LessThanOrEqual => "<=".to_string(),

            // String operators
            Self::CaseInsensitiveEquals => "ieq".to_string(),
            Self::CaseInsensitiveNotEquals => "ine".to_string(),
            Self::Contains => "contains".to_string(),
            Self::StartsWith => "starts".to_string(),
            Self::EndsWith => "ends".to_string(),
            Self::NotContains => "not_contains".to_string(),
            Self::NotStartsWith => "not_starts".to_string(),
            Self::NotEndsWith => "not_ends".to_string(),

            // Pattern operators
            Self::PatternMatch => "pattern_match".to_string(),
            Self::Matches => "matches".to_string(),

            // Set operators
            Self::SubsetOf => "subset_of".to_string(),
            Self::SupersetOf => "superset_of".to_string(),

            // Arithmetic operators
            Self::Plus => "+".to_string(),
            Self::Minus => "-".to_string(),
            Self::Multiply => "*".to_string(),
            Self::Divide => "/".to_string(),
            Self::Modulus => "%".to_string(),

            // Literals
            Self::StringLiteral(s) => s.to_esp_string(),
            Self::Integer(i) => i.to_string(),
            Self::Float(f) => f.to_string(),
            Self::Boolean(b) => b.to_string(),

            // Other tokens
            Self::Identifier(id) => id.clone(),
            Self::Dot => ".".to_string(),
            Self::Space => " ".to_string(),
            Self::Tab => "\t".to_string(),
            Self::Newline => "\n".to_string(),
            Self::Comment(text) => format!("#{}", text),
            Self::Eof => "<EOF>".to_string(),
        }
    }
}

impl fmt::Display for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_esp_string())
    }
}

impl fmt::Display for StringLiteral {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_esp_string())
    }
}

/// Token classification for different parsing phases
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TokenClass {
    /// Structural tokens (keywords)
    Structural,
    /// Operation symbols
    Operation,
    /// Literal values
    Literal,
    /// Identifiers (including data types)
    Identifier,
    /// Punctuation
    Punctuation,
    /// Whitespace and formatting
    Whitespace,
    /// Special tokens (EOF, comments)
    Special,
}

impl Token {
    /// Get the classification of this token
    pub fn token_class(&self) -> TokenClass {
        match self {
            Self::Keyword(_) => TokenClass::Structural,

            Self::Equals
            | Self::NotEquals
            | Self::GreaterThan
            | Self::LessThan
            | Self::GreaterThanOrEqual
            | Self::LessThanOrEqual
            | Self::CaseInsensitiveEquals
            | Self::CaseInsensitiveNotEquals
            | Self::Contains
            | Self::StartsWith
            | Self::EndsWith
            | Self::NotContains
            | Self::NotStartsWith
            | Self::NotEndsWith
            | Self::PatternMatch
            | Self::Matches
            | Self::SubsetOf
            | Self::SupersetOf
            | Self::Plus
            | Self::Minus
            | Self::Multiply
            | Self::Divide
            | Self::Modulus => TokenClass::Operation,

            Self::StringLiteral(_) | Self::Integer(_) | Self::Float(_) | Self::Boolean(_) => {
                TokenClass::Literal
            }

            Self::Identifier(_) => TokenClass::Identifier,
            Self::Dot => TokenClass::Punctuation,
            Self::Space | Self::Tab | Self::Newline => TokenClass::Whitespace,
            Self::Comment(_) | Self::Eof => TokenClass::Special,
        }
    }
}

// === SYSTEMATIC CLASSIFICATION FUNCTIONS ===

/// Classify a word as either keyword or identifier (no context sensitivity)
pub fn classify_word(word: &str) -> Token {
    // First check for operator words
    if let Some(op_token) = classify_operator_word(word) {
        return op_token;
    }

    // Then check for keywords
    if let Some(keyword) = Keyword::parse(word) {
        Token::Keyword(keyword)
    } else {
        // Handle boolean literals specially
        match word {
            "true" => Token::Boolean(true),
            "false" => Token::Boolean(false),
            _ => Token::Identifier(word.to_string()),
        }
    }
}

/// Check if a word is a data type identifier
pub fn is_data_type_identifier(word: &str) -> bool {
    matches!(
        word,
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

/// Check if a word is a context-sensitive identifier
pub fn is_context_sensitive_identifier(word: &str) -> bool {
    matches!(
        word,
        "literal" | "pattern" | "delimiter" | "character" | "start" | "length" | "field"
    )
}

/// Map operator words to symbol tokens
pub fn classify_operator_word(word: &str) -> Option<Token> {
    match word {
        // String operators
        "ieq" => Some(Token::CaseInsensitiveEquals),
        "ine" => Some(Token::CaseInsensitiveNotEquals),
        "contains" => Some(Token::Contains),
        "starts" => Some(Token::StartsWith),
        "ends" => Some(Token::EndsWith),
        "not_contains" => Some(Token::NotContains),
        "not_starts" => Some(Token::NotStartsWith),
        "not_ends" => Some(Token::NotEndsWith),

        // Pattern operators
        "pattern_match" => Some(Token::PatternMatch),
        "matches" => Some(Token::Matches),

        // Set operators
        "subset_of" => Some(Token::SubsetOf),
        "superset_of" => Some(Token::SupersetOf),

        _ => None,
    }
}

/// Check if a symbol character sequence is an operator
pub fn is_operator_symbol(symbol: &str) -> bool {
    matches!(
        symbol,
        "=" | "!=" | ">" | "<" | ">=" | "<=" | "+" | "-" | "*" | "/" | "%"
    )
}

/// Map symbol to operator token
pub fn classify_operator_symbol(symbol: &str) -> Option<Token> {
    match symbol {
        "=" => Some(Token::Equals),
        "!=" => Some(Token::NotEquals),
        ">" => Some(Token::GreaterThan),
        "<" => Some(Token::LessThan),
        ">=" => Some(Token::GreaterThanOrEqual),
        "<=" => Some(Token::LessThanOrEqual),
        "+" => Some(Token::Plus),
        "-" => Some(Token::Minus),
        "*" => Some(Token::Multiply),
        "/" => Some(Token::Divide),
        "%" => Some(Token::Modulus),
        _ => None,
    }
}
