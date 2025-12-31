//! Enhanced error types for syntax transformation with global logging integration
//!
//! Handles token-to-AST transformation errors with proper error code mapping
//! and span-accurate error reporting.

use common::logging::{codes, Code};
use common::utils::Span;

pub type SyntaxResult<T> = Result<T, SyntaxError>;

/// Enhanced syntax transformation errors with proper error code mapping
#[derive(Debug, Clone, thiserror::Error)]
pub enum SyntaxError {
    #[error("Unexpected token: expected {expected}, found '{found}' at {span}")]
    UnexpectedToken {
        expected: String,
        found: String,
        span: Span,
    },

    #[error("Unexpected end of input: expected {expected}")]
    UnexpectedEndOfInput { expected: String },

    #[error("Empty token stream - no tokens to parse")]
    EmptyTokenStream,

    #[error("Missing EOF token in token stream")]
    MissingEof,

    #[error("Grammar violation: {message} at {span}")]
    GrammarViolation { message: String, span: Span },

    #[error("Unmatched block delimiter: {delimiter} at {span}")]
    UnmatchedBlockDelimiter { delimiter: String, span: Span },

    #[error("Maximum recursion depth exceeded at {span}")]
    MaxRecursionDepth { span: Span },

    #[error("Internal parser error: {message}")]
    InternalParserError { message: String },

    #[error("Parse error: {message} at {span}")]
    ParseError { message: String, span: Span },
}

impl SyntaxError {
    /// Create unexpected token error
    pub fn unexpected_token(expected: &str, found: &str, span: Span) -> Self {
        Self::UnexpectedToken {
            expected: expected.to_string(),
            found: found.to_string(),
            span,
        }
    }

    /// Create unexpected end of input error
    pub fn unexpected_end_of_input(expected: &str) -> Self {
        Self::UnexpectedEndOfInput {
            expected: expected.to_string(),
        }
    }

    /// Create empty token stream error
    pub fn empty_token_stream() -> Self {
        Self::EmptyTokenStream
    }

    /// Create missing EOF error
    pub fn missing_eof() -> Self {
        Self::MissingEof
    }

    /// Create grammar violation error
    pub fn grammar_violation(message: &str, span: Span) -> Self {
        Self::GrammarViolation {
            message: message.to_string(),
            span,
        }
    }

    /// Create unmatched delimiter error
    pub fn unmatched_delimiter(delimiter: &str, span: Span) -> Self {
        Self::UnmatchedBlockDelimiter {
            delimiter: delimiter.to_string(),
            span,
        }
    }

    /// Create max recursion depth error
    pub fn max_recursion_depth(span: Span) -> Self {
        Self::MaxRecursionDepth { span }
    }

    /// Create internal parser error
    pub fn internal_parser_error(message: &str) -> Self {
        Self::InternalParserError {
            message: message.to_string(),
        }
    }

    /// Create parse error
    pub fn parse_error(message: &str, span: Span) -> Self {
        Self::ParseError {
            message: message.to_string(),
            span,
        }
    }

    /// Create error from builder error (for compatibility with existing builders)
    pub fn from_builder_error(error: String, span: Span) -> Self {
        Self::ParseError {
            message: error,
            span,
        }
    }

    /// Get error code for global logging system
    pub fn error_code(&self) -> Code {
        match self {
            Self::UnexpectedToken { .. } => codes::syntax::UNEXPECTED_TOKEN,
            Self::UnexpectedEndOfInput { .. } => codes::syntax::MISSING_EOF,
            Self::EmptyTokenStream => codes::syntax::EMPTY_TOKEN_STREAM,
            Self::MissingEof => codes::syntax::MISSING_EOF,
            Self::GrammarViolation { .. } => codes::syntax::GRAMMAR_VIOLATION,
            Self::UnmatchedBlockDelimiter { .. } => codes::syntax::UNMATCHED_BLOCK_DELIMITER,
            Self::MaxRecursionDepth { .. } => codes::syntax::MAX_RECURSION_DEPTH,
            Self::InternalParserError { .. } => codes::syntax::INTERNAL_PARSER_ERROR,
            Self::ParseError { .. } => codes::syntax::GRAMMAR_VIOLATION,
        }
    }

    /// Get span if available
    pub fn span(&self) -> Option<Span> {
        match self {
            Self::UnexpectedToken { span, .. }
            | Self::GrammarViolation { span, .. }
            | Self::UnmatchedBlockDelimiter { span, .. }
            | Self::MaxRecursionDepth { span }
            | Self::ParseError { span, .. } => Some(*span),
            Self::UnexpectedEndOfInput { .. }
            | Self::EmptyTokenStream
            | Self::MissingEof
            | Self::InternalParserError { .. } => None,
        }
    }

    /// Check if this error requires halting
    pub fn requires_halt(&self) -> bool {
        matches!(
            self,
            Self::InternalParserError { .. } | Self::MaxRecursionDepth { .. }
        )
    }

    /// Check if this error is recoverable
    pub fn is_recoverable(&self) -> bool {
        !matches!(
            self,
            Self::InternalParserError { .. } | Self::MaxRecursionDepth { .. }
        )
    }

    /// Get error severity
    pub fn severity(&self) -> &'static str {
        common::logging::codes::get_severity(self.error_code().as_str()).as_str()
    }

    /// Get error category
    pub fn category(&self) -> &'static str {
        common::logging::codes::get_category(self.error_code().as_str())
    }

    /// Get error description
    pub fn description(&self) -> &'static str {
        common::logging::codes::get_description(self.error_code().as_str())
    }

    /// Get recommended action
    pub fn recommended_action(&self) -> &'static str {
        common::logging::codes::get_action(self.error_code().as_str())
    }

    /// Create enhanced error message with context
    pub fn enhanced_message(&self) -> String {
        match self {
            Self::UnexpectedToken {
                expected, found, ..
            } => {
                format!(
                    "Expected {} but found '{}'. {}",
                    expected,
                    found,
                    self.recommended_action()
                )
            }
            Self::UnexpectedEndOfInput { expected } => {
                format!(
                    "Unexpected end of input while expecting {}. {}",
                    expected,
                    self.recommended_action()
                )
            }
            Self::GrammarViolation { message, .. } => {
                format!("{} ({})", message, self.recommended_action())
            }
            Self::UnmatchedBlockDelimiter { delimiter, .. } => {
                format!(
                    "Unmatched '{}' delimiter. {}",
                    delimiter,
                    self.recommended_action()
                )
            }
            _ => format!("{} ({})", self, self.recommended_action()),
        }
    }
}

/// Error context for enhanced error reporting
#[derive(Debug, Clone)]
pub struct ErrorContext {
    pub parsing_context: Vec<String>,
    pub surrounding_tokens: Vec<String>,
    pub file_position: Option<(u32, u32)>, // line, column
}

impl ErrorContext {
    pub fn new() -> Self {
        Self {
            parsing_context: Vec::new(),
            surrounding_tokens: Vec::new(),
            file_position: None,
        }
    }

    pub fn with_context(mut self, context: String) -> Self {
        self.parsing_context.push(context);
        self
    }

    pub fn with_tokens(mut self, tokens: Vec<String>) -> Self {
        self.surrounding_tokens = tokens;
        self
    }

    pub fn with_position(mut self, line: u32, column: u32) -> Self {
        self.file_position = Some((line, column));
        self
    }

    pub fn format_context(&self) -> String {
        let mut context = String::new();

        if !self.parsing_context.is_empty() {
            context.push_str(&format!("Context: {}\n", self.parsing_context.join(" -> ")));
        }

        if !self.surrounding_tokens.is_empty() {
            context.push_str(&format!("Near: {}\n", self.surrounding_tokens.join(" ")));
        }

        if let Some((line, column)) = self.file_position {
            context.push_str(&format!("Position: line {}, column {}\n", line, column));
        }

        context
    }
}

impl Default for ErrorContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Enhanced syntax error with rich context
#[derive(Debug, Clone)]
pub struct ContextualSyntaxError {
    pub error: SyntaxError,
    pub context: ErrorContext,
}

impl ContextualSyntaxError {
    pub fn new(error: SyntaxError) -> Self {
        Self {
            error,
            context: ErrorContext::new(),
        }
    }

    pub fn with_context(mut self, context: ErrorContext) -> Self {
        self.context = context;
        self
    }

    pub fn format_full_error(&self) -> String {
        format!(
            "{}\n{}Help: {} (Severity: {})",
            self.error.enhanced_message(),
            self.context.format_context(),
            self.error.recommended_action(),
            self.error.severity()
        )
    }
}

impl std::fmt::Display for ContextualSyntaxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.format_full_error())
    }
}

impl std::error::Error for ContextualSyntaxError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::utils::{Position, Span};

    #[test]
    fn test_error_code_mapping() {
        let span = Span::new(Position::start(), Position::start());

        let unexpected_token = SyntaxError::unexpected_token("identifier", "keyword", span);
        assert_eq!(unexpected_token.error_code().as_str(), "E050");

        let missing_eof = SyntaxError::missing_eof();
        assert_eq!(missing_eof.error_code().as_str(), "E040");

        let grammar_violation = SyntaxError::grammar_violation("Invalid syntax", span);
        assert_eq!(grammar_violation.error_code().as_str(), "E043");

        let max_recursion = SyntaxError::max_recursion_depth(span);
        assert_eq!(max_recursion.error_code().as_str(), "E087");
    }

    #[test]
    fn test_error_properties() {
        let span = Span::new(Position::start(), Position::start());

        let internal_error = SyntaxError::internal_parser_error("Test error");
        assert!(internal_error.requires_halt());
        assert!(!internal_error.is_recoverable());

        let unexpected_token = SyntaxError::unexpected_token("identifier", "keyword", span);
        assert!(!unexpected_token.requires_halt());
        assert!(unexpected_token.is_recoverable());
    }

    #[test]
    fn test_span_extraction() {
        let span = Span::new(Position::new(10, 1, 11), Position::new(15, 1, 16));
        let error = SyntaxError::unexpected_token("identifier", "keyword", span);

        assert_eq!(error.span(), Some(span));
        assert_eq!(error.span().unwrap().start().column, 11);
    }

    #[test]
    fn test_enhanced_messages() {
        let span = Span::new(Position::start(), Position::start());
        let error = SyntaxError::unexpected_token("identifier", "if", span);

        let enhanced = error.enhanced_message();
        assert!(enhanced.contains("Expected identifier"));
        assert!(enhanced.contains("found 'if'"));
    }

    #[test]
    fn test_error_context() {
        let context = ErrorContext::new()
            .with_context("parsing definition".to_string())
            .with_tokens(vec!["DEF".to_string(), "test".to_string()])
            .with_position(5, 10);

        let formatted = context.format_context();
        assert!(formatted.contains("Context: parsing definition"));
        assert!(formatted.contains("Near: DEF test"));
        assert!(formatted.contains("line 5, column 10"));
    }

    #[test]
    fn test_contextual_error() {
        let span = Span::new(Position::new(10, 2, 5), Position::new(15, 2, 10));
        let error = SyntaxError::grammar_violation("Invalid block structure", span);

        let context = ErrorContext::new()
            .with_context("parsing DEF block".to_string())
            .with_position(2, 5);

        let contextual = ContextualSyntaxError::new(error).with_context(context);
        let formatted = contextual.format_full_error();

        assert!(formatted.contains("Invalid block structure"));
        assert!(formatted.contains("parsing DEF block"));
        assert!(formatted.contains("Severity:"));
    }
}
