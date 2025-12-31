//! Enhanced parser implementation with global logging integration
//!
//! This parser maintains precise source location tracking and provides
//! enhanced error reporting using the global logging system.

use crate::grammar::{
    builders::{atomic::Parser, parse_esp_file},
    keywords::Keyword,
};
use crate::syntax::error::{ContextualSyntaxError, ErrorContext, SyntaxError, SyntaxResult};
use crate::tokens::{Token, TokenStream, TokenStreamError};
use common::ast::nodes::EspFile;
use common::config::constants::compile_time::syntax::*;
use common::logging::codes;
use common::utils::Span;
use common::{log_debug, log_error, log_info, log_success, log_warning};
use std::collections::VecDeque;

/// Parser checkpoint for backtracking with span accuracy
#[derive(Debug, Clone)]
pub struct ParserCheckpoint {
    /// Position in token stream
    pub position: usize,
    /// Context stack snapshot
    pub context_stack: Vec<String>,
    /// Start span for error ranges
    pub start_span: Option<Span>,
}

/// Enhanced parser with global logging and sophisticated error handling
pub struct EspParser {
    tokens: TokenStream,
    context_stack: Vec<String>,
    error_history: VecDeque<SyntaxError>,
    parse_depth: usize,
}

impl EspParser {
    /// Create new parser with global logging integration
    pub fn new(tokens: TokenStream) -> Self {
        log_debug!("Creating ESP parser", "tokens" => tokens.len());

        Self {
            tokens,
            context_stack: Vec::new(),
            error_history: VecDeque::new(),
            parse_depth: 0,
        }
    }

    /// Check if token stream has EOF token - fixed range
    fn has_eof_token(&self) -> bool {
        let total_tokens = self.tokens.len();
        log_debug!("Checking for EOF in token stream",
            "total_tokens" => total_tokens
        );

        // Check the last 5 tokens AND the position just beyond (which would be the actual last)
        for i in (total_tokens.saturating_sub(5))..=total_tokens {
            // Note the `=` in `..=`
            if let Some(token) = self.tokens.peek_ahead(i) {
                let token_desc = match &token.value {
                    Token::Eof => "EOF_TOKEN",
                    Token::Keyword(k) => &format!("KEYWORD({})", k.as_str()),
                    Token::Identifier(s) => &format!("ID({})", s),
                    Token::StringLiteral(_) => "STRING",
                    Token::Integer(n) => &format!("INT({})", n),
                    Token::Space => "SPACE",
                    Token::Newline => "NEWLINE",
                    _ => "OTHER",
                };
                log_debug!("Examining token at position",
                    "position" => i,
                    "token_description" => token_desc
                );

                if matches!(token.value, Token::Eof) {
                    log_debug!("Found EOF token in stream",
                        "position" => i
                    );
                    return true;
                }
            }
        }

        log_debug!("No EOF token found in stream");
        false
    }

    /// Parse TokenStream into AST with comprehensive error reporting
    pub fn parse_esp_file(&mut self) -> SyntaxResult<EspFile> {
        self.push_context("esp_file");

        log_info!("Starting ESP file parsing",
            "tokens" => self.tokens.len(),
            "context" => self.current_context()
        );

        // Check for empty token stream
        if self.tokens.is_empty() {
            let error = SyntaxError::empty_token_stream();
            log_error!(error.error_code(), "Cannot parse empty token stream");
            return Err(error);
        }

        // Validate token stream has EOF
        if !self.has_eof_token() {
            let error = SyntaxError::missing_eof();
            log_error!(error.error_code(), "Token stream missing EOF token");
            return Err(error);
        }

        // Prevent excessive recursion - NOW USING COMPILE-TIME CONSTANT
        if self.parse_depth >= MAX_PARSE_DEPTH {
            let error = SyntaxError::max_recursion_depth(self.current_span());
            log_error!(error.error_code(), "Maximum parser recursion depth exceeded",
                "depth" => self.parse_depth,
                "max_depth" => MAX_PARSE_DEPTH
            );
            return Err(error);
        }

        self.parse_depth += 1;

        // Use existing grammar builder with enhanced error context
        let result = parse_esp_file(self);

        self.parse_depth -= 1;

        match result {
            Ok(esp_file) => {
                log_success!(codes::success::AST_CONSTRUCTION_COMPLETE,
                    "ESP file parsing completed successfully",
                    "context" => self.current_context(),
                    "final_position" => self.tokens.position()
                );
                self.pop_context();
                Ok(esp_file)
            }
            Err(builder_error) => {
                let error = self.create_enhanced_error(&builder_error);
                self.record_error(error.clone());

                log_error!(error.error_code(), "ESP file parsing failed",
                    span = error.span().unwrap_or_else(|| self.current_span()),
                    "context" => self.current_context(),
                    "error_message" => builder_error,
                    "position" => self.tokens.position()
                );

                self.pop_context();
                Err(error)
            }
        }
    }

    /// Create enhanced error with accurate span and context
    fn create_enhanced_error(&self, message: &str) -> SyntaxError {
        let span = self.current_span();

        // Determine specific error type based on message content
        if message.contains("unexpected token") || message.contains("expected") {
            // Try to extract expected vs found information
            SyntaxError::unexpected_token("token", message, span)
        } else if message.contains("unmatched") || message.contains("delimiter") {
            SyntaxError::unmatched_delimiter("block", span)
        } else if message.contains("recursion") || message.contains("depth") {
            SyntaxError::max_recursion_depth(span)
        } else if message.contains("grammar") || message.contains("syntax") {
            SyntaxError::grammar_violation(message, span)
        } else {
            SyntaxError::parse_error(message, span)
        }
    }

    /// Record error for history and analysis - NOW USING COMPILE-TIME CONSTANT
    fn record_error(&mut self, error: SyntaxError) {
        if self.error_history.len() >= MAX_ERROR_HISTORY {
            self.error_history.pop_front();
        }
        self.error_history.push_back(error);
    }

    /// Get recent error history for context
    pub fn error_history(&self) -> Vec<&SyntaxError> {
        self.error_history.iter().collect()
    }

    /// Advanced error recovery with span context
    pub fn recover_to_synchronization_point(&mut self) -> bool {
        let sync_keywords = [
            Keyword::Def,
            Keyword::DefEnd,
            Keyword::Cri,
            Keyword::CriEnd,
            Keyword::Ctn,
            Keyword::CtnEnd,
            Keyword::State,
            Keyword::StateEnd,
            Keyword::Object,
            Keyword::ObjectEnd,
            Keyword::Meta,
            Keyword::MetaEnd,
        ];

        let start_position = self.tokens.position();

        log_debug!("Attempting error recovery",
            "start_position" => start_position,
            "context" => self.current_context()
        );

        while !self.tokens.is_at_end() {
            if let Some(Token::Keyword(kw)) = self.tokens.current_token() {
                if sync_keywords.contains(kw) {
                    let recovered_span = self
                        .tokens
                        .span_range(start_position, self.tokens.position());

                    log_info!("Successfully recovered to synchronization point",
                        "keyword" => kw.as_str(),
                        "skipped_span" => format!("{}", recovered_span),
                        "tokens_skipped" => self.tokens.position() - start_position
                    );
                    return true;
                }
            }
            self.tokens.advance();
        }

        log_warning!("Failed to find synchronization point",
            "tokens_processed" => self.tokens.position() - start_position
        );
        false
    }

    /// Get contextual error for enhanced reporting
    pub fn create_contextual_error(&self, error: SyntaxError) -> ContextualSyntaxError {
        let context = ErrorContext::new()
            .with_context(self.current_context())
            .with_tokens(self.get_surrounding_tokens())
            .with_position(
                self.current_span().start().line,
                self.current_span().start().column,
            );

        ContextualSyntaxError::new(error).with_context(context)
    }

    /// Get surrounding tokens for error context
    fn get_surrounding_tokens(&self) -> Vec<String> {
        self.tokens
            .context_snippet(3)
            .iter()
            .map(|t| t.value.as_esp_string())
            .collect()
    }
}

/// Enhanced Parser trait implementation with global logging
impl Parser for EspParser {
    fn current_token(&self) -> Option<&Token> {
        self.tokens.current_token()
    }

    fn advance(&mut self) {
        let old_pos = self.tokens.position();
        self.tokens.advance();

        log_debug!("Parser advanced",
            "from" => old_pos,
            "to" => self.tokens.position(),
            "context" => self.current_context()
        );
    }

    fn expect_keyword(&mut self, keyword: Keyword) -> Result<(), String> {
        log_debug!("Expecting keyword",
            "keyword" => keyword.as_str(),
            "position" => self.tokens.position()
        );

        match self.current_token() {
            Some(Token::Keyword(actual)) if *actual == keyword => {
                log_debug!("Keyword matched successfully", "keyword" => keyword.as_str());
                self.advance();
                Ok(())
            }
            Some(token) => {
                let span = self.current_span();
                let error_msg = format!(
                    "Expected keyword '{}', found '{}'",
                    keyword.as_str(),
                    token.as_esp_string()
                );

                log_error!(codes::syntax::UNEXPECTED_TOKEN, "Keyword expectation failed",
                    span = span,
                    "expected" => keyword.as_str(),
                    "found" => token.as_esp_string(),
                    "context" => self.current_context()
                );

                Err(error_msg)
            }
            None => {
                let error_msg = format!(
                    "Expected keyword '{}', reached end of input",
                    keyword.as_str()
                );

                log_error!(codes::syntax::MISSING_EOF, "Unexpected end while expecting keyword",
                    "expected" => keyword.as_str(),
                    "context" => self.current_context()
                );

                Err(error_msg)
            }
        }
    }

    fn expect_identifier(&mut self) -> Result<String, String> {
        log_debug!("Expecting identifier", "position" => self.tokens.position());

        match self.current_token() {
            Some(Token::Identifier(id)) => {
                let identifier = id.clone();
                log_debug!("Identifier matched", "identifier" => identifier.as_str());
                self.advance();
                Ok(identifier)
            }
            Some(token) => {
                let span = self.current_span();
                let error_msg = format!("Expected identifier, found '{}'", token.as_esp_string());

                log_error!(codes::syntax::UNEXPECTED_TOKEN, "Identifier expectation failed",
                    span = span,
                    "expected" => "identifier",
                    "found" => token.as_esp_string(),
                    "context" => self.current_context()
                );

                Err(error_msg)
            }
            None => {
                let error_msg = "Expected identifier, reached end of input".to_string();

                log_error!(codes::syntax::MISSING_EOF, "Unexpected end while expecting identifier",
                    "context" => self.current_context()
                );

                Err(error_msg)
            }
        }
    }

    fn expect_string_literal(&mut self) -> Result<String, String> {
        log_debug!("Expecting string literal", "position" => self.tokens.position());

        match self.current_token() {
            Some(Token::StringLiteral(s)) => {
                let content = s.content().to_string();
                log_debug!("String literal matched", "length" => content.len());
                self.advance();
                Ok(content)
            }
            Some(token) => {
                let span = self.current_span();
                let error_msg =
                    format!("Expected string literal, found '{}'", token.as_esp_string());

                log_error!(codes::syntax::UNEXPECTED_TOKEN, "String literal expectation failed",
                    span = span,
                    "expected" => "string literal",
                    "found" => token.as_esp_string(),
                    "context" => self.current_context()
                );

                Err(error_msg)
            }
            None => {
                let error_msg = "Expected string literal, reached end of input".to_string();

                log_error!(codes::syntax::MISSING_EOF, "Unexpected end while expecting string literal",
                    "context" => self.current_context()
                );

                Err(error_msg)
            }
        }
    }

    fn expect_integer(&mut self) -> Result<i64, String> {
        log_debug!("Expecting integer", "position" => self.tokens.position());

        match self.current_token() {
            Some(Token::Integer(value)) => {
                let int_value = *value;
                log_debug!("Integer matched", "value" => int_value);
                self.advance();
                Ok(int_value)
            }
            Some(token) => {
                let span = self.current_span();
                let error_msg = format!("Expected integer, found '{}'", token.as_esp_string());

                log_error!(codes::syntax::UNEXPECTED_TOKEN, "Integer expectation failed",
                    span = span,
                    "expected" => "integer",
                    "found" => token.as_esp_string(),
                    "context" => self.current_context()
                );

                Err(error_msg)
            }
            None => {
                let error_msg = "Expected integer, reached end of input".to_string();

                log_error!(codes::syntax::MISSING_EOF, "Unexpected end while expecting integer",
                    "context" => self.current_context()
                );

                Err(error_msg)
            }
        }
    }

    fn expect_float(&mut self) -> Result<f64, String> {
        log_debug!("Expecting float", "position" => self.tokens.position());

        match self.current_token() {
            Some(Token::Float(value)) => {
                let float_value = *value;
                log_debug!("Float matched", "value" => float_value);
                self.advance();
                Ok(float_value)
            }
            Some(token) => {
                let span = self.current_span();
                let error_msg = format!("Expected float, found '{}'", token.as_esp_string());

                log_error!(codes::syntax::UNEXPECTED_TOKEN, "Float expectation failed",
                    span = span,
                    "expected" => "float",
                    "found" => token.as_esp_string(),
                    "context" => self.current_context()
                );

                Err(error_msg)
            }
            None => {
                let error_msg = "Expected float, reached end of input".to_string();

                log_error!(codes::syntax::MISSING_EOF, "Unexpected end while expecting float",
                    "context" => self.current_context()
                );

                Err(error_msg)
            }
        }
    }

    fn current_span(&self) -> Span {
        self.tokens.current_span().unwrap_or_else(Span::dummy)
    }
}

/// Enhanced parser interface with context tracking and diagnostics
impl EspParser {
    // === LOOKAHEAD CAPABILITIES ===

    /// Peek ahead n tokens without advancing
    pub fn peek(&self, n: usize) -> Option<&Token> {
        self.tokens.peek_ahead(n).map(|spanned| &spanned.value)
    }

    /// Get multiple tokens for lookahead analysis - WITH BOUNDS
    pub fn lookahead(&self, count: usize) -> Vec<&Token> {
        let limited_count = count.min(MAX_LOOKAHEAD_TOKENS);
        self.tokens
            .lookahead_tokens(limited_count)
            .into_iter()
            .map(|spanned| &spanned.value)
            .collect()
    }

    /// Check if current sequence matches expected pattern
    pub fn matches_sequence(&self, expected: &[Token]) -> bool {
        let tokens = self.lookahead(expected.len());
        if tokens.len() < expected.len() {
            return false;
        }

        tokens
            .iter()
            .zip(expected.iter())
            .all(|(actual, expected)| {
                std::mem::discriminant(*actual) == std::mem::discriminant(expected)
            })
    }

    // === BACKTRACKING SUPPORT ===

    /// Save current parser state
    pub fn save_checkpoint(&self) -> ParserCheckpoint {
        ParserCheckpoint {
            position: self.tokens.save_position(),
            context_stack: self.context_stack.clone(),
            start_span: self.tokens.current_span(),
        }
    }

    /// Restore parser state from checkpoint
    pub fn restore_checkpoint(&mut self, checkpoint: ParserCheckpoint) {
        log_debug!("Restoring parser checkpoint",
            "position" => checkpoint.position,
            "context" => checkpoint.context_stack.join(" -> ")
        );

        self.tokens.restore_position(checkpoint.position);
        self.context_stack = checkpoint.context_stack;
    }

    /// Try parsing with automatic backtracking on failure
    pub fn try_parse<T, F>(&mut self, parse_fn: F) -> Option<T>
    where
        F: FnOnce(&mut Self) -> Result<T, String>,
    {
        let checkpoint = self.save_checkpoint();
        match parse_fn(self) {
            Ok(result) => {
                log_debug!("Backtracking parse succeeded");
                Some(result)
            }
            Err(error) => {
                log_debug!("Backtracking parse failed, restoring checkpoint", "error" => error);
                self.restore_checkpoint(checkpoint);
                None
            }
        }
    }

    // === CONTEXT TRACKING ===

    /// Push a parsing context for better error messages - WITH BOUNDS CHECK
    pub fn push_context(&mut self, context: &str) {
        if self.context_stack.len() >= MAX_CONTEXT_STACK_DEPTH {
            log_warning!("Context stack depth limit reached, dropping oldest context");
            self.context_stack.remove(0);
        }

        log_debug!("Entering parsing context", "context" => context);
        self.context_stack.push(context.to_string());
    }

    /// Pop the current parsing context
    pub fn pop_context(&mut self) {
        if let Some(context) = self.context_stack.pop() {
            log_debug!("Exiting parsing context", "context" => context);
        }
    }

    /// Get current parsing context
    pub fn current_context(&self) -> String {
        self.context_stack.join(" -> ")
    }

    // === ENHANCED ERROR HANDLING ===

    /// Expect token with enhanced error reporting
    pub fn expect_token_enhanced(&mut self, expected: Token) -> Result<Span, SyntaxError> {
        match self.tokens.expect_token(expected) {
            Ok(spanned_token) => Ok(spanned_token.span),
            Err(TokenStreamError::UnexpectedToken {
                expected,
                found,
                span,
            }) => Err(SyntaxError::unexpected_token(&expected, &found, span)),
            Err(TokenStreamError::UnexpectedEndOfStream { expected }) => {
                Err(SyntaxError::unexpected_end_of_input(&expected))
            }
            Err(TokenStreamError::SpanError {
                message,
                position: _,
            }) => Err(SyntaxError::parse_error(&message, self.current_span())),
        }
    }

    /// Skip to next recoverable position with span tracking - WITH LIMITS
    pub fn skip_to_recovery_point(&mut self, recovery_tokens: &[Token]) -> Option<Span> {
        let start_span = self.current_span();
        let start_pos = self.tokens.position();
        let mut tokens_scanned = 0;

        log_debug!("Searching for recovery point",
            "start_position" => start_pos,
            "recovery_tokens" => recovery_tokens.len()
        );

        while !self.tokens.is_at_end() && tokens_scanned < MAX_RECOVERY_SCAN_TOKENS {
            if let Some(current) = self.current_token() {
                if recovery_tokens.iter().any(|recovery_token| {
                    std::mem::discriminant(current) == std::mem::discriminant(recovery_token)
                }) {
                    let end_span = self.current_span();
                    let recovered_span = start_span.merge(end_span);

                    log_info!("Found recovery point",
                        "token" => current.as_esp_string(),
                        "skipped_tokens" => tokens_scanned
                    );

                    return Some(recovered_span);
                }
            }
            self.advance();
            tokens_scanned += 1;
        }

        if tokens_scanned >= MAX_RECOVERY_SCAN_TOKENS {
            log_warning!("Recovery scan limit reached without finding recovery point",
                "tokens_scanned" => tokens_scanned
            );
        } else {
            log_warning!("No recovery point found, reached end of stream",
                "tokens_scanned" => tokens_scanned
            );
        }

        // Return span covering scanned region
        Some(self.tokens.span_range(start_pos, self.tokens.position()))
    }

    // === SPAN UTILITIES ===

    /// Get span from start position to current position
    pub fn span_from_position(&self, start_position: usize) -> Span {
        self.tokens.span_from(start_position)
    }

    /// Get span covering a range of operations
    pub fn span_from_checkpoint(&self, checkpoint: &ParserCheckpoint) -> Span {
        if let Some(start_span) = checkpoint.start_span {
            if let Some(current_span) = self.tokens.current_span() {
                start_span.merge(current_span)
            } else {
                start_span
            }
        } else {
            self.current_span()
        }
    }

    // === DIAGNOSTIC METHODS ===

    /// Get comprehensive diagnostic information
    pub fn diagnostic_info(&self) -> String {
        format!(
            "Parser State:\n{}\nContext: {}\nError History: {}\nParse Depth: {}/{}",
            self.tokens.diagnostic(),
            self.current_context(),
            self.error_history.len(),
            self.parse_depth,
            MAX_PARSE_DEPTH
        )
    }

    /// Validate parser state consistency - UPDATED WITH CONSTANTS
    pub fn validate_state(&self) -> Result<(), String> {
        // Validate token stream integrity
        if let Err(e) = crate::tokens::token_stream::validation::validate_token_stream(&self.tokens)
        {
            return Err(format!("Token stream validation failed: {}", e));
        }

        // Validate context stack consistency - NOW USING CONSTANT
        if self.context_stack.len() > MAX_CONTEXT_STACK_DEPTH {
            return Err(format!(
                "Context stack depth {} exceeds maximum {}",
                self.context_stack.len(),
                MAX_CONTEXT_STACK_DEPTH
            ));
        }

        // Validate parse depth - NOW USING CONSTANT
        if self.parse_depth > MAX_PARSE_DEPTH {
            return Err(format!(
                "Parse depth {} exceeds maximum {}",
                self.parse_depth, MAX_PARSE_DEPTH
            ));
        }

        Ok(())
    }
}

/// Create parser with global logging integration
pub fn create_parser(tokens: TokenStream) -> EspParser {
    EspParser::new(tokens)
}

/// Parse TokenStream directly with global logging and enhanced error reporting
pub fn parse_token_stream_enhanced(tokens: TokenStream) -> SyntaxResult<EspFile> {
    log_info!("Starting enhanced token stream parsing", "tokens" => tokens.len());

    let mut parser = EspParser::new(tokens);

    // Validate parser state before parsing
    if let Err(validation_error) = parser.validate_state() {
        let error = SyntaxError::internal_parser_error(&format!(
            "Parser state validation failed: {}",
            validation_error
        ));
        log_error!(error.error_code(), "Parser validation failed", "error" => validation_error);
        return Err(error);
    }

    parser.parse_esp_file()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tokens::{Token, TokenStreamBuilder};
    use common::utils::{Position, Span};

    fn create_empty_token_stream() -> TokenStream {
        TokenStreamBuilder::new().build()
    }

    fn create_token_stream_with_eof() -> TokenStream {
        TokenStreamBuilder::new()
            .push_token_with_span(Token::Eof, Span::new(Position::start(), Position::start()))
            .build()
    }

    #[test]
    fn test_parser_creation() {
        let tokens = create_empty_token_stream();
        let parser = create_parser(tokens);

        // Should not panic
        drop(parser);
    }

    #[test]
    fn test_context_management() {
        let tokens = create_empty_token_stream();
        let mut parser = create_parser(tokens);

        assert_eq!(parser.current_context(), "");

        parser.push_context("test");
        assert_eq!(parser.current_context(), "test");

        parser.push_context("nested");
        assert_eq!(parser.current_context(), "test -> nested");

        parser.pop_context();
        assert_eq!(parser.current_context(), "test");

        parser.pop_context();
        assert_eq!(parser.current_context(), "");
    }

    #[test]
    fn test_error_recording() {
        let tokens = create_empty_token_stream();
        let mut parser = create_parser(tokens);

        let error = SyntaxError::empty_token_stream();
        parser.record_error(error.clone());

        let history = parser.error_history();
        assert_eq!(history.len(), 1);
    }

    #[test]
    fn test_checkpoint_system() {
        let tokens = create_empty_token_stream();
        let mut parser = create_parser(tokens);

        parser.push_context("test_context");
        let checkpoint = parser.save_checkpoint();

        parser.push_context("modified_context");
        assert!(parser.current_context().contains("modified_context"));

        parser.restore_checkpoint(checkpoint);
        assert_eq!(parser.current_context(), "test_context");
    }

    #[test]
    fn test_parser_validation() {
        let tokens = create_empty_token_stream();
        let parser = create_parser(tokens);

        let result = parser.validate_state();
        assert!(result.is_ok());
    }

    #[test]
    fn test_context_depth_limiting() {
        let tokens = create_empty_token_stream();
        let mut parser = create_parser(tokens);

        // Push more contexts than the limit
        for i in 0..(MAX_CONTEXT_STACK_DEPTH + 5) {
            parser.push_context(&format!("context_{}", i));
        }

        // Should not exceed the maximum depth
        assert!(parser.context_stack.len() <= MAX_CONTEXT_STACK_DEPTH);
    }

    #[test]
    fn test_error_history_limiting() {
        let tokens = create_empty_token_stream();
        let mut parser = create_parser(tokens);

        // Add more errors than the history limit
        for i in 0..(MAX_ERROR_HISTORY + 5) {
            let error = SyntaxError::parse_error(&format!("error_{}", i), parser.current_span());
            parser.record_error(error);
        }

        // Should not exceed the maximum history size
        assert!(parser.error_history.len() <= MAX_ERROR_HISTORY);
    }

    #[test]
    fn test_lookahead_limiting() {
        let tokens = create_token_stream_with_eof();
        let parser = create_parser(tokens);

        // Request more tokens than the limit
        let lookahead_tokens = parser.lookahead(MAX_LOOKAHEAD_TOKENS + 10);

        // Should not exceed the maximum lookahead
        assert!(lookahead_tokens.len() <= MAX_LOOKAHEAD_TOKENS);
    }

    #[test]
    fn test_empty_stream_parsing() {
        let tokens = create_empty_token_stream();
        let result = parse_token_stream_enhanced(tokens);

        // Should fail with empty token stream error
        assert!(result.is_err());
        if let Err(error) = result {
            assert_eq!(error.error_code().as_str(), "E041"); // EMPTY_TOKEN_STREAM
        }
    }

    #[test]
    fn test_error_context_creation() {
        let tokens = create_empty_token_stream();
        let parser = create_parser(tokens);

        let error = SyntaxError::empty_token_stream();
        let contextual = parser.create_contextual_error(error);

        // Should create enhanced error with context
        let formatted = contextual.format_full_error();
        assert!(formatted.contains("Help:"));
    }

    #[test]
    fn test_diagnostic_info() {
        let tokens = create_empty_token_stream();
        let parser = create_parser(tokens);

        let diagnostic = parser.diagnostic_info();
        assert!(diagnostic.contains("Parser State:"));
        assert!(diagnostic.contains("Context:"));
        assert!(diagnostic.contains("Error History:"));
        assert!(diagnostic.contains("Parse Depth:"));
    }
}
