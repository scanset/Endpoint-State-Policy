//! Span-accurate token stream management for ESP parser
//!
//! FIXED: Complete implementation that maintains accurate source locations
//! across filtered token streams for precise error reporting.

use crate::tokens::token::*;
use common::utils::{Position, SourceMap, Span, Spanned};

/// A token with span information
pub type SpannedToken = Spanned<Token>;

/// Span-accurate token stream that maintains precise source locations
/// even when filtering out whitespace and comments for parsing.
#[derive(Debug, Clone)]
pub struct TokenStream {
    /// All tokens (including whitespace and comments) with original spans
    all_tokens: Vec<SpannedToken>,
    /// Indices into all_tokens for significant (non-whitespace) tokens
    significant_indices: Vec<usize>,
    /// Current position in significant_indices array
    position: usize,
    /// Source map for error reporting and span validation
    source_map: Option<SourceMap>,
}

impl TokenStream {
    /// Create a new token stream with automatic filtering
    pub fn new(tokens: Vec<SpannedToken>) -> Self {
        let mut stream = Self {
            all_tokens: tokens,
            significant_indices: Vec::new(),
            position: 0,
            source_map: None,
        };
        stream.rebuild_significant_indices();
        stream
    }

    /// Create stream with source map for enhanced error reporting
    pub fn with_source_map(tokens: Vec<SpannedToken>, source_map: SourceMap) -> Self {
        let mut stream = Self {
            all_tokens: tokens,
            significant_indices: Vec::new(),
            position: 0,
            source_map: Some(source_map),
        };
        stream.rebuild_significant_indices();
        stream
    }

    /// Create stream including all tokens (no filtering)
    pub fn with_all_tokens(tokens: Vec<SpannedToken>) -> Self {
        let significant_indices = (0..tokens.len()).collect();
        Self {
            all_tokens: tokens,
            significant_indices,
            position: 0,
            source_map: None,
        }
    }

    fn rebuild_significant_indices(&mut self) {
        self.significant_indices.clear();
        let mut eof_found = false;

        for (i, spanned_token) in self.all_tokens.iter().enumerate() {
            if matches!(spanned_token.value, Token::Eof) {
                eof_found = true;
                common::log_debug!("Found EOF token at original index",
                    "original_index" => i
                );
            }

            if spanned_token.value.is_significant() {
                if matches!(spanned_token.value, Token::Eof) {
                    common::log_debug!("EOF token added to significant indices",
                        "position" => self.significant_indices.len()
                    );
                }
                self.significant_indices.push(i);
            }
        }

        common::log_debug!("Token processing summary",
            "total_tokens" => self.all_tokens.len(),
            "significant_tokens" => self.significant_indices.len(),
            "eof_found" => eof_found
        );

        self.position = 0;
    }

    // === CORE NAVIGATION WITH ACCURATE SPANS ===

    /// Get the current significant token with accurate span
    pub fn current(&self) -> Option<&SpannedToken> {
        self.significant_indices
            .get(self.position)
            .and_then(|&original_index| self.all_tokens.get(original_index))
    }

    /// Get the current token value (without span)
    pub fn current_token(&self) -> Option<&Token> {
        self.current().map(|spanned| &spanned.value)
    }

    /// Get the accurate span of the current token
    pub fn current_span(&self) -> Option<Span> {
        self.current().map(|spanned| spanned.span)
    }

    /// Peek at the next significant token without advancing
    pub fn peek(&self) -> Option<&SpannedToken> {
        self.peek_ahead(1)
    }

    /// Peek ahead by n positions in significant tokens
    pub fn peek_ahead(&self, n: usize) -> Option<&SpannedToken> {
        self.significant_indices
            .get(self.position + n)
            .and_then(|&original_index| self.all_tokens.get(original_index))
    }

    /// Advance to the next significant token
    pub fn advance(&mut self) -> Option<&SpannedToken> {
        if self.position < self.significant_indices.len() {
            self.position += 1;
        }
        self.current()
    }

    /// Check if we're at the end of significant tokens
    pub fn is_at_end(&self) -> bool {
        self.position >= self.significant_indices.len()
    }

    /// Get the number of significant tokens
    pub fn len(&self) -> usize {
        self.significant_indices.len()
    }

    /// Check if the stream has no significant tokens
    pub fn is_empty(&self) -> bool {
        self.significant_indices.is_empty()
    }

    // === SPAN ACCURACY METHODS ===

    /// Get span covering from start token to current position
    pub fn span_from(&self, start_position: usize) -> Span {
        if let (Some(start_span), Some(current_span)) =
            (self.span_at_position(start_position), self.current_span())
        {
            start_span.merge(current_span)
        } else {
            self.current_span().unwrap_or_else(Span::dummy)
        }
    }

    /// Get span at a specific position in significant tokens
    pub fn span_at_position(&self, position: usize) -> Option<Span> {
        self.significant_indices
            .get(position)
            .and_then(|&original_index| self.all_tokens.get(original_index))
            .map(|spanned| spanned.span)
    }

    /// Get span covering a range of significant token positions
    pub fn span_range(&self, start_pos: usize, end_pos: usize) -> Span {
        let start_span = self.span_at_position(start_pos);
        let end_span = self.span_at_position(end_pos);

        match (start_span, end_span) {
            (Some(start), Some(end)) => start.merge(end),
            (Some(start), None) => start,
            (None, Some(end)) => end,
            (None, None) => Span::dummy(),
        }
    }

    /// Get all tokens between two significant positions (including whitespace)
    pub fn tokens_between(&self, start_pos: usize, end_pos: usize) -> &[SpannedToken] {
        if let (Some(&start_idx), Some(&end_idx)) = (
            self.significant_indices.get(start_pos),
            self.significant_indices.get(end_pos),
        ) {
            self.all_tokens.get(start_idx..=end_idx).unwrap_or(&[])
        } else {
            &[]
        }
    }

    /// Get the original index in all_tokens for current significant position
    pub fn current_original_index(&self) -> Option<usize> {
        self.significant_indices.get(self.position).copied()
    }

    // === ERROR REPORTING WITH ACCURATE SPANS ===

    /// Format an error with accurate source context
    pub fn format_error(&self, span: Span, message: &str) -> String {
        if let Some(ref source_map) = self.source_map {
            source_map.format_error(&span, message)
        } else {
            format!("Error at {}: {}", span, message)
        }
    }

    /// Get source text for a span (if source map available)
    pub fn source_text(&self, span: &Span) -> Option<&str> {
        self.source_map.as_ref().map(|sm| sm.span_text(span))
    }

    /// Get line content for error context
    pub fn line_at_span(&self, span: Span) -> Option<&str> {
        self.source_map
            .as_ref()
            .and_then(|sm| sm.get_line(span.start().line))
    }

    // === PARSER INTEGRATION METHODS ===

    /// Check if current token matches expected with accurate span reporting
    pub fn check_token(&self, expected: &Token) -> bool {
        self.current_token()
            .map(|token| std::mem::discriminant(token) == std::mem::discriminant(expected))
            .unwrap_or(false)
    }

    /// Consume the next token if it matches predicate, preserving span accuracy
    pub fn consume_if<F>(&mut self, predicate: F) -> Option<SpannedToken>
    where
        F: FnOnce(&Token) -> bool,
    {
        if let Some(token) = self.current_token() {
            if predicate(token) {
                let result = self.current().cloned();
                self.advance();
                return result;
            }
        }
        None
    }

    /// Advance if current token matches expected
    pub fn advance_if_matches(&mut self, expected: &Token) -> bool {
        if self.check_token(expected) {
            self.advance();
            true
        } else {
            false
        }
    }

    /// Expect a specific token with accurate error span reporting
    pub fn expect_token(&mut self, expected: Token) -> Result<SpannedToken, TokenStreamError> {
        if let Some(current) = self.current() {
            if std::mem::discriminant(&current.value) == std::mem::discriminant(&expected) {
                let result = current.clone();
                self.advance();
                Ok(result)
            } else {
                Err(TokenStreamError::UnexpectedToken {
                    expected: expected.as_esp_string(),
                    found: current.value.as_esp_string(),
                    span: current.span,
                })
            }
        } else {
            Err(TokenStreamError::UnexpectedEndOfStream {
                expected: expected.as_esp_string(),
            })
        }
    }

    // === ADVANCED NAVIGATION ===

    /// Save current position as checkpoint for backtracking
    pub fn save_position(&self) -> usize {
        self.position
    }

    /// Restore position from checkpoint
    pub fn restore_position(&mut self, saved_position: usize) {
        self.position = saved_position.min(self.significant_indices.len());
    }

    /// Get lookahead tokens with accurate spans
    pub fn lookahead_tokens(&self, count: usize) -> Vec<&SpannedToken> {
        (0..count)
            .filter_map(|offset| self.peek_ahead(offset))
            .collect()
    }

    // === ITERATION WITH SPAN PRESERVATION ===

    /// Get an iterator over significant tokens with spans
    pub fn iter_significant(&self) -> impl Iterator<Item = &SpannedToken> {
        self.significant_indices
            .iter()
            .filter_map(|&i| self.all_tokens.get(i))
    }

    /// Get all tokens (including non-significant) with spans
    pub fn all_tokens(&self) -> &[SpannedToken] {
        &self.all_tokens
    }

    /// Get remaining significant tokens
    pub fn remaining_tokens(&self) -> impl Iterator<Item = &SpannedToken> {
        self.significant_indices
            .get(self.position..)
            .unwrap_or(&[])
            .iter()
            .filter_map(|&i| self.all_tokens.get(i))
    }

    // === DEBUGGING AND DIAGNOSTICS ===

    /// Get current position for debugging
    pub fn position(&self) -> usize {
        self.position
    }

    /// Get remaining token count
    pub fn remaining_count(&self) -> usize {
        self.significant_indices.len().saturating_sub(self.position)
    }

    /// Comprehensive diagnostic information with span details
    pub fn diagnostic(&self) -> String {
        let current_info = if let Some(current) = self.current() {
            format!("'{}' at {}", current.value.as_esp_string(), current.span)
        } else {
            "<EOF>".to_string()
        };

        let span_info = if let Some(span) = self.current_span() {
            if let Some(text) = self.source_text(&span) {
                format!(" (\"{}\")", text.chars().take(20).collect::<String>())
            } else {
                String::new()
            }
        } else {
            String::new()
        };

        format!(
            "TokenStream(pos: {}/{}, current: {}{})",
            self.position,
            self.significant_indices.len(),
            current_info,
            span_info
        )
    }

    /// Get context around current position for error reporting
    pub fn context_snippet(&self, radius: usize) -> Vec<&SpannedToken> {
        let start = self.position.saturating_sub(radius);
        let end = (self.position + radius + 1).min(self.significant_indices.len());

        (start..end)
            .filter_map(|pos| {
                self.significant_indices
                    .get(pos)
                    .and_then(|&idx| self.all_tokens.get(idx))
            })
            .collect()
    }

    pub fn has_eof(&self) -> bool {
        if let Some(&last_idx) = self.significant_indices.last() {
            if let Some(token) = self.all_tokens.get(last_idx) {
                matches!(token.value, Token::Eof)
            } else {
                false
            }
        } else {
            false
        }
    }
}

/// Enhanced token stream errors with span accuracy
#[derive(Debug, Clone, PartialEq)]
pub enum TokenStreamError {
    /// Unexpected token found with accurate span
    UnexpectedToken {
        expected: String,
        found: String,
        span: Span,
    },
    /// Unexpected end of stream
    UnexpectedEndOfStream { expected: String },
    /// Span calculation error
    SpanError { message: String, position: usize },
}

impl std::fmt::Display for TokenStreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnexpectedToken {
                expected,
                found,
                span,
            } => {
                write!(f, "Expected '{}', found '{}' at {}", expected, found, span)
            }
            Self::UnexpectedEndOfStream { expected } => {
                write!(f, "Expected '{}', but reached end of input", expected)
            }
            Self::SpanError { message, position } => {
                write!(f, "Span error at position {}: {}", position, message)
            }
        }
    }
}

impl std::error::Error for TokenStreamError {}

/// Enhanced token stream builder with source tracking
#[derive(Debug)]
pub struct TokenStreamBuilder {
    tokens: Vec<SpannedToken>,
    current_position: Position,
}

impl TokenStreamBuilder {
    /// Create a new builder starting at beginning of file
    pub fn new() -> Self {
        Self {
            tokens: Vec::new(),
            current_position: Position::start(),
        }
    }

    /// Add a token with calculated span
    pub fn push_token(mut self, token: Token, text: &str) -> Self {
        let start = self.current_position;
        let end = start.advance_str(text);
        let span = Span::new(start, end);

        self.tokens.push(SpannedToken::new(token, span));
        self.current_position = end;
        self
    }

    /// Add a token with explicit span
    pub fn push_token_with_span(mut self, token: Token, span: Span) -> Self {
        self.tokens.push(SpannedToken::new(token, span));
        self.current_position = span.end;
        self
    }

    /// Add multiple tokens from text parsing
    pub fn push_tokens_from_text(mut self, tokens_with_text: Vec<(Token, &str)>) -> Self {
        for (token, text) in tokens_with_text {
            self = self.push_token(token, text);
        }
        self
    }

    /// Build the token stream
    pub fn build(self) -> TokenStream {
        TokenStream::new(self.tokens)
    }

    /// Build with source map for enhanced error reporting
    pub fn build_with_source(self, source: String) -> TokenStream {
        let source_map = SourceMap::new(source);
        TokenStream::with_source_map(self.tokens, source_map)
    }
}

impl Default for TokenStreamBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Additional utility methods for SpannedToken with span accuracy
pub trait SpannedTokenExt {
    /// Get the token value
    fn token(&self) -> &Token;
    /// Get the accurate span
    fn span(&self) -> Span;
    /// Check if this token's span contains a position
    fn contains_position(&self, pos: Position) -> bool;
    /// Get the length of this token in the source
    fn source_length(&self) -> usize;
}

impl SpannedTokenExt for SpannedToken {
    fn token(&self) -> &Token {
        &self.value
    }

    fn span(&self) -> Span {
        self.span
    }

    fn contains_position(&self, pos: Position) -> bool {
        self.span.contains(pos)
    }

    fn source_length(&self) -> usize {
        self.span.len()
    }
}

/// Validation functions for span accuracy
pub mod validation {
    use super::*;

    /// Validate that spans are monotonically increasing
    pub fn validate_span_order(tokens: &[SpannedToken]) -> Result<(), String> {
        for window in tokens.windows(2) {
            let Some(current_token) = window.first() else {
                continue;
            };
            let Some(next_token) = window.get(1) else {
                continue;
            };
            let current = current_token.span;
            let next = next_token.span;

            if current.end.offset > next.start.offset {
                return Err(format!(
                    "Span order violation: token ending at {} starts after next token at {}",
                    current.end.offset, next.start.offset
                ));
            }
        }
        Ok(())
    }

    /// Validate that filtered tokens maintain accurate spans
    pub fn validate_filtered_spans(stream: &TokenStream) -> Result<(), String> {
        for (filtered_pos, &original_idx) in stream.significant_indices.iter().enumerate() {
            if let Some(token) = stream.all_tokens.get(original_idx) {
                // Verify span is accessible through filtered interface
                if let Some(filtered_span) = stream.span_at_position(filtered_pos) {
                    if filtered_span != token.span {
                        return Err(format!(
                            "Span mismatch at filtered position {}: expected {:?}, got {:?}",
                            filtered_pos, token.span, filtered_span
                        ));
                    }
                } else {
                    return Err(format!(
                        "Cannot access span at filtered position {}",
                        filtered_pos
                    ));
                }
            } else {
                return Err(format!(
                    "Invalid original index {} in significant_indices",
                    original_idx
                ));
            }
        }
        Ok(())
    }

    /// Validate token stream integrity
    pub fn validate_token_stream(stream: &TokenStream) -> Result<(), String> {
        validate_span_order(&stream.all_tokens)?;
        validate_filtered_spans(stream)?;
        Ok(())
    }
}
