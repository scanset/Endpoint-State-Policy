//! Core lexical analyzer implementation with FileProcessingResult integration
//!
//! Clean implementation focused on systematic tokenization with file-aware
//! processing and proper integration with the global logging system.

use crate::file_processor::FileProcessingResult;
use crate::grammar::keywords::{classify_word_type, Keyword, WordType};
use crate::tokens::{classify_operator_word, StringLiteral, Token, TokenStream};
use common::config::constants::compile_time::lexical::*;
use common::config::runtime::LexicalPreferences;
use common::logging::codes;
use common::utils::{Position, Span, Spanned};
use common::{log_debug, log_error, log_success};

/// Lexical analysis errors with compile-time security boundaries
#[derive(Debug, Clone, thiserror::Error)]
pub enum LexerError {
    #[error("Invalid character: '{character}' at line {line}, column {column}")]
    InvalidCharacter {
        character: char,
        line: u32,
        column: u32,
    },

    #[error("Unterminated string literal")]
    UnterminatedString,

    #[error("Invalid number format: '{text}'")]
    InvalidNumber { text: String },

    #[error("Identifier too long: {length} characters (max {MAX_IDENTIFIER_LENGTH})")]
    IdentifierTooLong { length: usize },

    #[error("String too large: {size} bytes (max {MAX_STRING_SIZE})")]
    StringTooLarge { size: usize },

    #[error("Comment too long: {length} characters (max {MAX_COMMENT_LENGTH})")]
    CommentTooLong { length: usize },

    #[error("Too many tokens: {count} (max {MAX_TOKEN_COUNT})")]
    TooManyTokens { count: usize },

    #[error("String nesting too deep: {depth} (max {MAX_STRING_NESTING_DEPTH})")]
    StringNestingTooDeep { depth: u32 },
}

impl LexerError {
    pub fn error_code(&self) -> common::logging::Code {
        match self {
            LexerError::InvalidCharacter { .. } => codes::lexical::INVALID_CHARACTER,
            LexerError::UnterminatedString => codes::lexical::UNTERMINATED_STRING,
            LexerError::InvalidNumber { .. } => codes::lexical::INVALID_NUMBER,
            LexerError::IdentifierTooLong { .. } => codes::lexical::IDENTIFIER_TOO_LONG,
            LexerError::StringTooLarge { .. } => codes::lexical::STRING_TOO_LARGE,
            LexerError::CommentTooLong { .. } => codes::lexical::COMMENT_TOO_LONG,
            LexerError::TooManyTokens { .. } => codes::lexical::TOO_MANY_TOKENS,
            LexerError::StringNestingTooDeep { .. } => codes::lexical::STRING_NESTING_TOO_DEEP,
        }
    }
}

/// Essential lexical analysis metrics with runtime preferences
#[derive(Debug, Default, Clone)]
pub struct LexicalMetrics {
    pub total_tokens: usize,
    pub keyword_tokens: usize,
    pub identifier_tokens: usize,
    pub operator_tokens: usize,
    pub invalid_chars: usize,
    pub max_string_length: usize,
    pub comment_count: usize,
    pub max_comment_length: usize,
    pub string_nesting_depth: u32,

    // Runtime preference-controlled metrics
    pub whitespace_tokens: usize,
    pub operator_usage_patterns: std::collections::HashMap<String, usize>,
}

impl LexicalMetrics {
    pub(crate) fn record_token(&mut self, token: &Token, preferences: &LexicalPreferences) {
        self.total_tokens += 1;

        match token {
            Token::Keyword(_) => self.keyword_tokens += 1,
            Token::Identifier(_) => self.identifier_tokens += 1,
            Token::Equals
            | Token::NotEquals
            | Token::GreaterThan
            | Token::LessThan
            | Token::GreaterThanOrEqual
            | Token::LessThanOrEqual
            | Token::Plus
            | Token::Minus
            | Token::Multiply
            | Token::Divide
            | Token::Modulus
            | Token::CaseInsensitiveEquals
            | Token::CaseInsensitiveNotEquals
            | Token::Contains
            | Token::StartsWith
            | Token::EndsWith
            | Token::NotContains
            | Token::NotStartsWith
            | Token::NotEndsWith
            | Token::PatternMatch
            | Token::Matches
            | Token::SubsetOf
            | Token::SupersetOf => {
                self.operator_tokens += 1;

                // Track operator patterns if enabled
                if preferences.track_operator_patterns {
                    let op_name = format!("{:?}", token);
                    *self.operator_usage_patterns.entry(op_name).or_insert(0) += 1;
                }
            }
            Token::Space | Token::Tab | Token::Newline => {
                if preferences.include_all_tokens_in_counts {
                    self.whitespace_tokens += 1;
                }
            }
            Token::Comment(_) => self.comment_count += 1,
            _ => {} // Literals, etc.
        }
    }

    pub(crate) fn record_string_length(&mut self, length: usize, preferences: &LexicalPreferences) {
        self.max_string_length = self.max_string_length.max(length);

        if preferences.log_string_statistics {
            log_debug!("String literal processed",
                "length" => length,
                "max_so_far" => self.max_string_length
            );
        }
    }

    pub(crate) fn record_comment_length(&mut self, length: usize) {
        self.max_comment_length = self.max_comment_length.max(length);
    }

    pub(crate) fn record_invalid_char(&mut self) {
        self.invalid_chars += 1;
    }

    pub(crate) fn record_string_nesting(&mut self, depth: u32) {
        self.string_nesting_depth = self.string_nesting_depth.max(depth);
    }
}

/// Core lexical analyzer with global logging integration and compile-time security boundaries
pub struct LexicalAnalyzer {
    metrics: LexicalMetrics,
    preferences: LexicalPreferences,
}

impl LexicalAnalyzer {
    pub fn new() -> Self {
        Self {
            metrics: LexicalMetrics::default(),
            preferences: LexicalPreferences::default(),
        }
    }

    pub fn with_preferences(preferences: LexicalPreferences) -> Self {
        Self {
            metrics: LexicalMetrics::default(),
            preferences,
        }
    }

    /// Tokenize file processing result with comprehensive file-aware logging and security boundaries
    pub fn tokenize_file_result(
        &mut self,
        file_result: FileProcessingResult,
    ) -> Result<TokenStream, LexerError> {
        // Reset metrics for this tokenization
        self.metrics = LexicalMetrics::default();

        let source = &file_result.source;
        let file_path = file_result.metadata.path.display().to_string();

        log_debug!("Starting lexical analysis",
            "file" => file_path.as_str(),
            "char_count" => file_result.char_count(),
            "line_count" => file_result.metadata.line_count,
            "file_size_bytes" => file_result.metadata.size,
            "max_tokens_allowed" => MAX_TOKEN_COUNT,
            "max_string_size_allowed" => MAX_STRING_SIZE
        );

        let mut tokens = Vec::new();
        let mut chars = source.char_indices().peekable();
        let mut current_pos = Position::start();
        let mut token_count = 0;

        // Systematic tokenization with security boundaries
        while let Some((byte_offset, ch)) = chars.next() {
            current_pos = Position::new(byte_offset, current_pos.line, current_pos.column);

            // SECURITY: Check token count limit to prevent DoS
            if token_count >= MAX_TOKEN_COUNT {
                let error = LexerError::TooManyTokens { count: token_count };
                let span = Span::new(current_pos, current_pos);
                log_error!(error.error_code(), "Token limit exceeded",
                    span = span,
                    "token_count" => token_count,
                    "limit" => MAX_TOKEN_COUNT,
                    "file" => file_path.as_str()
                );
                return Err(error);
            }

            let result = match ch {
                // Whitespace
                ' ' => {
                    let token = self.create_token(Token::Space, current_pos, 1);
                    self.metrics.record_token(&token.value, &self.preferences);
                    tokens.push(token);
                    current_pos = current_pos.advance(' ');
                    token_count += 1;
                    Ok(())
                }
                '\t' => {
                    let token = self.create_token(Token::Tab, current_pos, 1);
                    self.metrics.record_token(&token.value, &self.preferences);
                    tokens.push(token);
                    current_pos = current_pos.advance('\t');
                    token_count += 1;
                    Ok(())
                }
                '\n' => {
                    let token = self.create_token(Token::Newline, current_pos, 1);
                    self.metrics.record_token(&token.value, &self.preferences);
                    tokens.push(token);
                    current_pos = current_pos.advance('\n');
                    token_count += 1;
                    Ok(())
                }
                '\r' => {
                    // Handle CRLF
                    if chars.peek().map(|(_, c)| *c) == Some('\n') {
                        chars.next();
                        let token = self.create_token(Token::Newline, current_pos, 2);
                        self.metrics.record_token(&token.value, &self.preferences);
                        tokens.push(token);
                        current_pos = current_pos.advance_bytes(2);
                        current_pos = Position::new(current_pos.offset, current_pos.line + 1, 1);
                    } else {
                        let token = self.create_token(Token::Newline, current_pos, 1);
                        self.metrics.record_token(&token.value, &self.preferences);
                        tokens.push(token);
                        current_pos =
                            Position::new(current_pos.offset + 1, current_pos.line + 1, 1);
                    }
                    token_count += 1;
                    Ok(())
                }

                // Comments
                '#' => match self.parse_comment(&mut chars) {
                    Ok((token_val, len)) => {
                        let token = self.create_token(token_val, current_pos, len);
                        self.metrics.record_token(&token.value, &self.preferences);
                        tokens.push(token);
                        current_pos = current_pos.advance_bytes(len);
                        token_count += 1;
                        Ok(())
                    }
                    Err(e) => Err(e),
                },

                // String literals
                '`' => match self.parse_string_literal(byte_offset, source, &mut chars, 0) {
                    Ok((token_val, len)) => {
                        let token = self.create_token(token_val, current_pos, len);
                        self.metrics.record_token(&token.value, &self.preferences);
                        tokens.push(token);
                        current_pos = current_pos.advance_bytes(len);
                        token_count += 1;
                        Ok(())
                    }
                    Err(e) => Err(e),
                },

                // Raw strings and identifiers starting with 'r'
                'r' => {
                    if chars.peek().map(|(_, c)| *c) == Some('`') {
                        match self.parse_raw_string(byte_offset, source, &mut chars, 0) {
                            Ok((token_val, len)) => {
                                let token = self.create_token(token_val, current_pos, len);
                                self.metrics.record_token(&token.value, &self.preferences);
                                tokens.push(token);
                                current_pos = current_pos.advance_bytes(len);
                                token_count += 1;
                                Ok(())
                            }
                            Err(e) => Err(e),
                        }
                    } else {
                        match self.parse_identifier_or_operator(byte_offset, source, &mut chars) {
                            Ok((token_val, len)) => {
                                let token = self.create_token(token_val, current_pos, len);
                                self.metrics.record_token(&token.value, &self.preferences);
                                tokens.push(token);
                                current_pos = current_pos.advance_bytes(len);
                                token_count += 1;
                                Ok(())
                            }
                            Err(e) => Err(e),
                        }
                    }
                }

                // Punctuation
                '.' => {
                    let token = self.create_token(Token::Dot, current_pos, 1);
                    tokens.push(token);
                    current_pos = current_pos.advance('.');
                    token_count += 1;
                    Ok(())
                }

                // Numbers
                '0'..='9' => match self.parse_number(byte_offset, source, &mut chars) {
                    Ok((token_val, len)) => {
                        let token = self.create_token(token_val, current_pos, len);
                        self.metrics.record_token(&token.value, &self.preferences);
                        tokens.push(token);
                        current_pos = current_pos.advance_bytes(len);
                        token_count += 1;
                        Ok(())
                    }
                    Err(e) => Err(e),
                },

                // Operators and negative numbers
                '-' => {
                    if let Some((_, next_ch)) = chars.peek() {
                        if next_ch.is_ascii_digit() {
                            match self.parse_number(byte_offset, source, &mut chars) {
                                Ok((token_val, len)) => {
                                    let token = self.create_token(token_val, current_pos, len);
                                    self.metrics.record_token(&token.value, &self.preferences);
                                    tokens.push(token);
                                    current_pos = current_pos.advance_bytes(len);
                                    token_count += 1;
                                    Ok(())
                                }
                                Err(e) => Err(e),
                            }
                        } else {
                            let token = self.create_token(Token::Minus, current_pos, 1);
                            self.metrics.record_token(&token.value, &self.preferences);
                            tokens.push(token);
                            current_pos = current_pos.advance('-');
                            token_count += 1;
                            Ok(())
                        }
                    } else {
                        let token = self.create_token(Token::Minus, current_pos, 1);
                        self.metrics.record_token(&token.value, &self.preferences);
                        tokens.push(token);
                        current_pos = current_pos.advance('-');
                        token_count += 1;
                        Ok(())
                    }
                }

                // Single character operators
                '+' => {
                    let token = self.create_token(Token::Plus, current_pos, 1);
                    self.metrics.record_token(&token.value, &self.preferences);
                    tokens.push(token);
                    current_pos = current_pos.advance('+');
                    token_count += 1;
                    Ok(())
                }
                '*' => {
                    let token = self.create_token(Token::Multiply, current_pos, 1);
                    self.metrics.record_token(&token.value, &self.preferences);
                    tokens.push(token);
                    current_pos = current_pos.advance('*');
                    token_count += 1;
                    Ok(())
                }
                '/' => {
                    let token = self.create_token(Token::Divide, current_pos, 1);
                    self.metrics.record_token(&token.value, &self.preferences);
                    tokens.push(token);
                    current_pos = current_pos.advance('/');
                    token_count += 1;
                    Ok(())
                }
                '%' => {
                    let token = self.create_token(Token::Modulus, current_pos, 1);
                    self.metrics.record_token(&token.value, &self.preferences);
                    tokens.push(token);
                    current_pos = current_pos.advance('%');
                    token_count += 1;
                    Ok(())
                }
                '=' => {
                    let token = self.create_token(Token::Equals, current_pos, 1);
                    self.metrics.record_token(&token.value, &self.preferences);
                    tokens.push(token);
                    current_pos = current_pos.advance('=');
                    token_count += 1;
                    Ok(())
                }

                // Multi-character operators
                '!' => {
                    if chars.peek().map(|(_, c)| *c) == Some('=') {
                        chars.next();
                        let token = self.create_token(Token::NotEquals, current_pos, 2);
                        self.metrics.record_token(&token.value, &self.preferences);
                        tokens.push(token);
                        current_pos = current_pos.advance_bytes(2);
                        token_count += 1;
                        Ok(())
                    } else {
                        self.metrics.record_invalid_char();
                        Err(LexerError::InvalidCharacter {
                            character: ch,
                            line: current_pos.line,
                            column: current_pos.column,
                        })
                    }
                }
                '>' => {
                    if chars.peek().map(|(_, c)| *c) == Some('=') {
                        chars.next();
                        let token = self.create_token(Token::GreaterThanOrEqual, current_pos, 2);
                        self.metrics.record_token(&token.value, &self.preferences);
                        tokens.push(token);
                        current_pos = current_pos.advance_bytes(2);
                    } else {
                        let token = self.create_token(Token::GreaterThan, current_pos, 1);
                        self.metrics.record_token(&token.value, &self.preferences);
                        tokens.push(token);
                        current_pos = current_pos.advance('>');
                    }
                    token_count += 1;
                    Ok(())
                }
                '<' => {
                    if chars.peek().map(|(_, c)| *c) == Some('=') {
                        chars.next();
                        let token = self.create_token(Token::LessThanOrEqual, current_pos, 2);
                        self.metrics.record_token(&token.value, &self.preferences);
                        tokens.push(token);
                        current_pos = current_pos.advance_bytes(2);
                    } else {
                        let token = self.create_token(Token::LessThan, current_pos, 1);
                        self.metrics.record_token(&token.value, &self.preferences);
                        tokens.push(token);
                        current_pos = current_pos.advance('<');
                    }
                    token_count += 1;
                    Ok(())
                }

                // Identifiers, keywords, and word operators
                'a'..='z' | 'A'..='Z' | '_' => {
                    match self.parse_identifier_or_operator(byte_offset, source, &mut chars) {
                        Ok((token_val, len)) => {
                            let token = self.create_token(token_val, current_pos, len);
                            self.metrics.record_token(&token.value, &self.preferences);
                            tokens.push(token);
                            current_pos = current_pos.advance_bytes(len);
                            token_count += 1;
                            Ok(())
                        }
                        Err(e) => Err(e),
                    }
                }

                // Invalid characters
                _ => {
                    self.metrics.record_invalid_char();
                    Err(LexerError::InvalidCharacter {
                        character: ch,
                        line: current_pos.line,
                        column: current_pos.column,
                    })
                }
            };

            if let Err(error) = result {
                let span = Span::new(current_pos, current_pos);
                let error_message = if self.preferences.include_position_in_errors {
                    format!(
                        "Lexical analysis failed at line {}, column {}",
                        current_pos.line, current_pos.column
                    )
                } else {
                    "Lexical analysis failed".to_string()
                };

                log_error!(error.error_code(), &error_message,
                    span = span,
                    "character" => ch,
                    "line" => current_pos.line,
                    "column" => current_pos.column,
                    "file" => file_path.as_str(),
                    "tokens_processed" => token_count
                );
                return Err(error);
            }
        }

        // Add EOF token
        let eof_token = self.create_token(Token::Eof, current_pos, 0);
        tokens.push(eof_token);

        let token_stream = TokenStream::new(tokens);

        // Log successful completion with file-aware metrics and security info
        let processing_rate = if file_result.processing_duration.as_secs_f64() > 0.0 {
            file_result.char_count() as f64
                / (file_result.processing_duration.as_secs_f64() * 1000.0)
        } else {
            0.0
        };

        log_success!(codes::success::TOKENIZATION_COMPLETE,
            "Lexical analysis completed successfully",
            "file" => file_path.as_str(),
            "token_count" => token_stream.len(),
            "keywords" => self.metrics.keyword_tokens,
            "identifiers" => self.metrics.identifier_tokens,
            "operators" => self.metrics.operator_tokens,
            "comments" => self.metrics.comment_count,
            "file_size_bytes" => file_result.metadata.size,
            "file_lines" => file_result.metadata.line_count,
            "char_count" => file_result.char_count(),
            "chars_per_ms" => format!("{:.2}", processing_rate),
            "invalid_chars" => self.metrics.invalid_chars,
            "max_string_length" => self.metrics.max_string_length,
            "max_comment_length" => self.metrics.max_comment_length,
            "security_limits_applied" => format!("tokens:{}, strings:{}, identifiers:{}",
                MAX_TOKEN_COUNT, MAX_STRING_SIZE, MAX_IDENTIFIER_LENGTH)
        );

        Ok(token_stream)
    }

    /// Get current metrics
    pub fn metrics(&self) -> &LexicalMetrics {
        &self.metrics
    }

    /// Get current preferences
    pub fn preferences(&self) -> &LexicalPreferences {
        &self.preferences
    }

    /// Update preferences (runtime configurable)
    pub fn set_preferences(&mut self, preferences: LexicalPreferences) {
        self.preferences = preferences;
    }

    // ========================================================================
    // Private parsing methods with security boundaries
    // ========================================================================

    fn create_token(&self, token: Token, start_pos: Position, length: usize) -> Spanned<Token> {
        let end_pos = Position::new(
            start_pos.offset + length,
            start_pos.line,
            start_pos.column + length as u32,
        );
        let span = Span::new(start_pos, end_pos);
        Spanned::new(token, span)
    }

    fn parse_identifier_or_operator(
        &mut self,
        start_offset: usize,
        source: &str,
        chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
    ) -> Result<(Token, usize), LexerError> {
        let mut word = String::new();
        let mut len = 0;

        if let Some(ch) = source.chars().nth(start_offset) {
            word.push(ch);
            len += 1;
        }

        while let Some((_, ch)) = chars.peek() {
            match ch {
                'a'..='z' | 'A'..='Z' | '0'..='9' | '_' => {
                    word.push(*ch);
                    chars.next();
                    len += 1;
                }
                _ => break,
            }
        }

        // SECURITY: Check identifier length against compile-time limit
        if word.len() > MAX_IDENTIFIER_LENGTH {
            return Err(LexerError::IdentifierTooLong { length: word.len() });
        }

        let token = self.classify_word(&word);
        Ok((token, len))
    }

    fn classify_word(&mut self, word: &str) -> Token {
        match classify_word_type(word) {
            WordType::Keyword => Token::Keyword(Keyword::parse(word).unwrap()),
            WordType::SymbolOperator => classify_operator_word(word).unwrap(),
            WordType::DataTypeIdentifier
            | WordType::ContextSensitiveIdentifier
            | WordType::RegularIdentifier => match word {
                "true" => Token::Boolean(true),
                "false" => Token::Boolean(false),
                _ => Token::Identifier(word.to_string()),
            },
        }
    }

    fn parse_comment(
        &mut self,
        chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
    ) -> Result<(Token, usize), LexerError> {
        let mut content = String::new();
        let mut len = 1; // for the '#'

        while let Some((_, ch)) = chars.peek() {
            if *ch == '\n' || *ch == '\r' {
                break;
            }
            let (_, ch) = chars.next().unwrap();
            content.push(ch);
            len += ch.len_utf8();

            // SECURITY: Check comment length against compile-time limit
            if content.len() > MAX_COMMENT_LENGTH {
                return Err(LexerError::CommentTooLong {
                    length: content.len(),
                });
            }
        }

        self.metrics.record_comment_length(content.len());
        Ok((Token::Comment(content), len))
    }

    fn parse_string_literal(
        &mut self,
        start_offset: usize,
        source: &str,
        chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
        nesting_depth: u32,
    ) -> Result<(Token, usize), LexerError> {
        // SECURITY: Check nesting depth to prevent stack overflow
        if nesting_depth > MAX_STRING_NESTING_DEPTH {
            return Err(LexerError::StringNestingTooDeep {
                depth: nesting_depth,
            });
        }

        self.metrics.record_string_nesting(nesting_depth);

        // Check for multiline string
        if start_offset + 2 < source.len() {
            let next_chars: String = source.chars().skip(start_offset).take(3).collect();
            if next_chars == "```" {
                return self.parse_multiline_string(chars, nesting_depth);
            }
        }

        let mut content = String::new();
        let mut len = 1; // opening backtick

        loop {
            if let Some((_, ch)) = chars.next() {
                len += 1;
                if ch == '`' {
                    if chars.peek().map(|(_, c)| *c) == Some('`') {
                        chars.next(); // consume second backtick
                        len += 1;
                        content.push('`'); // literal backtick
                    } else {
                        self.validate_string_size(&content)?;
                        self.metrics
                            .record_string_length(content.len(), &self.preferences);
                        let token = if content.is_empty() {
                            Token::StringLiteral(StringLiteral::Empty)
                        } else {
                            Token::StringLiteral(StringLiteral::Backtick(content))
                        };
                        return Ok((token, len));
                    }
                } else {
                    content.push(ch);

                    // SECURITY: Check string size during parsing to fail fast
                    if content.len() > MAX_STRING_SIZE {
                        return Err(LexerError::StringTooLarge {
                            size: content.len(),
                        });
                    }
                }
            } else {
                return Err(LexerError::UnterminatedString);
            }
        }
    }

    fn parse_raw_string(
        &mut self,
        start_offset: usize,
        source: &str,
        chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
        nesting_depth: u32,
    ) -> Result<(Token, usize), LexerError> {
        // SECURITY: Check nesting depth
        if nesting_depth > MAX_STRING_NESTING_DEPTH {
            return Err(LexerError::StringNestingTooDeep {
                depth: nesting_depth,
            });
        }

        if start_offset + 3 < source.len() {
            let next_chars: String = source.chars().skip(start_offset).take(4).collect();
            if next_chars == "r```" {
                return self.parse_raw_multiline_string(chars, nesting_depth);
            }
        }

        if let Some((_, ch)) = chars.next() {
            if ch != '`' {
                return Err(LexerError::UnterminatedString);
            }
        } else {
            return Err(LexerError::UnterminatedString);
        }

        let mut content = String::new();
        let mut len = 2; // 'r' + '`'

        loop {
            if let Some((_, ch)) = chars.next() {
                len += 1;
                if ch == '`' {
                    self.validate_string_size(&content)?;
                    self.metrics
                        .record_string_length(content.len(), &self.preferences);
                    let token = if content.is_empty() {
                        Token::StringLiteral(StringLiteral::Empty)
                    } else {
                        Token::StringLiteral(StringLiteral::Raw(content))
                    };
                    return Ok((token, len));
                } else {
                    content.push(ch);

                    // SECURITY: Check string size during parsing
                    if content.len() > MAX_STRING_SIZE {
                        return Err(LexerError::StringTooLarge {
                            size: content.len(),
                        });
                    }
                }
            } else {
                return Err(LexerError::UnterminatedString);
            }
        }
    }

    fn parse_multiline_string(
        &mut self,
        chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
        _nesting_depth: u32,
    ) -> Result<(Token, usize), LexerError> {
        chars.next(); // first `
        chars.next(); // second `
        chars.next(); // third `

        let mut content = String::new();
        let mut len = 3;
        let mut backtick_count = 0;

        for (_, ch) in chars.by_ref() {
            len += 1;
            if ch == '`' {
                backtick_count += 1;
                if backtick_count == 3 {
                    self.validate_string_size(&content)?;
                    self.metrics
                        .record_string_length(content.len(), &self.preferences);
                    return Ok((Token::StringLiteral(StringLiteral::Multiline(content)), len));
                }
            } else {
                for _ in 0..backtick_count {
                    content.push('`');
                }
                backtick_count = 0;
                content.push(ch);

                // SECURITY: Check string size during parsing
                if content.len() > MAX_STRING_SIZE {
                    return Err(LexerError::StringTooLarge {
                        size: content.len(),
                    });
                }
            }
        }

        Err(LexerError::UnterminatedString)
    }

    fn parse_raw_multiline_string(
        &mut self,
        chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
        _nesting_depth: u32,
    ) -> Result<(Token, usize), LexerError> {
        chars.next(); // r
        chars.next(); // first `
        chars.next(); // second `
        chars.next(); // third `

        let mut content = String::new();
        let mut len = 4;
        let mut backtick_count = 0;

        for (_, ch) in chars.by_ref() {
            len += 1;
            if ch == '`' {
                backtick_count += 1;
                if backtick_count == 3 {
                    self.validate_string_size(&content)?;
                    self.metrics
                        .record_string_length(content.len(), &self.preferences);
                    return Ok((
                        Token::StringLiteral(StringLiteral::RawMultiline(content)),
                        len,
                    ));
                }
            } else {
                for _ in 0..backtick_count {
                    content.push('`');
                }
                backtick_count = 0;
                content.push(ch);

                // SECURITY: Check string size during parsing
                if content.len() > MAX_STRING_SIZE {
                    return Err(LexerError::StringTooLarge {
                        size: content.len(),
                    });
                }
            }
        }

        Err(LexerError::UnterminatedString)
    }

    fn parse_number(
        &self,
        start_offset: usize,
        source: &str,
        chars: &mut std::iter::Peekable<std::str::CharIndices<'_>>,
    ) -> Result<(Token, usize), LexerError> {
        let mut number_text = String::new();
        let mut has_dot = false;
        let mut len = 0;

        if let Some(first_char) = source.chars().nth(start_offset) {
            number_text.push(first_char);
            len += 1;

            if first_char == '-' {
                if let Some((_, ch)) = chars.next() {
                    if ch.is_ascii_digit() {
                        number_text.push(ch);
                        len += 1;
                    } else {
                        return Err(LexerError::InvalidNumber { text: number_text });
                    }
                } else {
                    return Err(LexerError::InvalidNumber { text: number_text });
                }
            }
        }

        while let Some((_, ch)) = chars.peek() {
            match ch {
                '0'..='9' => {
                    number_text.push(*ch);
                    chars.next();
                    len += 1;
                }
                '.' => {
                    if has_dot {
                        break;
                    }
                    let mut temp_chars = chars.clone();
                    temp_chars.next();
                    if let Some((_, next_ch)) = temp_chars.peek() {
                        if next_ch.is_ascii_digit() {
                            has_dot = true;
                            number_text.push('.');
                            chars.next();
                            len += 1;
                        } else {
                            break;
                        }
                    } else {
                        break;
                    }
                }
                _ => break,
            }
        }

        if has_dot {
            match number_text.parse::<f64>() {
                Ok(value) if value.is_finite() => Ok((Token::Float(value), len)),
                _ => Err(LexerError::InvalidNumber { text: number_text }),
            }
        } else {
            match number_text.parse::<i64>() {
                Ok(value) => Ok((Token::Integer(value), len)),
                Err(_) => Err(LexerError::InvalidNumber { text: number_text }),
            }
        }
    }

    /// SECURITY: Validate string size against compile-time limit
    fn validate_string_size(&self, content: &str) -> Result<(), LexerError> {
        if content.len() > MAX_STRING_SIZE {
            Err(LexerError::StringTooLarge {
                size: content.len(),
            })
        } else {
            Ok(())
        }
    }
}

impl Default for LexicalAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}
