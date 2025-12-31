//! Lexical analysis module with FileProcessingResult integration
//!
//! Provides systematic tokenization for ESP source text with file-aware
//! processing and integration with the global logging system.
//!

pub mod analyzer;

use crate::file_processor::FileProcessingResult;
use crate::tokens::TokenStream;
use common::config::constants::compile_time::lexical::*;
use common::config::runtime::LexicalPreferences;

pub use analyzer::{LexerError, LexicalAnalyzer, LexicalMetrics};

// ============================================================================
// FILE-AWARE MODULE API WITH SECURITY BOUNDARIES
// ============================================================================

/// Tokenize file processing result with comprehensive file context and security limits
pub fn tokenize_file_result(file_result: FileProcessingResult) -> Result<TokenStream, LexerError> {
    let mut analyzer = LexicalAnalyzer::new();
    analyzer.tokenize_file_result(file_result)
}

/// Tokenize with custom runtime preferences (security boundaries remain compile-time)
pub fn tokenize_file_result_with_preferences(
    file_result: FileProcessingResult,
    preferences: LexicalPreferences,
) -> Result<TokenStream, LexerError> {
    let mut analyzer = LexicalAnalyzer::with_preferences(preferences);
    analyzer.tokenize_file_result(file_result)
}

/// Create a new lexical analyzer with default preferences
pub fn create_analyzer() -> LexicalAnalyzer {
    LexicalAnalyzer::new()
}

/// Create analyzer with custom runtime preferences
pub fn create_analyzer_with_preferences(preferences: LexicalPreferences) -> LexicalAnalyzer {
    LexicalAnalyzer::with_preferences(preferences)
}

// ============================================================================
// MODULE INITIALIZATION AND VALIDATION
// ============================================================================

/// Initialize lexical analysis module validation (for system startup)
/// Validates that all error codes are properly configured and security limits are applied
pub fn init_lexical_analysis_logging() -> Result<(), String> {
    // Validate that all lexical error codes are properly configured
    let test_codes = [
        common::logging::codes::lexical::INVALID_CHARACTER,
        common::logging::codes::lexical::UNTERMINATED_STRING,
        common::logging::codes::lexical::INVALID_NUMBER,
        common::logging::codes::lexical::IDENTIFIER_TOO_LONG,
        common::logging::codes::lexical::STRING_TOO_LARGE,
        common::logging::codes::lexical::COMMENT_TOO_LONG,
        common::logging::codes::lexical::TOO_MANY_TOKENS,
        common::logging::codes::lexical::STRING_NESTING_TOO_DEEP,
    ];

    for code in &test_codes {
        let description = common::logging::codes::get_description(code.as_str());
        if description == "Unknown error" {
            return Err(format!(
                "Lexical error code {} has no description",
                code.as_str()
            ));
        }

        // Verify the code exists in the error metadata registry
        if common::logging::codes::get_error_metadata(code.as_str()).is_none() {
            return Err(format!(
                "Lexical error code {} not found in metadata registry",
                code.as_str()
            ));
        }
    }

    // Validate success code
    let success_code = common::logging::codes::success::TOKENIZATION_COMPLETE;
    if common::logging::codes::get_error_metadata(success_code.as_str()).is_none() {
        common::log_debug!("Success code validation skipped (not in error registry)",
            "code" => success_code.as_str());
    }

    // Log security limits that are now compile-time enforced
    common::log_debug!("Lexical security limits initialized",
        "max_string_size" => MAX_STRING_SIZE,
        "max_identifier_length" => MAX_IDENTIFIER_LENGTH,
        "max_comment_length" => MAX_COMMENT_LENGTH,
        "max_token_count" => MAX_TOKEN_COUNT,
        "max_string_nesting_depth" => MAX_STRING_NESTING_DEPTH
    );

    Ok(())
}

/// Validate basic tokenization functionality and security boundaries
pub fn validate_tokenization() -> Result<(), String> {
    // Validate error codes have proper metadata
    let test_codes = [
        common::logging::codes::lexical::INVALID_CHARACTER,
        common::logging::codes::lexical::UNTERMINATED_STRING,
        common::logging::codes::lexical::INVALID_NUMBER,
        common::logging::codes::lexical::IDENTIFIER_TOO_LONG,
        common::logging::codes::lexical::STRING_TOO_LARGE,
        common::logging::codes::lexical::COMMENT_TOO_LONG,
        common::logging::codes::lexical::TOO_MANY_TOKENS,
        common::logging::codes::lexical::STRING_NESTING_TOO_DEEP,
    ];

    for code in &test_codes {
        let description = common::logging::codes::get_description(code.as_str());
        if description == "Unknown error" {
            return Err(format!(
                "Lexical error code {} has no description",
                code.as_str()
            ));
        }
    }

    // Validate compile-time security limits are reasonable
    if MAX_STRING_SIZE == 0 {
        return Err("MAX_STRING_SIZE cannot be zero".to_string());
    }
    if MAX_IDENTIFIER_LENGTH == 0 {
        return Err("MAX_IDENTIFIER_LENGTH cannot be zero".to_string());
    }
    if MAX_TOKEN_COUNT == 0 {
        return Err("MAX_TOKEN_COUNT cannot be zero".to_string());
    }
    if MAX_COMMENT_LENGTH == 0 {
        return Err("MAX_COMMENT_LENGTH cannot be zero".to_string());
    }

    // Validate that limits are within reasonable bounds
    if MAX_STRING_SIZE > 100_000_000 {
        // 100MB
        return Err("MAX_STRING_SIZE exceeds reasonable limit".to_string());
    }
    if MAX_TOKEN_COUNT > 10_000_000 {
        // 10M tokens
        return Err("MAX_TOKEN_COUNT exceeds reasonable limit".to_string());
    }

    Ok(())
}

/// Get the current compile-time security limits (for reporting/debugging)
pub fn get_security_limits() -> SecurityLimits {
    SecurityLimits {
        max_string_size: MAX_STRING_SIZE,
        max_identifier_length: MAX_IDENTIFIER_LENGTH,
        max_comment_length: MAX_COMMENT_LENGTH,
        max_token_count: MAX_TOKEN_COUNT,
        max_string_nesting_depth: MAX_STRING_NESTING_DEPTH,
    }
}

/// Information about compile-time security limits
#[derive(Debug, Clone)]
pub struct SecurityLimits {
    pub max_string_size: usize,
    pub max_identifier_length: usize,
    pub max_comment_length: usize,
    pub max_token_count: usize,
    pub max_string_nesting_depth: u32,
}

impl SecurityLimits {
    /// Check if the limits are SSDF compliant (conservative estimates)
    pub fn is_ssdf_compliant(&self) -> bool {
        // Conservative bounds for SSDF compliance
        self.max_string_size <= 10_000_000 && // 10MB max
        self.max_identifier_length <= 1000 && // 1K chars max
        self.max_comment_length <= 100_000 && // 100K chars max
        self.max_token_count <= 5_000_000 && // 5M tokens max
        self.max_string_nesting_depth <= 1000 // 1K nesting max
    }
}

// ============================================================================
// ENHANCED ANALYSIS HELPERS WITH SECURITY CONTEXT
// ============================================================================

/// Get comprehensive token count information with security context
pub fn get_token_counts(token_stream: &TokenStream) -> TokenCounts {
    let mut counts = TokenCounts::default();

    for token in token_stream.all_tokens() {
        counts.total += 1;
        match &token.value {
            crate::tokens::Token::Keyword(_) => counts.keywords += 1,
            crate::tokens::Token::Identifier(_) => counts.identifiers += 1,
            crate::tokens::Token::Integer(_) | crate::tokens::Token::Float(_) => {
                counts.numbers += 1
            }
            crate::tokens::Token::Boolean(_) => counts.booleans += 1,
            crate::tokens::Token::StringLiteral(_) => counts.strings += 1,
            crate::tokens::Token::Comment(_) => counts.comments += 1,
            crate::tokens::Token::Space
            | crate::tokens::Token::Tab
            | crate::tokens::Token::Newline => counts.whitespace += 1,
            crate::tokens::Token::Equals
            | crate::tokens::Token::NotEquals
            | crate::tokens::Token::GreaterThan
            | crate::tokens::Token::LessThan
            | crate::tokens::Token::GreaterThanOrEqual
            | crate::tokens::Token::LessThanOrEqual
            | crate::tokens::Token::Contains
            | crate::tokens::Token::StartsWith
            | crate::tokens::Token::EndsWith
            | crate::tokens::Token::NotContains
            | crate::tokens::Token::NotStartsWith
            | crate::tokens::Token::NotEndsWith
            | crate::tokens::Token::PatternMatch
            | crate::tokens::Token::Matches
            | crate::tokens::Token::SubsetOf
            | crate::tokens::Token::SupersetOf
            | crate::tokens::Token::Plus
            | crate::tokens::Token::Minus
            | crate::tokens::Token::Multiply
            | crate::tokens::Token::Divide
            | crate::tokens::Token::Modulus
            | crate::tokens::Token::CaseInsensitiveEquals
            | crate::tokens::Token::CaseInsensitiveNotEquals => counts.operators += 1,
            _ => {} // Dot, EOF, etc.
        }
    }

    // Add security analysis
    counts.security_analysis = Some(SecurityAnalysis {
        exceeds_token_limit: counts.total > MAX_TOKEN_COUNT,
        token_density: if counts.total > 0 {
            counts.significant_tokens() as f64 / counts.total as f64
        } else {
            0.0
        },
        has_suspicious_patterns: counts.operators as f64 / counts.total.max(1) as f64 > 0.8,
    });

    counts
}

/// Enhanced token distribution information with security analysis
#[derive(Debug, Default, Clone)]
pub struct TokenCounts {
    pub total: usize,
    pub keywords: usize,
    pub identifiers: usize,
    pub numbers: usize,
    pub booleans: usize,
    pub strings: usize,
    pub comments: usize,
    pub operators: usize,
    pub whitespace: usize,
    pub security_analysis: Option<SecurityAnalysis>,
}

/// Security analysis of token distribution
#[derive(Debug, Clone)]
pub struct SecurityAnalysis {
    pub exceeds_token_limit: bool,
    pub token_density: f64,
    pub has_suspicious_patterns: bool,
}

impl TokenCounts {
    /// Get count of significant tokens (excluding whitespace and comments)
    pub fn significant_tokens(&self) -> usize {
        self.total - self.whitespace - self.comments
    }

    /// Check if tokenization appears successful (has meaningful content)
    pub fn has_content(&self) -> bool {
        self.keywords > 0 || self.identifiers > 0 || self.strings > 0
    }

    /// Check if token counts are within security limits
    pub fn is_within_security_limits(&self) -> bool {
        self.total <= MAX_TOKEN_COUNT
    }

    /// Get security risk assessment
    pub fn security_risk_level(&self) -> SecurityRiskLevel {
        if let Some(analysis) = &self.security_analysis {
            if analysis.exceeds_token_limit || analysis.has_suspicious_patterns {
                SecurityRiskLevel::High
            } else if analysis.token_density < 0.1 || self.total > MAX_TOKEN_COUNT / 2 {
                SecurityRiskLevel::Medium
            } else {
                SecurityRiskLevel::Low
            }
        } else {
            SecurityRiskLevel::Unknown
        }
    }
}

/// Security risk levels for tokenization
#[derive(Debug, Clone, PartialEq)]
pub enum SecurityRiskLevel {
    Low,
    Medium,
    High,
    Unknown,
}
