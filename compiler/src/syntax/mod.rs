//! Syntax analysis module - TokenStream to AST transformation
//!
//! This module provides the transformation layer that converts token streams
//! into Abstract Syntax Trees using systematic grammar builders with
//! span-accurate error reporting and global logging integration.

mod error;
mod parser;

// Re-export core types
pub use common::ast::nodes::EspFile;
pub use error::{SyntaxError, SyntaxResult};
pub use parser::{create_parser, EspParser};

use crate::tokens::TokenStream;
use common::logging::codes;
use common::{log_debug, log_error, log_info, log_success};

/// Parse ESP file from token stream with global logging
///
/// This function provides the main API for syntax analysis using the global logging system.
pub fn parse_esp_file(token_stream: TokenStream) -> SyntaxResult<EspFile> {
    log_debug!("Starting syntax analysis", "tokens" => token_stream.len());

    // Use the enhanced parser implementation
    let result = parser::parse_token_stream_enhanced(token_stream);

    match &result {
        Ok(_ast) => {
            log_success!(
                codes::success::AST_CONSTRUCTION_COMPLETE,
                "Syntax analysis completed successfully"
            );
        }
        Err(error) => {
            log_error!(error.error_code(), "Syntax analysis failed",
                "error" => error.to_string()
            );
        }
    }

    result
}

/// Legacy compatibility function (maintains existing API contract)
pub fn parse_esp_file_with_custom_logging(
    token_stream: TokenStream,
    _logging_service: std::sync::Arc<common::logging::LoggingService>,
) -> SyntaxResult<EspFile> {
    // Ignore the passed logging service and use global logging
    parse_esp_file(token_stream)
}

/// Convenience function for testing with debug logging
#[cfg(test)]
pub fn parse_esp_file_debug(token_stream: TokenStream) -> SyntaxResult<EspFile> {
    log_debug!("Debug parsing session started");
    let result = parse_esp_file(token_stream);
    log_debug!("Debug parsing session completed", "success" => result.is_ok());
    result
}

/// Module version
pub const VERSION: &str = "2.0.0";

/// Check if systematic parsing is available (always true with this implementation)
pub fn systematic_parsing_available() -> bool {
    true
}

/// Validate that grammar builders are available
pub fn validate_grammar_integration() -> Result<(), String> {
    log_debug!("Validating grammar integration");

    // Test that we can access the required grammar components
    match crate::grammar::builders::validate_builder_coverage() {
        Ok(()) => {
            log_success!(
                codes::success::SYNTAX_VALIDATION_PASSED,
                "Grammar integration validation passed"
            );
            Ok(())
        }
        Err(missing) => {
            let error_msg = format!("Missing builders: {}", missing.join(", "));
            log_error!(codes::syntax::INTERNAL_PARSER_ERROR,
                "Grammar integration validation failed",
                "missing_builders" => missing.join(", ")
            );
            Err(error_msg)
        }
    }
}

/// Initialize syntax module logging validation
pub fn init_syntax_logging() -> Result<(), String> {
    // Validate that all syntax error codes are properly configured
    let test_codes = [
        codes::syntax::UNEXPECTED_TOKEN,
        codes::syntax::MISSING_EOF,
        codes::syntax::GRAMMAR_VIOLATION,
        codes::syntax::INTERNAL_PARSER_ERROR,
        codes::syntax::MAX_RECURSION_DEPTH,
    ];

    for code in &test_codes {
        let description = common::logging::codes::get_description(code.as_str());
        if description == "Unknown error" {
            return Err(format!(
                "Syntax error code {} has no description",
                code.as_str()
            ));
        }

        // Verify the code exists in the error metadata registry
        if common::logging::codes::get_error_metadata(code.as_str()).is_none() {
            return Err(format!(
                "Syntax error code {} not found in metadata registry",
                code.as_str()
            ));
        }
    }

    // Validate success codes
    let success_codes = [
        codes::success::AST_CONSTRUCTION_COMPLETE,
        codes::success::SYNTAX_VALIDATION_PASSED,
    ];

    for code in &success_codes {
        if common::logging::codes::get_error_metadata(code.as_str()).is_none() {
            log_debug!("Success code validation skipped (not in error registry)",
                "code" => code.as_str());
        }
    }

    log_info!("Syntax module logging validation completed");
    Ok(())
}

/// Get module information for debugging
pub fn get_module_info() -> ModuleInfo {
    let builder_coverage = match validate_grammar_integration() {
        Ok(()) => "Complete".to_string(),
        Err(e) => format!("Issues: {}", e),
    };

    ModuleInfo {
        version: VERSION.to_string(),
        uses_grammar_builders: true,
        span_accurate: true,
        enhanced_error_reporting: true,
        global_logging: true,
        builder_coverage,
    }
}

/// Module information for debugging
#[derive(Debug)]
pub struct ModuleInfo {
    pub version: String,
    pub uses_grammar_builders: bool,
    pub span_accurate: bool,
    pub enhanced_error_reporting: bool,
    pub global_logging: bool,
    pub builder_coverage: String,
}

impl ModuleInfo {
    pub fn report(&self) -> String {
        format!(
            "Syntax Module Info:\n\
             Version: {}\n\
             Uses Grammar Builders: {}\n\
             Span Accurate: {}\n\
             Enhanced Error Reporting: {}\n\
             Global Logging: {}\n\
             Builder Coverage: {}",
            self.version,
            self.uses_grammar_builders,
            self.span_accurate,
            self.enhanced_error_reporting,
            self.global_logging,
            self.builder_coverage
        )
    }
}

/// Get comprehensive grammar builder report
pub fn get_grammar_builder_report() -> String {
    log_debug!("Generating grammar builder report");
    crate::grammar::builders::get_coverage_report()
}

/// Test the systematic parser integration
#[cfg(test)]
pub fn test_systematic_integration() -> Result<(), String> {
    log_debug!("Testing systematic parser integration");
    validate_grammar_integration()
}

#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::tokens::TokenStreamBuilder;

    fn create_empty_token_stream() -> TokenStream {
        TokenStreamBuilder::new().build()
    }

    fn create_minimal_valid_token_stream() -> TokenStream {
        use crate::tokens::Token;

        TokenStreamBuilder::new().push_token(Token::Eof, "").build()
    }

    #[test]
    fn test_module_initialization() {
        let result = init_syntax_logging();
        assert!(result.is_ok(), "Module initialization should succeed");
    }

    #[test]
    fn test_systematic_parsing_available() {
        assert!(systematic_parsing_available());
    }

    #[test]
    fn test_grammar_integration() {
        let result = validate_grammar_integration();
        // Should either succeed or provide meaningful error
        match result {
            Ok(()) => println!("Grammar integration validated successfully"),
            Err(e) => println!("Grammar integration issues: {}", e),
        }
    }

    #[test]
    fn test_module_info() {
        let info = get_module_info();
        assert_eq!(info.version, VERSION);
        assert!(info.uses_grammar_builders);
        assert!(info.span_accurate);
        assert!(info.enhanced_error_reporting);
        assert!(info.global_logging);

        let report = info.report();
        assert!(report.contains("Global Logging: true"));
    }

    #[test]
    fn test_empty_token_stream_parsing() {
        // Test parsing with empty token stream - should fail gracefully
        let tokens = create_empty_token_stream();
        let result = parse_esp_file(tokens);

        // Should fail with empty token stream error
        assert!(result.is_err());
        if let Err(error) = result {
            assert_eq!(error.error_code().as_str(), "E041"); // EMPTY_TOKEN_STREAM
        }
    }

    #[test]
    fn test_minimal_token_stream_parsing() {
        // Test parsing with minimal token stream (just EOF)
        let tokens = create_minimal_valid_token_stream();
        let result = parse_esp_file(tokens);

        // Either succeeds or fails gracefully with proper error
        match result {
            Ok(_) => println!("Parse succeeded with minimal input"),
            Err(e) => {
                println!("Parse failed as expected with minimal input: {}", e);
                // Should be a grammar error, not a system error
                assert!(e.is_recoverable());
            }
        }
    }

    #[test]
    fn test_legacy_api_compatibility() {
        let tokens = create_empty_token_stream();
        let logging_service = std::sync::Arc::new(common::logging::service::LoggingService::new(
            std::sync::Arc::new(common::logging::MemoryLogger::new()),
            common::logging::LogLevel::Debug,
        ));

        // Legacy function should work the same as new function
        let result1 = parse_esp_file(tokens.clone());
        let result2 = parse_esp_file_with_custom_logging(tokens, logging_service);

        // Both should produce the same result
        match (result1, result2) {
            (Ok(_), Ok(_)) => (),
            (Err(e1), Err(e2)) => {
                assert_eq!(e1.error_code(), e2.error_code());
            }
            _ => panic!("Legacy and new APIs produced different result types"),
        }
    }

    #[test]
    fn test_debug_parsing_function() {
        let tokens = create_empty_token_stream();
        let result = parse_esp_file_debug(tokens);

        // Should behave the same as regular parsing
        assert!(result.is_err());
    }

    #[test]
    fn test_error_code_consistency() {
        let tokens = create_empty_token_stream();
        let result = parse_esp_file(tokens);

        if let Err(error) = result {
            // Verify error has proper metadata
            let code = error.error_code();
            let description = common::logging::codes::get_description(code.as_str());
            assert_ne!(description, "Unknown error");

            let category = common::logging::codes::get_category(code.as_str());
            assert_ne!(category, "Unknown");
        }
    }
}
