// RUNTIME PREFERENCES (User Experience)

use serde::{Deserialize, Serialize};
use std::env;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileProcessorPreferences {
    /// Whether to require .esp extension (user preference, not security)
    pub require_esp_extension: bool,

    /// Whether to enable detailed performance logging (user preference)
    pub enable_performance_logging: bool,

    /// Whether to log debug information for non-ESP files
    pub log_non_esp_processing: bool,

    /// Whether to include complexity scores in output
    pub include_complexity_metrics: bool,
}

impl Default for FileProcessorPreferences {
    fn default() -> Self {
        Self {
            require_esp_extension: env::var("ESP_REQUIRE_ESP_EXTENSION")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(false),
            enable_performance_logging: env::var("ESP_ENABLE_PERFORMANCE_LOGGING")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(true),
            log_non_esp_processing: env::var("ESP_LOG_NON_ESP_PROCESSING")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(false),
            include_complexity_metrics: env::var("ESP_INCLUDE_COMPLEXITY_METRICS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(true),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LexicalPreferences {
    /// Whether to collect detailed token metrics
    pub collect_detailed_metrics: bool,

    /// Whether to include whitespace and comments in token counts
    pub include_all_tokens_in_counts: bool,

    /// Whether to log string length statistics
    pub log_string_statistics: bool,

    /// Whether to track operator usage patterns
    pub track_operator_patterns: bool,

    /// Whether to show position information in error messages
    pub include_position_in_errors: bool,
}

impl Default for LexicalPreferences {
    fn default() -> Self {
        Self {
            collect_detailed_metrics: env::var("ESP_LEXICAL_DETAILED_METRICS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(true),
            include_all_tokens_in_counts: env::var("ESP_LEXICAL_INCLUDE_ALL_TOKENS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(false),
            log_string_statistics: env::var("ESP_LEXICAL_LOG_STRING_STATS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(false),
            track_operator_patterns: env::var("ESP_LEXICAL_TRACK_OPERATORS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(false),
            include_position_in_errors: env::var("ESP_LEXICAL_INCLUDE_POSITIONS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(true),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolPreferences {
    /// Whether to collect detailed relationship information
    pub detailed_relationships: bool,

    /// Whether to track cross-reference statistics
    pub track_cross_references: bool,

    /// Whether to validate symbol naming conventions
    pub validate_naming_conventions: bool,

    /// Whether to include symbol usage metrics in output
    pub include_usage_metrics: bool,

    /// Whether to log warnings for failed relationship additions
    pub log_relationship_warnings: bool,

    /// Whether to include dependency chain analysis
    pub analyze_dependency_chains: bool,
}

impl Default for SymbolPreferences {
    fn default() -> Self {
        Self {
            detailed_relationships: env::var("ESP_SYMBOLS_DETAILED_RELATIONSHIPS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(true),
            track_cross_references: env::var("ESP_SYMBOLS_TRACK_CROSS_REFS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(false),
            validate_naming_conventions: env::var("ESP_SYMBOLS_VALIDATE_NAMING")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(false),
            include_usage_metrics: env::var("ESP_SYMBOLS_INCLUDE_USAGE_METRICS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(true),
            log_relationship_warnings: env::var("ESP_SYMBOLS_LOG_RELATIONSHIP_WARNINGS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(true),
            analyze_dependency_chains: env::var("ESP_SYMBOLS_ANALYZE_DEPENDENCY_CHAINS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(true),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReferenceValidationPreferences {
    /// Whether to perform cycle detection (user can disable for performance)
    pub enable_cycle_detection: bool,

    /// Whether to log detailed reference validation steps
    pub log_validation_details: bool,

    /// Whether to include cycle descriptions in output
    pub include_cycle_descriptions: bool,

    /// Whether to continue validation after finding cycles
    pub continue_after_cycles: bool,

    /// Whether to validate reference type consistency
    pub validate_reference_types: bool,
}

impl Default for ReferenceValidationPreferences {
    fn default() -> Self {
        Self {
            enable_cycle_detection: env::var("ESP_REFERENCES_ENABLE_CYCLE_DETECTION")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(true),
            log_validation_details: env::var("ESP_REFERENCES_LOG_VALIDATION_DETAILS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(false),
            include_cycle_descriptions: env::var("ESP_REFERENCES_INCLUDE_CYCLE_DESCRIPTIONS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(true),
            continue_after_cycles: env::var("ESP_REFERENCES_CONTINUE_AFTER_CYCLES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(false),
            validate_reference_types: env::var("ESP_REFERENCES_VALIDATE_TYPES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(true),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SemanticPreferences {
    /// Whether to perform comprehensive type checking
    pub comprehensive_type_checking: bool,

    /// Whether to validate runtime operation constraints
    pub validate_runtime_constraints: bool,

    /// Whether to check SET operation semantics
    pub check_set_semantics: bool,

    /// Whether to analyze dependency cycles
    pub analyze_cycles: bool,

    /// Whether to include detailed error context
    pub detailed_error_context: bool,
}

impl Default for SemanticPreferences {
    fn default() -> Self {
        Self {
            comprehensive_type_checking: env::var("ESP_SEMANTIC_COMPREHENSIVE_TYPE_CHECKING")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(true),
            validate_runtime_constraints: env::var("ESP_SEMANTIC_VALIDATE_RUNTIME_CONSTRAINTS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(true),
            check_set_semantics: env::var("ESP_SEMANTIC_CHECK_SET_SEMANTICS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(true),
            analyze_cycles: env::var("ESP_SEMANTIC_ANALYZE_CYCLES")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(true),
            detailed_error_context: env::var("ESP_SEMANTIC_DETAILED_ERROR_CONTEXT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(true),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructuralPreferences {
    /// Whether to perform advanced consistency checking (user preference)
    pub enable_advanced_consistency_checks: bool,

    /// Whether to log detailed structural analysis metrics
    pub log_detailed_structural_metrics: bool,

    /// Whether to include complexity breakdown in output
    pub include_complexity_breakdown: bool,

    /// Whether to validate optional structural recommendations
    pub validate_structural_recommendations: bool,

    /// Whether to analyze structural quality patterns
    pub analyze_quality_patterns: bool,
}

impl Default for StructuralPreferences {
    fn default() -> Self {
        Self {
            enable_advanced_consistency_checks: env::var(
                "ESP_STRUCTURAL_ADVANCED_CONSISTENCY_CHECKS",
            )
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(true),
            log_detailed_structural_metrics: env::var("ESP_STRUCTURAL_LOG_DETAILED_METRICS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(false),
            include_complexity_breakdown: env::var("ESP_STRUCTURAL_INCLUDE_COMPLEXITY_BREAKDOWN")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(true),
            validate_structural_recommendations: env::var(
                "ESP_STRUCTURAL_VALIDATE_RECOMMENDATIONS",
            )
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(false),
            analyze_quality_patterns: env::var("ESP_STRUCTURAL_ANALYZE_QUALITY_PATTERNS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(false),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingPreferences {
    /// Whether to use structured JSON logging (user preference)
    pub use_structured_logging: bool,

    /// Whether to enable console output (user preference)
    pub enable_console_logging: bool,

    /// User preferred minimum log level (within security constraints)
    /// Note: Security events will still be logged regardless of this setting
    pub min_log_level: LogLevel,

    /// Whether to include performance metrics in logs
    pub log_performance_events: bool,

    /// Whether to include detailed security metrics
    pub log_security_metrics: bool,

    /// Whether to enable cargo-style error reporting
    pub enable_cargo_style_output: bool,

    /// Whether to include file context in log messages
    pub include_file_context: bool,
}

impl Default for LoggingPreferences {
    fn default() -> Self {
        Self {
            use_structured_logging: env::var("ESP_LOGGING_USE_STRUCTURED")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(false),
            enable_console_logging: env::var("ESP_LOGGING_ENABLE_CONSOLE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(false),
            min_log_level: env::var("ESP_LOGGING_MIN_LEVEL")
                .ok()
                .and_then(|v| parse_log_level(&v))
                .unwrap_or(LogLevel::Info),
            log_performance_events: env::var("ESP_LOGGING_LOG_PERFORMANCE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(true),
            log_security_metrics: env::var("ESP_LOGGING_LOG_SECURITY")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(true),
            enable_cargo_style_output: env::var("ESP_LOGGING_CARGO_STYLE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(true),
            include_file_context: env::var("ESP_LOGGING_INCLUDE_FILE_CONTEXT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(true),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum LogLevel {
    Error = 0,
    Warning = 1,
    Info = 2,
    Debug = 3,
}

impl LogLevel {
    pub fn as_str(&self) -> &'static str {
        match self {
            LogLevel::Error => "ERROR",
            LogLevel::Warning => "WARN",
            LogLevel::Info => "INFO",
            LogLevel::Debug => "DEBUG",
        }
    }

    /// Convert to events::LogLevel for compatibility
    pub fn to_events_log_level(self) -> crate::logging::events::LogLevel {
        match self {
            LogLevel::Error => crate::logging::events::LogLevel::Error,
            LogLevel::Warning => crate::logging::events::LogLevel::Warning,
            LogLevel::Info => crate::logging::events::LogLevel::Info,
            LogLevel::Debug => crate::logging::events::LogLevel::Debug,
        }
    }

    /// Convert from events::LogLevel for compatibility
    pub fn from_events_log_level(level: crate::logging::events::LogLevel) -> Self {
        match level {
            crate::logging::events::LogLevel::Error => LogLevel::Error,
            crate::logging::events::LogLevel::Warning => LogLevel::Warning,
            crate::logging::events::LogLevel::Info => LogLevel::Info,
            crate::logging::events::LogLevel::Debug => LogLevel::Debug,
        }
    }
}

/// Parse log level from string (used for environment variables)
fn parse_log_level(level: &str) -> Option<LogLevel> {
    match level.to_lowercase().as_str() {
        "error" | "0" => Some(LogLevel::Error),
        "warning" | "warn" | "1" => Some(LogLevel::Warning),
        "info" | "2" => Some(LogLevel::Info),
        "debug" | "3" => Some(LogLevel::Debug),
        _ => None,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RuntimeConfig {
    pub file_processor: FileProcessorPreferences,
    pub lexical: LexicalPreferences,
    pub symbols: SymbolPreferences,
    pub references: ReferenceValidationPreferences,
    pub semantic: SemanticPreferences,
    pub structural: StructuralPreferences,
    pub logging: LoggingPreferences,
}

/// Environment variable names for configuration
pub mod env_vars {
    // File Processor
    pub const REQUIRE_ESP_EXTENSION: &str = "ESP_REQUIRE_ESP_EXTENSION";
    pub const ENABLE_PERFORMANCE_LOGGING: &str = "ESP_ENABLE_PERFORMANCE_LOGGING";
    pub const LOG_NON_ESP_PROCESSING: &str = "ESP_LOG_NON_ESP_PROCESSING";
    pub const INCLUDE_COMPLEXITY_METRICS: &str = "ESP_INCLUDE_COMPLEXITY_METRICS";

    // Lexical
    pub const LEXICAL_DETAILED_METRICS: &str = "ESP_LEXICAL_DETAILED_METRICS";
    pub const LEXICAL_INCLUDE_ALL_TOKENS: &str = "ESP_LEXICAL_INCLUDE_ALL_TOKENS";
    pub const LEXICAL_LOG_STRING_STATS: &str = "ESP_LEXICAL_LOG_STRING_STATS";
    pub const LEXICAL_TRACK_OPERATORS: &str = "ESP_LEXICAL_TRACK_OPERATORS";
    pub const LEXICAL_INCLUDE_POSITIONS: &str = "ESP_LEXICAL_INCLUDE_POSITIONS";

    // Symbols
    pub const SYMBOLS_DETAILED_RELATIONSHIPS: &str = "ESP_SYMBOLS_DETAILED_RELATIONSHIPS";
    pub const SYMBOLS_TRACK_CROSS_REFS: &str = "ESP_SYMBOLS_TRACK_CROSS_REFS";
    pub const SYMBOLS_VALIDATE_NAMING: &str = "ESP_SYMBOLS_VALIDATE_NAMING";
    pub const SYMBOLS_INCLUDE_USAGE_METRICS: &str = "ESP_SYMBOLS_INCLUDE_USAGE_METRICS";
    pub const SYMBOLS_LOG_RELATIONSHIP_WARNINGS: &str = "ESP_SYMBOLS_LOG_RELATIONSHIP_WARNINGS";
    pub const SYMBOLS_ANALYZE_DEPENDENCY_CHAINS: &str = "ESP_SYMBOLS_ANALYZE_DEPENDENCY_CHAINS";

    // References
    pub const REFERENCES_ENABLE_CYCLE_DETECTION: &str = "ESP_REFERENCES_ENABLE_CYCLE_DETECTION";
    pub const REFERENCES_LOG_VALIDATION_DETAILS: &str = "ESP_REFERENCES_LOG_VALIDATION_DETAILS";
    pub const REFERENCES_INCLUDE_CYCLE_DESCRIPTIONS: &str =
        "ESP_REFERENCES_INCLUDE_CYCLE_DESCRIPTIONS";
    pub const REFERENCES_CONTINUE_AFTER_CYCLES: &str = "ESP_REFERENCES_CONTINUE_AFTER_CYCLES";
    pub const REFERENCES_VALIDATE_TYPES: &str = "ESP_REFERENCES_VALIDATE_TYPES";

    // Semantic
    pub const SEMANTIC_COMPREHENSIVE_TYPE_CHECKING: &str =
        "ESP_SEMANTIC_COMPREHENSIVE_TYPE_CHECKING";
    pub const SEMANTIC_VALIDATE_RUNTIME_CONSTRAINTS: &str =
        "ESP_SEMANTIC_VALIDATE_RUNTIME_CONSTRAINTS";
    pub const SEMANTIC_CHECK_SET_SEMANTICS: &str = "ESP_SEMANTIC_CHECK_SET_SEMANTICS";
    pub const SEMANTIC_ANALYZE_CYCLES: &str = "ESP_SEMANTIC_ANALYZE_CYCLES";
    pub const SEMANTIC_DETAILED_ERROR_CONTEXT: &str = "ESP_SEMANTIC_DETAILED_ERROR_CONTEXT";

    // Structural
    pub const STRUCTURAL_ADVANCED_CONSISTENCY_CHECKS: &str =
        "ESP_STRUCTURAL_ADVANCED_CONSISTENCY_CHECKS";
    pub const STRUCTURAL_LOG_DETAILED_METRICS: &str = "ESP_STRUCTURAL_LOG_DETAILED_METRICS";
    pub const STRUCTURAL_INCLUDE_COMPLEXITY_BREAKDOWN: &str =
        "ESP_STRUCTURAL_INCLUDE_COMPLEXITY_BREAKDOWN";
    pub const STRUCTURAL_VALIDATE_RECOMMENDATIONS: &str = "ESP_STRUCTURAL_VALIDATE_RECOMMENDATIONS";
    pub const STRUCTURAL_ANALYZE_QUALITY_PATTERNS: &str = "ESP_STRUCTURAL_ANALYZE_QUALITY_PATTERNS";

    // Logging
    pub const LOGGING_USE_STRUCTURED: &str = "ESP_LOGGING_USE_STRUCTURED";
    pub const LOGGING_ENABLE_CONSOLE: &str = "ESP_LOGGING_ENABLE_CONSOLE";
    pub const LOGGING_MIN_LEVEL: &str = "ESP_LOGGING_MIN_LEVEL";
    pub const LOGGING_LOG_PERFORMANCE: &str = "ESP_LOGGING_LOG_PERFORMANCE";
    pub const LOGGING_LOG_SECURITY: &str = "ESP_LOGGING_LOG_SECURITY";
    pub const LOGGING_CARGO_STYLE: &str = "ESP_LOGGING_CARGO_STYLE";
    pub const LOGGING_INCLUDE_FILE_CONTEXT: &str = "ESP_LOGGING_INCLUDE_FILE_CONTEXT";
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_log_level_parsing() {
        assert_eq!(parse_log_level("error"), Some(LogLevel::Error));
        assert_eq!(parse_log_level("ERROR"), Some(LogLevel::Error));
        assert_eq!(parse_log_level("0"), Some(LogLevel::Error));
        assert_eq!(parse_log_level("warn"), Some(LogLevel::Warning));
        assert_eq!(parse_log_level("warning"), Some(LogLevel::Warning));
        assert_eq!(parse_log_level("1"), Some(LogLevel::Warning));
        assert_eq!(parse_log_level("info"), Some(LogLevel::Info));
        assert_eq!(parse_log_level("2"), Some(LogLevel::Info));
        assert_eq!(parse_log_level("debug"), Some(LogLevel::Debug));
        assert_eq!(parse_log_level("3"), Some(LogLevel::Debug));
        assert_eq!(parse_log_level("invalid"), None);
    }

    #[test]
    fn test_env_var_names_exist() {
        // Verify all env var names are properly defined
        assert!(!env_vars::ENABLE_PERFORMANCE_LOGGING.is_empty());
        assert!(!env_vars::LOGGING_MIN_LEVEL.is_empty());
        assert!(!env_vars::REFERENCES_ENABLE_CYCLE_DETECTION.is_empty());
    }
}
