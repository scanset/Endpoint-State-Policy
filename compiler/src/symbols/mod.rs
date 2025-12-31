//! Symbol Discovery Module for ESP Compiler with Global Logging
//!
//! Handles symbol collection and relationship tracking with clean global logging integration.

use common::ast::nodes::EspFile;
use common::config::runtime::SymbolPreferences;
use common::logging::codes;
use common::{log_debug, log_success};
use std::sync::Arc;

pub mod collector;
pub mod error;
pub mod table;

// Re-export main types
pub use collector::{AstVisitor, SymbolCollector};
pub use error::{SymbolDiscoveryError, SymbolResult};
pub use table::{
    CtnNodeId, GlobalSymbolTable, LocalObjectSymbol, LocalStateSymbol, LocalSymbolTable,
    ObjectSymbol, SetSymbol, StateSymbol, SymbolDiscoveryResult, SymbolTableBuilder,
    VariableSymbol,
};

/// Module constants
pub const VERSION: &str = "1.0.0";
pub const PASS_NUMBER: u8 = 3;

/// Symbol discovery service with logging (for backward compatibility)
pub struct SymbolDiscoveryService {
    _logging_service: Arc<common::logging::LoggingService>, // Keep for compatibility but don't use
    preferences: SymbolPreferences,
}

impl SymbolDiscoveryService {
    pub fn new(logging_service: Arc<common::logging::LoggingService>) -> Self {
        Self {
            _logging_service: logging_service,
            preferences: SymbolPreferences::default(),
        }
    }

    pub fn with_preferences(
        logging_service: Arc<common::logging::LoggingService>,
        preferences: SymbolPreferences,
    ) -> Self {
        Self {
            _logging_service: logging_service,
            preferences,
        }
    }

    pub fn discover_symbols(&self, ast: EspFile) -> SymbolResult<SymbolDiscoveryResult> {
        // Delegate to global logging approach with preferences
        discover_symbols_from_ast_with_preferences(ast, self.preferences.clone())
    }
}

/// Main entry point for symbol discovery using global logging with default preferences
pub fn discover_symbols_from_ast(ast: EspFile) -> SymbolResult<SymbolDiscoveryResult> {
    discover_symbols_from_ast_with_preferences(ast, SymbolPreferences::default())
}

/// Main entry point for symbol discovery using global logging with custom preferences
pub fn discover_symbols_from_ast_with_preferences(
    ast: EspFile,
    preferences: SymbolPreferences,
) -> SymbolResult<SymbolDiscoveryResult> {
    log_debug!("Symbol discovery using global logging with preferences",
        "detailed_relationships" => preferences.detailed_relationships,
        "track_cross_references" => preferences.track_cross_references,
        "validate_naming_conventions" => preferences.validate_naming_conventions,
        "include_usage_metrics" => preferences.include_usage_metrics,
        "log_relationship_warnings" => preferences.log_relationship_warnings,
        "analyze_dependency_chains" => preferences.analyze_dependency_chains
    );

    // Use collector with custom preferences
    let mut collector = SymbolCollector::with_preferences(preferences);
    let result = collector.collect_symbols(&ast)?;

    log_success!(
        codes::success::SYMBOL_DISCOVERY_COMPLETE,
        "Symbol discovery completed with preferences",
        "symbols" => result.total_symbol_count(),
        "relationships" => result.relationship_count()
    );

    Ok(result)
}

/// Enhanced discovery with custom logging service (for compatibility)
pub fn discover_symbols_with_metrics(
    ast: EspFile,
    _logging_service: Arc<common::logging::LoggingService>, // Ignored, kept for API compatibility
) -> SymbolResult<(SymbolDiscoveryResult, f64)> {
    let start_time = std::time::Instant::now();
    let result = discover_symbols_from_ast(ast)?;
    let duration_ms = start_time.elapsed().as_millis() as f64;
    Ok((result, duration_ms))
}

/// Enhanced discovery with metrics and custom preferences
pub fn discover_symbols_with_metrics_and_preferences(
    ast: EspFile,
    preferences: SymbolPreferences,
    _logging_service: Option<Arc<common::logging::LoggingService>>, // Optional for compatibility
) -> SymbolResult<(SymbolDiscoveryResult, f64)> {
    let start_time = std::time::Instant::now();
    let result = discover_symbols_from_ast_with_preferences(ast, preferences)?;
    let duration_ms = start_time.elapsed().as_millis() as f64;

    log_debug!("Symbol discovery completed with metrics",
        "duration_ms" => duration_ms,
        "symbols_found" => result.total_symbol_count(),
        "relationships_found" => result.relationship_count()
    );

    Ok((result, duration_ms))
}

/// Convenience function for detailed symbol analysis
pub fn discover_symbols_detailed(ast: EspFile) -> SymbolResult<SymbolDiscoveryResult> {
    let preferences = SymbolPreferences {
        detailed_relationships: true,
        track_cross_references: true,
        include_usage_metrics: true,
        analyze_dependency_chains: true,
        ..Default::default()
    };

    discover_symbols_from_ast_with_preferences(ast, preferences)
}

/// Convenience function for strict symbol analysis with naming validation
pub fn discover_symbols_strict(ast: EspFile) -> SymbolResult<SymbolDiscoveryResult> {
    let preferences = SymbolPreferences {
        validate_naming_conventions: true,
        log_relationship_warnings: true,
        detailed_relationships: true,
        ..Default::default()
    };

    discover_symbols_from_ast_with_preferences(ast, preferences)
}

/// Convenience function for minimal symbol analysis (performance optimized)
pub fn discover_symbols_minimal(ast: EspFile) -> SymbolResult<SymbolDiscoveryResult> {
    let preferences = SymbolPreferences {
        detailed_relationships: false,
        track_cross_references: false,
        include_usage_metrics: false,
        log_relationship_warnings: false,
        analyze_dependency_chains: false,
        validate_naming_conventions: false,
    };

    discover_symbols_from_ast_with_preferences(ast, preferences)
}

/// Initialize symbol discovery logging
pub fn init_symbol_discovery_logging() -> Result<(), String> {
    // Validate that symbol error codes are properly configured
    let test_codes = [
        codes::symbols::DUPLICATE_SYMBOL,
        codes::symbols::SYMBOL_DISCOVERY_ERROR,
        codes::symbols::SYMBOL_TABLE_CONSTRUCTION_ERROR,
        codes::symbols::MULTIPLE_LOCAL_OBJECTS,
        codes::symbols::SYMBOL_SCOPE_VALIDATION_ERROR,
    ];

    for code in &test_codes {
        let description = common::logging::codes::get_description(code.as_str());
        if description == "Unknown error" {
            return Err(format!(
                "Symbol error code {} has no description",
                code.as_str()
            ));
        }
    }

    log_debug!("Symbol discovery logging validation completed");
    Ok(())
}

/// Get default symbol preferences for user configuration
pub fn get_default_preferences() -> SymbolPreferences {
    SymbolPreferences::default()
}

/// Create preferences optimized for development/debugging
pub fn create_development_preferences() -> SymbolPreferences {
    SymbolPreferences {
        detailed_relationships: true,
        track_cross_references: true,
        validate_naming_conventions: true,
        include_usage_metrics: true,
        log_relationship_warnings: true,
        analyze_dependency_chains: true,
    }
}

/// Create preferences optimized for production/performance
pub fn create_production_preferences() -> SymbolPreferences {
    SymbolPreferences {
        detailed_relationships: false,
        track_cross_references: false,
        validate_naming_conventions: false,
        include_usage_metrics: true, // Keep metrics for monitoring
        log_relationship_warnings: false,
        analyze_dependency_chains: false,
    }
}
