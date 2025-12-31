//! Global logging module for ESP Compiler
//!
//! Provides thread-safe global logging with file-aware batch processing,
//! cargo-style error reporting, and clean macro interface.

pub mod codes;
pub mod collector;
pub mod config;
pub mod events;
pub mod macros;
pub mod service;

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};

// Re-export main types
pub use codes::Code;
pub use collector::{ErrorCollector, FileProcessingContext, ProcessingSummary};
pub use events::{LogEvent, LogLevel};
pub use service::{ConsoleLogger, Logger, LoggingService, MemoryLogger, StructuredLogger};

// ============================================================================
// GLOBAL STATE
// ============================================================================

static GLOBAL_LOGGER: OnceLock<Arc<LoggingService>> = OnceLock::new();
static GLOBAL_ERROR_COLLECTOR: OnceLock<Arc<ErrorCollector>> = OnceLock::new();

thread_local! {
    static FILE_CONTEXT: RefCell<Option<FileProcessingContext>> = const {RefCell::new(None)};
}

// ============================================================================
// INITIALIZATION
// ============================================================================

/// Initialize global logging system
pub fn init_global_logging() -> Result<(), String> {
    config::validate_config().map_err(|e| format!("Configuration validation failed: {}", e))?;

    let logging_service = Arc::new(service::create_configured_service());
    let error_collector = Arc::new(ErrorCollector::new());

    GLOBAL_LOGGER
        .set(logging_service.clone())
        .map_err(|_| "Global logger already initialized")?;

    GLOBAL_ERROR_COLLECTOR
        .set(error_collector)
        .map_err(|_| "Global error collector already initialized")?;

    // Validate error code system
    let test_codes = ["ERR001", "E005", "E020", "E040"];
    for &code in &test_codes {
        if codes::get_description(code) == "Unknown error" {
            return Err(format!("Missing metadata for error code: {}", code));
        }
    }

    // Log initialization success - FIXED: Use proper success code
    let event = events::LogEvent::success(
        codes::success::SYSTEM_INITIALIZATION_COMPLETED,
        "Global logging system initialized",
    );
    logging_service.log_event(event);

    Ok(())
}

/// Initialize with custom service (primarily for testing)
pub fn init_global_logging_with_service(service: Arc<LoggingService>) -> Result<(), String> {
    let error_collector = Arc::new(ErrorCollector::new());

    GLOBAL_LOGGER
        .set(service)
        .map_err(|_| "Global logger already initialized")?;

    GLOBAL_ERROR_COLLECTOR
        .set(error_collector)
        .map_err(|_| "Global error collector already initialized")?;

    Ok(())
}

/// Check if global logging is initialized
pub fn is_initialized() -> bool {
    GLOBAL_LOGGER.get().is_some() && GLOBAL_ERROR_COLLECTOR.get().is_some()
}

// ============================================================================
// GLOBAL ACCESS
// ============================================================================

/// Get global logger (panics if not initialized)
pub fn get_global_logger() -> &'static LoggingService {
    GLOBAL_LOGGER
        .get()
        .expect("Global logger not initialized. Call init_global_logging() first.")
        .as_ref()
}

/// Get global error collector (panics if not initialized)
pub fn get_global_error_collector() -> &'static ErrorCollector {
    GLOBAL_ERROR_COLLECTOR
        .get()
        .expect("Global error collector not initialized. Call init_global_logging() first.")
        .as_ref()
}

/// Safe access to global logger
pub fn try_get_global_logger() -> Option<&'static LoggingService> {
    GLOBAL_LOGGER.get().map(|service| service.as_ref())
}

/// Safe access to global error collector
pub fn try_get_global_error_collector() -> Option<&'static ErrorCollector> {
    GLOBAL_ERROR_COLLECTOR
        .get()
        .map(|collector| collector.as_ref())
}

// ============================================================================
// FILE CONTEXT MANAGEMENT
// ============================================================================

/// Set file context for current thread
pub fn set_file_context(file_path: PathBuf, file_id: usize) {
    let context = FileProcessingContext::new(file_path, file_id);

    if let Some(collector) = try_get_global_error_collector() {
        collector.record_file_context(context.clone());
    }

    FILE_CONTEXT.with(|ctx| {
        *ctx.borrow_mut() = Some(context);
    });
}

/// Clear file context for current thread
pub fn clear_file_context() {
    FILE_CONTEXT.with(|ctx| {
        *ctx.borrow_mut() = None;
    });
}

/// Execute function with file context
pub fn with_file_context<F, R>(file_path: PathBuf, file_id: usize, f: F) -> R
where
    F: FnOnce() -> R,
{
    set_file_context(file_path, file_id);
    let result = f();
    clear_file_context();
    result
}

/// Get current file context (used by macros)
pub fn get_current_file_context() -> Option<FileProcessingContext> {
    FILE_CONTEXT.with(|ctx| ctx.borrow().clone())
}

// ============================================================================
// MACRO SUPPORT FUNCTIONS - FIXED: Proper Code usage
// ============================================================================

/// Log error with context (used by log_error! macro) - FIXED: Code parameter
pub fn log_error_with_context(
    code: Code,
    message: &str,
    span: Option<crate::utils::Span>,
    context: Vec<(&str, &str)>,
) {
    let mut event = LogEvent::error(code, message);

    if let Some(s) = span {
        event = event.with_span(s);
    }

    for (key, value) in context {
        event = event.with_context(key, value);
    }

    if let Some(file_ctx) = get_current_file_context() {
        event = event.with_context("file", &file_ctx.file_path.display().to_string());
        event = event.with_context("file_id", &file_ctx.file_id.to_string());
    }

    if let Some(logger) = try_get_global_logger() {
        logger.log_event(event.clone());
    }

    if let Some(file_ctx) = get_current_file_context() {
        if let Some(collector) = try_get_global_error_collector() {
            collector.record_event(&file_ctx.file_path, event);
        }
    }
}

/// Log success with context (used by log_success! macro) - FIXED: Code parameter
pub fn log_success_with_context(code: Code, message: &str, context: Vec<(&str, &str)>) {
    let mut event = LogEvent::success(code, message);

    for (key, value) in context {
        event = event.with_context(key, value);
    }

    if let Some(file_ctx) = get_current_file_context() {
        event = event.with_context("file", &file_ctx.file_path.display().to_string());
        event = event.with_context("file_id", &file_ctx.file_id.to_string());
    }

    if let Some(logger) = try_get_global_logger() {
        logger.log_event(event);
    }
}

/// Log info with context (used by log_info! macro) - FIXED: No empty module parameter
pub fn log_info_with_context(message: &str, context: Vec<(&str, &str)>) {
    let mut event = LogEvent::info(message);

    for (key, value) in context {
        event = event.with_context(key, value);
    }

    if let Some(file_ctx) = get_current_file_context() {
        event = event.with_context("file", &file_ctx.file_path.display().to_string());
    }

    if let Some(logger) = try_get_global_logger() {
        logger.log_event(event);
    }
}

// ============================================================================
// BATCH PROCESSING
// ============================================================================

/// Get processing summary
pub fn get_processing_summary() -> ProcessingSummary {
    try_get_global_error_collector()
        .map(|collector| collector.get_summary())
        .unwrap_or_default()
}

/// Get errors for specific file
pub fn get_file_errors(file_path: &Path) -> Vec<LogEvent> {
    try_get_global_error_collector()
        .map(|collector| collector.get_file_errors(file_path))
        .unwrap_or_default()
}

/// Print cargo-style summary
pub fn print_cargo_style_summary() {
    if let Some(collector) = try_get_global_error_collector() {
        println!("{}", collector::format_cargo_style_errors(collector));
    } else {
        println!("No error collector available for summary");
    }
}

/// Clear all collected errors
pub fn clear_error_collection() {
    if let Some(collector) = try_get_global_error_collector() {
        collector.clear();
    }
}

/// Get system diagnostics
pub fn get_system_diagnostics() -> String {
    let mut diagnostics = String::new();

    diagnostics.push_str("=== Logging System Diagnostics ===\n");
    diagnostics.push_str(&format!("Initialized: {}\n", is_initialized()));

    if let Some(collector) = try_get_global_error_collector() {
        let (current, max, percentage) = collector.get_capacity_info();
        diagnostics.push_str(&format!(
            "Capacity: {}/{} ({:.1}%)\n",
            current,
            max,
            percentage * 100.0
        ));

        let summary = collector.get_summary();
        diagnostics.push_str(&format!("Files processed: {}\n", summary.total_files));
        diagnostics.push_str(&format!("Total errors: {}\n", summary.total_errors));
        diagnostics.push_str(&format!("Total warnings: {}\n", summary.total_warnings));
    }

    diagnostics.push('\n');
    diagnostics.push_str(&config::get_config_summary());

    diagnostics
}

// ============================================================================
// SAFE FALLBACK LOGGING - FIXED: Code parameters
// ============================================================================

/// Safe error logging (won't panic if uninitialized)
pub fn safe_log_error(code: Code, message: &str) {
    if let Some(logger) = try_get_global_logger() {
        let event = LogEvent::error(code, message);
        logger.log_event(event);
    } else {
        eprintln!("[ERROR] FALLBACK: [{}] {}", code.as_str(), message);
    }
}

/// Safe critical error logging
pub fn safe_log_critical(code: Code, message: &str) {
    if let Some(logger) = try_get_global_logger() {
        let event = LogEvent::error(code, message);
        logger.log_event(event);
    }
    // Always log critical errors to stderr regardless
    eprintln!("CRITICAL ERROR [{}]: {}", code.as_str(), message);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_global_logging_initialization() {
        // Can't test if already initialized
        if is_initialized() {
            return;
        }

        let result = init_global_logging();
        assert!(result.is_ok());
        assert!(is_initialized());
    }

    #[test]
    fn test_file_context_management() {
        let file_path = PathBuf::from("test.esp");
        let file_id = 1;

        assert!(get_current_file_context().is_none());

        set_file_context(file_path.clone(), file_id);
        let context = get_current_file_context();
        assert!(context.is_some());
        assert_eq!(context.unwrap().file_path, file_path);

        clear_file_context();
        assert!(get_current_file_context().is_none());
    }

    #[test]
    fn test_with_file_context() {
        let file_path = PathBuf::from("test.esp");
        let file_id = 2;

        let result = with_file_context(file_path.clone(), file_id, || {
            let context = get_current_file_context();
            assert!(context.is_some());
            assert_eq!(context.unwrap().file_path, file_path);
            42
        });

        assert_eq!(result, 42);
        assert!(get_current_file_context().is_none());
    }

    #[test]
    fn test_safe_logging() {
        safe_log_error(codes::system::INTERNAL_ERROR, "Test error");
        safe_log_critical(codes::system::INTERNAL_ERROR, "Test critical error");
        // Should not panic even if global logging is not initialized
    }

    #[test]
    fn test_diagnostics() {
        let diagnostics = get_system_diagnostics();
        assert!(diagnostics.contains("Logging System Diagnostics"));
        assert!(diagnostics.contains("Initialized:"));
    }
}
