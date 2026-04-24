//! Logging service implementation with updated LogEvent

use super::codes::Code;
use super::config;
use super::events::{LogEvent, LogLevel};
use crate::utils::Span;
use std::sync::{Arc, Mutex};

/// Simple logger trait
pub trait Logger: Send + Sync {
    fn log(&self, event: &LogEvent);
}

/// Main logging service with configuration awareness
pub struct LoggingService {
    logger: Arc<dyn Logger>,
    min_level: LogLevel,
}

impl LoggingService {
    /// Create new logging service with specified logger and minimum level
    pub fn new(logger: Arc<dyn Logger>, min_level: LogLevel) -> Self {
        Self { logger, min_level }
    }

    /// Create service with configuration-aware settings
    pub fn with_config() -> Self {
        let min_level = config::get_min_log_level();
        let logger: Arc<dyn Logger> = if config::use_structured_logging() {
            Arc::new(StructuredLogger::new(min_level))
        } else {
            Arc::new(ConsoleLogger::new(min_level))
        };

        Self::new(logger, min_level)
    }

    /// Set minimum log level
    pub fn set_min_level(&mut self, level: LogLevel) {
        self.min_level = level;
    }

    /// Check if level should be logged
    pub fn should_log(&self, level: LogLevel) -> bool {
        level <= self.min_level
    }

    /// Log an event
    pub fn log_event(&self, event: LogEvent) {
        if self.should_log(event.level) {
            self.logger.log(&event);
        }
    }

    /// Convenience method: log error with code
    pub fn log_error(&self, error_code: Code, message: &str) {
        let event = LogEvent::error(error_code, message);
        self.log_event(event);
    }

    /// Convenience method: log error with context
    pub fn log_error_with_context(
        &self,
        error_code: Code,
        message: &str,
        context: Vec<(&str, &str)>,
    ) {
        let mut event = LogEvent::error(error_code, message);
        for (key, value) in context {
            event = event.with_context(key, value);
        }
        self.log_event(event);
    }

    /// Convenience method: log error with span
    pub fn log_error_with_span(&self, error_code: Code, message: &str, span: Span) {
        let event = LogEvent::error(error_code, message).with_span(span);
        self.log_event(event);
    }

    /// Convenience method: log info
    pub fn log_info(&self, message: &str) {
        let event = LogEvent::info(message);
        self.log_event(event);
    }

    /// Convenience method: log info with code
    pub fn log_info_with_code(&self, info_code: Code, message: &str) {
        let event = LogEvent::info_with_code(info_code, message);
        self.log_event(event);
    }

    /// Convenience method: log success
    pub fn log_success(&self, success_code: Code, message: &str) {
        let event = LogEvent::success(success_code, message);
        self.log_event(event);
    }

    /// Convenience method: log success with context
    pub fn log_success_with_context(
        &self,
        success_code: Code,
        message: &str,
        context: Vec<(&str, &str)>,
    ) {
        let mut event = LogEvent::success(success_code, message);
        for (key, value) in context {
            event = event.with_context(key, value);
        }
        self.log_event(event);
    }

    /// Convenience method: log warning
    pub fn log_warning(&self, message: &str) {
        let event = LogEvent::warning(message);
        self.log_event(event);
    }

    /// Convenience method: log warning with code
    pub fn log_warning_with_code(&self, warning_code: Code, message: &str) {
        let event = LogEvent::warning_with_code(warning_code, message);
        self.log_event(event);
    }

    /// Convenience method: log debug
    pub fn log_debug(&self, message: &str) {
        let event = LogEvent::debug(message);
        self.log_event(event);
    }

    /// Convenience method: log debug with code
    pub fn log_debug_with_code(&self, debug_code: Code, message: &str) {
        let event = LogEvent::debug_with_code(debug_code, message);
        self.log_event(event);
    }
}

/// Simple console logger
pub struct ConsoleLogger {
    min_level: LogLevel,
}

impl ConsoleLogger {
    pub fn new(min_level: LogLevel) -> Self {
        Self { min_level }
    }
}

impl Logger for ConsoleLogger {
    fn log(&self, event: &LogEvent) {
        if event.level <= self.min_level {
            match event.level {
                LogLevel::Error => eprintln!("{}", event.format()),
                _ => println!("{}", event.format()),
            }
        }
    }
}

/// Structured logger for JSON output and better tooling integration
pub struct StructuredLogger {
    min_level: LogLevel,
}

impl StructuredLogger {
    pub fn new(min_level: LogLevel) -> Self {
        Self { min_level }
    }
}

impl Logger for StructuredLogger {
    fn log(&self, event: &LogEvent) {
        if event.level <= self.min_level {
            match event.format_json() {
                Ok(json) => match event.level {
                    LogLevel::Error => eprintln!("{}", json),
                    _ => println!("{}", json),
                },
                Err(_) => {
                    // Fallback to regular format if JSON serialization fails
                    match event.level {
                        LogLevel::Error => eprintln!("{}", event.format()),
                        _ => println!("{}", event.format()),
                    }
                }
            }
        }
    }
}

/// Memory logger for testing
pub struct MemoryLogger {
    events: Mutex<Vec<LogEvent>>,
}

impl MemoryLogger {
    pub fn new() -> Self {
        Self {
            events: Mutex::new(Vec::new()),
        }
    }

    pub fn get_events(&self) -> Vec<LogEvent> {
        self.events
            .lock()
            .map(|events| events.clone())
            .unwrap_or_default()
    }

    pub fn clear(&self) {
        if let Ok(mut events) = self.events.lock() {
            events.clear();
        }
    }

    pub fn event_count(&self) -> usize {
        self.events.lock().map(|e| e.len()).unwrap_or(0)
    }

    pub fn get_errors(&self) -> Vec<LogEvent> {
        self.events
            .lock()
            .map(|events| events.iter().filter(|e| e.is_error()).cloned().collect())
            .unwrap_or_default()
    }

    pub fn get_warnings(&self) -> Vec<LogEvent> {
        self.events
            .lock()
            .map(|events| events.iter().filter(|e| e.is_warning()).cloned().collect())
            .unwrap_or_default()
    }

    pub fn get_events_with_code(&self, code: Code) -> Vec<LogEvent> {
        self.events
            .lock()
            .map(|events| {
                events
                    .iter()
                    .filter(|e| e.code.as_str() == code.as_str())
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn has_error_with_code(&self, code: Code) -> bool {
        self.events
            .lock()
            .map(|events| {
                events
                    .iter()
                    .any(|e| e.is_error() && e.code.as_str() == code.as_str())
            })
            .unwrap_or(false)
    }

    pub fn has_success_with_code(&self, code: Code) -> bool {
        self.events
            .lock()
            .map(|events| {
                events
                    .iter()
                    .any(|e| e.is_info() && e.code.as_str() == code.as_str())
            })
            .unwrap_or(false)
    }

    pub fn get_critical_errors(&self) -> Vec<LogEvent> {
        self.events
            .lock()
            .map(|events| {
                events
                    .iter()
                    .filter(|e| e.is_error() && e.requires_halt())
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn get_events_by_severity(&self, min_severity: &str) -> Vec<LogEvent> {
        self.events
            .lock()
            .map(|events| {
                events
                    .iter()
                    .filter(|e| {
                        let event_severity = e.severity();
                        matches!(
                            (min_severity, event_severity),
                            ("Critical", "Critical")
                                | ("High", "Critical" | "High")
                                | ("Medium", "Critical" | "High" | "Medium")
                                | ("Low", _)
                        )
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn get_events_by_category(&self, category: &str) -> Vec<LogEvent> {
        self.events
            .lock()
            .map(|events| {
                events
                    .iter()
                    .filter(|e| e.category() == category)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn get_summary(&self) -> EventSummary {
        let Ok(events) = self.events.lock() else {
            return EventSummary::default();
        };
        let total_count = events.len();
        let error_count = events.iter().filter(|e| e.is_error()).count();
        let warning_count = events.iter().filter(|e| e.is_warning()).count();
        let info_count = events.iter().filter(|e| e.is_info()).count();
        let debug_count = events.iter().filter(|e| e.is_debug()).count();
        let critical_count = events
            .iter()
            .filter(|e| e.is_error() && e.requires_halt())
            .count();

        EventSummary {
            total_count,
            error_count,
            warning_count,
            info_count,
            debug_count,
            critical_count,
        }
    }
}

impl Default for MemoryLogger {
    fn default() -> Self {
        Self::new()
    }
}

impl Logger for MemoryLogger {
    fn log(&self, event: &LogEvent) {
        let Ok(mut events) = self.events.lock() else {
            return;
        };

        // Respect buffer size limits from config
        let max_events = config::get_error_buffer_size();
        if events.len() >= max_events {
            // Remove oldest events to make room
            let events_len = events.len();
            let remove_count = events_len - max_events + 1;
            events.drain(0..remove_count);
        }

        events.push(event.clone());
    }
}

/// Summary of events in memory logger
#[derive(Debug, Clone, Default)]
pub struct EventSummary {
    pub total_count: usize,
    pub error_count: usize,
    pub warning_count: usize,
    pub info_count: usize,
    pub debug_count: usize,
    pub critical_count: usize,
}

impl EventSummary {
    pub fn has_errors(&self) -> bool {
        self.error_count > 0
    }

    pub fn has_warnings(&self) -> bool {
        self.warning_count > 0
    }

    pub fn has_critical_errors(&self) -> bool {
        self.critical_count > 0
    }

    pub fn success_rate(&self) -> f64 {
        if self.total_count == 0 {
            1.0
        } else {
            1.0 - (self.error_count as f64 / self.total_count as f64)
        }
    }
}

/// File logger for persistent logging
pub struct FileLogger {
    file_path: std::path::PathBuf,
    min_level: LogLevel,
    structured: bool,
}

impl FileLogger {
    pub fn new<P: AsRef<std::path::Path>>(
        file_path: P,
        min_level: LogLevel,
        structured: bool,
    ) -> Result<Self, std::io::Error> {
        let path = file_path.as_ref().to_path_buf();

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Test write access
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;

        Ok(Self {
            file_path: path,
            min_level,
            structured,
        })
    }
}

impl Logger for FileLogger {
    fn log(&self, event: &LogEvent) {
        if event.level <= self.min_level {
            let output = if self.structured {
                event.format_json().unwrap_or_else(|_| event.format())
            } else {
                event.format()
            };

            // Write to file (ignore errors to avoid logging recursion)
            if let Ok(mut file) = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.file_path)
            {
                use std::io::Write;
                let _ = writeln!(file, "{}", output);
            }
        }
    }
}

/// Multi-target logger that can log to multiple destinations
pub struct MultiLogger {
    loggers: Vec<Arc<dyn Logger>>,
    min_level: LogLevel,
}

impl MultiLogger {
    pub fn new(min_level: LogLevel) -> Self {
        Self {
            loggers: Vec::new(),
            min_level,
        }
    }

    pub fn add_logger(&mut self, logger: Arc<dyn Logger>) {
        self.loggers.push(logger);
    }

    pub fn with_console(mut self, console_level: LogLevel) -> Self {
        self.add_logger(Arc::new(ConsoleLogger::new(console_level)));
        self
    }

    pub fn with_structured_console(mut self, console_level: LogLevel) -> Self {
        self.add_logger(Arc::new(StructuredLogger::new(console_level)));
        self
    }

    pub fn with_file<P: AsRef<std::path::Path>>(
        mut self,
        file_path: P,
        file_level: LogLevel,
        structured: bool,
    ) -> Result<Self, std::io::Error> {
        let file_logger = FileLogger::new(file_path, file_level, structured)?;
        self.add_logger(Arc::new(file_logger));
        Ok(self)
    }

    pub fn with_memory(mut self) -> (Self, Arc<MemoryLogger>) {
        let memory_logger = Arc::new(MemoryLogger::new());
        self.add_logger(memory_logger.clone());
        (self, memory_logger)
    }
}

impl Logger for MultiLogger {
    fn log(&self, event: &LogEvent) {
        if event.level <= self.min_level {
            for logger in &self.loggers {
                logger.log(event);
            }
        }
    }
}

// ============================================================================
// CONFIGURATION-AWARE FACTORY FUNCTIONS
// ============================================================================

/// Create logging service based on current configuration
pub fn create_configured_service() -> LoggingService {
    LoggingService::with_config()
}

/// Create multi-logger based on configuration
pub fn create_configured_multi_logger() -> Result<MultiLogger, std::io::Error> {
    let min_level = config::get_min_log_level();
    let mut multi_logger = MultiLogger::new(min_level);

    // Add console logger if enabled
    if config::use_console_logging() {
        if config::use_structured_logging() {
            multi_logger = multi_logger.with_structured_console(min_level);
        } else {
            multi_logger = multi_logger.with_console(min_level);
        }
    }

    Ok(multi_logger)
}

/// Create development logger (high verbosity, console output)
pub fn create_dev_logger() -> Arc<dyn Logger> {
    if config::use_structured_logging() {
        Arc::new(StructuredLogger::new(LogLevel::Debug))
    } else {
        Arc::new(ConsoleLogger::new(LogLevel::Debug))
    }
}

/// Create production logger (filtered output, structured format)
pub fn create_prod_logger() -> Arc<dyn Logger> {
    Arc::new(StructuredLogger::new(LogLevel::Info))
}

/// Create testing logger (memory-based, all events captured)
pub fn create_test_logger() -> Arc<MemoryLogger> {
    Arc::new(MemoryLogger::new())
}

#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::codes;

    #[test]
    fn test_console_logger() {
        let logger = ConsoleLogger::new(LogLevel::Info);
        let event = LogEvent::info("Test message");

        // Should not panic
        logger.log(&event);
    }

    #[test]
    fn test_structured_logger() {
        let logger = StructuredLogger::new(LogLevel::Debug);
        let event = LogEvent::error(codes::file_processing::FILE_NOT_FOUND, "Test error")
            .with_context("key", "value");

        // Should not panic and should produce JSON
        logger.log(&event);
    }

    #[test]
    fn test_memory_logger() {
        let logger = MemoryLogger::new();

        let event1 = LogEvent::info("Message 1");
        let event2 = LogEvent::error(codes::lexical::INVALID_CHARACTER, "Error message");

        logger.log(&event1);
        logger.log(&event2);

        assert_eq!(logger.event_count(), 2);
        assert_eq!(logger.get_errors().len(), 1);
        assert!(logger.has_error_with_code(codes::lexical::INVALID_CHARACTER));

        let summary = logger.get_summary();
        assert_eq!(summary.total_count, 2);
        assert_eq!(summary.error_count, 1);
        assert_eq!(summary.info_count, 1);

        logger.clear();
        assert_eq!(logger.event_count(), 0);
    }

    #[test]
    fn test_multi_logger() {
        let multi = MultiLogger::new(LogLevel::Debug);
        let (multi, memory) = multi.with_memory();
        let multi = multi.with_console(LogLevel::Info);

        let event = LogEvent::info("Test message");
        multi.log(&event);

        assert_eq!(memory.event_count(), 1);
    }

    #[test]
    fn test_logging_service() {
        let logger = Arc::new(MemoryLogger::new());
        let service = LoggingService::new(logger.clone(), LogLevel::Debug);

        service.log_error(codes::file_processing::PERMISSION_DENIED, "Test error");
        service.log_success(codes::success::FILE_PROCESSING_SUCCESS, "Test success");
        service.log_info("Test info");

        assert_eq!(logger.event_count(), 3);
        assert!(logger.has_error_with_code(codes::file_processing::PERMISSION_DENIED));
        assert!(logger.has_success_with_code(codes::success::FILE_PROCESSING_SUCCESS));
    }

    #[test]
    fn test_log_level_filtering() {
        let logger = Arc::new(MemoryLogger::new());
        let service = LoggingService::new(logger.clone(), LogLevel::Error);

        service.log_debug("Debug message");
        service.log_info("Info message");
        service.log_error(codes::system::INTERNAL_ERROR, "Error message");

        // Only error should be logged due to level filtering
        assert_eq!(logger.event_count(), 1);
        assert!(logger.has_error_with_code(codes::system::INTERNAL_ERROR));
    }

    #[test]
    fn test_critical_error_detection() {
        let logger = MemoryLogger::new();

        logger.log(&LogEvent::error(
            codes::system::INTERNAL_ERROR,
            "Critical error",
        ));
        logger.log(&LogEvent::error(
            codes::lexical::INVALID_CHARACTER,
            "Normal error",
        ));

        let critical_errors = logger.get_critical_errors();
        assert_eq!(critical_errors.len(), 1);
        assert_eq!(critical_errors[0].code.as_str(), "ERR001");
    }

    #[test]
    fn test_event_categorization() {
        let logger = MemoryLogger::new();

        logger.log(&LogEvent::error(
            codes::file_processing::FILE_NOT_FOUND,
            "File error",
        ));
        logger.log(&LogEvent::error(
            codes::lexical::INVALID_CHARACTER,
            "Lexical error",
        ));

        let file_events = logger.get_events_by_category("FileProcessing");
        let lexical_events = logger.get_events_by_category("Lexical");

        assert_eq!(file_events.len(), 1);
        assert_eq!(lexical_events.len(), 1);
    }

    #[test]
    fn test_convenience_methods() {
        let logger = Arc::new(MemoryLogger::new());
        let service = LoggingService::new(logger.clone(), LogLevel::Debug);

        // Test convenience methods
        service.log_error_with_context(
            codes::file_processing::FILE_TOO_LARGE,
            "File too large",
            vec![("size", "1024"), ("limit", "512")],
        );

        service.log_success_with_context(
            codes::success::TOKENIZATION_COMPLETE,
            "Tokenization done",
            vec![("tokens", "42")],
        );

        assert_eq!(logger.event_count(), 2);

        let events = logger.get_events();
        assert!(events[0].context.contains_key("size"));
        assert!(events[1].context.contains_key("tokens"));
    }
}
